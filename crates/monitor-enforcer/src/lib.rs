//! Native file authorization prototype. No network or GUI deployment is implied.
use monitor_core::protection::{
    ProtectionEngine, ProtectionMode, ProtectionPolicy, Transport, Verdict,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

#[cfg(target_os = "macos")]
pub mod native;
pub mod network;
#[cfg(unix)]
pub mod snapshot;
#[cfg(target_os = "macos")]
pub mod transport;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AgentIdentity {
    pub agent_id: String,
    pub executable: String,
    /// Exact kernel code directory hash, pinned during explicit enrollment.
    pub cdhash: String,
    #[serde(default)]
    pub policy: Option<ProtectionPolicy>,
    /// Projects are enrolled per exec instance, never unioned by Agent name.
    #[serde(default)]
    pub dynamic_project: bool,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct UserPolicy {
    pub uid: u32,
    pub policy: ProtectionPolicy,
    pub agents: Vec<AgentIdentity>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub revision: u64,
    pub users: Vec<UserPolicy>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ProcessKey {
    pub pid: u32,
    pub version: u32,
}
#[derive(Clone, Debug)]
pub struct ProcessIdentity<'a> {
    pub key: ProcessKey,
    pub uid: u32,
    pub executable: &'a str,
    pub signature_valid: bool,
    pub cdhash: [u8; 20],
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Scope {
    pub agent: usize,
    pub signature_mismatch: bool,
    pub instance: ProcessKey,
}
struct RegisteredAgent {
    user: usize,
    id: String,
    executable: String,
    hash: [u8; 20],
    mode: ProtectionMode,
    engine: ProtectionEngine,
    policy: ProtectionPolicy,
    dynamic_project: bool,
}
struct User {
    uid: u32,
}
pub struct FileAuthorizer {
    users: Vec<User>,
    agents: Vec<RegisteredAgent>,
    processes: HashMap<ProcessKey, Scope>,
    instances: HashMap<ProcessKey, ProtectionEngine>,
    projects: HashMap<ProcessKey, String>,
    last_sequence: Option<u64>,
    healthy: bool,
    pub revision: u64,
}
impl FileAuthorizer {
    pub fn new(snapshot: Snapshot) -> Result<Self, String> {
        if snapshot.users.len() > 32 {
            return Err("Too many users".into());
        }
        let mut users: Vec<User> = Vec::new();
        let mut agents: Vec<RegisteredAgent> = Vec::new();
        for user in snapshot.users {
            if user.uid == 0 || users.iter().any(|u| u.uid == user.uid) {
                return Err("Invalid or duplicate user".into());
            }
            let user_index = users.len();
            users.push(User { uid: user.uid });
            for agent in user.agents {
                if agents.len() >= 256
                    || agent.agent_id.is_empty()
                    || agent.agent_id.len() > 256
                    || agent.agent_id.chars().any(char::is_control)
                    || !agent.executable.starts_with('/')
                    || agent.executable.len() > 4096
                    || agent.executable.contains('\0')
                    || agent.executable.split('/').any(|p| p == ".." || p == ".")
                    || agents.iter().any(|a| {
                        a.user == user_index
                            && (a.id == agent.agent_id || a.executable == agent.executable)
                    })
                {
                    return Err("Invalid or duplicate Agent identity".into());
                }
                if agent.cdhash.len() != 40 || !agent.cdhash.bytes().all(|b| b.is_ascii_hexdigit())
                {
                    return Err("Agent CDHash must contain 40 hex digits".into());
                }
                let mut hash = [0; 20];
                for (i, byte) in hash.iter_mut().enumerate() {
                    *byte = u8::from_str_radix(&agent.cdhash[i * 2..i * 2 + 2], 16)
                        .map_err(|e| e.to_string())?;
                }
                if hash == [0; 20] {
                    return Err("Zero CDHash is not an identity".into());
                }
                if agents
                    .iter()
                    .any(|agent| agent.user == user_index && agent.hash == hash)
                {
                    return Err(
                        "A code identity cannot belong to multiple Agents for one user".into(),
                    );
                }
                let mut policy = agent.policy.unwrap_or_else(|| user.policy.clone());
                if agent.dynamic_project {
                    policy.project_directories.clear();
                }
                agents.push(RegisteredAgent {
                    user: user_index,
                    id: agent.agent_id,
                    executable: agent.executable,
                    hash,
                    mode: policy.mode,
                    engine: ProtectionEngine::new(policy.clone())?,
                    policy,
                    dynamic_project: agent.dynamic_project,
                });
            }
        }
        Ok(Self {
            users,
            agents,
            processes: HashMap::new(),
            instances: HashMap::new(),
            projects: HashMap::new(),
            last_sequence: None,
            healthy: true,
            revision: snapshot.revision,
        })
    }
    pub fn sequence(&mut self, number: u64) -> Result<(), String> {
        if !self.healthy {
            return Err("Process coverage was revoked".into());
        }
        if self
            .last_sequence
            .is_some_and(|last| last.checked_add(1) != Some(number))
        {
            self.healthy = false;
            return Err("Endpoint Security event gap; process scope is incomplete".into());
        }
        self.last_sequence = Some(number);
        Ok(())
    }
    pub fn identify(&mut self, process: &ProcessIdentity<'_>) -> Result<Option<Scope>, String> {
        if !self.healthy {
            return Err("Process coverage was revoked".into());
        }
        if let Some(scope) = self.processes.get_mut(&process.key) {
            let agent = &self.agents[scope.agent];
            if process.executable == agent.executable || process.cdhash == agent.hash {
                scope.signature_mismatch |=
                    !process.signature_valid || process.cdhash != agent.hash;
            }
            return Ok(Some(*scope));
        }
        let match_index = self.agents.iter().position(|a| {
            self.users[a.user].uid == process.uid
                && (a.executable == process.executable
                    || (process.signature_valid && a.hash == process.cdhash))
        });
        if let Some(agent) = match_index {
            let scope = Scope {
                agent,
                instance: process.key,
                signature_mismatch: !process.signature_valid
                    || self.agents[agent].hash != process.cdhash,
            };
            self.remember(process.key, scope)?;
            return Ok(Some(scope));
        }
        Ok(None)
    }
    fn remember(&mut self, key: ProcessKey, scope: Scope) -> Result<(), String> {
        if self.processes.len() >= 4096 && !self.processes.contains_key(&key) {
            self.healthy = false;
            return Err("Process tracking capacity exhausted".into());
        }
        self.processes.insert(key, scope);
        Ok(())
    }
    pub fn fork(
        &mut self,
        parent: &ProcessIdentity<'_>,
        child: &ProcessIdentity<'_>,
    ) -> Result<(), String> {
        if let Some(scope) = self.identify(parent)? {
            self.remember(child.key, scope)?;
        } else {
            self.identify(child)?;
        }
        Ok(())
    }
    pub fn exec(
        &mut self,
        old: &ProcessIdentity<'_>,
        new: &ProcessIdentity<'_>,
    ) -> Result<(), String> {
        let inherited = self.identify(old)?;
        self.processes.remove(&old.key);
        if let Some(scope) = inherited {
            self.remember(new.key, scope)?;
        } else {
            self.identify(new)?;
        }
        Ok(())
    }
    pub fn exit(&mut self, key: ProcessKey) {
        self.processes.remove(&key);
        self.instances.retain(|instance, _| {
            self.processes
                .values()
                .any(|scope| scope.instance == *instance)
        });
        self.projects
            .retain(|instance, _| self.instances.contains_key(instance));
    }
    /// Called only with the exec event's kernel-provided cwd. Child chdir or exec
    /// does not grant another project's files, and PID reuse never inherits scope.
    pub fn exec_project(
        &mut self,
        old: &ProcessIdentity<'_>,
        new: &ProcessIdentity<'_>,
        cwd: &str,
        truncated: bool,
    ) -> Result<(), String> {
        let inherited = self.identify(old)?;
        self.exec(old, new)?;
        if inherited.is_none() {
            if let Some(scope) = self.processes.get(&new.key).copied() {
                self.enroll_project(scope, cwd, truncated)?;
            }
        }
        Ok(())
    }
    fn enroll_project(&mut self, scope: Scope, cwd: &str, truncated: bool) -> Result<(), String> {
        let agent = &self.agents[scope.agent];
        if !agent.dynamic_project {
            return Ok(());
        }
        let mut policy = agent.policy.clone();
        policy.project_directories.clear();
        // Broad system/user roots are never automatic project grants.
        if !truncated
            && cwd != "/"
            && cwd != "/Users"
            && !cwd.starts_with("/System")
            && !cwd.starts_with("/Applications")
            && !(cwd.starts_with("/Users/") && cwd.trim_end_matches('/').split('/').count() == 3)
        {
            let candidate = ProtectionPolicy {
                project_directories: vec![cwd.into()],
                ..Default::default()
            };
            if candidate.validate().is_ok() {
                policy.project_directories = vec![cwd.into()];
                self.projects.insert(scope.instance, cwd.into());
            }
        }
        self.instances
            .insert(scope.instance, ProtectionEngine::new(policy)?);
        Ok(())
    }
    pub fn network(&self, scope: Scope, host: &str, port: u16, transport: Transport) -> Verdict {
        let agent = &self.agents[scope.agent];
        if scope.signature_mismatch && agent.mode != ProtectionMode::Observe {
            return Verdict::Deny;
        }
        agent.engine.network(host, port, transport).verdict
    }
    pub fn runtime_snapshot(&self) -> RuntimeSnapshot {
        RuntimeSnapshot {
            revision: self.revision,
            healthy: self.healthy,
            generated_at_ms: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            processes: self
                .processes
                .iter()
                .map(|(key, scope)| {
                    let agent = &self.agents[scope.agent];
                    RuntimeProcess {
                        pid: key.pid,
                        version: key.version,
                        uid: self.users[agent.user].uid,
                        agent_id: agent.id.clone(),
                        signature_mismatch: scope.signature_mismatch,
                        policy: agent.policy.clone(),
                    }
                })
                .collect(),
        }
    }
    pub fn file(
        &self,
        scope: Scope,
        path: &str,
        truncated: bool,
        regular: bool,
        links: u64,
    ) -> Verdict {
        let agent = &self.agents[scope.agent];
        if agent.mode == ProtectionMode::Observe {
            return Verdict::Observe;
        }
        // A hard-link alias can make a pathname-only grant authorize another
        // directory's inode. Until inode grants exist, deny multi-linked files.
        if scope.signature_mismatch || truncated || (regular && links > 1) {
            return Verdict::Deny;
        }
        if agent.dynamic_project {
            return self
                .instances
                .get(&scope.instance)
                .map(|engine| engine.file_read(path).verdict)
                .unwrap_or_else(|| agent.engine.file_read(path).verdict);
        }
        agent.engine.file_read(path).verdict
    }
    pub fn agent_id(&self, scope: Scope) -> &str {
        &self.agents[scope.agent].id
    }
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeProcess {
    pub pid: u32,
    pub version: u32,
    pub uid: u32,
    pub agent_id: String,
    pub signature_mismatch: bool,
    pub policy: ProtectionPolicy,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuntimeSnapshot {
    pub revision: u64,
    pub healthy: bool,
    pub generated_at_ms: u64,
    pub processes: Vec<RuntimeProcess>,
}
