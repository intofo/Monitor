use serde::Serialize;
use std::{
    collections::HashMap,
    path::{Path, PathBuf},
};
use sysinfo::{ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};

#[derive(Clone, Debug, Serialize)]
pub struct AgentProcess {
    pub pid: u32,
    pub start_time: u64,
    pub parent: Option<u32>,
    pub name: String,
    pub executable: String,
    pub agent: String,
    pub agent_id: String,
    pub inherited: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct Installation {
    pub agent: String,
    pub path: String,
    pub basis: String,
}

// Name matching is discovery evidence, never a trusted security identity.
pub fn identify(name: &str, executable: &str) -> Option<&'static str> {
    let name = name.to_ascii_lowercase();
    let name = name.trim_end_matches(".exe");
    let path = executable.replace('\\', "/").to_ascii_lowercase();
    for (agent, names, markers) in [
        (
            "Trae CN",
            &["trae cn"][..],
            &["/trae cn.app/", "/trae cn/"][..],
        ),
        ("Trae", &["trae"][..], &["/trae.app/", "/trae/"][..]),
        ("ZCode", &["zcode"][..], &["/zcode.app/", "/zcode/"][..]),
        ("Cursor", &["cursor"][..], &["/cursor.app/", "/cursor/"][..]),
        (
            "Windsurf",
            &["windsurf"][..],
            &["/windsurf.app/", "/windsurf/"][..],
        ),
        (
            "Claude Code",
            &["claude"][..],
            &["/@anthropic-ai/claude-code/"][..],
        ),
        (
            "Codex",
            &["codex"][..],
            &["/codex.app/", "/@openai/codex/"][..],
        ),
        ("OpenCode", &["opencode"][..], &["/opencode.app/"][..]),
        ("Gemini CLI", &["gemini"][..], &["/@google/gemini-cli/"][..]),
        ("Aider", &["aider"][..], &[][..]),
    ] {
        if names.contains(&name) || markers.iter().any(|m| path.contains(m)) {
            return Some(agent);
        }
    }
    None
}

pub struct Discovery {
    system: System,
    previous: HashMap<(u32, u64), AgentProcess>,
}
impl Default for Discovery {
    fn default() -> Self {
        Self {
            system: System::new(),
            previous: HashMap::new(),
        }
    }
}
impl Discovery {
    pub fn refresh(&mut self) -> Vec<AgentProcess> {
        self.refresh_config(&crate::settings::MonitorConfig::default())
    }
    pub fn refresh_config(&mut self, config: &crate::settings::MonitorConfig) -> Vec<AgentProcess> {
        self.system.refresh_processes_specifics(
            ProcessesToUpdate::All,
            true,
            ProcessRefreshKind::nothing()
                .with_exe(UpdateKind::Always)
                .with_cmd(UpdateKind::Always)
                .without_tasks(),
        );
        let mut found = HashMap::new();
        for (pid, process) in self.system.processes() {
            let executable = process
                .exe()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_default();
            let name = process.name().to_string_lossy().into_owned();
            // Only inspect the executable/script argument; never serialize full commands or tokens.
            let script = if matches!(
                name.as_str(),
                "node" | "node.exe" | "python" | "python3" | "python.exe"
            ) {
                process
                    .cmd()
                    .get(1)
                    .map(|s| s.to_string_lossy().into_owned())
                    .unwrap_or_default()
            } else {
                String::new()
            };
            let custom = config
                .custom_agents
                .iter()
                .find(|c| c.executable == executable);
            let agent = custom
                .map(|c| c.name.as_str())
                .or_else(|| identify(&name, &executable))
                .or_else(|| identify("", &script));
            let key = (pid.as_u32(), process.start_time());
            if let Some(agent) = agent {
                found.insert(
                    pid.as_u32(),
                    AgentProcess {
                        pid: pid.as_u32(),
                        start_time: process.start_time(),
                        parent: process.parent().map(|p| p.as_u32()),
                        name,
                        executable,
                        agent: agent.into(),
                        agent_id: custom
                            .map(|c| c.id.clone())
                            .unwrap_or_else(|| format!("known:{agent}")),
                        inherited: false,
                    },
                );
            } else if let Some(old) = self
                .previous
                .get(&key)
                .filter(|p| p.executable == executable && p.inherited)
            {
                found.insert(pid.as_u32(), old.clone());
            }
        }
        // Close over the live ancestry graph. A child cannot precede its current parent.
        for _ in 0..32 {
            let mut added = vec![];
            for (pid, process) in self.system.processes() {
                if found.contains_key(&pid.as_u32()) {
                    continue;
                }
                if let Some(parent) = process
                    .parent()
                    .and_then(|p| found.get(&p.as_u32()))
                    .filter(|p| p.start_time <= process.start_time())
                {
                    added.push(AgentProcess {
                        pid: pid.as_u32(),
                        start_time: process.start_time(),
                        parent: process.parent().map(|p| p.as_u32()),
                        name: process.name().to_string_lossy().into_owned(),
                        executable: process
                            .exe()
                            .map(|p| p.to_string_lossy().into_owned())
                            .unwrap_or_default(),
                        agent: parent.agent.clone(),
                        agent_id: parent.agent_id.clone(),
                        inherited: true,
                    });
                }
            }
            if added.is_empty() {
                break;
            }
            for p in added {
                found.insert(p.pid, p);
            }
        }
        // A recognized Agent launched by the monitor is still a real monitoring root.
        let agent_roots: std::collections::HashSet<_> = found
            .values()
            .filter(|p| !p.inherited)
            .map(|p| p.pid)
            .collect();
        // Exclude our own sensor subprocesses, but not managed Agent launches.
        found.retain(|pid, _| {
            let mut current = Some(sysinfo::Pid::from_u32(*pid));
            for _ in 0..64 {
                let Some(pid) = current else {
                    break;
                };
                if pid.as_u32() == std::process::id() {
                    return false;
                }
                if agent_roots.contains(&pid.as_u32()) {
                    return true;
                }
                current = self.system.process(pid).and_then(|p| p.parent());
            }
            true
        });
        // Inventory is independent of product recognition: unknown programs are monitored too.
        for (pid, process) in self.system.processes() {
            if pid.as_u32() == std::process::id() || found.contains_key(&pid.as_u32()) {
                continue;
            }
            let mut ancestor = process.parent();
            let mut own_child = false;
            for _ in 0..64 {
                let Some(parent) = ancestor else { break };
                if parent.as_u32() == std::process::id() {
                    own_child = true;
                    break;
                }
                ancestor = self.system.process(parent).and_then(|p| p.parent());
            }
            // Skip only collection utilities, not arbitrary programs launched by us.
            let name = process.name().to_string_lossy().into_owned();
            if own_child && matches!(name.as_str(), "lsof" | "powershell.exe") {
                continue;
            }
            found.insert(
                pid.as_u32(),
                AgentProcess {
                    pid: pid.as_u32(),
                    start_time: process.start_time(),
                    parent: process.parent().map(|p| p.as_u32()),
                    name,
                    executable: process
                        .exe()
                        .map(|p| p.to_string_lossy().into_owned())
                        .unwrap_or_default(),
                    agent: "未分类程序".into(),
                    agent_id: "unclassified".into(),
                    inherited: false,
                },
            );
        }
        let mut list: Vec<_> = found.into_values().collect();
        list.sort_by_key(|p| p.pid);
        self.previous = list
            .iter()
            .map(|p| ((p.pid, p.start_time), p.clone()))
            .collect();
        list
    }
}

pub fn installations() -> Vec<Installation> {
    let mut roots: Vec<PathBuf> = vec![];
    #[cfg(target_os = "macos")]
    {
        roots.push("/Applications".into());
        if let Some(home) = dirs::home_dir() {
            roots.push(home.join("Applications"));
        }
    }
    #[cfg(target_os = "windows")]
    {
        for var in ["ProgramFiles", "ProgramFiles(x86)"] {
            if let Some(p) = std::env::var_os(var) {
                roots.push(p.into());
            }
        }
        if let Some(local) = dirs::data_local_dir() {
            roots.push(local.join("Programs"));
        }
    }
    #[cfg(target_os = "linux")]
    {
        roots.extend([
            PathBuf::from("/opt"),
            PathBuf::from("/usr/bin"),
            PathBuf::from("/usr/local/bin"),
        ]);
    }
    if let Some(home) = dirs::home_dir() {
        roots.push(home.join(".local/bin"));
        roots.push(home.join(".cargo/bin"));
    }
    // Desktop launches may not inherit the user's shell PATH.
    #[cfg(unix)]
    roots.push(PathBuf::from("/usr/local/bin"));
    #[cfg(target_os = "macos")]
    roots.push(PathBuf::from("/opt/homebrew/bin"));
    if let Some(path) = std::env::var_os("PATH") {
        roots.extend(std::env::split_paths(&path).filter(|p| p.is_absolute()));
    }
    roots.sort();
    roots.dedup();
    let mut result = vec![];
    for root in roots {
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        for entry in entries.take(2048).flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            let name = name.strip_suffix(".app").unwrap_or(&name);
            if let Some(agent) = identify(name, "") {
                result.push(Installation {
                    agent: agent.into(),
                    path: entry.path().to_string_lossy().into_owned(),
                    basis: "常见安装位置名称匹配，未经签名验证".into(),
                });
            }
        }
    }
    result.sort_by(|a, b| a.path.cmp(&b.path));
    result.dedup_by(|a, b| a.path == b.path);
    result
}

pub fn is_source_path(path: &str) -> bool {
    if path.contains("/node_modules/") || path.contains(".app/") || path.contains("/site-packages/")
    {
        return false;
    }
    Path::new(path)
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| {
            matches!(
                e,
                "rs" | "py"
                    | "ts"
                    | "tsx"
                    | "js"
                    | "jsx"
                    | "go"
                    | "java"
                    | "c"
                    | "cpp"
                    | "h"
                    | "swift"
                    | "cs"
                    | "vue"
                    | "svelte"
            )
        })
}
