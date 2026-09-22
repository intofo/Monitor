//! Rule preparation for future native authorization adapters. The packet capture
//! helper cannot enforce these rules and must never advertise protection readiness.
use monitor_core::protection::ProtectionPolicy;

pub fn prepare_policy(policy: ProtectionPolicy) -> Result<ProtectionPolicy, String> {
    let mut policy = policy.validate()?;
    for directories in [
        &mut policy.project_directories,
        &mut policy.readable_directories,
    ] {
        for directory in directories.iter_mut() {
            let path =
                std::fs::canonicalize(&*directory).map_err(|e| format!("{directory}: {e}"))?;
            if !path.is_dir() {
                return Err(format!("Not a directory: {directory}"));
            }
            *directory = path
                .to_str()
                .ok_or("Directory path is not valid UTF-8")?
                .to_owned();
        }
    }
    policy.validate()
}

/// Current launch context is discovery evidence, not an authenticated ES identity.
/// Missing/ambiguous GUI contexts never widen the allowed project scope.
pub fn discover_projects(processes: &[crate::discovery::AgentProcess]) -> Vec<String> {
    use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System, UpdateKind};
    let ids: Vec<_> = processes
        .iter()
        .filter(|p| !p.inherited)
        .map(|p| Pid::from_u32(p.pid))
        .collect();
    if ids.is_empty() {
        return vec![];
    }
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&ids),
        true,
        ProcessRefreshKind::nothing()
            .with_cwd(UpdateKind::Always)
            .with_exe(UpdateKind::Always)
            .without_tasks(),
    );
    let home = dirs::home_dir().and_then(|p| p.canonicalize().ok());
    let mut roots = Vec::new();
    for expected in processes.iter().filter(|p| !p.inherited) {
        let Some(process) = system.process(Pid::from_u32(expected.pid)) else {
            continue;
        };
        if process.start_time() != expected.start_time
            || process
                .exe()
                .map(|p| p.to_string_lossy().as_ref() == expected.executable)
                != Some(true)
        {
            continue;
        }
        let Some(cwd) = process.cwd() else { continue };
        // Read the live cwd on every sample; launch arguments can become stale.
        let candidate = cwd;
        let Ok(path) = candidate.canonicalize() else {
            continue;
        };
        if !path.is_dir()
            || path.parent().is_none()
            || home.as_ref() == Some(&path)
            || path.starts_with("/Applications")
            || path.starts_with("/System")
        {
            continue;
        }
        let path = path.to_string_lossy().into_owned();
        if !roots.contains(&path) && roots.len() < 128 {
            roots.push(path);
        }
    }
    roots.sort();
    roots
}

#[cfg(all(test, unix))]
mod context_tests {
    use super::*;
    use crate::discovery::AgentProcess;
    #[test]
    fn project_changes_replace_old_context_and_exit_removes_it() {
        use std::io::{BufRead, Write};
        let first = tempfile::tempdir().unwrap();
        let second = tempfile::tempdir().unwrap();
        let mut child = std::process::Command::new("/bin/sh")
            .current_dir(first.path())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        let mut input = child.stdin.take().unwrap();
        let mut output = std::io::BufReader::new(child.stdout.take().unwrap());
        writeln!(input, "pwd").unwrap();
        input.flush().unwrap();
        let mut line = String::new();
        output.read_line(&mut line).unwrap();
        let pid = sysinfo::Pid::from_u32(child.id());
        let mut system = sysinfo::System::new();
        system.refresh_processes_specifics(
            sysinfo::ProcessesToUpdate::Some(&[pid]),
            true,
            sysinfo::ProcessRefreshKind::nothing().with_exe(sysinfo::UpdateKind::Always),
        );
        let process = system.process(pid).unwrap();
        let agent = AgentProcess {
            pid: child.id(),
            start_time: process.start_time(),
            parent: None,
            name: "test".into(),
            executable: process.exe().unwrap().to_string_lossy().into_owned(),
            agent: "test".into(),
            agent_id: "custom:test".into(),
            inherited: false,
        };
        let before = discover_projects(std::slice::from_ref(&agent));
        let quoted = second.path().to_string_lossy().replace('\'', "'\"'\"'");
        writeln!(input, "cd '{quoted}' && pwd").unwrap();
        input.flush().unwrap();
        line.clear();
        output.read_line(&mut line).unwrap();
        let after = discover_projects(std::slice::from_ref(&agent));
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(
            before,
            vec![first
                .path()
                .canonicalize()
                .unwrap()
                .to_string_lossy()
                .into_owned()]
        );
        assert_eq!(
            after,
            vec![second
                .path()
                .canonicalize()
                .unwrap()
                .to_string_lossy()
                .into_owned()]
        );
        assert!(discover_projects(&[agent]).is_empty());
    }
    #[test]
    fn project_context_is_not_persisted() {
        use crate::settings::{AgentProtection, ConfigStore};
        let temp = tempfile::tempdir().unwrap();
        let file = temp.path().join("config.json");
        let store = ConfigStore::open(file.clone()).unwrap();
        store
            .update(|config| {
                let mut entry = AgentProtection::default();
                entry.policy.project_directories = vec!["/old/project".into()];
                config.agent_protection.insert("test".into(), entry);
                Ok(())
            })
            .unwrap();
        assert!(ConfigStore::open(file.clone())
            .unwrap()
            .load()
            .unwrap()
            .agent_protection["test"]
            .policy
            .project_directories
            .is_empty());
        // Also migrate rules saved by older versions.
        let mut legacy = store.load().unwrap();
        legacy
            .agent_protection
            .get_mut("test")
            .unwrap()
            .policy
            .project_directories = vec!["/old/project".into()];
        std::fs::write(&file, serde_json::to_vec(&legacy).unwrap()).unwrap();
        assert!(ConfigStore::open(file.clone())
            .unwrap()
            .load()
            .unwrap()
            .agent_protection["test"]
            .policy
            .project_directories
            .is_empty());
        assert!(!std::fs::read_to_string(file)
            .unwrap()
            .contains("/old/project"));
    }
    #[test]
    fn projects_follow_live_root_identity_and_ignore_children() {
        let directory = tempfile::tempdir().unwrap();
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("30")
            .current_dir(directory.path())
            .spawn()
            .unwrap();
        let pid = sysinfo::Pid::from_u32(child.id());
        let mut system = sysinfo::System::new();
        system.refresh_processes_specifics(
            sysinfo::ProcessesToUpdate::Some(&[pid]),
            true,
            sysinfo::ProcessRefreshKind::nothing().with_exe(sysinfo::UpdateKind::Always),
        );
        let process = system.process(pid).unwrap();
        let mut agent = AgentProcess {
            pid: child.id(),
            start_time: process.start_time(),
            parent: None,
            name: "test".into(),
            executable: process.exe().unwrap().to_string_lossy().into_owned(),
            agent: "test".into(),
            agent_id: "custom:test".into(),
            inherited: false,
        };
        let actual = discover_projects(&[agent.clone()]);
        agent.inherited = true;
        let inherited = discover_projects(&[agent.clone()]);
        agent.inherited = false;
        agent.start_time += 1;
        let reused = discover_projects(&[agent]);
        let _ = child.kill();
        let _ = child.wait();
        assert_eq!(
            actual,
            vec![directory
                .path()
                .canonicalize()
                .unwrap()
                .to_string_lossy()
                .into_owned()]
        );
        assert!(inherited.is_empty());
        assert!(reused.is_empty());
    }
}
