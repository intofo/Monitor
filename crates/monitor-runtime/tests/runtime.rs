use monitor_runtime::{
    audit::Audit,
    discovery::{identify, AgentProcess},
    scan::{self, Source},
    sensor::parse_lsof,
};
#[cfg(unix)]
use std::{sync::Arc, time::Duration};
#[cfg(target_os = "macos")]
use tokio::net::{TcpListener, TcpStream};
#[cfg(unix)]
use tokio::time::timeout;

#[test]
fn scans_only_scoped_evidence_and_reports_pending_without_reading_it() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    std::fs::create_dir_all(root.join("workspace/pending")).unwrap();
    std::fs::write(
        root.join("workspace/state.json"),
        r#"{"lastAcceptedManifestHash":"PRIVATE-HASH","failureCount":3}"#,
    )
    .unwrap();
    std::fs::write(root.join("workspace/pending/archive.enc"), b"CIPHERTEXT").unwrap();
    std::fs::write(
        root.join("provider_config.json"),
        b"DO NOT READ THIS API KEY",
    )
    .unwrap();
    let report = scan::scan(&[Source {
        kind: "zcode".into(),
        root: root.into(),
    }]);
    let s = &report.sources[0];
    assert_eq!(s.files_read, 1);
    assert_eq!(s.pending_files, 1);
    assert_eq!(s.findings.len(), 2);
    let json = serde_json::to_string(&report).unwrap();
    assert!(!json.contains("PRIVATE-HASH"));
    assert!(!json.contains("API KEY"));
}
#[test]
fn absent_and_invalid_evidence_are_not_reported_as_clean() {
    let dir = tempfile::tempdir().unwrap();
    let s = Source {
        kind: "zcode".into(),
        root: dir.path().join("absent"),
    };
    assert_eq!(scan::scan(&[s]).sources[0].status, "not_found");
    std::fs::write(dir.path().join("state.json"), b"{incomplete").unwrap();
    assert_eq!(
        scan::scan(&[Source {
            kind: "zcode".into(),
            root: dir.path().into()
        }])
        .sources[0]
            .status,
        "partial"
    );
}
#[cfg(unix)]
#[test]
fn evidence_scan_does_not_follow_symlinks() {
    let root = tempfile::tempdir().unwrap();
    let outside = tempfile::tempdir().unwrap();
    std::fs::write(outside.path().join("state.json"), r#"{"failureCount":1}"#).unwrap();
    std::os::unix::fs::symlink(outside.path(), root.path().join("linked")).unwrap();
    let report = scan::scan(&[Source {
        kind: "zcode".into(),
        root: root.path().into(),
    }]);
    assert_eq!(report.sources[0].files_read, 0);
    assert_eq!(report.sources[0].status, "partial");
}
#[test]
fn discovery_uses_boundaries_and_activity_is_not_upload_proof() {
    assert_eq!(identify("Trae CN.exe", ""), Some("Trae CN"));
    assert_eq!(
        identify("node", "/a/@openai/codex/bin/codex.js"),
        Some("Codex")
    );
    assert_eq!(identify("not-codex", "/not-codex/bin"), None);
    let processes = vec![AgentProcess {
        pid: 42,
        start_time: 1,
        parent: None,
        name: "test".into(),
        executable: "/test".into(),
        agent: "Test".into(),
        agent_id: "known:Test".into(),
        inherited: false,
    }];
    let activities=parse_lsof("p42\nf1\ntREG\nn/project/main.rs\nf2\ntIPv4\nn127.0.0.1:1->203.0.113.2:443\np99\nf3\ntIPv4\nn127.0.0.1:1->203.0.113.3:443\n",&processes);
    assert_eq!(activities.len(), 2);
    assert!(activities[1].assessment.contains("不证明"));
}
#[test]
fn audit_filter_keeps_observation_out_of_block_log() {
    let a = Audit::memory().unwrap();
    a.append("connection", "agent", "host", "observation", false)
        .unwrap();
    a.append("blocked", "proxy", "host", "denied", true)
        .unwrap();
    assert_eq!(a.recent(false).unwrap().len(), 2);
    assert_eq!(a.recent(true).unwrap().len(), 1);
}
#[cfg(target_os = "macos")]
#[tokio::test]
async fn native_sensor_observes_a_real_local_connection() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let _client = TcpStream::connect(addr).await.unwrap();
    let _server = listener.accept().await.unwrap();
    let p = AgentProcess {
        pid: std::process::id(),
        start_time: 0,
        parent: None,
        name: "test".into(),
        executable: "test".into(),
        agent: "Test fixture".into(),
        agent_id: "known:Test fixture".into(),
        inherited: false,
    };
    let (activities, warnings) = monitor_runtime::sensor::collect(&[p]).await;
    assert!(
        activities
            .iter()
            .any(|a| a.kind == "connection" && a.target.ends_with(&addr.port().to_string())),
        "warnings: {warnings:?}; activities: {activities:?}"
    );
}

#[test]
fn audit_export_includes_retained_records_and_never_overwrites() {
    let audit = Audit::memory().unwrap();
    for i in 0..205 {
        audit
            .append(
                "connection",
                "Agent",
                &format!("example-{i}.test"),
                "observed",
                false,
            )
            .unwrap();
    }
    audit
        .append("blocked", "proxy", "blocked.test:443", "no upstream", true)
        .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let all = dir.path().join("all.json");
    let blocked = dir.path().join("blocked.json");
    assert_eq!(audit.recent(false).unwrap().len(), 200);
    assert_eq!(audit.export_to(&all, false).unwrap(), 206);
    assert_eq!(audit.export_to(&blocked, true).unwrap(), 1);
    let data: serde_json::Value = serde_json::from_slice(&std::fs::read(&all).unwrap()).unwrap();
    assert_eq!(data["events"].as_array().unwrap().len(), 206);
    let filtered: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&blocked).unwrap()).unwrap();
    assert_eq!(filtered["scope"], "enforced_blocks");
    assert_eq!(filtered["events"][0]["enforced"], true);
    let before = std::fs::read(&all).unwrap();
    assert!(audit.export_to(&all, true).is_err());
    assert_eq!(std::fs::read(&all).unwrap(), before);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(&all).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn generic_sampling_does_not_starve_unknown_processes() {
    use monitor_runtime::sensor::sampling_batch;
    let processes: Vec<_> = (1..=600)
        .map(|pid| AgentProcess {
            pid,
            start_time: 1,
            parent: None,
            name: format!("custom-{pid}"),
            executable: format!("/custom/{pid}"),
            agent: "未分类程序".into(),
            agent_id: "unclassified".into(),
            inherited: false,
        })
        .collect();
    let mut cursor = 0;
    let mut seen = std::collections::HashSet::new();
    for _ in 0..3 {
        let batch = sampling_batch(&processes, &mut cursor, 256);
        assert_eq!(batch.len(), 256);
        seen.extend(batch.iter().map(|p| p.pid));
    }
    assert_eq!(seen.len(), 600);
    assert!(sampling_batch(&[], &mut cursor, 256).is_empty());
    assert_eq!(sampling_batch(&processes[..2], &mut cursor, 256).len(), 2);
    let activity = parse_lsof(
        "p600\nf1\ntREG\nn/project/main.rs\nf2\ntIPv4\nn127.0.0.1:1->203.0.113.2:443\n",
        &processes,
    );
    assert_eq!(activity.len(), 2);
    assert!(activity.iter().all(|a| a.agent == "未分类程序"));
}

#[cfg(unix)]
#[test]
fn discovery_includes_unrecognized_live_program() {
    let mut child = std::process::Command::new("/bin/sleep")
        .arg("10")
        .spawn()
        .unwrap();
    let mut discovery = monitor_runtime::discovery::Discovery::default();
    let processes = discovery.refresh();
    let found = processes.iter().find(|p| p.pid == child.id());
    let _ = child.kill();
    let _ = child.wait();
    let found = found.expect("unrecognized process must be inventoried");
    assert_eq!(found.agent, "未分类程序");
    assert!(!found.inherited);
}

#[test]
fn monitoring_preferences_survive_restart_and_failed_save() {
    use monitor_runtime::settings::ConfigStore;
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    let store = ConfigStore::open(path.clone()).unwrap();
    assert!(store.load().unwrap().enabled("known:Codex"));
    assert!(!store.load().unwrap().packet_capture_enabled);
    assert!(!store.load().unwrap().close_to_tray);
    assert!(!store.load().unwrap().enabled("unclassified"));
    store
        .update(|c| {
            c.enabled.insert("known:Codex".into(), false);
            c.packet_capture_enabled = true;
            c.close_to_tray = true;
            Ok(())
        })
        .unwrap();
    assert!(!ConfigStore::open(path.clone())
        .unwrap()
        .load()
        .unwrap()
        .enabled("known:Codex"));
    assert!(
        ConfigStore::open(path.clone())
            .unwrap()
            .load()
            .unwrap()
            .packet_capture_enabled
    );
    assert!(
        ConfigStore::open(path.clone())
            .unwrap()
            .load()
            .unwrap()
            .close_to_tray
    );
    std::fs::remove_file(&path).unwrap();
    std::fs::create_dir(&path).unwrap();
    assert!(store
        .update(|c| {
            c.enabled.insert("known:Codex".into(), true);
            Ok(())
        })
        .is_err());
    assert!(!store.load().unwrap().enabled("known:Codex"));
    assert_eq!(store.load().unwrap().revision, 1);
}

#[test]
fn invalid_monitoring_config_is_not_silently_overwritten() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    std::fs::write(&path, "{broken").unwrap();
    assert!(monitor_runtime::settings::ConfigStore::open(path.clone()).is_err());
    assert_eq!(std::fs::read_to_string(path).unwrap(), "{broken");
}

#[test]
fn agent_catalog_merges_installed_and_running_and_preserves_disabled_entries() {
    use monitor_runtime::{
        catalog,
        discovery::Installation,
        settings::{CustomAgent, MonitorConfig},
    };
    let mut cfg = MonitorConfig::default();
    cfg.enabled.insert("known:Codex".into(), false);
    cfg.custom_agents.push(CustomAgent {
        id: "custom:test".into(),
        name: "Private Agent".into(),
        executable: "/missing/private-agent".into(),
    });
    let processes = vec![AgentProcess {
        pid: 42,
        start_time: 1,
        parent: None,
        name: "codex".into(),
        executable: "/usr/bin/codex".into(),
        agent: "Codex".into(),
        agent_id: "known:Codex".into(),
        inherited: false,
    }];
    let installs = vec![Installation {
        agent: "Codex".into(),
        path: "/usr/bin/codex".into(),
        basis: "name".into(),
    }];
    let entries = catalog::build(&processes, &installs, &cfg);
    let codex = entries.iter().find(|e| e.id == "known:Codex").unwrap();
    assert!(codex.installed);
    assert!(!codex.enabled);
    assert_eq!(codex.running, 1);
    assert_eq!(codex.paths.len(), 1);
    assert_eq!(
        entries
            .iter()
            .find(|e| e.id == "custom:test")
            .unwrap()
            .running,
        0
    );
}

#[test]
fn legacy_migration_includes_wal_and_never_overwrites_destination() {
    let dir = tempfile::tempdir().unwrap();
    let old = dir.path().join("old.sqlite3");
    let destination = dir.path().join(".monitor/audit.sqlite3");
    let db = rusqlite::Connection::open(&old).unwrap();
    db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0; CREATE TABLE events(id INTEGER PRIMARY KEY,at_ms INTEGER,category TEXT,actor TEXT,target TEXT,detail TEXT,enforced INTEGER); INSERT INTO events VALUES(1,1,'blocked','legacy','example:443','old block',1); CREATE TABLE settings(key TEXT PRIMARY KEY,value TEXT); INSERT INTO settings VALUES('proxy_config','{\"allowed\":[],\"denied_hosts\":[\"blocked.example\"],\"allow_private_targets\":false}');").unwrap();
    monitor_runtime::settings::migrate_legacy(&old, &destination).unwrap();
    let audit = Audit::open(&destination).unwrap();
    assert_eq!(audit.recent(true).unwrap().len(), 1);
    assert!(audit.recent(true).unwrap()[0].agent_id.is_none());
    // Migration retains legacy settings without exposing the removed proxy API.
    let migrated = rusqlite::Connection::open(&destination).unwrap();
    let retained: String = migrated
        .query_row(
            "SELECT value FROM settings WHERE key='proxy_config'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert!(retained.contains("blocked.example"));
    db.execute_batch("INSERT INTO events VALUES(2,2,'blocked','legacy','example:443','later',1)")
        .unwrap();
    monitor_runtime::settings::migrate_legacy(&old, &destination).unwrap();
    assert_eq!(audit.recent(true).unwrap().len(), 1);
    assert!(old.exists());
    assert!(destination.with_file_name("config.json").exists());
}

#[test]
fn agent_log_filter_runs_before_limit_and_export_keeps_scope() {
    use monitor_runtime::audit::{EventScope, NewEvent};
    let audit = Audit::memory().unwrap();
    let scope = EventScope {
        agent_id: "custom:a".into(),
        agent_name: "Agent A".into(),
        attribution: "process_observation".into(),
    };
    audit
        .append_for(
            &scope,
            NewEvent {
                category: "connection",
                actor: "A",
                target: "a.example",
                detail: "observation",
                enforced: false,
            },
        )
        .unwrap();
    for _ in 0..205 {
        audit
            .append("blocked", "unassigned", "b.example", "denied", true)
            .unwrap();
    }
    assert_eq!(
        audit
            .recent_filtered(false, Some("custom:a"))
            .unwrap()
            .len(),
        1
    );
    assert!(audit
        .recent_filtered(true, Some("custom:a"))
        .unwrap()
        .is_empty());
    assert_eq!(audit.recent_filtered(true, Some("")).unwrap().len(), 200);
    assert_eq!(audit.agent_groups().unwrap()[0].agent_id, "custom:a");
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("agent.json");
    assert_eq!(
        audit
            .export_filtered(&path, false, Some("custom:a"))
            .unwrap(),
        1
    );
    let json: serde_json::Value = serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap();
    assert_eq!(json["agent_id"], "custom:a");
    assert_eq!(json["events"][0]["agent_name"], "Agent A");
}

#[cfg(unix)]
#[test]
fn custom_agent_path_is_discovered_without_known_brand() {
    use monitor_runtime::{
        discovery::Discovery,
        settings::{CustomAgent, MonitorConfig},
    };
    let mut child = std::process::Command::new("/bin/sleep")
        .arg("10")
        .spawn()
        .unwrap();
    let mut discovery = Discovery::default();
    let processes = discovery.refresh();
    let path = processes
        .iter()
        .find(|p| p.pid == child.id())
        .unwrap()
        .executable
        .clone();
    let mut config = MonitorConfig::default();
    config.custom_agents.push(CustomAgent {
        id: "custom:sleeper".into(),
        name: "Private Agent".into(),
        executable: path,
    });
    let processes = discovery.refresh_config(&config);
    let found = processes.iter().find(|p| p.pid == child.id()).unwrap();
    let _ = child.kill();
    let _ = child.wait();
    assert_eq!(found.agent_id, "custom:sleeper");
    assert_eq!(found.agent, "Private Agent");
}

#[cfg(unix)]
#[tokio::test]
async fn monitoring_switch_keeps_live_data_out_of_storage() {
    use monitor_runtime::{
        discovery::Discovery,
        sensor::{self, SensorSnapshot},
        settings::CustomAgent,
    };
    let mut child = tokio::process::Command::new("/bin/sleep")
        .arg("30")
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let pid = child.id().unwrap();
    let path = Discovery::default()
        .refresh()
        .into_iter()
        .find(|p| p.pid == pid)
        .unwrap()
        .executable;
    let directory = tempfile::tempdir().unwrap();
    let database = directory.path().join("audit.sqlite3");
    let audit = Arc::new(Audit::open(&database).unwrap());
    audit
        .append(
            "blocked",
            "test",
            "example.test:443",
            "blocked fixture",
            true,
        )
        .unwrap();
    audit
        .preferences
        .update(|c| {
            c.custom_agents.push(CustomAgent {
                id: "custom:toggle".into(),
                name: "Toggle Agent".into(),
                executable: path,
            });
            c.enabled.insert("custom:toggle".into(), false);
            Ok(())
        })
        .unwrap();
    let state = Arc::new(std::sync::Mutex::new(SensorSnapshot::default()));
    let task = tokio::spawn(sensor::run(state.clone(), audit.clone()));
    async fn await_revision(state: &sensor::SensorState, revision: u64) {
        timeout(Duration::from_secs(8), async {
            loop {
                if state.lock().unwrap().running
                    && state.lock().unwrap().config_revision >= revision
                {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
    }
    await_revision(&state, 1).await;
    assert!(state.lock().unwrap().processes.iter().any(|p| p.pid == pid));
    assert!(audit
        .recent_filtered(false, Some("custom:toggle"))
        .unwrap()
        .is_empty());
    audit
        .preferences
        .update(|c| {
            c.enabled.insert("custom:toggle".into(), true);
            Ok(())
        })
        .unwrap();
    await_revision(&state, 2).await;
    let before = audit
        .recent_filtered(false, Some("custom:toggle"))
        .unwrap()
        .len();
    assert_eq!(before, 0);
    assert!(state
        .lock()
        .unwrap()
        .agents
        .iter()
        .any(|a| a.id == "custom:toggle" && a.enabled));
    audit
        .preferences
        .update(|c| {
            c.enabled.insert("custom:toggle".into(), false);
            Ok(())
        })
        .unwrap();
    await_revision(&state, 3).await;
    assert!(state
        .lock()
        .unwrap()
        .activities
        .iter()
        .all(|a| a.agent_id != "custom:toggle"));
    assert_eq!(
        audit
            .recent_filtered(false, Some("custom:toggle"))
            .unwrap()
            .len(),
        before
    );
    task.abort();
    let _ = task.await;
    drop(audit);
    let reopened = Audit::open(&database).unwrap();
    let retained = reopened.recent(false).unwrap();
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].category, "blocked");
    assert!(retained[0].enforced);
    let _ = child.kill().await;
    let _ = child.wait().await;
}

#[test]
fn protection_rules_persist_without_creating_block_events() {
    use monitor_core::protection::{ProtectionMode, ProtectionPolicy};
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("audit.sqlite3");
    let audit = Audit::open(&db).unwrap();
    let policy = monitor_runtime::protection::prepare_policy(ProtectionPolicy {
        mode: ProtectionMode::Allowlist,
        project_directories: vec![dir.path().to_str().unwrap().into()],
        ..Default::default()
    })
    .unwrap();
    audit
        .preferences
        .update(|config| {
            config.protection = policy.clone();
            Ok(())
        })
        .unwrap();
    drop(audit);
    let reopened = Audit::open(&db).unwrap();
    assert_eq!(reopened.preferences.load().unwrap().protection, policy);
    assert!(reopened.recent_filtered(true, None).unwrap().is_empty());
    assert!(reopened
        .preferences
        .update(|config| {
            config.protection.project_directories = vec!["/".into()];
            Ok(())
        })
        .is_err());
    assert_eq!(reopened.preferences.load().unwrap().protection, policy);
}

#[cfg(unix)]
#[test]
fn protection_directory_grants_resolve_symlinks_and_reject_files() {
    use monitor_core::protection::{ProtectionMode, ProtectionPolicy};
    let dir = tempfile::tempdir().unwrap();
    let project = dir.path().join("project");
    std::fs::create_dir(&project).unwrap();
    let link = dir.path().join("link");
    std::os::unix::fs::symlink(&project, &link).unwrap();
    let mut policy = ProtectionPolicy {
        mode: ProtectionMode::Allowlist,
        project_directories: vec![link.to_str().unwrap().into()],
        ..Default::default()
    };
    let prepared = monitor_runtime::protection::prepare_policy(policy.clone()).unwrap();
    assert_eq!(
        prepared.project_directories,
        vec![project.canonicalize().unwrap().to_str().unwrap()]
    );
    let file = dir.path().join("file");
    std::fs::write(&file, "test").unwrap();
    policy.project_directories = vec![file.to_str().unwrap().into()];
    assert!(monitor_runtime::protection::prepare_policy(policy).is_err());
}
