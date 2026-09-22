use monitor_core::protection::{ProtectionMode, ProtectionPolicy, Verdict};
use monitor_enforcer::*;
fn snapshot() -> Snapshot {
    Snapshot {
        revision: 7,
        users: vec![UserPolicy {
            uid: 501,
            policy: ProtectionPolicy {
                mode: ProtectionMode::Allowlist,
                project_directories: vec!["/project".into()],
                ..Default::default()
            },
            agents: vec![AgentIdentity {
                dynamic_project: false,
                agent_id: "known:Codex".into(),
                executable: "/Applications/Codex.app/Contents/MacOS/Codex".into(),
                policy: None,
                cdhash: "0101010101010101010101010101010101010101".into(),
            }],
        }],
    }
}
fn process(pid: u32, version: u32) -> ProcessIdentity<'static> {
    ProcessIdentity {
        key: ProcessKey { pid, version },
        uid: 501,
        executable: "/Applications/Codex.app/Contents/MacOS/Codex",
        signature_valid: true,
        cdhash: [1; 20],
    }
}
fn unrelated(pid: u32, version: u32) -> ProcessIdentity<'static> {
    ProcessIdentity {
        executable: "/bin/cat",
        cdhash: [2; 20],
        ..process(pid, version)
    }
}
#[test]
fn unrelated_processes_and_other_users_are_not_enrolled() {
    let mut a = FileAuthorizer::new(snapshot()).unwrap();
    assert!(a.identify(&unrelated(40, 1)).unwrap().is_none());
    let mut other = process(41, 1);
    other.uid = 502;
    assert!(a.identify(&other).unwrap().is_none());
}
#[test]
fn children_inherit_scope_across_exec_and_parent_exit() {
    let mut a = FileAuthorizer::new(snapshot()).unwrap();
    let parent = process(10, 1);
    let child = unrelated(11, 1);
    a.fork(&parent, &child).unwrap();
    let next = unrelated(11, 2);
    a.exec(&child, &next).unwrap();
    a.exit(parent.key);
    let scope = a.identify(&next).unwrap().unwrap();
    assert_eq!(a.agent_id(scope), "known:Codex");
    assert_eq!(
        a.file(
            scope,
            "/Users/alice/Library/OtherApp/database",
            false,
            true,
            1
        ),
        Verdict::Deny
    );
}
#[test]
fn pid_reuse_does_not_inherit_an_old_process_scope() {
    let mut a = FileAuthorizer::new(snapshot()).unwrap();
    a.identify(&process(10, 1)).unwrap();
    assert!(a.identify(&unrelated(10, 2)).unwrap().is_none());
    a.exit(process(10, 1).key);
    assert!(a.identify(&unrelated(10, 1)).unwrap().is_none());
}
#[test]
fn replacement_binary_at_registered_path_is_not_trusted() {
    let mut a = FileAuthorizer::new(snapshot()).unwrap();
    let mut replacement = process(12, 1);
    replacement.cdhash = [2; 20];
    let scope = a.identify(&replacement).unwrap().unwrap();
    assert!(scope.signature_mismatch);
    assert_eq!(
        a.file(scope, "/project/allowed.rs", false, true, 1),
        Verdict::Deny
    );
}
#[test]
fn truncated_paths_and_hard_link_aliases_are_denied() {
    let mut a = FileAuthorizer::new(snapshot()).unwrap();
    let scope = a.identify(&process(12, 1)).unwrap().unwrap();
    assert_eq!(
        a.file(scope, "/project/allowed.rs", false, true, 1),
        Verdict::Allow
    );
    assert_eq!(
        a.file(scope, "/project/allowed.rs", true, true, 1),
        Verdict::Deny
    );
    assert_eq!(
        a.file(scope, "/project/alias", false, true, 2),
        Verdict::Deny
    );
    assert_eq!(a.file(scope, "/project", false, false, 3), Verdict::Allow);
}
#[test]
fn sequence_gap_and_reordering_revoke_coverage() {
    let mut a = FileAuthorizer::new(snapshot()).unwrap();
    assert!(a.sequence(100).is_ok());
    assert!(a.sequence(101).is_ok());
    assert!(a.sequence(103).is_err());
    assert!(a.sequence(102).is_err());
    assert!(a.sequence(100).is_err());
}
#[test]
fn ask_returns_unapproved_not_allowed() {
    let mut snapshot = snapshot();
    snapshot.users[0].policy.mode = ProtectionMode::Ask;
    let mut a = FileAuthorizer::new(snapshot).unwrap();
    let scope = a.identify(&process(12, 1)).unwrap().unwrap();
    assert_eq!(a.file(scope, "/other/file", false, true, 1), Verdict::Ask);
}
#[test]
fn invalid_snapshot_is_rejected() {
    let mut s = snapshot();
    s.users[0].uid = 0;
    assert!(FileAuthorizer::new(s).is_err());
    let mut s = snapshot();
    s.users[0].agents[0].cdhash = "zz".repeat(20);
    assert!(FileAuthorizer::new(s).is_err());
}
#[cfg(unix)]
#[test]
fn policy_loader_rejects_user_writable_parent_and_symlinks() {
    let d = tempfile::tempdir().unwrap();
    let f = d.path().join("policy.json");
    std::fs::write(&f, serde_json::to_vec(&snapshot()).unwrap()).unwrap();
    assert!(monitor_enforcer::snapshot::read(&f).is_err());
    let link = d.path().join("link.json");
    std::os::unix::fs::symlink(&f, &link).unwrap();
    assert!(monitor_enforcer::snapshot::read(&link).is_err());
}

#[test]
fn invalidated_signature_revokes_existing_read_grants() {
    let mut authorizer = FileAuthorizer::new(snapshot()).unwrap();
    let mut identity = process(12, 1);
    let scope = authorizer.identify(&identity).unwrap().unwrap();
    assert_eq!(
        authorizer.file(scope, "/project/file", false, true, 1),
        Verdict::Allow
    );
    identity.signature_valid = false;
    let revoked = authorizer.identify(&identity).unwrap().unwrap();
    assert_eq!(
        authorizer.file(revoked, "/project/file", false, true, 1),
        Verdict::Deny
    );
}

#[test]
fn native_agent_policy_overrides_do_not_leak_between_agents() {
    let mut snapshot = snapshot();
    snapshot.users[0].agents[0].policy = Some(ProtectionPolicy {
        mode: ProtectionMode::Allowlist,
        project_directories: vec!["/first".into()],
        ..Default::default()
    });
    snapshot.users[0].agents.push(AgentIdentity {
        dynamic_project: false,
        agent_id: "other-agent".into(),
        executable: "/bin/cat".into(),
        cdhash: "02".repeat(20),
        policy: Some(ProtectionPolicy {
            mode: ProtectionMode::Allowlist,
            project_directories: vec!["/second".into()],
            ..Default::default()
        }),
    });
    let mut authorizer = FileAuthorizer::new(snapshot).unwrap();
    let first = authorizer.identify(&process(50, 1)).unwrap().unwrap();
    let second = authorizer.identify(&unrelated(51, 1)).unwrap().unwrap();
    assert_eq!(
        authorizer.file(first, "/first/code", false, true, 1),
        Verdict::Allow
    );
    assert_eq!(
        authorizer.file(first, "/second/code", false, true, 1),
        Verdict::Deny
    );
    assert_eq!(
        authorizer.file(second, "/second/code", false, true, 1),
        Verdict::Allow
    );
    assert_eq!(
        authorizer.file(second, "/first/code", false, true, 1),
        Verdict::Deny
    );
}

#[test]
fn dynamic_projects_are_bound_to_each_exec_instance_and_its_children() {
    let mut config = snapshot();
    config.users[0].agents[0].dynamic_project = true;
    let mut engine = FileAuthorizer::new(config).unwrap();
    let a = process(10, 1);
    let b = process(20, 1);
    engine
        .exec_project(&unrelated(10, 0), &a, "/code/a", false)
        .unwrap();
    engine
        .exec_project(&unrelated(20, 0), &b, "/code/b", false)
        .unwrap();
    let sa = engine.identify(&a).unwrap().unwrap();
    let sb = engine.identify(&b).unwrap().unwrap();
    assert_eq!(
        engine.file(sa, "/code/a/main.rs", false, true, 1),
        Verdict::Allow
    );
    assert_eq!(
        engine.file(sa, "/code/b/main.rs", false, true, 1),
        Verdict::Deny
    );
    assert_eq!(
        engine.file(sb, "/code/b/main.rs", false, true, 1),
        Verdict::Allow
    );
    assert_eq!(
        engine.file(sb, "/code/a/main.rs", false, true, 1),
        Verdict::Deny
    );
    let child = unrelated(11, 1);
    engine.fork(&a, &child).unwrap();
    let next = unrelated(11, 2);
    engine
        .exec_project(&child, &next, "/code/b", false)
        .unwrap();
    let sc = engine.identify(&next).unwrap().unwrap();
    assert_eq!(
        engine.file(sc, "/code/b/main.rs", false, true, 1),
        Verdict::Deny
    );
    engine.exit(a.key);
    assert_eq!(
        engine.file(sc, "/code/a/main.rs", false, true, 1),
        Verdict::Allow
    );
    engine.exit(next.key);
    let reused = process(10, 2);
    let scope = engine.identify(&reused).unwrap().unwrap();
    assert_eq!(
        engine.file(scope, "/code/a/main.rs", false, true, 1),
        Verdict::Deny
    );
}
#[test]
fn unknown_or_broad_exec_cwd_does_not_grant_a_project() {
    for (cwd, truncated) in [("/", false), ("/Users/alice", false), ("/code/a", true)] {
        let mut config = snapshot();
        config.users[0].agents[0].dynamic_project = true;
        let mut engine = FileAuthorizer::new(config).unwrap();
        let root = process(10, 1);
        engine
            .exec_project(&unrelated(10, 0), &root, cwd, truncated)
            .unwrap();
        let scope = engine.identify(&root).unwrap().unwrap();
        assert_eq!(
            engine.file(scope, "/project/old", false, true, 1),
            Verdict::Deny
        );
        assert_eq!(
            engine.file(scope, "/code/a/main", false, true, 1),
            Verdict::Deny
        );
    }
}
