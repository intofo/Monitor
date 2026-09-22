use monitor_core::protection::*;
fn policy(mode: ProtectionMode) -> ProtectionPolicy {
    ProtectionPolicy {
        allow_web: false,
        mode,
        project_directories: vec!["/work/project".into()],
        readable_directories: vec!["/opt/runtime".into()],
        model_api_allowlist: vec![],
        network_allowlist: vec![NetworkGrant {
            host: "API.Example.com.".into(),
            port: 443,
            transport: Transport::Tcp,
        }],
    }
}
#[test]
fn modes_do_not_conflate_observation_approval_and_denial() {
    for (mode, outside, unknown_network) in [
        (ProtectionMode::Observe, Verdict::Observe, Verdict::Observe),
        (ProtectionMode::Allowlist, Verdict::Deny, Verdict::Deny),
        (ProtectionMode::Ask, Verdict::Ask, Verdict::Ask),
        (ProtectionMode::Offline, Verdict::Deny, Verdict::Deny),
    ] {
        let engine = ProtectionEngine::new(policy(mode)).unwrap();
        assert_eq!(
            engine.file_read("/Users/alice/.ssh/id_ed25519").verdict,
            outside
        );
        assert_eq!(
            engine
                .network("unknown.example", 443, Transport::Tcp)
                .verdict,
            unknown_network
        );
    }
}
#[test]
fn directory_authorization_uses_components_and_rejects_traversal() {
    let engine = ProtectionEngine::new(policy(ProtectionMode::Allowlist)).unwrap();
    for path in [
        "/work/project/main.rs",
        "/opt/runtime/lib/code.js",
        "/work/project",
    ] {
        assert_eq!(engine.file_read(path).verdict, Verdict::Allow);
    }
    for path in [
        "/work/project-other/code.rs",
        "/work/project/../secret",
        "/work/project/./code.rs",
        "relative/path",
        "/work/project/\0foo",
        "/Users/alice/Library/OtherApp/data",
    ] {
        assert_eq!(engine.file_read(path).verdict, Verdict::Deny, "{path}");
    }
}
#[test]
fn host_port_and_protocol_are_all_required_without_suffix_or_ip_trust() {
    let engine = ProtectionEngine::new(policy(ProtectionMode::Allowlist)).unwrap();
    assert_eq!(
        engine
            .network("api.example.com", 443, Transport::Tcp)
            .verdict,
        Verdict::Allow
    );
    for host in [
        "sub.api.example.com",
        "api.example.com.evil.test",
        "127.0.0.1",
        "::1",
        "192.0.2.1",
    ] {
        assert_eq!(
            engine.network(host, 443, Transport::Tcp).verdict,
            Verdict::Deny
        );
    }
    assert_eq!(
        engine
            .network("api.example.com", 80, Transport::Tcp)
            .verdict,
        Verdict::Deny
    );
    assert_eq!(
        engine
            .network("api.example.com", 443, Transport::Udp)
            .verdict,
        Verdict::Deny
    );
    assert_eq!(
        engine.network("api.example.com", 0, Transport::Tcp).verdict,
        Verdict::Deny
    );
}
#[test]
fn offline_denies_even_explicitly_granted_network() {
    let engine = ProtectionEngine::new(policy(ProtectionMode::Offline)).unwrap();
    assert_eq!(
        engine
            .network("api.example.com", 443, Transport::Tcp)
            .verdict,
        Verdict::Deny
    );
    assert_eq!(
        engine.file_read("/work/project/main.rs").verdict,
        Verdict::Allow
    );
}
#[test]
fn ask_skips_prompts_for_existing_grants_but_never_auto_allows_unknown_targets() {
    let engine = ProtectionEngine::new(policy(ProtectionMode::Ask)).unwrap();
    assert_eq!(
        engine
            .network("api.example.com", 443, Transport::Tcp)
            .verdict,
        Verdict::Allow
    );
    assert_eq!(
        engine.file_read("/work/project/main.rs").verdict,
        Verdict::Allow
    );
    assert_eq!(
        engine.file_read("/other/project/main.rs").verdict,
        Verdict::Ask
    );
    assert_eq!(
        engine
            .network("https://evil.test", 443, Transport::Tcp)
            .verdict,
        Verdict::Deny
    );
}
#[test]
fn invalid_and_excessive_rules_fail_before_engine_creation() {
    for path in ["/", "relative", "/work/../Users", "/work/\0"] {
        let mut p = policy(ProtectionMode::Allowlist);
        p.project_directories = vec![path.into()];
        assert!(ProtectionEngine::new(p).is_err());
    }
    let mut p = policy(ProtectionMode::Ask);
    p.network_allowlist[0].host = "*.example.com".into();
    assert!(p.validate().is_err());
    let mut p = policy(ProtectionMode::Ask);
    p.network_allowlist[0].port = 0;
    assert!(p.validate().is_err());
    let mut p = policy(ProtectionMode::Ask);
    p.project_directories = vec!["/work/project".into(); 129];
    assert!(p.validate().is_err());
}

#[test]
fn offline_only_uses_explicit_model_api_exceptions() {
    let mut policy = policy(ProtectionMode::Offline);
    policy.model_api_allowlist = vec![NetworkGrant {
        host: "model.example".into(),
        port: 443,
        transport: Transport::Tcp,
    }];
    let engine = ProtectionEngine::new(policy).unwrap();
    assert_eq!(
        engine.network("model.example", 443, Transport::Tcp).verdict,
        Verdict::Allow
    );
    assert_eq!(
        engine.network("model.example", 443, Transport::Udp).verdict,
        Verdict::Deny
    );
    assert_eq!(
        engine
            .network("api.example.com", 443, Transport::Tcp)
            .verdict,
        Verdict::Deny
    );
    assert_eq!(
        engine
            .network("model.example.evil.test", 443, Transport::Tcp)
            .verdict,
        Verdict::Deny
    );
}
#[test]
fn ai_review_is_never_an_automatic_allow() {
    let engine = ProtectionEngine::new(policy(ProtectionMode::Ai)).unwrap();
    assert_eq!(engine.file_read("/private/secret").verdict, Verdict::Review);
    assert_eq!(
        engine
            .network("unknown.example", 443, Transport::Tcp)
            .verdict,
        Verdict::Review
    );
    assert_eq!(
        engine.file_read("/work/project/../secret").verdict,
        Verdict::Deny
    );
}

#[test]
fn optional_web_permission_allows_public_web_connections_only() {
    use monitor_core::protection::*;
    let policy = ProtectionPolicy {
        mode: ProtectionMode::Offline,
        allow_web: true,
        ..Default::default()
    };
    let engine = ProtectionEngine::new(policy).unwrap();
    assert_eq!(
        engine.network("1.1.1.1", 443, Transport::Tcp).verdict,
        Verdict::Allow
    );
    for address in [
        "127.0.0.1",
        "10.0.0.1",
        "169.254.169.254",
        "::1",
        "fd00::1",
        "::ffff:127.0.0.1",
        "198.18.0.1",
    ] {
        assert_eq!(
            engine.network(address, 443, Transport::Tcp).verdict,
            Verdict::Deny
        );
    }
    assert_eq!(
        engine.network("1.1.1.1", 443, Transport::Udp).verdict,
        Verdict::Deny
    );
    assert_eq!(
        engine.network("1.1.1.1", 22, Transport::Tcp).verdict,
        Verdict::Deny
    );
}
