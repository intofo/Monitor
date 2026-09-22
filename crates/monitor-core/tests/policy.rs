use monitor_core::{evidence, normalize_host, replay, Action, Replay};
use serde_json::{json, Value};

fn trace(host: &str) -> Value {
    json!({"policy":{"mode":"protect","allowed_hosts":["api.example.com"],"denied_hosts":[]},"events":[
        {"type":"process_start","at_ms":0,"process":"root:1","parent":null,"name":"Agent","protected":true},
        {"type":"connect","at_ms":1,"process":"root:1","host":host,"port":443,"protocol":"tcp","content":"unavailable"}
    ]})
}
fn run(v: Value) -> Vec<monitor_core::Decision> {
    replay(serde_json::from_value::<Replay>(v).unwrap()).unwrap()
}

#[test]
fn unknown_destinations_do_not_require_a_blacklist() {
    let result = run(trace("never-seen.example.net"));
    assert_eq!(result[0].action, Action::WouldBlock);
    assert!(!result[0].enforced);
    assert!(!result[0].content_visible);
}
#[test]
fn exact_host_matching_prevents_suffix_bypass() {
    for host in [
        "api.example.com.evil.test",
        "evilapi.example.com",
        "child.api.example.com",
    ] {
        assert_eq!(run(trace(host))[0].action, Action::WouldBlock);
    }
    assert_eq!(run(trace("API.EXAMPLE.COM."))[0].action, Action::Allow);
}
#[test]
fn deny_overrides_allow() {
    let mut t = trace("api.example.com");
    t["policy"]["denied_hosts"] = json!(["api.example.com"]);
    assert_eq!(run(t)[0].action, Action::WouldBlock);
}
#[test]
fn observation_does_not_claim_enforcement() {
    let mut t = trace("unknown.test");
    t["policy"]["mode"] = json!("observe");
    assert_eq!(run(t)[0].action, Action::Observe);
}
#[test]
fn secret_signal_overrides_authorized_destination() {
    let mut t = trace("api.example.com");
    t["events"][1]["content"] = json!("secret_fingerprint");
    assert_eq!(run(t)[0].action, Action::WouldBlock);
}
#[test]
fn descendants_remain_protected_after_parent_exits() {
    let mut t = trace("new.test");
    t["events"] = json!([
      {"type":"process_start","at_ms":0,"process":"root:1","parent":null,"name":"Agent","protected":true},
      {"type":"process_start","at_ms":1,"process":"child:2","parent":"root:1","name":"curl","protected":false},
      {"type":"process_exit","at_ms":2,"process":"root:1"},
      {"type":"connect","at_ms":3,"process":"child:2","host":"new.test","port":443,"protocol":"udp","content":"unavailable"}
    ]);
    let result = run(t);
    assert_eq!(result[0].action, Action::WouldBlock);
    assert_eq!(result[0].agent.as_deref(), Some("Agent"));
}
#[test]
fn stale_reads_are_not_correlated_and_recent_reads_do_not_prove_upload() {
    let mut t = trace("new.test");
    let events = t["events"].as_array_mut().unwrap();
    events.insert(
        1,
        json!({"type":"file_read","at_ms":1,"process":"root:1","class":"source"}),
    );
    events[2]["at_ms"] = json!(30_002);
    assert!(!run(t.clone())[0]
        .reasons
        .iter()
        .any(|s| s.contains("30 秒")));
    t["events"][2]["at_ms"] = json!(2);
    assert!(run(t)[0].reasons.iter().any(|s| s.contains("不证明上传")));
}
#[test]
fn missing_process_and_out_of_order_events_are_errors() {
    let mut t = trace("new.test");
    t["events"][1]["process"] = json!("unknown:1");
    assert!(replay(serde_json::from_value(t).unwrap()).is_err());
    let mut t = trace("new.test");
    t["events"][0]["at_ms"] = json!(10);
    assert!(replay(serde_json::from_value(t).unwrap()).is_err());
}
#[test]
fn malformed_hosts_are_rejected() {
    for host in [
        "",
        "https://api.example.com",
        "*.example.com",
        "a.test:443",
        "a@b.test",
        "a..b",
        "a.test..",
        "a_test",
        " a.test",
    ] {
        assert!(normalize_host(host).is_err(), "{host}");
    }
    assert_eq!(normalize_host("::1").unwrap(), "::1");
}
#[test]
fn known_endpoints_override_host_allow_but_do_not_blacklist_all_vendor_traffic() {
    let mut t = trace("zcode.z.ai");
    t["policy"]["allowed_hosts"] = json!(["zcode.z.ai"]);
    t["events"][1]["request_path"] = json!("/api/v1/snapshot/upload-credential");
    assert_eq!(run(t.clone())[0].action, Action::WouldBlock);
    t["events"][1]["request_path"] = json!("/api/chat");
    assert_eq!(run(t)[0].action, Action::Allow);
    assert!(
        evidence::endpoint_signal("evil.test", Some("/api/v1/snapshot/upload-credential"))
            .is_none()
    );
}
#[test]
fn trae_evidence_reports_counts_without_leaking_paths() {
    let result = evidence::audit("trae", "[CollectFilesAndRemoteEmbeddingStep] project secret-project total files: 3000, total uploaded files: 3000, total failed files: 0").unwrap();
    assert_eq!(result.len(), 1);
    assert!(result[0].summary.contains("3000"));
    assert!(!result[0].summary.contains("secret-project"));
    assert!(evidence::audit("trae", "total uploaded files: 3000")
        .unwrap()
        .is_empty());
    assert!(evidence::audit("trae","[CollectFilesAndRemoteEmbeddingStep] total files: 0, total uploaded files: 3000, total failed files: 0").is_err());
}
#[test]
fn zcode_failures_and_manifest_are_not_full_upload_proof() {
    let result = evidence::audit(
        "zcode",
        r#"{"lastAcceptedManifestHash":"private-hash","failureCount":152}"#,
    )
    .unwrap();
    assert_eq!(result.len(), 2);
    assert!(result[0].limitation.contains("不能单独证明"));
    assert!(evidence::audit("zcode", r#"{"failureCount":0}"#)
        .unwrap()
        .is_empty());
    assert!(evidence::audit("zcode", "[]").is_err());
}
#[test]
fn fixtures_are_valid() {
    for input in [
        include_str!("../../../fixtures/unknown-egress.json"),
        include_str!("../../../fixtures/known-endpoints.json"),
    ] {
        let results = replay(serde_json::from_str(input).unwrap()).unwrap();
        assert!(results.iter().any(|d| d.action == Action::WouldBlock));
        assert!(results.iter().all(|d| !d.enforced));
    }
}
