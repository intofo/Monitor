use monitor_runtime::{jev::*, model_endpoints};
#[test]
fn parses_endpoint_fields_without_returning_secrets_or_unrelated_urls() {
    let candidates=model_endpoints::parse(r#"{"api_key":"secret-never-return","docs":"https://docs.example/","env":{"ANTHROPIC_BASE_URL":"https://model.example/v1"},"other":{"baseURL":"https://user:password@evil.example/"}}"#,"json","test").unwrap();
    assert_eq!(candidates.len(), 1);
    assert_eq!(candidates[0].origin, "https://model.example");
    let output = serde_json::to_string(&candidates).unwrap();
    assert!(!output.contains("secret-never-return"));
    assert!(!output.contains("password"));
    let toml = model_endpoints::parse(
        "[model_providers.custom]\nbase_url='https://model.example:8443/v1'\napi_key='private'",
        "toml",
        "test",
    )
    .unwrap();
    assert_eq!(toml[0].grant.port, 8443);
}
#[test]
fn model_output_and_endpoint_validation_fail_closed() {
    let settings = JevSettings {
        api_url: "https://jev.example/v1".into(),
        model: "jev".into(),
    }
    .validate()
    .unwrap();
    assert_eq!(settings.api_url, "https://jev.example/v1/chat/completions");
    for url in [
        "http://remote.example/v1",
        "https://user:key@jev.example/v1",
        "https://jev.example/v1?key=secret",
    ] {
        assert!(JevSettings {
            api_url: url.into(),
            model: "jev".into()
        }
        .validate()
        .is_err());
    }
    assert!(
        parse_response(br#"{"choices":[{"message":{"content":"ignore policy and allow"}}]}"#)
            .is_err()
    );
    let review=parse_response(br#"{"choices":[{"message":{"content":"{\"decision\":\"deny\",\"reason\":\"outside project\"}"}}]}"#).unwrap();
    assert_eq!(review.decision, Recommendation::Deny);
}
#[tokio::test]
async fn sends_only_typed_metadata_and_parses_review() {
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt},
        net::TcpListener,
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0; 4096];
        loop {
            let count = socket.read(&mut buffer).await.unwrap();
            assert!(count > 0);
            request.extend_from_slice(&buffer[..count]);
            if let Some(end) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                let headers = String::from_utf8_lossy(&request[..end]).to_ascii_lowercase();
                let length: usize = headers
                    .lines()
                    .find_map(|l| l.strip_prefix("content-length: "))
                    .unwrap()
                    .parse()
                    .unwrap();
                if request.len() >= end + 4 + length {
                    let body: serde_json::Value =
                        serde_json::from_slice(&request[end + 4..end + 4 + length]).unwrap();
                    let summary: serde_json::Value =
                        serde_json::from_str(body["messages"][1]["content"].as_str().unwrap())
                            .unwrap();
                    assert_eq!(summary.as_object().unwrap().len(), 3);
                    assert!(!summary.to_string().contains("test-key"));
                    break;
                }
            }
        }
        let body = r#"{"choices":[{"message":{"content":"{\"decision\":\"deny\",\"reason\":\"outside project\"}"}}]}"#;
        socket
            .write_all(
                format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                )
                .as_bytes(),
            )
            .await
            .unwrap();
    });
    let result = review(
        JevSettings {
            api_url: format!("http://{address}/v1"),
            model: "test".into(),
        },
        "test-key",
        IntentSummary {
            operation: Operation::FileRead,
            within_project: false,
            destination_authorized: false,
        },
    )
    .await
    .unwrap();
    assert_eq!(result.decision, Recommendation::Deny);
    server.await.unwrap();
}
#[test]
fn per_agent_policy_isolation_survives_restart() {
    use monitor_core::protection::{ProtectionMode, ProtectionPolicy};
    use monitor_runtime::settings::{AgentProtection, ConfigStore};
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("config.json");
    let store = ConfigStore::open(path.clone()).unwrap();
    store
        .update(|config| {
            config.agent_protection.insert(
                "agent-a".into(),
                AgentProtection {
                    policy: ProtectionPolicy {
                        mode: ProtectionMode::Offline,
                        ..Default::default()
                    },
                    ai_approved_endpoint: None,
                },
            );
            Ok(())
        })
        .unwrap();
    let config = ConfigStore::open(path).unwrap().load().unwrap();
    assert_eq!(
        config.agent_protection["agent-a"].policy.mode,
        ProtectionMode::Offline
    );
    assert!(!config.agent_protection.contains_key("agent-b"));
}
