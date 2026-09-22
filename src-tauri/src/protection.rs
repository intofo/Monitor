use crate::RuntimeState;
use monitor_core::protection::{ProtectionMode, ProtectionPolicy};
use monitor_runtime::{
    model_endpoints::{Candidate, Discovery},
    settings::AgentProtection,
};
use std::{
    collections::HashMap,
    sync::Mutex,
    time::{Duration, Instant},
};
#[derive(Default)]
pub struct Approvals(Mutex<HashMap<String, Pending>>);
struct Pending {
    agent: String,
    revision: u64,
    expires: Instant,
    candidates: Vec<Candidate>,
}
impl Approvals {
    fn consume(
        &self,
        token: &str,
        agent: &str,
        revision: u64,
        origins: &[String],
    ) -> Result<Vec<monitor_core::protection::NetworkGrant>, String> {
        let pending = self
            .0
            .lock()
            .map_err(|_| "Approval store unavailable")?
            .remove(token)
            .ok_or("Approval expired; discover model APIs again")?;
        if pending.agent != agent
            || pending.revision != revision
            || pending.expires <= Instant::now()
        {
            return Err("Agent or configuration changed; approve again".into());
        }
        if origins.len() > 128
            || origins.iter().any(|origin| {
                !pending
                    .candidates
                    .iter()
                    .any(|candidate| &candidate.origin == origin)
            })
        {
            return Err("Unapproved model API target".into());
        }
        let mut grants = Vec::new();
        for candidate in pending.candidates {
            if origins.contains(&candidate.origin) && !grants.contains(&candidate.grant) {
                grants.push(candidate.grant);
            }
        }
        Ok(grants)
    }
}
#[derive(serde::Serialize)]
pub struct Settings {
    policy: ProtectionPolicy,
    enforcement_available: bool,
    ai_approved: bool,
}
fn known(state: &RuntimeState, id: &str) -> Result<(), String> {
    if id == "unclassified"
        || !state
            .sensor
            .lock()
            .map_err(|_| "Sensor unavailable")?
            .agents
            .iter()
            .any(|agent| agent.id == id)
    {
        return Err("Unknown Agent".into());
    }
    Ok(())
}
// Derive roots only from this Agent's live root processes, never from a UI path
// or an inherited tool that might have changed into an unrelated directory.
fn project_directories(state: &RuntimeState, id: &str) -> Result<Vec<String>, String> {
    let processes = state
        .sensor
        .lock()
        .map_err(|_| "Sensor unavailable")?
        .processes
        .iter()
        .filter(|p| p.agent_id == id && !p.inherited)
        .cloned()
        .collect::<Vec<_>>();
    Ok(monitor_runtime::protection::discover_projects(&processes))
}
#[tauri::command]
pub fn protection_settings(
    agent_id: String,
    state: tauri::State<'_, RuntimeState>,
) -> Result<Settings, String> {
    known(&state, &agent_id)?;
    let config = state.audit.preferences.load()?;
    let mut value = config
        .agent_protection
        .get(&agent_id)
        .cloned()
        .unwrap_or_default();
    value.policy.project_directories = project_directories(&state, &agent_id)?;
    Ok(Settings {
        policy: value.policy,
        enforcement_available: false,
        ai_approved: !config.jev.api_url.is_empty()
            && value.ai_approved_endpoint.as_deref() == Some(config.jev.api_url.as_str()),
    })
}
#[derive(serde::Serialize)]
pub struct DiscoveryReply {
    token: String,
    discovery: Discovery,
}
#[tauri::command]
pub async fn discover_model_apis(
    agent_id: String,
    mut policy: ProtectionPolicy,
    state: tauri::State<'_, RuntimeState>,
) -> Result<DiscoveryReply, String> {
    known(&state, &agent_id)?;
    policy.project_directories = project_directories(&state, &agent_id)?;
    let revision = state.audit.preferences.load()?.revision;
    let id = agent_id.clone();
    let discovery = tauri::async_runtime::spawn_blocking(move || {
        let policy = monitor_runtime::protection::prepare_policy(policy)?;
        let home = monitor_runtime::settings::home_root()?
            .parent()
            .ok_or("Home unavailable")?
            .to_path_buf();
        let paths =
            monitor_runtime::model_endpoints::paths(&home, &id, &policy.project_directories);
        Ok::<_, String>(monitor_runtime::model_endpoints::discover(&paths))
    })
    .await
    .map_err(|e| e.to_string())??;
    let token = uuid::Uuid::new_v4().to_string();
    let mut pending = state
        .model_approvals
        .0
        .lock()
        .map_err(|_| "Approval store unavailable")?;
    pending.retain(|_, value| value.expires > Instant::now());
    if pending.len() >= 32 {
        return Err("Too many pending approvals".into());
    }
    pending.insert(
        token.clone(),
        Pending {
            agent: agent_id,
            revision,
            expires: Instant::now() + Duration::from_secs(300),
            candidates: discovery.candidates.clone(),
        },
    );
    Ok(DiscoveryReply { token, discovery })
}
#[tauri::command]
pub async fn save_protection_settings(
    agent_id: String,
    mut policy: ProtectionPolicy,
    approval_token: Option<String>,
    approved_origins: Vec<String>,
    ai_approved: bool,
    approved_ai_endpoint: Option<String>,
    state: tauri::State<'_, RuntimeState>,
) -> Result<Settings, String> {
    known(&state, &agent_id)?;
    policy.project_directories = project_directories(&state, &agent_id)?;
    let mut policy = tauri::async_runtime::spawn_blocking(move || {
        monitor_runtime::protection::prepare_policy(policy)
    })
    .await
    .map_err(|e| e.to_string())??;
    let config = state.audit.preferences.load()?;
    let revision = config.revision;
    policy.model_api_allowlist.clear();
    if policy.mode == ProtectionMode::Offline {
        let token = approval_token.ok_or("Model API exceptions require user approval")?;
        policy.model_api_allowlist =
            state
                .model_approvals
                .consume(&token, &agent_id, revision, &approved_origins)?;
        policy.network_allowlist.clear();
    }
    let ai_endpoint = if policy.mode == ProtectionMode::Ai {
        if !ai_approved {
            return Err("AI review requires explicit consent".into());
        }
        let settings = config.jev.validate()?;
        if approved_ai_endpoint.as_deref() != Some(settings.api_url.as_str()) {
            return Err("Jev endpoint changed; approve again".into());
        }
        let endpoint = settings.api_url.clone();
        if !tauri::async_runtime::spawn_blocking(move || crate::jev::has_key(&endpoint))
            .await
            .map_err(|e| e.to_string())??
        {
            return Err("Configure a Jev API key first".into());
        }
        Some(settings.api_url)
    } else {
        None
    };
    state.audit.preferences.update(|config| {
        if config.revision != revision {
            return Err("Configuration changed; approve and save again".into());
        }
        config.agent_protection.insert(
            agent_id.clone(),
            AgentProtection {
                policy,
                ai_approved_endpoint: ai_endpoint,
            },
        );
        Ok(())
    })?;
    protection_settings(agent_id, state)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn approval() -> Approvals {
        let store = Approvals::default();
        store.0.lock().unwrap().insert(
            "test-token".into(),
            Pending {
                agent: "agent-a".into(),
                revision: 7,
                expires: Instant::now() + Duration::from_secs(60),
                candidates: monitor_runtime::model_endpoints::parse(
                    r#"{"base_url":"https://model.example/v1"}"#,
                    "json",
                    "test",
                )
                .unwrap(),
            },
        );
        store
    }
    #[test]
    fn approval_is_agent_bound_version_bound_and_single_use() {
        let target = vec!["https://model.example".into()];
        assert!(approval()
            .consume("test-token", "agent-b", 7, &target)
            .is_err());
        assert!(approval()
            .consume("test-token", "agent-a", 8, &target)
            .is_err());
        let store = approval();
        assert_eq!(
            store
                .consume("test-token", "agent-a", 7, &target)
                .unwrap()
                .len(),
            1
        );
        assert!(store.consume("test-token", "agent-a", 7, &target).is_err());
    }
    #[test]
    fn approval_cannot_expand_or_outlive_the_presented_candidates() {
        assert!(approval()
            .consume("test-token", "agent-a", 7, &["https://evil.example".into()])
            .is_err());
        let store = approval();
        store
            .0
            .lock()
            .unwrap()
            .get_mut("test-token")
            .unwrap()
            .expires = Instant::now();
        assert!(store.consume("test-token", "agent-a", 7, &[]).is_err());
        assert!(approval()
            .consume("test-token", "agent-a", 7, &[])
            .unwrap()
            .is_empty());
    }
}
