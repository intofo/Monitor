//! Decisions use the ES publisher's root-owned process registry, not process names.
use crate::{ProcessKey, RuntimeSnapshot};
use monitor_core::protection::{ProtectionEngine, ProtectionMode, Transport, Verdict};
use std::{
    collections::{HashMap, HashSet},
    net::{IpAddr, ToSocketAddrs},
    sync::{Mutex, OnceLock},
    time::{SystemTime, UNIX_EPOCH},
};
struct Rule {
    uid: u32,
    engine: ProtectionEngine,
    mismatch: bool,
    mode: ProtectionMode,
    domains: Vec<(String, u16, Transport)>,
}
pub struct NetworkAuthorizer {
    rules: HashMap<ProcessKey, Rule>,
    expires: u64,
    healthy: bool,
    addresses: HashMap<String, HashSet<IpAddr>>,
}
impl NetworkAuthorizer {
    pub fn new(
        snapshot: RuntimeSnapshot,
        addresses: HashMap<String, HashSet<IpAddr>>,
    ) -> Result<Self, String> {
        if snapshot.processes.len() > 4096 {
            return Err("Too many process rules".into());
        }
        let mut rules = HashMap::new();
        for process in snapshot.processes {
            if process.uid == 0 || process.pid == 0 || process.version == 0 {
                return Err("Invalid process identity".into());
            }
            let policy = process.policy.validate()?;
            let domains = if policy.mode == ProtectionMode::Offline {
                &policy.model_api_allowlist
            } else {
                &policy.network_allowlist
            };
            let domains = domains
                .iter()
                .filter(|g| g.host.parse::<IpAddr>().is_err())
                .map(|g| (g.host.clone(), g.port, g.transport))
                .collect();
            let key = ProcessKey {
                pid: process.pid,
                version: process.version,
            };
            if rules
                .insert(
                    key,
                    Rule {
                        uid: process.uid,
                        mismatch: process.signature_mismatch,
                        mode: policy.mode,
                        domains,
                        engine: ProtectionEngine::new(policy)?,
                    },
                )
                .is_some()
            {
                return Err("Duplicate process identity".into());
            }
        }
        Ok(Self {
            rules,
            expires: snapshot.generated_at_ms.saturating_add(5000),
            healthy: snapshot.healthy,
            addresses,
        })
    }
    // Mirrors the kernel flow identity and destination fields.
    #[allow(clippy::too_many_arguments)]
    pub fn decide(
        &self,
        key: ProcessKey,
        uid: u32,
        address: IpAddr,
        hostname: &str,
        port: u16,
        transport: Transport,
        now: u64,
    ) -> Verdict {
        let Some(rule) = self.rules.get(&key) else {
            return Verdict::Observe;
        };
        if rule.uid != uid {
            return Verdict::Deny;
        }
        if rule.mode == ProtectionMode::Observe {
            return Verdict::Observe;
        }
        if !self.healthy
            || now > self.expires
            || self.expires > now.saturating_add(10000)
            || rule.mismatch
        {
            return Verdict::Deny;
        }
        let direct = rule.engine.network_ip(address, port, transport).verdict;
        if direct == Verdict::Allow {
            return direct;
        }
        // Never grant a hostname exception from a caller-supplied name alone or
        // silently broaden a name-only exception to every site on a shared CDN IP.
        let host = monitor_core::normalize_host(hostname).ok();
        if let Some(host) = host {
            if rule
                .domains
                .iter()
                .any(|(name, p, t)| name == &host && *p == port && *t == transport)
                && self
                    .addresses
                    .get(&host)
                    .is_some_and(|ips| ips.contains(&address))
            {
                return Verdict::Allow;
            }
        }
        direct
    }
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
static CURRENT: OnceLock<Mutex<Option<NetworkAuthorizer>>> = OnceLock::new();
fn current() -> &'static Mutex<Option<NetworkAuthorizer>> {
    CURRENT.get_or_init(|| Mutex::new(None))
}
/// Called on a background queue, never in NEFilter callbacks. Failed reads retain
/// the previous identities only until their short heartbeat lease expires.
#[cfg(target_os = "macos")]
#[no_mangle]
pub extern "C" fn monitor_network_reload() -> i32 {
    std::panic::catch_unwind(|| {
        let snapshot: RuntimeSnapshot = match crate::transport::read() {
            Ok(v) => v,
            Err(_) => return 1,
        };
        let mut names = HashSet::new();
        for process in &snapshot.processes {
            for grant in process
                .policy
                .network_allowlist
                .iter()
                .chain(&process.policy.model_api_allowlist)
            {
                if grant.host.parse::<IpAddr>().is_err() {
                    names.insert(grant.host.clone());
                }
            }
        }
        if names.len() > 256 {
            return 2;
        }
        let addresses = names
            .into_iter()
            .map(|host| {
                let ips = (host.as_str(), 443)
                    .to_socket_addrs()
                    .map(|v| v.map(|a| a.ip()).collect())
                    .unwrap_or_default();
                (host, ips)
            })
            .collect();
        match NetworkAuthorizer::new(snapshot, addresses) {
            Ok(rules) => {
                *current().lock().unwrap_or_else(|e| e.into_inner()) = Some(rules);
                0
            }
            Err(_) => 2,
        }
    })
    .unwrap_or(3)
}
/// 0 = unrelated/allow; 1 = deny; 2 = ask; 4 = AI review (denied until approved).
/// # Safety
/// `address` and `hostname` must be NUL-terminated UTF-8 strings valid for this call.
#[no_mangle]
pub unsafe extern "C" fn monitor_network_decide(
    pid: u32,
    version: u32,
    uid: u32,
    address: *const std::ffi::c_char,
    hostname: *const std::ffi::c_char,
    port: u16,
    protocol: u32,
) -> u32 {
    std::panic::catch_unwind(|| {
        let guard = current().lock().unwrap_or_else(|e| e.into_inner());
        let Some(rules) = guard.as_ref() else {
            return 1;
        };
        let key = ProcessKey { pid, version };
        if !rules.rules.contains_key(&key) {
            return 0;
        }
        if address.is_null() {
            return 1;
        }
        let Ok(address) = std::ffi::CStr::from_ptr(address).to_string_lossy().parse() else {
            return 1;
        };
        let host = if hostname.is_null() {
            "".into()
        } else {
            std::ffi::CStr::from_ptr(hostname).to_string_lossy()
        };
        let transport = match protocol {
            6 => Transport::Tcp,
            17 => Transport::Udp,
            _ => return 1,
        };
        match rules.decide(key, uid, address, &host, port, transport, now()) {
            Verdict::Allow | Verdict::Observe => 0,
            Verdict::Ask => 2,
            Verdict::Review => 4,
            _ => 1,
        }
    })
    .unwrap_or(1)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuntimeProcess;
    use monitor_core::protection::{NetworkGrant, ProtectionPolicy};
    fn rules() -> NetworkAuthorizer {
        let mut policy = ProtectionPolicy {
            mode: ProtectionMode::Offline,
            ..Default::default()
        };
        policy.model_api_allowlist.push(NetworkGrant {
            host: "api.example.com".into(),
            port: 443,
            transport: Transport::Tcp,
        });
        NetworkAuthorizer::new(
            RuntimeSnapshot {
                revision: 1,
                healthy: true,
                generated_at_ms: 10000,
                processes: vec![RuntimeProcess {
                    pid: 10,
                    version: 2,
                    uid: 501,
                    agent_id: "test".into(),
                    signature_mismatch: false,
                    policy,
                }],
            },
            HashMap::from([(
                "api.example.com".into(),
                HashSet::from(["203.0.113.10".parse().unwrap()]),
            )]),
        )
        .unwrap()
    }
    #[test]
    fn api_exception_requires_matching_identity_name_address_port_and_fresh_registry() {
        let rules = rules();
        let key = ProcessKey {
            pid: 10,
            version: 2,
        };
        let ip = "203.0.113.10".parse().unwrap();
        assert_eq!(
            rules.decide(key, 501, ip, "api.example.com", 443, Transport::Tcp, 11000),
            Verdict::Allow
        );
        assert_eq!(
            rules.decide(key, 501, ip, "other.example", 443, Transport::Tcp, 11000),
            Verdict::Deny
        );
        assert_eq!(
            rules.decide(
                key,
                501,
                "203.0.113.11".parse().unwrap(),
                "api.example.com",
                443,
                Transport::Tcp,
                11000
            ),
            Verdict::Deny
        );
        assert_eq!(
            rules.decide(key, 501, ip, "api.example.com", 80, Transport::Tcp, 11000),
            Verdict::Deny
        );
        assert_eq!(
            rules.decide(key, 502, ip, "api.example.com", 443, Transport::Tcp, 11000),
            Verdict::Deny
        );
        assert_eq!(
            rules.decide(key, 501, ip, "api.example.com", 443, Transport::Tcp, 16000),
            Verdict::Deny
        );
        assert_eq!(
            rules.decide(
                ProcessKey {
                    pid: 10,
                    version: 3
                },
                501,
                ip,
                "api.example.com",
                443,
                Transport::Tcp,
                11000
            ),
            Verdict::Observe
        );
    }
}
