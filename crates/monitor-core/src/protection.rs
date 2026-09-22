//! Authorization decisions only. A Deny is not evidence of an enforced block.
//! Native adapters must authenticate process identity and supply resolved targets.
use serde::{Deserialize, Serialize};
use std::{
    net::IpAddr,
    path::{Component, Path},
};

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ProtectionMode {
    #[default]
    Observe,
    Allowlist,
    Ask,
    Offline,
    Ai,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    Tcp,
    Udp,
}
#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NetworkGrant {
    pub host: String,
    pub port: u16,
    pub transport: Transport,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ProtectionPolicy {
    pub mode: ProtectionMode,
    pub project_directories: Vec<String>,
    /// Explicit read grants for dependencies/configuration outside projects.
    pub readable_directories: Vec<String>,
    pub network_allowlist: Vec<NetworkGrant>,
    /// Only populated by the explicit model API approval flow.
    pub model_api_allowlist: Vec<NetworkGrant>,
    /// Optional connection-level web permission, not HTTP-method/content inspection.
    pub allow_web: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    Observe,
    Allow,
    Deny,
    Ask,
    Review,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reason {
    ObserveOnly,
    AuthorizedDirectory,
    OutsideDirectories,
    InvalidTarget,
    AuthorizedNetwork,
    UnauthorizedNetwork,
    Offline,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthorizationDecision {
    pub verdict: Verdict,
    pub reason: Reason,
}
fn decision(verdict: Verdict, reason: Reason) -> AuthorizationDecision {
    AuthorizationDecision { verdict, reason }
}
fn normalized_absolute(path: &str) -> bool {
    path.starts_with('/')
        && !path.contains('\0')
        && path.len() <= 4096
        && !path.split('/').any(|part| part == "." || part == "..")
        && Path::new(path)
            .components()
            .all(|part| matches!(part, Component::RootDir | Component::Normal(_)))
}
impl ProtectionPolicy {
    pub fn validate(mut self) -> Result<Self, String> {
        if self.project_directories.len() + self.readable_directories.len() > 128
            || self.network_allowlist.len() + self.model_api_allowlist.len() > 256
        {
            return Err("Too many protection rules".into());
        }
        for directories in [
            &mut self.project_directories,
            &mut self.readable_directories,
        ] {
            for path in directories.iter_mut() {
                if !normalized_absolute(path) || Path::new(path).parent().is_none() {
                    return Err(
                        "Directory rules require an absolute path other than /, without . or .."
                            .into(),
                    );
                }
                *path = Path::new(path)
                    .components()
                    .collect::<std::path::PathBuf>()
                    .to_string_lossy()
                    .into_owned();
            }
            directories.sort();
            directories.dedup();
        }
        for grant in self
            .network_allowlist
            .iter_mut()
            .chain(&mut self.model_api_allowlist)
        {
            grant.host = crate::normalize_host(&grant.host)?;
            if grant.port == 0 {
                return Err("Network port must be between 1 and 65535".into());
            }
        }
        let mut unique = Vec::new();
        for grant in self.network_allowlist {
            if !unique.contains(&grant) {
                unique.push(grant);
            }
        }
        self.network_allowlist = unique;
        Ok(self)
    }
}
/// Holds validated rules; native adapters compile a complete snapshot before use.
pub struct ProtectionEngine {
    policy: ProtectionPolicy,
}
impl ProtectionEngine {
    pub fn new(policy: ProtectionPolicy) -> Result<Self, String> {
        Ok(Self {
            policy: policy.validate()?,
        })
    }
    /// `resolved_path` must come from the native authorization event. Never use a
    /// caller-provided lexical path to authorize a symlink, alias, or hard link.
    pub fn file_read(&self, resolved_path: &str) -> AuthorizationDecision {
        if self.policy.mode == ProtectionMode::Observe {
            return decision(Verdict::Observe, Reason::ObserveOnly);
        }
        if !normalized_absolute(resolved_path) {
            return decision(Verdict::Deny, Reason::InvalidTarget);
        }
        if self
            .policy
            .project_directories
            .iter()
            .chain(&self.policy.readable_directories)
            .any(|root| Path::new(resolved_path).starts_with(root))
        {
            return decision(Verdict::Allow, Reason::AuthorizedDirectory);
        }
        decision(
            if self.policy.mode == ProtectionMode::Ask {
                Verdict::Ask
            } else if self.policy.mode == ProtectionMode::Ai {
                Verdict::Review
            } else {
                Verdict::Deny
            },
            Reason::OutsideDirectories,
        )
    }
    /// DNS names require trustworthy attribution by the network adapter. Reverse
    /// DNS and an app-supplied hostname are not sufficient authorization evidence.
    pub fn network(&self, host: &str, port: u16, transport: Transport) -> AuthorizationDecision {
        if self.policy.mode == ProtectionMode::Observe {
            return decision(Verdict::Observe, Reason::ObserveOnly);
        }
        let Ok(host) = crate::normalize_host(host) else {
            return decision(Verdict::Deny, Reason::InvalidTarget);
        };
        if port == 0 {
            return decision(Verdict::Deny, Reason::InvalidTarget);
        }
        if self.policy.allow_web
            && transport == Transport::Tcp
            && matches!(port, 80 | 443)
            && host.parse::<IpAddr>().is_ok_and(public_web_address)
        {
            return decision(Verdict::Allow, Reason::AuthorizedNetwork);
        }
        if self.policy.mode == ProtectionMode::Offline {
            return decision(
                if self.policy.model_api_allowlist.iter().any(|grant| {
                    grant.host == host && grant.port == port && grant.transport == transport
                }) {
                    Verdict::Allow
                } else {
                    Verdict::Deny
                },
                Reason::Offline,
            );
        }
        if self
            .policy
            .network_allowlist
            .iter()
            .any(|grant| grant.host == host && grant.port == port && grant.transport == transport)
        {
            return decision(Verdict::Allow, Reason::AuthorizedNetwork);
        }
        decision(
            if self.policy.mode == ProtectionMode::Ask {
                Verdict::Ask
            } else if self.policy.mode == ProtectionMode::Ai {
                Verdict::Review
            } else {
                Verdict::Deny
            },
            Reason::UnauthorizedNetwork,
        )
    }
    /// The adapter can always use the actual destination IP when no trustworthy
    /// hostname is available; an IP never inherits a DNS-name grant.
    pub fn network_ip(
        &self,
        address: IpAddr,
        port: u16,
        transport: Transport,
    ) -> AuthorizationDecision {
        self.network(&address.to_string(), port, transport)
    }
}

pub fn public_web_address(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(ip) => {
            let [a, b, c, _] = ip.octets();
            !ip.is_private()
                && !ip.is_loopback()
                && !ip.is_link_local()
                && !ip.is_unspecified()
                && !ip.is_broadcast()
                && !ip.is_multicast()
                && !ip.is_documentation()
                && a != 0
                && a < 224
                && !(a == 100 && (64..=127).contains(&b))
                && !(a == 198 && (b == 18 || b == 19))
                && !(a == 192 && b == 0 && c == 0)
        }
        IpAddr::V6(ip) => {
            if let Some(v4) = ip.to_ipv4_mapped() {
                return public_web_address(IpAddr::V4(v4));
            }
            let parts = ip.segments();
            // Only global unicast space; reject documentation and transition ranges.
            parts[0] & 0xe000 == 0x2000
                && !(parts[0] == 0x2001 && (parts[1] == 0xdb8 || parts[1] < 0x200))
                && parts[0] != 0x2002
        }
    }
}
