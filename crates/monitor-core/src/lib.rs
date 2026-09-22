//! Deterministic policy evaluation. This crate does not observe or block OS traffic.
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
pub mod evidence;
pub mod protection;

const MAX_PROCESSES: usize = 4096;
pub const MAX_EVENTS: usize = 10_000;
const READ_WINDOW_MS: u64 = 30_000;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub mode: Mode,
    /// Exact DNS names / IPs only. No implicit subdomain or wildcard trust.
    pub allowed_hosts: Vec<String>,
    pub denied_hosts: Vec<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Observe,
    Protect,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Event {
    ProcessStart {
        at_ms: u64,
        process: String,
        parent: Option<String>,
        name: String,
        protected: bool,
    },
    FileRead {
        at_ms: u64,
        process: String,
        class: FileClass,
    },
    Connect {
        at_ms: u64,
        process: String,
        host: String,
        port: u16,
        protocol: Protocol,
        content: Content,
        #[serde(default)]
        request_path: Option<String>,
    },
    ProcessExit {
        at_ms: u64,
        process: String,
    },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum FileClass {
    Source,
    Secret,
    Other,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Tcp,
    Udp,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Content {
    Unavailable,
    SourceFingerprint,
    SecretFingerprint,
}

#[derive(Clone, Debug, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Action {
    Allow,
    WouldBlock,
    Observe,
    OutOfScope,
}

#[derive(Clone, Debug, Serialize)]
pub struct Decision {
    pub at_ms: u64,
    pub process: String,
    pub agent: Option<String>,
    pub host: String,
    pub port: u16,
    pub protocol: Protocol,
    pub action: Action,
    pub reasons: Vec<String>,
    pub content_visible: bool,
    pub enforced: bool,
}

struct Process {
    agent: Option<String>,
    source_read: Option<u64>,
    secret_read: Option<u64>,
}

pub struct Engine {
    policy: Policy,
    allowed: HashSet<String>,
    denied: HashSet<String>,
    processes: HashMap<String, Process>,
    last_time: u64,
}

/// A host field is never interpreted as a URL, suffix pattern, or authority.
pub fn normalize_host(value: &str) -> Result<String, String> {
    if value.is_empty()
        || value.len() > 253
        || value.chars().any(|c| c.is_whitespace())
        || value.contains(['/', '@', '*', '?', '#', '%', '\\'])
    {
        return Err("目标必须是精确域名或 IP，不能包含 URL、通配符或空白".into());
    }
    if let Ok(ip) = value.parse::<std::net::IpAddr>() {
        return Ok(ip.to_string());
    }
    let trimmed = value.trim_end_matches('.');
    if trimmed.is_empty() || value.ends_with("..") || trimmed.contains(':') {
        return Err("无效目标地址".into());
    }
    let host = url::Host::parse(trimmed)
        .map_err(|_| "无效目标地址")?
        .to_string()
        .to_lowercase();
    if host.split('.').any(|label| {
        label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || c == b'-')
    }) {
        return Err("无效域名标签".into());
    }
    Ok(host)
}

impl Engine {
    pub fn new(policy: Policy) -> Result<Self, String> {
        if policy.allowed_hosts.len() + policy.denied_hosts.len() > 4096 {
            return Err("规则数量超过 4096".into());
        }
        let allowed = policy
            .allowed_hosts
            .iter()
            .map(|h| normalize_host(h))
            .collect::<Result<_, _>>()?;
        let denied = policy
            .denied_hosts
            .iter()
            .map(|h| normalize_host(h))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            policy,
            allowed,
            denied,
            processes: HashMap::new(),
            last_time: 0,
        })
    }

    pub fn ingest(&mut self, event: Event) -> Result<Option<Decision>, String> {
        let (at_ms, id) = match &event {
            Event::ProcessStart { at_ms, process, .. }
            | Event::FileRead { at_ms, process, .. }
            | Event::Connect { at_ms, process, .. }
            | Event::ProcessExit { at_ms, process } => (*at_ms, process),
        };
        if at_ms < self.last_time {
            return Err("事件必须按时间排序".into());
        }
        if id.is_empty() || id.len() > 256 {
            return Err("进程实例标识长度必须为 1–256".into());
        }
        self.last_time = at_ms;
        match event {
            Event::ProcessStart {
                process,
                parent,
                name,
                protected,
                ..
            } => {
                if self.processes.contains_key(&process) {
                    return Err("重复进程实例标识".into());
                }
                if self.processes.len() >= MAX_PROCESSES {
                    return Err("进程容量耗尽，不能静默丢弃保护状态".into());
                }
                if name.is_empty() || name.len() > 256 {
                    return Err("无效进程名称".into());
                }
                let ancestor = match parent {
                    Some(parent) => Some(
                        self.processes
                            .get(&parent)
                            .ok_or("父进程不存在，无法验证归属")?,
                    ),
                    None => None,
                };
                let inherited = ancestor.and_then(|p| p.agent.clone());
                let agent = inherited.or_else(|| protected.then_some(name));
                self.processes.insert(
                    process,
                    Process {
                        agent,
                        source_read: None,
                        secret_read: None,
                    },
                );
                Ok(None)
            }
            Event::FileRead { process, class, .. } => {
                let p = self
                    .processes
                    .get_mut(&process)
                    .ok_or("读取事件缺少进程实例")?;
                match class {
                    FileClass::Source => p.source_read = Some(at_ms),
                    FileClass::Secret => p.secret_read = Some(at_ms),
                    FileClass::Other => {}
                }
                Ok(None)
            }
            Event::ProcessExit { process, .. } => {
                self.processes
                    .remove(&process)
                    .ok_or("退出事件缺少进程实例")?;
                Ok(None)
            }
            Event::Connect {
                process,
                host,
                port,
                protocol,
                content,
                request_path,
                ..
            } => {
                if port == 0 {
                    return Err("端口不能为 0".into());
                }
                let host = normalize_host(&host)?;
                let p = self
                    .processes
                    .get(&process)
                    .ok_or("连接事件缺少进程实例，不能判定已保护")?;
                let mut reasons = Vec::new();
                let visible = content != Content::Unavailable;
                let action = if p.agent.is_none() {
                    reasons.push("进程不在保护范围内".into());
                    Action::OutOfScope
                } else {
                    let allowed = self.allowed.contains(&host);
                    let denied = self.denied.contains(&host);
                    let known = evidence::endpoint_signal(&host, request_path.as_deref());
                    if let Some(signal) = &known {
                        reasons.push(signal.clone());
                    }
                    if denied {
                        reasons.push("目标命中显式拒绝规则".into());
                    }
                    if !allowed {
                        reasons.push("目标未经授权；不依赖已知恶意域名名单".into());
                    }
                    if content == Content::SecretFingerprint {
                        reasons.push("输入证据标记：请求含敏感内容指纹（需可信采集器验证）".into());
                    }
                    if content == Content::SourceFingerprint {
                        reasons.push("输入证据标记：请求含源码指纹（需可信采集器验证）".into());
                    }
                    for (read, label) in [(p.secret_read, "敏感文件"), (p.source_read, "源码文件")]
                    {
                        if read.is_some_and(|t| at_ms.saturating_sub(t) <= READ_WINDOW_MS) {
                            reasons.push(format!(
                                "同一进程在 30 秒内读取了{label}；仅为行为关联，不证明上传"
                            ));
                        }
                    }
                    if !visible {
                        reasons.push("请求正文不可见，无法确认是否上传源码".into());
                    }
                    let block = denied
                        || !allowed
                        || content == Content::SecretFingerprint
                        || known.is_some();
                    if block {
                        if self.policy.mode == Mode::Protect {
                            Action::WouldBlock
                        } else {
                            Action::Observe
                        }
                    } else {
                        reasons.push("目标已授权；不代表该目标上的所有上传均安全".into());
                        Action::Allow
                    }
                };
                Ok(Some(Decision {
                    at_ms,
                    process,
                    agent: p.agent.clone(),
                    host,
                    port,
                    protocol,
                    action,
                    reasons,
                    content_visible: visible,
                    enforced: false,
                }))
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Replay {
    pub policy: Policy,
    pub events: Vec<Event>,
}

pub fn replay(input: Replay) -> Result<Vec<Decision>, String> {
    if input.events.len() > MAX_EVENTS {
        return Err("单次回放最多 10000 条事件".into());
    }
    let mut engine = Engine::new(input.policy)?;
    input
        .events
        .into_iter()
        .enumerate()
        .try_fold(Vec::new(), |mut result, (i, e)| {
            if let Some(d) = engine
                .ingest(e)
                .map_err(|e| format!("事件 {}: {e}", i + 1))?
            {
                result.push(d);
            }
            Ok(result)
        })
}
