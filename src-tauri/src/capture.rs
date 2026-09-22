//! One user-authorized, in-memory capture session for all enabled Agents.
use monitor_runtime::{audit::Audit, sensor::SensorState};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};

#[cfg(target_os = "macos")]
mod install;
#[cfg(target_os = "macos")]
mod macos;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, PartialOrd, Ord)]
struct Identity {
    pid: u32,
    start_time: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
struct Sample {
    pid: u32,
    start_time: u64,
    target: String,
    bytes: u32,
}
#[derive(Clone, Debug, Serialize)]
pub struct Packet {
    pid: u32,
    agent_id: String,
    start_time: u64,
    target: String,
    bytes: u32,
    at_ms: u64,
}
#[derive(Clone, Serialize)]
pub struct Status {
    pub supported: bool,
    pub installed: bool,
    pub phase: String,
    pub message: String,
    pub packets: Vec<Packet>,
}
pub struct Controller {
    state: Mutex<Status>,
    cancel: Mutex<Option<tokio::sync::watch::Sender<bool>>>,
    #[cfg(target_os = "macos")]
    generation: std::sync::atomic::AtomicU64,
}
impl Default for Controller {
    fn default() -> Self {
        Self {
            state: Mutex::new(Status {
                supported: cfg!(target_os = "macos"),
                installed: false,
                phase: "idle".into(),
                message: if cfg!(target_os = "macos") {
                    "首次授权安装，之后自动监测所有已开启的 Agent"
                } else {
                    "此平台尚未接入数据包采集"
                }
                .into(),
                packets: vec![],
            }),
            cancel: Mutex::new(None),
            #[cfg(target_os = "macos")]
            generation: std::sync::atomic::AtomicU64::new(0),
        }
    }
}
impl Controller {
    pub fn snapshot(&self, sensor: &SensorState, audit: &Audit) -> Result<Status, String> {
        let config = audit.preferences.load()?;
        let processes = sensor.lock().map_err(|_| "采集状态不可用")?;
        let mut state = self.state.lock().map_err(|_| "抓包状态不可用")?;
        let now = monitor_runtime::scan::now_ms();
        state.packets.retain(|p| {
            now.saturating_sub(p.at_ms) <= 10_000
                && config.enabled(&p.agent_id)
                && processes.processes.iter().any(|v| {
                    v.pid == p.pid && v.start_time == p.start_time && v.agent_id == p.agent_id
                })
        });
        #[cfg(target_os = "macos")]
        {
            state.installed = install::installed();
        }
        Ok(state.clone())
    }
    pub fn start(
        self: &Arc<Self>,
        sensor: SensorState,
        audit: Arc<Audit>,
        install_service: bool,
    ) -> Result<(), String> {
        #[cfg(target_os = "macos")]
        {
            let mut state = self.state.lock().map_err(|_| "抓包状态不可用")?;
            if matches!(
                state.phase.as_str(),
                "authorizing" | "running" | "stopping" | "removing"
            ) {
                return Err("抓包会话已运行或正在授权".into());
            }
            let (cancel, receiver) = tokio::sync::watch::channel(false);
            *self.cancel.lock().map_err(|_| "抓包状态不可用")? = Some(cancel);
            if !install_service && !install::installed() {
                return Err("请先授权安装抓包辅助服务".into());
            }
            state.phase = "authorizing".into();
            state.message = if install_service {
                "等待 macOS 授权安装辅助服务…"
            } else {
                "正在连接已安装的辅助服务…"
            }
            .into();
            state.packets.clear();
            let generation = self
                .generation
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
                + 1;
            let controller = self.clone();
            tauri::async_runtime::spawn(async move {
                let result = async {
                    if install_service {
                        install::install().await?;
                    }
                    if *receiver.borrow() {
                        return Ok(());
                    }
                    if !audit.preferences.load()?.packet_capture_enabled {
                        audit.preferences.update(|config| {
                            config.packet_capture_enabled = true;
                            Ok(())
                        })?;
                    }
                    macos::session(controller.clone(), sensor, audit, receiver).await
                }
                .await;
                let mut state = controller.state.lock().unwrap_or_else(|p| p.into_inner());
                if controller
                    .generation
                    .load(std::sync::atomic::Ordering::SeqCst)
                    != generation
                {
                    return;
                }
                state.packets.clear();
                if state.phase == "removing" {
                    return;
                }
                match result {
                    Ok(()) => {
                        state.phase = "idle".into();
                        state.message = "抓包已停止，普通连接监测继续运行".into();
                    }
                    Err(error) => {
                        state.phase = "error".into();
                        state.message = error;
                    }
                }
            });
            Ok(())
        }
        #[cfg(not(target_os = "macos"))]
        {
            let _ = (sensor, audit, install_service);
            Err("此平台尚未接入数据包采集".into())
        }
    }
    pub fn stop(&self) -> Result<(), String> {
        let mut state = self.state.lock().map_err(|_| "抓包状态不可用")?;
        if matches!(state.phase.as_str(), "authorizing" | "running") {
            state.phase = "stopping".into();
            state.message = "正在停止抓包…".into();
            state.packets.clear();
            if let Some(cancel) = self.cancel.lock().map_err(|_| "抓包状态不可用")?.as_ref()
            {
                let _ = cancel.send(true);
            }
        }
        Ok(())
    }

    pub async fn uninstall(&self) -> Result<(), String> {
        #[cfg(target_os = "macos")]
        {
            {
                let mut state = self.state.lock().map_err(|_| "抓包状态不可用")?;
                if matches!(
                    state.phase.as_str(),
                    "authorizing" | "stopping" | "removing"
                ) {
                    return Err("请等待当前操作完成后重试".into());
                }
                if let Some(cancel) = self.cancel.lock().map_err(|_| "抓包状态不可用")?.as_ref()
                {
                    let _ = cancel.send(true);
                }
                self.generation
                    .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                state.phase = "removing".into();
                state.packets.clear();
            }
            let result = install::uninstall().await;
            let mut state = self.state.lock().map_err(|_| "抓包状态不可用")?;
            state.phase = if result.is_ok() { "idle" } else { "error" }.into();
            state.message = result
                .as_ref()
                .err()
                .cloned()
                .unwrap_or_else(|| "辅助服务已移除".into());
            result
        }
        #[cfg(not(target_os = "macos"))]
        {
            Err("此平台尚未接入数据包采集".into())
        }
    }
}

/// The privileged entry point never initializes a WebView or reads configuration files.
pub fn helper_entry() -> Option<i32> {
    if std::env::args().nth(1).as_deref() != Some("--monitor-capture-service") {
        return None;
    }
    #[cfg(target_os = "macos")]
    {
        Some(macos::helper_entry())
    }
    #[cfg(not(target_os = "macos"))]
    {
        Some(1)
    }
}

#[cfg(any(target_os = "macos", test))]
fn parse(line: &str) -> Option<(u32, String, u32)> {
    let metadata = line.strip_prefix("(proc ")?;
    let pid: u32 = metadata
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()?;
    let (_, line) = line.split_once(") ")?;
    let (header, destination) = line.split_once(" > ")?;
    let ipv6 = header.starts_with("IP6 ");
    if !ipv6 && !header.starts_with("IP ") {
        return None;
    }
    let length = header
        .split_once(if ipv6 { "payload length: " } else { "length " })?
        .1;
    let length: u32 = length
        .split(|c: char| !c.is_ascii_digit())
        .next()?
        .parse()
        .ok()?;
    let bytes = if ipv6 {
        length.checked_add(40)?
    } else {
        length
    };
    if bytes < if ipv6 { 40 } else { 20 } {
        return None;
    }
    let endpoint = destination.split_whitespace().next()?.trim_end_matches(':');
    let (ip, port) = endpoint.rsplit_once('.')?;
    let target = std::net::SocketAddr::new(ip.parse().ok()?, port.parse().ok()?).to_string();
    Some((pid, target, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn packet_identity_and_ip_length_come_from_system_metadata() {
        // Verified with /usr/sbin/tcpdump -r on a synthetic PCAP-NG with a Process Information Block.
        let (pid, target, bytes) = parse("(proc 12345) IP (tos 0x0, ttl 64, proto TCP (6), length 40, bad cksum 0 (->7ccb)!192.0.2.1.1234 > 203.0.113.2.443: tcp 0").unwrap();
        assert_eq!(
            (pid, target.as_str(), bytes),
            (12345, "203.0.113.2:443", 40)
        );
        let (_, target, bytes) = parse("(proc 42, eproc 43) IP6 (hlim 64, next-header TCP (6) payload length: 20) 2001:db8::1.1234 > 2001:db8::2.443: tcp 0").unwrap();
        assert_eq!((target.as_str(), bytes), ("[2001:db8::2]:443", 60));
        assert!(parse("IP 192.0.2.1.1 > 203.0.113.1.443: length 100").is_none());
        assert!(parse("(proc -1) IP (length 40) x > y").is_none());
    }
}
