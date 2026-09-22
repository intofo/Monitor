use crate::{
    audit::Audit,
    discovery::{self, AgentProcess, Discovery, Installation},
};
use serde::Serialize;
use std::{
    collections::{HashMap, HashSet},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{io::AsyncReadExt, process::Command};

#[derive(Clone, Debug, Serialize)]
pub struct Activity {
    pub pid: u32,
    pub agent: String,
    pub agent_id: String,
    pub kind: String,
    pub target: String,
    pub assessment: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct SensorSnapshot {
    pub at_ms: u64,
    pub agents: Vec<crate::catalog::AgentEntry>,
    pub config_revision: u64,
    pub running: bool,
    pub processes: Vec<AgentProcess>,
    pub installations: Vec<Installation>,
    pub activities: Vec<Activity>,
    pub warnings: Vec<String>,
    pub interval_seconds: u64,
    pub network_enforcement: bool,
}
impl Default for SensorSnapshot {
    fn default() -> Self {
        Self {
            at_ms: 0,
            agents: vec![],
            config_revision: 0,
            running: false,
            processes: vec![],
            installations: vec![],
            activities: vec![],
            warnings: vec![],
            interval_seconds: 3,
            network_enforcement: false,
        }
    }
}
pub type SensorState = Arc<Mutex<SensorSnapshot>>;

pub async fn run(state: SensorState, audit: Arc<Audit>) {
    let mut discovery = Discovery::default();
    let mut installations = vec![];
    let mut round = 0u32;
    let mut cursor = 0usize;
    let mut egress = crate::egress::EgressTracker::default();
    let started = std::time::Instant::now();
    loop {
        let config = match audit.preferences.load() {
            Ok(config) => config,
            Err(e) => {
                state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .warnings
                    .push(e);
                break;
            }
        };
        let discovery_config = config.clone();
        let refreshed = tokio::task::spawn_blocking(move || {
            let processes = discovery.refresh_config(&discovery_config);
            (discovery, processes)
        })
        .await;
        let (next, processes) = match refreshed {
            Ok(r) => r,
            Err(e) => {
                state
                    .lock()
                    .unwrap_or_else(|p| p.into_inner())
                    .warnings
                    .push(format!("进程采集失败: {e}"));
                break;
            }
        };
        discovery = next;
        if round.is_multiple_of(20) {
            installations = tokio::task::spawn_blocking(discovery::installations)
                .await
                .unwrap_or_default();
        }
        round = round.wrapping_add(1);
        let agents = crate::catalog::build(&processes, &installations, &config);
        let monitored: Vec<_> = processes
            .iter()
            .filter(|p| config.enabled(&p.agent_id))
            .cloned()
            .collect();
        let sampled = sampling_batch(&monitored, &mut cursor, 256);
        let (mut activities, mut warnings) = collect(&sampled).await;
        let signals = egress.observe(
            started.elapsed().as_millis() as u64,
            &monitored,
            &activities,
        );
        activities.extend(signals);
        warnings.push(format!(
            "已选监测范围：本轮采集 {} / {} 个进程，按 PID 轮转；可在 Agent 卡片调整范围。",
            sampled.len(),
            monitored.len()
        ));
        // Live processes and activities stay in the snapshot only; never persist them.
        warnings.push(
            "3 秒采样可能遗漏短连接和短时文件操作；HTTPS 正文不可见。无告警不代表无外传。".into(),
        );
        *state.lock().unwrap_or_else(|p| p.into_inner()) = SensorSnapshot {
            at_ms: crate::scan::now_ms(),
            agents,
            config_revision: config.revision,
            running: true,
            processes,
            installations: installations.clone(),
            activities,
            warnings,
            interval_seconds: 3,
            network_enforcement: false,
        };
        tokio::time::sleep(Duration::from_secs(3)).await;
    }
    state.lock().unwrap_or_else(|p| p.into_inner()).running = false;
}

/// Bounded round-robin sampling avoids permanently starving unknown or high-PID programs.
pub fn sampling_batch(
    processes: &[AgentProcess],
    cursor: &mut usize,
    limit: usize,
) -> Vec<AgentProcess> {
    if processes.is_empty() || limit == 0 {
        return vec![];
    }
    let count = limit.min(processes.len());
    let start = *cursor % processes.len();
    let batch = (0..count)
        .map(|i| processes[(start + i) % processes.len()].clone())
        .collect();
    *cursor = (start + count) % processes.len();
    batch
}

pub async fn collect(processes: &[AgentProcess]) -> (Vec<Activity>, Vec<String>) {
    if processes.is_empty() {
        return (vec![], vec![]);
    }
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let ids = processes
            .iter()
            .take(256)
            .map(|p| p.pid.to_string())
            .collect::<Vec<_>>()
            .join(",");
        #[cfg(target_os = "macos")]
        let binary = "/usr/sbin/lsof";
        #[cfg(target_os = "linux")]
        let binary = "lsof";
        let mut cmd = Command::new(binary);
        cmd.args(["-nP", "-p", &ids, "-F", "pftn"]);
        match bounded_output(cmd, true).await {
            Ok((text, partial)) => {
                let mut warnings = vec![
                    "文件信息来自当前打开的文件描述符；不能证明执行了读取，也不能证明文件已上传。"
                        .into(),
                ];
                if partial {
                    warnings
                        .push("部分进程不可读取或已退出；仅展示成功采集的数据，覆盖不完整".into());
                }
                if processes.len() > 256 {
                    warnings.push("超过 256 个进程，部分进程未采集连接".into());
                }
                let activities = parse_lsof(&text, processes);
                if activities.len() >= 2000 {
                    warnings.push("活动达到 2000 条上限".into());
                }
                (activities, warnings)
            }
            Err(e) => (
                vec![],
                vec![format!("连接/文件采集不可用（权限、lsof 或进程退出）: {e}")],
            ),
        }
    }
    #[cfg(target_os = "windows")]
    {
        // Numeric PIDs only; no process paths or arbitrary user strings enter this script.
        let ids = processes
            .iter()
            .take(256)
            .map(|p| p.pid.to_string())
            .collect::<Vec<_>>()
            .join(",");
        let script=format!("$ErrorActionPreference='Stop'; Get-NetTCPConnection | Where-Object {{ $_.OwningProcess -in @({ids}) -and $_.RemotePort -gt 0 }} | ForEach-Object {{ '{{0}}|{{1}}:{{2}}' -f $_.OwningProcess,$_.RemoteAddress,$_.RemotePort }}");
        let mut cmd = Command::new("powershell.exe");
        cmd.args(["-NoProfile", "-NonInteractive", "-Command", &script]);
        match bounded_output(cmd, false).await {
            Ok((text, _)) => {
                let activities = text
                    .lines()
                    .filter_map(|l| {
                        let (pid, target) = l.trim().split_once('|')?;
                        let pid = pid.parse().ok()?;
                        let p = processes.iter().find(|p| p.pid == pid)?;
                        Some(Activity {
                            pid,
                            agent: p.agent.clone(),
                            agent_id: p.agent_id.clone(),
                            kind: "connection".into(),
                            target: target.into(),
                            assessment: "观察到 TCP 连接；正文不可见，不能确认上传内容".into(),
                        })
                    })
                    .take(2000)
                    .collect();
                (
                    activities,
                    vec!["Windows 当前采集 TCP 连接；UDP 远端与文件操作传感器尚未接入".into()],
                )
            }
            Err(e) => (vec![], vec![format!("Windows TCP 连接采集失败: {e}")]),
        }
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        (vec![], vec!["此平台暂未接入活动传感器".into()])
    }
}

async fn bounded_output(
    mut command: Command,
    allow_partial: bool,
) -> Result<(String, bool), String> {
    command
        .kill_on_drop(true)
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null());
    let mut child = command.spawn().map_err(|e| e.to_string())?;
    let stdout = child.stdout.take().ok_or("没有采集输出")?;
    let mut bytes = vec![];
    tokio::time::timeout(Duration::from_secs(2), async {
        stdout
            .take(4 * 1024 * 1024 + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(|e| e.to_string())?;
        if bytes.len() > 4 * 1024 * 1024 {
            return Err("采集结果超过 4 MiB".into());
        }
        let status = child.wait().await.map_err(|e| e.to_string())?;
        if !status.success() && (!allow_partial || bytes.is_empty()) {
            return Err(format!(
                "采集命令退出码 {:?}，覆盖可能不完整",
                status.code()
            ));
        }
        String::from_utf8(bytes)
            .map(|text| (text, !status.success()))
            .map_err(|_| "采集输出不是 UTF-8".into())
    })
    .await
    .map_err(|_| "采集命令超过 2 秒".to_string())?
}

pub fn parse_lsof(text: &str, processes: &[AgentProcess]) -> Vec<Activity> {
    let by_pid: HashMap<_, _> = processes.iter().map(|p| (p.pid, p)).collect();
    let mut pid = 0;
    let mut typ = "";
    let mut result = vec![];
    let mut seen = HashSet::new();
    for line in text.lines() {
        if line.is_empty() {
            continue;
        }
        let Some((tag, value)) = line.split_at_checked(1) else {
            continue;
        };
        match tag {
            "p" => {
                pid = value.parse().unwrap_or(0);
                typ = "";
            }
            "f" => typ = "",
            "t" => typ = value,
            "n" => {
                let Some(p) = by_pid.get(&pid) else {
                    continue;
                };
                let (kind, target, assessment) = if typ == "IPv4" || typ == "IPv6" {
                    let Some((_, remote)) = value.split_once("->") else {
                        continue;
                    };
                    (
                        "connection",
                        remote,
                        "观察到网络连接；未采集请求正文，不能判断是否上传源码",
                    )
                } else if typ == "REG" && discovery::is_source_path(value) {
                    (
                        "source_open",
                        value,
                        "观察到源码候选文件处于打开状态；不等于已读取或上传",
                    )
                } else {
                    continue;
                };
                if seen.insert((pid, kind.to_string(), target.to_string())) {
                    result.push(Activity {
                        pid,
                        agent: p.agent.clone(),
                        agent_id: p.agent_id.clone(),
                        kind: kind.into(),
                        target: target.into(),
                        assessment: assessment.into(),
                    });
                }
            }
            _ => {}
        }
        if result.len() >= 2000 {
            break;
        }
    }
    // Same-process correlation is a review signal, never proof of exfiltration.
    let readers: HashSet<_> = result
        .iter()
        .filter(|a| a.kind == "source_open")
        .map(|a| a.pid)
        .collect();
    for a in &mut result {
        if a.kind == "connection" && readers.contains(&a.pid) {
            a.assessment =
                "同一采样中进程打开源码候选文件并保持网络连接：需核查，不证明源码已上传".into();
        }
    }
    result
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;

    #[tokio::test]
    async fn partial_collection_keeps_evidence_and_reports_incomplete_coverage() {
        let mut command = Command::new("/bin/sh");
        command.args([
            "-c",
            "printf 'p42\\nf1\\ntREG\\nn/project/main.rs\\n'; exit 1",
        ]);
        let (text, partial) = bounded_output(command, true).await.unwrap();
        assert!(partial);
        assert!(text.contains("/project/main.rs"));
        let mut empty = Command::new("/bin/sh");
        empty.args(["-c", "exit 1"]);
        assert!(bounded_output(empty, true).await.is_err());
    }
}
