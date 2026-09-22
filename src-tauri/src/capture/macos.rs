use super::{Audit, Controller, Identity, Packet, Sample, SensorState};
use serde::{Deserialize, Serialize};
use std::{
    os::{fd::AsRawFd, unix::fs::PermissionsExt},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, AsyncWriteExt, BufReader},
    net::{UnixListener, UnixStream},
    sync::{mpsc, watch},
};

// Keep partial lines across select! cancellation, and reject oversized IPC before allocating it.
struct BoundedLines<R> {
    reader: R,
    pending: Vec<u8>,
    limit: usize,
}
impl<R: tokio::io::AsyncBufRead + Unpin> BoundedLines<R> {
    fn new(reader: R, limit: usize) -> Self {
        Self {
            reader,
            pending: Vec::new(),
            limit,
        }
    }
    async fn next(&mut self) -> Result<Option<String>, String> {
        loop {
            let available = self.reader.fill_buf().await.map_err(|e| e.to_string())?;
            if available.is_empty() {
                if self.pending.is_empty() {
                    return Ok(None);
                }
                return Err("会话数据不完整".into());
            }
            let newline = available.iter().position(|b| *b == b'\n');
            let count = newline.map_or(available.len(), |n| n + 1);
            if self.pending.len() + count > self.limit {
                return Err("会话数据超过上限".into());
            }
            self.pending.extend_from_slice(&available[..count]);
            self.reader.consume(count);
            if newline.is_some() {
                return String::from_utf8(std::mem::take(&mut self.pending))
                    .map(Some)
                    .map_err(|_| "会话数据编码无效".into());
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
enum Wire {
    Ready,
    Packet(Sample),
    Error(String),
}

fn peer_uid(stream: &UnixStream) -> Result<u32, String> {
    let mut uid = 0;
    let mut gid = 0;
    // SAFETY: valid socket descriptor and writable uid/gid pointers.
    if unsafe { libc::getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
        return Err("无法验证抓包会话身份".into());
    }
    Ok(uid)
}
fn desired(sensor: &SensorState, audit: &Audit) -> Result<Vec<Identity>, String> {
    let config = audit.preferences.load()?;
    let state = sensor.lock().map_err(|_| "采集状态不可用")?;
    let mut scope: Vec<_> = state
        .processes
        .iter()
        .filter(|p| config.enabled(&p.agent_id))
        .map(|p| Identity {
            pid: p.pid,
            start_time: p.start_time,
        })
        .collect();
    scope.sort();
    scope.dedup();
    if scope.len() > 1024 {
        return Err("已选进程超过 1024 个，请缩小监测范围后重新授权".into());
    }
    Ok(scope)
}

pub async fn session(
    controller: Arc<Controller>,
    sensor: SensorState,
    audit: Arc<Audit>,
    mut cancel: watch::Receiver<bool>,
) -> Result<(), String> {
    let connection = async {
        for _ in 0..50 {
            if let Ok(stream) =
                UnixStream::connect(super::install::socket(super::install::uid())).await
            {
                return Ok(stream);
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err("无法连接已安装的抓包服务，请修复辅助服务".to_string())
    };
    let stream = tokio::select! {
        result = connection => result?,
        _ = cancel.changed() => return Ok(()),
    };
    if peer_uid(&stream)? != 0 {
        return Err("拒绝未授权的抓包辅助进程".into());
    }
    let (read, mut write) = stream.into_split();
    let mut reader = BoundedLines::new(BufReader::new(read), 8192);
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut ready = false;
    loop {
        tokio::select! {
            _ = cancel.changed() => { let _ = write.shutdown().await; return Ok(()); }
            _ = tick.tick() => {
                let scope = desired(&sensor, &audit)?;
                let mut bytes = serde_json::to_vec(&scope).map_err(|e| e.to_string())?;
                bytes.push(b'\n');
                tokio::time::timeout(Duration::from_secs(2), write.write_all(&bytes)).await
                    .map_err(|_| "抓包辅助进程无响应")?.map_err(|_| "抓包辅助进程已断开")?;
            }
            line = reader.next() => {
                let Some(line) = line? else { return Err("抓包辅助进程已断开，请重新连接".into()); };
                let message: Wire = serde_json::from_str(&line).map_err(|_| "抓包输出格式无效")?;
                match message {
                    Wire::Ready => {
                        ready = true;
                        let mut state = controller.state.lock().map_err(|_| "抓包状态不可用")?;
                        if state.phase == "stopping" { return Ok(()); }
                        state.phase = "running".into();
                        state.message = "已授权 · 持续监测所有已开启的 Agent".into();
                    }
                    Wire::Error(error) => return Err(error),
                    Wire::Packet(sample) if ready => {
                        let config = audit.preferences.load()?;
                        let snapshot = sensor.lock().map_err(|_| "采集状态不可用")?;
                        let Some(process) = snapshot.processes.iter().find(|p| p.pid == sample.pid && p.start_time == sample.start_time && config.enabled(&p.agent_id)) else { continue; };
                        let mut state = controller.state.lock().map_err(|_| "抓包状态不可用")?;
                        if state.phase != "running" { continue; }
                        let now = monitor_runtime::scan::now_ms();
                        state.packets.retain(|p| now.saturating_sub(p.at_ms) <= 10_000);
                        if state.packets.len() >= 2000 { state.packets.drain(..500); }
                        state.packets.push(Packet { pid: sample.pid, agent_id: process.agent_id.clone(), start_time: sample.start_time, target: sample.target, bytes: sample.bytes, at_ms: now });
                    }
                    Wire::Packet(_) => return Err("抓包会话未完成身份验证".into()),
                }
            }
        }
    }
}

struct AbortTask(Option<tokio::task::JoinHandle<()>>);
impl Drop for AbortTask {
    fn drop(&mut self) {
        if let Some(task) = self.0.take() {
            task.abort();
        }
    }
}

pub fn helper_entry() -> i32 {
    // SAFETY: geteuid has no preconditions. Refuse to run a privileged UI or generic command.
    if unsafe { libc::geteuid() } != 0 {
        return 1;
    }
    let args: Vec<_> = std::env::args().collect();
    if args.len() != 3 {
        return 1;
    }
    let Ok(uid) = args[2].parse::<u32>() else {
        return 1;
    };
    let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(2)
        .enable_all()
        .build()
    else {
        return 1;
    };
    match runtime.block_on(daemon(uid)) {
        Ok(()) => 0,
        Err(_) => 1,
    }
}

async fn send(write: &mut tokio::net::unix::OwnedWriteHalf, value: &Wire) -> Result<(), String> {
    let mut bytes = serde_json::to_vec(value).map_err(|e| e.to_string())?;
    bytes.push(b'\n');
    tokio::time::timeout(Duration::from_secs(3), write.write_all(&bytes))
        .await
        .map_err(|_| "父进程无响应")?
        .map_err(|e| e.to_string())
}
fn validate_scope(scope: Vec<Identity>, uid: u32) -> Result<Vec<Identity>, String> {
    if scope.len() > 1024 {
        return Err("采集范围超过上限".into());
    }
    let mut system = sysinfo::System::new();
    let pids: Vec<_> = scope
        .iter()
        .map(|p| sysinfo::Pid::from_u32(p.pid))
        .collect();
    system.refresh_processes_specifics(
        sysinfo::ProcessesToUpdate::Some(&pids),
        true,
        sysinfo::ProcessRefreshKind::nothing()
            .with_user(sysinfo::UpdateKind::Always)
            .without_tasks(),
    );
    let mut scope: Vec<_> = scope
        .into_iter()
        .filter(|p| {
            system
                .process(sysinfo::Pid::from_u32(p.pid))
                .is_some_and(|v| {
                    v.start_time() == p.start_time
                        && v.user_id().is_some_and(|owner| **owner == uid)
                })
        })
        .collect();
    scope.sort();
    scope.dedup();
    Ok(scope)
}
async fn daemon(uid: u32) -> Result<(), String> {
    if uid == 0 {
        return Err("不支持 root 桌面会话".into());
    }
    let path = super::install::socket(uid);
    // /var/run is root-owned; unprivileged clients cannot replace the socket path.
    match std::fs::remove_file(&path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e.to_string()),
    }
    let listener = UnixListener::bind(&path).map_err(|e| e.to_string())?;
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))
        .map_err(|e| e.to_string())?;
    let cpath = std::ffi::CString::new(path.as_bytes()).map_err(|e| e.to_string())?;
    // SAFETY: valid NUL-terminated path; root grants socket access only to the installing uid.
    if unsafe { libc::chown(cpath.as_ptr(), uid, u32::MAX) } != 0 {
        return Err("无法设置服务访问权限".into());
    }
    loop {
        let (stream, _) = listener.accept().await.map_err(|e| e.to_string())?;
        if peer_uid(&stream)? != uid {
            continue;
        }
        // One client at a time; disconnecting the app drops and kills its capture subprocess.
        let _ = helper_connection(stream, uid).await;
    }
}
async fn helper_connection(stream: UnixStream, uid: u32) -> Result<(), String> {
    if peer_uid(&stream)? != uid {
        return Err("主程序身份不匹配".into());
    }
    let (read, mut write) = stream.into_split();
    let mut read = BoundedLines::new(BufReader::new(read), 65536);
    let (sender, mut receiver) = mpsc::channel::<Wire>(64);
    let mut scope = Vec::new();
    let mut capture = AbortTask(None);
    let mut heartbeat = tokio::time::Instant::now();
    let mut timer = tokio::time::interval(Duration::from_secs(1));
    send(&mut write, &Wire::Ready).await?;
    loop {
        tokio::select! {
            _ = timer.tick() => { if heartbeat.elapsed() > Duration::from_secs(10) { return Ok(()); } }
            line = read.next() => {
                let Some(line) = line? else { return Ok(()); };
                let requested: Vec<Identity> = serde_json::from_str(&line).map_err(|_| "采集指令无效")?;
                heartbeat = tokio::time::Instant::now();
                let next = validate_scope(requested, uid)?;
                if next != scope {
                    if let Some(task) = capture.0.take() { task.abort(); let _ = task.await; }
                    while receiver.try_recv().is_ok() {}
                    scope = next;
                    if !scope.is_empty() { capture.0 = Some(tokio::spawn(capture_scope(scope.clone(), sender.clone()))); }
                }
            }
            message = receiver.recv() => {
                if let Some(message) = message {
                    let failed = matches!(message, Wire::Error(_));
                    send(&mut write, &message).await?;
                    if failed { return Ok(()); }
                }
            }
        }
    }
}
fn filter(scope: &[Identity]) -> String {
    format!(
        "dir=out and ({})",
        scope
            .iter()
            .map(|p| format!("pid={}", p.pid))
            .collect::<Vec<_>>()
            .join(" or ")
    )
}
async fn capture_scope(scope: Vec<Identity>, sender: mpsc::Sender<Wire>) {
    let result = capture_loop(&scope, &sender).await;
    if let Err(error) = result {
        let _ = sender.send(Wire::Error(error)).await;
    }
}
async fn capture_loop(scope: &[Identity], sender: &mpsc::Sender<Wire>) -> Result<(), String> {
    let mut child = tokio::process::Command::new("/usr/sbin/tcpdump")
        .args([
            "-i",
            "pktap,all",
            "-nn",
            "-q",
            "-v",
            "-t",
            "-l",
            "-s",
            "128",
            "-k",
            "P",
            "--apple-oneline",
            "-Q",
            &filter(scope),
            "tcp or udp",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| "无法启动系统抓包工具")?;
    let mut read = BoundedLines::new(
        BufReader::new(child.stdout.take().ok_or("抓包输出不可用")?),
        8192,
    );
    let mut unparsed = 0;
    loop {
        let Some(input) = read.next().await? else {
            let _ = child.wait().await;
            return Err("系统抓包工具已退出，请重新连接服务".into());
        };
        let Some((pid, target, bytes)) = super::parse(input.trim()) else {
            unparsed += 1;
            if unparsed >= 100 {
                return Err("系统包元数据格式无法识别，已停止抓包".into());
            }
            continue;
        };
        unparsed = 0;
        let Some(identity) = scope.iter().find(|p| p.pid == pid) else {
            continue;
        };
        sender
            .send(Wire::Packet(Sample {
                pid,
                start_time: identity.start_time,
                target,
                bytes,
            }))
            .await
            .map_err(|_| "采集会话已关闭")?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn bounded_messages_survive_cancellation_and_reject_oversize() {
        let (mut write, read) = tokio::io::duplex(64);
        let mut read = BoundedLines::new(BufReader::new(read), 4);
        write.write_all(b"abc").await.unwrap();
        assert!(tokio::time::timeout(Duration::from_millis(10), read.next())
            .await
            .is_err());
        write.write_all(b"\n").await.unwrap();
        assert_eq!(read.next().await.unwrap().as_deref(), Some("abc\n"));
        write.write_all(b"12345").await.unwrap();
        assert!(read.next().await.is_err());
    }
    #[test]
    fn one_filter_covers_all_processes_without_shell_input() {
        assert_eq!(
            filter(&[
                Identity {
                    pid: 12,
                    start_time: 1
                },
                Identity {
                    pid: 34,
                    start_time: 2
                }
            ]),
            "dir=out and (pid=12 or pid=34)"
        );
    }
    #[tokio::test]
    async fn helper_stops_when_parent_disconnects_without_starting_capture() {
        let (client, server) = UnixStream::pair().unwrap();
        let uid = unsafe { libc::getuid() };
        let task = tokio::spawn(helper_connection(server, uid));
        let mut reader = BufReader::new(client);
        let mut line = String::new();
        reader.read_line(&mut line).await.unwrap();
        assert!(matches!(
            serde_json::from_str::<Wire>(&line).unwrap(),
            Wire::Ready
        ));
        drop(reader);
        tokio::time::timeout(Duration::from_secs(2), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
    #[test]
    fn scope_rejects_processes_owned_by_another_user_or_reused_pid() {
        let pid = std::process::id();
        let mut system = sysinfo::System::new();
        system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
        let start_time = system
            .process(sysinfo::Pid::from_u32(pid))
            .unwrap()
            .start_time();
        let identity = Identity { pid, start_time };
        let uid = unsafe { libc::getuid() };
        assert_eq!(
            validate_scope(vec![identity.clone()], uid).unwrap(),
            vec![identity.clone()]
        );
        assert!(validate_scope(vec![identity.clone()], uid + 1)
            .unwrap()
            .is_empty());
        assert!(validate_scope(
            vec![Identity {
                start_time: start_time + 1,
                ..identity
            }],
            uid
        )
        .unwrap()
        .is_empty());
    }
}
