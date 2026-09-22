//! Temporal review signals, never proof of a read or an upload.
use crate::{discovery::AgentProcess, sensor::Activity};
use std::{
    collections::{HashMap, HashSet},
    net::SocketAddr,
};

const WINDOW_MS: u64 = 30_000;
type Identity = (String, u32, u64);

#[derive(Default)]
pub struct EgressTracker {
    sources: HashMap<Identity, (u64, String)>,
}
impl EgressTracker {
    /// `now` is monotonic milliseconds. Only enabled, live processes may retain evidence.
    pub fn observe(
        &mut self,
        now: u64,
        monitored: &[AgentProcess],
        activities: &[Activity],
    ) -> Vec<Activity> {
        let by_pid: HashMap<_, _> = monitored.iter().map(|p| (p.pid, p)).collect();
        self.sources.retain(|(agent, pid, start), (at, _)| {
            now.saturating_sub(*at) <= WINDOW_MS
                && by_pid
                    .get(pid)
                    .is_some_and(|p| p.start_time == *start && p.agent_id == *agent)
        });
        for a in activities.iter().filter(|a| a.kind == "source_open") {
            let Some(p) = by_pid.get(&a.pid).filter(|p| p.agent_id == a.agent_id) else {
                continue;
            };
            let key = (p.agent_id.clone(), p.pid, p.start_time);
            if self.sources.len() < 4096 || self.sources.contains_key(&key) {
                self.sources.insert(key, (now, a.target.clone()));
            }
        }
        let mut seen = HashSet::new();
        activities.iter().filter(|a| a.kind == "connection").filter_map(|a| {
            let p = by_pid.get(&a.pid).filter(|p| p.agent_id == a.agent_id)?;
            // lsof -nP supplies numeric addresses. Never infer egress from listeners/local IPC.
            let remote: SocketAddr = a.target.parse().ok()?;
            let ip = match remote.ip() {
                std::net::IpAddr::V6(ip) => ip.to_ipv4_mapped().map(std::net::IpAddr::V4).unwrap_or(ip.into()),
                ip => ip,
            };
            if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || remote.port() == 0 { return None; }
            let (at, path) = self.sources.get(&(p.agent_id.clone(), p.pid, p.start_time))?;
            if !seen.insert((p.pid, a.target.clone())) { return None; }
            Some(Activity {
                pid: p.pid, agent: p.agent.clone(), agent_id: p.agent_id.clone(),
                kind: "source_egress_signal".into(), target: a.target.clone(),
                assessment: format!("需核查：同一进程在 {} 秒前观察到源码候选文件打开：{}；本轮观察到非本机回环连接 {}。仅为时间关联，连接可能早已存在，未确认读取、发送字节或源码上传，未执行阻断。", now.saturating_sub(*at) / 1000, path, a.target),
            })
        }).take(2000).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn process(pid: u32, start_time: u64) -> AgentProcess {
        AgentProcess {
            pid,
            start_time,
            parent: None,
            name: "test".into(),
            executable: "/test".into(),
            agent: "Test".into(),
            agent_id: "known:Test".into(),
            inherited: false,
        }
    }
    fn activity(pid: u32, kind: &str, target: &str) -> Activity {
        Activity {
            pid,
            agent: "Test".into(),
            agent_id: "known:Test".into(),
            kind: kind.into(),
            target: target.into(),
            assessment: String::new(),
        }
    }
    #[test]
    fn correlates_across_samples_but_expires() {
        let mut tracker = EgressTracker::default();
        let p = [process(1, 10)];
        assert!(tracker
            .observe(0, &p, &[activity(1, "source_open", "/project/main.rs")])
            .is_empty());
        let network = [activity(1, "connection", "203.0.113.1:443")];
        let signals = tracker.observe(5000, &p, &network);
        assert_eq!(signals.len(), 1);
        assert!(signals[0].assessment.contains("5 秒前"));
        assert!(signals[0].assessment.contains("/project/main.rs"));
        assert!(signals[0].assessment.contains("未确认"));
        assert!(tracker.observe(30001, &p, &network).is_empty());
    }
    #[test]
    fn never_crosses_process_identity_or_disabled_selection() {
        for next in [vec![process(2, 10)], vec![process(1, 11)], vec![]] {
            let mut tracker = EgressTracker::default();
            tracker.observe(
                0,
                &[process(1, 10)],
                &[activity(1, "source_open", "/project/main.rs")],
            );
            assert!(tracker
                .observe(
                    1000,
                    &next,
                    &[
                        activity(1, "connection", "203.0.113.1:443"),
                        activity(2, "connection", "203.0.113.1:443")
                    ]
                )
                .is_empty());
            assert!(tracker
                .observe(
                    2000,
                    &[process(1, 10)],
                    &[activity(1, "connection", "203.0.113.1:443")]
                )
                .is_empty());
        }
    }
    #[test]
    fn ignores_local_endpoints_and_deduplicates_connections() {
        let mut tracker = EgressTracker::default();
        let p = [process(1, 10)];
        tracker.observe(0, &p, &[activity(1, "source_open", "/project/main.rs")]);
        for target in [
            "127.0.0.1:443",
            "[::1]:443",
            "[::ffff:127.0.0.1]:443",
            "0.0.0.0:0",
            "224.0.0.1:443",
            "*:443",
        ] {
            assert!(tracker
                .observe(1, &p, &[activity(1, "connection", target)])
                .is_empty());
        }
        let a = activity(1, "connection", "[2001:db8::1]:443");
        assert_eq!(tracker.observe(2, &p, &[a.clone(), a]).len(), 1);
    }
}
