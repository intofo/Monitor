//! Local monitoring preferences. Atomic replacement prevents partially written selections.
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Mutex,
};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct MonitorConfig {
    pub revision: u64,
    pub packet_capture_enabled: bool,
    pub close_to_tray: bool,
    pub protection: monitor_core::protection::ProtectionPolicy,
    pub agent_protection: BTreeMap<String, AgentProtection>,
    pub jev: crate::jev::JevSettings,
    pub enabled: BTreeMap<String, bool>,
    pub custom_agents: Vec<CustomAgent>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AgentProtection {
    pub policy: monitor_core::protection::ProtectionPolicy,
    pub ai_approved_endpoint: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CustomAgent {
    pub id: String,
    pub name: String,
    pub executable: String,
}
impl MonitorConfig {
    pub fn enabled(&self, id: &str) -> bool {
        self.enabled
            .get(id)
            .copied()
            .unwrap_or(id != "unclassified")
    }
}
pub struct ConfigStore {
    value: Mutex<MonitorConfig>,
    path: Option<PathBuf>,
}
impl ConfigStore {
    pub fn memory() -> Self {
        Self {
            value: Mutex::new(MonitorConfig::default()),
            path: None,
        }
    }
    pub fn open(path: PathBuf) -> Result<Self, String> {
        let mut value: MonitorConfig = match std::fs::read(&path) {
            Ok(bytes) if bytes.len() <= 1024 * 1024 => serde_json::from_slice(&bytes)
                .map_err(|e| format!("配置文件无效，未覆盖原文件: {e}"))?,
            Ok(_) => return Err("配置文件超过 1 MiB".into()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => MonitorConfig::default(),
            Err(e) => return Err(e.to_string()),
        };
        // Project contexts are runtime observations, not durable grants.
        let had_projects = value
            .agent_protection
            .values()
            .any(|v| !v.policy.project_directories.is_empty());
        for settings in value.agent_protection.values_mut() {
            settings.policy.project_directories.clear();
        }
        let store = Self {
            value: Mutex::new(value),
            path: Some(path),
        };
        if had_projects || !store.path.as_ref().unwrap().exists() {
            store.persist(&store.load()?)?;
        }
        Ok(store)
    }
    pub fn load(&self) -> Result<MonitorConfig, String> {
        self.value
            .lock()
            .map(|v| v.clone())
            .map_err(|_| "配置锁异常".into())
    }
    pub fn update(
        &self,
        change: impl FnOnce(&mut MonitorConfig) -> Result<(), String>,
    ) -> Result<MonitorConfig, String> {
        let mut guard = self.value.lock().map_err(|_| "配置锁异常")?;
        let mut next = guard.clone();
        change(&mut next)?;
        next.revision = next.revision.checked_add(1).ok_or("配置版本超限")?;
        if next.enabled.len() > 2048 || next.custom_agents.len() > 256 {
            return Err("监测配置数量超过上限".into());
        }
        next.protection = next.protection.validate()?;
        if next.agent_protection.len() > 2048 {
            return Err("Too many Agent policies".into());
        }
        for settings in next.agent_protection.values_mut() {
            settings.policy.project_directories.clear();
            settings.policy = settings.policy.clone().validate()?;
        }
        self.persist(&next)?;
        *guard = next.clone();
        Ok(next)
    }
    fn persist(&self, value: &MonitorConfig) -> Result<(), String> {
        use std::io::Write;
        let Some(path) = &self.path else {
            return Ok(());
        };
        let parent = path.parent().ok_or("配置目录无效")?;
        let mut tmp = tempfile::NamedTempFile::new_in(parent).map_err(|e| e.to_string())?;
        serde_json::to_writer_pretty(&mut tmp, value).map_err(|e| e.to_string())?;
        tmp.write_all(b"\n").map_err(|e| e.to_string())?;
        tmp.as_file().sync_all().map_err(|e| e.to_string())?;
        tmp.persist(path).map_err(|e| e.to_string())?;
        Ok(())
    }
}
pub fn home_root() -> Result<PathBuf, String> {
    dirs::home_dir()
        .map(|p| p.join(".monitor"))
        .ok_or("无法定位用户目录".into())
}
/// SQLite VACUUM INTO includes committed WAL data; the old database is never removed.
pub fn migrate_legacy(source: &Path, destination: &Path) -> Result<(), String> {
    if destination.exists() || !source.is_file() {
        return Ok(());
    }
    let parent = destination.parent().ok_or("数据库目录无效")?;
    std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    let tmp = parent.join(format!("migration-{}.sqlite3", uuid::Uuid::new_v4()));
    let result = (|| {
        let db = rusqlite::Connection::open_with_flags(
            source,
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY,
        )
        .map_err(|e| e.to_string())?;
        db.busy_timeout(std::time::Duration::from_secs(2))
            .map_err(|e| e.to_string())?;
        db.execute("VACUUM INTO ?1", [tmp.to_string_lossy().as_ref()])
            .map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
        }
        match std::fs::hard_link(&tmp, destination) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(e) => Err(e.to_string()),
        }
    })();
    let _ = std::fs::remove_file(tmp);
    result
}

pub fn new_id() -> String {
    uuid::Uuid::new_v4().to_string()
}
