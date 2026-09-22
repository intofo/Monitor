use rusqlite::{params, Connection};
use serde::Serialize;
use std::{
    path::{Path, PathBuf},
    sync::Mutex,
};

pub struct Audit {
    db: Mutex<Connection>,
    pub preferences: crate::settings::ConfigStore,
}
#[derive(Clone, Debug, Serialize)]
pub struct AuditEvent {
    pub id: i64,
    pub at_ms: u64,
    pub category: String,
    pub actor: String,
    pub target: String,
    pub detail: String,
    pub enforced: bool,
    pub agent_id: Option<String>,
    pub agent_name: Option<String>,
    pub attribution: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct EventScope {
    pub agent_id: String,
    pub agent_name: String,
    pub attribution: String,
}
pub struct NewEvent<'a> {
    pub category: &'a str,
    pub actor: &'a str,
    pub target: &'a str,
    pub detail: &'a str,
    pub enforced: bool,
}
impl Audit {
    pub fn default_path() -> Result<PathBuf, String> {
        let root = crate::settings::home_root()?;
        std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&root, std::fs::Permissions::from_mode(0o700))
                .map_err(|e| e.to_string())?;
        }
        let path = root.join("audit.sqlite3");
        if let Some(old) = dirs::data_local_dir() {
            crate::settings::migrate_legacy(&old.join("AgentMonitor/audit.sqlite3"), &path)?;
        }
        Ok(path)
    }
    pub fn open(path: &Path) -> Result<Self, String> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                std::fs::set_permissions(parent, std::fs::Permissions::from_mode(0o700))
                    .map_err(|e| e.to_string())?;
            }
        }
        let db = Connection::open(path).map_err(|e| e.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))
                .map_err(|e| e.to_string())?;
        }
        let mut audit = Self::initialize(db)?;
        audit.preferences = crate::settings::ConfigStore::open(path.with_file_name("config.json"))?;
        Ok(audit)
    }
    pub fn memory() -> Result<Self, String> {
        Self::initialize(Connection::open_in_memory().map_err(|e| e.to_string())?)
    }
    fn initialize(db: Connection) -> Result<Self, String> {
        db.busy_timeout(std::time::Duration::from_secs(2))
            .map_err(|e| e.to_string())?;
        db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA journal_size_limit=1048576; PRAGMA max_page_count=16384;
          CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT, at_ms INTEGER NOT NULL, category TEXT NOT NULL, actor TEXT NOT NULL, target TEXT NOT NULL, detail TEXT NOT NULL, enforced INTEGER NOT NULL);
          CREATE INDEX IF NOT EXISTS events_category ON events(category,id);
          CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY,value TEXT NOT NULL);").map_err(|e| e.to_string())?;
        let columns = {
            let mut q = db
                .prepare("PRAGMA table_info(events)")
                .map_err(|e| e.to_string())?;
            let rows = q
                .query_map([], |r| r.get::<_, String>(1))
                .map_err(|e| e.to_string())?;
            rows.collect::<Result<Vec<_>, _>>()
                .map_err(|e| e.to_string())?
        };
        for (name, sql) in [
            ("agent_id", "ALTER TABLE events ADD COLUMN agent_id TEXT"),
            (
                "agent_name",
                "ALTER TABLE events ADD COLUMN agent_name TEXT",
            ),
            (
                "attribution",
                "ALTER TABLE events ADD COLUMN attribution TEXT NOT NULL DEFAULT 'unassigned'",
            ),
        ] {
            if !columns.iter().any(|c| c == name) {
                db.execute_batch(sql).map_err(|e| e.to_string())?;
            }
        }
        db.execute_batch("CREATE INDEX IF NOT EXISTS events_agent ON events(agent_id,id)")
            .map_err(|e| e.to_string())?;
        Ok(Self {
            db: Mutex::new(db),
            preferences: crate::settings::ConfigStore::memory(),
        })
    }
    pub fn append(
        &self,
        category: &str,
        actor: &str,
        target: &str,
        detail: &str,
        enforced: bool,
    ) -> Result<(), String> {
        self.append_for(
            &EventScope {
                agent_id: String::new(),
                agent_name: String::new(),
                attribution: "unassigned".into(),
            },
            NewEvent {
                category,
                actor,
                target,
                detail,
                enforced,
            },
        )
    }
    pub fn append_for(&self, scope: &EventScope, event: NewEvent<'_>) -> Result<(), String> {
        let NewEvent {
            category,
            actor,
            target,
            detail,
            enforced,
        } = event;
        if scope.agent_id.len() > 4096
            || scope.agent_name.len() > 256
            || scope.attribution.len() > 64
        {
            return Err("Agent 标识超过上限".into());
        }
        if category.len() > 64 || actor.len() > 1024 || target.len() > 4096 || detail.len() > 4096 {
            return Err("审计字段超过上限".into());
        }
        let mut db = self.db.lock().map_err(|_| "审计锁异常")?;
        let tx = db.transaction().map_err(|e| e.to_string())?;
        tx.execute("INSERT INTO events(at_ms,category,actor,target,detail,enforced,agent_id,agent_name,attribution) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)", params![crate::scan::now_ms() as i64,category,actor,target,detail,enforced,if scope.agent_id.is_empty() { None } else { Some(&scope.agent_id) },if scope.agent_name.is_empty() { None } else { Some(&scope.agent_name) },scope.attribution]).map_err(|e| e.to_string())?;
        tx.execute(
            "DELETE FROM events WHERE id <= (SELECT COALESCE(MAX(id),0)-10000 FROM events)",
            [],
        )
        .map_err(|e| e.to_string())?;
        tx.commit().map_err(|e| e.to_string())
    }
    /// Stream the retained audit to a new local file. Never overwrite an existing file.
    pub fn export_to(&self, path: &Path, blocked_only: bool) -> Result<usize, String> {
        self.export_filtered(path, blocked_only, None)
    }
    pub fn export_filtered(
        &self,
        path: &Path,
        blocked_only: bool,
        agent_id: Option<&str>,
    ) -> Result<usize, String> {
        use std::io::Write;
        if !path.is_absolute() {
            return Err("请选择绝对导出路径".into());
        }
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let file = options
            .open(path)
            .map_err(|e| format!("无法创建导出文件（不会覆盖已有文件）: {e}"))?;
        let result = (|| -> Result<usize, String> {
            let mut writer = std::io::BufWriter::new(file);
            let scope = if blocked_only {
                "enforced_blocks"
            } else {
                "all_retained_events"
            };
            write!(
                &mut writer,
                "{{\"schema_version\":1,\"scope\":\"{scope}\",\"exported_at_ms\":{},\"agent_id\":{},\"events\":[",
                crate::scan::now_ms(),
                serde_json::to_string(&agent_id).map_err(|e|e.to_string())?
            )
            .map_err(|e| e.to_string())?;
            let db = self.db.lock().map_err(|_| "审计锁异常")?;
            let mut query=db.prepare("SELECT id,at_ms,category,actor,target,detail,enforced,agent_id,agent_name,attribution FROM events WHERE (?1=0 OR (category='blocked' AND enforced=1)) AND (?2 IS NULL OR COALESCE(agent_id,'')=?2) ORDER BY id DESC LIMIT 10000").map_err(|e|e.to_string())?;
            let rows = query
                .query_map(params![blocked_only, agent_id], |r| {
                    Ok(AuditEvent {
                        id: r.get(0)?,
                        at_ms: r.get::<_, i64>(1)? as u64,
                        category: r.get(2)?,
                        actor: r.get(3)?,
                        target: r.get(4)?,
                        detail: r.get(5)?,
                        enforced: r.get(6)?,
                        agent_id: r.get(7)?,
                        agent_name: r.get(8)?,
                        attribution: r.get(9)?,
                    })
                })
                .map_err(|e| e.to_string())?;
            let mut count = 0;
            for row in rows {
                let event = row.map_err(|e| e.to_string())?;
                if count > 0 {
                    writer.write_all(b",").map_err(|e| e.to_string())?;
                }
                serde_json::to_writer(&mut writer, &event).map_err(|e| e.to_string())?;
                count += 1;
            }
            writer.write_all(b"]}\n").map_err(|e| e.to_string())?;
            writer.flush().map_err(|e| e.to_string())?;
            writer.get_ref().sync_all().map_err(|e| e.to_string())?;
            Ok(count)
        })();
        result.map_err(|e| format!("导出失败，所选位置可能留有不完整的新文件: {e}"))
    }
    pub fn recent(&self, blocked_only: bool) -> Result<Vec<AuditEvent>, String> {
        self.recent_filtered(blocked_only, None)
    }
    pub fn recent_filtered(
        &self,
        blocked_only: bool,
        agent_id: Option<&str>,
    ) -> Result<Vec<AuditEvent>, String> {
        let db = self.db.lock().map_err(|_| "审计锁异常")?;
        let mut q = db.prepare("SELECT id,at_ms,category,actor,target,detail,enforced,agent_id,agent_name,attribution FROM events WHERE (?1 = 0 OR (category='blocked' AND enforced=1)) AND (?2 IS NULL OR COALESCE(agent_id,'')=?2) ORDER BY id DESC LIMIT 200").map_err(|e| e.to_string())?;
        let rows = q
            .query_map(params![blocked_only, agent_id], |r| {
                Ok(AuditEvent {
                    id: r.get(0)?,
                    at_ms: r.get::<_, i64>(1)? as u64,
                    category: r.get(2)?,
                    actor: r.get(3)?,
                    target: r.get(4)?,
                    detail: r.get(5)?,
                    enforced: r.get(6)?,
                    agent_id: r.get(7)?,
                    agent_name: r.get(8)?,
                    attribution: r.get(9)?,
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }
    pub fn agent_groups(&self) -> Result<Vec<EventScope>, String> {
        let db = self.db.lock().map_err(|_| "审计锁异常")?;
        let mut query = db.prepare("SELECT agent_id, MAX(agent_name) FROM events WHERE agent_id IS NOT NULL GROUP BY agent_id ORDER BY MAX(agent_name)").map_err(|e|e.to_string())?;
        let rows = query
            .query_map([], |r| {
                Ok(EventScope {
                    agent_id: r.get(0)?,
                    agent_name: r.get(1)?,
                    attribution: "group".into(),
                })
            })
            .map_err(|e| e.to_string())?;
        rows.collect::<Result<Vec<_>, _>>()
            .map_err(|e| e.to_string())
    }
}
