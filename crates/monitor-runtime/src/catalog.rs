use crate::{
    discovery::{AgentProcess, Installation},
    settings::MonitorConfig,
};
use serde::Serialize;
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize)]
pub struct AgentEntry {
    pub id: String,
    pub name: String,
    pub paths: Vec<String>,
    pub installed: bool,
    pub running: usize,
    pub enabled: bool,
    pub custom: bool,
}
pub fn build(
    processes: &[AgentProcess],
    installations: &[Installation],
    config: &MonitorConfig,
) -> Vec<AgentEntry> {
    let mut entries = BTreeMap::<String, AgentEntry>::new();
    for item in installations {
        let id = format!("known:{}", item.agent);
        let entry = entries
            .entry(id.clone())
            .or_insert_with(|| entry(&id, &item.agent, config, false));
        entry.installed = true;
        entry.paths.push(item.path.clone());
    }
    for custom in &config.custom_agents {
        let entry = entries
            .entry(custom.id.clone())
            .or_insert_with(|| entry(&custom.id, &custom.name, config, true));
        entry.installed = std::path::Path::new(&custom.executable).is_file();
        entry.paths.push(custom.executable.clone());
    }
    for process in processes {
        let entry = entries.entry(process.agent_id.clone()).or_insert_with(|| {
            entry(
                &process.agent_id,
                &process.agent,
                config,
                process.agent_id.starts_with("custom:"),
            )
        });
        entry.running += 1;
        if !process.inherited
            && !process.executable.is_empty()
            && process.agent_id != "unclassified"
        {
            entry.paths.push(process.executable.clone());
        }
    }
    let mut result: Vec<_> = entries.into_values().collect();
    for item in &mut result {
        item.paths.sort();
        item.paths.dedup();
    }
    result.sort_by(|a, b| {
        (a.id == "unclassified")
            .cmp(&(b.id == "unclassified"))
            .then(a.name.cmp(&b.name))
    });
    result
}
fn entry(id: &str, name: &str, config: &MonitorConfig, custom: bool) -> AgentEntry {
    AgentEntry {
        id: id.into(),
        name: name.into(),
        paths: vec![],
        installed: false,
        running: 0,
        enabled: config.enabled(id),
        custom,
    }
}

/// Read only a discovered application's native icon; no network or executable launch.
pub async fn native_icon(paths: &[String]) -> Result<Option<String>, String> {
    #[cfg(target_os = "macos")]
    {
        use base64::{engine::general_purpose::STANDARD, Engine as _};
        use std::{
            hash::{Hash, Hasher},
            path::Path,
        };
        for path in paths {
            let Some(bundle) = Path::new(path)
                .ancestors()
                .find(|p| p.extension().is_some_and(|e| e == "app"))
            else {
                continue;
            };
            let Ok(info) = plist::Value::from_file(bundle.join("Contents/Info.plist")) else {
                continue;
            };
            let Some(name) = info
                .as_dictionary()
                .and_then(|v| v.get("CFBundleIconFile"))
                .and_then(|v| v.as_string())
            else {
                continue;
            };
            if name.contains(['/', '\\']) || name == "." || name == ".." {
                continue;
            }
            let mut icon = bundle.join("Contents/Resources").join(name);
            if icon.extension().is_none() {
                icon.set_extension("icns");
            }
            let Ok(meta) = icon.metadata() else { continue };
            if meta.len() > 8 * 1024 * 1024 {
                continue;
            }
            let mut hash = std::collections::hash_map::DefaultHasher::new();
            icon.hash(&mut hash);
            meta.modified().ok().hash(&mut hash);
            meta.len().hash(&mut hash);
            let root = crate::settings::home_root()?.join("icons");
            std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
            let cache = root.join(format!("{:x}.png", hash.finish()));
            if !cache.exists() {
                let tmp = tempfile::Builder::new()
                    .suffix(".png")
                    .tempfile_in(&root)
                    .map_err(|e| e.to_string())?;
                let mut command = tokio::process::Command::new("/usr/bin/sips");
                command
                    .kill_on_drop(true)
                    .args(["-s", "format", "png", "-Z", "64"])
                    .arg(&icon)
                    .arg("--out")
                    .arg(tmp.path())
                    .stdout(std::process::Stdio::null())
                    .stderr(std::process::Stdio::null());
                let status =
                    tokio::time::timeout(std::time::Duration::from_secs(2), command.status()).await;
                if !matches!(status, Ok(Ok(s)) if s.success()) {
                    continue;
                }
                tmp.persist(&cache).map_err(|e| e.to_string())?;
            }
            if cache.metadata().map_err(|e| e.to_string())?.len() > 128 * 1024 {
                continue;
            }
            let bytes = std::fs::read(cache).map_err(|e| e.to_string())?;
            if !bytes.starts_with(b"\x89PNG\r\n\x1a\n") {
                continue;
            }
            return Ok(Some(format!(
                "data:image/png;base64,{}",
                STANDARD.encode(bytes)
            )));
        }
    }
    #[cfg(not(target_os = "macos"))]
    let _ = paths;
    Ok(None)
}
