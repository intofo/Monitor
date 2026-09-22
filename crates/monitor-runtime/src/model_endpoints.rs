//! Read only configuration files matched to the Agent. Extract endpoint fields,
//! never return API keys or whole config contents. Discovery is not approval.
use monitor_core::protection::{NetworkGrant, Transport};
use serde::Serialize;
use std::{
    io::Read,
    path::{Path, PathBuf},
};
#[derive(Clone, Serialize)]
pub struct Candidate {
    pub origin: String,
    pub source: String,
    pub grant: NetworkGrant,
}
#[derive(Default, Serialize)]
pub struct Discovery {
    pub candidates: Vec<Candidate>,
    pub unreadable: Vec<String>,
}
fn endpoint_key(key: &str) -> bool {
    matches!(
        key.to_ascii_lowercase().as_str(),
        "base_url"
            | "baseurl"
            | "api_base"
            | "api_url"
            | "apiurl"
            | "apiendpoint"
            | "openai_base_url"
            | "anthropic_base_url"
            | "google_gemini_base_url"
            | "gemini_api_base_url"
    )
}
fn endpoint(value: &str, source: &str) -> Option<Candidate> {
    let url = url::Url::parse(value).ok()?;
    if !matches!(url.scheme(), "https" | "http")
        || !url.username().is_empty()
        || url.password().is_some()
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return None;
    }
    let host = monitor_core::normalize_host(url.host_str()?.trim_matches(['[', ']'])).ok()?;
    Some(Candidate {
        origin: url.origin().ascii_serialization(),
        source: source.into(),
        grant: NetworkGrant {
            host,
            port: url.port_or_known_default()?,
            transport: Transport::Tcp,
        },
    })
}
fn visit(value: &serde_json::Value, source: &str, depth: usize, out: &mut Vec<Candidate>) {
    if depth > 24 || out.len() >= 128 {
        return;
    }
    match value {
        serde_json::Value::Object(map) => {
            for (key, value) in map {
                if endpoint_key(key) {
                    if let Some(candidate) =
                        value.as_str().and_then(|value| endpoint(value, source))
                    {
                        if !out.iter().any(|c| c.origin == candidate.origin) {
                            out.push(candidate);
                        }
                    }
                } else {
                    visit(value, source, depth + 1, out);
                }
            }
        }
        serde_json::Value::Array(values) => {
            for value in values {
                visit(value, source, depth + 1, out);
            }
        }
        _ => {}
    }
}
pub fn parse(contents: &str, extension: &str, source: &str) -> Result<Vec<Candidate>, String> {
    if contents.len() > 262144 {
        return Err("Configuration exceeds 256 KiB".into());
    }
    let value = if extension == "toml" {
        let value =
            toml::from_str::<toml::Value>(contents).map_err(|_| "Invalid TOML configuration")?;
        serde_json::to_value(value).map_err(|_| "Invalid configuration")?
    } else {
        serde_json::from_str(contents).map_err(|_| "Invalid JSON configuration")?
    };
    let mut out = Vec::new();
    visit(&value, source, 0, &mut out);
    Ok(out)
}
pub fn paths(home: &Path, agent: &str, projects: &[String]) -> Vec<PathBuf> {
    let relative: &[&str] = match agent {
        "known:Codex" => &[".codex/config.toml"],
        "known:Claude Code" => &[".claude/settings.json", ".claude/settings.local.json"],
        "known:Gemini CLI" => &[".gemini/settings.json"],
        "known:OpenCode" => &[".config/opencode/opencode.json"],
        _ => &[],
    };
    let mut paths: Vec<_> = relative.iter().map(|p| home.join(p)).collect();
    for project in projects.iter().take(128) {
        for rel in relative {
            if !rel.starts_with(".config/") {
                paths.push(Path::new(project).join(rel));
            }
        }
    }
    paths
}
pub fn discover(paths: &[PathBuf]) -> Discovery {
    let mut result = Discovery::default();
    for path in paths.iter().take(256) {
        if !path.exists() {
            continue;
        }
        let read = || -> Result<Vec<Candidate>, String> {
            let mut options = std::fs::OpenOptions::new();
            options.read(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.custom_flags(libc_flag_no_follow());
            }
            let file = options
                .open(path)
                .map_err(|_| "Cannot open configuration")?;
            if !file
                .metadata()
                .map_err(|_| "Cannot inspect configuration")?
                .is_file()
            {
                return Err("Not a regular file".into());
            }
            let mut contents = String::new();
            file.take(262145)
                .read_to_string(&mut contents)
                .map_err(|_| "Cannot read configuration")?;
            parse(
                &contents,
                path.extension().and_then(|e| e.to_str()).unwrap_or("json"),
                &path.to_string_lossy(),
            )
        };
        match read() {
            Ok(candidates) => {
                for candidate in candidates {
                    if result.candidates.len() < 128
                        && !result
                            .candidates
                            .iter()
                            .any(|c| c.origin == candidate.origin)
                    {
                        result.candidates.push(candidate);
                    }
                }
            }
            Err(_) => result.unreadable.push(path.to_string_lossy().into_owned()),
        }
    }
    result
}
#[cfg(unix)]
fn libc_flag_no_follow() -> i32 {
    libc::O_NOFOLLOW | libc::O_NONBLOCK
}
