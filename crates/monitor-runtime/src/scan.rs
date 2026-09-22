//! Bounded, read-only scanning of explicitly scoped application evidence directories.
use monitor_core::evidence::{audit, Finding};
use serde::Serialize;
use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

const MAX_FILE: u64 = 4 * 1024 * 1024;
const MAX_TOTAL: u64 = 32 * 1024 * 1024;
const MAX_ENTRIES: usize = 10_000;
const MAX_FINDINGS: usize = 500;

#[derive(Clone, Debug)]
pub struct Source {
    pub kind: String,
    pub root: PathBuf,
}
#[derive(Serialize)]
pub struct SourceReport {
    pub kind: String,
    pub root: String,
    pub status: String,
    pub files_read: usize,
    pub bytes_read: u64,
    pub skipped: usize,
    pub pending_files: usize,
    pub findings: Vec<FileFinding>,
    pub warnings: Vec<String>,
}
#[derive(Serialize)]
pub struct FileFinding {
    pub file: String,
    pub finding: Finding,
}
#[derive(Serialize)]
pub struct ScanReport {
    pub at_ms: u64,
    pub sources: Vec<SourceReport>,
    pub enforced: bool,
}

pub fn default_sources() -> Vec<Source> {
    let Some(home) = dirs::home_dir() else {
        return vec![];
    };
    let mut sources = vec![Source {
        kind: "zcode".into(),
        root: home.join(".zcode/v2/checkpoints"),
    }];
    #[cfg(target_os = "macos")]
    sources.push(Source {
        kind: "trae".into(),
        root: home.join("Library/Application Support/Trae CN/logs"),
    });
    #[cfg(target_os = "windows")]
    if let Some(appdata) = std::env::var_os("APPDATA") {
        sources.push(Source {
            kind: "trae".into(),
            root: PathBuf::from(appdata).join("Trae CN/logs"),
        });
    }
    #[cfg(target_os = "linux")]
    if let Some(config) = dirs::config_dir() {
        sources.push(Source {
            kind: "trae".into(),
            root: config.join("Trae CN/logs"),
        });
    }
    sources
}

pub fn scan(sources: &[Source]) -> ScanReport {
    ScanReport {
        at_ms: now_ms(),
        sources: sources.iter().map(scan_source).collect(),
        enforced: false,
    }
}

pub fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn warning(report: &mut SourceReport, message: String) {
    report.status = "partial".into();
    if report.warnings.len() < 32 {
        report.warnings.push(message);
    }
}

fn relative(root: &Path, path: &Path) -> String {
    path.strip_prefix(root)
        .unwrap_or(path)
        .to_string_lossy()
        .into_owned()
}

fn scan_source(source: &Source) -> SourceReport {
    let mut report = SourceReport {
        kind: source.kind.clone(),
        root: source.root.to_string_lossy().into_owned(),
        status: "complete".into(),
        files_read: 0,
        bytes_read: 0,
        skipped: 0,
        pending_files: 0,
        findings: vec![],
        warnings: vec![],
    };
    if source.kind != "trae" && source.kind != "zcode" {
        warning(&mut report, "不支持的证据类型".into());
        return report;
    }
    // Do not follow static links or reparse points. This is not a race-proof sandbox.
    match fs::symlink_metadata(&source.root) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            report.status = "not_found".into();
            return report;
        }
        Err(e) => {
            warning(&mut report, format!("无法访问证据目录: {}", e.kind()));
            return report;
        }
        Ok(meta) if linked(&meta) || !meta.is_dir() => {
            warning(&mut report, "根路径不是普通目录或是链接".into());
            return report;
        }
        _ => {}
    }
    let mut stack = vec![(source.root.clone(), 0)];
    let mut entries = 0;
    while let Some((dir, depth)) = stack.pop() {
        if depth > 8 {
            warning(&mut report, "达到目录深度上限".into());
            continue;
        }
        let listing = match fs::read_dir(&dir) {
            Ok(listing) => listing,
            Err(e) => {
                warning(&mut report, format!("目录读取失败: {}", e.kind()));
                continue;
            }
        };
        for item in listing {
            entries += 1;
            if entries > MAX_ENTRIES {
                warning(&mut report, "达到 10000 个目录项上限，结果不完整".into());
                return report;
            }
            let item = match item {
                Ok(item) => item,
                Err(e) => {
                    warning(&mut report, format!("目录项读取失败: {}", e.kind()));
                    continue;
                }
            };
            let path = item.path();
            let meta = match fs::symlink_metadata(&path) {
                Ok(meta) => meta,
                Err(e) => {
                    warning(&mut report, format!("文件状态读取失败: {}", e.kind()));
                    continue;
                }
            };
            if linked(&meta) {
                report.skipped += 1;
                warning(&mut report, "跳过符号链接 / reparse point".into());
                continue;
            }
            if meta.is_dir() {
                stack.push((path, depth + 1));
                continue;
            }
            if !meta.is_file() {
                continue;
            }
            if source.kind == "zcode"
                && path
                    .strip_prefix(&source.root)
                    .is_ok_and(|p| p.components().any(|c| c.as_os_str() == "pending"))
            {
                report.pending_files += 1; // Count only; never read snapshot ciphertext.
                continue;
            }
            let name = item.file_name();
            let name = name.to_string_lossy();
            let matched = if source.kind == "zcode" {
                name == "state.json"
            } else {
                name.starts_with("ckg_0_") && name.ends_with("_stdout.log")
            };
            if !matched {
                continue;
            }
            if meta.len() > MAX_FILE || report.bytes_read.saturating_add(meta.len()) > MAX_TOTAL {
                report.skipped += 1;
                warning(
                    &mut report,
                    "达到文件 4 MiB / 总读取 32 MiB 上限，部分证据未读取".into(),
                );
                continue;
            }
            let mut bytes = vec![];
            let result = fs::File::open(&path)
                .and_then(|file| file.take(MAX_FILE + 1).read_to_end(&mut bytes));
            if result.is_err() || bytes.len() as u64 > MAX_FILE {
                warning(&mut report, "文件读取失败或读取期间增大超过上限".into());
                continue;
            }
            report.bytes_read += bytes.len() as u64;
            if report.bytes_read > MAX_TOTAL {
                warning(&mut report, "总读取达到上限".into());
                return report;
            }
            report.files_read += 1;
            let text = match std::str::from_utf8(&bytes) {
                Ok(text) => text,
                Err(_) => {
                    warning(&mut report, "非 UTF-8 证据未解析".into());
                    continue;
                }
            };
            match audit(&source.kind, text) {
                Ok(findings) => {
                    for finding in findings {
                        if report.findings.len() >= MAX_FINDINGS {
                            warning(&mut report, "达到 500 条结果上限".into());
                            return report;
                        }
                        report.findings.push(FileFinding {
                            file: relative(&source.root, &path),
                            finding,
                        });
                    }
                }
                Err(e) => warning(&mut report, format!("证据解析不完整: {e}")),
            }
        }
    }
    report
        .findings
        .sort_by(|a, b| a.file.cmp(&b.file).then(a.finding.rule.cmp(b.finding.rule)));
    report
}

fn linked(meta: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        meta.file_attributes() & 0x400 != 0
    }
    #[cfg(not(windows))]
    {
        meta.file_type().is_symlink()
    }
}
