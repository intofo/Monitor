//! Read-only parsers for user-supplied evidence, not claims of independent verification.
use regex::Regex;
use serde::Serialize;
use std::sync::LazyLock;

#[derive(Debug, Serialize)]
pub struct Finding {
    pub rule: &'static str,
    pub summary: String,
    pub strength: &'static str,
    pub limitation: &'static str,
}

pub fn endpoint_signal(host: &str, path: Option<&str>) -> Option<String> {
    let path = path?.split('?').next()?;
    match (host, path) {
        ("trae-api-cn.mchost.guru", "/api/ide/v1/knowledgebase/uploadFileIDs") => {
            Some("TRAE-CKG-001：命中远程索引文件标识接口；接口命中本身不证明文件正文已上传".into())
        }
        ("zcode.z.ai", "/api/v1/snapshot/upload-credential") => Some(
            "ZCODE-SNAPSHOT-001：命中快照上传凭证接口；可在后续动态存储上传前识别准备行为".into(),
        ),
        _ => None,
    }
}

static UPLOAD: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"total files:\s*(\d+),\s*total uploaded files:\s*(\d+),\s*total failed files:\s*(\d+)",
    )
    .expect("static pattern")
});

pub fn audit(kind: &str, input: &str) -> Result<Vec<Finding>, String> {
    if input.len() > 4 * 1024 * 1024 {
        return Err("证据输入超过 4 MiB".into());
    }
    let mut findings = Vec::new();
    match kind {
        "trae" => {
            // Bound returned results; never copy project paths or raw log lines to output.
            for line in input.lines() {
                if !line.contains("[CollectFilesAndRemoteEmbeddingStep]") {
                    continue;
                }
                if let Some(caps) = UPLOAD.captures(line) {
                    let total = caps[1].parse::<u64>().map_err(|_| "计数溢出")?;
                    let uploaded = caps[2].parse::<u64>().map_err(|_| "计数溢出")?;
                    let failed = caps[3].parse::<u64>().map_err(|_| "计数溢出")?;
                    if uploaded.saturating_add(failed) > total {
                        return Err("上传统计不一致".into());
                    }
                    if uploaded > 0 {
                        findings.push(Finding { rule: "TRAE-LOG-001", summary: format!("远程 embedding 日志自报：共 {total} 个文件，已上传 {uploaded} 个，失败 {failed} 个"),
                            strength: "历史上传日志证据", limitation: "应用自报统计，不等同于独立抓包；不能事后阻止已发生上传，也不能据此推断当前版本。" });
                    }
                }
                if findings.len() >= 200 {
                    return Err("结果超过 200 条，请按会话拆分证据".into());
                }
            }
        }
        "zcode" => {
            let state: serde_json::Value = serde_json::from_str(input)
                .map_err(|_| "请输入单个 checkpoint state.json 的有效 JSON")?;
            let object = state.as_object().ok_or("checkpoint 状态必须是 JSON 对象")?;
            if object
                .get("lastAcceptedManifestHash")
                .and_then(|v| v.as_str())
                .is_some_and(|s| !s.trim().is_empty())
            {
                findings.push(Finding { rule: "ZCODE-STATE-001", summary: "状态文件记录了已受理 manifest 的哈希".into(), strength: "历史状态线索",
                    limitation: "字段只支持 manifest 曾被受理的判断，不能单独证明完整快照成功上传或包含密钥。" });
            }
            if let Some(count) = object
                .get("failureCount")
                .and_then(|v| v.as_u64())
                .filter(|c| *c > 0)
            {
                findings.push(Finding {
                    rule: "ZCODE-STATE-002",
                    summary: format!("状态文件记录重试失败 {count} 次"),
                    strength: "重试状态线索",
                    limitation: "失败次数不能证明从未上传成功；零失败也不能证明上传成功。",
                });
            }
        }
        _ => return Err("证据类型必须是 trae 或 zcode".into()),
    }
    Ok(findings)
}
