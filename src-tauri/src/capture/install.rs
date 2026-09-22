//! Per-user root-owned launch daemon, installed only after an explicit system authorization.
use std::{os::unix::fs::MetadataExt, path::Path};

pub fn uid() -> u32 {
    // SAFETY: getuid has no preconditions.
    unsafe { libc::getuid() }
}
pub fn label(uid: u32) -> String {
    format!("dev.agentmonitor.capture.{uid}")
}
pub fn socket(uid: u32) -> String {
    format!("/var/run/monitor-capture-{uid}.sock")
}
fn executable(uid: u32) -> String {
    format!("/Library/PrivilegedHelperTools/{}", label(uid))
}
fn plist_path(uid: u32) -> String {
    format!("/Library/LaunchDaemons/{}.plist", label(uid))
}
fn trusted(path: &str) -> bool {
    std::fs::symlink_metadata(path)
        .is_ok_and(|m| m.is_file() && m.uid() == 0 && m.mode() & 0o022 == 0)
}
pub fn installed() -> bool {
    trusted(&executable(uid())) && trusted(&plist_path(uid()))
}
fn quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\\''"))
}
fn plist(uid: u32) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>Label</key><string>{label}</string>
<key>ProgramArguments</key><array><string>{executable}</string><string>--monitor-capture-service</string><string>{uid}</string></array>
<key>RunAtLoad</key><true/><key>KeepAlive</key><true/>
<key>ThrottleInterval</key><integer>10</integer>
<key>ProcessType</key><string>Background</string>
<key>Umask</key><integer>63</integer>
</dict></plist>"#,
        label = label(uid),
        executable = executable(uid)
    )
}
fn install_command(source: &str, uid: u32) -> String {
    let exe = quote(&executable(uid));
    let file = quote(&plist_path(uid));
    let temporary = quote(&format!("{}.install", executable(uid)));
    let plist_tmp = quote(&format!("{}.install", plist_path(uid)));
    format!("set -eu; test ! -L /Library/PrivilegedHelperTools; test ! -L /Library/LaunchDaemons; /usr/bin/install -d -o root -g wheel -m 755 /Library/PrivilegedHelperTools /Library/LaunchDaemons; /bin/rm -f {temporary} {plist_tmp}; /usr/bin/install -o root -g wheel -m 755 {source} {temporary}; /usr/bin/printf %s {xml} > {plist_tmp}; /usr/sbin/chown root:wheel {plist_tmp}; /bin/chmod 644 {plist_tmp}; /bin/launchctl bootout system/{label} 2>/dev/null || true; /bin/mv -f {temporary} {exe}; /bin/mv -f {plist_tmp} {file}; /bin/launchctl enable system/{label}; /bin/launchctl bootstrap system {file}", source=quote(source), xml=quote(&plist(uid)), label=label(uid))
}
fn uninstall_command(uid: u32) -> String {
    format!("set -eu; /bin/launchctl bootout system/{label} 2>/dev/null || true; /bin/rm -f {exe} {file} {socket}", label=label(uid), exe=quote(&executable(uid)), file=quote(&plist_path(uid)), socket=quote(&socket(uid)))
}
fn authorization_script(shell: &str) -> String {
    let escaped = shell.replace('\\', "\\\\").replace('"', "\\\"");
    format!("with timeout of 180 seconds\ndo shell script \"{escaped}\" with administrator privileges\nend timeout")
}
fn authorization_error(operation: &str, stderr: &[u8], code: Option<i32>) -> String {
    let detail = String::from_utf8_lossy(stderr);
    if detail.trim_end().ends_with("(-128)") {
        return "已取消授权，普通监测继续运行".into();
    }
    let detail: String = detail.trim().chars().take(2000).collect();
    if detail.is_empty() {
        format!("辅助服务{operation}失败（退出码：{code:?}）")
    } else {
        format!("辅助服务{operation}失败：{detail}")
    }
}
async fn authorize(shell: String, operation: &str) -> Result<(), String> {
    let script = authorization_script(&shell);
    let mut command = tokio::process::Command::new("/usr/bin/osascript");
    command.args(["-e", &script]).kill_on_drop(true);
    let result = tokio::time::timeout(std::time::Duration::from_secs(190), command.output())
        .await
        .map_err(|_| "系统授权等待超时，可重新尝试")?
        .map_err(|e| format!("无法打开系统授权弹窗：{e}"))?;
    if result.status.success() {
        Ok(())
    } else {
        Err(authorization_error(
            operation,
            &result.stderr,
            result.status.code(),
        ))
    }
}
pub async fn install() -> Result<(), String> {
    let path = std::env::current_exe().map_err(|e| e.to_string())?;
    if !Path::new(&path).is_file() || uid() == 0 {
        return Err("请使用普通用户启动 Monitor 后授权安装".into());
    }
    // Read the executable as Monitor before asking the privileged AppleScript
    // process to install it. That process may not have access to Documents/Desktop.
    // Keep the private staging directory alive until authorization has completed.
    let staging = tempfile::Builder::new()
        .prefix("monitor-helper-")
        .tempdir()
        .map_err(|e| format!("无法创建辅助服务临时目录：{e}"))?;
    let staged = staging.path().join("Monitor-helper");
    std::fs::copy(&path, &staged).map_err(|e| format!("无法准备辅助服务安装文件：{e}"))?;
    authorize(
        install_command(staged.to_str().ok_or("程序路径编码无效")?, uid()),
        "安装",
    )
    .await?;
    if !installed() {
        return Err("辅助服务文件校验失败".into());
    }
    Ok(())
}
pub async fn uninstall() -> Result<(), String> {
    authorize(uninstall_command(uid()), "移除").await
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn authorization_preserves_system_errors_and_recognizes_cancellation() {
        assert!(
            authorization_error("安装", b"install: Operation not permitted (1)", Some(1))
                .contains("Operation not permitted")
        );
        assert!(
            authorization_error("安装", b"User canceled. (-128)\n", Some(1)).contains("已取消授权")
        );
        assert!(authorization_error("移除", b"", Some(9)).contains('9'));
    }

    #[test]
    fn installer_applescript_compiles_without_running_authorization() {
        use std::io::Write;
        let directory = tempfile::tempdir().unwrap();
        let mut compiler = std::process::Command::new("/usr/bin/osacompile")
            .args(["-o"])
            .arg(directory.path().join("install.scpt"))
            .arg("-")
            .stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        compiler
            .stdin
            .take()
            .unwrap()
            .write_all(
                authorization_script(&install_command("/tmp/Monitor's app/辅助服务", 501))
                    .as_bytes(),
            )
            .unwrap();
        let output = compiler.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    #[test]
    fn installation_uses_fixed_root_owned_destinations_and_quotes_source() {
        let script = install_command("/Applications/Monitor's app/Monitor", 501);
        assert!(script.contains("'/Applications/Monitor'\\''s app/Monitor'"));
        assert!(script.contains("-o root -g wheel -m 755"));
        assert!(script.contains("bootstrap system"));
        assert!(!script.contains("/dev/bpf"));
        let value = plist::Value::from_reader_xml(plist(501).as_bytes()).unwrap();
        let dict = value.as_dictionary().unwrap();
        assert_eq!(
            dict["Label"].as_string(),
            Some("dev.agentmonitor.capture.501")
        );
        let args = dict["ProgramArguments"].as_array().unwrap();
        assert_eq!(args.len(), 3);
        assert_eq!(args[1].as_string(), Some("--monitor-capture-service"));
        assert_eq!(args[2].as_string(), Some("501"));
    }
}
