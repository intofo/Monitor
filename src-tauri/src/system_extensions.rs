//! SystemExtensions activation is separate from enforcement health. An activation
//! callback never means that rules were loaded or that network filtering is enabled.
#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn monitor_system_extensions_status() -> *mut std::ffi::c_char;
    fn monitor_activate_system_extension(kind: i32, development: i32) -> i32;
    fn monitor_set_network_filter(enabled: i32) -> *mut std::ffi::c_char;
}
#[tauri::command]
pub async fn system_extension_status() -> Result<serde_json::Value, String> {
    #[cfg(target_os = "macos")]
    {
        tauri::async_runtime::spawn_blocking(|| {
            // SAFETY: bridge returns a malloc-owned UTF-8 JSON string. It synchronizes
            // all Foundation/SystemExtensions access onto the main thread.
            let value = unsafe { monitor_system_extensions_status() };
            if value.is_null() {
                return Err("System extension status is unavailable".into());
            }
            let parsed =
                serde_json::from_slice(unsafe { std::ffi::CStr::from_ptr(value) }.to_bytes())
                    .map_err(|e| e.to_string());
            unsafe { libc::free(value.cast()) };
            let mut parsed: serde_json::Value = parsed?;
            parsed["sip"] = serde_json::json!(sip_status());
            Ok(parsed)
        })
        .await
        .map_err(|e| e.to_string())?
    }
    #[cfg(not(target_os = "macos"))]
    {
        Ok(serde_json::json!({"supported":false}))
    }
}
#[tauri::command]
pub async fn activate_system_extension(kind: String) -> Result<(), String> {
    let kind = match kind.as_str() {
        "endpoint" => 0,
        "network" => 1,
        _ => return Err("Unknown system extension".into()),
    };
    #[cfg(target_os = "macos")]
    {
        let result = tauri::async_runtime::spawn_blocking(move || unsafe {
            monitor_activate_system_extension(kind, i32::from(sip_status() == "disabled"))
        })
        .await
        .map_err(|e| e.to_string())?;
        match result {
            0 => Ok(()),
            2 => Err("Monitor must be signed with the system-extension.install entitlement".into()),
            3 => Err("A signed, entitled system extension must be bundled with Monitor".into()),
            _ => Err("System extension activation request failed".into()),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = kind;
        Err("System extensions require macOS".into())
    }
}

#[tauri::command]
pub async fn set_network_filter(enabled: bool) -> Result<(), String> {
    #[cfg(target_os = "macos")]
    {
        // Native preferences still enforce Apple signing/entitlement and user approval.
        tauri::async_runtime::spawn_blocking(move || {
            let error = unsafe { monitor_set_network_filter(i32::from(enabled)) };
            if error.is_null() {
                return Ok(());
            }
            let message = unsafe { std::ffi::CStr::from_ptr(error) }
                .to_string_lossy()
                .into_owned();
            unsafe { libc::free(error.cast()) };
            Err(message)
        })
        .await
        .map_err(|e| e.to_string())?
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = enabled;
        Err("Network filtering requires macOS".into())
    }
}

#[cfg(target_os = "macos")]
fn sip_status() -> &'static str {
    let Ok(output) = std::process::Command::new("/usr/bin/csrutil")
        .arg("status")
        .env("LC_ALL", "C")
        .output()
    else {
        return "unknown";
    };
    if !output.status.success() {
        return "unknown";
    }
    parse_sip_status(&String::from_utf8_lossy(&output.stdout))
}

#[cfg(any(target_os = "macos", test))]
fn parse_sip_status(output: &str) -> &'static str {
    match output.trim() {
        "System Integrity Protection status: enabled." => "enabled",
        "System Integrity Protection status: disabled." => "disabled",
        _ => "unknown",
    }
}

#[cfg(test)]
mod tests {
    use super::parse_sip_status;
    #[test]
    fn partial_and_failed_detection_never_mean_disabled() {
        assert_eq!(
            parse_sip_status("System Integrity Protection status: enabled.\n"),
            "enabled"
        );
        assert_eq!(
            parse_sip_status("System Integrity Protection status: disabled.\n"),
            "disabled"
        );
        assert_eq!(
            parse_sip_status("System Integrity Protection status: unknown (Custom Configuration)."),
            "unknown"
        );
        assert_eq!(parse_sip_status("failed"), "unknown");
    }
}
