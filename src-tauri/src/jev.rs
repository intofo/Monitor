use crate::RuntimeState;
use monitor_runtime::jev::{IntentSummary, JevSettings, Operation, Review};
#[cfg(target_os = "macos")]
unsafe extern "C" {
    fn monitor_jev_key_exists(account: *const std::ffi::c_char) -> i32;
    fn monitor_jev_key_save(account: *const std::ffi::c_char, key: *const std::ffi::c_char) -> i32;
    fn monitor_jev_key_get(
        account: *const std::ffi::c_char,
        result: *mut *mut std::ffi::c_char,
    ) -> i32;
}
#[cfg(target_os = "macos")]
fn account(endpoint: &str) -> Result<std::ffi::CString, String> {
    std::ffi::CString::new(endpoint).map_err(|_| "Invalid API endpoint".into())
}
pub fn has_key(endpoint: &str) -> Result<bool, String> {
    if endpoint.is_empty() {
        return Ok(false);
    }
    #[cfg(target_os = "macos")]
    {
        let endpoint = account(endpoint)?;
        match unsafe { monitor_jev_key_exists(endpoint.as_ptr()) } {
            0 => Ok(true),
            -25300 => Ok(false),
            code => Err(format!("Keychain error: {code}")),
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = endpoint;
        Ok(false)
    }
}
fn save_key(endpoint: &str, key: &str) -> Result<(), String> {
    if key.len() > 8192 || key.chars().any(char::is_control) {
        return Err("Invalid API key".into());
    }
    #[cfg(target_os = "macos")]
    {
        let endpoint = account(endpoint)?;
        let key = std::ffi::CString::new(key).map_err(|_| "Invalid API key")?;
        let code = unsafe { monitor_jev_key_save(endpoint.as_ptr(), key.as_ptr()) };
        if code == 0 {
            Ok(())
        } else {
            Err(format!("Keychain error: {code}"))
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = (endpoint, key);
        Err("Secure key storage currently requires macOS".into())
    }
}
fn get_key(endpoint: &str) -> Result<zeroize::Zeroizing<String>, String> {
    #[cfg(target_os = "macos")]
    {
        let endpoint = account(endpoint)?;
        let mut pointer = std::ptr::null_mut();
        let code = unsafe { monitor_jev_key_get(endpoint.as_ptr(), &mut pointer) };
        if code != 0 || pointer.is_null() {
            return Err(format!("Keychain error: {code}"));
        }
        let raw = unsafe { std::ffi::CStr::from_ptr(pointer) };
        let key = zeroize::Zeroizing::new(raw.to_string_lossy().into_owned());
        let length = raw.to_bytes().len();
        for index in 0..length {
            unsafe { pointer.add(index).write_volatile(0) }
        }
        unsafe { libc::free(pointer.cast()) };
        Ok(key)
    }
    #[cfg(not(target_os = "macos"))]
    {
        let _ = endpoint;
        Err("Secure key storage currently requires macOS".into())
    }
}
#[derive(serde::Serialize)]
pub struct Status {
    pub settings: JevSettings,
    pub has_key: bool,
}
#[tauri::command]
pub async fn jev_settings(state: tauri::State<'_, RuntimeState>) -> Result<Status, String> {
    let settings = state.audit.preferences.load()?.jev;
    tauri::async_runtime::spawn_blocking(move || {
        Ok(Status {
            has_key: has_key(&settings.api_url)?,
            settings,
        })
    })
    .await
    .map_err(|e| e.to_string())?
}
#[tauri::command]
pub async fn save_jev_settings(
    settings: JevSettings,
    key: Option<String>,
    state: tauri::State<'_, RuntimeState>,
) -> Result<Status, String> {
    let settings = settings.validate()?;
    let copy = settings.clone();
    tauri::async_runtime::spawn_blocking(move || {
        if let Some(key) = key {
            save_key(&copy.api_url, &key)?;
        }
        Ok::<_, String>(())
    })
    .await
    .map_err(|e| e.to_string())??;
    state.audit.preferences.update(|config| {
        if config.jev.api_url != settings.api_url || config.jev.model != settings.model {
            for policy in config.agent_protection.values_mut() {
                policy.ai_approved_endpoint = None;
            }
        }
        config.jev = settings.clone();
        Ok(())
    })?;
    jev_settings(state).await
}
#[tauri::command]
pub async fn test_jev_connection(state: tauri::State<'_, RuntimeState>) -> Result<Review, String> {
    let settings = state.audit.preferences.load()?.jev.validate()?;
    let endpoint = settings.api_url.clone();
    let key = tauri::async_runtime::spawn_blocking(move || get_key(&endpoint))
        .await
        .map_err(|e| e.to_string())??;
    monitor_runtime::jev::review(
        settings,
        &key,
        IntentSummary {
            operation: Operation::ConnectionTest,
            within_project: false,
            destination_authorized: false,
        },
    )
    .await
}
// A future authenticated native-event consumer calls this only after local hard
// rules. Model output is advisory and never directly resumes a blocked syscall.
pub async fn review_intent(
    config: &monitor_runtime::settings::MonitorConfig,
    agent: &str,
    summary: IntentSummary,
) -> Result<Review, String> {
    let policy = config
        .agent_protection
        .get(agent)
        .ok_or("Agent AI review is not enabled")?;
    if policy.policy.mode != monitor_core::protection::ProtectionMode::Ai
        || policy.ai_approved_endpoint.as_deref() != Some(config.jev.api_url.as_str())
    {
        return Err("Agent AI review requires user consent for this endpoint".into());
    }
    let settings = config.jev.clone().validate()?;
    let endpoint = settings.api_url.clone();
    let key = tauri::async_runtime::spawn_blocking(move || get_key(&endpoint))
        .await
        .map_err(|e| e.to_string())??;
    monitor_runtime::jev::review(settings, &key, summary).await
}
#[tauri::command]
pub async fn test_agent_ai_review(
    agent_id: String,
    state: tauri::State<'_, RuntimeState>,
) -> Result<Review, String> {
    review_intent(
        &state.audit.preferences.load()?,
        &agent_id,
        IntentSummary {
            operation: Operation::FileRead,
            within_project: false,
            destination_authorized: false,
        },
    )
    .await
}
