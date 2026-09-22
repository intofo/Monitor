mod capture;
mod jev;
mod protection;
mod system_extensions;
pub use capture::helper_entry as capture_helper_entry;
use monitor_runtime::executable;
use monitor_runtime::{
    audit::{Audit, AuditEvent, EventScope},
    sensor::{self, SensorSnapshot, SensorState},
};
use std::sync::{Arc, Mutex};
use tauri::Manager;

struct RuntimeState {
    capture: Arc<capture::Controller>,
    sensor: SensorState,
    audit: Arc<Audit>,
    model_approvals: protection::Approvals,
}

#[tauri::command]
fn capture_status(state: tauri::State<'_, RuntimeState>) -> Result<capture::Status, String> {
    state.capture.snapshot(&state.sensor, &state.audit)
}
#[tauri::command]
fn start_capture(state: tauri::State<'_, RuntimeState>) -> Result<(), String> {
    state
        .capture
        .start(state.sensor.clone(), state.audit.clone(), false)
}
#[tauri::command]
fn install_capture(state: tauri::State<'_, RuntimeState>) -> Result<(), String> {
    state
        .capture
        .start(state.sensor.clone(), state.audit.clone(), true)
}
#[tauri::command]
async fn uninstall_capture(state: tauri::State<'_, RuntimeState>) -> Result<(), String> {
    state.audit.preferences.update(|c| {
        c.packet_capture_enabled = false;
        Ok(())
    })?;
    state.capture.uninstall().await
}
#[tauri::command]
fn stop_capture(state: tauri::State<'_, RuntimeState>) -> Result<(), String> {
    state.audit.preferences.update(|c| {
        c.packet_capture_enabled = false;
        Ok(())
    })?;
    state.capture.stop()
}

#[tauri::command]
fn live_status(state: tauri::State<'_, RuntimeState>) -> Result<SensorSnapshot, String> {
    state
        .sensor
        .lock()
        .map(|s| s.clone())
        .map_err(|_| "采集状态不可用".into())
}
#[tauri::command]
async fn audit_log(
    blocked_only: bool,
    agent_id: Option<String>,
    state: tauri::State<'_, RuntimeState>,
) -> Result<Vec<AuditEvent>, String> {
    let audit = state.audit.clone();
    tauri::async_runtime::spawn_blocking(move || {
        audit.recent_filtered(blocked_only, agent_id.as_deref())
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
async fn export_audit_log(
    path: String,
    blocked_only: bool,
    agent_id: Option<String>,
    state: tauri::State<'_, RuntimeState>,
) -> Result<usize, String> {
    let audit = state.audit.clone();
    tauri::async_runtime::spawn_blocking(move || {
        audit.export_filtered(
            std::path::Path::new(&path),
            blocked_only,
            agent_id.as_deref(),
        )
    })
    .await
    .map_err(|e| e.to_string())?
}

#[tauri::command]
fn audit_groups(state: tauri::State<'_, RuntimeState>) -> Result<Vec<EventScope>, String> {
    state.audit.agent_groups()
}

#[tauri::command]
fn monitor_settings(
    state: tauri::State<'_, RuntimeState>,
) -> Result<monitor_runtime::settings::MonitorConfig, String> {
    state.audit.preferences.load()
}

#[tauri::command]
fn autostart_enabled(app: tauri::AppHandle) -> Result<bool, String> {
    use tauri_plugin_autostart::ManagerExt;
    app.autolaunch().is_enabled().map_err(|e| e.to_string())
}
#[tauri::command]
fn set_autostart(enabled: bool, app: tauri::AppHandle) -> Result<bool, String> {
    use tauri_plugin_autostart::ManagerExt;
    let manager = app.autolaunch();
    if enabled {
        manager.enable()
    } else {
        manager.disable()
    }
    .map_err(|e| e.to_string())?;
    manager.is_enabled().map_err(|e| e.to_string())
}
#[tauri::command]
fn set_close_to_tray(
    enabled: bool,
    state: tauri::State<'_, RuntimeState>,
) -> Result<monitor_runtime::settings::MonitorConfig, String> {
    state.audit.preferences.update(|config| {
        config.close_to_tray = enabled;
        Ok(())
    })
}

#[tauri::command]
fn set_agent_monitoring(
    id: String,
    enabled: bool,
    state: tauri::State<'_, RuntimeState>,
) -> Result<monitor_runtime::settings::MonitorConfig, String> {
    if !state
        .sensor
        .lock()
        .map_err(|_| "采集状态锁异常")?
        .agents
        .iter()
        .any(|a| a.id == id)
    {
        return Err("Agent 列表已变化，请刷新后重试".into());
    }
    state.audit.preferences.update(|c| {
        c.enabled.insert(id, enabled);
        Ok(())
    })
}
fn register_path(
    audit: &Audit,
    name: String,
    executable: String,
) -> Result<monitor_runtime::settings::CustomAgent, String> {
    let name = name.trim().to_string();
    if name.is_empty() || name.len() > 128 || name.chars().any(char::is_control) {
        return Err("Agent 名称不能为空或超过 128 字节".into());
    }
    let mut added = None;
    audit.preferences.update(|config| {
        if let Some(existing) = config
            .custom_agents
            .iter()
            .find(|a| a.executable == executable)
        {
            added = Some(existing.clone());
            return Ok(());
        }
        let custom = monitor_runtime::settings::CustomAgent {
            id: format!("custom:{}", monitor_runtime::settings::new_id()),
            name,
            executable,
        };
        config.custom_agents.push(custom.clone());
        added = Some(custom);
        Ok(())
    })?;
    added.ok_or("无法保存 Agent".into())
}
#[tauri::command]
async fn register_agent(
    name: String,
    executable: String,
    state: tauri::State<'_, RuntimeState>,
) -> Result<monitor_runtime::settings::MonitorConfig, String> {
    let path = executable::resolve_executable(std::path::Path::new(&executable))?;
    register_path(&state.audit, name, path.to_string_lossy().into_owned())?;
    state.audit.preferences.load()
}
#[tauri::command]
async fn agent_icon(
    id: String,
    state: tauri::State<'_, RuntimeState>,
) -> Result<Option<String>, String> {
    let paths = state
        .sensor
        .lock()
        .map_err(|_| "采集状态锁异常")?
        .agents
        .iter()
        .find(|a| a.id == id)
        .map(|a| a.paths.clone())
        .unwrap_or_default();
    monitor_runtime::catalog::native_icon(&paths).await
}
#[tauri::command]
fn storage_directory() -> Result<String, String> {
    Ok(monitor_runtime::settings::home_root()?
        .to_string_lossy()
        .into_owned())
}

pub fn run() {
    let mut context = tauri::generate_context!();
    context.package_info_mut().name = "Monitor".into();
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(tauri_plugin_autostart::init(
            tauri_plugin_autostart::MacosLauncher::LaunchAgent,
            None,
        ))
        .on_window_event(|window, event| {
            if let tauri::WindowEvent::CloseRequested { api, .. } = event {
                if window.label() != "main" {
                    return;
                }
                let state = window.state::<RuntimeState>();
                let close_to_tray = state
                    .audit
                    .preferences
                    .load()
                    .map(|c| c.close_to_tray)
                    .unwrap_or(false);
                if close_to_tray {
                    if window.hide().is_ok() {
                        api.prevent_close();
                    }
                } else {
                    window.app_handle().exit(0);
                }
            }
        })
        .setup(|app| {
            #[cfg(target_os = "macos")]
            install_application_menu(app)?;
            let audit = Arc::new(
                Audit::open(&Audit::default_path().map_err(std::io::Error::other)?)
                    .map_err(std::io::Error::other)?,
            );
            let sensor_state = Arc::new(Mutex::new(SensorSnapshot::default()));
            app.manage(RuntimeState {
                capture: Arc::new(capture::Controller::default()),
                sensor: sensor_state.clone(),
                audit: audit.clone(),
                model_approvals: protection::Approvals::default(),
            });
            if audit
                .preferences
                .load()
                .map_err(std::io::Error::other)?
                .packet_capture_enabled
            {
                let state = app.state::<RuntimeState>();
                if let Err(error) = state
                    .capture
                    .start(sensor_state.clone(), audit.clone(), false)
                {
                    eprintln!("无法自动连接抓包服务: {error}");
                }
            }
            tauri::async_runtime::spawn(sensor::run(sensor_state, audit));
            let open =
                tauri::menu::MenuItem::with_id(app, "open", "打开监测面板", true, None::<&str>)?;
            let quit =
                tauri::menu::MenuItem::with_id(app, "quit", "退出并停止监测", true, None::<&str>)?;
            let menu = tauri::menu::Menu::with_items(app, &[&open, &quit])?;
            let mut tray = tauri::tray::TrayIconBuilder::new()
                .tooltip("Monitor · 活动采样中（非系统防火墙）")
                .menu(&menu)
                .on_menu_event(|app, event| match event.id().as_ref() {
                    "open" => {
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.set_focus();
                        } else if let Some(config) = app.config().app.windows.first() {
                            if let Err(error) =
                                tauri::WebviewWindowBuilder::from_config(app, config)
                                    .and_then(|builder| builder.build())
                            {
                                eprintln!("无法重新打开监测面板: {error}");
                            }
                        }
                    }
                    "quit" => app.exit(0),
                    _ => {}
                });
            if let Some(icon) = app.default_window_icon() {
                tray = tray.icon(icon.clone());
            }
            tray.build(app)?;
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            live_status,
            capture_status,
            start_capture,
            stop_capture,
            install_capture,
            uninstall_capture,
            audit_log,
            export_audit_log,
            audit_groups,
            monitor_settings,
            protection::protection_settings,
            protection::discover_model_apis,
            jev::jev_settings,
            jev::save_jev_settings,
            jev::test_jev_connection,
            jev::test_agent_ai_review,
            system_extensions::system_extension_status,
            system_extensions::activate_system_extension,
            system_extensions::set_network_filter,
            protection::save_protection_settings,
            autostart_enabled,
            set_autostart,
            set_close_to_tray,
            set_agent_monitoring,
            register_agent,
            agent_icon,
            storage_directory
        ])
        .build(context)
        .expect("error while building Monitor")
        .run(|_, event| {
            // Keep background monitoring alive when there are no visible windows.
            // Explicit app.exit(0) from the tray has code=Some(0) and is allowed.
            if let tauri::RunEvent::ExitRequested {
                code: None, api, ..
            } = event
            {
                api.prevent_exit();
            }
        });
}

/// Keep only application actions, native text editing, and window controls.
#[cfg(target_os = "macos")]
fn install_application_menu(app: &tauri::App) -> tauri::Result<()> {
    use tauri::menu::{Menu, MenuItem, PredefinedMenuItem, Submenu};
    let about = MenuItem::with_id(app, "monitor-about", "关于Monitor", true, None::<&str>)?;
    let settings = MenuItem::with_id(app, "monitor-settings", "设置…", true, Some("CmdOrCtrl+,"))?;
    app.on_menu_event(|app, event| {
        if event.id().as_ref() == "monitor-settings" {
            use tauri::Emitter;
            if let Some(window) = app.get_webview_window("main") {
                let _ = window.unminimize();
                let _ = window.show();
                let _ = window.set_focus();
                let _ = window.emit("monitor-open-settings", ());
            }
        }
        if event.id().as_ref() == "monitor-about" {
            let version = app.package_info().version.to_string();
            let _ = app.run_on_main_thread(move || {
                unsafe extern "C" {
                    fn monitor_show_about(
                        version: *const std::ffi::c_char,
                        date: *const std::ffi::c_char,
                        icon: *const u8,
                        icon_len: usize,
                        github: *const u8,
                        github_len: usize,
                    );
                }
                let version = std::ffi::CString::new(version).expect("valid package version");
                let date = std::ffi::CString::new(env!("MONITOR_RELEASE_DATE"))
                    .expect("valid release date");
                let icon = include_bytes!("../../static/monitor-icon.png");
                let github = include_bytes!("../../static/github.svg");
                // The native panel copies its metadata synchronously on the main thread.
                unsafe {
                    monitor_show_about(
                        version.as_ptr(),
                        date.as_ptr(),
                        icon.as_ptr(),
                        icon.len(),
                        github.as_ptr(),
                        github.len(),
                    )
                };
            });
        }
    });
    let application = Submenu::with_items(
        app,
        "Monitor",
        true,
        &[
            &about,
            &settings,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::hide(app, Some("隐藏Monitor"))?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::quit(app, Some("退出Monitor"))?,
        ],
    )?;
    // Native editing items retain standard shortcuts in configuration inputs.
    let edit = Submenu::with_items(
        app,
        "编辑",
        true,
        &[
            &PredefinedMenuItem::undo(app, Some("撤销"))?,
            &PredefinedMenuItem::redo(app, Some("重做"))?,
            &PredefinedMenuItem::separator(app)?,
            &PredefinedMenuItem::cut(app, Some("剪切"))?,
            &PredefinedMenuItem::copy(app, Some("复制"))?,
            &PredefinedMenuItem::paste(app, Some("粘贴"))?,
            &PredefinedMenuItem::select_all(app, Some("全选"))?,
        ],
    )?;
    let window = Submenu::with_items(
        app,
        "窗口",
        true,
        &[
            &PredefinedMenuItem::minimize(app, Some("最小化"))?,
            &PredefinedMenuItem::close_window(app, Some("关闭窗口"))?,
        ],
    )?;
    let menu = Menu::with_items(app, &[&application, &edit, &window])?;
    app.set_menu(menu)?;
    Ok(())
}
