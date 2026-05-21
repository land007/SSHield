mod ssh_manager;
mod telnet_guard;
mod vulnerability_scanner;

use ssh_manager::{AuthMethod, SessionStore, SshConnection};
use telnet_guard::{apply_patch_with_telnet_guard, teardown_telnet, GuardedPatchResult};
use vulnerability_scanner::{apply_patch, apply_ssh_upgrade, scan_system};

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::State;

pub struct AppState {
    store: Arc<SessionStore>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectRequest {
    host: String,
    port: u16,
    username: String,
    auth_type: String,
    password: Option<String>,
    key_path: Option<String>,
    key_passphrase: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ConnectResponse {
    session_id: String,
    message: String,
}

#[tauri::command]
async fn ssh_connect(
    request: ConnectRequest,
    state: State<'_, AppState>,
) -> Result<ConnectResponse, String> {
    let auth_method = match request.auth_type.as_str() {
        "password" => AuthMethod::Password {
            password: request.password.unwrap_or_default(),
        },
        "key" => AuthMethod::PrivateKey {
            key_path: request.key_path.unwrap_or_default(),
            passphrase: request.key_passphrase,
        },
        _ => return Err("Invalid auth type".to_string()),
    };

    let conn = SshConnection {
        id: String::new(),
        host: request.host.clone(),
        port: request.port,
        username: request.username,
        auth_method,
        connected: false,
    };

    let store = state.store.clone();
    let session_id = tokio::task::spawn_blocking(move || store.connect(&conn))
        .await
        .map_err(|e| format!("Task error: {}", e))?
        .map_err(|e| e.to_string())?;

    Ok(ConnectResponse {
        session_id,
        message: format!("Connected to {}", request.host),
    })
}

#[tauri::command]
async fn ssh_disconnect(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<(), String> {
    let store = state.store.clone();
    tokio::task::spawn_blocking(move || store.disconnect(&session_id))
        .await
        .map_err(|e| format!("Task error: {}", e))?
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn scan_vulnerabilities(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<vulnerability_scanner::ScanResult, String> {
    let store = state.store.clone();
    tokio::task::spawn_blocking(move || scan_system(&store, &session_id))
        .await
        .map_err(|e| format!("Task error: {}", e))?
        .map_err(|e| e.to_string())
}

/// Direct patch — no telnet guard. Use only when telnet is unavailable/unwanted.
#[tauri::command]
async fn apply_vulnerability_patch(
    session_id: String,
    vulnerability_id: String,
    patch_command: String,
    state: State<'_, AppState>,
) -> Result<vulnerability_scanner::PatchResult, String> {
    let store = state.store.clone();
    tokio::task::spawn_blocking(move || {
        let mut result = apply_patch(&store, &session_id, &patch_command)?;
        result.vulnerability_id = vulnerability_id;
        Ok::<_, anyhow::Error>(result)
    })
    .await
    .map_err(|e| format!("Task error: {}", e))?
    .map_err(|e| e.to_string())
}

/// Safe patch — installs telnet fallback first, verifies sshd after, then removes telnet.
/// If sshd verification fails, telnet is left running for manual recovery.
#[tauri::command]
async fn apply_vulnerability_patch_safe(
    session_id: String,
    vulnerability_id: String,
    patch_command: String,
    state: State<'_, AppState>,
) -> Result<GuardedPatchResult, String> {
    let store = state.store.clone();
    tokio::task::spawn_blocking(move || {
        // Determine package manager (needed for telnet install/remove)
        let scan = scan_system(&store, &session_id)?;
        let pkg_mgr = scan.system_info.package_manager;

        let mut result =
            apply_patch_with_telnet_guard(&store, &session_id, &pkg_mgr, &patch_command)?;
        result.patch_output = format!("[{}]\n{}", vulnerability_id, result.patch_output);
        Ok::<_, anyhow::Error>(result)
    })
    .await
    .map_err(|e| format!("Task error: {}", e))?
    .map_err(|e| e.to_string())
}

/// Safe bulk SSH upgrade — same guard logic applied to the full openssh upgrade.
#[tauri::command]
async fn apply_all_patches_safe(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<GuardedPatchResult, String> {
    let store = state.store.clone();
    tokio::task::spawn_blocking(move || {
        let scan = scan_system(&store, &session_id)?;
        let pkg_mgr = scan.system_info.package_manager;
        let cmd = telnet_guard::OPENSSH_UPGRADE_CMD_EXPORT;
        apply_patch_with_telnet_guard(&store, &session_id, &pkg_mgr, cmd)
    })
    .await
    .map_err(|e| format!("Task error: {}", e))?
    .map_err(|e| e.to_string())
}

/// Manually remove telnet after the user has confirmed SSH is working.
#[tauri::command]
async fn cleanup_telnet(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let store = state.store.clone();
    tokio::task::spawn_blocking(move || {
        let scan = scan_system(&store, &session_id)?;
        let pkg_mgr = scan.system_info.package_manager;
        let status = telnet_guard::TelnetStatus {
            installed: true,
            listening: true,
            port: 23,
            start_method: telnet_guard::StartMethod::SystemdSocket,
        };
        teardown_telnet(&store, &session_id, &pkg_mgr, &status)
    })
    .await
    .map_err(|e| format!("Task error: {}", e))?
    .map_err(|e| e.to_string())
}

/// Unsafe fallback: direct SSH upgrade without telnet guard.
#[tauri::command]
async fn apply_all_patches(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<vulnerability_scanner::PatchResult, String> {
    let store = state.store.clone();
    tokio::task::spawn_blocking(move || apply_ssh_upgrade(&store, &session_id))
        .await
        .map_err(|e| format!("Task error: {}", e))?
        .map_err(|e| e.to_string())
}

#[tauri::command]
async fn execute_command(
    session_id: String,
    command: String,
    state: State<'_, AppState>,
) -> Result<ssh_manager::CommandResult, String> {
    let store = state.store.clone();
    tokio::task::spawn_blocking(move || store.execute(&session_id, &command))
        .await
        .map_err(|e| format!("Task error: {}", e))?
        .map_err(|e| e.to_string())
}

#[tauri::command]
fn check_session(session_id: String, state: State<'_, AppState>) -> bool {
    state.store.is_connected(&session_id)
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(AppState {
            store: Arc::new(SessionStore::new()),
        })
        .invoke_handler(tauri::generate_handler![
            ssh_connect,
            ssh_disconnect,
            scan_vulnerabilities,
            apply_vulnerability_patch,
            apply_vulnerability_patch_safe,
            apply_all_patches,
            apply_all_patches_safe,
            cleanup_telnet,
            execute_command,
            check_session,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
