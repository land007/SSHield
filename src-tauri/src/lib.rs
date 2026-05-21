mod ssh_manager;
mod telnet_guard;
mod telnet_terminal;
mod vulnerability_scanner;

use ssh_manager::{AuthMethod, SessionStore, SshConnection};
use telnet_guard::{check_port_listening, setup_telnet, teardown_telnet, verify_sshd};
use telnet_terminal::TelnetManager;
use vulnerability_scanner::{apply_patch, apply_ssh_upgrade, scan_system, PackageManager};

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tauri::State;

pub struct AppState {
    store: Arc<SessionStore>,
    telnet: Arc<TelnetManager>,
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

// ── SSH connection ────────────────────────────────────────────

#[tauri::command]
async fn ssh_connect(
    request: ConnectRequest,
    state: State<'_, AppState>,
) -> Result<ConnectResponse, String> {
    let auth_method = match request.auth_type.as_str() {
        "password" => AuthMethod::Password { password: request.password.unwrap_or_default() },
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
        .await.map_err(|e| format!("Task error: {}", e))?.map_err(|e| e.to_string())?;
    Ok(ConnectResponse { session_id, message: format!("Connected to {}", request.host) })
}

#[tauri::command]
async fn ssh_disconnect(session_id: String, state: State<'_, AppState>) -> Result<(), String> {
    let store = state.store.clone();
    tokio::task::spawn_blocking(move || store.disconnect(&session_id))
        .await.map_err(|e| format!("Task error: {}", e))?.map_err(|e| e.to_string())
}

#[tauri::command]
fn check_session(session_id: String, state: State<'_, AppState>) -> bool {
    state.store.is_connected(&session_id)
}

// ── Vulnerability scanning ────────────────────────────────────

#[tauri::command]
async fn scan_vulnerabilities(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<vulnerability_scanner::ScanResult, String> {
    let store = state.store.clone();
    tokio::task::spawn_blocking(move || scan_system(&store, &session_id))
        .await.map_err(|e| format!("Task error: {}", e))?.map_err(|e| e.to_string())
}

// ── Patching ──────────────────────────────────────────────────

/// Run the given patch command directly (no guard).
#[tauri::command]
async fn apply_vulnerability_patch(
    session_id: String,
    vulnerability_id: String,
    patch_command: String,
    state: State<'_, AppState>,
) -> Result<vulnerability_scanner::PatchResult, String> {
    let store = state.store.clone();
    tokio::task::spawn_blocking(move || {
        let mut r = apply_patch(&store, &session_id, &patch_command)?;
        r.vulnerability_id = vulnerability_id;
        Ok::<_, anyhow::Error>(r)
    })
    .await.map_err(|e| format!("Task error: {}", e))?.map_err(|e| e.to_string())
}

/// Upgrade only openssh-server / openssh-client.
#[tauri::command]
async fn apply_all_patches(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<vulnerability_scanner::PatchResult, String> {
    let store = state.store.clone();
    tokio::task::spawn_blocking(move || apply_ssh_upgrade(&store, &session_id))
        .await.map_err(|e| format!("Task error: {}", e))?.map_err(|e| e.to_string())
}

// ── Telnet guard — individual steps ──────────────────────────

fn detect_pkg_mgr(store: &SessionStore, session_id: &str) -> PackageManager {
    let r = store.execute(session_id,
        "which apt-get >/dev/null 2>&1 && echo apt || which dnf >/dev/null 2>&1 && echo dnf || which yum >/dev/null 2>&1 && echo yum || which pacman >/dev/null 2>&1 && echo pacman || echo unknown"
    ).unwrap_or_else(|_| ssh_manager::CommandResult { stdout: "unknown".into(), stderr: String::new(), exit_code: 1 });

    match r.stdout.lines()
        .find(|l| ["apt","dnf","yum","pacman","unknown"].contains(&l.trim()))
        .unwrap_or("unknown")
    {
        "apt" => PackageManager::Apt,
        "dnf" => PackageManager::Dnf,
        "yum" => PackageManager::Yum,
        "pacman" => PackageManager::Pacman,
        _ => PackageManager::Unknown,
    }
}

/// Step 1 — install telnetd and attempt to start it.
#[tauri::command]
async fn step_setup_telnet(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let store = state.store.clone();
    tokio::task::spawn_blocking(move || {
        let pkg = detect_pkg_mgr(&store, &session_id);
        setup_telnet(&store, &session_id, &pkg)
    })
    .await.map_err(|e| format!("Task error: {}", e))?.map_err(|e| e.to_string())
}

/// Step 2 — check whether port 23 is currently listening.
#[tauri::command]
async fn step_check_telnet_port(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<(bool, String), String> {
    let store = state.store.clone();
    tokio::task::spawn_blocking(move || check_port_listening(&store, &session_id))
        .await.map_err(|e| format!("Task error: {}", e))?.map_err(|e| e.to_string())
}

/// Step 4 — verify sshd is healthy after patching.
#[tauri::command]
async fn step_verify_ssh(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<(bool, String), String> {
    let store = state.store.clone();
    tokio::task::spawn_blocking(move || verify_sshd(&store, &session_id))
        .await.map_err(|e| format!("Task error: {}", e))?.map_err(|e| e.to_string())
}

/// Step 5 — stop and remove telnetd.
#[tauri::command]
async fn step_remove_telnet(
    session_id: String,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let store = state.store.clone();
    tokio::task::spawn_blocking(move || teardown_telnet(&store, &session_id))
        .await.map_err(|e| format!("Task error: {}", e))?.map_err(|e| e.to_string())
}

// ── SSH terminal (arbitrary command execution) ────────────────

#[tauri::command]
async fn execute_command(
    session_id: String,
    command: String,
    state: State<'_, AppState>,
) -> Result<ssh_manager::CommandResult, String> {
    let store = state.store.clone();
    tokio::task::spawn_blocking(move || store.execute(&session_id, &command))
        .await.map_err(|e| format!("Task error: {}", e))?.map_err(|e| e.to_string())
}

// ── Telnet terminal ───────────────────────────────────────────

#[derive(Debug, Serialize, Deserialize)]
struct TelnetConnectRequest {
    host: String,
    port: u16,
    username: String,
    password: String,
}

#[tauri::command]
async fn telnet_connect(
    request: TelnetConnectRequest,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let mgr = state.telnet.clone();
    let host = request.host.clone();
    tokio::task::spawn_blocking(move || {
        mgr.connect(&request.host, request.port, &request.username, &request.password)
    })
    .await.map_err(|e| format!("Task error: {}", e))?
    .map_err(|e| format!("Telnet 连接 {} 失败: {}", host, e))
}

#[tauri::command]
async fn telnet_execute(
    session_id: String,
    command: String,
    timeout_secs: Option<u64>,
    state: State<'_, AppState>,
) -> Result<String, String> {
    let mgr = state.telnet.clone();
    tokio::task::spawn_blocking(move || {
        mgr.execute(&session_id, &command, timeout_secs.unwrap_or(30))
    })
    .await.map_err(|e| format!("Task error: {}", e))?.map_err(|e| e.to_string())
}

#[tauri::command]
fn telnet_disconnect(session_id: String, state: State<'_, AppState>) {
    state.telnet.disconnect(&session_id);
}

#[tauri::command]
fn telnet_check_session(session_id: String, state: State<'_, AppState>) -> bool {
    state.telnet.is_connected(&session_id)
}

// ── App entry ─────────────────────────────────────────────────

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_shell::init())
        .manage(AppState {
            store: Arc::new(SessionStore::new()),
            telnet: Arc::new(TelnetManager::new()),
        })
        .invoke_handler(tauri::generate_handler![
            ssh_connect,
            ssh_disconnect,
            check_session,
            scan_vulnerabilities,
            apply_vulnerability_patch,
            apply_all_patches,
            step_setup_telnet,
            step_check_telnet_port,
            step_verify_ssh,
            step_remove_telnet,
            execute_command,
            telnet_connect,
            telnet_execute,
            telnet_disconnect,
            telnet_check_session,
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
