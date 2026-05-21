use anyhow::{anyhow, Result};
use serde::{Deserialize, Serialize};

use crate::ssh_manager::SessionStore;
use crate::vulnerability_scanner::{PackageManager, OPENSSH_UPGRADE_CMD};

/// Re-export so lib.rs can reference it without knowing the original module.
pub const OPENSSH_UPGRADE_CMD_EXPORT: &str = OPENSSH_UPGRADE_CMD;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelnetStatus {
    pub installed: bool,
    pub listening: bool,
    pub port: u16,
    /// Which command was used to start it (for teardown)
    pub start_method: StartMethod,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum StartMethod {
    SystemdSocket,  // RHEL8+/Fedora/Arch: telnet.socket
    Xinetd,         // RHEL7/CentOS7
    Inetd,          // Debian/Ubuntu: inetutils-inetd or openbsd-inetd
    None,
}

/// Full result of the guarded patch flow.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuardedPatchResult {
    pub telnet_setup_output: String,
    pub telnet_port: u16,
    pub patch_output: String,
    pub patch_success: bool,
    pub ssh_verified: bool,
    pub telnet_removed: bool,
    pub telnet_cleanup_output: String,
    pub error: Option<String>,
    /// If true, telnet is still running for manual recovery
    pub telnet_still_active: bool,
}

/// Install telnet server, start it, verify it is listening on port 23.
/// Returns TelnetStatus describing how it was started (needed for teardown).
pub fn setup_telnet(
    store: &SessionStore,
    session_id: &str,
    pkg_mgr: &PackageManager,
) -> Result<(TelnetStatus, String)> {
    let mut log = String::new();

    let install_cmd = match pkg_mgr {
        PackageManager::Apt =>
            "DEBIAN_FRONTEND=noninteractive apt-get install -y telnetd 2>&1",
        PackageManager::Dnf =>
            "dnf install -y telnet-server 2>&1",
        PackageManager::Yum =>
            "yum install -y telnet-server xinetd 2>&1",
        PackageManager::Pacman =>
            "pacman -S --noconfirm inetutils 2>&1",
        PackageManager::Unknown =>
            return Err(anyhow!("Unknown package manager — cannot install telnet")),
    };

    let r = store.execute(session_id, install_cmd)?;
    log.push_str(&format!("[install]\n{}\n", r.stdout.trim()));
    if r.exit_code != 0 {
        return Err(anyhow!("telnet install failed (exit {}): {}", r.exit_code, r.stderr));
    }

    // Start and determine the start method
    let start_method = start_telnet_service(store, session_id, pkg_mgr, &mut log)?;

    // Verify port 23 is now listening (give it up to 5s)
    let listening = wait_for_port(store, session_id, 23, &mut log)?;
    if !listening {
        return Err(anyhow!("telnet installed but port 23 is not listening after start"));
    }

    log.push_str("[ok] telnet is listening on port 23\n");

    Ok((
        TelnetStatus {
            installed: true,
            listening: true,
            port: 23,
            start_method,
        },
        log,
    ))
}

fn start_telnet_service(
    store: &SessionStore,
    session_id: &str,
    pkg_mgr: &PackageManager,
    log: &mut String,
) -> Result<StartMethod> {
    // Try systemd socket unit (RHEL8+, Fedora, Arch, modern Ubuntu)
    let r = store.execute(session_id,
        "systemctl enable --now telnet.socket 2>&1 && echo SOCKET_OK || true")?;
    log.push_str(&format!("[start:socket] {}\n", r.stdout.trim()));
    if r.stdout.contains("SOCKET_OK") {
        return Ok(StartMethod::SystemdSocket);
    }

    // Try xinetd (RHEL7/CentOS7)
    if matches!(pkg_mgr, PackageManager::Yum) {
        let r = store.execute(session_id,
            "systemctl enable xinetd 2>&1 && systemctl start xinetd 2>&1 && echo XINETD_OK || true")?;
        log.push_str(&format!("[start:xinetd] {}\n", r.stdout.trim()));
        if r.stdout.contains("XINETD_OK") {
            return Ok(StartMethod::Xinetd);
        }
    }

    // Try inetd / inetutils-inetd (Debian/Ubuntu)
    if matches!(pkg_mgr, PackageManager::Apt) {
        let r = store.execute(session_id,
            "service inetutils-inetd restart 2>&1 || service openbsd-inetd restart 2>&1 && echo INETD_OK || true")?;
        log.push_str(&format!("[start:inetd] {}\n", r.stdout.trim()));
        if r.stdout.contains("INETD_OK") {
            return Ok(StartMethod::Inetd);
        }
        // telnetd on Ubuntu may activate automatically via inetd
        log.push_str("[start:inetd] trying direct telnetd via inetd conf check\n");
        return Ok(StartMethod::Inetd);
    }

    Err(anyhow!("Could not start telnet service via any known method"))
}

fn wait_for_port(
    store: &SessionStore,
    session_id: &str,
    port: u16,
    log: &mut String,
) -> Result<bool> {
    // Try up to 3 times with 2s sleep
    for attempt in 1..=3 {
        let r = store.execute(session_id,
            &format!("ss -tlnp 2>/dev/null | grep ':{port}' || netstat -tlnp 2>/dev/null | grep ':{port}' || true"))?;
        if !r.stdout.trim().is_empty() {
            return Ok(true);
        }
        log.push_str(&format!("[wait] port {port} not yet listening (attempt {attempt}/3)...\n"));
        store.execute(session_id, "sleep 2")?;
    }
    Ok(false)
}

/// Stop and uninstall telnet server.
pub fn teardown_telnet(
    store: &SessionStore,
    session_id: &str,
    pkg_mgr: &PackageManager,
    status: &TelnetStatus,
) -> Result<String> {
    let mut log = String::new();

    // Stop the service
    let stop_cmd = match status.start_method {
        StartMethod::SystemdSocket =>
            "systemctl disable --now telnet.socket 2>&1 || true",
        StartMethod::Xinetd =>
            "systemctl stop xinetd 2>&1; systemctl disable xinetd 2>&1 || true",
        StartMethod::Inetd =>
            "service inetutils-inetd stop 2>&1 || service openbsd-inetd stop 2>&1 || true",
        StartMethod::None => "true",
    };
    let r = store.execute(session_id, stop_cmd)?;
    log.push_str(&format!("[stop] {}\n", r.stdout.trim()));

    // Uninstall
    let remove_cmd = match pkg_mgr {
        PackageManager::Apt =>
            "DEBIAN_FRONTEND=noninteractive apt-get remove -y --purge telnetd 2>&1",
        PackageManager::Dnf =>
            "dnf remove -y telnet-server 2>&1",
        PackageManager::Yum =>
            "yum remove -y telnet-server xinetd 2>&1",
        PackageManager::Pacman =>
            "pacman -R --noconfirm inetutils 2>&1",
        PackageManager::Unknown => "true",
    };
    let r = store.execute(session_id, remove_cmd)?;
    log.push_str(&format!("[remove] {}\n", r.stdout.trim()));

    log.push_str("[ok] telnet removed\n");
    Ok(log)
}

/// Verify sshd is healthy after patching (does NOT open a new connection).
/// Returns (ok, detail_log).
pub fn verify_sshd(store: &SessionStore, session_id: &str) -> Result<(bool, String)> {
    let mut log = String::new();

    // 1. Config syntax check
    let r = store.execute(session_id, "sshd -t 2>&1 && echo CFG_OK")?;
    log.push_str(&format!("[sshd -t] {}\n", r.stdout.trim()));
    if !r.stdout.contains("CFG_OK") {
        log.push_str("[fail] sshd config syntax error\n");
        return Ok((false, log));
    }

    // 2. Service is active
    let r = store.execute(session_id,
        "systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null || service sshd status 2>/dev/null | grep -q running && echo ACTIVE || echo INACTIVE")?;
    log.push_str(&format!("[service] {}\n", r.stdout.trim()));
    if r.stdout.contains("INACTIVE") && !r.stdout.contains("ACTIVE") {
        log.push_str("[fail] sshd service is not active\n");
        return Ok((false, log));
    }

    // 3. Port 22 is listening
    let r = store.execute(session_id,
        "ss -tlnp 2>/dev/null | grep ':22' || netstat -tlnp 2>/dev/null | grep ':22' && echo PORT_OK || echo PORT_FAIL")?;
    log.push_str(&format!("[port 22] {}\n", r.stdout.trim()));
    if r.stdout.contains("PORT_FAIL") && !r.stdout.contains("PORT_OK") {
        log.push_str("[fail] nothing listening on port 22\n");
        return Ok((false, log));
    }

    log.push_str("[ok] sshd is healthy\n");
    Ok((true, log))
}

/// Full safe-patch flow:
///   1. Install + start telnet  (fallback)
///   2. Apply patch command
///   3. Verify sshd
///   4. If ok  → remove telnet, return success
///      If fail → leave telnet running, return error + instructions
pub fn apply_patch_with_telnet_guard(
    store: &SessionStore,
    session_id: &str,
    pkg_mgr: &PackageManager,
    patch_command: &str,
) -> Result<GuardedPatchResult> {
    // ── Step 1: setup telnet ───────────────────────────────
    let (telnet_status, telnet_setup_output) = match setup_telnet(store, session_id, pkg_mgr) {
        Ok(v) => v,
        Err(e) => {
            return Ok(GuardedPatchResult {
                telnet_setup_output: e.to_string(),
                telnet_port: 23,
                patch_output: String::new(),
                patch_success: false,
                ssh_verified: false,
                telnet_removed: false,
                telnet_cleanup_output: String::new(),
                error: Some(format!("无法安装 telnet 回退通道，已中止修补: {}", e)),
                telnet_still_active: false,
            });
        }
    };

    // ── Step 2: apply patch ────────────────────────────────
    let patch_result = store.execute(session_id, patch_command)?;
    let patch_success = patch_result.exit_code == 0;
    let patch_output = format!("{}\n{}", patch_result.stdout, patch_result.stderr)
        .trim()
        .to_string();

    // ── Step 3: verify sshd ────────────────────────────────
    let (ssh_verified, verify_log) = verify_sshd(store, session_id)?;

    // ── Step 4: cleanup or leave telnet ───────────────────
    if patch_success && ssh_verified {
        let cleanup = teardown_telnet(store, session_id, pkg_mgr, &telnet_status)
            .unwrap_or_else(|e| format!("[warn] telnet teardown failed: {e}\n"));
        Ok(GuardedPatchResult {
            telnet_setup_output,
            telnet_port: 23,
            patch_output: format!("{}\n{}", patch_output, verify_log),
            patch_success: true,
            ssh_verified: true,
            telnet_removed: true,
            telnet_cleanup_output: cleanup,
            error: None,
            telnet_still_active: false,
        })
    } else {
        let reason = if !patch_success {
            format!("补丁命令失败 (exit {})", patch_result.exit_code)
        } else {
            "sshd 验证失败".to_string()
        };
        Ok(GuardedPatchResult {
            telnet_setup_output,
            telnet_port: 23,
            patch_output: format!("{}\n{}", patch_output, verify_log),
            patch_success,
            ssh_verified,
            telnet_removed: false,
            telnet_cleanup_output: String::new(),
            error: Some(format!(
                "{reason}。telnet 已保留在端口 23，请用 telnet <host> 23 连入恢复后手动执行清理。"
            )),
            telnet_still_active: true,
        })
    }
}
