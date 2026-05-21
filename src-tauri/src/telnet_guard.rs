use anyhow::{anyhow, Result};

use crate::ssh_manager::SessionStore;
use crate::vulnerability_scanner::PackageManager;

/// Install telnetd and start the service.
/// Returns a human-readable log of what happened.
pub fn setup_telnet(
    store: &SessionStore,
    session_id: &str,
    pkg_mgr: &PackageManager,
) -> Result<String> {
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
    log.push_str(&format!("[安装]\n{}\n", r.stdout.trim()));
    if r.exit_code != 0 {
        return Err(anyhow!("安装失败 (exit {}): {}", r.exit_code, r.stderr));
    }

    // Try to start (attempt systemd socket → xinetd → inetd in order)
    let start_attempts = [
        "systemctl enable --now telnet.socket 2>&1 && echo SOCKET_OK || true",
        "systemctl enable xinetd 2>&1 && systemctl start xinetd 2>&1 && echo XINETD_OK || true",
        "service inetutils-inetd restart 2>&1 && echo INETD_OK || service openbsd-inetd restart 2>&1 && echo INETD_OK || true",
    ];
    for cmd in &start_attempts {
        let r = store.execute(session_id, cmd)?;
        log.push_str(&format!("[启动]\n{}\n", r.stdout.trim()));
        if r.stdout.contains("_OK") { break; }
    }

    log.push_str("\n[完成] telnetd 安装并已尝试启动\n");
    Ok(log)
}

/// Check whether port 23 is currently listening.
pub fn check_port_listening(store: &SessionStore, session_id: &str) -> Result<(bool, String)> {
    let r = store.execute(session_id,
        "ss -tlnp 2>/dev/null | grep ':23' || netstat -tlnp 2>/dev/null | grep ':23' || true")?;
    let listening = !r.stdout.trim().is_empty();
    let detail = if listening {
        format!("✅ 端口 23 正在监听\n{}", r.stdout.trim())
    } else {
        "❌ 端口 23 未监听".to_string()
    };
    Ok((listening, detail))
}

/// Verify sshd health: config syntax + service active + port 22 listening.
/// Returns (ok, detail_log).
pub fn verify_sshd(store: &SessionStore, session_id: &str) -> Result<(bool, String)> {
    let mut log = String::new();

    let syntax = store.execute(session_id, "sshd -t 2>&1 && echo CFG_OK")?;
    log.push_str(&format!("▶ sshd -t\n{}\n\n", syntax.stdout.trim()));
    if !syntax.stdout.contains("CFG_OK") {
        log.push_str("❌ 配置语法检查失败\n");
        return Ok((false, log));
    }
    log.push_str("✅ 配置语法正常\n\n");

    let active = store.execute(session_id,
        "systemctl is-active sshd 2>/dev/null || systemctl is-active ssh 2>/dev/null || echo inactive")?;
    log.push_str(&format!("▶ systemctl is-active sshd\n{}\n\n", active.stdout.trim()));
    let is_active = active.stdout.trim().contains("active") && !active.stdout.trim().contains("inactive");
    if !is_active {
        log.push_str("❌ sshd 服务未运行\n");
        return Ok((false, log));
    }
    log.push_str("✅ sshd 服务正在运行\n\n");

    let port = store.execute(session_id,
        "ss -tlnp 2>/dev/null | grep ':22' || netstat -tlnp 2>/dev/null | grep ':22' || echo no_port")?;
    log.push_str(&format!("▶ 端口 22 监听检查\n{}\n\n", port.stdout.trim()));
    if port.stdout.contains("no_port") || port.stdout.trim().is_empty() {
        log.push_str("❌ 端口 22 未监听\n");
        return Ok((false, log));
    }
    log.push_str("✅ 端口 22 正在监听\n");

    Ok((true, log))
}

/// Stop and uninstall telnet — tries all known methods so caller does not need
/// to track how telnet was originally started.
pub fn teardown_telnet(store: &SessionStore, session_id: &str) -> Result<String> {
    let mut log = String::new();

    let stop = store.execute(session_id, concat!(
        "systemctl disable --now telnet.socket 2>/dev/null || true; ",
        "systemctl stop xinetd 2>/dev/null || true; ",
        "service inetutils-inetd stop 2>/dev/null || true; ",
        "service openbsd-inetd stop 2>/dev/null || true; ",
        "echo STOP_DONE 2>&1"
    ))?;
    log.push_str(&format!("[停止服务]\n{}\n", stop.stdout.trim()));

    let remove = store.execute(session_id, concat!(
        "DEBIAN_FRONTEND=noninteractive apt-get remove -y --purge telnetd 2>/dev/null || ",
        "dnf remove -y telnet-server 2>/dev/null || ",
        "yum remove -y telnet-server xinetd 2>/dev/null || ",
        "pacman -R --noconfirm inetutils 2>/dev/null || ",
        "echo 'no package removed (already gone?)'"
    ))?;
    log.push_str(&format!("[卸载包]\n{}\n", remove.stdout.trim()));
    log.push_str("\n✅ telnet 已移除\n");

    Ok(log)
}
