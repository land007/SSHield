import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ConnectPanel } from "./components/ConnectPanel";
import { ScanPanel } from "./components/ScanPanel";
import { TerminalPanel } from "./components/TerminalPanel";
import { TelnetTerminalPanel } from "./components/TelnetTerminalPanel";
import { PatchLog } from "./components/PatchLog";
import type {
  ConnectRequest,
  ConnectResponse,
  GuardedPatchResult,
  ScanResult,
  PatchResult,
  CommandResult,
  Session,
} from "./types";

type Tab = "connect" | "scan" | "terminal" | "telnet" | "logs";

export default function App() {
  const [session, setSession] = useState<Session | null>(null);
  const [activeTab, setActiveTab] = useState<Tab>("connect");
  const [connecting, setConnecting] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [scanResult, setScanResult] = useState<ScanResult | null>(null);
  const [patching, setPatching] = useState<string | null>(null);
  const [patchLogs, setPatchLogs] = useState<PatchResult[]>([]);
  const [lastGuarded, setLastGuarded] = useState<GuardedPatchResult | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [successMsg, setSuccessMsg] = useState<string | null>(null);

  const showError = (msg: string) => {
    setError(msg);
    setTimeout(() => setError(null), 8000);
  };

  const showSuccess = (msg: string) => {
    setSuccessMsg(msg);
    setTimeout(() => setSuccessMsg(null), 5000);
  };

  const handleConnect = async (req: ConnectRequest) => {
    setConnecting(true);
    setError(null);
    try {
      const resp = await invoke<ConnectResponse>("ssh_connect", { request: req });
      setSession({
        id: resp.session_id,
        host: req.host,
        port: req.port,
        username: req.username,
        connectedAt: new Date(),
      });
      setScanResult(null);
      setPatchLogs([]);
      setLastGuarded(null);
      showSuccess(resp.message);
      setActiveTab("scan");
    } catch (err) {
      showError(String(err));
    } finally {
      setConnecting(false);
    }
  };

  const handleDisconnect = async () => {
    if (!session) return;
    try {
      await invoke("ssh_disconnect", { sessionId: session.id });
    } catch {
      // ignore disconnect errors
    }
    setSession(null);
    setScanResult(null);
    setLastGuarded(null);
    setActiveTab("connect");
    showSuccess("已断开连接");
  };

  const handleScan = async () => {
    if (!session) return;
    setScanning(true);
    setError(null);
    try {
      const result = await invoke<ScanResult>("scan_vulnerabilities", { sessionId: session.id });
      setScanResult(result);
      showSuccess(`扫描完成，发现 ${result.vulnerabilities.length} 个安全问题`);
    } catch (err) {
      showError(`扫描失败: ${err}`);
    } finally {
      setScanning(false);
    }
  };

  const handlePatchOne = async (vulnId: string, cmd: string, safe: boolean) => {
    if (!session) return;
    setPatching(vulnId);
    setLastGuarded(null);
    try {
      if (safe) {
        const result = await invoke<GuardedPatchResult>("apply_vulnerability_patch_safe", {
          sessionId: session.id,
          vulnerabilityId: vulnId,
          patchCommand: cmd,
        });
        setLastGuarded(result);
        if (result.patch_success && result.ssh_verified) {
          showSuccess(`漏洞 ${vulnId} 修补成功，SSH 验证通过，Telnet 已移除`);
          await handleScan();
        } else {
          showError(result.error ?? "修补失败");
          // Auto-jump to telnet terminal for recovery
          setActiveTab("telnet");
        }
        // Convert to PatchResult for the log list
        setPatchLogs(prev => [...prev, {
          vulnerability_id: vulnId,
          success: result.patch_success && result.ssh_verified,
          output: `[telnet setup]\n${result.telnet_setup_output}\n\n[patch]\n${result.patch_output}\n\n[telnet cleanup]\n${result.telnet_cleanup_output}`,
          error: result.error,
        }]);
      } else {
        const result = await invoke<PatchResult>("apply_vulnerability_patch", {
          sessionId: session.id,
          vulnerabilityId: vulnId,
          patchCommand: cmd,
        });
        setPatchLogs(prev => [...prev, result]);
        if (result.success) {
          showSuccess(`漏洞 ${vulnId} 修补成功`);
          await handleScan();
        } else {
          showError(`修补失败: ${result.error}`);
          setActiveTab("logs");
        }
      }
    } catch (err) {
      showError(`修补出错: ${err}`);
    } finally {
      setPatching(null);
    }
  };

  const handlePatchAll = async (safe: boolean) => {
    if (!session) return;
    setPatching("all");
    setLastGuarded(null);
    try {
      if (safe) {
        const result = await invoke<GuardedPatchResult>("apply_all_patches_safe", {
          sessionId: session.id,
        });
        setLastGuarded(result);
        if (result.patch_success && result.ssh_verified) {
          showSuccess("OpenSSH 安全升级完成，SSH 验证通过，Telnet 已移除");
          await handleScan();
        } else {
          showError(result.error ?? "升级失败");
          setActiveTab("telnet");
        }
        setPatchLogs(prev => [...prev, {
          vulnerability_id: "全量 OpenSSH 升级",
          success: result.patch_success && result.ssh_verified,
          output: `[telnet setup]\n${result.telnet_setup_output}\n\n[patch]\n${result.patch_output}\n\n[telnet cleanup]\n${result.telnet_cleanup_output}`,
          error: result.error,
        }]);
      } else {
        const result = await invoke<PatchResult>("apply_all_patches", { sessionId: session.id });
        setPatchLogs(prev => [...prev, result]);
        if (result.success) {
          showSuccess("OpenSSH 升级完成");
          await handleScan();
        } else {
          showError(`升级失败: ${result.error}`);
          setActiveTab("logs");
        }
      }
    } catch (err) {
      showError(`升级出错: ${err}`);
    } finally {
      setPatching(null);
    }
  };

  const handleCleanupTelnet = async () => {
    if (!session) return;
    try {
      const output = await invoke<string>("cleanup_telnet", { sessionId: session.id });
      setLastGuarded(null);
      showSuccess("Telnet 已手动移除");
      setPatchLogs(prev => [...prev, {
        vulnerability_id: "手动移除 Telnet",
        success: true,
        output,
        error: null,
      }]);
    } catch (err) {
      showError(`移除 Telnet 失败: ${err}`);
    }
  };

  const handleExecute = async (cmd: string): Promise<CommandResult> => {
    if (!session) throw new Error("未连接");
    return invoke<CommandResult>("execute_command", { sessionId: session.id, command: cmd });
  };

  const telnetActive = lastGuarded?.telnet_still_active ?? false;

  const tabs: { id: Tab; label: string; icon: string; disabled?: boolean; urgent?: boolean }[] = [
    { id: "connect", label: "连接", icon: "🔌" },
    { id: "scan", label: "漏洞扫描", icon: "🔍", disabled: !session },
    { id: "terminal", label: "SSH 终端", icon: "💻", disabled: !session },
    {
      id: "telnet",
      label: telnetActive ? "🚨 Telnet 恢复" : "Telnet 终端",
      icon: "📡",
      disabled: !session,
      urgent: telnetActive,
    },
    { id: "logs", label: `日志${patchLogs.length > 0 ? ` (${patchLogs.length})` : ""}`, icon: "📋", disabled: patchLogs.length === 0 },
  ];

  return (
    <div className="app">
      <header className="app-header">
        <div className="header-left">
          <span className="app-logo">🛡️</span>
          <div>
            <h1 className="app-title">SSH 漏洞补丁管理器</h1>
            <p className="app-subtitle">SSH Vulnerability Patch Manager</p>
          </div>
        </div>
        {session && (
          <div className="session-info">
            <div className="session-badge">
              <span className="conn-dot" />
              <span className="conn-label">{session.username}@{session.host}:{session.port}</span>
            </div>
            <button className="btn btn-sm btn-ghost" onClick={handleDisconnect}>断开</button>
          </div>
        )}
      </header>

      {error && (
        <div className="alert alert-error"><span className="icon">⚠️</span> {error}</div>
      )}
      {successMsg && (
        <div className="alert alert-success"><span className="icon">✅</span> {successMsg}</div>
      )}

      <nav className="tab-nav">
        {tabs.map(tab => (
          <button
            key={tab.id}
            className={`tab-btn ${activeTab === tab.id ? "active" : ""} ${tab.urgent ? "urgent" : ""}`}
            onClick={() => setActiveTab(tab.id)}
            disabled={tab.disabled}
          >
            <span className="icon">{tab.icon}</span> {tab.label}
          </button>
        ))}
      </nav>

      <main className="app-main">
        {activeTab === "connect" && (
          <ConnectPanel onConnect={handleConnect} connecting={connecting} />
        )}
        {activeTab === "scan" && session && (
          <ScanPanel
            host={session.host}
            scanResult={scanResult}
            scanning={scanning}
            onScan={handleScan}
            onPatchOne={handlePatchOne}
            onPatchAll={handlePatchAll}
            patching={patching}
            lastGuarded={lastGuarded}
            onCleanupTelnet={handleCleanupTelnet}
          />
        )}
        {activeTab === "terminal" && session && (
          <TerminalPanel onExecute={handleExecute} disabled={!session} />
        )}
        {activeTab === "telnet" && session && (
          <TelnetTerminalPanel
            host={session.host}
            port={23}
            urgentRecovery={telnetActive}
          />
        )}
        {activeTab === "logs" && (
          <PatchLog logs={patchLogs} />
        )}
      </main>
    </div>
  );
}
