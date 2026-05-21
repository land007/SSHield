import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ConnectPanel } from "./components/ConnectPanel";
import { ScanPanel } from "./components/ScanPanel";
import { TerminalPanel } from "./components/TerminalPanel";
import { TelnetTerminalPanel } from "./components/TelnetTerminalPanel";
import { PatchLog } from "./components/PatchLog";
import type {
  ConnectRequest, ConnectResponse,
  ScanResult, PatchResult, CommandResult, Session,
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
      setSession({ id: resp.session_id, host: req.host, port: req.port, username: req.username, connectedAt: new Date() });
      setScanResult(null);
      setPatchLogs([]);
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
    try { await invoke("ssh_disconnect", { sessionId: session.id }); } catch {}
    setSession(null);
    setScanResult(null);
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

  // Direct patch — no wizard
  const handlePatchDirect = async (vulnId: string, cmd: string) => {
    if (!session) return;
    setPatching(vulnId);
    try {
      const result = await invoke<PatchResult>("apply_vulnerability_patch", {
        sessionId: session.id, vulnerabilityId: vulnId, patchCommand: cmd,
      });
      setPatchLogs(prev => [...prev, result]);
      if (result.success) {
        showSuccess(`${vulnId} 修补完成`);
        await handleScan();
      } else {
        showError(`修补失败: ${result.error}`);
        setActiveTab("logs");
      }
    } catch (err) {
      showError(`修补出错: ${err}`);
    } finally {
      setPatching(null);
    }
  };

  // Bulk openssh upgrade (no wizard, no guard)
  const handlePatchAll = async () => {
    if (!session) return;
    setPatching("all");
    try {
      const result = await invoke<PatchResult>("apply_all_patches", { sessionId: session.id });
      setPatchLogs(prev => [...prev, result]);
      if (result.success) {
        showSuccess("OpenSSH 升级完成");
        await handleScan();
      } else {
        showError(`升级失败: ${result.error}`);
        setActiveTab("logs");
      }
    } catch (err) {
      showError(`升级出错: ${err}`);
    } finally {
      setPatching(null);
    }
  };

  const handleExecute = async (cmd: string): Promise<CommandResult> => {
    if (!session) throw new Error("未连接");
    return invoke<CommandResult>("execute_command", { sessionId: session.id, command: cmd });
  };

  const tabs: { id: Tab; label: string; icon: string; disabled?: boolean }[] = [
    { id: "connect", label: "连接", icon: "🔌" },
    { id: "scan", label: "漏洞扫描", icon: "🔍", disabled: !session },
    { id: "terminal", label: "SSH 终端", icon: "💻", disabled: !session },
    { id: "telnet", label: "Telnet 终端", icon: "📡", disabled: !session },
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

      {error && <div className="alert alert-error"><span className="icon">⚠️</span> {error}</div>}
      {successMsg && <div className="alert alert-success"><span className="icon">✅</span> {successMsg}</div>}

      <nav className="tab-nav">
        {tabs.map(tab => (
          <button
            key={tab.id}
            className={`tab-btn ${activeTab === tab.id ? "active" : ""}`}
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
            sessionId={session.id}
            scanResult={scanResult}
            scanning={scanning}
            onScan={handleScan}
            onPatchDirect={handlePatchDirect}
            onPatchAll={handlePatchAll}
            patching={patching}
            onGoTelnet={() => setActiveTab("telnet")}
            onRescan={handleScan}
          />
        )}
        {activeTab === "terminal" && session && (
          <TerminalPanel onExecute={handleExecute} disabled={false} />
        )}
        {activeTab === "telnet" && session && (
          <TelnetTerminalPanel host={session.host} port={23} urgentRecovery={false} />
        )}
        {activeTab === "logs" && (
          <PatchLog logs={patchLogs} />
        )}
      </main>
    </div>
  );
}
