import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import { ConnectPanel } from "./components/ConnectPanel";
import { ScanPanel } from "./components/ScanPanel";
import { TerminalPanel } from "./components/TerminalPanel";
import { PatchLog } from "./components/PatchLog";
import type {
  ConnectRequest,
  ConnectResponse,
  ScanResult,
  PatchResult,
  CommandResult,
  Session,
} from "./types";

type Tab = "connect" | "scan" | "terminal" | "logs";

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
    setTimeout(() => setError(null), 6000);
  };

  const showSuccess = (msg: string) => {
    setSuccessMsg(msg);
    setTimeout(() => setSuccessMsg(null), 4000);
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
    setActiveTab("connect");
    showSuccess("已断开连接");
  };

  const handleScan = async () => {
    if (!session) return;
    setScanning(true);
    setError(null);
    try {
      const result = await invoke<ScanResult>("scan_vulnerabilities", {
        sessionId: session.id,
      });
      setScanResult(result);
      const total = result.vulnerabilities.length;
      showSuccess(`扫描完成，发现 ${total} 个安全问题`);
    } catch (err) {
      showError(`扫描失败: ${err}`);
    } finally {
      setScanning(false);
    }
  };

  const handlePatchOne = async (vulnId: string, cmd: string) => {
    if (!session) return;
    setPatching(vulnId);
    try {
      const result = await invoke<PatchResult>("apply_vulnerability_patch", {
        sessionId: session.id,
        vulnerabilityId: vulnId,
        patchCommand: cmd,
      });
      setPatchLogs(prev => [...prev, result]);
      if (result.success) {
        showSuccess(`漏洞 ${vulnId} 修补成功`);
        // Re-scan to update results
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

  const handlePatchAll = async () => {
    if (!session) return;
    setPatching("all");
    try {
      const result = await invoke<PatchResult>("apply_all_patches", {
        sessionId: session.id,
      });
      setPatchLogs(prev => [...prev, result]);
      if (result.success) {
        showSuccess("全量安全升级完成");
        await handleScan();
      } else {
        showError(`全量升级失败: ${result.error}`);
        setActiveTab("logs");
      }
    } catch (err) {
      showError(`全量升级出错: ${err}`);
    } finally {
      setPatching(null);
    }
  };

  const handleExecute = async (cmd: string): Promise<CommandResult> => {
    if (!session) throw new Error("未连接");
    return invoke<CommandResult>("execute_command", {
      sessionId: session.id,
      command: cmd,
    });
  };

  const tabs: { id: Tab; label: string; icon: string; disabled?: boolean }[] = [
    { id: "connect", label: "连接", icon: "🔌" },
    { id: "scan", label: "漏洞扫描", icon: "🔍", disabled: !session },
    { id: "terminal", label: "终端", icon: "💻", disabled: !session },
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
              <span className="conn-label">
                {session.username}@{session.host}:{session.port}
              </span>
            </div>
            <button className="btn btn-sm btn-ghost" onClick={handleDisconnect}>
              断开
            </button>
          </div>
        )}
      </header>

      {error && (
        <div className="alert alert-error">
          <span className="icon">⚠️</span> {error}
        </div>
      )}
      {successMsg && (
        <div className="alert alert-success">
          <span className="icon">✅</span> {successMsg}
        </div>
      )}

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
            scanResult={scanResult}
            scanning={scanning}
            onScan={handleScan}
            onPatchOne={handlePatchOne}
            onPatchAll={handlePatchAll}
            patching={patching}
          />
        )}
        {activeTab === "terminal" && session && (
          <TerminalPanel
            onExecute={handleExecute}
            disabled={!session}
          />
        )}
        {activeTab === "logs" && (
          <PatchLog logs={patchLogs} />
        )}
      </main>
    </div>
  );
}
