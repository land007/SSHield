import { useRef, useState } from "react";
import { invoke } from "@tauri-apps/api/core";

interface LogEntry {
  type: "cmd" | "output" | "error" | "info" | "system";
  content: string;
  timestamp: Date;
}

interface Props {
  host: string;
  port?: number;
  /** When true: show urgent recovery banner */
  urgentRecovery: boolean;
}

export function TelnetTerminalPanel({ host, port = 23, urgentRecovery }: Props) {
  const [sessionId, setSessionId] = useState<string | null>(null);
  const [connecting, setConnecting] = useState(false);
  const [username, setUsername] = useState("root");
  const [password, setPassword] = useState("");
  const [telnetHost, setTelnetHost] = useState(host);
  const [telnetPort, setTelnetPort] = useState(String(port));
  const [input, setInput] = useState("");
  const [running, setRunning] = useState(false);
  const [history, setHistory] = useState<string[]>([]);
  const [histIdx, setHistIdx] = useState(-1);
  const [log, setLog] = useState<LogEntry[]>([]);
  const logRef = useRef<HTMLDivElement>(null);

  const appendLog = (entry: LogEntry) => {
    setLog(prev => {
      const next = [...prev, entry];
      setTimeout(() => {
        logRef.current?.scrollTo({ top: logRef.current.scrollHeight, behavior: "smooth" });
      }, 0);
      return next;
    });
  };

  const handleConnect = async (e: React.FormEvent) => {
    e.preventDefault();
    setConnecting(true);
    appendLog({ type: "info", content: `正在连接 ${telnetHost}:${telnetPort}...`, timestamp: new Date() });
    try {
      const id = await invoke<string>("telnet_connect", {
        request: {
          host: telnetHost,
          port: parseInt(telnetPort) || 23,
          username,
          password,
        },
      });
      setSessionId(id);
      appendLog({ type: "system", content: `✓ 已连接，登录为 ${username}@${telnetHost}`, timestamp: new Date() });
    } catch (err) {
      appendLog({ type: "error", content: `连接失败: ${err}`, timestamp: new Date() });
    } finally {
      setConnecting(false);
    }
  };

  const handleDisconnect = async () => {
    if (!sessionId) return;
    await invoke("telnet_disconnect", { sessionId });
    setSessionId(null);
    appendLog({ type: "system", content: "已断开 Telnet 连接", timestamp: new Date() });
  };

  const handleExecute = async (e: React.FormEvent) => {
    e.preventDefault();
    const cmd = input.trim();
    if (!cmd || !sessionId || running) return;

    setHistory(prev => [cmd, ...prev.slice(0, 49)]);
    setHistIdx(-1);
    setInput("");
    setRunning(true);
    appendLog({ type: "cmd", content: `$ ${cmd}`, timestamp: new Date() });

    try {
      const output = await invoke<string>("telnet_execute", {
        sessionId,
        command: cmd,
        timeoutSecs: 60,
      });
      if (output.trim()) {
        appendLog({ type: "output", content: output, timestamp: new Date() });
      }
    } catch (err) {
      appendLog({ type: "error", content: String(err), timestamp: new Date() });
    } finally {
      setRunning(false);
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === "ArrowUp") {
      e.preventDefault();
      const newIdx = Math.min(histIdx + 1, history.length - 1);
      setHistIdx(newIdx);
      if (history[newIdx]) setInput(history[newIdx]);
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      const newIdx = Math.max(histIdx - 1, -1);
      setHistIdx(newIdx);
      setInput(newIdx === -1 ? "" : (history[newIdx] ?? ""));
    }
  };

  return (
    <div className="telnet-panel">
      {urgentRecovery && (
        <div className="telnet-urgent-banner">
          <span className="icon">🚨</span>
          <span>SSH 修补失败 — 使用此 Telnet 终端连入恢复。Telnet 服务运行在端口 23。</span>
        </div>
      )}

      {!sessionId ? (
        <div className="telnet-login">
          <h2 className="panel-title">
            <span className="icon">📡</span> Telnet 终端
            {urgentRecovery && <span className="recovery-tag">紧急恢复</span>}
          </h2>
          <form onSubmit={handleConnect} className="telnet-login-form">
            <div className="form-row">
              <div className="form-group flex-3">
                <label>主机</label>
                <input
                  type="text"
                  value={telnetHost}
                  onChange={e => setTelnetHost(e.target.value)}
                  placeholder="IP 或 hostname"
                  required
                />
              </div>
              <div className="form-group flex-1">
                <label>端口</label>
                <input
                  type="number"
                  value={telnetPort}
                  onChange={e => setTelnetPort(e.target.value)}
                  min="1" max="65535"
                />
              </div>
            </div>
            <div className="form-row">
              <div className="form-group flex-1">
                <label>用户名</label>
                <input
                  type="text"
                  value={username}
                  onChange={e => setUsername(e.target.value)}
                  required
                />
              </div>
              <div className="form-group flex-1">
                <label>密码</label>
                <input
                  type="password"
                  value={password}
                  onChange={e => setPassword(e.target.value)}
                  required
                />
              </div>
            </div>
            <button type="submit" className="btn btn-primary btn-full" disabled={connecting}>
              {connecting ? <><span className="spinner" /> 连接中...</> : <><span className="icon">📡</span> 建立 Telnet 连接</>}
            </button>
          </form>

          <div className="telnet-notice">
            <p><strong>⚠️ 安全提示</strong>：Telnet 为明文协议，仅用于紧急恢复。连接成功后请尽快修复 SSH 并断开 Telnet。</p>
            <div className="quick-cmds">
              <p className="quick-cmds-title">常用恢复命令：</p>
              <code>systemctl status sshd</code>
              <code>sshd -t</code>
              <code>systemctl restart sshd</code>
              <code>cp /etc/ssh/sshd_config.bak /etc/ssh/sshd_config &amp;&amp; systemctl restart sshd</code>
            </div>
          </div>
        </div>
      ) : (
        <div className="telnet-connected">
          <div className="terminal-header">
            <div style={{ display: "flex", alignItems: "center", gap: 10 }}>
              <h2 className="panel-title" style={{ margin: 0 }}>
                <span className="icon">📡</span> Telnet — {username}@{telnetHost}:{telnetPort}
              </h2>
              <span className="conn-dot" style={{ background: "#f59e0b" }} />
            </div>
            <div style={{ display: "flex", gap: 8 }}>
              <button
                className="btn btn-sm btn-ghost"
                onClick={() => setLog([])}
              >清空</button>
              <button className="btn btn-sm btn-danger" onClick={handleDisconnect}>
                断开
              </button>
            </div>
          </div>

          <div className="terminal-log telnet-log" ref={logRef}>
            {log.map((entry, i) => (
              <div key={i} className={`log-entry log-${entry.type}`}>
                <span className="log-time">{entry.timestamp.toLocaleTimeString("zh-CN")}</span>
                <pre className="log-content">{entry.content}</pre>
              </div>
            ))}
            {running && (
              <div className="log-entry log-info">
                <span className="log-time">—</span>
                <span className="log-content"><span className="spinner" /> 执行中...</span>
              </div>
            )}
          </div>

          <div className="quick-bar">
            {[
              "systemctl status sshd",
              "sshd -t",
              "systemctl restart sshd",
              "journalctl -u sshd -n 30",
              "cat /etc/ssh/sshd_config | grep -v '^#' | grep -v '^$'",
            ].map(cmd => (
              <button
                key={cmd}
                className="quick-cmd-btn"
                onClick={() => setInput(cmd)}
                disabled={running}
                title={cmd}
              >
                {cmd.split(" ").slice(0, 2).join(" ")}
              </button>
            ))}
          </div>

          <form onSubmit={handleExecute} className="terminal-input-row">
            <span className="prompt telnet-prompt">telnet$</span>
            <input
              type="text"
              className="terminal-input"
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="输入命令... (↑↓ 查看历史)"
              disabled={running}
              autoComplete="off"
              spellCheck={false}
              autoFocus
            />
            <button
              type="submit"
              className="btn btn-sm btn-secondary"
              disabled={running || !input.trim()}
            >
              执行
            </button>
          </form>
        </div>
      )}
    </div>
  );
}
