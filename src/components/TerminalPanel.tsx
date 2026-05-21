import { useRef, useState } from "react";
import type { CommandResult } from "../types";

interface LogEntry {
  type: "cmd" | "stdout" | "stderr" | "error" | "info";
  content: string;
  timestamp: Date;
}

interface Props {
  onExecute: (cmd: string) => Promise<CommandResult>;
  disabled: boolean;
}

export function TerminalPanel({ onExecute, disabled }: Props) {
  const [input, setInput] = useState("");
  const [log, setLog] = useState<LogEntry[]>([
    { type: "info", content: "终端就绪。在下方输入命令并回车执行。", timestamp: new Date() },
  ]);
  const [history, setHistory] = useState<string[]>([]);
  const [histIdx, setHistIdx] = useState(-1);
  const [running, setRunning] = useState(false);
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

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    const cmd = input.trim();
    if (!cmd || running) return;

    setHistory(prev => [cmd, ...prev.slice(0, 49)]);
    setHistIdx(-1);
    setInput("");
    setRunning(true);

    appendLog({ type: "cmd", content: `$ ${cmd}`, timestamp: new Date() });

    try {
      const result = await onExecute(cmd);
      if (result.stdout.trim()) {
        appendLog({ type: "stdout", content: result.stdout, timestamp: new Date() });
      }
      if (result.stderr.trim()) {
        appendLog({ type: "stderr", content: result.stderr, timestamp: new Date() });
      }
      if (result.exit_code !== 0) {
        appendLog({
          type: "error",
          content: `退出码: ${result.exit_code}`,
          timestamp: new Date(),
        });
      }
    } catch (err) {
      appendLog({
        type: "error",
        content: String(err),
        timestamp: new Date(),
      });
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

  const clearLog = () => {
    setLog([{ type: "info", content: "日志已清空", timestamp: new Date() }]);
  };

  return (
    <div className="terminal-panel">
      <div className="terminal-header">
        <h2 className="panel-title">
          <span className="icon">💻</span> 远程终端
        </h2>
        <button className="btn btn-sm btn-ghost" onClick={clearLog}>清空</button>
      </div>

      <div className="terminal-log" ref={logRef}>
        {log.map((entry, i) => (
          <div key={i} className={`log-entry log-${entry.type}`}>
            <span className="log-time">
              {entry.timestamp.toLocaleTimeString("zh-CN")}
            </span>
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

      <form onSubmit={handleSubmit} className="terminal-input-row">
        <span className="prompt">$</span>
        <input
          type="text"
          className="terminal-input"
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder="输入命令... (↑↓ 查看历史)"
          disabled={disabled || running}
          autoComplete="off"
          spellCheck={false}
        />
        <button
          type="submit"
          className="btn btn-sm btn-secondary"
          disabled={disabled || running || !input.trim()}
        >
          执行
        </button>
      </form>
    </div>
  );
}
