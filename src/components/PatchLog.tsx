import type { PatchResult } from "../types";

interface Props {
  logs: PatchResult[];
}

export function PatchLog({ logs }: Props) {
  if (logs.length === 0) return null;

  return (
    <div className="patch-log-panel">
      <h3 className="panel-title">
        <span className="icon">📋</span> 修补日志
      </h3>
      <div className="patch-log-list">
        {[...logs].reverse().map((log, i) => (
          <div key={i} className={`patch-log-entry ${log.success ? "success" : "failed"}`}>
            <div className="patch-log-header">
              <span className={`status-dot ${log.success ? "ok" : "err"}`} />
              <span className="patch-log-id">{log.vulnerability_id || "全量升级"}</span>
              <span className="patch-log-status">{log.success ? "修补成功" : "修补失败"}</span>
            </div>
            {log.output && (
              <pre className="patch-log-output">{log.output.slice(0, 2000)}</pre>
            )}
            {log.error && (
              <pre className="patch-log-error">{log.error}</pre>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}
