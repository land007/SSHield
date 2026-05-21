import { useState } from "react";
import type { ScanResult, Severity, Vulnerability } from "../types";
import { GuidedPatchWizard } from "./GuidedPatchWizard";

interface Props {
  sessionId: string;
  scanResult: ScanResult | null;
  scanning: boolean;
  onScan: () => void;
  onPatchDirect: (vulnId: string, cmd: string) => void;
  onPatchAll: () => void;
  patching: string | null;
  onGoTelnet: () => void;
  onRescan: () => void;
}

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: "#ff4444",
  high: "#ff8800",
  medium: "#ffbb00",
  low: "#44aaff",
  info: "#888",
};
const SEVERITY_LABELS: Record<Severity, string> = {
  critical: "严重", high: "高危", medium: "中危", low: "低危", info: "信息",
};
const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function ScanPanel({
  sessionId, scanResult, scanning, onScan,
  onPatchDirect, onPatchAll, patching, onGoTelnet, onRescan,
}: Props) {
  const [wizardVuln, setWizardVuln] = useState<Vulnerability | null>(null);
  const patchableCount = scanResult?.vulnerabilities.filter(v => v.patchable).length ?? 0;

  return (
    <div className="scan-panel">
      {/* Wizard overlay */}
      {wizardVuln && (
        <GuidedPatchWizard
          sessionId={sessionId}
          vuln={wizardVuln}
          onClose={() => setWizardVuln(null)}
          onGoTelnet={() => { setWizardVuln(null); onGoTelnet(); }}
          onRescan={onRescan}
        />
      )}

      <div className="scan-header">
        <h2 className="panel-title">
          <span className="icon">🔍</span> 漏洞扫描
        </h2>
        <div className="scan-actions">
          <button className="btn btn-secondary" onClick={onScan} disabled={scanning}>
            {scanning ? <><span className="spinner" /> 扫描中...</> : <><span className="icon">🔍</span> 开始扫描</>}
          </button>
          {patchableCount > 0 && (
            <button className="btn btn-danger" onClick={onPatchAll} disabled={patching !== null}>
              {patching === "all"
                ? <><span className="spinner" /> 升级中...</>
                : <><span className="icon">⬆️</span> 升级 OpenSSH ({patchableCount})</>}
            </button>
          )}
        </div>
      </div>

      {scanResult && (
        <>
          <div className="system-info-bar">
            <span className="info-item">
              <span className="info-label">主机</span>
              <span className="info-value">{scanResult.system_info.hostname}</span>
            </span>
            <span className="info-item">
              <span className="info-label">系统</span>
              <span className="info-value">{scanResult.system_info.os}</span>
            </span>
            <span className="info-item">
              <span className="info-label">内核</span>
              <span className="info-value">{scanResult.system_info.kernel}</span>
            </span>
            <span className="info-item">
              <span className="info-label">OpenSSH</span>
              <span className="info-value">{scanResult.system_info.openssh_version ?? "未检测到"}</span>
            </span>
            <span className="info-item">
              <span className="info-label">扫描时间</span>
              <span className="info-value">{new Date(scanResult.scan_time).toLocaleString("zh-CN")}</span>
            </span>
          </div>

          <div className="severity-summary">
            {(["critical", "high", "medium", "low"] as Severity[]).map(sev => {
              const count = scanResult.vulnerabilities.filter(v => v.severity === sev).length;
              return (
                <div key={sev} className="severity-badge" style={{ borderColor: SEVERITY_COLORS[sev] }}>
                  <span className="severity-count" style={{ color: SEVERITY_COLORS[sev] }}>{count}</span>
                  <span className="severity-label">{SEVERITY_LABELS[sev]}</span>
                </div>
              );
            })}
          </div>

          {scanResult.vulnerabilities.length === 0 ? (
            <div className="no-vulns">
              <span className="icon">✅</span>
              <p>未发现已知漏洞，系统状态良好</p>
            </div>
          ) : (
            <div className="vuln-list">
              {[...scanResult.vulnerabilities]
                .sort((a, b) => SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity))
                .map(vuln => (
                  <VulnCard
                    key={vuln.id}
                    vuln={vuln}
                    patching={patching === vuln.id}
                    disabled={patching !== null}
                    onGuided={() => setWizardVuln(vuln)}
                    onDirect={() => vuln.patch_command && onPatchDirect(vuln.id, vuln.patch_command)}
                  />
                ))}
            </div>
          )}
        </>
      )}

      {!scanResult && !scanning && (
        <div className="scan-placeholder">
          <span className="icon large-icon">🛡️</span>
          <p>点击「开始扫描」检测远程主机的 SSH 漏洞和安全配置问题</p>
        </div>
      )}
    </div>
  );
}

function VulnCard({ vuln, patching, disabled, onGuided, onDirect }: {
  vuln: Vulnerability;
  patching: boolean;
  disabled: boolean;
  onGuided: () => void;
  onDirect: () => void;
}) {
  return (
    <div className={`vuln-card severity-${vuln.severity}`}>
      <div className="vuln-header">
        <div className="vuln-title-row">
          <span className="severity-pill" style={{ backgroundColor: SEVERITY_COLORS[vuln.severity] }}>
            {SEVERITY_LABELS[vuln.severity]}
          </span>
          {vuln.cve_id && <span className="cve-badge">{vuln.cve_id}</span>}
          <span className="vuln-title">{vuln.title}</span>
        </div>
        <span className="vuln-component">{vuln.affected_component}</span>
      </div>

      <p className="vuln-desc">{vuln.description}</p>

      {(vuln.current_version || vuln.fixed_version) && (
        <div className="version-info">
          {vuln.current_version && (
            <span className="ver-item">
              <span className="ver-label">当前版本:</span>
              <span className="ver-value bad">{vuln.current_version}</span>
            </span>
          )}
          {vuln.fixed_version && (
            <span className="ver-item">
              <span className="ver-label">修复版本:</span>
              <span className="ver-value good">{vuln.fixed_version}</span>
            </span>
          )}
        </div>
      )}

      {vuln.patchable && (
        <div className="vuln-actions">
          {vuln.patch_command && (
            <code className="patch-cmd">
              {vuln.patch_command.split(";")[0].trim()}...
            </code>
          )}
          <div className="vuln-btn-group">
            <button
              className="btn btn-sm btn-safe"
              onClick={onGuided}
              disabled={disabled}
              title="分步引导：先装 Telnet → 补丁 → 验证 SSH → 移除 Telnet"
            >
              🛡️ 引导修补
            </button>
            {vuln.patch_command && (
              <button
                className="btn btn-sm btn-ghost"
                onClick={onDirect}
                disabled={disabled || patching}
                title="直接执行补丁命令，无 Telnet 保护"
              >
                {patching ? <><span className="spinner" /> 执行中...</> : "⚡ 直接修补"}
              </button>
            )}
          </div>
        </div>
      )}

      {vuln.patchable && !vuln.patch_command && (
        <div className="vuln-actions">
          <div className="vuln-btn-group">
            <button className="btn btn-sm btn-safe" onClick={onGuided} disabled={disabled}>
              🛡️ 引导修补
            </button>
          </div>
        </div>
      )}
    </div>
  );
}
