import { useState } from "react";
import { invoke } from "@tauri-apps/api/core";
import type { PatchResult, Vulnerability } from "../types";

type StepState = "idle" | "running" | "ok" | "fail" | "warn";

interface StepResult {
  state: StepState;
  output: string;
}

interface Props {
  sessionId: string;
  vuln: Vulnerability;
  onClose: () => void;
  onGoTelnet: () => void;
  onRescan: () => void;
}

const STEP_ICONS: Record<StepState, string> = {
  idle: "○",
  running: "⏳",
  ok: "✅",
  fail: "❌",
  warn: "⚠️",
};

export function GuidedPatchWizard({ sessionId, vuln, onClose, onGoTelnet, onRescan }: Props) {
  const [steps, setSteps] = useState<Record<string, StepResult>>({});

  const setState = (id: string, s: Partial<StepResult>) =>
    setSteps(prev => {
      const existing = prev[id] ?? { state: "idle" as StepState, output: "" };
      return { ...prev, [id]: { ...existing, ...s } };
    });

  const get = (id: string): StepResult =>
    steps[id] ?? { state: "idle", output: "" };

  // ── Step handlers ──────────────────────────────────────────

  const doInstallTelnet = async () => {
    setState("telnet_install", { state: "running", output: "" });
    try {
      const out = await invoke<string>("step_setup_telnet", { sessionId });
      setState("telnet_install", { state: "ok", output: out });
    } catch (e) {
      setState("telnet_install", { state: "fail", output: String(e) });
    }
  };

  const doCheckTelnet = async () => {
    setState("telnet_check", { state: "running", output: "" });
    try {
      const [ok, detail] = await invoke<[boolean, string]>("step_check_telnet_port", { sessionId });
      setState("telnet_check", { state: ok ? "ok" : "warn", output: detail });
    } catch (e) {
      setState("telnet_check", { state: "fail", output: String(e) });
    }
  };

  const doPatch = async () => {
    setState("patch", { state: "running", output: "" });
    try {
      const result = await invoke<PatchResult>("apply_vulnerability_patch", {
        sessionId,
        vulnerabilityId: vuln.id,
        patchCommand: vuln.patch_command,
      });
      setState("patch", {
        state: result.success ? "ok" : "fail",
        output: result.output + (result.error ? `\n错误: ${result.error}` : ""),
      });
    } catch (e) {
      setState("patch", { state: "fail", output: String(e) });
    }
  };

  const doVerifySSH = async () => {
    setState("verify", { state: "running", output: "" });
    try {
      const [ok, detail] = await invoke<[boolean, string]>("step_verify_ssh", { sessionId });
      setState("verify", { state: ok ? "ok" : "fail", output: detail });
    } catch (e) {
      setState("verify", { state: "fail", output: String(e) });
    }
  };

  const doRemoveTelnet = async () => {
    setState("telnet_remove", { state: "running", output: "" });
    try {
      const out = await invoke<string>("step_remove_telnet", { sessionId });
      setState("telnet_remove", { state: "ok", output: out });
    } catch (e) {
      setState("telnet_remove", { state: "fail", output: String(e) });
    }
  };

  const verifyFailed = get("verify").state === "fail";

  return (
    <div className="wizard-overlay">
      <div className="wizard-panel">
        {/* Header */}
        <div className="wizard-header">
          <div>
            <h2 className="wizard-title">🛡️ 引导修补</h2>
            <p className="wizard-vuln">{vuln.cve_id && <span className="cve-badge">{vuln.cve_id}</span>} {vuln.title}</p>
          </div>
          <button className="btn btn-sm btn-ghost" onClick={onClose}>✕ 关闭</button>
        </div>

        <div className="wizard-steps">

          {/* ── Step 1: Install Telnet ── */}
          <Step
            num={1}
            title="安装 Telnet 回退通道"
            desc="修补前先在远程主机上安装 telnetd，万一 SSH 修补失败仍可通过 Telnet 连入恢复。"
            command="apt-get install -y telnetd  /  dnf install -y telnet-server  /  yum install -y telnet-server xinetd"
            result={get("telnet_install")}
            onRun={doInstallTelnet}
          />

          {/* ── Step 2: Verify Telnet port ── */}
          <Step
            num={2}
            title="确认 Telnet 端口 23 监听"
            desc="检查 telnetd 是否已成功启动并在端口 23 上监听，确保回退通道可用。"
            command="ss -tlnp | grep :23"
            result={get("telnet_check")}
            onRun={doCheckTelnet}
            warning={get("telnet_check").state === "warn"
              ? "端口 23 未监听，可能需要手动启动：systemctl start telnet.socket 或 service inetutils-inetd restart"
              : undefined}
          />

          {/* ── Step 3: Apply patch ── */}
          <Step
            num={3}
            title="执行 SSH 补丁"
            desc="运行补丁命令。此步骤可能重启 sshd，若配置有误可能导致当前 SSH 会话失效。"
            command={vuln.patch_command ?? "（无具体命令，见包管理升级）"}
            result={get("patch")}
            onRun={doPatch}
            highlight
          />

          {/* ── Step 4: Verify SSH ── */}
          <Step
            num={4}
            title="验证 SSH 服务状态"
            desc="检查 sshd 配置语法、服务是否运行、端口 22 是否监听。三项全过说明 SSH 正常。"
            command="sshd -t  &&  systemctl is-active sshd  &&  ss -tlnp | grep :22"
            result={get("verify")}
            onRun={doVerifySSH}
          />

          {/* SSH failed → suggest telnet */}
          {verifyFailed && (
            <div className="wizard-recovery-hint">
              <span className="icon">🚨</span>
              <div>
                <strong>SSH 验证失败</strong> — Telnet 回退通道仍在运行（端口 23）。
                请切换到 Telnet 终端连入服务器排查问题，修复后再继续。
              </div>
              <button className="btn btn-sm btn-danger" onClick={onGoTelnet}>
                📡 打开 Telnet 终端
              </button>
            </div>
          )}

          {/* ── Step 5: Remove Telnet ── */}
          <Step
            num={5}
            title="移除 Telnet"
            desc="SSH 验证通过后，卸载 telnetd 并停止服务。请勿在 SSH 验证失败时执行此步。"
            command="systemctl disable --now telnet.socket  &&  apt-get remove -y telnetd"
            result={get("telnet_remove")}
            onRun={doRemoveTelnet}
            disabled={get("verify").state !== "ok"}
            disabledReason="请先完成 Step 4 并确认 SSH 正常"
          />
        </div>

        {/* Footer */}
        <div className="wizard-footer">
          {get("telnet_remove").state === "ok" && (
            <button className="btn btn-secondary" onClick={() => { onRescan(); onClose(); }}>
              🔍 重新扫描
            </button>
          )}
          <span className="wizard-hint">各步骤可独立重试，顺序由您决定</span>
        </div>
      </div>
    </div>
  );
}

// ── Single Step component ──────────────────────────────────────

function Step({
  num, title, desc, command, result, onRun, warning, highlight, disabled, disabledReason,
}: {
  num: number;
  title: string;
  desc: string;
  command: string;
  result: StepResult;
  onRun: () => void;
  warning?: string;
  highlight?: boolean;
  disabled?: boolean;
  disabledReason?: string;
}) {
  const [expanded, setExpanded] = useState(false);
  const hasOutput = result.output.trim().length > 0;

  return (
    <div className={`wizard-step ${highlight ? "step-highlight" : ""} step-${result.state}`}>
      <div className="wizard-step-header">
        <span className="step-num">{STEP_ICONS[result.state]}</span>
        <div className="step-meta">
          <span className="step-title">Step {num} — {title}</span>
          <span className="step-desc">{desc}</span>
          <code className="step-cmd">{command}</code>
        </div>
        <div className="step-actions">
          {hasOutput && (
            <button className="btn btn-sm btn-ghost" onClick={() => setExpanded(v => !v)}>
              {expanded ? "收起" : "展开"}
            </button>
          )}
          <button
            className={`btn btn-sm ${highlight ? "btn-danger" : "btn-secondary"}`}
            onClick={onRun}
            disabled={result.state === "running" || disabled}
            title={disabled ? disabledReason : undefined}
          >
            {result.state === "running"
              ? <><span className="spinner" /> 执行中...</>
              : result.state === "idle" ? "执行" : "重试"
            }
          </button>
        </div>
      </div>

      {disabled && disabledReason && result.state === "idle" && (
        <p className="step-disabled-msg">🔒 {disabledReason}</p>
      )}
      {warning && <p className="step-warning">⚠️ {warning}</p>}

      {hasOutput && expanded && (
        <pre className="step-output">{result.output}</pre>
      )}
      {hasOutput && !expanded && (
        <p className="step-output-hint" onClick={() => setExpanded(true)}>
          {result.state === "ok" ? "✅" : result.state === "fail" ? "❌" : "⚠️"} 有输出，点击展开查看
        </p>
      )}
    </div>
  );
}
