import { useState } from "react";
import type { ConnectRequest } from "../types";

interface Props {
  onConnect: (req: ConnectRequest) => Promise<void>;
  connecting: boolean;
}

export function ConnectPanel({ onConnect, connecting }: Props) {
  const [host, setHost] = useState("");
  const [port, setPort] = useState("22");
  const [username, setUsername] = useState("");
  const [authType, setAuthType] = useState<"password" | "key">("password");
  const [password, setPassword] = useState("");
  const [keyPath, setKeyPath] = useState("");
  const [keyPassphrase, setKeyPassphrase] = useState("");

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    await onConnect({
      host: host.trim(),
      port: parseInt(port) || 22,
      username: username.trim(),
      auth_type: authType,
      password: authType === "password" ? password : undefined,
      key_path: authType === "key" ? keyPath.trim() : undefined,
      key_passphrase: authType === "key" && keyPassphrase ? keyPassphrase : undefined,
    });
  };

  return (
    <div className="connect-panel">
      <h2 className="panel-title">
        <span className="icon">🔌</span> 新建 SSH 连接
      </h2>
      <form onSubmit={handleSubmit} className="connect-form">
        <div className="form-row">
          <div className="form-group flex-3">
            <label>主机地址</label>
            <input
              type="text"
              value={host}
              onChange={e => setHost(e.target.value)}
              placeholder="192.168.1.100 或 hostname"
              required
            />
          </div>
          <div className="form-group flex-1">
            <label>端口</label>
            <input
              type="number"
              value={port}
              onChange={e => setPort(e.target.value)}
              min="1" max="65535"
              placeholder="22"
            />
          </div>
        </div>

        <div className="form-group">
          <label>用户名</label>
          <input
            type="text"
            value={username}
            onChange={e => setUsername(e.target.value)}
            placeholder="root 或 ubuntu"
            required
          />
        </div>

        <div className="form-group">
          <label>认证方式</label>
          <div className="auth-tabs">
            <button
              type="button"
              className={`auth-tab ${authType === "password" ? "active" : ""}`}
              onClick={() => setAuthType("password")}
            >
              密码认证
            </button>
            <button
              type="button"
              className={`auth-tab ${authType === "key" ? "active" : ""}`}
              onClick={() => setAuthType("key")}
            >
              私钥认证
            </button>
          </div>
        </div>

        {authType === "password" ? (
          <div className="form-group">
            <label>密码</label>
            <input
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="SSH 密码"
              required
            />
          </div>
        ) : (
          <>
            <div className="form-group">
              <label>私钥路径</label>
              <input
                type="text"
                value={keyPath}
                onChange={e => setKeyPath(e.target.value)}
                placeholder="~/.ssh/id_rsa 或绝对路径"
                required
              />
            </div>
            <div className="form-group">
              <label>私钥密码（可选）</label>
              <input
                type="password"
                value={keyPassphrase}
                onChange={e => setKeyPassphrase(e.target.value)}
                placeholder="如私钥有密码请填写"
              />
            </div>
          </>
        )}

        <button
          type="submit"
          className="btn btn-primary btn-full"
          disabled={connecting}
        >
          {connecting ? (
            <><span className="spinner" /> 连接中...</>
          ) : (
            <><span className="icon">🔗</span> 建立连接</>
          )}
        </button>
      </form>
    </div>
  );
}
