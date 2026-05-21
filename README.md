# SSHield

SSH 漏洞扫描与补丁管理工具，基于 Tauri 2 构建的跨平台桌面应用。

连接远程 Linux 主机，扫描已知 OpenSSH CVE 及安全配置问题，通过引导式向导安全地完成补丁修复——修补前先建立 Telnet 回退通道，验证 SSH 正常后再移除，防止操作失误导致服务器失联。

---

## 功能特性

### 漏洞扫描
- OpenSSH CVE 检测（regreSSHion、PKCS#11 RCE、ProxyCommand 注入等）
- sshd_config 安全配置审计（PermitRootLogin、PasswordAuthentication、X11Forwarding、Protocol 1）
- OpenSSH 包更新检测（仅检查 openssh 相关包，不扫描全系统）
- Linux 内核版本检查

| CVE | 影响版本 | 严重度 |
|-----|---------|--------|
| CVE-2024-6387 (regreSSHion) | OpenSSH < 9.8p1 | 严重 |
| CVE-2023-38408 | OpenSSH < 9.3p2 | 严重 |
| CVE-2023-51385 | OpenSSH < 9.6 | 高危 |
| CVE-2016-20012 | OpenSSH < 8.7 | 中危 |

### 引导式修补向导
修补前弹出分步向导，每步独立执行，用户全程可控：

```
Step 1  安装 Telnet 回退通道      ← 防止修补失败被锁在外面
Step 2  确认端口 23 监听
Step 3  执行 SSH 补丁             ← 仅升级 openssh-server/openssh-client
Step 4  验证 SSH 服务状态         ← sshd -t + service active + port 22
Step 5  移除 Telnet               ← Step 4 通过后才解锁
```

验证失败时 Telnet 保留运行，可直接切换到内置 Telnet 终端连入恢复。

### SSH 终端
- 通过已建立的 SSH 连接执行任意命令
- 支持命令历史（↑↓）

### Telnet 终端
- 独立的 Telnet 客户端，用于紧急恢复
- 内置快捷命令栏（`sshd -t`、`systemctl restart sshd` 等）
- 自动处理 IAC 协议协商，输出干净可读

### 补丁安全原则
- **只升级 openssh**，不执行全系统 `apt-get upgrade`
- 支持 apt / dnf / yum / pacman 自动检测

---

## 技术栈

| 层 | 技术 |
|----|------|
| 前端 | React 18 + TypeScript + Vite |
| 后端 | Rust + Tauri 2 |
| SSH | `ssh2` crate |
| Telnet | 原生 TCP + 手写 IAC 协议处理 |

---

## 开发环境要求

- [Rust](https://rustup.rs/) 1.70+
- [Node.js](https://nodejs.org/) 18+
- Tauri 系统依赖：[参考官方文档](https://tauri.app/start/prerequisites/)
  - macOS：Xcode Command Line Tools
  - Linux：`libwebkit2gtk-4.1-dev build-essential libssl-dev`
  - Windows：WebView2、MSVC Build Tools

---

## 快速开始

```bash
# 克隆仓库
git clone git@github.com:land007/SSHield.git
cd SSHield

# 安装前端依赖
npm install

# 前端开发服务
npm run dev

# Tauri 桌面开发模式
npm run tauri:dev

# 构建前端
npm run build

# 构建桌面安装包
npm run tauri:build
```

---

## GitHub Actions 自动打包

`.github/workflows/release.yml` 会在以下场景自动构建：

- 推送 tag：`v*`
- 手动触发：Actions → Release → Run workflow

构建目标：

- macOS arm64
- macOS x64
- Linux x64
- Linux arm64
- Windows x64

tag 构建完成后会自动创建 GitHub Release 并上传安装包。

```bash
git tag v0.1.0
git push origin v0.1.0
```

如需 Tauri updater 签名，请在 GitHub 仓库 Secrets 中配置：

- `TAURI_SIGNING_PRIVATE_KEY`
- `TAURI_SIGNING_PRIVATE_KEY_PASSWORD`

---

## 使用流程

1. **连接** — 填写主机地址、端口、用户名，选择密码或私钥认证
2. **扫描** — 点击「开始扫描」，等待结果
3. **修补** — 对每个漏洞点击「🛡️ 引导修补」，按向导逐步操作
4. **验证** — 向导 Step 4 自动验证 SSH 是否正常
5. **清理** — Step 4 通过后执行 Step 5 移除 Telnet

> 如果 SSH 验证失败，切换到「📡 Telnet 终端」标签，用 Telnet 连入排查。

---

## 项目结构

```
SSHield/
├── src/                          # React 前端
│   ├── App.tsx
│   ├── components/
│   │   ├── ConnectPanel.tsx      # SSH 连接表单
│   │   ├── ScanPanel.tsx         # 漏洞扫描结果
│   │   ├── GuidedPatchWizard.tsx # 分步修补向导
│   │   ├── TerminalPanel.tsx     # SSH 终端
│   │   ├── TelnetTerminalPanel.tsx  # Telnet 终端
│   │   └── PatchLog.tsx          # 操作日志
│   └── types/index.ts
├── src-tauri/                    # Rust 后端
│   └── src/
│       ├── lib.rs                # Tauri 命令注册
│       ├── ssh_manager.rs        # SSH 会话管理
│       ├── vulnerability_scanner.rs  # 漏洞扫描引擎
│       ├── telnet_guard.rs       # Telnet 安装/验证/移除
│       └── telnet_terminal.rs    # Telnet 客户端
└── README.md
```

---

## 免责声明

本工具仅用于**授权的服务器运维和安全加固**。请勿用于未经授权的系统。修补操作会修改远程主机的系统配置，使用前请确保已备份重要数据。

---

## License

MIT
