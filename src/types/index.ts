export interface ConnectRequest {
  host: string;
  port: number;
  username: string;
  auth_type: "password" | "key";
  password?: string;
  key_path?: string;
  key_passphrase?: string;
}

export interface ConnectResponse {
  session_id: string;
  message: string;
}

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export interface Vulnerability {
  id: string;
  cve_id: string | null;
  title: string;
  description: string;
  severity: Severity;
  affected_component: string;
  current_version: string | null;
  fixed_version: string | null;
  patch_command: string | null;
  patchable: boolean;
}

export interface SystemInfo {
  os: string;
  kernel: string;
  arch: string;
  hostname: string;
  openssh_version: string | null;
  package_manager: "apt" | "yum" | "dnf" | "pacman" | "unknown";
}

export interface ScanResult {
  session_id: string;
  system_info: SystemInfo;
  vulnerabilities: Vulnerability[];
  scan_time: string;
  total_critical: number;
  total_high: number;
  total_medium: number;
  total_low: number;
}

export interface PatchResult {
  vulnerability_id: string;
  success: boolean;
  output: string;
  error: string | null;
}

export interface CommandResult {
  stdout: string;
  stderr: string;
  exit_code: number;
}

export interface GuardedPatchResult {
  telnet_setup_output: string;
  telnet_port: number;
  patch_output: string;
  patch_success: boolean;
  ssh_verified: boolean;
  telnet_removed: boolean;
  telnet_cleanup_output: string;
  error: string | null;
  /** true = telnet still running, user can connect via telnet <host> 23 */
  telnet_still_active: boolean;
}

export interface Session {
  id: string;
  host: string;
  port: number;
  username: string;
  connectedAt: Date;
}
