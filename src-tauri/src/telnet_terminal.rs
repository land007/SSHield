use anyhow::{anyhow, Result};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;
use uuid::Uuid;

// ── Telnet protocol constants ────────────────────────────────
const IAC: u8 = 0xFF;
const WILL: u8 = 0xFB;
const WONT: u8 = 0xFC;
const DO: u8 = 0xFD;
const DONT: u8 = 0xFE;
const SB: u8 = 0xFA;
const SE: u8 = 0xF0;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelnetSession {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub username: String,
}

struct Conn {
    stream: TcpStream,
}

impl Conn {
    /// Read raw bytes until timeout. Drains the socket.
    fn read_available(&mut self, timeout: Duration) -> Vec<u8> {
        let _ = self.stream.set_read_timeout(Some(timeout));
        let mut buf = [0u8; 4096];
        let mut out = Vec::new();
        loop {
            match self.stream.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => out.extend_from_slice(&buf[..n]),
                Err(_) => break, // timeout or error = stop reading
            }
        }
        out
    }

    /// Write bytes to the socket.
    fn write_all(&mut self, data: &[u8]) -> Result<()> {
        self.stream.write_all(data)
            .map_err(|e| anyhow!("telnet write error: {}", e))
    }

    /// Process IAC option negotiation: refuse everything.
    /// Returns clean text bytes and any responses to send back.
    fn process_iac(raw: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut text = Vec::new();
        let mut response = Vec::new();
        let mut i = 0;
        while i < raw.len() {
            if raw[i] != IAC {
                text.push(raw[i]);
                i += 1;
                continue;
            }
            i += 1;
            if i >= raw.len() { break; }
            match raw[i] {
                WILL => {
                    // Server will do X → we say DON'T
                    i += 1;
                    if i < raw.len() {
                        response.extend_from_slice(&[IAC, DONT, raw[i]]);
                        i += 1;
                    }
                }
                DO => {
                    // Server wants us to do X → we say WON'T
                    i += 1;
                    if i < raw.len() {
                        response.extend_from_slice(&[IAC, WONT, raw[i]]);
                        i += 1;
                    }
                }
                WONT | DONT => {
                    i += 2; // skip option byte
                }
                SB => {
                    // Sub-negotiation: skip until IAC SE
                    i += 1;
                    while i + 1 < raw.len() {
                        if raw[i] == IAC && raw[i + 1] == SE { i += 2; break; }
                        i += 1;
                    }
                }
                _ => { i += 1; }
            }
        }
        (text, response)
    }

    /// Strip ANSI escape sequences and non-printable chars (except \r \n \t).
    fn clean(bytes: &[u8]) -> String {
        let s = String::from_utf8_lossy(bytes);
        let mut out = String::with_capacity(s.len());
        let mut chars = s.chars().peekable();
        while let Some(c) = chars.next() {
            if c == '\x1b' {
                // ESC sequence: skip until letter
                while let Some(&nc) = chars.peek() {
                    chars.next();
                    if nc.is_ascii_alphabetic() || nc == 'm' || nc == 'J' || nc == 'H' { break; }
                }
                continue;
            }
            if c == '\r' { continue; } // collapse \r\n → \n
            if c.is_control() && c != '\n' && c != '\t' { continue; }
            out.push(c);
        }
        out
    }

    /// Read until any of the given needle strings appear, or timeout expires.
    fn read_until(&mut self, needles: &[&str], timeout: Duration) -> Result<String> {
        let deadline = std::time::Instant::now() + timeout;
        let mut buf = Vec::new();

        loop {
            if std::time::Instant::now() >= deadline {
                let text = Self::clean(&buf);
                return Err(anyhow!(
                    "timeout waiting for {:?}\nGot so far:\n{}",
                    needles, text
                ));
            }
            let remaining = deadline - std::time::Instant::now();
            let chunk_timeout = remaining.min(Duration::from_millis(200));
            let _ = self.stream.set_read_timeout(Some(chunk_timeout));
            let mut tmp = [0u8; 1024];
            match self.stream.read(&mut tmp) {
                Ok(0) => continue,
                Ok(n) => {
                    let (text_bytes, iac_resp) = Self::process_iac(&tmp[..n]);
                    if !iac_resp.is_empty() {
                        let _ = self.stream.write_all(&iac_resp);
                    }
                    buf.extend_from_slice(&text_bytes);
                    let s = String::from_utf8_lossy(&buf).to_lowercase();
                    for needle in needles {
                        if s.contains(&needle.to_lowercase()) {
                            return Ok(Self::clean(&buf));
                        }
                    }
                }
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                       || e.kind() == std::io::ErrorKind::TimedOut => {
                    // keep waiting
                }
                Err(e) => return Err(anyhow!("read error: {}", e)),
            }
        }
    }

    /// Send a line (appends \r\n).
    fn send_line(&mut self, line: &str) -> Result<()> {
        let mut data = line.as_bytes().to_vec();
        data.extend_from_slice(b"\r\n");
        self.write_all(&data)
    }

    /// Send a command, read output until shell prompt ($ or #) or timeout.
    fn exec(&mut self, command: &str, timeout: Duration) -> Result<String> {
        self.send_line(command)?;
        // Read with a generous timeout; stop when we see a shell prompt at EOL
        let deadline = std::time::Instant::now() + timeout;
        let mut buf = Vec::new();
        let mut stable_rounds = 0;
        let mut last_len = 0;

        loop {
            if std::time::Instant::now() >= deadline { break; }
            let remaining = deadline - std::time::Instant::now();
            let chunk = remaining.min(Duration::from_millis(300));
            let _ = self.stream.set_read_timeout(Some(chunk));
            let mut tmp = [0u8; 4096];
            match self.stream.read(&mut tmp) {
                Ok(0) => break,
                Ok(n) => {
                    let (text_bytes, iac_resp) = Self::process_iac(&tmp[..n]);
                    if !iac_resp.is_empty() { let _ = self.stream.write_all(&iac_resp); }
                    buf.extend_from_slice(&text_bytes);
                    // Check if last non-empty line looks like a shell prompt
                    let text = Self::clean(&buf);
                    let last_line = text.lines().rev()
                        .find(|l| !l.trim().is_empty())
                        .unwrap_or("");
                    if last_line.trim_end().ends_with('$')
                        || last_line.trim_end().ends_with('#')
                        || last_line.trim_end().ends_with('>')
                    {
                        stable_rounds += 1;
                        if stable_rounds >= 2 { break; } // two reads at prompt = done
                    }
                }
                Err(_) => {
                    // No more data right now
                    if buf.len() == last_len {
                        stable_rounds += 1;
                        if stable_rounds >= 3 { break; }
                    }
                    last_len = buf.len();
                }
            }
        }
        Ok(Self::clean(&buf))
    }
}

pub struct TelnetManager {
    sessions: Mutex<HashMap<String, Arc<Mutex<Conn>>>>,
}

impl TelnetManager {
    pub fn new() -> Self {
        TelnetManager { sessions: Mutex::new(HashMap::new()) }
    }

    /// Connect and perform login handshake. Returns session_id.
    pub fn connect(
        &self,
        host: &str,
        port: u16,
        username: &str,
        password: &str,
    ) -> Result<String> {
        let stream = TcpStream::connect(format!("{}:{}", host, port))
            .map_err(|e| anyhow!("TCP connect to {}:{} failed: {}", host, port, e))?;
        stream.set_write_timeout(Some(Duration::from_secs(10))).ok();

        let mut conn = Conn { stream };

        // Some servers send a banner immediately, handle IAC before the login prompt
        let banner = conn.read_until(
            &["login:", "username:", "user:", "$", "#"],
            Duration::from_secs(10),
        )?;
        let banner_lower = banner.to_lowercase();

        if banner_lower.contains("login:") || banner_lower.contains("username:") || banner_lower.contains("user:") {
            conn.send_line(username)?;
            let _pw_prompt = conn.read_until(&["password:", "assword:"], Duration::from_secs(8))?;
            conn.send_line(password)?;
        }

        // Wait for shell prompt after login
        let _prompt = conn.read_until(&["$", "#", ">"], Duration::from_secs(15))
            .map_err(|_| anyhow!("Login failed or no shell prompt received. Check credentials."))?;

        let id = Uuid::new_v4().to_string();
        self.sessions.lock().insert(id.clone(), Arc::new(Mutex::new(conn)));
        Ok(id)
    }

    /// Execute a command and return its output.
    pub fn execute(&self, session_id: &str, command: &str, timeout_secs: u64) -> Result<String> {
        let arc = {
            let sessions = self.sessions.lock();
            sessions.get(session_id)
                .ok_or_else(|| anyhow!("Telnet session not found: {}", session_id))?
                .clone()
        };
        let mut guard = arc.lock();
        guard.exec(command, Duration::from_secs(timeout_secs))
    }

    pub fn disconnect(&self, session_id: &str) {
        self.sessions.lock().remove(session_id);
    }

    pub fn is_connected(&self, session_id: &str) -> bool {
        self.sessions.lock().contains_key(session_id)
    }
}
