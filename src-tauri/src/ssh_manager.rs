use anyhow::{anyhow, Result};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};
use ssh2::Session;
use std::collections::HashMap;
use std::io::Read;
use std::net::TcpStream;
use std::sync::Arc;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SshConnection {
    pub id: String,
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_method: AuthMethod,
    pub connected: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AuthMethod {
    Password { password: String },
    PrivateKey { key_path: String, passphrase: Option<String> },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CommandResult {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: i32,
}

pub struct SessionStore {
    sessions: Mutex<HashMap<String, Arc<Mutex<Session>>>>,
}

impl SessionStore {
    pub fn new() -> Self {
        SessionStore {
            sessions: Mutex::new(HashMap::new()),
        }
    }

    pub fn connect(&self, conn: &SshConnection) -> Result<String> {
        let addr = format!("{}:{}", conn.host, conn.port);
        let tcp = TcpStream::connect(&addr)
            .map_err(|e| anyhow!("TCP connection failed to {}: {}", addr, e))?;

        let mut session = Session::new()
            .map_err(|e| anyhow!("Failed to create SSH session: {}", e))?;
        session.set_tcp_stream(tcp);
        session.handshake()
            .map_err(|e| anyhow!("SSH handshake failed: {}", e))?;

        match &conn.auth_method {
            AuthMethod::Password { password } => {
                session.userauth_password(&conn.username, password)
                    .map_err(|e| anyhow!("Password authentication failed: {}", e))?;
            }
            AuthMethod::PrivateKey { key_path, passphrase } => {
                let key_path = std::path::Path::new(key_path);
                let passphrase = passphrase.as_deref();
                session.userauth_pubkey_file(&conn.username, None, key_path, passphrase)
                    .map_err(|e| anyhow!("Private key authentication failed: {}", e))?;
            }
        }

        if !session.authenticated() {
            return Err(anyhow!("Authentication failed"));
        }

        let id = Uuid::new_v4().to_string();
        self.sessions.lock().insert(id.clone(), Arc::new(Mutex::new(session)));
        Ok(id)
    }

    pub fn disconnect(&self, session_id: &str) -> Result<()> {
        let mut sessions = self.sessions.lock();
        if let Some(session) = sessions.remove(session_id) {
            let sess = session.lock();
            let _ = sess.disconnect(None, "Bye", None);
        }
        Ok(())
    }

    pub fn execute(&self, session_id: &str, command: &str) -> Result<CommandResult> {
        let sessions = self.sessions.lock();
        let session = sessions.get(session_id)
            .ok_or_else(|| anyhow!("Session not found: {}", session_id))?
            .clone();
        drop(sessions);

        let sess = session.lock();
        let mut channel = sess.channel_session()
            .map_err(|e| anyhow!("Failed to open channel: {}", e))?;

        channel.exec(command)
            .map_err(|e| anyhow!("Failed to execute command: {}", e))?;

        let mut stdout = String::new();
        channel.read_to_string(&mut stdout)
            .map_err(|e| anyhow!("Failed to read stdout: {}", e))?;

        let mut stderr = String::new();
        channel.stderr().read_to_string(&mut stderr)
            .map_err(|e| anyhow!("Failed to read stderr: {}", e))?;

        channel.wait_close()
            .map_err(|e| anyhow!("Failed to wait for channel close: {}", e))?;
        let exit_code = channel.exit_status().unwrap_or(-1);

        Ok(CommandResult { stdout, stderr, exit_code })
    }

    pub fn is_connected(&self, session_id: &str) -> bool {
        self.sessions.lock().contains_key(session_id)
    }
}
