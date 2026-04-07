//! SFTP/SSH protocol implementation.
//!
//! Uses `ssh2` for SFTP operations. Since ssh2 is synchronous,
//! all operations are wrapped with `tokio::task::spawn_blocking`.
//!
//! Supports:
//! - SFTP read/write/stat
//! - SSH key + agent + password authentication

use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use async_trait::async_trait;
use ssh2::Session;

use super::Protocol;
use crate::auth::Credential;
use crate::types::{Method, TransferBody, TransferOutput, TransferRequest, TransferResult};

/// SFTP protocol handler.
pub struct SftpProtocol {
    /// Cached sessions keyed by "host:port".
    sessions: Mutex<std::collections::HashMap<String, Arc<Mutex<Session>>>>,
}

impl SftpProtocol {
    /// Create a new SFTP protocol handler.
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Parse an SFTP URL into (host, port, username, path).
    fn parse_url(url: &str) -> Result<(String, u16, Option<String>, String)> {
        let parsed =
            url::Url::parse(url).with_context(|| format!("invalid SFTP URL: {url}"))?;

        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("SFTP URL must have host: {url}"))?
            .to_string();

        let port = parsed.port().unwrap_or(22);

        let username = if parsed.username().is_empty() {
            None
        } else {
            Some(parsed.username().to_string())
        };

        let path = parsed.path().to_string();
        if path.is_empty() || path == "/" {
            anyhow::bail!("SFTP URL must have a path: {url}");
        }

        Ok((host, port, username, path))
    }

    /// Get or create an SSH session for the given host.
    fn get_session(
        &self,
        host: &str,
        port: u16,
        username: Option<&str>,
        auth: Option<&Credential>,
    ) -> Result<Arc<Mutex<Session>>> {
        let key = format!("{host}:{port}");

        {
            let sessions = self.sessions.lock().unwrap();
            if let Some(session) = sessions.get(&key) {
                return Ok(Arc::clone(session));
            }
        }

        // Create new session.
        let session = Self::create_session(host, port, username, auth)?;
        let session = Arc::new(Mutex::new(session));

        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(key, Arc::clone(&session));

        Ok(session)
    }

    fn create_session(
        host: &str,
        port: u16,
        username: Option<&str>,
        auth: Option<&Credential>,
    ) -> Result<Session> {
        let tcp = TcpStream::connect(format!("{host}:{port}"))
            .with_context(|| format!("connecting to {host}:{port}"))?;

        let mut session = Session::new().context("creating SSH session")?;
        session.set_tcp_stream(tcp);
        session.handshake().context("SSH handshake failed")?;

        let user = username
            .map(|s| s.to_string())
            .or_else(|| std::env::var("USER").ok())
            .unwrap_or_else(|| "root".to_string());

        let mut authenticated = false;

        match auth {
            Some(Credential::SshKey {
                key_path,
                password,
                use_agent,
            }) => {
                // Try SSH agent first if requested.
                if *use_agent {
                    authenticated = try_agent_auth(&session, &user);
                }

                // Try explicit key file.
                if !authenticated {
                    if let Some(ref kp) = key_path {
                        if session
                            .userauth_pubkey_file(
                                &user,
                                None,
                                Path::new(kp),
                                password.as_deref(),
                            )
                            .is_ok()
                        {
                            authenticated = true;
                        }
                    }
                }
            }
            Some(Credential::SshPassword {
                username: ref u,
                ref password,
            }) => {
                session
                    .userauth_password(u, password)
                    .context("SSH password authentication failed")?;
                authenticated = true;
            }
            _ => {
                // Try agent, then default keys.
                authenticated = try_agent_auth(&session, &user);
            }
        }

        // Try default key files if not yet authenticated.
        if !authenticated {
            let home = std::env::var("HOME").unwrap_or_else(|_| "/root".to_string());
            for key_name in &["id_ed25519", "id_rsa"] {
                let key_path = PathBuf::from(&home).join(".ssh").join(key_name);
                if key_path.exists()
                    && session
                        .userauth_pubkey_file(&user, None, &key_path, None)
                        .is_ok()
                {
                    authenticated = true;
                    break;
                }
            }
        }

        if !authenticated {
            anyhow::bail!(
                "SSH authentication failed for {user}@{host}:{port}. \
                 Provide SSH credentials via auth store."
            );
        }

        Ok(session)
    }

    fn sftp_read(session: &Mutex<Session>, path: &str) -> Result<Vec<u8>> {
        let session = session.lock().map_err(|e| anyhow::anyhow!("lock: {e}"))?;
        let sftp = session.sftp().context("opening SFTP channel")?;
        let mut file = sftp
            .open(Path::new(path))
            .with_context(|| format!("opening {path}"))?;
        let mut buf = Vec::new();
        file.read_to_end(&mut buf)
            .with_context(|| format!("reading {path}"))?;
        Ok(buf)
    }

    fn sftp_write(session: &Mutex<Session>, path: &str, data: &[u8]) -> Result<()> {
        let session = session.lock().map_err(|e| anyhow::anyhow!("lock: {e}"))?;
        let sftp = session.sftp().context("opening SFTP channel")?;

        // Ensure parent directory exists.
        if let Some(parent) = Path::new(path).parent() {
            let _ = sftp.mkdir(parent, 0o755);
        }

        let mut file = sftp
            .create(Path::new(path))
            .with_context(|| format!("creating {path}"))?;
        file.write_all(data)
            .with_context(|| format!("writing {path}"))?;
        Ok(())
    }

    fn sftp_stat(session: &Mutex<Session>, path: &str) -> Result<Option<u64>> {
        let session = session.lock().map_err(|e| anyhow::anyhow!("lock: {e}"))?;
        let sftp = session.sftp().context("opening SFTP channel")?;
        match sftp.stat(Path::new(path)) {
            Ok(stat) => Ok(Some(stat.size.unwrap_or(0))),
            Err(_) => Ok(None),
        }
    }

    fn sftp_delete(session: &Mutex<Session>, path: &str) -> Result<()> {
        let session = session.lock().map_err(|e| anyhow::anyhow!("lock: {e}"))?;
        let sftp = session.sftp().context("opening SFTP channel")?;
        sftp.unlink(Path::new(path))
            .with_context(|| format!("deleting {path}"))?;
        Ok(())
    }
}

impl Default for SftpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

fn try_agent_auth(session: &Session, username: &str) -> bool {
    if std::env::var("SSH_AUTH_SOCK").is_err() {
        return false;
    }

    if let Ok(mut agent) = session.agent() {
        if agent.connect().is_ok() && agent.list_identities().is_ok() {
            let identities: Vec<_> = agent.identities().unwrap_or_default();
            for identity in &identities {
                if agent.userauth(username, identity).is_ok() {
                    return true;
                }
            }
        }
    }

    false
}

#[async_trait]
impl Protocol for SftpProtocol {
    async fn execute(
        &self,
        request: &TransferRequest,
        auth: Option<&Credential>,
    ) -> Result<TransferResult> {
        let (host, port, username, remote_path) = Self::parse_url(&request.url)?;

        let session =
            self.get_session(&host, port, username.as_deref(), auth)?;

        match request.method {
            Method::Get => {
                let session_clone = Arc::clone(&session);
                let path = remote_path.clone();

                let data = tokio::task::spawn_blocking(move || {
                    Self::sftp_read(&session_clone, &path)
                })
                .await
                .context("SFTP read task panicked")??;

                let bytes_transferred = data.len() as u64;

                match &request.output {
                    TransferOutput::Memory => Ok(TransferResult {
                        status: 200,
                        headers: Vec::new(),
                        bytes_transferred,
                        content_length: Some(bytes_transferred),
                        body: Some(data),
                        hash: None,
                        resumed: false,
                    }),
                    TransferOutput::File(file_path) => {
                        if let Some(parent) = file_path.parent() {
                            tokio::fs::create_dir_all(parent).await?;
                        }
                        tokio::fs::write(file_path, &data).await?;
                        Ok(TransferResult {
                            status: 200,
                            headers: Vec::new(),
                            bytes_transferred,
                            content_length: Some(bytes_transferred),
                            body: None,
                            hash: None,
                            resumed: false,
                        })
                    }
                    TransferOutput::Callback(_) => Ok(TransferResult {
                        status: 200,
                        headers: Vec::new(),
                        bytes_transferred,
                        content_length: Some(bytes_transferred),
                        body: Some(data),
                        hash: None,
                        resumed: false,
                    }),
                }
            }
            Method::Put => {
                let data = match &request.body {
                    Some(TransferBody::Bytes(b)) => b.clone(),
                    Some(TransferBody::File(path)) => {
                        tokio::fs::read(path)
                            .await
                            .with_context(|| format!("reading {}", path.display()))?
                    }
                    Some(TransferBody::Stream(_)) => {
                        anyhow::bail!("stream body not supported for SFTP");
                    }
                    None => Vec::new(),
                };

                let data_len = data.len() as u64;
                let session_clone = Arc::clone(&session);
                let path = remote_path.clone();

                tokio::task::spawn_blocking(move || {
                    Self::sftp_write(&session_clone, &path, &data)
                })
                .await
                .context("SFTP write task panicked")??;

                Ok(TransferResult {
                    status: 200,
                    headers: Vec::new(),
                    bytes_transferred: data_len,
                    content_length: Some(data_len),
                    body: None,
                    hash: None,
                    resumed: false,
                })
            }
            Method::Head => {
                let session_clone = Arc::clone(&session);
                let path = remote_path.clone();

                let size = tokio::task::spawn_blocking(move || {
                    Self::sftp_stat(&session_clone, &path)
                })
                .await
                .context("SFTP stat task panicked")??;

                match size {
                    Some(s) => Ok(TransferResult {
                        status: 200,
                        headers: Vec::new(),
                        bytes_transferred: 0,
                        content_length: Some(s),
                        body: None,
                        hash: None,
                        resumed: false,
                    }),
                    None => Ok(TransferResult {
                        status: 404,
                        headers: Vec::new(),
                        bytes_transferred: 0,
                        content_length: None,
                        body: None,
                        hash: None,
                        resumed: false,
                    }),
                }
            }
            Method::Delete => {
                let session_clone = Arc::clone(&session);
                let path = remote_path.clone();

                tokio::task::spawn_blocking(move || {
                    Self::sftp_delete(&session_clone, &path)
                })
                .await
                .context("SFTP delete task panicked")??;

                Ok(TransferResult {
                    status: 204,
                    headers: Vec::new(),
                    bytes_transferred: 0,
                    content_length: None,
                    body: None,
                    hash: None,
                    resumed: false,
                })
            }
        }
    }

    fn supports_resume(&self) -> bool {
        false
    }

    fn supports_multipart(&self) -> bool {
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_url() {
        let (host, port, user, path) =
            SftpProtocol::parse_url("sftp://user@host.example.com:2222/home/user/file.txt")
                .unwrap();
        assert_eq!(host, "host.example.com");
        assert_eq!(port, 2222);
        assert_eq!(user, Some("user".to_string()));
        assert_eq!(path, "/home/user/file.txt");
    }

    #[test]
    fn test_parse_url_defaults() {
        let (host, port, user, path) =
            SftpProtocol::parse_url("sftp://host.com/path/file.txt").unwrap();
        assert_eq!(host, "host.com");
        assert_eq!(port, 22);
        assert_eq!(user, None);
        assert_eq!(path, "/path/file.txt");
    }

    #[test]
    fn test_parse_url_ssh_scheme() {
        let (host, port, _, path) =
            SftpProtocol::parse_url("ssh://host.com/path").unwrap();
        assert_eq!(host, "host.com");
        assert_eq!(port, 22);
        assert_eq!(path, "/path");
    }

    #[test]
    fn test_parse_url_no_path() {
        assert!(SftpProtocol::parse_url("sftp://host.com/").is_err());
    }
}
