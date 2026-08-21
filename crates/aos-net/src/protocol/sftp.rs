//! SFTP/SSH protocol implementation.
//!
//! Uses `ssh2` for SFTP operations. Since ssh2 is synchronous,
//! all operations are wrapped with `tokio::task::spawn_blocking`.
//! Reads and writes use 32KB chunked I/O to avoid buffering entire
//! files in memory.
//!
//! Supports:
//! - SFTP read/write/stat (chunked)
//! - SSH key + agent + password authentication
//! - Idle session eviction

use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use ssh2::Session;

use super::{ByteStream, Protocol};
use crate::auth::Credential;
use crate::types::{Method, TransferBody, TransferOutput, TransferRequest, TransferResult};

/// Size of read/write chunks for SFTP I/O.
const SFTP_CHUNK_SIZE: usize = 32 * 1024; // 32KB

/// A cached session with last-used timestamp for idle eviction.
struct CachedSession {
    session: Arc<Mutex<Session>>,
    last_used: Instant,
}

/// SFTP protocol handler.
///
/// SSH sessions are cached per `host:port` and reused across
/// transfers; sessions idle longer than the configured timeout are
/// evicted on the next access. Because the underlying `ssh2` library
/// is synchronous, all remote I/O runs on the Tokio blocking thread
/// pool.
pub struct SftpProtocol {
    /// Cached sessions keyed by "host:port".
    sessions: Mutex<BTreeMap<String, CachedSession>>,
    /// Idle timeout for cached sessions.
    idle_timeout: Duration,
}

impl SftpProtocol {
    /// Create a new SFTP protocol handler with default idle timeout (90s).
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(BTreeMap::new()),
            idle_timeout: Duration::from_secs(90),
        }
    }

    /// Create a new SFTP protocol handler with a custom idle timeout.
    pub fn with_idle_timeout(idle_timeout: Duration) -> Self {
        Self {
            sessions: Mutex::new(BTreeMap::new()),
            idle_timeout,
        }
    }

    /// Parse an SFTP URL into (host, port, username, path).
    ///
    /// The port defaults to 22 and the username to `None` when absent.
    /// Fails if the URL is malformed, has no host, or has an empty
    /// (`""` or `"/"`) path.
    fn parse_url(url: &str) -> Result<(String, u16, Option<String>, String)> {
        let parsed = url::Url::parse(url).with_context(|| format!("invalid SFTP URL: {url}"))?;

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

    /// Get or create an SSH session for the given host, evicting idle sessions.
    #[allow(clippy::disallowed_methods)]
    fn get_session(
        &self,
        host: &str,
        port: u16,
        username: Option<&str>,
        auth: Option<&Credential>,
    ) -> Result<Arc<Mutex<Session>>> {
        let key = format!("{host}:{port}");
        let now = Instant::now();

        {
            let mut sessions = self.sessions.lock().unwrap();

            // Evict expired sessions.
            sessions.retain(|_, cached| now.duration_since(cached.last_used) < self.idle_timeout);

            if let Some(cached) = sessions.get_mut(&key) {
                cached.last_used = now;
                return Ok(Arc::clone(&cached.session));
            }
        }

        // Create new session.
        let session = Self::create_session(host, port, username, auth)?;
        let session = Arc::new(Mutex::new(session));

        let mut sessions = self.sessions.lock().unwrap();
        sessions.insert(
            key,
            CachedSession {
                session: Arc::clone(&session),
                last_used: now,
            },
        );

        Ok(session)
    }

    /// Connect, handshake, and authenticate a new SSH session.
    ///
    /// The username falls back to `$USER`, then `"root"`. The
    /// authentication chain depends on the credential:
    ///
    /// - [`Credential::SshKey`]: agent (if `use_agent`), then the
    ///   explicit key file.
    /// - [`Credential::SshPassword`]: password auth only.
    /// - No/other credential: agent auth.
    ///
    /// If none of the above succeeds, the default key files
    /// `~/.ssh/id_ed25519` and `~/.ssh/id_rsa` are tried as a last
    /// resort before failing.
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
                if *use_agent {
                    authenticated = try_agent_auth(&session, &user);
                }

                if !authenticated {
                    if let Some(ref kp) = key_path {
                        if session
                            .userauth_pubkey_file(&user, None, Path::new(kp), password.as_deref())
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

    /// Read a remote file in chunks and write to a local file.
    fn sftp_read_to_file(
        session: &Mutex<Session>,
        remote_path: &str,
        local_path: &Path,
    ) -> Result<u64> {
        let session = session.lock().map_err(|e| anyhow::anyhow!("lock: {e}"))?;
        let sftp = session.sftp().context("opening SFTP channel")?;
        let mut remote_file = sftp
            .open(Path::new(remote_path))
            .with_context(|| format!("opening {remote_path}"))?;

        if let Some(parent) = local_path.parent() {
            std::fs::create_dir_all(parent)
                .with_context(|| format!("creating directory {}", parent.display()))?;
        }

        let mut local_file = std::fs::File::create(local_path)
            .with_context(|| format!("creating {}", local_path.display()))?;

        let mut bytes_written: u64 = 0;
        let mut buf = vec![0u8; SFTP_CHUNK_SIZE];

        loop {
            let n = remote_file
                .read(&mut buf)
                .with_context(|| format!("reading {remote_path}"))?;
            if n == 0 {
                break;
            }
            local_file
                .write_all(&buf[..n])
                .with_context(|| format!("writing {}", local_path.display()))?;
            bytes_written += n as u64;
        }

        local_file.flush()?;
        Ok(bytes_written)
    }

    /// Read a remote file in chunks into memory.
    fn sftp_read_to_memory(session: &Mutex<Session>, path: &str) -> Result<Vec<u8>> {
        let session = session.lock().map_err(|e| anyhow::anyhow!("lock: {e}"))?;
        let sftp = session.sftp().context("opening SFTP channel")?;
        let mut file = sftp
            .open(Path::new(path))
            .with_context(|| format!("opening {path}"))?;

        let mut buf = Vec::new();
        let mut chunk = vec![0u8; SFTP_CHUNK_SIZE];

        loop {
            let n = file
                .read(&mut chunk)
                .with_context(|| format!("reading {path}"))?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }

        Ok(buf)
    }

    /// Write data from a local file to a remote path in chunks.
    fn sftp_write_from_file(
        session: &Mutex<Session>,
        remote_path: &str,
        local_path: &Path,
    ) -> Result<u64> {
        let session = session.lock().map_err(|e| anyhow::anyhow!("lock: {e}"))?;
        let sftp = session.sftp().context("opening SFTP channel")?;

        if let Some(parent) = Path::new(remote_path).parent() {
            let _ = sftp.mkdir(parent, 0o755);
        }

        let mut local_file = std::fs::File::open(local_path)
            .with_context(|| format!("opening {}", local_path.display()))?;

        let mut remote_file = sftp
            .create(Path::new(remote_path))
            .with_context(|| format!("creating {remote_path}"))?;

        let mut bytes_written: u64 = 0;
        let mut buf = vec![0u8; SFTP_CHUNK_SIZE];

        loop {
            let n = local_file
                .read(&mut buf)
                .with_context(|| format!("reading {}", local_path.display()))?;
            if n == 0 {
                break;
            }
            remote_file
                .write_all(&buf[..n])
                .with_context(|| format!("writing {remote_path}"))?;
            bytes_written += n as u64;
        }

        Ok(bytes_written)
    }

    /// Write byte data to a remote path in chunks.
    fn sftp_write_bytes(session: &Mutex<Session>, path: &str, data: &[u8]) -> Result<()> {
        let session = session.lock().map_err(|e| anyhow::anyhow!("lock: {e}"))?;
        let sftp = session.sftp().context("opening SFTP channel")?;

        if let Some(parent) = Path::new(path).parent() {
            let _ = sftp.mkdir(parent, 0o755);
        }

        let mut file = sftp
            .create(Path::new(path))
            .with_context(|| format!("creating {path}"))?;

        // Write in chunks to avoid oversized single write.
        for chunk in data.chunks(SFTP_CHUNK_SIZE) {
            file.write_all(chunk)
                .with_context(|| format!("writing {path}"))?;
        }
        Ok(())
    }

    /// Stat a remote path, returning its size, or `None` if it does
    /// not exist (any stat error is treated as not-found).
    fn sftp_stat(session: &Mutex<Session>, path: &str) -> Result<Option<u64>> {
        let session = session.lock().map_err(|e| anyhow::anyhow!("lock: {e}"))?;
        let sftp = session.sftp().context("opening SFTP channel")?;
        match sftp.stat(Path::new(path)) {
            Ok(stat) => Ok(Some(stat.size.unwrap_or(0))),
            Err(_) => Ok(None),
        }
    }

    /// Unlink a remote file.
    fn sftp_delete(session: &Mutex<Session>, path: &str) -> Result<()> {
        let session = session.lock().map_err(|e| anyhow::anyhow!("lock: {e}"))?;
        let sftp = session.sftp().context("opening SFTP channel")?;
        sftp.unlink(Path::new(path))
            .with_context(|| format!("deleting {path}"))?;
        Ok(())
    }

    /// Read chunks from SFTP and send them through a channel (for streaming).
    ///
    /// Runs on a blocking thread; stops early (without error) if the
    /// receiving end of the channel is dropped.
    fn sftp_read_to_channel(
        session: &Mutex<Session>,
        path: &str,
        tx: std::sync::mpsc::Sender<Result<Bytes>>,
    ) -> Result<u64> {
        let session = session.lock().map_err(|e| anyhow::anyhow!("lock: {e}"))?;
        let sftp = session.sftp().context("opening SFTP channel")?;
        let mut file = sftp
            .open(Path::new(path))
            .with_context(|| format!("opening {path}"))?;

        let mut bytes_read: u64 = 0;
        let mut buf = vec![0u8; SFTP_CHUNK_SIZE];

        loop {
            let n = file
                .read(&mut buf)
                .with_context(|| format!("reading {path}"))?;
            if n == 0 {
                break;
            }
            bytes_read += n as u64;
            if tx.send(Ok(Bytes::copy_from_slice(&buf[..n]))).is_err() {
                break; // Receiver dropped.
            }
        }

        Ok(bytes_read)
    }
}

impl Default for SftpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

/// Attempt SSH agent authentication, trying every identity the agent
/// offers. Returns `false` immediately if `SSH_AUTH_SOCK` is unset.
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

        let session = self.get_session(&host, port, username.as_deref(), auth)?;

        match request.method {
            Method::Get => {
                match &request.output {
                    TransferOutput::File(file_path) => {
                        let session_clone = Arc::clone(&session);
                        let rpath = remote_path.clone();
                        let lpath = file_path.clone();

                        let bytes_transferred = tokio::task::spawn_blocking(move || {
                            Self::sftp_read_to_file(&session_clone, &rpath, &lpath)
                        })
                        .await
                        .context("SFTP read task panicked")??;

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
                    TransferOutput::Memory => {
                        let session_clone = Arc::clone(&session);
                        let path = remote_path.clone();

                        let data = tokio::task::spawn_blocking(move || {
                            Self::sftp_read_to_memory(&session_clone, &path)
                        })
                        .await
                        .context("SFTP read task panicked")??;

                        let bytes_transferred = data.len() as u64;

                        Ok(TransferResult {
                            status: 200,
                            headers: Vec::new(),
                            bytes_transferred,
                            content_length: Some(bytes_transferred),
                            body: Some(data),
                            hash: None,
                            resumed: false,
                        })
                    }
                    TransferOutput::Callback(ref cb) => {
                        // For callback output, read to memory in chunks then call back.
                        let session_clone = Arc::clone(&session);
                        let path = remote_path.clone();

                        let data = tokio::task::spawn_blocking(move || {
                            Self::sftp_read_to_memory(&session_clone, &path)
                        })
                        .await
                        .context("SFTP read task panicked")??;

                        // Deliver in chunks.
                        let bytes_transferred = data.len() as u64;
                        for chunk in data.chunks(SFTP_CHUNK_SIZE) {
                            cb(chunk)?;
                        }

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
                    TransferOutput::Sink(sink) => {
                        let session_clone = Arc::clone(&session);
                        let path = remote_path.clone();
                        let data = tokio::task::spawn_blocking(move || {
                            Self::sftp_read_to_memory(&session_clone, &path)
                        })
                        .await
                        .context("SFTP read task panicked")??;

                        let bytes_transferred = data.len() as u64;
                        for chunk in data.chunks(SFTP_CHUNK_SIZE) {
                            sink.write(chunk)?;
                        }
                        sink.flush()?;
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
                }
            }
            Method::Put => match &request.body {
                Some(TransferBody::File(path)) => {
                    let session_clone = Arc::clone(&session);
                    let rpath = remote_path.clone();
                    let lpath = path.clone();

                    let bytes_written = tokio::task::spawn_blocking(move || {
                        Self::sftp_write_from_file(&session_clone, &rpath, &lpath)
                    })
                    .await
                    .context("SFTP write task panicked")??;

                    Ok(TransferResult {
                        status: 200,
                        headers: Vec::new(),
                        bytes_transferred: bytes_written,
                        content_length: Some(bytes_written),
                        body: None,
                        hash: None,
                        resumed: false,
                    })
                }
                Some(TransferBody::Bytes(data)) => {
                    let data_len = data.len() as u64;
                    let data = data.clone();
                    let session_clone = Arc::clone(&session);
                    let rpath = remote_path.clone();

                    tokio::task::spawn_blocking(move || {
                        Self::sftp_write_bytes(&session_clone, &rpath, &data)
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
                Some(TransferBody::Stream(_)) => {
                    anyhow::bail!("stream body not supported for SFTP; use TransferBody::File or TransferBody::Bytes");
                }
                None => {
                    let session_clone = Arc::clone(&session);
                    let rpath = remote_path.clone();

                    tokio::task::spawn_blocking(move || {
                        Self::sftp_write_bytes(&session_clone, &rpath, &[])
                    })
                    .await
                    .context("SFTP write task panicked")??;

                    Ok(TransferResult {
                        status: 200,
                        headers: Vec::new(),
                        bytes_transferred: 0,
                        content_length: Some(0),
                        body: None,
                        hash: None,
                        resumed: false,
                    })
                }
            },
            Method::Head => {
                let session_clone = Arc::clone(&session);
                let path = remote_path.clone();

                let size =
                    tokio::task::spawn_blocking(move || Self::sftp_stat(&session_clone, &path))
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

                tokio::task::spawn_blocking(move || Self::sftp_delete(&session_clone, &path))
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
            Method::Post => {
                anyhow::bail!("POST is not supported by the SFTP protocol");
            }
        }
    }

    async fn stream(
        &self,
        request: &TransferRequest,
        auth: Option<&Credential>,
    ) -> Result<(TransferResult, ByteStream)> {
        if request.method != Method::Get {
            // Non-GET: use default fallback.
            let result = self.execute(request, auth).await?;
            let body_bytes = result.body.clone().unwrap_or_default();
            let stream: ByteStream = Box::pin(futures_util::stream::once(async move {
                Ok(Bytes::from(body_bytes))
            }));
            return Ok((result, stream));
        }

        let (host, port, username, remote_path) = Self::parse_url(&request.url)?;
        let session = self.get_session(&host, port, username.as_deref(), auth)?;

        // Get file size for content_length.
        let session_stat = Arc::clone(&session);
        let stat_path = remote_path.clone();
        let size = tokio::task::spawn_blocking(move || Self::sftp_stat(&session_stat, &stat_path))
            .await
            .context("SFTP stat task panicked")??;

        let result = TransferResult {
            status: 200,
            headers: Vec::new(),
            bytes_transferred: 0,
            content_length: size,
            body: None,
            hash: None,
            resumed: false,
        };

        // Create a channel-based stream: spawn_blocking reads SFTP chunks
        // and sends them through a std channel, which we convert to an async stream.
        let (tx, rx) = std::sync::mpsc::channel::<Result<Bytes>>();
        let session_clone = Arc::clone(&session);
        let path = remote_path.clone();

        tokio::task::spawn_blocking(move || {
            let _ = Self::sftp_read_to_channel(&session_clone, &path, tx);
        });

        let stream: ByteStream = Box::pin(futures_util::stream::unfold(rx, |rx| async move {
            // Try to receive from the blocking reader.
            match rx.recv() {
                Ok(item) => Some((item, rx)),
                Err(_) => None, // Channel closed = EOF.
            }
        }));

        Ok((result, stream))
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
        let (host, port, _, path) = SftpProtocol::parse_url("ssh://host.com/path").unwrap();
        assert_eq!(host, "host.com");
        assert_eq!(port, 22);
        assert_eq!(path, "/path");
    }

    #[test]
    fn test_parse_url_no_path() {
        assert!(SftpProtocol::parse_url("sftp://host.com/").is_err());
    }

    #[test]
    fn test_idle_timeout_config() {
        let proto = SftpProtocol::with_idle_timeout(Duration::from_secs(30));
        assert_eq!(proto.idle_timeout, Duration::from_secs(30));
    }
}
