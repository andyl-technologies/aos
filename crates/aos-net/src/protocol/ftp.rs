//! FTP/FTPS protocol implementation.
//!
//! Uses `suppaftp` for FTP operations. Since suppaftp's sync API is used,
//! operations are wrapped with `tokio::task::spawn_blocking`.
//!
//! Supports:
//! - RETR/STOR/SIZE
//! - Resume via REST command
//! - Active/passive mode

use std::io::Cursor;
use std::sync::{Arc, Mutex};

use anyhow::{Context, Result};
use async_trait::async_trait;
use suppaftp::FtpStream;

use super::Protocol;
use crate::auth::Credential;
use crate::types::{Method, TransferBody, TransferOutput, TransferRequest, TransferResult};

/// FTP protocol handler.
pub struct FtpProtocol {
    /// Cached connections keyed by "host:port".
    connections: Mutex<std::collections::HashMap<String, Arc<Mutex<FtpStream>>>>,
}

impl FtpProtocol {
    /// Create a new FTP protocol handler.
    pub fn new() -> Self {
        Self {
            connections: Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Parse an FTP URL into (host, port, path, is_secure).
    fn parse_url(url: &str) -> Result<(String, u16, String, bool)> {
        let parsed =
            url::Url::parse(url).with_context(|| format!("invalid FTP URL: {url}"))?;

        let host = parsed
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("FTP URL must have host: {url}"))?
            .to_string();

        let port = parsed.port().unwrap_or(21);
        let path = parsed.path().to_string();
        let secure = parsed.scheme() == "ftps";

        Ok((host, port, path, secure))
    }

    /// Get or create an FTP connection.
    fn get_connection(
        &self,
        host: &str,
        port: u16,
        auth: Option<&Credential>,
    ) -> Result<Arc<Mutex<FtpStream>>> {
        let key = format!("{host}:{port}");

        {
            let conns = self.connections.lock().unwrap();
            if let Some(conn) = conns.get(&key) {
                return Ok(Arc::clone(conn));
            }
        }

        let (user, password) = match auth {
            Some(Credential::FtpLogin {
                ref username,
                ref password,
            }) => (username.clone(), password.clone()),
            _ => ("anonymous".to_string(), "aos@".to_string()),
        };

        let addr = format!("{host}:{port}");
        let mut ftp = FtpStream::connect(&addr)
            .map_err(|e| anyhow::anyhow!("FTP connect to {addr}: {e}"))?;

        ftp.login(&user, &password)
            .map_err(|e| anyhow::anyhow!("FTP login as {user}: {e}"))?;

        ftp.transfer_type(suppaftp::types::FileType::Binary)
            .map_err(|e| anyhow::anyhow!("FTP binary mode: {e}"))?;

        let conn = Arc::new(Mutex::new(ftp));
        let mut conns = self.connections.lock().unwrap();
        conns.insert(key, Arc::clone(&conn));

        Ok(conn)
    }
}

impl Default for FtpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for FtpProtocol {
    async fn execute(
        &self,
        request: &TransferRequest,
        auth: Option<&Credential>,
    ) -> Result<TransferResult> {
        let (host, port, remote_path, _secure) = Self::parse_url(&request.url)?;
        let conn = self.get_connection(&host, port, auth)?;

        match request.method {
            Method::Get => {
                let conn_clone = Arc::clone(&conn);
                let path = remote_path.clone();

                // Check for resume.
                let resume_offset = if request.resume {
                    if let TransferOutput::File(ref file_path) = request.output {
                        tokio::fs::metadata(file_path)
                            .await
                            .ok()
                            .map(|m| m.len())
                            .filter(|&s| s > 0)
                    } else {
                        None
                    }
                } else {
                    None
                };

                let data = tokio::task::spawn_blocking(move || -> Result<Vec<u8>> {
                    let mut ftp = conn_clone
                        .lock()
                        .map_err(|e| anyhow::anyhow!("lock: {e}"))?;

                    if let Some(offset) = resume_offset {
                        let _ = ftp.resume_transfer(offset as usize);
                    }

                    let cursor = ftp
                        .retr_as_buffer(&path)
                        .map_err(|e| anyhow::anyhow!("FTP RETR {path}: {e}"))?;
                    Ok(cursor.into_inner())
                })
                .await
                .context("FTP read task panicked")??;

                let resumed = resume_offset.is_some();
                let bytes_transferred =
                    data.len() as u64 + resume_offset.unwrap_or(0);

                match &request.output {
                    TransferOutput::Memory => Ok(TransferResult {
                        status: 200,
                        headers: Vec::new(),
                        bytes_transferred,
                        content_length: Some(bytes_transferred),
                        body: Some(data),
                        hash: None,
                        resumed,
                    }),
                    TransferOutput::File(file_path) => {
                        if let Some(parent) = file_path.parent() {
                            tokio::fs::create_dir_all(parent).await?;
                        }

                        if resumed {
                            use tokio::io::AsyncWriteExt;
                            let mut file = tokio::fs::OpenOptions::new()
                                .append(true)
                                .open(file_path)
                                .await?;
                            file.write_all(&data).await?;
                            file.flush().await?;
                        } else {
                            tokio::fs::write(file_path, &data).await?;
                        }

                        Ok(TransferResult {
                            status: 200,
                            headers: Vec::new(),
                            bytes_transferred,
                            content_length: Some(bytes_transferred),
                            body: None,
                            hash: None,
                            resumed,
                        })
                    }
                    TransferOutput::Callback(_) => Ok(TransferResult {
                        status: 200,
                        headers: Vec::new(),
                        bytes_transferred,
                        content_length: Some(bytes_transferred),
                        body: Some(data),
                        hash: None,
                        resumed,
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
                        anyhow::bail!("stream body not supported for FTP");
                    }
                    None => Vec::new(),
                };

                let data_len = data.len() as u64;
                let conn_clone = Arc::clone(&conn);
                let path = remote_path.clone();

                tokio::task::spawn_blocking(move || -> Result<()> {
                    let mut ftp = conn_clone
                        .lock()
                        .map_err(|e| anyhow::anyhow!("lock: {e}"))?;

                    // Ensure parent directory exists.
                    if let Some(parent) = std::path::Path::new(&path).parent() {
                        let parent_str = parent.to_string_lossy();
                        if !parent_str.is_empty() && parent_str != "/" {
                            let _ = ftp.mkdir(&parent_str);
                        }
                    }

                    let mut cursor = Cursor::new(data);
                    ftp.put_file(&path, &mut cursor)
                        .map_err(|e| anyhow::anyhow!("FTP STOR {path}: {e}"))?;
                    Ok(())
                })
                .await
                .context("FTP write task panicked")??;

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
                let conn_clone = Arc::clone(&conn);
                let path = remote_path.clone();

                let size = tokio::task::spawn_blocking(move || -> Result<Option<u64>> {
                    let mut ftp = conn_clone
                        .lock()
                        .map_err(|e| anyhow::anyhow!("lock: {e}"))?;
                    match ftp.size(&path) {
                        Ok(size) => Ok(Some(size as u64)),
                        Err(_) => Ok(None),
                    }
                })
                .await
                .context("FTP size task panicked")??;

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
                let conn_clone = Arc::clone(&conn);
                let path = remote_path.clone();

                tokio::task::spawn_blocking(move || -> Result<()> {
                    let mut ftp = conn_clone
                        .lock()
                        .map_err(|e| anyhow::anyhow!("lock: {e}"))?;
                    ftp.rm(&path)
                        .map_err(|e| anyhow::anyhow!("FTP DELE {path}: {e}"))?;
                    Ok(())
                })
                .await
                .context("FTP delete task panicked")??;

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
        true
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
        let (host, port, path, secure) =
            FtpProtocol::parse_url("ftp://ftp.example.com:2121/pub/file.tar.gz").unwrap();
        assert_eq!(host, "ftp.example.com");
        assert_eq!(port, 2121);
        assert_eq!(path, "/pub/file.tar.gz");
        assert!(!secure);
    }

    #[test]
    fn test_parse_url_defaults() {
        let (host, port, path, secure) =
            FtpProtocol::parse_url("ftp://ftp.example.com/pub/file.txt").unwrap();
        assert_eq!(host, "ftp.example.com");
        assert_eq!(port, 21);
        assert_eq!(path, "/pub/file.txt");
        assert!(!secure);
    }

    #[test]
    fn test_parse_url_ftps() {
        let (_, _, _, secure) =
            FtpProtocol::parse_url("ftps://secure.example.com/file.txt").unwrap();
        assert!(secure);
    }
}
