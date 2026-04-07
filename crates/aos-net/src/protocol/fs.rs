//! Local filesystem (file://) protocol implementation.
//!
//! Uses `tokio::fs` for async file operations. Supports:
//! - Async read/write
//! - File copy with progress
//! - Atomic writes (write to temp file, rename)

use std::path::PathBuf;

use anyhow::{Context, Result};
use async_trait::async_trait;
use tokio::io::AsyncWriteExt;

use super::Protocol;
use crate::auth::Credential;
use crate::types::{Method, TransferBody, TransferOutput, TransferRequest, TransferResult};

/// Local filesystem protocol handler.
pub struct FsProtocol;

impl FsProtocol {
    /// Create a new filesystem protocol handler.
    pub fn new() -> Self {
        Self
    }

    /// Parse a file:// URL into a local path.
    fn parse_url(url: &str) -> Result<PathBuf> {
        let parsed =
            url::Url::parse(url).with_context(|| format!("invalid file URL: {url}"))?;

        parsed
            .to_file_path()
            .map_err(|_| anyhow::anyhow!("invalid file URL path: {url}"))
    }
}

impl Default for FsProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for FsProtocol {
    async fn execute(
        &self,
        request: &TransferRequest,
        _auth: Option<&Credential>,
    ) -> Result<TransferResult> {
        let local_path = Self::parse_url(&request.url)?;

        match request.method {
            Method::Get => {
                let data = tokio::fs::read(&local_path)
                    .await
                    .with_context(|| format!("reading {}", local_path.display()))?;

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
                    TransferOutput::File(dest) => {
                        // Ensure parent directory exists.
                        if let Some(parent) = dest.parent() {
                            tokio::fs::create_dir_all(parent)
                                .await
                                .with_context(|| {
                                    format!("creating directory {}", parent.display())
                                })?;
                        }

                        // Atomic write: write to temp file, then rename.
                        let temp_path = dest.with_extension("tmp");
                        tokio::fs::write(&temp_path, &data)
                            .await
                            .with_context(|| {
                                format!("writing temp file {}", temp_path.display())
                            })?;
                        tokio::fs::rename(&temp_path, dest)
                            .await
                            .with_context(|| {
                                format!(
                                    "renaming {} to {}",
                                    temp_path.display(),
                                    dest.display()
                                )
                            })?;

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
                        anyhow::bail!("stream body not supported for file:// protocol");
                    }
                    None => Vec::new(),
                };

                let data_len = data.len() as u64;

                // Ensure parent directory exists.
                if let Some(parent) = local_path.parent() {
                    tokio::fs::create_dir_all(parent)
                        .await
                        .with_context(|| {
                            format!("creating directory {}", parent.display())
                        })?;
                }

                // Atomic write.
                let temp_path = local_path.with_extension("tmp");
                let mut file = tokio::fs::File::create(&temp_path)
                    .await
                    .with_context(|| {
                        format!("creating temp file {}", temp_path.display())
                    })?;
                file.write_all(&data).await?;
                file.flush().await?;
                drop(file);

                tokio::fs::rename(&temp_path, &local_path)
                    .await
                    .with_context(|| {
                        format!(
                            "renaming {} to {}",
                            temp_path.display(),
                            local_path.display()
                        )
                    })?;

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
                match tokio::fs::metadata(&local_path).await {
                    Ok(metadata) => Ok(TransferResult {
                        status: 200,
                        headers: Vec::new(),
                        bytes_transferred: 0,
                        content_length: Some(metadata.len()),
                        body: None,
                        hash: None,
                        resumed: false,
                    }),
                    Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                        Ok(TransferResult {
                            status: 404,
                            headers: Vec::new(),
                            bytes_transferred: 0,
                            content_length: None,
                            body: None,
                            hash: None,
                            resumed: false,
                        })
                    }
                    Err(e) => Err(anyhow::anyhow!(
                        "stat {} failed: {e}",
                        local_path.display()
                    )),
                }
            }
            Method::Delete => {
                tokio::fs::remove_file(&local_path)
                    .await
                    .with_context(|| format!("deleting {}", local_path.display()))?;

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
        let path = FsProtocol::parse_url("file:///tmp/test/file.txt").unwrap();
        assert_eq!(path, PathBuf::from("/tmp/test/file.txt"));
    }

    #[test]
    fn test_parse_url_invalid() {
        assert!(FsProtocol::parse_url("not-a-url").is_err());
    }

    #[tokio::test]
    async fn test_head_nonexistent() {
        let proto = FsProtocol::new();
        let request = TransferRequest::head("file:///tmp/nonexistent_aos_test_file_12345");
        let result = proto.execute(&request, None).await.unwrap();
        assert_eq!(result.status, 404);
    }

    #[tokio::test]
    async fn test_put_get_delete() {
        let dir = tempfile::TempDir::new().unwrap();
        let file_path = dir.path().join("test.txt");
        let url = format!("file://{}", file_path.display());

        let proto = FsProtocol::new();

        // PUT
        let put_req = TransferRequest::put(&url, b"hello world".to_vec());
        let result = proto.execute(&put_req, None).await.unwrap();
        assert_eq!(result.status, 200);
        assert_eq!(result.bytes_transferred, 11);

        // HEAD
        let head_req = TransferRequest::head(&url);
        let result = proto.execute(&head_req, None).await.unwrap();
        assert_eq!(result.status, 200);
        assert_eq!(result.content_length, Some(11));

        // GET
        let get_req = TransferRequest::get(&url);
        let result = proto.execute(&get_req, None).await.unwrap();
        assert_eq!(result.status, 200);
        assert_eq!(result.body.unwrap(), b"hello world");

        // DELETE
        let del_req = TransferRequest {
            url: url.clone(),
            method: crate::types::Method::Delete,
            headers: Vec::new(),
            body: None,
            hash: None,
            resume: false,
            output: TransferOutput::Memory,
        };
        let result = proto.execute(&del_req, None).await.unwrap();
        assert_eq!(result.status, 204);

        // HEAD again (should be 404)
        let head_req = TransferRequest::head(&url);
        let result = proto.execute(&head_req, None).await.unwrap();
        assert_eq!(result.status, 404);
    }
}
