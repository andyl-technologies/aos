//! Local filesystem (file://) protocol implementation.
//!
//! Uses `tokio::fs` for async file operations. Supports:
//! - Async read/write with streaming chunks
//! - File copy with progress
//! - Atomic writes (write to temp file, rename)

use std::path::PathBuf;

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::{ByteStream, Protocol};
use crate::auth::Credential;
use crate::types::{Method, TransferBody, TransferOutput, TransferRequest, TransferResult};

static TEMP_FILE_SEQUENCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Atomically replaces `destination` through a uniquely created sibling.
///
/// The temporary name includes the complete destination filename. Files such
/// as `pack-<hash>.pack`, `.idx`, and `.bitmap` can therefore be transferred
/// concurrently without sharing the old `pack-<hash>.tmp` staging path.
async fn atomic_write(destination: &std::path::Path, data: &[u8]) -> Result<()> {
    let parent = destination
        .parent()
        .context("filesystem transfer destination has no parent directory")?;
    tokio::fs::create_dir_all(parent)
        .await
        .with_context(|| format!("creating directory {}", parent.display()))?;
    let filename = destination
        .file_name()
        .and_then(|name| name.to_str())
        .context("filesystem transfer destination filename is not UTF-8")?;

    for _ in 0..16 {
        let sequence = TEMP_FILE_SEQUENCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let temporary = parent.join(format!(
            ".{filename}.aos-transfer-{}-{sequence}",
            std::process::id()
        ));
        let mut file = match tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .await
        {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(error)
                    .with_context(|| format!("creating temp file {}", temporary.display()));
            }
        };

        let write_result = async {
            file.write_all(data).await?;
            file.flush().await?;
            drop(file);
            tokio::fs::rename(&temporary, destination)
                .await
                .with_context(|| {
                    format!(
                        "renaming {} to {}",
                        temporary.display(),
                        destination.display()
                    )
                })
        }
        .await;
        if write_result.is_err() {
            let _ = tokio::fs::remove_file(&temporary).await;
        }
        return write_result;
    }

    anyhow::bail!(
        "could not reserve a temporary file beside {}",
        destination.display()
    )
}

/// Chunk size for streaming file reads.
const FS_CHUNK_SIZE: usize = 64 * 1024; // 64KB

/// Local filesystem protocol handler.
///
/// Maps transfer methods onto local file operations: `Get` reads a
/// file, `Put` writes one atomically (temp file + rename), `Head`
/// stats it (404 result if missing), and `Delete` unlinks it. POST is
/// rejected. Parent directories are created as needed on writes.
pub struct FsProtocol;

impl FsProtocol {
    /// Create a new filesystem protocol handler.
    pub fn new() -> Self {
        Self
    }

    /// Parse a `file://` URL into a local path.
    fn parse_url(url: &str) -> Result<PathBuf> {
        let parsed = url::Url::parse(url).with_context(|| format!("invalid file URL: {url}"))?;

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
                        atomic_write(dest, &data).await?;

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
                    TransferOutput::Callback(ref cb) => {
                        // Deliver in chunks.
                        for chunk in data.chunks(FS_CHUNK_SIZE) {
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
                }
            }
            Method::Put => {
                let data = match &request.body {
                    Some(TransferBody::Bytes(b)) => b.clone(),
                    Some(TransferBody::File(path)) => tokio::fs::read(path)
                        .await
                        .with_context(|| format!("reading {}", path.display()))?,
                    Some(TransferBody::Stream(_)) => {
                        anyhow::bail!("stream body not supported for file:// protocol");
                    }
                    None => Vec::new(),
                };

                let data_len = data.len() as u64;

                atomic_write(&local_path, &data).await?;

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
            Method::Head => match tokio::fs::metadata(&local_path).await {
                Ok(metadata) => Ok(TransferResult {
                    status: 200,
                    headers: Vec::new(),
                    bytes_transferred: 0,
                    content_length: Some(metadata.len()),
                    body: None,
                    hash: None,
                    resumed: false,
                }),
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(TransferResult {
                    status: 404,
                    headers: Vec::new(),
                    bytes_transferred: 0,
                    content_length: None,
                    body: None,
                    hash: None,
                    resumed: false,
                }),
                Err(e) => Err(anyhow::anyhow!("stat {} failed: {e}", local_path.display())),
            },
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
            Method::Post => {
                anyhow::bail!("POST is not supported by the file:// protocol");
            }
        }
    }

    async fn stream(
        &self,
        request: &TransferRequest,
        _auth: Option<&Credential>,
    ) -> Result<(TransferResult, ByteStream)> {
        let local_path = Self::parse_url(&request.url)?;

        match request.method {
            Method::Get => {
                let metadata = tokio::fs::metadata(&local_path)
                    .await
                    .with_context(|| format!("stat {}", local_path.display()))?;
                let file_len = metadata.len();

                let result = TransferResult {
                    status: 200,
                    headers: Vec::new(),
                    bytes_transferred: 0,
                    content_length: Some(file_len),
                    body: None,
                    hash: None,
                    resumed: false,
                };

                // Stream the file in chunks.
                let file = tokio::fs::File::open(&local_path)
                    .await
                    .with_context(|| format!("opening {}", local_path.display()))?;

                let stream: ByteStream =
                    Box::pin(futures_util::stream::unfold(file, |mut file| async move {
                        let mut buf = vec![0u8; FS_CHUNK_SIZE];
                        match file.read(&mut buf).await {
                            Ok(0) => None,
                            Ok(n) => {
                                buf.truncate(n);
                                Some((Ok(Bytes::from(buf)), file))
                            }
                            Err(e) => Some((Err(anyhow::anyhow!("reading file: {e}")), file)),
                        }
                    }));

                Ok((result, stream))
            }
            _ => {
                // Non-GET: execute then return empty/single-chunk stream.
                let result = self.execute(request, _auth).await?;
                let body_bytes = result.body.clone().unwrap_or_default();
                let stream: ByteStream = Box::pin(futures_util::stream::once(async move {
                    Ok(Bytes::from(body_bytes))
                }));
                Ok((result, stream))
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
            maximum_bytes: None,
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

    #[tokio::test]
    async fn concurrent_same_stem_puts_keep_distinct_bytes() {
        let dir = tempfile::TempDir::new().unwrap();
        let pack_path = dir.path().join("pack-deadbeef.pack");
        let bitmap_path = dir.path().join("pack-deadbeef.bitmap");
        let pack_url = format!("file://{}", pack_path.display());
        let bitmap_url = format!("file://{}", bitmap_path.display());
        let pack_bytes = vec![b'P'; 4 * 1024 * 1024];
        let bitmap_bytes = vec![b'B'; 4 * 1024 * 1024];
        let pack_request = TransferRequest::put(&pack_url, pack_bytes.clone());
        let bitmap_request = TransferRequest::put(&bitmap_url, bitmap_bytes.clone());
        let proto = FsProtocol::new();

        let (pack_result, bitmap_result) = tokio::join!(
            proto.execute(&pack_request, None),
            proto.execute(&bitmap_request, None),
        );
        assert_eq!(pack_result.unwrap().status, 200);
        assert_eq!(bitmap_result.unwrap().status, 200);
        assert_eq!(std::fs::read(pack_path).unwrap(), pack_bytes);
        assert_eq!(std::fs::read(bitmap_path).unwrap(), bitmap_bytes);
    }

    #[tokio::test]
    async fn test_stream_get() {
        use futures_util::StreamExt;

        let dir = tempfile::TempDir::new().unwrap();
        let file_path = dir.path().join("stream_test.txt");
        let content = "streaming content here";
        std::fs::write(&file_path, content).unwrap();

        let url = format!("file://{}", file_path.display());
        let proto = FsProtocol::new();

        let request = TransferRequest::get(&url);
        let (result, mut stream) = proto.stream(&request, None).await.unwrap();

        assert_eq!(result.status, 200);
        assert_eq!(result.content_length, Some(content.len() as u64));

        let mut collected = Vec::new();
        while let Some(chunk) = stream.next().await {
            collected.extend_from_slice(&chunk.unwrap());
        }
        assert_eq!(collected, content.as_bytes());
    }
}
