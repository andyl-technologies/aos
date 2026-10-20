//! Local filesystem (file://) protocol implementation.
//!
//! Uses `tokio::fs` for async file operations. Supports:
//! - Async read/write with streaming chunks
//! - File copy with progress
//! - Atomic writes (write to temp file, rename)
//! - Conditional writes (`If-Match` / `If-None-Match: *`) evaluated under an
//!   exclusive sibling lock file; see [`super::conditional`]

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Context, Result};
use async_trait::async_trait;
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use super::conditional::{
    content_version, lock_attempts, lock_file_contents, lock_file_name, lock_timeout_error,
    precondition_failed_result, written_result, WritePrecondition, LOCK_POLL, LOCK_WAIT,
};
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

/// Exclusive lock file that serializes conditional writes of one target.
///
/// The lock is a sibling created with `O_CREAT | O_EXCL`, so exactly one
/// writer holds it at a time. It is removed by [`release`](Self::release),
/// or on drop if the owning future is cancelled first. Unconditional writes
/// do not take the lock.
struct ConditionalWriteLock {
    path: PathBuf,
    held: bool,
}

impl ConditionalWriteLock {
    /// Acquires the lock at `path`, polling while another writer holds it.
    ///
    /// Fails once `wait` elapses rather than blocking forever: a lock left
    /// behind by a crashed writer needs an operator decision.
    async fn acquire(path: PathBuf, wait: Duration) -> Result<Self> {
        for attempt in 1..=lock_attempts(wait) {
            if attempt > 1 {
                tokio::time::sleep(LOCK_POLL).await;
            }

            let opened = tokio::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .await;

            match opened {
                Ok(mut file) => {
                    // Own the lock before writing its diagnostic contents, so
                    // a failed write still removes it.
                    let lock = Self { path, held: true };
                    file.write_all(lock_file_contents().as_bytes())
                        .await
                        .with_context(|| format!("writing lock file {}", lock.path.display()))?;
                    return Ok(lock);
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => {
                    return Err(error)
                        .with_context(|| format!("creating lock file {}", path.display()));
                }
            }
        }

        Err(lock_timeout_error(&path.display().to_string(), wait))
    }

    /// Removes the lock file.
    async fn release(mut self) -> Result<()> {
        self.held = false;
        tokio::fs::remove_file(&self.path)
            .await
            .with_context(|| format!("removing lock file {}", self.path.display()))
    }
}

impl Drop for ConditionalWriteLock {
    fn drop(&mut self) {
        if self.held {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

/// Writes `data` to `destination` only if `precondition` holds.
///
/// The current version is read and compared while holding the target's
/// [`ConditionalWriteLock`], and the replacement is an atomic temp-file
/// rename, so readers observe either the old or the new bytes.
async fn conditional_write(
    destination: &Path,
    data: &[u8],
    precondition: &WritePrecondition,
    lock_wait: Duration,
) -> Result<TransferResult> {
    let parent = destination
        .parent()
        .context("filesystem transfer destination has no parent directory")?;
    let filename = destination
        .file_name()
        .and_then(|name| name.to_str())
        .context("filesystem transfer destination filename is not UTF-8")?;
    tokio::fs::create_dir_all(parent)
        .await
        .with_context(|| format!("creating directory {}", parent.display()))?;

    let lock =
        ConditionalWriteLock::acquire(parent.join(lock_file_name(filename)), lock_wait).await?;
    let outcome = compare_and_write(destination, data, precondition).await;

    // A leftover lock blocks later conditional writers with an explicit
    // timeout that names it, so a failed removal must not misreport a write
    // that already committed.
    if let Err(error) = lock.release().await {
        tracing::warn!("{error:#}");
    }

    outcome
}

/// Compares the current version of `destination` with `precondition` and
/// replaces it with `data` when it matches. Callers hold the target lock.
async fn compare_and_write(
    destination: &Path,
    data: &[u8],
    precondition: &WritePrecondition,
) -> Result<TransferResult> {
    let current = match tokio::fs::read(destination).await {
        Ok(bytes) => Some(content_version(&bytes)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
        Err(error) => {
            return Err(error).with_context(|| format!("reading {}", destination.display()));
        }
    };

    if !precondition.is_satisfied_by(current.as_deref()) {
        return Ok(precondition_failed_result(current));
    }

    atomic_write(destination, data).await?;
    Ok(written_result(content_version(data), data.len() as u64))
}

/// Chunk size for streaming file reads.
const FS_CHUNK_SIZE: usize = 64 * 1024; // 64KB

/// Local filesystem protocol handler.
///
/// Maps transfer methods onto local file operations: `Get` reads a
/// file, `Put` writes one atomically (temp file + rename, conditionally
/// when the request carries a [`super::conditional`] header), `Head`
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
                    TransferOutput::Sink(sink) => {
                        for chunk in data.chunks(FS_CHUNK_SIZE) {
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

                if let Some(precondition) = WritePrecondition::from_headers(&request.headers)? {
                    return conditional_write(&local_path, &data, &precondition, LOCK_WAIT).await;
                }

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
            expected_size: None,
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

    #[tokio::test]
    async fn conditional_put_creates_only_absent_files() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("channels/edge/generation");
        let url = format!("file://{}", path.display());
        let proto = FsProtocol::new();
        let create =
            || TransferRequest::put(&url, b"one".to_vec()).with_header("If-None-Match", "*");

        let created = proto.execute(&create(), None).await.unwrap();
        let refused = proto.execute(&create(), None).await.unwrap();

        assert_eq!(created.status, 200);
        assert_eq!(
            created.header("ETag"),
            Some(content_version(b"one").as_str())
        );
        assert_eq!(refused.status, 412);
        assert_eq!(
            refused.header("ETag"),
            Some(content_version(b"one").as_str())
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"one");
        assert!(!dir.path().join("channels/edge/.generation.lock").exists());
    }

    #[tokio::test]
    async fn conditional_put_replaces_only_the_expected_version() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("generation");
        std::fs::write(&path, b"one").unwrap();
        let url = format!("file://{}", path.display());
        let proto = FsProtocol::new();
        let current = content_version(b"one");

        let stale = TransferRequest::put(&url, b"two".to_vec()).with_header("If-Match", "stale");
        let fresh = TransferRequest::put(&url, b"two".to_vec()).with_header("If-Match", &current);
        let stale_result = proto.execute(&stale, None).await.unwrap();
        let fresh_result = proto.execute(&fresh, None).await.unwrap();

        assert_eq!(stale_result.status, 412);
        assert_eq!(stale_result.header("ETag"), Some(current.as_str()));
        assert_eq!(fresh_result.status, 200);
        assert_eq!(
            fresh_result.header("ETag"),
            Some(content_version(b"two").as_str())
        );
        assert_eq!(std::fs::read(&path).unwrap(), b"two");
        assert!(!dir.path().join(".generation.lock").exists());
    }

    #[tokio::test]
    async fn conditional_put_fails_closed_while_another_writer_holds_the_lock() {
        let dir = tempfile::TempDir::new().unwrap();
        let path = dir.path().join("generation");
        let lock = dir.path().join(".generation.lock");
        std::fs::write(&lock, b"held elsewhere").unwrap();

        let error = conditional_write(
            &path,
            b"one",
            &WritePrecondition::Absent,
            Duration::from_millis(150),
        )
        .await
        .unwrap_err();

        assert!(format!("{error:#}").contains("conditional-write lock"));
        assert!(!path.exists());
        assert_eq!(std::fs::read(&lock).unwrap(), b"held elsewhere");
    }
}
