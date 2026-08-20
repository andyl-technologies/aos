//! High-level, identity-safe download and upload operations.
//!
//! This module owns durable partial files, resume policy, whole-object
//! verification, atomic publication, mirror fallback, and upload-source
//! normalization. Protocol implementations remain responsible only for moving
//! bytes; callers describe the object identity and destination once here.

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;

use crate::hash::StreamingHasher;
use crate::progress::{NoopObserver, TransferEvent, TransferObserver};
use crate::transfer::TransferEngine;
use crate::types::{HashAlgorithm, HashSpec, TransferRequest, TransferResult};

const CHECKPOINT_SCHEMA_VERSION: u32 = 1;

/// Controls whether a managed download may reuse durable partial bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ResumePolicy {
    /// Always discard partial state and start from byte zero.
    Disabled,
    /// Resume when a cryptographic object identity makes it safe.
    #[default]
    Automatic,
    /// Require safe resumability and fail when no digest is supplied.
    Require,
}

/// Describes one identity-safe download.
#[derive(Debug, Clone)]
pub struct DownloadRequest {
    /// Candidate source URLs in mirror priority order.
    pub sources: Vec<String>,
    /// Final path atomically installed after verification.
    pub destination: PathBuf,
    /// Expected whole-object digest.
    pub hash: Option<HashSpec>,
    /// Expected complete byte length.
    pub expected_size: Option<u64>,
    /// Partial-transfer continuation policy.
    pub resume: ResumePolicy,
    /// Headers applied to every source request.
    pub headers: Vec<(String, String)>,
}

impl DownloadRequest {
    /// Creates a download from one source URL to an atomic file destination.
    pub fn new(source: impl Into<String>, destination: impl Into<PathBuf>) -> Self {
        Self {
            sources: vec![source.into()],
            destination: destination.into(),
            hash: None,
            expected_size: None,
            resume: ResumePolicy::Automatic,
            headers: Vec::new(),
        }
    }

    /// Replaces the source list with a priority-ordered mirror chain.
    pub fn with_sources(mut self, sources: Vec<String>) -> Self {
        self.sources = sources;
        self
    }

    /// Requires a complete byte length.
    pub fn with_expected_size(mut self, expected_size: u64) -> Self {
        self.expected_size = Some(expected_size);
        self
    }

    /// Requires a whole-object digest.
    pub fn with_hash(mut self, algorithm: HashAlgorithm, expected: impl Into<String>) -> Self {
        self.hash = Some(HashSpec {
            algorithm,
            expected: expected.into(),
        });
        self
    }

    /// Selects the partial-transfer continuation policy.
    pub fn with_resume(mut self, resume: ResumePolicy) -> Self {
        self.resume = resume;
        self
    }

    /// Adds one transport header to every source request.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

/// Result of an atomically completed managed download.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DownloadResult {
    /// Installed destination path.
    pub path: PathBuf,
    /// Complete object size.
    pub bytes: u64,
    /// Computed digest when verification was requested.
    pub hash: Option<String>,
    /// Source URL that supplied the final bytes.
    pub source: String,
    /// Number of validated partial bytes reused.
    pub resumed_bytes: u64,
}

/// Rewindable payload accepted by a managed upload.
#[derive(Debug)]
pub enum UploadSource {
    /// Reads upload bytes from a local regular file.
    File(PathBuf),
    /// Uploads an owned in-memory payload.
    Bytes(Vec<u8>),
}

/// Describes one managed upload.
#[derive(Debug)]
pub struct UploadRequest {
    /// Destination URL.
    pub destination: String,
    /// Rewindable upload payload.
    pub source: UploadSource,
    /// Headers applied to the upload request.
    pub headers: Vec<(String, String)>,
}

impl UploadRequest {
    /// Creates a file-backed upload.
    pub fn file(destination: impl Into<String>, source: impl Into<PathBuf>) -> Self {
        Self {
            destination: destination.into(),
            source: UploadSource::File(source.into()),
            headers: Vec::new(),
        }
    }

    /// Creates an in-memory upload.
    pub fn bytes(destination: impl Into<String>, source: Vec<u8>) -> Self {
        Self {
            destination: destination.into(),
            source: UploadSource::Bytes(source),
            headers: Vec::new(),
        }
    }

    /// Adds one transport header.
    pub fn with_header(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.headers.push((name.into(), value.into()));
        self
    }
}

/// Identity persisted beside a durable partial download.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct DownloadCheckpoint {
    schema_version: u32,
    expected_size: Option<u64>,
    hash_algorithm: String,
    expected_hash: String,
}

impl TransferEngine {
    /// Downloads, verifies, and atomically installs one object.
    ///
    /// A no-op observer is used. Call [`download_observed`](Self::download_observed)
    /// when the caller needs interactive or machine-readable progress.
    ///
    /// # Errors
    ///
    /// Returns an error when the request has no sources, required resume lacks
    /// a digest, local partial state is unsafe, every mirror fails, the final
    /// size or digest differs, or atomic publication fails.
    pub async fn download(&self, request: DownloadRequest) -> Result<DownloadResult> {
        self.download_observed(request, &NoopObserver).await
    }

    /// Downloads, verifies, and atomically installs one observed object.
    ///
    /// Valid partial bytes are retained across transient failures and process
    /// interruption. They are reused only when the checkpoint binds them to the
    /// same expected whole-object digest and size.
    ///
    /// # Errors
    ///
    /// Returns the errors described by [`download`](Self::download), including
    /// observer-independent transport and verification failures.
    pub async fn download_observed(
        &self,
        request: DownloadRequest,
        observer: &dyn TransferObserver,
    ) -> Result<DownloadResult> {
        if request.sources.is_empty() {
            bail!("managed download requires at least one source URL");
        }
        if request.resume == ResumePolicy::Require && request.hash.is_none() {
            bail!("required resume needs a whole-object digest");
        }

        validate_regular_or_absent(&request.destination)?;
        if destination_matches(&request).await? {
            let bytes = tokio::fs::metadata(&request.destination).await?.len();
            let source = request.sources[0].clone();
            observer.observe(TransferEvent::Started {
                url: &source,
                total_bytes: Some(bytes),
                resumed_bytes: bytes,
            });
            observer.observe(TransferEvent::Completed {
                url: &source,
                transferred_bytes: bytes,
            });
            return Ok(DownloadResult {
                path: request.destination,
                bytes,
                hash: request.hash.map(|hash| normalize_hash(&hash.expected)),
                source,
                resumed_bytes: bytes,
            });
        }

        let partial = sibling_path(&request.destination, ".aos-part")?;
        let checkpoint_path = sibling_path(&request.destination, ".aos-part.json")?;
        prepare_partial(&request, &partial, &checkpoint_path).await?;
        let resumed_bytes = existing_length(&partial).await?;

        let mut last_error = None;
        for source in &request.sources {
            let mut transfer = TransferRequest::get_to_file(source, partial.clone()).with_resume();
            transfer.headers.clone_from(&request.headers);
            if let Some(expected_size) = request.expected_size {
                transfer = transfer.with_maximum_bytes(expected_size);
            }
            if let Some(hash) = request.hash.as_ref() {
                transfer = transfer.with_hash(hash.algorithm, &hash.expected);
            }

            match self.execute_observed(transfer, observer).await {
                Ok(_) => match finish_download(&request, &partial, &checkpoint_path).await {
                    Ok((bytes, hash)) => {
                        return Ok(DownloadResult {
                            path: request.destination,
                            bytes,
                            hash,
                            source: source.clone(),
                            resumed_bytes,
                        });
                    }
                    Err(error) => {
                        discard_partial(&partial, &checkpoint_path).await?;
                        last_error =
                            Some(error.context(format!("verifying download from {source}")));
                    }
                },
                Err(error) => {
                    discard_complete_invalid_partial(&request, &partial, &checkpoint_path).await?;
                    last_error = Some(error.context(format!("downloading from {source}")));
                }
            }
        }

        Err(last_error.unwrap_or_else(|| anyhow::anyhow!("every download source failed")))
    }

    /// Uploads one rewindable payload through the shared transfer pipeline.
    ///
    /// # Errors
    ///
    /// Returns an error when the source is unreadable or the selected transport
    /// rejects or fails the upload.
    pub async fn upload(&self, request: UploadRequest) -> Result<TransferResult> {
        self.upload_observed(request, &NoopObserver).await
    }

    /// Uploads one rewindable payload and reports structured progress.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`upload`](Self::upload).
    pub async fn upload_observed(
        &self,
        request: UploadRequest,
        observer: &dyn TransferObserver,
    ) -> Result<TransferResult> {
        let mut transfer = match request.source {
            UploadSource::File(path) => TransferRequest::put_file(&request.destination, path),
            UploadSource::Bytes(bytes) => TransferRequest::put(&request.destination, bytes),
        };
        transfer.headers = request.headers;
        self.execute_observed(transfer, observer).await
    }
}

/// Returns whether an existing final destination already has the requested identity.
async fn destination_matches(request: &DownloadRequest) -> Result<bool> {
    let metadata = match tokio::fs::metadata(&request.destination).await {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => return Err(error.into()),
    };
    if request
        .expected_size
        .is_some_and(|expected| metadata.len() != expected)
    {
        return Ok(false);
    }
    match request.hash.as_ref() {
        Some(hash) => file_hash_matches(&request.destination, hash).await,
        None => Ok(false),
    }
}

/// Prepares or rejects the durable partial/checkpoint pair.
async fn prepare_partial(
    request: &DownloadRequest,
    partial: &Path,
    checkpoint_path: &Path,
) -> Result<()> {
    validate_regular_or_absent(partial)?;
    validate_regular_or_absent(checkpoint_path)?;

    let Some(hash) = request.hash.as_ref() else {
        discard_partial(partial, checkpoint_path).await?;
        return Ok(());
    };
    if request.resume == ResumePolicy::Disabled {
        discard_partial(partial, checkpoint_path).await?;
    }

    let expected = DownloadCheckpoint {
        schema_version: CHECKPOINT_SCHEMA_VERSION,
        expected_size: request.expected_size,
        hash_algorithm: algorithm_name(hash.algorithm).to_string(),
        expected_hash: normalize_hash(&hash.expected),
    };
    let current = read_checkpoint(checkpoint_path).await?;
    if current.as_ref().is_some_and(|current| current != &expected)
        || (current.is_none() && existing_length(partial).await? > 0)
    {
        discard_partial(partial, checkpoint_path).await?;
    }

    if let Some(expected_size) = request.expected_size {
        let existing = existing_length(partial).await?;
        if existing > expected_size {
            discard_partial(partial, checkpoint_path).await?;
        }
    }
    write_checkpoint(checkpoint_path, &expected).await
}

/// Validates and publishes a complete partial file.
async fn finish_download(
    request: &DownloadRequest,
    partial: &Path,
    checkpoint_path: &Path,
) -> Result<(u64, Option<String>)> {
    let bytes = existing_length(partial).await?;
    if let Some(expected_size) = request.expected_size {
        if bytes != expected_size {
            bail!("downloaded {bytes} bytes, expected {expected_size}");
        }
    }

    let hash = if let Some(expected) = request.hash.as_ref() {
        let actual = hash_file(partial, expected.algorithm).await?;
        if !hashes_equal(&actual, &expected.expected) {
            bail!(
                "download hash mismatch: expected {}, got {actual}",
                expected.expected
            );
        }
        Some(actual)
    } else {
        None
    };

    let file = tokio::fs::File::open(partial).await?;
    file.sync_all().await?;
    tokio::fs::rename(partial, &request.destination)
        .await
        .with_context(|| format!("installing {}", request.destination.display()))?;
    remove_if_exists(checkpoint_path).await?;
    Ok((bytes, hash))
}

/// Removes a full-size partial that failed integrity verification.
async fn discard_complete_invalid_partial(
    request: &DownloadRequest,
    partial: &Path,
    checkpoint_path: &Path,
) -> Result<()> {
    let Some(expected_size) = request.expected_size else {
        return Ok(());
    };
    if existing_length(partial).await? != expected_size {
        return Ok(());
    }
    if let Some(hash) = request.hash.as_ref() {
        if !file_hash_matches(partial, hash).await? {
            discard_partial(partial, checkpoint_path).await?;
        }
    }
    Ok(())
}

/// Reads one checkpoint, treating absence as no resumable state.
async fn read_checkpoint(path: &Path) -> Result<Option<DownloadCheckpoint>> {
    let bytes = match tokio::fs::read(path).await {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    let checkpoint = serde_json::from_slice(&bytes)
        .with_context(|| format!("reading transfer checkpoint {}", path.display()))?;
    Ok(Some(checkpoint))
}

/// Atomically writes one checkpoint beside its partial file.
async fn write_checkpoint(path: &Path, checkpoint: &DownloadCheckpoint) -> Result<()> {
    let temporary = sibling_path(path, ".tmp")?;
    let bytes = serde_json::to_vec(checkpoint)?;
    tokio::fs::write(&temporary, bytes).await?;
    tokio::fs::rename(&temporary, path).await?;
    Ok(())
}

/// Removes both sides of a partial/checkpoint pair.
async fn discard_partial(partial: &Path, checkpoint: &Path) -> Result<()> {
    remove_if_exists(partial).await?;
    remove_if_exists(checkpoint).await
}

/// Removes a path if present.
async fn remove_if_exists(path: &Path) -> Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Returns a regular file's length or zero for absence.
async fn existing_length(path: &Path) -> Result<u64> {
    match tokio::fs::metadata(path).await {
        Ok(metadata) if metadata.is_file() => Ok(metadata.len()),
        Ok(_) => bail!("transfer path is not a regular file: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
        Err(error) => Err(error.into()),
    }
}

/// Rejects symlinks and non-regular files at transfer-owned paths.
fn validate_regular_or_absent(path: &Path) -> Result<()> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(()),
        Ok(_) => bail!("transfer path is not a regular file: {}", path.display()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

/// Derives a hidden sibling path without lossy filename conversion.
fn sibling_path(destination: &Path, suffix: &str) -> Result<PathBuf> {
    let filename = destination
        .file_name()
        .context("transfer destination has no file name")?;
    let mut sibling = OsString::from(".");
    sibling.push(filename);
    sibling.push(suffix);
    Ok(destination.with_file_name(sibling))
}

/// Computes one whole-file digest without buffering the object.
async fn hash_file(path: &Path, algorithm: HashAlgorithm) -> Result<String> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut hasher = StreamingHasher::new(algorithm);
    let mut buffer = vec![0_u8; 128 * 1024];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            return Ok(hasher.finalize().hex);
        }
        hasher.update(&buffer[..read]);
    }
}

/// Returns whether a file matches one digest specification.
async fn file_hash_matches(path: &Path, expected: &HashSpec) -> Result<bool> {
    let actual = hash_file(path, expected.algorithm).await?;
    Ok(hashes_equal(&actual, &expected.expected))
}

/// Compares a computed digest to a normalized expected value.
fn hashes_equal(actual: &str, expected: &str) -> bool {
    actual.eq_ignore_ascii_case(&normalize_hash(expected))
}

/// Removes the accepted algorithm prefix from one expected digest.
fn normalize_hash(hash: &str) -> String {
    hash.strip_prefix("sha256:")
        .or_else(|| hash.strip_prefix("sha512:"))
        .unwrap_or(hash)
        .to_ascii_lowercase()
}

/// Returns the stable checkpoint name for one hash algorithm.
const fn algorithm_name(algorithm: HashAlgorithm) -> &'static str {
    match algorithm {
        HashAlgorithm::Sha256 => "sha256",
        HashAlgorithm::Sha512 => "sha512",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::transfer::TransferEngineConfig;

    const HELLO_SHA256: &str = "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824";

    #[tokio::test]
    async fn managed_download_installs_atomically_and_reuses_verified_final() {
        let directory = tempfile::TempDir::new().unwrap();
        let source = directory.path().join("source");
        let destination = directory.path().join("destination");
        std::fs::write(&source, b"hello").unwrap();
        let request =
            DownloadRequest::new(format!("file://{}", source.display()), destination.clone())
                .with_expected_size(5)
                .with_hash(HashAlgorithm::Sha256, HELLO_SHA256);
        let manager = TransferEngine::new(TransferEngineConfig::default());

        let first = manager.download(request.clone()).await.unwrap();
        std::fs::remove_file(source).unwrap();
        let second = manager.download(request).await.unwrap();

        assert_eq!(std::fs::read(destination).unwrap(), b"hello");
        assert_eq!(first.resumed_bytes, 0);
        assert_eq!(second.resumed_bytes, 5);
    }

    #[tokio::test]
    async fn mismatched_checkpoint_discards_partial_bytes() {
        let directory = tempfile::TempDir::new().unwrap();
        let destination = directory.path().join("destination");
        let partial = sibling_path(&destination, ".aos-part").unwrap();
        let checkpoint = sibling_path(&destination, ".aos-part.json").unwrap();
        std::fs::write(&partial, b"wrong").unwrap();
        std::fs::write(
            &checkpoint,
            br#"{"schemaVersion":1,"expectedSize":5,"hashAlgorithm":"sha256","expectedHash":"wrong"}"#,
        )
        .unwrap();
        let request = DownloadRequest::new("file:///missing", destination)
            .with_expected_size(5)
            .with_hash(HashAlgorithm::Sha256, HELLO_SHA256);

        prepare_partial(&request, &partial, &checkpoint)
            .await
            .unwrap();

        assert_eq!(existing_length(&partial).await.unwrap(), 0);
        assert_eq!(
            read_checkpoint(&checkpoint).await.unwrap(),
            Some(DownloadCheckpoint {
                schema_version: CHECKPOINT_SCHEMA_VERSION,
                expected_size: Some(5),
                hash_algorithm: "sha256".to_string(),
                expected_hash: HELLO_SHA256.to_string(),
            })
        );
    }

    #[test]
    fn sibling_paths_preserve_non_utf8_names() {
        use std::os::unix::ffi::OsStringExt;

        let destination = PathBuf::from(OsString::from_vec(vec![b'f', 0x80]));
        let partial = sibling_path(&destination, ".part").unwrap();
        assert_eq!(
            partial.file_name().unwrap().as_encoded_bytes(),
            &[b'.', b'f', 0x80, b'.', b'p', b'a', b'r', b't']
        );
    }
}
