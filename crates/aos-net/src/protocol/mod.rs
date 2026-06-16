//! Protocol trait and URL-scheme dispatch.
//!
//! Each protocol (HTTP, S3, SFTP, filesystem) implements the
//! `Protocol` trait. The `for_url()` function returns a shared,
//! process-wide handler for the URL's scheme so per-protocol resources
//! are reused across transfers: the HTTP client's connection pool, the
//! SFTP session cache, and the S3 client cache all persist instead of
//! being rebuilt on every request.

pub mod fs;
pub mod http;
pub mod s3;
pub mod sftp;

use std::pin::Pin;
use std::sync::{Arc, OnceLock};

use anyhow::Result;
use async_trait::async_trait;
use bytes::Bytes;
use futures_util::Stream;

use crate::auth::Credential;
use crate::types::{TransferRequest, TransferResult};

/// A boxed stream of byte chunks yielded during a transfer.
pub type ByteStream = Pin<Box<dyn Stream<Item = Result<Bytes>> + Send>>;

/// Trait for protocol-specific transfer implementations.
///
/// Implementations exist for HTTP(S) ([`http::HttpProtocol`]), S3
/// ([`s3::S3Protocol`]), SFTP/SSH ([`sftp::SftpProtocol`]), and the
/// local filesystem ([`fs::FsProtocol`]). Most callers should go
/// through [`TransferEngine`](crate::transfer::TransferEngine) rather
/// than using a protocol directly -- the engine adds pooling, retry,
/// hashing, bandwidth limiting, and progress reporting on top.
#[async_trait]
pub trait Protocol: Send + Sync {
    /// Execute a transfer request (legacy non-streaming path).
    ///
    /// The implementation handles the request's output destination
    /// itself (memory buffer, file, or callback).
    ///
    /// # Errors
    ///
    /// Returns an error if the URL is invalid for this protocol, the
    /// remote operation fails (network/auth/HTTP error status), the
    /// method or body type is unsupported by this protocol, or local
    /// I/O on the output destination fails.
    async fn execute(
        &self,
        request: &TransferRequest,
        auth: Option<&Credential>,
    ) -> Result<TransferResult>;

    /// Stream response body as chunks. Returns headers/status metadata
    /// plus a byte stream. The caller is responsible for writing chunks
    /// to the output, computing hashes, enforcing bandwidth limits, and
    /// reporting progress.
    ///
    /// The default implementation falls back to `execute()` and yields
    /// the body as a single chunk.
    ///
    /// # Errors
    ///
    /// Returns an error under the same conditions as
    /// [`execute`](Protocol::execute). Errors that occur mid-body are
    /// yielded as `Err` items from the returned stream instead.
    async fn stream(
        &self,
        request: &TransferRequest,
        auth: Option<&Credential>,
    ) -> Result<(TransferResult, ByteStream)> {
        let result = self.execute(request, auth).await?;
        let body_bytes = result.body.clone().unwrap_or_default();
        let stream: ByteStream = Box::pin(futures_util::stream::once(async move {
            Ok(Bytes::from(body_bytes))
        }));
        Ok((result, stream))
    }

    /// Whether this protocol supports resume (Range headers / REST command).
    fn supports_resume(&self) -> bool;

    /// Whether this protocol supports multi-part upload.
    fn supports_multipart(&self) -> bool;

    /// Size threshold above which uploads switch to multi-part
    /// (if supported). The default implementation returns `None`.
    fn multipart_threshold(&self) -> Option<u64> {
        None
    }
}

/// Returns the shared [`Protocol`] handler for a URL's scheme.
///
/// Each scheme family is backed by a single process-wide instance
/// (created on first use), so connection pools and session/client
/// caches are reused across every transfer rather than rebuilt per
/// request. The returned [`Arc`] is cheap to clone and safe to move
/// into spawned tasks.
///
/// Supported schemes:
/// - `http://`, `https://` -> HTTP protocol
/// - `s3://` -> S3 protocol
/// - `sftp://`, `ssh://` -> SFTP protocol
/// - `file://` -> Local filesystem protocol
///
/// # Errors
///
/// Returns an error if the URL has no `://` scheme separator or the
/// scheme is not one of the supported values above.
pub fn for_url(url: &str) -> Result<Arc<dyn Protocol>> {
    let scheme = url
        .split("://")
        .next()
        .ok_or_else(|| anyhow::anyhow!("invalid URL: no scheme found in '{url}'"))?
        .to_lowercase();

    match scheme.as_str() {
        "http" | "https" => Ok(http_protocol()),
        "s3" => Ok(s3_protocol()),
        "sftp" | "ssh" => Ok(sftp_protocol()),
        "file" => Ok(fs_protocol()),
        other => anyhow::bail!("unsupported URL scheme: '{other}'"),
    }
}

/// Returns the shared HTTP(S) handler, whose `reqwest::Client` pools
/// connections across all transfers.
fn http_protocol() -> Arc<dyn Protocol> {
    static HTTP: OnceLock<Arc<dyn Protocol>> = OnceLock::new();
    HTTP.get_or_init(|| Arc::new(http::HttpProtocol::new()))
        .clone()
}

/// Returns the shared S3 handler, whose internal client cache persists
/// across requests.
fn s3_protocol() -> Arc<dyn Protocol> {
    static S3: OnceLock<Arc<dyn Protocol>> = OnceLock::new();
    S3.get_or_init(|| Arc::new(s3::S3Protocol::new())).clone()
}

/// Returns the shared SFTP/SSH handler, whose per-host session cache
/// persists across requests.
fn sftp_protocol() -> Arc<dyn Protocol> {
    static SFTP: OnceLock<Arc<dyn Protocol>> = OnceLock::new();
    SFTP.get_or_init(|| Arc::new(sftp::SftpProtocol::new()))
        .clone()
}

/// Returns the shared (stateless) filesystem handler.
fn fs_protocol() -> Arc<dyn Protocol> {
    static FS: OnceLock<Arc<dyn Protocol>> = OnceLock::new();
    FS.get_or_init(|| Arc::new(fs::FsProtocol::new())).clone()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_for_url_http() {
        let proto = for_url("https://example.com/file.tar.gz").unwrap();
        assert!(proto.supports_resume());
    }

    #[test]
    fn test_for_url_s3() {
        let proto = for_url("s3://my-bucket/prefix/file.tar.gz").unwrap();
        assert!(proto.supports_multipart());
    }

    #[test]
    fn test_for_url_sftp() {
        let proto = for_url("sftp://host/path/file.tar.gz").unwrap();
        assert!(!proto.supports_resume());
    }

    #[test]
    fn test_for_url_file() {
        let proto = for_url("file:///tmp/file.tar.gz").unwrap();
        assert!(!proto.supports_resume());
    }

    #[test]
    fn test_for_url_unsupported() {
        assert!(for_url("gopher://example.com/path").is_err());
    }

    #[test]
    fn test_for_url_no_scheme() {
        assert!(for_url("no-scheme-here").is_err());
    }
}
