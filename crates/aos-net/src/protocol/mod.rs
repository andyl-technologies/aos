//! Protocol trait and URL-scheme dispatch.
//!
//! Each protocol (HTTP, S3, SFTP, filesystem) implements the
//! `Protocol` trait. The `for_url()` function creates the appropriate
//! implementation based on the URL scheme.

pub mod fs;
pub mod http;
pub mod s3;
pub mod sftp;

use std::pin::Pin;

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

/// Create a Protocol implementation based on URL scheme.
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
pub fn for_url(url: &str) -> Result<Box<dyn Protocol>> {
    let scheme = url
        .split("://")
        .next()
        .ok_or_else(|| anyhow::anyhow!("invalid URL: no scheme found in '{url}'"))?
        .to_lowercase();

    match scheme.as_str() {
        "http" | "https" => Ok(Box::new(http::HttpProtocol::new())),
        "s3" => Ok(Box::new(s3::S3Protocol::new())),
        "sftp" | "ssh" => Ok(Box::new(sftp::SftpProtocol::new())),
        "file" => Ok(Box::new(fs::FsProtocol::new())),
        other => anyhow::bail!("unsupported URL scheme: '{other}'"),
    }
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
