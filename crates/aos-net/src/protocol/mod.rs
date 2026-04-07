//! Protocol trait and URL-scheme dispatch.
//!
//! Each protocol (HTTP, S3, SFTP, FTP, filesystem) implements the
//! `Protocol` trait. The `for_url()` function creates the appropriate
//! implementation based on the URL scheme.

pub mod fs;
pub mod ftp;
pub mod http;
pub mod s3;
pub mod sftp;

use anyhow::Result;
use async_trait::async_trait;

use crate::auth::Credential;
use crate::types::{TransferRequest, TransferResult};

/// Trait for protocol-specific transfer implementations.
#[async_trait]
pub trait Protocol: Send + Sync {
    /// Execute a transfer request.
    async fn execute(
        &self,
        request: &TransferRequest,
        auth: Option<&Credential>,
    ) -> Result<TransferResult>;

    /// Whether this protocol supports resume (Range headers / REST command).
    fn supports_resume(&self) -> bool;

    /// Whether this protocol supports multi-part upload.
    fn supports_multipart(&self) -> bool;

    /// Maximum part size for multi-part upload (if supported).
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
/// - `ftp://`, `ftps://` -> FTP protocol
/// - `file://` -> Local filesystem protocol
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
        "ftp" | "ftps" => Ok(Box::new(ftp::FtpProtocol::new())),
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
    fn test_for_url_ftp() {
        let proto = for_url("ftp://ftp.example.com/pub/file.tar.gz").unwrap();
        assert!(proto.supports_resume());
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
