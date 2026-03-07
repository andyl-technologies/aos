pub mod fs;
pub mod ftp;
pub mod http;
pub mod s3;
pub mod sftp;

use anyhow::Result;
use async_trait::async_trait;

/// Trait for binary cache storage backends.
#[async_trait]
pub trait CacheBackend: Send + Sync {
    /// Check if narinfo exists for a store hash.
    async fn has_narinfo(&self, store_hash: &str) -> Result<bool>;

    /// Fetch narinfo text.
    async fn get_narinfo(&self, store_hash: &str) -> Result<String>;

    /// Upload narinfo.
    async fn put_narinfo(&self, store_hash: &str, content: &str) -> Result<()>;

    /// Stream-download a NAR file. Returns the raw bytes.
    async fn get_nar(&self, url: &str) -> Result<Vec<u8>>;

    /// Upload a NAR file from bytes.
    async fn put_nar(&self, filename: &str, data: &[u8]) -> Result<()>;

    /// Batch check: which store hashes are missing from the cache?
    async fn query_missing(&self, store_hashes: &[&str]) -> Result<Vec<String>>;

    /// Write nix-cache-info (one-time initialization).
    async fn ensure_cache_info(&self, store_dir: &str) -> Result<()>;

    /// Whether this backend supports AOSP pack upload (HTTP only).
    fn supports_pack(&self) -> bool {
        false
    }

    /// Upload a pack of small NARs (HTTP only).
    async fn upload_pack(&self, _data: &[u8]) -> Result<Vec<String>> {
        anyhow::bail!("pack upload not supported by this backend")
    }
}

/// Authentication options collected from CLI flags.
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct AuthOptions {
    // HTTP
    pub token: Option<String>,
    pub view: String,
    pub http_user: Option<String>,
    pub http_password: Option<String>,
    pub headers: Vec<String>,

    // S3
    pub s3_region: Option<String>,
    pub s3_profile: Option<String>,
    pub s3_endpoint: Option<String>,

    // SFTP
    pub ssh_key: Option<String>,
    pub ssh_password: Option<String>,
    pub ssh_ask_pass: bool,

    // FTP
    pub ftp_user: Option<String>,
    pub ftp_password: Option<String>,
}

/// Create a backend from a URL string and auth options.
pub async fn from_url(url_str: &str, auth: &AuthOptions) -> Result<Box<dyn CacheBackend>> {
    let parsed = url::Url::parse(url_str)
        .map_err(|e| anyhow::anyhow!("invalid cache URL '{url_str}': {e}"))?;

    match parsed.scheme() {
        "file" => {
            let path = parsed
                .to_file_path()
                .map_err(|_| anyhow::anyhow!("invalid file URL: {url_str}"))?;
            Ok(Box::new(fs::FsBackend::new(path)))
        }
        "http" | "https" => Ok(Box::new(
            http::HttpBackend::new(url_str, auth).await?,
        )),
        "s3" => {
            let bucket = parsed
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("S3 URL must have bucket name as host"))?;
            let prefix = parsed.path().trim_start_matches('/').to_string();
            Ok(Box::new(
                s3::S3Backend::new(bucket, &prefix, auth).await?,
            ))
        }
        "sftp" | "ssh" => {
            let host = parsed
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("SFTP URL must have host"))?;
            let port = parsed.port().unwrap_or(22);
            let user = if parsed.username().is_empty() {
                None
            } else {
                Some(parsed.username().to_string())
            };
            let path = parsed.path().to_string();
            Ok(Box::new(sftp::SftpBackend::new(
                host, port, user, &path, auth,
            )?))
        }
        "ftp" | "ftps" => {
            let host = parsed
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("FTP URL must have host"))?;
            let port = parsed.port().unwrap_or(21);
            let path = parsed.path().to_string();
            let secure = parsed.scheme() == "ftps";
            Ok(Box::new(ftp::FtpBackend::new(
                host, port, &path, secure, auth,
            )?))
        }
        other => anyhow::bail!("unsupported cache URL scheme: {other}"),
    }
}
