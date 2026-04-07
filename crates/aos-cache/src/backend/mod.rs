pub mod fs;
pub mod ftp;
pub mod http;
pub mod s3;
pub mod sftp;

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;

use aos_net::{TransferEngine, TransferEngineConfig};

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

/// Map `AuthOptions` to `aos_net` credentials and register them on the engine's auth store.
fn apply_auth_to_engine(engine: &TransferEngine, url: &str, auth: &AuthOptions) {
    let host = url::Url::parse(url)
        .ok()
        .and_then(|u| u.host_str().map(|h| h.to_string()));

    let Some(host) = host else { return };

    let scheme = url::Url::parse(url)
        .ok()
        .map(|u| u.scheme().to_string())
        .unwrap_or_default();

    match scheme.as_str() {
        "http" | "https" => {
            if let Some(ref token) = auth.token {
                engine.auth().set(
                    &host,
                    aos_net::Credential::Bearer {
                        token: token.clone(),
                        refresh: None,
                    },
                );
            } else if let (Some(user), Some(pass)) =
                (&auth.http_user, &auth.http_password)
            {
                engine.auth().set(
                    &host,
                    aos_net::Credential::Basic {
                        username: user.clone(),
                        password: pass.clone(),
                    },
                );
            }
            // Custom headers: use the first one as a Header credential if present.
            if auth.token.is_none()
                && auth.http_user.is_none()
                && !auth.headers.is_empty()
            {
                if let Some((k, v)) = auth.headers[0].split_once(':') {
                    engine.auth().set(
                        &host,
                        aos_net::Credential::Header {
                            name: k.trim().to_string(),
                            value: v.trim().to_string(),
                        },
                    );
                }
            }
        }
        "s3" => {
            engine.auth().set(
                &host,
                aos_net::Credential::AwsSigV4 {
                    region: auth
                        .s3_region
                        .clone()
                        .unwrap_or_else(|| "us-east-1".to_string()),
                    profile: auth.s3_profile.clone(),
                    endpoint: auth.s3_endpoint.clone(),
                },
            );
        }
        "sftp" | "ssh" => {
            if let Some(ref password) = auth.ssh_password {
                let username = url::Url::parse(url)
                    .ok()
                    .and_then(|u| {
                        if u.username().is_empty() {
                            None
                        } else {
                            Some(u.username().to_string())
                        }
                    })
                    .or_else(|| std::env::var("USER").ok())
                    .unwrap_or_else(|| "root".to_string());
                engine.auth().set(
                    &host,
                    aos_net::Credential::SshPassword {
                        username,
                        password: password.clone(),
                    },
                );
            } else {
                engine.auth().set(
                    &host,
                    aos_net::Credential::SshKey {
                        key_path: auth.ssh_key.as_ref().map(std::path::PathBuf::from),
                        password: None,
                        use_agent: true,
                    },
                );
            }
        }
        "ftp" | "ftps" => {
            let user = auth
                .ftp_user
                .clone()
                .unwrap_or_else(|| "anonymous".to_string());
            let password = auth
                .ftp_password
                .clone()
                .unwrap_or_else(|| "aos@".to_string());
            engine.auth().set(
                &host,
                aos_net::Credential::FtpLogin {
                    username: user,
                    password,
                },
            );
        }
        _ => {}
    }
}

/// Create a shared `TransferEngine` for a backend URL.
fn create_engine(url: &str, auth: &AuthOptions) -> Arc<TransferEngine> {
    let engine = TransferEngine::new(TransferEngineConfig::default());
    apply_auth_to_engine(&engine, url, auth);
    Arc::new(engine)
}

/// Create a backend from a URL string and auth options.
pub async fn from_url(url_str: &str, auth: &AuthOptions) -> Result<Box<dyn CacheBackend>> {
    let parsed = url::Url::parse(url_str)
        .map_err(|e| anyhow::anyhow!("invalid cache URL '{url_str}': {e}"))?;

    let engine = create_engine(url_str, auth);

    match parsed.scheme() {
        "file" => {
            let path = parsed
                .to_file_path()
                .map_err(|_| anyhow::anyhow!("invalid file URL: {url_str}"))?;
            Ok(Box::new(fs::FsBackend::new(path, engine)))
        }
        "http" | "https" => Ok(Box::new(
            http::HttpBackend::new(url_str, auth, engine).await?,
        )),
        "s3" => {
            let bucket = parsed
                .host_str()
                .ok_or_else(|| anyhow::anyhow!("S3 URL must have bucket name as host"))?;
            let prefix = parsed.path().trim_start_matches('/').to_string();
            Ok(Box::new(s3::S3Backend::new(
                bucket, &prefix, &engine,
            )))
        }
        "sftp" | "ssh" => {
            let path = parsed.path().to_string();
            Ok(Box::new(sftp::SftpBackend::new(
                url_str, &path, engine,
            )))
        }
        "ftp" | "ftps" => {
            let path = parsed.path().to_string();
            Ok(Box::new(ftp::FtpBackend::new(
                url_str, &path, engine,
            )))
        }
        other => anyhow::bail!("unsupported cache URL scheme: {other}"),
    }
}
