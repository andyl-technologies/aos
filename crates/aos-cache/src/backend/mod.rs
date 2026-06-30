//! Cache storage backends and backend selection.
//!
//! A binary cache is a key-value layout of `<hash>.narinfo` metadata
//! files, `nar/<filename>` archives, and a `nix-cache-info` marker. The
//! [`CacheBackend`] trait abstracts that layout over four transports,
//! all built on `aos_net::TransferEngine`:
//!
//! - [`fs::FsBackend`] for `file://` URLs
//! - [`http::HttpBackend`] for `http://` / `https://` (generic caches
//!   and the AOS server API, which additionally supports pack uploads)
//! - [`s3::S3Backend`] for `s3://` buckets
//! - [`sftp::SftpBackend`] for `sftp://` / `ssh://` remotes
//!
//! [`from_url`] dispatches on the URL scheme and wires CLI-supplied
//! [`AuthOptions`] into the engine's per-host credential store.

pub mod fs;
pub mod http;
pub mod s3;
pub mod sftp;

use std::sync::Arc;

use anyhow::Result;
use async_trait::async_trait;

use aos_net::{TransferEngine, TransferEngineConfig, TransferRequest};

/// Trait for binary cache storage backends.
///
/// Store paths are identified by their *store hash* — the 32-character
/// base-32 hash prefix of the store path basename — which doubles as the
/// narinfo key (`<hash>.narinfo`). NAR payloads live under
/// backend-relative `nar/...` URLs recorded in the narinfo `URL` field.
#[async_trait]
pub trait CacheBackend: Send + Sync {
    /// Checks whether a backend-relative cache object exists.
    ///
    /// `relative_path` is rooted at the binary cache/origin root, for example
    /// `"<hash>.narinfo"`, `"nar/<name>.nar.zst"`, or
    /// `"objects/<fanout>/<object>"`.
    ///
    /// # Errors
    ///
    /// Returns an error if the existence check itself fails. A clean "not
    /// found" is `Ok(false)`.
    async fn exists(&self, relative_path: &str) -> Result<bool>;

    /// Checks whether a narinfo exists for a store hash.
    ///
    /// # Errors
    ///
    /// Returns an error if the existence check itself fails (transport
    /// error); a clean "not found" is `Ok(false)`.
    async fn has_narinfo(&self, store_hash: &str) -> Result<bool> {
        self.exists(&format!("{store_hash}.narinfo")).await
    }

    /// Fetches narinfo text for a store hash.
    ///
    /// # Errors
    ///
    /// Returns an error if the narinfo does not exist, the transfer
    /// fails, or the body is empty or not valid UTF-8.
    async fn get_narinfo(&self, store_hash: &str) -> Result<String>;

    /// Uploads narinfo text for a store hash.
    ///
    /// On the AOS server this is a no-op: narinfo is synthesised
    /// server-side from the paths registered by NAR/pack uploads.
    ///
    /// HTTP-served backends (`http`, `s3`) tag the upload with
    /// [`MUTABLE_CACHE_CONTROL`], since a narinfo can be rewritten in place
    /// (e.g. re-signed) and must not be cached as immutable.
    ///
    /// # Errors
    ///
    /// Returns an error if the upload fails.
    async fn put_narinfo(&self, store_hash: &str, content: &str) -> Result<()>;

    /// Downloads a NAR file by its backend-relative URL (as recorded in
    /// the narinfo `URL` field, e.g. `nar/<hash>.nar.zst`). Returns the
    /// raw (still compressed) bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if the transfer fails or the response body is
    /// empty.
    async fn get_nar(&self, url: &str) -> Result<Vec<u8>>;

    /// Uploads a NAR file under `nar/<filename>`.
    ///
    /// HTTP-served backends (`http`, `s3`) tag the upload with
    /// [`IMMUTABLE_CACHE_CONTROL`]: the filename embeds the NAR hash, so the
    /// bytes behind a URL never change.
    ///
    /// # Errors
    ///
    /// Returns an error if the upload fails.
    async fn put_nar(&self, filename: &str, data: &[u8]) -> Result<()>;

    /// Mints a short-lived presigned upload URL for a cache-relative object
    /// `path` (e.g. `nar/<file>.nar.zst`), when the cache is backed by a
    /// presignable public origin (S3/R2 with credentials sealed in the hub).
    ///
    /// `Ok(Some(url))` means the caller should upload the bytes **directly** to
    /// `url` via [`put_to_url`](CacheBackend::put_to_url) — bypassing the hub so
    /// the bytes never traverse the Worker. `Ok(None)` means no presign is
    /// available and the caller must fall back to [`put_nar`](CacheBackend::put_nar)
    /// (or multipart) through the facade. The narinfo is uploaded through the
    /// facade regardless, so the hub index stays authoritative.
    ///
    /// The default returns `Ok(None)` — only AOS HTTP backends presign.
    ///
    /// # Errors
    ///
    /// Returns an error only on a hard transport failure; an unsupported or
    /// not-presignable cache is `Ok(None)`, not an error.
    async fn mint_upload_url(&self, _path: &str) -> Result<Option<String>> {
        Ok(None)
    }

    /// Uploads bytes directly to a presigned `url` minted by
    /// [`mint_upload_url`](CacheBackend::mint_upload_url), bypassing the hub.
    ///
    /// The URL carries its own query-string authorization, so no credential
    /// headers are attached.
    ///
    /// # Errors
    ///
    /// Returns an error if the direct upload fails, or if the backend does not
    /// support presigned upload (the default).
    async fn put_to_url(&self, _url: &str, _data: &[u8]) -> Result<()> {
        anyhow::bail!("backend does not support presigned direct upload")
    }

    /// Mints presigned upload URLs for many object paths in one round-trip.
    ///
    /// Returns a map from each input path to its presigned PUT URL; paths that
    /// are not presignable are simply absent from the map (the caller falls back
    /// to the facade for those). The default returns an empty map — only AOS
    /// HTTP backends batch-mint.
    ///
    /// # Errors
    ///
    /// Returns an error only on a hard transport failure; a not-presignable
    /// cache yields an empty map, not an error.
    async fn mint_upload_urls(
        &self,
        _paths: &[String],
    ) -> Result<std::collections::HashMap<String, String>> {
        Ok(std::collections::HashMap::new())
    }

    /// Registers (writes + indexes) a batch of narinfos in one round-trip.
    ///
    /// Each tuple is `(store_hash, narinfo_text)`. Used after the NAR bytes have
    /// been uploaded directly to the origin, so the hub index stays authoritative
    /// without a per-narinfo round-trip. The default falls back to a per-narinfo
    /// [`put_narinfo`](CacheBackend::put_narinfo) so every backend works.
    ///
    /// # Errors
    ///
    /// Returns an error if any narinfo write/registration fails.
    async fn register_narinfos(&self, narinfos: &[(String, String)]) -> Result<()> {
        for (store_hash, content) in narinfos {
            self.put_narinfo(store_hash, content).await?;
        }
        Ok(())
    }

    /// Batch check: returns the subset of `store_hashes` that are
    /// missing from the cache.
    ///
    /// # Errors
    ///
    /// Returns an error if the query itself fails. Backends performing
    /// per-hash existence checks may instead treat an individual failed
    /// check as "missing".
    async fn query_missing(&self, store_hashes: &[&str]) -> Result<Vec<String>>;

    /// Writes a default `nix-cache-info` if one is not already present
    /// (one-time cache initialization).
    ///
    /// # Errors
    ///
    /// Returns an error if the existence check or the write fails.
    async fn ensure_cache_info(&self, store_dir: &str) -> Result<()>;

    /// Uploads an exact `nix-cache-info` body, overwriting any existing
    /// one.
    ///
    /// HTTP-served backends (`http`, `s3`) tag the upload with
    /// [`MUTABLE_CACHE_CONTROL`], since the marker is rewritten in place
    /// (e.g. on a `Priority` change).
    ///
    /// # Errors
    ///
    /// Returns an error if the upload fails.
    async fn put_cache_info(&self, content: &str) -> Result<()>;

    /// Uploads a static file at a backend-relative path, with optional
    /// `Content-Type` and `Cache-Control` metadata where the transport
    /// supports them.
    ///
    /// Used by the package registry to publish its static git-origin
    /// surface alongside the binary cache.
    ///
    /// # Errors
    ///
    /// Returns an error if the upload fails or the backend does not
    /// support arbitrary static files (the AOS server API).
    async fn put_static_file(
        &self,
        relative_path: &str,
        source: &std::path::Path,
        content_type: Option<&str>,
        cache_control: Option<&str>,
    ) -> Result<()>;

    /// Returns whether this backend supports AOS pack upload.
    ///
    /// Only true for [`http::HttpBackend`] when talking to an AOS
    /// server; the default is `false`.
    fn supports_pack(&self) -> bool {
        false
    }

    /// Uploads a pack of small NARs in one request and returns the store
    /// paths the server imported.
    ///
    /// # Errors
    ///
    /// Returns an error if the upload fails. The default implementation
    /// always errors; only backends with [`supports_pack`]
    /// returning `true` accept packs.
    ///
    /// [`supports_pack`]: CacheBackend::supports_pack
    async fn upload_pack(&self, _data: &[u8]) -> Result<Vec<String>> {
        anyhow::bail!("pack upload not supported by this backend")
    }

    /// Whether this backend supports the multipart upload protocol
    /// (initiate → upload-part → complete) for large NARs.
    ///
    /// The default is `false`; only a backend that can assemble a single object
    /// from several sub-cap parts (an AOS hub, whose backend passes through to
    /// R2/S3/local-disk native multipart) returns `true`. A NAR larger than a
    /// single request can carry is uploadable only when this is `true`.
    fn supports_multipart(&self) -> bool {
        false
    }

    /// Begin a multipart upload of the NAR at `nar_path` (e.g.
    /// `nar/<file>.nar.zst`), returning the backend's opaque `upload_id` and the
    /// suggested part size in bytes.
    ///
    /// # Errors
    ///
    /// Returns an error when the backend does not support multipart or the
    /// request fails. The default always errors.
    async fn initiate_multipart(&self, _nar_path: &str) -> Result<(String, u64)> {
        anyhow::bail!("multipart upload not supported by this backend")
    }

    /// Upload one part (`part_number`, 1-based) of the in-progress upload
    /// `upload_id`, returning the part's `(part_number, etag)`.
    ///
    /// # Errors
    ///
    /// Returns an error when the backend does not support multipart or the
    /// part upload fails.
    async fn upload_part(
        &self,
        _nar_path: &str,
        _upload_id: &str,
        _part_number: u32,
        _data: &[u8],
    ) -> Result<(u32, String)> {
        anyhow::bail!("multipart upload not supported by this backend")
    }

    /// Complete the multipart upload `upload_id`, assembling the ordered
    /// `(part_number, etag)` parts into the final NAR.
    ///
    /// # Errors
    ///
    /// Returns an error when the backend does not support multipart or the
    /// completion fails.
    async fn complete_multipart(
        &self,
        _nar_path: &str,
        _upload_id: &str,
        _parts: &[(u32, String)],
    ) -> Result<()> {
        anyhow::bail!("multipart upload not supported by this backend")
    }
}

/// `Cache-Control` for content-addressed payloads that never change in
/// place: NAR archives, git loose objects, and release packs. The one-year
/// `max-age` plus `immutable` lets CDNs and browsers serve them without
/// revalidating, which is safe because the serving URL changes whenever the
/// bytes do.
///
/// This is the single source of truth for the registry's "immutable" caching
/// policy: the binary-cache backends apply it to NAR uploads, and the
/// git-origin uploader applies it to content-addressed objects and packs.
pub const IMMUTABLE_CACHE_CONTROL: &str = "public, max-age=31536000, s-maxage=31536000, immutable";

/// `Cache-Control` for small files that are rewritten in place across
/// publishes: git ref pointers (`HEAD`, `info/refs`, `objects/info/*`,
/// channel partitions), narinfos (which can be re-signed), and
/// `nix-cache-info`. The short `max-age` with `must-revalidate` bounds how
/// long a stale copy may be served — the freshness contract a CDN origin must
/// honor for a release to become visible promptly.
pub const MUTABLE_CACHE_CONTROL: &str = "public, max-age=60, s-maxage=60, must-revalidate";

/// Appends optional `Content-Type` / `Cache-Control` headers to a static
/// file upload request. Shared by all backends' `put_static_file`.
pub(crate) fn add_static_metadata_headers(
    request: &mut TransferRequest,
    content_type: Option<&str>,
    cache_control: Option<&str>,
) {
    if let Some(content_type) = content_type {
        request
            .headers
            .push(("Content-Type".to_string(), content_type.to_string()));
    }
    if let Some(cache_control) = cache_control {
        request
            .headers
            .push(("Cache-Control".to_string(), cache_control.to_string()));
    }
}

/// Authentication options collected from CLI flags.
///
/// All fields are optional; which subset is consulted depends on the URL
/// scheme of the cache (see [`from_url`]).
#[derive(Debug, Clone, Default)]
#[allow(dead_code)]
pub struct AuthOptions {
    // HTTP
    /// AOS provisioning token. Presence marks the target as an AOS
    /// server: the backend exchanges it for a JWT and enables the AOS
    /// API (query-missing, pack upload).
    pub token: Option<String>,
    /// AOS server view name (the path component of the cache URL, e.g.
    /// `default`).
    pub view: String,
    /// Username for HTTP basic auth (paired with `http_password`).
    pub http_user: Option<String>,
    /// Password for HTTP basic auth (paired with `http_user`).
    pub http_password: Option<String>,
    /// Extra `Name: value` headers added to every HTTP request. When no
    /// other HTTP credential is set, the first entry also serves as a
    /// header credential.
    pub headers: Vec<String>,

    // S3
    /// AWS region for SigV4 signing (default `us-east-1`).
    pub s3_region: Option<String>,
    /// AWS shared-config profile to take credentials from.
    pub s3_profile: Option<String>,
    /// Custom S3 endpoint URL (for S3-compatible object stores).
    pub s3_endpoint: Option<String>,

    // SFTP
    /// Path to an SSH private key file. When unset, the SSH agent is
    /// used.
    pub ssh_key: Option<String>,
    /// SSH password. Takes precedence over key/agent authentication.
    pub ssh_password: Option<String>,
    /// Whether to prompt interactively for the SSH password.
    pub ssh_ask_pass: bool,
}

/// Maps [`AuthOptions`] to `aos_net` credentials and registers them on
/// the engine's per-host auth store.
///
/// The credential kind follows the URL scheme: bearer/basic/header for
/// HTTP(S), AWS SigV4 for `s3`, and SSH password or key/agent for
/// `sftp`/`ssh`. Unparseable URLs and unknown schemes register nothing.
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
            } else if let (Some(user), Some(pass)) = (&auth.http_user, &auth.http_password) {
                engine.auth().set(
                    &host,
                    aos_net::Credential::Basic {
                        username: user.clone(),
                        password: pass.clone(),
                    },
                );
            }
            // Custom headers: use the first one as a Header credential if present.
            if auth.token.is_none() && auth.http_user.is_none() && !auth.headers.is_empty() {
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
        _ => {}
    }
}

/// Creates a shared `TransferEngine` for a backend URL with credentials
/// pre-registered.
fn create_engine(url: &str, auth: &AuthOptions) -> Arc<TransferEngine> {
    let engine = TransferEngine::new(TransferEngineConfig::default());
    apply_auth_to_engine(&engine, url, auth);
    Arc::new(engine)
}

/// Creates a backend from a URL string and auth options.
///
/// Dispatches on the URL scheme: `file` -> [`fs::FsBackend`],
/// `http`/`https` -> [`http::HttpBackend`], `s3` ->
/// [`s3::S3Backend`] (host is the bucket, path is the key prefix), and
/// `sftp`/`ssh` -> [`sftp::SftpBackend`].
///
/// # Errors
///
/// Returns an error if the URL does not parse, uses an unsupported
/// scheme, is a malformed `file` or `s3` URL, or — for AOS HTTP backends
/// — if exchanging the provisioning token for a JWT fails.
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
            Ok(Box::new(s3::S3Backend::new(bucket, &prefix, &engine)))
        }
        "sftp" | "ssh" => {
            let path = parsed.path().to_string();
            Ok(Box::new(sftp::SftpBackend::new(url_str, &path, engine)))
        }
        other => anyhow::bail!("unsupported cache URL scheme: {other}"),
    }
}
