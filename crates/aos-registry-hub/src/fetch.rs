//! Transport abstraction for reading a registry surface.
//!
//! The surface reader and indexer are transport-agnostic: they ask a
//! [`SurfaceFetch`] for relative paths (`HEAD`, `info/refs`,
//! `objects/ab/cd…`, `channels/stable/00`, …) and get bytes or a definite
//! "not present". Two transports cover the deployment matrix:
//!
//! - [`LocalFsFetch`] for `file://` storage bindings — the local-first
//!   mode, where the registry surface is a directory on disk.
//! - [`HttpFetch`] for registration-only registries indexed through their
//!   public CDN URL, exactly as an `apm` client would fetch them.
//!
//! Transport-level failures (network errors, non-404 HTTP statuses, local
//! IO errors other than absence) are wrapped in [`FetchError`] so callers
//! can classify them with [`is_fetch_error`] — e.g. the indexer marks a
//! registry *stale* (surface unreachable) rather than *failed* (surface
//! invalid) when the underlying error is a fetch error.

use std::path::PathBuf;
use std::time::Duration;

use anyhow::{bail, Result};
use async_trait::async_trait;

/// Maximum response body size accepted from a surface fetch (64 MiB).
///
/// Applies to HTTP responses: a `Content-Length` past the cap is rejected
/// before the body is read, and chunked/streamed bodies are accumulated
/// with the same cap (and additionally bounded by the client's 30-second
/// total-request timeout).
pub const MAX_FETCH_BYTES: u64 = 64 * 1024 * 1024;

/// Marker error for transport-level surface fetch failures.
///
/// All transport failures — reqwest errors, non-404 HTTP statuses, local
/// IO errors other than `NotFound`, symlink escapes — are wrapped in this
/// type (with the detail preserved in the message) so callers can
/// classify them through `anyhow` context chains via [`is_fetch_error`].
#[derive(Debug, thiserror::Error)]
#[error("surface fetch failed: {0}")]
pub struct FetchError(pub String);

/// Whether any error in `err`'s chain is a transport-level [`FetchError`].
///
/// Walks the full `anyhow` context chain, so classification survives any
/// number of `.context(…)` layers added by callers.
pub fn is_fetch_error(err: &anyhow::Error) -> bool {
    err.chain()
        .any(|cause| cause.downcast_ref::<FetchError>().is_some())
}

/// Wrap a message as a transport-level fetch failure.
fn fetch_err(message: impl Into<String>) -> anyhow::Error {
    anyhow::Error::new(FetchError(message.into()))
}

/// Build the hardened HTTP client used for all hub-originated requests.
///
/// 30-second total-request timeout, 10-second connect timeout. Shared by
/// [`HttpFetch`] and the cache validators so every outbound request is
/// bounded.
pub fn hardened_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(10))
        .build()
        // Building only fails when the TLS backend cannot initialize, in
        // which case `Client::new()` would panic identically; fall back
        // to the default client rather than aborting.
        .unwrap_or_else(|_| reqwest::Client::new())
}

/// Read access to a registry surface by relative path.
#[async_trait]
pub trait SurfaceFetch: Send + Sync {
    /// Fetch one surface path.
    ///
    /// Returns `Ok(None)` when the path definitively does not exist
    /// (missing file, HTTP 404) — a meaningful state for channel partition
    /// probing — and an error for transport failures.
    ///
    /// # Errors
    ///
    /// Returns an error for IO or transport failures other than absence;
    /// transport-level failures carry a [`FetchError`] in their chain.
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>>;

    /// A human-readable description of the source (for health/audit text).
    fn describe(&self) -> String;
}

/// Filesystem-backed surface access for `file://` bindings.
pub struct LocalFsFetch {
    root: PathBuf,
}

impl LocalFsFetch {
    /// Create a fetcher rooted at a surface directory.
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// The surface root directory.
    pub fn root(&self) -> &std::path::Path {
        &self.root
    }
}

#[async_trait]
impl SurfaceFetch for LocalFsFetch {
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
        let full = safe_join(&self.root, path)?;
        // Containment: resolve symlinks and require the real file to live
        // under the real root, so a hostile surface cannot link out of it.
        let root = tokio::fs::canonicalize(&self.root).await.map_err(|err| {
            fetch_err(format!(
                "canonicalizing surface root {}: {err}",
                self.root.display()
            ))
        })?;
        let canonical = match tokio::fs::canonicalize(&full).await {
            Ok(canonical) => canonical,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(fetch_err(format!("resolving {}: {err}", full.display())));
            }
        };
        if !canonical.starts_with(&root) {
            return Err(fetch_err(format!(
                "surface path '{path}' escapes the surface root via symlink"
            )));
        }
        match tokio::fs::read(&canonical).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(fetch_err(format!("reading {}: {err}", canonical.display()))),
        }
    }

    fn describe(&self) -> String {
        format!("file://{}", self.root.display())
    }
}

/// HTTP(S)-backed surface access for registration-only registries.
pub struct HttpFetch {
    base: String,
    client: reqwest::Client,
}

impl HttpFetch {
    /// Create a fetcher for a registry base URL.
    pub fn new(base: impl Into<String>) -> Self {
        Self {
            base: base.into().trim_end_matches('/').to_string(),
            client: hardened_client(),
        }
    }
}

#[async_trait]
impl SurfaceFetch for HttpFetch {
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
        let url = format!("{}/{path}", self.base);
        let mut response = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|err| fetch_err(format!("fetching {url}: {err}")))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            return Err(fetch_err(format!(
                "fetching {url}: HTTP {}",
                response.status()
            )));
        }
        // Reject oversized bodies up front when the server declares a
        // length, then stream with the same cap so chunked responses
        // (no Content-Length) are bounded too.
        if let Some(declared) = response.content_length() {
            if declared > MAX_FETCH_BYTES {
                return Err(fetch_err(format!(
                    "fetching {url}: response is {declared} bytes (cap {MAX_FETCH_BYTES})"
                )));
            }
        }
        let mut body: Vec<u8> = Vec::new();
        loop {
            let chunk = response
                .chunk()
                .await
                .map_err(|err| fetch_err(format!("reading {url}: {err}")))?;
            let Some(chunk) = chunk else { break };
            if body.len() as u64 + chunk.len() as u64 > MAX_FETCH_BYTES {
                return Err(fetch_err(format!(
                    "fetching {url}: response exceeds the {MAX_FETCH_BYTES}-byte cap"
                )));
            }
            body.extend_from_slice(&chunk);
        }
        Ok(Some(body))
    }

    fn describe(&self) -> String {
        self.base.clone()
    }
}

/// Construct a fetcher from a registry source URL.
///
/// `file://` and bare absolute paths map to [`LocalFsFetch`]; `http://`
/// and `https://` map to [`HttpFetch`].
///
/// # Errors
///
/// Returns an error for unsupported URL schemes.
pub fn fetch_for_url(source_url: &str) -> Result<Box<dyn SurfaceFetch>> {
    if let Some(path) = source_url.strip_prefix("file://") {
        return Ok(Box::new(LocalFsFetch::new(path)));
    }
    if source_url.starts_with('/') {
        return Ok(Box::new(LocalFsFetch::new(source_url)));
    }
    if source_url.starts_with("http://") || source_url.starts_with("https://") {
        return Ok(Box::new(HttpFetch::new(source_url)));
    }
    bail!(
        "unsupported registry source URL '{source_url}' (expected file://, /path, or http(s)://)"
    );
}

/// Join a relative surface path onto a root, rejecting traversal.
///
/// # Errors
///
/// Returns an error for absolute paths or any `..` component.
pub fn safe_join(root: &std::path::Path, relative: &str) -> Result<PathBuf> {
    let rel = std::path::Path::new(relative);
    if rel.is_absolute() {
        bail!("surface path must be relative: '{relative}'");
    }
    for component in rel.components() {
        match component {
            std::path::Component::Normal(_) => {}
            _ => bail!("surface path contains illegal component: '{relative}'"),
        }
    }
    Ok(root.join(rel))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn local_fetch_distinguishes_missing_from_error() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("HEAD"), b"ref: refs/heads/stable\n").unwrap();
        let fetch = LocalFsFetch::new(dir.path());
        assert!(fetch.fetch("HEAD").await.unwrap().is_some());
        assert!(fetch.fetch("info/refs").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn local_fetch_rejects_symlink_escape() {
        let dir = tempfile::tempdir().unwrap();
        let outside = dir.path().join("secret.txt");
        std::fs::write(&outside, b"keys").unwrap();
        let root = dir.path().join("surface");
        std::fs::create_dir_all(root.join("objects/zz")).unwrap();
        std::os::unix::fs::symlink(&outside, root.join("objects/zz/escape")).unwrap();

        let fetch = LocalFsFetch::new(&root);
        let err = fetch.fetch("objects/zz/escape").await.unwrap_err();
        assert!(is_fetch_error(&err), "got: {err:#}");
        assert!(err.to_string().contains("escapes"), "got: {err:#}");
    }

    #[test]
    fn safe_join_rejects_traversal() {
        let root = std::path::Path::new("/srv/reg");
        assert!(safe_join(root, "objects/ab/cd").is_ok());
        assert!(safe_join(root, "../etc/passwd").is_err());
        assert!(safe_join(root, "/etc/passwd").is_err());
        assert!(safe_join(root, "a/../../b").is_err());
    }

    #[test]
    fn fetch_for_url_dispatches_schemes() {
        assert!(fetch_for_url("file:///srv/reg").is_ok());
        assert!(fetch_for_url("/srv/reg").is_ok());
        assert!(fetch_for_url("https://cdn.example.com/reg").is_ok());
        assert!(fetch_for_url("s3://bucket/prefix").is_err());
    }

    #[test]
    fn fetch_error_classification_survives_context() {
        use anyhow::Context as _;
        let err: anyhow::Error = fetch_err("connection refused");
        let wrapped = Err::<(), _>(err)
            .context("indexing demo")
            .context("outer")
            .unwrap_err();
        assert!(is_fetch_error(&wrapped));
        assert!(!is_fetch_error(&anyhow::anyhow!("parse error")));
    }
}
