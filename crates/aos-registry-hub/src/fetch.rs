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

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use async_trait::async_trait;

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
    /// Returns an error for IO or transport failures other than absence.
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
        match tokio::fs::read(&full).await {
            Ok(bytes) => Ok(Some(bytes)),
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err).with_context(|| format!("reading {}", full.display())),
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
            client: reqwest::Client::new(),
        }
    }
}

#[async_trait]
impl SurfaceFetch for HttpFetch {
    async fn fetch(&self, path: &str) -> Result<Option<Vec<u8>>> {
        let url = format!("{}/{path}", self.base);
        let response = self
            .client
            .get(&url)
            .send()
            .await
            .with_context(|| format!("fetching {url}"))?;
        if response.status() == reqwest::StatusCode::NOT_FOUND {
            return Ok(None);
        }
        if !response.status().is_success() {
            bail!("fetching {url}: HTTP {}", response.status());
        }
        Ok(Some(response.bytes().await?.to_vec()))
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
}
