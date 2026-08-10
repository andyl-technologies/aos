//! Filesystem (`file://`) cache backend.

use std::io::Read as _;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;

use aos_net::{TransferEngine, TransferRequest};
use sha2::{Digest as _, Sha256};

use super::{CacheBackend, StaticFileIdentity, add_static_metadata_headers};

/// Filesystem cache backend.
///
/// Stores narinfos and NARs in a local directory, producing a layout directly
/// usable as `--substituters file:///path`.
/// Uses `aos_net::TransferEngine` with file:// URLs internally.
pub struct FsBackend {
    engine: Arc<TransferEngine>,
    root: PathBuf,
}

impl FsBackend {
    /// Creates a backend rooted at `root`. The directory is created
    /// lazily on first write.
    pub fn new(root: PathBuf, engine: Arc<TransferEngine>) -> Self {
        Self { engine, root }
    }

    /// Builds a `file://` URL for a path relative to the cache root.
    fn file_url(&self, relative: &str) -> String {
        let path = self.root.join(relative);
        format!("file://{}", path.display())
    }

    fn narinfo_url(&self, store_hash: &str) -> String {
        self.file_url(&format!("{store_hash}.narinfo"))
    }

    fn nar_dir(&self) -> PathBuf {
        self.root.join("nar")
    }
}

#[async_trait]
impl CacheBackend for FsBackend {
    async fn exists(&self, relative_path: &str) -> Result<bool> {
        Ok(self.root.join(relative_path).exists())
    }

    async fn static_file_identity(
        &self,
        relative_path: &str,
    ) -> Result<Option<StaticFileIdentity>> {
        let path = self.root.join(relative_path);
        let mut file = match std::fs::File::open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("opening {}", path.display())),
        };
        let metadata = file
            .metadata()
            .with_context(|| format!("stat {}", path.display()))?;
        if !metadata.is_file() {
            return Ok(None);
        }
        let mut hasher = Sha256::new();
        let mut buffer = [0_u8; 128 * 1024];
        loop {
            let count = file
                .read(&mut buffer)
                .with_context(|| format!("reading {}", path.display()))?;
            if count == 0 {
                break;
            }
            hasher.update(&buffer[..count]);
        }
        Ok(Some(StaticFileIdentity {
            byte_size: metadata.len(),
            sha256: hex::encode(hasher.finalize()),
        }))
    }

    async fn has_narinfo(&self, store_hash: &str) -> Result<bool> {
        let url = self.narinfo_url(store_hash);
        let result = self.engine.head(&url).await?;
        Ok(result.status == 200)
    }

    async fn get_narinfo(&self, store_hash: &str) -> Result<String> {
        let url = self.narinfo_url(store_hash);
        let result = self
            .engine
            .execute(TransferRequest::get(&url))
            .await
            .with_context(|| format!("reading narinfo {url}"))?;

        let body = result
            .body
            .ok_or_else(|| anyhow::anyhow!("empty response for {url}"))?;
        String::from_utf8(body).context("narinfo is not valid UTF-8")
    }

    async fn put_narinfo(&self, store_hash: &str, content: &str) -> Result<()> {
        // Ensure cache directory exists (TransferEngine's file:// protocol
        // creates parent dirs, but we need the root).
        tokio::fs::create_dir_all(&self.root)
            .await
            .context("creating cache directory")?;

        let url = self.narinfo_url(store_hash);
        let req = TransferRequest::put(&url, content.as_bytes().to_vec());
        self.engine
            .execute(req)
            .await
            .with_context(|| format!("writing narinfo {url}"))?;
        Ok(())
    }

    async fn get_nar(&self, relative_path: &str) -> Result<Vec<u8>> {
        let url = self.file_url(relative_path);
        let result = self
            .engine
            .execute(TransferRequest::get(&url))
            .await
            .with_context(|| format!("reading NAR {url}"))?;

        result
            .body
            .ok_or_else(|| anyhow::anyhow!("empty response for {url}"))
    }

    async fn put_nar(&self, filename: &str, data: &[u8]) -> Result<()> {
        let nar_dir = self.nar_dir();
        tokio::fs::create_dir_all(&nar_dir)
            .await
            .context("creating nar directory")?;

        let url = self.file_url(&format!("nar/{filename}"));
        let req = TransferRequest::put(&url, data.to_vec());
        self.engine
            .execute(req)
            .await
            .with_context(|| format!("writing NAR {url}"))?;
        Ok(())
    }

    async fn query_missing(&self, store_hashes: &[&str]) -> Result<Vec<String>> {
        // For filesystem, simple stat check is faster than going through engine.
        let mut missing = Vec::new();
        for hash in store_hashes {
            let path = self.root.join(format!("{hash}.narinfo"));
            if !path.exists() {
                missing.push(hash.to_string());
            }
        }
        Ok(missing)
    }

    async fn ensure_cache_info(&self, store_dir: &str) -> Result<()> {
        tokio::fs::create_dir_all(&self.root)
            .await
            .context("creating cache directory")?;

        let info_path = self.root.join("nix-cache-info");
        if !info_path.exists() {
            let content = format!("StoreDir: {store_dir}\nWantMassQuery: 1\nPriority: 40\n");
            let url = self.file_url("nix-cache-info");
            let req = TransferRequest::put(&url, content.into_bytes());
            self.engine
                .execute(req)
                .await
                .context("writing nix-cache-info")?;
        }
        Ok(())
    }

    async fn put_cache_info(&self, content: &str) -> Result<()> {
        tokio::fs::create_dir_all(&self.root)
            .await
            .context("creating cache directory")?;

        let url = self.file_url("nix-cache-info");
        let req = TransferRequest::put(&url, content.as_bytes().to_vec());
        self.engine
            .execute(req)
            .await
            .context("writing nix-cache-info")?;
        Ok(())
    }

    async fn put_static_file(
        &self,
        relative_path: &str,
        source: &std::path::Path,
        content_type: Option<&str>,
        cache_control: Option<&str>,
        content_disposition: Option<&str>,
        sha256: Option<&str>,
    ) -> Result<()> {
        let url = self.file_url(relative_path);
        let mut req = TransferRequest::put_file(&url, source.to_path_buf());
        add_static_metadata_headers(
            &mut req,
            content_type,
            cache_control,
            content_disposition,
            sha256,
        );
        self.engine
            .execute(req)
            .await
            .with_context(|| format!("writing static file {url}"))?;
        Ok(())
    }
}
