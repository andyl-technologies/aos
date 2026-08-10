//! SFTP (`sftp://` / `ssh://`) cache backend.

use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;

use aos_net::{TransferEngine, TransferRequest};

use super::{CacheBackend, add_static_metadata_headers};

/// SFTP cache backend.
///
/// Same layout as the filesystem backend, over SSH/SFTP.
/// Uses `aos_net::TransferEngine` with sftp:// URLs internally.
pub struct SftpBackend {
    engine: Arc<TransferEngine>,
    /// The base sftp:// URL (e.g. `sftp://user@host:port`).
    base_url: String,
    /// Remote root directory path.
    root: String,
}

impl SftpBackend {
    /// Creates a backend from the full cache URL and its already-parsed
    /// path component (the remote root directory). The path is stripped
    /// from `url` to recover the `sftp://user@host:port` base.
    pub fn new(url: &str, path: &str, engine: Arc<TransferEngine>) -> Self {
        // Strip the path from the original URL to get the base.
        let base_url = url
            .strip_suffix(path)
            .unwrap_or(url)
            .trim_end_matches('/')
            .to_string();

        Self {
            engine,
            base_url,
            root: path.trim_end_matches('/').to_string(),
        }
    }

    /// Builds a full sftp:// URL for a path relative to the remote root.
    fn remote_url(&self, relative_path: &str) -> String {
        format!("{}{}/{}", self.base_url, self.root, relative_path)
    }

    fn narinfo_url(&self, store_hash: &str) -> String {
        self.remote_url(&format!("{store_hash}.narinfo"))
    }

    fn nar_url(&self, filename: &str) -> String {
        self.remote_url(&format!("nar/{filename}"))
    }
}

#[async_trait]
impl CacheBackend for SftpBackend {
    async fn exists(&self, relative_path: &str) -> Result<bool> {
        let url = self.remote_url(relative_path.trim_start_matches('/'));
        let result = self.engine.head(&url).await?;
        Ok(result.status != 404)
    }

    async fn has_narinfo(&self, store_hash: &str) -> Result<bool> {
        let url = self.narinfo_url(store_hash);
        let result = self.engine.head(&url).await?;
        Ok(result.status != 404)
    }

    async fn get_narinfo(&self, store_hash: &str) -> Result<String> {
        let url = self.narinfo_url(store_hash);
        let result = self
            .engine
            .execute(TransferRequest::get(&url))
            .await
            .with_context(|| format!("fetching narinfo via SFTP: {url}"))?;

        let body = result
            .body
            .ok_or_else(|| anyhow::anyhow!("empty SFTP response for {url}"))?;
        String::from_utf8(body).context("narinfo is not valid UTF-8")
    }

    async fn put_narinfo(&self, store_hash: &str, content: &str) -> Result<()> {
        let url = self.narinfo_url(store_hash);
        let req = TransferRequest::put(&url, content.as_bytes().to_vec());
        self.engine
            .execute(req)
            .await
            .with_context(|| format!("uploading narinfo via SFTP: {url}"))?;
        Ok(())
    }

    async fn get_nar(&self, path: &str) -> Result<Vec<u8>> {
        let url = self.remote_url(path);
        let result = self
            .engine
            .execute(TransferRequest::get(&url))
            .await
            .with_context(|| format!("downloading NAR via SFTP: {url}"))?;

        result
            .body
            .ok_or_else(|| anyhow::anyhow!("empty SFTP NAR response for {url}"))
    }

    async fn put_nar(&self, filename: &str, data: &[u8]) -> Result<()> {
        let url = self.nar_url(filename);
        let req = TransferRequest::put(&url, data.to_vec());
        self.engine
            .execute(req)
            .await
            .with_context(|| format!("uploading NAR via SFTP: {url}"))?;
        Ok(())
    }

    async fn query_missing(&self, store_hashes: &[&str]) -> Result<Vec<String>> {
        let urls: Vec<String> = store_hashes.iter().map(|h| self.narinfo_url(h)).collect();
        let url_refs: Vec<&str> = urls.iter().map(String::as_str).collect();
        let results = self.engine.head_batch(&url_refs).await;

        let mut missing = Vec::new();
        for (i, result) in results.into_iter().enumerate() {
            let is_present = match result {
                Ok(r) => r.status != 404,
                Err(_) => false,
            };
            if !is_present {
                missing.push(store_hashes[i].to_string());
            }
        }
        Ok(missing)
    }

    async fn ensure_cache_info(&self, store_dir: &str) -> Result<()> {
        let info_url = self.remote_url("nix-cache-info");

        // Check if it already exists.
        let result = self.engine.head(&info_url).await?;
        if result.status == 200 {
            return Ok(());
        }

        // Create root and nar directories by writing empty marker files,
        // since SFTP protocol in aos-net creates parent dirs automatically.
        let content = format!("StoreDir: {store_dir}\nWantMassQuery: 1\nPriority: 40\n");
        let req = TransferRequest::put(&info_url, content.into_bytes());
        self.engine
            .execute(req)
            .await
            .context("writing nix-cache-info via SFTP")?;
        Ok(())
    }

    async fn put_cache_info(&self, content: &str) -> Result<()> {
        let info_url = self.remote_url("nix-cache-info");
        let req = TransferRequest::put(&info_url, content.as_bytes().to_vec());
        self.engine
            .execute(req)
            .await
            .context("writing nix-cache-info via SFTP")?;
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
        let url = self.remote_url(relative_path);
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
            .with_context(|| format!("uploading static file via SFTP: {url}"))?;
        Ok(())
    }
}
