use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;

use aos_net::{TransferEngine, TransferRequest};

use super::CacheBackend;

/// FTP cache backend.
///
/// Standard binary cache layout on a remote FTP server.
/// Uses `aos_net::TransferEngine` with ftp:// URLs internally.
pub struct FtpBackend {
    engine: Arc<TransferEngine>,
    /// The base ftp:// URL (e.g. `ftp://host:port`).
    base_url: String,
    /// Remote root directory path.
    root: String,
}

impl FtpBackend {
    pub fn new(
        url: &str,
        path: &str,
        engine: Arc<TransferEngine>,
    ) -> Self {
        // Strip the path from the original URL to get the base.
        let base_url = url
            .strip_suffix(path)
            .unwrap_or(url)
            .trim_end_matches('/')
            .to_string();

        Self {
            engine,
            base_url,
            root: path
                .trim_start_matches('/')
                .trim_end_matches('/')
                .to_string(),
        }
    }

    fn remote_url(&self, relative: &str) -> String {
        if self.root.is_empty() {
            format!("{}/{}", self.base_url, relative)
        } else {
            format!("{}/{}/{}", self.base_url, self.root, relative)
        }
    }

    fn narinfo_url(&self, store_hash: &str) -> String {
        self.remote_url(&format!("{store_hash}.narinfo"))
    }

    fn nar_url(&self, filename: &str) -> String {
        self.remote_url(&format!("nar/{filename}"))
    }
}

#[async_trait]
impl CacheBackend for FtpBackend {
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
            .with_context(|| format!("fetching narinfo via FTP: {url}"))?;

        let body = result
            .body
            .ok_or_else(|| anyhow::anyhow!("empty FTP response for {url}"))?;
        String::from_utf8(body).context("narinfo is not valid UTF-8")
    }

    async fn put_narinfo(&self, store_hash: &str, content: &str) -> Result<()> {
        let url = self.narinfo_url(store_hash);
        let req = TransferRequest::put(&url, content.as_bytes().to_vec());
        self.engine
            .execute(req)
            .await
            .with_context(|| format!("uploading narinfo via FTP: {url}"))?;
        Ok(())
    }

    async fn get_nar(&self, path: &str) -> Result<Vec<u8>> {
        let url = self.remote_url(path);
        let result = self
            .engine
            .execute(TransferRequest::get(&url))
            .await
            .with_context(|| format!("downloading NAR via FTP: {url}"))?;

        result
            .body
            .ok_or_else(|| anyhow::anyhow!("empty FTP NAR response for {url}"))
    }

    async fn put_nar(&self, filename: &str, data: &[u8]) -> Result<()> {
        let url = self.nar_url(filename);
        let req = TransferRequest::put(&url, data.to_vec());
        self.engine
            .execute(req)
            .await
            .with_context(|| format!("uploading NAR via FTP: {url}"))?;
        Ok(())
    }

    async fn query_missing(&self, store_hashes: &[&str]) -> Result<Vec<String>> {
        let urls: Vec<String> = store_hashes
            .iter()
            .map(|h| self.narinfo_url(h))
            .collect();
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

        let content = format!(
            "StoreDir: {store_dir}\nWantMassQuery: 1\nPriority: 40\n"
        );
        let req = TransferRequest::put(&info_url, content.into_bytes());
        self.engine
            .execute(req)
            .await
            .context("writing nix-cache-info via FTP")?;
        Ok(())
    }
}
