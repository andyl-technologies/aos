use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;

use aos_net::{TransferEngine, TransferRequest};

use super::CacheBackend;

/// S3 cache backend.
///
/// Standard binary cache layout in an S3 bucket:
/// `s3://bucket/{prefix}/{hash}.narinfo` and `s3://bucket/{prefix}/nar/{filename}`.
pub struct S3Backend {
    engine: Arc<TransferEngine>,
    bucket: String,
    prefix: String,
}

impl S3Backend {
    pub fn new(bucket: &str, prefix: &str, engine: &Arc<TransferEngine>) -> Self {
        Self {
            engine: Arc::clone(engine),
            bucket: bucket.to_string(),
            prefix: prefix.trim_matches('/').to_string(),
        }
    }

    fn s3_url(&self, path: &str) -> String {
        if self.prefix.is_empty() {
            format!("s3://{}/{}", self.bucket, path)
        } else {
            format!("s3://{}/{}/{}", self.bucket, self.prefix, path)
        }
    }
}

#[async_trait]
impl CacheBackend for S3Backend {
    async fn has_narinfo(&self, store_hash: &str) -> Result<bool> {
        let url = self.s3_url(&format!("{store_hash}.narinfo"));
        let result = self.engine.head(&url).await?;
        Ok(result.status != 404)
    }

    async fn get_narinfo(&self, store_hash: &str) -> Result<String> {
        let url = self.s3_url(&format!("{store_hash}.narinfo"));
        let result = self
            .engine
            .execute(TransferRequest::get(&url))
            .await
            .with_context(|| format!("S3 GetObject {url}"))?;

        let body = result
            .body
            .ok_or_else(|| anyhow::anyhow!("empty S3 response for {url}"))?;
        String::from_utf8(body).context("narinfo is not valid UTF-8")
    }

    async fn put_narinfo(&self, store_hash: &str, content: &str) -> Result<()> {
        let url = self.s3_url(&format!("{store_hash}.narinfo"));
        let mut req = TransferRequest::put(&url, content.as_bytes().to_vec());
        req.headers
            .push(("Content-Type".to_string(), "text/x-nix-narinfo".to_string()));
        self.engine
            .execute(req)
            .await
            .with_context(|| format!("S3 PutObject {url}"))?;
        Ok(())
    }

    async fn get_nar(&self, path: &str) -> Result<Vec<u8>> {
        let url = self.s3_url(path);
        let result = self
            .engine
            .execute(TransferRequest::get(&url))
            .await
            .with_context(|| format!("S3 GetObject {url}"))?;

        result
            .body
            .ok_or_else(|| anyhow::anyhow!("empty S3 NAR response for {url}"))
    }

    async fn put_nar(&self, filename: &str, data: &[u8]) -> Result<()> {
        let url = self.s3_url(&format!("nar/{filename}"));
        let mut req = TransferRequest::put(&url, data.to_vec());
        req.headers.push((
            "Content-Type".to_string(),
            "application/x-nix-nar".to_string(),
        ));
        self.engine
            .execute(req)
            .await
            .with_context(|| format!("S3 PutObject {url}"))?;
        Ok(())
    }

    async fn query_missing(&self, store_hashes: &[&str]) -> Result<Vec<String>> {
        // Batch HEAD requests via the engine.
        let urls: Vec<String> = store_hashes
            .iter()
            .map(|h| self.s3_url(&format!("{h}.narinfo")))
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
        let url = self.s3_url("nix-cache-info");

        // Check if it already exists.
        let result = self.engine.head(&url).await?;
        if result.status == 200 {
            return Ok(());
        }

        let content = format!("StoreDir: {store_dir}\nWantMassQuery: 1\nPriority: 40\n");
        let mut req = TransferRequest::put(&url, content.into_bytes());
        req.headers
            .push(("Content-Type".to_string(), "text/plain".to_string()));
        self.engine
            .execute(req)
            .await
            .context("writing nix-cache-info to S3")?;
        Ok(())
    }

    async fn put_cache_info(&self, content: &str) -> Result<()> {
        let url = self.s3_url("nix-cache-info");
        let mut req = TransferRequest::put(&url, content.as_bytes().to_vec());
        req.headers
            .push(("Content-Type".to_string(), "text/plain".to_string()));
        self.engine
            .execute(req)
            .await
            .context("writing nix-cache-info to S3")?;
        Ok(())
    }
}
