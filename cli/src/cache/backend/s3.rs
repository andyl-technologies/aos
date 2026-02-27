use anyhow::{Context, Result};
use async_trait::async_trait;

use super::{AuthOptions, CacheBackend};

/// S3 cache backend.
///
/// Standard binary cache layout in an S3 bucket:
/// `{prefix}/{hash}.narinfo` and `{prefix}/nar/{filename}`.
pub struct S3Backend {
    client: aws_sdk_s3::Client,
    bucket: String,
    prefix: String,
}

impl S3Backend {
    pub async fn new(bucket: &str, prefix: &str, auth: &AuthOptions) -> Result<Self> {
        let mut config_loader = aws_config::defaults(aws_config::BehaviorVersion::latest());

        if let Some(ref region) = auth.s3_region {
            config_loader =
                config_loader.region(aws_config::Region::new(region.clone()));
        }
        if let Some(ref profile) = auth.s3_profile {
            config_loader = config_loader.profile_name(profile);
        }

        let config = config_loader.load().await;

        let mut s3_config = aws_sdk_s3::config::Builder::from(&config);
        if let Some(ref endpoint) = auth.s3_endpoint {
            s3_config = s3_config.endpoint_url(endpoint).force_path_style(true);
        }

        let client = aws_sdk_s3::Client::from_conf(s3_config.build());

        Ok(Self {
            client,
            bucket: bucket.to_string(),
            prefix: prefix.trim_matches('/').to_string(),
        })
    }

    fn key(&self, path: &str) -> String {
        if self.prefix.is_empty() {
            path.to_string()
        } else {
            format!("{}/{}", self.prefix, path)
        }
    }
}

#[async_trait]
impl CacheBackend for S3Backend {
    async fn has_narinfo(&self, store_hash: &str) -> Result<bool> {
        let key = self.key(&format!("{store_hash}.narinfo"));
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
        {
            Ok(_) => Ok(true),
            Err(e) => {
                let svc = e.into_service_error();
                if svc.is_not_found() {
                    Ok(false)
                } else {
                    Err(anyhow::anyhow!("S3 HeadObject failed: {svc}"))
                }
            }
        }
    }

    async fn get_narinfo(&self, store_hash: &str) -> Result<String> {
        let key = self.key(&format!("{store_hash}.narinfo"));
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .with_context(|| format!("S3 GetObject {key}"))?;

        let body = resp
            .body
            .collect()
            .await
            .context("reading S3 object body")?;
        String::from_utf8(body.to_vec()).context("narinfo is not valid UTF-8")
    }

    async fn put_narinfo(&self, store_hash: &str, content: &str) -> Result<()> {
        let key = self.key(&format!("{store_hash}.narinfo"));
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .content_type("text/x-nix-narinfo")
            .body(content.as_bytes().to_vec().into())
            .send()
            .await
            .with_context(|| format!("S3 PutObject {key}"))?;
        Ok(())
    }

    async fn get_nar(&self, url: &str) -> Result<Vec<u8>> {
        let key = self.key(url);
        let resp = self
            .client
            .get_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
            .with_context(|| format!("S3 GetObject {key}"))?;

        let body = resp
            .body
            .collect()
            .await
            .context("reading NAR from S3")?;
        Ok(body.to_vec())
    }

    async fn put_nar(&self, filename: &str, data: &[u8]) -> Result<()> {
        let key = self.key(&format!("nar/{filename}"));
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .content_type("application/x-nix-nar")
            .body(data.to_vec().into())
            .send()
            .await
            .with_context(|| format!("S3 PutObject {key}"))?;
        Ok(())
    }

    async fn query_missing(&self, store_hashes: &[&str]) -> Result<Vec<String>> {
        // Parallel HeadObject checks.
        let mut missing = Vec::new();
        // Process in chunks to avoid overwhelming S3.
        for chunk in store_hashes.chunks(50) {
            let futs: Vec<_> = chunk
                .iter()
                .map(|hash| {
                    let hash = hash.to_string();
                    let this = &self;
                    async move {
                        let exists = this.has_narinfo(&hash).await.unwrap_or(false);
                        if !exists {
                            Some(hash)
                        } else {
                            None
                        }
                    }
                })
                .collect();

            let results = futures_util::future::join_all(futs).await;
            for r in results {
                if let Some(hash) = r {
                    missing.push(hash);
                }
            }
        }
        Ok(missing)
    }

    async fn ensure_cache_info(&self, store_dir: &str) -> Result<()> {
        let key = self.key("nix-cache-info");

        // Check if it already exists.
        match self
            .client
            .head_object()
            .bucket(&self.bucket)
            .key(&key)
            .send()
            .await
        {
            Ok(_) => return Ok(()),
            Err(_) => {}
        }

        let content = format!(
            "StoreDir: {store_dir}\nWantMassQuery: 1\nPriority: 40\n"
        );
        self.client
            .put_object()
            .bucket(&self.bucket)
            .key(&key)
            .content_type("text/plain")
            .body(content.into_bytes().into())
            .send()
            .await
            .context("writing nix-cache-info to S3")?;
        Ok(())
    }
}
