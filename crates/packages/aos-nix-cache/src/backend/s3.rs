//! S3 (`s3://`) cache backend.
//!
//! Conditional writes map onto `PutObject` with `If-Match` /
//! `If-None-Match: *`, so the service evaluates the precondition atomically.
//! Object versions are `ETag`s; see [`super::conditional`].
//!
//! Native AWS immutable multipart uploads resume accepted parts and apply the
//! destination condition at completion. Custom S3 endpoints, including R2,
//! use a streamed conditional PutObject up to 5 GiB: repeat runs reuse verified
//! complete objects, while an interrupted single request restarts its bytes.
//! Larger conditional objects fail until that provider has verified atomic
//! multipart completion support. Provider guarantees are documented in
//! [AWS conditional writes](https://docs.aws.amazon.com/AmazonS3/latest/userguide/conditional-writes.html)
//! and [R2 S3 compatibility](https://developers.cloudflare.com/r2/api/s3/api/).

use std::io::Write as _;
use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;

use aos_transfer::protocol::conditional::ETAG;
use aos_transfer::{TransferEngine, TransferRequest};

use super::conditional::{
    ConditionalResponse, read_small_object, send_conditional_put, validate_relative_path,
};
use super::{
    CacheBackend, ConditionalOutcome, Expectation, IMMUTABLE_CACHE_CONTROL, MUTABLE_CACHE_CONTROL,
    ObjectVersion, add_static_metadata_headers,
};

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
    /// Creates a backend for `bucket` with an optional key `prefix`
    /// (leading/trailing slashes are trimmed; empty means the bucket
    /// root).
    pub fn new(bucket: &str, prefix: &str, engine: &Arc<TransferEngine>) -> Self {
        Self {
            engine: Arc::clone(engine),
            bucket: bucket.to_string(),
            prefix: prefix.trim_matches('/').to_string(),
        }
    }

    /// Builds an `s3://bucket[/prefix]/path` URL for a cache-relative
    /// path.
    fn s3_url(&self, path: &str) -> String {
        if self.prefix.is_empty() {
            format!("s3://{}/{}", self.bucket, path)
        } else {
            format!("s3://{}/{}/{}", self.bucket, self.prefix, path)
        }
    }

    /// Returns the current `ETag` of the object at `url`, or `None` when it
    /// does not exist.
    async fn current_version(&self, url: &str) -> Result<Option<ObjectVersion>> {
        let head = self
            .engine
            .head(url)
            .await
            .with_context(|| format!("S3 HeadObject {url}"))?;
        if head.status == 404 {
            return Ok(None);
        }

        let etag = head
            .header(ETAG)
            .with_context(|| format!("S3 HeadObject {url} returned no ETag"))?;
        Ok(Some(ObjectVersion(etag.to_string())))
    }
}

#[async_trait]
impl CacheBackend for S3Backend {
    fn transfer_manager(&self) -> Option<&TransferEngine> {
        Some(self.engine.as_ref())
    }

    async fn exists(&self, relative_path: &str) -> Result<bool> {
        let url = self.s3_url(relative_path.trim_start_matches('/'));
        let result = self.engine.head(&url).await?;
        Ok(result.status != 404)
    }

    async fn static_file_identity(
        &self,
        relative_path: &str,
    ) -> Result<Option<super::StaticFileIdentity>> {
        validate_relative_path(relative_path)?;
        let url = self.s3_url(relative_path);
        if self.engine.head(&url).await?.status == 404 {
            return Ok(None);
        }
        let snapshot = tempfile::NamedTempFile::new()?;
        self.engine
            .execute(TransferRequest::get_to_file(
                &url,
                snapshot.path().to_path_buf(),
            ))
            .await?;
        let (byte_size, sha256) = crate::upload_resume::source_identity(
            &aos_transfer::MultipartSource::File(snapshot.path().to_path_buf()),
        )?;
        Ok(Some(super::StaticFileIdentity { byte_size, sha256 }))
    }

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
        // narinfos are rewritten in place (e.g. re-signed on key rotation), so
        // they must stay revalidatable rather than be cached as immutable.
        add_static_metadata_headers(
            &mut req,
            Some("text/x-nix-narinfo"),
            Some(MUTABLE_CACHE_CONTROL),
            None,
            None,
        );
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
        // A rewindable file source lets the shared S3 transport select its
        // bounded multipart path for large NARs and retry safely without
        // cloning the complete payload for each attempt.
        let mut spool = tempfile::NamedTempFile::new().context("creating S3 upload spool")?;
        spool.write_all(data).context("writing S3 upload spool")?;
        spool.flush().context("flushing S3 upload spool")?;
        let mut req = TransferRequest::put_file(&url, spool.path().to_path_buf());
        // NAR archives are content-addressed by the hash embedded in their
        // filename, so the bytes behind a URL never change: cache immutably.
        add_static_metadata_headers(
            &mut req,
            Some("application/x-nix-nar"),
            Some(IMMUTABLE_CACHE_CONTROL),
            None,
            None,
        );
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
        // The cache marker is rewritten in place (e.g. Priority changes), so
        // keep it revalidatable rather than long-lived.
        add_static_metadata_headers(
            &mut req,
            Some("text/plain"),
            Some(MUTABLE_CACHE_CONTROL),
            None,
            None,
        );
        self.engine
            .execute(req)
            .await
            .context("writing nix-cache-info to S3")?;
        Ok(())
    }

    async fn put_cache_info(&self, content: &str) -> Result<()> {
        let url = self.s3_url("nix-cache-info");
        let mut req = TransferRequest::put(&url, content.as_bytes().to_vec());
        add_static_metadata_headers(
            &mut req,
            Some("text/plain"),
            Some(MUTABLE_CACHE_CONTROL),
            None,
            None,
        );
        self.engine
            .execute(req)
            .await
            .context("writing nix-cache-info to S3")?;
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
        let url = self.s3_url(relative_path);
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
            .with_context(|| format!("S3 PutObject {url}"))?;
        Ok(())
    }

    async fn get_static_object(
        &self,
        relative_path: &str,
        max_bytes: usize,
    ) -> Result<Option<(Vec<u8>, ObjectVersion)>> {
        validate_relative_path(relative_path)?;
        let url = self.s3_url(relative_path);

        let Some(object) = read_small_object(&self.engine, &url, max_bytes).await? else {
            return Ok(None);
        };
        let etag = object
            .etag
            .with_context(|| format!("S3 GetObject {url} returned no ETag"))?;
        Ok(Some((object.bytes, ObjectVersion(etag))))
    }

    async fn put_static_file_conditional(
        &self,
        relative_path: &str,
        source: &std::path::Path,
        content_type: Option<&str>,
        cache_control: Option<&str>,
        expect: Expectation,
    ) -> Result<ConditionalOutcome> {
        validate_relative_path(relative_path)?;
        let url = self.s3_url(relative_path);

        let response = send_conditional_put(
            &self.engine,
            &url,
            source,
            content_type,
            cache_control,
            &expect,
        )
        .await?;

        match response {
            ConditionalResponse::Written(Some(etag)) => {
                Ok(ConditionalOutcome::Written(ObjectVersion(etag)))
            }
            // The write is durable, but without its version the caller
            // cannot chain the next compare-and-swap; fail closed.
            ConditionalResponse::Written(None) => {
                anyhow::bail!("S3 PutObject {url} committed but returned no ETag")
            }
            // S3 does not report the current ETag with a 412, so re-read it.
            // It may change again before the caller acts; the caller's next
            // conditional write detects that.
            ConditionalResponse::Refused(_) => Ok(ConditionalOutcome::PreconditionFailed {
                current: self.current_version(&url).await?,
            }),
        }
    }
}
