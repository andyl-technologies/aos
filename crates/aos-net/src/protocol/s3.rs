//! S3 / S3-compatible protocol implementation.
//!
//! Uses `aws-sdk-s3` for S3 operations. Supports:
//! - GetObject, PutObject, HeadObject, DeleteObject
//! - Multi-part upload (CreateMultipartUpload, UploadPart, CompleteMultipartUpload)
//! - Custom endpoints (MinIO, B2, Wasabi)

use anyhow::{Context, Result};
use async_trait::async_trait;

use super::Protocol;
use crate::auth::Credential;
use crate::types::{Method, TransferBody, TransferOutput, TransferRequest, TransferResult};

/// Default threshold for multi-part uploads (5 MB).
const MULTIPART_THRESHOLD: u64 = 5 * 1024 * 1024;

/// Default part size for multi-part uploads (5 MB).
const MULTIPART_PART_SIZE: u64 = 5 * 1024 * 1024;

/// S3 protocol handler.
pub struct S3Protocol {
    part_size: u64,
}

impl S3Protocol {
    /// Create a new S3 protocol handler.
    pub fn new() -> Self {
        Self {
            part_size: MULTIPART_PART_SIZE,
        }
    }

    /// Create a new S3 protocol handler with a custom part size.
    pub fn with_part_size(part_size: u64) -> Self {
        Self { part_size }
    }

    /// Build an S3 client from credentials.
    async fn build_client(&self, auth: Option<&Credential>) -> Result<aws_sdk_s3::Client> {
        let mut config_loader = aws_config::defaults(aws_config::BehaviorVersion::latest());

        if let Some(Credential::AwsSigV4 {
            ref region,
            ref profile,
            ref endpoint,
        }) = auth
        {
            config_loader = config_loader.region(aws_config::Region::new(region.clone()));
            if let Some(ref p) = profile {
                config_loader = config_loader.profile_name(p);
            }
            let config = config_loader.load().await;
            let mut s3_config = aws_sdk_s3::config::Builder::from(&config);
            if let Some(ref ep) = endpoint {
                s3_config = s3_config.endpoint_url(ep).force_path_style(true);
            }
            Ok(aws_sdk_s3::Client::from_conf(s3_config.build()))
        } else {
            let config = config_loader.load().await;
            Ok(aws_sdk_s3::Client::new(&config))
        }
    }

    /// Parse an S3 URL into (bucket, key).
    ///
    /// Format: `s3://bucket/key/path`
    fn parse_url(url: &str) -> Result<(String, String)> {
        let parsed = url::Url::parse(url)
            .with_context(|| format!("invalid S3 URL: {url}"))?;

        let bucket = parsed
            .host_str()
            .ok_or_else(|| anyhow::anyhow!("S3 URL must have bucket as host: {url}"))?
            .to_string();

        let key = parsed.path().trim_start_matches('/').to_string();
        if key.is_empty() {
            anyhow::bail!("S3 URL must have a key path: {url}");
        }

        Ok((bucket, key))
    }

    async fn do_get(
        &self,
        request: &TransferRequest,
        auth: Option<&Credential>,
    ) -> Result<TransferResult> {
        let client = self.build_client(auth).await?;
        let (bucket, key) = Self::parse_url(&request.url)?;

        let mut get_builder = client.get_object().bucket(&bucket).key(&key);

        // Handle resume with Range header.
        let mut resumed = false;
        let mut resume_offset: u64 = 0;

        if request.resume {
            if let TransferOutput::File(ref path) = request.output {
                if let Ok(metadata) = tokio::fs::metadata(path).await {
                    let existing_size = metadata.len();
                    if existing_size > 0 {
                        get_builder =
                            get_builder.range(format!("bytes={}-", existing_size));
                        resume_offset = existing_size;
                        resumed = true;
                    }
                }
            }
        }

        let resp = get_builder
            .send()
            .await
            .with_context(|| format!("S3 GetObject {bucket}/{key}"))?;

        let content_length = resp.content_length().map(|l| l as u64);
        let body_bytes = resp
            .body
            .collect()
            .await
            .context("reading S3 object body")?
            .to_vec();

        let bytes_transferred = body_bytes.len() as u64 + resume_offset;

        match &request.output {
            TransferOutput::Memory => Ok(TransferResult {
                status: 200,
                headers: Vec::new(),
                bytes_transferred,
                content_length,
                body: Some(body_bytes),
                hash: None,
                resumed,
            }),
            TransferOutput::File(path) => {
                use tokio::io::AsyncWriteExt;

                if let Some(parent) = path.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }

                if resumed {
                    let mut file = tokio::fs::OpenOptions::new()
                        .append(true)
                        .open(path)
                        .await?;
                    file.write_all(&body_bytes).await?;
                    file.flush().await?;
                } else {
                    tokio::fs::write(path, &body_bytes).await?;
                }

                Ok(TransferResult {
                    status: 200,
                    headers: Vec::new(),
                    bytes_transferred,
                    content_length,
                    body: None,
                    hash: None,
                    resumed,
                })
            }
            TransferOutput::Callback(_) => Ok(TransferResult {
                status: 200,
                headers: Vec::new(),
                bytes_transferred,
                content_length,
                body: Some(body_bytes),
                hash: None,
                resumed,
            }),
        }
    }

    async fn do_put(
        &self,
        request: &TransferRequest,
        auth: Option<&Credential>,
    ) -> Result<TransferResult> {
        let client = self.build_client(auth).await?;
        let (bucket, key) = Self::parse_url(&request.url)?;

        let data = match &request.body {
            Some(TransferBody::Bytes(b)) => b.clone(),
            Some(TransferBody::File(path)) => {
                tokio::fs::read(path)
                    .await
                    .with_context(|| format!("reading {}", path.display()))?
            }
            Some(TransferBody::Stream(_)) => {
                anyhow::bail!("stream body not directly supported for S3 put");
            }
            None => Vec::new(),
        };

        let data_len = data.len() as u64;

        // Use multi-part upload for large files.
        if data_len > MULTIPART_THRESHOLD {
            self.do_multipart_upload(&client, &bucket, &key, &data)
                .await?;
        } else {
            client
                .put_object()
                .bucket(&bucket)
                .key(&key)
                .body(data.into())
                .send()
                .await
                .with_context(|| format!("S3 PutObject {bucket}/{key}"))?;
        }

        Ok(TransferResult {
            status: 200,
            headers: Vec::new(),
            bytes_transferred: data_len,
            content_length: Some(data_len),
            body: None,
            hash: None,
            resumed: false,
        })
    }

    async fn do_head(
        &self,
        request: &TransferRequest,
        auth: Option<&Credential>,
    ) -> Result<TransferResult> {
        let client = self.build_client(auth).await?;
        let (bucket, key) = Self::parse_url(&request.url)?;

        let resp = client
            .head_object()
            .bucket(&bucket)
            .key(&key)
            .send()
            .await;

        match resp {
            Ok(output) => {
                let content_length = output.content_length().map(|l| l as u64);
                Ok(TransferResult {
                    status: 200,
                    headers: Vec::new(),
                    bytes_transferred: 0,
                    content_length,
                    body: None,
                    hash: None,
                    resumed: false,
                })
            }
            Err(e) => {
                let svc = e.into_service_error();
                if svc.is_not_found() {
                    Ok(TransferResult {
                        status: 404,
                        headers: Vec::new(),
                        bytes_transferred: 0,
                        content_length: None,
                        body: None,
                        hash: None,
                        resumed: false,
                    })
                } else {
                    Err(anyhow::anyhow!("S3 HeadObject failed: {svc}"))
                }
            }
        }
    }

    async fn do_delete(
        &self,
        request: &TransferRequest,
        auth: Option<&Credential>,
    ) -> Result<TransferResult> {
        let client = self.build_client(auth).await?;
        let (bucket, key) = Self::parse_url(&request.url)?;

        client
            .delete_object()
            .bucket(&bucket)
            .key(&key)
            .send()
            .await
            .with_context(|| format!("S3 DeleteObject {bucket}/{key}"))?;

        Ok(TransferResult {
            status: 204,
            headers: Vec::new(),
            bytes_transferred: 0,
            content_length: None,
            body: None,
            hash: None,
            resumed: false,
        })
    }

    /// Perform a multi-part upload.
    async fn do_multipart_upload(
        &self,
        client: &aws_sdk_s3::Client,
        bucket: &str,
        key: &str,
        data: &[u8],
    ) -> Result<()> {
        // 1. Create multipart upload.
        let create_resp = client
            .create_multipart_upload()
            .bucket(bucket)
            .key(key)
            .send()
            .await
            .context("S3 CreateMultipartUpload")?;

        let upload_id = create_resp
            .upload_id()
            .ok_or_else(|| anyhow::anyhow!("no upload_id returned"))?
            .to_string();

        // 2. Upload parts.
        let mut parts = Vec::new();
        let mut offset: usize = 0;
        let mut part_number: i32 = 1;

        while offset < data.len() {
            let end = (offset + self.part_size as usize).min(data.len());
            let chunk = &data[offset..end];

            let upload_resp = client
                .upload_part()
                .bucket(bucket)
                .key(key)
                .upload_id(&upload_id)
                .part_number(part_number)
                .body(chunk.to_vec().into())
                .send()
                .await
                .with_context(|| {
                    format!("S3 UploadPart {bucket}/{key} part {part_number}")
                })?;

            let etag = upload_resp
                .e_tag()
                .ok_or_else(|| anyhow::anyhow!("no ETag for part {part_number}"))?
                .to_string();

            parts.push(
                aws_sdk_s3::types::CompletedPart::builder()
                    .part_number(part_number)
                    .e_tag(etag)
                    .build(),
            );

            offset = end;
            part_number += 1;
        }

        // 3. Complete multipart upload.
        let completed = aws_sdk_s3::types::CompletedMultipartUpload::builder()
            .set_parts(Some(parts))
            .build();

        client
            .complete_multipart_upload()
            .bucket(bucket)
            .key(key)
            .upload_id(&upload_id)
            .multipart_upload(completed)
            .send()
            .await
            .context("S3 CompleteMultipartUpload")?;

        Ok(())
    }
}

impl Default for S3Protocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for S3Protocol {
    async fn execute(
        &self,
        request: &TransferRequest,
        auth: Option<&Credential>,
    ) -> Result<TransferResult> {
        match request.method {
            Method::Get => self.do_get(request, auth).await,
            Method::Put => self.do_put(request, auth).await,
            Method::Head => self.do_head(request, auth).await,
            Method::Delete => self.do_delete(request, auth).await,
        }
    }

    fn supports_resume(&self) -> bool {
        true
    }

    fn supports_multipart(&self) -> bool {
        true
    }

    fn multipart_threshold(&self) -> Option<u64> {
        Some(MULTIPART_THRESHOLD)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_url() {
        let (bucket, key) = S3Protocol::parse_url("s3://my-bucket/path/to/file.tar.gz").unwrap();
        assert_eq!(bucket, "my-bucket");
        assert_eq!(key, "path/to/file.tar.gz");
    }

    #[test]
    fn test_parse_url_root_key() {
        let (bucket, key) = S3Protocol::parse_url("s3://my-bucket/file.txt").unwrap();
        assert_eq!(bucket, "my-bucket");
        assert_eq!(key, "file.txt");
    }

    #[test]
    fn test_parse_url_no_key() {
        assert!(S3Protocol::parse_url("s3://my-bucket/").is_err());
    }

    #[test]
    fn test_parse_url_invalid() {
        assert!(S3Protocol::parse_url("not-a-url").is_err());
    }

    #[test]
    fn test_multipart_threshold() {
        let proto = S3Protocol::new();
        assert_eq!(proto.multipart_threshold(), Some(5 * 1024 * 1024));
    }
}
