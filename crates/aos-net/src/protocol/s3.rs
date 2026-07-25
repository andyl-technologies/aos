//! S3 / S3-compatible protocol implementation.
//!
//! Uses `aws-sdk-s3` for S3 operations. Supports:
//! - GetObject with streaming body (no full-buffer)
//! - PutObject with streaming / multi-part from file (chunked reads, no full-buffer)
//! - HeadObject, DeleteObject
//! - Custom endpoints (MinIO, B2, Wasabi)

use std::collections::BTreeMap;
use std::sync::Mutex;

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_s3::operation::head_object::HeadObjectError;
use bytes::Bytes;
use tokio::io::AsyncReadExt;

use super::{ByteStream, Protocol};
use crate::auth::Credential;
use crate::types::{Method, TransferBody, TransferOutput, TransferRequest, TransferResult};

/// Default threshold for multi-part uploads (5 MB).
const MULTIPART_THRESHOLD: u64 = 5 * 1024 * 1024;

/// Default part size for multi-part uploads (5 MB).
const MULTIPART_PART_SIZE: u64 = 5 * 1024 * 1024;

/// Describes where an S3 request is sent, for diagnostics.
///
/// A `None` endpoint means the request targets real AWS S3, which is the
/// usual cause of a surprising `403` when the credentials belong to an
/// S3-compatible store (Cloudflare R2, MinIO): naming the endpoint in an
/// error turns a misrouted request into an obvious fix.
fn s3_target(auth: Option<&Credential>) -> String {
    match auth {
        Some(Credential::AwsSigV4 {
            region, endpoint, ..
        }) => match endpoint {
            Some(endpoint) => format!("endpoint {endpoint} (region {region})"),
            None => format!("the default AWS S3 endpoint (region {region})"),
        },
        _ => "the default AWS credential chain endpoint".to_string(),
    }
}

/// Builds an actionable error for a failed S3 `operation` on `location`
/// (`bucket/key`) sent to `target` (see [`s3_target`]).
///
/// S3-compatible stores answer some requests — notably `HEAD`, which carries
/// no body — with a status the SDK cannot map to a modeled error, leaving the
/// opaque `Unhandled` variant whose `Display` is just `"unhandled error"`.
/// When a response reached us, this names the HTTP status, error code,
/// message, and request id off it; otherwise (a transport, timeout, or
/// construction failure with no response) it preserves the SDK error's own
/// message as the source so detail like a DNS or connection failure survives.
fn s3_operation_error<E>(
    operation: &str,
    location: &str,
    target: &str,
    err: SdkError<E>,
) -> anyhow::Error
where
    E: ProvideErrorMetadata + std::error::Error + Send + Sync + 'static,
{
    if let Some(response) = err.raw_response() {
        let status = response.status().as_u16();
        let request_id = response
            .headers()
            .get("x-amz-request-id")
            .or_else(|| response.headers().get("cf-ray"))
            .unwrap_or("none");
        anyhow::anyhow!(
            "S3 {operation} for {location} against {target} failed: HTTP status {status}, \
             error code {code}, message {message:?}, request id {request_id}",
            code = err.code().unwrap_or("none"),
            message = err.message().unwrap_or("none"),
        )
    } else {
        anyhow::Error::new(err)
            .context(format!("S3 {operation} for {location} against {target}"))
    }
}

/// Resolved [`Credential::AwsSigV4`] configuration that distinguishes one
/// cached S3 client from another.
///
/// Used as `Option<S3ClientConfig>`: `None` is the SDK default credential
/// chain, `Some(_)` an explicit SigV4 configuration. Two requests with an
/// equal key share one [`aws_sdk_s3::Client`].
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
struct S3ClientConfig {
    /// AWS region used for signing.
    region: String,
    /// Optional named AWS profile to load credentials from.
    profile: Option<String>,
    /// Optional custom endpoint URL for S3-compatible services.
    endpoint: Option<String>,
}

/// S3 protocol handler.
///
/// URLs use the `s3://bucket/key` form. SigV4 signing is delegated to
/// the AWS SDK; supply a [`Credential::AwsSigV4`] to control region,
/// profile, and endpoint, otherwise the SDK's default credential chain
/// (environment, profile, IMDS) is used. File uploads larger than
/// 5 MB automatically use multi-part upload.
///
/// Built clients are cached by configuration so the credential chain is
/// resolved once per distinct `(region, profile, endpoint)` rather than
/// on every request.
pub struct S3Protocol {
    /// Part size for multi-part uploads, in bytes.
    part_size: u64,
    /// Clients cached by their resolved configuration.
    clients: Mutex<BTreeMap<Option<S3ClientConfig>, aws_sdk_s3::Client>>,
}

impl S3Protocol {
    /// Create a new S3 protocol handler.
    pub fn new() -> Self {
        Self {
            part_size: MULTIPART_PART_SIZE,
            clients: Mutex::new(BTreeMap::new()),
        }
    }

    /// Create a new S3 protocol handler with a custom part size
    /// (in bytes) for multi-part uploads.
    pub fn with_part_size(part_size: u64) -> Self {
        Self {
            part_size,
            clients: Mutex::new(BTreeMap::new()),
        }
    }

    /// Returns an S3 client for the given credentials, building and
    /// caching one on first use for each distinct configuration.
    ///
    /// With a [`Credential::AwsSigV4`], the region (and optionally a
    /// named profile) configure the SDK loader, and a custom endpoint
    /// switches the client to path-style addressing for S3-compatible
    /// services. Without credentials, the SDK default chain is used.
    /// Subsequent calls with the same `(region, profile, endpoint)`
    /// reuse the cached client (a cheap `Arc` clone) instead of
    /// re-running the credential chain.
    async fn build_client(&self, auth: Option<&Credential>) -> Result<aws_sdk_s3::Client> {
        let key = match auth {
            Some(Credential::AwsSigV4 {
                region,
                profile,
                endpoint,
            }) => Some(S3ClientConfig {
                region: region.clone(),
                profile: profile.clone(),
                endpoint: endpoint.clone(),
            }),
            _ => None,
        };

        // A poisoned cache lock is harmless here (the map holds only
        // clonable clients), so recover the guard rather than panicking.
        if let Some(client) = self
            .clients
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .get(&key)
            .cloned()
        {
            return Ok(client);
        }

        // Build outside the lock: the credential chain resolution is
        // async and must not be held across the std Mutex. A benign
        // race may build the same client twice; the last insert wins.
        let client = self.build_client_uncached(auth).await?;
        self.clients
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(key, client.clone());
        Ok(client)
    }

    /// Builds a fresh S3 client, resolving the credential chain. Callers
    /// should prefer [`build_client`](Self::build_client), which caches.
    async fn build_client_uncached(&self, auth: Option<&Credential>) -> Result<aws_sdk_s3::Client> {
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
    /// Format: `s3://bucket/key/path`. Fails if the URL is malformed,
    /// has no bucket, or has an empty key.
    fn parse_url(url: &str) -> Result<(String, String)> {
        let parsed = url::Url::parse(url).with_context(|| format!("invalid S3 URL: {url}"))?;

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

    /// Buffering GetObject: reads the body in 64KB chunks into the
    /// request's output (memory, file with optional ranged resume, or
    /// callback).
    async fn do_get(
        &self,
        request: &TransferRequest,
        auth: Option<&Credential>,
    ) -> Result<TransferResult> {
        let client = self.build_client(auth).await?;
        let (bucket, key) = Self::parse_url(&request.url)?;
        let target = s3_target(auth);

        let mut get_builder = client.get_object().bucket(&bucket).key(&key);

        let mut resumed = false;
        let mut resume_offset: u64 = 0;

        if request.resume {
            if let TransferOutput::File(ref path) = request.output {
                if let Ok(metadata) = tokio::fs::metadata(path).await {
                    let existing_size = metadata.len();
                    if existing_size > 0 {
                        get_builder = get_builder.range(format!("bytes={}-", existing_size));
                        resume_offset = existing_size;
                        resumed = true;
                    }
                }
            }
        }

        let resp = get_builder
            .send()
            .await
            .map_err(|e| s3_operation_error("GetObject", &format!("{bucket}/{key}"), &target, e))?;

        let content_length = resp.content_length().map(|l| l as u64);

        // Stream the body in chunks via the SDK's async reader.
        let mut body_reader = resp.body.into_async_read();

        match &request.output {
            TransferOutput::Memory => {
                let mut buf = Vec::new();
                body_reader
                    .read_to_end(&mut buf)
                    .await
                    .context("reading S3 object body")?;
                let bytes_transferred = buf.len() as u64 + resume_offset;

                Ok(TransferResult {
                    status: 200,
                    headers: Vec::new(),
                    bytes_transferred,
                    content_length,
                    body: Some(buf),
                    hash: None,
                    resumed,
                })
            }
            TransferOutput::File(path) => {
                use tokio::io::AsyncWriteExt;

                if let Some(parent) = path.parent() {
                    tokio::fs::create_dir_all(parent).await?;
                }

                let mut file = if resumed {
                    tokio::fs::OpenOptions::new()
                        .append(true)
                        .open(path)
                        .await?
                } else {
                    tokio::fs::File::create(path).await?
                };

                let mut bytes_written: u64 = 0;
                let mut chunk_buf = vec![0u8; 64 * 1024]; // 64KB chunks

                loop {
                    let n = body_reader
                        .read(&mut chunk_buf)
                        .await
                        .context("reading S3 object chunk")?;
                    if n == 0 {
                        break;
                    }
                    file.write_all(&chunk_buf[..n]).await?;
                    bytes_written += n as u64;
                }

                file.flush().await?;

                Ok(TransferResult {
                    status: 200,
                    headers: Vec::new(),
                    bytes_transferred: bytes_written + resume_offset,
                    content_length,
                    body: None,
                    hash: None,
                    resumed,
                })
            }
            TransferOutput::Callback(ref cb) => {
                let mut bytes_transferred: u64 = 0;
                let mut chunk_buf = vec![0u8; 64 * 1024];

                loop {
                    let n = body_reader
                        .read(&mut chunk_buf)
                        .await
                        .context("reading S3 object chunk")?;
                    if n == 0 {
                        break;
                    }
                    cb(&chunk_buf[..n])?;
                    bytes_transferred += n as u64;
                }

                Ok(TransferResult {
                    status: 200,
                    headers: Vec::new(),
                    bytes_transferred: bytes_transferred + resume_offset,
                    content_length,
                    body: None,
                    hash: None,
                    resumed,
                })
            }
        }
    }

    /// Streaming GET -- returns metadata + byte stream.
    async fn do_get_stream(
        &self,
        request: &TransferRequest,
        auth: Option<&Credential>,
    ) -> Result<(TransferResult, ByteStream)> {
        let client = self.build_client(auth).await?;
        let (bucket, key) = Self::parse_url(&request.url)?;
        let target = s3_target(auth);

        let mut get_builder = client.get_object().bucket(&bucket).key(&key);

        let mut resumed = false;
        let mut resume_offset: u64 = 0;

        if request.resume {
            if let TransferOutput::File(ref path) = request.output {
                if let Ok(metadata) = tokio::fs::metadata(path).await {
                    let existing_size = metadata.len();
                    if existing_size > 0 {
                        get_builder = get_builder.range(format!("bytes={}-", existing_size));
                        resume_offset = existing_size;
                        resumed = true;
                    }
                }
            }
        }

        let resp = get_builder
            .send()
            .await
            .map_err(|e| s3_operation_error("GetObject", &format!("{bucket}/{key}"), &target, e))?;

        let content_length = resp.content_length().map(|l| l as u64);

        let result = TransferResult {
            status: 200,
            headers: Vec::new(),
            bytes_transferred: resume_offset,
            content_length,
            body: None,
            hash: None,
            resumed,
        };

        // Convert SDK byte stream into our ByteStream.
        let body_stream = resp.body;
        let stream: ByteStream = Box::pin(futures_util::stream::unfold(
            body_stream.into_async_read(),
            |mut reader| async move {
                let mut buf = vec![0u8; 64 * 1024];
                match reader.read(&mut buf).await {
                    Ok(0) => None,
                    Ok(n) => {
                        buf.truncate(n);
                        Some((Ok(Bytes::from(buf)), reader))
                    }
                    Err(e) => Some((Err(anyhow::anyhow!("reading S3 object chunk: {e}")), reader)),
                }
            },
        ));

        Ok((result, stream))
    }

    /// PutObject upload. File bodies above the 5 MB threshold use
    /// multi-part upload; smaller files and byte bodies upload in one
    /// shot. Stream bodies are rejected on this path.
    async fn do_put(
        &self,
        request: &TransferRequest,
        auth: Option<&Credential>,
    ) -> Result<TransferResult> {
        let client = self.build_client(auth).await?;
        let (bucket, key) = Self::parse_url(&request.url)?;
        let target = s3_target(auth);

        match &request.body {
            Some(TransferBody::File(path)) => {
                let metadata = tokio::fs::metadata(path)
                    .await
                    .with_context(|| format!("stat {}", path.display()))?;
                let file_len = metadata.len();

                if file_len > MULTIPART_THRESHOLD {
                    self.do_multipart_upload_from_file(
                        &client,
                        &bucket,
                        &key,
                        &target,
                        path,
                        file_len,
                        &request.headers,
                    )
                    .await?;
                } else {
                    // Small file: read and upload in one shot.
                    let data = tokio::fs::read(path)
                        .await
                        .with_context(|| format!("reading {}", path.display()))?;
                    let put = client
                        .put_object()
                        .bucket(&bucket)
                        .key(&key)
                        .body(data.into());
                    let put = apply_put_object_headers(put, &request.headers);
                    put.send().await.map_err(|e| {
                        s3_operation_error("PutObject", &format!("{bucket}/{key}"), &target, e)
                    })?;
                }

                Ok(TransferResult {
                    status: 200,
                    headers: Vec::new(),
                    bytes_transferred: file_len,
                    content_length: Some(file_len),
                    body: None,
                    hash: None,
                    resumed: false,
                })
            }
            Some(TransferBody::Bytes(data)) => {
                let data_len = data.len() as u64;
                let put = client
                    .put_object()
                    .bucket(&bucket)
                    .key(&key)
                    .body(data.clone().into());
                let put = apply_put_object_headers(put, &request.headers);
                put.send().await.map_err(|e| {
                    s3_operation_error("PutObject", &format!("{bucket}/{key}"), &target, e)
                })?;

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
            Some(TransferBody::Stream(_)) => {
                anyhow::bail!("stream body not directly supported for S3 put via Protocol::execute(); use TransferEngine");
            }
            None => {
                let put = client
                    .put_object()
                    .bucket(&bucket)
                    .key(&key)
                    .body(Vec::new().into());
                let put = apply_put_object_headers(put, &request.headers);
                put.send().await.map_err(|e| {
                    s3_operation_error("PutObject", &format!("{bucket}/{key}"), &target, e)
                })?;

                Ok(TransferResult {
                    status: 200,
                    headers: Vec::new(),
                    bytes_transferred: 0,
                    content_length: Some(0),
                    body: None,
                    hash: None,
                    resumed: false,
                })
            }
        }
    }

    /// HeadObject: returns a 200 result with the object size, or a
    /// 404 result (not an error) when the object does not exist.
    async fn do_head(
        &self,
        request: &TransferRequest,
        auth: Option<&Credential>,
    ) -> Result<TransferResult> {
        let client = self.build_client(auth).await?;
        let (bucket, key) = Self::parse_url(&request.url)?;
        let target = s3_target(auth);

        let resp = client.head_object().bucket(&bucket).key(&key).send().await;

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
                // A missing object is reported as absent, not an error. S3
                // returns a modeled `NotFound`; an S3-compatible store that
                // answers a HEAD with an empty body leaves the SDK only the
                // raw `404` status to go on, so accept either signal.
                let is_404 = e.as_service_error().is_some_and(HeadObjectError::is_not_found)
                    || e.raw_response().map(|r| r.status().as_u16()) == Some(404);
                if is_404 {
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
                    Err(s3_operation_error(
                        "HeadObject",
                        &format!("{bucket}/{key}"),
                        &target,
                        e,
                    ))
                }
            }
        }
    }

    /// DeleteObject: returns a 204 result on success.
    async fn do_delete(
        &self,
        request: &TransferRequest,
        auth: Option<&Credential>,
    ) -> Result<TransferResult> {
        let client = self.build_client(auth).await?;
        let (bucket, key) = Self::parse_url(&request.url)?;
        let target = s3_target(auth);

        client
            .delete_object()
            .bucket(&bucket)
            .key(&key)
            .send()
            .await
            .map_err(|e| s3_operation_error("DeleteObject", &format!("{bucket}/{key}"), &target, e))?;

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

    /// Multi-part upload reading from a file in chunks (no full-buffer).
    ///
    /// Runs CreateMultipartUpload, uploads `part_size`-byte parts
    /// sequentially while collecting their ETags, then
    /// CompleteMultipartUpload. An aborted upload is not cleaned up
    /// here; orphaned parts are left for a bucket lifecycle rule.
    async fn do_multipart_upload_from_file(
        &self,
        client: &aws_sdk_s3::Client,
        bucket: &str,
        key: &str,
        target: &str,
        path: &std::path::Path,
        file_len: u64,
        headers: &[(String, String)],
    ) -> Result<()> {
        let location = format!("{bucket}/{key}");
        let create = client.create_multipart_upload().bucket(bucket).key(key);
        let create = apply_create_multipart_headers(create, headers);
        let create_resp = create
            .send()
            .await
            .map_err(|e| s3_operation_error("CreateMultipartUpload", &location, target, e))?;

        let upload_id = create_resp
            .upload_id()
            .ok_or_else(|| anyhow::anyhow!("no upload_id returned"))?
            .to_string();

        let mut file = tokio::fs::File::open(path)
            .await
            .with_context(|| format!("opening {} for multipart upload", path.display()))?;

        let mut parts = Vec::new();
        let mut part_number: i32 = 1;
        let mut offset: u64 = 0;

        while offset < file_len {
            let chunk_size = ((file_len - offset) as usize).min(self.part_size as usize);
            let mut chunk = vec![0u8; chunk_size];
            file.read_exact(&mut chunk)
                .await
                .with_context(|| format!("reading part {} from {}", part_number, path.display()))?;

            let upload_resp = client
                .upload_part()
                .bucket(bucket)
                .key(key)
                .upload_id(&upload_id)
                .part_number(part_number)
                .body(chunk.into())
                .send()
                .await
                .map_err(|e| {
                    s3_operation_error(
                        &format!("UploadPart (part {part_number})"),
                        &location,
                        target,
                        e,
                    )
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

            offset += chunk_size as u64;
            part_number += 1;
        }

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
            .map_err(|e| s3_operation_error("CompleteMultipartUpload", &location, target, e))?;

        Ok(())
    }
}

/// Map recognized HTTP-style request headers (`Content-Type`,
/// `Cache-Control`) onto PutObject builder fields; other headers are
/// ignored because S3 models them as typed parameters, not headers.
fn apply_put_object_headers(
    mut builder: aws_sdk_s3::operation::put_object::builders::PutObjectFluentBuilder,
    headers: &[(String, String)],
) -> aws_sdk_s3::operation::put_object::builders::PutObjectFluentBuilder {
    for (name, value) in headers {
        match name.to_ascii_lowercase().as_str() {
            "content-type" => {
                builder = builder.content_type(value);
            }
            "cache-control" => {
                builder = builder.cache_control(value);
            }
            _ => {}
        }
    }
    builder
}

/// Same header mapping as [`apply_put_object_headers`], for the
/// CreateMultipartUpload builder.
fn apply_create_multipart_headers(
    mut builder: aws_sdk_s3::operation::create_multipart_upload::builders::CreateMultipartUploadFluentBuilder,
    headers: &[(String, String)],
) -> aws_sdk_s3::operation::create_multipart_upload::builders::CreateMultipartUploadFluentBuilder {
    for (name, value) in headers {
        match name.to_ascii_lowercase().as_str() {
            "content-type" => {
                builder = builder.content_type(value);
            }
            "cache-control" => {
                builder = builder.cache_control(value);
            }
            _ => {}
        }
    }
    builder
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
            Method::Post => anyhow::bail!("POST is not supported by the s3:// protocol"),
        }
    }

    async fn stream(
        &self,
        request: &TransferRequest,
        auth: Option<&Credential>,
    ) -> Result<(TransferResult, ByteStream)> {
        match request.method {
            Method::Get => self.do_get_stream(request, auth).await,
            _ => {
                // Non-GET methods: execute then return empty stream.
                let result = self.execute(request, auth).await?;
                let body_bytes = result.body.clone().unwrap_or_default();
                let stream: ByteStream = Box::pin(futures_util::stream::once(async move {
                    Ok(Bytes::from(body_bytes))
                }));
                Ok((result, stream))
            }
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
