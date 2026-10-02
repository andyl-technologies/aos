//! S3 / S3-compatible protocol implementation.
//!
//! Uses `aws-sdk-s3` for S3 operations. Supports:
//! - GetObject with streaming body (no full-buffer)
//! - PutObject with streaming / multi-part from file (chunked reads, no full-buffer)
//! - HeadObject, DeleteObject
//! - Conditional PutObject (`If-Match` / `If-None-Match: *`) with `ETag`
//!   results; see [`super::conditional`]
//! - Custom endpoints (MinIO, B2, Wasabi)
//!
//! Successful GetObject, HeadObject, and single-request PutObject results
//! carry the object's `ETag` response header verbatim.

use std::collections::BTreeMap;
use std::sync::Mutex;

mod resume;

use anyhow::{Context, Result};
use async_trait::async_trait;
use aws_sdk_s3::error::{ProvideErrorMetadata, SdkError};
use aws_sdk_s3::operation::head_object::HeadObjectError;
use bytes::Bytes;
use tokio::io::AsyncReadExt;

use super::conditional::{ETAG, WritePrecondition, precondition_failed_result};
use super::{ByteStream, Protocol};
use crate::auth::Credential;
use crate::multipart::{
    MultipartAdmission, MultipartBackend, MultipartFailurePolicy, MultipartSessionState,
    MultipartSource, MultipartUploadRequest,
};
use crate::transfer::{TransferEngine, TransferEngineConfig};
use crate::types::{Method, TransferBody, TransferOutput, TransferRequest, TransferResult};

/// Default threshold for multi-part uploads (5 MB).
const MULTIPART_THRESHOLD: u64 = 5 * 1024 * 1024;

/// Default part size for multi-part uploads (5 MB).
const MULTIPART_PART_SIZE: u64 = 5 * 1024 * 1024;

/// Maximum S3 parts uploaded concurrently for one object.
const MULTIPART_CONCURRENCY: usize = 4;

/// Adapts the S3 multipart RPCs to the backend-neutral upload manager.
struct S3MultipartBackend<'a> {
    client: &'a aws_sdk_s3::Client,
    bucket: &'a str,
    key: &'a str,
    diagnostic: &'a str,
    headers: &'a [(String, String)],
    part_size: u64,
    journal: resume::ResumeJournal,
    checkpoint: Mutex<Option<resume::Checkpoint>>,
    source_size: u64,
    source_sha256: String,
    already_complete: Mutex<bool>,
}

impl S3MultipartBackend<'_> {
    async fn exact_final_object_exists(&self) -> Result<bool> {
        use sha2::Digest as _;
        let response = match self
            .client
            .get_object()
            .bucket(self.bucket)
            .key(self.key)
            .send()
            .await
        {
            Ok(response) => response,
            Err(error)
                if error
                    .as_service_error()
                    .is_some_and(|service| service.code() == Some("NoSuchKey")) =>
            {
                return Ok(false);
            }
            Err(error) => {
                return Err(s3_operation_error(
                    "GetObject recovery",
                    &format!("{}/{}", self.bucket, self.key),
                    self.diagnostic,
                    error,
                ));
            }
        };
        let mut body = response.body.into_async_read();
        let mut sha256 = sha2::Sha256::new();
        let mut size = 0_u64;
        let mut buffer = [0_u8; 128 * 1024];
        loop {
            let count = body.read(&mut buffer).await?;
            if count == 0 {
                break;
            }
            size = size
                .checked_add(u64::try_from(count)?)
                .context("S3 recovery object size overflow")?;
            anyhow::ensure!(
                size <= self.source_size,
                "S3 recovery found conflicting object bytes"
            );
            sha256.update(&buffer[..count]);
        }
        anyhow::ensure!(
            size == self.source_size && hex::encode(sha256.finalize()) == self.source_sha256,
            "S3 recovery found conflicting object bytes"
        );
        Ok(true)
    }
}

#[async_trait]
impl MultipartBackend for S3MultipartBackend<'_> {
    type Session = String;
    type Part = aws_sdk_s3::types::CompletedPart;

    async fn begin(&self, _size: u64) -> Result<MultipartAdmission<Self::Session>> {
        if let Some(checkpoint) = self.journal.read()? {
            let session = self
                .client
                .list_parts()
                .bucket(self.bucket)
                .key(self.key)
                .upload_id(&checkpoint.upload_id)
                .max_parts(1)
                .send()
                .await;
            if let Err(error) = session {
                if !error
                    .as_service_error()
                    .is_some_and(|service| service.code() == Some("NoSuchUpload"))
                {
                    return Err(s3_operation_error(
                        "ListParts continuation",
                        &format!("{}/{}", self.bucket, self.key),
                        self.diagnostic,
                        error,
                    ));
                }
                if self.exact_final_object_exists().await? {
                    self.journal.clear()?;
                    *self
                        .already_complete
                        .lock()
                        .map_err(|_| anyhow::anyhow!("S3 checkpoint lock poisoned"))? = true;
                    return Ok(MultipartAdmission {
                        session: checkpoint.upload_id,
                        part_size: self.part_size,
                        next_part_number: u32::try_from(self.source_size.div_ceil(self.part_size))?
                            + 1,
                        state: MultipartSessionState::Completing,
                    });
                }
                self.journal.clear()?;
                // NoSuchUpload confirms the provider discarded only this session.
                // Admission below starts a fresh transfer of the identical object.
            } else {
                anyhow::ensure!(
                    checkpoint.part_size == self.part_size && !checkpoint.upload_id.is_empty(),
                    "S3 durable multipart geometry changed"
                );
                let mut next_part_number = 1;
                for (part, etag) in &checkpoint.parts {
                    anyhow::ensure!(
                        *part == next_part_number && !etag.is_empty(),
                        "S3 multipart checkpoint is invalid"
                    );
                    next_part_number = next_part_number
                        .checked_add(1)
                        .context("S3 multipart progress overflow")?;
                }
                let session = checkpoint.upload_id.clone();
                *self
                    .checkpoint
                    .lock()
                    .map_err(|_| anyhow::anyhow!("S3 checkpoint lock poisoned"))? =
                    Some(checkpoint);
                return Ok(MultipartAdmission {
                    session,
                    part_size: self.part_size,
                    next_part_number,
                    state: MultipartSessionState::Active,
                });
            }
        }
        let location = format!("{}/{}", self.bucket, self.key);
        let create = self
            .client
            .create_multipart_upload()
            .bucket(self.bucket)
            .key(self.key);
        let create = apply_create_multipart_headers(create, self.headers);
        let response = create.send().await.map_err(|error| {
            s3_operation_error("CreateMultipartUpload", &location, self.diagnostic, error)
        })?;
        let upload_id = response
            .upload_id()
            .context("S3 CreateMultipartUpload returned no upload id")?
            .to_string();

        let checkpoint = resume::Checkpoint {
            upload_id: upload_id.clone(),
            part_size: self.part_size,
            parts: Vec::new(),
        };
        self.journal.write(&checkpoint)?;
        *self
            .checkpoint
            .lock()
            .map_err(|_| anyhow::anyhow!("S3 checkpoint lock poisoned"))? = Some(checkpoint);
        Ok(MultipartAdmission {
            session: upload_id,
            part_size: self.part_size,
            next_part_number: 1,
            state: MultipartSessionState::Active,
        })
    }

    async fn upload_part(
        &self,
        upload_id: &Self::Session,
        part_number: u32,
        _offset: u64,
        bytes: Bytes,
    ) -> Result<Self::Part> {
        let part_number = i32::try_from(part_number).context("S3 part number exceeds i32")?;
        let location = format!("{}/{}", self.bucket, self.key);
        let response = self
            .client
            .upload_part()
            .bucket(self.bucket)
            .key(self.key)
            .upload_id(upload_id)
            .part_number(part_number)
            .body(bytes.into())
            .send()
            .await
            .map_err(|error| {
                s3_operation_error(
                    &format!("UploadPart (part {part_number})"),
                    &location,
                    self.diagnostic,
                    error,
                )
            })?;
        let etag = response
            .e_tag()
            .with_context(|| format!("S3 UploadPart returned no ETag for part {part_number}"))?;

        let mut checkpoint = self
            .checkpoint
            .lock()
            .map_err(|_| anyhow::anyhow!("S3 checkpoint lock poisoned"))?;
        let checkpoint = checkpoint
            .as_mut()
            .context("S3 multipart session was not admitted")?;
        anyhow::ensure!(
            part_number == i32::try_from(checkpoint.parts.len())? + 1,
            "S3 durable multipart receipts must be contiguous"
        );
        checkpoint
            .parts
            .push((u32::try_from(part_number)?, etag.to_owned()));
        self.journal.write(checkpoint)?;

        Ok(aws_sdk_s3::types::CompletedPart::builder()
            .part_number(part_number)
            .e_tag(etag)
            .build())
    }

    async fn complete(&self, upload_id: &Self::Session, _parts: &[Self::Part]) -> Result<()> {
        if *self
            .already_complete
            .lock()
            .map_err(|_| anyhow::anyhow!("S3 checkpoint lock poisoned"))?
        {
            return Ok(());
        }
        let location = format!("{}/{}", self.bucket, self.key);
        let accepted = self
            .checkpoint
            .lock()
            .map_err(|_| anyhow::anyhow!("S3 checkpoint lock poisoned"))?
            .as_ref()
            .context("S3 multipart session was not admitted")?
            .parts
            .clone();
        let completed = aws_sdk_s3::types::CompletedMultipartUpload::builder()
            .set_parts(Some(
                accepted
                    .iter()
                    .map(|(number, etag)| {
                        aws_sdk_s3::types::CompletedPart::builder()
                            .part_number(*number as i32)
                            .e_tag(etag)
                            .build()
                    })
                    .collect(),
            ))
            .build();
        let mut complete = self
            .client
            .complete_multipart_upload()
            .bucket(self.bucket)
            .key(self.key)
            .upload_id(upload_id)
            .multipart_upload(completed);
        for (name, value) in self.headers {
            if name.eq_ignore_ascii_case("if-none-match") {
                complete = complete.if_none_match(value);
            }
            if name.eq_ignore_ascii_case("if-match") {
                complete = complete.if_match(value);
            }
        }
        complete.send().await.map_err(|error| {
            s3_operation_error("CompleteMultipartUpload", &location, self.diagnostic, error)
        })?;
        self.journal.clear()?;
        Ok(())
    }

    async fn abort(&self, upload_id: &Self::Session) -> Result<()> {
        let location = format!("{}/{}", self.bucket, self.key);
        self.client
            .abort_multipart_upload()
            .bucket(self.bucket)
            .key(self.key)
            .upload_id(upload_id)
            .send()
            .await
            .map_err(|error| {
                s3_operation_error("AbortMultipartUpload", &location, self.diagnostic, error)
            })?;
        Ok(())
    }
}

/// Requires the SDK's native resolver, including service-specific profile overrides.
fn native_aws_configuration(config: &aws_config::SdkConfig) -> Result<bool> {
    Ok(configured_s3_endpoint(config)?.is_none())
}

/// Resolves the same service-before-global endpoint precedence as the SDK.
fn configured_s3_endpoint(config: &aws_config::SdkConfig) -> Result<Option<String>> {
    let key = aws_types::service_config::ServiceConfigKey::builder()
        .service_id("S3")
        .env("AWS_ENDPOINT_URL")
        .profile("endpoint_url")
        .build()?;
    Ok(config
        .service_config()
        .and_then(|service| service.load_config(key))
        .or_else(|| config.endpoint_url().map(str::to_owned)))
}

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
        anyhow::Error::new(err).context(format!("S3 {operation} for {location} against {target}"))
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
    clients: Mutex<BTreeMap<Option<S3ClientConfig>, (aws_sdk_s3::Client, bool, Option<String>)>>,
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
    async fn build_client(
        &self,
        auth: Option<&Credential>,
    ) -> Result<(aws_sdk_s3::Client, bool, Option<String>)> {
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
    async fn build_client_uncached(
        &self,
        auth: Option<&Credential>,
    ) -> Result<(aws_sdk_s3::Client, bool, Option<String>)> {
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
            let native_aws = endpoint.is_none() && native_aws_configuration(&config)?;
            let mut s3_config = aws_sdk_s3::config::Builder::from(&config);
            if let Some(ref ep) = endpoint {
                s3_config = s3_config.endpoint_url(ep).force_path_style(true);
            }
            Ok((
                aws_sdk_s3::Client::from_conf(s3_config.build()),
                native_aws,
                endpoint.clone().or(configured_s3_endpoint(&config)?),
            ))
        } else {
            let config = config_loader.load().await;
            let native_aws = native_aws_configuration(&config)?;
            Ok((
                aws_sdk_s3::Client::new(&config),
                native_aws,
                configured_s3_endpoint(&config)?,
            ))
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
        let (client, _, _) = self.build_client(auth).await?;
        let (bucket, key) = Self::parse_url(&request.url)?;
        let target = s3_target(auth);

        let mut get_builder = client.get_object().bucket(&bucket).key(&key);

        let mut resumed = false;
        let mut resume_offset: u64 = 0;

        if request.resume {
            let existing_size = Self::resume_offset(&request.output).await?;
            if existing_size > 0 {
                get_builder = get_builder.range(format!("bytes={existing_size}-"));
                resume_offset = existing_size;
                resumed = true;
            }
        }

        let resp = get_builder
            .send()
            .await
            .map_err(|e| s3_operation_error("GetObject", &format!("{bucket}/{key}"), &target, e))?;

        let content_length = resp.content_length().map(|l| l as u64);
        let headers = etag_header(resp.e_tag());

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
                    headers,
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
                    headers,
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
                    headers,
                    bytes_transferred: bytes_transferred + resume_offset,
                    content_length,
                    body: None,
                    hash: None,
                    resumed,
                })
            }
            TransferOutput::Sink(sink) => {
                let mut bytes_transferred = resume_offset;
                let mut chunk_buf = vec![0u8; 64 * 1024];

                loop {
                    let n = body_reader
                        .read(&mut chunk_buf)
                        .await
                        .context("reading S3 object chunk")?;
                    if n == 0 {
                        break;
                    }
                    sink.write(&chunk_buf[..n])?;
                    bytes_transferred = bytes_transferred
                        .checked_add(n as u64)
                        .context("S3 sink byte count overflow")?;
                }
                sink.flush()?;

                Ok(TransferResult {
                    status: 200,
                    headers,
                    bytes_transferred,
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
        let (client, _, _) = self.build_client(auth).await?;
        let (bucket, key) = Self::parse_url(&request.url)?;
        let target = s3_target(auth);

        let mut get_builder = client.get_object().bucket(&bucket).key(&key);

        let mut resumed = false;
        let mut resume_offset: u64 = 0;

        if request.resume {
            let existing_size = Self::resume_offset(&request.output).await?;
            if existing_size > 0 {
                get_builder = get_builder.range(format!("bytes={existing_size}-"));
                resume_offset = existing_size;
                resumed = true;
            }
        }

        let resp = get_builder
            .send()
            .await
            .map_err(|e| s3_operation_error("GetObject", &format!("{bucket}/{key}"), &target, e))?;

        let content_length = resp.content_length().map(|l| l as u64);

        let result = TransferResult {
            status: 200,
            headers: etag_header(resp.e_tag()),
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

    /// Returns the committed range offset for an S3 file or replayable sink.
    async fn resume_offset(output: &TransferOutput) -> Result<u64> {
        match output {
            TransferOutput::File(path) => match tokio::fs::metadata(path).await {
                Ok(metadata) => Ok(metadata.len()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(0),
                Err(error) => Err(error.into()),
            },
            TransferOutput::Sink(sink) => sink.position(),
            TransferOutput::Memory | TransferOutput::Callback(_) => Ok(0),
        }
    }

    /// PutObject upload. File bodies above the 5 MB threshold use
    /// multi-part upload; smaller files and byte bodies upload in one
    /// shot. Stream bodies are rejected on this path.
    ///
    /// Native AWS multipart completion enforces the write precondition.
    /// Custom providers use streamed conditional PutObject up to 5 GiB because
    /// conditional multipart completion is not a portable S3 guarantee.
    async fn do_put(
        &self,
        request: &TransferRequest,
        auth: Option<&Credential>,
    ) -> Result<TransferResult> {
        let (client, native_aws, endpoint) = self.build_client(auth).await?;
        let (bucket, key) = Self::parse_url(&request.url)?;
        let target = s3_target(auth);
        let conditional = WritePrecondition::from_headers(&request.headers)?.is_some();
        let single = SinglePut {
            client: &client,
            bucket: &bucket,
            key: &key,
            headers: &request.headers,
            conditional,
            target: &target,
        };

        match &request.body {
            Some(TransferBody::File(path)) => {
                let metadata = tokio::fs::metadata(path)
                    .await
                    .with_context(|| format!("stat {}", path.display()))?;
                let file_len = metadata.len();

                if file_len > MULTIPART_THRESHOLD && (!conditional || native_aws) {
                    let (size, digest) =
                        resume::source_identity(&MultipartSource::File(path.clone()))?;
                    anyhow::ensure!(
                        size == file_len,
                        "S3 source changed before multipart admission"
                    );
                    let namespace = serde_json::to_string(&(
                        &endpoint,
                        client.config().region().map(|region| region.as_ref()),
                        &request.headers,
                    ))?;
                    let journal =
                        resume::ResumeJournal::open(&namespace, &request.url, size, &digest)?;
                    let backend = S3MultipartBackend {
                        client: &client,
                        bucket: &bucket,
                        key: &key,
                        diagnostic: &target,
                        headers: &request.headers,
                        part_size: self.part_size,
                        journal,
                        checkpoint: Mutex::new(None),
                        source_size: size,
                        source_sha256: digest,
                        already_complete: Mutex::new(false),
                    };
                    let maximum_in_flight_bytes = self
                        .part_size
                        .checked_mul(MULTIPART_CONCURRENCY as u64)
                        .context("S3 multipart in-flight byte limit overflow")?;
                    let upload = MultipartUploadRequest::new(
                        request.url.clone(),
                        MultipartSource::File(path.clone()),
                    )
                    .with_concurrency(1)
                    .with_failure_policy(MultipartFailurePolicy::Preserve)
                    .with_maximum_in_flight_bytes(maximum_in_flight_bytes)
                    .with_part_limits(1, 5 * 1024 * 1024 * 1024, 10_000);
                    let uploaded = TransferEngine::new(TransferEngineConfig::default())
                        .upload_multipart(upload, &backend)
                        .await?;
                    let current = self
                        .do_head(&TransferRequest::head(&request.url), auth)
                        .await?;
                    anyhow::ensure!(
                        current.status == 200,
                        "S3 multipart object vanished after completion"
                    );

                    return Ok(TransferResult {
                        status: 200,
                        headers: current.headers,
                        bytes_transferred: file_len,
                        content_length: Some(file_len),
                        body: None,
                        hash: None,
                        resumed: uploaded.resumed_bytes > 0,
                    });
                }

                anyhow::ensure!(
                    file_len <= 5 * 1024 * 1024 * 1024,
                    "custom S3 immutable uploads above 5 GiB require a provider with verified conditional multipart completion"
                );
                let body = aws_sdk_s3::primitives::ByteStream::from_path(path)
                    .await
                    .with_context(|| format!("opening streaming S3 upload {}", path.display()))?;
                single.send_body(body, file_len).await
            }
            Some(TransferBody::Bytes(data)) => single.send(data.clone()).await,
            Some(TransferBody::Stream(_)) => {
                anyhow::bail!(
                    "stream body not directly supported for S3 put via Protocol::execute(); use TransferEngine"
                );
            }
            None => single.send(Vec::new()).await,
        }
    }

    /// HeadObject: returns a 200 result with the object size, or a
    /// 404 result (not an error) when the object does not exist.
    async fn do_head(
        &self,
        request: &TransferRequest,
        auth: Option<&Credential>,
    ) -> Result<TransferResult> {
        let (client, _, _) = self.build_client(auth).await?;
        let (bucket, key) = Self::parse_url(&request.url)?;
        let target = s3_target(auth);

        let resp = client.head_object().bucket(&bucket).key(&key).send().await;

        match resp {
            Ok(output) => {
                let content_length = output.content_length().map(|l| l as u64);
                Ok(TransferResult {
                    status: 200,
                    headers: etag_header(output.e_tag()),
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
                let is_404 = e
                    .as_service_error()
                    .is_some_and(HeadObjectError::is_not_found)
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
        let (client, _, _) = self.build_client(auth).await?;
        let (bucket, key) = Self::parse_url(&request.url)?;
        let target = s3_target(auth);

        client
            .delete_object()
            .bucket(&bucket)
            .key(&key)
            .send()
            .await
            .map_err(|e| {
                s3_operation_error("DeleteObject", &format!("{bucket}/{key}"), &target, e)
            })?;

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
}

/// One single-request PutObject target, shared by every non-multipart
/// branch of [`S3Protocol::do_put`].
struct SinglePut<'a> {
    client: &'a aws_sdk_s3::Client,
    bucket: &'a str,
    key: &'a str,
    headers: &'a [(String, String)],
    /// Whether the request carries a [`WritePrecondition`].
    conditional: bool,
    /// Endpoint description for diagnostics (see [`s3_target`]).
    target: &'a str,
}

impl SinglePut<'_> {
    /// Uploads `data` with one PutObject and reports the stored `ETag`.
    ///
    /// For a conditional request, a refused precondition becomes a
    /// [`PRECONDITION_FAILED`](super::conditional::PRECONDITION_FAILED)
    /// result instead of an error: nothing was written, and the caller
    /// decides whether to re-read and retry.
    async fn send(&self, data: Vec<u8>) -> Result<TransferResult> {
        let data_len = data.len() as u64;
        self.send_body(data.into(), data_len).await
    }

    async fn send_body(
        &self,
        body: aws_sdk_s3::primitives::ByteStream,
        data_len: u64,
    ) -> Result<TransferResult> {
        let put = self
            .client
            .put_object()
            .bucket(self.bucket)
            .key(self.key)
            .body(body);
        let put = apply_put_object_headers(put, self.headers);

        match put.send().await {
            Ok(output) => Ok(TransferResult {
                status: 200,
                headers: etag_header(output.e_tag()),
                bytes_transferred: data_len,
                content_length: Some(data_len),
                body: None,
                hash: None,
                resumed: false,
            }),
            Err(error) if self.conditional && is_precondition_refusal(&error) => {
                Ok(precondition_failed_result(None))
            }
            Err(error) => Err(s3_operation_error(
                "PutObject",
                &format!("{}/{}", self.bucket, self.key),
                self.target,
                error,
            )),
        }
    }
}

/// Returns whether a failed conditional PutObject was refused without
/// writing: `412 Precondition Failed`, or AWS's `409
/// ConditionalRequestConflict` when a concurrent conditional write to the
/// same key won the race.
fn is_precondition_refusal<E: ProvideErrorMetadata>(error: &SdkError<E>) -> bool {
    match error
        .raw_response()
        .map(|response| response.status().as_u16())
    {
        Some(412) => true,
        Some(409) => error.code() == Some("ConditionalRequestConflict"),
        _ => false,
    }
}

/// Builds the `ETag` response header list for an S3 result, empty when the
/// service reported no `ETag`.
fn etag_header(etag: Option<&str>) -> Vec<(String, String)> {
    etag.map(|etag| vec![(ETAG.to_string(), etag.to_string())])
        .unwrap_or_default()
}

/// Map recognized HTTP-style request headers (`Content-Type`,
/// `Cache-Control`, `If-Match`, `If-None-Match`) onto PutObject builder
/// fields; other headers are ignored because S3 models them as typed
/// parameters, not headers.
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
            "if-match" => {
                builder = builder.if_match(value);
            }
            "if-none-match" => {
                builder = builder.if_none_match(value);
            }
            _ => {}
        }
    }
    builder
}

/// Same metadata mapping as [`apply_put_object_headers`], for the
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
mod conditional_tests;

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
