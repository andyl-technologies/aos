//! HTTP/HTTPS protocol implementation.
//!
//! Uses `reqwest` with HTTP/1.1 + HTTP/2 via ALPN negotiation. Supports:
//! - GET with Range headers (resume)
//! - PUT with Content-Length / streaming body
//! - HEAD for existence/size checks
//! - Streaming response bodies (bytes_stream)

use std::path::PathBuf;

use anyhow::{Context, Result};
use async_trait::async_trait;
use futures_util::StreamExt;
use reqwest::Client;

use super::{ByteStream, Protocol};
use crate::auth::Credential;
use crate::pool::PoolConfig;
use crate::types::{Method, TransferBody, TransferOutput, TransferRequest, TransferResult};

/// HTTP/HTTPS protocol handler.
///
/// Wraps a shared [`reqwest::Client`] (connection-pooled, ALPN
/// HTTP/1.1 + HTTP/2). Resume is implemented with `Range` request
/// headers: if the server replies 200 instead of 206, the transfer
/// silently restarts from the beginning.
pub struct HttpProtocol {
    client: Client,
}

impl HttpProtocol {
    /// Create a new HTTP protocol handler.
    ///
    /// The internal client keeps up to 8 idle connections per host
    /// (90 second idle timeout) and uses a 10 second connect timeout.
    ///
    pub fn new() -> Self {
        Self::with_pool_config(&PoolConfig::default())
    }

    /// Creates a handler whose HTTP pool follows the transfer pool policy.
    pub fn with_pool_config(config: &PoolConfig) -> Self {
        let client = match Client::builder()
            .pool_max_idle_per_host(config.max_connections_per_host)
            .pool_idle_timeout(config.idle_timeout)
            .connect_timeout(config.connect_timeout)
            .build()
        {
            Ok(client) => client,
            Err(error) => {
                tracing::warn!(%error, "falling back to the default HTTP client");
                Client::new()
            }
        };

        Self { client }
    }

    /// Create an HTTP protocol handler with a custom client.
    pub fn with_client(client: Client) -> Self {
        Self { client }
    }

    /// Get a reference to the underlying reqwest client (for token refresh).
    pub fn client(&self) -> &Client {
        &self.client
    }

    /// Apply HTTP-header credentials (`Bearer`, `Basic`, `Header`) to
    /// a request builder. Other credential types are ignored.
    fn apply_auth(
        &self,
        mut builder: reqwest::RequestBuilder,
        auth: Option<&Credential>,
    ) -> reqwest::RequestBuilder {
        match auth {
            Some(Credential::Bearer { token, .. }) => {
                builder = builder.bearer_auth(token);
            }
            Some(Credential::Basic { username, password }) => {
                builder = builder.basic_auth(username, Some(password));
            }
            Some(Credential::Header { name, value }) => {
                builder = builder.header(name.as_str(), value.as_str());
            }
            _ => {}
        }
        builder
    }

    /// Apply a request's explicit headers and the engine credential, emitting
    /// **exactly one** `Authorization` header.
    ///
    /// An explicit `Authorization` in `request.headers` takes precedence and
    /// suppresses the credential's: a caller that carries the auth in the
    /// headers (e.g. the token-exchange `POST`, which sends the provisioning
    /// secret) must not *also* get the engine credential appended. Two
    /// `Authorization` headers (like two `Content-Length`s) are rejected by
    /// strict edges such as Cloudflare with `400 Bad Request`.
    fn apply_headers_and_auth(
        &self,
        mut builder: reqwest::RequestBuilder,
        request: &TransferRequest,
        auth: Option<&Credential>,
    ) -> reqwest::RequestBuilder {
        let mut has_explicit_auth = false;
        for (name, value) in &request.headers {
            if name.eq_ignore_ascii_case("authorization") {
                has_explicit_auth = true;
            }
            builder = builder.header(name.as_str(), value.as_str());
        }
        if !has_explicit_auth {
            builder = self.apply_auth(builder, auth);
        }
        builder
    }
}

impl Default for HttpProtocol {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl Protocol for HttpProtocol {
    async fn execute(
        &self,
        request: &TransferRequest,
        auth: Option<&Credential>,
    ) -> Result<TransferResult> {
        match request.method {
            Method::Get => self.do_get(request, auth).await,
            Method::Put => self.do_put(request, auth).await,
            Method::Post => self.do_post(request, auth).await,
            Method::Head => self.do_head(request, auth).await,
            Method::Delete => self.do_delete(request, auth).await,
        }
    }

    async fn stream(
        &self,
        request: &TransferRequest,
        auth: Option<&Credential>,
    ) -> Result<(TransferResult, ByteStream)> {
        match request.method {
            Method::Get => self.do_get_stream(request, auth).await,
            Method::Put => {
                // PUT returns metadata + empty stream (upload direction).
                let result = self.do_put(request, auth).await?;
                let stream: ByteStream = Box::pin(futures_util::stream::empty());
                Ok((result, stream))
            }
            Method::Post => {
                // POST returns metadata + empty stream (upload direction).
                let result = self.do_post(request, auth).await?;
                let stream: ByteStream = Box::pin(futures_util::stream::empty());
                Ok((result, stream))
            }
            Method::Head => {
                let result = self.do_head(request, auth).await?;
                let stream: ByteStream = Box::pin(futures_util::stream::empty());
                Ok((result, stream))
            }
            Method::Delete => {
                let result = self.do_delete(request, auth).await?;
                let stream: ByteStream = Box::pin(futures_util::stream::empty());
                Ok((result, stream))
            }
        }
    }

    fn supports_resume(&self) -> bool {
        true
    }

    fn supports_multipart(&self) -> bool {
        false
    }
}

impl HttpProtocol {
    /// GET that returns headers/status + a byte stream (no buffering).
    ///
    /// Adds a `Range` header when resuming to an existing output file;
    /// the returned result's `bytes_transferred` is pre-seeded with the
    /// resume offset and updated by the caller as chunks arrive.
    async fn do_get_stream(
        &self,
        request: &TransferRequest,
        auth: Option<&Credential>,
    ) -> Result<(TransferResult, ByteStream)> {
        let mut builder = self.client.get(&request.url);
        builder = self.apply_auth(builder, auth);

        for (name, value) in &request.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }

        // Handle resume.
        let mut resume_offset: u64 = 0;
        let mut resumed = false;

        if request.resume {
            if let TransferOutput::File(ref path) = request.output {
                if let Ok(metadata) = tokio::fs::metadata(path).await {
                    let existing_size = metadata.len();
                    if existing_size > 0 {
                        builder = builder.header("Range", format!("bytes={}-", existing_size));
                        resume_offset = existing_size;
                        resumed = true;
                    }
                }
            }
        }

        let response = builder
            .send()
            .await
            .with_context(|| format!("GET {}", request.url))?;

        let status = response.status().as_u16();

        if status >= 400 {
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("HTTP {} for {}: {}", status, request.url, body);
        }

        if resumed && status == 200 {
            resume_offset = 0;
            resumed = false;
        } else if resumed {
            validate_resumed_response(&response, resume_offset, &request.url)?;
        }

        let content_length = response.content_length();
        let response_headers = collect_headers(&response);

        let result = TransferResult {
            status,
            headers: response_headers,
            bytes_transferred: resume_offset, // Will be updated by the caller as chunks arrive.
            content_length,
            body: None,
            hash: None,
            resumed,
        };

        // Return the raw byte stream from reqwest.
        let stream: ByteStream = Box::pin(
            response
                .bytes_stream()
                .map(|r| r.map_err(|e| anyhow::anyhow!("reading response chunk: {e}"))),
        );

        Ok((result, stream))
    }

    /// Buffering GET: downloads the full body into the request's
    /// output destination (memory, file with optional resume, or
    /// callback) before returning.
    async fn do_get(
        &self,
        request: &TransferRequest,
        auth: Option<&Credential>,
    ) -> Result<TransferResult> {
        let mut builder = self.client.get(&request.url);
        builder = self.apply_auth(builder, auth);

        // Add custom headers.
        for (name, value) in &request.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }

        // Handle resume: check existing file size and add Range header.
        let mut resume_offset: u64 = 0;
        let mut resumed = false;

        if request.resume {
            if let TransferOutput::File(ref path) = request.output {
                if let Ok(metadata) = tokio::fs::metadata(path).await {
                    let existing_size = metadata.len();
                    if existing_size > 0 {
                        builder = builder.header("Range", format!("bytes={}-", existing_size));
                        resume_offset = existing_size;
                        resumed = true;
                    }
                }
            }
        }

        let response = builder
            .send()
            .await
            .with_context(|| format!("GET {}", request.url))?;

        let status = response.status().as_u16();

        // Check for error status.
        if status >= 400 {
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("HTTP {} for {}: {}", status, request.url, body);
        }

        // A full response safely restarts the destination. A partial response
        // must prove that it begins at the existing file boundary; blindly
        // appending a mismatched range would create a corrupt object.
        if resumed && status == 200 {
            resume_offset = 0;
            resumed = false;
        } else if resumed {
            validate_resumed_response(&response, resume_offset, &request.url)?;
        }

        let content_length = response.content_length();
        let response_headers = collect_headers(&response);

        // Stream the response body.
        match &request.output {
            TransferOutput::Memory => {
                let bytes = response
                    .bytes()
                    .await
                    .with_context(|| format!("reading body from {}", request.url))?;
                let bytes_transferred = bytes.len() as u64;

                Ok(TransferResult {
                    status,
                    headers: response_headers,
                    bytes_transferred,
                    content_length,
                    body: Some(bytes.to_vec()),
                    hash: None,
                    resumed,
                })
            }
            TransferOutput::File(path) => {
                let bytes = stream_to_file(response, path, resumed, resume_offset).await?;

                Ok(TransferResult {
                    status,
                    headers: response_headers,
                    bytes_transferred: bytes,
                    content_length,
                    body: None,
                    hash: None,
                    resumed,
                })
            }
            TransferOutput::Callback(ref cb) => {
                let mut bytes_transferred: u64 = 0;
                let mut stream = response.bytes_stream();

                while let Some(chunk) = stream.next().await {
                    let chunk = chunk.with_context(|| "reading response chunk")?;
                    cb(&chunk)?;
                    bytes_transferred += chunk.len() as u64;
                }

                Ok(TransferResult {
                    status,
                    headers: response_headers,
                    bytes_transferred,
                    content_length,
                    body: None,
                    hash: None,
                    resumed,
                })
            }
        }
    }

    /// PUT with a bytes or streamed-from-file body. Sets an explicit
    /// `Content-Length`; `TransferBody::Stream` is rejected on this
    /// path (the engine handles streamed uploads).
    async fn do_put(
        &self,
        request: &TransferRequest,
        auth: Option<&Credential>,
    ) -> Result<TransferResult> {
        let mut builder = self.client.put(&request.url);
        builder = self.apply_headers_and_auth(builder, request, auth);

        // Set the request body.
        match &request.body {
            Some(TransferBody::Bytes(data)) => {
                // reqwest derives Content-Length from a sized in-memory body.
                // Setting it manually too emits a *duplicate* Content-Length
                // header, which strict edges (Cloudflare) reject with 400. Let
                // reqwest set it. (The File arm below keeps an explicit length
                // because its wrapped stream has no inherent size.)
                builder = builder.body(data.clone());
            }
            Some(TransferBody::File(path)) => {
                let file = tokio::fs::File::open(path)
                    .await
                    .with_context(|| format!("opening file {}", path.display()))?;
                let metadata = file.metadata().await?;
                let file_len = metadata.len();
                let stream = tokio_util::io::ReaderStream::new(file);
                let body = reqwest::Body::wrap_stream(stream);
                builder = builder
                    .header("Content-Length", file_len.to_string())
                    .body(body);
            }
            Some(TransferBody::Stream(_reader)) => {
                // We cannot consume the reader through a shared reference, so for
                // the direct protocol path we fall back to reading to bytes.
                // The transfer engine's streaming path handles this properly.
                anyhow::bail!("stream body upload not directly supported via Protocol::execute(); use TransferEngine");
            }
            None => {}
        }

        let response = builder
            .send()
            .await
            .with_context(|| format!("PUT {}", request.url))?;

        let status = response.status().as_u16();
        let headers = collect_headers(&response);
        let content_length = response.content_length();

        let body = if status < 400 {
            response.bytes().await.ok().map(|b| b.to_vec())
        } else {
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("HTTP {} for PUT {}: {}", status, request.url, text);
        };

        Ok(TransferResult {
            status,
            headers,
            bytes_transferred: body.as_ref().map_or(0, |b| b.len() as u64),
            content_length,
            body,
            hash: None,
            resumed: false,
        })
    }

    /// POST with a bytes or streamed-from-file body. Mirrors
    /// [`do_put`](Self::do_put) but uses the POST method.
    async fn do_post(
        &self,
        request: &TransferRequest,
        auth: Option<&Credential>,
    ) -> Result<TransferResult> {
        let mut builder = self.client.post(&request.url);
        builder = self.apply_headers_and_auth(builder, request, auth);

        match &request.body {
            Some(TransferBody::Bytes(data)) => {
                // reqwest derives Content-Length from a sized in-memory body.
                // Setting it manually too emits a *duplicate* Content-Length
                // header, which strict edges (Cloudflare) reject with 400. Let
                // reqwest set it. (The File arm below keeps an explicit length
                // because its wrapped stream has no inherent size.)
                builder = builder.body(data.clone());
            }
            Some(TransferBody::File(path)) => {
                let file = tokio::fs::File::open(path)
                    .await
                    .with_context(|| format!("opening file {}", path.display()))?;
                let metadata = file.metadata().await?;
                let file_len = metadata.len();
                let stream = tokio_util::io::ReaderStream::new(file);
                let body = reqwest::Body::wrap_stream(stream);
                builder = builder
                    .header("Content-Length", file_len.to_string())
                    .body(body);
            }
            Some(TransferBody::Stream(_reader)) => {
                anyhow::bail!("stream body upload not directly supported via Protocol::execute(); use TransferEngine");
            }
            None => {}
        }

        let response = builder
            .send()
            .await
            .with_context(|| format!("POST {}", request.url))?;

        let status = response.status().as_u16();
        let headers = collect_headers(&response);
        let content_length = response.content_length();

        let body = if status < 400 {
            response.bytes().await.ok().map(|b| b.to_vec())
        } else {
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("HTTP {} for POST {}: {}", status, request.url, text);
        };

        Ok(TransferResult {
            status,
            headers,
            bytes_transferred: body.as_ref().map_or(0, |b| b.len() as u64),
            content_length,
            body,
            hash: None,
            resumed: false,
        })
    }

    /// HEAD request. Note that error statuses (4xx/5xx) are returned
    /// in the result rather than as an `Err`, so callers can probe for
    /// existence.
    async fn do_head(
        &self,
        request: &TransferRequest,
        auth: Option<&Credential>,
    ) -> Result<TransferResult> {
        let mut builder = self.client.head(&request.url);
        builder = self.apply_auth(builder, auth);

        for (name, value) in &request.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }

        let response = builder
            .send()
            .await
            .with_context(|| format!("HEAD {}", request.url))?;

        let status = response.status().as_u16();
        let headers = collect_headers(&response);
        let content_length = response.content_length();

        Ok(TransferResult {
            status,
            headers,
            bytes_transferred: 0,
            content_length,
            body: None,
            hash: None,
            resumed: false,
        })
    }

    /// DELETE request. Fails with an error on 4xx/5xx statuses.
    async fn do_delete(
        &self,
        request: &TransferRequest,
        auth: Option<&Credential>,
    ) -> Result<TransferResult> {
        let mut builder = self.client.delete(&request.url);
        builder = self.apply_auth(builder, auth);

        for (name, value) in &request.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }

        let response = builder
            .send()
            .await
            .with_context(|| format!("DELETE {}", request.url))?;

        let status = response.status().as_u16();
        let headers = collect_headers(&response);

        if status >= 400 {
            let text = response.text().await.unwrap_or_default();
            anyhow::bail!("HTTP {} for DELETE {}: {}", status, request.url, text);
        }

        Ok(TransferResult {
            status,
            headers,
            bytes_transferred: 0,
            content_length: None,
            body: None,
            hash: None,
            resumed: false,
        })
    }
}

/// Verifies that a ranged response is safe to append to a partial file.
fn validate_resumed_response(
    response: &reqwest::Response,
    expected_start: u64,
    url: &str,
) -> Result<()> {
    if response.status() != reqwest::StatusCode::PARTIAL_CONTENT {
        anyhow::bail!(
            "resume for {url} returned HTTP {}, expected 206 Partial Content",
            response.status()
        );
    }

    let content_range = response
        .headers()
        .get(reqwest::header::CONTENT_RANGE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| anyhow::anyhow!("resumed response for {url} omitted Content-Range"))?;
    let range = content_range
        .strip_prefix("bytes ")
        .and_then(|value| value.split_once('/').map(|(range, _)| range))
        .and_then(|range| range.split_once('-'))
        .ok_or_else(|| {
            anyhow::anyhow!(
                "resumed response for {url} has invalid Content-Range {content_range:?}"
            )
        })?;
    let actual_start = range.0.parse::<u64>().with_context(|| {
        format!("resumed response for {url} has invalid Content-Range {content_range:?}")
    })?;
    if actual_start != expected_start {
        anyhow::bail!(
            "resumed response for {url} starts at byte {actual_start}, expected {expected_start}"
        );
    }
    Ok(())
}

/// Stream a response body to a file, creating parent directories.
///
/// If `append` is true, opens the file in append mode for resume.
/// Returns `offset + bytes_written` so resumed transfers report the
/// total file size.
async fn stream_to_file(
    response: reqwest::Response,
    path: &PathBuf,
    append: bool,
    offset: u64,
) -> Result<u64> {
    use tokio::io::AsyncWriteExt;

    // Ensure parent directory exists.
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .with_context(|| format!("creating directory {}", parent.display()))?;
    }

    let mut file = if append {
        tokio::fs::OpenOptions::new()
            .append(true)
            .open(path)
            .await
            .with_context(|| format!("opening {} for append", path.display()))?
    } else {
        tokio::fs::File::create(path)
            .await
            .with_context(|| format!("creating {}", path.display()))?
    };

    let mut bytes_written: u64 = 0;
    let mut stream = response.bytes_stream();

    while let Some(chunk) = stream.next().await {
        let chunk = chunk.with_context(|| "reading response chunk")?;
        file.write_all(&chunk)
            .await
            .with_context(|| format!("writing to {}", path.display()))?;
        bytes_written += chunk.len() as u64;
    }

    file.flush().await?;

    Ok(offset + bytes_written)
}

/// Collect response headers into a Vec of (name, value) pairs.
///
/// Header values that are not valid UTF-8 are replaced with an empty
/// string.
fn collect_headers(response: &reqwest::Response) -> Vec<(String, String)> {
    response
        .headers()
        .iter()
        .map(|(name, value)| {
            (
                name.as_str().to_string(),
                value.to_str().unwrap_or("").to_string(),
            )
        })
        .collect()
}
