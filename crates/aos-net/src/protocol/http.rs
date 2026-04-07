//! HTTP/HTTPS protocol implementation.
//!
//! Uses `reqwest` with HTTP/1.1 + HTTP/2 via ALPN negotiation. Supports:
//! - GET with Range headers (resume)
//! - PUT with Content-Length
//! - HEAD for existence/size checks
//! - Streaming request/response bodies

use std::path::PathBuf;

use anyhow::{Context, Result};
use async_trait::async_trait;
use futures_util::StreamExt;
use reqwest::Client;

use super::Protocol;
use crate::auth::Credential;
use crate::types::{Method, TransferBody, TransferOutput, TransferRequest, TransferResult};

/// HTTP/HTTPS protocol handler.
pub struct HttpProtocol {
    client: Client,
}

impl HttpProtocol {
    /// Create a new HTTP protocol handler.
    pub fn new() -> Self {
        let client = Client::builder()
            .pool_max_idle_per_host(8)
            .pool_idle_timeout(std::time::Duration::from_secs(90))
            .connect_timeout(std::time::Duration::from_secs(10))
            .build()
            .expect("failed to build reqwest client");

        Self { client }
    }

    /// Create an HTTP protocol handler with a custom client.
    pub fn with_client(client: Client) -> Self {
        Self { client }
    }

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
            Method::Head => self.do_head(request, auth).await,
            Method::Delete => self.do_delete(request, auth).await,
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
                        builder =
                            builder.header("Range", format!("bytes={}-", existing_size));
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

        // If we attempted resume but got 200 (not 206), server doesn't support it.
        if resumed && status == 200 {
            resume_offset = 0;
            resumed = false;
        }

        // Check for error status.
        if status >= 400 {
            let body = response.text().await.unwrap_or_default();
            anyhow::bail!("HTTP {} for {}: {}", status, request.url, body);
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
            TransferOutput::Callback(ref _cb) => {
                // We need &mut for the callback, but the request is &.
                // The transfer engine handles callbacks at a higher level.
                // For direct protocol use, stream to memory.
                let bytes = response
                    .bytes()
                    .await
                    .with_context(|| format!("reading body from {}", request.url))?;

                Ok(TransferResult {
                    status,
                    headers: response_headers,
                    bytes_transferred: bytes.len() as u64,
                    content_length,
                    body: Some(bytes.to_vec()),
                    hash: None,
                    resumed,
                })
            }
        }
    }

    async fn do_put(
        &self,
        request: &TransferRequest,
        auth: Option<&Credential>,
    ) -> Result<TransferResult> {
        let mut builder = self.client.put(&request.url);
        builder = self.apply_auth(builder, auth);

        for (name, value) in &request.headers {
            builder = builder.header(name.as_str(), value.as_str());
        }

        // Set the request body.
        match &request.body {
            Some(TransferBody::Bytes(data)) => {
                builder = builder
                    .header("Content-Length", data.len().to_string())
                    .body(data.clone());
            }
            Some(TransferBody::File(path)) => {
                let data = tokio::fs::read(path)
                    .await
                    .with_context(|| format!("reading file {}", path.display()))?;
                builder = builder
                    .header("Content-Length", data.len().to_string())
                    .body(data);
            }
            Some(TransferBody::Stream(_)) => {
                // Stream bodies need special handling -- read to bytes.
                // The transfer engine handles true streaming at a higher level.
                anyhow::bail!("stream body upload not directly supported; use TransferBody::File or TransferBody::Bytes");
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

/// Stream a response body to a file.
///
/// If `append` is true, opens the file in append mode for resume.
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

