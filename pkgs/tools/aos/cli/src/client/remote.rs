use anyhow::{Context, Result};
use reqwest::Client;
use serde::Deserialize;

/// Client for communicating with the AOS cache server.
pub struct RemoteClient {
    client: Client,
    base_url: String,
    view: String,
    token: String,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct QueryMissingResponse {
    missing: Vec<String>,
}

#[derive(Deserialize)]
struct UploadResponse {
    path: String,
}

#[derive(Deserialize)]
struct CacheInfo {
    capabilities: Vec<String>,
}

/// Response from the server's `POST /{view}/gc` endpoint.
#[derive(Deserialize)]
pub struct GcResponse {
    pub expired: u64,
    pub evicted: u64,
    pub eviction_candidates: Vec<serde_json::Value>,
    pub dry_run: bool,
}

impl RemoteClient {
    /// Create a new `RemoteClient`.
    ///
    /// `base_url` is the root URL of the AOS cache server (e.g. `https://cache.example.com`).
    /// `view` is the cache view name.
    /// `token` is the provisioning token used for initial authentication.
    pub fn new(base_url: &str, view: &str, token: &str) -> Result<Self> {
        let client = Client::builder()
            .build()
            .context("failed to build HTTP client")?;

        Ok(Self {
            client,
            base_url: base_url.trim_end_matches('/').to_string(),
            view: view.to_string(),
            token: token.to_string(),
        })
    }

    /// Exchange the provisioning token for a JWT access token.
    ///
    /// Sends a `POST` to `/oauth2/token` with the provisioning token in the
    /// `Authorization: Bearer` header and a `client_credentials` grant type.
    /// On success the internal token is replaced with the returned JWT.
    pub async fn authenticate(&mut self) -> Result<()> {
        let url = format!("{}/oauth2/token", self.base_url);

        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.token)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body("grant_type=client_credentials")
            .send()
            .await
            .context("failed to send authentication request")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("authentication failed (HTTP {status}): {body}");
        }

        let token_resp: TokenResponse = resp
            .json()
            .await
            .context("failed to parse token response")?;

        self.token = token_resp.access_token;
        Ok(())
    }

    /// Fetch capabilities from the `nix-cache-info` endpoint.
    ///
    /// Parses the `Capabilities:` line from the plaintext response and returns
    /// the space-separated capability tokens.
    pub async fn capabilities(&self) -> Result<Vec<String>> {
        let url = format!("{}/{}/nix-cache-info", self.base_url, self.view);

        let resp = self
            .client
            .get(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .context("failed to fetch nix-cache-info")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("nix-cache-info request failed (HTTP {status}): {body}");
        }

        let body = resp.text().await.context("failed to read cache info body")?;

        for line in body.lines() {
            if let Some(caps) = line.strip_prefix("Capabilities:") {
                return Ok(caps
                    .split_whitespace()
                    .map(String::from)
                    .collect());
            }
        }

        Ok(Vec::new())
    }

    /// Query which store paths are missing on the server.
    ///
    /// Sends a `POST` to `/{view}/query-missing` with a JSON body containing
    /// the list of paths. Returns the subset of paths that the server does not
    /// have.
    pub async fn query_missing(&self, paths: &[String]) -> Result<Vec<String>> {
        let url = format!("{}/{}/query-missing", self.base_url, self.view);

        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.token)
            .json(&serde_json::json!({ "paths": paths }))
            .send()
            .await
            .context("failed to send query-missing request")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("query-missing failed (HTTP {status}): {body}");
        }

        let parsed: QueryMissingResponse = resp
            .json()
            .await
            .context("failed to parse query-missing response")?;

        Ok(parsed.missing)
    }

    /// Upload a single store path as a NAR export.
    ///
    /// Sends a `PUT` to `/{view}/store/{hash}` with the raw NAR data as the
    /// request body. Returns the imported store path.
    pub async fn upload_path(&self, hash: &str, nar_data: &[u8]) -> Result<String> {
        let url = format!("{}/{}/store/{}", self.base_url, self.view, hash);

        let resp = self
            .client
            .put(&url)
            .bearer_auth(&self.token)
            .header("Content-Type", "application/octet-stream")
            .body(nar_data.to_vec())
            .send()
            .await
            .context("failed to send upload-path request")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("upload-path failed (HTTP {status}): {body}");
        }

        let parsed: UploadResponse = resp
            .json()
            .await
            .context("failed to parse upload response")?;

        Ok(parsed.path)
    }

    /// Upload a store path with resumable chunked upload for large payloads.
    ///
    /// For payloads larger than 10 MB, splits the data into 5 MB chunks and
    /// sends each with a `Content-Range` header. On chunk failure, sends a
    /// `HEAD` request to discover the server's current offset and resumes from
    /// there. For payloads <= 10 MB, falls back to a single `upload_path` call.
    pub async fn upload_path_resumable(&self, hash: &str, nar_data: &[u8]) -> Result<String> {
        const CHUNK_THRESHOLD: usize = 10 * 1024 * 1024; // 10 MB
        const CHUNK_SIZE: usize = 5 * 1024 * 1024; // 5 MB

        if nar_data.len() <= CHUNK_THRESHOLD {
            return self.upload_path(hash, nar_data).await;
        }

        let url = format!("{}/{}/store/{}", self.base_url, self.view, hash);
        let total = nar_data.len() as u64;
        let mut offset: u64 = 0;

        while offset < total {
            let end = std::cmp::min(offset + CHUNK_SIZE as u64, total);
            let chunk = &nar_data[offset as usize..end as usize];
            let range_header = format!("bytes {}-{}/{}", offset, end - 1, total);

            let result = self
                .client
                .put(&url)
                .bearer_auth(&self.token)
                .header("Content-Type", "application/octet-stream")
                .header("Content-Range", &range_header)
                .body(chunk.to_vec())
                .send()
                .await;

            match result {
                Ok(resp) => {
                    let status = resp.status();
                    if status == reqwest::StatusCode::ACCEPTED {
                        // Intermediate chunk accepted — advance offset.
                        offset = end;
                        continue;
                    }
                    if status.is_success() {
                        // Final chunk — server returned the import result.
                        let parsed: UploadResponse = resp
                            .json()
                            .await
                            .context("failed to parse upload response")?;
                        return Ok(parsed.path);
                    }
                    // Unexpected status — attempt to resume.
                    let body = resp.text().await.unwrap_or_default();
                    eprintln!(
                        "chunk upload failed (HTTP {status}): {body}, attempting resume"
                    );
                }
                Err(e) => {
                    eprintln!("chunk upload error: {e}, attempting resume");
                }
            }

            // Query server for current progress via HEAD.
            offset = self.query_upload_progress(hash).await.unwrap_or(offset);
        }

        anyhow::bail!("upload completed all chunks but no final response received")
    }

    /// Query the server for the current progress of a partial upload.
    ///
    /// Sends a `HEAD` to `/{view}/store/{hash}` and reads the
    /// `Content-Length` header to determine how many bytes the server has
    /// received so far. Returns 0 if no partial upload exists.
    async fn query_upload_progress(&self, hash: &str) -> Result<u64> {
        let url = format!("{}/{}/store/{}", self.base_url, self.view, hash);

        let resp = self
            .client
            .head(&url)
            .bearer_auth(&self.token)
            .send()
            .await
            .context("failed to send HEAD request for upload progress")?;

        if !resp.status().is_success() {
            return Ok(0);
        }

        let size = resp
            .headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(0);

        Ok(size)
    }

    /// Upload a pack of multiple store paths in a single request.
    ///
    /// Sends a `POST` to `/{view}/upload-pack` with the pack data (created by
    /// [`crate::client::pack::create_pack`]) as the request body. Returns the
    /// list of imported store paths.
    pub async fn upload_pack(&self, pack_data: &[u8]) -> Result<Vec<String>> {
        let url = format!("{}/{}/upload-pack", self.base_url, self.view);

        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.token)
            .header("Content-Type", "application/octet-stream")
            .body(pack_data.to_vec())
            .send()
            .await
            .context("failed to send upload-pack request")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("upload-pack failed (HTTP {status}): {body}");
        }

        let parsed: Vec<String> = resp
            .json()
            .await
            .context("failed to parse upload-pack response")?;

        Ok(parsed)
    }

    /// Trigger garbage collection on the server for a view.
    ///
    /// Sends a `POST` to `/{view}/gc` with a JSON body containing
    /// `dry_run`, `collect`, and optionally `max_size`. Returns the
    /// server's GC response with expiry/eviction details.
    pub async fn gc(&self, dry_run: bool, collect: bool, max_size: Option<u64>) -> Result<GcResponse> {
        let url = format!("{}/{}/gc", self.base_url, self.view);
        let mut body = serde_json::json!({ "dry_run": dry_run, "collect": collect });
        if let Some(size) = max_size {
            body["max_size"] = serde_json::json!(size);
        }
        let resp = self
            .client
            .post(&url)
            .bearer_auth(&self.token)
            .json(&body)
            .send()
            .await
            .context("failed to send GC request")?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("GC request failed (HTTP {status}): {body}");
        }
        resp.json().await.context("failed to parse GC response")
    }

    /// Return the SSE build stream URL for the given derivation path.
    pub fn build_url(&self, drv_path: &str) -> String {
        format!(
            "{}/{}/build?drv={}",
            self.base_url, self.view, drv_path
        )
    }
}
