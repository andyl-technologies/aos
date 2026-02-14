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

    /// Return the SSE build stream URL for the given derivation path.
    pub fn build_url(&self, drv_path: &str) -> String {
        format!(
            "{}/{}/build?drv={}",
            self.base_url, self.view, drv_path
        )
    }
}
