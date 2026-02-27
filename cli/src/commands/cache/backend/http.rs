use anyhow::{Context, Result};
use async_trait::async_trait;
use reqwest::Client;
use serde::Deserialize;

use super::{AuthOptions, CacheBackend};

/// HTTP(S) cache backend.
///
/// For push to AOS serve: uses RemoteClient-style API (auth, query-missing, upload).
/// For pull from any binary cache: standard GET on narinfo + NAR URLs.
pub struct HttpBackend {
    client: Client,
    base_url: String,
    view: String,
    token: Option<String>,
    headers: Vec<(String, String)>,
    is_aos: bool,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

#[derive(Deserialize)]
struct QueryMissingResponse {
    missing: Vec<String>,
}

impl HttpBackend {
    pub async fn new(url: &str, auth: &AuthOptions) -> Result<Self> {
        let client = Client::builder()
            .build()
            .context("failed to build HTTP client")?;

        let base_url = url.trim_end_matches('/').to_string();
        let view = auth.view.clone();

        // Parse custom headers.
        let mut headers = Vec::new();
        for h in &auth.headers {
            if let Some((k, v)) = h.split_once(':') {
                headers.push((k.trim().to_string(), v.trim().to_string()));
            }
        }

        let mut backend = Self {
            client,
            base_url,
            view,
            token: auth.token.clone(),
            headers,
            is_aos: auth.token.is_some(),
        };

        // If we have an AOS token, authenticate to get a JWT.
        if let Some(ref provisioning_token) = auth.token {
            backend.authenticate(provisioning_token).await?;
        } else if let (Some(user), Some(pass)) =
            (&auth.http_user, &auth.http_password)
        {
            // Basic auth: we store credentials and add them per-request.
            // The token field doubles as basic-auth storage.
            backend.token = Some(format!("basic:{user}:{pass}"));
        }

        Ok(backend)
    }

    async fn authenticate(&mut self, provisioning_token: &str) -> Result<()> {
        let url = format!("{}/oauth2/token", self.base_url);
        let resp = self
            .client
            .post(&url)
            .bearer_auth(provisioning_token)
            .header("Content-Type", "application/x-www-form-urlencoded")
            .body("grant_type=client_credentials")
            .send()
            .await
            .context("authentication request failed")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("authentication failed (HTTP {status}): {body}");
        }

        let token_resp: TokenResponse = resp.json().await.context("parsing token response")?;
        self.token = Some(token_resp.access_token);
        Ok(())
    }

    fn apply_auth(&self, mut req: reqwest::RequestBuilder) -> reqwest::RequestBuilder {
        if let Some(ref token) = self.token {
            if let Some(basic) = token.strip_prefix("basic:") {
                if let Some((user, pass)) = basic.split_once(':') {
                    req = req.basic_auth(user, Some(pass));
                }
            } else {
                req = req.bearer_auth(token);
            }
        }
        for (k, v) in &self.headers {
            req = req.header(k.as_str(), v.as_str());
        }
        req
    }

    fn narinfo_url(&self, store_hash: &str) -> String {
        if self.is_aos {
            format!("{}/{}/{}.narinfo", self.base_url, self.view, store_hash)
        } else {
            format!("{}/{}.narinfo", self.base_url, store_hash)
        }
    }

    fn nar_url(&self, url: &str) -> String {
        if self.is_aos {
            format!("{}/{}/{}", self.base_url, self.view, url)
        } else {
            format!("{}/{}", self.base_url, url)
        }
    }
}

#[async_trait]
impl CacheBackend for HttpBackend {
    async fn has_narinfo(&self, store_hash: &str) -> Result<bool> {
        let url = self.narinfo_url(store_hash);
        let req = self.client.head(&url);
        let resp = self.apply_auth(req).send().await?;
        Ok(resp.status().is_success())
    }

    async fn get_narinfo(&self, store_hash: &str) -> Result<String> {
        let url = self.narinfo_url(store_hash);
        let req = self.client.get(&url);
        let resp = self
            .apply_auth(req)
            .send()
            .await
            .context("fetching narinfo")?;

        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!("GET {url} failed (HTTP {status})");
        }
        resp.text().await.context("reading narinfo body")
    }

    async fn put_narinfo(&self, store_hash: &str, content: &str) -> Result<()> {
        let url = self.narinfo_url(store_hash);
        let req = self
            .client
            .put(&url)
            .header("Content-Type", "text/x-nix-narinfo")
            .body(content.to_string());
        let resp = self.apply_auth(req).send().await.context("uploading narinfo")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("PUT narinfo failed (HTTP {status}): {body}");
        }
        Ok(())
    }

    async fn get_nar(&self, url: &str) -> Result<Vec<u8>> {
        let full_url = self.nar_url(url);
        let req = self.client.get(&full_url);
        let resp = self.apply_auth(req).send().await.context("fetching NAR")?;

        let status = resp.status();
        if !status.is_success() {
            anyhow::bail!("GET {full_url} failed (HTTP {status})");
        }
        resp.bytes()
            .await
            .map(|b| b.to_vec())
            .context("reading NAR body")
    }

    async fn put_nar(&self, filename: &str, data: &[u8]) -> Result<()> {
        let url = self.nar_url(&format!("nar/{filename}"));
        let req = self
            .client
            .put(&url)
            .header("Content-Type", "application/x-nix-nar")
            .body(data.to_vec());
        let resp = self.apply_auth(req).send().await.context("uploading NAR")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("PUT NAR failed (HTTP {status}): {body}");
        }
        Ok(())
    }

    async fn query_missing(&self, store_hashes: &[&str]) -> Result<Vec<String>> {
        if self.is_aos {
            // AOS serve has a batch endpoint.
            let url = format!("{}/{}/query-missing", self.base_url, self.view);
            let paths: Vec<String> = store_hashes.iter().map(|h| h.to_string()).collect();
            let req = self
                .client
                .post(&url)
                .json(&serde_json::json!({ "paths": paths }));
            let resp = self
                .apply_auth(req)
                .send()
                .await
                .context("query-missing request")?;

            let status = resp.status();
            if !status.is_success() {
                let body = resp.text().await.unwrap_or_default();
                anyhow::bail!("query-missing failed (HTTP {status}): {body}");
            }

            let parsed: QueryMissingResponse =
                resp.json().await.context("parsing query-missing response")?;
            return Ok(parsed.missing);
        }

        // Generic cache: batch HEAD requests.
        let mut missing = Vec::new();
        for hash in store_hashes {
            if !self.has_narinfo(hash).await? {
                missing.push(hash.to_string());
            }
        }
        Ok(missing)
    }

    async fn ensure_cache_info(&self, _store_dir: &str) -> Result<()> {
        // HTTP caches are assumed to already have nix-cache-info.
        Ok(())
    }

    fn supports_pack(&self) -> bool {
        self.is_aos
    }

    async fn upload_pack(&self, data: &[u8]) -> Result<Vec<String>> {
        let url = format!("{}/{}/upload-pack", self.base_url, self.view);
        let req = self
            .client
            .post(&url)
            .header("Content-Type", "application/octet-stream")
            .body(data.to_vec());
        let resp = self
            .apply_auth(req)
            .send()
            .await
            .context("upload-pack request")?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp.text().await.unwrap_or_default();
            anyhow::bail!("upload-pack failed (HTTP {status}): {body}");
        }

        resp.json().await.context("parsing upload-pack response")
    }
}
