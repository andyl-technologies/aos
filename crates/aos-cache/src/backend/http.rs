use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;

use aos_net::{TransferEngine, TransferRequest};

use super::{AuthOptions, CacheBackend};

/// HTTP(S) cache backend.
///
/// For push to AOS server: uses AOS server API (auth, query-missing, upload).
/// For pull from any binary cache: standard GET on narinfo + NAR URLs.
pub struct HttpBackend {
    engine: Arc<TransferEngine>,
    base_url: String,
    view: String,
    /// Extra headers added to every request.
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
    pub async fn new(
        url: &str,
        auth: &AuthOptions,
        engine: Arc<TransferEngine>,
    ) -> Result<Self> {
        let base_url = url.trim_end_matches('/').to_string();
        let view = auth.view.clone();

        // Parse custom headers.
        let mut headers = Vec::new();
        for h in &auth.headers {
            if let Some((k, v)) = h.split_once(':') {
                headers.push((k.trim().to_string(), v.trim().to_string()));
            }
        }

        let is_aos = auth.token.is_some();

        let mut backend = Self {
            engine,
            base_url,
            view,
            headers,
            is_aos,
        };

        // If we have an AOS token, authenticate to get a JWT.
        if let Some(ref provisioning_token) = auth.token {
            backend.authenticate(provisioning_token).await?;
        }

        Ok(backend)
    }

    async fn authenticate(&mut self, provisioning_token: &str) -> Result<()> {
        let url = format!("{}/oauth2/token", self.base_url);
        let mut req = TransferRequest::put(&url, b"grant_type=client_credentials".to_vec());
        req.headers
            .push(("Content-Type".to_string(), "application/x-www-form-urlencoded".to_string()));
        req.headers
            .push(("Authorization".to_string(), format!("Bearer {provisioning_token}")));

        let result = self
            .engine
            .execute(req)
            .await
            .context("authentication request failed")?;

        if result.status >= 400 {
            let body = result.body_string().unwrap_or_default();
            anyhow::bail!("authentication failed (HTTP {}): {body}", result.status);
        }

        let body = result
            .body
            .ok_or_else(|| anyhow::anyhow!("empty authentication response"))?;
        let token_resp: TokenResponse =
            serde_json::from_slice(&body).context("parsing token response")?;

        // Update the auth store with the JWT.
        let host = url::Url::parse(&self.base_url)
            .ok()
            .and_then(|u| u.host_str().map(|h| h.to_string()));
        if let Some(host) = host {
            self.engine.auth().set(
                &host,
                aos_net::Credential::Bearer {
                    token: token_resp.access_token,
                    refresh: None,
                },
            );
        }

        Ok(())
    }

    fn add_headers(&self, mut req: TransferRequest) -> TransferRequest {
        for (k, v) in &self.headers {
            req.headers.push((k.clone(), v.clone()));
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
        let req = self.add_headers(TransferRequest::head(&url));
        let result = self.engine.execute(req).await?;
        Ok(result.status < 400)
    }

    async fn get_narinfo(&self, store_hash: &str) -> Result<String> {
        let url = self.narinfo_url(store_hash);
        let req = self.add_headers(TransferRequest::get(&url));
        let result = self
            .engine
            .execute(req)
            .await
            .context("fetching narinfo")?;

        result
            .body_string()
            .ok_or_else(|| anyhow::anyhow!("empty narinfo response for {store_hash}"))
    }

    async fn put_narinfo(&self, store_hash: &str, content: &str) -> Result<()> {
        let url = self.narinfo_url(store_hash);
        let mut req = TransferRequest::put(&url, content.as_bytes().to_vec());
        req.headers.push((
            "Content-Type".to_string(),
            "text/x-nix-narinfo".to_string(),
        ));
        let req = self.add_headers(req);
        self.engine
            .execute(req)
            .await
            .context("uploading narinfo")?;
        Ok(())
    }

    async fn get_nar(&self, url: &str) -> Result<Vec<u8>> {
        let full_url = self.nar_url(url);
        let req = self.add_headers(TransferRequest::get(&full_url));
        let result = self
            .engine
            .execute(req)
            .await
            .context("fetching NAR")?;

        result
            .body
            .ok_or_else(|| anyhow::anyhow!("empty NAR response for {url}"))
    }

    async fn put_nar(&self, filename: &str, data: &[u8]) -> Result<()> {
        let url = self.nar_url(&format!("nar/{filename}"));
        let mut req = TransferRequest::put(&url, data.to_vec());
        req.headers.push((
            "Content-Type".to_string(),
            "application/x-nix-nar".to_string(),
        ));
        let req = self.add_headers(req);
        self.engine
            .execute(req)
            .await
            .context("uploading NAR")?;
        Ok(())
    }

    async fn query_missing(&self, store_hashes: &[&str]) -> Result<Vec<String>> {
        if self.is_aos {
            // AOS server has a batch endpoint.
            let url = format!("{}/{}/query-missing", self.base_url, self.view);
            let paths: Vec<String> = store_hashes.iter().map(|h| h.to_string()).collect();
            let body = serde_json::to_vec(&serde_json::json!({ "paths": paths }))?;
            let mut req = TransferRequest::put(&url, body);
            req.method = aos_net::Method::Put; // POST semantics via PUT
            req.headers.push((
                "Content-Type".to_string(),
                "application/json".to_string(),
            ));
            let req = self.add_headers(req);
            let result = self
                .engine
                .execute(req)
                .await
                .context("query-missing request")?;

            let resp_body = result
                .body
                .ok_or_else(|| anyhow::anyhow!("empty query-missing response"))?;
            let parsed: QueryMissingResponse =
                serde_json::from_slice(&resp_body).context("parsing query-missing response")?;
            return Ok(parsed.missing);
        }

        // Generic cache: sequential HEAD requests.
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
        let mut req = TransferRequest::put(&url, data.to_vec());
        req.headers.push((
            "Content-Type".to_string(),
            "application/octet-stream".to_string(),
        ));
        let req = self.add_headers(req);
        let result = self
            .engine
            .execute(req)
            .await
            .context("upload-pack request")?;

        let resp_body = result
            .body
            .ok_or_else(|| anyhow::anyhow!("empty upload-pack response"))?;
        serde_json::from_slice(&resp_body).context("parsing upload-pack response")
    }
}
