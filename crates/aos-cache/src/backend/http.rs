//! HTTP(S) cache backend: generic binary caches and the AOS server API.
//!
//! One backend serves two modes, switched by whether an AOS provisioning
//! token was supplied:
//!
//! - **Generic mode** — plain GET/PUT/HEAD on `<hash>.narinfo` and
//!   `nar/...` URLs, compatible with any Nix binary cache.
//! - **AOS mode** — the provisioning token is exchanged for a JWT at
//!   `/oauth2/token`, and the AOS server API is used: batch
//!   `/query-missing`, `/upload-pack` for batched NAR import, and
//!   server-synthesised narinfo / cache-info (the corresponding client
//!   puts become no-ops).

use std::sync::Arc;

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;

use aos_net::{TransferEngine, TransferRequest};

use super::{AuthOptions, CacheBackend, add_static_metadata_headers};

/// HTTP(S) cache backend.
///
/// For push to AOS server: uses AOS server API (auth, query-missing, upload).
/// For pull from any binary cache: standard GET on narinfo + NAR URLs.
pub struct HttpBackend {
    engine: Arc<TransferEngine>,
    /// Cache base URL without a trailing slash; for AOS servers this
    /// includes the view path (e.g. `http://host:15000/default`).
    base_url: String,
    /// Scheme + host[:port] only — the auth endpoint lives at the root,
    /// not under the view path that `base_url` encodes.
    origin: String,
    /// Extra headers added to every request.
    headers: Vec<(String, String)>,
    /// Whether the target is an AOS server (a provisioning token was
    /// supplied), enabling the AOS-specific API paths.
    is_aos: bool,
}

/// OAuth2 token-endpoint response; only the access token is consumed.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
}

/// Body of the AOS server's `/query-missing` response.
#[derive(Deserialize)]
struct QueryMissingResponse {
    missing: Vec<String>,
}

impl HttpBackend {
    /// Creates a backend for `url`, authenticating against the AOS
    /// server when `auth.token` is set.
    ///
    /// Custom `Name: value` headers from `auth.headers` are parsed once
    /// and attached to every subsequent request.
    ///
    /// # Errors
    ///
    /// Returns an error if an AOS provisioning token is supplied but the
    /// JWT exchange at `/oauth2/token` fails.
    pub async fn new(url: &str, auth: &AuthOptions, engine: Arc<TransferEngine>) -> Result<Self> {
        let base_url = url.trim_end_matches('/').to_string();

        let origin = url::Url::parse(&base_url)
            .ok()
            .and_then(|u| {
                let scheme = u.scheme().to_string();
                let host = u.host_str()?.to_string();
                Some(match u.port() {
                    Some(p) => format!("{scheme}://{host}:{p}"),
                    None => format!("{scheme}://{host}"),
                })
            })
            .unwrap_or_else(|| base_url.clone());

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
            origin,
            headers,
            is_aos,
        };

        // If we have an AOS token, authenticate to get a JWT.
        if let Some(ref provisioning_token) = auth.token {
            backend.authenticate(provisioning_token).await?;
        }

        Ok(backend)
    }

    /// Exchanges an AOS provisioning token for a JWT and stores it as
    /// the host's bearer credential on the engine.
    async fn authenticate(&mut self, provisioning_token: &str) -> Result<()> {
        // `oauth2/token` is a top-level route, NOT view-scoped — use
        // `self.origin`, not `self.base_url` (which already encodes the view).
        let url = format!("{}/oauth2/token", self.origin);
        let mut req = TransferRequest::post(&url, b"grant_type=client_credentials".to_vec());
        req.headers.push((
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        ));
        req.headers.push((
            "Authorization".to_string(),
            format!("Bearer {provisioning_token}"),
        ));

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

    /// Appends the backend's extra headers to a request.
    fn add_headers(&self, mut req: TransferRequest) -> TransferRequest {
        for (k, v) in &self.headers {
            req.headers.push((k.clone(), v.clone()));
        }
        req
    }

    // `base_url` already encodes the view (e.g. `http://host:15000/default`);
    // callers MUST NOT append `self.view` a second time.
    fn narinfo_url(&self, store_hash: &str) -> String {
        format!("{}/{}.narinfo", self.base_url, store_hash)
    }

    fn cache_info_url(&self) -> String {
        format!("{}/nix-cache-info", self.base_url)
    }

    fn nar_url(&self, url: &str) -> String {
        format!("{}/{}", self.base_url, url)
    }

    fn static_file_url(&self, relative_path: &str) -> String {
        format!(
            "{}/{}",
            self.base_url,
            relative_path.trim_start_matches('/')
        )
    }
}

#[async_trait]
impl CacheBackend for HttpBackend {
    async fn exists(&self, relative_path: &str) -> Result<bool> {
        let url = self.static_file_url(relative_path);
        let req = self.add_headers(TransferRequest::head(&url));
        let result = self.engine.execute(req).await?;
        Ok(result.status < 400)
    }

    async fn has_narinfo(&self, store_hash: &str) -> Result<bool> {
        let url = self.narinfo_url(store_hash);
        let req = self.add_headers(TransferRequest::head(&url));
        let result = self.engine.execute(req).await?;
        Ok(result.status < 400)
    }

    async fn get_narinfo(&self, store_hash: &str) -> Result<String> {
        let url = self.narinfo_url(store_hash);
        let req = self.add_headers(TransferRequest::get(&url));
        let result = self.engine.execute(req).await.context("fetching narinfo")?;

        result
            .body_string()
            .ok_or_else(|| anyhow::anyhow!("empty narinfo response for {store_hash}"))
    }

    async fn put_narinfo(&self, store_hash: &str, content: &str) -> Result<()> {
        if self.is_aos {
            // AOS servers generate narinfo on demand from the ValidPaths DB
            // (see `narinfo_handler` in aos-server/src/routes.rs:155-219).
            // There is no PUT-narinfo route — uploading a NAR via
            // `PUT /{view}/store/{hash}` or `POST /{view}/upload-pack`
            // registers the path and the narinfo becomes synthesisable.
            let _ = (store_hash, content);
            return Ok(());
        }
        let url = self.narinfo_url(store_hash);
        let mut req = TransferRequest::put(&url, content.as_bytes().to_vec());
        req.headers
            .push(("Content-Type".to_string(), "text/x-nix-narinfo".to_string()));
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
        let result = self.engine.execute(req).await.context("fetching NAR")?;

        result
            .body
            .ok_or_else(|| anyhow::anyhow!("empty NAR response for {url}"))
    }

    async fn put_nar(&self, filename: &str, data: &[u8]) -> Result<()> {
        // TODO(aos-cache push >1MB): when is_aos == true, this path is
        // broken on two axes:
        //   1. URL: PUT goes to {base_url}/nar/{filename}, but the
        //      server's only PUT route is /{view}/store/{hash}
        //      (aos-server/src/routes.rs). 405.
        //   2. Body: the server pipes `body` into `nix-store --import`,
        //      which expects (raw NAR + ExportTrailer), not compressed
        //      NAR. See `streaming_import` in aos-cache/src/compress.rs
        //      for the inverse format.
        // Untriggered in-tree under default `--batch-threshold 1MB`.
        // Fixing properly needs either a new server route accepting
        // compressed .nar.zst + metadata, or a client refactor to emit
        // uncompressed NAR + trailer. A cross-failing test in
        // tests/fleet/apm-e2e.nix (`step 3.9`) guards the eventual fix.
        let url = self.nar_url(&format!("nar/{filename}"));
        let mut req = TransferRequest::put(&url, data.to_vec());
        req.headers.push((
            "Content-Type".to_string(),
            "application/x-nix-nar".to_string(),
        ));
        let req = self.add_headers(req);
        self.engine.execute(req).await.context("uploading NAR")?;
        Ok(())
    }

    async fn query_missing(&self, store_hashes: &[&str]) -> Result<Vec<String>> {
        if self.is_aos {
            // AOS server has a batch endpoint.
            let url = format!("{}/query-missing", self.base_url);
            let paths: Vec<String> = store_hashes.iter().map(|h| h.to_string()).collect();
            let body = serde_json::to_vec(&serde_json::json!({ "paths": paths }))?;
            let mut req = TransferRequest::post(&url, body);
            req.headers
                .push(("Content-Type".to_string(), "application/json".to_string()));
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

    async fn put_cache_info(&self, content: &str) -> Result<()> {
        if self.is_aos {
            // AOS server cache-info is served dynamically from the view.
            let _ = content;
            return Ok(());
        }
        let url = self.cache_info_url();
        let mut req = TransferRequest::put(&url, content.as_bytes().to_vec());
        req.headers
            .push(("Content-Type".to_string(), "text/plain".to_string()));
        let req = self.add_headers(req);
        let result = self
            .engine
            .execute(req)
            .await
            .context("uploading nix-cache-info")?;
        if result.status >= 400 {
            anyhow::bail!(
                "uploading nix-cache-info failed with HTTP {}",
                result.status
            );
        }
        Ok(())
    }

    async fn put_static_file(
        &self,
        relative_path: &str,
        source: &std::path::Path,
        content_type: Option<&str>,
        cache_control: Option<&str>,
    ) -> Result<()> {
        if self.is_aos {
            anyhow::bail!("generic static-file upload is not supported by the AOS server API");
        }
        let url = self.static_file_url(relative_path);
        let mut req = TransferRequest::put_file(&url, source.to_path_buf());
        add_static_metadata_headers(&mut req, content_type, cache_control);
        let req = self.add_headers(req);
        let result = self
            .engine
            .execute(req)
            .await
            .with_context(|| format!("uploading static file {url}"))?;
        if result.status >= 400 {
            anyhow::bail!(
                "uploading static file {url} failed with HTTP {}",
                result.status
            );
        }
        Ok(())
    }

    fn supports_pack(&self) -> bool {
        self.is_aos
    }

    async fn upload_pack(&self, data: &[u8]) -> Result<Vec<String>> {
        let url = format!("{}/upload-pack", self.base_url);
        let mut req = TransferRequest::post(&url, data.to_vec());
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
        // Server wraps the imported paths in
        // `{accepted, rejected, paths}` (aos-server/src/routes.rs's
        // `upload_pack_handler`). Extract just the `paths` array; the
        // counts are tracing-only metadata.
        #[derive(serde::Deserialize)]
        struct UploadPackResponse {
            paths: Vec<String>,
        }
        let parsed: UploadPackResponse =
            serde_json::from_slice(&resp_body).context("parsing upload-pack response")?;
        Ok(parsed.paths)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::backend::AuthOptions;
    use aos_net::TransferEngineConfig;

    async fn make_backend(base_url: &str) -> HttpBackend {
        let engine = Arc::new(TransferEngine::new(TransferEngineConfig::default()));
        let auth = AuthOptions {
            view: "default".to_string(),
            ..Default::default()
        };
        HttpBackend::new(base_url, &auth, engine).await.unwrap()
    }

    #[tokio::test]
    async fn origin_strips_view_path() {
        let backend = make_backend("http://127.0.0.1:15000/default").await;
        assert_eq!(backend.origin, "http://127.0.0.1:15000");
    }

    #[tokio::test]
    async fn narinfo_url_does_not_double_view() {
        let backend = make_backend("http://127.0.0.1:15000/default").await;
        assert_eq!(
            backend.narinfo_url("abc"),
            "http://127.0.0.1:15000/default/abc.narinfo"
        );
    }

    #[tokio::test]
    async fn nar_url_does_not_double_view() {
        let backend = make_backend("http://127.0.0.1:15000/default").await;
        assert_eq!(
            backend.nar_url("nar/x.nar.zst"),
            "http://127.0.0.1:15000/default/nar/x.nar.zst"
        );
    }
}
