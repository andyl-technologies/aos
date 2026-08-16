//! HTTP(S) cache backend: generic binary caches and the AOS server API.
//!
//! One backend serves three negotiated modes:
//!
//! - **Generic mode** — plain GET/PUT/HEAD on `<hash>.narinfo` and
//!   `nar/...` URLs, compatible with any Nix binary cache.
//! - **AOS server mode** — the provisioning token is exchanged for a JWT at
//!   `/oauth2/token`, and the older standalone server API is used: batch
//!   `/query-missing`, `/upload-pack` for batched NAR import, and
//!   server-synthesised narinfo / cache-info (the corresponding client
//!   puts become no-ops).
//! - **Hub mode** — token capabilities or successful typed admission select
//!   `CreateCacheObjectUploads` plus typed multipart. No consumer delivery URL
//!   is used as an upload endpoint.

use std::{
    fs::File,
    io::Read as _,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use sha2::Digest as _;

use aos_net::{TransferEngine, TransferRequest};

use super::{
    AuthOptions, CacheBackend, IMMUTABLE_CACHE_CONTROL, MUTABLE_CACHE_CONTROL,
    add_static_metadata_headers,
};

/// Marks a request as Connect-JSON before it reaches the Hub control plane.
fn add_connect_json_headers(req: &mut TransferRequest) {
    req.headers
        .push(("Content-Type".to_string(), "application/json".to_string()));
    req.headers
        .push(("Connect-Protocol-Version".to_string(), "1".to_string()));
}

/// Encodes a 64-bit integer using the protobuf JSON wire representation.
fn connect_json_u64(value: u64) -> String {
    value.to_string()
}

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
    /// Whether the authenticated target speaks the AOS API.
    is_aos: bool,
    /// Whether authentication or typed upload admission identified the Hub API.
    is_hub: AtomicBool,
    /// Whether authentication or typed upload admission enabled multipart upload v1.
    multipart_v1: AtomicBool,
}

/// OAuth2 token-endpoint response, including explicitly negotiated features.
#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default)]
    capabilities: Vec<String>,
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
            is_hub: AtomicBool::new(false),
            multipart_v1: AtomicBool::new(false),
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
        let mut req = TransferRequest::post(
            &url,
            b"grant_type=urn%3Aaos%3Aparams%3Aoauth%3Agrant-type%3Aprovisioning-token".to_vec(),
        );
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
        self.multipart_v1.store(
            token_resp
                .capabilities
                .iter()
                .any(|capability| capability == "aos.multipart.v1"),
            Ordering::Relaxed,
        );
        self.is_hub.store(
            token_resp
                .capabilities
                .iter()
                .any(|capability| capability == "aos.hub.topology.v1"),
            Ordering::Relaxed,
        );

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

    async fn static_file_identity(
        &self,
        relative_path: &str,
    ) -> Result<Option<super::StaticFileIdentity>> {
        let url = self.static_file_url(relative_path);
        // Integrity headers on HEAD may merely echo uploader-controlled object
        // metadata. Read the representation itself and hash those exact bytes
        // before allowing publication to reuse a remote image object.
        let snapshot = tempfile::NamedTempFile::new().context("creating static readback file")?;
        let req = self.add_headers(TransferRequest::get_to_file(
            &url,
            snapshot.path().to_path_buf(),
        ));
        let result = self.engine.execute(req).await?;
        if result.status == 404 {
            return Ok(None);
        }
        if result.status >= 400 {
            anyhow::bail!(
                "probing static file {url} failed with HTTP {}",
                result.status
            );
        }
        let mut file =
            std::fs::File::open(snapshot.path()).context("opening static readback file")?;
        let mut hasher = sha2::Sha256::new();
        let mut byte_size = 0_u64;
        let mut buffer = [0_u8; 128 * 1024];
        loop {
            let count = file.read(&mut buffer).context("reading static readback")?;
            if count == 0 {
                break;
            }
            byte_size = byte_size
                .checked_add(count as u64)
                .context("static readback size overflow")?;
            hasher.update(&buffer[..count]);
        }
        Ok(Some(super::StaticFileIdentity {
            byte_size,
            sha256: hex::encode(hasher.finalize()),
        }))
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
        if self.is_hub.load(Ordering::Relaxed) {
            let path = format!("{store_hash}.narinfo");
            let upload_url = self
                .create_object_upload(&path, content.len() as u64)
                .await?
                .context("Hub did not admit the narinfo upload")?;
            return self
                .upload_to_admitted_url(&upload_url, content.as_bytes())
                .await;
        }
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
        // narinfos are rewritten in place (e.g. re-signed on key rotation), so
        // they must stay revalidatable rather than be cached as immutable.
        add_static_metadata_headers(
            &mut req,
            Some("text/x-nix-narinfo"),
            Some(MUTABLE_CACHE_CONTROL),
            None,
            None,
        );
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
        if self.is_hub.load(Ordering::Relaxed) {
            let path = format!("nar/{filename}");
            return match self.create_object_upload(&path, data.len() as u64).await? {
                Some(upload_url) => self.upload_to_admitted_url(&upload_url, data).await,
                None if self.supports_multipart() => {
                    crate::push::upload_nar_multipart(self, filename, data).await
                }
                None => anyhow::bail!("Hub requires unsupported multipart for this NAR upload"),
            };
        }
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
        // NAR archives are content-addressed by the hash embedded in their
        // filename, so the bytes behind a URL never change: cache immutably.
        add_static_metadata_headers(
            &mut req,
            Some("application/x-nix-nar"),
            Some(IMMUTABLE_CACHE_CONTROL),
            None,
            None,
        );
        let req = self.add_headers(req);
        self.engine.execute(req).await.context("uploading NAR")?;
        Ok(())
    }

    async fn create_object_upload(&self, path: &str, size: u64) -> Result<Option<String>> {
        // Only attempt against an authenticated AOS Hub: a provisioning-token
        // backend (`is_aos`) or one carrying an explicit `Authorization` header.
        // An unauthenticated plain-HTTP cache cannot request admission, so skip the RPC.
        let has_auth = self.is_aos
            || self
                .headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("authorization"));
        if !has_auth {
            return Ok(None);
        }
        // `CreateCacheObjectUploads` lives at the root (Connect-JSON), not
        // under the view path.
        let url = format!(
            "{}/aos.hub.v1.BinaryCacheService/CreateCacheObjectUploads",
            self.origin
        );
        // Connect-JSON uses the protobuf JSON mapping (camelCase field names).
        let body = serde_json::json!({
            "deliveryUrl": self.base_url,
            "path": path,
            "size": connect_json_u64(size)
        })
        .to_string();
        let mut req = TransferRequest::post(&url, body.into_bytes());
        add_connect_json_headers(&mut req);
        let req = self.add_headers(req);
        let result = self.engine.execute(req).await?;
        anyhow::ensure!(
            result.status < 400,
            "creating cache object upload failed with HTTP {}",
            result.status
        );
        // A successful typed admission is also the capability probe for
        // callers that supplied an already-minted Authorization header and
        // therefore did not use the provisioning-token exchange.
        self.is_hub.store(true, Ordering::Relaxed);
        self.multipart_v1.store(true, Ordering::Relaxed);
        let url = result
            .body
            .as_deref()
            .and_then(|body| {
                #[derive(Deserialize)]
                struct MintResponse {
                    #[serde(default, rename = "uploadUrl")]
                    upload_url: String,
                }
                serde_json::from_slice::<MintResponse>(body).ok()
            })
            .map(|resp| resp.upload_url)
            .filter(|u| !u.is_empty());
        Ok(url)
    }

    async fn upload_to_admitted_url(&self, url: &str, data: &[u8]) -> Result<()> {
        // Direct-origin URLs embed SigV4 authorization. Typed Hub-proxy URLs
        // stay on the Hub control origin and require the caller's normal auth.
        let req = TransferRequest::put(url, data.to_vec());
        let req = if url.starts_with(&format!(
            "{}/aos.hub.v1.BinaryCacheService/UploadObject/",
            self.origin
        )) {
            self.add_headers(req)
        } else {
            req
        };
        let result = self
            .engine
            .execute(req)
            .await
            .context("uploading NAR to presigned URL")?;
        if result.status >= 400 {
            anyhow::bail!(
                "presigned upload failed (HTTP {}): {}",
                result.status,
                result.body_string().unwrap_or_default()
            );
        }
        Ok(())
    }

    async fn create_object_uploads(
        &self,
        uploads: &[(String, u64)],
    ) -> Result<std::collections::HashMap<String, String>> {
        let empty = std::collections::HashMap::new();
        if uploads.is_empty() {
            return Ok(empty);
        }
        let has_auth = self.is_aos
            || self
                .headers
                .iter()
                .any(|(k, _)| k.eq_ignore_ascii_case("authorization"));
        if !has_auth {
            return Ok(empty);
        }
        let url = format!(
            "{}/aos.hub.v1.BinaryCacheService/CreateCacheObjectUploads",
            self.origin
        );
        let paths: Vec<&str> = uploads.iter().map(|(path, _)| path.as_str()).collect();
        let sizes: Vec<String> = uploads
            .iter()
            .map(|(_, size)| connect_json_u64(*size))
            .collect();
        let body = serde_json::json!({
            "deliveryUrl": self.base_url,
            "paths": paths,
            "sizes": sizes
        })
        .to_string();
        let mut req = TransferRequest::post(&url, body.into_bytes());
        add_connect_json_headers(&mut req);
        let req = self.add_headers(req);
        let result = self.engine.execute(req).await?;
        anyhow::ensure!(
            result.status < 400,
            "creating cache object uploads failed with HTTP {}",
            result.status
        );
        self.is_hub.store(true, Ordering::Relaxed);
        self.multipart_v1.store(true, Ordering::Relaxed);
        let Some(body) = result.body else {
            return Ok(empty);
        };
        #[derive(Deserialize)]
        struct Upload {
            #[serde(default)]
            path: String,
            #[serde(default, rename = "uploadUrl")]
            upload_url: String,
        }
        #[derive(Deserialize)]
        struct Resp {
            #[serde(default)]
            uploads: Vec<Upload>,
        }
        let resp: Resp =
            serde_json::from_slice(&body).context("parsing batch mint-credentials response")?;
        let map: std::collections::HashMap<String, String> = resp
            .uploads
            .into_iter()
            .filter(|u| !u.upload_url.is_empty())
            .map(|u| (u.path, u.upload_url))
            .collect();
        Ok(map)
    }

    async fn register_narinfos(&self, narinfos: &[(String, String)]) -> Result<()> {
        if narinfos.is_empty() {
            return Ok(());
        }
        if self.is_aos && !self.is_hub.load(Ordering::Relaxed) {
            // AOS pack-mode servers synthesise narinfo from registered paths.
            return Ok(());
        }
        for (store_hash, content) in narinfos {
            self.put_narinfo(store_hash, content).await?;
        }
        Ok(())
    }

    fn supports_multipart(&self) -> bool {
        self.multipart_v1.load(Ordering::Relaxed)
    }

    async fn initiate_multipart(
        &self,
        nar_path: &str,
        size: u64,
        sha256: Option<&str>,
    ) -> Result<(String, u64)> {
        let url = format!(
            "{}/aos.hub.v1.BinaryCacheService/BeginCacheMultipartUpload",
            self.origin
        );
        let body = serde_json::json!({
            "deliveryUrl": self.base_url,
            "path": nar_path,
            "byteSize": connect_json_u64(size),
            "sha256": sha256.unwrap_or_default(),
        });
        let mut req = TransferRequest::post(&url, serde_json::to_vec(&body)?);
        req.headers
            .push(("Content-Type".to_string(), "application/json".to_string()));
        let req = self.add_headers(req);
        let result = self
            .engine
            .execute(req)
            .await
            .context("initiating multipart upload")?;
        if result.status >= 400 {
            anyhow::bail!(
                "initiate multipart upload: HTTP {} for {nar_path}",
                result.status
            );
        }
        let body = result
            .body
            .ok_or_else(|| anyhow::anyhow!("empty initiate-multipart response"))?;
        #[derive(serde::Deserialize)]
        struct InitiateResp {
            #[serde(rename = "uploadId")]
            upload_id: String,
            #[serde(rename = "partSize")]
            part_size: u64,
        }
        let resp: InitiateResp =
            serde_json::from_slice(&body).context("parsing initiate-multipart response")?;
        Ok((resp.upload_id, resp.part_size))
    }

    async fn upload_part(
        &self,
        nar_path: &str,
        upload_id: &str,
        part_number: u32,
        data: &[u8],
    ) -> Result<(u32, String)> {
        let _ = nar_path;
        let url = format!(
            "{}/aos.hub.v1.BinaryCacheService/UploadPart/{upload_id}/{part_number}",
            self.origin
        );
        let mut req = TransferRequest::put(&url, data.to_vec());
        add_static_metadata_headers(&mut req, Some("application/x-nix-nar"), None, None, None);
        let req = self.add_headers(req);
        let result = self
            .engine
            .execute(req)
            .await
            .context("uploading multipart part")?;
        if result.status >= 400 {
            anyhow::bail!(
                "upload multipart part {part_number}: HTTP {} for {nar_path}",
                result.status
            );
        }
        let body = result
            .body
            .ok_or_else(|| anyhow::anyhow!("empty upload-part response"))?;
        #[derive(serde::Deserialize)]
        struct PartResp {
            #[serde(rename = "partNumber")]
            part_number: u32,
            etag: String,
        }
        let resp: PartResp =
            serde_json::from_slice(&body).context("parsing upload-part response")?;
        Ok((resp.part_number, resp.etag))
    }

    async fn complete_multipart(
        &self,
        nar_path: &str,
        upload_id: &str,
        parts: &[(u32, String)],
    ) -> Result<()> {
        let url = format!(
            "{}/aos.hub.v1.BinaryCacheService/CompleteCacheMultipartUpload",
            self.origin
        );
        let _ = nar_path;
        let payload = serde_json::to_vec(&serde_json::json!({
            "uploadId": upload_id,
            "parts": parts.iter().map(|(number, etag)| serde_json::json!({
                "partNumber": number,
                "etag": etag,
            })).collect::<Vec<_>>(),
        }))?;
        let mut req = TransferRequest::post(&url, payload);
        req.headers
            .push(("Content-Type".to_string(), "application/json".to_string()));
        let req = self.add_headers(req);
        let result = self
            .engine
            .execute(req)
            .await
            .context("completing multipart upload")?;
        if result.status >= 400 {
            anyhow::bail!(
                "complete multipart upload: HTTP {} for {nar_path}",
                result.status
            );
        }
        Ok(())
    }

    async fn abort_multipart(&self, nar_path: &str, upload_id: &str) -> Result<()> {
        let _ = nar_path;
        let url = format!(
            "{}/aos.hub.v1.BinaryCacheService/AbortCacheMultipartUpload",
            self.origin
        );
        let mut req = TransferRequest::post(
            &url,
            serde_json::to_vec(&serde_json::json!({ "uploadId": upload_id }))?,
        );
        req.headers
            .push(("Content-Type".to_string(), "application/json".to_string()));
        let req = self.add_headers(req);
        let result = self
            .engine
            .execute(req)
            .await
            .context("aborting multipart upload")?;
        if result.status >= 400 && result.status != 404 {
            anyhow::bail!(
                "abort multipart upload: HTTP {} for {nar_path}",
                result.status
            );
        }
        Ok(())
    }

    async fn query_missing(&self, store_hashes: &[&str]) -> Result<Vec<String>> {
        if self.is_aos && !self.is_hub.load(Ordering::Relaxed) {
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
        // The cache marker is rewritten in place (e.g. Priority changes), so
        // keep it revalidatable rather than long-lived.
        add_static_metadata_headers(
            &mut req,
            Some("text/plain"),
            Some(MUTABLE_CACHE_CONTROL),
            None,
            None,
        );
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
        content_disposition: Option<&str>,
        sha256: Option<&str>,
    ) -> Result<()> {
        const MULTIPART_THRESHOLD: u64 = 16 * 1024 * 1024;
        let size = std::fs::metadata(source)
            .with_context(|| format!("stat static file {}", source.display()))?
            .len();
        // A caller may provide a previously minted Authorization header rather
        // than a provisioning token. Typed admission discovers the Hub before
        // choosing between direct and multipart delivery.
        let admitted_url = if self.is_hub.load(Ordering::Relaxed) {
            None
        } else if self
            .headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("authorization"))
        {
            self.create_object_upload(relative_path, size).await?
        } else {
            None
        };
        if self.is_hub.load(Ordering::Relaxed) && size > MULTIPART_THRESHOLD {
            if !self.supports_multipart() {
                anyhow::bail!(
                    "AOS server did not negotiate multipart support for large static file {relative_path}"
                );
            }
            let (upload_id, part_size) =
                self.initiate_multipart(relative_path, size, sha256).await?;
            let upload = async {
                let part_size = usize::try_from(part_size)
                    .context("multipart part size exceeds local address space")?;
                anyhow::ensure!(
                    (5 * 1024 * 1024..=16 * 1024 * 1024).contains(&part_size),
                    "AOS server returned an unsafe multipart part size"
                );
                let mut file = File::open(source)
                    .with_context(|| format!("opening static file {}", source.display()))?;
                let mut parts = Vec::new();
                let mut part_number = 1_u32;
                loop {
                    let mut bytes = vec![0_u8; part_size];
                    let mut filled = 0;
                    while filled < bytes.len() {
                        let count = file.read(&mut bytes[filled..])?;
                        if count == 0 {
                            break;
                        }
                        filled += count;
                    }
                    if filled == 0 {
                        break;
                    }
                    bytes.truncate(filled);
                    parts.push(
                        self.upload_part(relative_path, &upload_id, part_number, &bytes)
                            .await?,
                    );
                    part_number = part_number
                        .checked_add(1)
                        .context("static-file multipart part count overflow")?;
                    anyhow::ensure!(
                        part_number <= 10_001,
                        "static-file multipart exceeds 10,000 parts"
                    );
                }
                self.complete_multipart(relative_path, &upload_id, &parts)
                    .await
            }
            .await;
            if let Err(error) = upload {
                let abort = self.abort_multipart(relative_path, &upload_id).await;
                if let Err(abort_error) = abort {
                    return Err(error).context(format!(
                        "multipart static upload failed; abort also failed: {abort_error:#}"
                    ));
                }
                return Err(error);
            }
            return Ok(());
        }
        if self.is_hub.load(Ordering::Relaxed) {
            let bytes = std::fs::read(source)
                .with_context(|| format!("reading static file {}", source.display()))?;
            let upload_url = match admitted_url {
                Some(url) => url,
                None => self
                    .create_object_upload(relative_path, size)
                    .await?
                    .context("Hub did not admit the static-file upload")?,
            };
            return self.upload_to_admitted_url(&upload_url, &bytes).await;
        }
        let url = self.static_file_url(relative_path);
        let mut req = TransferRequest::put_file(&url, source.to_path_buf());
        add_static_metadata_headers(
            &mut req,
            content_type,
            cache_control,
            content_disposition,
            sha256,
        );
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
        self.is_aos && !self.is_hub.load(Ordering::Relaxed)
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

    #[test]
    fn connect_json_requests_carry_protocol_version() {
        let mut request = TransferRequest::post("https://hub.example/rpc", Vec::new());
        add_connect_json_headers(&mut request);

        assert!(request.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("content-type") && value == "application/json"
        }));
        assert!(request.headers.iter().any(|(name, value)| {
            name.eq_ignore_ascii_case("connect-protocol-version") && value == "1"
        }));
    }

    #[test]
    fn connect_json_encodes_u64_values_as_decimal_strings() {
        let size = u64::MAX;
        let single = serde_json::json!({ "size": connect_json_u64(size) });
        let batch = serde_json::json!({ "sizes": [connect_json_u64(size)] });

        assert_eq!(single["size"], size.to_string());
        assert_eq!(batch["sizes"][0], size.to_string());
    }
}
