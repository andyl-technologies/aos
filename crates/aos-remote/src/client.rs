//! ConnectRPC client for communicating with the AOS cache server.
//!
//! This module replaces the REST+SSE client in `build.rs` and `sse.rs`
//! with a typed ConnectRPC client backed by the proto definitions in
//! `aos-proto`. The old `RemoteClient` and `SseStream` are preserved
//! for backward compatibility but are deprecated.

use std::time::Duration;

use anyhow::{Context, Result};
use connectrpc::client::{ClientConfig, HttpClient};

use aos_proto::aos::auth::v1::*;
use aos_proto::aos::build::v1::*;
use aos_proto::aos::cache::v1::*;
use aos_proto::aos::gc::v1::*;

/// Typed ConnectRPC client for the AOS server.
///
/// Provides access to all four services: cache, build, GC, and auth.
/// Replaces the ad-hoc REST client in `build.rs`.
pub struct AosClient {
    cache: CacheServiceClient<HttpClient>,
    build_svc: BuildServiceClient<HttpClient>,
    gc: GcServiceClient<HttpClient>,
    auth: AuthServiceClient<HttpClient>,
    /// The view name for all requests.
    view: String,
}

impl AosClient {
    /// Connect to an AOS server and authenticate with the given
    /// provisioning token.
    ///
    /// This exchanges the provisioning token for a JWT access token
    /// via `AuthService.GetToken`, then configures all service clients
    /// with the JWT as a default `authorization` header.
    pub async fn connect(base_url: &str, view: &str, provisioning_token: &str) -> Result<Self> {
        let http = HttpClient::plaintext();
        let base_uri = base_url
            .parse()
            .context("invalid base URL")?;

        // First, get a JWT token via the auth service (unauthenticated call).
        let initial_config = ClientConfig::new(base_uri)
            .default_timeout(Duration::from_secs(30));
        let auth_client = AuthServiceClient::new(http.clone(), initial_config);

        let token_resp = auth_client
            .get_token(TokenRequest {
                provisioning_token: provisioning_token.into(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("authentication failed: {e}"))?;

        let access_token: String = token_resp.into_owned().access_token;

        // Build authenticated config for all service clients.
        let base_uri2 = base_url.parse().context("invalid base URL")?;
        let config = ClientConfig::new(base_uri2)
            .default_timeout(Duration::from_secs(300))
            .default_header("authorization", format!("Bearer {access_token}"));

        Ok(Self {
            cache: CacheServiceClient::new(http.clone(), config.clone()),
            build_svc: BuildServiceClient::new(http.clone(), config.clone()),
            gc: GcServiceClient::new(http.clone(), config.clone()),
            auth: AuthServiceClient::new(http, config),
            view: view.to_string(),
        })
    }

    /// Connect with an existing JWT token (skip authentication step).
    pub fn connect_with_token(base_url: &str, view: &str, jwt_token: &str) -> Result<Self> {
        let http = HttpClient::plaintext();
        let base_uri = base_url
            .parse()
            .context("invalid base URL")?;

        let config = ClientConfig::new(base_uri)
            .default_timeout(Duration::from_secs(300))
            .default_header("authorization", format!("Bearer {jwt_token}"));

        Ok(Self {
            cache: CacheServiceClient::new(http.clone(), config.clone()),
            build_svc: BuildServiceClient::new(http.clone(), config.clone()),
            gc: GcServiceClient::new(http.clone(), config.clone()),
            auth: AuthServiceClient::new(http, config),
            view: view.to_string(),
        })
    }

    // -----------------------------------------------------------------------
    // Cache operations
    // -----------------------------------------------------------------------

    /// Fetch the cache info for the configured view.
    pub async fn get_cache_info(&self) -> Result<CacheInfo> {
        let resp = self
            .cache
            .get_cache_info(GetCacheInfoRequest {
                view: self.view.clone(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("get_cache_info failed: {e}"))?;

        Ok(resp.into_owned())
    }

    /// Fetch narinfo for a store path hash.
    pub async fn get_nar_info(&self, store_hash: &str) -> Result<NarInfo> {
        let resp = self
            .cache
            .get_nar_info(GetNarInfoRequest {
                view: self.view.clone(),
                store_hash: store_hash.into(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("get_nar_info failed: {e}"))?;

        Ok(resp.into_owned())
    }

    /// Query which store paths are missing on the server.
    pub async fn query_missing(&self, store_paths: &[String]) -> Result<Vec<String>> {
        let resp = self
            .cache
            .query_missing(QueryMissingRequest {
                view: self.view.clone(),
                store_paths: store_paths.to_vec(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("query_missing failed: {e}"))?;

        Ok(resp.into_owned().missing)
    }

    /// Upload a single store path as a NAR export via client streaming.
    pub async fn upload(&self, store_hash: &str, nar_data: &[u8]) -> Result<String> {
        const CHUNK_SIZE: usize = 5 * 1024 * 1024; // 5 MB

        let mut chunks = Vec::new();
        let mut offset = 0usize;

        while offset < nar_data.len() {
            let end = std::cmp::min(offset + CHUNK_SIZE, nar_data.len());
            let is_final = end == nar_data.len();

            chunks.push(UploadChunk {
                view: self.view.clone(),
                store_hash: store_hash.into(),
                data: nar_data[offset..end].to_vec(),
                offset: offset as i64,
                is_final,
                ..Default::default()
            });

            offset = end;
        }

        let resp = self
            .cache
            .upload(chunks)
            .await
            .map_err(|e| anyhow::anyhow!("upload failed: {e}"))?;

        Ok(resp.into_owned().store_path)
    }

    /// Download a NAR file via server streaming.
    pub async fn download(&self, filename: &str) -> Result<Vec<u8>> {
        let mut stream = self
            .cache
            .download(DownloadRequest {
                view: self.view.clone(),
                filename: filename.into(),
                offset: 0,
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("download failed: {e}"))?;

        let mut all_data = Vec::new();
        while let Some(chunk) = stream
            .message()
            .await
            .map_err(|e| anyhow::anyhow!("download stream error: {e}"))?
        {
            let data: &[u8] = chunk.data;
            all_data.extend_from_slice(data);
        }

        Ok(all_data)
    }

    /// Upload a pack of multiple store paths via client streaming.
    pub async fn upload_pack(&self, pack_data: &[u8]) -> Result<Vec<String>> {
        const CHUNK_SIZE: usize = 5 * 1024 * 1024;

        let mut chunks = Vec::new();
        let mut offset = 0usize;

        while offset < pack_data.len() {
            let end = std::cmp::min(offset + CHUNK_SIZE, pack_data.len());
            let is_final = end == pack_data.len();

            chunks.push(PackChunk {
                view: self.view.clone(),
                data: pack_data[offset..end].to_vec(),
                is_final,
                ..Default::default()
            });

            offset = end;
        }

        let resp = self
            .cache
            .upload_pack(chunks)
            .await
            .map_err(|e| anyhow::anyhow!("upload_pack failed: {e}"))?;

        Ok(resp.into_owned().paths)
    }

    // -----------------------------------------------------------------------
    // Build operations
    // -----------------------------------------------------------------------

    /// Trigger a remote build and return a stream of build events.
    ///
    /// This replaces the SSE-based `RemoteClient.build()` method.
    /// The callback receives each `BuildEvent` and returns `true` to
    /// continue or `false` to stop.
    pub async fn build(
        &self,
        drv_path: &str,
        mut on_event: impl FnMut(&BuildEvent) -> bool,
    ) -> Result<()> {
        let mut stream = self
            .build_svc
            .build(BuildRequest {
                view: self.view.clone(),
                derivation: drv_path.into(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("build RPC failed: {e}"))?;

        while let Some(event) = stream
            .message()
            .await
            .map_err(|e| anyhow::anyhow!("build stream error: {e}"))?
        {
            // event is OwnedView<BuildEventView>, which derefs to BuildEventView.
            // Convert to owned for the callback.
            let owned: BuildEvent = event.to_owned_message();
            let should_continue = on_event(&owned);
            if !should_continue {
                break;
            }
        }

        Ok(())
    }

    /// Trigger a closure build (multiple derivations) and stream events.
    ///
    /// This replaces the SSE-based `RemoteClient.build_closure()` method.
    pub async fn build_closure(
        &self,
        drvs: &[String],
        mut on_event: impl FnMut(&BuildEvent) -> bool,
    ) -> Result<()> {
        let mut stream = self
            .build_svc
            .build_closure(ClosureRequest {
                view: self.view.clone(),
                derivations: drvs.to_vec(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("build_closure RPC failed: {e}"))?;

        while let Some(event) = stream
            .message()
            .await
            .map_err(|e| anyhow::anyhow!("build_closure stream error: {e}"))?
        {
            let owned: BuildEvent = event.to_owned_message();
            let should_continue = on_event(&owned);
            if !should_continue {
                break;
            }
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // GC operations
    // -----------------------------------------------------------------------

    /// Trigger garbage collection on the server.
    pub async fn gc(
        &self,
        dry_run: bool,
        collect_store: bool,
        max_size: Option<u64>,
    ) -> Result<GcResponse> {
        let resp = self
            .gc
            .collect(GcRequest {
                view: self.view.clone(),
                dry_run,
                collect_store,
                max_size,
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("gc failed: {e}"))?;

        Ok(resp.into_owned())
    }

    // -----------------------------------------------------------------------
    // Auth operations
    // -----------------------------------------------------------------------

    /// Exchange a provisioning token for a JWT access token.
    pub async fn get_token(&self, provisioning_token: &str) -> Result<TokenResponse> {
        let resp = self
            .auth
            .get_token(TokenRequest {
                provisioning_token: provisioning_token.into(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("get_token failed: {e}"))?;

        Ok(resp.into_owned())
    }
}
