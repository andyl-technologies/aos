//! ConnectRPC client for communicating with the AOS cache server.
//!
//! Defines [`AosClient`], a typed ConnectRPC client backed by the proto
//! definitions in `aos-proto`. It provides access to all four server
//! services: cache, build, GC, and auth. A client is scoped to a single
//! *view* (a named slice of the server's store); the view name is sent
//! with every request.
//!
//! Connections use HTTP/2 with TLS for `https://` URLs (trusting the
//! platform certificate store, with the bundled webpki roots as a
//! fallback) and plaintext for `http://`. All user-supplied identifiers
//! (view names, store hashes, filenames) are validated locally before
//! being sent, primarily to reject path-traversal sequences.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use connectrpc::client::{ClientConfig, HttpClient};
use connectrpc::rustls;
use http::Uri;

use aos_proto::aos::auth::v1::*;
use aos_proto::aos::build::v1::*;
use aos_proto::aos::cache::v1::*;
use aos_proto::aos::gc::v1::*;

/// Typed ConnectRPC client for the AOS server.
///
/// Provides access to all four services: cache, build, GC, and auth.
/// Replaces the ad-hoc REST client in `build.rs`.
///
/// Construct one with [`AosClient::connect`] (exchanges a provisioning
/// token for a JWT) or [`AosClient::connect_with_token`] (reuses an
/// existing JWT). Every request carries the view name supplied at
/// construction time.
pub struct AosClient {
    cache: CacheServiceClient<HttpClient>,
    build_svc: BuildServiceClient<HttpClient>,
    gc: GcServiceClient<HttpClient>,
    auth: AuthServiceClient<HttpClient>,
    /// The view name for all requests.
    view: String,
}

// ---------------------------------------------------------------------------
// Input validation helpers
// ---------------------------------------------------------------------------

/// Validate that a view name is non-empty and contains no path traversal.
fn validate_view(view: &str) -> Result<()> {
    if view.is_empty() {
        bail!("view must not be empty");
    }
    if view.contains("..") || view.contains('/') || view.contains('\\') {
        bail!("view contains invalid characters (path traversal)");
    }
    Ok(())
}

/// Validate that a store hash contains only hex characters and has the
/// expected Nix store hash length (32 chars, base-32 encoding).
fn validate_store_hash(hash: &str) -> Result<()> {
    if hash.is_empty() {
        bail!("store_hash must not be empty");
    }
    // Nix store hashes are 32-char base-32 (0-9, a-z minus e/o/t/u).
    // Be lenient: accept any alphanumeric chars of the right length.
    if hash.len() != 32 {
        bail!(
            "store_hash has unexpected length {} (expected 32)",
            hash.len()
        );
    }
    if !hash.chars().all(|c| c.is_ascii_alphanumeric()) {
        bail!("store_hash contains non-alphanumeric characters");
    }
    Ok(())
}

/// Validate that a filename has no path traversal components.
fn validate_filename(filename: &str) -> Result<()> {
    if filename.is_empty() {
        bail!("filename must not be empty");
    }
    if filename.contains("..") || filename.contains('/') || filename.contains('\\') {
        bail!("filename contains invalid characters (path traversal)");
    }
    Ok(())
}

/// Validate and parse the base URL. Returns the parsed URI.
pub(crate) fn validate_base_url(base_url: &str) -> Result<Uri> {
    if !base_url.starts_with("http://") && !base_url.starts_with("https://") {
        bail!("base_url must start with http:// or https://");
    }
    base_url.parse().context("invalid base URL")
}

/// Build an `HttpClient` appropriate for the given URL scheme.
/// Uses TLS + HTTP/2 for `https://`, plaintext for `http://`.
pub(crate) fn make_http_client(base_url: &str) -> HttpClient {
    if base_url.starts_with("https://") {
        let tls_config = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(default_root_store())
                .with_no_client_auth(),
        );
        HttpClient::with_tls(tls_config)
    } else {
        HttpClient::plaintext()
    }
}

/// Build a `RootCertStore` from the platform's native certificate store,
/// falling back to the bundled webpki roots.
fn default_root_store() -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();

    // Try loading native certs; ignore individual failures.
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = roots.add(cert);
    }

    // If we got nothing from the OS, fall back to the compiled-in
    // Mozilla root set so TLS still works in minimal containers.
    if roots.is_empty() {
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    }

    roots
}

impl AosClient {
    /// Connect to an AOS server and authenticate with the given
    /// provisioning token.
    ///
    /// This exchanges the provisioning token for a JWT access token
    /// via `AuthService.GetToken`, then configures all service clients
    /// with the JWT as a default `authorization` header.
    ///
    /// # Errors
    ///
    /// Returns an error if `base_url` is not a valid `http://` or
    /// `https://` URL, if `view` is empty or contains path-traversal
    /// characters, or if the token exchange with the server fails
    /// (unreachable server, rejected provisioning token).
    pub async fn connect(base_url: &str, view: &str, provisioning_token: &str) -> Result<Self> {
        let base_uri = validate_base_url(base_url)?;
        validate_view(view)?;

        let http = make_http_client(base_url);

        // First, get a JWT token via the auth service (unauthenticated call).
        let initial_config =
            ClientConfig::new(base_uri.clone()).default_timeout(Duration::from_secs(30));
        let auth_client = AuthServiceClient::new(http.clone(), initial_config);

        let token_resp = auth_client
            .get_token(TokenRequest {
                provisioning_token: provisioning_token.into(),
                ..Default::default()
            })
            .await
            .map_err(|e| anyhow::anyhow!("authentication failed: {e}"))?;

        let access_token: String = token_resp.into_owned().access_token;

        // Build authenticated config, reusing the already-parsed URI.
        let config = ClientConfig::new(base_uri)
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
    ///
    /// No network traffic happens here; the token is simply installed as
    /// the default `authorization` header for subsequent requests.
    ///
    /// # Errors
    ///
    /// Returns an error if `base_url` is not a valid `http://` or
    /// `https://` URL, or if `view` is empty or contains path-traversal
    /// characters.
    pub fn connect_with_token(base_url: &str, view: &str, jwt_token: &str) -> Result<Self> {
        let base_uri = validate_base_url(base_url)?;
        validate_view(view)?;

        let http = make_http_client(base_url);

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
    ///
    /// # Errors
    ///
    /// Returns an error if the `CacheService.GetCacheInfo` RPC fails.
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
    ///
    /// # Errors
    ///
    /// Returns an error if `store_hash` is not a 32-character
    /// alphanumeric Nix store hash, or if the `CacheService.GetNarInfo`
    /// RPC fails.
    pub async fn get_nar_info(&self, store_hash: &str) -> Result<NarInfo> {
        validate_store_hash(store_hash)?;

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
    ///
    /// Returns the subset of `store_paths` that the server does not yet
    /// have, so callers can upload only what is needed.
    ///
    /// # Errors
    ///
    /// Returns an error if the `CacheService.QueryMissing` RPC fails.
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
    ///
    /// Chunks are produced lazily via an iterator to avoid buffering the
    /// entire payload in a separate `Vec`. Returns the resulting store
    /// path on the server.
    ///
    /// # Errors
    ///
    /// Returns an error if `store_hash` is not a 32-character
    /// alphanumeric Nix store hash, or if the streaming
    /// `CacheService.Upload` RPC fails.
    pub async fn upload(&self, store_hash: &str, nar_data: &[u8]) -> Result<String> {
        validate_store_hash(store_hash)?;

        const CHUNK_SIZE: usize = 5 * 1024 * 1024; // 5 MB

        let view = &self.view;
        let total_len = nar_data.len();

        let chunks = (0..total_len).step_by(CHUNK_SIZE).map(move |offset| {
            let end = std::cmp::min(offset + CHUNK_SIZE, total_len);
            UploadChunk {
                view: view.clone(),
                store_hash: store_hash.into(),
                data: nar_data[offset..end].to_vec(),
                offset: offset as i64,
                is_final: end == total_len,
                ..Default::default()
            }
        });

        let resp = self
            .cache
            .upload(chunks)
            .await
            .map_err(|e| anyhow::anyhow!("upload failed: {e}"))?;

        Ok(resp.into_owned().store_path)
    }

    /// Download a NAR file via server streaming.
    ///
    /// `offset` specifies the byte offset to resume from (0 for a fresh
    /// download). The full body is buffered in memory and returned.
    ///
    /// # Errors
    ///
    /// Returns an error if `filename` is empty or contains path-traversal
    /// characters, or if the `CacheService.Download` RPC or its response
    /// stream fails.
    pub async fn download(&self, filename: &str, offset: i64) -> Result<Vec<u8>> {
        validate_filename(filename)?;

        let mut stream = self
            .cache
            .download(DownloadRequest {
                view: self.view.clone(),
                filename: filename.into(),
                offset,
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
    ///
    /// Chunks are produced lazily via an iterator. The pack format
    /// (created by `aos_core::nar::pack`) bundles many small NARs into a
    /// single stream; the server unpacks it and returns the imported
    /// store paths.
    ///
    /// # Errors
    ///
    /// Returns an error if the streaming `CacheService.UploadPack` RPC
    /// fails.
    pub async fn upload_pack(&self, pack_data: &[u8]) -> Result<Vec<String>> {
        const CHUNK_SIZE: usize = 5 * 1024 * 1024;

        let view = &self.view;
        let total_len = pack_data.len();

        let chunks = (0..total_len).step_by(CHUNK_SIZE).map(move |offset| {
            let end = std::cmp::min(offset + CHUNK_SIZE, total_len);
            PackChunk {
                view: view.clone(),
                data: pack_data[offset..end].to_vec(),
                is_final: end == total_len,
                ..Default::default()
            }
        });

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
    /// The callback receives each [`BuildEvent`] and returns `true` to
    /// continue or `false` to stop consuming the stream early (the
    /// method still returns `Ok`).
    ///
    /// # Errors
    ///
    /// Returns an error if the `BuildService.Build` RPC fails to start
    /// or if the event stream is interrupted mid-flight. A build that
    /// fails on the server is reported through an `"error"` event, not
    /// through this method's `Result`.
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
            if !on_event(&owned) {
                break;
            }
        }

        Ok(())
    }

    /// Trigger a closure build (multiple derivations) and stream events.
    ///
    /// Semantics match [`AosClient::build`]: the callback returns `true`
    /// to keep consuming events, `false` to stop early.
    ///
    /// # Errors
    ///
    /// Returns an error if the `BuildService.BuildClosure` RPC fails to
    /// start or if the event stream is interrupted mid-flight.
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
            if !on_event(&owned) {
                break;
            }
        }

        Ok(())
    }

    // -----------------------------------------------------------------------
    // GC operations
    // -----------------------------------------------------------------------

    /// Trigger garbage collection on the server.
    ///
    /// When `dry_run` is set, the server reports what it would remove
    /// without acting. `collect_store` additionally runs
    /// `nix-store --gc` after roots are removed, and `max_size` (bytes)
    /// caps the view's store size by evicting low-score paths.
    ///
    /// # Errors
    ///
    /// Returns an error if the `GcService.Collect` RPC fails.
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
    ///
    /// [`AosClient::connect`] already performs this exchange; this method
    /// exists for callers that want a fresh token (e.g. to hand off to
    /// another process) without reconnecting.
    ///
    /// # Errors
    ///
    /// Returns an error if the `AuthService.GetToken` RPC fails or the
    /// server rejects the provisioning token.
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
