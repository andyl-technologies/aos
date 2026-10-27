//! HTTP surface of the server: the axum router, shared state, and all REST
//! handlers.
//!
//! [`router`] mounts every endpoint. REST routes are registered explicitly;
//! ConnectRPC method paths (from [`crate::services`]) are mounted alongside
//! them and also serve as the fallback, so the two APIs share one listener.
//!
//! # HTTP endpoints
//!
//! Read endpoints (anonymous when the view has `anonymous_read = true`,
//! otherwise JWT required):
//!
//! | Method | Path                        | Purpose                            |
//! |--------|-----------------------------|------------------------------------|
//! | GET    | `/{view}/nix-cache-info`    | Cache metadata + capabilities      |
//! | GET    | `/{view}/{hash}.narinfo`    | Path metadata (narinfo)            |
//! | GET    | `/{view}/nar/{filename}`    | NAR download (zstd/xz/none, ranges)|
//!
//! Authenticated endpoints (JWT via `Authorization: Bearer`; mutations
//! additionally need the `build` permission):
//!
//! | Method | Path                       | Purpose                              |
//! |--------|----------------------------|--------------------------------------|
//! | POST   | `/{view}/query-missing`    | Which paths the server lacks         |
//! | PUT    | `/{view}/store/{hash}`     | Upload a NAR (chunked via ranges)    |
//! | HEAD   | `/{view}/store/{hash}`     | Progress of a partial upload         |
//! | POST   | `/{view}/build?drv=...`    | Build one derivation (SSE stream)    |
//! | POST   | `/{view}/build-closure`    | Build many derivations (tagged SSE)  |
//! | POST   | `/{view}/upload-pack`      | Batched NAR upload (AOSP pack)       |
//! | POST   | `/{view}/gc`               | TTL expiry / eviction / store GC     |
//! | POST   | `/oauth2/token`            | Provisioning secret -> JWT exchange  |
//!
//! Every `/{view}/...` handler validates the view name against path
//! traversal, resolves it to a configured view (404 otherwise), and checks
//! the JWT's view list and permissions before doing any work.

use std::convert::Infallible;
use std::process::Stdio;
use std::sync::Arc;

use axum::{
    Json, Router,
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, head, post, put},
};
use serde::Deserialize;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt};
use tokio::process::Command;
use tokio::sync::Semaphore;
use tokio_stream::StreamExt;
use tokio_stream::wrappers::BroadcastStream;

use aos_nar::cache::nix_cache_info;
use aos_nix::{StoreHash, aos_nix_env};

use crate::access;
use crate::auth::{self, AuthClaims, AuthResult, ViewAccessError};
use crate::build::BuildManager;
use crate::compress::{self, Compression};
use crate::config::ServerConfig;
use crate::drain::DrainState;
use crate::narinfo;
use crate::pack;
use crate::sign::NarInfoSigner;
use crate::store::NixStore;
use crate::tokens::TokenStore;
use crate::upload_session::{self, SessionError, UploadRange};
use crate::views::ViewManager;

use tracing;

/// Validates that a view name extracted from a URL path is safe.
///
/// View names become filesystem path components under `gcroots/` and
/// `meta/`, so names containing path traversal sequences (`..`), directory
/// separators, or null bytes are rejected with `400 Bad Request`.
#[allow(
    clippy::result_large_err,
    reason = "Preserve ready-made HTTP error responses and their existing status and body handling."
)]
fn validate_view_name(name: &str) -> Result<(), Response> {
    if crate::views::validate_view_name(name).is_err() {
        tracing::warn!(view = %name, "rejected invalid view name");
        return Err((StatusCode::BAD_REQUEST, "invalid view name").into_response());
    }
    Ok(())
}

/// Parses a canonical store hash from an HTTP path component.
fn parse_store_hash(value: &str) -> Result<StoreHash, Response> {
    value.parse().map_err(|error| {
        tracing::warn!(hash = %value, %error, "rejected invalid store hash");
        (StatusCode::BAD_REQUEST, "invalid store hash").into_response()
    })
}

/// Parses a NAR filename and returns its canonical store identity.
fn parse_nar_filename(name: &str) -> Result<StoreHash, Response> {
    if name.is_empty()
        || !name.is_ascii()
        || !name
            .bytes()
            .all(|character| character.is_ascii_alphanumeric() || character == b'-')
    {
        return Err((StatusCode::BAD_REQUEST, "invalid NAR filename").into_response());
    }

    let hash = name.split_once('-').map_or(name, |(hash, _suffix)| hash);
    parse_store_hash(hash)
}

// ConnectRPC service extension traits for registration
use aos_build_api::aos::auth::v1::AuthServiceExt;
use aos_build_api::aos::build::v1::BuildServiceExt;
use aos_build_api::aos::cache::v1::CacheServiceExt;
use aos_build_api::aos::gc::v1::GcServiceExt;

use crate::services;

/// Shared server state, constructed once at startup and passed to every
/// handler behind an `Arc`.
pub struct AppState {
    /// Read-only handle to the Nix store SQLite database.
    pub store: NixStore,
    /// View configuration and GC root / metadata management.
    pub views: ViewManager,
    /// Parsed server configuration.
    pub config: ServerConfig,
    /// Absolute store directory advertised in `nix-cache-info` and narinfo
    /// (e.g. `/var/lib/aos/store`).
    pub store_dir: String,
    /// HMAC-SHA256 secret used to sign and verify JWT access tokens.
    pub jwt_secret: Vec<u8>,
    /// Provisioning token store backing the OAuth2 exchange and the
    /// bootstrap socket.
    pub tokens: TokenStore,
    /// Build deduplication and event streaming.
    pub build_mgr: Arc<BuildManager>,
    /// Graceful-shutdown coordination.
    pub drain: Arc<DrainState>,
    /// Signer used to add a fresh `Sig:` line to served narinfo.
    pub signer: NarInfoSigner,
    /// Admission bound shared by NAR range and narinfo materialization work.
    pub nar_materialization_admission: Arc<Semaphore>,
}

/// Failure to admit or complete bounded NAR materialization work.
#[derive(Debug)]
pub(crate) enum NarMaterializationError {
    /// All configured materialization slots are in use.
    Busy,
    /// The compression pipeline or blocking worker failed.
    Failed(anyhow::Error),
}

fn try_nar_materialization_permit(
    admission: &Arc<Semaphore>,
) -> Result<tokio::sync::OwnedSemaphorePermit, NarMaterializationError> {
    Arc::clone(admission)
        .try_acquire_owned()
        .map_err(|_| NarMaterializationError::Busy)
}

/// Measures compressed NAR metadata on an admitted blocking worker.
///
/// # Errors
///
/// Returns [`NarMaterializationError::Busy`] when all configured slots are in
/// use, or [`NarMaterializationError::Failed`] when measurement fails.
pub(crate) async fn measure_nar_bounded(
    state: &Arc<AppState>,
    info: crate::store::DbPathInfo,
) -> Result<Option<(String, u64)>, NarMaterializationError> {
    let permit = try_nar_materialization_permit(&state.nar_materialization_admission)?;
    let compression = state.config.compression.clone();

    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        narinfo::measure_nar(&info, &compression)
    })
    .await
    .map_err(|error| NarMaterializationError::Failed(error.into()))?
    .map_err(NarMaterializationError::Failed)
}

/// Builds the axum router with both REST and ConnectRPC endpoints.
///
/// Exact ConnectRPC method paths are registered individually (so the broad
/// `/{view}/{...}` REST patterns cannot shadow them), and the ConnectRPC
/// service also acts as the fallback for unmatched paths.
pub fn router(state: Arc<AppState>) -> Router {
    // Build ConnectRPC service router.
    let connect_router = build_connectrpc_router(Arc::clone(&state));
    let connect_paths: Vec<String> = connect_router
        .methods()
        .map(|method| format!("/{method}"))
        .collect();
    let connect_service = connect_router.into_axum_service();

    // Existing REST routes remain; exact ConnectRPC paths are registered
    // separately so broad REST routes cannot shadow them.
    let mut router = Router::new()
        .route("/{view}/nix-cache-info", get(cache_info_handler))
        .route("/{view}/{hash_narinfo}", get(narinfo_handler))
        .route("/{view}/nar/{filename}", get(nar_handler))
        .route("/{view}/query-missing", post(query_missing_handler))
        .route("/{view}/store/{hash}", put(upload_path_handler))
        .route("/{view}/store/{hash}", head(upload_progress_handler))
        .route("/{view}/build", post(build_handler))
        .route("/{view}/build-closure", post(build_closure_handler))
        .route("/{view}/upload-pack", post(upload_pack_handler))
        .route("/{view}/gc", post(gc_handler))
        .route("/oauth2/token", post(auth::oauth2_token_handler));

    for path in connect_paths {
        router = router.route_service(&path, connect_service.clone());
    }

    router.fallback_service(connect_service).with_state(state)
}

/// Builds the ConnectRPC service router with all four RPC services
/// (cache, build, gc, auth) registered against the shared state.
fn build_connectrpc_router(state: Arc<AppState>) -> connectrpc::Router {
    let cache_svc = Arc::new(services::cache::CacheServiceImpl::new(Arc::clone(&state)));
    let build_svc = Arc::new(services::build::BuildServiceImpl {
        state: Arc::clone(&state),
    });
    let gc_svc = Arc::new(services::gc::GcServiceImpl {
        state: Arc::clone(&state),
    });
    let auth_svc = Arc::new(services::auth::AuthServiceImpl {
        state: Arc::clone(&state),
    });

    let router = connectrpc::Router::new();
    let router = cache_svc.register(router);
    let router = build_svc.register(router);
    let router = gc_svc.register(router);

    auth_svc.register(router)
}

// ---------------------------------------------------------------------------
// Read-only endpoints (respect anonymous_read)
// ---------------------------------------------------------------------------

fn require_rest_read_access(
    auth: &AuthResult,
    view: &str,
    allow_anonymous: bool,
) -> Result<(), Response> {
    auth::require_view_permission(auth.claims(), view, "read", allow_anonymous).map_err(|error| {
        match error {
            ViewAccessError::AuthenticationRequired => {
                (StatusCode::UNAUTHORIZED, "authentication required").into_response()
            }
            ViewAccessError::ViewNotAuthorized => {
                (StatusCode::FORBIDDEN, "view not authorized").into_response()
            }
            ViewAccessError::PermissionRequired => {
                (StatusCode::FORBIDDEN, "read permission required").into_response()
            }
        }
    })
}

/// `GET /{view}/nix-cache-info` — Nix binary cache metadata.
///
/// Anonymous when the view has `anonymous_read = true`, otherwise requires
/// a valid JWT. Returns the standard `StoreDir`/`WantMassQuery`/`Priority`
/// fields plus a `Capabilities:` line advertising AOS extensions
/// (`pack-upload query-missing sse-logs zstd xz content-range`).
async fn cache_info_handler(
    Path(view): Path<String>,
    State(state): State<Arc<AppState>>,
    auth: AuthResult,
) -> Response {
    if let Err(resp) = validate_view_name(&view) {
        return resp;
    }
    let view_config = match state.views.get_view(&view) {
        Some(v) => v,
        None => return (StatusCode::NOT_FOUND, "unknown view").into_response(),
    };

    if let Err(response) = require_rest_read_access(&auth, &view, view_config.anonymous_read) {
        tracing::warn!(view = %view, "cache-info read access denied");
        return response;
    }

    let mut body = nix_cache_info(&state.store_dir, 30);
    body.push_str("Capabilities: pack-upload query-missing sse-logs zstd xz content-range\n");

    (StatusCode::OK, [(header::CONTENT_TYPE, "text/plain")], body).into_response()
}

/// `GET /{view}/{hash}.narinfo` — metadata for one store path.
///
/// Anonymous when the view allows it, otherwise requires a valid JWT. The
/// hash must be visible in the view (have a GC root); a path that exists
/// in the store but not in the view yields `404`, so views never leak each
/// other's contents. Serving the narinfo also bumps the path's access
/// metadata (best-effort) for eviction scoring.
async fn narinfo_handler(
    Path((view, hash_narinfo)): Path<(String, String)>,
    State(state): State<Arc<AppState>>,
    auth: AuthResult,
) -> Response {
    if let Err(resp) = validate_view_name(&view) {
        return resp;
    }
    let view_config = match state.views.get_view(&view) {
        Some(v) => v,
        None => return (StatusCode::NOT_FOUND, "unknown view").into_response(),
    };

    if let Err(response) = require_rest_read_access(&auth, &view, view_config.anonymous_read) {
        tracing::warn!(view = %view, hash = %hash_narinfo, "narinfo read access denied");
        return response;
    }

    let hash = match hash_narinfo.strip_suffix(".narinfo") {
        Some(h) => h,
        None => return (StatusCode::BAD_REQUEST, "expected .narinfo suffix").into_response(),
    };
    let hash = match parse_store_hash(hash) {
        Ok(hash) => hash,
        Err(response) => return response,
    };

    let store_path = match state.views.check_visibility(&view, &hash) {
        Ok(Some(path)) => path,
        Ok(None) => return (StatusCode::NOT_FOUND, "path not in view").into_response(),
        Err(e) => {
            tracing::error!(view = %view, hash = %hash, error = %e, "visibility check failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("visibility check: {e}"),
            )
                .into_response();
        }
    };

    let info = match state.store.path_info(&store_path) {
        Ok(Some(info)) => info,
        Ok(None) => return (StatusCode::NOT_FOUND, "path not in store").into_response(),
        Err(e) => {
            tracing::error!(view = %view, hash = %hash, error = %e, "store query failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("store query: {e}"),
            )
                .into_response();
        }
    };

    // Update access metadata (best-effort, don't fail the request).
    let _ = access::update_access(&state.views, &view, &hash);

    let measured_file = match measure_nar_bounded(&state, info.clone()).await {
        Ok(measured_file) => measured_file,
        Err(NarMaterializationError::Busy) => {
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                [(header::RETRY_AFTER, "1")],
                "NAR materialization capacity is busy",
            )
                .into_response();
        }
        Err(NarMaterializationError::Failed(error)) => {
            tracing::error!(view = %view, hash = %hash, %error, "narinfo measurement failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "narinfo rendering failed",
            )
                .into_response();
        }
    };

    let body = match narinfo::format_narinfo(
        &info,
        &state.store_dir,
        &state.config.compression,
        measured_file,
        Some(&state.signer),
    ) {
        Ok(body) => body,
        Err(error) => {
            tracing::error!(view = %view, hash = %hash, %error, "narinfo rendering failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                "narinfo rendering failed",
            )
                .into_response();
        }
    };

    tracing::info!(view = %view, hash = %hash, "narinfo served");

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/x-nix-narinfo")],
        body,
    )
        .into_response()
}

/// `GET /{view}/nar/{filename}` — download a NAR archive.
///
/// Anonymous when the view allows it, otherwise requires a valid JWT. The
/// filename's extension selects the compression (`.nar`, `.nar.zst`,
/// `.nar.xz`) and its leading hash segment must be visible in the view.
/// Full downloads are streamed without buffering. Range requests are
/// materialized into a bounded unlinked file on a blocking worker, then only
/// the requested slice is streamed to the client.
async fn nar_handler(
    Path((view, filename)): Path<(String, String)>,
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    auth: AuthResult,
) -> Response {
    if let Err(resp) = validate_view_name(&view) {
        return resp;
    }
    let view_config = match state.views.get_view(&view) {
        Some(v) => v,
        None => return (StatusCode::NOT_FOUND, "unknown view").into_response(),
    };

    if let Err(response) = require_rest_read_access(&auth, &view, view_config.anonymous_read) {
        tracing::warn!(view = %view, filename = %filename, "NAR read access denied");
        return response;
    }

    let zstd_level = state.config.compression.level;
    let (name, compression) = if let Some(name) = filename.strip_suffix(".nar.zst") {
        (name, Compression::Zstd { level: zstd_level })
    } else if let Some(name) = filename.strip_suffix(".nar.xz") {
        (name, Compression::Xz { level: zstd_level })
    } else if let Some(name) = filename.strip_suffix(".nar") {
        (name, Compression::None)
    } else {
        return (
            StatusCode::BAD_REQUEST,
            "expected .nar, .nar.zst, or .nar.xz suffix",
        )
            .into_response();
    };

    let store_hash = match parse_nar_filename(name) {
        Ok(hash) => hash,
        Err(response) => return response,
    };

    let store_path = match state.views.check_visibility(&view, &store_hash) {
        Ok(Some(path)) => path,
        Ok(None) => return (StatusCode::NOT_FOUND, "path not in view").into_response(),
        Err(e) => {
            tracing::error!(view = %view, hash = %store_hash, error = %e, "visibility check failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("visibility check: {e}"),
            )
                .into_response();
        }
    };

    if let Some(range) = headers.get(header::RANGE) {
        let range = match range
            .to_str()
            .ok()
            .and_then(|value| ByteRangeSpec::parse(value).ok())
        {
            Some(range) => range,
            None => return invalid_range_response(None),
        };
        let permit = match try_nar_materialization_permit(&state.nar_materialization_admission) {
            Ok(permit) => permit,
            Err(NarMaterializationError::Busy) => {
                return (
                    StatusCode::SERVICE_UNAVAILABLE,
                    [(header::RETRY_AFTER, "1")],
                    "NAR materialization capacity is busy",
                )
                    .into_response();
            }
            Err(_) => {
                return (StatusCode::INTERNAL_SERVER_ERROR, "streaming NAR failed").into_response();
            }
        };
        let maximum_bytes = state.config.compression.max_materialized_bytes;
        let materialized_path = store_path.clone();
        let temporary_directory = state.views.root().to_path_buf();
        let materialized = tokio::task::spawn_blocking(move || {
            let result = compress::materialize_nar(
                &materialized_path,
                compression,
                maximum_bytes,
                &temporary_directory,
            );
            (permit, result)
        })
        .await;
        let (permit, file, total) = match materialized {
            Ok((permit, Ok((file, total)))) => (permit, file, total),
            Ok((_permit, Err(error))) => {
                tracing::error!(view = %view, hash = %store_hash, %error, "NAR range materialization failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "streaming NAR failed").into_response();
            }
            Err(error) => {
                tracing::error!(view = %view, hash = %store_hash, %error, "NAR range worker failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, "streaming NAR failed").into_response();
            }
        };
        let Some((start, end)) = range.resolve(total) else {
            return invalid_range_response(Some(total));
        };
        let length = end - start + 1;
        let mut file = tokio::fs::File::from_std(file);
        if let Err(error) = file.seek(std::io::SeekFrom::Start(start)).await {
            tracing::error!(view = %view, hash = %store_hash, %error, "NAR range seek failed");
            return (StatusCode::INTERNAL_SERVER_ERROR, "streaming NAR failed").into_response();
        }

        let stream = tokio_util::io::ReaderStream::new(file.take(length)).map(move |chunk| {
            let _permit = &permit;
            chunk
        });
        tracing::info!(
            view = %view,
            hash = %store_hash,
            start,
            end,
            total,
            compression = %compression.narinfo_name(),
            "NAR range streamed"
        );
        return (
            StatusCode::PARTIAL_CONTENT,
            [
                (header::CONTENT_TYPE, compression.content_type().to_string()),
                (header::ACCEPT_RANGES, "bytes".to_string()),
                (
                    header::CONTENT_RANGE,
                    format!("bytes {start}-{end}/{total}"),
                ),
                (header::CONTENT_LENGTH, length.to_string()),
            ],
            Body::from_stream(stream),
        )
            .into_response();
    }

    match compress::nar_stream(&store_path, compression).await {
        Ok(body) => {
            tracing::info!(view = %view, hash = %store_hash, compression = %compression.narinfo_name(), "NAR streamed");
            (
                StatusCode::OK,
                [
                    (header::CONTENT_TYPE, compression.content_type()),
                    (header::ACCEPT_RANGES, "bytes"),
                ],
                body,
            )
                .into_response()
        }
        Err(e) => {
            tracing::error!(view = %view, hash = %store_hash, error = %e, "NAR streaming failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("streaming NAR: {e}"),
            )
                .into_response()
        }
    }
}

/// Parses a request `Range: bytes=...` header against a body of `total`
/// bytes, returning the inclusive `(start, end)` byte range.
///
/// Supports `start-end`, open-ended `start-`, and suffix `-len` forms.
/// Multi-range requests, malformed specs, and out-of-bounds starts yield
/// `None` (the caller answers `416 Range Not Satisfiable`); an `end` past
/// the body is clamped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ByteRangeSpec {
    FromTo { start: u64, end: u64 },
    From { start: u64 },
    Suffix { length: u64 },
}

impl ByteRangeSpec {
    fn parse(value: &str) -> Result<Self, ()> {
        let spec = value.trim().strip_prefix("bytes=").ok_or(())?;
        if spec.contains(',') {
            return Err(());
        }
        let (start, end) = spec.split_once('-').ok_or(())?;

        if start.is_empty() {
            let length = end.parse::<u64>().map_err(|_| ())?;
            return (length > 0).then_some(Self::Suffix { length }).ok_or(());
        }

        let start = start.parse::<u64>().map_err(|_| ())?;
        if end.is_empty() {
            return Ok(Self::From { start });
        }

        let end = end.parse::<u64>().map_err(|_| ())?;
        (start <= end)
            .then_some(Self::FromTo { start, end })
            .ok_or(())
    }

    fn resolve(self, total: u64) -> Option<(u64, u64)> {
        if total == 0 {
            return None;
        }

        match self {
            Self::Suffix { length } => Some((total.saturating_sub(length), total - 1)),
            Self::From { start } if start < total => Some((start, total - 1)),
            Self::FromTo { start, end } if start < total => Some((start, end.min(total - 1))),
            Self::From { .. } | Self::FromTo { .. } => None,
        }
    }
}

#[cfg(test)]
fn parse_range_header(value: &str, total: u64) -> Option<(u64, u64)> {
    ByteRangeSpec::parse(value).ok()?.resolve(total)
}

fn invalid_range_response(total: Option<u64>) -> Response {
    let mut response = (StatusCode::RANGE_NOT_SATISFIABLE, "range not satisfiable").into_response();
    response
        .headers_mut()
        .insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    if let Some(total) = total {
        if let Ok(value) = HeaderValue::from_str(&format!("bytes */{total}")) {
            response.headers_mut().insert(header::CONTENT_RANGE, value);
        }
    }
    response
}

// ---------------------------------------------------------------------------
// Build endpoints (require auth)
// ---------------------------------------------------------------------------

/// JSON body of `POST /{view}/query-missing`.
#[derive(Deserialize)]
struct QueryMissingRequest {
    /// Store paths (or bare store hashes) to check.
    paths: Vec<String>,
}

/// `POST /{view}/query-missing` — reports which of the given paths the
/// server does not have.
///
/// Requires a JWT authorized for the view (no specific permission).
/// Accepts full store paths or bare hashes — paths are matched by store
/// hash so client and server store roots may differ. Responds with
/// `{"missing": [...]}` listing the inputs not present locally.
async fn query_missing_handler(
    Path(view): Path<String>,
    State(state): State<Arc<AppState>>,
    AuthClaims(claims): AuthClaims,
    Json(body): Json<QueryMissingRequest>,
) -> Response {
    if let Err(resp) = validate_view_name(&view) {
        return resp;
    }
    if state.views.get_view(&view).is_none() {
        return (StatusCode::NOT_FOUND, "unknown view").into_response();
    }

    if !claims.has_view(&view) {
        tracing::warn!(view = %view, sub = %claims.sub, "view not authorized for query-missing");
        return (StatusCode::FORBIDDEN, "view not authorized").into_response();
    }

    let mut missing = Vec::new();
    for path in &body.paths {
        match state.store.is_valid_path_or_hash(path) {
            Ok(true) => {}
            Ok(false) => missing.push(path.clone()),
            Err(e) => {
                tracing::error!(view = %view, error = %e, "store query failed in query-missing");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("store query: {e}"),
                )
                    .into_response();
            }
        }
    }

    tracing::info!(view = %view, total = body.paths.len(), missing = missing.len(), "query-missing completed");
    Json(serde_json::json!({ "missing": missing })).into_response()
}

const MAX_RESUMABLE_UPLOAD_BYTES: u64 = 8 * 1024 * 1024 * 1024;

fn upload_session_error(error: SessionError) -> Response {
    let status = match error {
        SessionError::MalformedRange | SessionError::LengthMismatch { .. } => {
            StatusCode::BAD_REQUEST
        }
        SessionError::LimitExceeded { .. } => StatusCode::PAYLOAD_TOO_LARGE,
        SessionError::Busy
        | SessionError::Missing
        | SessionError::OffsetMismatch { .. }
        | SessionError::TotalChanged { .. }
        | SessionError::InvalidState => StatusCode::CONFLICT,
        SessionError::Io(_) => StatusCode::INTERNAL_SERVER_ERROR,
    };
    (status, error.to_string()).into_response()
}

/// `PUT /{view}/store/{hash}` — upload a NAR-exported store path.
///
/// Requires a JWT authorized for the view with the `build` permission, and
/// is subject to the view's `max_paths` quota (`507` when exceeded).
///
/// Two upload modes:
///
/// - **Single-shot** (no `Content-Range` header): the body is the complete
///   `nix-store --export` output; it is imported immediately and the
///   imported path returned as `{"path": ...}`.
/// - **Chunked/resumable** (`Content-Range: bytes start-end/total`): each
///   chunk extends a private session at its exact next offset; intermediate
///   chunks get `202 Accepted` with progress JSON, and the final chunk
///   triggers a streamed import.
///
/// Imported paths must pass the `.drv`-or-content-addressed safety check
/// and receive a temporary `tmp/` GC root until a build promotes them.
async fn upload_path_handler(
    Path((view, hash)): Path<(String, String)>,
    State(state): State<Arc<AppState>>,
    AuthClaims(claims): AuthClaims,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(resp) = validate_view_name(&view) {
        return resp;
    }
    if state.views.get_view(&view).is_none() {
        return (StatusCode::NOT_FOUND, "unknown view").into_response();
    }
    let hash = match parse_store_hash(&hash) {
        Ok(hash) => hash,
        Err(response) => return response,
    };

    if !claims.has_view(&view) {
        tracing::warn!(view = %view, sub = %claims.sub, "view not authorized for upload");
        return (StatusCode::FORBIDDEN, "view not authorized").into_response();
    }

    if !claims.has_permission("build") {
        tracing::warn!(view = %view, sub = %claims.sub, "build permission required for upload");
        return (StatusCode::FORBIDDEN, "build permission required").into_response();
    }

    // Enforce per-view max_paths quota.
    if let Some(view_config) = state.views.get_view(&view)
        && let Some(max_paths) = view_config.max_paths
    {
        match state.views.count_roots(&view) {
            Ok(count) if count >= max_paths => {
                tracing::warn!(view = %view, count, max_paths, "upload rejected: max_paths exceeded");
                return (
                    StatusCode::INSUFFICIENT_STORAGE,
                    format!("view has {count} rooted paths, max is {max_paths}"),
                )
                    .into_response();
            }
            Err(e) => {
                tracing::error!(view = %view, error = %e, "failed to count roots for quota check");
            }
            _ => {}
        }
    }

    if let Some(content_range) = headers.get(header::CONTENT_RANGE) {
        let content_range = match content_range.to_str() {
            Ok(value) => value,
            Err(_) => return upload_session_error(SessionError::MalformedRange),
        };
        let range = match UploadRange::parse(content_range) {
            Ok(range) => range,
            Err(error) => return upload_session_error(error),
        };
        let progress = match upload_session::append(
            state.views.root(),
            &view,
            &claims.sub,
            &hash,
            range,
            &body,
            MAX_RESUMABLE_UPLOAD_BYTES,
        )
        .await
        {
            Ok(progress) => progress,
            Err(error) => return upload_session_error(error),
        };

        if progress.is_complete() {
            tracing::info!(view = %view, hash = %hash, total_bytes = progress.total, "chunked upload complete, importing");
            let response =
                import_nar_file_with_tmp_root(&progress.path, &state.views, &view, &hash).await;
            upload_session::remove(&progress.path).await;
            return response;
        }

        return (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({
                "received": progress.received,
                "total": progress.total,
            })),
        )
            .into_response();
    }

    // No Content-Range — import the full body directly (original behavior).
    tracing::info!(view = %view, hash = %hash, bytes = body.len(), "upload received, importing");
    import_nar_with_tmp_root(&body, &state.views, &view, &hash).await
}

/// Imports NAR data via `nix-store --import` and returns the imported
/// store path, after vetting it with
/// [`pack::validate_imported_path`]. Failures are returned as ready-made
/// error responses (`500` for process errors, `400` for import or
/// validation rejections).
#[allow(
    clippy::result_large_err,
    reason = "Preserve ready-made HTTP error responses and their existing status and body handling."
)]
async fn import_nar(data: &[u8]) -> Result<String, Response> {
    let mut reader = std::io::Cursor::new(data);
    import_nar_reader(&mut reader).await
}

async fn import_nar_file(path: &std::path::Path) -> Result<String, Response> {
    let mut file = tokio::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to open completed upload");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("opening completed upload: {error}"),
            )
                .into_response()
        })?;
    file.seek(std::io::SeekFrom::Start(upload_session::HEADER_LENGTH))
        .await
        .map_err(|error| {
            tracing::error!(%error, "failed to read completed upload header");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("reading completed upload header: {error}"),
            )
                .into_response()
        })?;
    import_nar_reader(&mut file).await
}

async fn import_nar_reader<R>(reader: &mut R) -> Result<String, Response>
where
    R: AsyncRead + Unpin,
{
    let mut child = Command::new("nix-store")
        .envs(aos_nix_env())
        .arg("--import")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .map_err(|e| {
            tracing::error!(error = %e, "failed to spawn nix-store --import");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("spawning nix-store --import: {e}"),
            )
                .into_response()
        })?;

    if let Some(mut stdin) = child.stdin.take() {
        tokio::io::copy(reader, &mut stdin).await.map_err(|e| {
            tracing::error!(error = %e, "failed to write NAR to nix-store");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("writing NAR to nix-store: {e}"),
            )
                .into_response()
        })?;
        drop(stdin);
    }

    let output = child.wait_with_output().await.map_err(|e| {
        tracing::error!(error = %e, "failed waiting for nix-store --import");
        (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("waiting for nix-store --import: {e}"),
        )
            .into_response()
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::error!(stderr = %stderr, "nix-store --import failed");
        return Err((
            StatusCode::BAD_REQUEST,
            format!("nix-store --import failed: {stderr}"),
        )
            .into_response());
    }

    let imported = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if let Err(reason) = pack::validate_imported_path(&imported).await {
        tracing::warn!(path = %imported, reason = %reason, "imported path rejected");
        return Err((StatusCode::BAD_REQUEST, reason).into_response());
    }

    tracing::info!(path = %imported, "store path imported");
    Ok(imported)
}

/// Imports NAR data and creates a temporary GC root in the given view,
/// returning the `{"path": ...}` JSON response (or the import's error
/// response). A failure to create the tmp root is logged but not fatal.
async fn import_nar_with_tmp_root(
    data: &[u8],
    views: &ViewManager,
    view: &str,
    expected_hash: &StoreHash,
) -> Response {
    let imported = match import_nar(data).await {
        Ok(path) => path,
        Err(resp) => return resp,
    };

    finish_import(imported, views, view, expected_hash)
}

async fn import_nar_file_with_tmp_root(
    path: &std::path::Path,
    views: &ViewManager,
    view: &str,
    expected_hash: &StoreHash,
) -> Response {
    let imported = match import_nar_file(path).await {
        Ok(path) => path,
        Err(response) => return response,
    };

    finish_import(imported, views, view, expected_hash)
}

fn finish_import(
    imported: String,
    views: &ViewManager,
    view: &str,
    expected_hash: &StoreHash,
) -> Response {
    let imported_hash = match StoreHash::from_store_path(&imported) {
        Ok(hash) => hash,
        Err(error) => {
            tracing::warn!(path = %imported, %error, "import returned an invalid store path");
            return (
                StatusCode::BAD_REQUEST,
                "import returned an invalid store path",
            )
                .into_response();
        }
    };
    if &imported_hash != expected_hash {
        tracing::warn!(path = %imported, expected = %expected_hash, actual = %imported_hash, "import returned a different store identity");
        return (
            StatusCode::BAD_REQUEST,
            "imported store identity does not match request",
        )
            .into_response();
    }

    // Create a temporary GC root to protect the path until its build creates bin/ roots.
    if let Err(e) = views.create_tmp_root(view, &imported_hash, &imported) {
        tracing::warn!(view = %view, path = %imported, error = %e, "failed to create tmp GC root");
    }

    Json(serde_json::json!({ "path": imported })).into_response()
}

/// `HEAD /{view}/store/{hash}` — queries the progress of a partial upload.
///
/// Requires `build` permission for the requested view. Returns the current
/// payload size in `Content-Length` so the same principal can resume at the
/// next offset, or `404` if that principal has no matching session.
async fn upload_progress_handler(
    Path((view, hash)): Path<(String, String)>,
    State(state): State<Arc<AppState>>,
    AuthClaims(claims): AuthClaims,
) -> Response {
    if let Err(resp) = validate_view_name(&view) {
        return resp;
    }
    if state.views.get_view(&view).is_none() {
        return (StatusCode::NOT_FOUND, "unknown view").into_response();
    }
    if !claims.has_view(&view) || !claims.has_permission("build") {
        return (StatusCode::FORBIDDEN, "build permission required").into_response();
    }
    let hash = match parse_store_hash(&hash) {
        Ok(hash) => hash,
        Err(response) => return response,
    };

    match upload_session::progress(state.views.root(), &view, &claims.sub, &hash).await {
        Ok((received, total)) => (
            StatusCode::OK,
            [
                (header::CONTENT_LENGTH, received.to_string()),
                (
                    header::HeaderName::from_static("upload-length"),
                    total.to_string(),
                ),
            ],
        )
            .into_response(),
        Err(SessionError::Missing) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => upload_session_error(error),
    }
}

/// Query parameters of `POST /{view}/build`.
#[derive(Deserialize)]
struct BuildQuery {
    /// Full store path of the `.drv` to realise.
    drv: String,
}

/// `POST /{view}/build?drv=...` — triggers a build and returns a
/// Server-Sent Events stream of its progress.
///
/// Requires a JWT authorized for the view with the `build` permission; the
/// `.drv` must already be in the store (`400` otherwise) and builds are
/// rejected with `503` while the server is draining.
///
/// Builds are deduplicated per derivation: concurrent requests for the
/// same `.drv` attach to the same underlying build. The response replays
/// buffered events first (honouring a `Last-Event-ID` header on
/// reconnection) and then streams live events until the terminal
/// `complete` or `error` event.
async fn build_handler(
    Path(view): Path<String>,
    State(state): State<Arc<AppState>>,
    AuthClaims(claims): AuthClaims,
    headers: HeaderMap,
    Query(query): Query<BuildQuery>,
) -> Response {
    if let Err(resp) = validate_view_name(&view) {
        return resp;
    }
    if state.views.get_view(&view).is_none() {
        return (StatusCode::NOT_FOUND, "unknown view").into_response();
    }

    if !claims.has_view(&view) {
        tracing::warn!(view = %view, sub = %claims.sub, "view not authorized for build");
        return (StatusCode::FORBIDDEN, "view not authorized").into_response();
    }

    if !claims.has_permission("build") {
        tracing::warn!(view = %view, sub = %claims.sub, "build permission required");
        return (StatusCode::FORBIDDEN, "build permission required").into_response();
    }

    // Reject builds during drain.
    if state.drain.is_draining() {
        tracing::warn!(view = %view, drv = %query.drv, "build rejected during drain");
        return (StatusCode::SERVICE_UNAVAILABLE, "server is shutting down").into_response();
    }

    let drv_path = &query.drv;

    // Verify the .drv exists in the store.
    match state.store.is_valid_path(drv_path) {
        Ok(true) => {}
        Ok(false) => {
            tracing::warn!(view = %view, drv = %drv_path, "derivation not found");
            return (
                StatusCode::BAD_REQUEST,
                format!("derivation not found: {drv_path}"),
            )
                .into_response();
        }
        Err(e) => {
            tracing::error!(view = %view, drv = %drv_path, error = %e, "store query failed for build");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("store query: {e}"),
            )
                .into_response();
        }
    }

    // Parse Last-Event-ID for reconnection replay.
    let last_event_id: Option<u64> = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());

    // Get or start the build (deduplication).
    let handle = state.build_mgr.get_or_start(&state, &view, drv_path);

    tracing::info!(view = %view, drv = %drv_path, "build stream started");

    // Determine the replay start point.
    let replay_from = last_event_id.map(|id| id + 1).unwrap_or(0);

    // Replay buffered events, then stream live events.
    let replay_events = handle.log_buffer.events_from(replay_from);
    let rx = handle.tx.subscribe();

    // Build a stream: first replay, then live broadcast events.
    let replay_stream = tokio_stream::iter(
        replay_events
            .into_iter()
            .map(|e| Ok::<_, Infallible>(e.to_sse())),
    );

    // Find the highest replayed ID so we don't duplicate.
    let highest_replayed = handle.log_buffer.all_events().last().map(|e| e.id);

    let live_stream = BroadcastStream::new(rx).filter_map(move |result| match result {
        Ok(event) => {
            // Skip events we already replayed.
            if let Some(max_id) = highest_replayed
                && event.id <= max_id
            {
                return None;
            }
            Some(Ok::<_, Infallible>(event.to_sse()))
        }
        Err(_) => None, // lagged — skip
    });

    let combined = replay_stream.chain(live_stream);

    let body = Body::from_stream(combined);

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/event-stream"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        body,
    )
        .into_response()
}

/// JSON body of `POST /{view}/build-closure`.
#[derive(Deserialize)]
struct BuildClosureRequest {
    /// Store paths of the `.drv`s to realise.
    drvs: Vec<String>,
}

/// `POST /{view}/build-closure` — builds multiple derivations and returns
/// a multiplexed SSE stream with events tagged by derivation.
///
/// Same auth and drain rules as the single-build endpoint; all listed
/// `.drv`s must exist up front and the list must be non-empty. Each event
/// frame uses event type `build-closure` whose JSON data carries the
/// originating `drv` plus the inner event. Per-derivation streams end at
/// their terminal event; the response stream ends once every build has
/// finished.
async fn build_closure_handler(
    Path(view): Path<String>,
    State(state): State<Arc<AppState>>,
    AuthClaims(claims): AuthClaims,
    headers: HeaderMap,
    Json(body): Json<BuildClosureRequest>,
) -> Response {
    if let Err(resp) = validate_view_name(&view) {
        return resp;
    }
    if state.views.get_view(&view).is_none() {
        return (StatusCode::NOT_FOUND, "unknown view").into_response();
    }

    if !claims.has_view(&view) {
        tracing::warn!(view = %view, sub = %claims.sub, "view not authorized for build-closure");
        return (StatusCode::FORBIDDEN, "view not authorized").into_response();
    }

    if !claims.has_permission("build") {
        tracing::warn!(view = %view, sub = %claims.sub, "build permission required for build-closure");
        return (StatusCode::FORBIDDEN, "build permission required").into_response();
    }

    if state.drain.is_draining() {
        tracing::warn!(view = %view, count = body.drvs.len(), "build-closure rejected during drain");
        return (StatusCode::SERVICE_UNAVAILABLE, "server is shutting down").into_response();
    }

    if body.drvs.is_empty() {
        return (StatusCode::BAD_REQUEST, "drvs list is empty").into_response();
    }

    // Verify all drvs exist in the store.
    for drv_path in &body.drvs {
        match state.store.is_valid_path(drv_path) {
            Ok(true) => {}
            Ok(false) => {
                tracing::warn!(view = %view, drv = %drv_path, "derivation not found in build-closure");
                return (
                    StatusCode::BAD_REQUEST,
                    format!("derivation not found: {drv_path}"),
                )
                    .into_response();
            }
            Err(e) => {
                tracing::error!(view = %view, drv = %drv_path, error = %e, "store query failed in build-closure");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("store query: {e}"),
                )
                    .into_response();
            }
        }
    }

    tracing::info!(view = %view, count = body.drvs.len(), "build-closure started");

    let last_event_id: Option<u64> = headers
        .get("last-event-id")
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse().ok());

    // Start all builds and collect handles.
    let handles: Vec<_> = body
        .drvs
        .iter()
        .map(|drv| {
            let handle = state.build_mgr.get_or_start(&state, &view, drv);
            (drv.clone(), handle)
        })
        .collect();

    // Create a merged channel that tags events with their drv.
    let (merged_tx, merged_rx) = tokio::sync::mpsc::channel::<String>(4096);

    for (drv, handle) in handles {
        let tx = merged_tx.clone();
        let replay_from = last_event_id.map(|id| id + 1).unwrap_or(0);

        tokio::spawn(async move {
            // Replay buffered events.
            for event in handle.log_buffer.events_from(replay_from) {
                let tagged = format_build_closure_sse_event(&drv, &event);
                if tx.send(tagged).await.is_err() {
                    return;
                }
            }

            // Stream live events.
            let mut rx = handle.tx.subscribe();
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        let tagged = format_build_closure_sse_event(&drv, &event);
                        if tx.send(tagged).await.is_err() {
                            return;
                        }
                        // Stop streaming for this drv on terminal events.
                        if matches!(
                            event.kind,
                            crate::build::BuildEventKind::Complete { .. }
                                | crate::build::BuildEventKind::Error { .. }
                        ) {
                            return;
                        }
                    }
                    Err(_) => return,
                }
            }
        });
    }
    drop(merged_tx); // Close when all spawned tasks finish.

    let stream = tokio_stream::wrappers::ReceiverStream::new(merged_rx).map(Ok::<_, Infallible>);

    let body = Body::from_stream(stream);

    (
        StatusCode::OK,
        [
            (header::CONTENT_TYPE, "text/event-stream"),
            (header::CACHE_CONTROL, "no-cache"),
        ],
        body,
    )
        .into_response()
}

/// Wraps a build event in the `build-closure` SSE envelope, tagging it
/// with the derivation it belongs to (the inner event's own SSE frame is
/// embedded under `"inner"`).
fn format_build_closure_sse_event(drv: &str, event: &crate::build::BuildEvent) -> String {
    format!(
        "id: {}\nevent: {}\ndata: {}\n\n",
        event.id,
        "build-closure",
        serde_json::json!({"drv": drv, "inner": event.to_sse().trim()})
    )
}

/// `POST /{view}/upload-pack` — batched store path upload in the AOSP
/// pack format.
///
/// Requires a JWT authorized for the view with the `build` permission, and
/// is subject to the view's `max_paths` quota (`507` when exceeded). The
/// body is parsed with [`pack::parse_pack`] (checksummed; `400` on any
/// corruption) and imported entry by entry; every imported path gets a
/// temporary GC root. Responds with
/// `{"accepted": N, "rejected": 0, "paths": [...]}` on success.
async fn upload_pack_handler(
    Path(view): Path<String>,
    State(state): State<Arc<AppState>>,
    AuthClaims(claims): AuthClaims,
    body: Bytes,
) -> Response {
    if let Err(resp) = validate_view_name(&view) {
        return resp;
    }
    if state.views.get_view(&view).is_none() {
        return (StatusCode::NOT_FOUND, "unknown view").into_response();
    }

    if !claims.has_view(&view) {
        tracing::warn!(view = %view, sub = %claims.sub, "view not authorized for upload-pack");
        return (StatusCode::FORBIDDEN, "view not authorized").into_response();
    }

    if !claims.has_permission("build") {
        tracing::warn!(view = %view, sub = %claims.sub, "build permission required for upload-pack");
        return (StatusCode::FORBIDDEN, "build permission required").into_response();
    }

    // Enforce per-view max_paths quota.
    if let Some(view_config) = state.views.get_view(&view)
        && let Some(max_paths) = view_config.max_paths
    {
        match state.views.count_roots(&view) {
            Ok(count) if count >= max_paths => {
                tracing::warn!(view = %view, count, max_paths, "upload-pack rejected: max_paths exceeded");
                return (
                    StatusCode::INSUFFICIENT_STORAGE,
                    format!("view has {count} rooted paths, max is {max_paths}"),
                )
                    .into_response();
            }
            Err(e) => {
                tracing::error!(view = %view, error = %e, "failed to count roots for quota check");
            }
            _ => {}
        }
    }

    let entries = match pack::parse_pack(&body, state.config.uploads.max_pack_entries) {
        Ok(e) => e,
        Err(e) => {
            tracing::warn!(view = %view, error = %e, "invalid pack upload");
            return (StatusCode::BAD_REQUEST, format!("invalid pack: {e}")).into_response();
        }
    };

    let count = entries.len();

    match pack::import_pack(&entries).await {
        Ok(paths) => {
            // Create temporary GC roots for all imported paths.
            for path in &paths {
                if let Ok(hash) = StoreHash::from_store_path(path) {
                    if let Err(e) = state.views.create_tmp_root(&view, &hash, path) {
                        tracing::warn!(view = %view, path = %path, error = %e, "failed to create tmp GC root for pack entry");
                    }
                }
            }
            tracing::info!(view = %view, accepted = count, paths = paths.len(), "pack upload completed");
            Json(serde_json::json!({
                "accepted": count,
                "rejected": 0,
                "paths": paths,
            }))
            .into_response()
        }
        Err(e) => {
            tracing::error!(view = %view, error = %e, "pack import failed");
            (StatusCode::BAD_REQUEST, format!("pack import failed: {e}")).into_response()
        }
    }
}

// ---------------------------------------------------------------------------
// GC endpoint
// ---------------------------------------------------------------------------

/// JSON body of `POST /{view}/gc`.
#[derive(Deserialize)]
struct GcRequest {
    /// Report what would be evicted without removing anything.
    #[serde(default)]
    dry_run: bool,
    /// Also run `nix-store --gc` to reclaim unrooted paths.
    #[serde(default)]
    collect: bool,
    /// Maximum budget in bytes; evict until under this size.
    max_size: Option<u64>,
}

/// `POST /{view}/gc` — triggers garbage collection for a view.
///
/// Requires a JWT authorized for the view with the `build` permission.
/// Runs up to three steps: TTL expiry of roots whose `expires_at` has
/// passed (always, even under `dry_run`), budget-based eviction when
/// `max_size` is given, and a store-wide `nix-store --gc` when `collect`
/// is set and `dry_run` is not. Responds with a JSON summary: counts of
/// expired and evicted roots, the scored eviction candidates, and (when
/// the store GC ran) the freed byte count.
async fn gc_handler(
    Path(view): Path<String>,
    State(state): State<Arc<AppState>>,
    AuthClaims(claims): AuthClaims,
    Json(body): Json<GcRequest>,
) -> Response {
    if let Err(resp) = validate_view_name(&view) {
        return resp;
    }
    if state.views.get_view(&view).is_none() {
        return (StatusCode::NOT_FOUND, "unknown view").into_response();
    }

    if !claims.has_view(&view) {
        tracing::warn!(view = %view, sub = %claims.sub, "view not authorized for gc");
        return (StatusCode::FORBIDDEN, "view not authorized").into_response();
    }

    if !claims.has_permission("build") {
        tracing::warn!(view = %view, sub = %claims.sub, "build permission required for gc");
        return (StatusCode::FORBIDDEN, "build permission required").into_response();
    }

    tracing::info!(view = %view, dry_run = body.dry_run, collect = body.collect, "GC triggered");

    use crate::evict;

    // Step 1: Expire TTL roots.
    let expired = match evict::expire_ttl_roots(&state.views, &view) {
        Ok(e) => e,
        Err(e) => {
            tracing::error!(view = %view, error = %e, "TTL expiry failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("TTL expiry: {e}"),
            )
                .into_response();
        }
    };

    if !expired.is_empty() {
        tracing::info!(view = %view, count = expired.len(), "TTL roots expired");
    }

    // Step 2: Budget-based eviction if max_size is specified.
    let mut evicted = Vec::new();
    if let Some(max_size) = body.max_size {
        match evict::evict_until_budget(&state.store, &state.views, &view, max_size, body.dry_run) {
            Ok(candidates) => {
                if !candidates.is_empty() {
                    tracing::info!(view = %view, count = candidates.len(), max_size, "eviction candidates selected");
                }
                evicted = candidates
                    .iter()
                    .map(|c| {
                        serde_json::json!({
                            "hash": c.hash,
                            "store_path": c.store_path,
                            "unique_size": c.unique_size,
                            "age_days": c.age_days,
                            "score": c.score,
                        })
                    })
                    .collect();
            }
            Err(e) => {
                tracing::error!(view = %view, error = %e, "eviction failed");
                return (StatusCode::INTERNAL_SERVER_ERROR, format!("eviction: {e}"))
                    .into_response();
            }
        }
    }

    // Step 3: Run `nix-store --gc` when collect is true and not a dry run.
    let collected = if body.collect && !body.dry_run {
        match Command::new("nix-store")
            .envs(aos_nix_env())
            .arg("--gc")
            .arg("--print-freed")
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
        {
            Ok(child) => match child.wait_with_output().await {
                Ok(output) if output.status.success() => {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    // nix-store --gc --print-freed outputs freed bytes on the last line.
                    let freed_bytes: u64 = stdout
                        .lines()
                        .last()
                        .and_then(|line| line.trim().parse().ok())
                        .unwrap_or(0);
                    tracing::info!(view = %view, freed_bytes, "nix-store --gc completed");
                    Some(serde_json::json!({
                        "freed_bytes": freed_bytes,
                    }))
                }
                Ok(output) => {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    tracing::error!(view = %view, stderr = %stderr, "nix-store --gc failed");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("nix-store --gc failed: {stderr}"),
                    )
                        .into_response();
                }
                Err(e) => {
                    tracing::error!(view = %view, error = %e, "waiting for nix-store --gc failed");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("waiting for nix-store --gc: {e}"),
                    )
                        .into_response();
                }
            },
            Err(e) => {
                tracing::error!(view = %view, error = %e, "spawning nix-store --gc failed");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("spawning nix-store --gc: {e}"),
                )
                    .into_response();
            }
        }
    } else {
        None
    };

    tracing::info!(view = %view, expired = expired.len(), evicted = evicted.len(), "GC completed");

    Json(serde_json::json!({
        "expired": expired.len(),
        "evicted": evicted.len(),
        "eviction_candidates": evicted,
        "dry_run": body.dry_run,
        "collected": collected,
    }))
    .into_response()
}

#[cfg(test)]
mod tests {
    use super::{
        NarMaterializationError, format_build_closure_sse_event, parse_nar_filename,
        parse_range_header, try_nar_materialization_permit,
    };
    use crate::build::{BuildEvent, BuildEventKind};
    use std::sync::Arc;
    use tokio::sync::Semaphore;

    #[test]
    fn build_closure_sse_wrapper_preserves_inner_activity_type() {
        let event = BuildEvent {
            id: 9,
            kind: BuildEventKind::Log {
                line: "building member".into(),
            },
        };

        let frame = format_build_closure_sse_event("/nix/store/member.drv", &event);

        assert!(frame.starts_with("id: 9\n"));
        assert!(frame.contains("event: build-closure\n"));
        assert!(frame.contains("\"drv\":\"/nix/store/member.drv\""));
        assert!(frame.contains("event: log"));
        assert!(frame.ends_with("\n\n"));
    }

    #[test]
    fn range_header_parser_accepts_single_byte_ranges() {
        assert_eq!(parse_range_header("bytes=0-1023", 4096), Some((0, 1023)));
        assert_eq!(parse_range_header("bytes=1024-", 4096), Some((1024, 4095)));
        assert_eq!(parse_range_header("bytes=-512", 4096), Some((3584, 4095)));
        assert_eq!(
            parse_range_header("bytes=3000-9999", 4096),
            Some((3000, 4095))
        );
    }

    #[test]
    fn range_header_parser_rejects_invalid_or_unsatisfied_ranges() {
        assert_eq!(parse_range_header("items=0-1", 4096), None);
        assert_eq!(parse_range_header("bytes=4096-", 4096), None);
        assert_eq!(parse_range_header("bytes=10-9", 4096), None);
        assert_eq!(parse_range_header("bytes=0-1,3-4", 4096), None);
        assert_eq!(parse_range_header("bytes=-0", 4096), None);
        assert_eq!(parse_range_header("bytes=0-0", 0), None);
    }

    #[test]
    fn nar_materialization_admission_rejects_saturation() {
        let admission = Arc::new(Semaphore::new(1));
        let first = try_nar_materialization_permit(&admission).unwrap();

        assert!(matches!(
            try_nar_materialization_permit(&admission),
            Err(NarMaterializationError::Busy)
        ));

        drop(first);
        assert!(try_nar_materialization_permit(&admission).is_ok());
    }

    #[test]
    fn nar_filenames_require_a_canonical_store_hash() {
        let valid_hash = "0123456789abcdfghijklmnpqrsvwxyz";
        assert_eq!(
            parse_nar_filename(&format!("{valid_hash}-sha256-deadbeef"))
                .unwrap()
                .as_str(),
            valid_hash
        );

        for filename in [
            "../00000000000000000000000000000000",
            "/00000000000000000000000000000000",
            "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee-sha256-deadbeef",
            "00000000000000000000000000000000.payload",
        ] {
            assert!(
                parse_nar_filename(filename).is_err(),
                "accepted {filename:?}"
            );
        }
    }
}
