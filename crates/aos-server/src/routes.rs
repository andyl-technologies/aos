use std::convert::Infallible;
use std::process::Stdio;
use std::sync::Arc;

use axum::{
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, head, post, put},
    Json, Router,
};
use serde::Deserialize;
use tokio::io::{AsyncSeekExt, AsyncWriteExt};
use tokio::process::Command;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use crate::access;
use crate::auth::{self, AuthClaims, AuthResult};
use crate::build::BuildManager;
use crate::compress::{self, Compression};
use crate::config::ServerConfig;
use crate::drain::DrainState;
use crate::narinfo;
use crate::pack;
use crate::sign::NarInfoSigner;
use crate::store::NixStore;
use crate::tokens::TokenStore;
use crate::views::ViewManager;

use tracing;

// ConnectRPC service extension traits for registration
use aos_proto::aos::auth::v1::AuthServiceExt;
use aos_proto::aos::build::v1::BuildServiceExt;
use aos_proto::aos::cache::v1::CacheServiceExt;
use aos_proto::aos::gc::v1::GcServiceExt;

use crate::services;

/// Shared server state.
pub struct AppState {
    pub store: NixStore,
    pub views: ViewManager,
    pub config: ServerConfig,
    pub store_dir: String,
    pub jwt_secret: Vec<u8>,
    pub tokens: TokenStore,
    pub build_mgr: Arc<BuildManager>,
    pub drain: Arc<DrainState>,
    pub signer: NarInfoSigner,
}

/// Build the axum router with both REST and ConnectRPC endpoints.
pub fn router(state: Arc<AppState>) -> Router {
    // Build ConnectRPC service router.
    let connect_router = build_connectrpc_router(Arc::clone(&state));

    // Existing REST routes remain — ConnectRPC is served via fallback so
    // both coexist on the same port.
    Router::new()
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
        .route("/oauth2/token", post(auth::oauth2_token_handler))
        .fallback_service(connect_router.into_axum_service())
        .with_state(state)
}

/// Build the ConnectRPC service router with all RPC services registered.
fn build_connectrpc_router(state: Arc<AppState>) -> connectrpc::Router {
    let cache_svc = Arc::new(services::cache::CacheServiceImpl {
        state: Arc::clone(&state),
    });
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
    let router = auth_svc.register(router);

    router
}

// ---------------------------------------------------------------------------
// Read-only endpoints (respect anonymous_read)
// ---------------------------------------------------------------------------

async fn cache_info_handler(
    Path(view): Path<String>,
    State(state): State<Arc<AppState>>,
    auth: AuthResult,
) -> Response {
    let view_config = match state.views.get_view(&view) {
        Some(v) => v,
        None => return (StatusCode::NOT_FOUND, "unknown view").into_response(),
    };

    // Enforce auth unless anonymous_read is enabled.
    if !view_config.anonymous_read {
        if let AuthResult::Anonymous = auth {
            tracing::warn!(view = %view, "auth required for cache-info");
            return (StatusCode::UNAUTHORIZED, "authentication required").into_response();
        }
    }

    let body = format!(
        "StoreDir: {}\nWantMassQuery: 1\nPriority: 30\nCapabilities: pack-upload query-missing sse-logs zstd xz content-range\n",
        state.store_dir
    );

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain")],
        body,
    )
        .into_response()
}

async fn narinfo_handler(
    Path((view, hash_narinfo)): Path<(String, String)>,
    State(state): State<Arc<AppState>>,
    auth: AuthResult,
) -> Response {
    let view_config = match state.views.get_view(&view) {
        Some(v) => v,
        None => return (StatusCode::NOT_FOUND, "unknown view").into_response(),
    };

    if !view_config.anonymous_read {
        if let AuthResult::Anonymous = auth {
            tracing::warn!(view = %view, hash = %hash_narinfo, "auth required for narinfo");
            return (StatusCode::UNAUTHORIZED, "authentication required").into_response();
        }
    }

    let hash = match hash_narinfo.strip_suffix(".narinfo") {
        Some(h) => h,
        None => return (StatusCode::BAD_REQUEST, "expected .narinfo suffix").into_response(),
    };

    let store_path = match state.views.check_visibility(&view, hash) {
        Ok(Some(path)) => path,
        Ok(None) => return (StatusCode::NOT_FOUND, "path not in view").into_response(),
        Err(e) => {
            tracing::error!(view = %view, hash = %hash, error = %e, "visibility check failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("visibility check: {e}"),
            )
                .into_response()
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
                .into_response()
        }
    };

    // Update access metadata (best-effort, don't fail the request).
    let _ = access::update_access(&state.views, &view, hash);

    let body = narinfo::format_narinfo(&info, &state.store_dir, &state.config.compression, Some(&state.signer));

    tracing::info!(view = %view, hash = %hash, "narinfo served");

    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/x-nix-narinfo")],
        body,
    )
        .into_response()
}

async fn nar_handler(
    Path((view, filename)): Path<(String, String)>,
    State(state): State<Arc<AppState>>,
    auth: AuthResult,
) -> Response {
    let view_config = match state.views.get_view(&view) {
        Some(v) => v,
        None => return (StatusCode::NOT_FOUND, "unknown view").into_response(),
    };

    if !view_config.anonymous_read {
        if let AuthResult::Anonymous = auth {
            tracing::warn!(view = %view, filename = %filename, "auth required for NAR");
            return (StatusCode::UNAUTHORIZED, "authentication required").into_response();
        }
    }

    let zstd_level = state.config.compression.level;
    let (name, compression) = if let Some(name) = filename.strip_suffix(".nar.zst") {
        (name, Compression::Zstd { level: zstd_level })
    } else if let Some(name) = filename.strip_suffix(".nar.xz") {
        (name, Compression::Xz { level: zstd_level })
    } else if let Some(name) = filename.strip_suffix(".nar") {
        (name, Compression::None)
    } else {
        return (StatusCode::BAD_REQUEST, "expected .nar, .nar.zst, or .nar.xz suffix").into_response();
    };

    let store_hash = match name.split('-').next() {
        Some(h) if !h.is_empty() => h,
        _ => return (StatusCode::BAD_REQUEST, "invalid NAR filename").into_response(),
    };

    let store_path = match state.views.check_visibility(&view, store_hash) {
        Ok(Some(path)) => path,
        Ok(None) => return (StatusCode::NOT_FOUND, "path not in view").into_response(),
        Err(e) => {
            tracing::error!(view = %view, hash = %store_hash, error = %e, "visibility check failed");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("visibility check: {e}"),
            )
                .into_response()
        }
    };

    match compress::nar_stream(&store_path, compression).await {
        Ok(body) => {
            tracing::info!(view = %view, hash = %store_hash, compression = %compression.narinfo_name(), "NAR streamed");
            (
                StatusCode::OK,
                [(header::CONTENT_TYPE, compression.content_type())],
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

// ---------------------------------------------------------------------------
// Build endpoints (require auth)
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
struct QueryMissingRequest {
    paths: Vec<String>,
}

async fn query_missing_handler(
    Path(view): Path<String>,
    State(state): State<Arc<AppState>>,
    AuthClaims(claims): AuthClaims,
    Json(body): Json<QueryMissingRequest>,
) -> Response {
    if state.views.get_view(&view).is_none() {
        return (StatusCode::NOT_FOUND, "unknown view").into_response();
    }

    if !claims.has_view(&view) {
        tracing::warn!(view = %view, sub = %claims.sub, "view not authorized for query-missing");
        return (StatusCode::FORBIDDEN, "view not authorized").into_response();
    }

    let mut missing = Vec::new();
    for path in &body.paths {
        match state.store.is_valid_path(path) {
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

/// Parse a `Content-Range: bytes start-end/total` header value.
/// Returns `(start, end, total)` on success.
fn parse_content_range(value: &str) -> Option<(u64, u64, u64)> {
    let rest = value.strip_prefix("bytes ")?;
    let (range, total_str) = rest.split_once('/')?;
    let (start_str, end_str) = range.split_once('-')?;
    let start: u64 = start_str.parse().ok()?;
    let end: u64 = end_str.parse().ok()?;
    let total: u64 = total_str.parse().ok()?;
    if start > end || end >= total {
        return None;
    }
    Some((start, end, total))
}

/// Return the path to the partial upload file for a given hash.
fn partial_upload_path(hash: &str) -> std::path::PathBuf {
    crate::aos_root().join("uploads").join(format!("{hash}.partial"))
}

async fn upload_path_handler(
    Path((view, hash)): Path<(String, String)>,
    State(state): State<Arc<AppState>>,
    AuthClaims(claims): AuthClaims,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if state.views.get_view(&view).is_none() {
        return (StatusCode::NOT_FOUND, "unknown view").into_response();
    }

    if !claims.has_view(&view) {
        tracing::warn!(view = %view, sub = %claims.sub, "view not authorized for upload");
        return (StatusCode::FORBIDDEN, "view not authorized").into_response();
    }

    if !claims.has_permission("build") {
        tracing::warn!(view = %view, sub = %claims.sub, "build permission required for upload");
        return (StatusCode::FORBIDDEN, "build permission required").into_response();
    }

    // Enforce per-view max_paths quota.
    if let Some(view_config) = state.views.get_view(&view) {
        if let Some(max_paths) = view_config.max_paths {
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
    }

    // Check for Content-Range header for chunked/resumable uploads.
    let content_range = headers
        .get(header::CONTENT_RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_content_range);

    if let Some((start, end, total)) = content_range {
        // Chunked upload: write chunk to partial file.
        let upload_dir = crate::aos_root().join("uploads");
        if let Err(e) = tokio::fs::create_dir_all(&upload_dir).await {
            tracing::error!(view = %view, hash = %hash, error = %e, "failed to create upload dir");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("creating upload dir: {e}"),
            )
                .into_response();
        }

        let partial_path = partial_upload_path(&hash);

        let file = tokio::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(false)
            .open(&partial_path)
            .await;

        let mut file = match file {
            Ok(f) => f,
            Err(e) => {
                tracing::error!(view = %view, hash = %hash, error = %e, "failed to open partial file");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("opening partial file: {e}"),
                )
                    .into_response();
            }
        };

        if let Err(e) = file.seek(std::io::SeekFrom::Start(start)).await {
            tracing::error!(view = %view, hash = %hash, error = %e, "failed to seek in partial file");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("seeking in partial file: {e}"),
            )
                .into_response();
        }

        if let Err(e) = file.write_all(&body).await {
            tracing::error!(view = %view, hash = %hash, error = %e, "failed to write chunk");
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("writing chunk to partial file: {e}"),
            )
                .into_response();
        }

        drop(file);

        let received = end + 1;

        // If this is the final chunk, import the assembled file.
        if received == total {
            tracing::info!(view = %view, hash = %hash, total_bytes = total, "chunked upload complete, importing");
            let full_data = match tokio::fs::read(&partial_path).await {
                Ok(d) => d,
                Err(e) => {
                    tracing::error!(view = %view, hash = %hash, error = %e, "failed to read assembled file");
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("reading assembled file: {e}"),
                    )
                        .into_response();
                }
            };

            // Clean up the partial file.
            let _ = tokio::fs::remove_file(&partial_path).await;

            return import_nar_with_tmp_root(&full_data, &state.views, &view).await;
        }

        // Not the final chunk — return 202 Accepted.
        return (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({ "received": received, "total": total })),
        )
            .into_response();
    }

    // No Content-Range — import the full body directly (original behavior).
    tracing::info!(view = %view, hash = %hash, bytes = body.len(), "upload received, importing");
    import_nar_with_tmp_root(&body, &state.views, &view).await
}

/// Import NAR data via `nix-store --import` and return the imported store path.
async fn import_nar(data: &[u8]) -> Result<String, Response> {
    let mut child = Command::new("nix-store")
        .arg("--import")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .map_err(|e| {
            tracing::error!(error = %e, "failed to spawn nix-store --import");
            (StatusCode::INTERNAL_SERVER_ERROR, format!("spawning nix-store --import: {e}")).into_response()
        })?;

    if let Some(mut stdin) = child.stdin.take() {
        stdin.write_all(data).await.map_err(|e| {
            tracing::error!(error = %e, "failed to write NAR to nix-store");
            (StatusCode::INTERNAL_SERVER_ERROR, format!("writing NAR to nix-store: {e}")).into_response()
        })?;
        drop(stdin);
    }

    let output = child.wait_with_output().await.map_err(|e| {
        tracing::error!(error = %e, "failed waiting for nix-store --import");
        (StatusCode::INTERNAL_SERVER_ERROR, format!("waiting for nix-store --import: {e}")).into_response()
    })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        tracing::error!(stderr = %stderr, "nix-store --import failed");
        return Err((StatusCode::BAD_REQUEST, format!("nix-store --import failed: {stderr}")).into_response());
    }

    let imported = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if let Err(reason) = pack::validate_imported_path(&imported) {
        tracing::warn!(path = %imported, reason = %reason, "imported path rejected");
        return Err((StatusCode::BAD_REQUEST, reason).into_response());
    }

    tracing::info!(path = %imported, "store path imported");
    Ok(imported)
}

/// Import NAR data and create a temporary GC root in the given view.
async fn import_nar_with_tmp_root(data: &[u8], views: &ViewManager, view: &str) -> Response {
    let imported = match import_nar(data).await {
        Ok(path) => path,
        Err(resp) => return resp,
    };

    // Create a temporary GC root to protect the path until its build creates bin/ roots.
    if let Some(hash) = ViewManager::store_path_hash(&imported) {
        if let Err(e) = views.create_tmp_root(view, hash, &imported) {
            tracing::warn!(view = %view, path = %imported, error = %e, "failed to create tmp GC root");
        }
    }

    Json(serde_json::json!({ "path": imported })).into_response()
}

/// `HEAD /:view/store/:hash` — query the progress of a partial upload.
///
/// Returns the current size of the partial upload file in `Content-Length`.
/// Returns 404 if no partial upload exists for the given hash.
async fn upload_progress_handler(
    Path((view, hash)): Path<(String, String)>,
    State(state): State<Arc<AppState>>,
    AuthClaims(_claims): AuthClaims,
) -> Response {
    if state.views.get_view(&view).is_none() {
        return (StatusCode::NOT_FOUND, "unknown view").into_response();
    }

    let partial_path = partial_upload_path(&hash);

    match tokio::fs::metadata(&partial_path).await {
        Ok(meta) => {
            let size = meta.len();
            (
                StatusCode::OK,
                [(header::CONTENT_LENGTH, size.to_string())],
            )
                .into_response()
        }
        Err(_) => StatusCode::NOT_FOUND.into_response(),
    }
}

#[derive(Deserialize)]
struct BuildQuery {
    drv: String,
}

/// `POST /:view/build?drv=...` — trigger a build, return SSE event stream.
///
/// Supports `Last-Event-ID` header for reconnection replay.
async fn build_handler(
    Path(view): Path<String>,
    State(state): State<Arc<AppState>>,
    AuthClaims(claims): AuthClaims,
    headers: HeaderMap,
    Query(query): Query<BuildQuery>,
) -> Response {
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
    let handle = state
        .build_mgr
        .get_or_start(&state, &view, drv_path);

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
    let highest_replayed = handle
        .log_buffer
        .all_events()
        .last()
        .map(|e| e.id);

    let live_stream = BroadcastStream::new(rx)
        .filter_map(move |result| match result {
            Ok(event) => {
                // Skip events we already replayed.
                if let Some(max_id) = highest_replayed {
                    if event.id <= max_id {
                        return None;
                    }
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

#[derive(Deserialize)]
struct BuildClosureRequest {
    drvs: Vec<String>,
}

/// `POST /:view/build-closure` — build multiple derivations and return a
/// multiplexed SSE stream with events tagged by derivation.
async fn build_closure_handler(
    Path(view): Path<String>,
    State(state): State<Arc<AppState>>,
    AuthClaims(claims): AuthClaims,
    headers: HeaderMap,
    Json(body): Json<BuildClosureRequest>,
) -> Response {
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
                let tagged = format!(
                    "id: {}\nevent: {}\ndata: {}\n\n",
                    event.id,
                    "build-closure",
                    serde_json::json!({"drv": drv, "inner": event.to_sse().trim()})
                );
                if tx.send(tagged).await.is_err() {
                    return;
                }
            }

            // Stream live events.
            let mut rx = handle.tx.subscribe();
            loop {
                match rx.recv().await {
                    Ok(event) => {
                        let tagged = format!(
                            "id: {}\nevent: {}\ndata: {}\n\n",
                            event.id,
                            "build-closure",
                            serde_json::json!({"drv": drv, "inner": event.to_sse().trim()})
                        );
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

    let stream = tokio_stream::wrappers::ReceiverStream::new(merged_rx)
        .map(|s| Ok::<_, Infallible>(s));

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

async fn upload_pack_handler(
    Path(view): Path<String>,
    State(state): State<Arc<AppState>>,
    AuthClaims(claims): AuthClaims,
    body: Bytes,
) -> Response {
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
    if let Some(view_config) = state.views.get_view(&view) {
        if let Some(max_paths) = view_config.max_paths {
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
    }

    let entries = match pack::parse_pack(&body) {
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
                if let Some(hash) = ViewManager::store_path_hash(path) {
                    if let Err(e) = state.views.create_tmp_root(&view, hash, path) {
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

#[derive(Deserialize)]
struct GcRequest {
    #[serde(default)]
    dry_run: bool,
    #[serde(default)]
    collect: bool,
    /// Maximum budget in bytes; evict until under this size.
    max_size: Option<u64>,
}

/// `POST /:view/gc` — trigger garbage collection for a view.
async fn gc_handler(
    Path(view): Path<String>,
    State(state): State<Arc<AppState>>,
    AuthClaims(claims): AuthClaims,
    Json(body): Json<GcRequest>,
) -> Response {
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
                    .map(|c| serde_json::json!({
                        "hash": c.hash,
                        "store_path": c.store_path,
                        "unique_size": c.unique_size,
                        "age_days": c.age_days,
                        "score": c.score,
                    }))
                    .collect();
            }
            Err(e) => {
                tracing::error!(view = %view, error = %e, "eviction failed");
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("eviction: {e}"),
                )
                    .into_response();
            }
        }
    }

    // Step 3: Run `nix-store --gc` when collect is true and not a dry run.
    let collected = if body.collect && !body.dry_run {
        match Command::new("nix-store")
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
