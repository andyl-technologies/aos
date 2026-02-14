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

use crate::server::access;
use crate::server::auth::{self, AuthClaims, AuthResult};
use crate::server::build::BuildManager;
use crate::server::compress::{self, Compression};
use crate::server::config::ServerConfig;
use crate::server::drain::DrainState;
use crate::server::narinfo;
use crate::server::pack;
use crate::server::sign::NarInfoSigner;
use crate::server::store::NixStore;
use crate::server::tokens::TokenStore;
use crate::server::views::ViewManager;

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

/// Build the axum router.
pub fn router(state: Arc<AppState>) -> Router {
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
        .with_state(state)
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
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("visibility check: {e}"),
            )
                .into_response()
        }
    };

    match compress::nar_stream(&store_path, compression).await {
        Ok(body) => (
            StatusCode::OK,
            [(header::CONTENT_TYPE, compression.content_type())],
            body,
        )
            .into_response(),
        Err(e) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("streaming NAR: {e}"),
        )
            .into_response(),
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

    if !claims.views.contains(&view) && !claims.views.contains(&"*".to_string()) {
        return (StatusCode::FORBIDDEN, "view not authorized").into_response();
    }

    let mut missing = Vec::new();
    for path in &body.paths {
        match state.store.is_valid_path(path) {
            Ok(true) => {}
            Ok(false) => missing.push(path.clone()),
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("store query: {e}"),
                )
                    .into_response();
            }
        }
    }

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
    crate::server::aos_root().join("uploads").join(format!("{hash}.partial"))
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

    if !claims.views.contains(&view) && !claims.views.contains(&"*".to_string()) {
        return (StatusCode::FORBIDDEN, "view not authorized").into_response();
    }

    if !claims.permissions.contains(&"build".to_string()) {
        return (StatusCode::FORBIDDEN, "build permission required").into_response();
    }

    // Check for Content-Range header for chunked/resumable uploads.
    let content_range = headers
        .get(header::CONTENT_RANGE)
        .and_then(|v| v.to_str().ok())
        .and_then(parse_content_range);

    if let Some((start, end, total)) = content_range {
        // Chunked upload: write chunk to partial file.
        let upload_dir = crate::server::aos_root().join("uploads");
        if let Err(e) = tokio::fs::create_dir_all(&upload_dir).await {
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
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("opening partial file: {e}"),
                )
                    .into_response();
            }
        };

        if let Err(e) = file.seek(std::io::SeekFrom::Start(start)).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("seeking in partial file: {e}"),
            )
                .into_response();
        }

        if let Err(e) = file.write_all(&body).await {
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
            let full_data = match tokio::fs::read(&partial_path).await {
                Ok(d) => d,
                Err(e) => {
                    return (
                        StatusCode::INTERNAL_SERVER_ERROR,
                        format!("reading assembled file: {e}"),
                    )
                        .into_response();
                }
            };

            // Clean up the partial file.
            let _ = tokio::fs::remove_file(&partial_path).await;

            return import_nar_data(&full_data).await;
        }

        // Not the final chunk — return 202 Accepted.
        return (
            StatusCode::ACCEPTED,
            Json(serde_json::json!({ "received": received, "total": total })),
        )
            .into_response();
    }

    // No Content-Range — import the full body directly (original behavior).
    import_nar_data(&body).await
}

/// Import NAR data via `nix-store --import` and return the JSON response.
async fn import_nar_data(data: &[u8]) -> Response {
    let mut child = match Command::new("nix-store")
        .arg("--import")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(c) => c,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("spawning nix-store --import: {e}"),
            )
                .into_response();
        }
    };

    if let Some(mut stdin) = child.stdin.take() {
        if let Err(e) = stdin.write_all(data).await {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("writing NAR to nix-store: {e}"),
            )
                .into_response();
        }
        drop(stdin);
    }

    let output = match child.wait_with_output().await {
        Ok(o) => o,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("waiting for nix-store --import: {e}"),
            )
                .into_response();
        }
    };

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return (
            StatusCode::BAD_REQUEST,
            format!("nix-store --import failed: {stderr}"),
        )
            .into_response();
    }

    let imported = String::from_utf8_lossy(&output.stdout).trim().to_string();

    if let Err(reason) = pack::validate_imported_path(&imported) {
        return (StatusCode::BAD_REQUEST, reason).into_response();
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

    if !claims.views.contains(&view) && !claims.views.contains(&"*".to_string()) {
        return (StatusCode::FORBIDDEN, "view not authorized").into_response();
    }

    if !claims.permissions.contains(&"build".to_string()) {
        return (StatusCode::FORBIDDEN, "build permission required").into_response();
    }

    // Reject builds during drain.
    if state.drain.is_draining() {
        return (StatusCode::SERVICE_UNAVAILABLE, "server is shutting down").into_response();
    }

    let drv_path = &query.drv;

    // Verify the .drv exists in the store.
    match state.store.is_valid_path(drv_path) {
        Ok(true) => {}
        Ok(false) => {
            return (
                StatusCode::BAD_REQUEST,
                format!("derivation not found: {drv_path}"),
            )
                .into_response();
        }
        Err(e) => {
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

/// `POST /:view/build-closure` — trigger builds for multiple derivations,
/// return a multiplexed SSE stream with events tagged by drv.
async fn build_closure_handler(
    Path(view): Path<String>,
    State(state): State<Arc<AppState>>,
    AuthClaims(claims): AuthClaims,
    Json(body): Json<BuildClosureRequest>,
) -> Response {
    if state.views.get_view(&view).is_none() {
        return (StatusCode::NOT_FOUND, "unknown view").into_response();
    }

    if !claims.views.contains(&view) && !claims.views.contains(&"*".to_string()) {
        return (StatusCode::FORBIDDEN, "view not authorized").into_response();
    }

    if !claims.permissions.contains(&"build".to_string()) {
        return (StatusCode::FORBIDDEN, "build permission required").into_response();
    }

    if state.drain.is_draining() {
        return (StatusCode::SERVICE_UNAVAILABLE, "server is shutting down").into_response();
    }

    if body.drvs.is_empty() {
        return (StatusCode::BAD_REQUEST, "drvs array must not be empty").into_response();
    }

    // Verify all drvs exist and start builds.
    let mut handles = Vec::new();
    for drv_path in &body.drvs {
        match state.store.is_valid_path(drv_path) {
            Ok(true) => {}
            Ok(false) => {
                return (
                    StatusCode::BAD_REQUEST,
                    format!("derivation not found: {drv_path}"),
                )
                    .into_response();
            }
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("store query: {e}"),
                )
                    .into_response();
            }
        }

        let handle = state.build_mgr.get_or_start(&state, &view, drv_path);
        handles.push((drv_path.clone(), handle));
    }

    // Create a merged SSE stream that tags each event with its drv path.
    let streams: Vec<_> = handles
        .into_iter()
        .map(|(drv, handle)| {
            let replay_events = handle.log_buffer.events_from(0);
            let rx = handle.tx.subscribe();

            let highest_replayed = handle
                .log_buffer
                .all_events()
                .last()
                .map(|e| e.id);

            let drv_replay = drv.clone();
            let replay_stream = tokio_stream::iter(
                replay_events
                    .into_iter()
                    .map(move |e| {
                        Ok::<_, Infallible>(format!(
                            "event: build\ndata: {{\"drv\":{},\"event\":{}}}\n\n",
                            serde_json::json!(drv_replay),
                            e.to_sse().trim(),
                        ))
                    }),
            );

            let drv_live = drv;
            let live_stream = BroadcastStream::new(rx)
                .filter_map(move |result| match result {
                    Ok(event) => {
                        if let Some(max_id) = highest_replayed {
                            if event.id <= max_id {
                                return None;
                            }
                        }
                        Some(Ok::<_, Infallible>(format!(
                            "event: build\ndata: {{\"drv\":{},\"event\":{}}}\n\n",
                            serde_json::json!(drv_live),
                            event.to_sse().trim(),
                        )))
                    }
                    Err(_) => None,
                });

            replay_stream.chain(live_stream)
        })
        .collect();

    // Merge all streams using select_all for fair interleaving.
    let merged = tokio_stream::StreamExt::map(
        futures_util::stream::select_all(streams),
        |item| item,
    );

    let body = Body::from_stream(merged);

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

    if !claims.views.contains(&view) && !claims.views.contains(&"*".to_string()) {
        return (StatusCode::FORBIDDEN, "view not authorized").into_response();
    }

    if !claims.permissions.contains(&"build".to_string()) {
        return (StatusCode::FORBIDDEN, "build permission required").into_response();
    }

    if state.drain.is_draining() {
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
                return (
                    StatusCode::BAD_REQUEST,
                    format!("derivation not found: {drv_path}"),
                )
                    .into_response();
            }
            Err(e) => {
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("store query: {e}"),
                )
                    .into_response();
            }
        }
    }

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
                            crate::server::build::BuildEventKind::Complete { .. }
                                | crate::server::build::BuildEventKind::Error { .. }
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

    if !claims.views.contains(&view) && !claims.views.contains(&"*".to_string()) {
        return (StatusCode::FORBIDDEN, "view not authorized").into_response();
    }

    if !claims.permissions.contains(&"build".to_string()) {
        return (StatusCode::FORBIDDEN, "build permission required").into_response();
    }

    let entries = match pack::parse_pack(&body) {
        Ok(e) => e,
        Err(e) => {
            return (StatusCode::BAD_REQUEST, format!("invalid pack: {e}")).into_response();
        }
    };

    let count = entries.len();

    match pack::import_pack(&entries).await {
        Ok(paths) => Json(serde_json::json!({
            "accepted": count,
            "rejected": 0,
            "paths": paths,
        }))
        .into_response(),
        Err(e) => (StatusCode::BAD_REQUEST, format!("pack import failed: {e}")).into_response(),
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

    if !claims.views.contains(&view) && !claims.views.contains(&"*".to_string()) {
        return (StatusCode::FORBIDDEN, "view not authorized").into_response();
    }

    if !claims.permissions.contains(&"build".to_string()) {
        return (StatusCode::FORBIDDEN, "build permission required").into_response();
    }

    use crate::server::evict;

    // Step 1: Expire TTL roots.
    let expired = match evict::expire_ttl_roots(&state.views, &view) {
        Ok(e) => e,
        Err(e) => {
            return (
                StatusCode::INTERNAL_SERVER_ERROR,
                format!("TTL expiry: {e}"),
            )
                .into_response();
        }
    };

    // Step 2: Budget-based eviction if max_size is specified.
    let mut evicted = Vec::new();
    if let Some(max_size) = body.max_size {
        match evict::evict_until_budget(&state.store, &state.views, &view, max_size, body.dry_run) {
            Ok(candidates) => {
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
                return (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    format!("eviction: {e}"),
                )
                    .into_response();
            }
        }
    }

    Json(serde_json::json!({
        "expired": expired.len(),
        "evicted": evicted.len(),
        "eviction_candidates": evicted,
        "dry_run": body.dry_run,
    }))
    .into_response()
}
