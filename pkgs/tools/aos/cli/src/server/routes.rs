use std::convert::Infallible;
use std::process::Stdio;
use std::sync::Arc;

use axum::{
    body::{Body, Bytes},
    extract::{Path, Query, State},
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post, put},
    Json, Router,
};
use serde::Deserialize;
use tokio::io::AsyncWriteExt;
use tokio::process::Command;
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

use crate::server::auth::{self, AuthClaims};
use crate::server::build::BuildManager;
use crate::server::compress::{self, Compression};
use crate::server::config::ServerConfig;
use crate::server::drain::DrainState;
use crate::server::narinfo;
use crate::server::pack;
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
}

/// Build the axum router.
pub fn router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/{view}/nix-cache-info", get(cache_info_handler))
        .route("/{view}/{hash_narinfo}", get(narinfo_handler))
        .route("/{view}/nar/{filename}", get(nar_handler))
        .route("/{view}/query-missing", post(query_missing_handler))
        .route("/{view}/store/{hash}", put(upload_path_handler))
        .route("/{view}/build", post(build_handler))
        .route("/{view}/upload-pack", post(upload_pack_handler))
        .route("/oauth2/token", post(auth::oauth2_token_handler))
        .with_state(state)
}

async fn cache_info_handler(
    Path(view): Path<String>,
    State(state): State<Arc<AppState>>,
) -> Response {
    if state.views.get_view(&view).is_none() {
        return (StatusCode::NOT_FOUND, "unknown view").into_response();
    }

    let body = format!(
        "StoreDir: {}\nWantMassQuery: 1\nPriority: 30\nCapabilities: pack-upload query-missing sse-logs content-range zstd\n",
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
) -> Response {
    if state.views.get_view(&view).is_none() {
        return (StatusCode::NOT_FOUND, "unknown view").into_response();
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

    let body = narinfo::format_narinfo(&info, &state.store_dir, &state.config.compression);

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
) -> Response {
    if state.views.get_view(&view).is_none() {
        return (StatusCode::NOT_FOUND, "unknown view").into_response();
    }

    let zstd_level = state.config.compression.level;
    let (name, compression) = if let Some(name) = filename.strip_suffix(".nar.zst") {
        (name, Compression::Zstd { level: zstd_level })
    } else if let Some(name) = filename.strip_suffix(".nar") {
        (name, Compression::None)
    } else {
        return (StatusCode::BAD_REQUEST, "expected .nar or .nar.zst suffix").into_response();
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
// Build endpoints
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

async fn upload_path_handler(
    Path((view, _hash)): Path<(String, String)>,
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
        if let Err(e) = stdin.write_all(&body).await {
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

    Json(serde_json::json!({ "path": imported })).into_response()
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
