//! The machine-path *write* facade: authenticated surface uploads.
//!
//! This is the upload half of the byte-faithful facade
//! ([`crate::compat`] serves reads). A managed registry's on-disk surface
//! is published by writing each relative file path of the static origin
//! under the registry's canonical URL, exactly as `apr origin upload` and
//! `apr cache generate --upload-url` already write to any generic binary
//! cache. The hub is therefore a drop-in upload target — *"like magic"* —
//! requiring no client changes.
//!
//! # Shared write handler
//!
//! RFC-0004 Phase 5 stage H2 moved the upload logic into the shared,
//! transport-free service
//! ([`RpcService::put_machine_path`](aos_hub_core::service::RpcService::put_machine_path)
//! / [`head_machine_path`](aos_hub_core::service::RpcService::head_machine_path)),
//! so the *same* handler runs on the native hub and the Cloudflare Worker (which
//! mounts it on the shared `/{slug}/{*path}` facade route, letting the Worker
//! store published artifacts). The native hub keeps its own richer
//! `/{slug}/{*path}` route — filesystem autoindex, `http(s)` redirect,
//! pull-through mirroring, inert producer-document serving, session-cookie
//! authorization, and **nested-canonical (slash) slug resolution** the flat
//! shared route cannot express — so its `PUT`/`HEAD` route methods stay in
//! [`crate::server`] and *delegate* to the shared handler through the thin
//! [`put_machine_path`]/[`head_machine_path`] shims here. Every check (publish
//! authorization, the TOCTOU-safe quota reserve-before-write, the publish lease,
//! the inline re-index, and the `507`/`413`/`409`/`400`/`404`/`405` status
//! contract) lives once, in core.
//!
//! # Discovered upload wire protocol
//!
//! The producer CLIs upload a registry surface through
//! `aos_cache::backend::CacheBackend::put_static_file`
//! (`crates/aos-package/src/registry/static_upload.rs`):
//!
//! ```text
//! PUT  {base_url}/{relative_path}
//! Authorization: Bearer <jwt>          (from --header, attached to every request)
//! Content-Type:  <per-file>            (text/x-nix-narinfo, application/zstd, …)
//! Cache-Control: <per-file>            (immutable for objects/NARs, revalidate for pointers)
//! <file bytes as the body>
//!
//! HEAD {base_url}/{relative_path}      (query_missing in generic mode probes existence)
//! ```
//!
//! A `2xx` is success; a `>= 400` status is an upload failure. The facade
//! requires [`Permission::Publish`](aos_hub_core::domain::Permission::Publish)
//! on the registry's canonical [`Scope`](aos_hub_core::domain::Scope).

use std::sync::Arc;

use axum::body::Bytes;
use axum::http::{header, HeaderMap};
use axum::response::Response;

use aos_hub_core::service::{FacadeWrite, RpcService};

use crate::server::AppState;

/// The native, process-local publish lease backing the upload facade.
///
/// Relocated to shared core ([`aos_hub_core::lease`]) in RFC-0004 Phase 5
/// stage H2 and re-exported here under its historical hub name so the
/// [`AppState`](crate::server::AppState) field and existing call sites keep their
/// shape. It serializes a registry's mutable-pointer flips within one hub
/// process; a cross-process deployment uses the Worker's D1-backed lease (the
/// "later phase multi-process" lease).
pub use aos_hub_core::lease::InMemoryLease as LeaseMap;

/// Maximum surface-file upload size accepted by a single `PUT` (256 MiB).
///
/// Re-exported from shared core so the router's per-route body-limit layer
/// ([`crate::server`]) and the upload handler agree on one bound; a body past
/// this cap is rejected `413 Payload Too Large`.
pub use aos_hub_core::service::MAX_UPLOAD_BYTES;

/// Build the shared write-capable [`RpcService`] over the hub's `AppState`.
///
/// The shims below construct a throwaway service from the `AppState`'s shared
/// `Arc`s (the database, JWT keys, base URL, rate limiter, and the native
/// surface/write/lease/reindex ports). All fields are cheap `Arc` clones, so the
/// per-request build is negligible, and it keeps the hub's `PUT`/`HEAD` route
/// methods on the single-source shared handler without storing a service handle
/// in `AppState` (which would change its struct shape across every call site).
///
/// The lease passed is the *same* [`AppState::leases`](crate::server::AppState)
/// the hub holds, so the facade's pointer-flip serialization is process-wide,
/// not per-request.
pub(crate) fn write_service(state: &AppState) -> RpcService {
    RpcService::new(
        Arc::clone(&state.db),
        state.auth.jwt_keys.clone(),
        state.external_url.clone(),
        Arc::clone(&state.ratelimit) as Arc<dyn aos_hub_core::ratelimit::RateLimiter>,
        Arc::new(crate::coreports::HubSurfaceProvider::new(Arc::clone(
            &state.db,
        ))),
        Arc::new(crate::coreports::HubSurfaceWriteProvider::new(Arc::clone(
            &state.db,
        ))),
        Arc::clone(&state.leases) as Arc<dyn aos_hub_core::lease::PublishLease>,
        Arc::new(crate::coreports::HubReindexer::new(Arc::clone(&state.db))),
        Some(Arc::clone(&state.sealer)),
    )
}

/// Pull the raw `Authorization` header value, if present and ASCII.
fn auth_value(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// Handle a `PUT` of one surface path for a managed registry.
///
/// A thin shim over the shared
/// [`RpcService::put_machine_path`](aos_hub_core::service::RpcService::put_machine_path):
/// the hub's `/{slug}/{*path}` route resolves the target registry slug (including
/// nested-canonical slash slugs) and the surface tail, then calls this; the
/// shared handler performs every check and write. The returned [`FacadeWrite`]
/// is rendered to the byte-identical HTTP response.
pub async fn put_machine_path(
    state: &AppState,
    slug: &str,
    path: &str,
    headers: &HeaderMap,
    body: Bytes,
) -> Response {
    let auth = auth_value(headers);
    let outcome = write_service(state)
        .put_machine_path(auth.as_deref(), slug, path, &body)
        .await;
    render(outcome, path)
}

/// Handle a `HEAD` of one surface path for a managed registry.
///
/// A thin shim over the shared
/// [`RpcService::head_machine_path`](aos_hub_core::service::RpcService::head_machine_path)
/// (see [`put_machine_path`]). Lets an uploader skip files it has already pushed:
/// `200` when the file exists, `404` when it does not; authorization matches the
/// `PUT` (a probe reveals surface contents, so it requires `Publish`).
pub async fn head_machine_path(
    state: &AppState,
    slug: &str,
    path: &str,
    headers: &HeaderMap,
) -> Response {
    let auth = auth_value(headers);
    let outcome = write_service(state)
        .head_machine_path(auth.as_deref(), slug, path)
        .await;
    render(outcome, path)
}

/// Stream a cache surface file from disk, honoring a `Range:` request.
///
/// The native cache read path **streams** (rather than buffering the whole NAR
/// into memory like the registry `compat` reader), so a multi-hundred-MB NAR
/// never sits in RAM. A `Range: bytes=…` request is answered with `206 Partial
/// Content` + `Content-Range`; every response advertises `Accept-Ranges: bytes`.
/// Authorization/visibility is the caller's responsibility
/// ([`crate::server::authorize_cache_read`]); this serves bytes from an
/// already-authorized cache surface, with symlink containment under `root`.
pub async fn cache_serve_file(root: &std::path::Path, rel: &str, headers: &HeaderMap) -> Response {
    use axum::body::Body;
    use axum::http::StatusCode;
    use axum::response::IntoResponse as _;
    use tokio::io::{AsyncReadExt as _, AsyncSeekExt as _};
    use tokio_util::io::ReaderStream;

    let Ok(target) = crate::fetch::safe_join(root, rel) else {
        return StatusCode::BAD_REQUEST.into_response();
    };
    // Symlink containment: the resolved file must stay under the real surface
    // root (the same guard `LocalFsFetch` applies to buffered reads).
    let (real_root, real_target) =
        match (tokio::fs::canonicalize(root).await, tokio::fs::canonicalize(&target).await) {
            (Ok(r), Ok(t)) => (r, t),
            _ => return StatusCode::NOT_FOUND.into_response(),
        };
    if !real_target.starts_with(&real_root) {
        return StatusCode::NOT_FOUND.into_response();
    }
    let file = match tokio::fs::File::open(&real_target).await {
        Ok(f) => f,
        Err(_) => return StatusCode::NOT_FOUND.into_response(),
    };
    let total = match file.metadata().await {
        Ok(m) => m.len(),
        Err(_) => return StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    };
    let ct = aos_hub_core::keymap::content_type(rel);
    let cc = aos_hub_core::keymap::cache_control(rel);

    if let Some((start, end)) = parse_range(headers, total) {
        let len = end - start + 1;
        let mut file = file;
        if file.seek(std::io::SeekFrom::Start(start)).await.is_err() {
            return StatusCode::INTERNAL_SERVER_ERROR.into_response();
        }
        let stream = ReaderStream::new(file.take(len));
        return axum::http::Response::builder()
            .status(StatusCode::PARTIAL_CONTENT)
            .header(header::CONTENT_TYPE, ct)
            .header(header::CACHE_CONTROL, cc)
            .header(header::ACCEPT_RANGES, "bytes")
            .header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{total}"))
            .header(header::CONTENT_LENGTH, len)
            .body(Body::from_stream(stream))
            .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response());
    }

    let stream = ReaderStream::new(file);
    axum::http::Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, ct)
        .header(header::CACHE_CONTROL, cc)
        .header(header::ACCEPT_RANGES, "bytes")
        .header(header::CONTENT_LENGTH, total)
        .body(Body::from_stream(stream))
        .unwrap_or_else(|_| StatusCode::INTERNAL_SERVER_ERROR.into_response())
}

/// Parse a single-range `Range: bytes=start-end` header against `total` bytes.
///
/// Returns the inclusive `(start, end)` range, or `None` when there is no
/// `Range`, it is malformed, multi-range, or unsatisfiable (the caller then
/// serves the full body). Supports `bytes=START-`, `bytes=START-END`, and the
/// suffix form `bytes=-SUFFIXLEN`.
fn parse_range(headers: &HeaderMap, total: u64) -> Option<(u64, u64)> {
    if total == 0 {
        return None;
    }
    let spec = headers.get(header::RANGE)?.to_str().ok()?.strip_prefix("bytes=")?;
    if spec.contains(',') {
        return None; // multi-range unsupported; serve full
    }
    let (start_s, end_s) = spec.split_once('-')?;
    let (start, end) = if start_s.is_empty() {
        let suffix: u64 = end_s.parse().ok()?;
        if suffix == 0 {
            return None;
        }
        (total.saturating_sub(suffix), total - 1)
    } else {
        let start: u64 = start_s.parse().ok()?;
        let end = if end_s.is_empty() {
            total - 1
        } else {
            end_s.parse::<u64>().ok()?.min(total - 1)
        };
        (start, end)
    };
    if start > end || start >= total {
        return None;
    }
    Some((start, end))
}

/// Render a shared-handler [`FacadeWrite`] outcome as the hub's HTTP response.
///
/// Maps each variant to the byte-identical status (and `{"path": …}` JSON body on
/// success) the prior in-hub facade returned, so the upload wire contract is
/// unchanged.
fn render(outcome: FacadeWrite, path: &str) -> Response {
    use axum::http::StatusCode;
    use axum::response::IntoResponse as _;
    use axum::Json;
    match outcome {
        FacadeWrite::Created => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "path": path })),
        )
            .into_response(),
        FacadeWrite::Overwritten | FacadeWrite::Present => (
            StatusCode::OK,
            Json(serde_json::json!({ "path": path })),
        )
            .into_response(),
        FacadeWrite::NotFound => StatusCode::NOT_FOUND.into_response(),
        FacadeWrite::NotWritable(reason) => {
            (StatusCode::METHOD_NOT_ALLOWED, reason).into_response()
        }
        FacadeWrite::BadPath(reason) => (StatusCode::BAD_REQUEST, reason).into_response(),
        FacadeWrite::Unauthorized(reason) => (StatusCode::UNAUTHORIZED, reason).into_response(),
        FacadeWrite::Forbidden => {
            (StatusCode::FORBIDDEN, "insufficient permission").into_response()
        }
        FacadeWrite::LeaseConflict => (
            StatusCode::CONFLICT,
            "another publisher holds the registry publish lease",
        )
            .into_response(),
        FacadeWrite::TooLarge => StatusCode::PAYLOAD_TOO_LARGE.into_response(),
        FacadeWrite::QuotaExceeded => (
            StatusCode::INSUFFICIENT_STORAGE,
            "org storage quota exceeded",
        )
            .into_response(),
        FacadeWrite::Internal => {
            (StatusCode::INTERNAL_SERVER_ERROR, "internal error").into_response()
        }
    }
}
