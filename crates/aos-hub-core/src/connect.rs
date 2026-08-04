//! The shared Connect-JSON `axum` router for the `aos.hub.v1` API.
//!
//! RFC-0004 Phase 5 serves the registry-hub RPC surface as a single transport
//! on both deployment targets: **Connect-JSON** — the Connect protocol's JSON
//! encoding — over plain `axum` handlers. The native hub mounts this router via
//! `axum::serve`; the Cloudflare Worker mounts the *same* router via
//! `axum-cloudflare-adapter`. The `connectrpc` server runtime (hyper/tokio) is
//! not used on the registry path at all, so this compiles to
//! `wasm32-unknown-unknown`.
//!
//! # Wire format
//!
//! Each method is one route: `POST /aos.hub.v1.{Service}/{Method}`. The
//! request body is the JSON-encoded request message; the success response is
//! the JSON-encoded response message with `200 OK`. An error is the Connect
//! error envelope with the matching HTTP status:
//!
//! ```text
//! POST /aos.hub.v1.RegistryService/GetRegistry
//! Content-Type: application/json
//! { "slug": "acme/cdn" }
//!   -> 200 { "registry": { "slug": "acme/cdn", … } }
//!   -> 404 { "code": "not_found", "message": "registry not found" }
//! ```
//!
//! An empty request body is accepted and decoded as the default message (the
//! Connect convention for no-argument calls). The bearer JWT, when present,
//! rides in the `Authorization` header and is verified inside
//! [`RpcService`](crate::service::RpcService); these handlers are pure
//! transport glue.

use std::sync::Arc;

use axum::body::Bytes;
use axum::extract::{Path, Request, State};
use axum::http::{header, HeaderMap, StatusCode, Uri};
#[cfg(not(target_arch = "wasm32"))]
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::service::{FacadeWrite, ReadAuthorization, RegistryServeOutcome, RpcError, RpcService};
use crate::web::browse::{self, Rendered};

/// The reserved human-namespace marker segment (`/{slug}/-/…`).
///
/// Browse pages and the JSON read API live under this segment so they can never
/// be shadowed by the machine surface that owns the registry root (RFC-0004
/// "The `/-/` namespace").
const BROWSE_MARKER: &str = "-";

/// Canonical Connect namespace for placement collection reads.
const LIST_PLACEMENTS_PATH: &str = "/aos.hub.v1.TopologyService/ListPlacements";
/// Canonical Connect namespace for one placement read.
const GET_PLACEMENT_PATH: &str = "/aos.hub.v1.TopologyService/GetPlacement";
/// Canonical Connect namespace for placement creation.
const CREATE_PLACEMENT_PATH: &str = "/aos.hub.v1.TopologyService/CreatePlacement";
/// Canonical Connect namespace for mutable placement updates.
const UPDATE_PLACEMENT_PATH: &str = "/aos.hub.v1.TopologyService/UpdatePlacement";
/// Canonical Connect namespace for the desired/observed authority view.
const GET_WRITE_AUTHORITY_PATH: &str = "/aos.hub.v1.TopologyService/GetWriteAuthority";
/// Canonical Connect namespace for immutable promotion planning.
const PLAN_PROMOTE_PLACEMENT_PATH: &str = "/aos.hub.v1.TopologyService/PlanPromotePlacement";
/// Canonical Connect namespace for promotion-plan application.
const PROMOTE_PLACEMENT_PATH: &str = "/aos.hub.v1.TopologyService/PromotePlacement";
/// Canonical Connect namespace for controller authority observations.
const RECONCILE_WRITE_AUTHORITY_PATH: &str = "/aos.hub.v1.TopologyService/ReconcileWriteAuthority";
/// Canonical Connect namespace for explicit read-only planning.
const PLAN_REMOVE_WRITE_AUTHORITY_PATH: &str =
    "/aos.hub.v1.TopologyService/PlanRemoveWriteAuthority";
/// Canonical Connect namespace for explicit read-only plan application.
const REMOVE_WRITE_AUTHORITY_PATH: &str = "/aos.hub.v1.TopologyService/RemoveWriteAuthority";
/// Canonical Connect namespace for placement drain plans/applies.
const DRAIN_PLACEMENT_PATH: &str = "/aos.hub.v1.TopologyService/DrainPlacement";
/// Canonical Connect namespace for placement deletion plans/applies.
const DELETE_PLACEMENT_PATH: &str = "/aos.hub.v1.TopologyService/DeletePlacement";

#[cfg(target_arch = "wasm32")]
use send_wrapper::SendWrapper;

// --- The wasm `Send` bridge ---------------------------------------------------
//
// `axum`'s `Handler` and `Router` state demand `Send + Sync`, but the Worker's
// D1-backed `RpcService` is `?Send` (its `Backend`/`RateLimiter` futures hold
// non-`Send` JS values). On the single-threaded Worker that is sound, so a
// `SendWrapper` (which is unconditionally `Send + Sync` and panics only if
// touched off its origin thread — impossible with one thread) bridges the gap.
// On native, where threads are real, the bridge is the identity: the service is
// genuinely `Send + Sync`.

/// The axum state type carrying the shared service, made `Send + Sync`.
#[cfg(not(target_arch = "wasm32"))]
type SharedState = Arc<RpcService>;
/// See the native definition — `SendWrapper`-wrapped on the wasm32 Worker.
#[cfg(target_arch = "wasm32")]
type SharedState = SendWrapper<Arc<RpcService>>;

/// Wrap the service as axum state (identity on native, `SendWrapper` on wasm).
#[cfg(not(target_arch = "wasm32"))]
fn into_state(svc: Arc<RpcService>) -> SharedState {
    svc
}
/// See the native definition.
#[cfg(target_arch = "wasm32")]
fn into_state(svc: Arc<RpcService>) -> SharedState {
    SendWrapper::new(svc)
}

/// Recover the `Arc<RpcService>` from axum state (identity on native).
#[cfg(not(target_arch = "wasm32"))]
fn from_state(state: SharedState) -> Arc<RpcService> {
    state
}
/// See the native definition — `take()` is sound on the single-threaded Worker.
#[cfg(target_arch = "wasm32")]
fn from_state(state: SharedState) -> Arc<RpcService> {
    state.take()
}

/// Make a handler future satisfy axum's `Send` bound (identity on native).
#[cfg(not(target_arch = "wasm32"))]
fn send_bridge<F: std::future::Future>(fut: F) -> F {
    fut
}
/// See the native definition — `SendWrapper` makes the `?Send` future `Send`.
#[cfg(target_arch = "wasm32")]
fn send_bridge<F: std::future::Future>(fut: F) -> SendWrapper<F> {
    SendWrapper::new(fut)
}

/// Build a `text/plain; charset=utf-8` `200` response with a one-hour public
/// cache, for the generated `robots.txt` / `llms.txt` documents.
fn text_plain_response(body: String) -> Response {
    (
        [
            (header::CONTENT_TYPE, "text/plain; charset=utf-8"),
            (header::CACHE_CONTROL, "public, max-age=3600"),
        ],
        body,
    )
        .into_response()
}

/// Render an [`RpcError`] as the Connect-JSON error envelope plus HTTP status.
fn error_response(err: &RpcError) -> Response {
    let status =
        StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    let body = Json(serde_json::json!({ "code": err.code(), "message": err.message() }));
    (status, body).into_response()
}

/// Pull the raw `Authorization` header value, if present and ASCII.
///
/// Returned owned so it can cross the `await` in the dispatched call without
/// borrowing the request's [`HeaderMap`]. [`RpcService`] does the `Bearer`
/// parsing and JWT verification.
fn auth_header(headers: &HeaderMap) -> Option<String> {
    headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned)
}

/// Decode a Connect-JSON request body into the typed request message.
///
/// An empty body decodes as the default message (Connect's no-argument
/// convention). A malformed body is an `invalid_argument`.
fn decode_request<Req: DeserializeOwned>(body: &Bytes) -> Result<Req, RpcError> {
    let bytes: &[u8] = if body.is_empty() { b"{}" } else { body };
    serde_json::from_slice(bytes).map_err(|e| RpcError::invalid(format!("decode request: {e}")))
}

/// Drive one unary Connect-JSON call: decode → invoke `call` → encode.
///
/// `call` receives the shared service, the owned `Authorization` header, and the
/// decoded request, and returns the service result. Success encodes as a JSON
/// `200`; an [`RpcError`] encodes as the Connect error envelope.
async fn unary<Req, Resp, F, Fut>(
    svc: Arc<RpcService>,
    headers: HeaderMap,
    body: Bytes,
    call: F,
) -> Response
where
    Req: DeserializeOwned,
    Resp: Serialize,
    F: FnOnce(Arc<RpcService>, Option<String>, Req) -> Fut,
    Fut: std::future::Future<Output = Result<Resp, RpcError>>,
{
    let auth = auth_header(&headers);
    let req: Req = match decode_request(&body) {
        Ok(req) => req,
        Err(err) => return error_response(&err),
    };
    match call(svc, auth, req).await {
        Ok(resp) => Json(resp).into_response(),
        Err(err) => error_response(&err),
    }
}

/// Serve one registry machine path from the shared surface facade.
///
/// The catch-all `GET`/`HEAD` handler for the registry machine surface
/// (`/{slug}/{*path}`): it delegates to
/// [`RpcService::registry_serve`](crate::service::RpcService::registry_serve),
/// which classifies the path, enforces registry visibility against the
/// `Authorization` header, and streams through the placement-aware
/// [`SurfaceProvider`](crate::fetch::SurfaceProvider). A hit renders as `200`
/// with the path's `Content-Type` and `Cache-Control`; a `None` (non-machine
/// path or absent object) renders as `404`; an [`RpcError`] renders as the
/// Connect error envelope (so a private registry read without authority is the
/// usual `401`/`403`/`404`).
///
/// A `HEAD` and a `GET` share this one handler and differ only in whether axum
/// elides the already-streaming body.
async fn facade(
    svc: Arc<RpcService>,
    headers: HeaderMap,
    slug: String,
    path: String,
    query: Option<String>,
) -> Response {
    let auth = auth_header(&headers);
    // A managed cache: stream NAR/narinfo through the shared `cache_serve`
    // (Range-aware, generated `nix-cache-info`, presigned-`302`) — the *same*
    // path the native hub uses, so the Worker streams a NAR from R2 rather than
    // buffering it. Caches and registries are separate slug namespaces, so a
    // cache slug is never a registry; registries continue to `registry_serve`.
    if let Ok(Some(cache)) = svc.db.cache_by_slug(&slug).await {
        let range = headers.get(header::RANGE).and_then(|v| v.to_str().ok());
        return match svc
            .cache_serve(
                ReadAuthorization::AuthorizationHeader(auth.as_deref()),
                &cache,
                &path,
                range,
            )
            .await
        {
            Ok(Some(resp)) => resp,
            Ok(None) => StatusCode::NOT_FOUND.into_response(),
            Err(err) => error_response(&err),
        };
    }
    // A resolved registry uses the same placement-aware streaming path as the
    // native shell. Selection/failover finishes before the Body is returned;
    // Range and large NAR/release payloads therefore retain parity without
    // buffering the object in the Worker isolate.
    if let Ok(Some(registry)) = svc.db.registry_by_slug(&slug).await {
        let range = headers.get(header::RANGE).and_then(|v| v.to_str().ok());
        return match svc
            .registry_serve(
                ReadAuthorization::AuthorizationHeader(auth.as_deref()),
                &registry,
                &path,
                range,
            )
            .await
        {
            Ok(RegistryServeOutcome::Response(resp)) => resp,
            Ok(RegistryServeOutcome::NotFound | RegistryServeOutcome::UnplacedNotFound) => {
                StatusCode::NOT_FOUND.into_response()
            }
            Err(err) => error_response(&err),
        };
    }
    // Neither flat namespace matched. Reconstruct the full path and resolve a
    // nested registry directly; all public machine reads then re-enter this
    // function through the placement-aware streaming branches above.
    nested_dispatch(svc, headers, &slug, &path, query).await
}

/// Dispatch a nested-canonical (`org/registry`, `acme/infra/cdn`) GET/HEAD
/// request that the `/{slug}/{*path}` wildcard captured with a single-segment
/// slug, reconstructing the full path from `slug` + `path`.
///
/// The reserved browse marker (`/-/`) takes precedence over machine resolution:
/// a path containing it splits into the registry slug (left) and the page/`api/…`
/// tail (right) and dispatches through [`browse_dispatch`], so the human
/// namespace can never be shadowed by a machine path. Otherwise the longest
/// registry-slug prefix is resolved ([`resolve_registry_prefix`]): an empty tail
/// is the registry home (browse), a non-empty tail is a machine path served by
/// recursing into [`facade`] with the now-flat resolved slug (which terminates —
/// the resolved slug is a real registry, so its own `Ok(None)` is a plain `404`).
/// An unresolvable path is a `404`.
async fn nested_dispatch(
    svc: Arc<RpcService>,
    headers: HeaderMap,
    slug: &str,
    path: &str,
    query: Option<String>,
) -> Response {
    let full = format!("{slug}/{path}");
    let full = full.trim_end_matches('/');
    if let Some((left, rest)) = split_browse_marker(full) {
        let left = left.trim_end_matches('/').to_string();
        return browse_dispatch(svc, headers, left, rest, query).await;
    }
    match resolve_registry_prefix(&svc, full).await {
        Some((rslug, tail)) if tail.is_empty() => {
            browse_dispatch(svc, headers, rslug, String::new(), query).await
        }
        Some((rslug, tail)) => Box::pin(facade(svc, headers, rslug, tail, query)).await,
        None => StatusCode::NOT_FOUND.into_response(),
    }
}

/// Render a [`FacadeWrite`] outcome as the byte-identical HTTP response the
/// upload protocol expects.
///
/// A success ([`FacadeWrite::Created`]/[`FacadeWrite::Overwritten`]) carries a
/// small `{"path": …}` JSON body and `201`/`200`; every denial maps to its fixed
/// status (`400`/`401`/`403`/`404`/`405`/`409`/`413`/`507`/`500`), preserving the
/// prior hub facade's wire contract.
fn facade_write_response(outcome: FacadeWrite, path: &str) -> Response {
    match outcome {
        FacadeWrite::Created => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "path": path })),
        )
            .into_response(),
        FacadeWrite::Overwritten | FacadeWrite::Present => {
            (StatusCode::OK, Json(serde_json::json!({ "path": path }))).into_response()
        }
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

/// Handle a facade `PUT` of one registry surface path through the shared write
/// handler.
///
/// Delegates to
/// [`RpcService::put_machine_path`](crate::service::RpcService::put_machine_path),
/// which authorizes [`Permission::Publish`](crate::domain::Permission::Publish),
/// enforces the quota and publish lease, writes through the
/// [`SurfaceWriteProvider`](crate::surface_write::SurfaceWriteProvider), and
/// re-indexes a completing pointer — so the same upload logic runs on the native
/// hub and the Cloudflare Worker.
async fn facade_put(
    svc: Arc<RpcService>,
    headers: HeaderMap,
    slug: String,
    path: String,
    query: Option<String>,
    body: Bytes,
) -> Response {
    let auth = auth_header(&headers);
    // A multipart part upload (`?uploadId=…&partNumber=N`) streams this one part
    // straight to the backend; any other `PUT` is a single-object write.
    let mp = parse_multipart_query(query.as_deref());
    if let (Some(upload_id), Some(part_number)) = (mp.upload_id.as_deref(), mp.part_number) {
        return match svc
            .upload_part(auth.as_deref(), &slug, &path, upload_id, part_number, &body)
            .await
        {
            Ok(tag) => multipart_part_response(&tag),
            Err(deny) => facade_write_response(deny, &path),
        };
    }
    let outcome = svc
        .put_machine_path(auth.as_deref(), &slug, &path, &body)
        .await;
    // A nested-canonical upload (`PUT /andyl/demo/nar/x`) arrives with the slug
    // captured as the single leading segment, so the flat write misses the
    // registry. When the single-segment slug names no flat registry, resolve the
    // nested registry by longest prefix and retry the upload against it — the
    // mirror of the read-path fallthrough in `facade`.
    if matches!(outcome, FacadeWrite::NotFound)
        && !matches!(svc.db.registry_by_slug(&slug).await, Ok(Some(_)))
    {
        let full = format!("{slug}/{path}");
        if let Some((rslug, tail)) = resolve_registry_prefix(&svc, full.trim_end_matches('/')).await
        {
            if !tail.is_empty() {
                let nested = svc
                    .put_machine_path(auth.as_deref(), &rslug, &tail, &body)
                    .await;
                return facade_write_response(nested, &tail);
            }
        }
    }
    facade_write_response(outcome, &path)
}

/// Suggested multipart part size handed back at initiate (16 MiB): above the
/// R2/S3 5 MiB minimum and under the Worker request-body cap, so each part is
/// one bounded-memory request.
const MULTIPART_PART_SIZE: u64 = 16 * 1024 * 1024;

/// Maximum buffered facade request body (32 MiB): comfortably above the
/// 16 MiB multipart part size (with headroom) yet far below the Worker isolate
/// memory, so a single buffered part can never pressure it. Lifts axum's 2 MiB
/// `DefaultBodyLimit`, which otherwise 413s every part.
const MAX_FACADE_BODY_BYTES: usize = 32 * 1024 * 1024;

/// Multipart query parameters parsed off a facade request's query string.
///
/// The facade overloads the `/{slug}/{*path}` route with the S3-style multipart
/// query convention: `?uploads` initiates, `?uploadId=…&partNumber=N` uploads a
/// part, `?uploadId=…` (POST) completes / (DELETE) aborts.
struct MultipartQuery {
    /// `?uploads` present — an initiate request.
    initiate: bool,
    /// `?uploadId=…` — names an in-progress upload (part/complete/abort).
    upload_id: Option<String>,
    /// `?partNumber=…` — the 1-based part index on a part `PUT`.
    part_number: Option<u32>,
}

/// Parse the multipart query parameters from a raw query string.
fn parse_multipart_query(query: Option<&str>) -> MultipartQuery {
    let mut out = MultipartQuery {
        initiate: false,
        upload_id: None,
        part_number: None,
    };
    if let Some(q) = query {
        for (k, v) in url::form_urlencoded::parse(q.as_bytes()) {
            match k.as_ref() {
                "uploads" => out.initiate = true,
                "uploadId" => out.upload_id = Some(v.into_owned()),
                "partNumber" => out.part_number = v.parse().ok(),
                _ => {}
            }
        }
    }
    out
}

/// Initiate (`?uploads`) / complete (`?uploadId`) of a multipart upload, on the
/// facade `POST` to a surface path.
async fn facade_post(
    svc: Arc<RpcService>,
    headers: HeaderMap,
    slug: String,
    path: String,
    query: Option<String>,
    body: Bytes,
) -> Response {
    let auth = auth_header(&headers);
    let mp = parse_multipart_query(query.as_deref());
    if mp.initiate {
        return match svc.initiate_upload(auth.as_deref(), &slug, &path).await {
            Ok(upload_id) => Json(MultipartInitiate {
                upload_id,
                part_size: MULTIPART_PART_SIZE,
            })
            .into_response(),
            Err(deny) => facade_write_response(deny, &path),
        };
    }
    if let Some(upload_id) = mp.upload_id.as_deref() {
        let parts = match serde_json::from_slice::<MultipartComplete>(&body) {
            Ok(req) => req
                .parts
                .into_iter()
                .map(|p| crate::surface_write::PartTag {
                    part_number: p.part_number,
                    etag: p.etag,
                })
                .collect::<Vec<_>>(),
            Err(_) => {
                return (StatusCode::BAD_REQUEST, "invalid multipart complete body").into_response()
            }
        };
        let outcome = svc
            .complete_upload(auth.as_deref(), &slug, &path, upload_id, &parts)
            .await;
        return facade_write_response(outcome, &path);
    }
    (
        StatusCode::BAD_REQUEST,
        "unsupported POST to a surface path",
    )
        .into_response()
}

/// Abort (`?uploadId`) of a multipart upload, on the facade `DELETE` to a
/// surface path.
async fn facade_delete(
    svc: Arc<RpcService>,
    headers: HeaderMap,
    slug: String,
    path: String,
    query: Option<String>,
) -> Response {
    let auth = auth_header(&headers);
    let mp = parse_multipart_query(query.as_deref());
    if let Some(upload_id) = mp.upload_id.as_deref() {
        let outcome = svc
            .abort_upload(auth.as_deref(), &slug, &path, upload_id)
            .await;
        return facade_write_response(outcome, &path);
    }
    (
        StatusCode::BAD_REQUEST,
        "unsupported DELETE to a surface path",
    )
        .into_response()
}

/// `200` JSON response to a multipart part upload (`PUT ?uploadId&partNumber`).
fn multipart_part_response(tag: &crate::surface_write::PartTag) -> Response {
    Json(MultipartPart {
        part_number: tag.part_number,
        etag: tag.etag.clone(),
    })
    .into_response()
}

/// Initiate response body: the opaque backend `upload_id` and the suggested
/// `part_size`.
#[derive(Serialize)]
struct MultipartInitiate {
    upload_id: String,
    part_size: u64,
}

/// Part-upload response body: the part's number and backend `etag`.
#[derive(Serialize)]
struct MultipartPart {
    part_number: u32,
    etag: String,
}

/// Complete request body: the ordered parts (number + etag) to assemble.
#[derive(serde::Deserialize)]
struct MultipartComplete {
    parts: Vec<MultipartCompletePart>,
}

/// One `(part_number, etag)` entry in a [`MultipartComplete`] body.
#[derive(serde::Deserialize)]
struct MultipartCompletePart {
    part_number: u32,
    etag: String,
}

/// Turn a [`Rendered`] browse outcome into an HTTP response.
///
/// [`Rendered::Html`] is a `200` `text/html` with the strict first-party CSP
/// (`default-src 'self'; frame-ancestors 'none'` — no third-party origins, no
/// framing); [`Rendered::Json`] is a `200` `application/json`;
/// [`Rendered::Redirect`] is a `308 Permanent Redirect`;
/// [`Rendered::TooManyRequests`] is a `429` with a `Retry-After`;
/// [`Rendered::NotFound`] is a bare `404` (the visibility matrix returns this for
/// a hidden registry alike, never disclosing "absent" from "private");
/// [`Rendered::NotAcceptable`] is a `406` (content negotiation: a non-HTML client
/// for a visible registry that ships no machine `index.html`).
fn browse_response(rendered: Rendered) -> Response {
    match rendered {
        Rendered::Html(body) => (
            [
                (header::CONTENT_TYPE, "text/html; charset=utf-8"),
                (
                    header::CONTENT_SECURITY_POLICY,
                    "default-src 'self'; frame-ancestors 'none'",
                ),
            ],
            body,
        )
            .into_response(),
        Rendered::Json(body) => {
            ([(header::CONTENT_TYPE, "application/json")], body).into_response()
        }
        Rendered::Redirect(location) => {
            axum::response::Redirect::permanent(&location).into_response()
        }
        Rendered::TooManyRequests(retry_after) => (
            StatusCode::TOO_MANY_REQUESTS,
            [(header::RETRY_AFTER, retry_after.max(1).to_string())],
            "rate limit exceeded",
        )
            .into_response(),
        Rendered::NotFound => StatusCode::NOT_FOUND.into_response(),
        Rendered::NotAcceptable => StatusCode::NOT_ACCEPTABLE.into_response(),
    }
}

/// Dispatch a `GET` browse request under `/{slug}/-/{*rest}` to the matching
/// session-aware [`browse`] handler.
///
/// Splits the reserved `/-/` tail into its page or `api/…` route and calls the
/// corresponding [`browse`] read. The HTML pages resolve the request's session
/// (so the masthead reflects the login and the visibility matrix admits the
/// caller's internal/granted-private registries) and honor the
/// `?q`/`?filter`/`?sort`/`?dir`/`?page`/`?bucket` controls parsed from `query`;
/// the `/-/api/…` JSON reads stay bearer-only. This is the *same* code the
/// native hub now serves — the divergence between the two shells is gone.
async fn browse_dispatch(
    svc: Arc<RpcService>,
    headers: HeaderMap,
    slug: String,
    rest: String,
    query: Option<String>,
) -> Response {
    let q = browse::BrowseQuery::parse(query.as_deref());
    // A cache slug routes to the managed-cache browse pages (caches and
    // registries share the `/{slug}/…` namespace but are disjoint slugs).
    if matches!(svc.db.cache_by_slug(&slug).await, Ok(Some(_))) {
        let rendered = match rest.strip_prefix("api/") {
            Some("objects") => browse::api_cache_objects(&svc, &slug, &q).await,
            Some(_) => Rendered::NotFound,
            None => match rest.as_str() {
                "" => browse::cache_home(&svc, &headers, &slug).await,
                "objects" => browse::cache_objects(&svc, &headers, &slug, &q).await,
                other => {
                    if let Some(hash) = other.strip_prefix("objects/").filter(|h| !h.is_empty()) {
                        browse::cache_object(&svc, &headers, &slug, hash).await
                    } else if let Some(hash) =
                        other.strip_prefix("closure/").filter(|h| !h.is_empty())
                    {
                        browse::cache_closure(&svc, &headers, &slug, hash).await
                    } else {
                        Rendered::NotFound
                    }
                }
            },
        };
        return browse_response(rendered);
    }
    let rendered = match rest.strip_prefix("api/") {
        Some(api) => match api {
            "registry" => browse::api_registry(&svc, &slug).await,
            "packages" => browse::api_packages(&svc, &slug).await,
            "channels" => browse::api_channels(&svc, &slug).await,
            "releases" => browse::api_releases(&svc, &slug).await,
            other => match other.strip_prefix("packages/") {
                Some(name) if !name.is_empty() => browse::api_package(&svc, &slug, name).await,
                _ => Rendered::NotFound,
            },
        },
        None => match rest.as_str() {
            "" => browse::registry_home(&svc, &headers, &slug).await,
            "packages" => browse::packages(&svc, &headers, &slug, &q).await,
            "channels" => browse::channels(&svc, &headers, &slug, &q).await,
            "releases" => browse::releases(&svc, &headers, &slug, &q).await,
            "health" => browse::health(&svc, &headers, &slug).await,
            other => {
                if let Some(name) = other.strip_prefix("packages/").filter(|n| !n.is_empty()) {
                    browse::package(&svc, &headers, &slug, name).await
                } else if let Some(name) = other.strip_prefix("channels/").filter(|n| !n.is_empty())
                {
                    browse::channel(&svc, &headers, &slug, name, &q).await
                } else {
                    Rendered::NotFound
                }
            }
        },
    };
    browse_response(rendered)
}

/// Mount one `aos.hub.v1` method as a `POST` route delegating to the
/// same-named [`RpcService`] method.
macro_rules! rpc_route {
    ($router:expr, $path:expr, $method:ident) => {
        $router.route(
            $path,
            post(
                |State(state): State<SharedState>, headers: HeaderMap, body: Bytes| {
                    let svc = from_state(state);
                    send_bridge(unary(svc, headers, body, |svc, auth, req| async move {
                        svc.$method(auth.as_deref(), req).await
                    }))
                },
            ),
        )
    };
}

/// Build the shared Connect-JSON router over the given [`RpcService`],
/// including the machine-surface facade.
///
/// Wires every ported `aos.hub.v1` method to `POST
/// /aos.hub.v1.{Service}/{Method}`, including the three `GitService`
/// methods served over the surface-read port
/// ([`SurfaceProvider`](crate::fetch::SurfaceProvider)). It additionally mounts
/// the machine-surface facade as a catch-all `GET`/`HEAD` `/{slug}/{*path}`
/// route (delegating to the placement-aware streaming
/// [`RpcService::registry_serve`](crate::service::RpcService::registry_serve)
/// and [`RpcService::cache_serve`](crate::service::RpcService::cache_serve)
/// paths), registered last so the static RPC method paths win over the wildcard
/// by axum's static-over-dynamic precedence.
///
/// This is the variant the Cloudflare Worker mounts whole: it has no facade of
/// its own, so the shared route is its only machine-surface serving path. The
/// native hub instead mounts the facade-less [`rpc_router`] and keeps its own
/// `/{slug}/{*path}` route for nested resolution, session-cookie authorization,
/// and the transitional pull-through hook; successful registry bytes still run
/// through the same [`RpcService::registry_serve`] streamer. The returned router
/// carries the service as axum state.
#[must_use]
/// Which serving target a frontend domain resolves to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FrontendKind {
    /// A managed binary cache (gated on `serves_cache`).
    Cache,
    /// A registry's git/web surface (gated on `serves_git`/`serves_web`).
    Registry,
}

/// A request resolved to a serving frontend by its `Host` and path.
struct ResolvedFrontend {
    /// The target's URL slug (the instance-internal `/{slug}/…` identity the
    /// rewritten request is dispatched through).
    slug: String,
    /// Whether the target is a cache or a registry.
    kind: FrontendKind,
    /// The request path with the frontend's `base_path` stripped (no leading
    /// slash).
    surface_path: String,
    /// The frontend's advertised surface subset.
    serves_git: bool,
    serves_cache: bool,
    serves_web: bool,
}

impl ResolvedFrontend {
    /// Whether this frontend serves the surface class of `surface_path`.
    ///
    /// A machine path ([`keymap::is_machine_path`](crate::keymap::is_machine_path))
    /// is the cache (`serves_cache`) or git (`serves_git`) surface; anything else
    /// is a browse/web page (`serves_web`).
    ///
    /// Classification runs on the **percent-decoded** path: a downstream
    /// extractor decodes the path before serving, so gating on the raw encoded
    /// form would let an encoded token (e.g. `%6Fbjects` for `objects`) dodge the
    /// subset gate yet still resolve to the machine surface.
    fn serves(&self) -> bool {
        let decoded = percent_decode_path(&self.surface_path);
        let machine = crate::keymap::is_machine_path(&decoded);
        match self.kind {
            FrontendKind::Cache => {
                if machine {
                    self.serves_cache
                } else {
                    self.serves_web
                }
            }
            FrontendKind::Registry => {
                if machine {
                    self.serves_git
                } else {
                    self.serves_web
                }
            }
        }
    }
}

/// The hub's own host, parsed from [`RpcService::external_url`] and normalized
/// the same way [`request_host`] normalizes the request `Host` (lowercased, no
/// `:port`, no trailing dot), or `None` when `external_url` carries no host.
///
/// Used by [`rewrite_for_frontend`] to recognize traffic on the instance's own
/// domain — which is never a proxied frontend — and skip the per-request
/// `frontends_by_domain` lookup for it.
fn instance_host(svc: &RpcService) -> Option<String> {
    let host = svc
        .external_url
        .parse::<Uri>()
        .ok()
        .and_then(|uri| uri.host().map(str::to_string))?;
    let host = host.trim().trim_end_matches('.');
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// The request `Host`, lowercased and without any `:port`, for frontend
/// matching.
///
/// Prefers the URI authority (HTTP/2 `:authority`) and falls back to the `Host`
/// header (HTTP/1.1). Returns `None` when neither is present.
fn request_host(headers: &HeaderMap, uri: &Uri) -> Option<String> {
    let raw = uri.host().map(str::to_string).or_else(|| {
        headers
            .get(header::HOST)
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
    })?;
    // Drop any `:port`, then a single FQDN trailing dot, so `cache.example.com`,
    // `cache.example.com:8443`, and `cache.example.com.` all match one row.
    let host = raw
        .split(':')
        .next()
        .unwrap_or(&raw)
        .trim()
        .trim_end_matches('.');
    if host.is_empty() {
        None
    } else {
        Some(host.to_ascii_lowercase())
    }
}

/// Percent-decode the `%XX` escapes in a surface path (lossy on invalid UTF-8).
///
/// Used to classify the surface class on the same decoded form a downstream
/// extractor sees, so an encoded token cannot bypass the `serves_*` gate.
fn percent_decode_path(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hex = |b: u8| match b {
                b'0'..=b'9' => Some(b - b'0'),
                b'a'..=b'f' => Some(b - b'a' + 10),
                b'A'..=b'F' => Some(b - b'A' + 10),
                _ => None,
            };
            if let (Some(hi), Some(lo)) = (hex(bytes[i + 1]), hex(bytes[i + 2])) {
                out.push(hi * 16 + lo);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i]);
        i += 1;
    }
    String::from_utf8_lossy(&out).into_owned()
}

/// One resolved frontend in the per-host routing projection (RFC-0004 ch.14
/// Phase C): the bound target's slug + the surface gates, with its `base_path`.
///
/// The host→target resolution (the `frontends_by_domain` D1 read plus the
/// per-frontend `cache_by_id`/`registry_by_id` slug lookups) is the expensive
/// part; the `base_path` prefix match against the request path is pure. So the
/// list of these per host is read-through cached under `fe:{host}`, and the
/// per-request match runs over it with no database round-trip.
#[derive(serde::Serialize, serde::Deserialize)]
struct FrontendRouteEntry {
    /// The frontend's path prefix under the domain (matched on a segment
    /// boundary).
    base_path: String,
    /// The bound target's internal slug.
    slug: String,
    /// Whether the target is a cache (`true`) or a registry (`false`).
    is_cache: bool,
    /// The advertised surface subset.
    serves_git: bool,
    serves_cache: bool,
    serves_web: bool,
}

/// The per-host frontend routing entries, read-through cached in KV when a
/// store is attached, else resolved live.
///
/// Returns an empty list when the host binds no frontend (or the read fails),
/// which the caller treats as "not a frontend domain".
async fn frontend_routes(svc: &RpcService, host: &str) -> Vec<FrontendRouteEntry> {
    let load = || async {
        let Ok(frontends) = svc.db.frontends_by_domain(host).await else {
            return Ok(None);
        };
        let mut entries = Vec::new();
        for fe in frontends {
            let (slug, is_cache) = if let Some(cache_id) = fe.cache_id {
                match svc.db.cache_by_id(cache_id).await {
                    Ok(Some(cache)) => (cache.slug, true),
                    _ => continue,
                }
            } else if let Some(registry_id) = fe.registry_id {
                match svc.db.registry_by_id(registry_id).await {
                    Ok(Some(reg)) => (reg.slug, false),
                    _ => continue,
                }
            } else {
                continue;
            };
            entries.push(FrontendRouteEntry {
                base_path: fe.base_path,
                slug,
                is_cache,
                serves_git: fe.serves_git,
                serves_cache: fe.serves_cache,
                serves_web: fe.serves_web,
            });
        }
        Ok(Some(entries))
    };
    match &svc.kv {
        Some(kv) => crate::cache::read_through(
            kv.as_ref(),
            &format!("fe:{host}"),
            Some(crate::cache::HOT_TTL_SECS),
            load,
        )
        .await
        .ok()
        .flatten()
        .unwrap_or_default(),
        None => load().await.ok().flatten().unwrap_or_default(),
    }
}

/// Resolve an incoming `(host, path)` to the registry/cache a serving frontend
/// binds, or `None` when the host is not a frontend domain.
///
/// Picks the frontend whose `base_path` most specifically prefixes `path`
/// (longest first), strips that prefix, and resolves the bound target's slug.
/// The host→target resolution is served from the KV routing projection
/// ([`frontend_routes`]) when a store is attached, off the D1 read path.
async fn resolve_frontend_route(
    svc: &RpcService,
    host: &str,
    path: &str,
) -> Option<ResolvedFrontend> {
    for fe in frontend_routes(svc, host).await {
        let base = fe.base_path.trim_matches('/');
        let trimmed = path.trim_start_matches('/');
        // Match the base path on a *segment* boundary, so base `v1` matches
        // `/v1` and `/v1/x` but never `/v10/x`.
        let rest = if base.is_empty() {
            Some(trimmed)
        } else {
            match trimmed.strip_prefix(base) {
                Some(r) if r.is_empty() => Some(""),
                Some(r) if r.starts_with('/') => Some(r.trim_start_matches('/')),
                _ => None,
            }
        };
        let Some(surface_path) = rest else {
            continue;
        };
        return Some(ResolvedFrontend {
            slug: fe.slug,
            kind: if fe.is_cache {
                FrontendKind::Cache
            } else {
                FrontendKind::Registry
            },
            surface_path: surface_path.to_string(),
            serves_git: fe.serves_git,
            serves_cache: fe.serves_cache,
            serves_web: fe.serves_web,
        });
    }
    None
}

/// Apply frontend domain-routing to `request`, returning the request to
/// continue with (its URI rewritten to the bound `/{slug}/…` identity when the
/// `Host` is a serving frontend domain) or an early [`Response`] (a `404` when
/// the frontend does not serve the requested surface class).
///
/// When the request `Host` matches a serving frontend (a *proxied* per-registry
/// or per-cache domain — a Direct frontend CNAMEs straight to the origin and
/// never reaches the hub), this strips the frontend's `base_path`, enforces its
/// `serves_git`/`serves_cache`/`serves_web` subset gate (a `404` for a surface
/// the frontend does not advertise), and rewrites the request to the internal
/// `/{slug}/{surface_path}` form so every existing handler (the cache/git
/// facade, the browse pages) serves it unchanged. A request whose host is not a
/// frontend (the instance's own domain, or any unrecognized host) is returned
/// unchanged for normal slug routing.
///
/// This is the shared decision both shells run: the native hub wraps it in a
/// [`with_frontend_dispatch`] middleware (its services are `Send`), and the
/// Worker calls it directly from its request bridge (its services are `!Send`,
/// which `axum::middleware::from_fn` would reject).
///
/// # Errors
///
/// Returns `Err(response)` with a `404` when a frontend serves the host but not
/// the requested surface class, or a `400` when the rewritten URI is invalid.
pub async fn rewrite_for_frontend(
    svc: &RpcService,
    mut request: Request,
) -> Result<Request, Response> {
    let Some(host) = request_host(request.headers(), request.uri()) else {
        return Ok(request);
    };
    // The instance's own host is never a per-registry/per-cache frontend domain,
    // so skip the `frontends_by_domain` D1 round-trip for it — the common case
    // for browse/RPC traffic on the hub's own domain. Only genuinely foreign
    // hosts (proxied frontend CNAMEs) hit the lookup. A no-custom-domain deploy
    // serves on its `*.workers.dev` host with `external_url` set to match, so
    // this still short-circuits there.
    if instance_host(svc).as_deref() == Some(host.as_str()) {
        return Ok(request);
    }
    let path = request.uri().path().to_string();
    let Some(route) = resolve_frontend_route(svc, &host, &path).await else {
        return Ok(request);
    };
    if !route.serves() {
        return Err(StatusCode::NOT_FOUND.into_response());
    }
    // Rewrite to the internal `/{slug}/{surface_path}` identity, preserving the
    // query string, and re-dispatch through the normal routes.
    let mut rewritten = format!("/{}/{}", route.slug, route.surface_path);
    if let Some(query) = request.uri().query() {
        rewritten.push('?');
        rewritten.push_str(query);
    }
    match Uri::try_from(rewritten) {
        Ok(uri) => *request.uri_mut() = uri,
        Err(_) => return Err(StatusCode::BAD_REQUEST.into_response()),
    }
    Ok(request)
}

/// The native [`with_frontend_dispatch`] middleware body: run the shared
/// [`rewrite_for_frontend`] decision, then continue or short-circuit.
///
/// Native-only: `axum::middleware::from_fn` requires a `Send` future, which the
/// Worker's `!Send` services cannot satisfy — the Worker instead calls
/// [`rewrite_for_frontend`] directly from its request bridge.
#[cfg(not(target_arch = "wasm32"))]
async fn dispatch_frontend_domain(svc: Arc<RpcService>, request: Request, next: Next) -> Response {
    match rewrite_for_frontend(&svc, request).await {
        Ok(request) => next.run(request).await,
        Err(response) => response,
    }
}

/// Wrap `router` with the [`dispatch_frontend_domain`] middleware so requests on
/// a serving frontend's domain resolve to the bound registry/cache.
///
/// Both shells apply this to their outermost router: the Worker over the shared
/// [`router`], the native hub over its merged router (which carries its own
/// machine facade). The middleware captures `service` directly, so it composes
/// regardless of the wrapped router's axum state type.
///
/// Native-only (see [`dispatch_frontend_domain`]); the Worker bridges
/// [`rewrite_for_frontend`] directly.
#[cfg(not(target_arch = "wasm32"))]
#[must_use]
pub fn with_frontend_dispatch(router: Router, service: Arc<RpcService>) -> Router {
    // The middleware must run *before* routing so its URI rewrite changes which
    // route matches. `Router::layer` runs *after* routing, so instead the inner
    // router becomes the fallback of a fresh outer router carrying the
    // middleware: the rewrite lands between the outer pass (always falls through)
    // and the inner router's routing, which then matches the rewritten path.
    Router::new()
        .fallback_service(router)
        .layer(axum::middleware::from_fn(move |request, next| {
            let svc = Arc::clone(&service);
            async move { dispatch_frontend_domain(svc, request, next).await }
        }))
}

/// Resolve the longest registry slug that is a path-segment prefix of `path`,
/// returning `(slug, tail)` where `tail` is the remaining machine-path tail.
///
/// This mirrors the native hub's `resolve_by_prefix`, but stays shell-agnostic:
/// it returns the resolved slug `String` (not the full registry record) so it
/// composes with the shared [`browse_dispatch`]/[`facade`] handlers, which
/// re-resolve the registry and enforce visibility downstream. `exists` is the
/// "is there a registry with this exact slug" predicate (the wasm shell's
/// service is `!Send`, so the loop takes the lookup as an `async` closure rather
/// than borrowing a `Send` future across iterations).
///
/// `acme/infra/prod/cdn/objects/ab` resolves to `(acme/infra/prod/cdn,
/// objects/ab)`; an exact match yields an empty tail (the registry home).
/// Matching is on `/` boundaries, so `acme/infra/prod/cdn-staging` never
/// resolves to `acme/infra/prod/cdn`.
async fn resolve_prefix_with<'a, F, Fut>(path: &'a str, mut exists: F) -> Option<(String, String)>
where
    F: FnMut(&'a str) -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let mut candidate = path;
    loop {
        if exists(candidate).await {
            let tail = path[candidate.len()..].trim_start_matches('/').to_string();
            return Some((candidate.to_string(), tail));
        }
        match candidate.rsplit_once('/') {
            Some((head, _)) => candidate = head,
            None => return None,
        }
    }
}

/// Resolve `path` to the registry it names by longest registry-slug prefix.
///
/// Thin wrapper over [`resolve_prefix_with`] that uses the service's
/// `registry_by_slug` read as the existence predicate. Returns `(slug, tail)`
/// on a hit; `None` when no slug prefix of `path` names a registry (or on a
/// database error, which the shared handlers surface as a `404` rather than
/// leaking the error through the nested fallback).
async fn resolve_registry_prefix(svc: &RpcService, path: &str) -> Option<(String, String)> {
    resolve_prefix_with(path, |candidate| async move {
        matches!(svc.db.registry_by_slug(candidate).await, Ok(Some(_)))
    })
    .await
}

/// Split a decoded path at the first browse marker (`/-/`, or a trailing `/-`),
/// returning `(left, rest)` where `left` is the registry-slug portion and `rest`
/// is the page/`api/…` tail after the marker (empty for a trailing marker).
///
/// Returns `None` when the path does not contain the reserved marker segment.
fn split_browse_marker(path: &str) -> Option<(String, String)> {
    let mid = format!("/{BROWSE_MARKER}/");
    if let Some((left, rest)) = path.split_once(&mid) {
        return Some((left.to_string(), rest.to_string()));
    }
    let end = format!("/{BROWSE_MARKER}");
    path.strip_suffix(&end)
        .map(|left| (left.to_string(), String::new()))
}

pub fn router(service: Arc<RpcService>) -> Router {
    // The Worker entry: browse + the machine facade. Nested-canonical (slashed)
    // slugs are handled inside the [`facade`] wildcard handler (the route that
    // captures them), which resolves the longest registry-slug prefix and
    // dispatches to the shared browse/facade — so the Worker serves `org/registry`
    // registries identically to flat ones. The native hub doesn't use this entry;
    // it composes [`rpc_browse_router`] and keeps its own richer `nested_catch_all`.
    build(service, true, true)
}

/// Build the shared Connect-JSON router with neither the browse surface nor the
/// machine-surface facade — the RPC methods only.
///
/// Omits the catch-all `/{slug}/{*path}` facade route *and* the browse routes,
/// so it can be merged into a host that already owns those paths. Retained for
/// any host that wants only the wire RPC; the native hub instead uses
/// [`rpc_browse_router`] to take the shared session-aware browse while keeping
/// its own richer machine facade. The returned router carries the service as
/// axum state.
#[must_use]
pub fn rpc_router(service: Arc<RpcService>) -> Router {
    build(service, false, false)
}

/// Build the shared Connect-JSON router *with* the session-aware browse surface
/// but *without* the machine-surface facade.
///
/// This is the variant the native hub mounts (RFC-0004 Phase 5, console-dedup
/// stage G): it takes the shared rich, branded, session-aware browse (the hub
/// home `/`, the `/{slug}` redirect, the registry home `/{slug}/` and
/// `/{slug}/-/`, the `/{slug}/-/…` pages, and the `/{slug}/-/api/…` JSON reads)
/// so the native hub and the Worker serve the **identical** browse, while the
/// hub keeps its own richer `/{slug}/{*path}` machine facade (filesystem
/// autoindex, `http(s)` redirect, pull-through mirroring, inert
/// producer-document serving, the upload `PUT`/`HEAD`) — so omitting the shared
/// facade here avoids a wildcard collision on merge. The returned router carries
/// the service as axum state.
#[must_use]
pub fn rpc_browse_router(service: Arc<RpcService>) -> Router {
    build(service, true, false)
}

/// Lifetime, in seconds, of an access JWT minted at `POST /oauth2/token`
/// (1 hour).
///
/// Matches the native hub's access-token TTL so the Worker and native
/// deployments issue equivalently short-lived tokens. One hour gives bulk
/// publish operations (a large `aos cache push`) comfortable headroom while
/// keeping the bearer's leak window short; a client running longer than this
/// re-exchanges its provisioning token for a fresh access JWT (the provisioning
/// token is the durable credential — there is no separate OAuth refresh token).
const ACCESS_TOKEN_TTL_SECS: i64 = 3600;

/// OAuth2 token-exchange response: `access_token`, `token_type` (`"Bearer"`),
/// and `expires_in` (seconds) — the same shape the native hub's
/// `/oauth2/token` returns, so a client cannot tell the runtimes apart.
#[derive(Serialize)]
struct TokenExchangeResponse {
    access_token: String,
    token_type: &'static str,
    expires_in: i64,
}

/// Exchange a provisioning secret for a short-TTL access JWT (`POST
/// /oauth2/token`).
///
/// The caller presents its `aos_`-prefixed provisioning secret as
/// `Authorization: Bearer <secret>`; on success the `200` JSON grant is the
/// `Authorization: Bearer <jwt>` the client then sends to the cache and publish
/// surfaces. This is the Worker's counterpart to the native hub's
/// `oauth2_token_handler`: that fragment (which also rate-limits per source IP)
/// lives in the `aos-hub` binary and is unreachable from the Worker, so the
/// exchange is mounted on the shared worker entry ([`router`]) instead.
///
/// Returns `401` when the header is missing/malformed or the secret is
/// unknown, expired, or revoked, and `500` on a token-store or minting failure.
async fn oauth2_token_exchange(svc: &RpcService, headers: &HeaderMap) -> Response {
    let secret = match headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|h| h.strip_prefix("Bearer "))
    {
        Some(s) => s,
        None => {
            return (
                StatusCode::UNAUTHORIZED,
                "missing or malformed Authorization header",
            )
                .into_response()
        }
    };
    // RFC-0004 ch.14 Phase C: validate through the KV cache (with the revocation
    // tombstone) when one is attached, off the D1 read path.
    let auth = match svc.validate_token_cached(secret).await {
        Ok(Some(auth)) => auth,
        Ok(None) => {
            return (StatusCode::UNAUTHORIZED, "invalid provisioning secret").into_response()
        }
        Err(_) => {
            return (StatusCode::INTERNAL_SERVER_ERROR, "token validation error").into_response()
        }
    };
    match svc.jwt_keys.mint(&auth, ACCESS_TOKEN_TTL_SECS) {
        Ok(access_token) => Json(TokenExchangeResponse {
            access_token,
            token_type: "Bearer",
            expires_in: ACCESS_TOKEN_TTL_SECS,
        })
        .into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "token creation error").into_response(),
    }
}

/// Build the shared router, optionally mounting the browse surface and/or the
/// machine-surface facade.
///
/// `mount_browse` adds the no-JS browse routes (the hub home `/`, the `/{slug}`
/// redirect, the registry home `/{slug}/` and `/{slug}/-/`, the `/{slug}/-/…`
/// pages, and the `/{slug}/-/api/…` JSON read API). `mount_facade` adds the
/// catch-all `GET`/`HEAD`/`PUT` `/{slug}/{*path}` machine-surface facade (which
/// also resolves nested-canonical slugs internally; see [`facade`]). The Worker
/// takes both ([`router`]); the native hub takes browse only
/// ([`rpc_browse_router`]) and keeps its own facade + nested handling;
/// [`rpc_router`] takes neither.
fn build(service: Arc<RpcService>, mount_browse: bool, mount_facade: bool) -> Router {
    let mut r = Router::new();
    // RegistryService
    r = rpc_route!(
        r,
        "/aos.hub.v1.RegistryService/ListRegistries",
        list_registries
    );
    r = rpc_route!(r, "/aos.hub.v1.RegistryService/GetRegistry", get_registry);
    r = rpc_route!(r, "/aos.hub.v1.RegistryService/ListReleases", list_releases);
    r = rpc_route!(
        r,
        "/aos.hub.v1.RegistryService/CreateRegistry",
        create_registry
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.RegistryService/SetCrawlPolicy",
        set_crawl_policy
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.RegistryService/ChangeRegistryStorage",
        change_registry_storage
    );
    // OrganizationService
    r = rpc_route!(r, "/aos.hub.v1.OrganizationService/CreateOrg", create_org);
    r = rpc_route!(r, "/aos.hub.v1.OrganizationService/GetOrg", get_org);
    r = rpc_route!(r, "/aos.hub.v1.OrganizationService/ListOrgs", list_orgs);
    // ProjectService
    r = rpc_route!(
        r,
        "/aos.hub.v1.ProjectService/CreateProject",
        create_project
    );
    r = rpc_route!(r, "/aos.hub.v1.ProjectService/ListProjects", list_projects);
    // StorageBindingService
    r = rpc_route!(
        r,
        "/aos.hub.v1.StorageBindingService/CreateBinding",
        create_binding
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.StorageBindingService/ListBindings",
        list_bindings
    );
    // TopologyService — typed registry/cache placement inventory.
    r = r.route(
        LIST_PLACEMENTS_PATH,
        post(
            |State(state): State<SharedState>, headers: HeaderMap, body: Bytes| {
                let svc = from_state(state);
                send_bridge(unary(svc, headers, body, |svc, auth, req| async move {
                    svc.list_placements(auth.as_deref(), req).await
                }))
            },
        ),
    );
    r = r.route(
        GET_PLACEMENT_PATH,
        post(
            |State(state): State<SharedState>, headers: HeaderMap, body: Bytes| {
                let svc = from_state(state);
                send_bridge(unary(svc, headers, body, |svc, auth, req| async move {
                    svc.get_placement(auth.as_deref(), req).await
                }))
            },
        ),
    );
    r = rpc_route!(r, CREATE_PLACEMENT_PATH, create_placement);
    r = rpc_route!(r, UPDATE_PLACEMENT_PATH, update_placement);
    r = rpc_route!(r, GET_WRITE_AUTHORITY_PATH, get_write_authority);
    r = rpc_route!(r, PLAN_PROMOTE_PLACEMENT_PATH, plan_promote_placement);
    r = rpc_route!(r, PROMOTE_PLACEMENT_PATH, promote_placement);
    r = rpc_route!(r, RECONCILE_WRITE_AUTHORITY_PATH, reconcile_write_authority);
    r = rpc_route!(
        r,
        PLAN_REMOVE_WRITE_AUTHORITY_PATH,
        plan_remove_write_authority
    );
    r = rpc_route!(r, REMOVE_WRITE_AUTHORITY_PATH, remove_write_authority);
    r = rpc_route!(r, DRAIN_PLACEMENT_PATH, drain_placement);
    r = rpc_route!(r, DELETE_PLACEMENT_PATH, delete_placement);
    // PackageService
    r = rpc_route!(r, "/aos.hub.v1.PackageService/ListPackages", list_packages);
    r = rpc_route!(r, "/aos.hub.v1.PackageService/GetPackage", get_package);
    // ChannelService
    r = rpc_route!(r, "/aos.hub.v1.ChannelService/ListChannels", list_channels);
    r = rpc_route!(r, "/aos.hub.v1.ChannelService/GetChannel", get_channel);
    // AuditService
    r = rpc_route!(r, "/aos.hub.v1.AuditService/ListAudit", list_audit);
    // InstanceService
    r = rpc_route!(
        r,
        "/aos.hub.v1.InstanceService/GetInstanceSettings",
        get_instance_settings
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.InstanceService/UpdateInstanceSettings",
        update_instance_settings
    );
    // RegistryConfigurationService
    r = rpc_route!(
        r,
        "/aos.hub.v1.RegistryConfigurationService/ListChangesets",
        list_changesets
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.RegistryConfigurationService/GetChangeset",
        get_changeset
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.RegistryConfigurationService/RevertChangeset",
        revert_changeset
    );
    // IdentityService — service-account / grant / token management (the machine API
    // behind the console's identity settings; RFC-0004 ch.14).
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/CreateServiceAccount",
        create_service_account
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/GrantMembership",
        grant_membership
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/RevokeMembership",
        revoke_membership
    );
    r = rpc_route!(r, "/aos.hub.v1.IdentityService/MintToken", mint_token);
    r = rpc_route!(r, "/aos.hub.v1.IdentityService/RevokeToken", revoke_token);
    r = rpc_route!(r, "/aos.hub.v1.IdentityService/ListTokens", list_tokens);
    // WebhookService
    r = rpc_route!(
        r,
        "/aos.hub.v1.WebhookService/CreateWebhook",
        create_webhook
    );
    r = rpc_route!(r, "/aos.hub.v1.WebhookService/ListWebhooks", list_webhooks);
    r = rpc_route!(
        r,
        "/aos.hub.v1.WebhookService/DeleteWebhook",
        delete_webhook
    );
    // PublishService
    r = rpc_route!(
        r,
        "/aos.hub.v1.PublishService/MintUploadCredentials",
        mint_upload_credentials
    );
    // GitService
    r = rpc_route!(r, "/aos.hub.v1.GitService/GitLog", git_log);
    r = rpc_route!(r, "/aos.hub.v1.GitService/GitDiff", git_diff);
    r = rpc_route!(
        r,
        "/aos.hub.v1.GitService/ListChangeRequests",
        list_change_requests
    );
    // BinaryCacheService (RFC-0004 "11-caches")
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/CreateCache",
        create_cache
    );
    r = rpc_route!(r, "/aos.hub.v1.BinaryCacheService/GetCache", get_cache);
    r = rpc_route!(r, "/aos.hub.v1.BinaryCacheService/ListCaches", list_caches);
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/UpdateCache",
        update_cache
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/DeleteCache",
        delete_cache
    );
    r = rpc_route!(r, "/aos.hub.v1.BinaryCacheService/LinkCache", link_cache);
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/UnlinkCache",
        unlink_cache
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/ListCacheLinks",
        list_cache_links
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/SetCacheGcPolicy",
        set_cache_gc_policy
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/GetCacheGcPolicy",
        get_cache_gc_policy
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/PinCachePath",
        pin_cache_path
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/UnpinCachePath",
        unpin_cache_path
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/ListCacheRoots",
        list_cache_roots
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/SearchCache",
        search_cache
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/GetCacheObject",
        get_cache_object
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/ListCacheGcRuns",
        list_cache_gc_runs
    );
    r = rpc_route!(r, "/aos.hub.v1.BinaryCacheService/RunCacheGc", run_cache_gc);
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/CacheClosure",
        cache_closure
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/ChangeCacheStorage",
        change_cache_storage
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/MintCacheUploadCredentials",
        mint_cache_upload_credentials
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/RegisterCacheNarinfos",
        register_cache_narinfos
    );
    // The machine-surface facade: a catch-all `GET` (axum routes `HEAD` to it,
    // eliding the body) for the registry machine path, registered LAST. The
    // static `/aos.hub.v1.{Service}/{Method}` RPC routes above win over
    // this `/{slug}/{*path}` wildcard by axum's static-over-dynamic precedence,
    // so the facade only matches a registry URL. Omitted by [`rpc_router`] so a
    // host with its own `/{slug}/{*path}` (the native hub) does not double-mount
    // it.
    if mount_browse {
        // First-party static assets (`/_assets/*`) the browse pages + console
        // link. Served from the shared router so the Worker exposes them too
        // (otherwise its CSS/JS/fonts 404). Static-prefixed, so they outrank the
        // facade wildcard.
        use crate::web::assets;
        r = r
            .route("/_assets/style.css", get(assets::stylesheet))
            .route("/_assets/app.js", get(assets::app_js))
            .route(
                "/_assets/jetbrains-mono-regular.woff2",
                get(assets::font_regular),
            )
            .route("/_assets/jetbrains-mono-bold.woff2", get(assets::font_bold))
            .route("/_assets/OFL.txt", get(assets::font_license));
        // Crawler-control and LLM-summary documents, served from the shared
        // router so both shells expose identical output. Static-prefixed, so
        // they outrank the facade wildcard. The per-registry forms gate on
        // public visibility inside the service (a non-public registry's document
        // is a `404`). Each is `text/plain` with a one-hour cache.
        r = r
            .route(
                "/robots.txt",
                get(|State(state): State<SharedState>| {
                    let svc = from_state(state);
                    send_bridge(async move {
                        match svc.serve_root_robots().await {
                            Ok(body) => text_plain_response(body),
                            Err(err) => error_response(&err),
                        }
                    })
                }),
            )
            .route(
                "/llms.txt",
                get(|State(state): State<SharedState>| {
                    let svc = from_state(state);
                    send_bridge(async move {
                        match svc.serve_root_llms().await {
                            Ok(body) => text_plain_response(body),
                            Err(err) => error_response(&err),
                        }
                    })
                }),
            )
            .route(
                "/{slug}/robots.txt",
                get(
                    |State(state): State<SharedState>, Path(slug): Path<String>| {
                        let svc = from_state(state);
                        send_bridge(async move {
                            match svc.serve_registry_robots(&slug).await {
                                Ok(Some(body)) => text_plain_response(body),
                                Ok(None) => StatusCode::NOT_FOUND.into_response(),
                                Err(err) => error_response(&err),
                            }
                        })
                    },
                ),
            )
            .route(
                "/{slug}/llms.txt",
                get(
                    |State(state): State<SharedState>, Path(slug): Path<String>| {
                        let svc = from_state(state);
                        send_bridge(async move {
                            match svc.serve_registry_llms(&slug).await {
                                Ok(Some(body)) => text_plain_response(body),
                                Ok(None) => StatusCode::NOT_FOUND.into_response(),
                                Err(err) => error_response(&err),
                            }
                        })
                    },
                ),
            );
        // The no-JS browse surface: the hub home, the `/{slug}/-/…` pages, and
        // the `/{slug}/-/api/…` JSON read API. These static-prefixed routes win
        // over the facade wildcard below by axum's static-over-dynamic
        // precedence, so the reserved `/-/` namespace can never be shadowed by a
        // machine path. The bare `/{slug}/-/` registry-home route is registered
        // alongside the `/{slug}/-/{*rest}` wildcard because axum does not match
        // an empty `{*rest}` capture.
        r = r.route(
            "/",
            get(
                |State(state): State<SharedState>, headers: HeaderMap, uri: axum::http::Uri| {
                    let svc = from_state(state);
                    send_bridge(async move {
                        let q = browse::BrowseQuery::parse(uri.query());
                        browse_response(browse::home(&svc, &headers, &q).await)
                    })
                },
            ),
        );
        // `/{slug}` (no trailing slash) permanently redirects to `/{slug}/` so
        // the registry root has one canonical, slash-terminated URL.
        r = r.route(
            "/{slug}",
            get(|Path(slug): Path<String>| {
                send_bridge(async move { browse_response(Rendered::Redirect(format!("/{slug}/"))) })
            }),
        );
        // The registry home is served both at `/{slug}/` (the canonical,
        // slash-terminated root the rich pages link to) and at the marker form
        // `/{slug}/-/`; both dispatch to the registry-home browse read, which
        // content-negotiates HTML vs the machine `index.html` pointer.
        let registry_home = |State(state): State<SharedState>,
                             headers: HeaderMap,
                             Path(slug): Path<String>,
                             uri: axum::http::Uri| {
            let svc = from_state(state);
            send_bridge(browse_dispatch(
                svc,
                headers,
                slug,
                String::new(),
                uri.query().map(str::to_owned),
            ))
        };
        r = r.route("/{slug}/", get(registry_home));
        r = r.route(&format!("/{{slug}}/{BROWSE_MARKER}/"), get(registry_home));
        r = r.route(
            &format!("/{{slug}}/{BROWSE_MARKER}/{{*rest}}"),
            get(
                |State(state): State<SharedState>,
                 headers: HeaderMap,
                 Path((slug, rest)): Path<(String, String)>,
                 uri: axum::http::Uri| {
                    let svc = from_state(state);
                    send_bridge(browse_dispatch(
                        svc,
                        headers,
                        slug,
                        rest,
                        uri.query().map(str::to_owned),
                    ))
                },
            ),
        );
    }
    if mount_facade {
        // The machine-surface facade: a catch-all `GET` (axum routes `HEAD` to
        // it, eliding the body) for the registry machine path, registered LAST.
        // The static `/aos.hub.v1.{Service}/{Method}` RPC routes and the
        // browse routes above win over this `/{slug}/{*path}` wildcard by axum's
        // static-over-dynamic precedence, so the facade only matches a machine
        // URL. Omitted by [`rpc_router`]/[`rpc_browse_router`] so a host with its
        // own `/{slug}/{*path}` (the native hub) does not double-mount it.
        r = r.route(
            "/{slug}/{*path}",
            get(
                |State(state): State<SharedState>,
                 headers: HeaderMap,
                 Path((slug, path)): Path<(String, String)>,
                 uri: axum::http::Uri| {
                    let svc = from_state(state);
                    let query = uri.query().map(str::to_owned);
                    send_bridge(facade(svc, headers, slug, path, query))
                },
            )
            // The authenticated surface-upload `PUT` shares the wildcard so an
            // `apr origin upload` / `apm` publish lands directly on the registry
            // URL (RFC-0004 "like magic"). The body extractor is last so axum
            // buffers it only for the write method. The Worker mounts this whole
            // router, so this is how it stores published artifacts; the native
            // hub keeps its own richer `/{slug}/{*path}` handler instead (this
            // facade route is omitted for it via `mount_facade = false`).
            .put(
                |State(state): State<SharedState>,
                 headers: HeaderMap,
                 Path((slug, path)): Path<(String, String)>,
                 uri: axum::http::Uri,
                 body: Bytes| {
                    let svc = from_state(state);
                    let query = uri.query().map(str::to_owned);
                    send_bridge(facade_put(svc, headers, slug, path, query, body))
                },
            )
            // Multipart upload over the same wildcard (S3-style query
            // convention): `POST ?uploads` initiates, `POST ?uploadId` completes,
            // `DELETE ?uploadId` aborts; the parts ride the `PUT` above. Each
            // part is a small, sub-cap body, so they upload with bounded memory
            // even for NARs far larger than the request-body limit.
            .post(
                |State(state): State<SharedState>,
                 headers: HeaderMap,
                 Path((slug, path)): Path<(String, String)>,
                 uri: axum::http::Uri,
                 body: Bytes| {
                    let svc = from_state(state);
                    let query = uri.query().map(str::to_owned);
                    send_bridge(facade_post(svc, headers, slug, path, query, body))
                },
            )
            .delete(
                |State(state): State<SharedState>,
                 headers: HeaderMap,
                 Path((slug, path)): Path<(String, String)>,
                 uri: axum::http::Uri| {
                    let svc = from_state(state);
                    let query = uri.query().map(str::to_owned);
                    send_bridge(facade_delete(svc, headers, slug, path, query))
                },
            ),
        );
        // Raise axum's 2 MiB default body limit for the worker facade: a
        // multipart *part* (the client chunks at the server-suggested 16 MiB)
        // must not be rejected. Multipart bounds each request — and thus the
        // buffered body — to one part, so this is a safety ceiling, not the
        // steady state; NARs larger than it upload as several parts.
        r = r.layer(axum::extract::DefaultBodyLimit::max(MAX_FACADE_BODY_BYTES));
    }
    // `POST /oauth2/token` provisioning-secret -> JWT exchange. The native hub
    // mounts its own rate-limited fragment in `server.rs`; the Worker has none,
    // so the shared worker entry ([`router`], the only builder with
    // `mount_facade`) mounts it here. Gated on `mount_facade` so the native
    // `rpc_browse_router` (`mount_facade = false`) never double-mounts it.
    if mount_facade {
        r = r.route(
            "/oauth2/token",
            post(|State(state): State<SharedState>, headers: HeaderMap| {
                let svc = from_state(state);
                send_bridge(async move { oauth2_token_exchange(&svc, &headers).await })
            }),
        );
    }
    r.with_state(into_state(service))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use aos_proto_types as pb;

    /// Run [`resolve_prefix_with`] against a fixed set of known slugs.
    async fn resolve(path: &str, slugs: &[&str]) -> Option<(String, String)> {
        resolve_prefix_with(path, |candidate| {
            let hit = slugs.contains(&candidate);
            async move { hit }
        })
        .await
    }

    #[tokio::test]
    async fn longest_prefix_resolves_nested_slug_with_tail() {
        let slugs = ["andyl/demo", "andyl"];
        assert_eq!(
            resolve("andyl/demo/nar/x", &slugs).await,
            Some(("andyl/demo".to_string(), "nar/x".to_string()))
        );
    }

    #[tokio::test]
    async fn exact_match_resolves_to_empty_tail() {
        let slugs = ["andyl/demo", "andyl"];
        assert_eq!(
            resolve("andyl/demo", &slugs).await,
            Some(("andyl/demo".to_string(), String::new()))
        );
    }

    #[tokio::test]
    async fn falls_back_to_shorter_slug_prefix() {
        let slugs = ["andyl/demo", "andyl"];
        assert_eq!(
            resolve("andyl/other", &slugs).await,
            Some(("andyl".to_string(), "other".to_string()))
        );
    }

    #[tokio::test]
    async fn unknown_path_resolves_to_none() {
        let slugs = ["andyl/demo", "andyl"];
        assert_eq!(resolve("acme/infra/cdn", &slugs).await, None);
    }

    #[tokio::test]
    async fn segment_boundary_is_respected() {
        // `andyl/demo-staging` must not resolve to `andyl/demo`.
        let slugs = ["andyl/demo", "andyl"];
        assert_eq!(
            resolve("andyl/demo-staging", &slugs).await,
            Some(("andyl".to_string(), "demo-staging".to_string()))
        );
    }

    #[test]
    fn browse_marker_split_mid_and_trailing() {
        assert_eq!(
            split_browse_marker("andyl/demo/-/packages"),
            Some(("andyl/demo".to_string(), "packages".to_string()))
        );
        assert_eq!(
            split_browse_marker("andyl/demo/-"),
            Some(("andyl/demo".to_string(), String::new()))
        );
        assert_eq!(split_browse_marker("andyl/demo/packages"), None);
    }

    #[test]
    fn topology_paths_use_the_public_hub_namespace() {
        assert_eq!(
            LIST_PLACEMENTS_PATH,
            "/aos.hub.v1.TopologyService/ListPlacements"
        );
        assert_eq!(
            GET_PLACEMENT_PATH,
            "/aos.hub.v1.TopologyService/GetPlacement"
        );
        assert_eq!(
            CREATE_PLACEMENT_PATH,
            "/aos.hub.v1.TopologyService/CreatePlacement"
        );
        assert_eq!(
            UPDATE_PLACEMENT_PATH,
            "/aos.hub.v1.TopologyService/UpdatePlacement"
        );
        assert_eq!(
            GET_WRITE_AUTHORITY_PATH,
            "/aos.hub.v1.TopologyService/GetWriteAuthority"
        );
        assert_eq!(
            PLAN_PROMOTE_PLACEMENT_PATH,
            "/aos.hub.v1.TopologyService/PlanPromotePlacement"
        );
        assert_eq!(
            PROMOTE_PLACEMENT_PATH,
            "/aos.hub.v1.TopologyService/PromotePlacement"
        );
        assert_eq!(
            RECONCILE_WRITE_AUTHORITY_PATH,
            "/aos.hub.v1.TopologyService/ReconcileWriteAuthority"
        );
        assert_eq!(
            PLAN_REMOVE_WRITE_AUTHORITY_PATH,
            "/aos.hub.v1.TopologyService/PlanRemoveWriteAuthority"
        );
        assert_eq!(
            REMOVE_WRITE_AUTHORITY_PATH,
            "/aos.hub.v1.TopologyService/RemoveWriteAuthority"
        );
        assert_eq!(
            DRAIN_PLACEMENT_PATH,
            "/aos.hub.v1.TopologyService/DrainPlacement"
        );
        assert_eq!(
            DELETE_PLACEMENT_PATH,
            "/aos.hub.v1.TopologyService/DeletePlacement"
        );
    }

    #[test]
    fn surface_ref_uses_canonical_camel_case_oneof_json() {
        let request = pb::ListPlacementsRequest {
            surface: Some(pb::SurfaceRef {
                target: Some(pb::surface_ref::Target::RegistrySlug(
                    "andyl/main".to_string(),
                )),
            }),
            page_size: 25,
            page_token: "next".to_string(),
        };
        let json = serde_json::to_value(request).unwrap();
        assert_eq!(json["surface"]["registrySlug"], "andyl/main");
        assert_eq!(json["pageSize"], 25);
        assert_eq!(json["pageToken"], "next");
        assert!(json["surface"].get("target").is_none());
        assert!(json["surface"].get("registry_slug").is_none());
    }
}
