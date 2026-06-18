//! The shared Connect-JSON `axum` router for the `aos.registry.v1` API.
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
//! Each method is one route: `POST /aos.registry.v1.{Service}/{Method}`. The
//! request body is the JSON-encoded request message; the success response is
//! the JSON-encoded response message with `200 OK`. An error is the Connect
//! error envelope with the matching HTTP status:
//!
//! ```text
//! POST /aos.registry.v1.RegistryService/GetRegistry
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
use axum::extract::{Path, State};
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::service::{FacadeObject, FacadeWrite, RpcError, RpcService};
use crate::web::browse::{self, Rendered};

/// The reserved human-namespace marker segment (`/{slug}/-/…`).
///
/// Browse pages and the JSON read API live under this segment so they can never
/// be shadowed by the machine surface that owns the registry root (RFC-0004
/// "The `/-/` namespace").
const BROWSE_MARKER: &str = "-";

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

/// Render an [`RpcError`] as the Connect-JSON error envelope plus HTTP status.
fn error_response(err: &RpcError) -> Response {
    let status = StatusCode::from_u16(err.http_status()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
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
/// [`RpcService::facade_fetch`](crate::service::RpcService::facade_fetch), which
/// classifies the path, enforces registry visibility against the
/// `Authorization` header, and reads the bytes through the
/// [`SurfaceProvider`](crate::fetch::SurfaceProvider). A hit renders as `200`
/// with the path's `Content-Type` and `Cache-Control`; a `None` (non-machine
/// path or absent object) renders as `404`; an [`RpcError`] renders as the
/// Connect error envelope (so a private registry read without authority is the
/// usual `401`/`403`/`404`).
///
/// The body is dropped for the response either way, so a `HEAD` and a `GET`
/// share this one handler and differ only in whether axum elides the body.
async fn facade(
    svc: Arc<RpcService>,
    headers: HeaderMap,
    slug: String,
    path: String,
) -> Response {
    let auth = auth_header(&headers);
    match svc.facade_fetch(auth.as_deref(), &slug, &path).await {
        // A presigned private-origin read: `302` to the (short-lived) origin URL
        // the client fetches directly, instead of serving bytes through the hub.
        Ok(Some(FacadeObject {
            redirect: Some(location),
            ..
        })) => match header::HeaderValue::from_str(&location) {
            Ok(value) => (StatusCode::FOUND, [(header::LOCATION, value)]).into_response(),
            Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
        },
        Ok(Some(object)) => (
            [
                (header::CONTENT_TYPE, object.content_type),
                (header::CACHE_CONTROL, object.cache_control),
            ],
            object.bytes,
        )
            .into_response(),
        Ok(None) => StatusCode::NOT_FOUND.into_response(),
        Err(err) => error_response(&err),
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
    body: Bytes,
) -> Response {
    let auth = auth_header(&headers);
    let outcome = svc
        .put_machine_path(auth.as_deref(), &slug, &path, &body)
        .await;
    facade_write_response(outcome, &path)
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
        Rendered::Json(body) => (
            [(header::CONTENT_TYPE, "application/json")],
            body,
        )
            .into_response(),
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
                } else if let Some(name) =
                    other.strip_prefix("channels/").filter(|n| !n.is_empty())
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

/// Mount one `aos.registry.v1` method as a `POST` route delegating to the
/// same-named [`RpcService`] method.
macro_rules! rpc_route {
    ($router:expr, $path:literal, $method:ident) => {
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
/// Wires every ported `aos.registry.v1` method to `POST
/// /aos.registry.v1.{Service}/{Method}`, including the three `GitService`
/// methods served over the surface-read port
/// ([`SurfaceProvider`](crate::fetch::SurfaceProvider)). It additionally mounts
/// the machine-surface facade as a catch-all `GET`/`HEAD` `/{slug}/{*path}`
/// route (delegating to
/// [`RpcService::facade_fetch`](crate::service::RpcService::facade_fetch) over
/// the same surface port), registered last so the static RPC method paths win
/// over the wildcard by axum's static-over-dynamic precedence.
///
/// This is the variant the Cloudflare Worker mounts whole: it has no facade of
/// its own, so the shared route is its only machine-surface serving path. The
/// native hub instead mounts the facade-less [`rpc_router`] and keeps its own
/// richer `/{slug}/{*path}` handler (filesystem autoindex, `http(s)` redirect,
/// pull-through mirroring, producer-document inert serving, and session-cookie
/// authorization), delegating only the plain fetch+serve to the same
/// [`RpcService::facade_fetch`](crate::service::RpcService::facade_fetch). The
/// returned router carries the service as axum state.
#[must_use]
pub fn router(service: Arc<RpcService>) -> Router {
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

/// Build the shared router, optionally mounting the browse surface and/or the
/// machine-surface facade.
///
/// `mount_browse` adds the no-JS browse routes (the hub home `/`, the `/{slug}`
/// redirect, the registry home `/{slug}/` and `/{slug}/-/`, the `/{slug}/-/…`
/// pages, and the `/{slug}/-/api/…` JSON read API). `mount_facade` adds the
/// catch-all `GET`/`HEAD` `/{slug}/{*path}` machine-surface facade. The Worker
/// takes both ([`router`]); the native hub takes browse only
/// ([`rpc_browse_router`]) and keeps its own facade; [`rpc_router`] takes
/// neither.
fn build(service: Arc<RpcService>, mount_browse: bool, mount_facade: bool) -> Router {
    let mut r = Router::new();
    // RegistryService
    r = rpc_route!(r, "/aos.registry.v1.RegistryService/ListRegistries", list_registries);
    r = rpc_route!(r, "/aos.registry.v1.RegistryService/GetRegistry", get_registry);
    r = rpc_route!(r, "/aos.registry.v1.RegistryService/ListReleases", list_releases);
    r = rpc_route!(r, "/aos.registry.v1.RegistryService/CreateRegistry", create_registry);
    // OrgService
    r = rpc_route!(r, "/aos.registry.v1.OrgService/CreateOrg", create_org);
    r = rpc_route!(r, "/aos.registry.v1.OrgService/GetOrg", get_org);
    r = rpc_route!(r, "/aos.registry.v1.OrgService/ListOrgs", list_orgs);
    // ProjectService
    r = rpc_route!(r, "/aos.registry.v1.ProjectService/CreateProject", create_project);
    r = rpc_route!(r, "/aos.registry.v1.ProjectService/ListProjects", list_projects);
    // StorageService
    r = rpc_route!(r, "/aos.registry.v1.StorageService/CreateBinding", create_binding);
    r = rpc_route!(r, "/aos.registry.v1.StorageService/ListBindings", list_bindings);
    // PackageService
    r = rpc_route!(r, "/aos.registry.v1.PackageService/ListPackages", list_packages);
    r = rpc_route!(r, "/aos.registry.v1.PackageService/GetPackage", get_package);
    // ChannelService
    r = rpc_route!(r, "/aos.registry.v1.ChannelService/ListChannels", list_channels);
    r = rpc_route!(r, "/aos.registry.v1.ChannelService/GetChannel", get_channel);
    // AuditService
    r = rpc_route!(r, "/aos.registry.v1.AuditService/ListAudit", list_audit);
    // ConfigService
    r = rpc_route!(r, "/aos.registry.v1.ConfigService/ListChangesets", list_changesets);
    r = rpc_route!(r, "/aos.registry.v1.ConfigService/GetChangeset", get_changeset);
    r = rpc_route!(r, "/aos.registry.v1.ConfigService/RevertChangeset", revert_changeset);
    // WebhookService
    r = rpc_route!(r, "/aos.registry.v1.WebhookService/CreateWebhook", create_webhook);
    r = rpc_route!(r, "/aos.registry.v1.WebhookService/ListWebhooks", list_webhooks);
    r = rpc_route!(r, "/aos.registry.v1.WebhookService/DeleteWebhook", delete_webhook);
    // PublishService
    r = rpc_route!(r, "/aos.registry.v1.PublishService/MintUploadCredentials", mint_upload_credentials);
    // GitService
    r = rpc_route!(r, "/aos.registry.v1.GitService/GitLog", git_log);
    r = rpc_route!(r, "/aos.registry.v1.GitService/GitDiff", git_diff);
    r = rpc_route!(r, "/aos.registry.v1.GitService/ListChangeRequests", list_change_requests);
    // CacheService (RFC-0004 "11-caches")
    r = rpc_route!(r, "/aos.registry.v1.CacheService/CreateCache", create_cache);
    r = rpc_route!(r, "/aos.registry.v1.CacheService/GetCache", get_cache);
    r = rpc_route!(r, "/aos.registry.v1.CacheService/ListCaches", list_caches);
    r = rpc_route!(r, "/aos.registry.v1.CacheService/UpdateCache", update_cache);
    r = rpc_route!(r, "/aos.registry.v1.CacheService/DeleteCache", delete_cache);
    r = rpc_route!(r, "/aos.registry.v1.CacheService/LinkCache", link_cache);
    r = rpc_route!(r, "/aos.registry.v1.CacheService/UnlinkCache", unlink_cache);
    r = rpc_route!(r, "/aos.registry.v1.CacheService/ListCacheLinks", list_cache_links);
    r = rpc_route!(r, "/aos.registry.v1.CacheService/SetCacheGcPolicy", set_cache_gc_policy);
    r = rpc_route!(r, "/aos.registry.v1.CacheService/GetCacheGcPolicy", get_cache_gc_policy);
    r = rpc_route!(r, "/aos.registry.v1.CacheService/PinCachePath", pin_cache_path);
    r = rpc_route!(r, "/aos.registry.v1.CacheService/UnpinCachePath", unpin_cache_path);
    r = rpc_route!(r, "/aos.registry.v1.CacheService/ListCacheRoots", list_cache_roots);
    r = rpc_route!(r, "/aos.registry.v1.CacheService/SearchCache", search_cache);
    r = rpc_route!(r, "/aos.registry.v1.CacheService/GetCacheObject", get_cache_object);
    r = rpc_route!(r, "/aos.registry.v1.CacheService/ListCacheGcRuns", list_cache_gc_runs);
    r = rpc_route!(r, "/aos.registry.v1.CacheService/RunCacheGc", run_cache_gc);
    r = rpc_route!(r, "/aos.registry.v1.CacheService/CacheClosure", cache_closure);
    // The machine-surface facade: a catch-all `GET` (axum routes `HEAD` to it,
    // eliding the body) for the registry machine path, registered LAST. The
    // static `/aos.registry.v1.{Service}/{Method}` RPC routes above win over
    // this `/{slug}/{*path}` wildcard by axum's static-over-dynamic precedence,
    // so the facade only matches a registry URL. Omitted by [`rpc_router`] so a
    // host with its own `/{slug}/{*path}` (the native hub) does not double-mount
    // it.
    if mount_browse {
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
        let registry_home =
            |State(state): State<SharedState>, headers: HeaderMap, Path(slug): Path<String>, uri: axum::http::Uri| {
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
                |State(state): State<SharedState>, headers: HeaderMap, Path((slug, rest)): Path<(String, String)>, uri: axum::http::Uri| {
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
        // The static `/aos.registry.v1.{Service}/{Method}` RPC routes and the
        // browse routes above win over this `/{slug}/{*path}` wildcard by axum's
        // static-over-dynamic precedence, so the facade only matches a machine
        // URL. Omitted by [`rpc_router`]/[`rpc_browse_router`] so a host with its
        // own `/{slug}/{*path}` (the native hub) does not double-mount it.
        r = r.route(
            "/{slug}/{*path}",
            get(
                |State(state): State<SharedState>, headers: HeaderMap, Path((slug, path)): Path<(String, String)>| {
                    let svc = from_state(state);
                    send_bridge(facade(svc, headers, slug, path))
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
                |State(state): State<SharedState>, headers: HeaderMap, Path((slug, path)): Path<(String, String)>, body: Bytes| {
                    let svc = from_state(state);
                    send_bridge(facade_put(svc, headers, slug, path, body))
                },
            ),
        );
    }
    r.with_state(into_state(service))
}
