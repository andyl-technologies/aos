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

use crate::service::{RpcError, RpcService};

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
    build(service, true)
}

/// Build the shared Connect-JSON router *without* the machine-surface facade.
///
/// Identical to [`router`] but omits the catch-all `/{slug}/{*path}` facade
/// route, so it can be merged into a host that already owns that path with a
/// richer handler — the native hub, whose facade serves filesystem autoindexes,
/// `http(s)` redirects, pull-through mirroring, and inert producer documents,
/// and authorizes private reads from a session cookie as well as a bearer JWT
/// (merging two routers that both define `/{slug}/{*path}` would otherwise
/// panic). The returned router carries the service as axum state.
#[must_use]
pub fn rpc_router(service: Arc<RpcService>) -> Router {
    build(service, false)
}

/// Build the shared router, optionally mounting the machine-surface facade.
///
/// `mount_facade` adds the catch-all `GET`/`HEAD` `/{slug}/{*path}` facade route
/// last; see [`router`] (mounts it) and [`rpc_router`] (omits it).
fn build(service: Arc<RpcService>, mount_facade: bool) -> Router {
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
    // The machine-surface facade: a catch-all `GET` (axum routes `HEAD` to it,
    // eliding the body) for the registry machine path, registered LAST. The
    // static `/aos.registry.v1.{Service}/{Method}` RPC routes above win over
    // this `/{slug}/{*path}` wildcard by axum's static-over-dynamic precedence,
    // so the facade only matches a registry URL. Omitted by [`rpc_router`] so a
    // host with its own `/{slug}/{*path}` (the native hub) does not double-mount
    // it.
    if mount_facade {
        r = r.route(
            "/{slug}/{*path}",
            get(
                |State(state): State<SharedState>, headers: HeaderMap, Path((slug, path)): Path<(String, String)>| {
                    let svc = from_state(state);
                    send_bridge(facade(svc, headers, slug, path))
                },
            ),
        );
    }
    r.with_state(into_state(service))
}
