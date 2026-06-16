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
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::post;
use axum::{Json, Router};
use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::service::{RpcError, RpcService};

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

/// Mount one `aos.registry.v1` method as a `POST` route delegating to the
/// same-named [`RpcService`] method.
macro_rules! rpc_route {
    ($router:expr, $path:literal, $method:ident) => {
        $router.route(
            $path,
            post(
                |State(svc): State<Arc<RpcService>>, headers: HeaderMap, body: Bytes| {
                    unary(svc, headers, body, |svc, auth, req| async move {
                        svc.$method(auth.as_deref(), req).await
                    })
                },
            ),
        )
    };
}

/// Build the shared Connect-JSON router over the given [`RpcService`].
///
/// Wires every ported `aos.registry.v1` method to `POST
/// /aos.registry.v1.{Service}/{Method}`. The three `GitService` methods are not
/// yet mounted (they await the surface/blob-store port; RFC-0004 Phase 5 step
/// 4c). The returned router carries the service as axum state and is mounted
/// unchanged by both the native hub and the Cloudflare Worker.
#[must_use]
pub fn router(service: Arc<RpcService>) -> Router {
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
    r.with_state(service)
}
