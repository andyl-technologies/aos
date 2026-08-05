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
//! Connect-Protocol-Version: 1
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
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderMap, Method, StatusCode, Uri};
#[cfg(not(target_arch = "wasm32"))]
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use serde::de::DeserializeOwned;
use serde::Serialize;
use unicode_normalization::UnicodeNormalization as _;

use crate::service::{ReadAuthorization, RegistryServeOutcome, RpcError, RpcService};
use crate::web::browse::{self, Rendered};

/// The reserved human-namespace marker segment (`/{slug}/-/…`).
///
/// Browse pages and the JSON read API live under this segment so they can never
/// be shadowed by the machine surface that owns the registry root (RFC-0004
/// "The `/-/` namespace").
const BROWSE_MARKER: &str = "-";
const DOMAIN_PROBE_PATH: &str = "/.well-known/aos-domain-probe";

#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DomainProbeQuery {
    nonce: String,
}

/// Canonical Connect namespace for placement collection reads.
const LIST_PLACEMENTS_PATH: &str = "/aos.hub.v1.TopologyService/ListPlacements";
/// Canonical Connect namespace for one placement read.
const GET_PLACEMENT_PATH: &str = "/aos.hub.v1.TopologyService/GetPlacement";
/// Canonical Connect namespace for placement creation.
const PLAN_CREATE_PLACEMENT_PATH: &str = "/aos.hub.v1.TopologyService/PlanCreatePlacement";
/// Canonical Connect namespace for placement creation-plan application.
const CREATE_PLACEMENT_PATH: &str = "/aos.hub.v1.TopologyService/CreatePlacement";
/// Canonical Connect namespace for mutable placement updates.
const PLAN_UPDATE_PLACEMENT_PATH: &str = "/aos.hub.v1.TopologyService/PlanUpdatePlacement";
/// Canonical Connect namespace for placement update-plan application.
const UPDATE_PLACEMENT_PATH: &str = "/aos.hub.v1.TopologyService/UpdatePlacement";
/// Canonical Connect namespace for the desired/observed authority view.
const GET_WRITE_AUTHORITY_PATH: &str = "/aos.hub.v1.TopologyService/GetWriteAuthority";
/// Canonical Connect namespace for immutable promotion planning.
const PLAN_PROMOTE_PLACEMENT_PATH: &str = "/aos.hub.v1.TopologyService/PlanPromotePlacement";
/// Canonical Connect namespace for promotion-plan application.
const PROMOTE_PLACEMENT_PATH: &str = "/aos.hub.v1.TopologyService/PromotePlacement";
/// Canonical Connect namespace for controller authority observations.
const REPORT_WRITE_AUTHORITY_PATH: &str =
    "/aos.hub.v1.TopologyControllerService/ReportWriteAuthority";
/// Canonical Connect namespace for explicit read-only planning.
const PLAN_REMOVE_WRITE_AUTHORITY_PATH: &str =
    "/aos.hub.v1.TopologyService/PlanRemoveWriteAuthority";
/// Canonical Connect namespace for explicit read-only plan application.
const REMOVE_WRITE_AUTHORITY_PATH: &str = "/aos.hub.v1.TopologyService/RemoveWriteAuthority";
/// Canonical Connect namespace for placement drain planning.
const PLAN_DRAIN_PLACEMENT_PATH: &str = "/aos.hub.v1.TopologyService/PlanDrainPlacement";
/// Canonical Connect namespace for placement drain application.
const DRAIN_PLACEMENT_PATH: &str = "/aos.hub.v1.TopologyService/DrainPlacement";
/// Canonical Connect namespace for placement drain-cancellation planning.
const PLAN_CANCEL_PLACEMENT_DRAIN_PATH: &str =
    "/aos.hub.v1.TopologyService/PlanCancelPlacementDrain";
/// Canonical Connect namespace for placement drain-cancellation application.
const CANCEL_PLACEMENT_DRAIN_PATH: &str = "/aos.hub.v1.TopologyService/CancelPlacementDrain";
/// Canonical Connect namespace for placement deletion plans/applies.
const PLAN_DELETE_PLACEMENT_PATH: &str = "/aos.hub.v1.TopologyService/PlanDeletePlacement";
/// Canonical Connect namespace for placement deletion-plan application.
const DELETE_PLACEMENT_PATH: &str = "/aos.hub.v1.TopologyService/DeletePlacement";

/// Maximum buffered body size for every unary Connect request on both shells.
pub const CONNECT_REQUEST_BODY_LIMIT_BYTES: usize = 8 * 1024 * 1024;

/// Connect unary protocol-version request header.
const CONNECT_PROTOCOL_VERSION_HEADER: &str = "connect-protocol-version";

#[cfg(target_arch = "wasm32")]
use send_wrapper::SendWrapper;

// --- The wasm `Send` bridge ---------------------------------------------------
//
// `axum`'s `Handler` and `Router` state demand `Send + Sync`, but the Worker's
// Worker-backed `RpcService` is `?Send` (its runtime futures hold
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

/// Validates the headers required by a Connect unary JSON request.
fn validate_connect_headers(headers: &HeaderMap) -> Result<(), Response> {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .ok_or_else(|| StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response())?;
    let media_type = content_type
        .split(';')
        .next()
        .map(str::trim)
        .unwrap_or_default();
    if !media_type.eq_ignore_ascii_case("application/json") {
        return Err(StatusCode::UNSUPPORTED_MEDIA_TYPE.into_response());
    }

    let mut encodings = headers.get_all(header::CONTENT_ENCODING).iter();
    if let Some(encoding) = encodings.next() {
        if encodings.next().is_some() || !encoding.as_bytes().eq_ignore_ascii_case(b"identity") {
            return Err(error_response(&RpcError::Unimplemented(
                "unsupported Content-Encoding; supported encodings: identity".to_string(),
            )));
        }
    }

    let mut versions = headers.get_all(CONNECT_PROTOCOL_VERSION_HEADER).iter();
    let version = versions
        .next()
        .ok_or_else(|| error_response(&RpcError::invalid("missing Connect-Protocol-Version: 1")))?;
    if versions.next().is_some() || version.as_bytes() != b"1" {
        return Err(error_response(&RpcError::invalid(
            "Connect-Protocol-Version must occur once with value 1",
        )));
    }
    Ok(())
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
    if let Err(response) = validate_connect_headers(&headers) {
        return response;
    }
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

/// Converts a shared browse rendering into an HTTP response.
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
        Rendered::ServiceUnavailable => StatusCode::SERVICE_UNAVAILABLE.into_response(),
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
    if matches!(svc.db.binary_cache_by_slug(&slug).await, Ok(Some(_))) {
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
            "images" => browse::images(&svc, &headers, &slug, &q).await,
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

/// Trusted transport facts supplied by the native listener or Worker runtime.
/// Trusted transport facts supplied by the native listener or Worker runtime.
///
/// These values are not inferred from forwarding headers. A trusted layer-7
/// adapter may construct the evidence only after authenticating its ingress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryTransportEvidence {
    /// Actual listener scheme.
    pub scheme: String,
    /// `hub` or `layer7`, matching the immutable endpoint revision.
    pub ingress_kind: String,
    /// TLS-verified DNS/IP identity. Absent for cleartext HTTP.
    pub tls_identity: Option<crate::db::InboundEndpointHost>,
}

impl DeliveryTransportEvidence {
    /// Builds transport evidence from a runtime-verified absolute request URL.
    #[must_use]
    pub fn from_verified_url(url: &url::Url, ingress_kind: &str) -> Option<Self> {
        if !matches!(ingress_kind, "hub" | "layer7") {
            return None;
        }
        let scheme = url.scheme();
        if !matches!(scheme, "http" | "https") {
            return None;
        }
        let host = canonical_endpoint_host(url.host_str()?).ok()?;
        Some(Self {
            scheme: scheme.to_owned(),
            ingress_kind: ingress_kind.to_owned(),
            tls_identity: (scheme == "https").then_some(host),
        })
    }
}

/// Trusted route-access assertion supplied by a configured ingress.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeliveryAccessEvidence {
    /// Exact verified private-network boundary.
    pub boundary: Option<(String, i64)>,
    /// Exact verified external provider `(kind, resource, revision)`.
    pub external_provider: Option<(String, String, String)>,
}

/// Capability selected by the shared path classifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryAudience {
    /// Registry Git protocol and immutable release paths.
    Git,
    /// Nix binary-cache protocol.
    NixCache,
    /// Human-readable Web surface.
    Web,
}

/// Typed route resolution carried to the internal delivery handler.
#[derive(Debug, Clone)]
pub struct ResolvedDeliveryRoute {
    /// Exact immutable route snapshot selected for this request.
    pub route: crate::db::InboundDeliveryRouteRecord,
    /// Route-relative canonical path, without a leading slash.
    pub surface_path: String,
    /// Capability selected from the surface kind and path.
    pub audience: DeliveryAudience,
}

/// Verifies a configured ingress assertion and replaces any existing evidence.
///
/// An assertion header is always consumed. If no verifier is configured, its
/// presence is treated as a spoof attempt rather than ignored.
///
/// # Errors
///
/// Returns `401 Unauthorized` for an absent verifier, duplicate/malformed
/// header, invalid signature, expired assertion, or request mismatch.
pub fn apply_delivery_attestation(
    mut request: Request,
    verifier: Option<&crate::delivery_attestation::DeliveryAttestationVerifier>,
    now: i64,
) -> Result<Request, Response> {
    use crate::delivery_attestation::DELIVERY_ATTESTATION_HEADER;

    let values = request
        .headers()
        .get_all(DELIVERY_ATTESTATION_HEADER)
        .iter()
        .collect::<Vec<_>>();
    if values.is_empty() {
        return Ok(request);
    }
    if values.len() != 1 {
        return Err(StatusCode::UNAUTHORIZED.into_response());
    }
    let compact = values[0]
        .to_str()
        .map_err(|_| StatusCode::UNAUTHORIZED.into_response())?
        .to_owned();
    request.headers_mut().remove(DELIVERY_ATTESTATION_HEADER);
    let verifier = verifier.ok_or_else(|| StatusCode::UNAUTHORIZED.into_response())?;
    let uri_authority = request.uri().authority().map(|value| value.as_str());
    let host_authority = request
        .headers()
        .get(header::HOST)
        .and_then(|value| value.to_str().ok());
    if let (Some(uri), Some(host)) = (uri_authority, host_authority) {
        if uri != host {
            return Err(StatusCode::UNAUTHORIZED.into_response());
        }
    }
    let authority = uri_authority
        .or(host_authority)
        .ok_or_else(|| StatusCode::UNAUTHORIZED.into_response())?;
    let path_and_query = request
        .uri()
        .path_and_query()
        .map(|value| value.as_str())
        .unwrap_or(request.uri().path());
    let verified = verifier
        .verify(
            &compact,
            request.method().as_str(),
            authority,
            path_and_query,
            now,
        )
        .map_err(|_| StatusCode::UNAUTHORIZED.into_response())?;
    request.extensions_mut().insert(verified.transport.clone());
    request.extensions_mut().insert(verified);
    Ok(request)
}

/// Canonicalizes one raw HTTP request path under the RFC-0012 rules.
fn canonical_request_path(raw: &str) -> Result<String, ()> {
    if !raw.starts_with('/') || raw.contains(['\\', '\0']) || raw.contains("//") {
        return Err(());
    }
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] != b'%' {
            if bytes[index].is_ascii_control() {
                return Err(());
            }
            decoded.push(bytes[index]);
            index += 1;
            continue;
        }
        if index + 2 >= bytes.len() {
            return Err(());
        }
        let hex = |byte: u8| match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        };
        let Some(high) = hex(bytes[index + 1]) else {
            return Err(());
        };
        let Some(low) = hex(bytes[index + 2]) else {
            return Err(());
        };
        let byte = high * 16 + low;
        // Encoded ASCII is never canonical. This includes `%25`, closing the
        // double-encoding ambiguity before a second decoder can see it.
        if byte.is_ascii() {
            return Err(());
        }
        decoded.push(byte);
        index += 3;
    }
    let decoded = String::from_utf8(decoded).map_err(|_| ())?;
    let normalized = decoded.nfc().collect::<String>();
    if normalized
        .split('/')
        .any(|segment| matches!(segment, "." | ".."))
    {
        return Err(());
    }
    Ok(normalized)
}

fn canonical_endpoint_host(host: &str) -> Result<crate::db::InboundEndpointHost, ()> {
    use std::net::IpAddr;
    use std::str::FromStr as _;

    if host.is_empty()
        || host.ends_with('.')
        || host.contains(['%', '@'])
        || host.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(());
    }
    match IpAddr::from_str(host).ok() {
        Some(IpAddr::V4(address)) => Ok(crate::db::InboundEndpointHost::Ipv4(
            address.octets().to_vec(),
        )),
        Some(IpAddr::V6(address)) => {
            if address.to_ipv4_mapped().is_some() {
                return Err(());
            }
            Ok(crate::db::InboundEndpointHost::Ipv6(
                address.octets().to_vec(),
            ))
        }
        None => match url::Host::parse(host).map_err(|_| ())? {
            url::Host::Domain(domain) if !domain.is_empty() => {
                Ok(crate::db::InboundEndpointHost::Domain(domain))
            }
            _ => Err(()),
        },
    }
}

/// Extracts and canonicalizes the host from an already authenticated authority.
pub(crate) fn attested_authority_host(
    authority: &str,
) -> Result<crate::db::InboundEndpointHost, ()> {
    let authority = authority
        .parse::<axum::http::uri::Authority>()
        .map_err(|_| ())?;
    if authority.as_str().contains('@') {
        return Err(());
    }
    canonical_endpoint_host(authority.host())
}

/// Parses request authority using only actual listener evidence.
fn request_endpoint(
    request: &Request,
) -> Result<Option<(crate::db::InboundEndpointHost, u16, String, String)>, ()> {
    let Some(evidence) = request
        .extensions()
        .get::<DeliveryTransportEvidence>()
        .cloned()
    else {
        return Ok(None);
    };
    let default_port = match evidence.scheme.as_str() {
        "http" => 80,
        "https" => 443,
        _ => return Err(()),
    };
    let uri_authority = request.uri().authority().cloned();
    let host_authority = request
        .headers()
        .get(header::HOST)
        .map(|value| value.to_str().map_err(|_| ()))
        .transpose()?
        .map(|value| value.parse().map_err(|_| ()))
        .transpose()?;
    let Some(authority) = uri_authority.as_ref().or(host_authority.as_ref()) else {
        return Ok(None);
    };
    let parse_authority = |authority: &axum::http::uri::Authority| {
        if authority.as_str().contains('@') {
            return Err(());
        }
        Ok((
            canonical_endpoint_host(authority.host())?,
            authority.port_u16().unwrap_or(default_port),
        ))
    };
    let (host, port) = parse_authority(authority)?;
    if let (Some(uri), Some(header)) = (uri_authority.as_ref(), host_authority.as_ref()) {
        if parse_authority(uri)? != parse_authority(header)? {
            return Err(());
        }
    }
    if evidence.scheme == "https" && evidence.tls_identity.as_ref() != Some(&host) {
        return Err(());
    }
    Ok(Some((host, port, evidence.scheme, evidence.ingress_kind)))
}

/// Strips a route base path on a segment boundary.
fn strip_route_base_path<'a>(base_path: &str, request_path: &'a str) -> Option<&'a str> {
    let base = base_path.trim_start_matches('/');
    let path = request_path.trim_start_matches('/');
    if base.is_empty() {
        return Some(path);
    }
    match path.strip_prefix(base) {
        Some("") => Some(""),
        Some(rest) if rest.starts_with('/') => Some(&rest[1..]),
        _ => None,
    }
}

fn delivery_audience(surface: crate::db::SurfaceTarget, path: &str) -> DeliveryAudience {
    let nix = path == "nix-cache-info"
        || path.starts_with("nar/")
        || path
            .strip_suffix(".narinfo")
            .is_some_and(|hash| !hash.is_empty() && !hash.contains('/'));
    if nix {
        return DeliveryAudience::NixCache;
    }
    if matches!(surface, crate::db::SurfaceTarget::Registry(_))
        && (matches!(path, "HEAD" | "info/refs")
            || path.starts_with("objects/")
            || path.starts_with("releases/")
            || path.starts_with("channels/"))
    {
        return DeliveryAudience::Git;
    }
    DeliveryAudience::Web
}

fn is_reserved_control_path(path: &str) -> bool {
    let trimmed = path.trim_start_matches('/');
    trimmed.is_empty()
        || trimmed.split('/').any(|segment| segment == "-")
        || matches!(
            trimmed,
            "_assets"
                | "account"
                | "activate"
                | "auth"
                | "healthz"
                | "llms.txt"
                | "login"
                | "logout"
                | "metrics"
                | "robots.txt"
        )
        || trimmed.starts_with("_assets/")
        || trimmed.starts_with("account/")
        || trimmed.starts_with("activate/")
        || trimmed.starts_with("auth/")
        || trimmed.starts_with("login/")
        || trimmed.starts_with("logout/")
        || trimmed.starts_with("oauth2/")
        || trimmed.starts_with("aos.hub.v1.")
}

async fn domain_probe_handler(
    State(state): State<SharedState>,
    Query(query): Query<DomainProbeQuery>,
    request: Request,
) -> Response {
    let svc = from_state(state);
    let Some((host, port, scheme, _ingress_kind)) = request_endpoint(&request).ok().flatten()
    else {
        return StatusCode::MISDIRECTED_REQUEST.into_response();
    };
    if scheme != "https" || port != 443 {
        return StatusCode::MISDIRECTED_REQUEST.into_response();
    }
    let crate::db::InboundEndpointHost::Domain(host) = host else {
        return StatusCode::MISDIRECTED_REQUEST.into_response();
    };
    match svc
        .domain_probe_response(&host, &query.nonce, crate::clock::now_unix_secs())
        .await
    {
        Ok(body) => (
            StatusCode::OK,
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CACHE_CONTROL, "no-store"),
            ],
            body,
        )
            .into_response(),
        Err(error) => {
            tracing::warn!(
                %host,
                error = %format!("{error:#}"),
                "domain probe responder rejected request"
            );
            StatusCode::SERVICE_UNAVAILABLE.into_response()
        }
    }
}

/// Parses the configured external origin into its exact control-plane
/// `(host, port, scheme)` authority.
///
/// The configured value is deployment state, unlike `Host`, `Forwarded`, or
/// the request target. Requiring an origin (with no credentials, query,
/// fragment, or non-root path) keeps control-plane admission independent from
/// client-controlled forwarding metadata.
fn configured_control_authority(
    external_url: &str,
) -> Result<(crate::db::InboundEndpointHost, u16, String), ()> {
    let url = url::Url::parse(external_url).map_err(|_| ())?;
    if !matches!(url.scheme(), "http" | "https")
        || !url.username().is_empty()
        || url.password().is_some()
        || !matches!(url.path(), "" | "/")
        || url.query().is_some()
        || url.fragment().is_some()
    {
        return Err(());
    }
    let scheme = url.scheme().to_owned();
    let port = url
        .port_or_known_default()
        .and_then(|port| u16::try_from(port).ok())
        .ok_or(())?;
    Ok((
        canonical_endpoint_host(url.host_str().ok_or(())?)?,
        port,
        scheme,
    ))
}

async fn require_route_access(
    svc: &RpcService,
    route: &crate::db::InboundDeliveryRouteRecord,
    headers: HeaderMap,
    attestation: Option<crate::delivery_attestation::VerifiedDeliveryAttestation>,
) -> Result<(), RpcError> {
    let authorization = headers
        .get(header::AUTHORIZATION)
        .map(|value| {
            value.to_str().map(str::to_owned).map_err(|_| {
                RpcError::Unauthenticated("Authorization header is not valid ASCII".into())
            })
        })
        .transpose()?;
    let session_secret = crate::web::session::session_secret_from_headers(&headers);
    if let Some(attestation) = attestation.as_ref() {
        if !attestation_matches_route(attestation, route) {
            return Err(RpcError::PermissionDenied(
                "delivery assertion belongs to another route configuration".into(),
            ));
        }
        if !svc
            .db
            .claim_delivery_attestation_nonce(
                &route.id,
                &route.configuration_digest,
                &attestation.nonce_digest,
                attestation.expires_at,
                crate::delivery_attestation::delivery_attestation_now(),
            )
            .await
            .map_err(RpcError::internal)?
        {
            return Err(RpcError::PermissionDenied(
                "delivery assertion is stale or has already been used".into(),
            ));
        }
    }
    match route.access_policy_kind.as_str() {
        "public" => Ok(()),
        "hub_auth" => {
            if let Some(value) = authorization.as_deref() {
                svc.require_claims(Some(value)).map(|_| ())
            } else {
                let secret = session_secret.ok_or_else(|| {
                    RpcError::Unauthenticated("authentication is required".into())
                })?;
                match svc
                    .resolve_session_cached(&secret)
                    .await
                    .map_err(RpcError::internal)?
                {
                    Some(_) => Ok(()),
                    None => Err(RpcError::Unauthenticated(
                        "session is invalid or expired".into(),
                    )),
                }
            }
        }
        "private_network" => attestation
            .as_ref()
            .filter(|attestation| attested_access_matches_route(&attestation.access, route))
            .map(|_| ())
            .ok_or_else(|| {
                RpcError::PermissionDenied(
                    "private-network route assertion is missing or stale".into(),
                )
            }),
        "external_provider" => attestation
            .as_ref()
            .filter(|attestation| attested_access_matches_route(&attestation.access, route))
            .map(|_| ())
            .ok_or_else(|| {
                RpcError::PermissionDenied(
                    "external-provider route assertion is missing or stale".into(),
                )
            }),
        _ => Err(RpcError::PermissionDenied(
            "route access policy is not supported".into(),
        )),
    }
}

fn attestation_matches_route(
    attestation: &crate::delivery_attestation::VerifiedDeliveryAttestation,
    route: &crate::db::InboundDeliveryRouteRecord,
) -> bool {
    attestation.route_id == route.id
        && attestation.route_configuration_digest == route.configuration_digest
}

fn attested_access_matches_route(
    access: &DeliveryAccessEvidence,
    route: &crate::db::InboundDeliveryRouteRecord,
) -> bool {
    match route.access_policy_kind.as_str() {
        "private_network" => access.boundary.as_ref().is_some_and(|boundary| {
            route.access_boundary_id.as_deref() == Some(boundary.0.as_str())
                && route.access_boundary_revision == Some(boundary.1)
        }),
        "external_provider" => {
            access
                .external_provider
                .as_ref()
                .is_some_and(|(kind, resource, revision)| {
                    Some(kind) == route.external_provider_kind.as_ref()
                        && Some(resource) == route.external_provider_resource_id.as_ref()
                        && Some(revision) == route.external_provider_revision.as_ref()
                })
        }
        _ => false,
    }
}

/// Applies typed delivery-route dispatch to one incoming request.
///
/// The most-specific enabled route on the exact domain/IP endpoint wins.
/// Hub-proxy and Hub-redirect routes must have current healthy/degraded
/// endpoint, route, and access observations. A direct route that reaches Hub
/// is rejected with 421 Misdirected Request; it is never silently proxied.
///
/// # Errors
///
/// Returns an early 404 for a disallowed route capability, 421 for a direct
/// route, 503 for an unready Hub route, or 400 for an invalid internal rewrite
/// URI.
pub async fn rewrite_for_delivery_route(
    svc: &RpcService,
    mut request: Request,
) -> Result<Request, Response> {
    let endpoint = match request_endpoint(&request) {
        Ok(endpoint) => endpoint,
        Err(()) => return Err(StatusCode::BAD_REQUEST.into_response()),
    };
    let Some((host, port, scheme, ingress_kind)) = endpoint else {
        return Err(StatusCode::MISDIRECTED_REQUEST.into_response());
    };
    let control_authority = match configured_control_authority(&svc.external_url) {
        Ok(control) => control,
        Err(()) => return Err(StatusCode::SERVICE_UNAVAILABLE.into_response()),
    };
    let is_control_authority = control_authority == (host.clone(), port, scheme.clone());
    let Ok(routes) = svc
        .db
        .inbound_delivery_routes(&host, port, &scheme, &ingress_kind)
        .await
    else {
        return Err(StatusCode::SERVICE_UNAVAILABLE.into_response());
    };
    let host_is_delivery = if routes.is_empty() {
        match svc.db.delivery_endpoint_host_exists(&host).await {
            Ok(exists) => exists,
            Err(_) => return Err(StatusCode::SERVICE_UNAVAILABLE.into_response()),
        }
    } else {
        true
    };
    let request_path = match canonical_request_path(request.uri().path()) {
        Ok(path) => path,
        Err(()) => return Err(StatusCode::BAD_REQUEST.into_response()),
    };
    if request_path == DOMAIN_PROBE_PATH {
        return if scheme == "https" && port == 443 && host_is_delivery {
            Ok(request)
        } else {
            Err(StatusCode::MISDIRECTED_REQUEST.into_response())
        };
    }
    if is_reserved_control_path(&request_path) {
        return if is_control_authority {
            Ok(request)
        } else if host_is_delivery {
            Err(StatusCode::NOT_FOUND.into_response())
        } else {
            Err(StatusCode::MISDIRECTED_REQUEST.into_response())
        };
    }
    let Some((route, surface_path)) = routes.iter().find_map(|route| {
        strip_route_base_path(&route.base_path, &request_path).map(|path| (route, path))
    }) else {
        // Public serving is valid only after resolving an explicit delivery
        // route; no authority may fall through to a resource-slug path.
        return Err(StatusCode::MISDIRECTED_REQUEST.into_response());
    };
    if !matches!(*request.method(), Method::GET | Method::HEAD) {
        return Err((
            StatusCode::METHOD_NOT_ALLOWED,
            [(header::ALLOW, "GET, HEAD")],
        )
            .into_response());
    }
    let audience = delivery_audience(route.surface, surface_path);
    let serves = match audience {
        DeliveryAudience::Git => route.serves_git,
        DeliveryAudience::NixCache => route.serves_cache,
        DeliveryAudience::Web => route.serves_web,
    };
    if !serves {
        return Err(StatusCode::NOT_FOUND.into_response());
    }
    let access_headers = request.headers().clone();
    let attestation = request
        .extensions()
        .get::<crate::delivery_attestation::VerifiedDeliveryAttestation>()
        .cloned();
    if let Err(error) = require_route_access(svc, route, access_headers, attestation).await {
        return Err(error_response(&error));
    }
    if route.mode == "direct" {
        return Err(StatusCode::MISDIRECTED_REQUEST.into_response());
    }
    if !route.ready {
        return Err(StatusCode::SERVICE_UNAVAILABLE.into_response());
    }
    request.extensions_mut().insert(ResolvedDeliveryRoute {
        route: route.clone(),
        surface_path: surface_path.to_owned(),
        audience,
    });
    let mut rewritten = "/_aos-internal/delivery".to_owned();
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

/// Serves a route that has already passed exact transport/path/access checks.
async fn serve_resolved_delivery(
    svc: Arc<RpcService>,
    method: axum::http::Method,
    headers: HeaderMap,
    resolved: ResolvedDeliveryRoute,
) -> Response {
    let auth = auth_header(&headers);
    let session_secret = crate::web::session::session_secret_from_headers(&headers);
    let authorization = match (auth.as_deref(), session_secret.as_deref()) {
        (Some(auth), _) => ReadAuthorization::AuthorizationHeader(Some(auth)),
        (None, Some(secret)) => ReadAuthorization::SessionCookie(secret),
        (None, None) => ReadAuthorization::AuthorizationHeader(None),
    };
    if resolved.route.mode == "hub_redirect" {
        if let Err(error) = svc
            .authorize_delivery_surface_read(authorization, resolved.route.surface)
            .await
        {
            return error_response(&error);
        }
        let crate::db::SurfaceTarget::BinaryCache(cache_id) = resolved.route.surface else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        let Some(placement_id) = resolved.route.placement_id else {
            return StatusCode::SERVICE_UNAVAILABLE.into_response();
        };
        let placement = match svc.db.surface_placement(placement_id).await {
            Ok(Some(placement)) if placement.cache_id == Some(cache_id) => placement,
            Ok(None) => return StatusCode::NOT_FOUND.into_response(),
            Ok(Some(_)) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
            Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        };
        let location = match svc
            .presign_cache_read(
                &placement,
                &resolved.surface_path,
                crate::clock::now_unix_secs(),
            )
            .await
        {
            Ok(Some(location)) => location,
            Ok(None) | Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
        };
        return (
            StatusCode::TEMPORARY_REDIRECT,
            [
                (header::LOCATION, location),
                (header::CACHE_CONTROL, "private, no-store".to_owned()),
                (header::REFERRER_POLICY, "no-referrer".to_owned()),
            ],
        )
            .into_response();
    }

    if resolved.audience == DeliveryAudience::Web {
        return browse_dispatch(
            svc,
            headers,
            resolved.route.target_slug,
            resolved.surface_path,
            None,
        )
        .await;
    }
    let range = headers
        .get(header::RANGE)
        .and_then(|value| value.to_str().ok());
    match resolved.route.surface {
        crate::db::SurfaceTarget::Registry(registry_id) => {
            let registry = match svc.db.registry_by_id(registry_id).await {
                Ok(Some(registry)) => registry,
                Ok(None) => return StatusCode::NOT_FOUND.into_response(),
                Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
            };
            match svc
                .registry_serve(
                    authorization,
                    &registry,
                    &resolved.surface_path,
                    range,
                    if method == axum::http::Method::HEAD {
                        crate::image_http::ImageMethod::Head
                    } else {
                        crate::image_http::ImageMethod::Get
                    },
                )
                .await
            {
                Ok(RegistryServeOutcome::Response(response)) => response,
                Ok(RegistryServeOutcome::NotFound) => StatusCode::NOT_FOUND.into_response(),
                Err(error) => error_response(&error),
            }
        }
        crate::db::SurfaceTarget::BinaryCache(cache_id) => {
            let cache = match svc.db.binary_cache_by_id(cache_id).await {
                Ok(Some(cache)) => cache,
                Ok(None) => return StatusCode::NOT_FOUND.into_response(),
                Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
            };
            match svc
                .cache_serve(authorization, &cache, &resolved.surface_path, range)
                .await
            {
                Ok(Some(response)) => response,
                Ok(None) => StatusCode::NOT_FOUND.into_response(),
                Err(error) => error_response(&error),
            }
        }
    }
}

async fn resolved_delivery_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let method = request.method().clone();
    let Some(resolved) = request.extensions().get::<ResolvedDeliveryRoute>().cloned() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    serve_resolved_delivery(from_state(state), method, headers, resolved).await
}

/// Runs typed delivery-route rewriting before native router dispatch.
///
/// Native-only: `axum::middleware::from_fn` requires a `Send` future, which the
/// Worker's `!Send` services cannot satisfy — the Worker instead calls
/// [`rewrite_for_delivery_route`] directly from its request bridge.
#[cfg(not(target_arch = "wasm32"))]
async fn dispatch_delivery_route(
    svc: Arc<RpcService>,
    verifier: Option<Arc<crate::delivery_attestation::DeliveryAttestationVerifier>>,
    request: Request,
    next: Next,
) -> Response {
    let mut request = match apply_delivery_attestation(
        request,
        verifier.as_deref(),
        crate::delivery_attestation::delivery_attestation_now(),
    ) {
        Ok(request) => request,
        Err(response) => return response,
    };
    if request
        .extensions()
        .get::<DeliveryTransportEvidence>()
        .is_none()
    {
        request.extensions_mut().insert(DeliveryTransportEvidence {
            // The native server currently binds a plain TCP HTTP listener. An
            // HTTPS/layer-7 deployment must insert authenticated evidence at
            // its TLS/proxy adapter rather than trusting request-target text.
            scheme: "http".to_owned(),
            ingress_kind: "hub".to_owned(),
            tls_identity: None,
        });
    }
    match rewrite_for_delivery_route(&svc, request).await {
        Ok(request) => next.run(request).await,
        Err(response) => response,
    }
}

/// Wraps `router` with typed domain/IP endpoint and delivery-route dispatch.
///
/// Both shells apply this to their outermost router: the Worker over the shared
/// [`router`], the native hub over its merged router (which carries its own
/// machine facade). The middleware captures `service` directly, so it composes
/// regardless of the wrapped router's axum state type.
///
/// Native-only (see [`dispatch_delivery_route`]); the Worker bridges
/// [`rewrite_for_delivery_route`] directly.
#[cfg(not(target_arch = "wasm32"))]
#[must_use]
pub fn with_delivery_route_dispatch(
    router: Router,
    service: Arc<RpcService>,
    verifier: Option<Arc<crate::delivery_attestation::DeliveryAttestationVerifier>>,
) -> Router {
    // The middleware must run *before* routing so its URI rewrite changes which
    // route matches. `Router::layer` runs *after* routing, so instead the inner
    // router becomes the fallback of a fresh outer router carrying the
    // middleware: the rewrite lands between the outer pass (always falls through)
    // and the inner router's routing, which then matches the rewritten path.
    Router::new()
        .fallback_service(router)
        .layer(axum::middleware::from_fn(move |request, next| {
            let svc = Arc::clone(&service);
            let verifier = verifier.as_ref().map(Arc::clone);
            async move { dispatch_delivery_route(svc, verifier, request, next).await }
        }))
}

/// Builds the Worker router with browse and token exchange.
pub fn router(service: Arc<RpcService>) -> Router {
    // The Worker entry includes browse and its token exchange. Public bytes are
    // still admitted only by `with_delivery_route_dispatch`.
    build(service, true, true)
}

/// Builds the Connect-JSON router without browse pages or token exchange.
#[must_use]
pub fn rpc_router(service: Arc<RpcService>) -> Router {
    build(service, false, false)
}

/// Builds the Connect-JSON router with the shared session-aware browse surface.
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
    capabilities: [&'static str; 1],
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
    // tombstone) when one is attached, off the relational read path.
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
            capabilities: ["aos.multipart.v1"],
        })
        .into_response(),
        Err(_) => (StatusCode::INTERNAL_SERVER_ERROR, "token creation error").into_response(),
    }
}

/// Builds the shared router with optional browse and token-exchange surfaces.
///
/// `mount_browse` adds the no-JS browse routes (the hub home `/`, the `/{slug}`
/// redirect, the registry home `/{slug}/` and `/{slug}/-/`, the `/{slug}/-/…`
/// pages, and the `/{slug}/-/api/…` JSON read API). `mount_oauth` adds the
/// Worker-owned provisioning-token exchange; native mounts its hardened local
/// exchange separately.
fn build(service: Arc<RpcService>, mount_browse: bool, mount_oauth: bool) -> Router {
    // The route-dispatch middleware targets this typed-only handler. A direct
    // external request has no `ResolvedDeliveryRoute` extension and receives
    // 404, so the internal name is not an alternate public surface URL.
    let mut r = Router::new()
        .route("/_aos-internal/delivery", get(resolved_delivery_handler))
        .route(DOMAIN_PROBE_PATH, get(domain_probe_handler));
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
        "/aos.hub.v1.RegistryService/PlanCreateRegistry",
        plan_create_registry
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.RegistryService/CreateRegistry",
        apply_create_registry
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.RegistryService/PlanUpdateRegistry",
        plan_update_registry
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.RegistryService/UpdateRegistry",
        apply_update_registry
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.RegistryService/PlanDeleteRegistry",
        plan_delete_registry
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.RegistryService/DeleteRegistry",
        apply_delete_registry
    );
    // OrganizationService
    r = rpc_route!(
        r,
        "/aos.hub.v1.OrganizationService/ListOrganizations",
        list_organizations
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.OrganizationService/GetOrganization",
        get_organization
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.OrganizationService/PlanCreateOrganization",
        plan_create_organization
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.OrganizationService/CreateOrganization",
        apply_create_organization
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.OrganizationService/PlanUpdateOrganization",
        plan_update_organization
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.OrganizationService/UpdateOrganization",
        apply_update_organization
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.OrganizationService/PlanDeleteOrganization",
        plan_delete_organization
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.OrganizationService/DeleteOrganization",
        apply_delete_organization
    );
    // SigningKeyService — immutable public generations and typed usage pins.
    r = rpc_route!(
        r,
        "/aos.hub.v1.SigningKeyService/ListSigningKeys",
        list_signing_keys
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.SigningKeyService/GetSigningKey",
        get_signing_key
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.SigningKeyService/PlanEnrollSigningKey",
        plan_enroll_signing_key
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.SigningKeyService/EnrollSigningKey",
        apply_enroll_signing_key
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.SigningKeyService/PlanRotateSigningKey",
        plan_rotate_signing_key
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.SigningKeyService/RotateSigningKey",
        apply_rotate_signing_key
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.SigningKeyService/PlanRetireSigningKey",
        plan_retire_signing_key
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.SigningKeyService/RetireSigningKey",
        apply_retire_signing_key
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.SigningKeyService/PlanSetSigningKeyUsage",
        plan_set_signing_key_usage
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.SigningKeyService/SetSigningKeyUsage",
        apply_set_signing_key_usage
    );
    // RegistryMirrorService — registry-owned upstream synchronization.
    r = rpc_route!(
        r,
        "/aos.hub.v1.RegistryMirrorService/GetRegistryMirror",
        get_registry_mirror
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.RegistryMirrorService/PlanSetRegistryMirror",
        plan_set_registry_mirror
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.RegistryMirrorService/SetRegistryMirror",
        set_registry_mirror
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.RegistryMirrorService/PlanDeleteRegistryMirror",
        plan_delete_registry_mirror
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.RegistryMirrorService/DeleteRegistryMirror",
        delete_registry_mirror
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.RegistryMirrorService/PlanSyncRegistryMirror",
        plan_sync_registry_mirror
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.RegistryMirrorService/SyncRegistryMirror",
        sync_registry_mirror
    );
    // ProjectService
    r = rpc_route!(r, "/aos.hub.v1.ProjectService/ListProjects", list_projects);
    r = rpc_route!(r, "/aos.hub.v1.ProjectService/GetProject", get_project);
    r = rpc_route!(
        r,
        "/aos.hub.v1.ProjectService/PlanCreateProject",
        plan_create_project
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.ProjectService/CreateProject",
        apply_create_project
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.ProjectService/PlanDeleteProject",
        plan_delete_project
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.ProjectService/DeleteProject",
        apply_delete_project
    );
    // StorageBindingService — final topology identity/spec lifecycle.
    r = rpc_route!(
        r,
        "/aos.hub.v1.StorageBindingService/ListStorageBindings",
        list_storage_bindings_v1
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.StorageBindingService/GetStorageBinding",
        get_storage_binding_v1
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.StorageBindingService/PlanCreateStorageBinding",
        plan_create_storage_binding
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.StorageBindingService/CreateStorageBinding",
        apply_create_storage_binding
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.StorageBindingService/PlanDeleteStorageBinding",
        plan_delete_storage_binding
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.StorageBindingService/DeleteStorageBinding",
        apply_delete_storage_binding
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.StorageBindingService/PlanSetStorageBindingCredential",
        plan_set_storage_binding_credential
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.StorageBindingService/SetStorageBindingCredential",
        apply_set_storage_binding_credential
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.StorageBindingService/PlanRotateStorageBindingCredential",
        plan_rotate_storage_binding_credential
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.StorageBindingService/RotateStorageBindingCredential",
        apply_rotate_storage_binding_credential
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.StorageBindingService/PlanValidateStorageBindingCredential",
        plan_validate_storage_binding_credential
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.StorageBindingService/ValidateStorageBindingCredential",
        validate_storage_binding_credential
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.StorageBindingService/PlanGrantStorageBindingScope",
        plan_grant_storage_binding_scope
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.StorageBindingService/GrantStorageBindingScope",
        apply_grant_storage_binding_scope
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.StorageBindingService/PlanRevokeStorageBindingScope",
        plan_revoke_storage_binding_scope
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.StorageBindingService/RevokeStorageBindingScope",
        apply_revoke_storage_binding_scope
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.StorageBindingService/ListStorageBindingWriteRevisions",
        list_storage_binding_write_revisions
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.StorageBindingService/GetStorageBindingWriteRevision",
        get_storage_binding_write_revision
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.StorageBindingService/GetInstanceDefaultStorageBinding",
        get_instance_default_storage_binding
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.StorageBindingService/GetInstanceTopologyDefaults",
        get_instance_topology_defaults
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.StorageBindingService/PlanSetInstanceTopologyDefaults",
        plan_set_instance_topology_defaults
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.StorageBindingService/SetInstanceTopologyDefaults",
        apply_set_instance_topology_defaults
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.StorageBindingService/GetOrganizationTopologyDefaults",
        get_organization_topology_defaults
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.StorageBindingService/PlanSetOrganizationTopologyDefaults",
        plan_set_organization_topology_defaults
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.StorageBindingService/SetOrganizationTopologyDefaults",
        apply_set_organization_topology_defaults
    );
    // DomainService — immutable hostname identity and explicit desired/observed posture.
    r = rpc_route!(r, "/aos.hub.v1.DomainService/ListDomains", list_domains);
    r = rpc_route!(r, "/aos.hub.v1.DomainService/GetDomain", get_domain);
    r = rpc_route!(
        r,
        "/aos.hub.v1.DomainService/PlanCreateDomain",
        plan_create_domain
    );
    r = rpc_route!(r, "/aos.hub.v1.DomainService/CreateDomain", create_domain);
    r = rpc_route!(
        r,
        "/aos.hub.v1.DomainService/PlanConfigureDomainDns",
        plan_configure_domain_dns
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DomainService/ConfigureDomainDns",
        configure_domain_dns
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DomainService/PlanConfigureDomainCertificate",
        plan_configure_domain_certificate
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DomainService/ConfigureDomainCertificate",
        configure_domain_certificate
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DomainService/PlanVerifyDomain",
        plan_verify_domain
    );
    r = rpc_route!(r, "/aos.hub.v1.DomainService/VerifyDomain", verify_domain);
    r = rpc_route!(
        r,
        "/aos.hub.v1.DomainService/PlanDeleteDomain",
        plan_delete_domain
    );
    r = rpc_route!(r, "/aos.hub.v1.DomainService/DeleteDomain", delete_domain);
    // NetworkBoundaryService — immutable identity, revision, and controller views.
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkBoundaryService/ListNetworkBoundaries",
        list_network_boundaries
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkBoundaryService/GetNetworkBoundary",
        get_network_boundary
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkBoundaryService/PlanCreateNetworkBoundary",
        plan_create_network_boundary
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkBoundaryService/CreateNetworkBoundary",
        create_network_boundary
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkBoundaryService/ListNetworkBoundaryRevisions",
        list_network_boundary_revisions
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkBoundaryService/GetNetworkBoundaryRevision",
        get_network_boundary_revision
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkBoundaryService/PlanReviseNetworkBoundary",
        plan_revise_network_boundary
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkBoundaryService/ReviseNetworkBoundary",
        revise_network_boundary
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkBoundaryService/PlanActivateNetworkBoundaryRevision",
        plan_activate_network_boundary_revision
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkBoundaryService/ActivateNetworkBoundaryRevision",
        activate_network_boundary_revision
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkBoundaryService/PlanRetireNetworkBoundaryRevision",
        plan_retire_network_boundary_revision
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkBoundaryService/RetireNetworkBoundaryRevision",
        retire_network_boundary_revision
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkBoundaryService/PlanGrantNetworkBoundaryScope",
        plan_grant_network_boundary_scope
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkBoundaryService/GrantNetworkBoundaryScope",
        apply_grant_network_boundary_scope
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkBoundaryService/PlanRevokeNetworkBoundaryScope",
        plan_revoke_network_boundary_scope
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkBoundaryService/RevokeNetworkBoundaryScope",
        apply_revoke_network_boundary_scope
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkBoundaryService/PlanDeleteNetworkBoundary",
        plan_delete_network_boundary
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkBoundaryService/DeleteNetworkBoundary",
        delete_network_boundary
    );
    // DeliveryService — endpoint identity and controller-observation reads.
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/ListDeliveryEndpoints",
        list_delivery_endpoints
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/GetDeliveryEndpoint",
        get_delivery_endpoint
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/PlanCreateDeliveryEndpoint",
        plan_create_delivery_endpoint
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/CreateDeliveryEndpoint",
        apply_create_delivery_endpoint
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/ListDeliveryEndpointGenerations",
        list_delivery_endpoint_generations
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/GetDeliveryEndpointGeneration",
        get_delivery_endpoint_generation
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/PlanStageDeliveryEndpointGeneration",
        plan_stage_delivery_endpoint_generation
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/StageDeliveryEndpointGeneration",
        stage_delivery_endpoint_generation
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/PlanActivateDeliveryEndpointGeneration",
        plan_activate_delivery_endpoint_generation
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/ActivateDeliveryEndpointGeneration",
        activate_delivery_endpoint_generation
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/PlanGrantDeliveryEndpointScope",
        plan_grant_delivery_endpoint_scope
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/GrantDeliveryEndpointScope",
        apply_grant_delivery_endpoint_scope
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/PlanRevokeDeliveryEndpointScope",
        plan_revoke_delivery_endpoint_scope
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/RevokeDeliveryEndpointScope",
        apply_revoke_delivery_endpoint_scope
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/PlanDeleteDeliveryEndpoint",
        plan_delete_delivery_endpoint
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/DeleteDeliveryEndpoint",
        delete_delivery_endpoint
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/ListStorageGateways",
        list_storage_gateways
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/GetStorageGateway",
        get_storage_gateway
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/PlanCreateStorageGateway",
        plan_create_storage_gateway
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/CreateStorageGateway",
        create_storage_gateway
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/PlanUpdateStorageGateway",
        plan_update_storage_gateway
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/UpdateStorageGateway",
        update_storage_gateway
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/PlanGrantStorageGatewayScope",
        plan_grant_storage_gateway_scope
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/GrantStorageGatewayScope",
        grant_storage_gateway_scope
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/PlanRevokeStorageGatewayScope",
        plan_revoke_storage_gateway_scope
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/RevokeStorageGatewayScope",
        revoke_storage_gateway_scope
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/PreviewGatewayRoutes",
        preview_gateway_routes
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/PlanEnableStorageGateway",
        plan_enable_storage_gateway
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/EnableStorageGateway",
        enable_storage_gateway
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/PlanDisableStorageGateway",
        plan_disable_storage_gateway
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/DisableStorageGateway",
        disable_storage_gateway
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/PlanDeleteStorageGateway",
        plan_delete_storage_gateway
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/DeleteStorageGateway",
        delete_storage_gateway
    );
    // RouteService — explicit immutable route identities and plan/apply mutations.
    r = rpc_route!(r, "/aos.hub.v1.RouteService/ListRoutes", list_routes);
    r = rpc_route!(r, "/aos.hub.v1.RouteService/GetRoute", get_route);
    r = rpc_route!(
        r,
        "/aos.hub.v1.RouteService/PlanCreateRoute",
        plan_create_route
    );
    r = rpc_route!(r, "/aos.hub.v1.RouteService/CreateRoute", create_route);
    r = rpc_route!(
        r,
        "/aos.hub.v1.RouteService/PlanUpdateRoute",
        plan_update_route
    );
    r = rpc_route!(r, "/aos.hub.v1.RouteService/UpdateRoute", update_route);
    r = rpc_route!(
        r,
        "/aos.hub.v1.RouteService/PlanReplaceRoute",
        plan_replace_route
    );
    r = rpc_route!(r, "/aos.hub.v1.RouteService/ReplaceRoute", replace_route);
    r = rpc_route!(
        r,
        "/aos.hub.v1.RouteService/PlanEnableRoute",
        plan_enable_route
    );
    r = rpc_route!(r, "/aos.hub.v1.RouteService/EnableRoute", enable_route);
    r = rpc_route!(
        r,
        "/aos.hub.v1.RouteService/PlanDisableRoute",
        plan_disable_route
    );
    r = rpc_route!(r, "/aos.hub.v1.RouteService/DisableRoute", disable_route);
    r = rpc_route!(
        r,
        "/aos.hub.v1.RouteService/PlanDeleteRoute",
        plan_delete_route
    );
    r = rpc_route!(r, "/aos.hub.v1.RouteService/DeleteRoute", delete_route);
    r = rpc_route!(
        r,
        "/aos.hub.v1.RouteService/PlanSetCanonicalRoute",
        plan_set_canonical_route
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.RouteService/SetCanonicalRoute",
        set_canonical_route
    );
    r = rpc_route!(r, "/aos.hub.v1.RouteService/ExplainRoute", explain_route);
    // TopologyService — typed registry/cache placement inventory.
    r = rpc_route!(
        r,
        "/aos.hub.v1.TopologyService/GetSurfaceTopology",
        get_surface_topology
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.TopologyService/ExplainSurfaceRequest",
        explain_surface_request
    );
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
    r = rpc_route!(r, PLAN_CREATE_PLACEMENT_PATH, plan_create_placement);
    r = rpc_route!(r, CREATE_PLACEMENT_PATH, apply_create_placement);
    r = rpc_route!(r, PLAN_UPDATE_PLACEMENT_PATH, plan_update_placement);
    r = rpc_route!(r, UPDATE_PLACEMENT_PATH, apply_update_placement);
    r = rpc_route!(r, GET_WRITE_AUTHORITY_PATH, get_write_authority);
    r = rpc_route!(r, PLAN_PROMOTE_PLACEMENT_PATH, plan_promote_placement);
    r = rpc_route!(r, PROMOTE_PLACEMENT_PATH, promote_placement);
    r = rpc_route!(
        r,
        "/aos.hub.v1.TopologyService/PlanCancelPlacementPromotion",
        plan_cancel_placement_promotion
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.TopologyService/CancelPlacementPromotion",
        cancel_placement_promotion
    );
    r = rpc_route!(
        r,
        PLAN_REMOVE_WRITE_AUTHORITY_PATH,
        plan_remove_write_authority
    );
    r = rpc_route!(r, REMOVE_WRITE_AUTHORITY_PATH, remove_write_authority);
    r = rpc_route!(r, PLAN_DRAIN_PLACEMENT_PATH, plan_drain_placement);
    r = rpc_route!(r, DRAIN_PLACEMENT_PATH, drain_placement);
    r = rpc_route!(
        r,
        PLAN_CANCEL_PLACEMENT_DRAIN_PATH,
        plan_cancel_placement_drain
    );
    r = rpc_route!(r, CANCEL_PLACEMENT_DRAIN_PATH, cancel_placement_drain);
    r = rpc_route!(r, PLAN_DELETE_PLACEMENT_PATH, plan_delete_placement);
    r = rpc_route!(r, DELETE_PLACEMENT_PATH, apply_delete_placement);
    r = rpc_route!(
        r,
        "/aos.hub.v1.TopologyService/PlanScanPlacement",
        plan_scan_placement
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.TopologyService/ScanPlacement",
        scan_placement
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.TopologyService/PlanReplicatePlacement",
        plan_replicate_placement
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.TopologyService/ReplicatePlacement",
        replicate_placement
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.TopologyService/PlanRepairPlacement",
        plan_repair_placement
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.TopologyService/RepairPlacement",
        repair_placement
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.TopologyService/ListObjectPresence",
        list_object_presence
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.TopologyService/ListPlacementPolicies",
        list_placement_policies
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.TopologyService/GetPlacementPolicy",
        get_placement_policy
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.TopologyService/ListPlacementPolicyRevisions",
        list_placement_policy_revisions
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.TopologyService/GetPlacementPolicyRevision",
        get_placement_policy_revision
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.TopologyService/PlanCreatePlacementPolicy",
        plan_create_placement_policy
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.TopologyService/CreatePlacementPolicy",
        create_placement_policy
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.TopologyService/PlanRevisePlacementPolicy",
        plan_revise_placement_policy
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.TopologyService/RevisePlacementPolicy",
        revise_placement_policy
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.TopologyService/TestPlacementPolicyRevision",
        test_placement_policy_revision
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.TopologyService/ListPlacementEquivalences",
        list_placement_equivalences
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.TopologyService/PlanConfirmPlacementEquivalence",
        plan_confirm_placement_equivalence
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.TopologyService/ConfirmPlacementEquivalence",
        confirm_placement_equivalence
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.TopologyService/PlanDeletePlacementEquivalence",
        plan_delete_placement_equivalence
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.TopologyService/DeletePlacementEquivalence",
        delete_placement_equivalence
    );
    // PackageService
    r = rpc_route!(r, "/aos.hub.v1.PackageService/ListPackages", list_packages);
    r = rpc_route!(r, "/aos.hub.v1.PackageService/GetPackage", get_package);
    // ChannelService
    r = rpc_route!(r, "/aos.hub.v1.ChannelService/ListChannels", list_channels);
    r = rpc_route!(r, "/aos.hub.v1.ChannelService/GetChannel", get_channel);
    // ImageService — signed catalog discovery and immutable disk resolution.
    r = rpc_route!(r, "/aos.hub.v1.ImageService/ListImages", list_images);
    r = rpc_route!(r, "/aos.hub.v1.ImageService/GetImage", get_image);
    r = rpc_route!(r, "/aos.hub.v1.ImageService/ResolveImage", resolve_image);
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
        "/aos.hub.v1.InstanceService/PlanSetInstanceSettings",
        plan_set_instance_settings
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.InstanceService/SetInstanceSettings",
        apply_set_instance_settings
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
    // IdentityService — service-account / grant / token management (the machine API
    // behind the console's identity settings; RFC-0004 ch.14).
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/PlanCreateAutomationPrincipal",
        plan_create_automation_principal
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/CreateAutomationPrincipal",
        apply_create_automation_principal
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/GetMembership",
        get_membership
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/PlanSetMembership",
        plan_set_membership
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/SetMembership",
        apply_set_membership
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/PlanIssueRegistryToken",
        plan_issue_registry_token
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/IssueRegistryToken",
        apply_issue_registry_token
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/PlanRetireRegistryToken",
        plan_retire_registry_token
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/RetireRegistryToken",
        apply_retire_registry_token
    );
    r = rpc_route!(r, "/aos.hub.v1.IdentityService/ListTokens", list_tokens);
    // WebhookService
    r = rpc_route!(r, "/aos.hub.v1.WebhookService/ListWebhooks", list_webhooks);
    r = rpc_route!(
        r,
        "/aos.hub.v1.WebhookService/PlanCreateWebhook",
        plan_create_webhook
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.WebhookService/CreateWebhook",
        apply_create_webhook
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.WebhookService/PlanDeleteWebhook",
        plan_delete_webhook
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.WebhookService/DeleteWebhook",
        apply_delete_webhook
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
    // BinaryCacheService
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/ListBinaryCaches",
        list_binary_caches
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/GetBinaryCache",
        get_binary_cache
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/PlanCreateBinaryCache",
        plan_create_binary_cache
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/CreateBinaryCache",
        create_binary_cache
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/PlanUpdateBinaryCache",
        plan_update_binary_cache
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/UpdateBinaryCache",
        update_binary_cache
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/PlanDeleteBinaryCache",
        plan_delete_binary_cache
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/DeleteBinaryCache",
        delete_binary_cache
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/GetCacheGcPolicy",
        get_cache_gc_policy
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/PlanSetCacheGcPolicy",
        plan_set_cache_gc_policy
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/SetCacheGcPolicy",
        set_cache_gc_policy
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/PlanRunCacheGc",
        plan_run_cache_gc
    );
    r = rpc_route!(r, "/aos.hub.v1.BinaryCacheService/RunCacheGc", run_cache_gc);
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/PlanAcknowledgeCacheGcFirstSweep",
        plan_acknowledge_cache_gc_first_sweep
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/AcknowledgeCacheGcFirstSweep",
        acknowledge_cache_gc_first_sweep
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/GetCacheGcPlan",
        get_cache_gc_plan
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/GetCacheGcRun",
        get_cache_gc_run
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/ListCacheGcRuns",
        list_cache_gc_runs
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/GetCacheGcDeletionJob",
        get_cache_gc_deletion_job
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/ListCacheGcDeletionJobs",
        list_cache_gc_deletion_jobs
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/PlanRetryCacheGcDeletionJob",
        plan_retry_cache_gc_deletion_job
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/RetryCacheGcDeletionJob",
        retry_cache_gc_deletion_job
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/PlanAbandonCacheGcDeletionJob",
        plan_abandon_cache_gc_deletion_job
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/AbandonCacheGcDeletionJob",
        abandon_cache_gc_deletion_job
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/ListRootReasons",
        list_root_reasons
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/GetRetentionRoot",
        get_retention_root
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/ListRetentionRoots",
        list_retention_roots
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/PlanCreateManualRetentionRoot",
        plan_create_manual_retention_root
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/CreateManualRetentionRoot",
        create_manual_retention_root
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/PlanRenewRetentionLease",
        plan_renew_retention_lease
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/RenewRetentionLease",
        renew_retention_lease
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/PlanRevokeRetentionLease",
        plan_revoke_retention_lease
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/RevokeRetentionLease",
        revoke_retention_lease
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/PlanDeleteManualRetentionRoot",
        plan_delete_manual_retention_root
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/DeleteManualRetentionRoot",
        delete_manual_retention_root
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/PlanRefreshAllRetention",
        plan_refresh_all_retention
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/RefreshAllRetention",
        refresh_all_retention
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/PlanRunPlacementEviction",
        plan_run_placement_eviction
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/RunPlacementEviction",
        run_placement_eviction
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
        "/aos.hub.v1.BinaryCacheService/CacheClosure",
        cache_closure
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/MintCacheUploadCredentials",
        mint_cache_upload_credentials
    );
    // CacheIntegrationService — independent publication, retention, and population facts.
    r = rpc_route!(
        r,
        "/aos.hub.v1.CacheIntegrationService/ListRegistryCacheIntegrations",
        list_registry_cache_integrations
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.CacheIntegrationService/ListCacheRegistryIntegrations",
        list_cache_registry_integrations
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.CacheIntegrationService/GetCacheRegistryIntegration",
        get_cache_registry_integration
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.CacheIntegrationService/PreviewCacheIntegration",
        preview_cache_integration
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.CacheIntegrationService/GetConsumerCacheStack",
        get_consumer_cache_stack
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.CacheIntegrationService/ValidateConsumerCacheStack",
        validate_consumer_cache_stack
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.CacheIntegrationService/PlanCreateConsumerCacheChangeset",
        plan_create_consumer_cache_changeset
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.CacheIntegrationService/CreateConsumerCacheChangeset",
        create_consumer_cache_changeset
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.CacheIntegrationService/GetRetentionSubscription",
        get_retention_subscription
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.CacheIntegrationService/ListRetentionSubscriptions",
        list_retention_subscriptions
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.CacheIntegrationService/PlanSetRetentionSubscription",
        plan_set_retention_subscription
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.CacheIntegrationService/SetRetentionSubscription",
        set_retention_subscription
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.CacheIntegrationService/PlanDeleteRetentionSubscription",
        plan_delete_retention_subscription
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.CacheIntegrationService/DeleteRetentionSubscription",
        delete_retention_subscription
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.CacheIntegrationService/PlanRefreshRetentionSubscription",
        plan_refresh_retention_subscription
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.CacheIntegrationService/RefreshRetentionSubscription",
        refresh_retention_subscription
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.CacheIntegrationService/ExplainRetention",
        explain_retention
    );
    // CacheIntegrationService population and coverage
    r = rpc_route!(
        r,
        "/aos.hub.v1.CacheIntegrationService/GetPopulationTarget",
        get_population_target
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.CacheIntegrationService/ListPopulationTargets",
        list_population_targets
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.CacheIntegrationService/PlanSetPopulationTarget",
        plan_set_population_target
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.CacheIntegrationService/SetPopulationTarget",
        set_population_target
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.CacheIntegrationService/PlanDeletePopulationTarget",
        plan_delete_population_target
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.CacheIntegrationService/DeletePopulationTarget",
        delete_population_target
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.CacheIntegrationService/PlanRunPopulation",
        plan_run_population
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.CacheIntegrationService/RunPopulation",
        run_population
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.CacheIntegrationService/GetCoverage",
        get_coverage
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.CacheIntegrationService/PlanRunCoverageValidation",
        plan_run_coverage_validation
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.CacheIntegrationService/RunCoverageValidation",
        run_coverage_validation
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.CacheIntegrationService/PlanRunCoverageRepair",
        plan_run_coverage_repair
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.CacheIntegrationService/RunCoverageRepair",
        run_coverage_repair
    );
    // Controller-only observation services. Every handler independently
    // requires a service-account token and an exact lease/generation/version fence.
    r = rpc_route!(
        r,
        "/aos.hub.v1.StorageBindingControllerService/ReportStorageBindingWriteRevision",
        report_storage_binding_write_revision
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkBoundaryControllerService/CompleteNetworkBoundaryRevisionProbe",
        complete_network_boundary_revision_probe
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkBoundaryControllerService/ReportNetworkBoundaryRevision",
        report_network_boundary_revision
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryControllerService/CompleteDeliveryEndpointProbe",
        complete_delivery_endpoint_probe
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryControllerService/ReportDeliveryEndpoint",
        report_delivery_endpoint
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryControllerService/ReportStorageGateway",
        report_storage_gateway
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.RouteControllerService/CompleteRouteProbe",
        complete_route_probe
    );
    r = rpc_route!(r, REPORT_WRITE_AUTHORITY_PATH, report_write_authority);
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheUploadControllerService/ReportCacheUpload",
        report_cache_upload
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheUploadControllerService/ReportCacheNarinfos",
        report_cache_narinfos
    );

    // OperationService
    r = rpc_route!(
        r,
        "/aos.hub.v1.OperationService/GetOperation",
        get_operation
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.OperationService/ListOperations",
        list_operations
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.OperationService/WatchOperation",
        watch_operation
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.OperationService/CancelOperation",
        cancel_operation
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.OperationService/RetryOperation",
        retry_operation
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
    // The native shell mounts its rate-limited exchange separately; Worker
    // uses this shared route.
    if mount_oauth {
        r = r.route(
            "/oauth2/token",
            post(|State(state): State<SharedState>, headers: HeaderMap| {
                let svc = from_state(state);
                send_bridge(async move { oauth2_token_exchange(&svc, &headers).await })
            }),
        );
    }
    // Apply the same unary request ceiling in both runtimes.
    r.layer(axum::extract::DefaultBodyLimit::max(
        CONNECT_REQUEST_BODY_LIMIT_BYTES,
    ))
    .with_state(into_state(service))
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;

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
            PLAN_CREATE_PLACEMENT_PATH,
            "/aos.hub.v1.TopologyService/PlanCreatePlacement"
        );
        assert_eq!(
            CREATE_PLACEMENT_PATH,
            "/aos.hub.v1.TopologyService/CreatePlacement"
        );
        assert_eq!(
            PLAN_UPDATE_PLACEMENT_PATH,
            "/aos.hub.v1.TopologyService/PlanUpdatePlacement"
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
            REPORT_WRITE_AUTHORITY_PATH,
            "/aos.hub.v1.TopologyControllerService/ReportWriteAuthority"
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
            PLAN_DRAIN_PLACEMENT_PATH,
            "/aos.hub.v1.TopologyService/PlanDrainPlacement"
        );
        assert_eq!(
            DRAIN_PLACEMENT_PATH,
            "/aos.hub.v1.TopologyService/DrainPlacement"
        );
        assert_eq!(
            PLAN_CANCEL_PLACEMENT_DRAIN_PATH,
            "/aos.hub.v1.TopologyService/PlanCancelPlacementDrain"
        );
        assert_eq!(
            CANCEL_PLACEMENT_DRAIN_PATH,
            "/aos.hub.v1.TopologyService/CancelPlacementDrain"
        );
        assert_eq!(
            PLAN_DELETE_PLACEMENT_PATH,
            "/aos.hub.v1.TopologyService/PlanDeletePlacement"
        );
        assert_eq!(
            DELETE_PLACEMENT_PATH,
            "/aos.hub.v1.TopologyService/DeletePlacement"
        );
    }

    #[test]
    fn public_schema_has_no_pre_topology_binding_or_placement_contracts() {
        let schema = include_str!("../../aos-proto/src/proto/aos/hub/v1/hub.proto");
        for forbidden in [
            "message Binding {",
            "message CreateBindingRequest {",
            "message ListBindingsRequest {",
            "message CreatePlacementRequest {",
            "message UpdatePlacementRequest {",
            "message DeletePlacementRequest {",
            "message DrainPlacementRequest {",
            "message DrainPlacementResponse {",
            "message PlacementMutationPlan {",
            "rpc CreateBinding(",
            "rpc ListBindings(",
        ] {
            assert!(
                !schema.contains(forbidden),
                "legacy public contract remains in descriptor source: {forbidden}"
            );
        }
    }

    #[test]
    fn every_descriptor_procedure_is_declared_by_the_shared_router() {
        let router_source = include_str!("connect.rs");
        let missing = pb::EXPECTED_CONNECT_PATHS
            .iter()
            .copied()
            .filter(|path| !router_source.contains(&format!("\"{path}\"")))
            .collect::<Vec<_>>();
        assert!(
            missing.is_empty(),
            "Connect procedures missing from the shared native/Worker router: {missing:?}"
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

    #[test]
    fn connect_unary_headers_are_required_and_strict() {
        let mut headers = HeaderMap::new();
        headers.insert(
            header::CONTENT_TYPE,
            "application/json; charset=utf-8".parse().unwrap(),
        );
        headers.insert(CONNECT_PROTOCOL_VERSION_HEADER, "1".parse().unwrap());
        assert!(validate_connect_headers(&headers).is_ok());

        let mut missing_version = headers.clone();
        missing_version.remove(CONNECT_PROTOCOL_VERSION_HEADER);
        assert!(validate_connect_headers(&missing_version).is_err());

        let mut wrong_version = headers.clone();
        wrong_version.insert(CONNECT_PROTOCOL_VERSION_HEADER, "2".parse().unwrap());
        assert!(validate_connect_headers(&wrong_version).is_err());

        let mut duplicate_version = headers.clone();
        duplicate_version.append(CONNECT_PROTOCOL_VERSION_HEADER, "1".parse().unwrap());
        assert!(validate_connect_headers(&duplicate_version).is_err());

        let mut wrong_content_type = headers;
        wrong_content_type.insert(header::CONTENT_TYPE, "application/proto".parse().unwrap());
        assert_eq!(
            validate_connect_headers(&wrong_content_type)
                .expect_err("unsupported codec must fail")
                .status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );

        let mut compressed = wrong_content_type;
        compressed.insert(header::CONTENT_TYPE, "application/json".parse().unwrap());
        compressed.insert(header::CONTENT_ENCODING, "gzip".parse().unwrap());
        assert_eq!(
            validate_connect_headers(&compressed)
                .expect_err("unsupported compression must fail")
                .status(),
            StatusCode::NOT_IMPLEMENTED
        );
    }

    #[test]
    fn raw_delivery_path_parser_rejects_ambiguous_ascii_encodings() {
        for invalid in [
            "/a%2fb", "/a%252fb", "/a%5cb", "/a%2eb", "/a%00b", "/a%", "/a%0g", "/a\\b", "/a//b",
            "/a/../b", "/a/./b",
        ] {
            assert!(
                canonical_request_path(invalid).is_err(),
                "accepted {invalid}"
            );
        }
        assert_eq!(canonical_request_path("/caf%C3%A9").as_deref(), Ok("/café"));
        assert_eq!(canonical_request_path("/café").as_deref(), Ok("/café"));
    }

    #[test]
    fn unconfigured_delivery_assertion_is_rejected_not_ignored() {
        let request = Request::builder()
            .method("GET")
            .uri("https://cache.example/nar/abc")
            .header(
                crate::delivery_attestation::DELIVERY_ATTESTATION_HEADER,
                "client-controlled-value",
            )
            .body(axum::body::Body::empty())
            .unwrap();
        let response = apply_delivery_attestation(request, None, 100)
            .expect_err("an assertion without a configured verifier must fail closed");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn attested_access_is_bound_to_exact_route_and_revision() {
        let route = crate::db::InboundDeliveryRouteRecord {
            id: "route-1".into(),
            configuration_generation: 3,
            configuration_digest:
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa".into(),
            base_path: "/cache".into(),
            surface: crate::db::SurfaceTarget::BinaryCache(1),
            target_slug: "cache".into(),
            mode: "hub_proxy".into(),
            access_policy_kind: "private_network".into(),
            access_boundary_id: Some("boundary-1".into()),
            access_boundary_revision: Some(7),
            external_provider_kind: None,
            external_provider_resource_id: None,
            external_provider_revision: None,
            placement_id: Some(1),
            placement_policy_revision_id: None,
            serves_git: false,
            serves_cache: true,
            serves_web: false,
            ready: true,
        };
        let verified = crate::delivery_attestation::VerifiedDeliveryAttestation {
            transport: DeliveryTransportEvidence {
                scheme: "https".into(),
                ingress_kind: "layer7".into(),
                tls_identity: Some(crate::db::InboundEndpointHost::Domain(
                    "cache.example".into(),
                )),
            },
            access: DeliveryAccessEvidence {
                boundary: Some(("boundary-1".into(), 7)),
                external_provider: None,
            },
            route_id: "route-1".into(),
            route_configuration_digest: route.configuration_digest.clone(),
            nonce_digest: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb".into(),
            expires_at: 130,
        };
        assert!(attestation_matches_route(&verified, &route));
        assert!(attested_access_matches_route(&verified.access, &route));

        let mut stale = verified.clone();
        stale.access.boundary = Some(("boundary-1".into(), 6));
        assert!(!attested_access_matches_route(&stale.access, &route));
        stale.access.boundary = Some(("boundary-2".into(), 7));
        assert!(!attested_access_matches_route(&stale.access, &route));
        stale.route_configuration_digest =
            "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc".into();
        assert!(!attestation_matches_route(&stale, &route));
    }

    #[test]
    fn authority_requires_adapter_evidence_and_rejects_host_disagreement() {
        let no_evidence = Request::builder()
            .uri("https://cache.example/nix-cache-info")
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(matches!(request_endpoint(&no_evidence), Ok(None)));

        let host = crate::db::InboundEndpointHost::Domain("cache.example".into());
        let evidence = DeliveryTransportEvidence {
            scheme: "https".into(),
            ingress_kind: "hub".into(),
            tls_identity: Some(host.clone()),
        };
        let exact = Request::builder()
            .uri("https://cache.example/nix-cache-info")
            .header(header::HOST, "cache.example:443")
            .extension(evidence.clone())
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(
            request_endpoint(&exact),
            Ok(Some((host, 443, "https".into(), "hub".into())))
        );

        let mismatch = Request::builder()
            .uri("https://cache.example/nix-cache-info")
            .header(header::HOST, "other.example")
            .extension(evidence)
            .body(axum::body::Body::empty())
            .unwrap();
        assert!(request_endpoint(&mismatch).is_err());
    }

    #[test]
    fn configured_control_authority_is_an_exact_origin() {
        let expected = (
            crate::db::InboundEndpointHost::Domain("hub.example".into()),
            443,
            "https".to_string(),
        );
        assert_eq!(
            configured_control_authority("https://hub.example"),
            Ok(expected.clone())
        );
        assert_eq!(
            configured_control_authority("https://hub.example:443/"),
            Ok(expected)
        );
        assert_ne!(
            configured_control_authority("http://hub.example"),
            configured_control_authority("https://hub.example")
        );
        for invalid in [
            "https://user@hub.example",
            "https://hub.example/control",
            "https://hub.example?forwarded=evil.example",
            "https://hub.example./",
        ] {
            assert!(
                configured_control_authority(invalid).is_err(),
                "accepted {invalid}"
            );
        }
    }

    #[test]
    fn only_control_plane_paths_bypass_delivery_resolution() {
        assert!(!is_reserved_control_path(DOMAIN_PROBE_PATH));
        for path in [
            "/",
            "/healthz",
            "/metrics",
            "/oauth2/token",
            "/aos.hub.v1.RouteService/ListRoutes",
            "/-/org/acme/caches",
            "/acme/main/-/settings/delivery-routes",
            "/_assets/style.css",
            "/robots.txt",
            "/llms.txt",
        ] {
            assert!(is_reserved_control_path(path), "rejected {path}");
        }
        for serving_path in [
            "/acme/main",
            "/acme/main/",
            "/objects/aa/bb",
            "/nar/archive.nar.zst",
            "/hash.narinfo",
        ] {
            assert!(
                !is_reserved_control_path(serving_path),
                "admitted legacy serving path {serving_path}"
            );
        }
    }

    #[test]
    fn capability_classifier_separates_registry_git_nix_and_web() {
        let registry = crate::db::SurfaceTarget::Registry(1);
        assert_eq!(
            delivery_audience(registry, "objects/aa/bb"),
            DeliveryAudience::Git
        );
        assert_eq!(
            delivery_audience(registry, "abc.narinfo"),
            DeliveryAudience::NixCache
        );
        assert_eq!(
            delivery_audience(registry, "-/packages"),
            DeliveryAudience::Web
        );
        assert_eq!(
            delivery_audience(crate::db::SurfaceTarget::BinaryCache(2), "objects/aa"),
            DeliveryAudience::Web
        );
    }
}
