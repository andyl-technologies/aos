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

use aos_proto_types::{CONNECT_PROTOCOL_VERSION, CONNECT_PROTOCOL_VERSION_HEADER};
use axum::body::Bytes;
use axum::extract::{Path, Query, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode, Uri};
#[cfg(not(target_arch = "wasm32"))]
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post, put};
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
    if versions.next().is_some() || version.as_bytes() != CONNECT_PROTOCOL_VERSION.as_bytes() {
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
        Ok(resp) => (
            [
                (header::CACHE_CONTROL, "no-store"),
                (header::PRAGMA, "no-cache"),
                (header::REFERRER_POLICY, "no-referrer"),
            ],
            Json(resp),
        )
            .into_response(),
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
        Rendered::ImmutableJson { body, etag } => (
            [
                (header::CONTENT_TYPE, "application/json"),
                (header::CACHE_CONTROL, "public, max-age=31536000, immutable"),
                (header::ETAG, &format!("\"{etag}\"")),
            ],
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
    let api_rest = rest
        .strip_prefix("api/v1/")
        .or_else(|| rest.strip_prefix("api/"));
    let rendered = match api_rest {
        Some(api) => match api {
            "registry" => browse::api_registry(&svc, &slug).await,
            "packages" => browse::api_packages(&svc, &slug).await,
            "docs/search" => browse::api_documentation_search(&svc, &slug, &q).await,
            "docs/schema" => browse::api_documentation_schema(&svc, &slug).await,
            "channels" => browse::api_channels(&svc, &slug).await,
            "releases" => browse::api_releases(&svc, &slug).await,
            other => {
                if let Some(digest) = other
                    .strip_prefix("documentation/")
                    .filter(|digest| !digest.is_empty() && !digest.contains('/'))
                {
                    browse::api_documentation_artifact(&svc, &slug, digest).await
                } else if let Some(name) = other
                    .strip_prefix("packages/")
                    .filter(|name| !name.is_empty())
                {
                    if let Some((package, suffix)) = name.split_once('/') {
                        match suffix {
                            "documentation" => {
                                browse::api_package_documentation(&svc, &slug, package, &q).await
                            }
                            "options" => {
                                browse::api_package_options(&svc, &slug, package, &q).await
                            }
                            "compare" => {
                                browse::api_documentation_compare(&svc, &slug, package, &q).await
                            }
                            option if option.starts_with("options/") => {
                                browse::api_package_option(
                                    &svc,
                                    &slug,
                                    package,
                                    option.trim_start_matches("options/"),
                                    &q,
                                )
                                .await
                            }
                            _ => Rendered::NotFound,
                        }
                    } else {
                        browse::api_package(&svc, &slug, name).await
                    }
                } else if let Some(selection) = documentation_selection(other, "docs/") {
                    browse::api_documentation(&svc, &slug, selection.0, selection.1, selection.2)
                        .await
                } else {
                    Rendered::NotFound
                }
            }
        },
        None => match rest.as_str() {
            "" => browse::registry_home(&svc, &headers, &slug).await,
            "packages" => browse::packages(&svc, &headers, &slug, &q).await,
            "docs" => browse::documentation_search(&svc, &headers, &slug, &q).await,
            "images" => browse::images(&svc, &headers, &slug, &q).await,
            "channels" => browse::channels(&svc, &headers, &slug, &q).await,
            "releases" => browse::releases(&svc, &headers, &slug, &q).await,
            "health" => browse::health(&svc, &headers, &slug).await,
            other => {
                if let Some(name) = other.strip_prefix("packages/").filter(|n| !n.is_empty()) {
                    browse::package(&svc, &headers, &slug, name, &q).await
                } else if let Some(selection) = documentation_selection(other, "docs/") {
                    browse::documentation(
                        &svc,
                        &headers,
                        &slug,
                        selection.0,
                        selection.1,
                        selection.2,
                    )
                    .await
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

fn documentation_selection<'a>(path: &'a str, prefix: &str) -> Option<(&'a str, &'a str, &'a str)> {
    let mut segments = path.strip_prefix(prefix)?.split('/');
    let package = segments.next().filter(|segment| !segment.is_empty())?;
    let version = segments.next().filter(|segment| !segment.is_empty())?;
    let platform = segments.next().filter(|segment| !segment.is_empty())?;
    segments
        .next()
        .is_none()
        .then_some((package, version, platform))
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
    /// Exact verified private-network policy.
    pub boundary: Option<(String, i64)>,
    /// Exact verified external provider `(kind, resource, revision)`.
    pub external_provider: Option<(String, String, String)>,
}

/// Capability selected by the shared path classifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DeliveryAudience {
    /// Registry Git protocol, immutable releases, and signed image objects.
    Git,
    /// Nix binary-cache protocol.
    NixCache,
    /// Human-readable Web surface.
    Web,
}

/// Typed route resolution carried to the internal delivery handler.
#[derive(Debug, Clone)]
pub struct ResolvedRoute {
    /// Exact immutable route snapshot selected for this request.
    pub route: crate::db::InboundRouteRecord,
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
            || path.starts_with("channels/")
            || path.starts_with("images/"))
    {
        return DeliveryAudience::Git;
    }
    DeliveryAudience::Web
}

fn is_reserved_control_path(path: &str) -> bool {
    let trimmed = path.trim_start_matches('/');
    trimmed.is_empty()
        || (trimmed.split('/').any(|segment| segment == "-")
            && public_browse_delivery_path(trimmed).is_none())
        || registry_document_path(trimmed).is_some()
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

/// Returns the browse-relative path for a public, read-only `/-/` namespace.
fn public_browse_delivery_path(path: &str) -> Option<&str> {
    let (slug, rest) = path.trim_start_matches('/').split_once("/-/")?;
    if slug.is_empty() {
        return None;
    }
    let root = rest.split('/').next().unwrap_or_default();
    matches!(
        root,
        "" | "api"
            | "channels"
            | "closure"
            | "docs"
            | "health"
            | "images"
            | "objects"
            | "packages"
            | "releases"
    )
    .then_some(rest)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RegistryDocument {
    Robots,
    Llms,
}

/// Splits a registry-scoped crawler document from an arbitrarily nested slug.
fn registry_document_path(path: &str) -> Option<(&str, RegistryDocument)> {
    let path = path.trim_start_matches('/');
    for (suffix, document) in [
        ("/robots.txt", RegistryDocument::Robots),
        ("/llms.txt", RegistryDocument::Llms),
    ] {
        if let Some(slug) = path
            .strip_suffix(suffix)
            .filter(|slug| slug.contains('/') && !slug.ends_with('/'))
        {
            return Some((slug, document));
        }
    }
    None
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
    route: &crate::db::InboundRouteRecord,
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
    route: &crate::db::InboundRouteRecord,
) -> bool {
    attestation.route_id == route.id
        && attestation.route_configuration_digest == route.configuration_digest
}

fn attested_access_matches_route(
    access: &DeliveryAccessEvidence,
    route: &crate::db::InboundRouteRecord,
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
pub async fn rewrite_for_route(
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
        .inbound_routes(&host, port, &scheme, &ingress_kind)
        .await
    else {
        return Err(StatusCode::SERVICE_UNAVAILABLE.into_response());
    };
    let host_is_delivery = if routes.is_empty() {
        match svc.db.endpoint_host_exists(&host).await {
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
        // The exact control authority may continue into its RPC, console, and
        // browse router. That router has no resource-slug byte fallback, so an
        // unmatched machine path becomes an ordinary 404. Every non-control
        // authority still requires an explicit route.
        return if is_control_authority {
            Ok(request)
        } else {
            Err(StatusCode::MISDIRECTED_REQUEST.into_response())
        };
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
    // Browser reads apply the registry visibility matrix in `browse_dispatch`:
    // hidden registries deliberately look absent instead of issuing an
    // authentication challenge. Keep transport-attested route boundaries here,
    // while allowing public and hub-auth Web routes to reach that finer-grained
    // registry authorization layer.
    let browse_namespace = surface_path == "-" || surface_path.starts_with("-/");
    let browse_authorizes_registry = audience == DeliveryAudience::Web
        && browse_namespace
        && matches!(route.access_policy_kind.as_str(), "public" | "hub_auth");
    if !browse_authorizes_registry {
        if let Err(error) = require_route_access(svc, route, access_headers, attestation).await {
            return Err(error_response(&error));
        }
    }
    if route.mode == "direct" {
        return Err(StatusCode::MISDIRECTED_REQUEST.into_response());
    }
    if !route.ready {
        return Err(StatusCode::SERVICE_UNAVAILABLE.into_response());
    }
    request.extensions_mut().insert(ResolvedRoute {
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
    resolved: ResolvedRoute,
    query: Option<String>,
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
        let browse_path = resolved
            .surface_path
            .strip_prefix("-/")
            .or_else(|| (resolved.surface_path == "-").then_some(""))
            .unwrap_or(&resolved.surface_path);
        return browse_dispatch(
            svc,
            headers,
            resolved.route.target_slug,
            browse_path.to_owned(),
            query,
        )
        .await;
    }
    match resolved.route.surface {
        crate::db::SurfaceTarget::Registry(registry_id) => {
            let registry = match svc.db.registry_by_id(registry_id).await {
                Ok(Some(registry)) => registry,
                Ok(None) => return StatusCode::NOT_FOUND.into_response(),
                Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
            };
            let now = match crate::delivery_http::HttpTimestamp::from_unix_seconds(
                crate::clock::now_unix_secs(),
            ) {
                Ok(now) => now,
                Err(_) => return StatusCode::SERVICE_UNAVAILABLE.into_response(),
            };
            let image_request = crate::image_http::ImageHttpRequest {
                method: if method == axum::http::Method::HEAD {
                    crate::delivery_http::DeliveryMethod::Head
                } else {
                    crate::delivery_http::DeliveryMethod::Get
                },
                range: headers.get(header::RANGE).map(HeaderValue::as_bytes),
                if_match: headers.get(header::IF_MATCH).map(HeaderValue::as_bytes),
                if_unmodified_since: headers
                    .get(header::IF_UNMODIFIED_SINCE)
                    .map(HeaderValue::as_bytes),
                if_none_match: headers
                    .get(header::IF_NONE_MATCH)
                    .map(HeaderValue::as_bytes),
                if_modified_since: headers
                    .get(header::IF_MODIFIED_SINCE)
                    .map(HeaderValue::as_bytes),
                if_range: headers.get(header::IF_RANGE).map(HeaderValue::as_bytes),
                now,
            };
            match svc
                .registry_serve(
                    authorization,
                    &registry,
                    &resolved.surface_path,
                    image_request,
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
                .cache_serve(
                    authorization,
                    &cache,
                    &resolved.surface_path,
                    headers
                        .get(header::RANGE)
                        .and_then(|value| value.to_str().ok()),
                )
                .await
            {
                Ok(Some(response)) => response,
                Ok(None) => StatusCode::NOT_FOUND.into_response(),
                Err(error) => error_response(&error),
            }
        }
    }
}

/// Serves immutable signed-image bytes through the Hub control origin.
///
/// Private image resolutions use this same-origin path so browsers can present
/// their host-only session cookie and CLI clients can present the bearer they
/// used for discovery. Public resolutions remain free to select a CDN-backed
/// route advertisement.
async fn serve_control_image(
    svc: Arc<RpcService>,
    method: Method,
    headers: HeaderMap,
    registry_id: i64,
    path: String,
) -> Response {
    if !path.starts_with("images/") {
        return private_control_response(StatusCode::NOT_FOUND.into_response());
    }
    let registry = match svc.db.registry_by_id(registry_id).await {
        Ok(Some(registry)) => registry,
        Ok(None) => return private_control_response(StatusCode::NOT_FOUND.into_response()),
        Err(_) => {
            return private_control_response(StatusCode::SERVICE_UNAVAILABLE.into_response());
        }
    };
    let private = registry.visibility != "public";
    let now =
        match crate::delivery_http::HttpTimestamp::from_unix_seconds(crate::clock::now_unix_secs())
        {
            Ok(now) => now,
            Err(_) => {
                let response = StatusCode::SERVICE_UNAVAILABLE.into_response();
                return if private {
                    private_control_response(response)
                } else {
                    response
                };
            }
        };
    let auth_header = auth_header(&headers);
    let session_secret = crate::web::session::session_secret_from_headers(&headers);
    let authorization = match (auth_header.as_deref(), session_secret.as_deref()) {
        (Some(auth), _) => ReadAuthorization::AuthorizationHeader(Some(auth)),
        (None, Some(secret)) => ReadAuthorization::SessionCookie(secret),
        (None, None) => ReadAuthorization::AuthorizationHeader(None),
    };
    let request = crate::image_http::ImageHttpRequest {
        method: if method == Method::HEAD {
            crate::delivery_http::DeliveryMethod::Head
        } else {
            crate::delivery_http::DeliveryMethod::Get
        },
        range: headers.get(header::RANGE).map(HeaderValue::as_bytes),
        if_match: headers.get(header::IF_MATCH).map(HeaderValue::as_bytes),
        if_unmodified_since: headers
            .get(header::IF_UNMODIFIED_SINCE)
            .map(HeaderValue::as_bytes),
        if_none_match: headers
            .get(header::IF_NONE_MATCH)
            .map(HeaderValue::as_bytes),
        if_modified_since: headers
            .get(header::IF_MODIFIED_SINCE)
            .map(HeaderValue::as_bytes),
        if_range: headers.get(header::IF_RANGE).map(HeaderValue::as_bytes),
        now,
    };
    let response = match svc
        .registry_serve(authorization, &registry, &path, request)
        .await
    {
        Ok(RegistryServeOutcome::Response(response)) => response,
        Ok(RegistryServeOutcome::NotFound) => StatusCode::NOT_FOUND.into_response(),
        Err(error) => error_response(&error),
    };
    if private {
        private_control_response(response)
    } else {
        response
    }
}

fn private_control_response(mut response: Response) -> Response {
    response.headers_mut().insert(
        header::CACHE_CONTROL,
        HeaderValue::from_static("private, no-store"),
    );
    response.headers_mut().insert(
        header::VARY,
        HeaderValue::from_static("Authorization, Cookie"),
    );
    response
}

async fn resolved_delivery_handler(
    State(state): State<SharedState>,
    headers: HeaderMap,
    request: Request,
) -> Response {
    let method = request.method().clone();
    let Some(resolved) = request.extensions().get::<ResolvedRoute>().cloned() else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let query = request.uri().query().map(str::to_owned);
    serve_resolved_delivery(from_state(state), method, headers, resolved, query).await
}

/// Runs typed delivery-route rewriting before native router dispatch.
///
/// Native-only: `axum::middleware::from_fn` requires a `Send` future, which the
/// Worker's `!Send` services cannot satisfy — the Worker instead calls
/// [`rewrite_for_route`] directly from its request bridge.
#[cfg(not(target_arch = "wasm32"))]
async fn dispatch_route(
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
    match rewrite_for_route(&svc, request).await {
        Ok(request) => next.run(request).await,
        Err(response) => response,
    }
}

/// Wraps `router` with typed domain/IP endpoint and delivery-route dispatch.
///
/// Both shells apply this to their outermost router: the Worker over the shared
/// [`router`], the native hub over its merged router (which carries its own
/// typed delivery handler). The middleware captures `service` directly, so it composes
/// regardless of the wrapped router's axum state type.
///
/// Native-only (see [`dispatch_route`]); the Worker bridges
/// [`rewrite_for_route`] directly.
#[cfg(not(target_arch = "wasm32"))]
#[must_use]
pub fn with_route_dispatch(
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
            async move { dispatch_route(svc, verifier, request, next).await }
        }))
}

/// Builds the Worker router with browse pages.
pub fn router(service: Arc<RpcService>) -> Router {
    // The shared console router owns OAuth on both runtimes. Public bytes are
    // still admitted only by `with_route_dispatch`.
    build(service, true)
}

/// Builds the Connect-JSON router without browse pages.
#[must_use]
pub fn rpc_router(service: Arc<RpcService>) -> Router {
    build(service, false)
}

/// Builds the Connect-JSON router with the shared session-aware browse surface.
#[must_use]
pub fn rpc_browse_router(service: Arc<RpcService>) -> Router {
    build(service, true)
}

/// Builds the shared router with optional browse and token-exchange surfaces.
///
/// `mount_browse` adds the no-JS browse routes (the hub home `/`, the `/{slug}`
/// redirect, the registry home `/{slug}/` and `/{slug}/-/`, the `/{slug}/-/…`
/// pages, and the `/{slug}/-/api/…` JSON read API). The shared console router
/// mounts OAuth independently of this machine-plane router.
fn build(service: Arc<RpcService>, mount_browse: bool) -> Router {
    // The route-dispatch middleware targets this typed-only handler. A direct
    // external request has no `ResolvedRoute` extension and receives
    // 404, so the internal name is not an alternate public surface URL.
    let mut r = Router::new()
        .route(
            "/_aos-internal/delivery",
            get(
                |state: State<SharedState>, headers: HeaderMap, request: Request| {
                    send_bridge(resolved_delivery_handler(state, headers, request))
                },
            ),
        )
        .route(
            DOMAIN_PROBE_PATH,
            get(
                |state: State<SharedState>, query: Query<DomainProbeQuery>, request: Request| {
                    send_bridge(domain_probe_handler(state, query, request))
                },
            ),
        );
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
        "/aos.hub.v1.SigningKeyService/GetSigningKeyUsage",
        get_signing_key_usage
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
    // BindingService — final topology identity/spec lifecycle.
    r = rpc_route!(
        r,
        "/aos.hub.v1.BindingService/ListBindings",
        list_bindings_v1
    );
    r = rpc_route!(r, "/aos.hub.v1.BindingService/GetBinding", get_binding_v1);
    r = rpc_route!(
        r,
        "/aos.hub.v1.BindingService/PlanCreateBinding",
        plan_create_binding
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BindingService/CreateBinding",
        apply_create_binding
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BindingService/PlanDeleteBinding",
        plan_delete_binding
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BindingService/DeleteBinding",
        apply_delete_binding
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BindingService/PlanSetBindingCredential",
        plan_set_binding_credential
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BindingService/SetBindingCredential",
        apply_set_binding_credential
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BindingService/PlanRotateBindingCredential",
        plan_rotate_binding_credential
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BindingService/RotateBindingCredential",
        apply_rotate_binding_credential
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BindingService/PlanValidateBindingCredential",
        plan_validate_binding_credential
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BindingService/ValidateBindingCredential",
        validate_binding_credential
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BindingService/PlanGrantBindingScope",
        plan_grant_binding_scope
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BindingService/GrantBindingScope",
        apply_grant_binding_scope
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BindingService/PlanRevokeBindingScope",
        plan_revoke_binding_scope
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BindingService/RevokeBindingScope",
        apply_revoke_binding_scope
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BindingService/ListBindingWriteRevisions",
        list_binding_write_revisions
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BindingService/GetBindingWriteRevision",
        get_binding_write_revision
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BindingService/GetInstanceTopologyDefaults",
        get_instance_topology_defaults
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BindingService/PlanSetInstanceTopologyDefaults",
        plan_set_instance_topology_defaults
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BindingService/SetInstanceTopologyDefaults",
        apply_set_instance_topology_defaults
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BindingService/GetOrganizationTopologyDefaults",
        get_organization_topology_defaults
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BindingService/PlanSetOrganizationTopologyDefaults",
        plan_set_organization_topology_defaults
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BindingService/SetOrganizationTopologyDefaults",
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
    // NetworkPolicyService — immutable identity, revision, and controller views.
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkPolicyService/ListNetworkPolicies",
        list_network_policies
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkPolicyService/GetNetworkPolicy",
        get_network_policy
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkPolicyService/PlanCreateNetworkPolicy",
        plan_create_network_policy
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkPolicyService/CreateNetworkPolicy",
        create_network_policy
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkPolicyService/ListNetworkPolicyRevisions",
        list_network_policy_revisions
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkPolicyService/GetNetworkPolicyRevision",
        get_network_policy_revision
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkPolicyService/PlanReviseNetworkPolicy",
        plan_revise_network_policy
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkPolicyService/ReviseNetworkPolicy",
        revise_network_policy
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkPolicyService/PlanActivateNetworkPolicyRevision",
        plan_activate_network_policy_revision
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkPolicyService/ActivateNetworkPolicyRevision",
        activate_network_policy_revision
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkPolicyService/PlanRetireNetworkPolicyRevision",
        plan_retire_network_policy_revision
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkPolicyService/RetireNetworkPolicyRevision",
        retire_network_policy_revision
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkPolicyService/PlanGrantNetworkPolicyScope",
        plan_grant_network_policy_scope
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkPolicyService/GrantNetworkPolicyScope",
        apply_grant_network_policy_scope
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkPolicyService/PlanRevokeNetworkPolicyScope",
        plan_revoke_network_policy_scope
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkPolicyService/RevokeNetworkPolicyScope",
        apply_revoke_network_policy_scope
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkPolicyService/PlanDeleteNetworkPolicy",
        plan_delete_network_policy
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkPolicyService/DeleteNetworkPolicy",
        delete_network_policy
    );
    // DeliveryService — endpoint identity and controller-observation reads.
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/ListEndpoints",
        list_endpoints
    );
    r = rpc_route!(r, "/aos.hub.v1.DeliveryService/GetEndpoint", get_endpoint);
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/PlanCreateEndpoint",
        plan_create_endpoint
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/CreateEndpoint",
        apply_create_endpoint
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/ListEndpointGenerations",
        list_endpoint_generations
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/GetEndpointGeneration",
        get_endpoint_generation
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/PlanStageEndpointGeneration",
        plan_stage_endpoint_generation
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/StageEndpointGeneration",
        stage_endpoint_generation
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/PlanActivateEndpointGeneration",
        plan_activate_endpoint_generation
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/ActivateEndpointGeneration",
        activate_endpoint_generation
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/PlanGrantEndpointScope",
        plan_grant_endpoint_scope
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/GrantEndpointScope",
        apply_grant_endpoint_scope
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/PlanRevokeEndpointScope",
        plan_revoke_endpoint_scope
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/RevokeEndpointScope",
        apply_revoke_endpoint_scope
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/PlanDeleteEndpoint",
        plan_delete_endpoint
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/DeleteEndpoint",
        delete_endpoint
    );
    r = rpc_route!(r, "/aos.hub.v1.DeliveryService/ListGateways", list_gateways);
    r = rpc_route!(r, "/aos.hub.v1.DeliveryService/GetGateway", get_gateway);
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/PlanCreateGateway",
        plan_create_gateway
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/CreateGateway",
        create_gateway
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/PlanUpdateGateway",
        plan_update_gateway
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/UpdateGateway",
        update_gateway
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/PlanGrantGatewayScope",
        plan_grant_gateway_scope
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/GrantGatewayScope",
        grant_gateway_scope
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/PlanRevokeGatewayScope",
        plan_revoke_gateway_scope
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/RevokeGatewayScope",
        revoke_gateway_scope
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/PreviewGatewayRoutes",
        preview_gateway_routes
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/PlanEnableGateway",
        plan_enable_gateway
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/EnableGateway",
        enable_gateway
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/PlanDisableGateway",
        plan_disable_gateway
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/DisableGateway",
        disable_gateway
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/PlanDeleteGateway",
        plan_delete_gateway
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryService/DeleteGateway",
        delete_gateway
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
        "/aos.hub.v1.RouteService/PlanSetRouteAdvertisement",
        plan_set_route_advertisement
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.RouteService/SetRouteAdvertisement",
        set_route_advertisement
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
    // DocumentationService
    r = rpc_route!(
        r,
        "/aos.hub.v1.DocumentationService/GetPackageDocumentation",
        get_package_documentation
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DocumentationService/SearchPackageDocumentation",
        search_package_documentation
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DocumentationService/ListPackageOptions",
        list_package_options
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DocumentationService/GetPackageOption",
        get_package_option
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DocumentationService/ComparePackageDocumentation",
        compare_package_documentation
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DocumentationService/GetDocumentationArtifact",
        get_documentation_artifact
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DocumentationService/GetPackageDocumentationSchema",
        get_package_documentation_schema
    );
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
    r = rpc_route!(r, "/aos.hub.v1.IdentityService/WhoAmI", who_am_i);
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/ListServiceAccounts",
        list_service_accounts
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/GetServiceAccount",
        get_service_account
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/PlanCreateServiceAccount",
        plan_create_service_account
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/CreateServiceAccount",
        apply_create_service_account
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/PlanUpdateServiceAccount",
        plan_update_service_account
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/UpdateServiceAccount",
        apply_update_service_account
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/PlanDeleteServiceAccount",
        plan_delete_service_account
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/DeleteServiceAccount",
        apply_delete_service_account
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
        "/aos.hub.v1.IdentityService/ListInvitations",
        list_invitations
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/GetInvitation",
        get_invitation
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/PlanCreateInvitation",
        plan_create_invitation
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/CreateInvitation",
        apply_create_invitation
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/PlanCancelInvitation",
        plan_cancel_invitation
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/CancelInvitation",
        apply_cancel_invitation
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/AcceptInvitation",
        accept_invitation
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/GetIdentityProvider",
        get_identity_provider
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/PlanSetIdentityProvider",
        plan_set_identity_provider
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/SetIdentityProvider",
        apply_set_identity_provider
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/PlanRemoveIdentityProvider",
        plan_remove_identity_provider
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/RemoveIdentityProvider",
        apply_remove_identity_provider
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/ListOrganizationDomains",
        list_organization_domains
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/GetOrganizationDomain",
        get_organization_domain
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/PlanClaimOrganizationDomain",
        plan_claim_organization_domain
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/ClaimOrganizationDomain",
        apply_claim_organization_domain
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/PlanVerifyOrganizationDomain",
        plan_verify_organization_domain
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/VerifyOrganizationDomain",
        apply_verify_organization_domain
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/PlanReleaseOrganizationDomain",
        plan_release_organization_domain
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/ReleaseOrganizationDomain",
        apply_release_organization_domain
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/PlanIssueAccessToken",
        plan_issue_access_token
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/IssueAccessToken",
        apply_issue_access_token
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/PlanRetireAccessToken",
        plan_retire_access_token
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/RetireAccessToken",
        apply_retire_access_token
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.IdentityService/ListAccessTokens",
        list_access_tokens
    );
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
        "/aos.hub.v1.PublishService/BeginRegistryPublication",
        begin_registry_publication
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.PublishService/BeginRegistryPublicationManifest",
        begin_registry_publication_manifest
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.PublishService/AppendRegistryPublicationManifest",
        append_registry_publication_manifest
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.PublishService/SealRegistryPublicationManifest",
        seal_registry_publication_manifest
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.PublishService/BeginRegistryPublicationMultipartUpload",
        begin_registry_publication_multipart_upload
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.PublishService/CompleteRegistryPublicationMultipartUpload",
        complete_registry_publication_multipart_upload
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.PublishService/AbortRegistryPublicationMultipartUpload",
        abort_registry_publication_multipart_upload
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.PublishService/ListRegistryPublications",
        list_registry_publications
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.PublishService/GetRegistryPublication",
        get_registry_publication
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.PublishService/CommitRegistryPublication",
        commit_registry_publication
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.PublishService/AbortRegistryPublication",
        abort_registry_publication
    );
    r = r.route(
        "/aos.hub.v1.PublishService/UploadObject/{publication_id}/{object_id}",
        put(
            |State(state): State<SharedState>,
             Path((publication_id, object_id)): Path<(String, i64)>,
             headers: HeaderMap,
             request: Request| {
                let svc = from_state(state);
                send_bridge(async move {
                    match svc
                        .upload_registry_publication_object(
                            auth_header(&headers).as_deref(),
                            &publication_id,
                            object_id,
                            request.into_body(),
                        )
                        .await
                    {
                        Ok(()) => StatusCode::CREATED.into_response(),
                        Err(error) => error_response(&error),
                    }
                })
            },
        ),
    );
    r = r.route(
        "/aos.hub.v1.PublishService/UploadPart/{upload_id}/{part_number}",
        put(
            |State(state): State<SharedState>,
             Path((upload_id, part_number)): Path<(String, u32)>,
             headers: HeaderMap,
             body: Bytes| {
                let svc = from_state(state);
                send_bridge(async move {
                    match svc
                        .upload_registry_publication_multipart_part(
                            auth_header(&headers).as_deref(),
                            &upload_id,
                            part_number,
                            &body,
                        )
                        .await
                    {
                        Ok(part) => Json(part).into_response(),
                        Err(error) => error_response(&error),
                    }
                })
            },
        ),
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
        "/aos.hub.v1.BinaryCacheService/CreateCacheObjectUploads",
        create_cache_object_uploads
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/RegisterCacheNarinfos",
        register_cache_narinfos
    );
    r = r.route(
        "/aos.hub.v1.BinaryCacheService/UploadObject/{cache_id}/{ticket_id}/{encoded_path}",
        put(
            |State(state): State<SharedState>,
             Path((cache_id, ticket_id, encoded_path)): Path<(String, String, String)>,
             headers: HeaderMap,
             body: Bytes| {
                let svc = from_state(state);
                send_bridge(async move {
                    match svc
                        .upload_cache_object(
                            auth_header(&headers).as_deref(),
                            &cache_id,
                            &ticket_id,
                            &encoded_path,
                            &body,
                        )
                        .await
                    {
                        Ok(()) => StatusCode::CREATED.into_response(),
                        Err(error) => error_response(&error),
                    }
                })
            },
        ),
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/BeginCacheMultipartUpload",
        begin_cache_multipart_upload
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/CompleteCacheMultipartUpload",
        complete_cache_multipart_upload
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.BinaryCacheService/AbortCacheMultipartUpload",
        abort_cache_multipart_upload
    );
    r = r.route(
        "/aos.hub.v1.BinaryCacheService/UploadPart/{upload_id}/{part_number}",
        put(
            |State(state): State<SharedState>,
             Path((upload_id, part_number)): Path<(String, u32)>,
             headers: HeaderMap,
             body: Bytes| {
                let svc = from_state(state);
                send_bridge(async move {
                    match svc
                        .upload_cache_multipart_part(
                            auth_header(&headers).as_deref(),
                            &upload_id,
                            part_number,
                            &body,
                        )
                        .await
                    {
                        Ok(part) => Json(part).into_response(),
                        Err(error) => error_response(&error),
                    }
                })
            },
        ),
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
        "/aos.hub.v1.BindingControllerService/ReportBindingWriteRevision",
        report_binding_write_revision
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkPolicyControllerService/CompleteNetworkPolicyRevisionProbe",
        complete_network_policy_revision_probe
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.NetworkPolicyControllerService/ReportNetworkPolicyRevision",
        report_network_policy_revision
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryControllerService/CompleteEndpointProbe",
        complete_endpoint_probe
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryControllerService/ReportEndpoint",
        report_endpoint
    );
    r = rpc_route!(
        r,
        "/aos.hub.v1.DeliveryControllerService/ReportGateway",
        report_gateway
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
    r = r.route(
        "/-/images/{registry_id}/{*path}",
        get(
            |State(state): State<SharedState>,
             method: Method,
             headers: HeaderMap,
             Path((registry_id, path)): Path<(i64, String)>| {
                let service = from_state(state);
                send_bridge(serve_control_image(
                    service,
                    method,
                    headers,
                    registry_id,
                    path,
                ))
            },
        )
        .head(
            |State(state): State<SharedState>,
             method: Method,
             headers: HeaderMap,
             Path((registry_id, path)): Path<(i64, String)>| {
                let service = from_state(state);
                send_bridge(serve_control_image(
                    service,
                    method,
                    headers,
                    registry_id,
                    path,
                ))
            },
        ),
    );
    // Browse and static control-plane routes are mounted only when requested.
    // Machine bytes are never selected by a slug wildcard; the outer typed
    // delivery dispatcher resolves an exact endpoint and route before
    // rewriting to the private delivery handler.
    if mount_browse {
        // First-party static assets (`/_assets/*`) the browse pages + console
        // link. Served from the shared router so the Worker exposes them too
        // (otherwise its CSS/JS/fonts 404).
        use crate::web::assets;
        r = r
            .route("/_assets/style.css", get(assets::stylesheet))
            .route("/_assets/app.js", get(assets::app_js))
            .route("/_assets/{asset}", get(assets::console_asset))
            .route(
                "/_assets/jetbrains-mono-regular.woff2",
                get(assets::font_regular),
            )
            .route("/_assets/jetbrains-mono-bold.woff2", get(assets::font_bold))
            .route("/_assets/OFL.txt", get(assets::font_license));
        // Crawler-control and LLM-summary documents, served from the shared
        // router so both shells expose identical output. The per-registry forms gate on
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
        // the `/{slug}/-/api/…` JSON read API. The reserved `/-/` namespace is
        // control-plane-only and cannot be shadowed by a route. The
        // bare `/{slug}/-/` registry-home route is registered
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
        r = r.route(
            "/{org}/{registry}",
            get(
                |State(state): State<SharedState>,
                 Path((org, registry)): Path<(String, String)>| {
                    let svc = from_state(state);
                    send_bridge(async move {
                        let slug = format!("{org}/{registry}");
                        match svc.db.registry_by_slug(&slug).await {
                            Ok(Some(_)) => browse_response(Rendered::Redirect(format!("/{slug}/"))),
                            Ok(None) => StatusCode::NOT_FOUND.into_response(),
                            Err(_) => StatusCode::SERVICE_UNAVAILABLE.into_response(),
                        }
                    })
                },
            ),
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
        let organization_registry_home =
            |State(state): State<SharedState>,
             headers: HeaderMap,
             Path((org, registry)): Path<(String, String)>,
             uri: axum::http::Uri| {
                let svc = from_state(state);
                send_bridge(browse_dispatch(
                    svc,
                    headers,
                    format!("{org}/{registry}"),
                    String::new(),
                    uri.query().map(str::to_owned),
                ))
            };
        r = r.route("/{org}/{registry}/", get(organization_registry_home));
        r = r.route(
            &format!("/{{org}}/{{registry}}/{BROWSE_MARKER}/"),
            get(organization_registry_home),
        );
        r = r.route(
            &format!("/{{org}}/{{registry}}/{BROWSE_MARKER}/{{*rest}}"),
            get(
                |State(state): State<SharedState>,
                 headers: HeaderMap,
                 Path((org, registry, rest)): Path<(String, String, String)>,
                 uri: axum::http::Uri| {
                    let svc = from_state(state);
                    send_bridge(browse_dispatch(
                        svc,
                        headers,
                        format!("{org}/{registry}"),
                        rest,
                        uri.query().map(str::to_owned),
                    ))
                },
            ),
        );
        // Project-nested registry slugs have arbitrary depth. Axum wildcard
        // routes overlap the explicit one- and two-segment browse routes, so
        // unmatched GETs are decoded here after those more-specific routes
        // have had first refusal. Delivery middleware still handles machine
        // paths before routing; this fallback owns only nested registry homes
        // and the reserved `/-/` browse namespace.
        r = r.fallback(
            |State(state): State<SharedState>,
             method: Method,
             headers: HeaderMap,
             uri: axum::http::Uri| {
                let svc = from_state(state);
                send_bridge(async move {
                    if method != Method::GET {
                        return StatusCode::NOT_FOUND.into_response();
                    }
                    let nested = uri.path().trim_start_matches('/');
                    if let Some((slug, document)) = registry_document_path(nested) {
                        return match document {
                            RegistryDocument::Robots => match svc.serve_registry_robots(slug).await
                            {
                                Ok(Some(body)) => text_plain_response(body),
                                Ok(None) => StatusCode::NOT_FOUND.into_response(),
                                Err(err) => error_response(&err),
                            },
                            RegistryDocument::Llms => match svc.serve_registry_llms(slug).await {
                                Ok(Some(body)) => text_plain_response(body),
                                Ok(None) => StatusCode::NOT_FOUND.into_response(),
                                Err(err) => error_response(&err),
                            },
                        };
                    }
                    let marker = format!("/{BROWSE_MARKER}/");
                    if let Some((slug, rest)) = nested.split_once(&marker) {
                        if slug.is_empty() || !slug.contains('/') {
                            return StatusCode::NOT_FOUND.into_response();
                        }
                        return browse_dispatch(
                            svc,
                            headers,
                            slug.to_string(),
                            rest.to_string(),
                            uri.query().map(str::to_owned),
                        )
                        .await;
                    }
                    let Some(slug) = nested.strip_suffix('/').filter(|slug| slug.contains('/'))
                    else {
                        return StatusCode::NOT_FOUND.into_response();
                    };
                    browse_dispatch(
                        svc,
                        headers,
                        slug.to_string(),
                        String::new(),
                        uri.query().map(str::to_owned),
                    )
                    .await
                })
            },
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
    use aos_proto_types as pb;

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
    fn public_schema_has_no_legacy_storage_binding_or_placement_contracts() {
        let schema = include_str!("../../aos-proto/src/proto/aos/hub/v1/hub.proto");
        for forbidden in [
            "message StorageBinding {",
            "message CreateStorageBindingRequest {",
            "message ListStorageBindingsRequest {",
            "message CreatePlacementRequest {",
            "message UpdatePlacementRequest {",
            "message DeletePlacementRequest {",
            "message DrainPlacementRequest {",
            "message DrainPlacementResponse {",
            "message PlacementMutationPlan {",
            "rpc CreateStorageBinding(",
            "rpc ListStorageBindings(",
        ] {
            let remains = if forbidden.starts_with("message ") {
                schema.lines().any(|line| line.trim() == forbidden)
            } else {
                schema.contains(forbidden)
            };
            assert!(
                !remains,
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
    fn private_control_responses_are_never_shared_cached() {
        let response = private_control_response(StatusCode::UNAUTHORIZED.into_response());
        assert_eq!(
            response.headers().get(header::CACHE_CONTROL),
            Some(&HeaderValue::from_static("private, no-store"))
        );
        assert_eq!(
            response.headers().get(header::VARY),
            Some(&HeaderValue::from_static("Authorization, Cookie"))
        );
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
        let route = crate::db::InboundRouteRecord {
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
            "/acme/main/-/settings/routes",
            "/_assets/style.css",
            "/robots.txt",
            "/llms.txt",
            "/acme/main/robots.txt",
            "/acme/main/llms.txt",
            "/acme/project/main/llms.txt",
        ] {
            assert!(is_reserved_control_path(path), "rejected {path}");
        }
        for serving_path in [
            "/acme/main",
            "/acme/main/",
            "/acme/main/-/docs",
            "/acme/main/-/docs/nginx/1.30.4/x86_64-linux",
            "/acme/main/-/api/v1/packages/nginx/documentation",
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
    fn delivery_browse_paths_admit_reads_but_not_management() {
        assert_eq!(
            public_browse_delivery_path("/acme/main/-/docs"),
            Some("docs")
        );
        assert_eq!(
            public_browse_delivery_path("/acme/project/main/-/api/v1/packages"),
            Some("api/v1/packages")
        );
        assert_eq!(
            public_browse_delivery_path("/acme/main/-/settings/routes"),
            None
        );
    }

    #[test]
    fn registry_documents_preserve_nested_slugs() {
        assert_eq!(
            registry_document_path("/acme/main/robots.txt"),
            Some(("acme/main", RegistryDocument::Robots))
        );
        assert_eq!(
            registry_document_path("/acme/project/main/llms.txt"),
            Some(("acme/project/main", RegistryDocument::Llms))
        );
        assert_eq!(registry_document_path("/llms.txt"), None);
        assert_eq!(registry_document_path("/acme/llms.txt"), None);
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
