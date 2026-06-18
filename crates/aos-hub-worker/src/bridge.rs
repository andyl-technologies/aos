//! The hand-rolled Workers ↔ `axum` request/response bridge (wasm32-only).
//!
//! RFC-0004 Phase 5 serves the registry-hub RPC surface from the *same*
//! [`aos_hub_core::connect`] router on both deployment targets. The native
//! hub mounts that router under `axum::serve`; the Cloudflare Worker has no
//! hyper/tokio server, so it drives the router one request at a time with
//! [`tower::ServiceExt::oneshot`]. This module is the conversion layer between
//! the Workers runtime's [`worker::Request`]/[`worker::Response`] and the
//! [`http`] request/response the router speaks.
//!
//! There is deliberately no `axum-cloudflare-adapter` dependency: no published
//! release of that adapter supports the `worker` 0.4.x pin this crate uses, and
//! the conversion is small enough to own. The bridge buffers both bodies fully
//! (the registry RPC payloads are small JSON messages), so it never needs a
//! streaming body type across the boundary.
//!
//! # Flow
//!
//! ```text
//! worker::Request --to_axum--> http::Request<Body> --router.oneshot--> http::Response<Body>
//!                                                                              |
//! worker::Response <--to_worker---------------------------------------------- +
//! ```

use axum::body::Body;
use tower::ServiceExt;
use worker::{Headers, Request, Response, Result};

/// Convert an incoming [`worker::Request`] into an [`http::Request`].
///
/// Copies the method, the path-and-query (from the parsed request URL), every
/// request header, and the fully-buffered request body. The resulting request
/// carries an [`axum::body::Body`] so it can be fed straight to the shared
/// router.
///
/// # Errors
///
/// Returns an error if the request URL cannot be parsed, the request body
/// cannot be read, or the assembled [`http::Request`] is malformed (an invalid
/// method or header value).
pub async fn to_axum(mut req: Request) -> Result<http::Request<Body>> {
    let method = req.method().as_ref().to_string();

    let url = req.url()?;
    // Reconstruct the origin-form target (path + optional query) the router
    // matches on; the authority/scheme are irrelevant to route dispatch.
    let target = match url.query() {
        Some(query) => format!("{}?{query}", url.path()),
        None => url.path().to_string(),
    };

    // Snapshot the headers before the body read consumes `req` mutably.
    let header_pairs: Vec<(String, String)> = req.headers().into_iter().collect();

    let body_bytes = req.bytes().await?;

    // Resolve the trusted client IP from Cloudflare's `cf-connecting-ip` header,
    // which the edge sets to the real client address and a client cannot forge.
    // (Empty when absent — e.g. a non-edge invocation — which the shared login
    // handlers treat as a single shared rate-limit bucket rather than failing
    // open.)
    let client_ip = header_pairs
        .iter()
        .find(|(name, _)| name.eq_ignore_ascii_case("cf-connecting-ip"))
        .map(|(_, value)| value.clone())
        .unwrap_or_default();

    let mut builder = http::Request::builder().method(method.as_str()).uri(target);
    for (name, value) in &header_pairs {
        // Drop any inbound `x-aos-client-ip`: only the edge-resolved value below
        // is trusted (see the invariant on
        // `aos_hub_core::web::console::CLIENT_IP_HEADER`).
        if name.eq_ignore_ascii_case(aos_hub_core::web::console::CLIENT_IP_HEADER) {
            continue;
        }
        builder = builder.header(name, value);
    }
    // Stamp (overwrite) the runtime-neutral client-IP header the shared console's
    // pre-auth login handlers meter on. Overwrite — not append — is load-bearing:
    // a client must not be able to forge its own rate-limit bucket.
    builder = builder.header(aos_hub_core::web::console::CLIENT_IP_HEADER, &client_ip);
    builder
        .body(Body::from(body_bytes))
        .map_err(|err| worker::Error::RustError(format!("building axum request: {err}")))
}

/// Convert an [`http::Response`] from the router back into a [`worker::Response`].
///
/// Reads the status, buffers the response body in full, and copies every
/// response header onto the Workers response.
///
/// # Errors
///
/// Returns an error if the response body cannot be collected, a header name or
/// value is not valid UTF-8, or the [`worker::Response`] cannot be built.
pub async fn to_worker(resp: http::Response<Body>) -> Result<Response> {
    let (parts, body) = resp.into_parts();
    let bytes = axum::body::to_bytes(body, usize::MAX)
        .await
        .map_err(|err| worker::Error::RustError(format!("reading router response body: {err}")))?;

    let mut headers = Headers::new();
    for (name, value) in parts.headers.iter() {
        let value = value
            .to_str()
            .map_err(|err| worker::Error::RustError(format!("non-ASCII response header: {err}")))?;
        headers.set(name.as_str(), value)?;
    }

    Ok(Response::from_bytes(bytes.to_vec())?
        .with_status(parts.status.as_u16())
        .with_headers(headers))
}

/// Drive one request through the shared Connect-JSON router and bridge the
/// result back to the Workers runtime.
///
/// Converts the [`worker::Request`] to an [`http::Request`], runs it through the
/// router with [`tower::ServiceExt::oneshot`], and converts the
/// [`http::Response`] back to a [`worker::Response`].
///
/// # Errors
///
/// Returns an error if either conversion fails or the router itself errors (the
/// shared router is infallible at the `tower::Service` level, so an error here
/// is a bridge failure, surfaced as a `500` by the caller).
pub async fn dispatch(router: axum::Router, req: Request) -> Result<Response> {
    let axum_req = to_axum(req).await?;
    let axum_resp = router
        .oneshot(axum_req)
        .await
        .map_err(|err| worker::Error::RustError(format!("router dispatch: {err}")))?;
    to_worker(axum_resp).await
}
