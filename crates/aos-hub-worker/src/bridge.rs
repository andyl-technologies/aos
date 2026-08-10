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
//! release of that adapter tracks the `worker` version this crate pins, and
//! the conversion is small enough to own. Incoming bodies cross into Axum as
//! streams so route-specific limits apply before buffering. Responses stream
//! back to the runtime as well.
//!
//! # Flow
//!
//! ```text
//! worker::Request --to_axum--> delivery rewrite --> nested console --> API/facade router
//!                                                                           |
//! worker::Response <--to_worker---------------------------------------------+
//! ```

use axum::body::Body;
use worker::{Headers, Request, Response, Result};

/// Convert an incoming [`worker::Request`] into an [`http::Request`].
///
/// Copies the method, the path-and-query (from the parsed request URL), every
/// request header, and the streaming request body. The resulting request
/// carries an [`axum::body::Body`] so it can be fed straight to the shared
/// router.
///
/// # Errors
///
/// Returns an error if the request URL cannot be parsed, the request body
/// cannot be streamed, or the assembled [`http::Request`] is malformed (an invalid
/// method or header value).
pub async fn to_axum(mut req: Request) -> Result<http::Request<Body>> {
    let method = req.method().as_ref().to_string();

    let url = req.url()?;
    // Preserve the absolute URL until the shared delivery parser has bound the
    // request to its exact scheme/authority/port. Axum still routes by its path.
    let target = url.as_str().to_owned();
    let transport =
        aos_hub_core::connect::DeliveryTransportEvidence::from_verified_url(&url, "hub")
            .ok_or_else(|| {
                worker::Error::RustError("request URL is not an HTTP(S) origin".into())
            })?;

    // Snapshot the headers before the body read consumes `req` mutably.
    let header_pairs: Vec<(String, String)> = req.headers().into_iter().collect();

    let body = match req.stream() {
        Ok(stream) => Body::from_stream(send_wrapper::SendWrapper::new(stream)),
        // worker-rs reports an absent Fetch body as a RustError. That is the
        // ordinary representation of a bodyless GET/HEAD or empty POST, not a
        // consumed-body condition; BodyUsed and all other failures stay fatal.
        Err(worker::Error::RustError(_)) => Body::empty(),
        Err(error) => return Err(error),
    };

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

    let mut builder = http::Request::builder()
        .method(method.as_str())
        .uri(target)
        .extension(transport);
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
        .body(body)
        .map_err(|err| worker::Error::RustError(format!("building axum request: {err}")))
}

/// Convert an [`http::Response`] from the router back into a [`worker::Response`].
///
/// Reads the status, preserves the response body as a backpressured stream, and
/// copies every response header onto the Workers response.
///
/// # Errors
///
/// Returns an error if a header value is not valid UTF-8 or the streaming
/// [`worker::Response`] cannot be built. Stream failures are forwarded as body
/// errors after the response begins.
pub async fn to_worker(resp: http::Response<Body>) -> Result<Response> {
    use axum::body::HttpBody as _;
    use futures_util::TryStreamExt as _;

    let (parts, body) = resp.into_parts();

    let headers = Headers::new();
    for (name, value) in parts.headers.iter() {
        let value = value
            .to_str()
            .map_err(|err| worker::Error::RustError(format!("non-ASCII response header: {err}")))?;
        headers.append(name.as_str(), value)?;
    }

    // Preserve an actually bodyless response as the Workers runtime's native
    // empty-body variant. Representing HEAD, 304, or 412 as a readable stream
    // with no chunks can leave workerd waiting for stream completion before it
    // commits the response headers, which in turn deadlocks the next request on
    // the same Durable Object. Axum marks `Body::empty()` as end-of-stream, so
    // this branch does not buffer or otherwise affect streamed representations.
    if body.is_end_stream() {
        return Ok(Response::empty()?
            .with_status(parts.status.as_u16())
            .with_headers(headers));
    }

    // Stream the router's response body straight through to the Workers runtime
    // rather than buffering it (no `to_bytes(usize::MAX)`): a large cache NAR the
    // shared `cache_serve` streams from R2 never lands fully in the isolate's
    // memory. Each `Bytes` chunk becomes a `Vec<u8>` the runtime emits as it
    // arrives; an axum body error maps to a worker error.
    let stream = body
        .into_data_stream()
        .map_ok(|chunk| chunk.to_vec())
        .map_err(|err| worker::Error::RustError(format!("router response body: {err}")));

    Ok(Response::from_stream(stream)?
        .with_status(parts.status.as_u16())
        .with_headers(headers))
}

/// Drive one request through the shared Connect-JSON router and bridge the
/// result back to the Workers runtime.
///
/// Converts the [`worker::Request`] to an [`http::Request`], verifies delivery
/// ownership, runs it through the console/API/facade dispatch pipeline, and
/// converts the [`http::Response`] back to a [`worker::Response`].
///
/// After delivery ownership has failed closed, every non-streaming request is
/// offered to the shared nested-canonical console dispatcher
/// ([`aos_hub_core::web::console::dispatch_nested`]): the shared console routes
/// capture only a single-segment `{slug}`, so a registry whose canonical path
/// has slashes (`andyl/demo`) never matches them and would otherwise 404 at the
/// facade wildcard. When the dispatcher recognizes a nested console page it
/// returns the rendered response; otherwise the request flows on to the router
/// unchanged. Nested dispatch buffers the stream once, within the same
/// route-class limit enforced by the native shell, then reuses those bytes for
/// fall-through so the request is never read twice.
///
/// # Errors
///
/// Returns an error if either request or response conversion fails.
pub async fn dispatch(
    router: axum::Router,
    svc: &aos_hub_core::service::RpcService,
    console_deps: aos_hub_core::web::console::ConsoleDeps,
    delivery_attestation_verifier: Option<
        &aos_hub_core::delivery_attestation::DeliveryAttestationVerifier,
    >,
    req: Request,
) -> Result<Response> {
    let axum_req = to_axum(req).await?;
    let axum_req = match aos_hub_core::connect::apply_delivery_attestation(
        axum_req,
        delivery_attestation_verifier,
        aos_hub_core::delivery_attestation::delivery_attestation_now(),
    ) {
        Ok(request) => request,
        Err(response) => return to_worker(response).await,
    };

    match crate::bridge_dispatch::dispatch_converted_request(router, svc, console_deps, axum_req)
        .await
    {
        crate::bridge_dispatch::ConvertedDispatch::Response(response) => to_worker(response).await,
        crate::bridge_dispatch::ConvertedDispatch::PayloadTooLarge(error) => {
            worker::console_log!("request body rejected while buffering: {error}");
            Response::error("payload too large", 413)
        }
    }
}

/// Dispatches one live-workerd test request through the production bridge
/// conversion, delivery rewrite, and shared router.
///
/// Open-source workerd cannot provide the console's production bindings. This
/// non-default e2e seam therefore omits only console dispatch and attestation;
/// machine and Connect API requests still use their ordinary shared routes.
///
/// # Errors
///
/// Returns an error when conversion, delivery rewriting, or router dispatch
/// fails.
#[cfg(feature = "do-e2e")]
pub(crate) async fn dispatch_do_e2e(
    router: axum::Router,
    svc: &aos_hub_core::service::RpcService,
    req: Request,
) -> Result<Response> {
    use tower::ServiceExt as _;

    let axum_req = to_axum(req).await?;
    let axum_req = match aos_hub_core::connect::rewrite_for_delivery_route(svc, axum_req).await {
        Ok(request) => request,
        Err(response) => return to_worker(response).await,
    };
    let axum_resp = router
        .oneshot(axum_req)
        .await
        .map_err(|error| worker::Error::RustError(format!("router dispatch: {error}")))?;
    to_worker(axum_resp).await
}
