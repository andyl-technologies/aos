//! Testable request-routing seam for the Cloudflare Worker bridge.
//!
//! The Worker runtime's request and response types require JavaScript, but the
//! ordering invariant between delivery-route rewriting, the nested console,
//! and the machine delivery surface does not. Keeping that post-conversion pipeline in
//! this pure module lets native tests exercise the production Worker ordering
//! without fabricating Workers runtime objects.

use std::future::Future;

use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Method, Uri};
use axum::response::Response;
use tower::ServiceExt;

use aos_hub_core::service::RpcService;
use aos_hub_core::web::console::{dispatch_nested, ConsoleDeps};

/// Classifies a potentially streaming machine-surface write without reading its body.
///
/// Connect RPC paths are static under `/aos.hub.v1.` and console paths contain
/// the reserved `/-/` marker. Every remaining `PUT` or `POST` may be the
/// machine delivery surface. The Worker bridge uses this structural classification to
/// preserve its request stream and let the delivery handler's 20 MiB/multipart boundary
/// own buffering, instead of imposing a different pre-router limit based on
/// query spelling or parameter order.
#[must_use]
pub(crate) fn is_streaming_machine_request(method: &Method, uri: &Uri) -> bool {
    matches!(*method, Method::PUT | Method::POST)
        && !uri.path().starts_with("/aos.hub.v1.")
        && !uri.path().contains("/-/")
}

/// The result of offering one buffered Worker request to the nested console.
pub(crate) enum NestedDispatch {
    /// The console recognized the request and produced the final response.
    Handled(Response),
    /// The console did not recognize the request; continue through the router.
    Forward(http::Request<Body>),
}

/// Offers a request to the nested console before rebuilding any fall-through.
///
/// The callback is deliberately method-agnostic: `PUT`, `HEAD`, `DELETE`, and
/// `PATCH` must reach the shared classifier just like `GET` and `POST`, because
/// a recognized console path returns `405 Method Not Allowed` rather than being
/// mistaken for a machine-facade request.
pub(crate) async fn dispatch_nested_first<F, Fut>(
    request: http::Request<Body>,
    max_body_bytes: usize,
    dispatch: F,
) -> Result<NestedDispatch, axum::Error>
where
    F: FnOnce(Method, Uri, HeaderMap, Bytes) -> Fut,
    Fut: Future<Output = Option<Response>>,
{
    let (parts, body) = request.into_parts();
    let body = axum::body::to_bytes(body, max_body_bytes).await?;

    if let Some(response) = dispatch(
        parts.method.clone(),
        parts.uri.clone(),
        parts.headers.clone(),
        body.clone(),
    )
    .await
    {
        return Ok(NestedDispatch::Handled(response));
    }

    Ok(NestedDispatch::Forward(http::Request::from_parts(
        parts,
        Body::from(body),
    )))
}

/// The result of dispatching one request after Workers-to-Axum conversion.
pub(crate) enum ConvertedDispatch {
    /// The production routing pipeline produced the final Axum response.
    Response(Response),
    /// The nested-console classifier could not buffer the bounded request.
    PayloadTooLarge(axum::Error),
}

/// Runs a converted Worker request through the production routing pipeline.
///
/// Delivery ownership is resolved first so an owned delivery host cannot fall
/// through to the control plane. Non-streaming requests then reach the shared
/// nested-console classifier before the ordinary API and facade router. This
/// function is used directly by the wasm bridge and by the native parity test.
pub(crate) async fn dispatch_converted_request(
    router: axum::Router,
    svc: &RpcService,
    console_deps: ConsoleDeps,
    request: http::Request<Body>,
) -> ConvertedDispatch {
    let request = match aos_hub_core::connect::rewrite_for_route(svc, request).await {
        Ok(request) => request,
        Err(response) => return ConvertedDispatch::Response(response),
    };

    let request = if is_streaming_machine_request(request.method(), request.uri()) {
        request
    } else {
        let nested = dispatch_nested_first(
            request,
            aos_hub_core::connect::CONNECT_REQUEST_BODY_LIMIT_BYTES,
            move |method, uri, headers, body| {
                dispatch_nested(console_deps, method, uri, headers, body)
            },
        )
        .await;
        match nested {
            Err(error) => return ConvertedDispatch::PayloadTooLarge(error),
            Ok(NestedDispatch::Handled(response)) => {
                return ConvertedDispatch::Response(response);
            }
            Ok(NestedDispatch::Forward(request)) => request,
        }
    };

    match router.oneshot(request).await {
        Ok(response) => ConvertedDispatch::Response(response),
        Err(error) => match error {},
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use aos_hub_core::fetch::SurfaceProvider;
    use aos_hub_core::lease::PublishLease;
    use aos_hub_core::reindex::Reindexer;
    use aos_hub_core::surface_write::SurfaceWriteProvider;
    use aos_hub_core::topology_probe::DatabaseTopologyProbeScheduler;
    use aos_hub_core::web::console::{
        console_router, route_manifest, ConsoleRouteMatched, RouteMethods,
    };
    use axum::http::StatusCode;
    use tower::ServiceExt as _;

    use super::*;

    fn worker_rpc_service(state: &Arc<aos_hub::server::AppState>) -> RpcService {
        let surface: Arc<dyn SurfaceProvider> = Arc::new(
            aos_hub::coreports::HubSurfaceProvider::new(
                Arc::clone(&state.db),
                state.http.clone(),
                state.image_snapshots.clone(),
            )
            .with_credentials(Arc::clone(&state.secret_versions)),
        );
        let surface_write: Arc<dyn SurfaceWriteProvider> = Arc::new(
            aos_hub::coreports::HubSurfaceWriteProvider::new(
                Arc::clone(&state.db),
                state.http.clone(),
            )
            .with_credentials(Arc::clone(&state.secret_versions)),
        );
        let reindexer: Arc<dyn Reindexer> = Arc::new(aos_hub::coreports::HubReindexer::new(
            Arc::clone(&state.db),
            state.image_snapshots.clone(),
        ));
        RpcService::new(
            Arc::clone(&state.db),
            state.auth.jwt_keys.clone(),
            state.external_url.clone(),
            Arc::clone(&state.ratelimit) as Arc<dyn aos_hub_core::ratelimit::RateLimiter>,
            surface,
            surface_write,
            Arc::clone(&state.leases) as Arc<dyn PublishLease>,
            reindexer,
            Arc::new(DatabaseTopologyProbeScheduler::new(Arc::clone(&state.db))),
            Some(Arc::clone(&state.sealer)),
        )
        .with_secret_versions(Arc::clone(&state.secret_versions))
    }

    async fn worker_console_request(
        router: axum::Router,
        svc: &RpcService,
        deps: ConsoleDeps,
        request: http::Request<Body>,
    ) -> Response {
        match dispatch_converted_request(router, svc, deps, request).await {
            ConvertedDispatch::Response(response) => response,
            ConvertedDispatch::PayloadTooLarge(error) => {
                panic!("console route exceeded the bridge body limit: {error}")
            }
        }
    }

    async fn console_contract_response(
        deps: &ConsoleDeps,
        request: http::Request<Body>,
    ) -> Response {
        let nested_deps = deps.clone();
        match dispatch_nested_first(request, 1024 * 1024, move |method, uri, headers, body| {
            let deps = nested_deps.clone();
            async move { dispatch_nested(deps, method, uri, headers, body).await }
        })
        .await
        .unwrap()
        {
            NestedDispatch::Handled(response) => response,
            NestedDispatch::Forward(request) => {
                console_router(deps.clone()).oneshot(request).await.unwrap()
            }
        }
    }

    fn converted_request(method: Method, path: &str) -> http::Request<Body> {
        let url = url::Url::parse(&format!("http://worker.test{path}")).unwrap();
        http::Request::builder()
            .method(method)
            .uri(url.as_str())
            .extension(
                aos_hub_core::connect::DeliveryTransportEvidence::from_verified_url(&url, "hub")
                    .unwrap(),
            )
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn worker_bridge_reaches_every_declared_console_route() {
        let db = Arc::new(aos_hub_core::db::Database::open_in_memory().await.unwrap());
        let state =
            Arc::new(aos_hub::server::AppState::new(db, "http://worker.test".to_string()).await);
        let deps = aos_hub::server::console_deps_for_worker_test(&state);
        let svc = worker_rpc_service(&state);
        let router = console_router(deps.clone());

        for route in route_manifest() {
            let flat = route.sample_path("missing");
            assert_worker_route(router.clone(), &svc, deps.clone(), route.methods, &flat).await;
            if route.is_registry() {
                let nested = route.sample_path("acme/infra/prod/cdn");
                assert_worker_route(router.clone(), &svc, deps.clone(), route.methods, &nested)
                    .await;
            }
        }
    }

    async fn assert_worker_route(
        router: axum::Router,
        svc: &RpcService,
        deps: ConsoleDeps,
        methods: RouteMethods,
        path: &str,
    ) {
        for method in [
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::HEAD,
            Method::OPTIONS,
            Method::TRACE,
            Method::CONNECT,
        ] {
            let declared = (method == Method::GET && methods.allows_get())
                || (method == Method::POST && methods.allows_post());
            let expected =
                console_contract_response(&deps, converted_request(method.clone(), path)).await;
            let response = worker_console_request(
                router.clone(),
                svc,
                deps.clone(),
                converted_request(method.clone(), path),
            )
            .await;
            assert!(
                response.extensions().get::<ConsoleRouteMatched>().is_some(),
                "Worker response for {method} {path} lacked the console-route sentinel"
            );
            assert_eq!(
                response.status(),
                expected.status(),
                "Worker bridge changed the console status for {method} {path}",
            );
            assert_eq!(
                response.headers().get(http::header::ALLOW),
                expected.headers().get(http::header::ALLOW),
                "Worker bridge changed the console Allow header for {method} {path}",
            );
            if declared {
                assert_ne!(
                    response.status(),
                    StatusCode::METHOD_NOT_ALLOWED,
                    "Worker rejected declared {method} for {path}"
                );
            } else {
                assert_eq!(
                    response.status(),
                    StatusCode::METHOD_NOT_ALLOWED,
                    "Worker did not recognize rejected {method} for {path}"
                );
                assert_eq!(
                    response
                        .headers()
                        .get(http::header::ALLOW)
                        .and_then(|value| value.to_str().ok()),
                    Some(methods.allow_header()),
                    "Worker route {path} returned the wrong Allow header for {method}",
                );
            }
        }
    }

    #[tokio::test]
    async fn rejects_a_body_before_nested_dispatch_can_buffer_past_its_limit() {
        let request = http::Request::builder()
            .method(Method::POST)
            .uri("/aos.hub.v1.RegistryService/GetRegistry")
            .body(Body::from(vec![0_u8; 1025]))
            .unwrap();

        let result = dispatch_nested_first(request, 1024, |_, _, _, _| async {
            panic!("oversized body reached nested dispatch")
        })
        .await;
        assert!(result.is_err());
    }

    #[test]
    fn machine_put_is_classified_without_body_inspection() {
        assert!(is_streaming_machine_request(
            &Method::PUT,
            &"/andyl/main/nar/object.nar".parse().unwrap()
        ));
        assert!(!is_streaming_machine_request(
            &Method::PUT,
            &"/andyl/main/-/settings/placements".parse().unwrap()
        ));
        assert!(!is_streaming_machine_request(
            &Method::PUT,
            &"/aos.hub.v1.RegistryService/UpdateRegistry"
                .parse()
                .unwrap()
        ));
        assert!(is_streaming_machine_request(
            &Method::POST,
            &"/andyl/main/nar/object.nar?uploadId=abc".parse().unwrap()
        ));
        assert!(is_streaming_machine_request(
            &Method::POST,
            &"/andyl/main/nar/object.nar?size=99&uploads"
                .parse()
                .unwrap()
        ));
    }
}
