//! Testable request-routing seam for the Cloudflare Worker bridge.
//!
//! The Worker runtime's request and response types require JavaScript, but the
//! ordering invariant between the nested console and the machine facade does
//! not: every HTTP method must be offered to the shared nested-console
//! dispatcher before the request may fall through to frontend rewriting and
//! facade routing. Keeping that step in this pure module lets native tests
//! exercise the Worker shell without fabricating Workers runtime objects.

use std::future::Future;

use axum::body::{Body, Bytes};
use axum::http::{HeaderMap, Method, Uri};
use axum::response::Response;

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
    dispatch: F,
) -> Result<NestedDispatch, axum::Error>
where
    F: FnOnce(Method, Uri, HeaderMap, Bytes) -> Fut,
    Fut: Future<Output = Option<Response>>,
{
    let (parts, body) = request.into_parts();
    let body = axum::body::to_bytes(body, usize::MAX).await?;

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

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;
    use axum::response::IntoResponse;

    use super::*;

    #[tokio::test]
    async fn unsupported_methods_reach_nested_console_before_router_fallthrough() {
        for method in [Method::PUT, Method::HEAD, Method::DELETE, Method::PATCH] {
            let request = http::Request::builder()
                .method(method.clone())
                .uri("/acme/infra/prod/cdn/-/settings/storage")
                .body(Body::empty())
                .unwrap();

            let outcome = dispatch_nested_first(request, |offered, uri, _, _| async move {
                assert_eq!(offered, method);
                assert_eq!(uri.path(), "/acme/infra/prod/cdn/-/settings/storage");
                Some(StatusCode::METHOD_NOT_ALLOWED.into_response())
            })
            .await
            .unwrap();

            match outcome {
                NestedDispatch::Handled(response) => {
                    assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
                }
                NestedDispatch::Forward(_) => panic!("console response reached facade router"),
            }
        }
    }
}
