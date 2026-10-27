//! Bounds Controller RPC materialization before entering the shared decoder.
//!
//! Public and diagnostic surfaces use the same limiter with separate fixed
//! capacities. Excess requests are rejected immediately, without decoding or
//! queuing another handler. A successful slot stays with the response body so
//! streaming calls cannot escape the bound after returning their headers.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use aos_sandbox_controller_domain::public_api_session::{
    MAXIMUM_RPC_ELEMENT_MEMORY_BYTES, MAXIMUM_RPC_MESSAGE_BYTES,
};
use axum::body::Body;
use axum::extract::{Request, State};
use axum::middleware::{Next, from_fn_with_state};
use axum::response::Response;
use http_body_util::BodyExt as _;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

/// Keeps one actual connection slot through the complete transport lifetime.
pub(super) struct LimitedConnection<Stream> {
    pub(super) stream: Stream,
    _permit: OwnedSemaphorePermit,
}

impl<Stream> LimitedConnection<Stream> {
    pub(super) fn new(stream: Stream, permit: OwnedSemaphorePermit) -> Self {
        Self {
            stream,
            _permit: permit,
        }
    }
}

impl<Stream: AsyncRead + Unpin> AsyncRead for LimitedConnection<Stream> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(context, buffer)
    }
}

impl<Stream: AsyncWrite + Unpin> AsyncWrite for LimitedConnection<Stream> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        context: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(context, bytes)
    }

    fn poll_flush(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(context)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(context)
    }
}

pub(super) fn application(router: connectrpc::Router, capacity: usize) -> axum::Router {
    let limits = connectrpc::Limits::default()
        .with_max_request_body_size(MAXIMUM_RPC_MESSAGE_BYTES)
        .with_max_message_size(MAXIMUM_RPC_MESSAGE_BYTES)
        .with_element_memory_limit(MAXIMUM_RPC_ELEMENT_MEMORY_BYTES);
    let service = router.into_axum_service().with_limits(limits);
    bounded_application(axum::Router::new().fallback_service(service), capacity)
}

fn bounded_application(application: axum::Router, capacity: usize) -> axum::Router {
    application.layer(from_fn_with_state(
        Arc::new(Semaphore::new(capacity)),
        require_capacity,
    ))
}

async fn require_capacity(
    State(capacity): State<Arc<Semaphore>>,
    request: Request,
    next: Next,
) -> Response {
    let Ok(permit) = capacity.try_acquire_owned() else {
        return connectrpc::ConnectError::resource_exhausted(
            "Controller request capacity exhausted",
        )
        .into_http_response(request.headers())
        .map(Body::new);
    };

    let response = next.run(request).await;
    response.map(|body| {
        Body::new(body.map_frame(move |frame| {
            // The closure owns the slot until the actual body is consumed or
            // dropped. Frames, including trailers, pass through unchanged.
            let _held = &permit;
            frame
        }))
    })
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicUsize, Ordering};

    use axum::body::Bytes;
    use axum::http::StatusCode;
    use tower::ServiceExt as _;

    use super::*;

    fn runtime() -> tokio::runtime::Runtime {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    fn request(body: Body) -> Request {
        Request::builder()
            .method("POST")
            .uri("/")
            .body(body)
            .unwrap()
    }

    fn echo(capacity: usize) -> axum::Router {
        let router =
            axum::Router::new().route("/", axum::routing::post(|body: Bytes| async move { body }));
        bounded_application(router, capacity)
    }

    #[test]
    fn saturated_clones_reject_before_reading_or_decoding_the_request_body() {
        runtime().block_on(async {
            let application = echo(1);
            let first = application
                .clone()
                .oneshot(request(Body::from("first")))
                .await
                .unwrap();
            assert_eq!(first.status(), StatusCode::OK);

            let reads = Arc::new(AtomicUsize::new(0));
            let observed = Arc::clone(&reads);
            let body = Body::new(Body::from("must remain unread").map_frame(move |frame| {
                observed.fetch_add(1, Ordering::SeqCst);
                frame
            }));
            let rejected = application.clone().oneshot(request(body)).await.unwrap();

            assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
            assert_eq!(reads.load(Ordering::SeqCst), 0);
            drop(first);

            let next = application
                .oneshot(request(Body::from("next")))
                .await
                .unwrap();
            assert_eq!(next.status(), StatusCode::OK);
        });
    }

    #[test]
    fn capacity_stays_with_the_response_body_until_consumed_or_cancelled() {
        runtime().block_on(async {
            let application = echo(1);
            let first = application
                .clone()
                .oneshot(request(Body::from("payload")))
                .await
                .unwrap();
            let body = first.into_body();

            let rejected = application
                .clone()
                .oneshot(request(Body::empty()))
                .await
                .unwrap();
            assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
            let collected = body.collect().await.unwrap();
            assert_eq!(collected.to_bytes(), "payload");

            let next = application
                .clone()
                .oneshot(request(Body::from("cancelled")))
                .await
                .unwrap();
            assert_eq!(next.status(), StatusCode::OK);
            drop(next);

            let last = application.oneshot(request(Body::empty())).await.unwrap();
            assert_eq!(last.status(), StatusCode::OK);
        });
    }

    #[test]
    fn saturation_preserves_the_request_protocol_error_framing() {
        runtime().block_on(async {
            let application = echo(1);
            let held = application
                .clone()
                .oneshot(request(Body::empty()))
                .await
                .unwrap();
            for content_type in [
                "application/grpc+proto",
                "application/grpc-web+proto",
                "application/connect+proto",
            ] {
                let mut request = request(Body::empty());
                request
                    .headers_mut()
                    .insert("content-type", content_type.parse().unwrap());
                let rejected = application.clone().oneshot(request).await.unwrap();
                assert_eq!(rejected.status(), StatusCode::OK);
                assert_eq!(rejected.headers()["content-type"], content_type);
                if content_type == "application/grpc+proto" {
                    assert_eq!(rejected.headers()["grpc-status"], "8");
                } else {
                    let body = rejected.into_body().collect().await.unwrap().to_bytes();
                    if content_type == "application/grpc-web+proto" {
                        assert_eq!(body[0], 0x80);
                        assert!(
                            std::str::from_utf8(&body[5..])
                                .unwrap()
                                .contains("grpc-status: 8")
                        );
                    } else {
                        assert_eq!(body[0], 0x02);
                        assert!(
                            std::str::from_utf8(&body[5..])
                                .unwrap()
                                .contains("resource_exhausted")
                        );
                    }
                }
            }
            drop(held);
        });
    }

    #[test]
    fn public_saturation_preserves_the_independent_diagnostic_pool() {
        runtime().block_on(async {
            let public = echo(1);
            let diagnostic = echo(1);
            let held = public
                .clone()
                .oneshot(request(Body::empty()))
                .await
                .unwrap();

            let rejected = public.oneshot(request(Body::empty())).await.unwrap();
            assert_eq!(rejected.status(), StatusCode::TOO_MANY_REQUESTS);
            let response = diagnostic.oneshot(request(Body::empty())).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            drop(held);
        });
    }
}
