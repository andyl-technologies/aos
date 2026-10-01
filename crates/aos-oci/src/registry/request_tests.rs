//! Distribution request framing and bounded recovery against real local HTTP faults.

#![allow(clippy::expect_used)]

use std::sync::{Arc, Mutex};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::http::header::CONTENT_LENGTH;
use axum::http::{HeaderMap, StatusCode, Version};
use axum::routing::post;
use reqwest::Method;
use reqwest::redirect::Policy;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

use super::RegistryClient;
use crate::RegistryReference;

#[tokio::test]
async fn empty_upload_start_has_explicit_length_over_http1() {
    assert_empty_upload_framing(Version::HTTP_11).await;
}

#[tokio::test]
async fn empty_upload_start_has_explicit_length_over_http2() {
    assert_empty_upload_framing(Version::HTTP_2).await;
}

#[tokio::test]
async fn bodyless_head_recovers_once_after_consumed_request_reset() {
    let server = FaultServer::start(|_| vec![Reply::Reset, Reply::status(200)]).await;
    let client = server.client();
    let scope = "repository:aos:pull";
    client
        .store_scoped_token(scope, zeroize::Zeroizing::new("fixture-token".into()))
        .expect("cached token");
    let mut headers = HeaderMap::new();
    headers.insert("x-fixture-probe", "exact-value".parse().expect("header"));
    let url = client
        .url("v2/aos/blobs/sha256:fixture?probe=1")
        .expect("URL");

    let response = tokio::time::timeout(
        Duration::from_secs(5),
        client.send(
            Method::HEAD,
            url,
            scope,
            &headers,
            None,
            &CancellationToken::new(),
        ),
    )
    .await
    .expect("request deadline")
    .expect("recovered HEAD");

    assert_eq!(response.status(), StatusCode::OK);
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0], requests[1]);
    assert!(requests[0].starts_with("HEAD /v2/aos/blobs/sha256:fixture?probe=1 HTTP/1.1\r\n"));
    assert!(requests[0].contains("authorization: Bearer fixture-token\r\n"));
    assert!(requests[0].contains("x-fixture-probe: exact-value\r\n"));
}

#[tokio::test]
async fn repeated_head_resets_stop_after_two_consumed_requests() {
    // A third response would succeed, making an extra retry observable.
    let server = FaultServer::start(|_| vec![Reply::Reset, Reply::Reset, Reply::status(200)]).await;
    let client = server.client();

    let error = tokio::time::timeout(
        Duration::from_secs(5),
        client.send(
            Method::HEAD,
            client.url("v2/aos/blobs/sha256:fixture").expect("URL"),
            "repository:aos:pull",
            &HeaderMap::new(),
            None,
            &CancellationToken::new(),
        ),
    )
    .await
    .expect("request deadline")
    .expect_err("second reset remains an error");

    assert!(error.downcast_ref::<reqwest::Error>().is_some());
    assert_eq!(server.requests().len(), 2);
}

#[tokio::test]
async fn head_transport_retry_preserves_token_across_concurrent_cache_refresh() {
    let shared_client = Arc::new(Mutex::new(None::<RegistryClient>));
    let refreshing_client = Arc::clone(&shared_client);
    let server = FaultServer::start(move |_| {
        vec![
            Reply::ResetAfter(Box::new(move || {
                refreshing_client
                    .lock()
                    .expect("shared client")
                    .as_ref()
                    .expect("client installed")
                    .store_scoped_token(
                        "repository:aos:pull",
                        zeroize::Zeroizing::new("replacement-token".into()),
                    )
                    .expect("concurrent cache refresh");
            })),
            Reply::status(200),
        ]
    })
    .await;
    let client = server.client();
    client
        .store_scoped_token(
            "repository:aos:pull",
            zeroize::Zeroizing::new("original-token".into()),
        )
        .expect("original token");
    *shared_client.lock().expect("shared client") = Some(client.clone());

    let response = tokio::time::timeout(
        Duration::from_secs(5),
        client.send(
            Method::HEAD,
            client.url("v2/aos/blobs/sha256:fixture").expect("URL"),
            "repository:aos:pull",
            &HeaderMap::new(),
            None,
            &CancellationToken::new(),
        ),
    )
    .await
    .expect("request deadline")
    .expect("recovered HEAD");

    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        client
            .token_for_scope("repository:aos:pull")
            .expect("cached token")
            .map(|token| token.to_string()),
        Some("replacement-token".into())
    );
    let requests = server.requests();
    assert_eq!(requests.len(), 2);
    assert_eq!(requests[0], requests[1]);
    assert!(requests[1].contains("authorization: Bearer original-token\r\n"));
}

#[tokio::test]
async fn reset_after_provider_effect_post_is_not_retried() {
    let server = FaultServer::start(|_| vec![Reply::Reset, Reply::status(201)]).await;
    let client = server.client();

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        client.send(
            Method::POST,
            client.url("v2/aos/blobs/uploads/").expect("URL"),
            "repository:aos:pull,push",
            &HeaderMap::new(),
            Some(Bytes::from_static(b"provider-effect")),
            &CancellationToken::new(),
        ),
    )
    .await
    .expect("request deadline");

    assert!(result.is_err());
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].starts_with("POST /v2/aos/blobs/uploads/ HTTP/1.1\r\n"));
    assert!(requests[0].ends_with("\r\n\r\nprovider-effect"));
}

#[tokio::test]
async fn head_with_a_request_body_is_not_retried() {
    let server = FaultServer::start(|_| vec![Reply::Reset, Reply::status(200)]).await;
    let client = server.client();

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        client.send(
            Method::HEAD,
            client.url("v2/aos/blobs/sha256:fixture").expect("URL"),
            "repository:aos:pull",
            &HeaderMap::new(),
            Some(Bytes::from_static(b"request-body")),
            &CancellationToken::new(),
        ),
    )
    .await
    .expect("request deadline");

    assert!(result.is_err());
    let requests = server.requests();
    assert_eq!(requests.len(), 1);
    assert!(requests[0].ends_with("\r\n\r\nrequest-body"));
}

#[tokio::test]
async fn cancelled_head_dispatches_no_request() {
    let server = FaultServer::start(|_| vec![Reply::status(200)]).await;
    let client = server.client();
    let cancellation = CancellationToken::new();
    cancellation.cancel();

    let result = client
        .send(
            Method::HEAD,
            client.url("v2/aos/blobs/sha256:fixture").expect("URL"),
            "repository:aos:pull",
            &HeaderMap::new(),
            None,
            &cancellation,
        )
        .await;

    let error = result.expect_err("cancelled before dispatch");
    assert_eq!(error.to_string(), "OCI transfer cancelled");
    assert!(server.requests().is_empty());
}

#[tokio::test]
async fn head_cancelled_while_waiting_for_response_is_not_retried() {
    let (consumed, observed) = tokio::sync::oneshot::channel();
    let server = FaultServer::start(|_| vec![Reply::Hold(consumed)]).await;
    let client = server.client();
    let cancellation = CancellationToken::new();
    let request_cancellation = cancellation.clone();
    let request = tokio::spawn(async move {
        client
            .send(
                Method::HEAD,
                client.url("v2/aos/blobs/sha256:fixture").expect("URL"),
                "repository:aos:pull",
                &HeaderMap::new(),
                None,
                &request_cancellation,
            )
            .await
    });
    tokio::time::timeout(Duration::from_secs(5), observed)
        .await
        .expect("consumed request deadline")
        .expect("request consumed");

    cancellation.cancel();
    let result = tokio::time::timeout(Duration::from_secs(5), request)
        .await
        .expect("cancellation deadline")
        .expect("request task");

    let error = result.expect_err("cancelled while awaiting response");
    assert_eq!(error.to_string(), "OCI transfer cancelled");
    assert_eq!(server.requests().len(), 1);
}

#[tokio::test]
async fn head_transport_retry_budget_survives_authentication_exchange() {
    let server = FaultServer::start(|origin| vec![
        Reply::Reset,
        Reply::Http {
            status: 401,
            headers: format!("WWW-Authenticate: Bearer realm=\"{origin}token\",service=\"fixture\",scope=\"repository:aos:pull\"\r\n"),
            body: String::new(),
        },
        Reply::Http {
            status: 200,
            headers: "Content-Type: application/json\r\n".into(),
            body: r#"{"token":"fixture-authorized-token"}"#.into(),
        },
        Reply::Reset,
        Reply::status(200),
    ]).await;
    let client = server.client();

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        client.send(
            Method::HEAD,
            client.url("v2/aos/blobs/sha256:fixture").expect("URL"),
            "repository:aos:pull",
            &HeaderMap::new(),
            None,
            &CancellationToken::new(),
        ),
    )
    .await
    .expect("request deadline");

    assert!(result.is_err());
    let requests = server.requests();
    assert_eq!(requests.len(), 4);
    assert!(requests[2].starts_with("GET /token?"));
    assert!(requests[3].starts_with("HEAD /v2/"));
    assert!(requests[3].contains("authorization: Bearer fixture-authorized-token\r\n"));
}

#[tokio::test]
async fn head_status_response_is_not_retried() {
    let server = FaultServer::start(|_| vec![Reply::status(503), Reply::status(200)]).await;
    let client = server.client();

    let response = client
        .send(
            Method::HEAD,
            client.url("v2/aos/blobs/sha256:fixture").expect("URL"),
            "repository:aos:pull",
            &HeaderMap::new(),
            None,
            &CancellationToken::new(),
        )
        .await
        .expect("status response");

    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(server.requests().len(), 1);
}

enum Reply {
    Reset,
    ResetAfter(Box<dyn FnOnce() + Send>),
    Hold(tokio::sync::oneshot::Sender<()>),
    Http {
        status: u16,
        headers: String,
        body: String,
    },
}

impl Reply {
    fn status(status: u16) -> Self {
        Self::Http {
            status,
            headers: String::new(),
            body: String::new(),
        }
    }
}

struct FaultServer {
    origin: String,
    requests: Arc<Mutex<Vec<String>>>,
    task: tokio::task::JoinHandle<()>,
}

impl FaultServer {
    async fn start(replies: impl FnOnce(&str) -> Vec<Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let origin = format!(
            "http://{}/",
            listener.local_addr().expect("listener address")
        );
        let replies = replies(&origin);
        let requests = Arc::new(Mutex::new(Vec::new()));
        let observed = Arc::clone(&requests);
        let task = tokio::spawn(async move {
            for reply in replies {
                let (mut stream, _) = listener.accept().await.expect("accepted connection");
                let mut request = Vec::new();
                let mut buffer = [0; 4096];
                loop {
                    let count = stream.read(&mut buffer).await.expect("request bytes");
                    assert_ne!(count, 0, "client closed before complete request");
                    request.extend_from_slice(&buffer[..count]);
                    assert!(request.len() < 65536, "bounded fixture request");
                    if let Some(end) = request.windows(4).position(|bytes| bytes == b"\r\n\r\n") {
                        let headers = std::str::from_utf8(&request[..end]).expect("HTTP headers");
                        let length = headers
                            .lines()
                            .find_map(|line| {
                                let (name, value) = line.split_once(':')?;
                                name.eq_ignore_ascii_case("content-length")
                                    .then(|| value.trim().parse::<usize>().expect("body length"))
                            })
                            .unwrap_or(0);
                        if request.len() >= end + 4 + length {
                            break;
                        }
                    }
                }
                observed
                    .lock()
                    .expect("request observations")
                    .push(String::from_utf8(request).expect("fixture request"));

                match reply {
                    Reply::Reset => {
                        // Reset only after consuming the whole request, so the
                        // failure cannot be mistaken for an undispatched send.
                        #[allow(deprecated)]
                        stream
                            .set_linger(Some(Duration::ZERO))
                            .expect("reset linger");
                    }
                    Reply::ResetAfter(before) => {
                        before();
                        #[allow(deprecated)]
                        stream
                            .set_linger(Some(Duration::ZERO))
                            .expect("reset linger");
                    }
                    Reply::Hold(consumed) => {
                        consumed.send(()).expect("consumed request observer");
                        std::future::pending::<()>().await;
                    }
                    Reply::Http {
                        status,
                        headers,
                        body,
                    } => {
                        let response = format!(
                            "HTTP/1.1 {status} Fixture\r\nContent-Length: {}\r\nConnection: close\r\n{headers}\r\n{body}",
                            body.len()
                        );
                        stream
                            .write_all(response.as_bytes())
                            .await
                            .expect("response bytes");
                    }
                }
            }
        });
        Self {
            origin,
            requests,
            task,
        }
    }

    fn client(&self) -> RegistryClient {
        let authority = self
            .origin
            .strip_prefix("http://")
            .expect("HTTP origin")
            .trim_end_matches('/');
        let reference =
            RegistryReference::parse(&format!("{authority}/aos:latest")).expect("reference");
        let mut client = RegistryClient::new(&reference, Some(&self.origin), None).expect("client");
        Arc::get_mut(&mut client.inner)
            .expect("unshared client")
            .http = reqwest::Client::builder()
            .http1_only()
            .redirect(Policy::none())
            .build()
            .expect("HTTP transport");
        client
    }

    fn requests(&self) -> Vec<String> {
        self.requests.lock().expect("request observations").clone()
    }
}

impl Drop for FaultServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn assert_empty_upload_framing(version: Version) {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("listener address");
    let registry = Router::new().route(
        "/v2/aos/blobs/uploads/",
        post(|headers: HeaderMap, body: Bytes| async move {
            // Artifact Registry rejects an unframed empty upload with HTTP 411.
            if headers
                .get(CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                != Some("0")
            {
                return StatusCode::LENGTH_REQUIRED;
            }
            if !body.is_empty() {
                return StatusCode::BAD_REQUEST;
            }

            StatusCode::ACCEPTED
        }),
    );
    let server = tokio::spawn(async move {
        axum::serve(listener, registry)
            .await
            .expect("registry server");
    });

    let reference =
        RegistryReference::parse(&format!("{address}/aos:latest")).expect("loopback reference");
    let origin = format!("http://{address}/");
    let mut client = RegistryClient::new(&reference, Some(&origin), None).expect("registry client");
    let transport = reqwest::Client::builder().redirect(Policy::none());
    let transport = if version == Version::HTTP_2 {
        transport.http2_prior_knowledge()
    } else {
        transport.http1_only()
    };
    Arc::get_mut(&mut client.inner)
        .expect("unshared client")
        .http = transport.build().expect("HTTP transport");

    let response = tokio::time::timeout(
        Duration::from_secs(5),
        client.send(
            Method::POST,
            client.url("v2/aos/blobs/uploads/").expect("upload URL"),
            "repository:aos:pull,push",
            &HeaderMap::new(),
            Some(Bytes::new()),
            &CancellationToken::new(),
        ),
    )
    .await;
    server.abort();

    let response = response.expect("request deadline").expect("upload request");
    assert_eq!(response.version(), version);
    assert_eq!(response.status(), StatusCode::ACCEPTED);
}
