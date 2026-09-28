//! Distribution request framing against registries requiring an explicit body length.

#![allow(clippy::expect_used)]

use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::http::header::CONTENT_LENGTH;
use axum::http::{HeaderMap, StatusCode, Version};
use axum::routing::post;
use reqwest::Method;
use reqwest::redirect::Policy;
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
