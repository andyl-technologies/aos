//! Tests for conditional PutObject header mapping and precondition results.
//!
//! The wire-level tests point a real SDK client at a one-shot local HTTP
//! responder, so they cover exactly what S3 would receive and how its
//! answers are mapped, without provider credentials or external network access.

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;

use super::*;
use crate::protocol::conditional::PRECONDITION_FAILED;

/// Builds an SDK client with static credentials, no retries, and a
/// path-style `endpoint`.
fn test_client(endpoint: &str) -> aws_sdk_s3::Client {
    let credentials =
        aws_sdk_s3::config::Credentials::new("test-access", "test-secret", None, None, "test");
    // This fixture serves plain loopback HTTP; loading machine TLS roots would
    // add an unrelated environment requirement before any request is sent.
    let http_client = aws_smithy_http_client::Builder::new().build_http();
    let config = aws_sdk_s3::Config::builder()
        .behavior_version(aws_sdk_s3::config::BehaviorVersion::latest())
        .region(aws_sdk_s3::config::Region::new("us-east-1"))
        .credentials_provider(credentials)
        .http_client(http_client)
        .endpoint_url(endpoint)
        .force_path_style(true)
        .retry_config(aws_sdk_s3::config::retry::RetryConfig::disabled())
        .build();
    aws_sdk_s3::Client::from_conf(config)
}

fn headers(pairs: &[(&str, &str)]) -> Vec<(String, String)> {
    pairs
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
}

/// Accepts one request, answers it with `response`, and yields the
/// lowercased request head.
async fn respond_once(response: String) -> (String, JoinHandle<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let endpoint = format!("http://{}", listener.local_addr().unwrap());

    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let mut request = Vec::new();
        let mut buffer = [0_u8; 4096];

        let head_end = loop {
            let count = stream.read(&mut buffer).await.unwrap();
            assert_ne!(count, 0, "client closed before sending a request head");
            request.extend_from_slice(&buffer[..count]);
            if let Some(index) = request.windows(4).position(|w| w == b"\r\n\r\n") {
                break index + 4;
            }
        };
        let head = String::from_utf8_lossy(&request[..head_end]).to_ascii_lowercase();

        let body_length: usize = head
            .lines()
            .find_map(|line| line.strip_prefix("content-length:"))
            .map(|value| value.trim().parse().unwrap())
            .unwrap_or(0);
        while request.len() < head_end + body_length {
            let count = stream.read(&mut buffer).await.unwrap();
            if count == 0 {
                break;
            }
            request.extend_from_slice(&buffer[..count]);
        }

        stream.write_all(response.as_bytes()).await.unwrap();
        stream.shutdown().await.unwrap();
        head
    });

    (endpoint, server)
}

fn http_response(status: &str, extra_headers: &str, body: &str) -> String {
    format!(
        "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n{extra_headers}\r\n{body}",
        body.len()
    )
}

const PRECONDITION_FAILED_BODY: &str = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
<Error><Code>PreconditionFailed</Code><Message>At least one of the pre-conditions you specified did not hold</Message></Error>";

async fn send(
    endpoint: &str,
    request_headers: &[(String, String)],
    conditional: bool,
) -> Result<TransferResult> {
    let client = test_client(endpoint);
    let put = SinglePut {
        client: &client,
        bucket: "bucket",
        key: "channels/edge/generation",
        headers: request_headers,
        conditional,
        target: "test endpoint",
    };
    put.send(b"record".to_vec()).await
}

#[test]
fn put_headers_map_preconditions_onto_the_builder() {
    let client = test_client("http://127.0.0.1:9");
    let request_headers = headers(&[
        ("Content-Type", "application/json"),
        ("If-Match", "\"etag-1\""),
    ]);
    let absent_headers = headers(&[("if-none-match", "*")]);

    let matching = apply_put_object_headers(client.put_object(), &request_headers);
    let absent = apply_put_object_headers(client.put_object(), &absent_headers);

    assert_eq!(matching.get_if_match().as_deref(), Some("\"etag-1\""));
    assert_eq!(matching.get_if_none_match().as_deref(), None);
    assert_eq!(
        matching.get_content_type().as_deref(),
        Some("application/json")
    );
    assert_eq!(absent.get_if_none_match().as_deref(), Some("*"));
    assert_eq!(absent.get_if_match().as_deref(), None);
}

#[tokio::test]
async fn conditional_put_sends_if_none_match_and_returns_the_etag() {
    let (endpoint, server) =
        respond_once(http_response("200 OK", "ETag: \"etag-2\"\r\n", "")).await;
    let request_headers = headers(&[("If-None-Match", "*")]);

    let result = send(&endpoint, &request_headers, true).await.unwrap();
    let head = server.await.unwrap();

    assert!(head.contains("\r\nif-none-match: *\r\n"), "{head}");
    assert_eq!(result.status, 200);
    assert_eq!(result.header("ETag"), Some("\"etag-2\""));
}

#[tokio::test]
async fn conditional_put_maps_412_to_a_precondition_failed_result() {
    let (endpoint, server) = respond_once(http_response(
        "412 Precondition Failed",
        "Content-Type: application/xml\r\n",
        PRECONDITION_FAILED_BODY,
    ))
    .await;
    let request_headers = headers(&[("If-Match", "\"stale\"")]);

    let result = send(&endpoint, &request_headers, true).await.unwrap();
    let head = server.await.unwrap();

    assert!(head.contains("\r\nif-match: \"stale\"\r\n"), "{head}");
    assert_eq!(result.status, PRECONDITION_FAILED);
    assert_eq!(result.header("ETag"), None);
}

#[tokio::test]
async fn unconditional_put_keeps_reporting_412_as_an_error() {
    let (endpoint, server) = respond_once(http_response(
        "412 Precondition Failed",
        "Content-Type: application/xml\r\n",
        PRECONDITION_FAILED_BODY,
    ))
    .await;

    let error = send(&endpoint, &[], false).await.unwrap_err();
    server.await.unwrap();

    assert!(
        format!("{error:#}").contains("HTTP status 412"),
        "{error:#}"
    );
}
