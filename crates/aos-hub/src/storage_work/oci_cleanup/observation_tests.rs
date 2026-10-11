//! Actual local HTTP transport counters remain separate from physical completion.

use std::time::Duration;

use aos_hub_core::storage_work::{StorageObjectIdentity, StorageWorkKey};
use axum::{Router, body::Body, http::Response, routing::post};
use sha2::{Digest as _, Sha256};
use tracing::instrument::WithSubscriber as _;
use tracing_subscriber::layer::SubscriberExt as _;

use super::*;

fn request() -> ManagedOciCleanupRequest {
    let now = u64::try_from(aos_hub_core::clock::now_unix_secs()).unwrap();
    ManagedOciCleanupRequest {
        deployment_id: "cleanup-transport-fixture".into(),
        original: ManagedOciCleanupOriginal {
            upload_id: "1".repeat(32),
            upload_resource_version: 1,
            terminal_state: "complete".into(),
            finished_at: 1,
            registry_id: 1,
            repository_id: 1,
            writer_id: "writer".into(),
            token_id: "token".into(),
            ordinal: 0,
            offset: 0,
            path: format!("oci/uploads/{}/chunks/0-fixture", "1".repeat(32)),
            sha256: "2".repeat(64),
            size: 256,
            placement_id: 1,
            placement_resource_version: 1,
            placement_prefix: "qualification/oci-terminal-cleanup/transport".into(),
            binding_id: 1,
            binding_resource_version: 1,
            binding_write_revision: 1,
            delete_capability_fingerprint: "independent-delete".into(),
            delete_capability_resource_version: 1,
        },
        protected_profile_digest: "3".repeat(64),
        issuer: MirrorGuardIssuer {
            source_digest: "4".repeat(64),
            script_version: "fixture-script".into(),
        },
        clock_uncertainty_seconds: 1,
        nonce: "5".repeat(64),
        issued_at: now,
        expires_at: now + 30,
    }
}

fn keys() -> (StorageWorkKey, StorageWorkKey) {
    (
        StorageWorkKey::new(&[6; 32]).unwrap(),
        StorageWorkKey::new(&[7; 32]).unwrap(),
    )
}

fn reply(request: &ManagedOciCleanupRequest, guard: &StorageWorkKey) -> (Vec<u8>, String) {
    ManagedOciCleanupReply {
        request_digest: hex::encode(Sha256::digest(serde_json::to_vec(request).unwrap())),
        original_digest: request.original.fingerprint().unwrap(),
        nonce: request.nonce.clone(),
        object: StorageObjectIdentity {
            key: request.original.key(),
            size: request.original.size,
            etag: "\"actual-etag\"".into(),
            provider_version: Some("opaque-r2-version".into()),
        },
        receipt_digest: "8".repeat(64),
    }
    .sign(request, guard)
    .unwrap()
}

async fn local(app: Router) -> (String, tokio::task::JoinHandle<()>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (
        format!("http://{address}{MANAGED_OCI_CLEANUP_PATH}"),
        server,
    )
}

async fn run(
    url: &str,
    request: &ManagedOciCleanupRequest,
    guard: &StorageWorkKey,
    body: Vec<u8>,
    signature: String,
) -> (Result<ManagedOciCleanupReply>, serde_json::Value) {
    let capture = observations::Capture::default();
    let http = reqwest::Client::builder()
        .tls_built_in_root_certs(false)
        .no_proxy()
        .build()
        .unwrap();
    let result = async {
        let mut exchange = ExchangeTelemetry::control(&request.nonce, "managed_oci_cleanup");
        exchange_cleanup(
            &http,
            url,
            request,
            guard,
            body,
            signature,
            2,
            &mut exchange,
        )
        .await
    }
    .with_subscriber(tracing_subscriber::registry().with(capture.clone()))
    .await;
    (result, capture.snapshot())
}

fn accounting(capture: &serde_json::Value) -> &serde_json::Value {
    assert_eq!(capture["complete"], true);
    let rows: Vec<_> = capture["events"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|row| row["message"] == "hybrid storage exchange accounting")
        .collect();
    assert_eq!(rows.len(), 1);
    rows[0]
}

#[tokio::test]
async fn positive_reply_counts_native_chunks_and_actual_call_id_without_final_sql() {
    let request = request();
    let (application, guard) = keys();
    let (body, signature) = request.sign(&application).unwrap();
    let request_sha = hex::encode(Sha256::digest(&body));
    let (response_body, response_signature) = reply(&request, &guard);
    let reply_length = response_body.len();
    let app = Router::new().route(
        MANAGED_OCI_CLEANUP_PATH,
        post(move |headers: axum::http::HeaderMap| async move {
            let call_id = headers[STORAGE_CALL_ID_HEADER].to_str().unwrap();
            assert_eq!(call_id.len(), 32);
            assert!(
                call_id
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            );
            Response::builder()
                .header(MANAGED_OCI_CLEANUP_HEADER, response_signature)
                .body(Body::from(response_body))
                .unwrap()
        }),
    );
    let (url, server) = local(app).await;
    let (result, capture) = run(&url, &request, &guard, body, signature).await;
    result.unwrap();
    let row = accounting(&capture);
    assert_eq!(row["outcome"], "success");
    assert_eq!(row["observed_body_bytes"], reply_length.to_string());
    assert_eq!(row["offered_request_sha256"], request_sha);
    assert_eq!(row["exchange_attempts"], "1");
    assert_eq!(capture["events"].as_array().unwrap().len(), 2);
    let encoded = capture.to_string();
    assert!(!encoded.contains("storage_final_sql_checked"));
    assert!(!encoded.contains("opaque-r2-version"));
    server.abort();
}

#[tokio::test]
async fn unread_error_and_missing_signature_never_claim_native_reply_consumption() {
    for status in [200, 409] {
        let request = request();
        let (application, guard) = keys();
        let (body, signature) = request.sign(&application).unwrap();
        let app = Router::new().route(
            MANAGED_OCI_CLEANUP_PATH,
            post(move || async move {
                Response::builder()
                    .status(status)
                    .body(Body::from("unread-private-body"))
                    .unwrap()
            }),
        );
        let (url, server) = local(app).await;
        let (result, capture) = run(&url, &request, &guard, body, signature).await;
        assert!(result.is_err());
        assert_eq!(accounting(&capture)["observed_body_bytes"], "0");
        assert_eq!(capture["events"].as_array().unwrap().len(), 1);
        server.abort();
    }
}

#[tokio::test]
async fn consumed_wrong_mac_is_counted_but_never_authenticated() {
    let request = request();
    let (application, guard) = keys();
    let (body, signature) = request.sign(&application).unwrap();
    let app = Router::new().route(
        MANAGED_OCI_CLEANUP_PATH,
        post(|| async {
            Response::builder()
                .header(MANAGED_OCI_CLEANUP_HEADER, "invalid")
                .body(Body::from("actually-consumed-but-invalid"))
                .unwrap()
        }),
    );
    let (url, server) = local(app).await;
    let (result, capture) = run(&url, &request, &guard, body, signature).await;
    assert!(result.is_err());
    assert_eq!(accounting(&capture)["observed_body_bytes"], "29");
    assert_eq!(accounting(&capture)["outcome"], "invalid_result");
    assert_eq!(capture["events"].as_array().unwrap().len(), 1);
    server.abort();
}

#[tokio::test]
async fn partial_native_response_records_only_exposed_prefix_without_authentication() {
    let request = request();
    let (application, guard) = keys();
    let (body, signature) = request.sign(&application).unwrap();
    let app = Router::new().route(
        MANAGED_OCI_CLEANUP_PATH,
        post(|| async {
            let stream = futures::stream::unfold(0, |step| async move {
                if step == 0 {
                    return Some((
                        Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"partial")),
                        1,
                    ));
                }
                tokio::time::sleep(Duration::from_millis(30)).await;
                Some((
                    Err(std::io::Error::other(
                        "actual stream ended without completion",
                    )),
                    2,
                ))
            });
            Response::builder()
                .header(MANAGED_OCI_CLEANUP_HEADER, "present")
                .header("content-length", "100")
                .body(Body::from_stream(stream))
                .unwrap()
        }),
    );
    let (url, server) = local(app).await;
    let (result, capture) = run(&url, &request, &guard, body, signature).await;
    assert!(result.is_err());
    assert_eq!(accounting(&capture)["observed_body_bytes"], "7");
    assert_eq!(accounting(&capture)["outcome"], "response_read_failed");
    assert_eq!(capture["events"].as_array().unwrap().len(), 1);
    server.abort();
}

#[test]
fn bounded_helper_capture_retains_overflow_as_incomplete() {
    let capture = observations::Capture::default();
    tracing::subscriber::with_default(tracing_subscriber::registry().with(capture.clone()), || {
        for _ in 0..65 {
            tracing::info!(
                operation = "managed_oci_cleanup",
                "hybrid storage exchange accounting"
            );
        }
    });
    assert_eq!(capture.snapshot()["complete"], false);
    assert_eq!(capture.snapshot()["events"].as_array().unwrap().len(), 64);
}
