//! Actual ordinary dispatch retry, cancellation and sensitive-control tests.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

use aos_hub_core::storage_work::{StorageWorkOperation, StorageWorkOutcome};
use axum::{
    body::Bytes,
    http::{HeaderMap, StatusCode},
    routing::post,
};
use sha2::{Digest as _, Sha256};

use super::*;
use crate::outbound_inventory::tests::{Loopback, capture, rows};

const SYNTHETIC_KEY: &[u8] = b"outbound-window-test-only-hmac-key";

fn plan() -> StorageWorkPlan {
    let now = aos_hub_core::clock::now_unix_secs();
    StorageWorkPlan {
        version: 1,
        plan_id: "1".repeat(32),
        deployment_id: "window-test".into(),
        issued_at: now,
        expires_at: now + 30,
        placement_id: 1,
        placement_resource_version: 1,
        binding_id: 1,
        binding_resource_version: 1,
        binding_kind: "deployment_r2".into(),
        binding_snapshot_revision: None,
        credential_references: Vec::new(),
        placement_prefix: "registry".into(),
        operation: StorageWorkOperation::Head {
            path: "original".into(),
        },
    }
}

fn client(origin: &str) -> RemoteStorageWorkClient {
    let mut client =
        RemoteStorageWorkClient::new("https://worker.test", "window-test".into(), SYNTHETIC_KEY)
            .unwrap();
    client.endpoint = format!("{origin}/");
    client.binding_control_endpoint = format!("{origin}/");
    client
}

#[tokio::test]
async fn actual_execute_retry_closes_two_distinct_dispatches() {
    let original = plan();
    let body = serde_json::to_vec(&original).unwrap();
    let expected = body.clone();
    let reply = serde_json::to_vec(&StorageWorkResult {
        versioned_sources: Vec::new(),
        plan_id: original.plan_id.clone(),
        placement_id: 1,
        placement_resource_version: 1,
        binding_id: 1,
        binding_resource_version: 1,
        source_bytes: 0,
        outcome: StorageWorkOutcome::NotFound,
    })
    .unwrap();
    let attempts = Arc::new(AtomicUsize::new(0));
    let received = Arc::clone(&attempts);
    let app = axum::Router::new().route(
        "/",
        post(move |headers: HeaderMap, bytes: Bytes| {
            let attempts = Arc::clone(&received);
            let reply = reply.clone();
            let expected = expected.clone();
            async move {
                assert_eq!(bytes.as_ref(), expected.as_slice());
                StorageWorkKey::new(SYNTHETIC_KEY)
                    .unwrap()
                    .verify_body(
                        headers[STORAGE_WORK_SIGNATURE_HEADER].to_str().unwrap(),
                        &bytes,
                    )
                    .unwrap();
                assert_eq!(
                    headers[telemetry::STORAGE_CALL_ID_HEADER].as_bytes().len(),
                    32
                );
                if attempts.fetch_add(1, Ordering::SeqCst) == 0 {
                    (StatusCode::SERVICE_UNAVAILABLE, b"unread-error".to_vec())
                } else {
                    (StatusCode::OK, reply)
                }
            }
        }),
    );
    let server = Loopback::start(app).await;
    let client = client(&server.origin);
    let (result, records) = capture(client.execute(&original)).await;
    result.unwrap();
    server.retire().await;

    assert_eq!(attempts.load(Ordering::SeqCst), 2);
    let offered = rows(&records, "offered");
    let terminal = rows(&records, "terminal");
    let end = rows(&records, "end");
    assert_eq!(offered.len(), 2);
    assert_ne!(offered[0]["transportCallId"], offered[1]["transportCallId"]);
    assert!(
        offered
            .iter()
            .all(|row| row["requestSha256"] == hex::encode(Sha256::digest(&body)))
    );
    assert_eq!(terminal[0]["replyStatus"], 503);
    assert_eq!(terminal[0]["exposedReplyBytes"], "0");
    assert_eq!(terminal[0]["replyEof"], false);
    assert_eq!(terminal[1]["replyStatus"], 200);
    assert_eq!(terminal[1]["replyEof"], true);
    assert_eq!(end[0]["offered"], "2");
    assert_eq!(end[0]["terminal"], "2");
    assert_eq!(end[0]["pending"], "0");
    assert_eq!(end[0]["incomplete"], "1");
}

#[tokio::test]
async fn actual_cancelled_execute_keeps_unknown_terminal() {
    let entered = Arc::new(tokio::sync::Notify::new());
    let received = Arc::clone(&entered);
    let server = Loopback::start(axum::Router::new().route(
        "/",
        post(move || {
            let received = Arc::clone(&received);
            async move {
                received.notify_one();
                std::future::pending::<&'static str>().await
            }
        }),
    ))
    .await;
    let client = client(&server.origin);
    let original = plan();
    let (_, records) = capture(async {
        let mut pending = Box::pin(client.execute(&original));
        tokio::time::timeout(Duration::from_secs(10), async {
            tokio::select! {
                result = &mut pending => panic!("request ended before cancellation: {result:?}"),
                _ = entered.notified() => {},
            }
        })
        .await
        .unwrap();
        drop(pending);
    })
    .await;
    server.retire().await;

    let terminal = rows(&records, "terminal");
    assert_eq!(terminal.len(), 1);
    assert!(terminal[0]["replyStatus"].is_null());
    assert_eq!(terminal[0]["exposedReplyBytes"], "0");
    assert_eq!(terminal[0]["replyEof"], false);
    assert_eq!(terminal[0]["outcome"], "send_unfinished");
    assert!(terminal[0]["replyMacAuthentication"].is_null());
    assert_eq!(rows(&records, "end")[0]["incomplete"], "1");
}

#[tokio::test]
async fn actual_length_only_control_does_not_hash_or_export_body() {
    let private = "synthetic-private-control-value";
    let now = aos_hub_core::clock::now_unix_secs();
    let original = StorageBindingControl::Revoke {
        deployment_id: private.into(),
        binding_id: 1,
        revision: "f".repeat(64),
        issued_at: now,
        expires_at: now + 30,
    };
    let original_body = serde_json::to_vec(&original).unwrap();
    let expected = original_body.clone();
    let server = Loopback::start(axum::Router::new().route(
        "/",
        post(move |bytes: Bytes| {
            let expected = expected.clone();
            async move {
                assert_eq!(bytes.as_ref(), expected.as_slice());
                format!("{{\"revision\":\"{}\"}}", "f".repeat(64))
            }
        }),
    ))
    .await;
    let client = client(&server.origin);
    let (result, records) = capture(client.send_binding_control(&original, &"f".repeat(64))).await;
    result.unwrap();
    server.retire().await;

    assert!(!records.join("\n").contains(private));
    assert!(
        !records
            .join("\n")
            .contains(&hex::encode(Sha256::digest(&original_body)))
    );
    let offered = rows(&records, "offered");
    let terminal = rows(&records, "terminal");
    assert!(offered[0]["requestSha256"].is_null());
    assert!(offered[0]["transportCallId"].is_null());
    assert_eq!(
        offered[0]["offeredRequestBytes"],
        original_body.len().to_string()
    );
    assert!(terminal[0]["exposedReplySha256"].is_null());
    assert_eq!(terminal[0]["replyEof"], true);
    assert!(terminal[0]["finalSqlAuthority"].is_null());
}
