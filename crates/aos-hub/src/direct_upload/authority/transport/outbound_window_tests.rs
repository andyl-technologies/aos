//! Real Direct HTTP response ownership and header-preservation checks.

use std::{
    io,
    sync::{Arc, Mutex},
};

use aos_hub_core::direct_upload::{
    DirectStorageCapabilitiesRequest, WireInteger, sign_direct_storage_capabilities_request,
    verify_direct_storage_capabilities_request,
};
use axum::{
    body::{Body, Bytes},
    http::HeaderMap,
    routing::post,
};
use futures_util::StreamExt as _;
use sha2::{Digest as _, Sha256};

use super::*;
use crate::outbound_inventory::tests::{Loopback, capture, capture_until_exposed, rows};

const SYNTHETIC_KEY: &[u8] = b"direct-window-test-only-hmac-key";

fn original() -> DirectStorageCapabilitiesRequest {
    let now = u64::try_from(aos_hub_core::clock::now_unix_secs()).unwrap();
    DirectStorageCapabilitiesRequest {
        version: 2,
        deployment_id: "window-test".into(),
        executor_public_origin: "https://worker.test".into(),
        request_nonce: "1".repeat(64),
        issued_at: WireInteger::new(now),
        expires_at: WireInteger::new(now + 30),
        managed: true,
        external_selectors: Vec::new(),
    }
}

fn signed(original: &DirectStorageCapabilitiesRequest) -> SignedDirectControl {
    sign_direct_storage_capabilities_request(&StorageWorkKey::new(SYNTHETIC_KEY).unwrap(), original)
        .unwrap()
}

#[tokio::test]
async fn actual_transport_preserves_signed_request_and_exposed_reply() {
    let received = Arc::new(Mutex::new(Vec::new()));
    let retained = Arc::clone(&received);
    let original = original();
    let expected = original.clone();
    let server = Loopback::start(axum::Router::new().route(
        STORAGE_CAPABILITIES_PATH,
        post(move |headers: HeaderMap, bytes: Bytes| {
            let retained = Arc::clone(&retained);
            let expected = expected.clone();
            async move {
                let decoded = verify_direct_storage_capabilities_request(
                    &StorageWorkKey::new(SYNTHETIC_KEY).unwrap(),
                    headers[STORAGE_WORK_SIGNATURE_HEADER].to_str().unwrap(),
                    &bytes,
                    &expected.deployment_id,
                    &expected.executor_public_origin,
                    u64::try_from(aos_hub_core::clock::now_unix_secs()).unwrap(),
                )
                .unwrap();
                assert_eq!(decoded, expected);
                retained.lock().unwrap().push((bytes.to_vec(), headers));
                (
                    [(STORAGE_WORK_SIGNATURE_HEADER, "synthetic-reply-assertion")],
                    "reply",
                )
            }
        }),
    ))
    .await;
    let http = reqwest::Client::new();
    let before = post_exchange(
        &http,
        &server.origin,
        STORAGE_CAPABILITIES_PATH,
        STORAGE_WORK_SIGNATURE_HEADER,
        signed(&original),
        4096,
        &original.request_nonce,
        false,
    )
    .await
    .unwrap();
    let (after, records) = capture(post_exchange(
        &http,
        &server.origin,
        STORAGE_CAPABILITIES_PATH,
        STORAGE_WORK_SIGNATURE_HEADER,
        signed(&original),
        4096,
        &original.request_nonce,
        false,
    ))
    .await;
    assert_eq!(before, after.unwrap());
    server.retire().await;

    let received = received.lock().unwrap();
    assert_eq!(received.len(), 2);
    assert_eq!(received[0], received[1]);
    assert!(received[1].1.get(observation::CALL_ID_HEADER).is_none());
    let terminal = rows(&records, "terminal");
    assert_eq!(terminal.len(), 1);
    assert!(terminal[0]["transportCallId"].is_null());
    assert_eq!(terminal[0]["replyEof"], true);
    assert_eq!(terminal[0]["exposedReplyBytes"], "5");
    assert_eq!(
        terminal[0]["exposedReplySha256"],
        hex::encode(Sha256::digest(b"reply"))
    );
    assert!(terminal[0]["replyMacAuthentication"].is_null());
    assert!(!records.join("\n").contains("synthetic-reply-assertion"));
    assert!(
        !records
            .join("\n")
            .contains(std::str::from_utf8(SYNTHETIC_KEY).unwrap())
    );
}

#[tokio::test]
async fn actual_dropped_partial_reply_keeps_prefix_without_eof() {
    let server = Loopback::start(axum::Router::new().route(
        STORAGE_CAPABILITIES_PATH,
        post(|| async {
            let stream = futures_util::stream::once(async {
                Ok::<_, io::Error>(Bytes::from_static(b"prefix"))
            })
            .chain(futures_util::stream::pending::<
                std::result::Result<Bytes, io::Error>,
            >());
            (
                [(STORAGE_WORK_SIGNATURE_HEADER, "synthetic-reply-assertion")],
                Body::from_stream(stream),
            )
        }),
    ))
    .await;
    let http = reqwest::Client::new();
    let original = original();
    let records = capture_until_exposed(post_exchange(
        &http,
        &server.origin,
        STORAGE_CAPABILITIES_PATH,
        STORAGE_WORK_SIGNATURE_HEADER,
        signed(&original),
        4096,
        &original.request_nonce,
        false,
    ))
    .await;
    server.retire().await;

    let terminal = rows(&records, "terminal");
    assert_eq!(terminal.len(), 1);
    assert_eq!(terminal[0]["replyStatus"], 200);
    assert_eq!(terminal[0]["exposedReplyBytes"], "6");
    assert_eq!(
        terminal[0]["exposedReplySha256"],
        hex::encode(Sha256::digest(b"prefix"))
    );
    assert_eq!(terminal[0]["replyEof"], false);
    assert_eq!(terminal[0]["outcome"], "reply_unfinished");
    assert_eq!(rows(&records, "end")[0]["incomplete"], "1");
}
