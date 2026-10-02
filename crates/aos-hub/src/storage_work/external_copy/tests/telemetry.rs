//! Actual local HTTP copy accounting after exact existing reply authentication.
//!
//! These tests reuse the SQLite claim and HTTP/event fixtures. They exercise no
//! provider effect, Worker distribution, runtime acceptance or fleet qualification.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use aos_hub_core::{
    storage_authority::{
        external_object::copy::{
            control::{CopyControl, CopyProgress, ExternalCopyReply, ExternalCopyRequest},
            metadata::{CopyMetadataProfile, CopyMetadataReply, CopyMetadataRequest},
            session::CopyPhase,
            CopySourceObject, ExternalCopyOriginal,
        },
        lease::LeaseInteger,
    },
    storage_work::{
        StorageCredentialSelector, StorageWorkKey, StorageWorkOperation, StorageWorkPlan,
        STORAGE_WORK_SIGNATURE_HEADER,
    },
};
use axum::{
    body::Bytes,
    http::{HeaderMap, StatusCode},
};
use sha2::{Digest as _, Sha256};
use tracing::instrument::WithSubscriber as _;
use tracing_subscriber::layer::SubscriberExt as _;

use crate::storage_work::telemetry::tests::{serve, RecordedEvents};

async fn requests() -> (ExternalCopyRequest, CopyMetadataRequest, StorageWorkKey) {
    let (writer, operation, source, destination, token) = super::fixture().await;
    let current = writer
        .current_copy(&operation, &source, &destination, true)
        .await
        .unwrap();
    let claim = writer
        .recheck_copy(&current, &operation, &token, &source, &destination)
        .await
        .unwrap();
    let now = aos_hub_core::clock::now_unix_secs();
    let original = ExternalCopyOriginal {
        version: 1,
        deployment_id: writer.work.deployment_id.clone(),
        topology: current.topology.clone(),
        binding_id: LeaseInteger::new(current.binding.id).unwrap(),
        binding_stable_id: current.binding.stable_id.clone(),
        binding_resource_version: LeaseInteger::new(current.binding.resource_version).unwrap(),
        snapshot_revision: "a".repeat(64),
        source: current.source.clone(),
        destination: current.destination.clone(),
        path: "nar/source.nar".into(),
        source_object: CopySourceObject {
            provider_version: Some("fixture-version".into()),
            etag: "\"fixture-tag\"".into(),
            bytes: LeaseInteger::new(11).unwrap(),
            guard_stamp: None,
        },
        read_generation: LeaseInteger::new(1).unwrap(),
        write_generation: LeaseInteger::new(1).unwrap(),
        binding_write_revision: LeaseInteger::new(current.revision.revision).unwrap(),
        profile_digest: "b".repeat(64),
        part_bytes: LeaseInteger::new(5 * 1024 * 1024).unwrap(),
        expected_sha256: None,
        source_receipt_digest: None,
    };
    let mut plan = StorageWorkPlan {
        version: 1,
        plan_id: "e".repeat(32),
        deployment_id: original.deployment_id.clone(),
        issued_at: now,
        expires_at: now + 30,
        placement_id: destination.id,
        placement_resource_version: destination.resource_version,
        binding_id: current.binding.id,
        binding_resource_version: current.binding.resource_version,
        binding_kind: "s3".into(),
        binding_snapshot_revision: Some(original.snapshot_revision.clone()),
        credential_references: vec![
            StorageCredentialSelector {
                purpose: "read".into(),
                generation: 1,
            },
            StorageCredentialSelector {
                purpose: "write".into(),
                generation: 1,
            },
        ],
        placement_prefix: destination.prefix.clone(),
        operation: StorageWorkOperation::CopyObject {
            source_placement_id: source.id,
            source_placement_resource_version: source.resource_version,
            source_prefix: source.prefix.clone(),
            path: original.path.clone(),
            expected_size: 11,
            expected_etag: original.source_object.etag.clone(),
        },
    };
    let control = ExternalCopyRequest::new(
        original.clone(),
        claim.clone(),
        plan.clone(),
        CopyControl::Status,
        now,
    )
    .unwrap();
    plan.plan_id = "f".repeat(32);
    plan.operation = StorageWorkOperation::Head {
        path: original.path.clone(),
    };
    plan.credential_references.truncate(1);
    let metadata = CopyMetadataRequest::new(
        original.topology,
        original.source,
        original.destination,
        Some(claim),
        plan,
        original.path,
        now,
    )
    .unwrap();
    (control, metadata, writer.work.key.clone())
}

async fn exchange(
    metadata: bool,
    outcome: &str,
) -> (
    BTreeMap<String, String>,
    usize,
    usize,
    Vec<serde_json::Value>,
) {
    let (control, query, key) = requests().await;
    let mut response = if metadata {
        let reply = CopyMetadataReply {
            version: 1,
            request_digest: hex::encode(Sha256::digest(serde_json::to_vec(&query).unwrap())),
            profile: CopyMetadataProfile {
                binding_stable_id: control.original.binding_stable_id.clone(),
                binding_write_revision: control.original.binding_write_revision,
                profile_digest: control.original.profile_digest.clone(),
                part_bytes: control.original.part_bytes,
                read_generation: control.original.read_generation,
                write_generation: control.original.write_generation,
                protected_versionless: false,
            },
            retained: None,
            source_closure: None,
        };
        reply.sign(&key, &query).unwrap()
    } else {
        let progress = CopyProgress {
            phase: CopyPhase::Creating,
            completed_parts: 0,
            copied_bytes: LeaseInteger::new(0).unwrap(),
            pending: false,
            destination: None,
            sha256: None,
        };
        ExternalCopyReply::new(&control, progress)
            .unwrap()
            .sign(&key, &control)
            .unwrap()
    };
    if outcome == "bad_mac" {
        response.1 = "00".repeat(32);
    }
    let request_body = if metadata {
        serde_json::to_vec(&query).unwrap()
    } else {
        serde_json::to_vec(&control).unwrap()
    };
    let expected_request = request_body.clone();
    let response_bytes = response.0.len();
    let request_sha256 = hex::encode(Sha256::digest(&request_body));
    let reply_sha256 = hex::encode(Sha256::digest(&response.0));
    let rejected = outcome == "http_rejected";
    let route = if metadata {
        super::EXTERNAL_COPY_METADATA_PATH
    } else {
        super::EXTERNAL_COPY_PATH
    };
    let call_id = Arc::new(Mutex::new(String::new()));
    let received_call_id = Arc::clone(&call_id);
    let app = axum::Router::new().route(
        route,
        axum::routing::post(move |headers: HeaderMap, body: Bytes| {
            assert_eq!(body.as_ref(), expected_request.as_slice());
            *received_call_id.lock().unwrap() = headers
                .get(crate::storage_work::telemetry::STORAGE_CALL_ID_HEADER)
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();
            let response = response.clone();
            async move {
                let mut headers = HeaderMap::new();
                headers.insert(STORAGE_WORK_SIGNATURE_HEADER, response.1.parse().unwrap());
                (
                    if rejected {
                        StatusCode::FORBIDDEN
                    } else {
                        StatusCode::OK
                    },
                    headers,
                    response.0,
                )
            }
        }),
    );
    let (mut client, server) = serve(app).await;
    client.key = key;
    client.deployment_id = control.original.deployment_id.clone();
    let recorded = RecordedEvents::default();
    let subscriber = tracing_subscriber::registry().with(recorded.clone());
    let accepted = if metadata {
        client
            .external_copy_metadata(&query)
            .with_subscriber(subscriber)
            .await
            .is_ok()
    } else {
        client
            .external_copy_control(&control)
            .with_subscriber(subscriber)
            .await
            .is_ok()
    };
    server.abort();
    assert_eq!(accepted, outcome == "success");
    let controls = recorded.authenticated_controls();
    if accepted {
        assert_eq!(controls.len(), 1);
        assert_eq!(controls[0]["version"], 2);
        assert_eq!(
            controls[0]["transportCallId"].as_str().unwrap(),
            call_id.lock().unwrap().as_str()
        );
        assert_eq!(
            uuid::Uuid::parse_str(controls[0]["transportCallId"].as_str().unwrap())
                .unwrap()
                .get_version_num(),
            4
        );
        assert_eq!(controls[0]["requestSha256"], request_sha256);
        assert_eq!(controls[0]["replySha256"], reply_sha256);
        assert_eq!(controls[0]["requestBytes"], request_body.len());
        assert_eq!(controls[0]["replyBytes"], response_bytes);
        assert_eq!(controls[0]["route"], route);
        assert_eq!(
            controls[0]["planId"],
            if metadata {
                query.plan.plan_id.as_str()
            } else {
                control.plan.plan_id.as_str()
            }
        );
    } else {
        assert!(controls.is_empty());
    }
    (
        recorded.exchange(),
        request_body.len(),
        response_bytes,
        controls,
    )
}

#[tokio::test]
async fn copy_accounting_requires_authentication_and_measures_actual_reply_payload() {
    for metadata in [false, true] {
        let (event, request, response, controls) = exchange(metadata, "success").await;
        assert_eq!(event["outcome"], "success");
        assert_eq!(event["exchange_attempts"], "1");
        assert_eq!(event["offered_plan_bytes"], request.to_string());
        assert_eq!(event["observed_body_bytes"], response.to_string());
        assert_eq!(event["discarded_status_responses"], "0");
        assert_eq!(controls[0].as_object().unwrap().len(), 9);
    }
}

async fn identical_copy_calls(late_second: bool) {
    let (mut request, _, key) = requests().await;
    if late_second {
        request.plan.expires_at = aos_hub_core::clock::now_unix_secs() + 2;
    }
    let progress = CopyProgress {
        phase: CopyPhase::Creating,
        completed_parts: 0,
        copied_bytes: LeaseInteger::new(0).unwrap(),
        pending: false,
        destination: None,
        sha256: None,
    };
    let signed = ExternalCopyReply::new(&request, progress)
        .unwrap()
        .sign(&key, &request)
        .unwrap();
    let expected_request = serde_json::to_vec(&request).unwrap();
    let request_body = expected_request.clone();
    let reply_bytes = signed.0.len();
    let expires_at = request.plan.expires_at;
    let call_ids = Arc::new(Mutex::new(Vec::<String>::new()));
    let observed_ids = Arc::clone(&call_ids);
    let app = axum::Router::new().route(
        super::EXTERNAL_COPY_PATH,
        axum::routing::post(move |headers: HeaderMap, body: Bytes| {
            assert_eq!(body.as_ref(), expected_request.as_slice());
            let call_id = headers
                .get(crate::storage_work::telemetry::STORAGE_CALL_ID_HEADER)
                .unwrap()
                .to_str()
                .unwrap()
                .to_owned();
            let index = {
                let mut ids = observed_ids.lock().unwrap();
                let index = ids.len();
                ids.push(call_id);
                index
            };
            let signed = signed.clone();
            async move {
                if late_second && index == 1 {
                    while aos_hub_core::clock::now_unix_secs() < expires_at {
                        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
                    }
                }
                let mut headers = HeaderMap::new();
                headers.insert(STORAGE_WORK_SIGNATURE_HEADER, signed.1.parse().unwrap());
                (headers, signed.0)
            }
        }),
    );
    let (mut client, server) = serve(app).await;
    client.key = key;
    client.deployment_id = request.original.deployment_id.clone();

    for index in 0..2 {
        let events = RecordedEvents::default();
        let subscriber = tracing_subscriber::registry().with(events.clone());
        let result = client
            .external_copy_control(&request)
            .with_subscriber(subscriber)
            .await;
        let accepted = !late_second || index == 0;
        assert_eq!(result.is_ok(), accepted);
        let accounting = events.exchange();
        assert_eq!(
            accounting["offered_plan_bytes"],
            request_body.len().to_string()
        );
        assert_eq!(accounting["observed_body_bytes"], reply_bytes.to_string());
        let controls = events.authenticated_controls();
        if accepted {
            assert_eq!(controls.len(), 1);
            assert_eq!(
                controls[0]["transportCallId"].as_str().unwrap(),
                call_ids.lock().unwrap()[index]
            );
        } else {
            assert!(controls.is_empty());
            assert_eq!(accounting["outcome"], "invalid_result");
        }
    }
    server.abort();
    let ids = call_ids.lock().unwrap();
    assert_eq!(ids.len(), 2);
    assert_ne!(ids[0], ids[1]);
}

#[tokio::test]
async fn identical_copy_replays_have_separate_authenticated_call_ids() {
    identical_copy_calls(false).await;
}

#[tokio::test]
async fn late_identical_reply_is_consumed_without_a_successful_call_receipt() {
    identical_copy_calls(true).await;
}

#[tokio::test]
async fn copy_accounting_keeps_consumed_invalid_and_unread_rejected_replies_distinct() {
    for metadata in [false, true] {
        let (event, _, response, _) = exchange(metadata, "bad_mac").await;
        assert_eq!(event["outcome"], "invalid_result");
        assert_eq!(event["observed_body_bytes"], response.to_string());
        let (event, _, _, _) = exchange(metadata, "http_rejected").await;
        assert_eq!(event["outcome"], "http_rejected");
        assert_eq!(event["observed_body_bytes"], "0");
        assert_eq!(event["discarded_status_responses"], "1");
    }
}

#[tokio::test]
async fn copy_accounting_cancellation_retains_offered_plan_without_claiming_consumption() {
    use std::sync::{Arc, Mutex};
    use std::time::Duration;

    let (control, _, key) = requests().await;
    let expected = serde_json::to_vec(&control).unwrap().len();
    let (sent, received) = tokio::sync::oneshot::channel();
    let sent = Arc::new(Mutex::new(Some(sent)));
    let app = axum::Router::new().route(
        super::EXTERNAL_COPY_PATH,
        axum::routing::post(move || {
            let sent = Arc::clone(&sent);
            async move {
                sent.lock().unwrap().take().unwrap().send(()).unwrap();
                std::future::pending::<&'static str>().await
            }
        }),
    );
    let (mut client, server) = serve(app).await;
    client.key = key;
    client.deployment_id = control.original.deployment_id.clone();
    let recorded = RecordedEvents::default();
    let subscriber = tracing_subscriber::registry().with(recorded.clone());
    let mut pending = Box::pin(
        client
            .external_copy_control(&control)
            .with_subscriber(subscriber),
    );

    tokio::time::timeout(Duration::from_secs(10), async {
        tokio::select! {
            result = &mut pending => panic!("copy completed before cancellation: {result:?}"),
            result = received => result.unwrap(),
        }
    })
    .await
    .unwrap();
    drop(pending);
    server.abort();

    let event = recorded.exchange();
    assert_eq!(event["outcome"], "cancelled");
    assert_eq!(event["exchange_attempts"], "1");
    assert_eq!(event["offered_plan_bytes"], expected.to_string());
    assert_eq!(event["observed_body_bytes"], "0");
    assert!(recorded.authenticated_controls().is_empty());
}
