//! Signed transport fixtures; no issuer, provider or mutable-read qualification.

use std::sync::{
    atomic::{AtomicUsize, Ordering},
    Arc,
};

use aos_hub_core::storage_authority::external_object::{
    observation::{ExternalObservation, ExternalObservationOutcome},
    ExternalObjectHead,
};
use axum::{body::Bytes, http::HeaderMap, response::IntoResponse as _};

use super::*;

const KEY: &[u8] = b"external-observation-native-transport-fixture-key";
const DEPLOYMENT: &str = "observation-native-fixture";

fn request(now: i64) -> SemanticExternalObservationRequest {
    let mut request: SemanticExternalObservationRequest = serde_json::from_str(include_str!(
        "../../../../aos-hub-core/src/storage_authority/external_object/observation/semantic/tests/fixture.json"
    )).unwrap();
    request.plan.issued_at = now;
    request.plan.expires_at = now + 30;
    request.plan.plan_id = uuid::Uuid::new_v4().simple().to_string();
    request.operation_id = uuid::Uuid::new_v4().simple().to_string();
    request
}

#[derive(Clone, Copy)]
enum Mode {
    Current,
    Historical,
    WrongRequest,
    WrongStamp,
    Refused,
    Oversized,
    WrongMac,
}

async fn server(
    mode: Mode,
) -> (
    RemoteStorageWorkClient,
    Arc<AtomicUsize>,
    tokio::task::JoinHandle<std::io::Result<()>>,
) {
    let attempts = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&attempts);
    let app = axum::Router::new().route(
        SEMANTIC_OBSERVATION_PATH,
        axum::routing::post(move |headers: HeaderMap, body: Bytes| {
            let attempts = Arc::clone(&observed);
            async move {
                attempts.fetch_add(1, Ordering::SeqCst);
                let key = StorageWorkKey::new(KEY).unwrap();
                let mac = headers
                    .get(STORAGE_WORK_SIGNATURE_HEADER)
                    .unwrap()
                    .to_str()
                    .unwrap();
                let request = SemanticExternalObservationRequest::authenticate(
                    &key,
                    mac,
                    &body,
                    DEPLOYMENT,
                    aos_hub_core::clock::now_unix_secs(),
                )
                .unwrap();
                assert_eq!(request.binding_write_revision.get(), 4);
                assert_eq!(request.plan.binding_resource_version, 3);
                let mut stamp = request.expected_guard_stamp.clone();
                if matches!(mode, Mode::Refused) {
                    return axum::http::StatusCode::CONFLICT.into_response();
                }
                if matches!(mode, Mode::Oversized) {
                    return (
                        [(STORAGE_WORK_SIGNATURE_HEADER, "fixture-signature")],
                        vec![b'x'; MAX_OBSERVATION_REPLY_BYTES + 1],
                    )
                        .into_response();
                }
                if matches!(mode, Mode::WrongStamp) {
                    stamp.incarnation = aos_hub_core::storage_authority::GuardIncarnation::parse("3").unwrap();
                }
                let observation = ExternalObservation {
                    operation_id: request.operation_id,
                    intent_digest: "b".repeat(64),
                    turn_digest: "c".repeat(64),
                    guard_stamp: stamp,
                    observed_at: aos_hub_core::clock::now_unix_secs().to_string(),
                    object: Some(ExternalObjectHead {
                        provider_version: None,
                        bytes: "9007199254740993".into(),
                        etag: "\"exact-provider-etag\"".into(),
                    }),
                };
                let outcome = if matches!(mode, Mode::Historical) {
                    ExternalObservationOutcome::HistoricalObservation(observation)
                } else {
                    ExternalObservationOutcome::ObservedThisInvocation(observation)
                };
                let mut reply = serde_json::json!({
                    "version": 1,
                    "domain": aos_hub_core::storage_authority::external_object::observation::semantic::SEMANTIC_OBSERVATION_REPLY_DOMAIN,
                    "request_digest": hex::encode(sha2::Sha256::digest(&body)),
                    "outcome": outcome,
                });
                if matches!(mode, Mode::WrongRequest) {
                    reply["request_digest"] = serde_json::Value::String("d".repeat(64));
                }
                // Encode through the exact closed DTO's field order, including
                // deliberately signed invalid context in the negative fixtures.
                let reply: SemanticExternalObservationReply = serde_json::from_value(reply).unwrap();
                let encoded = serde_json::to_vec(&reply).unwrap();
                let mut mac = key.sign_body(&encoded).unwrap();
                if matches!(mode, Mode::WrongMac) {
                    mac = "0".repeat(64);
                }
                ([(STORAGE_WORK_SIGNATURE_HEADER, mac)], encoded).into_response()
            }
        }),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let handle = tokio::spawn(async move { axum::serve(listener, app).await });
    let mut client =
        RemoteStorageWorkClient::new("https://worker.example", DEPLOYMENT.into(), KEY).unwrap();
    // Local transport qualification does not claim HTTPS/provider behavior.
    client.endpoint = format!("http://{address}/legacy-storage-path");
    (client, attempts, handle)
}

#[tokio::test]
async fn current_reply_preserves_exact_stamp_metadata_and_original_request() {
    let (client, attempts, handle) = server(Mode::Current).await;
    let request = request(aos_hub_core::clock::now_unix_secs());
    let original = serde_json::to_vec(&request).unwrap();
    let reply = client.observe_external_head(&request).await.unwrap();
    let ExternalObservationOutcome::ObservedThisInvocation(value) = reply.outcome else {
        panic!("fresh interval was not preserved");
    };

    assert_eq!(value.guard_stamp, request.expected_guard_stamp);
    assert_eq!(value.object.unwrap().bytes, "9007199254740993");
    assert_eq!(serde_json::to_vec(&request).unwrap(), original);
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    handle.abort();
}

#[tokio::test]
async fn historical_reply_remains_explicit_history_without_new_request() {
    let (client, attempts, handle) = server(Mode::Historical).await;
    let reply = client
        .observe_external_head(&request(aos_hub_core::clock::now_unix_secs()))
        .await
        .unwrap();

    assert!(matches!(
        reply.outcome,
        ExternalObservationOutcome::HistoricalObservation(_)
    ));
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    handle.abort();
}

#[tokio::test]
async fn another_invocations_signed_reply_is_rejected() {
    rejected(Mode::WrongRequest).await;
}

#[tokio::test]
async fn another_guard_incarnation_is_rejected() {
    rejected(Mode::WrongStamp).await;
}

#[tokio::test]
async fn refusal_never_retries_or_replaces_observation_identity() {
    rejected(Mode::Refused).await;
}

#[tokio::test]
async fn oversized_reply_is_refused_before_decoding() {
    rejected(Mode::Oversized).await;
}

#[tokio::test]
async fn invalid_reply_mac_is_rejected() {
    rejected(Mode::WrongMac).await;
}

#[tokio::test]
async fn original_deadline_is_rechecked_after_authenticated_http_reply() {
    let (client, attempts, handle) = server(Mode::Current).await;
    let now = aos_hub_core::clock::now_unix_secs();
    let observations = AtomicUsize::new(0);
    let result = client
        .observe_external_head_at_time(&request(now), || {
            if observations.fetch_add(1, Ordering::SeqCst) == 0 {
                now
            } else {
                now + 31
            }
        })
        .await;

    assert!(result.is_err());
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    handle.abort();
}

async fn rejected(mode: Mode) {
    let (client, attempts, handle) = server(mode).await;
    let result = client
        .observe_external_head(&request(aos_hub_core::clock::now_unix_secs()))
        .await;

    assert!(result.is_err());
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
    handle.abort();
}

#[test]
fn original_application_deadline_is_not_extended_by_reply_or_decoding() {
    let request = request(100);
    assert!(check_application_time(&request, 130).is_ok());
    assert!(check_application_time(&request, 131).is_err());
    assert!(check_application_time(&request, 94).is_err());
}

#[tokio::test]
async fn expired_request_is_not_sent_after_local_queue() {
    let (client, attempts, handle) = server(Mode::Current).await;
    let client = Arc::new(client);
    let permit = client.in_flight.acquire_many(4).await.unwrap();
    let clock = Arc::new(std::sync::atomic::AtomicI64::new(100));
    let task_client = Arc::clone(&client);
    let task_clock = Arc::clone(&clock);
    let pending = tokio::spawn(async move {
        task_client
            .observe_external_head_at_time(&request(100), || task_clock.load(Ordering::SeqCst))
            .await
    });
    tokio::task::yield_now().await;
    clock.store(131, Ordering::SeqCst);
    drop(permit);

    assert!(pending.await.unwrap().is_err());
    assert_eq!(attempts.load(Ordering::SeqCst), 0);
    handle.abort();
}

#[test]
fn malformed_authenticated_reply_errors_do_not_expose_private_diagnostics() {
    let key = StorageWorkKey::new(KEY).unwrap();
    let request = request(100);
    let (request, _) = request.sign(&key, DEPLOYMENT, 100).unwrap();
    let bytes = br#"{"private-diagnostic":"must-not-escape"}"#;
    let mac = key.sign_body(bytes).unwrap();
    let error = authenticate_reply(&key, &mac, bytes, &request)
        .err()
        .unwrap();

    assert_eq!(
        format!("{error:#}"),
        "semantic observation reply authentication failed"
    );
}

use sha2::Digest as _;
