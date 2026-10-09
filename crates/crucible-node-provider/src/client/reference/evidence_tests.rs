//! Component checks for bounded original observations and secret exclusion.

// crucible-lint: allow rust-allow -- invalid component evidence deliberately fails assertions.
#![allow(clippy::unwrap_used)]

use crucible_node_contract::{Extensions, U64};
use serde_json::{Map, json};

use crate::envelope::MessageKind;
use crate::reference_service::ReferenceProfile;

use super::*;

fn id(value: &str) -> Id {
    Id::new(value).unwrap()
}

pub(super) fn limits() -> ObservationLimits {
    ObservationLimits {
        maximum_requests: 4,
        maximum_objects: 4,
        maximum_bytes: 65536,
    }
}

pub(super) fn scope() -> ObservationScope {
    let executable =
        canonical::content_ref(b"component executable", "application/octet-stream").unwrap();
    let profile = ReferenceProfile::build(
        id("node"),
        id("owner"),
        executable.clone(),
        executable.clone(),
        U64::new(50),
        U64::new(1_000_000),
    )
    .unwrap();
    let compatibility = profile
        .bind(crucible_node_contract::LiveAuthority {
            schema_version: 1,
            session_id: id("session"),
            incarnation_id: id("incarnation"),
            realization_id: id("realization"),
            activation_id: None,
            world_generation: U64::new(0),
            owner_generation: U64::new(1),
            input_epoch: id("epoch"),
            host_receipt: canonical::content_ref(b"component receipt", "application/octet-stream")
                .unwrap(),
            extensions: Extensions::new(),
        })
        .unwrap()
        .0
        .compatibility;
    ObservationScope {
        provider_pid: U64::new(44),
        provider_executable: executable,
        session_id: id("session"),
        incarnation_id: id("incarnation"),
        connection_id: id("connection"),
        connection_epoch: U64::new(1),
        selected_features: vec![id("cnp.core/1")],
        binding_hash: compatibility.identity().unwrap(),
        compatibility,
    }
}

fn original(origin: RequestOrigin) -> (ObservedRequestKey, ClientOriginal) {
    let key = ObservedRequestKey {
        origin,
        request_id: id("same-request"),
    };
    let request = Envelope {
        protocol: "CNP/1".into(),
        message: MessageKind::Request,
        session_id: Nullable(Some(id("session"))),
        incarnation_id: Nullable(Some(id("incarnation"))),
        node_id: Nullable(None),
        execution_owner_id: Nullable(None),
        capture_owner_id: Nullable(None),
        request_id: Nullable(Some(key.request_id.clone())),
        operation_id: Nullable(None),
        sequence: U64::new(19),
        method: Method::Discover,
        body: Map::new(),
        extensions: Extensions::new(),
    };
    let identity = request.request_hash(origin).unwrap();
    (
        key,
        ClientOriginal {
            request,
            identity,
            response: None,
        },
    )
}

#[test]
fn unanswered_original_remains_absent_with_exact_transport_sequence() {
    let (key, original) = original(RequestOrigin::Controller);
    let observed = snapshot(scope(), &[(&key, &original)], &[], limits()).unwrap();
    let record = &observed.requests[0];
    assert!(record.response.0.is_none());
    assert_eq!(record.identity, original.identity);
    let envelope = Envelope::decode(record.request.bytes.as_slice(), 65536).unwrap();
    assert_eq!(envelope.sequence, U64::new(19));
    assert_eq!(envelope.request_id.0, Some(key.request_id));
    record
        .request
        .reference
        .verify(record.request.bytes.as_slice())
        .unwrap();

    let encoded = observed.encode(65536).unwrap();
    let value = canonical::parse_json(&encoded, 65536).unwrap();
    assert!(value["requests"][0]["response"].is_null());
    assert_eq!(value["encoding"], "retained-canonical-envelope-v1");
}

#[test]
fn equal_request_ids_retain_distinct_explicit_origin_and_identity() {
    let (controller_key, controller) = original(RequestOrigin::Controller);
    let (provider_key, provider) = original(RequestOrigin::Provider);
    let observed = snapshot(
        scope(),
        &[(&controller_key, &controller), (&provider_key, &provider)],
        &[],
        limits(),
    )
    .unwrap();

    assert_eq!(observed.requests.len(), 2);
    assert_eq!(observed.requests[0].key.origin, RequestOrigin::Controller);
    assert_eq!(observed.requests[1].key.origin, RequestOrigin::Provider);
    assert_ne!(observed.requests[0].identity, observed.requests[1].identity);
    assert!(snapshot(scope(), &[(&provider_key, &controller)], &[], limits()).is_err());
}

#[test]
fn changed_original_or_foreign_response_cannot_be_reconstructed_as_success() {
    let (key, mut original) = original(RequestOrigin::Controller);
    original.request.body.insert("changed".into(), json!(true));
    assert!(snapshot(scope(), &[(&key, &original)], &[], limits()).is_err());

    original.request.body.clear();
    let mut response = original.request.clone();
    response.message = MessageKind::Response;
    response.session_id = Nullable(Some(id("foreign-session")));
    original.response = Some(response);
    assert!(snapshot(scope(), &[(&key, &original)], &[], limits()).is_err());
}

#[test]
fn latest_authentic_response_keeps_its_actual_sequence_and_body() {
    let (key, mut original) = original(RequestOrigin::Controller);
    let mut response = original.request.clone();
    response.message = MessageKind::Response;
    response.sequence = U64::new(31);
    response.body.insert("status".into(), json!("running"));
    original.response = Some(response);

    let observed = snapshot(scope(), &[(&key, &original)], &[], limits()).unwrap();
    let response = observed.requests[0].response.0.as_ref().unwrap();
    let envelope = Envelope::decode(response.bytes.as_slice(), 65536).unwrap();
    assert_eq!(envelope.sequence, U64::new(31));
    assert_eq!(envelope.body.get("status"), Some(&json!("running")));
}

#[test]
fn handshake_and_nested_credentials_refuse_before_request_hashing() {
    let (key, mut original) = original(RequestOrigin::Controller);
    original.request.method = Method::Hello;
    assert!(matches!(
        snapshot(scope(), &[(&key, &original)], &[], limits()),
        Err(ProviderError::Frame("handshake observations are private"))
    ));

    original.request.method = Method::Discover;
    original.request.body.insert(
        "nested".into(),
        json!({"rows":[{"resume_token":"must-not-enter-an-artifact"}]}),
    );
    assert!(matches!(
        snapshot(scope(), &[(&key, &original)], &[], limits()),
        Err(ProviderError::Frame("private control credential selected"))
    ));
}

#[test]
fn selected_content_preserves_metadata_and_refuses_aggregate_overflow() {
    let bytes = b"original opaque payload";
    let reference = canonical::content_ref(bytes, "application/octet-stream").unwrap();
    let observed = snapshot(scope(), &[], &[(&reference, bytes)], limits()).unwrap();
    assert_eq!(observed.objects[0].reference, reference);
    assert_eq!(observed.objects[0].bytes.as_slice(), bytes);

    let low_limit = ObservationLimits {
        maximum_bytes: bytes.len() - 1,
        ..limits()
    };
    assert!(snapshot(scope(), &[], &[(&reference, bytes)], low_limit).is_err());
    let mut changed = reference;
    changed.length = U64::new(1);
    assert!(snapshot(scope(), &[], &[(&changed, bytes)], limits()).is_err());
}

#[test]
fn controls_and_content_share_one_budget_and_encoding_has_its_own_budget() {
    let (key, original) = original(RequestOrigin::Controller);
    let observed = snapshot(scope(), &[(&key, &original)], &[], limits()).unwrap();
    let control_length = observed.requests[0].request.bytes.as_slice().len();
    let bytes = b"payload";
    let reference = canonical::content_ref(bytes, "application/octet-stream").unwrap();
    let exact = ObservationLimits {
        maximum_bytes: control_length + bytes.len(),
        ..limits()
    };
    let observed = snapshot(scope(), &[(&key, &original)], &[(&reference, bytes)], exact).unwrap();
    assert!(observed.encode(1).is_err());
    assert!(observed.encode(MAX_BYTES + 1).is_err());
    assert!(
        snapshot(
            scope(),
            &[(&key, &original)],
            &[(&reference, bytes)],
            ObservationLimits {
                maximum_bytes: exact.maximum_bytes - 1,
                ..exact
            },
        )
        .is_err()
    );
}

#[test]
fn private_binary_text_and_structured_content_are_excluded() {
    let secret = [7; 32];
    assert!(reject_private_content(&secret, &secret).is_err());
    let encoded = serde_json::to_vec(&Bytes::new(secret.to_vec())).unwrap();
    assert!(reject_private_content(&encoded, &secret).is_err());
    assert!(reject_private_content(br#"{"admission_token":"private"}"#, &secret).is_err());
    assert!(reject_private_content(br#"{"checksum":"0"}"#, &secret).is_ok());

    let mut nested = json!(null);
    for _ in 0..65 {
        nested = json!([nested]);
    }
    assert!(reject_credentials(&nested).is_err());
}
