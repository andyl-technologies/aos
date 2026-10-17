//! Closed semantic wire and exact original-request response fixtures.

use super::*;
use crate::storage_authority::external_object::{
    observation::ExternalObservation, ExternalObjectHead,
};

const KEY: &[u8] = b"semantic-observation-model-fixture-key-32-bytes";
const DEPLOYMENT: &str = "observation-native-fixture";

fn request() -> SemanticExternalObservationRequest {
    serde_json::from_str(include_str!("tests/fixture.json")).unwrap()
}

fn observation(request: &SemanticExternalObservationRequest) -> ExternalObservation {
    ExternalObservation {
        operation_id: request.operation_id.clone(),
        intent_digest: "b".repeat(64),
        turn_digest: "c".repeat(64),
        guard_stamp: request.expected_guard_stamp.clone(),
        observed_at: "101".into(),
        object: Some(ExternalObjectHead {
            provider_version: None,
            bytes: "9007199254740993".into(),
            etag: "\"exact-object\"".into(),
        }),
    }
}

#[test]
fn semantic_request_requires_exact_sql_identity_and_has_no_lease_field() {
    let key = StorageWorkKey::new(KEY).unwrap();
    let request = request();
    let (bytes, mac) = request.sign(&key, DEPLOYMENT, 101).unwrap();
    let decoded =
        SemanticExternalObservationRequest::authenticate(&key, &mac, &bytes, DEPLOYMENT, 101)
            .unwrap();
    assert_eq!(decoded.expected_guard_stamp, request.expected_guard_stamp);
    assert_eq!(decoded.profile_selector, request.profile_selector);
    assert!(!String::from_utf8(bytes).unwrap().contains("\"lease\""));
}

#[test]
fn semantic_request_rejects_missing_stamp_unknown_lease_and_wrong_domain() {
    let mut value = serde_json::to_value(request()).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .remove("expected_guard_stamp");
    assert!(serde_json::from_value::<SemanticExternalObservationRequest>(value).is_err());
    let mut value = serde_json::to_value(request()).unwrap();
    value["lease"] = serde_json::Value::String("untrusted-default".into());
    assert!(serde_json::from_value::<SemanticExternalObservationRequest>(value).is_err());
    let mut request = request();
    request.domain = super::super::OBSERVATION_APPLICATION_DOMAIN.into();
    assert!(request.validate(DEPLOYMENT, 101).is_err());
}

#[test]
fn semantic_request_rejects_non_head_and_foreign_stamp_authority() {
    let mut request = request();
    request.plan.operation = StorageWorkOperation::PutMetadata {
        path: "object".into(),
        content_base64: String::new(),
        sha256: "a".repeat(64),
    };
    assert!(request.validate(DEPLOYMENT, 101).is_err());
    request.plan.operation = StorageWorkOperation::Head {
        path: "object".into(),
    };
    request.expected_guard_stamp.physical_authority_id =
        crate::storage_authority::PhysicalStorageAuthorityId::parse(
            "00000000-0000-4000-8000-000000000002",
        )
        .unwrap();
    assert!(request.validate(DEPLOYMENT, 101).is_err());
}

#[test]
fn semantic_binding_writer_and_read_revision_cannot_be_substituted() {
    let mut request = request();
    request.binding_write_revision = LeaseInteger::new(5).unwrap();
    assert!(request.validate(DEPLOYMENT, 101).is_err());
    request.binding_write_revision = LeaseInteger::new(4).unwrap();
    request.plan.credential_references[0].generation = 3;
    assert!(request.validate(DEPLOYMENT, 101).is_err());
    request.plan.credential_references[0].generation = 2;
    request.plan.binding_resource_version = 4;
    assert!(request.validate(DEPLOYMENT, 101).is_err());
}

#[test]
fn semantic_original_deadline_and_profile_commitment_are_required() {
    let mut request = request();
    assert!(request.validate(DEPLOYMENT, 130).is_ok());
    assert!(request.validate(DEPLOYMENT, 131).is_err());
    request.expected_profile_fingerprint.clear();
    assert!(request.validate(DEPLOYMENT, 101).is_err());
}

#[test]
fn semantic_canonical_mac_and_whole_encoding_bounds_are_closed() {
    let key = StorageWorkKey::new(KEY).unwrap();
    let request = request();
    let bytes = serde_json::to_vec_pretty(&request).unwrap();
    let mac = key.sign_body(&bytes).unwrap();
    assert!(
        SemanticExternalObservationRequest::authenticate(&key, &mac, &bytes, DEPLOYMENT, 101)
            .is_err()
    );
    let oversized = vec![b'x'; MAX_SEMANTIC_OBSERVATION_BYTES + 1];
    assert!(SemanticExternalObservationRequest::authenticate(
        &key,
        "not-a-mac",
        &oversized,
        DEPLOYMENT,
        101
    )
    .is_err());
    assert!(encode(
        &"x".repeat(MAX_SEMANTIC_OBSERVATION_BYTES),
        MAX_SEMANTIC_OBSERVATION_BYTES
    )
    .is_err());
    assert!(SemanticExternalObservationRequest::authenticate(
        &key,
        "not-a-mac",
        b"private malformed JSON",
        DEPLOYMENT,
        101
    )
    .is_err());
}

#[test]
fn semantic_current_and_historical_outcomes_preserve_exact_original_request() {
    let key = StorageWorkKey::new(KEY).unwrap();
    let request = request();
    let observed = observation(&request);
    let (bytes, _) = request.sign(&key, DEPLOYMENT, 101).unwrap();
    for outcome in [
        ExternalObservationOutcome::ObservedThisInvocation(observed.clone()),
        ExternalObservationOutcome::HistoricalObservation(observed.clone()),
    ] {
        let reply = SemanticExternalObservationReply::new(&bytes, outcome.clone()).unwrap();
        let (encoded, mac) = reply.sign(&key, &bytes).unwrap();
        let decoded =
            SemanticExternalObservationReply::authenticate(&key, &mac, &encoded, &bytes).unwrap();
        assert!(decoded.outcome == outcome);
    }
    // Reply correlation deliberately has no new permission-time assertion.
    // Recipients apply their original cutoff and live authority after await.
    assert!(request.validate(DEPLOYMENT, 131).is_err());
    assert!(SemanticExternalObservationReply::new(
        &bytes,
        ExternalObservationOutcome::HistoricalObservation(observed)
    )
    .is_ok());
}

#[test]
fn semantic_reply_cannot_bind_another_attempt_or_inner_token_request() {
    let key = StorageWorkKey::new(KEY).unwrap();
    let original = request();
    let (bytes, _) = original.sign(&key, DEPLOYMENT, 101).unwrap();
    let reply = SemanticExternalObservationReply::new(
        &bytes,
        ExternalObservationOutcome::ObservedThisInvocation(observation(&original)),
    )
    .unwrap();
    let (encoded, mac) = reply.sign(&key, &bytes).unwrap();
    let mut other = request();
    other.plan.plan_id = "e".repeat(32);
    let (other_bytes, _) = other.sign(&key, DEPLOYMENT, 101).unwrap();
    assert!(
        SemanticExternalObservationReply::authenticate(&key, &mac, &encoded, &other_bytes).is_err()
    );
    let mut value = observation(&original);
    value.operation_id = "different-observation".into();
    assert!(SemanticExternalObservationReply::new(
        &bytes,
        ExternalObservationOutcome::ObservedThisInvocation(value)
    )
    .is_err());
    let mut value = observation(&original);
    value.guard_stamp.incarnation = crate::storage_authority::GuardIncarnation::parse("3").unwrap();
    assert!(SemanticExternalObservationReply::new(
        &bytes,
        ExternalObservationOutcome::ObservedThisInvocation(value)
    )
    .is_err());
}
