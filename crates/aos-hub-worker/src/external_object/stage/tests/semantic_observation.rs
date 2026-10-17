//! Exact issuer-domain selection and original-request reply-binding regressions.

use aos_hub_core::storage_authority::external_object::observation::{
    semantic::{SemanticExternalObservationReply, SemanticExternalObservationRequest},
    ExternalObservation, ExternalObservationOutcome, ExternalObservationReply,
    ExternalObservationRequest, ObservationExpectation, OBSERVATION_APPLICATION_DOMAIN,
};

use super::super::super::observation::reply::ReplyBinding;
use super::*;

fn semantic() -> SemanticExternalObservationRequest {
    serde_json::from_str(include_str!(
        "../../../../../aos-hub-core/src/storage_authority/external_object/observation/semantic/tests/fixture.json"
    )).unwrap()
}

#[test]
fn configured_read_issuer_domain_cannot_be_missing_or_ambiguous() {
    let object = config();
    let context = context(&object, 1);
    let mut stage = staging(&object, &context);
    let read = object.cohorts[1].clone();
    assert!(stage.observation_domain(&read).is_ok());
    let mut foreign = read.clone();
    foreign.credential.generation = LeaseInteger::new(99).unwrap();
    assert!(stage.observation_domain(&foreign).is_err());
    stage.domains.push(stage.domains[0].clone());
    assert!(stage.observation_domain(&read).is_err());
}

#[test]
fn semantic_reply_requires_exact_selected_cohort_and_original_bytes() {
    let key = StorageWorkKey::new(b"semantic-worker-reply-binding-test-key").unwrap();
    let semantic = semantic();
    let (bytes, _) = semantic
        .sign(&key, "observation-native-fixture", 101)
        .unwrap();
    let object = config();
    let read = &object.cohorts[1];
    let binding = ReplyBinding::Semantic {
        bytes: &bytes,
        cohort: read,
    };
    assert!(binding.validate_cohort(read).is_ok());
    assert!(binding.validate_cohort(&object.cohorts[0]).is_err());
    let outcome = ExternalObservationOutcome::ObservedThisInvocation(ExternalObservation {
        operation_id: semantic.operation_id.clone(),
        intent_digest: "b".repeat(64),
        turn_digest: "c".repeat(64),
        guard_stamp: semantic.expected_guard_stamp.clone(),
        observed_at: "101".into(),
        object: None,
    });
    let (reply, mac) = binding.sign(&key, outcome.clone()).unwrap();
    let decoded =
        SemanticExternalObservationReply::authenticate(&key, &mac, &reply, &bytes).unwrap();
    assert!(decoded.outcome == outcome);
    let mut other = semantic;
    other.plan.plan_id = "e".repeat(32);
    let (other, _) = other.sign(&key, "observation-native-fixture", 101).unwrap();
    assert!(SemanticExternalObservationReply::authenticate(&key, &mac, &reply, &other).is_err());
}

#[test]
fn existing_observation_reply_bytes_and_mac_remain_identical() {
    let key = StorageWorkKey::new(b"semantic-worker-reply-binding-test-key").unwrap();
    let semantic = semantic();
    let request = ExternalObservationRequest {
        version: 1,
        domain: OBSERVATION_APPLICATION_DOMAIN.into(),
        authorization: aos_hub_core::storage_authority::external_object::ExternalObjectRequest {
            version: 1,
            domain:
                aos_hub_core::storage_authority::external_object::EXTERNAL_OBJECT_APPLICATION_DOMAIN
                    .into(),
            operation_id: semantic.operation_id,
            binding_write_revision: semantic.binding_write_revision,
            plan: semantic.plan,
            lease: "fixture-only".into(),
        },
        expectation: ObservationExpectation::KnownStamp {
            stamp: semantic.expected_guard_stamp.clone(),
        },
    };
    let (bytes, _) = request
        .sign(&key, "observation-native-fixture", 101)
        .unwrap();
    let outcome = ExternalObservationOutcome::HistoricalObservation(ExternalObservation {
        operation_id: request.authorization.operation_id.clone(),
        intent_digest: "b".repeat(64),
        turn_digest: "c".repeat(64),
        guard_stamp: semantic.expected_guard_stamp,
        observed_at: "101".into(),
        object: None,
    });
    let original = ExternalObservationReply::new(&bytes, outcome.clone())
        .unwrap()
        .sign(&key, &bytes)
        .unwrap();
    let extracted = ReplyBinding::Existing(&bytes).sign(&key, outcome).unwrap();
    assert_eq!(extracted, original);
}

#[test]
fn semantic_begin_checks_original_app_and_snapshot_after_control_cpu() {
    let object = config();
    let semantic = semantic();
    let binding = ReplyBinding::Semantic {
        bytes: &[],
        cohort: &object.cohorts[1],
    };
    let mut work = super::super::super::tests::application();
    work.plan.issued_at = 100;
    work.plan.expires_at = 130;
    let mut snapshot = super::super::super::tests::snapshot(&object);
    snapshot.issued_at = 100;
    snapshot.expires_at = 140;
    assert!(binding.check_begin_time(&work, &snapshot, 130).is_ok());
    assert!(binding.check_begin_time(&work, &snapshot, 131).is_err());
    work.plan.expires_at = 150;
    assert!(binding.check_begin_time(&work, &snapshot, 141).is_err());
    assert!(binding.check_begin_time(&work, &snapshot, 94).is_err());
    assert!(ReplyBinding::Existing(&[])
        .check_begin_time(&work, &snapshot, 141)
        .is_ok());
    assert_eq!(semantic.plan.expires_at, 130);
}
