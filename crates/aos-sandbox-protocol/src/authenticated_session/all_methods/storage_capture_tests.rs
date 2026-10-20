//! Checks physical Capture taxonomy, body binding and outcome correlation.

use super::*;
use buffa::Message as _;
use aos_proto::aos::sandbox::local::v1::{
    Audience, QueryStorageExecutionCaptureRequestV1, RequestHeader,
    ReserveStorageExecutionCaptureRequestV1, StorageExecutionCaptureAttemptStatusV1,
    StorageExecutionCaptureAttemptV1,
};
use crate::storage_capture_grant::{
    StorageCaptureGrantMethodV1, StorageCaptureGrantSourceV2,
    STORAGE_CAPTURE_GRANT_SOURCE_BYTES_V2,
};

const RESERVE: BrokerMethod = BrokerMethod::BROKER_METHOD_STORAGE_RESERVE_EXECUTION_CAPTURE_V1;
const QUERY: BrokerMethod = BrokerMethod::BROKER_METHOD_STORAGE_QUERY_EXECUTION_CAPTURE_V1;

fn source_bytes() -> [u8; STORAGE_CAPTURE_GRANT_SOURCE_BYTES_V2] {
    *crate::storage_capture_grant::tests::ongoing_source_data().canonical_bytes_v2()
}

fn request(method: BrokerMethod, request_id: u8, deadline: u64) -> Vec<u8> {
    let header = RequestHeader {
        protocol_major: 1,
        request_id: vec![request_id; 16],
        audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
        deadline_boottime_nanoseconds: deadline,
        maximum_response_bytes: 8192,
        ..Default::default()
    };
    if method == RESERVE {
        ReserveStorageExecutionCaptureRequestV1 {
            header: Some(header).into(), canonical_grant_source: source_bytes().to_vec(),
            canonical_original_storage_output_request: crate::storage_capture_grant::tests::original_body(),
            ..Default::default()
        }.encode_to_vec()
    } else {
        QueryStorageExecutionCaptureRequestV1 {
            header: Some(header).into(), canonical_grant_source: source_bytes().to_vec(),
            ..Default::default()
        }.encode_to_vec()
    }
}

fn semantic(method: BrokerMethod, body: &[u8], now: u64)
    -> Result<ValidatedRequestSemanticV1, AuthenticatedBrokerMethodErrorV1>
{
    validate_request_semantics(method, body, &[],
        PeerCredentials { uid: 0, gid: 0, pid: Some(9) },
        PeerPolicy { uid: 0, gid: Some(0), audience: Audience::AUDIENCE_NODE_CONTROLLER },
        now, AuthenticatedBrokerSemanticBindingsV1::default())
}

fn response(absent: bool) -> StorageExecutionCaptureAttemptV1 {
    let source = StorageCaptureGrantSourceV2::from_canonical_bytes_v2(&source_bytes()).unwrap();
    let locator = source.locator_v2();
    StorageExecutionCaptureAttemptV1 {
        status: if absent {
            StorageExecutionCaptureAttemptStatusV1::STORAGE_EXECUTION_CAPTURE_ATTEMPT_STATUS_ABSENT
        } else {
            StorageExecutionCaptureAttemptStatusV1::STORAGE_EXECUTION_CAPTURE_ATTEMPT_STATUS_EFFECT_POSSIBLE
        }.into(),
        execution_id: locator.execution().as_bytes().to_vec(),
        create_operation_id: locator.create_operation().as_bytes().to_vec(),
        original_reserve_request_id: locator.original_reserve_request_id().to_vec(),
        grant_source_digest: locator.source_digest().as_bytes().to_vec(),
        output_record_digest: locator.output_record_digest().as_bytes().to_vec(),
        attempt_id: if absent { Vec::new() } else { vec![23; 16] },
        durable_attempt_digest: if absent { Vec::new() } else { vec![24; 32] },
        effective_deadline_boottime_nanoseconds: if absent { 0 } else { source.effective_execution_deadline_v2() },
        ..Default::default()
    }
}

#[test]
fn registered_physical_methods_require_distinct_signed_authority_and_remain_unadvertised() {
    use aos_sandbox_broker_session_protocol::{
        BrokerSessionAuthorizationPresenceV1, BrokerSessionProtocolV1,
        authenticated_broker_methods_for_role_v1,
    };
    use aos_sandbox_core::BrokerVerb;

    let source = StorageCaptureGrantSourceV2::from_canonical_bytes_v2(&source_bytes()).unwrap();
    for (method, kind, id, verb) in [
        (RESERVE, StorageCaptureGrantMethodV1::Reserve, [17; 16], BrokerVerb::StorageReserveExecutionCapture),
        (QUERY, StorageCaptureGrantMethodV1::Query, [18; 16], BrokerVerb::StorageQueryExecutionCapture),
    ] {
        let profile = authenticated_broker_method_profile_v1(method).unwrap();
        assert_eq!(profile.protocol(), BrokerSessionProtocolV1::Storage);
        assert_eq!(profile.audience(), Audience::AUDIENCE_NODE_CONTROLLER);
        assert_eq!(profile.authorization(), BrokerSessionAuthorizationPresenceV1::Required);
        assert!(profile.request_descriptor_roles().is_empty());
        assert!(profile.success_response_descriptor_roles().is_empty());
        assert!(!authenticated_broker_methods_for_role_v1(profile.protocol(), profile.audience()).contains(&method));
        assert_eq!(source.broker_grant_v2(kind, id).unwrap().verb(), verb);
        assert_ne!(verb, BrokerVerb::StorageReserveExecutionOutput);
        assert_ne!(verb, BrokerVerb::StorageQueryExecutionOutput);
        assert!(crate::session::encode_unauthed_request_envelope(
            aos_sandbox_core::ProtocolId::StorageBroker, method, b"not authority").is_err());
    }
    assert_eq!(RESERVE as i32, 60);
    assert_eq!(QUERY as i32, 61);
}

#[test]
fn request_context_commits_full_source_and_refuses_reserve_query_aliases() {
    let reserve = semantic(RESERVE, &request(RESERVE, 17, 100), 99).unwrap();
    // Historical Query keeps its original expired reserve source, but has a
    // fresh request ID/deadline and cannot renew or repeat that Reserve.
    let query = semantic(QUERY, &request(QUERY, 18, 200), 150).unwrap();
    // A fresh read-only request may report terminal facts after the immutable
    // execution bound; it cannot mint a new Reserve or change that bound.
    assert!(semantic(QUERY, &request(QUERY, 18, 2000), 1500).is_ok());

    let source = StorageCaptureGrantSourceV2::from_canonical_bytes_v2(&source_bytes()).unwrap();

    assert_eq!(reserve.kind, AuthenticatedBrokerMethodSemanticsV1::StorageReserveExecutionCapture);
    assert_eq!(query.kind, AuthenticatedBrokerMethodSemanticsV1::StorageQueryExecutionCapture);
    assert_eq!(reserve.commitment, *source.argument_commitment_v2(StorageCaptureGrantMethodV1::Reserve, [17; 16]).unwrap().digest().as_bytes());
    assert_eq!(query.commitment, *source.argument_commitment_v2(StorageCaptureGrantMethodV1::Query, [18; 16]).unwrap().digest().as_bytes());
    assert_ne!(reserve.commitment, query.commitment);
    assert!(matches!(reserve.outcome_context, RequestOutcomeContextV1::StorageCaptureReserve(_)));
    assert!(matches!(query.outcome_context, RequestOutcomeContextV1::StorageCaptureQuery(_)));
    assert!(semantic(QUERY, &request(RESERVE, 17, 100), 99).is_err());
    assert!(semantic(RESERVE, &request(QUERY, 18, 200), 99).is_err());
    assert!(semantic(RESERVE, &request(RESERVE, 17, 100), 101).is_err());

    let mut unknown = request(RESERVE, 17, 100);
    unknown.extend_from_slice(&[0x98, 0x06, 1]);
    assert!(semantic(RESERVE, &unknown, 99).is_err());
}

#[test]
fn outcome_uses_exact_original_locator_and_only_query_can_report_absence() {
    let reserve = semantic(RESERVE, &request(RESERVE, 17, 100), 99).unwrap();
    let query = semantic(QUERY, &request(QUERY, 18, 200), 150).unwrap();
    let absent = response(true).encode_to_vec();
    let possible = response(false).encode_to_vec();

    assert!(validate_storage_capture_response(RESERVE, &reserve.outcome_context, &absent).is_err());
    assert!(validate_storage_capture_response(QUERY, &query.outcome_context, &absent).is_ok());
    assert!(validate_storage_capture_response(RESERVE, &reserve.outcome_context, &possible).is_ok());
    assert!(validate_storage_capture_response(QUERY, &query.outcome_context, &possible).is_ok());
    assert!(validate_storage_capture_response(RESERVE, &query.outcome_context, &possible).is_err());

    let mut foreign = response(false);
    foreign.output_record_digest[0] ^= 1;
    for (method, context) in [(RESERVE, &reserve.outcome_context), (QUERY, &query.outcome_context)] {
        assert!(validate_storage_capture_response(method, context, &foreign.encode_to_vec()).is_err());
    }
}
