//! Authenticated Host no-Apply marker extraction regressions.

use aos_proto::aos::sandbox::local::v1::{
    Audience, HostExecutionNoApplyStatusV1, QueryHostExecutionArgumentNoApplyRequestV1,
    QueryHostExecutionArgumentNoApplyResponseV1, RequestHeader,
    TerminalHostExecutionArgumentNoApplyRequestV1, TerminalHostExecutionArgumentNoApplyResponseV1,
};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use super::{RequestOutcomeContextV1, decode_recorded_host_no_apply};
use crate::host_execution_no_apply::{
    HostExecutionNoApplyRecordFieldsV1, HostExecutionNoApplyRecordV1,
    decode_host_execution_argument_no_apply_request_v1,
    decode_host_execution_argument_query_no_apply_request_v1,
};
use crate::{PeerCredentials, PeerPolicy};

fn original_attempt() -> [u8; 336] {
    let mut source = [0; 336];
    source[..8].copy_from_slice(b"AOSCIA02");
    source[8..24].copy_from_slice(&[1; 16]);
    source[24..40].copy_from_slice(&[2; 16]);
    source[40..56].copy_from_slice(&[7; 16]);
    source[56..184].fill(3);
    source[184..216].copy_from_slice(&[5; 32]);
    source[216..248].fill(6);
    source[248..264].copy_from_slice(&[8; 16]);
    source[264..296].fill(9);
    source[296..304].copy_from_slice(&1_u64.to_be_bytes());
    let checksum = Sha256::new()
        .chain_update(b"aos.sandbox.controller-argument-attempt.v1\0")
        .chain_update(&source[..304])
        .finalize();
    source[304..].copy_from_slice(&checksum);
    source
}

fn header(request_id: [u8; 16]) -> RequestHeader {
    RequestHeader {
        protocol_major: 1,
        request_id: request_id.to_vec(),
        audience: Audience::AUDIENCE_NODE_CONTROLLER.into(),
        deadline_boottime_nanoseconds: 100,
        maximum_response_bytes: 8192,
        ..Default::default()
    }
}

fn peer_policy() -> (PeerCredentials, PeerPolicy) {
    (
        PeerCredentials {
            uid: 0,
            gid: 0,
            pid: Some(9),
        },
        PeerPolicy {
            uid: 0,
            gid: Some(0),
            audience: Audience::AUDIENCE_NODE_CONTROLLER,
        },
    )
}

fn marker(source: &[u8; 336]) -> HostExecutionNoApplyRecordV1 {
    HostExecutionNoApplyRecordV1::new(HostExecutionNoApplyRecordFieldsV1 {
        execution_id: [1; 16],
        create_operation_id: [2; 16],
        original_request_id: [7; 16],
        terminal_request_id: [9; 16],
        host_boot_id: [8; 16],
        assignment_digest: [5; 32],
        source_record_digest: source[304..336].try_into().unwrap(),
        original_session_binding: [12; 32],
        original_signed_request_digest: [13; 32],
        terminal_session_binding: [14; 32],
        terminal_signed_request_digest: [15; 32],
        runtime_handle: [16; 32],
        execution_store_binding: [17; 32],
        commit_sequence: 18,
    })
    .unwrap()
}

#[test]
fn method39_extraction_requires_exact_signed_current_identity() {
    let source = original_attempt();
    let (peer, policy) = peer_policy();
    let request = TerminalHostExecutionArgumentNoApplyRequestV1 {
        header: Some(header([9; 16])).into(),
        canonical_attempt: source.to_vec(),
        original_session_binding: vec![12; 32],
        original_signed_request_digest: vec![13; 32],
        ..Default::default()
    };
    let context = RequestOutcomeContextV1::HostNoApply(
        decode_host_execution_argument_no_apply_request_v1(
            &request.encode_to_vec(),
            peer,
            policy,
            99,
        )
        .unwrap(),
    );
    let record = marker(&source);
    let response = TerminalHostExecutionArgumentNoApplyResponseV1 {
        canonical_record: record.encode_canonical().to_vec(),
        ..Default::default()
    };

    assert_eq!(
        decode_recorded_host_no_apply(
            aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY,
            &context,
            &response.encode_to_vec(),
            [14; 32],
            [15; 32],
        ),
        Ok(Some(record)),
    );
    assert!(
        decode_recorded_host_no_apply(
            aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY,
            &context,
            &response.encode_to_vec(),
            [14; 32],
            [19; 32],
        )
        .is_err()
    );
    assert!(
        decode_recorded_host_no_apply(
            aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY,
            &context,
            &response.encode_to_vec(),
            [14; 32],
            [15; 32],
        )
        .is_err()
    );
}

#[test]
fn method40_absence_never_extracts_a_recorded_marker() {
    let source = original_attempt();
    let (peer, policy) = peer_policy();
    let request = QueryHostExecutionArgumentNoApplyRequestV1 {
        header: Some(header([10; 16])).into(),
        canonical_attempt: source.to_vec(),
        original_session_binding: vec![12; 32],
        original_signed_request_digest: vec![13; 32],
        ..Default::default()
    };
    let context = RequestOutcomeContextV1::HostNoApplyQuery(
        decode_host_execution_argument_query_no_apply_request_v1(
            &request.encode_to_vec(),
            peer,
            policy,
            99,
        )
        .unwrap(),
    );
    let absent = QueryHostExecutionArgumentNoApplyResponseV1 {
        status: HostExecutionNoApplyStatusV1::HOST_EXECUTION_NO_APPLY_STATUS_ABSENT.into(),
        ..Default::default()
    };
    let method =
        aos_proto::aos::sandbox::local::v1::BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY;

    assert_eq!(
        decode_recorded_host_no_apply(
            method,
            &context,
            &absent.encode_to_vec(),
            [14; 32],
            [15; 32]
        ),
        Ok(None),
    );
    let record = marker(&source);
    let recorded = QueryHostExecutionArgumentNoApplyResponseV1 {
        status: HostExecutionNoApplyStatusV1::HOST_EXECUTION_NO_APPLY_STATUS_RECORDED.into(),
        canonical_record: record.encode_canonical().to_vec(),
        ..Default::default()
    };
    assert_eq!(
        decode_recorded_host_no_apply(
            method,
            &context,
            &recorded.encode_to_vec(),
            [14; 32],
            [15; 32],
        ),
        Ok(Some(record)),
    );
    let mut invalid_absent = absent;
    invalid_absent.canonical_record = record.encode_canonical().to_vec();
    assert!(
        decode_recorded_host_no_apply(
            method,
            &context,
            &invalid_absent.encode_to_vec(),
            [14; 32],
            [15; 32],
        )
        .is_err()
    );
}
