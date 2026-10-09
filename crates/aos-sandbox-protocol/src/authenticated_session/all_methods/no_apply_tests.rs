//! Public authenticated-outcome carrier regressions with shared transport fixtures.

use aos_proto::aos::sandbox::local::v1::{
    Audience, BrokerError, BrokerErrorCode, BrokerMethod, BrokerRequestEnvelope,
    BrokerResponseEnvelope, HostExecutionNoApplyStatusV1, HostNoApplySettlementPhaseV2,
    QueryHostExecutionArgumentNoApplyRequestV1, QueryHostExecutionArgumentNoApplyResponseV1,
    QueryHostExecutionNoApplySettlementRequestV2, QueryHostExecutionNoApplySettlementResponseV2,
    SettleHostExecutionNoApplyRequestV2, TerminalHostExecutionArgumentNoApplyRequestV1,
    TerminalHostExecutionArgumentNoApplyResponseV1,
};
use aos_sandbox_broker_session_protocol::{
    BrokerSessionProtocolV1, authenticated_broker_methods_for_role_v1, decode_canonical_request_v1,
};
use aos_sandbox_core::{ObjectDigest, ProtocolId};
use buffa::Message as _;
use sha2::{Digest as _, Sha256};

use super::{
    AuthenticatedBrokerMethodOutcomeV1, AuthenticatedBrokerMethodRequestV1,
    AuthenticatedBrokerMethodResultV1, AuthenticatedBrokerMethodSemanticsV1,
    AuthenticatedBrokerOutcomeDirectionV1, AuthenticatedBrokerRequestDirectionV1,
    AuthenticatedBrokerSemanticBindingsV1, OUTCOME_SEMANTIC_DOMAIN, RequestOutcomeContextV1,
    method_digest, validate_decoded_request_envelope, validate_decoded_response_envelope,
    validate_request_semantics,
};
use crate::host_execution_no_apply::{
    decode_host_execution_argument_no_apply_request_v1,
    decode_host_execution_argument_query_no_apply_request_v1,
    decode_host_no_apply_settlement_query_request_v2, decode_host_no_apply_settlement_request_v2,
    match_archived_host_no_apply_outcome_v2,
    test_support::{header, peer_policy, record, source},
};

// The production constructor is signed traffic admission. Test-only assembly
// isolates the public carrier's direction, error, and recorded/absent gates.
fn outcome(
    method: BrokerMethod,
    request_body: Vec<u8>,
    context: RequestOutcomeContextV1,
    response_body: Vec<u8>,
) -> AuthenticatedBrokerMethodOutcomeV1 {
    let (peer, policy) = peer_policy();
    let request_id = match &context {
        RequestOutcomeContextV1::HostNoApply(value)
        | RequestOutcomeContextV1::HostNoApplyQuery(value) => *value.header().request_id(),
        RequestOutcomeContextV1::HostNoApplySettlementQuery(value) => *value.header().request_id(),
        _ => panic!("test requires a Host no-Apply context"),
    };
    let envelope = validate_decoded_request_envelope(
        BrokerRequestEnvelope {
            method: method.into(),
            body: request_body.clone(),
            ..Default::default()
        },
        ProtocolId::HostBroker,
        0,
    )
    .unwrap();
    let request = AuthenticatedBrokerMethodRequestV1 {
        direction: AuthenticatedBrokerRequestDirectionV1::ClientSend,
        method,
        semantics: match method {
            BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY => {
                AuthenticatedBrokerMethodSemanticsV1::HostTerminalNoApply
            }
            BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY => {
                AuthenticatedBrokerMethodSemanticsV1::HostQueryNoApply
            }
            BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2 => {
                AuthenticatedBrokerMethodSemanticsV1::HostQueryNoApplySettlement
            }
            _ => panic!("test requires a Host no-Apply method"),
        },
        canonical_packet: vec![1],
        exact_body: request_body,
        semantic_commitment: [1; 32],
        catalog_binding: None,
        published_catalog_binding: None,
        peer,
        peer_policy: policy,
        session_binding: [14; 32],
        request_id,
        client_sequence: 1,
        maximum_response_bytes: 8192,
        deadline_boottime_nanoseconds: 100,
        signed_request_digest: [15; 32],
        envelope,
        outcome_context: context,
    };
    AuthenticatedBrokerMethodOutcomeV1 {
        direction: AuthenticatedBrokerOutcomeDirectionV1::ClientReceive,
        method,
        canonical_packet: vec![2],
        request,
        broker_sequence: 1,
        result: AuthenticatedBrokerMethodResultV1::Success {
            semantic_commitment: method_digest(OUTCOME_SEMANTIC_DOMAIN, method, &response_body),
            exact_body: response_body,
            filesystem_worker_qualification_commitment: None,
        },
    }
}

#[test]
fn methods42_and43_reject_unsigned_packets() {
    for method in [
        BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2,
        BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2,
    ] {
        let unsigned = BrokerRequestEnvelope {
            method: method.into(),
            body: vec![1],
            ..Default::default()
        };
        assert!(decode_canonical_request_v1(&unsigned.encode_to_vec()).is_err());
    }
}

#[test]
fn method42_semantic_admission_rejects_later_controller_phases() {
    let (peer, policy) = peer_policy();
    let mut request = SettleHostExecutionNoApplyRequestV2 {
        header: Some(header([11; 16])).into(),
        canonical_attempt: source().to_vec(),
        original_session_binding: vec![12; 32],
        original_signed_request_digest: vec![13; 32],
        archive_head: vec![10; 32],
        signed_terminal_outcome: vec![11; 32],
        phase: HostNoApplySettlementPhaseV2::HOST_NO_APPLY_SETTLEMENT_PHASE_PRELIMINARY.into(),
        challenge: vec![9; 16],
        ..Default::default()
    };
    let admit = |request: &SettleHostExecutionNoApplyRequestV2| {
        validate_request_semantics(
            BrokerMethod::BROKER_METHOD_HOST_SETTLE_NO_APPLY_V2,
            &request.encode_to_vec(),
            &[],
            peer,
            policy,
            99,
            AuthenticatedBrokerSemanticBindingsV1::default(),
        )
    };

    assert!(admit(&request).is_ok());
    request.phase =
        HostNoApplySettlementPhaseV2::HOST_NO_APPLY_SETTLEMENT_PHASE_FLOOR_SEALED.into();
    request.canonical_controller_coordinate = vec![20; 32];
    assert!(admit(&request).is_err());

    let mut ack = [0; 156];
    ack[..8].copy_from_slice(b"AOSCFA01");
    ack[8..10].copy_from_slice(&1_u16.to_be_bytes());
    ack[12..28].copy_from_slice(&source()[24..40]);
    ack[28..60].fill(3);
    ack[60..92].fill(20);
    ack[92..124].fill(21);
    let checksum = Sha256::new()
        .chain_update(b"aos.sandbox.create-failure-settlement-ack.v1\0")
        .chain_update(&ack[..124])
        .finalize();
    ack[124..].copy_from_slice(&checksum);
    request.phase =
        HostNoApplySettlementPhaseV2::HOST_NO_APPLY_SETTLEMENT_PHASE_ACK_RETAINED.into();
    request.canonical_controller_coordinate = ack.to_vec();
    assert!(
        decode_host_no_apply_settlement_request_v2(&request.encode_to_vec(), peer, policy, 99)
            .is_ok()
    );
    assert!(admit(&request).is_err());
}

#[test]
fn method42_archive_matcher_binds_exact_signed_terminal_and_h_head() {
    let source = source();
    let terminal = TerminalHostExecutionArgumentNoApplyRequestV1 {
        header: Some(header([9; 16])).into(),
        canonical_attempt: source.to_vec(),
        original_session_binding: vec![12; 32],
        original_signed_request_digest: vec![13; 32],
        ..Default::default()
    };
    let (peer, policy) = peer_policy();
    let context = RequestOutcomeContextV1::HostNoApply(
        decode_host_execution_argument_no_apply_request_v1(
            &terminal.encode_to_vec(),
            peer,
            policy,
            99,
        )
        .unwrap(),
    );
    let marker = record(&source);
    let outcome = outcome(
        BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY,
        terminal.encode_to_vec(),
        context,
        TerminalHostExecutionArgumentNoApplyResponseV1 {
            canonical_record: marker.encode_canonical().to_vec(),
            ..Default::default()
        }
        .encode_to_vec(),
    );
    let signed_digest: [u8; 32] = Sha256::digest(outcome.canonical_packet()).into();
    let settle = SettleHostExecutionNoApplyRequestV2 {
        header: Some(header([11; 16])).into(),
        canonical_attempt: source.to_vec(),
        original_session_binding: vec![12; 32],
        original_signed_request_digest: vec![13; 32],
        archive_head: vec![10; 32],
        signed_terminal_outcome: signed_digest.to_vec(),
        phase: HostNoApplySettlementPhaseV2::HOST_NO_APPLY_SETTLEMENT_PHASE_PRELIMINARY.into(),
        challenge: vec![9; 16],
        ..Default::default()
    };
    let request =
        decode_host_no_apply_settlement_request_v2(&settle.encode_to_vec(), peer, policy, 99)
            .unwrap();
    assert_eq!(
        match_archived_host_no_apply_outcome_v2(
            &request,
            ObjectDigest::from_bytes([10; 32]),
            &outcome,
        )
        .unwrap(),
        marker
    );
    assert!(
        match_archived_host_no_apply_outcome_v2(
            &request,
            ObjectDigest::from_bytes([11; 32]),
            &outcome,
        )
        .is_err()
    );
    let mut changed_outcome = outcome;
    changed_outcome.canonical_packet.push(3);
    assert!(
        match_archived_host_no_apply_outcome_v2(
            &request,
            ObjectDigest::from_bytes([10; 32]),
            &changed_outcome,
        )
        .is_err()
    );
}

#[test]
fn one_shot_host_envelopes_are_structural_only_and_not_in_production_hello() {
    let advertised = authenticated_broker_methods_for_role_v1(
        BrokerSessionProtocolV1::Host,
        Audience::AUDIENCE_NODE_CONTROLLER,
    );
    for method in [
        BrokerMethod::BROKER_METHOD_HOST_OBSERVE_EXECUTION_ARGUMENT,
        BrokerMethod::BROKER_METHOD_HOST_QUERY_EXECUTION_ARGUMENT,
        BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY,
        BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY,
    ] {
        let envelope = BrokerRequestEnvelope {
            method: method.into(),
            body: vec![1],
            ..Default::default()
        };
        assert!(
            validate_decoded_request_envelope(envelope.clone(), ProtocolId::HostBroker, 0).is_ok()
        );
        assert!(validate_decoded_request_envelope(envelope, ProtocolId::MountBroker, 0).is_err());
        assert!(!advertised.contains(&method));
    }
}

#[test]
fn recorded_method39_carrier_keeps_outcome_and_rejects_changed_identity() {
    let source = source();
    let request = TerminalHostExecutionArgumentNoApplyRequestV1 {
        header: Some(header([9; 16])).into(),
        canonical_attempt: source.to_vec(),
        original_session_binding: vec![12; 32],
        original_signed_request_digest: vec![13; 32],
        ..Default::default()
    };
    let body = request.encode_to_vec();
    let (peer, policy) = peer_policy();
    let context = RequestOutcomeContextV1::HostNoApply(
        decode_host_execution_argument_no_apply_request_v1(&body, peer, policy, 99).unwrap(),
    );
    let marker = record(&source);
    let response = TerminalHostExecutionArgumentNoApplyResponseV1 {
        canonical_record: marker.encode_canonical().to_vec(),
        ..Default::default()
    };
    let method = BrokerMethod::BROKER_METHOD_HOST_TERMINAL_NO_APPLY;
    let mut admitted = outcome(method, body, context, response.encode_to_vec());

    let readback = admitted.recorded_host_no_apply().unwrap().unwrap();
    assert_eq!(*readback.record(), marker);
    assert!(std::ptr::eq(readback.outcome(), &admitted));

    admitted.direction = AuthenticatedBrokerOutcomeDirectionV1::ServerSend;
    assert!(admitted.recorded_host_no_apply().is_err());
    admitted.direction = AuthenticatedBrokerOutcomeDirectionV1::ClientReceive;
    admitted.request.signed_request_digest = [19; 32];
    assert!(admitted.recorded_host_no_apply().is_err());
    admitted.request.signed_request_digest = [15; 32];
    if let AuthenticatedBrokerMethodResultV1::Success {
        semantic_commitment,
        ..
    } = &mut admitted.result
    {
        *semantic_commitment = [20; 32];
    }
    assert!(admitted.recorded_host_no_apply().is_err());
}

#[test]
fn method40_absent_and_terminal_error_never_yield_a_recorded_carrier() {
    let source = source();
    let request = QueryHostExecutionArgumentNoApplyRequestV1 {
        header: Some(header([10; 16])).into(),
        canonical_attempt: source.to_vec(),
        original_session_binding: vec![12; 32],
        original_signed_request_digest: vec![13; 32],
        ..Default::default()
    };
    let body = request.encode_to_vec();
    let (peer, policy) = peer_policy();
    let context = RequestOutcomeContextV1::HostNoApplyQuery(
        decode_host_execution_argument_query_no_apply_request_v1(&body, peer, policy, 99).unwrap(),
    );
    let absent = QueryHostExecutionArgumentNoApplyResponseV1 {
        status: HostExecutionNoApplyStatusV1::HOST_EXECUTION_NO_APPLY_STATUS_ABSENT.into(),
        ..Default::default()
    };
    let method = BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY;
    let mut admitted = outcome(method, body, context, absent.encode_to_vec());
    assert!(admitted.recorded_host_no_apply().unwrap().is_none());

    let marker = record(&source);
    let recorded = QueryHostExecutionArgumentNoApplyResponseV1 {
        status: HostExecutionNoApplyStatusV1::HOST_EXECUTION_NO_APPLY_STATUS_RECORDED.into(),
        canonical_record: marker.encode_canonical().to_vec(),
        ..Default::default()
    };
    admitted.result = AuthenticatedBrokerMethodResultV1::Success {
        exact_body: recorded.encode_to_vec(),
        semantic_commitment: method_digest(
            OUTCOME_SEMANTIC_DOMAIN,
            method,
            &recorded.encode_to_vec(),
        ),
        filesystem_worker_qualification_commitment: None,
    };
    assert_eq!(
        *admitted.recorded_host_no_apply().unwrap().unwrap().record(),
        marker
    );

    let error = validate_decoded_response_envelope(
        BrokerResponseEnvelope {
            request_id: vec![10; 16],
            method: method.into(),
            error: Some(BrokerError {
                code: BrokerErrorCode::BROKER_ERROR_CODE_INVALID_REQUEST.into(),
                safe_message: "rejected".to_owned(),
                ..Default::default()
            })
            .into(),
            ..Default::default()
        },
        &[10; 16],
        method,
        &[],
        0,
    )
    .unwrap()
    .error()
    .unwrap()
    .clone();
    admitted.result = AuthenticatedBrokerMethodResultV1::Error(error);
    assert!(admitted.recorded_host_no_apply().unwrap().is_none());
}

#[test]
fn method43_signed_cold_query_carrier_rejects_changed_status_and_commitment() {
    let request = QueryHostExecutionNoApplySettlementRequestV2 {
        header: Some(header([10; 16])).into(),
        canonical_attempt: source().to_vec(),
        original_session_binding: vec![12; 32],
        original_signed_request_digest: vec![13; 32],
        ..Default::default()
    };
    let body = request.encode_to_vec();
    let (peer, policy) = peer_policy();
    assert!(
        validate_request_semantics(
            BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2,
            &body,
            &[],
            peer,
            policy,
            99,
            AuthenticatedBrokerSemanticBindingsV1::default(),
        )
        .is_ok()
    );
    let context = RequestOutcomeContextV1::HostNoApplySettlementQuery(
        decode_host_no_apply_settlement_query_request_v2(&body, peer, policy, 99).unwrap(),
    );
    let response = QueryHostExecutionNoApplySettlementResponseV2 {
        status: aos_proto::aos::sandbox::local::v1::HostNoApplySettlementStatusV2::HOST_NO_APPLY_SETTLEMENT_STATUS_ABSENT.into(),
        ..Default::default()
    };
    let method = BrokerMethod::BROKER_METHOD_HOST_QUERY_NO_APPLY_SETTLEMENT_V2;
    let mut admitted = outcome(method, body, context, response.encode_to_vec());

    assert_eq!(
        admitted
            .recorded_host_no_apply_settlement_history()
            .unwrap()
            .unwrap()
            .stages(),
        &[None, None, None]
    );

    admitted.direction = AuthenticatedBrokerOutcomeDirectionV1::ServerSend;
    assert!(
        admitted
            .recorded_host_no_apply_settlement_history()
            .is_err()
    );
    admitted.direction = AuthenticatedBrokerOutcomeDirectionV1::ClientReceive;
    if let AuthenticatedBrokerMethodResultV1::Success {
        semantic_commitment,
        ..
    } = &mut admitted.result
    {
        *semantic_commitment = [20; 32];
    }
    assert!(
        admitted
            .recorded_host_no_apply_settlement_history()
            .is_err()
    );

    let invalid = QueryHostExecutionNoApplySettlementResponseV2 {
        status: aos_proto::aos::sandbox::local::v1::HostNoApplySettlementStatusV2::HOST_NO_APPLY_SETTLEMENT_STATUS_PRELIMINARY.into(),
        ..Default::default()
    };
    admitted.result = AuthenticatedBrokerMethodResultV1::Success {
        semantic_commitment: method_digest(
            OUTCOME_SEMANTIC_DOMAIN,
            method,
            &invalid.encode_to_vec(),
        ),
        exact_body: invalid.encode_to_vec(),
        filesystem_worker_qualification_commitment: None,
    };
    assert!(
        admitted
            .recorded_host_no_apply_settlement_history()
            .is_err()
    );
}
