//! Exercises explicit state8 framing and its distinct public residual meaning.

use super::*;
use crate::domain_ledger::operation::{OperationRecord, decode_operation, encode_operation_record};

fn metadata(method: PublicOperationMethodV1) -> DurablePublicOperationV1 {
    DurablePublicOperationV1 {
        method,
        recovery_kind: PublicRecoveryKindV1::Ordinary,
        accepted_generation: 1,
        observation_sequence: 1,
        audit_id: [1; 16],
        accepted_wall_seconds: 100,
        last_reconciliation_wall_seconds: 100,
        completed_wall_seconds: None,
    }
}

#[test]
fn closed_state_eight_projects_cleanup_and_round_trips_canonical_stop() {
    let state = OperationState::CommittedWithResidualCleanup;
    let public = metadata(PublicOperationMethodV1::StopSandbox).advance(state, 101).unwrap();
    let record = OperationRecord::new(state, 1, false, None, Some(public));
    let bytes = encode_operation_record(record);

    assert_eq!(bytes[0..4], [2, 8, 2, 0]);
    assert_eq!(decode_operation(&bytes).unwrap(), record);
    let projected = public.project(OperationId::from_bytes([2; 16]), state,
        1, 1, true, false, &bytes, &[b"actual matching terminal Effect"]);
    assert_eq!(projected.phase.as_known(), Some(OperationPhase::OPERATION_PHASE_COMMITTED_WITH_RESIDUAL_CLEANUP));
    assert_eq!(projected.progress.as_option().unwrap().milestone, "cleanup");
    assert_eq!(projected.retry_class.as_known(), Some(RetryClass::RETRY_CLASS_AFTER_STATE_CHANGE));
    assert!(!projected.cancelable);
    crate::public_api::CheckedOperationResourceV1::try_from(projected.clone()).unwrap();
    for replacement in 0..3 {
        let mut changed = projected.clone();
        match replacement {
            0 => changed.method = PublicOperationMethodV1::StartSandbox.as_str().to_owned(),
            1 => changed.retry_class = RetryClass::RETRY_CLASS_NEVER.into(),
            _ => changed.cancelable = true,
        }
        assert!(crate::public_api::CheckedOperationResourceV1::try_from(changed).is_err());
    }
}

#[test]
fn state_eight_never_adopts_an_internal_other_method_or_gated_graph() {
    let state = OperationState::CommittedWithResidualCleanup;
    let public = metadata(PublicOperationMethodV1::StopSandbox).advance(state, 101).unwrap();
    for record in [
        OperationRecord::new(state, 1, false, None, None),
        OperationRecord::new(state, 2, false, None, Some(public)),
        OperationRecord::new(state, 1, true, None, Some(public)),
    ] {
        assert!(decode_operation(&encode_operation_record(record)).is_err());
    }
    assert!(metadata(PublicOperationMethodV1::StartSandbox).advance(state, 101).is_err());
    let mut bytes = encode_operation_record(OperationRecord::new(state, 1, false, None, Some(public)));
    bytes[40] = public_operation_method_record_code_v1(PublicOperationMethodV1::StartSandbox);
    assert!(decode_operation(&bytes).is_err());
    bytes[1] = 9;
    assert!(decode_operation(&bytes).is_err());
}

#[test]
fn every_established_state_code_keeps_its_original_wire_discriminant() {
    let states = [OperationState::Accepted, OperationState::Applying, OperationState::Succeeded,
        OperationState::PermanentlyBlocked, OperationState::OwnershipPending,
        OperationState::CanceledBeforeCommit, OperationState::FailedBeforeCommit];
    for (index, state) in states.into_iter().enumerate() {
        let code = u8::try_from(index + 1).unwrap();
        assert_eq!(state as u8, code);
        assert_eq!(OperationState::from_byte(code).unwrap(), state);
        let public = metadata(PublicOperationMethodV1::StopSandbox).advance(state, 101).unwrap();
        let record = OperationRecord::new(state, 1, state == OperationState::OwnershipPending,
            None, Some(public));
        let bytes = encode_operation_record(record);
        assert_eq!(bytes[1], code);
        assert_eq!(decode_operation(&bytes).unwrap(), record);
        assert_eq!(encode_operation_record(decode_operation(&bytes).unwrap()), bytes);
    }
}
