//! Exercises actual decoder ownership at partial, positive and repeated entry.

use super::*;
use super::super::*;

fn accepted() -> LifecycleOperationV1 {
    let sandbox = SandboxId::from_bytes([3; 16]);
    let step = LifecycleStepV1::planned(
        0, LifecycleStepClassV1::PostCommitForward, LifecycleStepDomainV1::Controller,
        LifecycleStepRequestDigestV1::commit(b"request"),
        LifecycleStepBodyDigestV1::commit(b"body"),
        LifecycleStepPlanDigestV1::commit(b"plan"), None, None, None,
    ).unwrap();
    LifecycleOperationV1::new(
        OperationId::from_bytes([1; 16]), aos_sandbox_model::PrincipalId::from_bytes([2; 16]),
        aos_sandbox_model::ProjectId::from_bytes([4; 16]),
        LifecycleIdempotencyDigestV1::commit(b"idempotency"),
        LifecycleIntentV1::Create { sandbox }, LifecycleTimeV1::new(1).unwrap(), Revision::new(1),
        vec![ResourceExpectationV1::absent(LifecycleResourceV1::Sandbox(sandbox)).unwrap()],
        vec![step], LifecyclePhaseV1::Accepted, 0, 0, None, None, None, None, None, None,
    ).unwrap()
}

#[test]
fn positive_model_moves_once_and_matches_ordinary_decoder() {
    let operation = accepted();
    let encoded = encode_operation_record_v1(&operation).unwrap();
    let ordinary = decode_operation_record_v1(&encoded).unwrap();
    let mut original = LifecycleOperationDecodeOriginalV1::new();

    assert_eq!(original.decode_once(&encoded), Ok(()));
    assert_eq!(original.completed(), Some(&ordinary));
    assert_eq!(original.take_completed_once(), Some(operation));
    assert!(original.take_completed_once().is_none());
    assert!(original.failure().is_none());
}

#[test]
fn later_attempt_refusal_retains_earlier_attempt_and_expectation() {
    let operation = accepted();
    let mut encoded = encode_operation_record_v1(&operation).unwrap();
    let step_offset = FIXED_BODY_BYTES + EXPECTATION_BYTES;
    encoded[step_offset + 6] = LifecycleStepStateV1::Applying as u8;
    encoded[step_offset + 8..step_offset + 12].copy_from_slice(&2_u32.to_be_bytes());
    let attempt = LifecycleEffectAttemptV1::new(
        1, LifecycleEffectDirectionV1::Forward,
        LifecycleStepRequestDigestV1::commit(b"request"),
        LifecycleStepBodyDigestV1::commit(b"body"),
        LifecycleStepPlanDigestV1::commit(b"plan"),
        LifecycleStepAdmissionDigestV1::commit(b"admitted"), LifecycleTimeV1::new(1).unwrap(),
        LifecycleAttemptStateV1::Reserved, None, None, None, None, None,
    ).unwrap();
    let mut slots = Vec::new();
    encode_attempt_slots(&mut slots, &[attempt]);
    encoded[step_offset + 364..step_offset + 364 + ATTEMPT_BYTES]
        .copy_from_slice(&slots[..ATTEMPT_BYTES]);
    let body_length = encoded.len() - DIGEST_BYTES;
    let digest = hash_record(&encoded[..body_length]);
    encoded[body_length..].copy_from_slice(digest.digest().as_bytes());
    let mut original = LifecycleOperationDecodeOriginalV1::new();

    assert_eq!(original.decode_once(&encoded), Err(LifecycleModelError::CorruptEncoding));
    assert_eq!(original.expectations.as_slice(), operation.expectations());
    assert_eq!(original.forward, vec![attempt]);
    assert!(original.steps.is_empty());
    assert!(original.take_completed_once().is_none());
    let pointer = original.forward.as_ptr();
    let first = original.failure().unwrap() as *const LifecycleModelError;

    assert_eq!(original.decode_once(&encoded), Err(LifecycleModelError::InvalidTransition));
    assert_eq!(original.forward.as_ptr(), pointer);
    assert_eq!(original.failure().unwrap() as *const LifecycleModelError, first);
    assert_eq!(decode_operation_record_v1(&encoded), Err(LifecycleModelError::CorruptEncoding));
}

#[test]
fn captured_companion_model_is_reused_for_the_actual_phase() {
    use aos_sandbox_protocol::domain_ledger::records::ProtectedDomainSchemaReplayCaptureV1;
    use crate::lifecycle::protected_journal::{
        LifecycleProtectedJournalSchemaV1 as Schema, LifecycleProtectedRecordKindV1 as Kind,
        LifecycleSchemaReplayCaptureV1,
    };
    let operation = accepted();
    let encoded = encode_operation_record_v1(&operation).unwrap();
    let mut identity = Vec::new();
    identity.extend_from_slice(operation.project().as_bytes());
    identity.extend_from_slice(&crate::lifecycle::protected_journal::lifecycle_journal_subject(operation.intent()));
    identity.extend_from_slice(operation.operation_id().as_bytes());
    let verifier = crate::lifecycle::LifecycleJournalVerifierV1::from_verified_authority(
        ObjectDigest::from_bytes([7; 32]), Vec::new(), Vec::new(),
    ).unwrap();
    let mut capture = LifecycleSchemaReplayCaptureV1::new();

    assert!(Schema::semantic_tuple_retaining_v1(Kind::Intent, &identity, &encoded, &mut capture).is_some());
    assert_eq!(Schema::decode_reducer_phase_retaining_v1(
        &verifier, Kind::Intent, &identity, &encoded, &mut capture,
    ), Some(aos_sandbox_protocol::domain_ledger::records::ProtectedReducerPhaseV1::Observed));
    assert!(capture.failure().is_none());
}

fn accepted_start_with_origin() -> LifecycleOperationV1 {
    use aos_sandbox_model::{DesiredGeneration, RawClockProvenance, RawPairedClockSample};
    use aos_sandbox_protocol::domain_ledger::operation::{AcceptedStartOriginDataV1, StartNativeOriginDataV1};
    let sandbox = SandboxId::from_bytes([3; 16]);
    let resource = LifecycleResourceV1::Sandbox(sandbox);
    let state = LifecycleResourceStateDigestV1::commit(b"actual-stopped-data-fixture");
    let fence = DesiredStateFenceV1::new(resource, DesiredGeneration::new(1), Revision::new(1), state).unwrap();
    let clock = RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted(*b"aos-cli-clock-v1").unwrap(), [7; 16], 100, 10_000_000_000,
    ).unwrap();
    let accepted = AcceptedStartOriginDataV1::from_data_v1(clock, 90_000_000_000,
        160, 150, 60_000_000_000).unwrap();
    let native = RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted(*b"aos-kernel-clock").unwrap(), [7; 16], 101, 11_000_000_000,
    ).unwrap();
    let cutoff = accepted.cutoff_for_sample_data_v1(native).unwrap();
    let origin = StartNativeOriginDataV1::from_data_v1(accepted, native, cutoff).unwrap();
    let step = LifecycleStepV1::unbound(0, LifecycleStepClassV1::PostCommitForward,
        LifecycleStepDomainV1::Controller, LifecycleStepRequestDigestV1::commit(b"request"), None).unwrap();
    let mut operation = LifecycleOperationV1::new(
        OperationId::from_bytes([1; 16]), aos_sandbox_model::PrincipalId::from_bytes([2; 16]),
        aos_sandbox_model::ProjectId::from_bytes([4; 16]), LifecycleIdempotencyDigestV1::commit(b"idempotency"),
        LifecycleIntentV1::Start { sandbox, fence }, LifecycleTimeV1::new(100_000_000_000).unwrap(), Revision::new(1),
        vec![ResourceExpectationV1::present(resource, Revision::new(1), state).unwrap()],
        vec![step], LifecyclePhaseV1::Accepted, 0, 0, None, None, None, None, None, None,
    ).unwrap();
    operation.select_start_native_origin_retaining_v1(origin).unwrap();
    operation
}

#[test]
fn explicit_start_origin_round_trips_and_cold_successors_cannot_renew_it() {
    use crate::lifecycle::history::LifecycleHistoryV1;
    let original = accepted_start_with_origin();
    let encoded = encode_operation_record_v1(&original).unwrap();
    assert_eq!(&encoded[..8], b"AOSLIF05");
    assert_eq!(decode_operation_record_v1(&encoded).unwrap(), original);
    let step = LifecycleStepV1::planned(0, LifecycleStepClassV1::PostCommitForward,
        LifecycleStepDomainV1::Controller, LifecycleStepRequestDigestV1::commit(b"request"),
        LifecycleStepBodyDigestV1::commit(b"body"), LifecycleStepPlanDigestV1::commit(b"plan"),
        None, None, None).unwrap();
    let successor = original.successor(record_digest(&encoded).unwrap(), LifecyclePhaseV1::Accepted,
        0, 0, vec![step], None, None, None, None, None).unwrap();
    assert_eq!(successor.start_native_origin_v1(), original.start_native_origin_v1());
    let next = encode_operation_record_v1(&successor).unwrap();
    assert!(LifecycleHistoryV1::replay([encoded.as_slice(), next.as_slice()]).is_ok());

    // Both changed pairs remain structurally valid DATA; the immutable replay
    // chain rejects changing which paid first pair was originally persisted.
    let mut substituted = next.clone();
    let offset = substituted.len() - DIGEST_BYTES - START_ORIGIN_BYTES + 80;
    substituted[offset + 32..offset + 40].copy_from_slice(&102_i64.to_le_bytes());
    substituted[offset + 40..offset + 48].copy_from_slice(&12_000_000_000_u64.to_le_bytes());
    let end = substituted.len() - DIGEST_BYTES;
    let digest = hash_record(&substituted[..end]);
    substituted[end..].copy_from_slice(digest.digest().as_bytes());
    assert!(decode_operation_record_v1(&substituted).is_ok());
    assert!(LifecycleHistoryV1::replay([encoded.as_slice(), substituted.as_slice()]).is_err());
}

#[test]
fn invalid_start_suffix_keeps_the_actual_decoded_prefix_and_original_cause() {
    let operation = accepted_start_with_origin();
    let mut encoded = encode_operation_record_v1(&operation).unwrap();
    let end = encoded.len() - DIGEST_BYTES;
    encoded[end - 8..end].copy_from_slice(&u64::MAX.to_le_bytes());
    let digest = hash_record(&encoded[..end]);
    encoded[end..].copy_from_slice(digest.digest().as_bytes());
    let mut original = LifecycleOperationDecodeOriginalV1::new();

    assert_eq!(original.decode_once(&encoded), Err(LifecycleModelError::CorruptEncoding));
    assert_eq!(original.expectations.as_slice(), operation.expectations());
    assert_eq!(original.steps.as_slice(), operation.steps());
    let pointer = original.expectations.as_ptr();
    let cause = original.failure_view_v1().unwrap() as *const dyn std::error::Error;
    assert_eq!(original.decode_once(&encoded), Err(LifecycleModelError::InvalidTransition));
    assert_eq!(original.expectations.as_ptr(), pointer);
    assert!(std::ptr::eq(original.failure_view_v1().unwrap() as *const dyn std::error::Error, cause));
}
