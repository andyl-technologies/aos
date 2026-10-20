//! Exercises whole-baseline precharge and the exact single-recipient replacement.

use super::*;
use super::super::{EnrollmentMutation, NativeLayoutDemand, initial_enrollment_claims,
    prepare_enrollment_subdivisions};
use aos_sandbox_core::{ResourceDimension as D, ResourceVector};

fn enrolled_bank() -> (State, EnrollmentIdentity, super::super::ImageBootstrapPolicy) {
    enrolled_bank_version(10)
}

fn enrolled_bank_version(version: usize) -> (State, EnrollmentIdentity, super::super::ImageBootstrapPolicy) {
    let (policy, _) = codec::image_policy_tests::fixture(version);
    let enrollment = EnrollmentIdentity { node: [1; 16], epoch: [2; 16], boot: [3; 16],
        invocation: [4; 16], manifest: [5; 32] };
    let (heads, host, prefix, intake, q04, root, create, storage) =
        prepare_enrollment_subdivisions(enrollment, policy, NativeLayoutDemand::new(0, 0)).unwrap();
    let claims = initial_enrollment_claims(enrollment, policy, &heads);
    let delete = super::super::delete_operation_intake_claim(enrollment, policy).unwrap();
    let execution = super::super::execution_operation_intake_claim(enrollment, policy).unwrap();
    let prepare = super::super::host_execution_prepare_claim(enrollment, policy).unwrap();
    let accept = super::super::host_execution_accept_claim(enrollment, policy).unwrap();
    let initial = initial_recipient_precharge_v1(enrollment, policy, [10; 16]).unwrap();
    let id = [6; 16];
    let mutation = EnrollmentMutation::new((&id, &heads, &claims, &host, &prefix,
        &intake, &q04, &root, &create, &storage))
        .with_delete_operation_intake(delete.as_ref()).with_execution_operation_intake(execution.as_ref())
        .with_host_execution_prepare(prepare.as_ref()).with_host_execution_accept(accept.as_ref())
        .with_recipient_precharge_v1(initial.as_ref());
    let transaction = mutation.transaction().unwrap();
    let mut state = State::new();
    validate_recipient_transaction_v1(&state, &transaction).unwrap();
    mutation.require_exact(&state, &transaction).unwrap();
    apply(&mut state, &transaction);
    mutation.require_returned_rows(&state).unwrap();
    assert_eq!(replay::validate(&state).unwrap(), Some(enrollment));
    (state, enrollment, policy)
}

fn apply(state: &mut State, transaction: &JournalTransaction) {
    for record in transaction.records() {
        state.insert((record.namespace(), record.key().to_vec()), record.value().unwrap().to_vec());
    }
}

#[test]
fn successor_preserves_every_existing_account_and_claim_and_carries_every_plane() {
    let (mut state, enrollment, policy) = enrolled_bank();
    let original = state.clone();
    let initial = recipient_incarnation(&state, enrollment).unwrap().unwrap();
    let (baseline, normal, recovery) = policy.controller_baseline_partition_v1().unwrap();
    assert_eq!(initial.charged_baseline_v1().unwrap(), normal);
    let successor = RecipientSuccessorMutation::new(&state, enrollment, [10;16], [11;16], [12;32]).unwrap();
    let transaction = successor.transaction([13;16]).unwrap();
    validate_recipient_transaction_v1(&state, &transaction).unwrap();
    successor.require_exact(&state, &transaction).unwrap();
    assert_eq!(successor.row().predecessor_row_digest(), initial.commitment().unwrap());
    assert_eq!(successor.row().normal_precharge_v1(), normal);
    assert_eq!(successor.row().recovery_reserve_v1(), recovery);
    assert_eq!(successor.row().charged_baseline_v1().unwrap(), baseline);
    apply(&mut state, &transaction);
    successor.require_returned_rows(&state).unwrap();
    for (key, value) in original.iter().filter(|((_, key), _)| key.first() != Some(&PREFIX)) {
        assert_eq!(state.get(key), Some(value));
    }
    assert_eq!(state.len(), original.len());
    for dimension in [D::NetworkBytes, D::LogBytes, D::PublicationStagingBytes, D::OutputBytes] {
        assert_eq!(successor.row().normal_precharge_v1().get(dimension), normal.get(dimension));
    }
    assert!(RecipientSuccessorMutation::new(&state, enrollment, [11;16], [14;16], [15;32]).is_err());
    assert!(validate_recipient_transaction_v1(&state, &transaction).is_err());
}

#[test]
fn no_missing_old_or_rebound_partition_can_create_a_successor() {
    let (state, enrollment, policy) = enrolled_bank();
    let row = recipient_incarnation(&state, enrollment).unwrap().unwrap();
    let key = (RecordNamespace::ControllerResourceReservation, replay::key(PREFIX, enrollment.node).to_vec());
    let mut missing = state.clone();
    missing.remove(&key);
    assert!(RecipientSuccessorMutation::new(&missing, enrollment, [10;16], [11;16], [12;32]).is_err());
    let mut old = state.clone();
    let mut old_bytes = vec![0; 272];
    old_bytes[..8].copy_from_slice(b"AOSRRI01");
    old.insert(key.clone(), old_bytes);
    assert!(replay::validate(&old).is_err());
    assert!(RecipientSuccessorMutation::new(&old, enrollment, [10;16], [11;16], [12;32]).is_err());

    let mut changed = row;
    changed.normal = changed.normal.checked_add(ResourceVector::new([1;D::COUNT])).unwrap();
    assert!(changed.require_policy_v1(policy).is_err());
    let mut malformed = state;
    malformed.insert(key, changed.to_bytes().unwrap().to_vec());
    assert!(replay::validate(&malformed).is_err());
}

#[test]
fn changed_full_bank_and_wrong_predecessor_refuse_without_a_repairing_retry() {
    let (mut state, enrollment, _) = enrolled_bank();
    let successor = RecipientSuccessorMutation::new(&state, enrollment, [10;16], [11;16], [12;32]).unwrap();
    let transaction = successor.transaction([13;16]).unwrap();
    assert!(RecipientSuccessorMutation::new(&state, enrollment, [90;16], [11;16], [12;32]).is_err());
    let (_, raw) = state.iter_mut().find(|((namespace,key),_)|
        *namespace == RecordNamespace::ControllerResourceReservation && key.first() == Some(&replay::CLAIM_PREFIX)).unwrap();
    let mut claim = codec::decode_claim(raw).unwrap();
    claim.owner = [99;32];
    assert!(codec::encode_claim(claim).is_err());
    // The strict encoder cannot emit an owner-rebound claim. Construct a
    // checksum-valid hostile row so full replay, rather than SHA alone, refuses.
    raw[152..184].copy_from_slice(&claim.owner);
    let checksum_offset = raw.len() - 32;
    let checksum = Sha256::digest(&raw[..checksum_offset]);
    raw[checksum_offset..].copy_from_slice(&checksum);
    // The changed enrollment-owned claim is itself invalid under full replay.
    // A prepared successor must neither accept that bank nor repair any bytes.
    let changed_bank = state.clone();
    let proposed = transaction.clone();
    assert!(replay::validate(&state).is_err());
    assert!(successor.require_exact(&state, &transaction).is_err());
    assert!(validate_recipient_transaction_v1(&state, &transaction).is_err());
    assert_eq!(state, changed_bank);
    assert_eq!(transaction, proposed);
}

#[test]
fn strict_codec_refuses_truncation_trailing_bad_generation_and_valid_checksum_rebinding() {
    let (state, enrollment, _) = enrolled_bank();
    let row = recipient_incarnation(&state, enrollment).unwrap().unwrap();
    let bytes = row.to_bytes().unwrap();
    assert_eq!(RecipientIncarnation::decode(&bytes).unwrap(), row);
    for end in 0..bytes.len() { assert!(RecipientIncarnation::decode(&bytes[..end]).is_err()); }
    let mut trailing = bytes.to_vec(); trailing.push(0);
    assert!(RecipientIncarnation::decode(&trailing).is_err());
    let mut changed = bytes;
    changed[104..112].copy_from_slice(&2_u64.to_be_bytes());
    let checksum = Sha256::digest(&changed[..592]); changed[592..].copy_from_slice(&checksum);
    assert!(RecipientIncarnation::decode(&changed).is_err());
}

#[test]
fn finite_range_preserves_committed_history_and_skips_only_charged_native_ordinals() {
    let (mut state, enrollment, policy) = enrolled_bank_version(11);
    let before = state.clone();
    let range = codec::controller_recipient_range_commitment_v1(enrollment, policy).unwrap();
    let initial = recipient_incarnation(&state, enrollment).unwrap().unwrap();
    assert_eq!(initial.to_bytes().unwrap().len(), range::RECIPIENT_RANGE_INCARNATION_BYTES);

    // Native consumed ordinal one but it died before committing any bank row.
    // The bank CAS therefore still uses literal initial row zero, not donor one.
    let second = RecipientSuccessorMutation::new_range_v2(&state, enrollment,
        [12; 16], 2, range, 0, [10; 16], [22; 32]).unwrap();
    let transaction = second.transaction([32; 16]).unwrap();
    assert_eq!(transaction.records().len(), 2);
    validate_recipient_transaction_v1(&state, &transaction).unwrap();
    second.require_exact(&state, &transaction).unwrap();
    apply(&mut state, &transaction);
    second.require_returned_rows(&state).unwrap();

    // A second candidate committed but died before ACK. PID1's confirmed floor
    // remains zero while the actual durable predecessor is now ordinal two.
    let third = RecipientSuccessorMutation::new_range_v2(&state, enrollment,
        [13; 16], 3, range, 0, [10; 16], [23; 32]).unwrap();
    let transaction = third.transaction([33; 16]).unwrap();
    validate_recipient_transaction_v1(&state, &transaction).unwrap();
    apply(&mut state, &transaction);
    third.require_returned_rows(&state).unwrap();

    assert_eq!(range::controller_recipient_for_invocation_v2(&state, enrollment, [10; 16]).unwrap(), initial);
    assert_eq!(range::controller_recipient_for_invocation_v2(&state, enrollment, [12; 16]).unwrap(), second.row());
    let (baseline, _, recovery) = policy.controller_baseline_partition_v1().unwrap();
    let (count, allowance) = policy.controller_recovery_range_v1().unwrap();
    assert_eq!(count, 3);
    for dimension in D::ALL {
        assert_eq!(allowance.get(dimension).checked_mul(count).unwrap(), recovery.get(dimension));
    }
    assert_eq!(third.row().outside_allowance_v2().unwrap(), baseline.checked_sub(allowance).unwrap());
    for (key, value) in before.iter().filter(|((_, key), _)| key.first() != Some(&PREFIX)) {
        assert_eq!(state.get(key), Some(value));
    }
    assert!(RecipientSuccessorMutation::new_range_v2(&state, enrollment,
        [14; 16], 4, range, 0, [10; 16], [24; 32]).is_err());

    let key = (RecordNamespace::ControllerResourceReservation, range::history_key(initial).to_vec());
    let mut missing = state.clone();
    missing.remove(&key);
    assert!(replay::validate(&missing).is_err());
}

#[test]
fn range_policy_refuses_unfunded_count_and_current_row_downgrade() {
    let (mut state, enrollment, policy) = enrolled_bank_version(11);
    let (decoded, mut bytes) = codec::image_policy_tests::fixture(11);
    assert_eq!(decoded, policy);
    assert_eq!(codec::decode_component_image_policy(&bytes).unwrap(), policy);
    bytes[3032..3040].copy_from_slice(&4_u64.to_be_bytes());
    let checksum = Sha256::digest(&bytes[..3216]);
    bytes[3216..].copy_from_slice(&checksum);
    assert!(codec::decode_component_image_policy(&bytes).is_err());
    assert!(RecipientSuccessorMutation::new(&state, enrollment, [10; 16], [11; 16], [12; 32]).is_err());

    let range = codec::controller_recipient_range_commitment_v1(enrollment, policy).unwrap();
    let first = RecipientSuccessorMutation::new_range_v2(&state, enrollment,
        [11; 16], 1, range, 0, [10; 16], [21; 32]).unwrap();
    apply(&mut state, &first.transaction([31; 16]).unwrap());
    let next = RecipientSuccessorMutation::new_range_v2(&state, enrollment,
        [12; 16], 2, range, 1, [11; 16], [22; 32]).unwrap();
    let mut wrong = state.clone();
    let previous = recipient_incarnation(&wrong, enrollment).unwrap().unwrap();
    let mut changed = previous;
    changed.range.as_mut().unwrap().allowance = ResourceVector::new([1; D::COUNT]);
    wrong.insert((RecordNamespace::ControllerResourceReservation, replay::key(PREFIX, enrollment.node).to_vec()), changed.to_bytes().unwrap());
    assert!(next.require_exact(&wrong, &next.transaction([32; 16]).unwrap()).is_err());
    assert!(RecipientSuccessorMutation::new_range_v2(&state, enrollment,
        [10; 16], 2, range, 1, [11; 16], [22; 32]).is_err());
}

#[test]
fn funding_stays_bound_to_archived_recipient_without_reopening_its_seed() {
    use super::super::{RecoveredHostStopCleanupAssociationDataV1,
        RecoveredHostStopCleanupFundingDataV1, validate_recovered_funding_transaction_v2};

    let (mut state, enrollment, policy) = enrolled_bank_version(11);
    let range = codec::controller_recipient_range_commitment_v1(enrollment, policy).unwrap();
    let first = RecipientSuccessorMutation::new_range_v2(&state, enrollment,
        [11; 16], 1, range, 0, [10; 16], [21; 32]).unwrap();
    apply(&mut state, &first.transaction([31; 16]).unwrap());
    let baseline = first.row().charged_baseline_v1().unwrap();
    let complete = ResourceVector::ZERO.with(D::MemoryBytes, 16);
    let before = first.row().outside_allowance_v2().unwrap();
    let old = RecoveredHostStopCleanupFundingDataV1 {
        enrollment, recipient: [11; 16], baseline, charged_before: before,
        charged_after: before.checked_add(complete).unwrap(), complete,
        association: RecoveredHostStopCleanupAssociationDataV1 {
            recovery_operation: [40; 16], cleanup_operation: [41; 16],
            target_stop_operation: [42; 16], expected_resource_version: [43; 32],
            public_request_digest: [44; 32], source_parent_digest: [45; 32],
            cleanup_subject_digest: [46; 32],
        }, controller_next: 10, controller_end: 100,
    };
    let old_transaction = old.transaction_data_v1().unwrap();
    validate_recovered_funding_transaction_v2(&state, &old_transaction, 10, 100).unwrap();
    apply(&mut state, &old_transaction);
    let old_bytes = old.encode_v1().unwrap();

    let second = RecipientSuccessorMutation::new_range_v2(&state, enrollment,
        [12; 16], 2, range, 1, [11; 16], [22; 32]).unwrap();
    apply(&mut state, &second.transaction([32; 16]).unwrap());
    second.require_returned_rows(&state).unwrap();

    old.require_replayed_v1(&state).unwrap();
    assert_eq!(state.get(&(RecordNamespace::ControllerResourceReservation,
        old.key_v1().to_vec())).unwrap().as_slice(), old_bytes.as_slice());
    assert!(validate_recovered_funding_transaction_v2(&state, &old_transaction, 10, 100).is_err());
    assert_eq!(second.row().outside_allowance_v2().unwrap(), before);
}
