//! Exercises canonical debit witnesses and unchanged already-precharged accounts.

use super::*;
use aos_sandbox_core::ResourceDimension as D;

fn apply(state: &mut State, transaction: &JournalTransaction) {
    for record in transaction.records() {
        state.insert((record.namespace(), record.key().to_vec()), record.value().unwrap().to_vec());
    }
}

fn fixture() -> (State, [RecoveredOperationFundingDataV1; 2]) {
    // These are passive format fixtures, never native enrollment or debit proofs.
    let (policy, _) = codec::image_policy_tests::fixture(10);
    let enrollment = EnrollmentIdentity { node: [1; 16], epoch: [2; 16], boot: [3; 16],
        invocation: [4; 16], manifest: [5; 32] };
    let (heads, host, prefix, intake, q04, root, create, storage) =
        bootstrap::prepare_enrollment_subdivisions(enrollment, policy, NativeLayoutDemand::new(0, 0)).unwrap();
    let claims = bootstrap::initial_enrollment_claims(enrollment, policy, &heads);
    let delete = bootstrap::delete_operation_intake_claim(enrollment, policy).unwrap().unwrap();
    let execution = bootstrap::execution_operation_intake_claim(enrollment, policy).unwrap().unwrap();
    let prepare = bootstrap::host_execution_prepare_claim(enrollment, policy).unwrap();
    let accept = bootstrap::host_execution_accept_claim(enrollment, policy).unwrap();
    let initial = recipient::initial_recipient_precharge_v1(enrollment, policy, [10; 16]).unwrap();
    let id = [6; 16];
    let mutation = EnrollmentMutation::new((&id, &heads, &claims, &host, &prefix,
        &intake, &q04, &root, &create, &storage))
        .with_delete_operation_intake(Some(&delete)).with_execution_operation_intake(Some(&execution))
        .with_host_execution_prepare(prepare.as_ref()).with_host_execution_accept(accept.as_ref())
        .with_recipient_precharge_v1(initial.as_ref());
    let mut state = State::new();
    apply(&mut state, &mutation.transaction().unwrap());
    let successor = recipient::RecipientSuccessorMutation::new(&state, enrollment,
        [10; 16], [11; 16], [12; 32]).unwrap();
    apply(&mut state, &successor.transaction([13; 16]).unwrap());
    let (baseline, normal, _) = policy.controller_baseline_partition_v1().unwrap();
    let amount = |bytes| ResourceVector::ZERO.with(D::MemoryBytes, bytes);
    let before = normal.checked_add(amount(64)).unwrap();
    let first = RecoveredOperationFundingDataV1 { purpose: RecoveredOperationFundingPurposeV1::Delete,
        enrollment, recipient: [11; 16], baseline, charged_before: before,
        charged_after: before.checked_add(amount(16)).unwrap(), complete: amount(16),
        declared: delete.native_fields().amount, controller_next: 10, controller_end: 100 };
    let second = RecoveredOperationFundingDataV1 { purpose: RecoveredOperationFundingPurposeV1::Execution,
        charged_before: first.charged_after, charged_after: first.charged_after.checked_add(amount(32)).unwrap(),
        complete: amount(32), declared: execution.native_fields().amount, ..first };
    (state, [first, second])
}

fn cleanup_fixture() -> (State, RecoveredHostStopCleanupFundingDataV1) {
    let (state, pair) = fixture();
    let paid = pair[0];
    let association = RecoveredHostStopCleanupAssociationDataV1 {
        recovery_operation: [20; 16], cleanup_operation: [21; 16], target_stop_operation: [22; 16],
        expected_resource_version: [23; 32], public_request_digest: [24; 32],
        source_parent_digest: [25; 32], cleanup_subject_digest: [26; 32],
    };
    let cleanup = RecoveredHostStopCleanupFundingDataV1 {
        enrollment: paid.enrollment, recipient: paid.recipient, baseline: paid.baseline,
        charged_before: paid.charged_before, charged_after: paid.charged_after,
        complete: paid.complete, association, controller_next: paid.controller_next,
        controller_end: paid.controller_end,
    };
    (state, cleanup)
}

#[test]
fn cleanup_seed_replays_before_ordinary_enrollment_without_inventing_its_pair() {
    let (mut state, cleanup) = cleanup_fixture();
    let before = state.clone();
    let transaction = cleanup.transaction_data_v1().unwrap();
    validate_recovered_funding_transaction_v2(&state, &transaction, 10, 100).unwrap();

    apply(&mut state, &transaction);

    assert_eq!(state.len(), before.len() + 1);
    for (key, value) in before { assert_eq!(state.get(&key), Some(&value)); }
    assert_eq!(replay::validate(&state).unwrap(), Some(cleanup.enrollment));
    cleanup.require_replayed_v1(&state).unwrap();
    assert!(validate_recovered_funding_transaction_v2(&state, &transaction, 10, 100).is_err());

    // Purpose21 retains its original mandatory completed D/X pair law.
    let ordinary = RecoveredLifecycleStopFundingDataV2 {
        enrollment: cleanup.enrollment, recipient: cleanup.recipient, baseline: cleanup.baseline,
        charged_before: cleanup.charged_before, charged_after: cleanup.charged_after,
        complete: cleanup.complete, controller_next: 10, controller_end: 100,
    };
    assert_ne!(ordinary.key_v2(), cleanup.key_v1());
    assert!(validate_recovered_funding_transaction_v2(&state,
        &ordinary.transaction_data_v2().unwrap(), 10, 100).is_err());
}

#[test]
fn cleanup_seed_refuses_purpose_alias_native_cut_changes_and_foreign_recipient() {
    let (state, cleanup) = cleanup_fixture();
    let encoded = cleanup.encode_v1().unwrap();
    assert_eq!(RecoveredHostStopCleanupFundingDataV1::decode_v1(&encoded).unwrap(), cleanup);
    assert!(RecoveredOperationFundingDataV1::decode_v1(&encoded).is_err());
    assert!(RecoveredLifecycleStopFundingDataV2::decode_v2(&encoded).is_err());

    let transaction = cleanup.transaction_data_v1().unwrap();
    assert!(validate_recovered_funding_transaction_v2(&state, &transaction, 11, 100).is_err());
    assert!(validate_recovered_funding_transaction_v2(&state, &transaction, 10, 101).is_err());
    let foreign = RecoveredHostStopCleanupFundingDataV1 { recipient: [27; 16], ..cleanup };
    assert!(validate_recovered_funding_transaction_v2(&state,
        &foreign.transaction_data_v1().unwrap(), 10, 100).is_err());
    let (_, pair) = fixture();
    let mixed = JournalTransaction::new([28; 16], vec![
        transaction.records()[0].clone(),
        recovered_funding_pair_transaction_data_v1(&pair).unwrap().records()[0].clone(),
    ]).unwrap();
    assert!(validate_recovered_funding_transaction_v2(&state, &mixed, 10, 100).is_err());
    let alias = RecoveredHostStopCleanupAssociationDataV1 {
        cleanup_operation: cleanup.association.recovery_operation, ..cleanup.association
    };
    assert!(alias.encode_v1().is_err());

    let mut disguised = encoded;
    disguised[8] = 21;
    let checksum = Sha256::digest(&disguised[..1024]);
    disguised[1024..].copy_from_slice(&checksum);
    assert!(RecoveredLifecycleStopFundingDataV2::decode_v2(&disguised).is_err());

    for index in [8, 9, 480, 832, 1008] {
        let mut substituted = encoded;
        substituted[index] ^= 0x80;
        assert!(RecoveredHostStopCleanupFundingDataV1::decode_v1(&substituted).is_err());
    }
    assert!(RecoveredHostStopCleanupFundingDataV1::decode_v1(&encoded[..1055]).is_err());
}

#[test]
fn paired_metadata_preserves_all_old_accounts_claims_and_predecessor_debt() {
    let (mut state, pair) = fixture();
    let before = state.clone();
    let transaction = recovered_funding_pair_transaction_data_v1(&pair).unwrap();
    validate_recovered_funding_transaction_v1(&state, &transaction, 10, 100).unwrap();

    apply(&mut state, &transaction);

    assert_eq!(replay::validate(&state).unwrap(), Some(pair[0].enrollment));
    assert_eq!(state.len(), before.len() + 2);
    for (key, value) in before { assert_eq!(state.get(&key), Some(&value)); }
    for row in pair { row.require_replayed_v1(&state).unwrap(); }
    assert!(validate_recovered_funding_transaction_v1(&state, &transaction, 10, 100).is_err());
}

#[test]
fn partial_changed_recipient_and_false_prior_debt_do_not_replay() {
    let (state, pair) = fixture();
    let mut partial = state.clone();
    partial.insert((RecordNamespace::ControllerResourceReservation, pair[0].key_v1().to_vec()),
        pair[0].encode_v1().unwrap().to_vec());
    assert!(replay::validate(&partial).is_err());

    let mut changed = pair;
    changed[1].charged_before = changed[1].charged_before.checked_add(
        ResourceVector::ZERO.with(D::MemoryBytes, 1)).unwrap();
    changed[1].charged_after = changed[1].charged_before.checked_add(changed[1].complete).unwrap();
    assert!(require_recovered_funding_pair_data_v1(&changed).is_err());
    let transaction = recovered_funding_pair_transaction_data_v1(&pair).unwrap();
    assert!(validate_recovered_funding_transaction_v1(&state, &transaction, 11, 100).is_err());
    assert!(validate_recovered_funding_transaction_v1(&state, &transaction, 10, 101).is_err());

    let mut wrong_recipient = pair;
    for row in &mut wrong_recipient { row.recipient = [14; 16]; }
    let transaction = recovered_funding_pair_transaction_data_v1(&wrong_recipient).unwrap();
    assert!(validate_recovered_funding_transaction_v1(&state, &transaction, 10, 100).is_err());
}

#[test]
fn canonical_codec_refuses_wrong_role_reserved_bits_balance_and_checksum() {
    let (_, pair) = fixture();
    let row = pair[0];
    let bytes = row.encode_v1().unwrap();
    assert_eq!(RecoveredOperationFundingDataV1::decode_v1(&bytes).unwrap(), row);
    for index in [8, 9, 480, 1024] {
        let mut changed = bytes;
        changed[index] ^= 0x80;
        if index < 1024 {
            let digest = Sha256::digest(&changed[..1024]);
            changed[1024..].copy_from_slice(&digest);
        }
        assert!(RecoveredOperationFundingDataV1::decode_v1(&changed).is_err());
    }
    assert!(RecoveredOperationFundingDataV1::decode_v1(&bytes[..1055]).is_err());
}


#[test]
fn operation_union_preserves_initial_claim_bytes_and_its_named_preimage() {
    use crate::domain_ledger::resource_bank::OperationIntakeFundingDataV1;

    let (state, pair) = fixture();
    let initial = state.values().filter_map(|bytes| Claim::decode(bytes).ok())
        .find(|claim| claim.native_fields().purpose == ClaimPurpose::DeleteOperationIntake)
        .unwrap();
    let funding = OperationIntakeFundingDataV1::InitialReservedClaim(initial);
    let bytes = funding.encode_v1().unwrap();

    assert_eq!(&bytes[16..16 + CLAIM_BYTES_V1], &initial.encode().unwrap());
    assert!(bytes[16 + CLAIM_BYTES_V1..].iter().all(|byte| *byte == 0));
    assert_eq!(OperationIntakeFundingDataV1::decode_v1(&bytes).unwrap(), funding);
    assert!(OperationIntakeFundingDataV1::decode_v1(&initial.encode().unwrap()).is_err());
    assert_eq!(funding.controller_funding_cut_data_v3(20, 200).unwrap(),
        crate::domain_ledger::delete_root::named_cuts::controller_cut_from_encoded_claim_data_v2(
            &initial.encode().unwrap(), 20, 200));

    // The real successor state still contains the literal predecessor Claim,
    // but its canonical recipient row prevents that provenance branch reuse.
    assert!(funding.require_bank_record_v1(&state).is_err());
    let mut initial_state = state.clone();
    let (policy, _) = codec::image_policy_tests::fixture(10);
    let recipient = recipient::initial_recipient_precharge_v1(initial.enrollment, policy, [10; 16])
        .unwrap().unwrap();
    initial_state.insert((RecordNamespace::ControllerResourceReservation,
        replay::key(recipient::PREFIX, initial.enrollment.node).to_vec()),
        recipient.to_bytes().unwrap().to_vec());
    funding.require_bank_record_v1(&initial_state).unwrap();

    // Explicit framing cannot silently reinterpret an initial reservation as
    // recovered debt or ignore padding after the historical literal Claim531.
    for offset in [8, 9, 10, 12, 16 + CLAIM_BYTES_V1] {
        let mut changed = bytes;
        changed[offset] ^= 0x80;
        assert!(OperationIntakeFundingDataV1::decode_v1(&changed).is_err());
    }
    assert_ne!(OperationIntakeFundingDataV1::RecoveredBaseline(pair[0])
        .controller_funding_cut_data_v3(20, 200).unwrap(), funding.controller_funding_cut_data_v3(20, 200).unwrap());
}

#[test]
fn recovered_union_requires_the_complete_actual_bank_pair_and_closed_delete_purpose() {
    use crate::domain_ledger::resource_bank::OperationIntakeFundingDataV1;
    use crate::domain_ledger::delete_root::controller_cut::DeleteRootControllerCutDataV3;

    let (mut state, pair) = fixture();
    let funding = OperationIntakeFundingDataV1::RecoveredBaseline(pair[0]);
    assert!(funding.require_bank_record_v1(&state).is_err());
    apply(&mut state, &recovered_funding_pair_transaction_data_v1(&pair).unwrap());
    funding.require_bank_record_v1(&state).unwrap();
    let bytes = funding.encode_v1().unwrap();
    assert_eq!(OperationIntakeFundingDataV1::decode_v1(&bytes).unwrap(), funding);

    let mut changed = pair[0];
    changed.recipient = [99; 16];
    assert!(OperationIntakeFundingDataV1::RecoveredBaseline(changed)
        .require_bank_record_v1(&state).is_err());
    assert!(OperationIntakeFundingDataV1::RecoveredBaseline(pair[1]).require_delete_data_v1().is_err());

    let cut = DeleteRootControllerCutDataV3 { challenge: [42; 32], funding, next: 20, end: 200 };
    let bytes = cut.encode_v3().unwrap();
    assert_eq!(DeleteRootControllerCutDataV3::decode_v3(&bytes).unwrap(), cut);
    let mut old = bytes;
    old[..8].copy_from_slice(b"AOSDRC02");
    old[8..10].copy_from_slice(&2_u16.to_be_bytes());
    assert!(DeleteRootControllerCutDataV3::decode_v3(&old).is_err());
    assert!(DeleteRootControllerCutDataV3 { funding: OperationIntakeFundingDataV1::RecoveredBaseline(pair[1]), ..cut }
        .encode_v3().is_err());
}


#[test]
fn planning_v3_challenge_commits_the_whole_recovered_funding_witness() {
    use crate::domain_ledger::resource_bank::OperationIntakeFundingDataV1;
    use crate::domain_ledger::delete_root::planning::{DeleteRootPlanningOpenDataV3,
        DeleteRootPlanningChallengeDataV3, DELETE_ROOT_PLANNING_OPEN_BYTES_V3};
    use aos_sandbox_core::{RawClockProvenance, RawPairedClockSample};

    let (_, pair) = fixture();
    let sample = |wall, boot| RawPairedClockSample::new_untrusted(
        RawClockProvenance::new_untrusted([1; 16]).unwrap(), [2; 16], wall, boot,
    ).unwrap();
    let open = DeleteRootPlanningOpenDataV3 {
        project: [3; 16], caller: [4; 16], input: [5; 32],
        authorization_clock: sample(100, 10_000_000_000), authorization_expires: 500,
        controller_nonce: [6; 16], controller_cutoff: 15_000_000_000,
        controller_next: 7, controller_end: 4096, source_next: 8, source_end: 8192,
        funding: OperationIntakeFundingDataV1::RecoveredBaseline(pair[0]),
    };
    let bytes = open.encode_v3().unwrap();
    let challenge = DeleteRootPlanningChallengeDataV3 {
        open: open.digest_v3().unwrap(), clock: sample(101, 11_000_000_000),
        nonce: [9; 16], cutoff: 15_000_000_000,
    };

    assert_eq!(bytes.len(), DELETE_ROOT_PLANNING_OPEN_BYTES_V3);
    assert_eq!(DeleteRootPlanningOpenDataV3::decode_v3(&bytes).unwrap(), open);
    challenge.require_open_v3(open).unwrap();
    let mut changed = pair[0];
    changed.controller_end += 1;
    let substituted = DeleteRootPlanningOpenDataV3 {
        funding: OperationIntakeFundingDataV1::RecoveredBaseline(changed), ..open
    };
    assert!(substituted.encode_v3().is_ok());
    assert!(challenge.require_open_v3(substituted).is_err());
}

#[test]
fn sole_funding_family_keeps_purposes_distinct_and_refuses_obsolete_magic() {
    let (mut state, pair) = fixture();
    let transaction = recovered_funding_pair_transaction_data_v1(&pair).unwrap();
    validate_recovered_funding_transaction_v2(&state, &transaction, 10, 100).unwrap();
    apply(&mut state, &transaction);

    let complete = ResourceVector::ZERO.with(D::MemoryBytes, 8);
    let stop = RecoveredLifecycleStopFundingDataV2 {
        enrollment: pair[0].enrollment, recipient: pair[0].recipient, baseline: pair[0].baseline,
        charged_before: pair[1].charged_after, charged_after: pair[1].charged_after.checked_add(complete).unwrap(),
        complete, controller_next: 20, controller_end: 200,
    };
    let encoded = stop.encode_v2().unwrap();
    assert_eq!(encoded.len(), 880);
    assert_eq!(&encoded[..8], b"AOSRFS02");
    assert_eq!(encoded[8], 21);
    assert_eq!(RecoveredLifecycleStopFundingDataV2::decode_v2(&encoded).unwrap(), stop);
    assert!(RecoveredOperationFundingDataV1::decode_v1(&encoded).is_err());
    assert!(RecoveredLifecycleStopFundingDataV2::decode_v2(&pair[0].encode_v1().unwrap()).is_err());
    assert_ne!(stop.key_v2(), pair[0].key_v1());
    assert_ne!(stop.key_v2(), pair[1].key_v1());

    let transaction = stop.transaction_data_v2().unwrap();
    let before = state.clone();
    validate_recovered_funding_transaction_v2(&state, &transaction, 20, 200).unwrap();
    assert!(validate_recovered_funding_transaction_v2(&state, &transaction, 21, 200).is_err());
    apply(&mut state, &transaction);
    stop.require_replayed_v2(&state).unwrap();
    assert_eq!(replay::validate(&state).unwrap(), Some(stop.enrollment));
    assert!(validate_recovered_funding_transaction_v2(&state, &transaction, 20, 200).is_err());
    for (key, value) in before { assert_eq!(state.get(&key), Some(&value)); }

    for row in pair {
        let mut obsolete = row.encode_v1().unwrap();
        obsolete[..8].copy_from_slice(b"AOSRFS01");
        let checksum = Sha256::digest(&obsolete[..1024]);
        obsolete[1024..].copy_from_slice(&checksum);
        assert!(RecoveredOperationFundingDataV1::decode_v1(&obsolete).is_err());
    }
}

#[test]
fn stop_seed_rejects_false_balance_recipient_shape_and_declaration_substitution() {
    let (state, pair) = fixture();
    let complete = ResourceVector::ZERO.with(D::MemoryBytes, 8);
    let stop = RecoveredLifecycleStopFundingDataV2 {
        enrollment: pair[0].enrollment, recipient: pair[0].recipient, baseline: pair[0].baseline,
        charged_before: pair[1].charged_after, charged_after: pair[1].charged_after.checked_add(complete).unwrap(),
        complete, controller_next: 20, controller_end: 200,
    };
    let mut false_balance = stop;
    false_balance.charged_after = false_balance.charged_before;
    assert!(false_balance.encode_v2().is_err());
    let mut other = stop;
    other.recipient = [31; 16];
    assert!(validate_recovered_funding_transaction_v2(&state, &other.transaction_data_v2().unwrap(), 20, 200).is_err());
    for purpose in [17, 18, 19, 20, 22] {
        let mut substituted = stop.encode_v2().unwrap();
        substituted[8] = purpose;
        let checksum = Sha256::digest(&substituted[..848]);
        substituted[848..].copy_from_slice(&checksum);
        assert!(RecoveredLifecycleStopFundingDataV2::decode_v2(&substituted).is_err());
        assert!(RecoveredOperationFundingDataV1::decode_v1(&substituted).is_err());
    }
}

#[test]
fn funding_union_uses_only_current_magic_and_keeps_initial_claim_bytes_literal() {
    let (_, pair) = fixture();
    let recovered = OperationIntakeFundingDataV1::RecoveredBaseline(pair[0]);
    let encoded = recovered.encode_v1().unwrap();
    assert_eq!(&encoded[..8], b"AOSOIF02");
    assert_eq!(OperationIntakeFundingDataV1::decode_v1(&encoded).unwrap(), recovered);
    let mut obsolete = encoded;
    obsolete[..8].copy_from_slice(b"AOSOIF01");
    assert!(OperationIntakeFundingDataV1::decode_v1(&obsolete).is_err());

    let (policy, _) = codec::image_policy_tests::fixture(10);
    let claim = bootstrap::delete_operation_intake_claim(pair[0].enrollment, policy).unwrap().unwrap();
    let initial = OperationIntakeFundingDataV1::InitialReservedClaim(claim);
    let encoded = initial.encode_v1().unwrap();
    assert_eq!(&encoded[..8], b"AOSOIF02");
    assert_eq!(&encoded[16..16 + CLAIM_BYTES_V1], claim.encode().unwrap().as_slice());
    assert!(encoded[16 + CLAIM_BYTES_V1..].iter().all(|byte| *byte == 0));
    assert_eq!(OperationIntakeFundingDataV1::decode_v1(&encoded).unwrap(), initial);
}

#[test]
fn stop_seed_requires_the_actual_enrollment_pair_and_never_rolls_its_debit_back() {
    let (mut state, pair) = fixture();
    let complete = ResourceVector::ZERO.with(D::MemoryBytes, 8);
    let stop = RecoveredLifecycleStopFundingDataV2 {
        enrollment: pair[0].enrollment, recipient: pair[0].recipient, baseline: pair[0].baseline,
        charged_before: pair[1].charged_after, charged_after: pair[1].charged_after.checked_add(complete).unwrap(),
        complete, controller_next: 20, controller_end: 200,
    };
    let transaction = stop.transaction_data_v2().unwrap();
    assert!(validate_recovered_funding_transaction_v2(&state, &transaction, 20, 200).is_err());

    apply(&mut state, &recovered_funding_pair_transaction_data_v1(&pair).unwrap());
    validate_recovered_funding_transaction_v2(&state, &transaction, 20, 200).unwrap();
    let earlier = RecoveredLifecycleStopFundingDataV2 {
        charged_before: pair[0].charged_before,
        charged_after: pair[0].charged_before.checked_add(complete).unwrap(),
        ..stop
    };
    assert!(validate_recovered_funding_transaction_v2(&state,
        &earlier.transaction_data_v2().unwrap(), 20, 200).is_err());
}
