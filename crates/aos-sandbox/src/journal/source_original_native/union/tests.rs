//! UNRUN policy, full-framing, canonical-union refusal and accounting vectors.
//!
//! The independent legacy preimage is canonical DATA, not an owner graph.
//! Complete original Journal positives still need a shared canonical graph
//! fixture; these helper tests do not claim protected configuration coverage.

use super::*;
use sha2::{Digest as _, Sha256};

fn legacy_row(byte: u8) -> ([u8; 32], JournalRecord) {
    let fields = SourceCapacityBindingFieldsV1 {
        owner_id: [byte; 32], owner_digest: ObjectDigest::from_bytes([2; 32]),
        operation_id: [3; 16], artifact_digest: ObjectDigest::from_bytes([4; 32]),
        checkpoint_digest: ObjectDigest::from_bytes([5; 32]),
        chain_head_digest: ObjectDigest::from_bytes([6; 32]),
    };
    let request = ordinary_request(fields, (4, 4096));
    let mut body = Vec::new();
    body.extend_from_slice(&request.owner_id);
    body.extend_from_slice(&request.owner_digest);
    body.extend_from_slice(&request.operation_id);
    body.extend_from_slice(&request.artifact_digest);
    body.extend_from_slice(&request.checkpoint_digest);
    body.extend_from_slice(&request.chain_head_digest);
    body.extend_from_slice(&request.terminal_records.to_be_bytes());
    body.extend_from_slice(&request.terminal_bytes.to_be_bytes());
    body.extend_from_slice(&request.poison_records.to_be_bytes());
    body.extend_from_slice(&request.poison_bytes.to_be_bytes());
    body.extend_from_slice(&[byte; 16]);
    let identity: [u8; 32] = Sha256::new()
        .chain_update(b"aos.sandbox.journal.global-capacity-reservation.v1\0")
        .chain_update([3, 41]).chain_update(&body).finalize().into();
    let mut value = b"AOSJCR01\0\x01\x29\x03\0\0".to_vec();
    value.extend_from_slice(&body);
    value.extend_from_slice(&identity);
    let key = crate::journal::capacity_reservation::reservation_key_for_validation(identity);
    (identity, JournalRecord::put(RecordNamespace::GlobalCapacityReservation, key, value))
}

#[test]
fn ordinary_policy_preserves_all_fields_namespace_and_release_budget() {
    let binding = NativeReleaseStatusCapacityBindingV1 {
        owner_id: [1; 32], owner_digest: ObjectDigest::from_bytes([2; 32]),
        operation_id: [3; 16], artifact_digest: ObjectDigest::from_bytes([4; 32]),
        checkpoint_digest: ObjectDigest::from_bytes([5; 32]),
        chain_head_digest: ObjectDigest::from_bytes([6; 32]),
    };
    let request = source_native_release_status_capacity_request_v1(binding);

    assert_eq!(request.owner_namespace, RecordNamespace::SourceProviderAuthority);
    assert_eq!(request.purpose, GlobalCapacityReservationPurposeV1::SourceProviderNativeTerminal);
    assert_eq!(request.owner_id, binding.owner_id);
    assert_eq!(request.owner_digest, *binding.owner_digest.as_bytes());
    assert_eq!(request.artifact_digest, *binding.artifact_digest.as_bytes());
    assert_eq!(request.checkpoint_digest, *binding.checkpoint_digest.as_bytes());
    assert_eq!(request.chain_head_digest, *binding.chain_head_digest.as_bytes());
    assert_eq!(request.future_transactions, 1);
    assert_eq!((request.terminal_records, request.terminal_bytes),
        (NATIVE_RELEASE_STATUS_TERMINAL_RECORDS_V1, NATIVE_RELEASE_STATUS_TERMINAL_BYTES_V1));
    assert_eq!((request.poison_records, request.poison_bytes), (request.terminal_records, request.terminal_bytes));
    assert_eq!(SOURCE_NATIVE_NO_DISPATCH_TERMINAL_BYTES_V1, 3 * 1024 * 1024);
}

#[test]
fn selected_aggregate_debt_counts_real_changed_floors_once() {
    let (first, row1) = legacy_row(31);
    let (second, row2) = legacy_row(32);
    let state = [row1, row2].into_iter().map(|row|
        ((row.namespace(), row.key().to_vec()), row.value().unwrap().to_vec())).collect::<State>();

    assert_eq!(selected_debt(&state, &BTreeSet::from([first])).unwrap(), (4, 4096, 1));
    assert_eq!(selected_debt(&state, &BTreeSet::from([first, second])).unwrap(), (8, 8192, 2));
    assert_eq!(selected_debt(&state, &BTreeSet::new()).unwrap(), (0, 0, 0));
    assert!(selected_debt(&state, &BTreeSet::from([[33; 32]])).is_err());
    assert!(compare_source_capacity_union_data_v5(
        &state, None, &[], &[], JournalLimits::default(),
    ).is_err()); // Canonical floors cannot manufacture their missing owners.
}

#[test]
fn full_transaction_charges_actual_ordinary_delete_not_a_budget_label() {
    let (identifier, floor) = legacy_row(34);
    assert_eq!(floor.key().len(), 75);
    assert_eq!(floor.value().unwrap().len(), 262);
    let own = JournalRecord::put(RecordNamespace::SourceProviderAuthority, vec![1; 40], vec![2; 64]);
    let one = JournalTransaction::new([35; 16], vec![own.clone()]).unwrap();
    let delete = JournalRecord::delete(
        RecordNamespace::GlobalCapacityReservation,
        crate::journal::capacity_reservation::reservation_key_for_validation(identifier),
    );
    let both = JournalTransaction::new([36; 16], vec![own, delete]).unwrap();
    let first_bytes = crate::journal::encoded_transaction_append_bytes(&one).unwrap();
    let full_bytes = crate::journal::encoded_transaction_append_bytes(&both).unwrap();

    assert_eq!(full_bytes - first_bytes, 154);
    assert!(check_bounded_transfer(&both, (2, full_bytes), None, JournalLimits::default(),
        ("records", "spend")).is_ok());
    assert!(check_bounded_transfer(&both, (1, full_bytes), None, JournalLimits::default(),
        ("records", "spend")).is_err());
    assert!(check_bounded_transfer(&both, (2, full_bytes - 1), None, JournalLimits::default(),
        ("records", "spend")).is_err());
}

#[test]
fn opened_payload_key_and_materialized_boundaries_refuse_one_less() {
    let state = State::from([((RecordNamespace::SourceProviderAuthority, vec![1; 40]), vec![2; 64])]);
    let baseline = JournalLimits::default();
    let exact = JournalLimits {
        maximum_key_bytes: 40, maximum_record_bytes: 111,
        maximum_materialized_bytes: 104, maximum_materialized_records: 1, ..baseline
    };
    assert!(bound_source_state(&state, exact).is_ok());
    for short in [
        JournalLimits { maximum_key_bytes: 39, ..exact },
        JournalLimits { maximum_record_bytes: 110, ..exact },
        JournalLimits { maximum_materialized_bytes: 103, ..exact },
        JournalLimits { maximum_materialized_records: 0, ..exact },
    ] {
        assert!(bound_source_state(&state, short).is_err());
    }
}

#[test]
fn actual_all_family_next_bound_counts_unchanged_ordinary_debt_once() {
    let (_, row) = legacy_row(37);
    let state = State::from([((row.namespace(), row.key().to_vec()), row.value().unwrap().to_vec())]);
    assert!(crate::journal::root_original_inventory::require_sequence_headroom(&state, u64::MAX - 6).is_ok());
    assert!(crate::journal::root_original_inventory::require_sequence_headroom(&state, u64::MAX - 5).is_err());
}

// This harness is deliberately not #[test]: no shared cross-crate canonical
// Applying/held/cold graph factory is available in this module.
#[allow(dead_code)]
fn complete_original_union_fixture_harness(
    before: &State,
    transaction: &JournalTransaction,
    origins: &[SourceOriginalAdmissionDataV5],
    challenges: &[OriginalSourceChallengeDataV5<'_>],
) {
    let limits = JournalLimits::default();
    let result = compare_source_capacity_union_data_v5(
        before, Some(transaction), origins, challenges, limits,
    ).unwrap();
    assert!(result.requires_physical_owner_proofs());
    let mut reordered = transaction.records().to_vec();
    reordered.rotate_left(1);
    let reordered = JournalTransaction::new(*transaction.id(), reordered).unwrap();
    assert!(compare_source_capacity_union_data_v5(
        before, Some(&reordered), origins, challenges, limits,
    ).is_err());
}
