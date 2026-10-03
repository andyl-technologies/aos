//! UNRUN pure coupled-source, retained-DATA and independent framing vectors.
//!
//! No test opens a protected journal, mints a receipt, samples a clock/nonce,
//! signs through current custody, or qualifies executable funding.

use super::*;
use super::super::capacity_reservation::native_held::{
    NativeHeldCapacityAppendV2, NativeHeldCapacityChangeV3, NativeHeldCapacityPathV3,
    NativeHeldCapacityRecordV3, NativeHeldCapacityStepV3, OriginalSourceCapacityBudgetsV5,
};
use super::super::{encoded_transaction_append_bytes, encoded_transaction_record_bytes};
use aos_sandbox_source_provider_ledger::ledger::{
    format,
    model::DecodedRecordV1,
    native_completion::{OriginalSourceProvenanceV5, classify_original_source_owner_v5},
};

mod fixtures;

/// Shares only canonical DATA from the unchanged private Applying fixture.
pub(super) fn original_replay_fixture_v5() -> (State, JournalTransaction, JournalTransaction) {
    let fixture = fixtures::fixture();
    (fixture.before, fixture.applying, fixture.requested)
}

fn configuration() -> ObjectDigest {
    ObjectDigest::from_bytes([102; 32])
}

fn compare_applying(fixture: &fixtures::Fixture) -> OriginalSourceAppendCandidateV5 {
    compare_original_source_applying_transaction_v5(
        &fixture.before,
        &fixture.applying,
        configuration(),
        JournalLimits::default(),
    )
    .unwrap()
}

fn compare_requested(
    fixture: &fixtures::Fixture,
    admission: &OriginalSourceAppendCandidateV5,
) -> OriginalSourceAppendCandidateV5 {
    compare_original_source_requested_transaction_v5(
        &admission.after,
        &fixture.requested,
        admission,
        configuration(),
        JournalLimits::default(),
    )
    .unwrap()
}

fn with_records(id: [u8; 16], records: Vec<JournalRecord>) -> JournalTransaction {
    JournalTransaction::new(id, records).unwrap()
}

fn replace_applying_floor(
    fixture: &fixtures::Fixture,
    floor: &OriginalSourceCapacityRecordV5,
) -> JournalTransaction {
    let mut records = fixture.applying.records().to_vec();
    records[4] = floor.to_journal_record().unwrap();
    with_records(*fixture.applying.id(), records)
}

fn changed_floor(
    original: &OriginalSourceCapacityRecordV5,
    request: super::super::capacity_reservation::native_held::NativeHeldCapacityRequestV3,
) -> OriginalSourceCapacityRecordV5 {
    OriginalSourceCapacityRecordV5::new(
        request,
        original.admission_transaction_id(),
        original.origin_budgets(),
        original.original_provenance().clone(),
    )
    .unwrap()
}

#[test]
fn exact_applying_requested_and_independent_framing_are_comparison_data() {
    let fixture = fixtures::fixture();
    let admission = compare_applying(&fixture);
    let requested = compare_requested(&fixture, &admission);
    let floor_width = fixture.applying.records()[4].value().unwrap().len() as u64;
    let owner_values: u64 = fixture.applying.records()[..4]
        .iter()
        .map(|record| record.value().unwrap().len() as u64)
        .sum();
    let held_width = fixture.requested.records()[0].value().unwrap().len() as u64;

    assert_eq!(
        admission.owner.data().prefix,
        OriginalSourceOwnerPrefixV5::Applying,
    );
    assert_eq!(
        requested.owner.data().prefix,
        OriginalSourceOwnerPrefixV5::Requested,
    );
    assert_eq!(admission.floor.request().future_transactions, 20);
    assert_eq!(requested.floor.request().future_transactions, 19);
    assert_eq!(admission.transaction.records().len(), 5);
    assert_eq!(requested.transaction.records().len(), 3);
    assert_eq!(
        encoded_transaction_append_bytes(&admission.transaction).unwrap(),
        1015 + owner_values + floor_width,
    );
    assert_eq!(
        encoded_transaction_record_bytes(&admission.transaction).unwrap(),
        471 + owner_values + floor_width,
    );
    assert_eq!(
        encoded_transaction_append_bytes(&requested.transaction).unwrap(),
        611 + held_width + floor_width,
    );
    assert_eq!(
        encoded_transaction_record_bytes(&requested.transaction).unwrap(),
        211 + held_width + floor_width,
    );
    assert_eq!(requested.original_transaction(), &fixture.applying);
    assert_eq!(requested.original_floor(), &fixture.initial_floor);

    compare_readback_data(
        &admission,
        &fixture.before,
        &admission.after,
        &fixture.applying,
        10,
        16,
        17,
    )
    .unwrap();
    compare_readback_data(
        &requested,
        &admission.after,
        &requested.after,
        &fixture.requested,
        17,
        21,
        22,
    )
    .unwrap();
}

#[test]
fn applying_requires_before_to_after_reservation_not_after_classification() {
    let fixture = fixtures::fixture();
    let admission = compare_applying(&fixture);
    let mut bad_before = fixture.before.clone();
    let witnesses = &fixture.initial_floor.original_provenance().claims().records;
    let holder_key = (
        RecordNamespace::SourceProviderAuthority,
        witnesses[2].key().to_vec(),
    );
    let DecodedRecordV1::Session(mut idle) =
        format::decode_record(&holder_key.1, &bad_before[&holder_key]).unwrap()
    else {
        panic!("idle holder");
    };
    idle.revision += 1;
    bad_before.insert(holder_key, format::encode_session(&idle));
    bad_before.insert(
        (
            RecordNamespace::SourceProviderAuthority,
            witnesses[3].key().to_vec(),
        ),
        format::encode_session_history(&idle),
    );

    // The SAME after graph still classifies: only the exact predecessor join
    // exposes the changed reservation revision.
    classify_original_source_owner_v5(
        owner_views(&admission.after),
        fixture.initial_floor.original_provenance(),
        configuration(),
    )
    .unwrap();
    let comparison = compare_original_source_applying_transaction_v5(
        &bad_before,
        &fixture.applying,
        configuration(),
        JournalLimits::default(),
    );

    assert!(comparison.is_err());
}

#[test]
fn coupled_order_counts_deletes_noops_and_foreign_records_are_rejected() {
    let fixture = fixtures::fixture();
    let base = fixture.applying.records().to_vec();
    let mut swapped = base.clone();
    swapped.swap(0, 1);
    let mut deleted = base.clone();
    deleted[0] = JournalRecord::delete(deleted[0].namespace(), deleted[0].key().to_vec());
    let mut duplicated = base.clone();
    duplicated[1] = duplicated[0].clone();
    let mut noop = base.clone();
    let holder_key = (
        RecordNamespace::SourceProviderAuthority,
        noop[2].key().to_vec(),
    );
    noop[2] = JournalRecord::put(
        holder_key.0,
        holder_key.1.clone(),
        fixture.before[&holder_key].clone(),
    );
    let mut foreign = base.clone();
    foreign[0] = JournalRecord::put(
        RecordNamespace::DesiredState,
        foreign[0].key().to_vec(),
        vec![1],
    );
    let mut extra = base.clone();
    extra.push(JournalRecord::put(
        RecordNamespace::SourceProviderAuthority,
        vec![1],
        vec![2],
    ));

    for (case, records) in [
        ("order", swapped),
        ("delete", deleted),
        ("duplicate", duplicated),
        ("noop", noop),
        ("foreign", foreign),
        ("extra", extra),
        ("missing", base[..4].to_vec()),
    ] {
        let transaction = with_records([30; 16], records);
        let comparison = compare_original_source_applying_transaction_v5(
            &fixture.before,
            &transaction,
            configuration(),
            JournalLimits::default(),
        );

        assert!(comparison.is_err(), "{case}");
    }
}

#[test]
fn every_floor_is_validated_before_the_own_source_selection() {
    let fixture = fixtures::fixture();
    let admission = compare_applying(&fixture);
    let mut malformed = admission.after.clone();
    malformed.insert(
        (RecordNamespace::GlobalCapacityReservation, vec![255; 75]),
        b"AOSJCR01\0\x05\x29\x0c\0\0".to_vec(),
    );

    let comparison = compare_original_source_requested_transaction_v5(
        &malformed,
        &fixture.requested,
        &admission,
        configuration(),
        JournalLimits::default(),
    );

    assert!(comparison.is_err());
}

#[test]
fn binding_substitutions_with_refreshed_floor_identity_are_rejected() {
    let fixture = fixtures::fixture();
    let initial = &fixture.initial_floor;
    let mut owner_digest = initial.request();
    owner_digest.owner_digest = [103; 32];
    let mut operation = initial.request();
    operation.operation_id = [104; 16];

    for request in [owner_digest, operation] {
        let changed = changed_floor(initial, request);
        let transaction = replace_applying_floor(&fixture, &changed);
        OriginalSourceCapacityRecordV5::from_journal_record(&transaction.records()[4]).unwrap();

        let comparison = compare_original_source_applying_transaction_v5(
            &fixture.before,
            &transaction,
            configuration(),
            JournalLimits::default(),
        );

        assert!(comparison.is_err());
    }
}

#[test]
fn applying_comparison_does_not_claim_future_funding_from_scalar_budgets() {
    let fixture = fixtures::fixture();
    let mut request = fixture.initial_floor.request();
    request.terminal_records = 1;
    request.terminal_bytes = 1;
    request.poison_records = 1;
    request.poison_bytes = 1;
    let floor = OriginalSourceCapacityRecordV5::new(
        request,
        [30; 16],
        OriginalSourceCapacityBudgetsV5 {
            terminal_records: 1,
            terminal_bytes: 1,
            poison_records: 1,
            poison_bytes: 1,
        },
        fixture.initial_floor.original_provenance().clone(),
    )
    .unwrap();

    // Exact DATA can compare even with an envelope too small for Requested.
    // No production route consumes this result as sufficient admission.
    let admission = compare_original_source_applying_transaction_v5(
        &fixture.before,
        &replace_applying_floor(&fixture, &floor),
        configuration(),
        JournalLimits::default(),
    )
    .unwrap();

    assert_eq!(admission.floor.request().terminal_bytes, 1);
    let comparison = compare_original_source_requested_transaction_v5(
        &admission.after,
        &fixture.requested,
        &admission,
        configuration(),
        JournalLimits::default(),
    );

    assert!(comparison.is_err());
}

#[test]
fn requested_origin_count_and_transfer_budget_substitutions_are_rejected() {
    let fixture = fixtures::fixture();
    let admission = compare_applying(&fixture);
    let next = OriginalSourceCapacityRecordV5::from_journal_record(
        &fixture.requested.records()[2],
    )
    .unwrap();
    let mut wrong_count = next.request();
    wrong_count.future_transactions = 18;
    let mut overspent = next.request();
    overspent.terminal_records = fixture.initial_floor.request().terminal_records;
    overspent.poison_records = fixture.initial_floor.request().poison_records;

    for request in [wrong_count, overspent] {
        let changed = changed_floor(&next, request);
        let mut records = fixture.requested.records().to_vec();
        records[2] = changed.to_journal_record().unwrap();

        let transaction = with_records([31; 16], records);
        let comparison = compare_original_source_requested_transaction_v5(
            &admission.after,
            &transaction,
            &admission,
            configuration(),
            JournalLimits::default(),
        );

        assert!(comparison.is_err());
    }
}

#[test]
fn changed_origin_archive_is_not_repaired_by_reproducing_a_self_id() {
    let fixture = fixtures::fixture();
    let admission = compare_applying(&fixture);
    let next = OriginalSourceCapacityRecordV5::from_journal_record(
        &fixture.requested.records()[2],
    )
    .unwrap();
    let mut claims = next.original_provenance().claims().clone();
    claims.journal_sequence += 1;
    let provenance = OriginalSourceProvenanceV5::new_untrusted(claims).unwrap();
    let changed = OriginalSourceCapacityRecordV5::new(
        next.request(),
        next.admission_transaction_id(),
        next.origin_budgets(),
        provenance,
    )
    .unwrap();

    assert_ne!(
        changed.origin_reservation_id().unwrap(),
        admission.floor.reservation_id(),
    );
    assert!(compare_origin_floor_data(&admission, &changed).is_err());
}

#[test]
fn readback_requires_all_ordered_tx_bytes_and_unchanged_unrelated_rows() {
    let fixture = fixtures::fixture();
    let admission = compare_applying(&fixture);
    let mut records = fixture.applying.records().to_vec();
    records.swap(0, 1);
    let same_id_different_tx = with_records(*fixture.applying.id(), records);
    let mut changed = admission.after.clone();
    let unrelated_key = fixture.before.keys().next().unwrap().clone();
    changed.get_mut(&unrelated_key).unwrap().push(1);

    assert!(compare_readback_data(
        &admission, &fixture.before, &admission.after, &same_id_different_tx, 1, 7, 8,
    )
    .is_err());
    assert!(compare_readback_data(
        &admission, &fixture.before, &changed, &fixture.applying, 1, 7, 8,
    )
    .is_err());
    assert!(compare_original_source_requested_transaction_v5(
        &changed, &fixture.requested, &admission, configuration(), JournalLimits::default(),
    )
    .is_err());
}

#[test]
fn frame_positions_are_checked_next_frame_data_not_receipts() {
    let fixture = fixtures::fixture();

    compare_frame_positions(&fixture.applying, 1, 7, 8).unwrap();
    compare_frame_positions(&fixture.requested, 8, 12, 13).unwrap();
    for (before, commit, after) in [(0, 6, 7), (1, 8, 8), (1, 7, 7), (1, 6, 8)] {
        assert!(compare_frame_positions(&fixture.applying, before, commit, after).is_err());
    }
    assert!(compare_frame_positions(&fixture.applying, u64::MAX, u64::MAX, u64::MAX).is_err());
}

#[test]
fn pure_refusal_does_not_drop_the_owned_candidate_and_origin_data() {
    let fixture = fixtures::fixture();
    let admission = compare_applying(&fixture);
    let requested = compare_requested(&fixture, &admission);
    let retained_tx = requested.transaction.clone();
    let retained_origin = requested.original_transaction().clone();

    assert!(compare_readback_data(
        &requested, &admission.after, &requested.after, &fixture.requested, 8, 13, 13,
    )
    .is_err());

    assert_eq!(requested.transaction, retained_tx);
    assert_eq!(requested.original_transaction(), &retained_origin);
    assert_eq!(requested.original_floor().request().future_transactions, 20);
}

#[test]
fn failed_comparisons_leave_caller_owned_transactions_unchanged() {
    let fixture = fixtures::fixture();
    let retained_applying = fixture.applying.clone();
    let retained_requested = fixture.requested.clone();
    let wrong_configuration = ObjectDigest::from_bytes([103; 32]);

    assert!(compare_original_source_applying_transaction_v5(
        &fixture.before,
        &fixture.applying,
        wrong_configuration,
        JournalLimits::default(),
    )
    .is_err());
    assert_eq!(fixture.applying, retained_applying);

    let admission = compare_applying(&fixture);
    assert!(compare_original_source_requested_transaction_v5(
        &admission.after,
        &fixture.requested,
        &admission,
        wrong_configuration,
        JournalLimits::default(),
    )
    .is_err());

    assert_eq!(fixture.requested, retained_requested);
    assert_eq!(admission.transaction, retained_applying);
}

#[test]
fn materialized_and_per_transaction_limits_refuse_without_expansion() {
    let fixture = fixtures::fixture();
    let mut limits = JournalLimits::default();
    limits.maximum_records_per_transaction = 4;
    assert!(compare_original_source_applying_transaction_v5(
        &fixture.before, &fixture.applying, configuration(), limits,
    )
    .is_err());

    limits = JournalLimits::default();
    limits.maximum_materialized_records = fixture.before.len();
    assert!(compare_original_source_applying_transaction_v5(
        &fixture.before, &fixture.applying, configuration(), limits,
    )
    .is_err());

    limits = JournalLimits::default();
    limits.maximum_materialized_bytes = fixture.before.iter()
        .map(|((_, key), value)| key.len() + value.len()).sum();
    assert!(compare_original_source_applying_transaction_v5(
        &fixture.before, &fixture.applying, configuration(), limits,
    )
    .is_err());
}

fn terminal_suffix() -> NativeHeldCapacitySuffixV2<'static> {
    let key = vec![7; 40];
    let first = NativeHeldCapacityAppendV2::provider(
        NativeHeldCapacityStepV3::ProviderRootTerminalStored,
        [51; 16],
        vec![NativeHeldCapacityChangeV3::new(
            key.clone(), Some(vec![1]), Some(vec![2]),
        )
        .unwrap()],
    )
    .unwrap();
    let cleanup = NativeHeldCapacityAppendV2::provider(
        NativeHeldCapacityStepV3::ProviderLifecycleCleanup,
        [52; 16],
        vec![NativeHeldCapacityChangeV3::new(key, Some(vec![2]), None).unwrap()],
    )
    .unwrap();
    NativeHeldCapacitySuffixV2::new(
        NativeHeldCapacityPurposeV3::Provider,
        NativeHeldCapacityPathV3::Normal,
        vec![first, cleanup],
    )
    .unwrap()
}

#[test]
fn shared_width_factor_preserves_old_266_and_owner_only_growth() {
    let fixture = fixtures::fixture();
    let suffix = terminal_suffix();
    let old = suffix.measure(JournalLimits::default()).unwrap();
    let source = measure_source_suffix_data(
        &fixture.initial_floor, &suffix, JournalLimits::default(),
    )
    .unwrap();
    let width = fixture.initial_floor.to_journal_record().unwrap().value().unwrap().len() as u64;

    // First transfer:40PUT/value1 +75DEL +75PUT/valueF; cleanup:40DEL +75DEL.
    assert_eq!(old.append_bytes, (612 + 266) + 457);
    assert_eq!(source.append_bytes, (612 + width) + 457);
    assert_eq!(source.records, 5);
    assert_eq!(source.maximum_transaction_record_bytes, 212 + width);
    assert_eq!(source.maximum_retained_growth_bytes, old.maximum_retained_growth_bytes);
    assert_eq!(source.maximum_retained_growth_records, old.maximum_retained_growth_records);
    assert_eq!(old.maximum_retained_growth_bytes, 0);
    assert_eq!(old.maximum_retained_growth_records, 0);
    assert_eq!(source.transactions, 2);

    assert!(NativeHeldCapacityRecordV3::new(
        fixture.initial_floor.request(), [30; 16],
    )
    .is_err());
    assert_eq!(NativeHeldCapacityPurposeV3::Provider.maximum_future_transactions(), 19);
}
