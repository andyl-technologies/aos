//! UNRUN discoverable helper vectors and unexercised full-comparator harnesses.
//!
//! Helper tests do not substitute for retained protected configuration plus
//! actual complete owner graphs. The five named full-comparator vectors below
//! are intentionally non-`#[test]`: no configuration factory or authority exists.

use super::*;
use aos_sandbox::journal::native_held::{NativeHeldCapacityPurposeV3, NativeHeldCapacityRecordV3};

mod fixtures;

// Not #[test]: genuine archived public custody/current configuration/full cuts
// are unavailable here. This harness is explicitly NOT coverage or Source GO.
#[allow(dead_code)]
fn archived_durable_cut_with_independent_current_eligibility_harness(
    state: &State,
    archived: &aos_sandbox_source_provider_security::ProtectedOriginalDeploymentV5,
    current: &ProtectedProviderConfigurationV1,
) {
    let recovered = authenticate_archived_complete_cut_v5(state, archived, current).unwrap();
    let durable = ProtectedProviderConfigurationV1::from_original_archive_v5(archived).unwrap();

    assert!(durable.matches_authority_and_catalog(&recovered.authority, &recovered.catalog));
    // Today's catalog floor/head need not equal this old durable cut. Its
    // issuance/revocation policy still authenticates these SAME retained facts.
}

#[test]
fn shared_union_admission_refuses_floor_only_data_and_preserves_borrowed_transaction() {
    let before = fixtures::floor_only_union_state();
    let floor = fixtures::floor().to_journal_record().unwrap();
    let transaction = JournalTransaction::new([199; 16], vec![floor]).unwrap();
    let retained = transaction.clone();

    assert!(aos_sandbox::journal::compare_source_original_admission_data_v5(
        aos_sandbox::journal::SourceOriginalAdmissionInputV5 {
            original_before: &before, original_applying: &transaction,
        },
        aos_sandbox::JournalLimits::default(),
    ).is_err());
    assert!(aos_sandbox::journal::compare_source_capacity_union_data_v5(
        &before, None, &[], &[], aos_sandbox::JournalLimits::default(),
    ).is_err());
    assert_eq!(transaction, retained);
}

// Not #[test]: this needs genuine retained ProtectedConfig/current graph inputs.
// Existing five full-comparator harnesses remain noncoverage too.
#[allow(dead_code)]
fn authenticated_all_prefix_union_fixture_harness(
    before: &State,
    transaction: &JournalTransaction,
    origins: &[aos_sandbox::journal::SourceOriginalAdmissionDataV5],
    challenges: &[aos_sandbox_source_provider_ledger::ledger::source_capacity::OriginalSourceChallengeDataV5<'_>],
    configuration: &ProtectedProviderConfigurationV1,
) {
    let result = compare_authenticated_source_capacity_union_data_v5(
        before, Some(transaction), origins, challenges, configuration,
        aos_sandbox::JournalLimits::default(),
    ).unwrap();
    assert!(result.comparison.requires_physical_owner_proofs());
    assert_eq!(result.configuration_origin, UnresolvedNativeProofV1::Unresolved);
    assert_eq!(result.original_physical_membership, UnresolvedNativeProofV1::Unresolved);
    assert_eq!(result.archive_eligibility, UnresolvedNativeProofV1::Unresolved);
    assert_eq!(result.whole_journal_funding, UnresolvedNativeProofV1::Unresolved);
}

fn digest(byte: u8) -> ObjectDigest {
    ObjectDigest::from_bytes([byte; 32])
}

fn state_with(rows: &[JournalRecord]) -> State {
    rows.iter().map(|row| {
        ((row.namespace(), row.key().to_vec()), row.value().unwrap().to_vec())
    }).collect()
}

#[test]
fn full_canonical_inventory_retains_original_row_and_admission_bytes() {
    let floor = fixtures::floor();
    let row = floor.to_journal_record().unwrap();
    let inventory = Floors::collect_original_source_comparison(vec![row.clone()]).unwrap();
    let entry = &inventory.0[&floor.reservation_id()];

    assert_eq!(entry.row, row);
    assert_eq!(entry.admission_transaction_id, floor.admission_transaction_id());
    assert!(matches!(&entry.floor, Floor::OriginalSource(actual) if actual == &floor));
}

#[test]
fn selected_floor_borrows_the_existing_inventory_entry() {
    let admission = fixtures::origin(fixtures::floor());
    let floor = &admission.initial_floor;
    let inventory = Floors::collect_original_source_comparison(vec![
        floor.to_journal_record().unwrap(),
    ]).unwrap();
    let Floor::OriginalSource(stored) = &inventory.0[&floor.reservation_id()].floor else {
        panic!("canonical Source5 entry");
    };

    let selected = {
        let lookup = fixtures::origin(floor.clone());
        selected_floor(&inventory, &lookup).unwrap().unwrap()
    };

    assert!(std::ptr::eq(selected, stored));
    assert_eq!(selected, floor);
}

#[test]
fn selected_floor_matches_canonical_recollection_at_each_edge_count() {
    let admission = fixtures::origin(fixtures::floor());
    let (_, legacy) = fixtures::legacy_row(43);
    for count in [20, 19, 2, 1] {
        let floor = fixtures::successor(&admission.initial_floor, count);
        let row = floor.to_journal_record().unwrap();
        let state = state_with(&[row.clone(), legacy.clone()]);
        let inventory = Floors::collect_original_source_comparison(capacity_rows(&state)).unwrap();
        let canonical = OriginalSourceCapacityRecordV5::from_journal_record(&row).unwrap();

        let selected = selected_floor(&inventory, &admission).unwrap().unwrap();

        assert_eq!(selected, &canonical, "count {count}");
        assert_eq!(selected.to_journal_record().unwrap(), row);
        assert_eq!(inventory.0.len(), 2);
    }
}

#[test]
fn selected_floor_is_absent_without_the_typed_original_source_row() {
    let admission = fixtures::origin(fixtures::floor());
    let (_, legacy) = fixtures::legacy_row(44);
    let mut native_request = admission.initial_floor.request();
    native_request.future_transactions = 19;
    let native = NativeHeldCapacityRecordV3::new(native_request, [45; 16])
        .unwrap()
        .to_journal_record();
    let inventories = [
        Vec::new(),
        vec![legacy],
        // An equal owner ID in another family cannot substitute for Source5.
        vec![native],
    ];

    for rows in inventories {
        let inventory = Floors::collect_original_source_comparison(rows).unwrap();

        assert!(selected_floor(&inventory, &admission).unwrap().is_none());
    }
}

#[test]
fn selected_floor_rejects_duplicate_owner_identity_in_either_record_order() {
    let admission = fixtures::origin(fixtures::floor());
    let original = admission.initial_floor.to_journal_record().unwrap();
    let successor = fixtures::successor(&admission.initial_floor, 19)
        .to_journal_record()
        .unwrap();
    assert_ne!(original.key(), successor.key());
    let inventories = [
        vec![original.clone(), successor.clone()],
        vec![successor, original],
    ];

    for rows in inventories {
        let inventory = Floors::collect_original_source_comparison(rows).unwrap();

        assert!(selected_floor(&inventory, &admission).is_err());
    }
}

#[test]
fn foreign_native_unknown_and_duplicate_families_fail_closed() {
    let floor = fixtures::floor();
    let row = floor.to_journal_record().unwrap();
    let mut foreign = floor.request();
    foreign.purpose = NativeHeldCapacityPurposeV3::Root;
    foreign.future_transactions = 1;
    let foreign = NativeHeldCapacityRecordV3::new(foreign, [14; 16]).unwrap().to_journal_record();
    let mut unknown = row.value().unwrap().to_vec();
    unknown[8..10].copy_from_slice(&6_u16.to_be_bytes());
    let unknown = JournalRecord::put(row.namespace(), row.key().to_vec(), unknown);

    for extra in [row.clone(), foreign, unknown] {
        assert!(Floors::collect_original_source_comparison(vec![row.clone(), extra]).is_err());
    }
    // Query6 refusal is Source-scope behavior, not a permanent unknown-codec claim.
}

#[test]
fn canonical_data_does_not_establish_an_original_owner_or_admission() {
    let floor = fixtures::floor();
    let row = floor.to_journal_record().unwrap();
    validate_capacity_snapshot_data_v2(&state_with(&[row.clone()])).unwrap();
    assert!(classify_original_source_owner_v5(
        std::iter::empty::<(&[u8], &[u8])>(),
        floor.original_provenance(),
        floor.original_provenance().claims().configuration,
    ).is_err());
    let transaction = JournalTransaction::new(floor.admission_transaction_id(), vec![row]).unwrap();
    let retained = transaction.clone();

    assert!(validate_original_admission(&State::new(), &transaction).is_err());
    assert_eq!(transaction, retained);
}

#[test]
fn immutable_origin_and_successor_no_growth_are_independent_checks() {
    let floor = fixtures::floor();
    let next = fixtures::successor(&floor, 19);
    require_retained_floor(&next, &floor).unwrap();
    require_no_budget_growth(&floor, &next).unwrap();
    let mut reduced = next.request();
    reduced.terminal_bytes -= 1;
    let reduced = OriginalSourceCapacityRecordV5::new(
        reduced, next.admission_transaction_id(), next.origin_budgets(),
        next.original_provenance().clone(),
    ).unwrap();

    require_retained_floor(&reduced, &floor).unwrap();
    assert!(require_no_budget_growth(&reduced, &next).is_err());
    let changed = OriginalSourceCapacityRecordV5::new(
        next.request(), [15; 16], next.origin_budgets(), next.original_provenance().clone(),
    ).unwrap();
    assert!(require_retained_floor(&changed, &floor).is_err());
}

#[test]
fn tiny_canonical_origin_remains_data_and_legacy_decode_stays_closed() {
    use aos_sandbox::journal::native_held::OriginalSourceCapacityBudgetsV5;

    let floor = fixtures::floor();
    let mut request = floor.request();
    request.terminal_records = 1;
    request.terminal_bytes = 1;
    request.poison_records = 1;
    request.poison_bytes = 1;
    let tiny = OriginalSourceCapacityRecordV5::new(
        request,
        floor.admission_transaction_id(),
        OriginalSourceCapacityBudgetsV5 {
            terminal_records: 1,
            terminal_bytes: 1,
            poison_records: 1,
            poison_bytes: 1,
        },
        floor.original_provenance().clone(),
    ).unwrap();
    let row = tiny.to_journal_record().unwrap();

    validate_capacity_snapshot_data_v2(&state_with(&[row.clone()])).unwrap();
    assert!(aos_sandbox::decode_capacity_reservation_request_v1(&row).is_err());
    assert_eq!(tiny.request().terminal_bytes, 1);
    // No comparison helper promotes this syntactic budget to whole-journal funding.
}

#[test]
fn all_five_exact_shapes_and_noop_delete_duplicate_refusals_retain_tx() {
    let expected = [
        (OriginalSourceFloorEdgeV5::Applying, (5, 4, None, Some(20))),
        (OriginalSourceFloorEdgeV5::FirstRequested, (3, 1, Some(20), Some(19))),
        (OriginalSourceFloorEdgeV5::ColdClosedPrepared, (7, 5, Some(20), Some(2))),
        (OriginalSourceFloorEdgeV5::ColdClosureStored, (3, 1, Some(2), Some(1))),
        (OriginalSourceFloorEdgeV5::ColdRootAcknowledged, (2, 1, Some(1), None)),
    ];
    for (edge, shape) in expected { assert_eq!(edge.shape(), shape); }
    let row = JournalRecord::put(RecordNamespace::SourceProviderAuthority, vec![1], vec![2]);
    let before = state_with(&[row.clone()]);
    let missing_delete = JournalRecord::delete(RecordNamespace::SourceProviderAuthority, vec![3]);
    for records in [vec![row.clone()], vec![missing_delete], vec![row.clone(), row.clone()]] {
        let transaction = JournalTransaction::new([16; 16], records).unwrap();
        let retained_transaction = transaction.clone();
        let retained_before = before.clone();

        assert!(apply_transaction(&before, &transaction).is_err());
        assert_eq!(transaction, retained_transaction);
        assert_eq!(before, retained_before);
    }
}

#[test]
fn ordered_full_state_reapplication_retains_untouched_floor_bytes() {
    let floor = fixtures::floor();
    let floor_row = floor.to_journal_record().unwrap();
    let old = JournalRecord::put(RecordNamespace::SourceProviderAuthority, vec![1], vec![2]);
    let before = state_with(&[floor_row.clone(), old]);
    let transaction = JournalTransaction::new([17; 16], vec![
        JournalRecord::put(RecordNamespace::SourceProviderAuthority, vec![1], vec![3]),
    ]).unwrap();
    let retained_transaction = transaction.clone();
    let after = apply_transaction(&before, &transaction).unwrap();

    assert_eq!(after[&(floor_row.namespace(), floor_row.key().to_vec())], floor_row.value().unwrap());
    assert_eq!(after[&(RecordNamespace::SourceProviderAuthority, vec![1])], vec![3]);
    assert_eq!(transaction, retained_transaction);
}

#[test]
fn malformed_floor_width_is_bounded_before_inventory_projection() {
    let row = JournalRecord::put(
        RecordNamespace::GlobalCapacityReservation, vec![1; 75],
        vec![0; ORIGINAL_SOURCE_CAPACITY_MAXIMUM_VALUE_BYTES_V5 + 1],
    );
    assert!(bound_state(&state_with(&[row])).is_err());
}

#[test]
fn exact_legacy_obligations_match_once_or_refuse_missing_ambiguous_and_changed_budgets() {
    let (request, first) = fixtures::legacy_row(35);
    let (_, second) = fixtures::legacy_row(36);
    let source = fixtures::floor().to_journal_record().unwrap();
    let one = Floors::collect_original_source_comparison(vec![source, first.clone()]).unwrap();
    let (_, admission, identifier) = aos_sandbox::decode_capacity_reservation_request_v1(&first).unwrap();
    assert_eq!(admission, [35; 16]);
    assert_eq!(one.exact_legacy(request).unwrap(), identifier);
    let mut changed = request;
    changed.terminal_bytes += 1;
    assert!(one.exact_legacy(changed).is_err());
    assert!(Floors::collect_original_source_comparison(Vec::new()).unwrap().exact_legacy(request).is_err());

    let ambiguous = Floors::collect_original_source_comparison(vec![first, second]).unwrap();
    assert!(ambiguous.exact_legacy(request).is_err());
}

#[test]
fn independent_floor_rewrite_or_removal_is_not_own_floor_settlement() {
    let admission = fixtures::origin(fixtures::floor());
    let (_, legacy) = fixtures::legacy_row(37);
    let (_, changed_admission) = fixtures::legacy_row(38);
    let own = admission.initial_floor.to_journal_record().unwrap();
    let before = Floors::collect_original_source_comparison(vec![own.clone(), legacy.clone()]).unwrap();
    let next = fixtures::successor(&admission.initial_floor, 19).to_journal_record().unwrap();
    let after = Floors::collect_original_source_comparison(vec![next.clone(), legacy]).unwrap();
    preserve_other_floors(&before, &after, &admission).unwrap();

    let changed = Floors::collect_original_source_comparison(vec![next.clone(), changed_admission]).unwrap();
    let removed = Floors::collect_original_source_comparison(vec![next]).unwrap();
    assert!(preserve_other_floors(&before, &changed, &admission).is_err());
    assert!(preserve_other_floors(&before, &removed, &admission).is_err());
}

#[test]
fn copied_cold_floor_and_original_provenance_are_exact_data_not_graph_proof() {
    use aos_sandbox_source_provider_protocol::PreparedSourceNoEscapeClosureV1;

    let admission = fixtures::origin(fixtures::floor());
    let archive = fixtures::cold(&admission);
    require_cold_origin(&archive, &admission).unwrap();
    let key = native_completion_key_v2(admission.owner.acquisition_id);
    assert_eq!(SourcePreRequestedColdArchiveV1::from_canonical_bytes(
        &key, &archive.to_canonical_bytes(),
    ).unwrap(), archive);
    assert!(classify_original_source_pre_requested_cold_v1(
        std::iter::once((key.as_slice(), archive.to_canonical_bytes().as_slice())),
        admission.owner.acquisition_id,
    ).is_err());

    let mut copied = archive.initial_source_floor_bytes().to_vec();
    copied[14] ^= 1;
    let changed_floor = SourcePreRequestedColdArchiveV1::new_untrusted(
        copied, archive.prepared().clone(), None, None,
    ).unwrap();
    assert!(require_cold_origin(&changed_floor, &admission).is_err());
    for index in 0..4 {
        let mut claims = archive.prepared().claims().clone();
        match index {
            0 => claims.admission_transaction = [39; 16],
            1 => claims.original_signed_request = digest(40),
            2 => claims.original_root_prepared = digest(41),
            _ => claims.staged_claims = digest(42),
        }
        let prepared = PreparedSourceNoEscapeClosureV1::new_untrusted(
            claims, archive.prepared().signer().clone(),
        ).unwrap();
        let changed = SourcePreRequestedColdArchiveV1::new_untrusted(
            archive.initial_source_floor_bytes().to_vec(), prepared, None, None,
        ).unwrap();
        assert!(require_cold_origin(&changed, &admission).is_err());
    }
}

/// Supplies genuine retained configuration and complete canonical fixture cuts.
///
/// This is only a future harness input contract. It creates no configuration and
/// these full-comparator helpers are unexercised, non-discoverable UNRUN vectors.
struct FullComparisonVector<'a> {
    before: &'a State,
    after: &'a State,
    transaction: &'a JournalTransaction,
    original_before: &'a State,
    applying_transaction: &'a JournalTransaction,
    configuration: &'a ProtectedProviderConfigurationV1,
}

fn full_vector(vector: FullComparisonVector<'_>, edge: OriginalSourceFloorEdgeV5) {
    let retained_tx = vector.transaction.clone();
    let retained_admission = vector.applying_transaction.clone();
    let compared = compare_original_source_floor_union_transaction_v5(
        vector.before, vector.after, vector.transaction,
        OriginalAdmissionComparisonV5 {
            original_before: vector.original_before,
            applying_transaction: vector.applying_transaction,
        },
        vector.configuration, edge,
    ).unwrap();

    assert_eq!(compared.transaction, retained_tx);
    assert_eq!(compared.applying_transaction, retained_admission);
    assert_eq!(&compared.before, vector.before);
    assert_eq!(&compared.after, vector.after);
    assert_eq!(&compared.original_before, vector.original_before);
    for proof in [
        compared.original_physical_membership, compared.configuration_origin,
        compared.archive_eligibility, compared.whole_journal_funding,
    ] { assert_eq!(proof, UnresolvedNativeProofV1::Unresolved); }

    let mut mismatched_after = vector.after.clone();
    mismatched_after.insert((RecordNamespace::SourceProviderAuthority, vec![255]), vec![255]);
    assert!(compare_original_source_floor_union_transaction_v5(
        vector.before, &mismatched_after, vector.transaction,
        OriginalAdmissionComparisonV5 {
            original_before: vector.original_before,
            applying_transaction: vector.applying_transaction,
        },
        vector.configuration, edge,
    ).is_err());
    assert_eq!(vector.transaction, &retained_tx);
    assert_eq!(vector.applying_transaction, &retained_admission);
}

fn full_applying_with_independent_ordinary_debt_unrun(vector: FullComparisonVector<'_>) {
    full_vector(vector, OriginalSourceFloorEdgeV5::Applying);
}

fn full_requested_with_independent_release_debt_unrun(vector: FullComparisonVector<'_>) {
    full_vector(vector, OriginalSourceFloorEdgeV5::FirstRequested);
}

fn full_closed_with_other_original_and_ordinary_debt_unrun(vector: FullComparisonVector<'_>) {
    full_vector(vector, OriginalSourceFloorEdgeV5::ColdClosedPrepared);
}

fn full_stored_with_exact_copied_floor_unrun(vector: FullComparisonVector<'_>) {
    full_vector(vector, OriginalSourceFloorEdgeV5::ColdClosureStored);
}

fn full_ack_with_no_selected_floor_and_preserved_other_debt_unrun(vector: FullComparisonVector<'_>) {
    full_vector(vector, OriginalSourceFloorEdgeV5::ColdRootAcknowledged);
}
