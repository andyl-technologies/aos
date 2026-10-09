//! UNRUN replay payload/routing vectors; actual protected origin fixtures remain missing.

use super::*;
use aos_sandbox_source_provider_ledger::ledger::native_held_completion::
    derive_original_source_continuations_v5;
use crate::journal::capacity_reservation::native_held::{
    OriginalSourceCapacityRecordV5, OriginalSourceGeometryDataV5,
};

fn canonical_admission() -> (State, JournalTransaction, JournalTransaction, SourceOriginalAdmissionDataV5) {
    let (before, applying, requested) = super::super::tests::original_replay_fixture_v5();
    let limits = JournalLimits::default();
    let generous = compare_source_original_admission_data_v5(
        SourceOriginalAdmissionInputV5 {
            original_before: &before,
            original_applying: &applying,
        },
        limits,
    ).unwrap();
    let floor = generous.initial_floor();
    let provenance = floor.original_provenance();
    let configuration = provenance.claims().configuration;
    let continuation = derive_original_source_continuations_v5(
        owner_views(generous.applying_after()), Some(generous.admission_comparison()),
        provenance, configuration,
    ).unwrap();
    let budgets = OriginalSourceGeometryDataV5::measure_initial_envelopes(
        &continuation, limits,
    ).unwrap();
    let mut initial = floor.request();
    initial.terminal_records = budgets.terminal_records;
    initial.terminal_bytes = budgets.terminal_bytes;
    initial.poison_records = budgets.poison_records;
    initial.poison_bytes = budgets.poison_bytes;
    let floor = OriginalSourceCapacityRecordV5::new(
        initial, *applying.id(), budgets, provenance.clone(),
    ).unwrap();
    let floor_record = floor.to_journal_record().unwrap();
    let mut applying_records = applying.records().to_vec();
    applying_records[4] = floor_record.clone();
    let applying = JournalTransaction::new(*applying.id(), applying_records).unwrap();
    let admission = compare_source_original_admission_data_v5(
        SourceOriginalAdmissionInputV5 {
            original_before: &before,
            original_applying: &applying,
        },
        limits,
    ).unwrap();

    // Keep the same owner mutations and transaction identities. Only their
    // coupled floor DATA uses the actual complete continuation geometry.
    let owner_transaction = JournalTransaction::new(
        *requested.id(), vec![requested.records()[0].clone()],
    ).unwrap();
    let requested_owners = crate::journal::root_original_inventory::materialize(
        admission.applying_after(), &owner_transaction,
    );
    let continuation = derive_original_source_continuations_v5(
        owner_views(&requested_owners), Some(admission.admission_comparison()),
        floor.original_provenance(), configuration,
    ).unwrap();
    let geometry = OriginalSourceGeometryDataV5::measure_remaining(
        &floor, &continuation, limits,
    ).unwrap();
    let successor = OriginalSourceCapacityRecordV5::new(
        geometry.remaining_request().unwrap(), *applying.id(), budgets,
        floor.original_provenance().clone(),
    ).unwrap();
    let requested = JournalTransaction::new(*requested.id(), vec![
        requested.records()[0].clone(),
        crate::journal::JournalRecord::delete(
            RecordNamespace::GlobalCapacityReservation, floor_record.key().to_vec(),
        ),
        successor.to_journal_record().unwrap(),
    ]).unwrap();

    (before, applying, requested, admission)
}

#[test]
fn generous_initial_budget_data_refuses_complete_replay_union() {
    let (before, applying, _) = super::super::tests::original_replay_fixture_v5();
    let limits = JournalLimits::default();
    let admission = compare_source_original_admission_data_v5(
        SourceOriginalAdmissionInputV5 {
            original_before: &before,
            original_applying: &applying,
        },
        limits,
    ).unwrap();
    let mut cache = SourceOriginalReplayCacheV5::default();
    cache.retain_admission(admission, &applying, limits).unwrap();

    assert!(matches!(
        cache.compare_rows(&before, Some(&applying), &[], limits),
        Err(JournalError::MalformedRecord("original Source capacity bindings or budgets")),
    ));
    assert_eq!(cache.origins.len(), 1);
    assert!(cache.origins[0].retained_retirement().is_none());
}

#[test]
fn canonical_original_retention_reuses_exact_union_for_applying_and_requested() {
    let (before, applying, requested, admission) = canonical_admission();
    let after = admission.applying_after().clone();
    let acquisition = admission.admission_comparison().original().acquisition_id;
    let mut cache = SourceOriginalReplayCacheV5::default();
    cache.retain_admission(admission, &applying, JournalLimits::default()).unwrap();

    let applying_comparison = cache.compare_rows(
        &before, Some(&applying), &[], JournalLimits::default(),
    ).unwrap().0;
    let requested_comparison = cache.compare_rows(
        &after, Some(&requested), &[], JournalLimits::default(),
    ).unwrap().0;

    assert_eq!(cache.origins.len(), 1);
    assert_eq!(cache.origins[0].admission_comparison().original().acquisition_id, acquisition);
    assert_eq!(applying_comparison.after(), &after);
    assert!(cache.has_dependencies());
    assert!(requested_comparison.requires_physical_owner_proofs());
    assert!(cache.origins[0].retained_retirement().is_none());
}

#[test]
fn canonical_reordered_transaction_and_wrong_current_rows_refuse() {
    let (_, applying, requested, admission) = canonical_admission();
    let after = admission.applying_after().clone();
    let mut cache = SourceOriginalReplayCacheV5::default();
    cache.retain_admission(admission, &applying, JournalLimits::default()).unwrap();
    let mut reordered = requested.records().to_vec();
    reordered.rotate_left(1);
    let reordered = JournalTransaction::new(*requested.id(), reordered).unwrap();
    let mut missing = after.clone();
    // The genuine fixture's second Applying mutation is its Acquisition.
    missing.remove(&(RecordNamespace::SourceProviderAuthority, applying.records()[1].key().to_vec()));

    assert!(cache.compare_rows(&after, Some(&reordered), &[], JournalLimits::default()).is_err());
    assert!(cache.compare_rows(&missing, Some(&requested), &[], JournalLimits::default()).is_err());
    assert_eq!(cache.origins.len(), 1);
    assert!(cache.origins[0].retained_retirement().is_none());
}

#[test]
fn retained_original_payload_is_bounded_before_cache_installation() {
    let (before, applying, _, admission) = canonical_admission();
    let limits = JournalLimits::default();
    let exact = super::super::bounded_snapshot_bytes(&before, limits).unwrap()
        + super::super::bounded_snapshot_bytes(admission.applying_after(), limits).unwrap()
        + admission_payload_bound(&before, &applying).unwrap();
    let mut cache = SourceOriginalReplayCacheV5::default();
    let short = JournalLimits { maximum_materialized_bytes: exact - 1, ..limits };

    assert!(cache.retain_admission(admission.clone(), &applying, short).is_err());
    assert!(cache.origins.is_empty());
    assert_eq!(cache.retained_bytes, 0);
    cache.retain_admission(admission, &applying, JournalLimits {
        maximum_materialized_bytes: exact, ..limits
    }).unwrap();
    assert_eq!(cache.retained_bytes, exact);
}

#[test]
fn retained_full_before_map_can_share_only_an_exact_cut() {
    let (before, _, _, mut admission) = canonical_admission();
    let retained = Arc::new(before.clone());
    admission.reuse_retained_before(&retained).unwrap();
    assert!(Arc::ptr_eq(&retained, &admission.retained_cut_rows().0));

    let mut foreign = before;
    foreign.insert((RecordNamespace::SourceProviderAuthority, vec![255]), vec![255]);
    assert!(admission.reuse_retained_before(&Arc::new(foreign)).is_err());
    assert!(Arc::ptr_eq(&retained, &admission.retained_cut_rows().0));
}

#[test]
fn exact_prospective_payload_charges_put_growth_and_actual_delete_once() {
    let mut before = State::new();
    before.insert((RecordNamespace::SourceProviderAuthority, vec![1]), vec![2; 10]);
    before.insert((RecordNamespace::GlobalCapacityReservation, vec![3; 75]), vec![4; 262]);
    let transaction = JournalTransaction::new([1; 16], vec![
        super::super::super::JournalRecord::put(RecordNamespace::SourceProviderAuthority,
            vec![1], vec![5; 20]),
        super::super::super::JournalRecord::delete(RecordNamespace::GlobalCapacityReservation, vec![3; 75]),
    ]).unwrap();
    let original = before.clone();

    assert_eq!(prospective_payload_bytes(&before, &transaction, 348).unwrap(), 21);
    assert_eq!(before, original);
    assert!(prospective_payload_bytes(&before, &transaction, 0).is_err());
    assert!(prospective_payload_bytes(&State::new(), &transaction, usize::MAX).is_err());
}

#[test]
fn arbitrary_version_five_capacity_bytes_do_not_create_source_dependencies() {
    let mut value = vec![0; 300];
    value[..8].copy_from_slice(b"AOSJCR01");
    value[8..10].copy_from_slice(&5_u16.to_be_bytes());

    assert!(!is_original_row(RecordNamespace::GlobalCapacityReservation, &[1; 75], &value));
    assert!(!is_original_row(RecordNamespace::DesiredState, &[1], &value));
}

#[test]
fn retired_dependencies_remain_live_for_compaction_even_without_own_debt() {
    let mut cache = SourceOriginalReplayCacheV5::default();
    let mut state = State::new();
    let mut held = vec![0; 12];
    held[..8].copy_from_slice(b"AOSSPL01");
    held[8..10].copy_from_slice(&8_u16.to_be_bytes());
    state.insert((RecordNamespace::SourceProviderAuthority, vec![1]), held);
    cache.observe_compaction(&state);

    assert!(cache.needs_closure());
    assert!(cache.has_dependencies());
    assert!(cache.preview_transaction(&state,
        &JournalTransaction::new([1; 16], vec![super::super::super::JournalRecord::put(
            RecordNamespace::SourceProviderAuthority, vec![2], vec![3],
        )]).unwrap(), JournalLimits::default()).is_err());
}
