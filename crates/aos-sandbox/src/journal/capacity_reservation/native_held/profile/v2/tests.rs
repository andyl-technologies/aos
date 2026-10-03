//! Syntactic Provider DATA shape/framing and unchanged V3 regression vectors.
//!
//! These small byte-accounting inputs are not canonical Source owner graphs,
//! attained maxima, protected floors or independently legitimate lifecycle proof.

use super::super::super::{
    NativeHeldCapacityAppendV3, NativeHeldCapacitySuffixV3, validate_capacity_snapshot_data_v2,
};
use super::*;
use crate::journal::{RecordNamespace, encoded_transaction_append_bytes};

fn change(width: usize, before: u8, after: Option<u8>) -> NativeHeldCapacityChangeV3 {
    NativeHeldCapacityChangeV3::new(
        vec![1; width],
        Some(vec![before; 16]),
        after.map(|byte| vec![byte; 16]),
    )
    .unwrap()
}

fn suffix(
    path: NativeHeldCapacityPathV3,
    appends: Vec<NativeHeldCapacityAppendV2<'static>>,
) -> NativeHeldCapacitySuffixV2<'static> {
    NativeHeldCapacitySuffixV2::new(NativeHeldCapacityPurposeV3::Provider, path, appends).unwrap()
}

fn request(count: u32) -> NativeHeldCapacityRequestV3 {
    NativeHeldCapacityRequestV3 {
        purpose: NativeHeldCapacityPurposeV3::Provider,
        owner_id: [1; 32],
        owner_digest: [2; 32],
        operation_id: [3; 16],
        artifact_digest: [4; 32],
        checkpoint_digest: [5; 32],
        chain_head_digest: [6; 32],
        future_transactions: count,
        terminal_records: 100,
        terminal_bytes: 100_000,
        poison_records: 100,
        poison_bytes: 100_000,
    }
}

#[test]
fn slot18_pending_retirement_shape_frames_seven_records_and_preserves_cleanup_credit() {
    let changes = [40, 63, 96, 99, 103]
        .into_iter()
        .map(|width| change(width, 1, Some(2)))
        .collect::<Vec<_>>();
    let append = NativeHeldCapacityAppendV2::provider(
        NativeHeldCapacityStepV3::ProviderRootTerminalStored,
        [1; 16],
        changes.clone(),
    )
    .unwrap();
    assert!(
        NativeHeldCapacityAppendV3::new(
            NativeHeldCapacityStepV3::ProviderRootTerminalStored,
            [1; 16],
            changes
        )
        .is_err()
    );
    let final_append = NativeHeldCapacityAppendV2::provider(
        NativeHeldCapacityStepV3::ProviderLifecycleCleanup,
        [2; 16],
        vec![change(40, 2, None)],
    )
    .unwrap();
    let normal = suffix(NativeHeldCapacityPathV3::Normal, vec![final_append.clone()]);
    let cold = suffix(NativeHeldCapacityPathV3::ColdClosed, vec![final_append]);
    let old = NativeHeldCapacityRecordV3::new(request(2), [3; 16]).unwrap();

    let (transaction, next) = provider_native_capacity_transition_v2(
        &append,
        &old,
        Some((&normal, &cold)),
        JournalLimits::default(),
    )
    .unwrap();
    assert_eq!(transaction.records().len(), 7);
    assert_eq!(next.as_ref().unwrap().request().future_transactions, 1);
    assert_eq!(transaction.records()[5].value(), None);
    assert_eq!(transaction.records()[6], next.unwrap().to_journal_record());
    assert!(
        provider_native_capacity_transition_v2(&append, &old, None, JournalLimits::default())
            .is_err()
    );
}

#[test]
fn slot18_pending_retirement_rejects_authority_instead_of_current_session() {
    let changes = [40, 49, 96, 99, 103]
        .into_iter()
        .map(|width| change(width, 1, Some(2)))
        .collect::<Vec<_>>();

    assert!(
        NativeHeldCapacityAppendV2::provider(
            NativeHeldCapacityStepV3::ProviderRootTerminalStored,
            [1; 16],
            changes
        )
        .is_err()
    );
}

#[test]
fn completed_slot18_uses_three_records_and_v3_measurement_is_unchanged() {
    let step = NativeHeldCapacityStepV3::ProviderRootTerminalStored;
    let final_step = NativeHeldCapacityStepV3::ProviderLifecycleCleanup;
    let append =
        NativeHeldCapacityAppendV2::provider(step, [1; 16], vec![change(40, 1, Some(2))]).unwrap();
    let cleanup =
        NativeHeldCapacityAppendV2::provider(final_step, [2; 16], vec![change(40, 2, None)])
            .unwrap();
    let v2 = suffix(
        NativeHeldCapacityPathV3::Normal,
        vec![append.clone(), cleanup.clone()],
    );
    let v3 = NativeHeldCapacitySuffixV3::new(
        NativeHeldCapacityPurposeV3::Provider,
        NativeHeldCapacityPathV3::Normal,
        vec![
            NativeHeldCapacityAppendV3::new(step, [1; 16], vec![change(40, 1, Some(2))]).unwrap(),
            NativeHeldCapacityAppendV3::new(final_step, [2; 16], vec![change(40, 2, None)])
                .unwrap(),
        ],
    )
    .unwrap();
    assert_eq!(
        v2.measure(JournalLimits::default()).unwrap(),
        v3.measure(JournalLimits::default()).unwrap()
    );
    let normal = suffix(NativeHeldCapacityPathV3::Normal, vec![cleanup.clone()]);
    let cold = suffix(NativeHeldCapacityPathV3::ColdClosed, vec![cleanup]);
    let old = NativeHeldCapacityRecordV3::new(request(2), [3; 16]).unwrap();

    let (transaction, _) = provider_native_capacity_transition_v2(
        &append,
        &old,
        Some((&normal, &cold)),
        JournalLimits::default(),
    )
    .unwrap();
    assert_eq!(transaction.records().len(), 3);
    assert_eq!(
        encoded_transaction_append_bytes(&transaction).unwrap(),
        184 + 79 + 40 + 16 + 154 + 420
    );
}

#[test]
fn actual_release_key95_is_v2_cleanup_syntax_only_not_a_legacy_grant() {
    let changes = vec![change(95, 1, Some(2)), change(99, 1, Some(2))];
    assert!(
        NativeHeldCapacityAppendV3::new(
            NativeHeldCapacityStepV3::ProviderLifecycleCleanup,
            [1; 16],
            changes.clone()
        )
        .is_err()
    );
    let cleanup = NativeHeldCapacityAppendV2::provider(
        NativeHeldCapacityStepV3::ProviderLifecycleCleanup,
        [1; 16],
        changes,
    )
    .unwrap();
    let old = NativeHeldCapacityRecordV3::new(request(1), [3; 16]).unwrap();
    let (transaction, next) =
        provider_native_capacity_transition_v2(&cleanup, &old, None, JournalLimits::default())
            .unwrap();
    assert_eq!(transaction.records().len(), 3);
    assert!(next.is_none());
    let record = old.to_journal_record();
    let state = std::collections::BTreeMap::from([(
        (record.namespace(), record.key().to_vec()),
        record.value().unwrap().to_vec(),
    )]);
    assert!(super::super::super::require_legacy_transaction(&state, &transaction).is_err());
}

#[test]
fn suffix_rejects_wrong_slots_duplicate_ids_missing_retirement_and_short_old_budget() {
    assert!(
        NativeHeldCapacityAppendV2::provider(
            NativeHeldCapacityStepV3::RootTerminalAckStored,
            [1; 16],
            vec![change(68, 1, Some(2))]
        )
        .is_err()
    );
    assert!(
        NativeHeldCapacityAppendV2::provider(
            NativeHeldCapacityStepV3::ProviderRootTerminalStored,
            [1; 16],
            vec![change(40, 1, Some(2)), change(95, 1, Some(2))]
        )
        .is_err()
    );
    let append = NativeHeldCapacityAppendV2::provider(
        NativeHeldCapacityStepV3::ProviderRootTerminalStored,
        [1; 16],
        vec![change(40, 1, Some(2))],
    )
    .unwrap();
    assert!(
        NativeHeldCapacitySuffixV2::new(
            NativeHeldCapacityPurposeV3::Provider,
            NativeHeldCapacityPathV3::Normal,
            vec![append.clone()]
        )
        .is_err()
    );
    let repeated_tx = NativeHeldCapacityAppendV2::provider(
        NativeHeldCapacityStepV3::ProviderLifecycleCleanup,
        [1; 16],
        vec![change(40, 2, None)],
    )
    .unwrap();
    assert!(
        NativeHeldCapacitySuffixV2::new(
            NativeHeldCapacityPurposeV3::Provider,
            NativeHeldCapacityPathV3::Normal,
            vec![append.clone(), repeated_tx]
        )
        .is_err()
    );
    let cleanup = NativeHeldCapacityAppendV2::provider(
        NativeHeldCapacityStepV3::ProviderLifecycleCleanup,
        [2; 16],
        vec![change(40, 2, None)],
    )
    .unwrap();
    let normal = suffix(NativeHeldCapacityPathV3::Normal, vec![cleanup.clone()]);
    let cold = suffix(NativeHeldCapacityPathV3::ColdClosed, vec![cleanup]);
    let mut short = request(2);
    short.terminal_bytes = 1;
    short.poison_bytes = 1;
    let old = NativeHeldCapacityRecordV3::new(short, [3; 16]).unwrap();
    assert!(
        provider_native_capacity_transition_v2(
            &append,
            &old,
            Some((&normal, &cold)),
            JournalLimits::default()
        )
        .is_err()
    );
    let limits = JournalLimits {
        maximum_records_per_transaction: 2,
        ..JournalLimits::default()
    };
    assert!(
        provider_native_capacity_transition_v2(
            &append,
            &NativeHeldCapacityRecordV3::new(request(2), [3; 16]).unwrap(),
            Some((&normal, &cold)),
            limits
        )
        .is_err()
    );
}

#[test]
fn complete_snapshot_validation_never_short_circuits_on_a_selected_native_floor() {
    let floor = NativeHeldCapacityRecordV3::new(request(1), [3; 16]).unwrap();
    let record = floor.to_journal_record();
    let mut state = std::collections::BTreeMap::from([(
        (record.namespace(), record.key().to_vec()),
        record.value().unwrap().to_vec(),
    )]);
    validate_capacity_snapshot_data_v2(&state).unwrap();
    NativeHeldCapacityRecordV3::from_journal_record(&record).unwrap();
    state.insert(
        (RecordNamespace::GlobalCapacityReservation, vec![255; 75]),
        vec![0; 300],
    );
    assert!(validate_capacity_snapshot_data_v2(&state).is_err());
    assert!(NativeHeldCapacityRecordV3::from_journal_record(&record).is_ok());
}
