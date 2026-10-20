//! Retains complete upper suffix and geometry tests with private Native profiles.

use aos_sandbox_protocol::domain_ledger::capacity_family::native_held::NativeHeldCapacityPurposeV3;

use super::*;
use crate::journal::{JournalLimits, JournalTransaction, encoded_transaction_append_bytes};

fn append(
    step: NativeHeldCapacityStepV3,
    id: u8,
    before: usize,
    after: usize,
) -> NativeHeldCapacityAppendV3 {
    use NativeHeldCapacityStepV3::*;
    let widths: &[usize] = match step {
        RootDispositionCas => &[68, 75, 64, 66],
        RootPreparedStored
        | RootHeldStored
        | RootDispositionPrepared
        | RootDispositionStored
        | RootTerminalProofStored
        | RootTerminalAckStored => &[68],
        ProviderSixRowComplete => &[96, 99, 63, 103, 49, 40],
        _ => &[40],
    };
    let changes = widths
        .iter()
        .map(|width| {
            NativeHeldCapacityChangeV3::new(
                vec![1; *width],
                Some(vec![1; before]),
                Some(vec![1; after]),
            )
            .unwrap()
        })
        .collect();
    NativeHeldCapacityAppendV3::new(step, [id; 16], changes).unwrap()
}

#[test]
fn complete_cold_suffix_measures_frames_capacity_replacements_and_retained_growth() {
    let suffix = NativeHeldCapacitySuffixV3::new(
        NativeHeldCapacityPurposeV3::Root,
        NativeHeldCapacityPathV3::ColdClosed,
        vec![
            append(NativeHeldCapacityStepV3::RootDispositionPrepared, 1, 16, 32),
            append(NativeHeldCapacityStepV3::RootTerminalProofStored, 2, 32, 48),
            append(NativeHeldCapacityStepV3::RootTerminalAckStored, 3, 48, 64),
        ],
    )
    .unwrap();
    let geometry = suffix.measure(JournalLimits::default()).unwrap();

    // Begin=72+4, Commit=72+36. Record headers=7 and frame headers=72.
    // Capacity key=43+32; successor value=266. Final deletion has no successor.
    let capacity_delete = 7 + 75;
    let capacity_put = 7 + 75 + 266;
    let first = 76 + 108 + 3 * 72 + (7 + 68 + 32) + capacity_delete + capacity_put;
    let second = 76 + 108 + 3 * 72 + (7 + 68 + 48) + capacity_delete + capacity_put;
    let last = 76 + 108 + 2 * 72 + (7 + 68 + 64) + capacity_delete;
    assert_eq!(geometry.transactions, 3);
    assert_eq!(geometry.records, 8);
    assert_eq!(geometry.append_bytes, (first + second + last) as u64);
    assert_eq!(geometry.maximum_transaction_records, 3);
    assert_eq!(geometry.maximum_retained_growth_bytes, 48);
    assert_eq!(geometry.maximum_retained_growth_records, 0);
    assert!(geometry.append_bytes > 3 * 64);
}

#[test]
fn independent_full_frame_golden_counts_delete_payloads() {
    let transaction = JournalTransaction::new(
        [1; 16],
        vec![
            JournalRecord::put(
                RecordNamespace::MountSourceAcquisition,
                b"k".to_vec(),
                vec![1, 2],
            ),
            JournalRecord::delete(RecordNamespace::MountSourceAcquisition, b"old".to_vec()),
        ],
    )
    .unwrap();
    assert_eq!(
        encoded_transaction_append_bytes(&transaction).unwrap(),
        76 + 108 + 2 * 72 + (7 + 1 + 2) + (7 + 3)
    );
}

#[test]
fn per_append_and_aggregate_existing_floors_are_checked_separately() {
    let suffix = NativeHeldCapacitySuffixV3::new(
        NativeHeldCapacityPurposeV3::Root,
        NativeHeldCapacityPathV3::Normal,
        vec![append(
            NativeHeldCapacityStepV3::RootTerminalAckStored,
            1,
            16,
            32,
        )],
    )
    .unwrap();
    let geometry = suffix.measure(JournalLimits::default()).unwrap();
    let mut limits = JournalLimits::default();
    limits.maximum_transaction_bytes = geometry.maximum_transaction_record_bytes as usize - 1;
    assert!(suffix.measure(limits).is_err());
    limits = JournalLimits::default();
    limits.maximum_journal_bytes = geometry.append_bytes;
    assert!(
        geometry
            .require_headroom(limits, NativeHeldCapacityUsageV3::default())
            .is_ok()
    );
    assert!(
        geometry
            .require_headroom(
                limits,
                NativeHeldCapacityUsageV3 {
                    reserved_bytes: 1,
                    ..Default::default()
                }
            )
            .is_err()
    );
    limits = JournalLimits::default();
    limits.maximum_transactions = 1;
    assert!(
        geometry
            .require_headroom(
                limits,
                NativeHeldCapacityUsageV3 {
                    reserved_transactions: 1,
                    ..Default::default()
                }
            )
            .is_err()
    );
    limits = JournalLimits::default();
    limits.maximum_materialized_records = geometry.records as usize;
    assert!(
        geometry
            .require_headroom(
                limits,
                NativeHeldCapacityUsageV3 {
                    materialized_records: 1,
                    ..Default::default()
                }
            )
            .is_err()
    );
}

#[test]
fn suffixes_reject_missing_retirement_repetition_gaps_and_inconsistent_images() {
    let purpose = NativeHeldCapacityPurposeV3::Root;
    assert!(
        NativeHeldCapacitySuffixV3::new(
            purpose,
            NativeHeldCapacityPathV3::Normal,
            vec![append(NativeHeldCapacityStepV3::RootHeldStored, 1, 1, 2)]
        )
        .is_err()
    );
    assert!(
        NativeHeldCapacitySuffixV3::new(
            purpose,
            NativeHeldCapacityPathV3::Normal,
            vec![
                append(NativeHeldCapacityStepV3::RootDispositionPrepared, 1, 1, 2),
                append(NativeHeldCapacityStepV3::RootTerminalAckStored, 2, 2, 3)
            ]
        )
        .is_err()
    );
    assert!(
        NativeHeldCapacitySuffixV3::new(
            purpose,
            NativeHeldCapacityPathV3::ColdClosed,
            vec![
                append(NativeHeldCapacityStepV3::RootHeldStored, 1, 1, 2),
                append(NativeHeldCapacityStepV3::RootTerminalAckStored, 2, 2, 3)
            ]
        )
        .is_err()
    );
    let suffix = NativeHeldCapacitySuffixV3::new(
        purpose,
        NativeHeldCapacityPathV3::Recovery,
        vec![
            append(NativeHeldCapacityStepV3::RootTerminalProofStored, 1, 1, 2),
            append(NativeHeldCapacityStepV3::RootTerminalAckStored, 2, 3, 4),
        ],
    )
    .unwrap();
    assert!(suffix.measure(JournalLimits::default()).is_err());
}

#[test]
fn full_native_paths_keep_root_seven_provider_nineteen_and_cleanup_one() {
    use NativeHeldCapacityStepV3::*;
    let root = [
        RootPreparedStored,
        RootHeldStored,
        RootDispositionCas,
        RootDispositionPrepared,
        RootDispositionStored,
        RootTerminalProofStored,
        RootTerminalAckStored,
    ];
    let provider = [
        ProviderChallengeIssued,
        ProviderStoragePrepared,
        ProviderChallengeSpent,
        ProviderSixRowComplete,
        ProviderHeldPrepared,
        ProviderHeldStored,
        ProviderRootDispositionPrepared,
        ProviderRelayStored,
        ProviderStorageSettlement,
        ProviderSettledPrepared,
        ProviderSettledStored,
        ProviderRootRecoveryStored,
        ProviderRecoveryRelayPrepared,
        ProviderRecoveryRelayStored,
        ProviderStorageRecoveryStored,
        ProviderRecoveryTerminalPrepared,
        ProviderRecoveryTerminalStored,
        ProviderRootTerminalStored,
        ProviderLifecycleCleanup,
    ];
    let make = |steps: &[NativeHeldCapacityStepV3]| {
        steps
            .iter()
            .enumerate()
            .map(|(index, step)| append(*step, index as u8 + 1, index + 1, index + 2))
            .collect()
    };
    let root = NativeHeldCapacitySuffixV3::new(
        NativeHeldCapacityPurposeV3::Root,
        NativeHeldCapacityPathV3::Normal,
        make(&root),
    )
    .unwrap();
    let recovery = NativeHeldCapacitySuffixV3::new(
        NativeHeldCapacityPurposeV3::Provider,
        NativeHeldCapacityPathV3::Recovery,
        make(&provider),
    )
    .unwrap();
    let normal_steps = provider
        .into_iter()
        .filter(|step| {
            !matches!(
                step,
                ProviderRootRecoveryStored
                    | ProviderRecoveryRelayPrepared
                    | ProviderRecoveryRelayStored
                    | ProviderStorageRecoveryStored
                    | ProviderRecoveryTerminalPrepared
                    | ProviderRecoveryTerminalStored
            )
        })
        .collect::<Vec<_>>();
    let normal = NativeHeldCapacitySuffixV3::new(
        NativeHeldCapacityPurposeV3::Provider,
        NativeHeldCapacityPathV3::Normal,
        make(&normal_steps),
    )
    .unwrap();
    let cleanup = NativeHeldCapacitySuffixV3::new(
        NativeHeldCapacityPurposeV3::Provider,
        NativeHeldCapacityPathV3::Normal,
        vec![append(ProviderLifecycleCleanup, 1, 1, 2)],
    )
    .unwrap();

    assert_eq!(
        root.measure(JournalLimits::default()).unwrap().transactions,
        7
    );
    assert_eq!(
        recovery
            .measure(JournalLimits::default())
            .unwrap()
            .transactions,
        19
    );
    assert_eq!(
        normal
            .measure(JournalLimits::default())
            .unwrap()
            .transactions,
        13
    );
    assert_eq!(
        cleanup
            .measure(JournalLimits::default())
            .unwrap()
            .transactions,
        1
    );
    assert!(
        NativeHeldCapacitySuffixV3::new(
            NativeHeldCapacityPurposeV3::Provider,
            NativeHeldCapacityPathV3::Normal,
            make(&provider)
        )
        .is_err()
    );
}

#[test]
fn precise_unescaped_offer_recovery_paths_count_only_existing_checkpoints() {
    use NativeHeldCapacityStepV3::*;
    let positive = [
        ProviderChallengeIssued,
        ProviderStoragePrepared,
        ProviderChallengeSpent,
        ProviderSixRowComplete,
        ProviderHeldPrepared,
        ProviderHeldStored,
        ProviderRootDispositionPrepared,
        ProviderRelayStored,
        ProviderStorageSettlement,
        ProviderSettledPrepared,
        ProviderSettledStored,
    ];
    let recovery = [
        ProviderRootRecoveryStored,
        ProviderRecoveryRelayPrepared,
        ProviderRecoveryRelayStored,
        ProviderStorageRecoveryStored,
        ProviderRecoveryTerminalPrepared,
        ProviderRecoveryTerminalStored,
        ProviderRootTerminalStored,
        ProviderLifecycleCleanup,
    ];

    // Actual caseA has unescaped5 after seven prefix writes; caseB has
    // unescaped3 after five. The cold substitutions consume existing slots12
    // and13, never an invented preparation-clear or successor signature write.
    for (prefix_end, expected_future) in [(0, 8), (5, 13), (7, 15), (11, 19)] {
        let steps = positive[..prefix_end]
            .iter()
            .chain(&recovery)
            .copied()
            .collect::<Vec<_>>();
        let appends = steps
            .iter()
            .enumerate()
            .map(|(index, step)| append(*step, index as u8 + 1, index + 1, index + 2))
            .collect();
        let suffix = NativeHeldCapacitySuffixV3::new(
            NativeHeldCapacityPurposeV3::Provider,
            NativeHeldCapacityPathV3::Recovery,
            appends,
        )
        .unwrap();
        let geometry = suffix.measure(JournalLimits::default()).unwrap();

        assert_eq!(geometry.transactions, expected_future);
        let owner_records = if prefix_end >= 4 {
            expected_future + 5 // The exact Complete append owns six rows.
        } else {
            expected_future
        };
        assert_eq!(geometry.records, owner_records + 2 * expected_future - 1);
        assert!(geometry.append_bytes > u64::from(geometry.records) * 72);
    }

    let omitted_first_query = vec![
        append(ProviderHeldPrepared, 1, 1, 2),
        append(ProviderRecoveryRelayPrepared, 2, 2, 3),
        append(ProviderRecoveryRelayStored, 3, 3, 4),
        append(ProviderStorageRecoveryStored, 4, 4, 5),
        append(ProviderRecoveryTerminalPrepared, 5, 5, 6),
        append(ProviderRecoveryTerminalStored, 6, 6, 7),
        append(ProviderRootTerminalStored, 7, 7, 8),
        append(ProviderLifecycleCleanup, 8, 8, 9),
    ];
    assert!(
        NativeHeldCapacitySuffixV3::new(
            NativeHeldCapacityPurposeV3::Provider,
            NativeHeldCapacityPathV3::Recovery,
            omitted_first_query,
        )
        .is_err()
    );
    assert!(
        NativeHeldCapacitySuffixV3::new(
            NativeHeldCapacityPurposeV3::Provider,
            NativeHeldCapacityPathV3::ColdClosed,
            vec![
                append(ProviderHeldPrepared, 1, 1, 2),
                append(ProviderLifecycleCleanup, 2, 2, 3),
            ],
        )
        .is_err()
    );
}
