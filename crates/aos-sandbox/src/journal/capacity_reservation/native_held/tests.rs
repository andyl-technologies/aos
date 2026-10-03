//! Independent native capacity and unchanged legacy format vectors.
//!
//! Golden review reconstructs the literal fixed fields below and hashes
//! domain || purpose || namespace || fields || admission with SHA-256 outside
//! the production encoder. V1 omits count; V2/V3 include its big-endian bytes.
//! A new golden must be reviewed against that preimage, never regenerated from
//! `reservation_id` or the native codec being tested.

use super::super::{
    GlobalCapacityReservationPurposeV1 as LegacyPurpose,
    GlobalCapacityReservationRequestV1 as LegacyRequest, MAXIMUM_FUTURE_TRANSACTIONS,
    decode_reservation, encode_reservation, reservation_id,
};
use super::*;
use crate::journal::{JournalLimits, JournalTransaction, encoded_transaction_append_bytes};

fn request(purpose: NativeHeldCapacityPurposeV3, count: u32) -> NativeHeldCapacityRequestV3 {
    NativeHeldCapacityRequestV3 {
        purpose,
        owner_id: [1; 32],
        owner_digest: [2; 32],
        operation_id: [3; 16],
        artifact_digest: [4; 32],
        checkpoint_digest: [5; 32],
        chain_head_digest: [6; 32],
        future_transactions: count,
        terminal_records: 2,
        terminal_bytes: 1024,
        poison_records: 3,
        poison_bytes: 2048,
    }
}

fn digest(hex: &str) -> [u8; 32] {
    let mut bytes = [0; 32];
    for (index, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[index * 2..index * 2 + 2], 16).unwrap();
    }
    bytes
}

fn independent_fields(explicit_count: bool) -> Vec<u8> {
    let mut fields = vec![1; 32];
    fields.extend_from_slice(&[2; 32]);
    fields.extend_from_slice(&[3; 16]);
    fields.extend_from_slice(&[4; 32]);
    fields.extend_from_slice(&[5; 32]);
    fields.extend_from_slice(&[6; 32]);
    fields.extend_from_slice(&[0, 0, 0, 2]);
    fields.extend_from_slice(&[0, 0, 0, 0, 0, 0, 4, 0]);
    fields.extend_from_slice(&[0, 0, 0, 3]);
    fields.extend_from_slice(&[0, 0, 0, 0, 0, 0, 8, 0]);
    if explicit_count {
        fields.extend_from_slice(&[0, 0, 0, 1]);
    }
    fields
}

#[test]
fn every_legacy_purpose_keeps_independent_bytes_and_identity_golden() {
    let cases = [
        (
            LegacyPurpose::PublisherCompletion,
            RecordNamespace::PublisherAuthority,
            1,
            "ba0bada33775bb5638892434397e23e282a027b84dbebbd8e3a45e2d376cbe7d",
        ),
        (
            LegacyPurpose::RuntimeExecution,
            RecordNamespace::Effect,
            1,
            "837feae50f22a2786cd7068b835f76778bc83d7363d3b2084e996c0585dd4f7e",
        ),
        (
            LegacyPurpose::SourceProviderNativeTerminal,
            RecordNamespace::SourceProviderAuthority,
            1,
            "693aef0be027b1affc35d294b9857ceec1f4d767f62ad128e0e99056921dbe65",
        ),
        (
            LegacyPurpose::RootProjectAdmission,
            RecordNamespace::DesiredState,
            1,
            "a165d12334d9cf96d047e3320f0ac6b07c68aa3f919124a7643aa7d7282389df",
        ),
        (
            LegacyPurpose::ControllerProjectAdmission,
            RecordNamespace::Effect,
            2,
            "9b9cd5d707ec083557966461343369a8d29f9226c73654eb53fef4a0c3a96090",
        ),
        (
            LegacyPurpose::RootSourceGenesisAnchor,
            RecordNamespace::DesiredState,
            1,
            "7dfc41c1fe59284ec66c2b48c7ce24880ee46acda846a738360c52ca8e9ee119",
        ),
        (
            LegacyPurpose::ControllerConsumerResource,
            RecordNamespace::ControllerConsumerReadAttempt,
            1,
            "9d31bf45875f4c7d8efecab11678dea7a85bd0a628bfdce0c174a3be2bb878a0",
        ),
    ];
    for (purpose, namespace, version, expected_hex) in cases {
        let request = LegacyRequest {
            purpose,
            owner_namespace: namespace,
            owner_id: [1; 32],
            owner_digest: [2; 32],
            operation_id: [3; 16],
            artifact_digest: [4; 32],
            checkpoint_digest: [5; 32],
            chain_head_digest: [6; 32],
            future_transactions: 1,
            terminal_records: 2,
            terminal_bytes: 1024,
            poison_records: 3,
            poison_bytes: 2048,
        };
        let expected_id = digest(expected_hex);
        let mut expected = b"AOSJCR01".to_vec();
        expected.extend_from_slice(&[0, version, namespace as u8, purpose as u8, 0, 0]);
        expected.extend_from_slice(&independent_fields(version == 2));
        expected.extend_from_slice(&[7; 16]);
        expected.extend_from_slice(&expected_id);

        assert_eq!(reservation_id(&request, [7; 16]), expected_id);
        assert_eq!(encode_reservation(&request, [7; 16], expected_id), expected);
        assert_eq!(
            decode_reservation(&expected).unwrap(),
            (request, [7; 16], expected_id)
        );
    }
    assert_eq!(MAXIMUM_FUTURE_TRANSACTIONS, 3);
    for byte in [0, 8, 9, 255] {
        assert!(LegacyPurpose::from_byte(byte).is_err());
    }
}

#[test]
fn native_count_one_is_always_version_three_and_has_separate_domain_goldens() {
    for (purpose, expected_hex) in [
        (
            NativeHeldCapacityPurposeV3::Root,
            "0fba182c14bfe1006967fb542bae13fc6c287fe5ccd48655e97895d71f938de0",
        ),
        (
            NativeHeldCapacityPurposeV3::Provider,
            "f1b25817879d2bb6739d34bb0582357d6704d84c86bdaad4ed4f821441b1233e",
        ),
    ] {
        let record = NativeHeldCapacityRecordV3::new(request(purpose, 1), [7; 16]).unwrap();
        let actual = record.to_journal_record();
        let mut expected = b"AOSJCR01".to_vec();
        expected.extend_from_slice(&[0, 3, purpose.owner_namespace() as u8, purpose as u8, 0, 0]);
        expected.extend_from_slice(&independent_fields(true));
        expected.extend_from_slice(&[7; 16]);
        expected.extend_from_slice(&digest(expected_hex));

        assert_eq!(actual.value(), Some(expected.as_slice()));
        assert_eq!(expected.len(), 266);
        let mut expected_key = b"aos.journal.global-capacity-reservation.v1\0".to_vec();
        expected_key.extend_from_slice(&digest(expected_hex));
        assert_eq!(actual.key(), expected_key);
        assert_eq!(
            NativeHeldCapacityRecordV3::from_journal_record(&actual).unwrap(),
            record
        );
        assert!(decode_reservation(actual.value().unwrap()).is_err());
        assert!(super::super::decode_capacity_reservation_request_v1(&actual).is_err());
    }
}

#[test]
fn old_ordered_count_two_and_three_keep_independent_v2_goldens() {
    for (purpose, namespace, count, expected_hex) in [
        (
            LegacyPurpose::RootProjectAdmission,
            RecordNamespace::DesiredState,
            2,
            "07cbf195d33ca5192687af3e002f7067dad1476dddfcf116ad9050c10ca554be",
        ),
        (
            LegacyPurpose::ControllerProjectAdmission,
            RecordNamespace::Effect,
            2,
            "7258d4e39e6751803cb36d4d89059641422a43050bc7f84a14c394c1f01441b9",
        ),
        (
            LegacyPurpose::ControllerProjectAdmission,
            RecordNamespace::Effect,
            3,
            "fa52fd59298b2c58073fb119698ef519ec87822f414937dbbf43a284ca08c607",
        ),
    ] {
        let request = LegacyRequest {
            purpose,
            owner_namespace: namespace,
            owner_id: [1; 32],
            owner_digest: [2; 32],
            operation_id: [3; 16],
            artifact_digest: [4; 32],
            checkpoint_digest: [5; 32],
            chain_head_digest: [6; 32],
            future_transactions: count,
            terminal_records: 2,
            terminal_bytes: 1024,
            poison_records: 3,
            poison_bytes: 2048,
        };
        let expected_id = digest(expected_hex);
        let mut expected = b"AOSJCR01".to_vec();
        expected.extend_from_slice(&[0, 2, namespace as u8, purpose as u8, 0, 0]);
        let mut fields = independent_fields(false);
        fields.extend_from_slice(&count.to_be_bytes());
        expected.extend_from_slice(&fields);
        expected.extend_from_slice(&[7; 16]);
        expected.extend_from_slice(&expected_id);

        assert_eq!(reservation_id(&request, [7; 16]), expected_id);
        assert_eq!(encode_reservation(&request, [7; 16], expected_id), expected);
        assert_eq!(
            decode_reservation(&expected).unwrap(),
            (request, [7; 16], expected_id)
        );
    }
}

#[test]
fn native_counts_have_distinct_closed_ranges_without_changing_old_counts() {
    for purpose in [
        NativeHeldCapacityPurposeV3::Root,
        NativeHeldCapacityPurposeV3::Provider,
    ] {
        for count in 1..=purpose.maximum_future_transactions() {
            let record = NativeHeldCapacityRecordV3::new(request(purpose, count), [7; 16]).unwrap();
            let encoded = record.to_journal_record();
            assert_eq!(
                NativeHeldCapacityRecordV3::from_journal_record(&encoded).unwrap(),
                record
            );
            let decoded =
                super::super::decode_capacity_record(encoded.key(), encoded.value().unwrap())
                    .unwrap();
            assert_eq!(decoded.maximum_transactions, count as usize);
        }
        for count in [0, purpose.maximum_future_transactions() + 1, u32::MAX] {
            assert!(NativeHeldCapacityRecordV3::new(request(purpose, count), [7; 16]).is_err());
        }
    }
    assert_eq!(
        NativeHeldCapacityPurposeV3::Root.owner_namespace() as u8,
        40
    );
    assert_eq!(
        NativeHeldCapacityPurposeV3::Provider.owner_namespace() as u8,
        41
    );
    assert!(!super::super::valid_future_transactions(
        LegacyPurpose::ControllerConsumerResource,
        2
    ));
    assert!(!super::super::valid_future_transactions(
        LegacyPurpose::SourceProviderNativeTerminal,
        2
    ));
    assert!(!super::super::valid_future_transactions(
        LegacyPurpose::ControllerProjectAdmission,
        4
    ));
}

#[test]
fn substitution_version_padding_and_key_relabel_are_rejected() {
    let record =
        NativeHeldCapacityRecordV3::new(request(NativeHeldCapacityPurposeV3::Root, 7), [7; 16])
            .unwrap()
            .to_journal_record();
    for index in [0, 8, 9, 10, 11, 12, 13, 14, 238, 265] {
        let mut value = record.value().unwrap().to_vec();
        value[index] ^= 1;
        let changed = JournalRecord::put(record.namespace(), record.key().to_vec(), value);
        assert!(NativeHeldCapacityRecordV3::from_journal_record(&changed).is_err());
    }
    let wrong_key = JournalRecord::put(
        record.namespace(),
        vec![1; record.key().len()],
        record.value().unwrap().to_vec(),
    );
    assert!(NativeHeldCapacityRecordV3::from_journal_record(&wrong_key).is_err());
    for version in [1_u16, 2] {
        let mut value = record.value().unwrap().to_vec();
        value[8..10].copy_from_slice(&version.to_be_bytes());
        assert!(decode_reservation(&value).is_err());
    }
}

#[test]
fn native_rows_are_canonical_accounting_data_but_reject_legacy_authority() {
    let native =
        NativeHeldCapacityRecordV3::new(request(NativeHeldCapacityPurposeV3::Root, 7), [7; 16])
            .unwrap()
            .to_journal_record();
    let state = std::collections::BTreeMap::from([(
        (native.namespace(), native.key().to_vec()),
        native.value().unwrap().to_vec(),
    )]);
    assert!(super::super::decode_capacity_record(native.key(), native.value().unwrap()).is_ok());
    assert!(super::super::validate_all_reservations(&state).is_ok());
    assert!(
        super::super::all_reservations_owned_by(&state, RecordNamespace::MountSourceAcquisition)
            .unwrap()
    );
    assert!(super::super::require_legacy_reservations(&state).is_err());
    assert!(require_legacy_owner(&state, RecordNamespace::MountSourceAcquisition).is_err());

    for record in [
        native.clone(),
        JournalRecord::delete(native.namespace(), native.key().to_vec()),
        JournalRecord::put(RecordNamespace::MountSourceAcquisition, vec![1], vec![2]),
    ] {
        let transaction = JournalTransaction::new([8; 16], vec![record]).unwrap();
        assert!(require_legacy_transaction(&state, &transaction).is_err());
    }
    let unrelated = JournalTransaction::new(
        [8; 16],
        vec![JournalRecord::put(
            RecordNamespace::Effect,
            vec![1],
            vec![2],
        )],
    )
    .unwrap();
    assert!(require_legacy_transaction(&state, &unrelated).is_ok());
}

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
