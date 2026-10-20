//! Independent native capacity and unchanged legacy format vectors.
//!
//! Golden review reconstructs the literal fixed fields below and hashes
//! domain || purpose || namespace || fields || admission with SHA-256 outside
//! the production encoder. V1 omits count; V2/V3 include its big-endian bytes.
//! A new golden must be reviewed against that preimage, never regenerated from
//! `reservation_id` or the native codec being tested.

use crate::domain_ledger::capacity_family::family::{
    require_legacy_owner, require_legacy_transaction,
};
use crate::domain_ledger::capacity_family::native_held::{
    NativeHeldCapacityPurposeV3, NativeHeldCapacityRecordV3, NativeHeldCapacityRequestV3,
};

use crate::domain_ledger::capacity::{
    GlobalCapacityReservationPurposeV1 as LegacyPurpose,
    GlobalCapacityReservationRequestV1 as LegacyRequest, MAXIMUM_FUTURE_TRANSACTIONS,
    decode_reservation, encode_reservation, reservation_id,
};

use super::*;
use crate::domain_ledger::transaction::{
    JournalLimits, JournalTransaction, encoded_transaction_append_bytes,
};

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
            1,
            "ba0bada33775bb5638892434397e23e282a027b84dbebbd8e3a45e2d376cbe7d",
        ),
        (
            LegacyPurpose::RuntimeExecution,
            RecordNamespace::Effect,
            1,
            1,
            "837feae50f22a2786cd7068b835f76778bc83d7363d3b2084e996c0585dd4f7e",
        ),
        (
            LegacyPurpose::SourceProviderNativeTerminal,
            RecordNamespace::SourceProviderAuthority,
            1,
            1,
            "693aef0be027b1affc35d294b9857ceec1f4d767f62ad128e0e99056921dbe65",
        ),
        (
            LegacyPurpose::RootProjectAdmission,
            RecordNamespace::DesiredState,
            1,
            1,
            "a165d12334d9cf96d047e3320f0ac6b07c68aa3f919124a7643aa7d7282389df",
        ),
        (
            LegacyPurpose::ControllerProjectAdmission,
            RecordNamespace::Effect,
            2,
            1,
            "9b9cd5d707ec083557966461343369a8d29f9226c73654eb53fef4a0c3a96090",
        ),
        (
            LegacyPurpose::RootSourceGenesisAnchor,
            RecordNamespace::DesiredState,
            1,
            1,
            "7dfc41c1fe59284ec66c2b48c7ce24880ee46acda846a738360c52ca8e9ee119",
        ),
        (
            LegacyPurpose::ControllerConsumerResource,
            RecordNamespace::ControllerConsumerReadAttempt,
            1,
            1,
            "9d31bf45875f4c7d8efecab11678dea7a85bd0a628bfdce0c174a3be2bb878a0",
        ),
        (
            LegacyPurpose::RootFirstSourceSuccessorAnchor,
            RecordNamespace::DesiredState,
            1,
            1,
            "ce0fae4c8c128f649aad8c469fef1d227ab4539d3c6a92fea1a2effd0c67a9e6",
        ),
        (
            LegacyPurpose::SourceFirstSourceSuccessorAck,
            RecordNamespace::DesiredState,
            1,
            1,
            "1b789754a46f024770e07d9f779db6c2780339ad48669a0289755c1c29a615ee",
        ),
        (
            LegacyPurpose::ControllerFirstSourceSuccessorComplete,
            RecordNamespace::DesiredState,
            2,
            2,
            "603d962e72bc28f0584ea56bf96430688194a2cb232649e4903841c786c84703",
        ),
    ];
    for (purpose, namespace, version, count, expected_hex) in cases {
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
        expected.extend_from_slice(&[0, version, namespace as u8, purpose as u8, 0, 0]);
        expected.extend_from_slice(&independent_fields(false));
        if version == 2 {
            expected.extend_from_slice(&count.to_be_bytes());
        }
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
    for byte in [0, 11, 12, 255] {
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
        assert!(
            crate::domain_ledger::capacity_family::decode_capacity_reservation_request_v1(&actual)
                .is_err()
        );
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
            let decoded = crate::domain_ledger::capacity_family::family::accounting_reservation(
                encoded.key(),
                encoded.value().unwrap(),
            )
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
    assert!(!crate::domain_ledger::capacity::valid_future_transactions(
        LegacyPurpose::ControllerConsumerResource,
        2
    ));
    assert!(!crate::domain_ledger::capacity::valid_future_transactions(
        LegacyPurpose::SourceProviderNativeTerminal,
        2
    ));
    assert!(!crate::domain_ledger::capacity::valid_future_transactions(
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
    assert!(
        crate::domain_ledger::capacity_family::family::accounting_reservation(
            native.key(),
            native.value().unwrap()
        )
        .is_ok()
    );
    assert!(
        crate::domain_ledger::capacity_family::validate_capacity_snapshot_data_v2(&state).is_ok()
    );
    assert!(
        crate::domain_ledger::capacity_family::all_reservations_owned_by(
            &state,
            RecordNamespace::MountSourceAcquisition
        )
        .unwrap()
    );
    assert!(
        crate::domain_ledger::capacity_family::family::require_legacy_reservations(&state).is_err()
    );
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
