//! Source-only ordinary framing, canonical refusal, and mixed-family fixtures.
//!
//! The literal vector below is assembled independently of the production
//! encoder. Its R1 preimage is domain || u32be(268) || exact first 268 bytes.
//! Tiny owner values in framing fixtures are deliberately opaque DATA, not
//! maximal valid owner graphs or protected producer/settlement evidence.

use std::collections::BTreeMap;

use sha2::{Digest as _, Sha256};

use super::super::family::{
    CanonicalCapacityFamily, require_legacy_owner, require_legacy_transaction,
};
use super::super::native_held::{
    NativeHeldCapacityPurposeV3, NativeHeldCapacityRecordV3, NativeHeldCapacityRequestV3,
};
use super::super::{
    GlobalCapacityReservationPurposeV1 as LegacyPurpose,
    GlobalCapacityReservationRequestV1 as LegacyRequest, all_reservations_owned_by,
    capacity_record_has_legacy_purpose, decode_capacity_record,
    decode_capacity_reservation_request_v1, decode_reservation, encode_reservation,
    require_legacy_reservations, reservation_id, validate_all_reservations,
};
use super::*;
use crate::journal::{
    JournalLimits, JournalTransaction, encoded_transaction_append_bytes,
    encoded_transaction_record_bytes,
};

fn local_data() -> OrdinaryCapacityDataV4 {
    OrdinaryCapacityDataV4 {
        kind: OrdinaryCapacityKindV4::IdleReplacement,
        profile: OrdinaryCapacityProfileV4::LocalCommittedReadback,
        owner_id: [1; 32],
        original_owner_cut_digest: [2; 32],
        operation_id: [3; 16],
        original_artifact_digest: [4; 32],
        admission_owner_mutation_digest: [5; 32],
        admission_native_preservation_union_digest: [6; 32],
        remaining_transactions: 1,
        remaining_record_frames: 1,
        remaining_append_bytes: 338,
        maximum_retained_growth_entries: 0,
        maximum_retained_growth_bytes: 0,
        admission_transaction: [3; 16],
        remaining_profile_digest: [7; 32],
    }
}

fn independent_identity(payload: &[u8], domain: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update(u32::try_from(payload.len()).unwrap().to_be_bytes());
    hash.update(payload);
    hash.finalize().into()
}

fn independent_value() -> Vec<u8> {
    let mut bytes = b"AOSJCR01".to_vec();
    bytes.extend_from_slice(&[0, 4, 40, 10, 1, 1, 0, 0]);
    for (byte, width) in [(1, 32), (2, 32), (3, 16), (4, 32), (5, 32), (6, 32)] {
        bytes.extend(vec![byte; width]);
    }
    bytes.extend_from_slice(&[0, 0, 0, 1, 0, 0, 0, 1]);
    bytes.extend_from_slice(&[0, 0, 0, 0, 0, 0, 1, 82]);
    bytes.extend_from_slice(&[0; 12]);
    bytes.extend_from_slice(&[3; 16]);
    bytes.extend_from_slice(&[7; 32]);
    assert_eq!(bytes.len(), 268);

    let identity = independent_identity(
        &bytes,
        b"aos.journal.root-ordinary-capacity.v4.r1.floor-identity\0",
    );
    bytes.extend_from_slice(&identity);
    bytes
}

fn rebound(mut value: Vec<u8>) -> JournalRecord {
    let identity = independent_identity(
        &value[..268],
        b"aos.journal.root-ordinary-capacity.v4.r1.floor-identity\0",
    );
    value[268..300].copy_from_slice(&identity);
    JournalRecord::put(
        RecordNamespace::GlobalCapacityReservation,
        reservation_key(identity),
        value,
    )
}

#[test]
fn exact_r1_literal_value_and_real_transaction_framing() {
    let floor = OrdinaryCapacityRecordV4::new(local_data()).unwrap();
    let record = floor.to_journal_record();
    let expected = independent_value();
    assert_eq!(record.value(), Some(expected.as_slice()));
    assert_eq!(record.key().len(), 75);
    assert_eq!(expected.len(), 300);
    assert_eq!(
        OrdinaryCapacityRecordV4::from_journal_record(&record).unwrap(),
        floor
    );
    assert_eq!(
        record.key(),
        reservation_key(expected[268..].try_into().unwrap())
    );

    let put = JournalTransaction::new([9; 16], vec![record.clone()]).unwrap();
    let delete = JournalTransaction::new(
        [8; 16],
        vec![JournalRecord::delete(
            record.namespace(),
            record.key().to_vec(),
        )],
    )
    .unwrap();
    assert_eq!(encoded_transaction_append_bytes(&put).unwrap(), 184 + 454);
    assert_eq!(
        encoded_transaction_record_bytes(&put).unwrap(),
        7 + 75 + 300
    );
    assert_eq!(
        encoded_transaction_append_bytes(&delete).unwrap(),
        184 + 154
    );
    assert_eq!(encoded_transaction_record_bytes(&delete).unwrap(), 7 + 75);

    // This three-record DATA admission uses the real encoder and exact tiny
    // values. It makes no canonical owner-graph or maximal-envelope claim.
    let admission = JournalTransaction::new(
        [3; 16],
        vec![
            JournalRecord::put(
                RecordNamespace::MountSourceAcquisition,
                b"session".to_vec(),
                b"exact session DATA".to_vec(),
            ),
            JournalRecord::put(
                RecordNamespace::MountSourceAcquisition,
                b"head".to_vec(),
                b"exact head DATA".to_vec(),
            ),
            record,
        ],
    )
    .unwrap();
    assert_eq!(
        encoded_transaction_append_bytes(&admission).unwrap(),
        184 + (79 + 7 + 18) + (79 + 4 + 15) + 454
    );
}

#[test]
fn shared_scalar_extraction_preserves_ordinary_error_precedence() {
    for (offset, replacement, reason) in [
        (9, 6, "ordinary capacity envelope"),
        (12, 0, "unknown ordinary capacity kind"),
        (13, 0, "unknown ordinary capacity profile"),
        (16, 0, "ordinary capacity key or identity"),
    ] {
        let mut value = independent_value();
        value[offset] = replacement;
        value[268] ^= 1;

        assert!(matches!(
            OrdinaryCapacityRecordV4::decode(&[], &value),
            Err(JournalError::MalformedRecord(actual)) if actual == reason
        ));
    }

    let mut value = independent_value();
    value[12] = 0;
    value[13] = 0;
    assert!(matches!(
        OrdinaryCapacityRecordV4::decode(&[], &value),
        Err(JournalError::MalformedRecord("unknown ordinary capacity kind"))
    ));
    assert!(matches!(
        floor_identity(&[0; 267]),
        Err(JournalError::MalformedRecord("ordinary identity payload width"))
    ));
}

#[test]
fn every_closed_kind_profile_and_count_is_checked() {
    for kind in 0..=13 {
        for profile in 0..=5 {
            for count in 0_u32..=3 {
                let mut value = independent_value();
                value[12] = kind;
                value[13] = profile;
                value[192..196].copy_from_slice(&count.to_be_bytes());
                if profile != 1 {
                    value[196..200].copy_from_slice(&7_u32.to_be_bytes());
                    value[200..208].copy_from_slice(&4096_u64.to_be_bytes());
                }
                let expected = match kind {
                    1..=5 | 8..=11 => profile == 1 && count == 1,
                    6..=7 => profile == 2 && count == 1,
                    12 => (profile == 3 && count == 2) || (profile == 4 && count == 1),
                    _ => false,
                };
                assert_eq!(
                    OrdinaryCapacityRecordV4::from_journal_record(&rebound(value)).is_ok(),
                    expected,
                    "kind={kind}, profile={profile}, count={count}"
                );
            }
        }
    }
    assert!(LegacyPurpose::from_byte(10).is_err());
    assert_eq!(super::super::MAXIMUM_FUTURE_TRANSACTIONS, 3);
}

#[test]
fn every_envelope_binding_key_identity_and_domain_refuses_substitution() {
    let original = independent_value();
    for length in 0..300 {
        assert!(
            OrdinaryCapacityRecordV4::decode(&[1], &original[..length]).is_err(),
            "length={length}"
        );
    }
    let mut tail = original.clone();
    tail.push(0);
    assert!(OrdinaryCapacityRecordV4::decode(&[1], &tail).is_err());

    for offset in [0, 8, 9, 10, 11, 14, 15] {
        let mut value = original.clone();
        value[offset] ^= 1;
        assert!(
            OrdinaryCapacityRecordV4::from_journal_record(&rebound(value)).is_err(),
            "header offset={offset}"
        );
    }
    for (offset, width) in [
        (16, 32),
        (48, 32),
        (80, 16),
        (96, 32),
        (128, 32),
        (160, 32),
        (220, 16),
        (236, 32),
    ] {
        let mut value = original.clone();
        value[offset..offset + width].fill(0);
        assert!(
            OrdinaryCapacityRecordV4::from_journal_record(&rebound(value)).is_err(),
            "sentinel offset={offset}"
        );
    }

    let valid = rebound(original.clone());
    for key in [
        vec![],
        vec![1; 75],
        valid.key()[..74].to_vec(),
        [valid.key(), &[0]].concat(),
    ] {
        assert!(OrdinaryCapacityRecordV4::decode(&key, &original).is_err());
    }
    let mut changed_identity = original.clone();
    changed_identity[268] ^= 1;
    assert!(OrdinaryCapacityRecordV4::decode(valid.key(), &changed_identity).is_err());
    for domain in [
        b"aos.journal.root-ordinary-capacity.v4.floor-identity\0".as_slice(),
        b"aos.journal.root-ordinary-capacity.v4.r1.floor-identity".as_slice(),
        b"aos.sandbox.journal.global-capacity-reservation.v3\0".as_slice(),
    ] {
        let mut value = original.clone();
        let identity = independent_identity(&value[..268], domain);
        value[268..].copy_from_slice(&identity);
        assert!(OrdinaryCapacityRecordV4::decode(&reservation_key(identity), &value).is_err());
    }
    let wrong_namespace = JournalRecord::put(
        RecordNamespace::MountSourceAcquisition,
        valid.key().to_vec(),
        original,
    );
    assert!(OrdinaryCapacityRecordV4::from_journal_record(&wrong_namespace).is_err());
    assert!(
        OrdinaryCapacityRecordV4::from_journal_record(&JournalRecord::delete(
            valid.namespace(),
            valid.key().to_vec()
        ))
        .is_err()
    );
}

#[test]
fn rebound_impossible_local_and_request_geometry_refuses() {
    for (offset, bytes) in [
        (80, vec![8; 16]),
        (196, 2_u32.to_be_bytes().to_vec()),
        (200, 337_u64.to_be_bytes().to_vec()),
        (200, 339_u64.to_be_bytes().to_vec()),
        (208, 1_u32.to_be_bytes().to_vec()),
        (212, 1_u64.to_be_bytes().to_vec()),
    ] {
        let mut value = independent_value();
        value[offset..offset + bytes.len()].copy_from_slice(&bytes);
        assert!(OrdinaryCapacityRecordV4::from_journal_record(&rebound(value)).is_err());
    }
    let mut data = local_data();
    data.kind = OrdinaryCapacityKindV4::OrdinaryInventory;
    data.profile = OrdinaryCapacityProfileV4::InventoryResponse;
    data.remaining_record_frames = 3;
    data.remaining_append_bytes = 184 + 79 * 3 - 1;
    assert!(OrdinaryCapacityRecordV4::new(data).is_err());
    data.remaining_append_bytes = 4096;
    data.maximum_retained_growth_entries = 1;
    assert!(OrdinaryCapacityRecordV4::new(data).is_err());
    data.maximum_retained_growth_bytes = 1;
    assert!(OrdinaryCapacityRecordV4::new(data).is_ok());
}

fn legacy(purpose: LegacyPurpose, count: u32, byte: u8) -> JournalRecord {
    let request = LegacyRequest {
        purpose,
        owner_namespace: purpose.owner_namespace(),
        owner_id: [byte; 32],
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
    let identity = reservation_id(&request, [byte; 16]);
    JournalRecord::put(
        RecordNamespace::GlobalCapacityReservation,
        reservation_key(identity),
        encode_reservation(&request, [byte; 16], identity),
    )
}

fn native(purpose: NativeHeldCapacityPurposeV3, count: u32) -> JournalRecord {
    NativeHeldCapacityRecordV3::new(
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
        },
        [7; 16],
    )
    .unwrap()
    .to_journal_record()
}

fn state(records: &[JournalRecord]) -> BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>> {
    records
        .iter()
        .map(|record| {
            (
                (record.namespace(), record.key().to_vec()),
                record.value().unwrap().to_vec(),
            )
        })
        .collect()
}

#[test]
fn mixed_families_account_without_becoming_legacy_grants() {
    let ordinary = OrdinaryCapacityRecordV4::new(local_data())
        .unwrap()
        .to_journal_record();
    let rows = vec![
        legacy(LegacyPurpose::PublisherCompletion, 1, 10),
        legacy(LegacyPurpose::ControllerProjectAdmission, 3, 11),
        native(NativeHeldCapacityPurposeV3::Root, 7),
        native(NativeHeldCapacityPurposeV3::Provider, 19),
        ordinary.clone(),
    ];
    let state = state(&rows);
    assert!(validate_all_reservations(&state).is_ok());
    assert!(!all_reservations_owned_by(&state, RecordNamespace::MountSourceAcquisition).unwrap());
    assert!(require_legacy_reservations(&state).is_err());

    let totals = rows
        .iter()
        .map(|row| decode_capacity_record(row.key(), row.value().unwrap()).unwrap())
        .fold((0, 0, 0), |(records, bytes, transactions), row| {
            (
                records + row.maximum_records,
                bytes + row.maximum_bytes,
                transactions + row.maximum_transactions,
            )
        });
    assert_eq!(totals, (13, 8530, 31));

    for row in &rows[2..] {
        assert!(decode_reservation(row.value().unwrap()).is_err());
        assert!(decode_capacity_reservation_request_v1(row).is_err());
        assert!(
            !capacity_record_has_legacy_purpose(row, LegacyPurpose::ControllerConsumerResource)
                .unwrap()
        );
    }
    assert!(matches!(
        CanonicalCapacityFamily::decode(rows[0].key(), rows[0].value().unwrap()).unwrap(),
        CanonicalCapacityFamily::Legacy1(_)
    ));
    assert!(matches!(
        CanonicalCapacityFamily::decode(rows[1].key(), rows[1].value().unwrap()).unwrap(),
        CanonicalCapacityFamily::Legacy2(_)
    ));
    assert_eq!(
        super::super::legacy_capacity_ids_for_purpose(
            &state,
            LegacyPurpose::ControllerProjectAdmission
        )
        .unwrap(),
        vec![reservation_id(
            &decode_reservation(rows[1].value().unwrap()).unwrap().0,
            [11; 16]
        )]
    );
    assert!(
        super::super::legacy_capacity_ids_for_purpose(
            &state,
            LegacyPurpose::RootSourceGenesisAnchor
        )
        .unwrap()
        .is_empty()
    );

    let limits = JournalLimits {
        maximum_journal_bytes: 8530,
        maximum_materialized_bytes: 8530,
        maximum_materialized_records: state.len() + 13,
        maximum_transactions: 31,
        ..JournalLimits::default()
    };
    assert!(
        crate::journal::validate_reserved_capacity(&state, 0, &[], None, 0, 0, limits, None)
            .is_ok()
    );
    for limit in [
        JournalLimits {
            maximum_journal_bytes: 8529,
            ..limits
        },
        JournalLimits {
            maximum_materialized_bytes: 8529,
            ..limits
        },
        JournalLimits {
            maximum_materialized_records: state.len() + 12,
            ..limits
        },
        JournalLimits {
            maximum_transactions: 30,
            ..limits
        },
    ] {
        assert!(
            crate::journal::validate_reserved_capacity(&state, 0, &[], None, 0, 0, limit, None)
                .is_err()
        );
    }
}

#[test]
fn growth_projection_and_all_old_uncertain_floors_remain_independent() {
    let mut data = local_data();
    data.kind = OrdinaryCapacityKindV4::OrdinaryInventory;
    data.profile = OrdinaryCapacityProfileV4::InventoryResponse;
    data.remaining_record_frames = 3;
    data.remaining_append_bytes = 4096;
    data.maximum_retained_growth_entries = 5;
    data.maximum_retained_growth_bytes = 8192;
    let mut rows = vec![native(NativeHeldCapacityPurposeV3::Root, 7)];
    for byte in 10..14 {
        data.owner_id = [byte; 32];
        data.operation_id = [byte; 16];
        rows.push(
            OrdinaryCapacityRecordV4::new(data)
                .unwrap()
                .to_journal_record(),
        );
    }
    let state = state(&rows);
    assert!(validate_all_reservations(&state).is_ok());
    assert!(all_reservations_owned_by(&state, RecordNamespace::MountSourceAcquisition).unwrap());
    let totals = rows
        .iter()
        .map(|row| decode_capacity_record(row.key(), row.value().unwrap()).unwrap())
        .fold((0, 0, 0), |(records, bytes, transactions), row| {
            (
                records + row.maximum_records,
                bytes + row.maximum_bytes,
                transactions + row.maximum_transactions,
            )
        });
    assert_eq!(totals, (23, 34816, 11));
    assert_eq!(rows[0], native(NativeHeldCapacityPurposeV3::Root, 7));
}

#[test]
fn unknown_or_malformed_rows_are_never_hidden_by_foreign_ownership_or_prior_match() {
    let good = legacy(LegacyPurpose::ControllerConsumerResource, 1, 12);
    let mut rows = vec![
        good.clone(),
        OrdinaryCapacityRecordV4::new(local_data())
            .unwrap()
            .to_journal_record(),
    ];
    let mut malformed = rows[1].value().unwrap().to_vec();
    malformed[8..10].copy_from_slice(&99_u16.to_be_bytes());
    rows.push(JournalRecord::put(
        good.namespace(),
        vec![255; 75],
        malformed,
    ));
    let state = state(&rows);
    assert!(validate_all_reservations(&state).is_err());
    assert!(all_reservations_owned_by(&state, RecordNamespace::Effect).is_err());
    assert!(require_legacy_owner(&state, RecordNamespace::Effect).is_err());
    let matches = rows.iter().try_fold(false, |found, row| {
        let matches =
            capacity_record_has_legacy_purpose(row, LegacyPurpose::ControllerConsumerResource)?;
        Ok::<_, JournalError>(found || matches)
    });
    assert!(matches.is_err());
    assert!(
        super::super::legacy_capacity_ids_for_purpose(
            &state,
            LegacyPurpose::ControllerConsumerResource
        )
        .is_err()
    );
}

#[test]
fn every_known_family_has_canonical_key_validation_before_selection() {
    let rows = [
        legacy(LegacyPurpose::PublisherCompletion, 1, 10),
        legacy(LegacyPurpose::ControllerProjectAdmission, 3, 11),
        native(NativeHeldCapacityPurposeV3::Root, 7),
        OrdinaryCapacityRecordV4::new(local_data())
            .unwrap()
            .to_journal_record(),
    ];
    for row in rows {
        let mut invalid_key = row.key().to_vec();
        invalid_key[0] ^= 1;
        let invalid =
            JournalRecord::put(row.namespace(), invalid_key, row.value().unwrap().to_vec());
        let malformed = state(&[invalid.clone()]);
        assert!(validate_all_reservations(&malformed).is_err());
        assert!(all_reservations_owned_by(&malformed, RecordNamespace::Effect).is_err());
        assert!(
            capacity_record_has_legacy_purpose(&invalid, LegacyPurpose::ControllerConsumerResource)
                .is_err()
        );
        assert!(
            super::super::legacy_capacity_ids_for_purpose(
                &malformed,
                LegacyPurpose::ControllerProjectAdmission
            )
            .is_err()
        );
        assert!(decode_capacity_reservation_request_v1(&invalid).is_err());
    }
}

#[test]
fn generic_owner_put_delete_and_capacity_overwrite_remain_closed() {
    let ordinary = OrdinaryCapacityRecordV4::new(local_data())
        .unwrap()
        .to_journal_record();
    let state = state(&[ordinary.clone()]);
    assert!(require_legacy_owner(&state, RecordNamespace::MountSourceAcquisition).is_err());
    assert!(require_legacy_reservations(&state).is_err());
    for record in [
        ordinary.clone(),
        JournalRecord::delete(ordinary.namespace(), ordinary.key().to_vec()),
        JournalRecord::put(RecordNamespace::MountSourceAcquisition, vec![1], vec![2]),
        JournalRecord::delete(RecordNamespace::MountSourceAcquisition, vec![1]),
        JournalRecord::put(
            ordinary.namespace(),
            ordinary.key().to_vec(),
            legacy(LegacyPurpose::RuntimeExecution, 1, 11)
                .value()
                .unwrap()
                .to_vec(),
        ),
    ] {
        let transaction = JournalTransaction::new([9; 16], vec![record]).unwrap();
        assert!(require_legacy_transaction(&state, &transaction).is_err());
    }
    let put = JournalTransaction::new([9; 16], vec![ordinary]).unwrap();
    assert!(require_legacy_transaction(&BTreeMap::new(), &put).is_err());
}
