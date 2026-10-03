//! Authored, unrun Query6 byte, geometry, and closed-dispatch vectors.
//!
//! Literal bodies below are assembled independently of the shared codec.
//! Review their offsets and domain preimage before changing the wire format;
//! these opaque DATA fixtures are not valid owner graphs or writer authority.

use std::collections::BTreeMap;

use sha2::{Digest as _, Sha256};

use super::super::family::{CanonicalCapacityFamily, require_legacy_transaction};
use super::super::ordinary::{
    OrdinaryCapacityDataV4, OrdinaryCapacityKindV4, OrdinaryCapacityProfileV4,
    OrdinaryCapacityRecordV4,
};
use super::super::{
    accounting_reservation, accounting_reservations, decode_capacity_record,
    validate_all_reservations,
};
use super::*;

const QUERY_DOMAIN: &[u8] =
    b"aos.journal.root-recovery-query-capacity.v6.floor-identity\0";
const ORDINARY_DOMAIN: &[u8] = b"aos.journal.root-ordinary-capacity.v4.r1.floor-identity\0";

fn literal_geometry(profile: QueryCapacityProfileV6) -> (u32, u32, u64) {
    match profile {
        QueryCapacityProfileV6::StatusOrComplete => (2, 9, 25_167_849),
        QueryCapacityProfileV6::RetainedUncertain => (1, 5, 16_778_150),
    }
}

fn data(profile: QueryCapacityProfileV6) -> QueryCapacityDataV6 {
    let (transactions, frames, bytes) = literal_geometry(profile);
    QueryCapacityDataV6 {
        profile,
        owner_id: [1; 32],
        original_owner_cut_digest: [2; 32],
        operation_id: [3; 16],
        original_artifact_digest: [4; 32],
        admission_owner_mutation_digest: [5; 32],
        admission_native_preservation_union_digest: [6; 32],
        remaining_transactions: transactions,
        remaining_record_frames: frames,
        remaining_append_bytes: bytes,
        maximum_retained_growth_entries: 0,
        maximum_retained_growth_bytes: bytes,
        admission_transaction: [7; 16],
        remaining_profile_digest: [8; 32],
    }
}

fn independent_identity(payload: &[u8], domain: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(domain);
    digest.update(u32::try_from(payload.len()).unwrap().to_be_bytes());
    digest.update(payload);
    digest.finalize().into()
}

fn literal_value(profile: QueryCapacityProfileV6) -> Vec<u8> {
    let (transactions, frames, bytes) = literal_geometry(profile);
    let mut value = b"AOSJCR01".to_vec();
    value.extend_from_slice(&[0, 6, 40, 10, 7, profile as u8, 0, 0]);
    for (byte, width) in [(1, 32), (2, 32), (3, 16), (4, 32), (5, 32), (6, 32)] {
        value.extend(vec![byte; width]);
    }
    value.extend_from_slice(&transactions.to_be_bytes());
    value.extend_from_slice(&frames.to_be_bytes());
    value.extend_from_slice(&bytes.to_be_bytes());
    value.extend_from_slice(&0_u32.to_be_bytes());
    value.extend_from_slice(&bytes.to_be_bytes());
    value.extend_from_slice(&[7; 16]);
    value.extend_from_slice(&[8; 32]);
    assert_eq!(value.len(), 268);

    let identity = independent_identity(&value, QUERY_DOMAIN);
    value.extend_from_slice(&identity);
    value
}

fn rebound(value: Vec<u8>, domain: &[u8]) -> JournalRecord {
    let mut value = value;
    let identity = independent_identity(&value[..268], domain);
    value[268..].copy_from_slice(&identity);
    let mut key = b"aos.journal.global-capacity-reservation.v1\0".to_vec();
    key.extend_from_slice(&identity);
    JournalRecord::put(RecordNamespace::GlobalCapacityReservation, key, value)
}

#[test]
fn both_profiles_match_independent_exact_bytes_offsets_key_and_identity() {
    for profile in [
        QueryCapacityProfileV6::StatusOrComplete,
        QueryCapacityProfileV6::RetainedUncertain,
    ] {
        let floor = QueryCapacityRecordV6::new(data(profile)).unwrap();
        let row = floor.to_journal_record();
        let expected = literal_value(profile);
        let (transactions, frames, bytes) = literal_geometry(profile);
        let expected_identity: [u8; 32] = expected[268..].try_into().unwrap();

        assert_eq!(row.value(), Some(expected.as_slice()));
        assert_eq!(expected.len(), 300);
        assert_eq!(row.key().len(), 75);
        assert_eq!(row.key(), rebound(expected.clone(), QUERY_DOMAIN).key());
        assert_eq!(floor.reservation_id(), expected_identity);
        assert_eq!(floor.data(), data(profile));
        assert_eq!(expected[192..196], transactions.to_be_bytes());
        assert_eq!(expected[196..200], frames.to_be_bytes());
        assert_eq!(expected[200..208], bytes.to_be_bytes());
        assert_eq!(expected[208..212], [0; 4]);
        assert_eq!(expected[212..220], bytes.to_be_bytes());
        assert_eq!(expected[220..236], [7; 16]);
        assert_eq!(expected[236..268], [8; 32]);
        assert_eq!(
            QueryCapacityRecordV6::from_journal_record(&row).unwrap(),
            floor
        );
    }
}

#[test]
fn conservative_profiles_use_real_framing_keys_and_existing_value_bounds() {
    let status = status_envelope().unwrap();
    let retained = retained_envelope().unwrap();

    assert_eq!(status.records().len(), 4);
    assert_eq!(retained.records().len(), 5);
    assert_eq!(encoded_transaction_append_bytes(&status).unwrap(), 1091);
    assert_eq!(encoded_transaction_append_bytes(&retained).unwrap(), 934);
    assert_eq!(1091 + 934, 2025);
    assert_eq!(
        QueryCapacityProfileV6::StatusOrComplete
            .remaining_append_bytes()
            .unwrap(),
        2025 + 3 * MAXIMUM_PROVIDER_ATTEMPT_VALUE_BYTES as u64
            + 2 * MAXIMUM_PROVIDER_HEAD_VALUE_BYTES as u64
            + MAXIMUM_ACQUISITION_VALUE_BYTES as u64
    );
    assert_eq!(
        QueryCapacityProfileV6::RetainedUncertain
            .remaining_append_bytes()
            .unwrap(),
        934 + 2 * MAXIMUM_PROVIDER_ATTEMPT_VALUE_BYTES as u64
            + MAXIMUM_PROVIDER_HEAD_VALUE_BYTES as u64
            + MAXIMUM_ACQUISITION_VALUE_BYTES as u64
    );

    // Independent ordinary two-owner DATA framing; no owner graph is claimed.
    let floor = QueryCapacityRecordV6::new(data(QueryCapacityProfileV6::StatusOrComplete))
        .unwrap()
        .to_journal_record();
    let owners = || {
        vec![
            JournalRecord::put(
                RecordNamespace::MountSourceAcquisition,
                provider_attempt_key([1; 32]),
                vec![11; 17],
            ),
            JournalRecord::put(
                RecordNamespace::MountSourceAcquisition,
                provider_head_key([2; 16], [3; 16]),
                vec![12; 19],
            ),
        ]
    };
    let mut admission = owners();
    admission.push(floor.clone());
    let mut complete = owners();
    complete.push(JournalRecord::delete(floor.namespace(), floor.key().to_vec()));

    assert_eq!(
        encoded_transaction_append_bytes(&JournalTransaction::new([9; 16], admission).unwrap())
            .unwrap(),
        937 + 17 + 19
    );
    assert_eq!(
        encoded_transaction_append_bytes(&JournalTransaction::new([10; 16], complete).unwrap())
            .unwrap(),
        637 + 17 + 19
    );
}

#[test]
fn kind_profile_discriminator_and_transaction_count_are_closed_independently() {
    for kind in 0..=u8::MAX {
        let mut value = literal_value(QueryCapacityProfileV6::StatusOrComplete);
        value[12] = kind;
        assert_eq!(
            QueryCapacityRecordV6::from_journal_record(&rebound(value, QUERY_DOMAIN)).is_ok(),
            kind == 7,
            "kind={kind}"
        );
    }
    for profile in 0..=u8::MAX {
        for count in 0_u32..=3 {
            let base = if profile == 2 {
                QueryCapacityProfileV6::RetainedUncertain
            } else {
                QueryCapacityProfileV6::StatusOrComplete
            };
            let mut value = literal_value(base);
            value[13] = profile;
            value[192..196].copy_from_slice(&count.to_be_bytes());
            assert_eq!(
                QueryCapacityRecordV6::from_journal_record(&rebound(value, QUERY_DOMAIN)).is_ok(),
                (profile == 1 && count == 2) || (profile == 2 && count == 1),
                "profile={profile}, count={count}"
            );
        }
    }
}

#[test]
fn truncation_tail_envelope_zero_bindings_and_wrong_namespace_are_rejected() {
    let original = literal_value(QueryCapacityProfileV6::StatusOrComplete);
    for length in 0..300 {
        assert!(QueryCapacityRecordV6::decode(&[], &original[..length]).is_err());
    }
    let mut trailing = original.clone();
    trailing.push(0);
    assert!(QueryCapacityRecordV6::decode(&[], &trailing).is_err());
    for offset in [0, 7, 8, 9, 10, 11, 14, 15] {
        let mut value = original.clone();
        value[offset] ^= 1;
        assert!(QueryCapacityRecordV6::from_journal_record(&rebound(value, QUERY_DOMAIN)).is_err());
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
            QueryCapacityRecordV6::from_journal_record(&rebound(value, QUERY_DOMAIN)).is_err(),
            "zero binding at {offset}"
        );
    }
    let valid = rebound(original.clone(), QUERY_DOMAIN);
    let foreign = JournalRecord::put(
        RecordNamespace::MountSourceAcquisition,
        valid.key().to_vec(),
        original,
    );
    assert!(matches!(
        QueryCapacityRecordV6::from_journal_record(&foreign),
        Err(JournalError::ForeignAuthorityNamespace)
    ));
    assert!(matches!(
        QueryCapacityRecordV6::from_journal_record(&JournalRecord::delete(
            valid.namespace(),
            valid.key().to_vec()
        )),
        Err(JournalError::InvalidTransaction)
    ));
}

#[test]
fn noncanonical_framing_overflow_and_reduced_or_excess_growth_are_rejected() {
    for profile in [
        QueryCapacityProfileV6::StatusOrComplete,
        QueryCapacityProfileV6::RetainedUncertain,
    ] {
        let (_, frames, bytes) = literal_geometry(profile);
        for (offset, replacement) in [
            (192, 0_u32.to_be_bytes().to_vec()),
            (192, u32::MAX.to_be_bytes().to_vec()),
            (196, (frames - 1).to_be_bytes().to_vec()),
            (196, (frames + 1).to_be_bytes().to_vec()),
            (196, u32::MAX.to_be_bytes().to_vec()),
            (200, (bytes - 1).to_be_bytes().to_vec()),
            (200, (bytes + 1).to_be_bytes().to_vec()),
            (200, u64::MAX.to_be_bytes().to_vec()),
            (208, 1_u32.to_be_bytes().to_vec()),
            (208, u32::MAX.to_be_bytes().to_vec()),
            (212, 0_u64.to_be_bytes().to_vec()),
            (212, (bytes - 1).to_be_bytes().to_vec()),
            (212, (bytes + 1).to_be_bytes().to_vec()),
            (212, u64::MAX.to_be_bytes().to_vec()),
        ] {
            let mut value = literal_value(profile);
            value[offset..offset + replacement.len()].copy_from_slice(&replacement);
            assert!(
                QueryCapacityRecordV6::from_journal_record(&rebound(value, QUERY_DOMAIN)).is_err(),
                "profile={profile:?}, geometry offset={offset}"
            );
        }
    }
}

#[test]
fn wrong_key_identity_and_foreign_domain_cannot_rebind_query_data() {
    let value = literal_value(QueryCapacityProfileV6::StatusOrComplete);
    let valid = rebound(value.clone(), QUERY_DOMAIN);
    for key in [
        Vec::new(),
        vec![1; 75],
        valid.key()[..74].to_vec(),
        [valid.key(), &[0]].concat(),
    ] {
        assert!(QueryCapacityRecordV6::decode(&key, &value).is_err());
    }
    let mut corrupt = value.clone();
    corrupt[268] ^= 1;
    assert!(QueryCapacityRecordV6::decode(valid.key(), &corrupt).is_err());
    for domain in [
        ORDINARY_DOMAIN,
        b"aos.journal.root-recovery-query-capacity.v6.floor-identity".as_slice(),
        b"aos.journal.root-recovery-query-capacity.v6.profile\0".as_slice(),
        b"aos.sandbox.journal.global-capacity-reservation.v3\0".as_slice(),
    ] {
        assert!(
            QueryCapacityRecordV6::from_journal_record(&rebound(value.clone(), domain)).is_err()
        );
    }
}

fn ordinary_recovery() -> OrdinaryCapacityRecordV4 {
    let query = data(QueryCapacityProfileV6::RetainedUncertain);
    OrdinaryCapacityRecordV4::new(OrdinaryCapacityDataV4 {
        kind: OrdinaryCapacityKindV4::RecoveryInventory,
        profile: OrdinaryCapacityProfileV4::InventoryResponse,
        owner_id: query.owner_id,
        original_owner_cut_digest: query.original_owner_cut_digest,
        operation_id: query.operation_id,
        original_artifact_digest: query.original_artifact_digest,
        admission_owner_mutation_digest: query.admission_owner_mutation_digest,
        admission_native_preservation_union_digest: query
            .admission_native_preservation_union_digest,
        remaining_transactions: query.remaining_transactions,
        remaining_record_frames: query.remaining_record_frames,
        remaining_append_bytes: query.remaining_append_bytes,
        maximum_retained_growth_entries: query.maximum_retained_growth_entries,
        maximum_retained_growth_bytes: query.maximum_retained_growth_bytes,
        admission_transaction: query.admission_transaction,
        remaining_profile_digest: query.remaining_profile_digest,
    })
    .unwrap()
}

#[test]
fn ordinary_kind7_bytes_domain_and_version_are_preserved_and_not_interchangeable() {
    let ordinary = ordinary_recovery().to_journal_record();
    let query = QueryCapacityRecordV6::new(data(QueryCapacityProfileV6::RetainedUncertain))
        .unwrap()
        .to_journal_record();
    let mut expected = literal_value(QueryCapacityProfileV6::RetainedUncertain);
    expected[9] = 4;
    let expected = rebound(expected, ORDINARY_DOMAIN);

    assert_eq!(ordinary, expected);
    assert!(OrdinaryCapacityRecordV4::from_journal_record(&ordinary).is_ok());
    assert!(QueryCapacityRecordV6::from_journal_record(&ordinary).is_err());
    assert!(OrdinaryCapacityRecordV4::from_journal_record(&query).is_err());
    assert_ne!(
        &ordinary.value().unwrap()[268..],
        &query.value().unwrap()[268..]
    );

    let mut retagged = ordinary.value().unwrap().to_vec();
    retagged[9] = 6;
    assert!(QueryCapacityRecordV6::decode(ordinary.key(), &retagged).is_err());
}

#[test]
fn global_query_accounting_remains_distinct_from_generic_admission() {
    let ordinary = ordinary_recovery().to_journal_record();
    assert!(CanonicalCapacityFamily::decode(ordinary.key(), ordinary.value().unwrap()).is_ok());
    for profile in [
        QueryCapacityProfileV6::StatusOrComplete,
        QueryCapacityProfileV6::RetainedUncertain,
    ] {
        let row = QueryCapacityRecordV6::new(data(profile))
            .unwrap()
            .to_journal_record();
        let value = row.value().unwrap();
        let state = BTreeMap::from([((row.namespace(), row.key().to_vec()), value.to_vec())]);
        let transaction = JournalTransaction::new([9; 16], vec![row.clone()]).unwrap();

        assert!(QueryCapacityRecordV6::from_journal_record(&row).is_ok());
        assert!(matches!(
            CanonicalCapacityFamily::decode(row.key(), value),
            Ok(CanonicalCapacityFamily::Query6(_))
        ));
        let accounting = accounting_reservation(row.key(), value).unwrap();
        assert_eq!(accounting.maximum_records, profile.remaining_record_frames() as usize);
        assert_eq!(accounting.maximum_bytes, profile.remaining_append_bytes().unwrap());
        assert_eq!(accounting.maximum_transactions, profile.remaining_transactions() as usize);
        assert!(accounting_reservations(&state).is_ok());
        assert!(decode_capacity_record(row.key(), value).is_ok());
        assert!(validate_all_reservations(&state).is_ok());
        assert!(require_legacy_transaction(&BTreeMap::new(), &transaction).is_err());
        assert!(crate::journal::root_original_inventory::pending(&state,
            crate::journal::JournalLimits::default()).is_err());
    }
}
