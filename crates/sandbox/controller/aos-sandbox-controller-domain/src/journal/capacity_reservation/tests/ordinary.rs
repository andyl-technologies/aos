//! Retains real Native admission accounting beside the canonical lower grammar.

use crate::journal::JournalError;

use aos_sandbox_protocol::domain_ledger::capacity_family::family::{
    CanonicalCapacityFamily, accounting_reservation, require_legacy_owner,
    require_legacy_reservations, require_legacy_transaction,
};
use aos_sandbox_protocol::domain_ledger::capacity_family::native_held::{
    NativeHeldCapacityPurposeV3, NativeHeldCapacityRecordV3, NativeHeldCapacityRequestV3,
};
use aos_sandbox_protocol::domain_ledger::capacity_family::ordinary::{
    OrdinaryCapacityDataV4, OrdinaryCapacityKindV4, OrdinaryCapacityProfileV4,
    OrdinaryCapacityRecordV4,
};
use aos_sandbox_protocol::domain_ledger::capacity_family::{
    all_reservations_owned_by, capacity_record_has_legacy_purpose,
    decode_capacity_reservation_request_v1, validate_capacity_snapshot_data_v2,
};

use std::collections::BTreeMap;

use super::*;
use super::{
    GlobalCapacityReservationPurposeV1 as LegacyPurpose,
    GlobalCapacityReservationRequestV1 as LegacyRequest, decode_reservation, encode_reservation,
    reservation_id,
};
use crate::journal::{JournalLimits, JournalTransaction};

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
    .map_err(JournalError::from)
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
        .map_err(JournalError::from)
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
    assert!(
        validate_capacity_snapshot_data_v2(&state)
            .map_err(JournalError::from)
            .is_ok()
    );
    assert!(
        !all_reservations_owned_by(&state, RecordNamespace::MountSourceAcquisition)
            .map_err(JournalError::from)
            .unwrap()
    );
    assert!(
        require_legacy_reservations(&state)
            .map_err(JournalError::from)
            .is_err()
    );

    let totals = rows
        .iter()
        .map(|row| {
            accounting_reservation(row.key(), row.value().unwrap())
                .map_err(JournalError::from)
                .unwrap()
        })
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
        assert!(
            decode_capacity_reservation_request_v1(row)
                .map_err(JournalError::from)
                .is_err()
        );
        assert!(
            !capacity_record_has_legacy_purpose(row, LegacyPurpose::ControllerConsumerResource)
                .map_err(JournalError::from)
                .unwrap()
        );
    }
    assert!(matches!(
        CanonicalCapacityFamily::decode(rows[0].key(), rows[0].value().unwrap())
            .map_err(JournalError::from)
            .unwrap(),
        CanonicalCapacityFamily::Legacy1(_)
    ));
    assert!(matches!(
        CanonicalCapacityFamily::decode(rows[1].key(), rows[1].value().unwrap())
            .map_err(JournalError::from)
            .unwrap(),
        CanonicalCapacityFamily::Legacy2(_)
    ));
    assert_eq!(
        aos_sandbox_protocol::domain_ledger::capacity_family::legacy_capacity_ids_for_purpose(
            &state,
            LegacyPurpose::ControllerProjectAdmission
        )
        .map_err(JournalError::from)
        .unwrap(),
        vec![reservation_id(
            &decode_reservation(rows[1].value().unwrap()).unwrap().0,
            [11; 16]
        )]
    );
    assert!(
        aos_sandbox_protocol::domain_ledger::capacity_family::legacy_capacity_ids_for_purpose(
            &state,
            LegacyPurpose::RootSourceGenesisAnchor
        )
        .map_err(JournalError::from)
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
