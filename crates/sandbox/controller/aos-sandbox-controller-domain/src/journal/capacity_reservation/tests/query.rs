//! Retains the actual Native Inventory admission refusal for both Query6 profiles.

use crate::journal::JournalError;

use aos_sandbox_protocol::domain_ledger::capacity_family::family::{
    CanonicalCapacityFamily, accounting_reservation, accounting_reservations,
    require_legacy_transaction,
};
use aos_sandbox_protocol::domain_ledger::capacity_family::ordinary::{
    OrdinaryCapacityDataV4, OrdinaryCapacityKindV4, OrdinaryCapacityProfileV4,
    OrdinaryCapacityRecordV4,
};
use aos_sandbox_protocol::domain_ledger::capacity_family::query::{
    QueryCapacityDataV6, QueryCapacityProfileV6, QueryCapacityRecordV6,
};
use aos_sandbox_protocol::domain_ledger::capacity_family::validate_capacity_snapshot_data_v2;

use std::collections::BTreeMap;

use super::*;

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
    .map_err(JournalError::from)
    .unwrap()
}

#[test]
fn global_query_accounting_remains_distinct_from_generic_admission() {
    let ordinary = ordinary_recovery().to_journal_record();
    assert!(
        CanonicalCapacityFamily::decode(ordinary.key(), ordinary.value().unwrap())
            .map_err(JournalError::from)
            .is_ok()
    );
    for profile in [
        QueryCapacityProfileV6::StatusOrComplete,
        QueryCapacityProfileV6::RetainedUncertain,
    ] {
        let row = QueryCapacityRecordV6::new(data(profile))
            .map_err(JournalError::from)
            .unwrap()
            .to_journal_record();
        let value = row.value().unwrap();
        let state = BTreeMap::from([((row.namespace(), row.key().to_vec()), value.to_vec())]);
        let transaction = JournalTransaction::new([9; 16], vec![row.clone()]).unwrap();

        assert!(
            QueryCapacityRecordV6::from_journal_record(&row)
                .map_err(JournalError::from)
                .is_ok()
        );
        assert!(matches!(
            CanonicalCapacityFamily::decode(row.key(), value).map_err(JournalError::from),
            Ok(CanonicalCapacityFamily::Query6(_))
        ));
        let accounting = accounting_reservation(row.key(), value)
            .map_err(JournalError::from)
            .unwrap();
        assert_eq!(
            accounting.maximum_records,
            profile.remaining_record_frames() as usize
        );
        assert_eq!(
            accounting.maximum_bytes,
            profile
                .remaining_append_bytes()
                .map_err(JournalError::from)
                .unwrap()
        );
        assert_eq!(
            accounting.maximum_transactions,
            profile.remaining_transactions() as usize
        );
        assert!(
            accounting_reservations(&state)
                .map_err(JournalError::from)
                .is_ok()
        );
        assert!(
            accounting_reservation(row.key(), value)
                .map_err(JournalError::from)
                .is_ok()
        );
        assert!(
            validate_capacity_snapshot_data_v2(&state)
                .map_err(JournalError::from)
                .is_ok()
        );
        assert!(
            require_legacy_transaction(&BTreeMap::new(), &transaction)
                .map_err(JournalError::from)
                .is_err()
        );
        assert!(
            crate::journal::root_original_inventory::pending(
                &state,
                crate::journal::JournalLimits::default()
            )
            .is_err()
        );
    }
}
