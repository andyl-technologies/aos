//! Compares settled Root Source history with independently retained pin DATA.
//!
//! The serving caller retains its actual fixed Authority and Policy writers,
//! credential originals, authenticated Source reply and native before/after
//! posts. This module supplies only the complete historical comparison. It
//! cannot open a writer, establish currentness or authorize a Delete effect.

use aos_sandbox_ledger_replay::replay::{
    root_genesis_pins, root_genesis_records, root_saved_floor, root_successor,
};
use aos_sandbox_model::RecordNamespace;
use aos_sandbox_protocol::domain_ledger::{
    capacity::GlobalCapacityReservationPurposeV1,
    capacity_family::legacy_capacity_ids_for_purpose,
    delete_root::source_current::SourceDeleteCurrentReplyFieldsV1,
    readonly::{HistoricalLedgerReadViewV1, HistoricalLedgerRowsDataV2},
};

use root_saved_floor::{RootSavedFloorComparisonDataErrorV1, RootSavedSourceFloorDataV1};

/// Compares the complete settled Source-floor family under the supplied pins.
///
/// Pins and rows are comparison DATA. The caller must retain their independent
/// native owners through this comparison and the ensuing effect handoff.
/// Pending genesis or successor work requires its owning recovery continuation;
/// it cannot be skipped while comparing another project's settled floor.
///
/// # Errors
/// Refuses changed pins, malformed or foreign history, outstanding genesis or
/// successor reservations, unfinished mutations, or a different Source tuple.
pub fn compare_settled_source_floor_data_v1(
    rows: HistoricalLedgerReadViewV1<'_>,
    pins: &[u8; 488],
    source: &SourceDeleteCurrentReplyFieldsV1,
) -> Result<RootSavedSourceFloorDataV1, RootSavedFloorComparisonDataErrorV1> {
    if rows.is_poisoned() {
        return Err(
            aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::Poisoned
                .into(),
        );
    }
    require_settled_history(rows.rows_data_v2(), pins)?;
    root_saved_floor::compare_saved_source_floor_v1(rows, source)
}

fn require_settled_history(
    rows: HistoricalLedgerRowsDataV2<'_>,
    pins: &[u8; 488],
) -> Result<(), RootSavedFloorComparisonDataErrorV1> {
    use RootSavedFloorComparisonDataErrorV1::Changed;
    use root_genesis_records::{
        FLOOR_PREFIX, INSTANCE_KEY, INTENT_PREFIX, PINS_KEY, SourceHierarchyFloorRecordV1,
        decode_instance, project_key,
    };

    let namespace = RecordNamespace::DesiredState;
    let roles = root_genesis_pins::role_tuple_digest(pins)?;
    let instance = rows
        .get_data_v2(namespace, INSTANCE_KEY)
        .map(decode_instance)
        .transpose()?;
    let saved_pins = rows.get_data_v2(namespace, PINS_KEY);
    if instance.is_some() != saved_pins.is_some() || saved_pins.is_some_and(|saved| saved != pins) {
        return Err(Changed);
    }

    let mut floors = 0_usize;
    for (member_namespace, key, value) in rows.all_records() {
        let genesis_floor = key.starts_with(FLOOR_PREFIX);
        let unfinished =
            key.starts_with(INTENT_PREFIX) || key.starts_with(root_successor::INTENT_PREFIX);
        if unfinished {
            return Err(Changed);
        }
        if !genesis_floor {
            continue;
        }
        let floor = SourceHierarchyFloorRecordV1::from_record_bytes(value)?;
        if member_namespace != namespace
            || instance != Some(floor.instance())
            || key != project_key(FLOOR_PREFIX, floor.project())
            || floor.roles() != roles
        {
            return Err(Changed);
        }
        floors += 1;
        if floors > 4096 {
            return Err(Changed);
        }
    }

    let state = rows.materialized_state_data_v2();
    for purpose in [
        GlobalCapacityReservationPurposeV1::RootSourceGenesisAnchor,
        GlobalCapacityReservationPurposeV1::RootFirstSourceSuccessorAnchor,
    ] {
        let reservations = legacy_capacity_ids_for_purpose(state, purpose).map_err(
            aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1::from,
        )?;
        if !reservations.is_empty() {
            return Err(Changed);
        }
    }
    root_successor::validate_project_successor_replay_v3(state)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use ed25519_dalek::SigningKey;

    use super::*;

    fn pins() -> [u8; 488] {
        use crate::controller_readback::encode_controller_hold_signer_credential_v1;
        use aos_sandbox_ledger_replay::source_signer_data::encode_source_hold_readback_signer_credential_v1;
        use aos_sandbox_protocol::{
            controller_source_seed::encode_controller_source_tree_seed_credential_v1,
            publisher_project_authorization::encode_project_authorization_issuer_credential_v2,
        };

        let keys =
            [1, 2, 3, 4, 5, 6].map(|seed| SigningKey::from_bytes(&[seed; 32]).verifying_key());
        let deployment =
            root_genesis_pins::encode_policy_signer_pins_v1(1, &keys[4], 1, &keys[5]).unwrap();
        root_genesis_pins::encode(
            &encode_controller_source_tree_seed_credential_v1(1, &keys[0]).unwrap(),
            &encode_project_authorization_issuer_credential_v2(1, &keys[1]).unwrap(),
            &encode_controller_hold_signer_credential_v1(1, &keys[2]).unwrap(),
            &encode_source_hold_readback_signer_credential_v1(1, &keys[3]).unwrap(),
            deployment.as_slice().try_into().unwrap(),
        )
        .unwrap()
    }

    #[test]
    fn complete_history_rejects_unfinished_work_outside_the_selected_project() {
        let pins = pins();
        let mut state = BTreeMap::new();
        let index = BTreeMap::new();
        let rows = HistoricalLedgerRowsDataV2::new(&state, &index);
        assert!(require_settled_history(rows, &pins).is_ok());

        for prefix in [
            root_genesis_records::INTENT_PREFIX,
            root_successor::INTENT_PREFIX,
        ] {
            let mut key = prefix.to_vec();
            key.extend_from_slice(&[9; 16]);
            state.insert((RecordNamespace::DesiredState, key.clone()), vec![1]);

            let rows = HistoricalLedgerRowsDataV2::new(&state, &index);
            assert!(matches!(
                require_settled_history(rows, &pins),
                Err(RootSavedFloorComparisonDataErrorV1::Changed)
            ));
            assert_eq!(
                state.get(&(RecordNamespace::DesiredState, key.clone())),
                Some(&vec![1])
            );

            state.remove(&(RecordNamespace::DesiredState, key));
        }
    }

    #[test]
    fn saved_instance_and_pins_cannot_be_partial_or_replaced() {
        let pins = pins();
        let mut state = BTreeMap::new();
        let index = BTreeMap::new();
        state.insert(
            (
                RecordNamespace::DesiredState,
                root_genesis_records::INSTANCE_KEY.to_vec(),
            ),
            root_genesis_records::instance_bytes([1; 32])
                .unwrap()
                .to_vec(),
        );
        assert!(
            require_settled_history(HistoricalLedgerRowsDataV2::new(&state, &index), &pins)
                .is_err()
        );

        let key = (
            RecordNamespace::DesiredState,
            root_genesis_records::PINS_KEY.to_vec(),
        );
        state.insert(key.clone(), pins.to_vec());
        assert!(
            require_settled_history(HistoricalLedgerRowsDataV2::new(&state, &index), &pins).is_ok()
        );

        state.get_mut(&key).unwrap()[16] ^= 1;
        assert!(
            require_settled_history(HistoricalLedgerRowsDataV2::new(&state, &index), &pins)
                .is_err()
        );
    }
}
