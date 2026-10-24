//! Selects actual Native errors for the sole portable Source transition fold.

use super::*;
type H = crate::hierarchy::protected_journal::HierarchyProtectedJournalErrorV1;
type R = crate::hierarchy::genesis_profile::SourceGenesisErrorV1;
pub(super) type SourceTransitionOriginalsV1 = aos_sandbox_ledger_replay::replay::source_tree_successor::transition_retained::SourceTransitionOriginalsV1<JournalError, H, R>;
pub(in crate::journal) type SourceReplayTransactionOriginalsV1 = aos_sandbox_ledger_replay::replay::source_tree_successor::SourceReplayTransactionOriginalsV1<JournalError, H, R>;
pub(super) fn dynamic_demand_v1(state: &State, transaction: &JournalTransaction)
    -> Result<aos_sandbox_model::ResourceVector, JournalError>
{
    aos_sandbox_ledger_replay::replay::source_tree_successor::transition_retained::dynamic_demand_v1(state, transaction)
        .map_err(JournalError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn receipt() -> SourceFirstSuccessorReceiptV2 {
        use aos_sandbox_ledger_replay::replay::phase_records::SourceFirstSuccessorReceiptFieldsV2;
        let digest = |byte| ObjectDigest::from_bytes([byte; 32]);
        SourceFirstSuccessorReceiptV2::new(SourceFirstSuccessorReceiptFieldsV2 {
            instance: [1; 32], project: ProjectId::from_bytes([2; 16]), request: [3; 16],
            approval: digest(4), epoch: 1, before_generation: 1, after_generation: 2,
            predecessor_floor: digest(5), old_tree_head: digest(6), old_lineage_head: digest(7),
            old_tree_commit: digest(8), next_tree_head: digest(9), next_lineage_head: digest(10),
            next_tree_commit: digest(11), roles: digest(12), begin: digest(13), root_intent: digest(14),
            source_names: crate::journal::ProtectedJournalNamesV1::from_historical_fields((1, 2), (1, 3), (1, 4)),
        }).map_err(crate::hierarchy::genesis_profile::SourceGenesisErrorV1::from).unwrap()
    }

    #[test]
    fn actual_source_transition_keeps_a_decoded_receipt_before_pending_refusal() {
        let receipt = receipt();
        let transaction = JournalTransaction::new([17; 16], vec![
            JournalRecord::put(RecordNamespace::DesiredState, b"tree".to_vec(), vec![1]),
            JournalRecord::put(RecordNamespace::DesiredState, b"lineage".to_vec(), vec![1]),
            JournalRecord::put(RecordNamespace::DesiredState, receipt_key(receipt.project()), receipt.as_bytes().to_vec()),
            JournalRecord::put(RecordNamespace::DesiredState, PENDING_KEY.to_vec(), vec![0]),
            JournalRecord::put(RecordNamespace::GlobalCapacityReservation, b"capacity".to_vec(), vec![0]),
        ]).unwrap();
        let state = State::new();
        assert!(require_source_transition_with_recipe(&state, &transaction,
            Some(FirstSourceSuccessorNativePhaseV2::SourceAppend), SourceSuccessorFamilyRecipeV3::SingleProjectV2).is_err());
        let mut originals = SourceTransitionOriginalsV1::new();

        assert!(originals.observe_once(&state, &transaction,
            Some(FirstSourceSuccessorNativePhaseV2::SourceAppend), SourceSuccessorFamilyRecipeV3::SingleProjectV2).is_err());
        assert_eq!(originals.receipt.as_ref(), Some(&receipt));
        assert!(originals.pending.is_none());
        assert!(originals.rows.as_ref().unwrap().receipts.is_empty());
        let cause = originals.cause().unwrap() as *const dyn std::error::Error;

        assert!(originals.observe_once(&state, &transaction, None, SourceSuccessorFamilyRecipeV3::SingleProjectV2).is_err());
        assert!(std::ptr::addr_eq(originals.cause().unwrap(), cause));
        assert_eq!(originals.receipt.as_ref(), Some(&receipt));
    }

    #[test]
    fn actual_transition_current_family_refusal_keeps_the_scanned_orphan_ack() {
        let project = ProjectId::from_bytes([2; 16]);
        let ack = SourceFirstSuccessorAckV2::new(aos_sandbox_ledger_replay::replay::phase_records::SourceFirstSuccessorAckFieldsV2 {
            instance: [1; 32], project, receipt: ObjectDigest::from_bytes([3; 32]),
            root_floor: ObjectDigest::from_bytes([4; 32]), controller_anchored: ObjectDigest::from_bytes([5; 32]),
        }).map_err(crate::hierarchy::genesis_profile::SourceGenesisErrorV1::from).unwrap();
        let mut state = State::new();
        state.insert((RecordNamespace::DesiredState, ack_key(project)), ack.as_bytes().to_vec());
        let transaction = JournalTransaction::new([17; 16], vec![
            JournalRecord::put(RecordNamespace::DesiredState, b"unrelated".to_vec(), vec![1]),
        ]).unwrap();
        let mut originals = SourceTransitionOriginalsV1::new();

        assert!(originals.observe_once(&state, &transaction, None, SourceSuccessorFamilyRecipeV3::SingleProjectV2).is_err());
        assert_eq!(originals.before_family.rows.as_ref().unwrap().acks.get(&project), Some(&ack));
        assert!(originals.rows.is_none());
        assert!(originals.after.is_none());
    }

    #[test]
    fn actual_empty_transition_matches_ordinary_and_retains_until_outer_completion() {
        let state = State::new();
        let transaction = JournalTransaction::new([17; 16], vec![
            JournalRecord::put(RecordNamespace::DesiredState, b"unrelated".to_vec(), vec![1]),
        ]).unwrap();
        let ordinary = require_source_transition_with_recipe(&state, &transaction, None,
            SourceSuccessorFamilyRecipeV3::SingleProjectV2).unwrap();
        let mut originals = SourceTransitionOriginalsV1::new();

        assert_eq!(originals.observe_once(&state, &transaction, None,
            SourceSuccessorFamilyRecipeV3::SingleProjectV2).unwrap(), ordinary);
        assert!(originals.rows.as_ref().unwrap().receipts.is_empty());
        assert!(originals.cause().is_none());
        assert!(SourceReplayTransactionOriginalsV1::fixed_footprint_v1().is_some());
    }

    #[test]
    fn closed_native_destination_cannot_reenter_another_commit() {
        let state = State::new();
        let transaction = JournalTransaction::new([17; 16], vec![
            JournalRecord::put(RecordNamespace::DesiredState, b"unrelated".to_vec(), vec![1]),
        ]).unwrap();
        let mut original = Some(Box::new(SourceReplayTransactionOriginalsV1::new()));

        assert!(super::super::super::validate_replayed_source_transaction(&state, &transaction,
            super::super::super::JournalLimits::default(), true, &mut original).is_err());
        // This inert fixture has no descriptor table, bank, receiving original,
        // native IO or armed Drop guard. Rejection precedes all validators.
        assert!(!original.as_ref().unwrap().entered);
    }

    #[test]
    fn reached_transition_geometry_uses_actual_rows_and_no_descriptor_grant() {
        use aos_sandbox_model::ResourceDimension as D;
        let mut state = State::new();
        state.insert((RecordNamespace::DesiredState, b"one".to_vec()), vec![1; 7]);
        let transaction = JournalTransaction::new([17; 16], vec![
            JournalRecord::put(RecordNamespace::DesiredState, b"two".to_vec(), vec![2; 11]),
        ]).unwrap();
        let current = dynamic_demand_v1(&state, &transaction).unwrap();
        state.insert((RecordNamespace::DesiredState, b"three".to_vec()), vec![3; 13]);
        let larger = dynamic_demand_v1(&state, &transaction).unwrap();

        assert!(larger.get(D::MemoryBytes) > current.get(D::MemoryBytes));
        assert!(larger.get(D::MetadataEntries) > current.get(D::MetadataEntries));
        assert_eq!(current.get(D::OpenFiles), 0);
        assert_eq!(larger.get(D::OpenFiles), 0);
        assert_eq!(aos_sandbox_protocol::domain_ledger::capacity::reservation_key([1; 32]).len(),
            aos_sandbox_protocol::domain_ledger::capacity::RESERVATION_KEY_BYTES_V1);
    }
}
