//! Selects actual Native error types for canonical project-genesis DATA work.

use super::*;
pub(super) type SourceGenesisSelectionOriginalsV1 = aos_sandbox_ledger_replay::replay::source_tree_successor::project_genesis_retained::SourceGenesisSelectionOriginalsV1<JournalError, crate::hierarchy::genesis_profile::SourceGenesisErrorV1>;
pub(super) type SourceProjectGenesisOriginalsV1 = aos_sandbox_ledger_replay::replay::source_tree_successor::SourceProjectGenesisOriginalsV1<JournalError,
    crate::hierarchy::protected_journal::HierarchyProtectedJournalErrorV1,
    crate::hierarchy::genesis_profile::SourceGenesisErrorV1>;
use aos_sandbox_ledger_replay::genesis::SourceTreeGenesisReceiptV1;

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::super::source_tree_genesis::genesis_receipt_data_for_test;

    fn append(receipt: &SourceTreeGenesisReceiptV1) -> JournalTransaction {
        JournalTransaction::new([17; 16], vec![
            JournalRecord::put(RecordNamespace::DesiredState, b"tree".to_vec(), b"tree".to_vec()),
            JournalRecord::put(RecordNamespace::DesiredState, b"lineage".to_vec(), b"lineage".to_vec()),
            JournalRecord::put(RecordNamespace::DesiredState,
                super::super::super::source_tree_genesis::receipt_key(receipt.project()), receipt.as_bytes().to_vec()),
            JournalRecord::put(RecordNamespace::DesiredState,
                super::super::super::source_tree_genesis::PENDING_KEY.to_vec(), vec![0]),
        ]).unwrap()
    }

    #[test]
    fn selection_keeps_actual_proposed_receipt_through_later_family_refusal() {
        let receipt = genesis_receipt_data_for_test(b"tree", b"lineage");
        let transaction = append(&receipt);
        let mut state = State::new();
        // Deliberately malformed earlier family DATA: selection itself reads
        // only this canonical name, then the next actual fold must reject it.
        state.insert((RecordNamespace::DesiredState, receipt_key(ProjectId::from_bytes([2; 16]))), vec![0]);
        let mut originals = SourceProjectGenesisOriginalsV1::new();
        let selected = select_replayed_genesis_project_engine(&state, &transaction, None, None).unwrap();

        assert_eq!(originals.selection.observe_once(&state, &transaction, None).unwrap(), selected);
        assert_eq!(selected, Some(receipt.project()));
        assert_eq!(originals.selection.receipt.as_ref(), Some(&receipt));
        assert!(originals.observe_once(&state, &transaction, receipt.project()).is_err());
        assert_eq!(originals.selection.receipt.as_ref(), Some(&receipt));
        assert!(originals.after.is_none());
    }

    #[test]
    fn project_mismatch_keeps_completed_before_rows_and_actual_receipt() {
        let receipt = genesis_receipt_data_for_test(b"tree", b"lineage");
        let transaction = append(&receipt);
        let selected = ProjectId::from_bytes([2; 16]);
        let mut originals = SourceProjectGenesisOriginalsV1::new();
        assert!(require_project_genesis_transition_v3(&State::new(), &transaction, selected).is_err());

        assert!(originals.observe_once(&State::new(), &transaction, selected).is_err());
        assert_eq!(originals.receipt.as_ref(), Some(&receipt));
        assert!(originals.before.as_ref().unwrap().receipts.is_empty());
        assert!(originals.after.is_none());
        let cause = originals.cause().unwrap() as *const dyn std::error::Error;

        assert!(originals.observe_once(&State::new(), &transaction, receipt.project()).is_err());
        assert!(std::ptr::addr_eq(originals.cause().unwrap(), cause));
    }

    #[test]
    fn actual_inner_mutation_keeps_its_own_receipt_before_bad_pending() {
        let receipt = genesis_receipt_data_for_test(b"tree", b"lineage");
        let transaction = append(&receipt);
        let mut originals = SourceProjectGenesisOriginalsV1::new();

        assert!(require_project_genesis_transition_v3(&State::new(), &transaction, receipt.project()).is_err());
        assert!(originals.observe_once(&State::new(), &transaction, receipt.project()).is_err());
        assert_eq!(originals.receipt.as_ref(), Some(&receipt));
        assert!(originals.mutation.cause().is_some());
        assert!(std::ptr::addr_eq(originals.cause().unwrap(), originals.mutation.cause().unwrap()));
        assert!(originals.after.is_none());
    }

    #[test]
    fn absent_anchor_pending_keeps_actual_returned_genesis_rows() {
        let transaction = JournalTransaction::new([17; 16], vec![
            JournalRecord::delete(RecordNamespace::DesiredState,
                super::super::super::source_tree_genesis::PENDING_KEY.to_vec()),
            JournalRecord::put(RecordNamespace::DesiredState, b"ack".to_vec(), vec![0]),
        ]).unwrap();
        let project = ProjectId::from_bytes([1; 16]);
        let mut originals = SourceProjectGenesisOriginalsV1::new();

        assert!(require_project_genesis_transition_v3(&State::new(), &transaction, project).is_err());
        assert!(originals.observe_once(&State::new(), &transaction, project).is_err());
        let rows = originals.anchor_rows.as_ref().unwrap();
        assert!(rows.pending.is_none());
        assert!(rows.receipts.is_empty());
        assert!(originals.before.as_ref().unwrap().receipts.is_empty());
        assert!(originals.after.is_none());
        assert!(SourceProjectGenesisOriginalsV1::fixed_footprint_v1().is_some());
    }
}
