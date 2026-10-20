//! Selects original native diagnostics for canonical predecessor DATA work.

use super::*;
pub(in crate::journal) type SourceGenesisPredecessorOriginalsV1 = aos_sandbox_ledger_replay::replay::source_tree_successor::SourceGenesisPredecessorOriginalsV1<JournalError,
    crate::hierarchy::protected_journal::HierarchyProtectedJournalErrorV1,
    crate::hierarchy::genesis_profile::SourceGenesisErrorV1>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_missing_predecessor_keeps_both_returned_family_maps() {
        let state = State::new();
        let transaction = JournalTransaction::new([17; 16], vec![
            JournalRecord::put(RecordNamespace::DesiredState, b"unrelated".to_vec(), vec![1]),
        ]).unwrap();
        let mut originals = SourceGenesisPredecessorOriginalsV1::new();
        assert!(require_genesis_predecessor(&state, &transaction).is_err());

        assert!(originals.observe_once(&state, &transaction).is_err());
        assert!(originals.genesis.as_ref().unwrap().receipts.is_empty());
        assert!(originals.rows.as_ref().unwrap().receipts.is_empty());
        assert!(originals.receipt.is_none());
        let cause = originals.cause().unwrap() as *const dyn std::error::Error;

        assert!(originals.observe_once(&state, &transaction).is_err());
        assert!(std::ptr::addr_eq(originals.cause().unwrap(), cause));
    }
}
