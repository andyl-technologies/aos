//! Retains ordinary-Journal refusal regressions for the Root-owned family.
//!
//! Positive Root capacity custody and final crossings live only with the actual
//! Policy native owner. Generic Domain append keeps its canonical deny boundary.

use crate::journal::{GlobalCapacityReservationPurposeV1, GlobalCapacityReservationRequestV1, Journal, JournalError, JournalRecord, JournalTransaction, RecordNamespace};
use aos_sandbox_ledger_replay::replay::root_genesis_records::{FLOOR_PREFIX, INSTANCE_KEY, INTENT_PREFIX, PINS_KEY};

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::JournalLimits;

    #[test]
    fn generic_genesis_key_writes_are_refused_before_append_and_after_reopen() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.journal");
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let before = journal.snapshot_sequence();
        let length = std::fs::metadata(&path).unwrap().len();
        let keys = [
            INSTANCE_KEY.to_vec(),
            PINS_KEY.to_vec(),
            [INTENT_PREFIX, &[1; 16]].concat(),
            [FLOOR_PREFIX, &[1; 16]].concat(),
        ];

        for (index, key) in keys.iter().enumerate() {
            for record in [
                JournalRecord::put(RecordNamespace::DesiredState, key.clone(), vec![1]),
                JournalRecord::delete(RecordNamespace::DesiredState, key.clone()),
            ] {
                let transaction =
                    JournalTransaction::new([index as u8 + 1; 16], vec![record]).unwrap();
                assert!(matches!(
                    journal.commit(&transaction),
                    Err(JournalError::ProtectedBoundary)
                ));
                assert_eq!(journal.snapshot_sequence(), before);
                assert_eq!(std::fs::metadata(&path).unwrap().len(), length);
            }
        }
        drop(journal);

        let (journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        assert_eq!(journal.snapshot_sequence(), before);
        assert!(
            keys.iter()
                .all(|key| journal.get(RecordNamespace::DesiredState, key).is_none())
        );
    }

    #[test]
    fn foreign_capacity_cannot_carry_a_genesis_intent() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("state.journal");
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let request = GlobalCapacityReservationRequestV1 {
            purpose: GlobalCapacityReservationPurposeV1::RuntimeExecution,
            owner_namespace: RecordNamespace::Effect,
            owner_id: [1; 32],
            owner_digest: [2; 32],
            operation_id: [3; 16],
            artifact_digest: [4; 32],
            checkpoint_digest: [5; 32],
            chain_head_digest: [6; 32],
            future_transactions: 1,
            terminal_records: 3,
            terminal_bytes: 4096,
            poison_records: 3,
            poison_bytes: 4096,
        };
        let prepared = journal
            .prepare_global_capacity_reservation_v1(request, [7; 16])
            .unwrap();
        let transaction = JournalTransaction::new(
            [7; 16],
            vec![
                JournalRecord::put(
                    RecordNamespace::DesiredState,
                    [INTENT_PREFIX, &[1; 16]].concat(),
                    vec![1],
                ),
                prepared.record().clone(),
            ],
        )
        .unwrap();
        let before = journal.snapshot_sequence();
        let length = std::fs::metadata(&path).unwrap().len();

        assert!(
            journal
                .commit_global_capacity_reservation_v1(prepared, &transaction)
                .is_err()
        );
        assert_eq!(journal.snapshot_sequence(), before);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), length);
        assert_eq!(
            journal
                .records(RecordNamespace::GlobalCapacityReservation)
                .count(),
            0
        );
    }
}
