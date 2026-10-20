//! Routes exact closed Controller prepare/CAS only through its genuine C18 loan.
//!
//! Registration, canonical812 or a Root signature cannot authorize generic
//! writes to this relation. Append and forecast share the same targeted denial;
//! the private actual Source/C18 native loan selects the sole common engine.

use std::collections::BTreeMap;

use super::{CommitResult, Journal, JournalError, JournalTransaction, RecordNamespace};

#[cfg(target_os = "linux")]
impl Journal {
    pub(crate) fn commit_execution_no_apply_controller_original_v2(
        &mut self,
        transaction: &JournalTransaction,
        original: &mut crate::controller_execution_operation::ControllerExecutionNoApplyAppendLoanV2<'_, '_, '_>,
    ) -> Result<CommitResult, JournalError> {
        self.commit_create_storage_original_v1(
            transaction,
            super::create_storage_append::CreateStorageAppendOriginalV1::ExecutionNoApplyController(
                original,
            ),
        )
    }
}

// Kind2 metadata has its own genuine Source22 role. It cannot borrow the C18
// exception merely because both roles share the same physical append carrier.
pub(super) fn require_no_stop_cleanup_controller_mutation_v1(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::ordinary_mutation::require_no_stop_cleanup_controller_mutation_v1(state, transaction)
        .map_err(JournalError::from)
}

pub(super) fn require_no_closed_controller_mutation_v2(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::ordinary_mutation::require_no_closed_controller_mutation_v2(state, transaction)
        .map_err(JournalError::from)
}

#[cfg(test)]
impl Journal {
    /// Writes a passive cold-history corpus, consuming its DATA-only fixture writer.
    ///
    /// This test-only path deliberately bypasses semantic admission so tests
    /// can read historical closed bytes without fabricating a genuine Root/C18
    /// append original. It refuses every selected native writer. Consumption
    /// forces independent protected reopen/replay before the corpus is used.
    pub(crate) fn append_closed_no_apply_planner_fixture_data_v2(mut self,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        self.ensure_protected_authority()?;
        if !matches!(&self.native, super::native_backing::JournalNativeBackingV1::Ordinary(_))
            || self.native.transaction_ids().contains(transaction.id()) {
            return Err(JournalError::ProtectedBoundary);
        }
        let namespaces = transaction.records().iter().map(|record| record.namespace()).collect::<Vec<_>>();
        if namespaces != [RecordNamespace::ControllerCreateFailurePrepare]
            && namespaces != [RecordNamespace::Effect, RecordNamespace::Operation, RecordNamespace::DesiredState] {
            return Err(JournalError::ProtectedBoundary);
        }
        let frames = aos_sandbox_journal::transaction::encode_transaction(*transaction.id(), self.snapshot_sequence(),
            transaction.records().iter().map(|record| aos_sandbox_journal::transaction::NativeRecordRef {
                namespace_byte: record.namespace() as u8, key: record.key(), value: record.value(),
            }))?;
        let expected = self.native.expected_append_length_for_fixture(&frames)?;
        self.native.append_exact(&frames, expected)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use aos_sandbox_protocol::host_execution_no_apply::closed_controller::{
        CLOSED_CREATE_FAILURE_PREPARE_MAGIC_V2, ClosedCreateFailurePrepareDataV2,
    };
    use aos_sandbox_protocol::public_api::projection::{PROJECTION_KEY_PREFIX, PublicProjectionKindV1};

    use crate::journal::JournalRecord;

    #[test]
    fn admitted_stop_cleanup_requires_its_actual_source22_append_original() {
        use aos_sandbox_protocol::domain_ledger::{
            operation::{OperationRecord, encode_operation_record},
            public_operation::{DurablePublicOperationV1, OperationState},
        };
        let operation = [17; 16];
        let metadata = DurablePublicOperationV1::stop_cleanup_initial_v1(operation, 100).unwrap();
        let pending = encode_operation_record(OperationRecord::new(
            OperationState::Accepted, 0, false, None, Some(metadata)));
        let completed = encode_operation_record(OperationRecord::new(
            OperationState::Succeeded, 0, false, None,
            Some(metadata.advance(OperationState::Succeeded, 101).unwrap())));
        let state = BTreeMap::from([((RecordNamespace::Operation, operation.to_vec()), pending.clone())]);

        for value in [Some(pending), Some(completed), None] {
            let record = match value {
                Some(value) => JournalRecord::put(RecordNamespace::Operation, operation.to_vec(), value),
                None => JournalRecord::delete(RecordNamespace::Operation, operation.to_vec()),
            };
            let transaction = JournalTransaction::new([18; 16], vec![record]).unwrap();
            assert!(require_no_stop_cleanup_controller_mutation_v1(&state, &transaction).is_err());
        }
    }

    #[test]
    fn admitted_execution_cleanup_cannot_be_rewritten_by_a_generic_append() {
        use aos_sandbox_protocol::domain_ledger::{operation::{OperationRecord, encode_operation_record},
            public_operation::{DurablePublicOperationV1, OperationState}};
        let operation = [7; 16];
        let metadata = DurablePublicOperationV1::execution_no_apply_initial_v1(operation, 100).unwrap();
        let pending = encode_operation_record(OperationRecord::new(OperationState::Accepted, 0, false, None, Some(metadata)));
        let mut state = BTreeMap::new();
        state.insert((RecordNamespace::Operation, operation.to_vec()), pending.clone());
        let completed = encode_operation_record(OperationRecord::new(OperationState::Succeeded, 0, false, None,
            Some(metadata.advance(OperationState::Succeeded, 101).unwrap())));
        for replacement in [pending, completed] {
            let transaction = JournalTransaction::new([8; 16], vec![JournalRecord::put(
                RecordNamespace::Operation, operation.to_vec(), replacement)]).unwrap();
            assert!(matches!(require_no_closed_controller_mutation_v2(&state, &transaction),
                Err(JournalError::ProtectedBoundary)));
        }
    }

    #[test]
    fn service_local_operation_formats_do_not_enter_the_controller_decoder() {
        let operation = vec![7; 16];
        // These prefixes belong to the independent Storage MAC envelope and
        // Mount JSON resource codec; this boundary does not parse either.
        for bytes in [b"AOSSTX01".as_slice(), br#"{"version":1}"#.as_slice()] {
            let mut state = BTreeMap::new();
            state.insert((RecordNamespace::Operation, operation.clone()), bytes.to_vec());
            let transaction = JournalTransaction::new([8; 16], vec![JournalRecord::put(
                RecordNamespace::Operation, operation.clone(), bytes.to_vec())]).unwrap();
            assert!(require_no_closed_controller_mutation_v2(&state, &transaction).is_ok());
        }
    }

    #[test]
    fn malformed_controller_versioned_operations_still_refuse_replacement() {
        let operation = vec![7; 16];
        for version in [1, 2, 3] {
            let mut state = BTreeMap::new();
            state.insert((RecordNamespace::Operation, operation.clone()), vec![version]);
            let transaction = JournalTransaction::new([8; 16], vec![JournalRecord::delete(
                RecordNamespace::Operation, operation.clone())]).unwrap();
            assert!(matches!(require_no_closed_controller_mutation_v2(&state, &transaction),
                Err(JournalError::ProtectedBoundary)));
        }
    }

    #[test]
    fn canonical_magic_cannot_open_an_ordinary_prepare_append() {
        let transaction = JournalTransaction::new(
            [1; 16],
            vec![JournalRecord::put(
                RecordNamespace::ControllerCreateFailurePrepare,
                vec![2; 16],
                CLOSED_CREATE_FAILURE_PREPARE_MAGIC_V2.to_vec(),
            )],
        )
        .unwrap();

        assert!(matches!(
            require_no_closed_controller_mutation_v2(&BTreeMap::new(), &transaction),
            Err(JournalError::ProtectedBoundary)
        ));
    }

    #[test]
    fn an_ordinary_replacement_cannot_erase_the_closed_prepare() {
        let mut state = BTreeMap::new();
        state.insert(
            (RecordNamespace::ControllerCreateFailurePrepare, vec![2; 16]),
            CLOSED_CREATE_FAILURE_PREPARE_MAGIC_V2.to_vec(),
        );
        let transaction = JournalTransaction::new(
            [1; 16],
            vec![JournalRecord::put(
                RecordNamespace::ControllerCreateFailurePrepare,
                vec![2; 16],
                b"replacement".to_vec(),
            )],
        )
        .unwrap();

        assert!(matches!(
            require_no_closed_controller_mutation_v2(&state, &transaction),
            Err(JournalError::ProtectedBoundary)
        ));
    }
}
