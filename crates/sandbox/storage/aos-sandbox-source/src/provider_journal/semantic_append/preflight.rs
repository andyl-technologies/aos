//! Forecasts Source transactions with the existing canonical DATA engines.
//!
//! The actual writer remains immutably held throughout this advisory. No map,
//! encoded frame or successful forecast can be installed as a native owner or
//! replace the original writer's final comparison and append crossing.

use aos_sandbox_broker::domain_transaction_custody::pressure::{
    CapacityDeletionSelectorDataV1, validate_reserved_capacity_data_v1,
};
use aos_sandbox_journal::materialized::{RecordMutationRef, apply_mutation};
use aos_sandbox_protocol::domain_ledger::{
    readonly::{apply_idempotency_record, validate_idempotency_changes},
    transaction::encode_transaction,
};

use super::super::{
    Journal, JournalError, JournalTransaction, RecordNamespace, delete_batch, original,
    root_original_inventory, validate_materialized_change, validate_transaction,
};
use super::{PreflightScope, SourceOwnerEdge, policy};
use aos_sandbox_ledger_replay::ordinary_mutation as ordinary;

impl Journal {
    /// Forecasts ordinary Source rows without selecting an original owner edge.
    ///
    /// # Errors
    /// Refuses protected original/floor mutations, changed canonical input,
    /// reused transactions, or unchanged journal and retained-capacity bounds.
    pub fn preflight_transactions(
        &self,
        transactions: &[JournalTransaction],
    ) -> Result<(), JournalError> {
        self.preflight_in_scope(transactions, PreflightScope::default())
    }

    pub(in crate::provider_journal) fn preflight_in_scope(
        &self,
        transactions: &[JournalTransaction],
        scope: PreflightScope,
    ) -> Result<(), JournalError> {
        self.ensure_healthy()?;
        let native = self.native_view();
        for transaction in transactions {
            ordinary::require_no_create_storage_mutation(native.state(), transaction)?;
        }
        #[cfg(target_os = "linux")]
        aos_sandbox_ledger_replay::git_coverage_prefix::require_no_cache_exclusive_mutation_v1(
            native,
            native.state(),
        )?;
        if scope.root_local_edge.is_some() && transactions.len() != 1 {
            return Err(JournalError::ProtectedBoundary);
        }

        delete_batch::bound_preview(native.state(), transactions, native.limits())?;
        let mut state = native.state().clone();
        let mut idempotency = native.idempotency_index().clone();
        let mut transaction_ids = native.transaction_ids().clone();
        let mut materialized_bytes = native.materialized_bytes();
        let mut next_sequence = native.next_sequence();
        let mut committed_transactions = native.committed_transactions();
        let mut expected_length = native.metadata()?.len();

        for transaction in transactions {
            let scope = policy::with_successor_settling(&state, transaction, scope)?;
            #[cfg(target_os = "linux")]
            aos_sandbox_ledger_replay::git_coverage_prefix::require_no_cache_exclusive_mutation_v1(
                native, &state,
            )?;
            ordinary::require_no_nix_native_mutation_v1(&state, transaction)?;
            let scope = policy::require_owner_branch(self, &state, transaction, scope, false)?;
            policy::require_common_boundaries(&state, transaction)?;
            policy::require_holds_and_git(self, &state, transaction)?;

            let has_capacity_records = transaction
                .records()
                .iter()
                .any(|record| record.namespace() == RecordNamespace::GlobalCapacityReservation);
            // The old consumer comparison uses the actual current writer,
            // independently of the prospective replay state.
            ordinary::require_no_consumer_resource_transition_v1(
                native.state(),
                transaction,
                scope.allow_capacity_records,
            )?;
            if has_capacity_records != scope.allow_capacity_records {
                return Err(JournalError::ProtectedBoundary);
            }
            validate_transaction(transaction, native.limits())?;
            delete_batch::validate(&state, transaction, next_sequence, native.limits())?;
            if !transaction_ids.insert(*transaction.id()) {
                return Err(JournalError::DuplicateTransaction);
            }
            if committed_transactions >= native.limits().maximum_transactions {
                return Err(JournalError::LimitExceeded("committed transaction count"));
            }
            validate_idempotency_changes(&idempotency, transaction.records())?;
            materialized_bytes = validate_materialized_change(
                &state,
                materialized_bytes,
                transaction.records(),
                native.limits(),
            )?;

            let frames = encode_transaction(transaction, next_sequence)?;
            let frame_count = u64::try_from(frames.len())
                .map_err(|_| JournalError::LimitExceeded("transaction frame count"))?;
            let following_sequence = next_sequence
                .checked_add(frame_count)
                .ok_or(JournalError::SequenceExhausted)?;
            root_original_inventory::require_append_sequence_headroom(
                &state,
                transaction,
                following_sequence,
            )?;
            let additional = frames
                .iter()
                .try_fold(0_u64, |bytes, frame| bytes.checked_add(frame.len() as u64))
                .ok_or(JournalError::JournalTooLarge)?;
            expected_length = expected_length
                .checked_add(additional)
                .ok_or(JournalError::JournalTooLarge)?;
            if expected_length > native.limits().maximum_journal_bytes {
                return Err(JournalError::JournalTooLarge);
            }

            if matches!(scope.root_local_edge, Some(SourceOwnerEdge::SourceOriginal)) {
                let (_, comparison) = self.source_original_replay.preview_transaction(
                    &state,
                    transaction,
                    native.limits(),
                )?;
                original::replay::require_advisory_bounds(
                    &comparison,
                    native.limits(),
                    expected_length,
                    committed_transactions
                        .checked_add(1)
                        .ok_or(JournalError::LimitExceeded("committed transaction count"))?,
                    following_sequence,
                )?;
            }
            let deletion = match scope.root_local_edge {
                Some(SourceOwnerEdge::SourceOriginal) => {
                    CapacityDeletionSelectorDataV1::ExistingRecord
                }
                None => CapacityDeletionSelectorDataV1::Reservation(scope.settling_reservation),
            };
            validate_reserved_capacity_data_v1(
                &state,
                materialized_bytes,
                transaction.records(),
                deletion,
                expected_length,
                committed_transactions
                    .checked_add(1)
                    .ok_or(JournalError::LimitExceeded("committed transaction count"))?,
                native.limits(),
            )?;

            for record in transaction.records() {
                apply_mutation(&mut state, RecordMutationRef::from(record));
                apply_idempotency_record(&mut idempotency, record)?;
            }
            next_sequence = following_sequence;
            committed_transactions += 1;
        }
        Ok(())
    }
}
