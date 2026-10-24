//! Keeps Mount's finite semantic edges before the common native append.
//!
//! Private selectors carry no reusable right. Actual Root5, Query6, local
//! recovery and startup lenders keep their original custody and currentness
//! through these comparisons and through the durable native crossing.

mod delete_batch;

use aos_sandbox_journal::materialized::{self, RecordMutationRef};
use aos_sandbox_ledger_replay::ordinary_mutation;
use aos_sandbox_protocol::domain_ledger::{
    readonly::{apply_idempotency_record, validate_idempotency_changes},
    transaction::{encode_transaction, validate_transaction},
};

use super::*;

#[derive(Clone, Copy, Default)]
pub(super) struct AppendScope {
    pub(super) settling_reservation: Option<[u8; 32]>,
    pub(super) allow_capacity_records: bool,
    pub(super) root_local_edge: Option<RootOwnerEdge>,
}

#[derive(Default)]
pub(super) struct PreflightScope {
    pub(super) settling_reservation: Option<[u8; 32]>,
    pub(super) allow_capacity_records: bool,
    pub(super) root_local_edge: Option<RootOwnerEdge>,
}

fn root_edge(
    state: &State,
    transaction: &JournalTransaction,
    edge: RootOwnerEdge,
    limits: JournalLimits,
) -> Result<Option<[u8; 32]>, JournalError> {
    let settling = match edge {
        RootOwnerEdge::Local(edge) => root_local_recovery::validate_edge(state, transaction, edge),
        RootOwnerEdge::OriginalNative(attempt) => {
            root_original_native::validate_edge(state, transaction, attempt, limits)
        }
        RootOwnerEdge::OriginalInventory { root, query, kind } => {
            root_original_inventory::validate_edge(state, transaction, root, query, kind, limits)
        }
    }?;
    if !matches!(edge, RootOwnerEdge::OriginalInventory { .. }) {
        root_original_inventory::preserve_other_owner(state, transaction, limits)?;
    }
    Ok(settling)
}

impl MountJournalV1 {
    fn require_semantic_scope_v1(
        &self,
        state: &State,
        transaction: &JournalTransaction,
        scope: AppendScope,
    ) -> Result<AppendScope, JournalError> {
        self.ensure_healthy()?;
        ordinary_mutation::require_no_create_storage_mutation(state, transaction)?;
        // No Controller receiving original enters this concrete writer. Each
        // private Mount edge below independently requires its exact canonical
        // owner transaction before reaching a capacity-enabled crossing.
        if transaction
            .records()
            .iter()
            .any(|record| record.namespace() == RecordNamespace::ControllerResourceReservation)
        {
            return Err(MechanicalError::ProtectedBoundary.into());
        }
        let source_settling =
            aos_sandbox_ledger_replay::replay::source_tree_successor::require_transition::<
                MechanicalError,
                aos_sandbox_protocol::domain_ledger::DomainLedgerDataError,
                aos_sandbox_ledger_replay::genesis::SourceGenesisReceiptDataErrorV1,
            >(state, transaction, None)?;
        ordinary_mutation::require_no_nix_native_mutation_v1(state, transaction)?;
        let settling = match scope.root_local_edge {
            Some(edge) => root_edge(
                state,
                transaction,
                edge,
                self.native.read_view_v1().limits(),
            )?,
            None => {
                if self.semantic.original_replay.has_dependencies() {
                    return Err(MechanicalError::ProtectedBoundary.into());
                }
                root_local_recovery::require_fences(state, transaction)?;
                root_original_native::require_generic_transaction(state, transaction)?;
                root_original_inventory::require_generic_transaction(
                    state,
                    transaction,
                    self.native.read_view_v1().limits(),
                )?;
                aos_sandbox_protocol::domain_ledger::capacity_family::family::require_legacy_transaction(
                    state, transaction,
                )?;
                source_settling.or(scope.settling_reservation)
            }
        };
        ordinary_mutation::require_no_consumer_resource_transition_v1(
            state,
            transaction,
            scope.allow_capacity_records,
        )?;
        if ordinary_mutation::transaction_touches_root_genesis_v1(transaction) {
            return Err(MechanicalError::ProtectedBoundary.into());
        }
        self.require_common_mutation_boundaries_v1(state, transaction)?;
        self.require_mount_git_transition_v1(state, transaction)?;
        Ok(AppendScope {
            settling_reservation: settling,
            ..scope
        })
    }

    fn require_common_mutation_boundaries_v1(
        &self,
        state: &State,
        transaction: &JournalTransaction,
    ) -> Result<(), JournalError> {
        use aos_sandbox_ledger_replay::replay::{
            controller_source_genesis, controller_source_successor_issuance, source_tree_genesis,
        };
        // No native exception enters this owner. Preserve the ordinary engine's
        // comparison order so a later hold cannot replace an earlier refusal.
        ordinary_mutation::require_no_generic_settlement_v1(state, transaction)?;
        ordinary_mutation::require_no_stop_cleanup_controller_mutation_v1(state, transaction)?;
        ordinary_mutation::require_no_closed_controller_mutation_v2(state, transaction)?;
        ordinary_mutation::require_no_root_execution_no_apply_floor_mutation_v2(transaction)?;
        ordinary_mutation::require_no_create_storage_mutation(state, transaction)?;
        controller_source_genesis::require_no_mutation(
            state,
            transaction,
            controller_source_genesis::ControllerSourceGenesisTransition::None,
        )?;
        controller_source_successor_issuance::require_no_mutation(state, transaction, None)?;
        source_tree_genesis::require_no_mutation(
            state,
            transaction,
            source_tree_genesis::SourceGenesisTransitionV1::None,
        )?;
        let project = aos_sandbox_ledger_replay::source_project_readback::current_rows(state)
            .map_err(|_| MechanicalError::ProtectedBoundary)?;
        ordinary_mutation::require_no_project_admission_mutation_v1(&project, transaction)?;
        aos_sandbox_ledger_replay::host_fence::settlement_admission::require_no_mutation_v1(
            state,
            transaction,
        )?;
        aos_sandbox_ledger_replay::host_fence::currentness::require_no_mutation_v1(
            state,
            transaction,
        )?;
        aos_sandbox_ledger_replay::host_fence::execution::require_no_mutation_v1(
            state,
            transaction,
        )?;
        aos_sandbox_ledger_replay::controller_policy_hold::require_q04_ordinary_boundary(
            state,
            transaction,
        )?;
        ordinary_mutation::require_no_source_q04_mutation_v1(state, transaction)?;
        ordinary_mutation::require_no_cache_q04_mutation_v1(state, transaction)?;
        ordinary_mutation::require_no_root_q04_mutation_v1(state, transaction)?;
        aos_sandbox_ledger_replay::controller_policy_hold::require_no_mutation(state, transaction)?;
        ordinary_mutation::require_no_source_policy_mutation_v1(state, transaction)?;
        Ok(())
    }

    /// Preflights the exact ordered ordinary transactions without effects.
    ///
    /// # Errors
    /// Refuses an unsupported family, changed root edge, capacity/sequence/file
    /// bound, duplicate identity or any canonical encoding/materialization error.
    pub fn preflight_transactions(
        &self,
        transactions: &[JournalTransaction],
    ) -> Result<(), JournalError> {
        self.preflight_in_scope(
            PreflightTransactionViewV1::Ordinary(transactions),
            PreflightScope::default(),
        )
    }

    /// Appends an ordinary Mount transaction through its existing native owner.
    ///
    /// # Errors
    /// Preserves semantic, native, capacity and independently owed post causes.
    pub fn commit(
        &mut self,
        transaction: &JournalTransaction,
    ) -> Result<CommitResult, JournalError> {
        self.commit_in_scope(transaction, AppendScope::default())
    }

    pub(super) fn commit_in_scope(
        &mut self,
        transaction: &JournalTransaction,
        scope: AppendScope,
    ) -> Result<CommitResult, JournalError> {
        let view = self.native.read_view_v1();
        let scope = self.require_semantic_scope_v1(view.state(), transaction, scope)?;
        validate_transaction(transaction, view.limits())?;
        delete_batch::validate(
            view.state(),
            transaction,
            view.next_sequence(),
            view.limits(),
        )?;
        require_capacity_scope(transaction, scope.allow_capacity_records)?;
        if view.transaction_ids().contains(transaction.id()) {
            return Err(MechanicalError::DuplicateTransaction.into());
        }
        if view.committed_transactions() >= view.limits().maximum_transactions {
            return Err(MechanicalError::LimitExceeded("committed transaction count").into());
        }
        validate_idempotency_changes(view.idempotency_index(), transaction.records())
            .map_err(MechanicalError::from)?;
        self.append_after_semantics_once_v1(transaction, scope)
    }

    pub(super) fn preflight_in_scope(
        &self,
        transactions: PreflightTransactionViewV1<'_>,
        scope: PreflightScope,
    ) -> Result<(), JournalError> {
        self.ensure_healthy()?;
        let PreflightTransactionViewV1::Ordinary(transactions) = transactions;
        let view = self.native.read_view_v1();
        delete_batch::bound_preview(view.state(), transactions, view.limits())?;
        let mut state = view.state().clone();
        let mut idempotency = view.idempotency_index().clone();
        let mut transaction_ids = view.transaction_ids().clone();
        let mut materialized_bytes = view.materialized_bytes();
        let mut next_sequence = view.next_sequence();
        let mut committed_transactions = view.committed_transactions();
        let mut expected_length = view.metadata()?.len();

        for transaction in transactions {
            let scope = self.require_semantic_scope_v1(
                &state,
                transaction,
                AppendScope {
                    settling_reservation: scope.settling_reservation,
                    allow_capacity_records: scope.allow_capacity_records,
                    root_local_edge: scope.root_local_edge,
                },
            )?;
            validate_transaction(transaction, view.limits())?;
            delete_batch::validate(&state, transaction, next_sequence, view.limits())?;
            require_capacity_scope(transaction, scope.allow_capacity_records)?;
            if !transaction_ids.insert(*transaction.id()) {
                return Err(MechanicalError::DuplicateTransaction.into());
            }
            if committed_transactions >= view.limits().maximum_transactions {
                return Err(MechanicalError::LimitExceeded("committed transaction count").into());
            }
            validate_idempotency_changes(&idempotency, transaction.records())
                .map_err(MechanicalError::from)?;
            materialized_bytes = materialized::validate_change(
                &state,
                materialized_bytes,
                transaction.records().iter().map(RecordMutationRef::from),
                view.limits().maximum_materialized_bytes,
                view.limits().maximum_materialized_records,
            )?;
            let frames = encode_transaction(transaction, next_sequence)?;
            let frame_count = u64::try_from(frames.len())
                .map_err(|_| MechanicalError::LimitExceeded("transaction frame count"))?;
            let following = next_sequence
                .checked_add(frame_count)
                .ok_or(MechanicalError::SequenceExhausted)?;
            root_original_inventory::require_append_sequence_headroom(
                &state,
                transaction,
                following,
            )?;
            expected_length = frames
                .iter()
                .try_fold(expected_length, |length, frame| {
                    length.checked_add(u64::try_from(frame.len()).ok()?)
                })
                .ok_or(MechanicalError::JournalTooLarge)?;
            if expected_length > view.limits().maximum_journal_bytes {
                return Err(MechanicalError::JournalTooLarge.into());
            }
            let following_transactions =
                committed_transactions
                    .checked_add(1)
                    .ok_or(MechanicalError::LimitExceeded(
                        "committed transaction count",
                    ))?;
            validate_reserved_capacity(
                &state,
                materialized_bytes,
                transaction.records(),
                scope.settling_reservation,
                expected_length,
                following_transactions,
                view.limits(),
                scope.root_local_edge,
            )?;
            for record in transaction.records() {
                materialized::apply_mutation(&mut state, RecordMutationRef::from(record));
                apply_idempotency_record(&mut idempotency, record)
                    .map_err(MechanicalError::from)?;
            }
            next_sequence = following;
            committed_transactions = following_transactions;
        }
        Ok(())
    }

    pub(super) fn require_append_capacity_v1(
        &self,
        transaction: &JournalTransaction,
        scope: AppendScope,
        materialized_bytes: usize,
        expected_length: u64,
        following_sequence: u64,
    ) -> Result<(), JournalError> {
        let view = self.native.read_view_v1();
        root_original_inventory::require_append_sequence_headroom(
            view.state(),
            transaction,
            following_sequence,
        )?;
        validate_reserved_capacity(
            view.state(),
            materialized_bytes,
            transaction.records(),
            scope.settling_reservation,
            expected_length,
            view.committed_transactions()
                .checked_add(1)
                .ok_or(MechanicalError::LimitExceeded(
                    "committed transaction count",
                ))?,
            view.limits(),
            scope.root_local_edge,
        )
    }
}

fn require_capacity_scope(
    transaction: &JournalTransaction,
    allow_capacity_records: bool,
) -> Result<(), JournalError> {
    let has_capacity = transaction
        .records()
        .iter()
        .any(|record| record.namespace() == RecordNamespace::GlobalCapacityReservation);
    if has_capacity != allow_capacity_records {
        return Err(MechanicalError::ProtectedBoundary.into());
    }
    Ok(())
}

pub(super) fn validate_reserved_capacity(
    state: &State,
    materialized_bytes: usize,
    records: &[JournalRecord],
    settling: Option<[u8; 32]>,
    journal_bytes: u64,
    transactions: usize,
    limits: JournalLimits,
    _edge: Option<RootOwnerEdge>,
) -> Result<(), JournalError> {
    use aos_sandbox_broker::domain_transaction_custody::pressure::{
        CapacityDeletionSelectorDataV1, validate_reserved_capacity_data_v1,
    };
    validate_reserved_capacity_data_v1(
        state,
        materialized_bytes,
        records,
        CapacityDeletionSelectorDataV1::Reservation(settling),
        journal_bytes,
        transactions,
        limits,
    )
    .map_err(Into::into)
}
