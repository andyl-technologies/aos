//! Keeps ordinary and private Source validation at their original frontiers.
//!
//! Each comparison delegates to the canonical historical DATA engine. The
//! private Source edge only selects its genuine witnessed replay; ordinary
//! callers retain the full arbitrary-path refusal schedule and gain no typed
//! exception from a namespace, decoded row or successful preview.

use std::collections::BTreeMap;

use aos_sandbox_broker::domain_transaction_custody::pressure::{
    CapacityDeletionSelectorDataV1, validate_reserved_capacity_data_v1,
};
use aos_sandbox_ledger_replay::{
    ordinary_mutation as ordinary,
    replay::{
        root_local_recovery, root_original_inventory, root_original_native, source_tree_successor,
    },
};
use aos_sandbox_protocol::domain_ledger::{
    capacity_family::family::require_legacy_transaction, readonly::validate_idempotency_changes,
};

use super::super::{
    Journal, JournalError, JournalTransaction, RecordNamespace, delete_batch, ordinary_guards,
};
use super::{AppendScope, SourceOwnerEdge};

pub(super) type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

/// Preserves the derived settling reservation without selecting a native phase.
pub(super) fn with_successor_settling(
    state: &State,
    transaction: &JournalTransaction,
    mut scope: AppendScope,
) -> Result<AppendScope, JournalError> {
    let settling = source_tree_successor::require_transition::<
        JournalError,
        aos_sandbox_protocol::domain_ledger::DomainLedgerDataError,
        aos_sandbox_ledger_replay::genesis::SourceGenesisReceiptDataErrorV1,
    >(state, transaction, None)?;
    scope.settling_reservation = settling.or(scope.settling_reservation);
    Ok(scope)
}

/// Uses the real Source replay only for the actual private Source crossing.
pub(super) fn require_owner_branch(
    journal: &Journal,
    state: &State,
    transaction: &JournalTransaction,
    mut scope: AppendScope,
    compare_before: bool,
) -> Result<AppendScope, JournalError> {
    if matches!(scope.root_local_edge, Some(SourceOwnerEdge::SourceOriginal)) {
        let (_, comparison) = journal.source_original_replay.preview_transaction(
            state,
            transaction,
            journal.native_view().limits(),
        )?;
        if compare_before && comparison.before() != state {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        scope.settling_reservation = None;
    } else {
        if journal.source_original_replay.has_dependencies() {
            return Err(JournalError::ProtectedBoundary);
        }
        root_local_recovery::require_fences(state, transaction)?;
        root_original_native::require_generic_transaction(state, transaction)?;
        root_original_inventory::require_generic_transaction(
            state,
            transaction,
            journal.native_view().limits(),
        )?;
        require_legacy_transaction(state, transaction)?;
    }
    Ok(scope)
}

/// Delegates the same no-selected boundaries at the original Source slot.
pub(super) fn require_common_boundaries(
    state: &State,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    ordinary::require_common_no_selected_boundaries_v1(state, transaction)
}

/// Checks the independent Q04 markers before the canonical hold comparisons.
pub(super) fn require_holds_and_git(
    journal: &Journal,
    state: &State,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    #[cfg(target_os = "linux")]
    {
        aos_sandbox_ledger_replay::controller_policy_hold::require_q04_ordinary_boundary(
            state,
            transaction,
        )?;
        ordinary::require_no_source_q04_mutation_v1(state, transaction)?;
        ordinary::require_no_cache_q04_mutation_v1(state, transaction)?;
        ordinary::require_no_root_q04_mutation_v1(state, transaction)?;
    }

    aos_sandbox_ledger_replay::controller_policy_hold::require_no_mutation(state, transaction)?;
    ordinary::require_no_source_policy_mutation_v1(state, transaction)?;
    ordinary_guards::require_mount_transition_read_v1(
        journal.native_view(),
        false,
        state,
        transaction,
    )?;
    ordinary_guards::require_storage_transition_read_v1(journal.native_view(), state, transaction)?;
    ordinary_guards::require_owner_transition_read_v1(journal.native_view(), state, transaction)?;
    Ok(())
}

/// Runs the same commit checks before any native projection or frame growth.
pub(super) fn validate_before_projection(
    journal: &Journal,
    transaction: &JournalTransaction,
    scope: AppendScope,
) -> Result<AppendScope, JournalError> {
    journal.ensure_healthy()?;
    let native = journal.native_view();
    ordinary::require_no_create_storage_mutation(native.state(), transaction)?;
    if transaction
        .records()
        .iter()
        .any(|record| record.namespace() == RecordNamespace::ControllerResourceReservation)
    {
        return Err(JournalError::ProtectedBoundary);
    }
    let scope = with_successor_settling(native.state(), transaction, scope)?;
    ordinary::require_no_nix_native_mutation_v1(native.state(), transaction)?;
    #[cfg(target_os = "linux")]
    aos_sandbox_ledger_replay::git_coverage_prefix::require_no_cache_exclusive_mutation_v1(
        native,
        native.state(),
    )?;
    let scope = require_owner_branch(journal, native.state(), transaction, scope, true)?;
    ordinary::require_no_consumer_resource_transition_v1(
        native.state(),
        transaction,
        scope.allow_capacity_records,
    )?;

    // Ordinary callers have no Root genesis capacity port. The only private
    // capacity path is the exact Source namespace claim validated by its owner.
    #[cfg(target_os = "linux")]
    if ordinary::transaction_touches_root_genesis_v1(transaction) {
        return Err(JournalError::ProtectedBoundary);
    }

    require_common_boundaries(native.state(), transaction)?;
    require_holds_and_git(journal, native.state(), transaction)?;
    super::super::validate_transaction(transaction, native.limits())?;
    delete_batch::validate(
        native.state(),
        transaction,
        native.next_sequence(),
        native.limits(),
    )?;
    let has_capacity_records = transaction
        .records()
        .iter()
        .any(|record| record.namespace() == RecordNamespace::GlobalCapacityReservation);
    if has_capacity_records != scope.allow_capacity_records {
        return Err(JournalError::ProtectedBoundary);
    }
    if native.transaction_ids().contains(transaction.id()) {
        return Err(JournalError::DuplicateTransaction);
    }
    if native.committed_transactions() >= native.limits().maximum_transactions {
        return Err(JournalError::LimitExceeded("committed transaction count"));
    }
    validate_idempotency_changes(native.idempotency_index(), transaction.records())?;
    Ok(scope)
}

pub(super) fn validate_after_coordinates(
    journal: &Journal,
    transaction: &JournalTransaction,
    scope: AppendScope,
    following_sequence: u64,
) -> Result<(), JournalError> {
    let native = journal.native_view();
    let transactions = native
        .committed_transactions()
        .checked_add(1)
        .ok_or(JournalError::LimitExceeded("committed transaction count"))?;

    root_original_inventory::require_append_sequence_headroom(
        native.state(),
        transaction,
        following_sequence,
    )?;

    if matches!(scope.root_local_edge, Some(SourceOwnerEdge::SourceOriginal)) {
        let (_, comparison) = journal.source_original_replay.preview_transaction(
            native.state(),
            transaction,
            native.limits(),
        )?;
        let prospective_length = native
            .metadata()?
            .len()
            .checked_add(super::super::encoded_transaction_append_bytes(transaction)?)
            .ok_or(JournalError::JournalTooLarge)?;
        super::super::original::replay::require_advisory_bounds(
            &comparison,
            native.limits(),
            prospective_length,
            transactions,
            following_sequence,
        )?;
    }

    Ok(())
}

pub(super) fn validate_after_expected_length(
    journal: &Journal,
    transaction: &JournalTransaction,
    scope: AppendScope,
    materialized_bytes: usize,
    expected_length: u64,
) -> Result<(), JournalError> {
    let native = journal.native_view();
    let transactions = native
        .committed_transactions()
        .checked_add(1)
        .ok_or(JournalError::LimitExceeded("committed transaction count"))?;

    let deletion = match scope.root_local_edge {
        Some(SourceOwnerEdge::SourceOriginal) => CapacityDeletionSelectorDataV1::ExistingRecord,
        None => CapacityDeletionSelectorDataV1::Reservation(scope.settling_reservation),
    };
    validate_reserved_capacity_data_v1(
        native.state(),
        materialized_bytes,
        transaction.records(),
        deletion,
        expected_length,
        transactions,
        native.limits(),
    )?;
    Ok(())
}
