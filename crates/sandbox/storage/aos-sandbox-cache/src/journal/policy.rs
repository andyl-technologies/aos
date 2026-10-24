//! Preserves Cache's ordinary semantic checks at their original append slots.
//!
//! Shared historical predicates inspect the complete real held state and
//! proposed records. They cannot mint a native role, replace the actual Cache
//! interlock or select a privileged Source, Root or Controller crossing.

use std::collections::BTreeMap;

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as Mechanical;
use aos_sandbox_broker::domain_transaction_custody::pressure::{
    CapacityDeletionSelectorDataV1, validate_reserved_capacity_data_v1,
};
use aos_sandbox_ledger_replay::{
    ordinary_mutation as ordinary,
    replay::{root_local_recovery, root_original_inventory, root_original_native, source_tree_successor},
};

use super::{Journal, JournalError, JournalTransaction, RecordNamespace, delete_batch, ordinary_guards};

pub(super) type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

// This private recipe selection is advisory DATA. Only the separate typed
// Root entry can select its final native crossing; ordinary callers always
// enter Ordinary and cannot obtain a waiver from equal transaction bytes.
#[derive(Clone, Copy)]
pub(crate) enum CacheTransactionRecipeV1<'recipe, 'cut> {
    Ordinary,
    Q04 { recipes: &'recipe super::q04::CacheQ04TransactionRecipesV1<'cut>, index: usize },
}

pub(super) fn successor_settling(
    state: &State,
    transaction: &JournalTransaction,
) -> Result<Option<[u8; 32]>, JournalError> {
    source_tree_successor::require_transition::<
        Mechanical,
        aos_sandbox_protocol::domain_ledger::DomainLedgerDataError,
        aos_sandbox_ledger_replay::genesis::SourceGenesisReceiptDataErrorV1,
    >(state, transaction, None).map_err(JournalError::from)
}

pub(super) fn require_ordinary_owner(
    journal: &Journal,
    state: &State,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    if journal.remainder.original_replay.has_dependencies() {
        return Err(JournalError::boundary());
    }
    root_local_recovery::require_fences(state, transaction)?;
    root_original_native::require_generic_transaction(state, transaction)?;
    root_original_inventory::require_generic_transaction(state, transaction, journal.limits())?;
    aos_sandbox_protocol::domain_ledger::capacity_family::family::require_legacy_transaction(state, transaction)?;
    Ok(())
}

pub(super) fn require_holds_and_git(
    journal: &Journal,
    state: &State,
    transaction: &JournalTransaction,
    recipe: CacheTransactionRecipeV1<'_, '_>,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::controller_policy_hold::require_q04_ordinary_boundary(state, transaction)?;
    ordinary::require_no_source_q04_mutation_v1(state, transaction)?;
    match recipe {
        CacheTransactionRecipeV1::Ordinary => ordinary::require_no_cache_q04_mutation_v1(state, transaction)?,
        CacheTransactionRecipeV1::Q04 { recipes, index } => recipes.require_transition(state, transaction, index)?,
    }
    ordinary::require_no_root_q04_mutation_v1(state, transaction)?;
    aos_sandbox_ledger_replay::controller_policy_hold::require_no_mutation(state, transaction)?;
    ordinary::require_no_source_policy_mutation_v1(state, transaction)?;
    ordinary_guards::require_mount_transition_read_v1(journal.read_view(), false, state, transaction)?;
    ordinary_guards::require_storage_transition_read_v1(journal.read_view(), state, transaction)?;
    ordinary_guards::require_owner_transition_read_v1(journal.read_view(), state, transaction)?;
    Ok(())
}

pub(crate) fn validate_before_projection_for_recipe_v1(
    journal: &Journal,
    transaction: &JournalTransaction,
    recipe: CacheTransactionRecipeV1<'_, '_>,
) -> Result<Option<[u8; 32]>, JournalError> {
    journal.ensure_healthy()?;
    let native = journal.read_view();
    ordinary::require_no_create_storage_mutation(native.state(), transaction)?;
    if transaction.records().iter().any(|record| record.namespace() == RecordNamespace::ControllerResourceReservation) {
        return Err(JournalError::boundary());
    }
    let settling = successor_settling(native.state(), transaction)?;
    ordinary::require_no_nix_native_mutation_v1(native.state(), transaction)?;
    aos_sandbox_ledger_replay::git_coverage_prefix::require_no_cache_exclusive_mutation_v1(native, native.state())?;
    require_ordinary_owner(journal, native.state(), transaction)?;
    ordinary::require_no_consumer_resource_transition_v1(native.state(), transaction, false)?;
    if ordinary::transaction_touches_root_genesis_v1(transaction) {
        return Err(JournalError::boundary());
    }
    ordinary::require_common_no_selected_boundaries_v1(native.state(), transaction)?;
    require_holds_and_git(journal, native.state(), transaction, recipe)?;
    aos_sandbox_protocol::domain_ledger::transaction::validate_transaction(transaction, native.limits())?;
    delete_batch::validate(native.state(), transaction, native.next_sequence(), native.limits())?;
    if transaction.records().iter().any(|record| record.namespace() == RecordNamespace::GlobalCapacityReservation) {
        return Err(JournalError::boundary());
    }
    if native.transaction_ids().contains(transaction.id()) {
        return Err(Mechanical::DuplicateTransaction.into());
    }
    if native.committed_transactions() >= native.limits().maximum_transactions {
        return Err(JournalError::limit_exceeded("committed transaction count"));
    }
    aos_sandbox_protocol::domain_ledger::readonly::validate_idempotency_changes(native.idempotency_index(), transaction.records())?;
    Ok(settling)
}

pub(crate) fn validate_after_coordinates(
    journal: &Journal,
    transaction: &JournalTransaction,
    following_sequence: u64,
) -> Result<(), JournalError> {
    root_original_inventory::require_append_sequence_headroom(
        journal.read_view().state(), transaction, following_sequence,
    ).map_err(JournalError::from)
}

pub(crate) fn validate_after_expected_length(
    journal: &Journal,
    transaction: &JournalTransaction,
    settling: Option<[u8; 32]>,
    materialized_bytes: usize,
    expected_length: u64,
) -> Result<(), JournalError> {
    let native = journal.read_view();
    let transactions = native.committed_transactions().checked_add(1)
        .ok_or(JournalError::limit_exceeded("committed transaction count"))?;
    validate_reserved_capacity_data_v1(
        native.state(), materialized_bytes, transaction.records(),
        CapacityDeletionSelectorDataV1::Reservation(settling), expected_length,
        transactions, native.limits(),
    ).map_err(Mechanical::from).map_err(JournalError::from)
}


// These two finite stages surround the actual Held/Released upper currentness
// join. Only the genuine Cache original constructs that public opaque context;
// no ordinary caller can select a CreateStorage waiver through DATA.
pub(crate) fn validate_before_create_storage_transition_v1(
    journal: &Journal,
    transaction: &JournalTransaction,
) -> Result<Option<[u8; 32]>, JournalError> {
    journal.ensure_healthy()?;
    let native = journal.read_view();
    if transaction.records().iter().any(|record| {
        record.namespace() == RecordNamespace::ControllerResourceReservation
    }) {
        return Err(JournalError::boundary());
    }
    let settling = successor_settling(native.state(), transaction)?;
    ordinary::require_no_nix_native_mutation_v1(native.state(), transaction)?;
    aos_sandbox_ledger_replay::git_coverage_prefix::require_no_cache_exclusive_mutation_v1(
        native, native.state(),
    )?;
    require_ordinary_owner(journal, native.state(), transaction)?;
    ordinary::require_no_consumer_resource_transition_v1(native.state(), transaction, false)?;
    if ordinary::transaction_touches_root_genesis_v1(transaction) {
        return Err(JournalError::boundary());
    }
    // The old genuine CreateStorage selector required settling=None before
    // invoking its first native and upper transition observations.
    if settling.is_some() {
        return Err(JournalError::boundary());
    }
    Ok(settling)
}

pub(crate) fn validate_after_create_storage_transition_v1(
    journal: &Journal,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    let native = journal.read_view();
    ordinary::require_common_outside_create_storage_boundaries_v1(native.state(), transaction)?;
    require_holds_and_git(journal, native.state(), transaction, CacheTransactionRecipeV1::Ordinary)?;
    aos_sandbox_protocol::domain_ledger::transaction::validate_transaction(transaction, native.limits())?;
    delete_batch::validate(native.state(), transaction, native.next_sequence(), native.limits())?;
    if transaction.records().iter().any(|record| {
        record.namespace() == RecordNamespace::GlobalCapacityReservation
    }) {
        return Err(JournalError::boundary());
    }
    if native.transaction_ids().contains(transaction.id()) {
        return Err(Mechanical::DuplicateTransaction.into());
    }
    if native.committed_transactions() >= native.limits().maximum_transactions {
        return Err(JournalError::limit_exceeded("committed transaction count"));
    }
    aos_sandbox_protocol::domain_ledger::readonly::validate_idempotency_changes(
        native.idempotency_index(), transaction.records(),
    )?;
    Ok(())
}
