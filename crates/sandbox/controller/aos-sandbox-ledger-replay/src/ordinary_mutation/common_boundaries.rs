//! Composes the actual no-selected common mutation denials in their old order.
//!
//! This is one fixed pure DATA path. It accepts no native original, exception
//! selector, cache mode, allow bit, callback, financial handle or success grant.
//! Actual role adapters keep native currentness and selected final crossings
//! outside this function at their unchanged frontiers.

use std::collections::BTreeMap;

use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as JournalError;
use aos_sandbox_model::RecordNamespace;
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;

// The selected companion omits only the separately authenticated
// CreateStorage family denial. It supplies no native original or append port.
macro_rules! common_boundaries {
    ($state:ident, $transaction:ident, { $($create_storage:tt)* }) => {{
    super::require_no_generic_settlement_v1($state, $transaction)?;
    super::require_no_stop_cleanup_controller_mutation_v1($state, $transaction)?;
    super::require_no_closed_controller_mutation_v2($state, $transaction)?;
    super::require_no_root_execution_no_apply_floor_mutation_v2($transaction)?;
        $($create_storage)*
    crate::replay::controller_source_genesis::require_no_mutation(
        $state,
        $transaction,
        crate::replay::controller_source_genesis::ControllerSourceGenesisTransition::None,
    )?;
    crate::replay::controller_source_successor_issuance::require_no_mutation(
        $state, $transaction, None,
    )?;
    crate::replay::source_tree_genesis::require_no_mutation(
        $state,
        $transaction,
        crate::replay::source_tree_genesis::SourceGenesisTransitionV1::None,
    )?;
    crate::source_project_readback::require_no_mutation(
        $state,
        $transaction,
        crate::source_project_readback::SourceProjectAdmissionTransition::None,
    )?;
    crate::host_fence::settlement_admission::require_no_mutation_v1($state, $transaction)?;
    crate::host_fence::currentness::require_no_mutation_v1($state, $transaction)?;
    crate::host_fence::execution::require_no_mutation_v1($state, $transaction)?;
    Ok(())
    }};
}

/// Refuses privileged common mutations without a selected original.
///
/// This retains the complete existing saved-state and proposed-record folds,
/// including reserved prefixes within otherwise generic namespaces. A passing
/// comparison establishes no role, native ownership or append permission.
///
/// # Errors
/// Returns the first canonical denial in the original A8, Controller Stop,
/// Controller NoApply, Root floor, Create storage, genesis, successor, project,
/// Host settlement/currentness/execution order.
pub fn require_common_no_selected_boundaries_v1(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    common_boundaries!(state, transaction, {
        super::require_no_create_storage_mutation(state, transaction)?;
    })
}


/// Checks every ordinary common boundary outside the Create Storage family.
///
/// The native role must separately authenticate its exact Create Storage
/// transition and final crossing. This comparison accepts no allow selector,
/// owns no native original, and grants no append or receiving permission.
///
/// # Errors
/// Returns the first ordinary denial in the original order, omitting only the
/// separately checked Create Storage family predicate.
pub fn require_common_outside_create_storage_boundaries_v1(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    common_boundaries!(state, transaction, {})
}
