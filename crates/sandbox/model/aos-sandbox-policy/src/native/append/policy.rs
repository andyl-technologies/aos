//! Preserves the fixed Root owners' ordinary denial frontiers.
//!
//! Native exceptions are dispatched only by the private concrete gate. The
//! folds below use the same complete current/prospective rows and canonical
//! lower predicates; no namespace-only final-map shortcut replaces them.

use super::{ErrorV1, PolicyMutationGateV1, RootPolicyJournalV1};
use aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1 as Mechanical;
use aos_sandbox_model::RecordNamespace;
use aos_sandbox_ledger_replay::{ordinary_mutation, replay};
use aos_sandbox_protocol::domain_ledger::transaction::JournalTransaction;
use std::collections::BTreeMap;

type State = BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>;

fn require_source_and_inventory_v1(
    journal: &RootPolicyJournalV1,
    state: &State,
    transaction: &JournalTransaction,
    original: super::genesis::GenesisSourceBorrowV1<'_, '_>,
) -> Result<Option<[u8; 32]>, ErrorV1> {
    let settling = original.require_transition_v1(journal, state, transaction)?;
    ordinary_mutation::require_no_nix_native_mutation_v1(state, transaction)?;
    aos_sandbox_ledger_replay::git_coverage_prefix::require_no_cache_exclusive_mutation_v1(
        journal.read_view(),
        state,
    )?;
    if journal.history.original_replay.has_dependencies() {
        return Err(ErrorV1::boundary());
    }
    replay::root_local_recovery::require_fences(state, transaction)?;
    replay::root_original_native::require_generic_transaction(state, transaction)?;
    replay::root_original_inventory::require_generic_transaction(
        state,
        transaction,
        journal.limits(),
    )?;
    aos_sandbox_protocol::domain_ledger::capacity_family::family::require_legacy_transaction(
        state,
        transaction,
    )
    .map_err(Mechanical::from)?;
    Ok(settling)
}

macro_rules! require_common_and_q04_v1 {
    ($journal:ident, $state:ident, $transaction:ident, $($q04:tt)*) => {{
        let journal = $journal;
        let state = $state;
        let transaction = $transaction;
    ordinary_mutation::require_common_no_selected_boundaries_v1(state, transaction)?;
    aos_sandbox_ledger_replay::controller_policy_hold::require_q04_ordinary_boundary(
        state, transaction,
    )?;
    ordinary_mutation::require_no_source_q04_mutation_v1(state, transaction)?;
    ordinary_mutation::require_no_cache_q04_mutation_v1(state, transaction)?;
    $($q04)*
    aos_sandbox_ledger_replay::controller_policy_hold::require_no_mutation(state, transaction)?;
    ordinary_mutation::require_no_source_policy_mutation_v1(state, transaction)?;

    // Fixed Root journals cannot be the Mount/Storage/Controller writers.
    // The shared closed arm retains the actual path-dependent remote-owner
    // denial, including ordinary fixture paths, without instantiating their
    // unrelated native role implementations here.
    let read = journal.read_view();
    aos_sandbox_ledger_replay::define_provider_git_ordinary_data_recipe_v1! {
        @fixed_remote read, state, ErrorV1::boundary()
    }
    Ok::<(), ErrorV1>(())
    }};
}

pub(super) fn require_live_v1(
    journal: &RootPolicyJournalV1,
    transaction: &JournalTransaction,
    gate: &mut PolicyMutationGateV1<'_, '_, '_, '_, '_>,
) -> Result<super::genesis::CapacityCoordinatesV1, ErrorV1> {
    let read = journal.read_view();
    let state = read.state();
    journal.ensure_healthy()?;
    match gate {
        PolicyMutationGateV1::RootOpen(original) => {
            original.require_transition(journal, transaction)?;
        }
        _ => ordinary_mutation::require_no_create_storage_mutation(state, transaction)?,
    }
    if transaction
        .records()
        .iter()
        .any(|record| record.namespace() == RecordNamespace::ControllerResourceReservation)
    {
        return Err(ErrorV1::boundary());
    }
    let settling =
        require_source_and_inventory_v1(journal, state, transaction, gate.source_borrow_v1())?;
    let capacity = gate.capacity_coordinates_v1(settling);
    capacity.require_consumer_v1(state, transaction)?;
    gate.require_root_genesis_v1(journal, transaction)?;
    require_common_and_q04_v1!(journal, state, transaction,
        gate.require_q04_transition_v1(state, transaction, 0)?;
    )?;
    Ok(capacity)
}

pub(super) fn require_forecast_v1(
    journal: &RootPolicyJournalV1,
    state: &State,
    transaction: &JournalTransaction,
    index: usize,
    gate: &mut super::preflight::PolicyPreflightGateV1<'_, '_, '_, '_, '_, '_>,
) -> Result<super::genesis::CapacityCoordinatesV1, ErrorV1> {
    // The old advisory loop does not run the live-only Root-genesis mutation
    // gate. Its actual finite forecast/transition remains separately checked.
    let settling =
        require_source_and_inventory_v1(journal, state, transaction, gate.source_borrow_v1())?;
    let capacity = gate.capacity_coordinates_v1(settling);
    require_common_and_q04_v1!(journal, state, transaction,
        gate.require_q04_transition_v1(state, transaction, index)?;
    )?;
    capacity.require_consumer_v1(state, transaction)?;
    Ok(capacity)
}
