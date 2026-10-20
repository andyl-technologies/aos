//! Semantic transaction append and paired advisory preflight recipes.
//!
//! This group owns the complete ordinary and closed append paths, their
//! preflights, Q04 adapters and append-only guards on the original `Journal`.
//! The final native crossings, retained loans, durable append and subsequent
//! publication form one ordered recipe. Opening, replay, selector DATA and
//! domain authority admission remain in the parent and their existing owners.

pub(super) mod engine;
mod preflight_retained;
mod stop_cleanup_source;
pub use preflight_retained::ProtectedJournalPreflightOriginalV2;
#[cfg(target_os = "linux")]
pub(crate) mod delete;

use aos_sandbox_protocol::domain_ledger::capacity_family::capacity_record_has_legacy_purpose;

use std::collections::BTreeMap;

use sha2::{Digest, Sha256};

use super::{
    CacheMutationGateV1, CommitResult, FirstSourceSuccessorNativePhaseV2,
    GlobalCapacityReservationPurposeV1, HeldCacheMutationGateV1, Journal, JournalError,
    JournalLimits, JournalRecord, JournalTransaction, PreflightTransactionViewV1,
    PreparedGlobalCapacityReservationV1, ProjectNativeTransitionV3, ProtectedJournalAuthority,
    RecordNamespace, RootOwnerEdge, RootSourceGenesisTransitionV1, SourceProjectAdmissionTransition,
    apply_record, cache_policy_hold,
    capacity_reservation, controller_policy_hold, controller_source_genesis,
    controller_source_successor_issuance, delete_batch, encode_transaction,
    encoded_transaction_append_bytes, host_currentness_fence, host_execution_fence,
    host_settlement_admission_gate, native_held, root_local_recovery, root_original_inventory,
    root_original_native, source_domain_policy_hold, source_history,
    source_project_admission_challenge, source_tree_genesis, source_tree_successor,
    validate_idempotency_changes, validate_materialized_change, validate_reserved_capacity,
    validate_transaction,
};
#[cfg(target_os = "linux")]
use super::{
    CacheQ04TransactionRecipesV1, ControllerQ04TransitionV1, GlobalCapacityReservationV1,
    GlobalGenesisNativeCutV2, Q04JournalTransitionV1, SourceQ04TransactionRecipesV1,
    is_q04_lower_history_record_v1, nix_offline_provisioning,
};

/// Contains private append selectors without admission or reusable rights.
///
/// Genuine gates and final-crossing loans remain separate engine arguments.
#[derive(Clone, Copy)]
pub(super) struct AppendScope {
    pub(super) settling_reservation: Option<[u8; 32]>,
    pub(super) allow_capacity_records: bool,
    pub(super) allow_policy_hold_transition: bool,
    pub(super) allow_host_fence_acquisition: bool,
    pub(super) allow_host_currentness_fence_acquisition: bool,
    pub(super) allow_host_settlement_admission_append: bool,
    pub(super) project_admission_transition: SourceProjectAdmissionTransition,
    pub(super) controller_genesis_transition:
        aos_sandbox_ledger_replay::replay::controller_source_genesis::ControllerSourceGenesisTransition,
    pub(super) source_genesis_transition: source_tree_genesis::SourceGenesisTransitionV1,
    pub(super) root_genesis_transition: RootSourceGenesisTransitionV1,
    pub(super) root_local_edge: Option<RootOwnerEdge>,
    pub(super) successor_issuance_transition:
        Option<controller_source_successor_issuance::Transition>,
    pub(super) first_successor: Option<FirstSourceSuccessorNativePhaseV2>,
}

impl Default for AppendScope {
    fn default() -> Self {
        Self {
            settling_reservation: None,
            allow_capacity_records: false,
            allow_policy_hold_transition: false,
            allow_host_fence_acquisition: false,
            allow_host_currentness_fence_acquisition: false,
            allow_host_settlement_admission_append: false,
            project_admission_transition: SourceProjectAdmissionTransition::None,
            controller_genesis_transition:
                aos_sandbox_ledger_replay::replay::controller_source_genesis::ControllerSourceGenesisTransition::None,
            source_genesis_transition: source_tree_genesis::SourceGenesisTransitionV1::None,
            root_genesis_transition: RootSourceGenesisTransitionV1::None,
            root_local_edge: None,
            successor_issuance_transition: None,
            first_successor: None,
        }
    }
}

/// Borrows immutable forecast selectors without original final-crossing loans.
///
/// The Q04 recipe view and Cache gate retain independent borrow lifetimes.
#[derive(Default)]
pub(super) struct PreflightScope<'phases> {
    pub(super) settling_reservation: Option<[u8; 32]>,
    pub(super) allow_capacity_records: bool,
    pub(super) allow_policy_hold_transition: bool,
    pub(super) project_transitions: Option<&'phases [SourceProjectAdmissionTransition]>,
    pub(super) controller_genesis_transitions:
        Option<&'phases [aos_sandbox_ledger_replay::replay::controller_source_genesis::ControllerSourceGenesisTransition]>,
    pub(super) genesis_transitions:
        Option<&'phases [source_tree_genesis::SourceGenesisTransitionV1]>,
    pub(super) root_local_edge: Option<RootOwnerEdge>,
    pub(super) successor_issuance_transitions:
        Option<&'phases [controller_source_successor_issuance::Transition]>,
    pub(super) first_successors: Option<&'phases [FirstSourceSuccessorNativePhaseV2]>,
}

impl Journal {
    /// Dispatches ordinary selectors without original final-crossing loans.
    ///
    /// # Errors
    /// Returns the original semantic, capacity, gate or durable append failure.
    pub(super) fn commit_in_scope(
        &mut self,
        transaction: &JournalTransaction,
        scope: AppendScope,
        cache_gate: CacheMutationGateV1<'_>,
    ) -> Result<CommitResult, JournalError> {
        self.commit_with_native_scope(
            transaction,
            scope,
            cache_gate,
            #[cfg(target_os = "linux")]
            None,
            None,
            #[cfg(target_os = "linux")]
            None,
        )
    }

    /// Advises ordinary transactions without selecting project-genesis phases.
    ///
    /// # Errors
    /// Returns the original semantic, capacity, gate or forecast failure.
    pub(super) fn preflight_in_scope(
        &self,
        transactions: PreflightTransactionViewV1<'_>,
        scope: PreflightScope<'_>,
        cache_gate: CacheMutationGateV1<'_>,
    ) -> Result<(), JournalError> {
        self.preflight_with_project_genesis(transactions, scope, cache_gate, None)
    }
}

#[cfg(target_os = "linux")]
impl GlobalGenesisNativeCutV2<'_> {
    fn final_crossing(
        &self,
        journal: &Journal,
        source_transition: source_tree_genesis::SourceGenesisTransitionV1,
        controller_transition: aos_sandbox_ledger_replay::replay::controller_source_genesis::ControllerSourceGenesisTransition,
    ) -> Result<(), JournalError> {
        use aos_sandbox_ledger_replay::replay::controller_source_genesis::ControllerSourceGenesisTransition as Controller;
        use source_tree_genesis::SourceGenesisTransitionV1 as Source;
        let original = match self {
            Self::SourcePrepared(root) if source_transition == Source::Append
                && controller_transition == Controller::None =>
            {
                if journal.protected_owner_uid()? != root.record().source_uid()
                    || root.record().accepted_input().resource_envelope().is_none()
                {
                    return Err(JournalError::ProtectedBoundary);
                }
                crate::hierarchy::source_genesis::require_location(journal, root.record().source_uid())
                    .and_then(|()| root.native_crossing_clock_v2())
            }
            Self::SourceAnchored(root) if source_transition == Source::Anchor
                && controller_transition == Controller::None =>
            {
                if root.floor().record_bytes().len() != crate::policy_compiler::SOURCE_HIERARCHY_FLOOR_BYTES_V2 {
                    return Err(JournalError::ProtectedBoundary);
                }
                crate::hierarchy::source_genesis::require_location(journal, root.source_uid())
                    .and_then(|()| root.native_crossing_clock_v2())
            }
            Self::ControllerAnchored(root) if source_transition == Source::None
                && matches!(controller_transition, Controller::FloorAck | Controller::Complete) =>
            {
                if root.floor().record_bytes().len() != crate::policy_compiler::SOURCE_HIERARCHY_FLOOR_BYTES_V2
                    || journal.protected_owner_uid()? != root.source_uid()
                {
                    return Err(JournalError::ProtectedBoundary);
                }
                crate::hierarchy::controller_genesis::require_controller(journal, journal.protected_owner_uid()?)
                    .and_then(|()| root.native_crossing_clock_v2())
            }
            _ => return Err(JournalError::ProtectedBoundary),
        };
        original.map_err(|cause| JournalError::GlobalGenesisOriginal(Box::new(cause)))
    }
}

fn nix_offline_provisioning_edge(edge: Option<RootOwnerEdge>) -> bool {
    #[cfg(target_os = "linux")]
    if matches!(edge, Some(RootOwnerEdge::NixOffline | RootOwnerEdge::NixOfflineClosureData)) {
        return true;
    }
    let _ = edge;
    false
}

fn require_no_nix_native_mutation(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::ordinary_mutation::require_no_nix_native_mutation_v1(state, transaction)
        .map_err(crate::journal::JournalError::from)
}

fn require_no_create_storage_mutation(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
) -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::ordinary_mutation::require_no_create_storage_mutation(state, transaction)
        .map_err(JournalError::from)
}

// Append and forecast share these refusals in the same order. The scope is
// Copy selector DATA; Native custody and final crossings stay with each caller.
fn require_common_mutation_boundaries(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    scope: AppendScope,
    create_storage_original: bool,
    #[cfg(target_os = "linux")] root_floor: Option<&crate::policy_compiler::execution_no_apply_root::RootExecutionNoApplyFloorAppendLoanV2<'_, '_, '_>>,
    #[cfg(target_os = "linux")] controller_no_apply: Option<&crate::controller_execution_operation::ControllerExecutionNoApplyAppendLoanV2<'_, '_, '_>>,
    #[cfg(target_os = "linux")] controller_stop_cleanup: Option<&crate::controller_lifecycle_stop::StopCleanupControllerAppendContextV1<'_>>,
    cache_gate: &CacheMutationGateV1<'_>,
) -> Result<(), JournalError> {
    // This closed path selects no native exception. The canonical DATA folds
    // run in exactly the old common order; actual selected branches remain
    // below and keep their genuine original rather than a comparison flag.
    #[cfg(target_os = "linux")]
    let no_native_original = root_floor.is_none()
        && controller_no_apply.is_none()
        && controller_stop_cleanup.is_none();
    #[cfg(not(target_os = "linux"))]
    let no_native_original = true;
    if no_native_original
        && !create_storage_original
        && !matches!(cache_gate, CacheMutationGateV1::StopCleanupSource(_))
        && scope.controller_genesis_transition
            == aos_sandbox_ledger_replay::replay::controller_source_genesis::ControllerSourceGenesisTransition::None
        && scope.successor_issuance_transition.is_none()
        && scope.first_successor.is_none()
        && scope.source_genesis_transition == source_tree_genesis::SourceGenesisTransitionV1::None
        && scope.project_admission_transition == SourceProjectAdmissionTransition::None
        && !scope.allow_host_settlement_admission_append
        && !scope.allow_host_currentness_fence_acquisition
        && !scope.allow_host_fence_acquisition
    {
        return aos_sandbox_ledger_replay::ordinary_mutation::require_common_no_selected_boundaries_v1(
            state, transaction,
        ).map_err(JournalError::from);
    }

    stop_cleanup_source::require_append_scope_v1(state, transaction, cache_gate)?;
    #[cfg(target_os = "linux")]
    match controller_stop_cleanup {
        Some(original) => original.require_prechecked_transaction_v1(transaction)?,
        None => super::execution_no_apply_settlement::require_no_stop_cleanup_controller_mutation_v1(state, transaction)?,
    }
    #[cfg(not(target_os = "linux"))]
    super::execution_no_apply_settlement::require_no_stop_cleanup_controller_mutation_v1(state, transaction)?;
    #[cfg(target_os = "linux")]
    match controller_no_apply {
        Some(original) => original.require_prechecked_transaction_v2(transaction)?,
        None => super::execution_no_apply_settlement::require_no_closed_controller_mutation_v2(state, transaction)?,
    }
    #[cfg(not(target_os = "linux"))]
    super::execution_no_apply_settlement::require_no_closed_controller_mutation_v2(state, transaction)?;
    // Namespace registration and canonical DATA confer no native append port.
    // The distinct paid Root floor issuer must supply its own exact original
    // through this shared engine before this transition can be opened.
    #[cfg(target_os = "linux")]
    match root_floor {
        Some(original) => original.require_prechecked_floor_successor_v2(transaction)?,
        None => require_no_root_execution_no_apply_floor_mutation_v2(transaction)?,
    }
    #[cfg(not(target_os = "linux"))]
    require_no_root_execution_no_apply_floor_mutation_v2(transaction)?;
    if !create_storage_original {
        require_no_create_storage_mutation(state, transaction)?;
    }
    aos_sandbox_ledger_replay::replay::controller_source_genesis::require_no_mutation(
        state,
        transaction,
        scope.controller_genesis_transition,
    ).map_err(crate::journal::JournalError::from)?;
    controller_source_successor_issuance::require_no_mutation(
        state,
        transaction,
        scope
            .first_successor
            .map(|phase| phase.controller_transition_for(transaction))
            .transpose()?
            .flatten()
            .or(scope.successor_issuance_transition),
    )?;
    source_tree_genesis::require_no_mutation(
        state,
        transaction,
        scope
            .first_successor
            .map_or(scope.source_genesis_transition, |phase| {
                phase.source_genesis_transition()
            }),
    )?;
    source_project_admission_challenge::require_no_mutation(
        state,
        transaction,
        scope.project_admission_transition,
    )?;
    host_settlement_admission_gate::require_no_mutation(
        state,
        transaction,
        scope.allow_host_settlement_admission_append,
    )?;
    host_currentness_fence::require_no_mutation(
        state,
        transaction,
        scope.allow_host_currentness_fence_acquisition,
    )?;
    host_execution_fence::require_no_mutation(
        state,
        transaction,
        scope.allow_host_fence_acquisition,
    )?;
    Ok(())
}

fn require_no_root_execution_no_apply_floor_mutation_v2(transaction: &JournalTransaction)
    -> Result<(), JournalError> {
    aos_sandbox_ledger_replay::ordinary_mutation::require_no_root_execution_no_apply_floor_mutation_v2(transaction)
        .map_err(JournalError::from)
}

#[cfg(test)]
mod execution_no_apply_floor_boundary_tests {
    use super::*;

    #[test]
    fn registered_root_floor_data_has_no_generic_append_permission() {
        let transaction = JournalTransaction::new([1; 16], vec![super::super::JournalRecord::put(
            RecordNamespace::RootExecutionNoApplyFloorV2, vec![2; 16], vec![3; 104],
        )]).unwrap();

        assert!(matches!(require_no_root_execution_no_apply_floor_mutation_v2(&transaction),
            Err(JournalError::ProtectedBoundary)));
    }
}

#[cfg(target_os = "linux")]
fn require_q04_journal_transition(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    transition: Option<
        Q04JournalTransitionV1<'_, '_, '_, '_, '_, '_, '_, '_, '_, '_, '_, '_>,
    >,
    terminal: Option<&crate::controller_resource_reservation::Q04TerminalBankAppendV1<'_>>,
    intake: Option<&crate::controller_resource_reservation::CreateIntakeBankAppendV1<'_>>,
    storage_use: Option<&crate::controller_resource_reservation::CreateStorageUseBankAppendV1<'_>>,
    history: Option<&crate::controller_resource_reservation::CreateStorageHistoryAppendLoanV1<'_, '_>>,
    root_open: Option<&crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenAppendLoanV1<'_, '_, '_>>,
    provisioning: Option<&crate::reconciler::provisioning::ProvisioningAppendLoanV1<'_>>,
    source_provisioning: Option<&super::source_provisioning::SourceProvisioningAppendLoanV1<'_>>,
    create_stopped_pre_ack: Option<&super::create_stopped_pre_ack::CreateStoppedControllerPreAckAppendLoanV1<'_>>,
    create_stopped_terminal: Option<&super::create_stopped_terminal::CreateStoppedControllerTerminalAppendLoanV1<'_, '_>>,
    recover: Option<&super::operator_recover_floor::OperatorRecoverAppendLoanV1<'_>>,
    delete_admission: Option<&dyn super::delete_admission::DeleteAdmissionOriginalV3>,
) -> Result<(), JournalError> {
    if delete_admission.is_some() && (transition.is_some() || terminal.is_some()
        || intake.is_some() || storage_use.is_some() || history.is_some() || root_open.is_some()
        || provisioning.is_some() || source_provisioning.is_some()
        || create_stopped_pre_ack.is_some() || create_stopped_terminal.is_some() || recover.is_some()) {
        return Err(JournalError::ProtectedBoundary);
    }
    if recover.is_some() && (transition.is_some() || terminal.is_some()
        || intake.is_some() || storage_use.is_some() || history.is_some() || root_open.is_some()
        || provisioning.is_some() || source_provisioning.is_some()
        || create_stopped_pre_ack.is_some() || create_stopped_terminal.is_some()) {
        return Err(JournalError::ProtectedBoundary);
    }
    if create_stopped_terminal.is_some() && (transition.is_some() || terminal.is_some()
            || intake.is_some() || storage_use.is_some() || history.is_some()
            || root_open.is_some() || provisioning.is_some() || source_provisioning.is_some()
            || create_stopped_pre_ack.is_some())
        || create_stopped_pre_ack.is_some() && (transition.is_some() || terminal.is_some()
            || intake.is_some() || storage_use.is_some() || history.is_some()
            || root_open.is_some() || provisioning.is_some() || source_provisioning.is_some())
        || source_provisioning.is_some() && (transition.is_some() || terminal.is_some()
            || intake.is_some() || storage_use.is_some() || history.is_some()
            || root_open.is_some() || provisioning.is_some())
        || provisioning.is_some() && (transition.is_some() || terminal.is_some()
            || intake.is_some() || storage_use.is_some() || history.is_some() || root_open.is_some())
        || storage_use.is_some() && (transition.is_some() || terminal.is_some() || intake.is_some() || history.is_some() || root_open.is_some())
        || root_open.is_some() && (transition.is_some() || terminal.is_some() || intake.is_some() || history.is_some())
        || transition.is_some() && (terminal.is_some() || intake.is_some() || history.is_some())
        || terminal.is_some() && (intake.is_some() || history.is_some())
        || intake.is_some() && history.is_some()
    {
        return Err(JournalError::ProtectedBoundary);
    }
    match transition {
        Some(Q04JournalTransitionV1::Controller(recipe, _)) => {
            controller_policy_hold::require_q04_transition(state, transaction, recipe)?;
        }
        _ if delete_admission.is_some() =>
            controller_policy_hold::require_q04_delete_admission_successor_v3(
                state, delete_admission.ok_or(JournalError::ProtectedBoundary)?)?,
        _ if recover.is_some() =>
            controller_policy_hold::require_q04_operator_recover_successor(
                state, recover.ok_or(JournalError::ProtectedBoundary)?)?,
        _ if create_stopped_terminal.is_some() =>
            controller_policy_hold::require_q04_create_stopped_terminal_successor(
                state, create_stopped_terminal.ok_or(JournalError::ProtectedBoundary)?)?,
        _ if create_stopped_pre_ack.is_some() =>
            controller_policy_hold::require_q04_create_stopped_pre_ack_successor(
                state, create_stopped_pre_ack.ok_or(JournalError::ProtectedBoundary)?)?,
        _ if storage_use.is_some() => controller_policy_hold::require_q04_create_storage_use_bank_successor(
            state, transaction, storage_use.ok_or(JournalError::ProtectedBoundary)?,
        )?,
        _ => match (terminal, intake) {
            (Some(original), None) => controller_policy_hold::require_q04_terminal_bank_successor(
                state, transaction, original,
            )?,
            (None, Some(original)) => controller_policy_hold::require_q04_create_intake_bank_successor(
                state, transaction, original,
            )?,
            (None, None) => match history {
                Some(original) => controller_policy_hold::require_q04_create_storage_history_successor(state, transaction, original)?,
                None => match provisioning {
                    Some(original) => controller_policy_hold::require_q04_provisioning_successor(state, original)?,
                    None => controller_policy_hold::require_q04_ordinary_boundary(state, transaction)?,
                },
            },
            _ => return Err(JournalError::ProtectedBoundary),
        },
    }
    match transition {
        Some(Q04JournalTransitionV1::Source(recipes, index, ..)) => {
            source_domain_policy_hold::require_q04_transition(state, transaction, recipes, index)?;
        }
        _ => match source_provisioning {
            Some(original) => original.require_retained_source_cut_v1(state)?,
            None => source_domain_policy_hold::require_q04_ordinary_boundary(state, transaction)?,
        },
    }
    match transition {
        Some(Q04JournalTransitionV1::Cache(recipes, index, ..)) => {
            cache_policy_hold::require_q04_transition(state, transaction, recipes, index)?;
        }
        _ => cache_policy_hold::require_q04_ordinary_boundary(state, transaction)?,
    }
    match transition {
        Some(Q04JournalTransitionV1::Root(history, index, _)) => {
            history.require_transition(state, transaction, index)?;
        }
        Some(Q04JournalTransitionV1::RootCapacity(expected)) if expected == transaction => {}
        _ => match root_open {
            Some(original) => original.require_prechecked_root_history_successor_v1(transaction)?,
            None => crate::policy_compiler::create_q04::require_root_q04_ordinary_boundary(state, transaction)?,
        },
    }
    Ok(())
}

fn validate_root_owner_edge(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    edge: RootOwnerEdge,
    limits: JournalLimits,
) -> Result<Option<[u8; 32]>, JournalError> {
    let settling = match edge {
        #[cfg(target_os = "linux")]
        RootOwnerEdge::NixOffline => {
            nix_offline_provisioning::require_native_edge(state, transaction, limits)?;
            Ok(None)
        }
        #[cfg(target_os = "linux")]
        RootOwnerEdge::NixOfflineClosureData => {
            nix_offline_provisioning::require_closure_data_edge(state, transaction, limits)?;
            Ok(None)
        }
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

impl Journal {
    fn validate_consumer_resource_transition(
        &self,
        transaction: &JournalTransaction,
        allow_capacity: bool,
        settling: Option<[u8; 32]>,
    ) -> Result<(), JournalError> {
        #[cfg(target_os = "linux")]
        {
            crate::attachment_effect_owner::validate_consumer_resource_transaction(
                self,
                transaction,
                allow_capacity,
                settling,
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (allow_capacity, settling);
            if transaction
                .records()
                .iter()
                .any(|record| record.namespace() == RecordNamespace::ControllerConsumerReadAttempt)
            {
                return Err(JournalError::ProtectedBoundary);
            }
            let mut touches_our_capacity = false;
            for record in transaction
                .records()
                .iter()
                .filter(|record| record.namespace() == RecordNamespace::GlobalCapacityReservation)
            {
                let stored;
                let capacity = if record.value().is_some() {
                    record
                } else if let Some(value) =
                    self.get(RecordNamespace::GlobalCapacityReservation, record.key())
                {
                    stored = JournalRecord::put(
                        RecordNamespace::GlobalCapacityReservation,
                        record.key().to_vec(),
                        value.to_vec(),
                    );
                    &stored
                } else {
                    continue;
                };
                let matches = capacity_record_has_legacy_purpose(
                    capacity,
                    GlobalCapacityReservationPurposeV1::ControllerConsumerResource,
                )?;
                touches_our_capacity |= matches;
            }
            if touches_our_capacity {
                return Err(JournalError::ProtectedBoundary);
            }
            Ok(())
        }
    }

    /// Appends and synchronously commits one transaction.
    ///
    /// The in-memory view changes only after all frames have been written and
    /// `sync_data` succeeds. An I/O error leaves the handle unusable for safe
    /// retry; callers must drop and reopen it to replay the durable prefix.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] for invalid records, duplicate keys, exceeded
    /// bounds, exhausted sequence space, a retained closed owner hold or Host
    /// Effect fence, or an append/sync failure.
    pub fn commit(
        &mut self,
        transaction: &JournalTransaction,
    ) -> Result<CommitResult, JournalError> {
        self.commit_in_scope(
            transaction,
            AppendScope::default(),
            CacheMutationGateV1::Ordinary,
        )
    }

    pub(super) fn commit_source_project_admission_transition(
        &mut self,
        transaction: &JournalTransaction,
        transition: SourceProjectAdmissionTransition,
    ) -> Result<CommitResult, JournalError> {
        self.commit_in_scope(
            transaction,
            AppendScope {
                project_admission_transition: transition,
                ..AppendScope::default()
            },
            CacheMutationGateV1::Ordinary,
        )
    }

    pub(crate) fn commit_controller_source_genesis_transition(
        &mut self,
        transaction: &JournalTransaction,
        transition: aos_sandbox_ledger_replay::replay::controller_source_genesis::ControllerSourceGenesisTransition,
    ) -> Result<CommitResult, JournalError> {
        self.commit_in_scope(
            transaction,
            AppendScope {
                controller_genesis_transition: transition,
                ..AppendScope::default()
            },
            CacheMutationGateV1::Ordinary,
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn commit_root_source_genesis_initialization_v1(
        &mut self,
        transaction: &JournalTransaction,
    ) -> Result<CommitResult, JournalError> {
        self.commit_in_scope(
            transaction,
            AppendScope {
                root_genesis_transition: RootSourceGenesisTransitionV1::Initialize,
                ..AppendScope::default()
            },
            CacheMutationGateV1::Ordinary,
        )
    }

    /// Uses the original Cache interlock without changing generic mutation scope.
    ///
    /// # Errors
    /// Returns unchanged Journal bounds or retained-gate/append refusal.
    pub(crate) fn commit_with_retained_cache_gate_v1(
        &mut self,
        transaction: &JournalTransaction,
        gate: &mut HeldCacheMutationGateV1,
    ) -> Result<CommitResult, JournalError> {
        self.commit_with_original_cache_gate_v1(transaction, CacheMutationGateV1::Retained(gate))
    }

    /// Appends with the closed original Cache disposition and ordinary bounds.
    ///
    /// # Errors
    /// Returns the same gate, preflight, durability or exact-successor failure.
    pub(crate) fn commit_with_original_cache_gate_v1(
        &mut self,
        transaction: &JournalTransaction,
        gate: CacheMutationGateV1<'_>,
    ) -> Result<CommitResult, JournalError> {
        self.commit_in_scope(transaction, AppendScope::default(), gate)
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn preflight_project_source_genesis_v3(
        &self,
        transactions: &[JournalTransaction],
        transitions: &[source_tree_genesis::SourceGenesisTransitionV1],
        project: aos_sandbox_model::ProjectId,
    ) -> Result<(), JournalError> {
        use source_tree_genesis::SourceGenesisTransitionV1 as Genesis;
        use source_tree_successor::ProjectGenesisNativePhaseV3 as Phase;

        let phases = [Phase::SourceAppend(project), Phase::SourceAck(project)];
        let selected = match transitions {
            [Genesis::Append, Genesis::Anchor] if transactions.len() == 2 => phases.as_slice(),
            [Genesis::Anchor] if transactions.len() == 1 => &phases[1..],
            _ => return Err(JournalError::ProtectedBoundary),
        };
        self.preflight_with_project_genesis(
            PreflightTransactionViewV1::Ordinary(transactions),
            PreflightScope {
                genesis_transitions: Some(transitions),
                ..PreflightScope::default()
            },
            CacheMutationGateV1::Ordinary,
            Some(selected),
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn commit_global_genesis_append_v2(
        &mut self,
        transaction: &JournalTransaction,
        root: &crate::policy_compiler::HeldRootSourceGenesisIntentV1<'_>,
    ) -> Result<CommitResult, JournalError> {
        self.commit_with_native_scope(
            transaction,
            AppendScope {
                source_genesis_transition: source_tree_genesis::SourceGenesisTransitionV1::Append,
                ..AppendScope::default()
            },
            CacheMutationGateV1::Ordinary,
            #[cfg(target_os = "linux")]
            None,
            Some(ProjectNativeTransitionV3::GlobalGenesis(
                GlobalGenesisNativeCutV2::SourcePrepared(root),
            )),
            #[cfg(target_os = "linux")]
            None,
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn commit_global_genesis_ack_v2(
        &mut self,
        transaction: &JournalTransaction,
        root: &crate::policy_compiler::RootSourceGenesisFloorProofV1<'_>,
    ) -> Result<CommitResult, JournalError> {
        self.commit_with_native_scope(
            transaction,
            AppendScope {
                source_genesis_transition: source_tree_genesis::SourceGenesisTransitionV1::Anchor,
                ..AppendScope::default()
            },
            CacheMutationGateV1::Ordinary,
            #[cfg(target_os = "linux")]
            None,
            Some(ProjectNativeTransitionV3::GlobalGenesis(
                GlobalGenesisNativeCutV2::SourceAnchored(root),
            )),
            #[cfg(target_os = "linux")]
            None,
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn commit_controller_global_genesis_v2(
        &mut self,
        transaction: &JournalTransaction,
        transition: aos_sandbox_ledger_replay::replay::controller_source_genesis::ControllerSourceGenesisTransition,
        root: &crate::policy_compiler::RootSourceGenesisFloorProofV1<'_>,
    ) -> Result<CommitResult, JournalError> {
        self.commit_with_native_scope(
            transaction,
            AppendScope {
                controller_genesis_transition: transition,
                ..AppendScope::default()
            },
            CacheMutationGateV1::Ordinary,
            #[cfg(target_os = "linux")]
            None,
            Some(ProjectNativeTransitionV3::GlobalGenesis(
                GlobalGenesisNativeCutV2::ControllerAnchored(root),
            )),
            #[cfg(target_os = "linux")]
            None,
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn commit_project_genesis_append_v3(
        &mut self,
        transaction: &JournalTransaction,
        root: &crate::policy_compiler::HeldRootSourceProjectGenesisIntentV3<'_>,
    ) -> Result<CommitResult, JournalError> {
        use source_tree_successor::{ProjectGenesisNativeCutV3 as Cut, ProjectGenesisNativePhaseV3 as Phase};
        if self.protected_owner_uid()? != root.record().source_uid() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.commit_with_native_scope(
            transaction,
            AppendScope {
                source_genesis_transition: source_tree_genesis::SourceGenesisTransitionV1::Append,
                ..AppendScope::default()
            },
            CacheMutationGateV1::Ordinary,
            #[cfg(target_os = "linux")]
            None,
            Some(ProjectNativeTransitionV3::Genesis(
                Phase::SourceAppend(root.record().project()),
                Cut::SourcePrepared(root),
            )),
            #[cfg(target_os = "linux")]
            None,
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn commit_project_genesis_ack_v3(
        &mut self,
        transaction: &JournalTransaction,
        root: &crate::policy_compiler::RootSourceProjectGenesisFloorProofV3<'_>,
    ) -> Result<CommitResult, JournalError> {
        use source_tree_successor::{ProjectGenesisNativeCutV3 as Cut, ProjectGenesisNativePhaseV3 as Phase};
        if self.protected_owner_uid()? != root.source_uid() {
            return Err(JournalError::ProtectedBoundary);
        }
        self.commit_with_native_scope(
            transaction,
            AppendScope {
                source_genesis_transition: source_tree_genesis::SourceGenesisTransitionV1::Anchor,
                ..AppendScope::default()
            },
            CacheMutationGateV1::Ordinary,
            #[cfg(target_os = "linux")]
            None,
            Some(ProjectNativeTransitionV3::Genesis(
                Phase::SourceAck(root.floor().project()),
                Cut::SourceAnchored(root),
            )),
            #[cfg(target_os = "linux")]
            None,
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn commit_controller_project_genesis_v3(
        &mut self,
        transaction: &JournalTransaction,
        transition: aos_sandbox_ledger_replay::replay::controller_source_genesis::ControllerSourceGenesisTransition,
        root: &crate::policy_compiler::RootSourceProjectGenesisFloorProofV3<'_>,
    ) -> Result<CommitResult, JournalError> {
        use aos_sandbox_ledger_replay::replay::controller_source_genesis::ControllerSourceGenesisTransition as Transition;
        use source_tree_successor::{ProjectGenesisNativeCutV3 as Cut, ProjectGenesisNativePhaseV3 as Phase};
        let phase = match transition {
            Transition::FloorAck => Phase::ControllerFloorAck(root.floor().project()),
            Transition::Complete => Phase::ControllerComplete(root.floor().project()),
            _ => return Err(JournalError::ProtectedBoundary),
        };
        self.commit_with_native_scope(
            transaction,
            AppendScope {
                controller_genesis_transition: transition,
                ..AppendScope::default()
            },
            CacheMutationGateV1::Ordinary,
            #[cfg(target_os = "linux")]
            None,
            Some(ProjectNativeTransitionV3::Genesis(
                phase,
                Cut::SourceAnchored(root),
            )),
            #[cfg(target_os = "linux")]
            None,
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn commit_project_successor_issuance_v3(
        &mut self, transaction: &JournalTransaction,
        transition: controller_source_successor_issuance::Transition,
        completed: &crate::policy_compiler::CompletedRootSourceProjectGenesisFloorV3<'_, '_>,
    ) -> Result<CommitResult, JournalError> {
        self.commit_with_native_scope(
            transaction,
            AppendScope {
                successor_issuance_transition: Some(transition),
                ..AppendScope::default()
            },
            CacheMutationGateV1::Ordinary,
            #[cfg(target_os = "linux")]
            None,
            Some(ProjectNativeTransitionV3::Issuance {
                transition,
                completed,
            }),
            #[cfg(target_os = "linux")]
            None,
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn preflight_root_project_genesis_prepared_v3(
        &self,
        prepared: &PreparedGlobalCapacityReservationV1,
        transaction: &JournalTransaction,
        project: aos_sandbox_model::ProjectId,
    ) -> Result<(), JournalError> {
        crate::policy_compiler::validate_root_source_genesis_capacity_admission_v1(self, transaction, &prepared.request)?;
        if prepared.request.purpose != GlobalCapacityReservationPurposeV1::RootSourceGenesisAnchor
            || transaction.id() != &prepared.admission_transaction_id
            || transaction.records().iter().filter(|record| record.namespace() == RecordNamespace::GlobalCapacityReservation).ne([prepared.record()])
        { return Err(JournalError::AuthorityPreflightMismatch); }
        self.preflight_with_project_genesis(
            PreflightTransactionViewV1::Ordinary(std::slice::from_ref(transaction)),
            PreflightScope {
                allow_capacity_records: true,
                ..PreflightScope::default()
            },
            CacheMutationGateV1::Ordinary,
            Some(&[source_tree_successor::ProjectGenesisNativePhaseV3::RootPrepared(project)]),
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn commit_root_project_genesis_prepared_v3(
        &mut self,
        prepared: PreparedGlobalCapacityReservationV1,
        transaction: &JournalTransaction,
        project: aos_sandbox_model::ProjectId,
        original: &aos_sandbox_model::RawPairedClockSample,
        deadline: std::time::Instant,
    ) -> Result<(CommitResult, GlobalCapacityReservationV1), JournalError> {
        self.preflight_root_project_genesis_prepared_v3(&prepared, transaction, project)?;
        let record_digest = Sha256::digest(prepared.record.value().ok_or(JournalError::InvalidTransaction)?).into();
        let result = self.commit_with_native_scope(
            transaction,
            AppendScope {
                allow_capacity_records: true,
                ..AppendScope::default()
            },
            CacheMutationGateV1::Ordinary,
            #[cfg(target_os = "linux")]
            None,
            Some(ProjectNativeTransitionV3::Genesis(
                source_tree_successor::ProjectGenesisNativePhaseV3::RootPrepared(project),
                source_tree_successor::ProjectGenesisNativeCutV3::RootServer { original, deadline },
            )),
            #[cfg(target_os = "linux")]
            None,
        )?;
        Ok((result, GlobalCapacityReservationV1 {
            request: prepared.request, admission_transaction_id: prepared.admission_transaction_id,
            reservation_id: prepared.reservation_id, record_digest,
        }))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn preflight_root_project_genesis_anchor_v3(
        &self,
        reservation: &GlobalCapacityReservationV1,
        transaction: &JournalTransaction,
        project: aos_sandbox_model::ProjectId,
    ) -> Result<(), JournalError> {
        if reservation.request.purpose != GlobalCapacityReservationPurposeV1::RootSourceGenesisAnchor {
            return Err(JournalError::ProtectedBoundary);
        }
        capacity_reservation::validate_settlement_shape(self, reservation, transaction)?;
        self.preflight_with_project_genesis(
            PreflightTransactionViewV1::Ordinary(std::slice::from_ref(transaction)),
            PreflightScope {
                settling_reservation: Some(reservation.reservation_id),
                allow_capacity_records: true,
                ..PreflightScope::default()
            },
            CacheMutationGateV1::Ordinary,
            Some(&[source_tree_successor::ProjectGenesisNativePhaseV3::RootAnchor(project)]),
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn commit_root_project_genesis_anchor_v3(
        &mut self,
        reservation: GlobalCapacityReservationV1,
        transaction: &JournalTransaction,
        project: aos_sandbox_model::ProjectId,
        original: &aos_sandbox_model::RawPairedClockSample,
        deadline: std::time::Instant,
    ) -> Result<CommitResult, JournalError> {
        self.preflight_root_project_genesis_anchor_v3(&reservation, transaction, project)?;
        self.commit_with_native_scope(
            transaction,
            AppendScope {
                settling_reservation: Some(reservation.reservation_id),
                allow_capacity_records: true,
                ..AppendScope::default()
            },
            CacheMutationGateV1::Ordinary,
            #[cfg(target_os = "linux")]
            None,
            Some(ProjectNativeTransitionV3::Genesis(
                source_tree_successor::ProjectGenesisNativePhaseV3::RootAnchor(project),
                source_tree_successor::ProjectGenesisNativeCutV3::RootServer { original, deadline },
            )),
            #[cfg(target_os = "linux")]
            None,
        )
    }

    /// Appends the retained Global instance under its original Root crossing.
    #[cfg(target_os = "linux")]
    pub(crate) fn commit_root_global_genesis_initialization_v2(
        &mut self,
        transaction: &JournalTransaction,
        original: &crate::policy_compiler::GlobalRootGenesisNativeCutV2<'_>,
    ) -> Result<CommitResult, JournalError> {
        self.preflight_transactions(std::slice::from_ref(transaction))?;
        self.commit_with_native_scope(
            transaction,
            AppendScope {
                root_genesis_transition: RootSourceGenesisTransitionV1::Initialize,
                ..AppendScope::default()
            },
            CacheMutationGateV1::Ordinary,
            #[cfg(target_os = "linux")]
            None,
            Some(ProjectNativeTransitionV3::GlobalRootGenesis(original)),
            #[cfg(target_os = "linux")]
            None,
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn commit_root_global_genesis_prepared_v2(
        &mut self,
        prepared: PreparedGlobalCapacityReservationV1,
        transaction: &JournalTransaction,
        original: &crate::policy_compiler::GlobalRootGenesisNativeCutV2<'_>,
    ) -> Result<(CommitResult, GlobalCapacityReservationV1), JournalError> {
        if prepared.request.purpose != GlobalCapacityReservationPurposeV1::RootSourceGenesisAnchor {
            return Err(JournalError::ProtectedBoundary);
        }
        self.claim_global_capacity_reservation_authority(prepared.request.purpose)?
            .preflight_global_capacity_reservation_v1(&prepared, transaction)?;
        let record_digest = Sha256::digest(prepared.record.value().ok_or(JournalError::InvalidTransaction)?).into();
        let result = self.commit_with_native_scope(
            transaction,
            AppendScope {
                allow_capacity_records: true,
                ..AppendScope::default()
            },
            CacheMutationGateV1::Ordinary,
            #[cfg(target_os = "linux")]
            None,
            Some(ProjectNativeTransitionV3::GlobalRootGenesis(original)),
            #[cfg(target_os = "linux")]
            None,
        )?;
        Ok((result, GlobalCapacityReservationV1 {
            request: prepared.request,
            admission_transaction_id: prepared.admission_transaction_id,
            reservation_id: prepared.reservation_id, record_digest,
        }))
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn commit_root_global_genesis_anchor_v2(
        &mut self,
        reservation: GlobalCapacityReservationV1,
        transaction: &JournalTransaction,
        original: &crate::policy_compiler::GlobalRootGenesisNativeCutV2<'_>,
    ) -> Result<CommitResult, JournalError> {
        if reservation.request.purpose != GlobalCapacityReservationPurposeV1::RootSourceGenesisAnchor {
            return Err(JournalError::ProtectedBoundary);
        }
        self.claim_global_capacity_reservation_authority(reservation.request.purpose)?
            .preflight_reserved_terminal_v1(&reservation, transaction)?;
        self.commit_with_native_scope(
            transaction,
            AppendScope {
                settling_reservation: Some(reservation.reservation_id),
                allow_capacity_records: true,
                ..AppendScope::default()
            },
            CacheMutationGateV1::Ordinary,
            #[cfg(target_os = "linux")]
            None,
            Some(ProjectNativeTransitionV3::GlobalRootGenesis(original)),
            #[cfg(target_os = "linux")]
            None,
        )
    }

    /// Appends only the exact private bank CAS through the ordinary engine.
    #[cfg(target_os = "linux")]
    pub(crate) fn commit_controller_resource_transition_v1(
        &mut self,
        transaction: &JournalTransaction,
        original: &crate::controller_resource_reservation::Transition,
    ) -> Result<CommitResult, JournalError> {
        self.validate_held_protected_names()?;
        self.commit_with_native_scope(
            transaction,
            AppendScope::default(),
            CacheMutationGateV1::Ordinary,
            #[cfg(target_os = "linux")]
            None,
            None,
            #[cfg(target_os = "linux")]
            Some(original),
        )
    }

    /// Appends with the original private selectors and separate Native loans.
    ///
    /// # Errors
    /// Returns the original validation, final-crossing or durability failure.
    pub(super) fn commit_with_native_scope(
        &mut self,
        transaction: &JournalTransaction,
        scope: AppendScope,
        cache_gate: CacheMutationGateV1<'_>,
        #[cfg(target_os = "linux")] q04_transition: Option<
            Q04JournalTransitionV1<'_, '_, '_, '_, '_, '_, '_, '_, '_, '_, '_, '_>,
        >,
        project_genesis: Option<ProjectNativeTransitionV3<'_, '_>>,
        #[cfg(target_os = "linux")] resource_reservation: Option<
            &crate::controller_resource_reservation::Transition,
        >,
    ) -> Result<CommitResult, JournalError> {
        self.commit_with_native_scope_and_storage_clock(
            transaction, scope, cache_gate,
            #[cfg(target_os = "linux")]
            q04_transition,
            project_genesis,
            #[cfg(target_os = "linux")]
            resource_reservation,
            #[cfg(target_os = "linux")]
            None,
            #[cfg(target_os = "linux")]
            None,
        )
    }

    // The Storage restriction is additive. Its only entrypoint selects the
    // ordinary scope; every existing owner guard and final crossing stays here.
    pub(super) fn commit_with_native_scope_and_storage_clock(
        &mut self,
        transaction: &JournalTransaction,
        scope: AppendScope,
        mut cache_gate: CacheMutationGateV1<'_>,
        #[cfg(target_os = "linux")] q04_transition: Option<
            Q04JournalTransitionV1<'_, '_, '_, '_, '_, '_, '_, '_, '_, '_, '_, '_>,
        >,
        project_genesis: Option<ProjectNativeTransitionV3<'_, '_>>,
        #[cfg(target_os = "linux")] resource_reservation: Option<
            &crate::controller_resource_reservation::Transition,
        >,
        #[cfg(target_os = "linux")] mut storage_clock: Option<(
            &aos_sandbox_broker::StoragePrepareNativeClockLoanV1<'_>,
            &mut super::StoragePrepareNativeClockCaptureV1,
        )>,
        #[cfg(target_os = "linux")] mut create_storage: Option<
            super::create_storage_append::CreateStorageAppendOriginalV1<'_, '_, '_, '_, '_, '_, '_, '_, '_, '_, '_, '_, '_>,
        >,
    ) -> Result<CommitResult, JournalError> {
        self.commit_with_native_scope_and_financial_original(
            transaction, scope, cache_gate,
            #[cfg(target_os = "linux")]
            q04_transition,
            project_genesis,
            #[cfg(target_os = "linux")]
            resource_reservation,
            #[cfg(target_os = "linux")]
            storage_clock,
            #[cfg(target_os = "linux")]
            create_storage,
            #[cfg(target_os = "linux")]
            None,
        )
    }

    pub(super) fn commit_with_native_scope_and_financial_original(
        &mut self,
        transaction: &JournalTransaction,
        scope: AppendScope,
        cache_gate: CacheMutationGateV1<'_>,
        #[cfg(target_os = "linux")] q04_transition: Option<
            Q04JournalTransitionV1<'_, '_, '_, '_, '_, '_, '_, '_, '_, '_, '_, '_>,
        >,
        project_genesis: Option<ProjectNativeTransitionV3<'_, '_>>,
        #[cfg(target_os = "linux")] resource_reservation: Option<
            &crate::controller_resource_reservation::Transition,
        >,
        #[cfg(target_os = "linux")] storage_clock: Option<(
            &aos_sandbox_broker::StoragePrepareNativeClockLoanV1<'_>,
            &mut super::StoragePrepareNativeClockCaptureV1,
        )>,
        #[cfg(target_os = "linux")] create_storage: Option<
            super::create_storage_append::CreateStorageAppendOriginalV1<'_, '_, '_, '_, '_, '_, '_, '_, '_, '_, '_, '_, '_>,
        >,
        #[cfg(target_os = "linux")] borrowed_root: Option<
            &aos_sandbox_broker::receiving::RootJournalFinancialBorrowV1<'_>,
        >,
    ) -> Result<CommitResult, JournalError> {
        let mut context = engine::OriginalAppendContextV1::new(self);
        engine::commit(&mut context,
            transaction, scope, cache_gate,
            #[cfg(target_os = "linux")]
            q04_transition,
            project_genesis,
            #[cfg(target_os = "linux")]
            resource_reservation,
            #[cfg(target_os = "linux")]
            storage_clock,
            #[cfg(target_os = "linux")]
            create_storage,
            #[cfg(target_os = "linux")]
            borrowed_root,
        )
    }

    /// Validates that an ordered sequence of future transactions fits all bounds.
    ///
    /// This performs the same structural, transaction-count, materialized-view,
    /// sequence, and append-length checks as [`Self::commit`] against a cloned
    /// view. It does not write or reserve bytes, so its result is advisory and
    /// can be invalidated by an intervening commit. Protected authority owners
    /// should use [`ProtectedJournalAuthority::preflight_transactions`] and
    /// validate its opaque token at the dependent effect boundary.
    ///
    /// # Errors
    ///
    /// Returns [`JournalError`] if the handle is poisoned, metadata cannot be
    /// read, a closed policy owner hold or Host Effect fence is retained, or
    /// any transaction in the ordered sequence would fail a commit bound or
    /// conflict with preceding durable or simulated state.
    pub fn preflight_transactions(
        &self,
        transactions: &[JournalTransaction],
    ) -> Result<(), JournalError> {
        self.preflight_in_scope(
            PreflightTransactionViewV1::Ordinary(transactions),
            PreflightScope::default(),
            CacheMutationGateV1::Ordinary,
        )
    }

    pub(crate) fn preflight_controller_source_genesis_transitions(
        &self,
        transactions: &[JournalTransaction],
        transitions: &[aos_sandbox_ledger_replay::replay::controller_source_genesis::ControllerSourceGenesisTransition],
    ) -> Result<(), JournalError> {
        self.preflight_in_scope(
            PreflightTransactionViewV1::Ordinary(transactions),
            PreflightScope {
                controller_genesis_transitions: Some(transitions),
                ..PreflightScope::default()
            },
            CacheMutationGateV1::Ordinary,
        )
    }

    /// Simulates the same bounds while borrowing the original Cache interlock.
    ///
    /// # Errors
    /// Returns unchanged preflight errors or changed original-gate refusal.
    pub(crate) fn preflight_with_retained_cache_gate_v1(
        &self,
        transactions: &[JournalTransaction],
        gate: &mut HeldCacheMutationGateV1,
    ) -> Result<(), JournalError> {
        self.preflight_with_original_cache_gate_v1(
            transactions,
            CacheMutationGateV1::Retained(gate),
        )
    }

    /// Uses the same eight limits and sequence checks with an original gate.
    ///
    /// # Errors
    /// Returns unchanged simulation errors or original-writer refusal.
    pub(crate) fn preflight_with_original_cache_gate_v1(
        &self,
        transactions: &[JournalTransaction],
        gate: CacheMutationGateV1<'_>,
    ) -> Result<(), JournalError> {
        self.preflight_in_scope(
            PreflightTransactionViewV1::Ordinary(transactions),
            PreflightScope::default(),
            gate,
        )
    }

    fn preflight_with_project_genesis(
        &self,
        transactions: PreflightTransactionViewV1<'_>,
        scope: PreflightScope<'_>,
        mut cache_gate: CacheMutationGateV1<'_>,
        project_genesis: Option<&[source_tree_successor::ProjectGenesisNativePhaseV3]>,
    ) -> Result<(), JournalError> {
        self.preflight_with_source_selection_v1(transactions, scope, cache_gate, project_genesis, None)
    }

    pub(crate) fn preflight_with_source_provisioning_v1(&self,
        transactions: &[JournalTransaction],
        original: &super::source_provisioning::SourceProvisioningAppendLoanV1<'_>,
    ) -> Result<(), JournalError> {
        self.preflight_with_source_selection_v1(PreflightTransactionViewV1::Ordinary(transactions),
            PreflightScope::default(), CacheMutationGateV1::Ordinary, None, Some(original))
    }

    fn preflight_with_source_selection_v1(&self,
        transactions: PreflightTransactionViewV1<'_>, scope: PreflightScope<'_>,
        mut cache_gate: CacheMutationGateV1<'_>,
        project_genesis: Option<&[source_tree_successor::ProjectGenesisNativePhaseV3]>,
        source_provisioning: Option<&super::source_provisioning::SourceProvisioningAppendLoanV1<'_>>,
    ) -> Result<(), JournalError> {
        self.preflight_with_source_selection_engine_v2(transactions, scope, cache_gate,
            project_genesis, source_provisioning, None)
    }

    fn preflight_with_source_selection_engine_v2(&self,
        transactions: PreflightTransactionViewV1<'_>, scope: PreflightScope<'_>,
        mut cache_gate: CacheMutationGateV1<'_>,
        project_genesis: Option<&[source_tree_successor::ProjectGenesisNativePhaseV3]>,
        source_provisioning: Option<&super::source_provisioning::SourceProvisioningAppendLoanV1<'_>>,
        mut retained: Option<&mut ProtectedJournalPreflightOriginalV2>,
    ) -> Result<(), JournalError> {
        let PreflightScope {
            settling_reservation,
            allow_capacity_records,
            allow_policy_hold_transition,
            project_transitions,
            controller_genesis_transitions,
            genesis_transitions,
            root_local_edge,
            successor_issuance_transitions,
            first_successors,
        } = scope;

        self.ensure_healthy()?;
        // Refuse the held family before cloning any prospective map/model.
        // Every branch here is advisory DATA; no Root original enters it.
        for index in 0..transactions.len() {
            if let Some(original) = source_provisioning {
                original.require_transition(self, transactions.transaction(index))?;
            } else {
                require_no_create_storage_mutation(self.native.state(), transactions.transaction(index))?;
            }
        }
        if first_successors.is_some_and(|phases| phases.len() != transactions.len()) {
            return Err(JournalError::ProtectedBoundary);
        }
        if project_genesis.is_some_and(|phases| phases.len() != transactions.len())
            || project_genesis.is_some() && first_successors.is_some()
        {
            return Err(JournalError::ProtectedBoundary);
        }
        #[cfg(target_os = "linux")]
        cache_policy_hold::require_no_exclusive_mutation_v1(self, self.native.state())?;
        if root_local_edge.is_some() && transactions.len() != 1
            && !nix_offline_provisioning_edge(root_local_edge)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        #[cfg(target_os = "linux")]
        if matches!(root_local_edge, Some(RootOwnerEdge::NixOfflineClosureData))
            && transactions.len() > 42
        {
            return Err(JournalError::ProtectedBoundary);
        }
        if project_transitions.is_some_and(|transitions| transitions.len() != transactions.len()) {
            return Err(JournalError::ProtectedBoundary);
        }
        if controller_genesis_transitions
            .is_some_and(|transitions| transitions.len() != transactions.len())
        {
            return Err(JournalError::ProtectedBoundary);
        }
        if genesis_transitions.is_some_and(|transitions| transitions.len() != transactions.len()) {
            return Err(JournalError::ProtectedBoundary);
        }
        if successor_issuance_transitions
            .is_some_and(|transitions| transitions.len() != transactions.len())
        {
            return Err(JournalError::ProtectedBoundary);
        }
        #[cfg(target_os = "linux")]
        if let PreflightTransactionViewV1::CacheQ04ReadOnlyBase { hold, .. } = &transactions {
            self.require_q04_cache_read_only_base_v1(hold)?;
        } else {
            cache_gate.check(self)?;
        }
        #[cfg(not(target_os = "linux"))]
        cache_gate.check(self)?;

        delete_batch::bound_preview_view(self.native.state(), &transactions, self.native.limits())?;
        if let Some(original) = retained.as_deref_mut() {
            original.reserve_transactions_v2(transactions.len())?;
        }
        let mut state = self.native.state().clone();
        let mut idempotency = self.native.idempotency().clone();
        let mut transaction_ids = self.native.transaction_ids().clone();
        let mut materialized_bytes = self.native.materialized_bytes();
        let mut next_sequence = self.native.next_sequence();
        let mut committed_transactions = self.native.committed_transactions();
        let result: Result<(), JournalError> = (|| {
            let mut expected_length = match retained.as_deref_mut() {
                Some(original) => original.metadata_once_v2(self)?,
                None => self.native.metadata()?.len(),
            };

            for index in 0..transactions.len() {
                let transaction = transactions.transaction(index);
                if let Some(original) = retained.as_deref_mut() {
                    original.begin_transaction_v2();
                }
                let mut retained_frames = None;
                let transaction_result: Result<(), JournalError> = (|| {
                    let first_successor = first_successors.map(|phases| phases[index]);
                    let first_successor_settling = if let Some(phases) = project_genesis {
                        source_tree_successor::require_project_genesis_native_owner_v3(self, phases[index])?;
                        source_tree_successor::require_project_genesis_family_v3(&state, transaction, phases[index])?;
                        None
                    } else {
                        source_tree_successor::require_transition(&state, transaction, first_successor)?
                    };
                    let allow_capacity_records = first_successor
                        .map_or(allow_capacity_records, |phase| phase.has_capacity_records());
                    let settling_reservation = first_successor_settling.or(settling_reservation);
                    if let Some(phase) = first_successor {
                        source_tree_successor::require_live_custody(self, &state, transaction, phase)?;
                        capacity_reservation::validate_first_source_successor_capacity_records_v2(self, transaction)?;
                    }
                    #[cfg(target_os = "linux")]
                    cache_policy_hold::require_no_exclusive_mutation_v1(self, &state)?;
                    if !nix_offline_provisioning_edge(root_local_edge) {
                        require_no_nix_native_mutation(&state, transaction)?;
                    }
                    let settling_reservation = if let Some(edge) = root_local_edge {
                        validate_root_owner_edge(&state, transaction, edge, self.native.limits())?
                    } else {
                        if self.source_original_replay.has_dependencies() {
                            return Err(JournalError::ProtectedBoundary);
                        }
                        root_local_recovery::require_fences(&state, transaction)?;
                        root_original_native::require_generic_transaction(&state, transaction)?;
                        root_original_inventory::require_generic_transaction(
                            &state,
                            transaction,
                            self.native.limits(),
                        )?;
                        aos_sandbox_protocol::domain_ledger::capacity_family::family::require_legacy_transaction(&state, transaction)?;
                        settling_reservation
                    };
                    #[cfg(target_os = "linux")]
                    if matches!(root_local_edge, Some(RootOwnerEdge::NixOffline)) {
                        nix_offline_provisioning::require_native_identifier(
                            &state, transaction, next_sequence,
                        )?;
                    }
                    require_common_mutation_boundaries(
                        &state,
                        transaction,
                        AppendScope {
                            controller_genesis_transition: controller_genesis_transitions
                                .map(|transitions| transitions[index])
                                .unwrap_or(
                                    aos_sandbox_ledger_replay::replay::controller_source_genesis::ControllerSourceGenesisTransition::None,
                                ),
                            successor_issuance_transition: successor_issuance_transitions
                                .map(|transitions| transitions[index]),
                            source_genesis_transition: genesis_transitions
                                .map(|transitions| transitions[index])
                                .unwrap_or(source_tree_genesis::SourceGenesisTransitionV1::None),
                            project_admission_transition: project_transitions
                                .map(|transitions| transitions[index])
                                .unwrap_or(SourceProjectAdmissionTransition::None),
                            first_successor,
                            ..AppendScope::default()
                        },
                        source_provisioning.is_some(),
                        #[cfg(target_os = "linux")] None,
                        #[cfg(target_os = "linux")] None,
                        #[cfg(target_os = "linux")] None,
                        &cache_gate,
                    )?;
                    #[cfg(target_os = "linux")]
                    let q04_transition = transactions.q04_transition(index);
                    #[cfg(target_os = "linux")]
                    if q04_transition.is_some()
                        && (allow_capacity_records || allow_policy_hold_transition
                            || settling_reservation.is_some() || root_local_edge.is_some()
                            || project_transitions.is_some() || controller_genesis_transitions.is_some()
                            || genesis_transitions.is_some() || successor_issuance_transitions.is_some()
                            || !matches!(&cache_gate, CacheMutationGateV1::Ordinary))
                    {
                        return Err(JournalError::ProtectedBoundary);
                    }
                    #[cfg(target_os = "linux")]
                    require_q04_journal_transition(&state, transaction, q04_transition, None, None, None, None, None, None, source_provisioning, None, None, None, None)?;
                    if !allow_policy_hold_transition {
                        #[cfg(target_os = "linux")]
                        if !matches!(q04_transition, Some(Q04JournalTransitionV1::Controller(..))) {
                            controller_policy_hold::require_no_mutation(&state, transaction)?;
                        }
                        #[cfg(not(target_os = "linux"))]
                        controller_policy_hold::require_no_mutation(&state, transaction)?;
                        #[cfg(target_os = "linux")]
                        if !matches!(q04_transition, Some(Q04JournalTransitionV1::Source(..))) {
                            match source_provisioning {
                                Some(original) => original.require_retained_source_cut_v1(&state)?,
                                None => source_domain_policy_hold::require_no_mutation(&state, transaction)?,
                            }
                        }
                        #[cfg(not(target_os = "linux"))]
                        source_domain_policy_hold::require_no_mutation(&state, transaction)?;
                    }
                    self.require_mount_git_coverage_source_transition_v1(&state, transaction)?;
                    self.require_storage_git_coverage_transition_v1(&state, transaction)?;
                    self.require_owner_git_coverage_transition_v1(&state, transaction)?;
                    let has_capacity_records = transaction
                        .records()
                        .iter()
                        .any(|record| record.namespace() == RecordNamespace::GlobalCapacityReservation);
                    self.validate_consumer_resource_transition(
                        transaction,
                        allow_capacity_records,
                        settling_reservation,
                    )?;
                    if has_capacity_records != allow_capacity_records {
                        return Err(JournalError::ProtectedBoundary);
                    }
                    match retained.as_deref_mut() {
                        Some(original) => original.validate_transaction_v2(transaction, self.native.limits())?,
                        None => validate_transaction(transaction, self.native.limits())?,
                    }
                    delete_batch::validate(&state, transaction, next_sequence, self.native.limits())?;
                    if !transaction_ids.insert(*transaction.id()) {
                        return Err(JournalError::DuplicateTransaction);
                    }
                    if committed_transactions >= self.native.limits().maximum_transactions {
                        return Err(JournalError::LimitExceeded("committed transaction count"));
                    }
                    validate_idempotency_changes(&idempotency, transaction.records())?;
                    materialized_bytes = validate_materialized_change(
                        &state,
                        materialized_bytes,
                        transaction.records(),
                        self.native.limits(),
                    )?;

                    retained_frames = Some(match retained.as_deref_mut() {
                        Some(original) => original.encode_transaction_v2(transaction, next_sequence)?,
                        None => encode_transaction(transaction, next_sequence)?,
                    });
                    let frames = retained_frames.as_ref().ok_or(JournalError::ProtectedBoundary)?;
                    let frame_count = u64::try_from(frames.len())
                        .map_err(|_| JournalError::LimitExceeded("transaction frame count"))?;
                    root_original_inventory::require_append_sequence_headroom(
                        &state,
                        transaction,
                        next_sequence.checked_add(frame_count).ok_or(JournalError::SequenceExhausted)?,
                    )?;
                    let additional_bytes = frames
                        .iter()
                        .try_fold(0_u64, |total, frame| total.checked_add(frame.len() as u64));
                    expected_length = expected_length
                        .checked_add(additional_bytes.ok_or(JournalError::JournalTooLarge)?)
                        .ok_or(JournalError::JournalTooLarge)?;
                    if expected_length > self.native.limits().maximum_journal_bytes {
                        return Err(JournalError::JournalTooLarge);
                    }


                    validate_reserved_capacity(
                        &state,
                        materialized_bytes,
                        transaction.records(),
                        settling_reservation,
                        expected_length,
                        committed_transactions
                            .checked_add(1)
                            .ok_or(JournalError::LimitExceeded("committed transaction count"))?,
                        self.native.limits(),
                        root_local_edge,
                    )?;
                    if first_successor.is_some() {
                        source_tree_successor::require_sequence_headroom(
                            &root_original_inventory::materialize(&state, transaction),
                            next_sequence.checked_add(frame_count).ok_or(JournalError::SequenceExhausted)?,
                        )?;
                    }

                    for record in transaction.records() {
                        apply_record(&mut state, &mut idempotency, record)?;
                    }
                    next_sequence = next_sequence
                        .checked_add(frame_count)
                        .ok_or(JournalError::SequenceExhausted)?;
                    committed_transactions += 1;
                    Ok(())
                })();
                if let Some(original) = retained.as_deref_mut() {
                    original.retain_frames_v2(retained_frames);
                }
                transaction_result?;
            }
            Ok(())
        })();
        if let Some(original) = retained {
            original.retain_models_v2(preflight_retained::PreflightModelsV2 {
                state, idempotency, transaction_ids, materialized_bytes,
                next_sequence, committed_transactions,
            });
        }
        result
    }
}

#[cfg(target_os = "linux")]
impl Journal {
    // Only the zero-suffix DATA branch can bypass the ordinary reopen-based
    // mutation gate. It compares the actual retained hold, audits the entire
    // native file and enters the same preflight engine; it cannot append.
    pub(crate) fn preflight_q04_cache_read_only_base_v1(
        &self,
        hold: &Journal,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        self.preflight_in_scope(
            PreflightTransactionViewV1::CacheQ04ReadOnlyBase {
                hold,
                transactions: &[],
            },
            PreflightScope::default(),
            CacheMutationGateV1::Ordinary,
        )?;
        Ok(())
    }

    // Only Root's fixed nonissuing owner preflight calls this DATA position.
    // It cannot be selected by actual commit, even for identical bytes.
    pub(crate) fn preflight_root_q04_capacity_v1(
        &self,
        transactions: &[JournalTransaction],
    ) -> Result<(), JournalError> {
        crate::policy_compiler::create_q04::require_root_q04_fixed_writer(self)?;
        self.preflight_in_scope(
            PreflightTransactionViewV1::RootQ04Capacity(transactions),
            PreflightScope::default(),
            CacheMutationGateV1::Ordinary,
        )
    }

    // This returns directly to the actual Root parent, which parks the whole
    // Result before native/name/floor/clock postchecks. No retry classification
    // or postappend failure can consume the original returned outcome here.
    pub(crate) fn commit_root_q04_original_v1(
        &mut self,
        history: &crate::policy_compiler::create_q04::Q04RootAuthorityHistoryV1,
        index: usize,
        original: &crate::policy_compiler::create_q04::RootOriginalInputLoanV1<'_, '_>,
    ) -> Result<CommitResult, crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        use crate::policy_compiler::create_q04::CreateQ04ErrorV1;

        if !history.may_append(index) {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        history.require_fixed_original(self)?;
        self.preflight_in_scope(
            PreflightTransactionViewV1::RootQ04 {
                history,
                first: index,
                end: history.transactions().len(),
            },
            PreflightScope::default(),
            CacheMutationGateV1::Ordinary,
        )?;
        history.require_fixed_original(self)?;
        original.recheck_cut(history.identity())?;
        self.commit_with_native_scope(
            &history.transactions()[index],
            AppendScope::default(),
            CacheMutationGateV1::Ordinary,
            #[cfg(target_os = "linux")]
            Some(Q04JournalTransitionV1::Root(history, index, Some(original))),
            None,
            #[cfg(target_os = "linux")]
            None,
        ).map_err(Into::into)
    }

    /// Advises the complete eight-phase suffix through the same native engine.
    ///
    /// This does not write, hold, reserve capacity, issue Stage or authenticate
    /// predicted future events. The actual caller repeats every owner and
    /// original-cut check before each permitted transition.
    pub(crate) fn preflight_controller_q04_suffix_v1(
        &mut self,
        transitions: &[ControllerQ04TransitionV1<'_>],
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        use crate::policy_compiler::create_q04::CreateQ04ErrorV1;

        if transitions.len() != 8 {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let ledger = transitions[0].ledger();
        for (index, transition) in transitions.iter().enumerate() {
            if !transition.same_original_cut(&transitions[0])
                || transition.phase_number() != u8::try_from(index + 1)
                    .map_err(|_| CreateQ04ErrorV1::Bounds)?
            {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
            transition.require_fixed_owner(self)?;
        }
        ledger.require_original(self)?;
        self.preflight_in_scope(
            PreflightTransactionViewV1::ControllerQ04(transitions),
            PreflightScope::default(),
            CacheMutationGateV1::Ordinary,
        )?;
        ledger.require_original(self)?;
        Ok(())
    }

    /// Appends one exact closed phase without borrowing a generic hold waiver.
    ///
    /// Original admission, native prefix and fixed names are rejoined on both
    /// sides. Any append/readback ambiguity stays in the same owning caller;
    /// this method supplies neither retry nor a final Create/Effect outcome.
    pub(crate) fn commit_controller_q04_phase_v1(
        &mut self,
        transitions: &[ControllerQ04TransitionV1<'_>],
        index: usize,
        root: &crate::policy_compiler::create_q04::OriginalQ04RootCacheLoanV1<'_, '_, '_>,
    ) -> Result<CommitResult, crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        use crate::policy_compiler::create_q04::CreateQ04ErrorV1;

        if transitions.len() != 8 || index >= transitions.len() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        let transition = &transitions[index];
        transition.require_fixed_owner(self)?;
        for (number, prior) in transitions.iter().enumerate() {
            if !prior.same_original_cut(transition)
                || prior.phase_number() != u8::try_from(number + 1)
                    .map_err(|_| CreateQ04ErrorV1::Bounds)?
            {
                return Err(CreateQ04ErrorV1::ChangedCut);
            }
        }
        transition.ledger().require_original(self)?;
        self.require_q04_native_recipe_view_at_original_v1(
            PreflightTransactionViewV1::ControllerQ04(&transitions[..index]),
            Some(transition.ledger().original_next()),
        )?;
        // The first full suffix is advisory, not a reusable funding token.
        // Re-enter the same native engine from this actual committed prefix
        // before every append, including all still-eligible terminal phases.
        self.preflight_in_scope(
            PreflightTransactionViewV1::ControllerQ04(&transitions[index..]),
            PreflightScope::default(),
            CacheMutationGateV1::Ordinary,
        )?;
        transition.ledger().require_original(self)?;
        if !std::ptr::eq(root.identity(), transition.identity()) {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        root.require_controller_transition(transition)?;
        // The caller parks this whole outcome before any fallible readback.
        // In particular, an acknowledged append is not replaced by a later
        // currentness error and its original native position remains owned.
        let resource = transition.resource_transfer().map(|resource| resource.crossing());
        self.commit_with_native_scope(
            transition.transaction(),
            AppendScope::default(),
            CacheMutationGateV1::Ordinary,
            #[cfg(target_os = "linux")]
            Some(Q04JournalTransitionV1::Controller(transition, Some(root))),
            None,
            #[cfg(target_os = "linux")]
            resource.as_ref(),
        ).map_err(Into::into)
    }

    /// Advises all three Source phases without creating a hold or clearance.
    ///
    /// The recipes are comparison DATA. The actual live action must supply
    /// the same retained owners and phase-specific Root/Cache loans; this
    /// method does not construct those proofs or permit a Source append.
    pub(crate) fn preflight_source_q04_suffix_v1(
        &mut self,
        recipes: &SourceQ04TransactionRecipesV1<'_>,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        self.preflight_source_q04_remaining_v1(recipes, 0)
    }

    pub(crate) fn preflight_source_q04_remaining_v1(
        &mut self,
        recipes: &SourceQ04TransactionRecipesV1<'_>,
        first: usize,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        if first >= 3 {
            return Err(crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut);
        }
        recipes.require_fixed_journal(self)?;
        recipes.require_prefix(self.native.state(), first)?;
        self.require_q04_native_recipe_prefix_v1(&recipes.transactions()[..first], recipes.original_next())?;
        self.preflight_in_scope(
            PreflightTransactionViewV1::SourceQ04 {
                recipes,
                first,
                end: 3,
            },
            PreflightScope::default(),
            CacheMutationGateV1::Ordinary,
        )?;
        recipes.require_fixed_journal(self)?;
        recipes.require_prefix(self.native.state(), first)?;
        self.require_q04_native_recipe_prefix_v1(&recipes.transactions()[..first], recipes.original_next())?;
        Ok(())
    }

    /// Advises the complete inert Cache suffix through the same native engine.
    ///
    /// This does not hold Cache, authorize a release or construct clearance.
    pub(crate) fn preflight_cache_q04_suffix_v1(
        &mut self,
        recipes: &CacheQ04TransactionRecipesV1<'_>,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        self.preflight_cache_q04_remaining_v1(recipes, 0)
    }

    pub(crate) fn preflight_cache_q04_remaining_v1(
        &mut self,
        recipes: &CacheQ04TransactionRecipesV1<'_>,
        first: usize,
    ) -> Result<(), crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        if first >= 3 {
            return Err(crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut);
        }
        recipes.require_fixed_journal(self)?;
        recipes.require_prefix(self.native.state(), first)?;
        self.require_q04_native_recipe_prefix_v1(&recipes.transactions()[..first], recipes.original_next())?;
        self.preflight_in_scope(
            PreflightTransactionViewV1::CacheQ04 {
                recipes,
                first,
                end: 3,
            },
            PreflightScope::default(),
            CacheMutationGateV1::Ordinary,
        )?;
        recipes.require_fixed_journal(self)?;
        recipes.require_prefix(self.native.state(), first)?;
        self.require_q04_native_recipe_prefix_v1(&recipes.transactions()[..first], recipes.original_next())?;
        Ok(())
    }

    pub(crate) fn commit_source_q04_original_v1(
        &mut self,
        recipes: &SourceQ04TransactionRecipesV1<'_>,
        index: usize,
        root: &crate::policy_compiler::create_q04::OriginalQ04RootCacheLoanV1<'_, '_, '_>,
        clearance: Option<&crate::cache_residency::OriginalQ04CacheClearanceLoanV1<'_, '_, '_, '_, '_>>,
    ) -> Result<CommitResult, crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        use crate::policy_compiler::create_q04::CreateQ04ErrorV1;

        if !std::ptr::eq(recipes.identity(), root.identity()) || (index == 2) != clearance.is_some() {
            return Err(CreateQ04ErrorV1::ChangedCut);
        }
        root.require_lower_transition(index, recipes.release_authorization())?;
        self.preflight_source_q04_remaining_v1(recipes, index)?;
        if let Some(clearance) = clearance {
            clearance.recheck_at_append(recipes.identity())?;
        }
        // No postappend check can consume this original result. The actual
        // Source owner parks it before full native/name/Root/Cache readback.
        self.commit_with_native_scope(
            &recipes.transactions()[index],
            AppendScope::default(),
            CacheMutationGateV1::Ordinary,
            #[cfg(target_os = "linux")]
            Some(Q04JournalTransitionV1::Source(
                recipes,
                index,
                Some(root),
                clearance,
            )),
            None,
            #[cfg(target_os = "linux")]
            None,
        ).map_err(Into::into)
    }

    pub(crate) fn commit_cache_q04_original_v1(
        &mut self,
        recipes: &CacheQ04TransactionRecipesV1<'_>,
        index: usize,
        root: &crate::policy_compiler::create_q04::OriginalQ04RootCacheLoanV1<'_, '_, '_>,
    ) -> Result<CommitResult, crate::policy_compiler::create_q04::CreateQ04ErrorV1> {
        if !std::ptr::eq(recipes.identity(), root.identity()) {
            return Err(crate::policy_compiler::create_q04::CreateQ04ErrorV1::ChangedCut);
        }
        root.require_lower_transition(index, recipes.release_authorization())?;
        self.preflight_cache_q04_remaining_v1(recipes, index)?;
        self.commit_with_native_scope(
            &recipes.transactions()[index],
            AppendScope::default(),
            CacheMutationGateV1::Ordinary,
            #[cfg(target_os = "linux")]
            Some(Q04JournalTransitionV1::Cache(recipes, index, Some(root))),
            None,
            #[cfg(target_os = "linux")]
            None,
        ).map_err(Into::into)
    }
}


#[cfg(target_os = "linux")]
impl Journal {
    /// Appends a fixed RootOpen or UseAuthorized pair under its same Root original.
    ///
    /// # Errors
    /// Retains the shared semantic, original-currentness and durability refusal.
    pub(crate) fn commit_create_storage_root_history_v1(
        &mut self,
        transaction: &JournalTransaction,
        original: &mut crate::policy_compiler::create_storage_current::root_open::RootCurrentOpenAppendLoanV1<'_, '_, '_>,
    ) -> Result<CommitResult, JournalError> {
        self.commit_with_native_scope_and_storage_clock(transaction, AppendScope::default(),
            CacheMutationGateV1::Ordinary, None, None, None, None,
            Some(super::create_storage_append::CreateStorageAppendOriginalV1::Root(original)))
    }
}

#[cfg(test)]
mod create_storage_generic_boundary_tests {
    use super::*;
    use aos_sandbox_protocol::domain_ledger::create_storage_history::{
        KeyV1, LatestHeadV1, OwnerV1, PhaseV1, RecordCoordinatesV1, RecordEnvelopeV1,
        root_open::RootOpenBodyDataV1,
        transport::OpenQueryV1,
    };
    use crate::journal::ProtectedJournalNamesV1;

    #[test]
    fn canonical_root_open_data_cannot_enter_generic_native_mutation() {
        // These are explicit historical DATA coordinates, not actual native
        // names, a RootR original, a current peer or an append-loan fixture.
        let body = RootOpenBodyDataV1 {
            open: OpenQueryV1 {
                controller_nonce: [1; 16],
                lane: [2; 16],
                seed: [3; 32],
                ready: [4; 32],
            },
            root_nonce: [5; 16],
            boot: [6; 16],
            started: 7,
            cutoff: 8,
            authority_names: ProtectedJournalNamesV1::from_historical_fields((1, 2), (3, 4), (5, 6)),
            policy_names: ProtectedJournalNamesV1::from_historical_fields((1, 2), (7, 8), (9, 10)),
            authority_next: 1,
            policy_next: 1,
            root_profile: [11; 32],
            root_recipient: [12; 16],
            root_producer: [13; 16],
            root_pid: 14,
            controller_pid: 15,
            controller_uid: 16,
            controller_gid: 17,
        };
        let key = KeyV1::new(body.open.lane, OwnerV1::Root, 1).unwrap();
        let phase = PhaseV1::new(OwnerV1::Root, 1).unwrap();
        let latest = KeyV1::new(body.open.lane, OwnerV1::Root, 0).unwrap();
        let mut record = [0; 500];
        let checksum = RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
            key,
            phase,
            predecessor: [0; 32],
            correlation: body.open.seed,
        }, &body.encode().unwrap(), &mut record).unwrap();
        assert!(RecordEnvelopeV1::decode(&record, key, phase).is_ok());
        let transaction = JournalTransaction::new([18; 16], vec![
            JournalRecord::put(RecordNamespace::CreateStorageHistory, key.encode().to_vec(), record.to_vec()),
            JournalRecord::put(RecordNamespace::CreateStorageHistory, latest.encode().to_vec(),
                LatestHeadV1::new(1, checksum).unwrap().encode().to_vec()),
        ]).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("journal");
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let sequence = journal.snapshot_sequence();
        let length = std::fs::metadata(&path).unwrap().len();

        let forecast = journal.preflight_transactions(std::slice::from_ref(&transaction));
        let returned = journal.commit(&transaction);

        assert!(matches!(forecast, Err(JournalError::ProtectedBoundary)));
        assert!(matches!(returned, Err(JournalError::ProtectedBoundary)));
        assert_eq!(journal.snapshot_sequence(), sequence);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), length);
        assert!(journal.records(RecordNamespace::CreateStorageHistory).next().is_none());
    }

    #[test]
    fn canonical_use_authorized_data_cannot_substitute_a_live_root_append_loan() {
        use aos_sandbox_model::{ResourceDimension, ResourceVector};
        use aos_sandbox_protocol::domain_ledger::create_storage_history::{
            association::AcceptedAssociationDataV1,
            use_authorized::{UseAuthorizedBodyDataV1, USE_AUTHORIZED_RECORD_BYTES_V1},
        };

        // Strict canonical DATA still carries no R, accepted flight, typed
        // readonly interval, same writer or purpose-closed native loan.
        let body = UseAuthorizedBodyDataV1 {
            association: AcceptedAssociationDataV1 {
                operation: [1; 16], project: [2; 16], sandbox: [3; 16],
                accepted_request: [4; 32], coissuance_binding: [5; 32],
                seed: [6; 32], controller_nonce: [7; 16], boot: [8; 16],
                started: 10, cutoff: 20,
            },
            root_nonce: [9; 16], root_open: [10; 32], ready: [11; 32],
            inputs_ready: [12; 32], current_proofs: [13; 32],
            source_current: [14; 32], assignment: [15; 32], ownership_lease: [16; 32],
            receiving: ResourceVector::ZERO.with(ResourceDimension::MemoryBytes, 4096),
        };
        let lane = [17; 16];
        let key = KeyV1::new(lane, OwnerV1::Root, 2).unwrap();
        let phase = PhaseV1::new(OwnerV1::Root, 2).unwrap();
        let mut record = [0; USE_AUTHORIZED_RECORD_BYTES_V1];
        let checksum = RecordEnvelopeV1::encode_into(RecordCoordinatesV1 {
            key, phase, predecessor: body.root_open, correlation: body.association.seed,
        }, &body.encode().unwrap(), &mut record).unwrap();
        let transaction = crate::journal::create_storage_history::prepare_history_pair_v1(
            key, phase, &record, &LatestHeadV1::new(2, checksum).unwrap().encode(),
        ).unwrap();
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("journal");
        let (mut journal, _) = Journal::open(&path, JournalLimits::default()).unwrap();
        let sequence = journal.snapshot_sequence();
        let length = std::fs::metadata(&path).unwrap().len();

        let forecast = journal.preflight_transactions(std::slice::from_ref(&transaction));
        let returned = journal.commit(&transaction);

        assert!(matches!(forecast, Err(JournalError::ProtectedBoundary)));
        assert!(matches!(returned, Err(JournalError::ProtectedBoundary)));
        assert_eq!(journal.snapshot_sequence(), sequence);
        assert_eq!(std::fs::metadata(&path).unwrap().len(), length);
        assert!(journal.records(RecordNamespace::CreateStorageHistory).next().is_none());
    }
}

#[cfg(target_os = "linux")]
impl ProtectedJournalAuthority<'_> {
    pub(crate) fn commit_root_credential_receiving_v1(
        &mut self,
        transaction: &JournalTransaction,
        original: &aos_sandbox_broker::receiving::RootJournalFinancialBorrowV1<'_>,
    ) -> Result<CommitResult, JournalError> {
        self.validate_generic_authority_mutation()?;
        self.journal.ensure_protected_authority()?;
        self.validate_transaction_namespace(transaction)?;
        original.require_current_v1().map_err(|_| match original.diagnostic_original_v1() {
            Some(cause) => JournalError::RootFinancial(cause),
            None => JournalError::ProtectedBoundary,
        })?;
        self.journal.commit_with_native_scope_and_financial_original(
            transaction, AppendScope::default(), CacheMutationGateV1::Ordinary,
            None, None, None, None, None, Some(original),
        )
    }
}
