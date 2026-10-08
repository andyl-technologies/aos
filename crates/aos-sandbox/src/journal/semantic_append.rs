//! Semantic transaction append and paired advisory preflight recipes.
//!
//! This group owns the complete ordinary and closed append paths, their
//! preflights, Q04 adapters and append-only guards on the original `Journal`.
//! The final native crossings, retained loans, durable append and subsequent
//! publication form one ordered recipe. Opening, replay, selector DATA and
//! domain authority admission remain in the parent and their existing owners.

use std::collections::BTreeMap;

use aos_sandbox_journal::materialized::RecordMutationRef;
use aos_sandbox_journal::transaction::NativeRecordRef;
use sha2::{Digest, Sha256};

use super::{
    CacheMutationGateV1, CommitResult, FirstSourceSuccessorNativePhaseV2,
    GlobalCapacityReservationPurposeV1, HeldCacheMutationGateV1, Journal, JournalError,
    JournalLimits, JournalRecord, JournalTransaction, PreflightTransactionViewV1,
    PreparedGlobalCapacityReservationV1, ProjectNativeTransitionV3, ProtectedJournalAuthority,
    RecordNamespace, RootOwnerEdge, RootSourceGenesisTransitionV1, SourceProjectAdmissionTransition,
    apply_idempotency_record, apply_record, cache_policy_hold,
    capacity_reservation, controller_policy_hold, controller_source_genesis,
    controller_source_successor_issuance, delete_batch, encode_transaction,
    encoded_transaction_append_bytes, host_currentness_fence, host_execution_fence,
    host_settlement_admission_gate, native_held, root_local_recovery, root_original_inventory,
    root_original_native, source_domain_policy_hold, source_original_native,
    source_project_admission_challenge, source_tree_genesis, source_tree_successor,
    validate_idempotency_changes, validate_materialized_change, validate_reserved_capacity,
    validate_transaction,
};
#[cfg(not(target_os = "linux"))]
use super::capacity_record_has_legacy_purpose;
#[cfg(target_os = "linux")]
use super::{
    CacheQ04TransactionRecipesV1, ControllerQ04TransitionV1, GlobalCapacityReservationV1,
    GlobalGenesisNativeCutV2, Q04JournalTransitionV1, SourceQ04TransactionRecipesV1,
    is_q04_lower_history_record_v1, nix_offline_provisioning,
};

#[cfg(target_os = "linux")]
impl GlobalGenesisNativeCutV2<'_> {
    fn final_crossing(
        &self,
        journal: &Journal,
        source_transition: source_tree_genesis::SourceGenesisTransitionV1,
        controller_transition: controller_source_genesis::ControllerSourceGenesisTransition,
    ) -> Result<(), JournalError> {
        use controller_source_genesis::ControllerSourceGenesisTransition as Controller;
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
    if state.keys().any(|(namespace, _)| *namespace == RecordNamespace::NixOfflineProvisioning)
        || transaction.records().iter().any(|record| {
            record.namespace() == RecordNamespace::NixOfflineProvisioning
        })
    {
        return Err(JournalError::ProtectedBoundary);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn require_q04_journal_transition(
    state: &BTreeMap<(RecordNamespace, Vec<u8>), Vec<u8>>,
    transaction: &JournalTransaction,
    transition: Option<
        Q04JournalTransitionV1<'_, '_, '_, '_, '_, '_, '_, '_, '_, '_, '_, '_>,
    >,
) -> Result<(), JournalError> {
    match transition {
        Some(Q04JournalTransitionV1::Controller(recipe, _)) => {
            controller_policy_hold::require_q04_transition(state, transaction, recipe)?;
        }
        _ => controller_policy_hold::require_q04_ordinary_boundary(state, transaction)?,
    }
    match transition {
        Some(Q04JournalTransitionV1::Source(recipes, index, ..)) => {
            source_domain_policy_hold::require_q04_transition(state, transaction, recipes, index)?;
        }
        _ => source_domain_policy_hold::require_q04_ordinary_boundary(state, transaction)?,
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
        _ => crate::policy_compiler::create_q04::require_root_q04_ordinary_boundary(state, transaction)?,
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
        // The Source route also needs actual replay/challenge witnesses, so its
        // caller uses the Journal-owned branch rather than a state-only check.
        RootOwnerEdge::SourceOriginal => return Err(JournalError::ProtectedBoundary),
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
        self.commit_with_capacity_scope(transaction, None, false, false, false, false, false)
    }

    pub(super) fn commit_with_capacity_scope(
        &mut self,
        transaction: &JournalTransaction,
        settling_reservation: Option<[u8; 32]>,
        allow_capacity_records: bool,
        allow_policy_hold_transition: bool,
        allow_host_fence_acquisition: bool,
        allow_host_currentness_fence_acquisition: bool,
        allow_host_settlement_admission_append: bool,
    ) -> Result<CommitResult, JournalError> {
        self.commit_with_capacity_scope_and_project_admission(
            transaction,
            settling_reservation,
            allow_capacity_records,
            allow_policy_hold_transition,
            allow_host_fence_acquisition,
            allow_host_currentness_fence_acquisition,
            allow_host_settlement_admission_append,
            SourceProjectAdmissionTransition::None,
            controller_source_genesis::ControllerSourceGenesisTransition::None,
            RootSourceGenesisTransitionV1::None,
        )
    }

    pub(super) fn commit_source_project_admission_transition(
        &mut self,
        transaction: &JournalTransaction,
        transition: SourceProjectAdmissionTransition,
    ) -> Result<CommitResult, JournalError> {
        self.commit_with_capacity_scope_and_project_admission(
            transaction,
            None,
            false,
            false,
            false,
            false,
            false,
            transition,
            controller_source_genesis::ControllerSourceGenesisTransition::None,
            RootSourceGenesisTransitionV1::None,
        )
    }

    pub(crate) fn commit_controller_source_genesis_transition(
        &mut self,
        transaction: &JournalTransaction,
        transition: controller_source_genesis::ControllerSourceGenesisTransition,
    ) -> Result<CommitResult, JournalError> {
        self.commit_with_capacity_scope_and_project_admission(
            transaction,
            None,
            false,
            false,
            false,
            false,
            false,
            SourceProjectAdmissionTransition::None,
            transition,
            RootSourceGenesisTransitionV1::None,
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn commit_root_source_genesis_initialization_v1(
        &mut self,
        transaction: &JournalTransaction,
    ) -> Result<CommitResult, JournalError> {
        self.commit_with_capacity_scope_and_project_admission(
            transaction,
            None,
            false,
            false,
            false,
            false,
            false,
            SourceProjectAdmissionTransition::None,
            controller_source_genesis::ControllerSourceGenesisTransition::None,
            RootSourceGenesisTransitionV1::Initialize,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_with_capacity_scope_and_project_admission(
        &mut self,
        transaction: &JournalTransaction,
        settling_reservation: Option<[u8; 32]>,
        allow_capacity_records: bool,
        allow_policy_hold_transition: bool,
        allow_host_fence_acquisition: bool,
        allow_host_currentness_fence_acquisition: bool,
        allow_host_settlement_admission_append: bool,
        project_admission_transition: SourceProjectAdmissionTransition,
        controller_genesis_transition: controller_source_genesis::ControllerSourceGenesisTransition,
        root_genesis_transition: RootSourceGenesisTransitionV1,
    ) -> Result<CommitResult, JournalError> {
        self.commit_with_capacity_scope_and_source_genesis(
            transaction,
            settling_reservation,
            allow_capacity_records,
            allow_policy_hold_transition,
            allow_host_fence_acquisition,
            allow_host_currentness_fence_acquisition,
            allow_host_settlement_admission_append,
            project_admission_transition,
            controller_genesis_transition,
            source_tree_genesis::SourceGenesisTransitionV1::None,
            root_genesis_transition,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn commit_with_capacity_scope_and_source_genesis(
        &mut self,
        transaction: &JournalTransaction,
        settling_reservation: Option<[u8; 32]>,
        allow_capacity_records: bool,
        allow_policy_hold_transition: bool,
        allow_host_fence_acquisition: bool,
        allow_host_currentness_fence_acquisition: bool,
        allow_host_settlement_admission_append: bool,
        project_admission_transition: SourceProjectAdmissionTransition,
        controller_genesis_transition: controller_source_genesis::ControllerSourceGenesisTransition,
        source_genesis_transition: source_tree_genesis::SourceGenesisTransitionV1,
        root_genesis_transition: RootSourceGenesisTransitionV1,
    ) -> Result<CommitResult, JournalError> {
        self.commit_with_cache_gate(
            transaction,
            settling_reservation,
            allow_capacity_records,
            allow_policy_hold_transition,
            allow_host_fence_acquisition,
            allow_host_currentness_fence_acquisition,
            allow_host_settlement_admission_append,
            project_admission_transition,
            controller_genesis_transition,
            source_genesis_transition,
            root_genesis_transition,
            None,
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
        self.commit_with_cache_gate(
            transaction,
            None,
            false,
            false,
            false,
            false,
            false,
            SourceProjectAdmissionTransition::None,
            controller_source_genesis::ControllerSourceGenesisTransition::None,
            source_tree_genesis::SourceGenesisTransitionV1::None,
            RootSourceGenesisTransitionV1::None,
            None,
            gate,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn commit_with_cache_gate(
        &mut self,
        transaction: &JournalTransaction,
        settling_reservation: Option<[u8; 32]>,
        allow_capacity_records: bool,
        allow_policy_hold_transition: bool,
        allow_host_fence_acquisition: bool,
        allow_host_currentness_fence_acquisition: bool,
        allow_host_settlement_admission_append: bool,
        project_admission_transition: SourceProjectAdmissionTransition,
        controller_genesis_transition: controller_source_genesis::ControllerSourceGenesisTransition,
        source_genesis_transition: source_tree_genesis::SourceGenesisTransitionV1,
        root_genesis_transition: RootSourceGenesisTransitionV1,
        root_local_edge: Option<RootOwnerEdge>,
        cache_gate: CacheMutationGateV1<'_>,
    ) -> Result<CommitResult, JournalError> {
        self.commit_with_cache_gate_and_successor_issuance(
            transaction,
            settling_reservation,
            allow_capacity_records,
            allow_policy_hold_transition,
            allow_host_fence_acquisition,
            allow_host_currentness_fence_acquisition,
            allow_host_settlement_admission_append,
            project_admission_transition,
            controller_genesis_transition,
            source_genesis_transition,
            root_genesis_transition,
            root_local_edge,
            cache_gate,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn commit_with_cache_gate_and_successor_issuance(
        &mut self,
        transaction: &JournalTransaction,
        settling_reservation: Option<[u8; 32]>,
        allow_capacity_records: bool,
        allow_policy_hold_transition: bool,
        allow_host_fence_acquisition: bool,
        allow_host_currentness_fence_acquisition: bool,
        allow_host_settlement_admission_append: bool,
        project_admission_transition: SourceProjectAdmissionTransition,
        controller_genesis_transition: controller_source_genesis::ControllerSourceGenesisTransition,
        source_genesis_transition: source_tree_genesis::SourceGenesisTransitionV1,
        root_genesis_transition: RootSourceGenesisTransitionV1,
        root_local_edge: Option<RootOwnerEdge>,
        cache_gate: CacheMutationGateV1<'_>,
        successor_issuance_transition: Option<controller_source_successor_issuance::Transition>,
    ) -> Result<CommitResult, JournalError> {
        self.commit_with_cache_gate_and_q04_transition(
            transaction, settling_reservation, allow_capacity_records,
            allow_policy_hold_transition, allow_host_fence_acquisition,
            allow_host_currentness_fence_acquisition, allow_host_settlement_admission_append,
            project_admission_transition, controller_genesis_transition,
            source_genesis_transition, root_genesis_transition, root_local_edge, cache_gate,
            successor_issuance_transition,
            #[cfg(target_os = "linux")]
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn commit_with_cache_gate_and_q04_transition(
        &mut self,
        transaction: &JournalTransaction,
        settling_reservation: Option<[u8; 32]>,
        allow_capacity_records: bool,
        allow_policy_hold_transition: bool,
        allow_host_fence_acquisition: bool,
        allow_host_currentness_fence_acquisition: bool,
        allow_host_settlement_admission_append: bool,
        project_admission_transition: SourceProjectAdmissionTransition,
        controller_genesis_transition: controller_source_genesis::ControllerSourceGenesisTransition,
        source_genesis_transition: source_tree_genesis::SourceGenesisTransitionV1,
        root_genesis_transition: RootSourceGenesisTransitionV1,
        root_local_edge: Option<RootOwnerEdge>,
        cache_gate: CacheMutationGateV1<'_>,
        successor_issuance_transition: Option<controller_source_successor_issuance::Transition>,
        #[cfg(target_os = "linux")]
        q04_transition: Option<
            Q04JournalTransitionV1<'_, '_, '_, '_, '_, '_, '_, '_, '_, '_, '_, '_>,
        >,
    ) -> Result<CommitResult, JournalError> {
        self.commit_with_first_source_successor_transition_v2(
            transaction, settling_reservation, allow_capacity_records,
            allow_policy_hold_transition, allow_host_fence_acquisition,
            allow_host_currentness_fence_acquisition, allow_host_settlement_admission_append,
            project_admission_transition, controller_genesis_transition,
            source_genesis_transition, root_genesis_transition, root_local_edge, cache_gate,
            successor_issuance_transition,
            #[cfg(target_os = "linux")]
            q04_transition,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn commit_with_first_source_successor_transition_v2(
        &mut self,
        transaction: &JournalTransaction,
        settling_reservation: Option<[u8; 32]>,
        allow_capacity_records: bool,
        allow_policy_hold_transition: bool,
        allow_host_fence_acquisition: bool,
        allow_host_currentness_fence_acquisition: bool,
        allow_host_settlement_admission_append: bool,
        project_admission_transition: SourceProjectAdmissionTransition,
        controller_genesis_transition: controller_source_genesis::ControllerSourceGenesisTransition,
        source_genesis_transition: source_tree_genesis::SourceGenesisTransitionV1,
        root_genesis_transition: RootSourceGenesisTransitionV1,
        root_local_edge: Option<RootOwnerEdge>,
        cache_gate: CacheMutationGateV1<'_>,
        successor_issuance_transition: Option<controller_source_successor_issuance::Transition>,
        #[cfg(target_os = "linux")]
        q04_transition: Option<
            Q04JournalTransitionV1<'_, '_, '_, '_, '_, '_, '_, '_, '_, '_, '_, '_>,
        >,
        first_successor: Option<FirstSourceSuccessorNativePhaseV2>,
    ) -> Result<CommitResult, JournalError> {
        self.commit_with_project_genesis_transition_v3(
            transaction, settling_reservation, allow_capacity_records,
            allow_policy_hold_transition, allow_host_fence_acquisition,
            allow_host_currentness_fence_acquisition, allow_host_settlement_admission_append,
            project_admission_transition, controller_genesis_transition,
            source_genesis_transition, root_genesis_transition, root_local_edge, cache_gate,
            successor_issuance_transition,
            #[cfg(target_os = "linux")]
            q04_transition,
            first_successor, None,
            #[cfg(target_os = "linux")]
            None,
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn preflight_project_source_genesis_v3(
        &self,
        transactions: &[JournalTransaction],
        transitions: &[source_tree_genesis::SourceGenesisTransitionV1],
        project: aos_sandbox_core::ProjectId,
    ) -> Result<(), JournalError> {
        use source_tree_genesis::SourceGenesisTransitionV1 as Genesis;
        use source_tree_successor::ProjectGenesisNativePhaseV3 as Phase;

        let phases = [Phase::SourceAppend(project), Phase::SourceAck(project)];
        let selected = match transitions {
            [Genesis::Append, Genesis::Anchor] if transactions.len() == 2 => phases.as_slice(),
            [Genesis::Anchor] if transactions.len() == 1 => &phases[1..],
            _ => return Err(JournalError::ProtectedBoundary),
        };
        self.preflight_with_project_genesis_v3(
            PreflightTransactionViewV1::Ordinary(transactions), None, false, false,
            None, None, Some(transitions), None, CacheMutationGateV1::Ordinary,
            None, None, Some(selected),
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn commit_global_genesis_append_v2(
        &mut self,
        transaction: &JournalTransaction,
        root: &crate::policy_compiler::HeldRootSourceGenesisIntentV1<'_>,
    ) -> Result<CommitResult, JournalError> {
        self.commit_with_project_genesis_transition_v3(
            transaction, None, false, false, false, false, false,
            SourceProjectAdmissionTransition::None,
            controller_source_genesis::ControllerSourceGenesisTransition::None,
            source_tree_genesis::SourceGenesisTransitionV1::Append,
            RootSourceGenesisTransitionV1::None, None, CacheMutationGateV1::Ordinary,
            None, None, None,
            Some(ProjectNativeTransitionV3::GlobalGenesis(GlobalGenesisNativeCutV2::SourcePrepared(root))),
            None,
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn commit_global_genesis_ack_v2(
        &mut self,
        transaction: &JournalTransaction,
        root: &crate::policy_compiler::RootSourceGenesisFloorProofV1<'_>,
    ) -> Result<CommitResult, JournalError> {
        self.commit_with_project_genesis_transition_v3(
            transaction, None, false, false, false, false, false,
            SourceProjectAdmissionTransition::None,
            controller_source_genesis::ControllerSourceGenesisTransition::None,
            source_tree_genesis::SourceGenesisTransitionV1::Anchor,
            RootSourceGenesisTransitionV1::None, None, CacheMutationGateV1::Ordinary,
            None, None, None,
            Some(ProjectNativeTransitionV3::GlobalGenesis(GlobalGenesisNativeCutV2::SourceAnchored(root))),
            None,
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn commit_controller_global_genesis_v2(
        &mut self,
        transaction: &JournalTransaction,
        transition: controller_source_genesis::ControllerSourceGenesisTransition,
        root: &crate::policy_compiler::RootSourceGenesisFloorProofV1<'_>,
    ) -> Result<CommitResult, JournalError> {
        self.commit_with_project_genesis_transition_v3(
            transaction, None, false, false, false, false, false,
            SourceProjectAdmissionTransition::None, transition,
            source_tree_genesis::SourceGenesisTransitionV1::None,
            RootSourceGenesisTransitionV1::None, None, CacheMutationGateV1::Ordinary,
            None, None, None,
            Some(ProjectNativeTransitionV3::GlobalGenesis(GlobalGenesisNativeCutV2::ControllerAnchored(root))),
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
        self.commit_with_project_genesis_transition_v3(
            transaction, None, false, false, false, false, false,
            SourceProjectAdmissionTransition::None,
            controller_source_genesis::ControllerSourceGenesisTransition::None,
            source_tree_genesis::SourceGenesisTransitionV1::Append,
            RootSourceGenesisTransitionV1::None, None, CacheMutationGateV1::Ordinary,
            None, None, None,
            Some(ProjectNativeTransitionV3::Genesis(Phase::SourceAppend(root.record().project()), Cut::SourcePrepared(root))),
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
        self.commit_with_project_genesis_transition_v3(
            transaction, None, false, false, false, false, false,
            SourceProjectAdmissionTransition::None,
            controller_source_genesis::ControllerSourceGenesisTransition::None,
            source_tree_genesis::SourceGenesisTransitionV1::Anchor,
            RootSourceGenesisTransitionV1::None, None, CacheMutationGateV1::Ordinary,
            None, None, None,
            Some(ProjectNativeTransitionV3::Genesis(Phase::SourceAck(root.floor().project()), Cut::SourceAnchored(root))),
            None,
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn commit_controller_project_genesis_v3(
        &mut self,
        transaction: &JournalTransaction,
        transition: controller_source_genesis::ControllerSourceGenesisTransition,
        root: &crate::policy_compiler::RootSourceProjectGenesisFloorProofV3<'_>,
    ) -> Result<CommitResult, JournalError> {
        use controller_source_genesis::ControllerSourceGenesisTransition as Transition;
        use source_tree_successor::{ProjectGenesisNativeCutV3 as Cut, ProjectGenesisNativePhaseV3 as Phase};
        let phase = match transition {
            Transition::FloorAck => Phase::ControllerFloorAck(root.floor().project()),
            Transition::Complete => Phase::ControllerComplete(root.floor().project()),
            _ => return Err(JournalError::ProtectedBoundary),
        };
        self.commit_with_project_genesis_transition_v3(
            transaction, None, false, false, false, false, false,
            SourceProjectAdmissionTransition::None, transition,
            source_tree_genesis::SourceGenesisTransitionV1::None,
            RootSourceGenesisTransitionV1::None, None, CacheMutationGateV1::Ordinary,
            None, None, None, Some(ProjectNativeTransitionV3::Genesis(phase, Cut::SourceAnchored(root))),
            None,
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn commit_project_successor_issuance_v3(
        &mut self, transaction: &JournalTransaction,
        transition: controller_source_successor_issuance::Transition,
        completed: &crate::policy_compiler::CompletedRootSourceProjectGenesisFloorV3<'_, '_>,
    ) -> Result<CommitResult, JournalError> {
        self.commit_with_project_genesis_transition_v3(
            transaction, None, false, false, false, false, false,
            SourceProjectAdmissionTransition::None,
            controller_source_genesis::ControllerSourceGenesisTransition::None,
            source_tree_genesis::SourceGenesisTransitionV1::None,
            RootSourceGenesisTransitionV1::None, None, CacheMutationGateV1::Ordinary,
            Some(transition), None, None,
            Some(ProjectNativeTransitionV3::Issuance { transition, completed }),
            None,
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn preflight_root_project_genesis_prepared_v3(
        &self,
        prepared: &PreparedGlobalCapacityReservationV1,
        transaction: &JournalTransaction,
        project: aos_sandbox_core::ProjectId,
    ) -> Result<(), JournalError> {
        crate::policy_compiler::validate_root_source_genesis_capacity_admission_v1(self, transaction, &prepared.request)?;
        if prepared.request.purpose != GlobalCapacityReservationPurposeV1::RootSourceGenesisAnchor
            || transaction.id() != &prepared.admission_transaction_id
            || transaction.records().iter().filter(|record| record.namespace() == RecordNamespace::GlobalCapacityReservation).ne([prepared.record()])
        { return Err(JournalError::AuthorityPreflightMismatch); }
        self.preflight_with_project_genesis_v3(
            PreflightTransactionViewV1::Ordinary(std::slice::from_ref(transaction)), None, true, false,
            None, None, None, None, CacheMutationGateV1::Ordinary, None, None,
            Some(&[source_tree_successor::ProjectGenesisNativePhaseV3::RootPrepared(project)]),
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn commit_root_project_genesis_prepared_v3(
        &mut self,
        prepared: PreparedGlobalCapacityReservationV1,
        transaction: &JournalTransaction,
        project: aos_sandbox_core::ProjectId,
        original: &aos_sandbox_core::RawPairedClockSample,
        deadline: std::time::Instant,
    ) -> Result<(CommitResult, GlobalCapacityReservationV1), JournalError> {
        self.preflight_root_project_genesis_prepared_v3(&prepared, transaction, project)?;
        let record_digest = Sha256::digest(prepared.record.value().ok_or(JournalError::InvalidTransaction)?).into();
        let result = self.commit_with_project_genesis_transition_v3(
            transaction, None, true, false, false, false, false,
            SourceProjectAdmissionTransition::None,
            controller_source_genesis::ControllerSourceGenesisTransition::None,
            source_tree_genesis::SourceGenesisTransitionV1::None,
            RootSourceGenesisTransitionV1::None, None, CacheMutationGateV1::Ordinary,
            None, None, None, Some(ProjectNativeTransitionV3::Genesis(source_tree_successor::ProjectGenesisNativePhaseV3::RootPrepared(project),
                source_tree_successor::ProjectGenesisNativeCutV3::RootServer { original, deadline })),
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
        project: aos_sandbox_core::ProjectId,
    ) -> Result<(), JournalError> {
        if reservation.request.purpose != GlobalCapacityReservationPurposeV1::RootSourceGenesisAnchor {
            return Err(JournalError::ProtectedBoundary);
        }
        capacity_reservation::validate_settlement_shape(self, reservation, transaction)?;
        self.preflight_with_project_genesis_v3(
            PreflightTransactionViewV1::Ordinary(std::slice::from_ref(transaction)), Some(reservation.reservation_id), true, false,
            None, None, None, None, CacheMutationGateV1::Ordinary, None, None,
            Some(&[source_tree_successor::ProjectGenesisNativePhaseV3::RootAnchor(project)]),
        )
    }

    #[cfg(target_os = "linux")]
    pub(crate) fn commit_root_project_genesis_anchor_v3(
        &mut self,
        reservation: GlobalCapacityReservationV1,
        transaction: &JournalTransaction,
        project: aos_sandbox_core::ProjectId,
        original: &aos_sandbox_core::RawPairedClockSample,
        deadline: std::time::Instant,
    ) -> Result<CommitResult, JournalError> {
        self.preflight_root_project_genesis_anchor_v3(&reservation, transaction, project)?;
        self.commit_with_project_genesis_transition_v3(
            transaction, Some(reservation.reservation_id), true, false, false, false, false,
            SourceProjectAdmissionTransition::None,
            controller_source_genesis::ControllerSourceGenesisTransition::None,
            source_tree_genesis::SourceGenesisTransitionV1::None,
            RootSourceGenesisTransitionV1::None, None, CacheMutationGateV1::Ordinary,
            None, None, None, Some(ProjectNativeTransitionV3::Genesis(source_tree_successor::ProjectGenesisNativePhaseV3::RootAnchor(project),
                source_tree_successor::ProjectGenesisNativeCutV3::RootServer { original, deadline })),
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
        self.commit_with_project_genesis_transition_v3(
            transaction, None, false, false, false, false, false,
            SourceProjectAdmissionTransition::None,
            controller_source_genesis::ControllerSourceGenesisTransition::None,
            source_tree_genesis::SourceGenesisTransitionV1::None,
            RootSourceGenesisTransitionV1::Initialize, None, CacheMutationGateV1::Ordinary,
            None, None, None, Some(ProjectNativeTransitionV3::GlobalRootGenesis(original)), None,
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
        let result = self.commit_with_project_genesis_transition_v3(
            transaction, None, true, false, false, false, false,
            SourceProjectAdmissionTransition::None,
            controller_source_genesis::ControllerSourceGenesisTransition::None,
            source_tree_genesis::SourceGenesisTransitionV1::None,
            RootSourceGenesisTransitionV1::None, None, CacheMutationGateV1::Ordinary,
            None, None, None, Some(ProjectNativeTransitionV3::GlobalRootGenesis(original)), None,
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
        self.commit_with_project_genesis_transition_v3(
            transaction, Some(reservation.reservation_id), true, false, false, false, false,
            SourceProjectAdmissionTransition::None,
            controller_source_genesis::ControllerSourceGenesisTransition::None,
            source_tree_genesis::SourceGenesisTransitionV1::None,
            RootSourceGenesisTransitionV1::None, None, CacheMutationGateV1::Ordinary,
            None, None, None, Some(ProjectNativeTransitionV3::GlobalRootGenesis(original)), None,
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
        self.commit_with_project_genesis_transition_v3(
            transaction, None, false, false, false, false, false,
            SourceProjectAdmissionTransition::None,
            controller_source_genesis::ControllerSourceGenesisTransition::None,
            source_tree_genesis::SourceGenesisTransitionV1::None,
            RootSourceGenesisTransitionV1::None, None, CacheMutationGateV1::Ordinary,
            None,
            #[cfg(target_os = "linux")]
            None,
            None, None, Some(original),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn commit_with_project_genesis_transition_v3(
        &mut self,
        transaction: &JournalTransaction,
        settling_reservation: Option<[u8; 32]>,
        allow_capacity_records: bool,
        allow_policy_hold_transition: bool,
        allow_host_fence_acquisition: bool,
        allow_host_currentness_fence_acquisition: bool,
        allow_host_settlement_admission_append: bool,
        project_admission_transition: SourceProjectAdmissionTransition,
        controller_genesis_transition: controller_source_genesis::ControllerSourceGenesisTransition,
        source_genesis_transition: source_tree_genesis::SourceGenesisTransitionV1,
        root_genesis_transition: RootSourceGenesisTransitionV1,
        root_local_edge: Option<RootOwnerEdge>,
        mut cache_gate: CacheMutationGateV1<'_>,
        successor_issuance_transition: Option<controller_source_successor_issuance::Transition>,
        #[cfg(target_os = "linux")]
        q04_transition: Option<
            Q04JournalTransitionV1<'_, '_, '_, '_, '_, '_, '_, '_, '_, '_, '_, '_>,
        >,
        first_successor: Option<FirstSourceSuccessorNativePhaseV2>,
        project_genesis: Option<ProjectNativeTransitionV3<'_, '_>>,
        #[cfg(target_os = "linux")]
        resource_reservation: Option<&crate::controller_resource_reservation::Transition>,
    ) -> Result<CommitResult, JournalError> {
        #[cfg(target_os = "linux")]
        if matches!(root_local_edge, Some(RootOwnerEdge::NixOfflineClosureData)) {
            // Synthetic upper-size values are preview DATA, never an effect.
            return Err(JournalError::ProtectedBoundary);
        }
        self.ensure_healthy()?;
        #[cfg(target_os = "linux")]
        crate::controller_resource_reservation::require_transition(
            self.native.state(), transaction, resource_reservation,
        )?;
        #[cfg(not(target_os = "linux"))]
        if transaction.records().iter().any(|record| {
            record.namespace() == RecordNamespace::ControllerResourceReservation
        }) {
            return Err(JournalError::ProtectedBoundary);
        }
        let selected_successor = first_successor.is_some_and(|phase| phase != phase.canonical());
        #[cfg(target_os = "linux")]
        if selected_successor != matches!(&project_genesis, Some(ProjectNativeTransitionV3::FirstSuccessor(_))) {
            return Err(JournalError::ProtectedBoundary);
        }
        #[cfg(not(target_os = "linux"))]
        if selected_successor {
            return Err(JournalError::ProtectedBoundary);
        }
        let first_successor_settling = if let Some(ProjectNativeTransitionV3::Genesis(phase, _)) = &project_genesis {
            if first_successor.is_some() {
                return Err(JournalError::ProtectedBoundary);
            }
            source_tree_successor::require_project_genesis_native_owner_v3(self, *phase)?;
            source_tree_successor::require_project_genesis_family_v3(self.native.state(), transaction, *phase)?;
            None
        } else {
            source_tree_successor::require_transition(self.native.state(), transaction, first_successor)?
        };
        let settling_reservation = first_successor_settling.or(settling_reservation);
        if let Some(phase) = first_successor {
            source_tree_successor::require_live_custody(self, self.native.state(), transaction, phase)?;
            capacity_reservation::validate_first_source_successor_capacity_records_v2(self, transaction)?;
            if allow_capacity_records != phase.has_capacity_records() {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        if !nix_offline_provisioning_edge(root_local_edge) {
            require_no_nix_native_mutation(self.native.state(), transaction)?;
        }
        #[cfg(target_os = "linux")]
        cache_policy_hold::require_no_exclusive_mutation_v1(self, self.native.state())?;
        let settling_reservation = if matches!(root_local_edge, Some(RootOwnerEdge::SourceOriginal)) {
            let (_, comparison) = self.source_original_replay.preview_transaction(
                self.native.state(), transaction, self.native.limits(),
            )?;
            if comparison.before() != self.native.state() {
                return Err(JournalError::StaleAuthoritySnapshot);
            }
            None
        } else if let Some(edge) = root_local_edge {
            validate_root_owner_edge(self.native.state(), transaction, edge, self.native.limits())?
        } else {
            if self.source_original_replay.has_dependencies() {
                return Err(JournalError::ProtectedBoundary);
            }
            root_local_recovery::require_fences(self.native.state(), transaction)?;
            root_original_native::require_generic_transaction(self.native.state(), transaction)?;
            root_original_inventory::require_generic_transaction(
                self.native.state(), transaction, self.native.limits(),
            )?;
            native_held::require_legacy_transaction(self.native.state(), transaction)?;
            settling_reservation
        };
        #[cfg(target_os = "linux")]
        if nix_offline_provisioning_edge(root_local_edge) {
            nix_offline_provisioning::require_native_identifier(
                self.native.state(), transaction, self.native.next_sequence(),
            )?;
        }
        self.validate_consumer_resource_transition(
            transaction,
            allow_capacity_records,
            settling_reservation,
        )?;
        #[cfg(target_os = "linux")]
        crate::policy_compiler::require_root_source_genesis_mutation_v1(
            self,
            transaction,
            root_genesis_transition,
            allow_capacity_records,
            settling_reservation,
        )?;
        controller_source_genesis::require_no_mutation(
            self.native.state(),
            transaction,
            controller_genesis_transition,
        )?;
        controller_source_successor_issuance::require_no_mutation(
            self.native.state(),
            transaction,
            first_successor.map(|phase| phase.controller_transition_for(transaction)).transpose()?.flatten().or(successor_issuance_transition),
        )?;
        source_tree_genesis::require_no_mutation(
            self.native.state(),
            transaction,
            first_successor.map_or(source_genesis_transition, |phase| phase.source_genesis_transition()),
        )?;
        source_project_admission_challenge::require_no_mutation(
            self.native.state(),
            transaction,
            project_admission_transition,
        )?;
        host_settlement_admission_gate::require_no_mutation(
            self.native.state(),
            transaction,
            allow_host_settlement_admission_append,
        )?;
        host_currentness_fence::require_no_mutation(
            self.native.state(),
            transaction,
            allow_host_currentness_fence_acquisition,
        )?;
        host_execution_fence::require_no_mutation(
            self.native.state(),
            transaction,
            allow_host_fence_acquisition,
        )?;
        #[cfg(target_os = "linux")]
        if q04_transition.is_some() {
            if matches!(q04_transition, Some(Q04JournalTransitionV1::RootCapacity(_)))
                || matches!(q04_transition, Some(Q04JournalTransitionV1::Controller(_, None)))
                || matches!(q04_transition, Some(Q04JournalTransitionV1::Root(_, _, None)))
                || matches!(q04_transition, Some(Q04JournalTransitionV1::Source(_, _, None, _)))
                || matches!(q04_transition, Some(Q04JournalTransitionV1::Source(_, 2, _, None)))
                || matches!(q04_transition, Some(Q04JournalTransitionV1::Cache(_, _, None)))
                || allow_capacity_records || allow_policy_hold_transition
                || allow_host_fence_acquisition || allow_host_currentness_fence_acquisition
                || allow_host_settlement_admission_append || settling_reservation.is_some()
                || project_admission_transition != SourceProjectAdmissionTransition::None
                || controller_genesis_transition
                    != controller_source_genesis::ControllerSourceGenesisTransition::None
                || source_genesis_transition != source_tree_genesis::SourceGenesisTransitionV1::None
                || root_genesis_transition != RootSourceGenesisTransitionV1::None
                || root_local_edge.is_some() || successor_issuance_transition.is_some()
                || !matches!(&cache_gate, CacheMutationGateV1::Ordinary)
            {
                return Err(JournalError::ProtectedBoundary);
            }
        }
        #[cfg(target_os = "linux")]
        require_q04_journal_transition(self.native.state(), transaction, q04_transition)?;
        if !allow_policy_hold_transition {
            #[cfg(target_os = "linux")]
            if !matches!(q04_transition, Some(Q04JournalTransitionV1::Controller(..))) {
                controller_policy_hold::require_no_mutation(self.native.state(), transaction)?;
            }
            #[cfg(not(target_os = "linux"))]
            controller_policy_hold::require_no_mutation(self.native.state(), transaction)?;
            #[cfg(target_os = "linux")]
            if !matches!(q04_transition, Some(Q04JournalTransitionV1::Source(..))) {
                source_domain_policy_hold::require_no_mutation(self.native.state(), transaction)?;
            }
            #[cfg(not(target_os = "linux"))]
            source_domain_policy_hold::require_no_mutation(self.native.state(), transaction)?;
        }
        self.require_mount_git_coverage_source_transition_v1(self.native.state(), transaction)?;
        self.require_storage_git_coverage_transition_v1(self.native.state(), transaction)?;
        self.require_owner_git_coverage_transition_v1(self.native.state(), transaction)?;
        validate_transaction(transaction, self.native.limits())?;
        delete_batch::validate(self.native.state(), transaction, self.native.next_sequence(), self.native.limits())?;
        let has_capacity_records = transaction
            .records()
            .iter()
            .any(|record| record.namespace() == RecordNamespace::GlobalCapacityReservation);
        if has_capacity_records != allow_capacity_records {
            return Err(JournalError::ProtectedBoundary);
        }
        if self.native.transaction_ids().contains(transaction.id()) {
            return Err(JournalError::DuplicateTransaction);
        }
        if self.native.committed_transactions() >= self.native.limits().maximum_transactions {
            return Err(JournalError::LimitExceeded("committed transaction count"));
        }
        validate_idempotency_changes(&self.idempotency, transaction.records())?;
        let materialized_bytes = self.native.projected_change(
            transaction.records().iter().map(RecordMutationRef::from),
        )?;
        let frames = self.native.encode_at_head(
            *transaction.id(),
            transaction.records().iter().map(|record| NativeRecordRef {
                namespace_byte: record.namespace() as u8,
                key: record.key(),
                value: record.value(),
            }),
        )?;
        let frame_count = u64::try_from(frames.len())
            .map_err(|_| JournalError::LimitExceeded("transaction frame count"))?;
        let commit_sequence = self.native.next_sequence()
            .checked_add(frame_count - 1)
            .ok_or(JournalError::SequenceExhausted)?;
        let following_sequence = commit_sequence
            .checked_add(1)
            .ok_or(JournalError::SequenceExhausted)?;
        root_original_inventory::require_append_sequence_headroom(
            self.native.state(), transaction, following_sequence,
        )?;
        if matches!(root_local_edge, Some(RootOwnerEdge::SourceOriginal)) {
            let (_, comparison) = self.source_original_replay.preview_transaction(
                self.native.state(), transaction, self.native.limits(),
            )?;
            source_original_native::replay::require_advisory_bounds(
                &comparison,
                self.native.limits(),
                self.native.file().metadata()?.len().checked_add(
                    encoded_transaction_append_bytes(transaction)?,
                ).ok_or(JournalError::JournalTooLarge)?,
                self.native.committed_transactions().checked_add(1)
                    .ok_or(JournalError::LimitExceeded("committed transaction count"))?,
                following_sequence,
            )?;
        }
        let expected_length = self.native.expected_append_length(&frames)?;
        validate_reserved_capacity(
            self.native.state(),
            materialized_bytes,
            transaction.records(),
            settling_reservation,
            expected_length,
            self.native.committed_transactions()
                .checked_add(1)
                .ok_or(JournalError::LimitExceeded("committed transaction count"))?,
            self.native.limits(),
            root_local_edge,
        )?;
        if first_successor.is_some() {
            source_tree_successor::require_sequence_headroom(
                &root_original_inventory::materialize(self.native.state(), transaction),
                following_sequence,
            )?;
        }

        // Retain the hold-journal lock through the durable append. The freeze
        // writer takes Cache journal locks before this lock in the same order.
        let _cache_policy_guard = cache_gate.before_append(self)?;

        #[cfg(target_os = "linux")]
        if let Some(Q04JournalTransitionV1::Root(history, _, Some(original))) = q04_transition {
            // This is the actual borrowed Root flight, checked after native
            // encoding/preflight and immediately before the shared append.
            // The lower synchronous I/O can still straddle the cutoff; its
            // outcome must remain resident and pass an upper postcheck.
            original.recheck_cut(history.identity())
                .map_err(|first| JournalError::Q04RootOriginal(Box::new(first)))?;
        }
        #[cfg(target_os = "linux")]
        match q04_transition {
            Some(Q04JournalTransitionV1::Controller(transition, Some(root))) => {
                if !std::ptr::eq(root.identity(), transition.identity()) {
                    return Err(JournalError::ProtectedBoundary);
                }
                root.require_controller_transition(transition)
                    .map_err(|first| JournalError::Q04RootOriginal(Box::new(first)))?;
            }
            Some(Q04JournalTransitionV1::Source(recipes, index, Some(root), clearance)) => {
                root.require_lower_transition(index, recipes.release_authorization())
                    .map_err(|first| JournalError::Q04RootOriginal(Box::new(first)))?;
                if let Some(clearance) = clearance {
                    clearance.recheck_at_append(recipes.identity())
                        .map_err(|first| JournalError::Q04RootOriginal(Box::new(first)))?;
                }
            }
            Some(Q04JournalTransitionV1::Cache(recipes, index, Some(root))) => {
                root.require_lower_transition(index, recipes.release_authorization())
                    .map_err(|first| JournalError::Q04RootOriginal(Box::new(first)))?;
            }
            _ => {}
        }

        if let Some(phase) = first_successor {
            source_tree_successor::require_live_custody(self, self.native.state(), transaction, phase)?;
        }

        if let Some(ProjectNativeTransitionV3::Genesis(phase, original)) = &project_genesis {
            source_tree_successor::require_project_genesis_native_owner_v3(self, *phase)?;
            #[cfg(target_os = "linux")]
            {
                let admission_expiry = if matches!(phase, source_tree_successor::ProjectGenesisNativePhaseV3::RootPrepared(_)) {
                    Some(crate::policy_compiler::RootSourceGenesisAuthorityV1::require_project_genesis_current_deployment_v3(self)
                        .map_err(|error| JournalError::ProjectGenesisOriginal(Box::new(error)))?)
                } else { None };
                original.final_crossing(admission_expiry)
                    .map_err(|cause| JournalError::ProjectGenesisOriginal(Box::new(cause)))?;
            }
            #[cfg(not(target_os = "linux"))]
            {
                let _ = original;
                return Err(JournalError::ProtectedBoundary);
            }
        }

        #[cfg(target_os = "linux")]
        if let Some(ProjectNativeTransitionV3::Issuance { transition, completed }) = &project_genesis {
            let project = match transition {
                controller_source_successor_issuance::Transition::ProjectSave(project)
                | controller_source_successor_issuance::Transition::ProjectDelivered(project) => *project,
                _ => return Err(JournalError::ProtectedBoundary),
            };
            if successor_issuance_transition != Some(*transition) || completed.floor().project() != project
                || first_successor.is_some()
            { return Err(JournalError::ProtectedBoundary); }
            crate::hierarchy::controller_genesis::require_controller(self, self.protected_owner_uid()?)
                .map_err(|cause| JournalError::ProjectGenesisOriginal(Box::new(cause)))?;
            controller_source_successor_issuance::require_no_mutation(self.native.state(), transaction, Some(*transition))?;
            completed.recheck().map_err(|cause| JournalError::ProjectGenesisOriginal(Box::new(cause)))?;
            completed.signing_boundary_clock().map_err(|cause| JournalError::ProjectGenesisOriginal(Box::new(cause)))?;
        }

        #[cfg(target_os = "linux")]
        if let Some(ProjectNativeTransitionV3::FirstSuccessor(original)) = &project_genesis {
            let phase = first_successor.ok_or(JournalError::ProtectedBoundary)?;
            original.final_crossing(self, transaction, phase)
                .map_err(|cause| JournalError::ProjectGenesisOriginal(Box::new(cause)))?;
        }

        #[cfg(target_os = "linux")]
        if let Some(original) = resource_reservation {
            original.final_crossing()?;
        }

        #[cfg(target_os = "linux")]
        if let Some(ProjectNativeTransitionV3::GlobalGenesis(original)) = &project_genesis {
            original.final_crossing(self, source_genesis_transition, controller_genesis_transition)?;
        }

        #[cfg(target_os = "linux")]
        if let Some(ProjectNativeTransitionV3::GlobalRootGenesis(original)) = &project_genesis {
            if source_genesis_transition != source_tree_genesis::SourceGenesisTransitionV1::None
                || controller_genesis_transition != controller_source_genesis::ControllerSourceGenesisTransition::None
                || first_successor.is_some() || resource_reservation.is_some()
            { return Err(JournalError::ProtectedBoundary); }
            original.final_crossing(
                self, root_genesis_transition == RootSourceGenesisTransitionV1::Initialize,
                allow_capacity_records, settling_reservation.is_some(),
            )?;
        }

        let durable_bytes = self.native.append_exact(&frames, expected_length)?;

        for record in transaction.records() {
            self.native.apply_mutation(RecordMutationRef::from(record));
            apply_idempotency_record(&mut self.idempotency, record)?;
        }
        self.native.publish_append(
            materialized_bytes, following_sequence, *transaction.id(),
            transaction.records().iter().map(JournalRecord::namespace),
        );
        #[cfg(target_os = "linux")]
        {
            self.q04_lower_history_present |= transaction.records().iter()
                .any(is_q04_lower_history_record_v1);
        }

        if let Err(error) =
            cache_gate.own_successor(self, transaction, following_sequence, durable_bytes)
        {
            self.native.poison();
            return Err(error);
        }

        Ok(CommitResult {
            commit_sequence,
            durable_bytes,
        })
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
        self.preflight_transactions_with_capacity_scope(transactions, None, false, false)
    }

    pub(super) fn preflight_transactions_with_capacity_scope(
        &self,
        transactions: &[JournalTransaction],
        settling_reservation: Option<[u8; 32]>,
        allow_capacity_records: bool,
        allow_policy_hold_transition: bool,
    ) -> Result<(), JournalError> {
        self.preflight_transactions_with_capacity_scope_and_project_admission(
            transactions,
            settling_reservation,
            allow_capacity_records,
            allow_policy_hold_transition,
            None,
            None,
        )
    }

    pub(crate) fn preflight_controller_source_genesis_transitions(
        &self,
        transactions: &[JournalTransaction],
        transitions: &[controller_source_genesis::ControllerSourceGenesisTransition],
    ) -> Result<(), JournalError> {
        self.preflight_transactions_with_capacity_scope_and_project_admission(
            transactions,
            None,
            false,
            false,
            None,
            Some(transitions),
        )
    }

    pub(super) fn preflight_transactions_with_capacity_scope_and_project_admission(
        &self,
        transactions: &[JournalTransaction],
        settling_reservation: Option<[u8; 32]>,
        allow_capacity_records: bool,
        allow_policy_hold_transition: bool,
        project_transitions: Option<&[SourceProjectAdmissionTransition]>,
        controller_genesis_transitions: Option<
            &[controller_source_genesis::ControllerSourceGenesisTransition],
        >,
    ) -> Result<(), JournalError> {
        self.preflight_transactions_with_capacity_scope_and_source_genesis(
            transactions,
            settling_reservation,
            allow_capacity_records,
            allow_policy_hold_transition,
            project_transitions,
            controller_genesis_transitions,
            None,
        )
    }

    pub(super) fn preflight_transactions_with_capacity_scope_and_source_genesis(
        &self,
        transactions: &[JournalTransaction],
        settling_reservation: Option<[u8; 32]>,
        allow_capacity_records: bool,
        allow_policy_hold_transition: bool,
        project_transitions: Option<&[SourceProjectAdmissionTransition]>,
        controller_genesis_transitions: Option<
            &[controller_source_genesis::ControllerSourceGenesisTransition],
        >,
        genesis_transitions: Option<&[source_tree_genesis::SourceGenesisTransitionV1]>,
    ) -> Result<(), JournalError> {
        self.preflight_with_cache_gate(
            transactions,
            settling_reservation,
            allow_capacity_records,
            allow_policy_hold_transition,
            project_transitions,
            controller_genesis_transitions,
            genesis_transitions,
            None,
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
        self.preflight_with_cache_gate(
            transactions,
            None,
            false,
            false,
            None,
            None,
            None,
            None,
            gate,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn preflight_with_cache_gate(
        &self,
        transactions: &[JournalTransaction],
        settling_reservation: Option<[u8; 32]>,
        allow_capacity_records: bool,
        allow_policy_hold_transition: bool,
        project_transitions: Option<&[SourceProjectAdmissionTransition]>,
        controller_genesis_transitions: Option<
            &[controller_source_genesis::ControllerSourceGenesisTransition],
        >,
        genesis_transitions: Option<&[source_tree_genesis::SourceGenesisTransitionV1]>,
        root_local_edge: Option<RootOwnerEdge>,
        cache_gate: CacheMutationGateV1<'_>,
    ) -> Result<(), JournalError> {
        self.preflight_with_cache_gate_and_successor_issuance(
            transactions,
            settling_reservation,
            allow_capacity_records,
            allow_policy_hold_transition,
            project_transitions,
            controller_genesis_transitions,
            genesis_transitions,
            root_local_edge,
            cache_gate,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn preflight_with_cache_gate_and_successor_issuance(
        &self,
        transactions: &[JournalTransaction],
        settling_reservation: Option<[u8; 32]>,
        allow_capacity_records: bool,
        allow_policy_hold_transition: bool,
        project_transitions: Option<&[SourceProjectAdmissionTransition]>,
        controller_genesis_transitions: Option<
            &[controller_source_genesis::ControllerSourceGenesisTransition],
        >,
        genesis_transitions: Option<&[source_tree_genesis::SourceGenesisTransitionV1]>,
        root_local_edge: Option<RootOwnerEdge>,
        cache_gate: CacheMutationGateV1<'_>,
        successor_issuance_transitions: Option<&[controller_source_successor_issuance::Transition]>,
    ) -> Result<(), JournalError> {
        self.preflight_with_q04_transaction_view(
            PreflightTransactionViewV1::Ordinary(transactions), settling_reservation,
            allow_capacity_records, allow_policy_hold_transition, project_transitions,
            controller_genesis_transitions, genesis_transitions, root_local_edge,
            cache_gate, successor_issuance_transitions,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn preflight_with_q04_transaction_view(
        &self,
        transactions: PreflightTransactionViewV1<'_>,
        settling_reservation: Option<[u8; 32]>,
        allow_capacity_records: bool,
        allow_policy_hold_transition: bool,
        project_transitions: Option<&[SourceProjectAdmissionTransition]>,
        controller_genesis_transitions: Option<
            &[controller_source_genesis::ControllerSourceGenesisTransition],
        >,
        genesis_transitions: Option<&[source_tree_genesis::SourceGenesisTransitionV1]>,
        root_local_edge: Option<RootOwnerEdge>,
        cache_gate: CacheMutationGateV1<'_>,
        successor_issuance_transitions: Option<&[controller_source_successor_issuance::Transition]>,
    ) -> Result<(), JournalError> {
        self.preflight_with_first_source_successor_v2(
            transactions, settling_reservation, allow_capacity_records,
            allow_policy_hold_transition, project_transitions, controller_genesis_transitions,
            genesis_transitions, root_local_edge, cache_gate, successor_issuance_transitions, None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn preflight_with_first_source_successor_v2(
        &self,
        transactions: PreflightTransactionViewV1<'_>,
        settling_reservation: Option<[u8; 32]>,
        allow_capacity_records: bool,
        allow_policy_hold_transition: bool,
        project_transitions: Option<&[SourceProjectAdmissionTransition]>,
        controller_genesis_transitions: Option<&[controller_source_genesis::ControllerSourceGenesisTransition]>,
        genesis_transitions: Option<&[source_tree_genesis::SourceGenesisTransitionV1]>,
        root_local_edge: Option<RootOwnerEdge>,
        cache_gate: CacheMutationGateV1<'_>,
        successor_issuance_transitions: Option<&[controller_source_successor_issuance::Transition]>,
        first_successors: Option<&[FirstSourceSuccessorNativePhaseV2]>,
    ) -> Result<(), JournalError> {
        self.preflight_with_project_genesis_v3(
            transactions, settling_reservation, allow_capacity_records,
            allow_policy_hold_transition, project_transitions, controller_genesis_transitions,
            genesis_transitions, root_local_edge, cache_gate, successor_issuance_transitions,
            first_successors, None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn preflight_with_project_genesis_v3(
        &self,
        transactions: PreflightTransactionViewV1<'_>,
        settling_reservation: Option<[u8; 32]>,
        allow_capacity_records: bool,
        allow_policy_hold_transition: bool,
        project_transitions: Option<&[SourceProjectAdmissionTransition]>,
        controller_genesis_transitions: Option<
            &[controller_source_genesis::ControllerSourceGenesisTransition],
        >,
        genesis_transitions: Option<&[source_tree_genesis::SourceGenesisTransitionV1]>,
        root_local_edge: Option<RootOwnerEdge>,
        mut cache_gate: CacheMutationGateV1<'_>,
        successor_issuance_transitions: Option<&[controller_source_successor_issuance::Transition]>,
        first_successors: Option<&[FirstSourceSuccessorNativePhaseV2]>,
        project_genesis: Option<&[source_tree_successor::ProjectGenesisNativePhaseV3]>,
    ) -> Result<(), JournalError> {
        self.ensure_healthy()?;
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
        let mut state = self.native.state().clone();
        let mut idempotency = self.idempotency.clone();
        let mut transaction_ids = self.native.transaction_ids().clone();
        let mut materialized_bytes = self.native.materialized_bytes();
        let mut next_sequence = self.native.next_sequence();
        let mut committed_transactions = self.native.committed_transactions();
        let mut expected_length = self.native.file().metadata()?.len();

        for index in 0..transactions.len() {
            let transaction = transactions.transaction(index);
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
            let settling_reservation = if matches!(root_local_edge, Some(RootOwnerEdge::SourceOriginal)) {
                self.source_original_replay.preview_transaction(
                    &state, transaction, self.native.limits(),
                )?;
                None
            } else if let Some(edge) = root_local_edge {
                validate_root_owner_edge(&state, transaction, edge, self.native.limits())?
            } else {
                if self.source_original_replay.has_dependencies() {
                    return Err(JournalError::ProtectedBoundary);
                }
                root_local_recovery::require_fences(&state, transaction)?;
                root_original_native::require_generic_transaction(&state, transaction)?;
                root_original_inventory::require_generic_transaction(
                    &state, transaction, self.native.limits(),
                )?;
                native_held::require_legacy_transaction(&state, transaction)?;
                settling_reservation
            };
            #[cfg(target_os = "linux")]
            if matches!(root_local_edge, Some(RootOwnerEdge::NixOffline)) {
                nix_offline_provisioning::require_native_identifier(
                    &state, transaction, next_sequence,
                )?;
            }
            controller_source_genesis::require_no_mutation(
                &state,
                transaction,
                controller_genesis_transitions
                    .map(|transitions| transitions[index])
                    .unwrap_or(controller_source_genesis::ControllerSourceGenesisTransition::None),
            )?;
            controller_source_successor_issuance::require_no_mutation(
                &state,
                transaction,
                first_successor.map(|phase| phase.controller_transition_for(transaction)).transpose()?.flatten()
                    .or_else(|| successor_issuance_transitions.map(|transitions| transitions[index])),
            )?;
            source_tree_genesis::require_no_mutation(
                &state,
                transaction,
                first_successor.map(|phase| phase.source_genesis_transition()).or_else(|| genesis_transitions
                    .map(|transitions| transitions[index])
                ).unwrap_or(source_tree_genesis::SourceGenesisTransitionV1::None),
            )?;
            source_project_admission_challenge::require_no_mutation(
                &state,
                transaction,
                project_transitions
                    .map(|transitions| transitions[index])
                    .unwrap_or(SourceProjectAdmissionTransition::None),
            )?;
            host_settlement_admission_gate::require_no_mutation(&state, transaction, false)?;
            host_currentness_fence::require_no_mutation(&state, transaction, false)?;
            host_execution_fence::require_no_mutation(&state, transaction, false)?;
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
            require_q04_journal_transition(&state, transaction, q04_transition)?;
            if !allow_policy_hold_transition {
                #[cfg(target_os = "linux")]
                if !matches!(q04_transition, Some(Q04JournalTransitionV1::Controller(..))) {
                    controller_policy_hold::require_no_mutation(&state, transaction)?;
                }
                #[cfg(not(target_os = "linux"))]
                controller_policy_hold::require_no_mutation(&state, transaction)?;
                #[cfg(target_os = "linux")]
                if !matches!(q04_transition, Some(Q04JournalTransitionV1::Source(..))) {
                    source_domain_policy_hold::require_no_mutation(&state, transaction)?;
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
            validate_transaction(transaction, self.native.limits())?;
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

            let frames = encode_transaction(transaction, next_sequence)?;
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

            if matches!(root_local_edge, Some(RootOwnerEdge::SourceOriginal)) {
                let (_, comparison) = self.source_original_replay.preview_transaction(
                    &state, transaction, self.native.limits(),
                )?;
                source_original_native::replay::require_advisory_bounds(
                    &comparison,
                    self.native.limits(),
                    expected_length,
                    committed_transactions.checked_add(1)
                        .ok_or(JournalError::LimitExceeded("committed transaction count"))?,
                    next_sequence.checked_add(frame_count).ok_or(JournalError::SequenceExhausted)?,
                )?;
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
        }
        Ok(())
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
        self.preflight_with_q04_transaction_view(
            PreflightTransactionViewV1::CacheQ04ReadOnlyBase { hold, transactions: &[] },
            None, false, false, None, None, None, None, CacheMutationGateV1::Ordinary, None,
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
        self.preflight_with_q04_transaction_view(
            PreflightTransactionViewV1::RootQ04Capacity(transactions),
            None, false, false, None, None, None, None, CacheMutationGateV1::Ordinary, None,
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
        self.preflight_with_q04_transaction_view(
            PreflightTransactionViewV1::RootQ04 {
                history, first: index, end: history.transactions().len(),
            },
            None, false, false, None, None, None, None, CacheMutationGateV1::Ordinary, None,
        )?;
        history.require_fixed_original(self)?;
        original.recheck_cut(history.identity())?;
        self.commit_with_cache_gate_and_q04_transition(
            &history.transactions()[index], None, false, false, false, false, false,
            SourceProjectAdmissionTransition::None,
            controller_source_genesis::ControllerSourceGenesisTransition::None,
            source_tree_genesis::SourceGenesisTransitionV1::None,
            RootSourceGenesisTransitionV1::None, None, CacheMutationGateV1::Ordinary,
            None, Some(Q04JournalTransitionV1::Root(history, index, Some(original))),
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
        self.preflight_with_q04_transaction_view(
            PreflightTransactionViewV1::ControllerQ04(transitions),
            None, false, false, None, None, None, None,
            CacheMutationGateV1::Ordinary, None,
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
        self.preflight_with_q04_transaction_view(
            PreflightTransactionViewV1::ControllerQ04(&transitions[index..]),
            None, false, false, None, None, None, None,
            CacheMutationGateV1::Ordinary, None,
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
        self.commit_with_project_genesis_transition_v3(
            transition.transaction(), None, false, false, false, false, false,
            SourceProjectAdmissionTransition::None,
            controller_source_genesis::ControllerSourceGenesisTransition::None,
            source_tree_genesis::SourceGenesisTransitionV1::None,
            RootSourceGenesisTransitionV1::None, None, CacheMutationGateV1::Ordinary,
            None, Some(Q04JournalTransitionV1::Controller(transition, Some(root))),
            None, None, resource.as_ref(),
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
        self.preflight_with_q04_transaction_view(
            PreflightTransactionViewV1::SourceQ04 { recipes, first, end: 3 },
            None, false, false, None, None, None, None,
            CacheMutationGateV1::Ordinary, None,
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
        self.preflight_with_q04_transaction_view(
            PreflightTransactionViewV1::CacheQ04 { recipes, first, end: 3 },
            None, false, false, None, None, None, None,
            CacheMutationGateV1::Ordinary, None,
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
        self.commit_with_cache_gate_and_q04_transition(
            &recipes.transactions()[index], None, false, false, false, false, false,
            SourceProjectAdmissionTransition::None,
            controller_source_genesis::ControllerSourceGenesisTransition::None,
            source_tree_genesis::SourceGenesisTransitionV1::None,
            RootSourceGenesisTransitionV1::None, None, CacheMutationGateV1::Ordinary,
            None, Some(Q04JournalTransitionV1::Source(recipes, index, Some(root), clearance)),
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
        self.commit_with_cache_gate_and_q04_transition(
            &recipes.transactions()[index], None, false, false, false, false, false,
            SourceProjectAdmissionTransition::None,
            controller_source_genesis::ControllerSourceGenesisTransition::None,
            source_tree_genesis::SourceGenesisTransitionV1::None,
            RootSourceGenesisTransitionV1::None, None, CacheMutationGateV1::Ordinary,
            None, Some(Q04JournalTransitionV1::Cache(recipes, index, Some(root))),
        ).map_err(Into::into)
    }
}
