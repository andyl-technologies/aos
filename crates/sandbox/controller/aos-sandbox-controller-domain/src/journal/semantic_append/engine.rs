//! Runs the sole semantic append schedule through closed native contexts.
//!
//! Ordinary callers retain their original Journal and typed final crossings.
//! Delete borrows the same cached semantic fields separately from its actual
//! exclusive Source scope. Neither context constructs another Journal.

use super::*;
use aos_sandbox_broker::canonical_journal::coordinator::CanonicalWriterReadViewV1;
use super::super::native_backing::{JournalNativeBackingV1, Selection};
use super::super::native_append::JournalAppendStageV1;

pub(super) type Read<'a> = CanonicalWriterReadViewV1<'a, Selection>;
pub(super) type SourceReplay = super::super::source_history::replay::SourceOriginalReplayCacheV5;

// This trait is private. Its two actual implementations cannot be supplied by
// a caller, decoded record or callback. Typed non-Delete crossings still need
// the original whole Journal, never an identity or historical view substitute.
pub(super) trait AppendContextV1<'transaction> {
    fn read(&self) -> Read<'_>;

    fn journal(&self) -> Result<&Journal, JournalError>;

    #[cfg(target_os = "linux")]
    fn first_successor_crossing(&mut self,
        original: &source_tree_successor::FirstSuccessorNativeCutV3<'_, '_>,
        transaction: &JournalTransaction, phase: FirstSourceSuccessorNativePhaseV2,
    ) -> Result<(), JournalError>;

    fn source_replay(&self) -> &SourceReplay;

    fn ensure_healthy(&self) -> Result<(), JournalError>;

    fn require_consumer_transition(&self, transaction: &JournalTransaction, capacity: bool, settling: Option<[u8; 32]>) -> Result<(), JournalError>;

    #[cfg(target_os = "linux")]
    fn require_root_genesis_transition(&self, transaction: &JournalTransaction) -> Result<(), JournalError>;

    fn require_source_policy_transition(&self, transaction: &JournalTransaction) -> Result<(), JournalError>;

    fn require_mount_transition(&self, transaction: &JournalTransaction) -> Result<(), JournalError>;

    #[cfg(target_os = "linux")]
    fn begin(&mut self, transaction: &JournalTransaction, root: Option<&aos_sandbox_broker::receiving::RootJournalFinancialBorrowV1<'_>>) -> Result<(), JournalError>;

    fn prepare(&mut self, transaction: &'transaction JournalTransaction) -> Result<(), JournalError>;

    fn projected_materialized_bytes(&self) -> Option<usize>;

    fn coordinates(&mut self) -> Result<(u64, u64), JournalError>;

    fn expected_length(&mut self) -> Result<u64, JournalError>;

    fn before_cache_append(&self, gate: &mut CacheMutationGateV1<'_>) -> Result<Option<Journal>, JournalError>;

    fn append(&mut self) -> Result<u64, JournalError>;

    fn apply_next_record(&mut self) -> Result<bool, JournalError>;

    fn publish(&mut self) -> Result<(), JournalError>;

    #[cfg(target_os = "linux")]
    fn mark_q04(&mut self, transaction: &JournalTransaction);

    fn own_cache_successor(&mut self, gate: &mut CacheMutationGateV1<'_>, transaction: &JournalTransaction, sequence: u64, bytes: u64) -> Result<(), JournalError>;

    fn poison(&mut self);

    fn is_ordinary(&self) -> bool;

    fn finish_ordinary(&mut self) -> Result<(), JournalError>;

    #[cfg(target_os = "linux")]
    fn finish_selected(&mut self, primary: Result<CommitResult, JournalError>) -> Result<CommitResult, JournalError>;

    fn drop_stage(&mut self);
}

// Counts the actual additional call/return representations introduced by
// this shared adapter. The old stage/model/native terms remain independently
// priced; no Option/scalar is treated as a namespace metadata entry.
pub(in crate::journal) fn receiving_frame_bytes_v1() -> Option<usize> {
    let common = std::mem::size_of::<(
        AppendScope, CacheMutationGateV1<'_>, Option<ProjectNativeTransitionV3<'_, '_>>,
        Result<CommitResult, JournalError>, Option<Journal>,
    )>().checked_mul(3)?;

    #[cfg(target_os = "linux")]
    let selected = std::mem::size_of::<(
        Option<Q04JournalTransitionV1<'_, '_, '_, '_, '_, '_, '_, '_, '_, '_>>,
        Option<&crate::controller_resource_reservation::Transition>,
        Option<(&aos_sandbox_broker::StoragePrepareNativeClockLoanV1<'_>, &mut super::super::StoragePrepareNativeClockCaptureV1)>,
        Option<super::super::create_storage_append::CreateStorageAppendOriginalV1<'_, '_, '_, '_, '_, '_, '_, '_, '_, '_>>,
        Option<&aos_sandbox_broker::receiving::RootJournalFinancialBorrowV1<'_>>,
    )>().checked_mul(3)?;

    #[cfg(not(target_os = "linux"))]
    let selected = 0;
    common.checked_add(selected)
}

pub(in crate::journal) struct OriginalAppendContextV1<'journal, 'transaction> {
    journal: &'journal mut Journal,
    stage: Option<JournalAppendStageV1<'transaction>>,
}

impl<'journal, 'transaction> OriginalAppendContextV1<'journal, 'transaction> {
    pub(in crate::journal) fn receiving_construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<Self>().checked_mul(3)?
            .checked_add(receiving_frame_bytes_v1()?)
    }

    /// Prices the ordinary context with the actual shared stage's return lanes.
    ///
    /// The three context slots already contain the two stage headers and one
    /// optional stage slot counted by the shared recipe. Replace those exact
    /// embedded lanes once, retaining the upper enum/reference controls and
    /// adding the shared Result and diagnostic carriers. Selected owners keep
    /// their original context recipe. Returns `None` on checked overflow.
    pub(in crate::journal) fn ordinary_receiving_construction_bytes_v1() -> Option<usize> {
        use aos_sandbox_broker::canonical_journal::CanonicalOrdinaryAppendStageV1 as Stage;

        let embedded = std::mem::size_of::<Stage<'transaction>>().checked_mul(2)?
            .checked_add(std::mem::size_of::<Option<Stage<'transaction>>>())?;
        Self::receiving_construction_bytes_v1()?
            .checked_sub(embedded)?
            .checked_add(Stage::receiving_construction_bytes_v1()?)
    }

    pub(super) fn new(journal: &'journal mut Journal) -> Self {
        Self { journal, stage: None }
    }
}

impl<'transaction> AppendContextV1<'transaction> for OriginalAppendContextV1<'_, 'transaction> {
    fn read(&self) -> Read<'_> {
        self.journal.native.read_view()
    }

    fn journal(&self) -> Result<&Journal, JournalError> {
        Ok(self.journal)
    }

    #[cfg(target_os = "linux")]
    fn first_successor_crossing(&mut self,
        original: &source_tree_successor::FirstSuccessorNativeCutV3<'_, '_>,
        transaction: &JournalTransaction, phase: FirstSourceSuccessorNativePhaseV2,
    ) -> Result<(), JournalError> {
        original.final_crossing(self.journal, transaction, phase)
            .map_err(|cause| JournalError::ProjectGenesisOriginal(Box::new(cause)))
    }

    fn source_replay(&self) -> &SourceReplay {
        &self.journal.source_original_replay
    }

    fn ensure_healthy(&self) -> Result<(), JournalError> {
        self.journal.ensure_healthy()
    }

    fn require_consumer_transition(&self, transaction: &JournalTransaction, capacity: bool, settling: Option<[u8; 32]>) -> Result<(), JournalError> {
        self.journal.validate_consumer_resource_transition(transaction, capacity, settling)
    }

    #[cfg(target_os = "linux")]
    fn require_root_genesis_transition(&self, transaction: &JournalTransaction) -> Result<(), JournalError> {
        aos_sandbox_ledger_replay::replay::root_genesis_capacity::require_no_mutation_v1(transaction)
            .map_err(JournalError::from)
    }

    fn require_source_policy_transition(&self, transaction: &JournalTransaction) -> Result<(), JournalError> {
        source_domain_policy_hold::require_no_mutation(self.read().state(), transaction)
    }

    fn require_mount_transition(&self, transaction: &JournalTransaction) -> Result<(), JournalError> {
        self.journal.require_mount_git_coverage_source_transition_v1(self.read().state(), transaction)
    }

    #[cfg(target_os = "linux")]
    fn begin(&mut self, transaction: &JournalTransaction, root: Option<&aos_sandbox_broker::receiving::RootJournalFinancialBorrowV1<'_>>) -> Result<(), JournalError> {
        self.journal.begin_native_append_interval_v1(transaction, root)
    }

    fn prepare(&mut self, transaction: &'transaction JournalTransaction) -> Result<(), JournalError> {
        #[cfg(target_os = "linux")]
        self.journal.observe_captured_append_before_v1()?;
        self.stage = Some(self.journal.native.prepare_append(transaction)?);
        Ok(())
    }

    fn projected_materialized_bytes(&self) -> Option<usize> {
        self.stage.as_ref()?.projected_materialized_bytes()
    }

    fn coordinates(&mut self) -> Result<(u64, u64), JournalError> {
        self.journal.native.append_coordinates(self.stage.as_mut().ok_or(JournalError::ProtectedBoundary)?)
    }


    fn expected_length(&mut self) -> Result<u64, JournalError> {
        self.journal.native.expected_append_length(self.stage.as_mut().ok_or(JournalError::ProtectedBoundary)?)
    }

    fn before_cache_append(&self, gate: &mut CacheMutationGateV1<'_>) -> Result<Option<Journal>, JournalError> {
        gate.before_append(self.journal)
    }

    fn append(&mut self) -> Result<u64, JournalError> {
        self.journal.native.append_prepared(self.stage.as_mut().ok_or(JournalError::ProtectedBoundary)?)
    }

    fn apply_next_record(&mut self) -> Result<bool, JournalError> {
        self.journal.native.apply_next_record(self.stage.as_mut().ok_or(JournalError::ProtectedBoundary)?)
    }

    fn publish(&mut self) -> Result<(), JournalError> {
        self.journal.native.publish_append(self.stage.as_mut().ok_or(JournalError::ProtectedBoundary)?).map(|_| ())
    }

    #[cfg(target_os = "linux")]
    fn mark_q04(&mut self, transaction: &JournalTransaction) {
        self.journal.q04_lower_history_present |= transaction.records().iter().any(is_q04_lower_history_record_v1);
    }

    fn own_cache_successor(&mut self, gate: &mut CacheMutationGateV1<'_>, transaction: &JournalTransaction, sequence: u64, bytes: u64) -> Result<(), JournalError> {
        gate.own_successor(self.journal, transaction, sequence, bytes)
    }

    fn poison(&mut self) {
        self.journal.native.poison();
    }

    fn is_ordinary(&self) -> bool {
        match &self.journal.native {
            JournalNativeBackingV1::Ordinary(ordinary) => {
                #[cfg(target_os = "linux")] { ordinary.captured_append.is_none() }
                #[cfg(not(target_os = "linux"))] { true }
            }
            #[cfg(target_os = "linux")]
            _ => false,
        }
    }

    fn finish_ordinary(&mut self) -> Result<(), JournalError> {
        self.journal.native.finish_append_after_posts(self.stage.as_mut().ok_or(JournalError::ProtectedBoundary)?)
    }

    #[cfg(target_os = "linux")]
    fn finish_selected(&mut self, primary: Result<CommitResult, JournalError>) -> Result<CommitResult, JournalError> {
        self.journal.finish_native_append_interval_v1(primary, self.stage.take())
    }

    fn drop_stage(&mut self) {
        drop(self.stage.take());
    }

}

pub(super) fn commit<'transaction, C: AppendContextV1<'transaction>>(
    context: &mut C,
    transaction: &'transaction JournalTransaction,
    scope: AppendScope,
    mut cache_gate: CacheMutationGateV1<'_>,
    #[cfg(target_os = "linux")] q04_transition: Option<
        Q04JournalTransitionV1<'_, '_, '_, '_, '_, '_, '_, '_, '_, '_>,
    >,
    project_genesis: Option<ProjectNativeTransitionV3<'_, '_>>,
    #[cfg(target_os = "linux")] resource_reservation: Option<
        &crate::controller_resource_reservation::Transition,
    >,
    #[cfg(target_os = "linux")] mut storage_clock: Option<(
        &aos_sandbox_broker::StoragePrepareNativeClockLoanV1<'_>,
        &mut super::super::StoragePrepareNativeClockCaptureV1,
    )>,
    #[cfg(target_os = "linux")] mut create_storage: Option<
        super::super::create_storage_append::CreateStorageAppendOriginalV1<'_, '_, '_, '_, '_, '_, '_, '_, '_, '_>,
    >,
    #[cfg(target_os = "linux")] borrowed_root: Option<
        &aos_sandbox_broker::receiving::RootJournalFinancialBorrowV1<'_>,
    >,
) -> Result<CommitResult, JournalError> {
    let AppendScope {
        settling_reservation,
        allow_capacity_records,
        allow_policy_hold_transition,
        allow_host_fence_acquisition,
        allow_host_currentness_fence_acquisition,
        allow_host_settlement_admission_append,
        project_admission_transition,
        controller_genesis_transition,
        source_genesis_transition,
        root_local_edge,
        successor_issuance_transition,
        first_successor,
    } = scope;

    #[cfg(target_os = "linux")]
    if matches!(root_local_edge, Some(RootOwnerEdge::NixOfflineClosureData)) {
        // Synthetic upper-size values are preview DATA, never an effect.
        return Err(JournalError::ProtectedBoundary);
    }
    context.ensure_healthy()?;

    #[cfg(target_os = "linux")]
    if create_storage.is_none() {
        require_no_create_storage_mutation(context.read().state(), transaction)?;
    }

    #[cfg(not(target_os = "linux"))]
    require_no_create_storage_mutation(context.read().state(), transaction)?;

    #[cfg(target_os = "linux")]
    crate::controller_resource_reservation::require_transition(
        context.read().state(), transaction, resource_reservation,
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
        source_tree_successor::require_project_genesis_native_owner_v3(context.journal()?, *phase)?;
        source_tree_successor::require_project_genesis_family_v3(context.read().state(), transaction, *phase)?;
        None
    } else {
        source_tree_successor::require_transition(context.read().state(), transaction, first_successor)?
    };
    let settling_reservation = first_successor_settling.or(settling_reservation);
    if let Some(phase) = first_successor {
        source_tree_successor::require_live_custody(context.journal()?, context.read().state(), transaction, phase)?;
        capacity_reservation::validate_first_source_successor_capacity_records_v2(context.journal()?, transaction)?;
        if allow_capacity_records != phase.has_capacity_records() {
            return Err(JournalError::ProtectedBoundary);
        }
    }
    if !nix_offline_provisioning_edge(root_local_edge) {
        require_no_nix_native_mutation(context.read().state(), transaction)?;
    }

    #[cfg(target_os = "linux")]
    cache_policy_hold::require_no_exclusive_mutation_read_v1(context.read(), context.read().state())?;
    let settling_reservation = if let Some(edge) = root_local_edge {
        validate_root_owner_edge(context.read().state(), transaction, edge, context.read().limits())?
    } else {
        if context.source_replay().has_dependencies() {
            return Err(JournalError::ProtectedBoundary);
        }
        root_local_recovery::require_fences(context.read().state(), transaction)?;
        root_original_native::require_generic_transaction(context.read().state(), transaction)?;
        root_original_inventory::require_generic_transaction(
            context.read().state(),
            transaction,
            context.read().limits(),
        )?;
        aos_sandbox_protocol::domain_ledger::capacity_family::family::require_legacy_transaction(context.read().state(), transaction)?;
        settling_reservation
    };

    #[cfg(target_os = "linux")]
    if nix_offline_provisioning_edge(root_local_edge) {
        nix_offline_provisioning::require_native_identifier(
            context.read().state(), transaction, context.read().next_sequence(),
        )?;
    }
    context.require_consumer_transition(
        transaction,
        allow_capacity_records,
        settling_reservation,
    )?;

    #[cfg(target_os = "linux")]
    context.require_root_genesis_transition(transaction)?;

    #[cfg(target_os = "linux")]
    let create_storage_original = create_storage.is_some();

    #[cfg(not(target_os = "linux"))]
    let create_storage_original = false;

    #[cfg(target_os = "linux")]
    if let Some(original) = create_storage.as_mut() {
        if q04_transition.is_some() || project_genesis.is_some() || resource_reservation.is_some()
            || storage_clock.is_some() || settling_reservation.is_some()
            || allow_capacity_records || allow_policy_hold_transition || allow_host_fence_acquisition
            || allow_host_currentness_fence_acquisition || allow_host_settlement_admission_append
            || project_admission_transition != SourceProjectAdmissionTransition::None
            || controller_genesis_transition != aos_sandbox_ledger_replay::replay::controller_source_genesis::ControllerSourceGenesisTransition::None
            || source_genesis_transition != source_tree_genesis::SourceGenesisTransitionV1::None
            || root_local_edge.is_some() || successor_issuance_transition.is_some() || first_successor.is_some()
            || !matches!(&cache_gate, CacheMutationGateV1::Ordinary)
        {
            return Err(JournalError::ProtectedBoundary);
        }
        original.require_transition(context.journal()?, transaction)?;
    }
    require_common_mutation_boundaries(context.read().state(), transaction, scope, create_storage_original,
        #[cfg(target_os = "linux")] create_storage.as_ref().and_then(|original| original.execution_no_apply_floor_successor()),
        #[cfg(target_os = "linux")] create_storage.as_ref().and_then(|original| original.execution_no_apply_controller_successor()),
        #[cfg(target_os = "linux")] create_storage.as_ref()
            .and_then(|original| original.provisioning_successor())
            .and_then(|original| original.stop_cleanup_controller_original_v1()),
        &cache_gate)?;

    #[cfg(target_os = "linux")]
    if q04_transition.is_some() {
        if matches!(q04_transition, Some(Q04JournalTransitionV1::Controller(_, None)))
            || matches!(q04_transition, Some(Q04JournalTransitionV1::Source(_, _, None, _)))
            || matches!(q04_transition, Some(Q04JournalTransitionV1::Source(_, 2, _, None)))
            || allow_capacity_records || allow_policy_hold_transition
            || allow_host_fence_acquisition || allow_host_currentness_fence_acquisition
            || allow_host_settlement_admission_append || settling_reservation.is_some()
            || project_admission_transition != SourceProjectAdmissionTransition::None
            || controller_genesis_transition
                != aos_sandbox_ledger_replay::replay::controller_source_genesis::ControllerSourceGenesisTransition::None
            || source_genesis_transition != source_tree_genesis::SourceGenesisTransitionV1::None
            || root_local_edge.is_some() || successor_issuance_transition.is_some()
            || !matches!(&cache_gate, CacheMutationGateV1::Ordinary)
        {
            return Err(JournalError::ProtectedBoundary);
        }
    }

    #[cfg(target_os = "linux")]
    let terminal = resource_reservation.and_then(|original| original.q04_terminal());

    #[cfg(target_os = "linux")]
    let intake = resource_reservation.and_then(|original| original.create_intake());

    #[cfg(target_os = "linux")]
    let storage_use = resource_reservation.and_then(|original| original.create_storage_use());

    #[cfg(target_os = "linux")]
    if let Some(original) = terminal {
        original.require_native_position(context.journal()?)?;
    }

    #[cfg(target_os = "linux")]
    if let Some(original) = intake {
        original.require_native_position(context.journal()?)?;
    }

    #[cfg(target_os = "linux")]
    if let Some(original) = storage_use { original.require_native_position(context.journal()?)?; }
    #[cfg(target_os = "linux")]
    let history_successor = create_storage.as_ref().and_then(|original| original.controller_history_successor());

    #[cfg(target_os = "linux")]
    let root_open_successor = create_storage.as_ref().and_then(|original| original.root_open_history_successor());

    #[cfg(target_os = "linux")]
    let recover = create_storage.as_ref().and_then(|original| original.operator_recover_successor());

    #[cfg(target_os = "linux")]
    let provisioning = create_storage.as_ref().and_then(|original| original.provisioning_successor());

    #[cfg(target_os = "linux")]
    let create_stopped_terminal = create_storage.as_ref()
        .and_then(|original| original.create_stopped_terminal_successor());

    #[cfg(target_os = "linux")]
    let create_stopped_pre_ack = create_storage.as_ref()
        .and_then(|original| original.create_stopped_pre_ack_successor());

    #[cfg(target_os = "linux")]
    let source_provisioning = create_storage.as_ref()
        .and_then(|original| original.source_provisioning_successor());

    #[cfg(target_os = "linux")]
    let delete_admission = create_storage.as_ref().and_then(|original| original.delete_admission_successor());

    #[cfg(target_os = "linux")]
    require_q04_journal_transition(context.read().state(), transaction, q04_transition,
        terminal, intake, storage_use, history_successor, root_open_successor, provisioning,
        source_provisioning, create_stopped_pre_ack, create_stopped_terminal, recover, delete_admission)?;
    if !allow_policy_hold_transition {
        #[cfg(target_os = "linux")]
        if !matches!(q04_transition, Some(Q04JournalTransitionV1::Controller(..))) {
            if let Some(original) = storage_use {
                controller_policy_hold::require_q04_create_storage_use_bank_successor(
                    context.read().state(), transaction, original,
                )?;
            } else {
                match (terminal, intake) {
                    (Some(original), None) => controller_policy_hold::require_q04_terminal_bank_successor(
                        context.read().state(), transaction, original,
                    )?,
                    (None, Some(original)) => controller_policy_hold::require_q04_create_intake_bank_successor(
                        context.read().state(), transaction, original,
                    )?,
                    (None, None) => match history_successor {
                        Some(original) => controller_policy_hold::require_q04_create_storage_history_successor(context.read().state(), transaction, original)?,
                        None => match provisioning {
                            Some(original) => controller_policy_hold::require_q04_provisioning_successor(context.read().state(), original)?,
                            None if create_stopped_terminal.is_some() =>
                                controller_policy_hold::require_q04_create_stopped_terminal_successor(
                                    context.read().state(), create_stopped_terminal.ok_or(JournalError::ProtectedBoundary)?)?,
                            None if create_stopped_pre_ack.is_some() =>
                                controller_policy_hold::require_q04_create_stopped_pre_ack_successor(
                                    context.read().state(), create_stopped_pre_ack.ok_or(JournalError::ProtectedBoundary)?)?,
                            None if delete_admission.is_some() =>
                                controller_policy_hold::require_q04_delete_admission_successor_v3(
                                    context.read().state(), delete_admission.ok_or(JournalError::ProtectedBoundary)?)?,
                            None if recover.is_some() =>
                                controller_policy_hold::require_q04_operator_recover_successor(
                                    context.read().state(), recover.ok_or(JournalError::ProtectedBoundary)?)?,
                            None => controller_policy_hold::require_no_mutation(context.read().state(), transaction)?,
                        },
                    },
                    _ => return Err(JournalError::ProtectedBoundary),
                }
            }
        }
        #[cfg(not(target_os = "linux"))]
        controller_policy_hold::require_no_mutation(context.read().state(), transaction)?;
        #[cfg(target_os = "linux")]
        if !matches!(q04_transition, Some(Q04JournalTransitionV1::Source(..))) {
            match source_provisioning {
                Some(original) => original.require_retained_source_cut_v1(context.read().state())?,
                None => context.require_source_policy_transition(transaction)?,
            }
        }
        #[cfg(not(target_os = "linux"))]
        context.require_source_policy_transition(transaction)?;
    }
    context.require_mount_transition(transaction)?;
    super::super::git_coverage_history::require_storage_transition_read_v1(context.read(), context.read().state(), transaction)?;
    super::super::git_coverage_history::require_owner_transition_read_v1(context.read(), context.read().state(), transaction)?;
    validate_transaction(transaction, context.read().limits())?;
    delete_batch::validate(context.read().state(), transaction, context.read().next_sequence(), context.read().limits())?;
    let has_capacity_records = transaction
        .records()
        .iter()
        .any(|record| record.namespace() == RecordNamespace::GlobalCapacityReservation);
    if has_capacity_records != allow_capacity_records {
        return Err(JournalError::ProtectedBoundary);
    }
    if context.read().transaction_ids().contains(transaction.id()) {
        return Err(JournalError::DuplicateTransaction);
    }
    if context.read().committed_transactions() >= context.read().limits().maximum_transactions {
        return Err(JournalError::LimitExceeded("committed transaction count"));
    }
    validate_idempotency_changes(context.read().idempotency_index(), transaction.records())?;

    #[cfg(target_os = "linux")]
    context.begin(transaction, borrowed_root)?;
    let mut cache_policy_guard = None;
    let primary = (|| {
        context.prepare(transaction)?;
        let materialized_bytes = context.projected_materialized_bytes()
            .ok_or(JournalError::ProtectedBoundary)?;
        let (commit_sequence, following_sequence) = context.coordinates()?;
        root_original_inventory::require_append_sequence_headroom(
            context.read().state(), transaction, following_sequence,
        )?;
        let expected_length = context.expected_length()?;
        validate_reserved_capacity(
            context.read().state(),
            materialized_bytes,
            transaction.records(),
            settling_reservation,
            expected_length,
            context.read().committed_transactions()
                .checked_add(1)
                .ok_or(JournalError::LimitExceeded("committed transaction count"))?,
            context.read().limits(),
            root_local_edge,
        )?;
        if first_successor.is_some() {
            source_tree_successor::require_sequence_headroom(
                &root_original_inventory::materialize(context.read().state(), transaction),
                following_sequence,
            )?;
        }

        // Retain the hold-journal lock through the durable append. The freeze
        // writer takes Cache journal locks before this lock in the same order.
        cache_policy_guard = Some(context.before_cache_append(&mut cache_gate)?);

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
            _ => {}
        }

        if let Some(phase) = first_successor {
            source_tree_successor::require_live_custody(context.journal()?, context.read().state(), transaction, phase)?;
        }

        if let Some(ProjectNativeTransitionV3::Genesis(phase, original)) = &project_genesis {
            source_tree_successor::require_project_genesis_native_owner_v3(context.journal()?, *phase)?;
            #[cfg(target_os = "linux")]
            {
                original.final_crossing()
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
            crate::hierarchy::controller_genesis::require_controller(context.journal()?, context.journal()?.protected_owner_uid()?)
                .map_err(|cause| JournalError::ProjectGenesisOriginal(Box::new(cause)))?;
            controller_source_successor_issuance::require_no_mutation(context.read().state(), transaction, Some(*transition))?;
            completed.recheck().map_err(|cause| JournalError::ProjectGenesisOriginal(Box::new(cause)))?;
            completed.signing_boundary_clock().map_err(|cause| JournalError::ProjectGenesisOriginal(Box::new(cause)))?;
        }

        #[cfg(target_os = "linux")]
        if let Some(ProjectNativeTransitionV3::FirstSuccessor(original)) = &project_genesis {
            let phase = first_successor.ok_or(JournalError::ProtectedBoundary)?;
            context.first_successor_crossing(original, transaction, phase)?;
        }

        #[cfg(target_os = "linux")]
        if let Some(original) = resource_reservation {
            if let Some(terminal) = original.q04_terminal() {
                terminal.require_native_position(context.journal()?)?;
            }
            if let Some(intake) = original.create_intake() {
                intake.require_native_position(context.journal()?)?;
            }
            if let Some(storage_use) = original.create_storage_use() {
                storage_use.require_native_position(context.journal()?)?;
            }
            original.final_crossing()?;
        }

        #[cfg(target_os = "linux")]
        if let Some(ProjectNativeTransitionV3::GlobalGenesis(original)) = &project_genesis {
            original.final_crossing(context.journal()?, source_genesis_transition, controller_genesis_transition)?;
        }

        #[cfg(target_os = "linux")]
        if let Some(original) = create_storage.as_mut() {
            original.final_crossing(context.journal()?)?;
        }

        #[cfg(target_os = "linux")]
        if let Some((loan, capture)) = storage_clock.as_mut() {
            capture.require_final_clock(loan)?;
        }
        if let CacheMutationGateV1::StopCleanupSource(original) = &cache_gate {
            original.final_append_gate_once_v1(context.journal()?, transaction)?;
        }
        let durable_bytes = context.append()?;

        #[cfg(all(target_os = "linux", any(test, feature = "test-fixtures")))]
        if storage_clock.as_mut().is_some_and(|(_, capture)| capture.take_durable_append_failure()) {
            context.poison();
            return Err(JournalError::Io(std::io::Error::other(
                "injected Storage Prepare failure after durable native append",
            )));
        }

        while context.apply_next_record()? {}
        context.publish()?;

        #[cfg(target_os = "linux")]
        {
            context.mark_q04(transaction);
        }

        if let Err(error) =
            context.own_cache_successor(&mut cache_gate, transaction, following_sequence, durable_bytes)
        {
            context.poison();
            return Err(error);
        }

        if context.is_ordinary() {
            context.finish_ordinary()?;
        }
        Ok(CommitResult {
            commit_sequence,
            durable_bytes,
        })
    })();

    #[cfg(target_os = "linux")]
    if !context.is_ordinary() {
        let result = context.finish_selected(primary);
        drop(cache_policy_guard);
        return result;
    }
    // The ordinary cache guard still drops before the native stage, and
    // only after the original positive finish or original error frontier.
    drop(cache_policy_guard);
    context.drop_stage();
    primary
}
