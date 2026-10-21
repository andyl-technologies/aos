//! Borrows actual Source semantic fields beside the closed C17 native scope.
//!
//! The Journal is split once before constructing the native scope. No second
//! Journal, copied semantic cache, raw coordinator or identity-only owner is
//! constructed. One append uses the ordinary semantic schedule, then retains
//! exact readback, canonical replay and native posts before positive disposal.

use std::error::Error;
use std::path::PathBuf;

use aos_sandbox_model::{ResourceDimension as D, ResourceVector};
use aos_sandbox_broker::canonical_journal::coordinator::{CanonicalWriterReadViewV1, CanonicalCoordinatorAppendDataV1};
use aos_sandbox_broker::controller_receiving::bank_launch::{
    ControllerBankLaunchOriginalV1, ControllerOperationIntakeReceivingLoanV1,
};
use aos_sandbox_broker::controller_receiving::profile::ControllerSelfProfileOriginalV1;
use aos_sandbox_broker::source_receiving::{
    SourceDeleteAppendOriginalV1, SourceDeleteAppendDisposalV1, SourceDeleteScopeV1,
};

use super::{AppendScope, CacheMutationGateV1, CommitResult, engine};
use super::super::*;
use super::super::native_backing::{JournalNativeBackingV1, Selection};
use super::engine::AppendContextV1;

mod metadata_dependencies;
mod dependency_graph;
pub(crate) use dependency_graph::SourceDeleteGraphErrorV2;
pub(crate) use metadata_dependencies::{
    SourceDeleteMetadataRequestDataV2, SourceDeleteMetadataRequestErrorV2,
};

mod cache_audit;
mod planning_cuts;
pub(crate) use planning_cuts::DeletePlanningBaseCutsDataV2;
mod readiness;
pub(crate) use readiness::DeleteSourceFrontierClockV3;
mod completion;
pub(crate) use completion::SourceDeleteCompletionDisposalOriginalV4;
mod pending_fence;
pub(crate) use pending_fence::SourceDeletePendingFenceV1;
pub use pending_fence::{DeleteInventorySessionAppendOriginalV1, DeleteInventorySessionAppendDisposalV1, DeleteInventoryIoDisposalV1, DeleteInventorySecurityShapeDataV1};
pub(in crate::journal) use pending_fence::PendingNativeObserverV1;
use pending_fence::PendingSourceCompletionV1;

// References retain the very same caches/gates. None are reconstructed from
// the historical view, and the native scope holds its sole writer separately.
struct SourceSemanticFieldsV1<'journal> {
    cache_policy_gate: &'journal Option<(PathBuf, u32)>,
    source_challenge_history: &'journal mut Vec<source_history::SourceOriginalChallengeCheckpointV5>,
    source_original_replay: &'journal mut source_history::replay::SourceOriginalReplayCacheV5,
    source_history_compacted: &'journal mut bool,
    q04_lower_history_present: &'journal mut bool,
}

/// Keeps the actual Source native scope and semantic fields exclusively held.
///
/// The constructor is confined to the actual Journal's Source backing. This
/// private type cannot be built from a historical view, authorization DTO or
/// a separate writer. Its native owner's failure/forget laws stay unchanged.
pub(crate) struct SourceDeleteSemanticScopeV1<'journal, 'original> {
    native: SourceDeleteScopeV1<'journal, 'original, Selection>,
    semantic: SourceSemanticFieldsV1<'journal>,
    pending_completion: Option<PendingSourceCompletionV1>,
    pending_prepare_entered: bool,
    readiness: readiness::SourceReadinessCurrentV3,
    completion: completion::SourceCompletionCurrentV4,
}

impl Journal {
    // Actual extra Domain scope construction is paid with the authorization
    // prefix before its Native source loan exists. No DATA view pays itself.
    pub(crate) fn delete_semantic_scope_construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<SourceDeleteSemanticScopeV1<'_, '_>>().checked_mul(3)?
            .checked_add(std::mem::size_of::<SourceDeletePendingFenceV1<'_, '_, '_, '_>>().checked_mul(3)?)
    }

    /// Splits the same Source Journal under its genuine C17 loan.
    ///
    /// # Errors
    /// Rejects wrong backing, native uncertainty, foreign C/profile/Launch or
    /// the original joint scope's pre-entry/currentness/financial refusal.
    pub(crate) fn borrow_delete_semantic_scope_v1<'journal, 'original>(
        &'journal mut self,
        receiving: &'journal mut ControllerOperationIntakeReceivingLoanV1<'original>,
        controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<SourceDeleteSemanticScopeV1<'journal, 'original>, JournalError> {
        self.ensure_healthy()?;
        let source = match &mut self.native {
            JournalNativeBackingV1::Source(source) => source,
            _ => return Err(JournalError::ProtectedBoundary),
        };
        let semantic = SourceSemanticFieldsV1 {
            cache_policy_gate: &self.cache_policy_gate,
            source_challenge_history: &mut self.source_challenge_history,
            source_original_replay: &mut self.source_original_replay,
            source_history_compacted: &mut self.source_history_compacted,
            q04_lower_history_present: &mut self.q04_lower_history_present,
        };
        let native = source.borrow_delete_scope_v1(receiving,
            controller.controller_coordinator_for_bank_read_v1()?, launch, profile)
            .map_err(JournalError::ControllerNative)?;
        Ok(SourceDeleteSemanticScopeV1 { native, semantic,
            pending_completion: None, pending_prepare_entered: false,
            readiness: Default::default(), completion: Default::default() })
    }
}

pub(crate) type SourceDeleteSemanticAppendV1<'append, 'journal, 'original> =
    SourceOperationSemanticAppendV1<'append, 'journal, 'original>;
pub(crate) type SourceDeleteSemanticDisposalV1<'disposal, 'append, 'journal, 'original> =
    SourceOperationSemanticDisposalV1<'disposal, 'append, 'journal, 'original>;

mod native_operation;
use native_operation::{SourceSemanticNativeAppendV1, SourceSemanticNativeDisposalV1, SourceSemanticNativeScopeRefV1};
mod execution_environment;
pub(crate) use execution_environment::{SourceExecutionSemanticScopeV1, CompletedEnvironmentSourceAppendV1, QualifiedEnvironmentSourceViewV1};

/// Retains semantic body, actual input/readback and native post chronologically.
///
/// The first field owns the abort-on-abandonment native obligation. Errors can
/// be inspected while all original inputs and native work remain resident.
#[must_use]
pub(crate) struct SourceOperationSemanticAppendV1<'append, 'journal, 'original> {
    native: SourceSemanticNativeAppendV1<'append, 'journal, 'original>,
    continued_complete: ResourceVector,
    environment_clock: Option<&'append mut crate::controller_execution_operation::ControllerExecutionClockOriginalV1>,
    environment_horizon: Option<crate::environment::deployment::transport::EnvironmentRootOpenDataV1>,
    environment_clock_result: Option<Result<(), JournalError>>,
    semantic: &'append mut SourceSemanticFieldsV1<'journal>,
    transaction: &'append JournalTransaction,
    pending: Option<&'append crate::lifecycle::delete_pending::SourceDeletePendingPlanV1<'append>>,
    pending_native: Option<PendingNativeObserverV1<'append>>,
    readiness_clock: Option<readiness::DeleteSourceFrontierClockV3>,
    readiness_plan: Option<&'append crate::lifecycle::delete_pending::SourceDeleteReadinessPlanV3>,
    readiness_current: Option<&'append mut readiness::SourceReadinessCurrentV3>,
    completion_plan: Option<&'append crate::lifecycle::delete_pending::SourceDeleteCompletionPlanV4>,
    completion_current: Option<&'append mut completion::SourceCompletionCurrentV4>,
    pending_completion: &'append mut Option<PendingSourceCompletionV1>,
    primary: Option<Result<CommitResult, JournalError>>,
    readback: Vec<u8>,
    identity: Option<Result<FileIdentity, JournalError>>,
    replay: Option<Result<ObservedReplayStateV1, JournalError>>,
    comparison: Option<Result<(), JournalError>>,
    native_after: Option<Result<(), aos_sandbox_broker::source_receiving::SourceNativeErrorV1>>,
    attempted: bool,
    reentry: Option<JournalError>,
}

impl<'journal, 'original> SourceDeleteSemanticScopeV1<'journal, 'original> {
    /// Borrows only the exact retained C17 financial/native refusal.
    pub(crate) fn planning_root_intake_failure_view_v1<'cause>(
        &'cause self,
        profile: &'cause ControllerSelfProfileOriginalV1,
    ) -> Option<aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeFailureViewV1<'cause>> {
        self.native.delete_intake_failure_view_v1(profile)
    }

    pub(crate) fn planning_read_view_construction_bytes_v1() -> Option<usize> {
        CanonicalWriterReadViewV1::<Selection>::receiving_construction_bytes_v1()
    }

    pub(crate) fn planning_source_boundary_data_v1(&self) -> Result<(u64, u64), JournalError> {
        let read = self.native.historical_view_v1().map_err(JournalError::ControllerNative)?;
        let _ = read;
        Ok((self.native.semantic_read_view_v1().next_sequence(), self.native.durable_end_data_v1()))
    }

    pub(crate) fn reserve_planning_root_additional_v1(
        &mut self,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        additional: ResourceVector,
    ) -> Result<(), JournalError> {
        self.native.reserve_delete_preaccept_additional_v1(
            controller.controller_coordinator_for_bank_v1()?, launch, profile,
            aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1::from_demand_v1(additional),
        ).map_err(JournalError::ControllerNative)
    }

    pub(crate) fn prepare_planning_root_turn_v1<'profile>(
        &mut self,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &'profile ControllerSelfProfileOriginalV1,
    ) -> Result<aos_sandbox_broker::controller_receiving::bank_launch::ControllerDeletePreacceptTurnOriginalV1<'profile>, JournalError> {
        self.native.prepare_delete_preaccept_turn_v1(
            controller.controller_coordinator_for_bank_v1()?, launch, profile,
            aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1::from_demand_v1(ResourceVector::ZERO),
        ).map_err(JournalError::ControllerNative)
    }

    pub(crate) fn local_runtime_funding_data_v3(
        &self,
        controller: &Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<aos_sandbox_protocol::domain_ledger::resource_bank::OperationIntakeFundingDataV1, JournalError> {
        self.native.current_delete_funding_data_v3(
            controller.controller_coordinator_for_bank_read_v1()?, launch, profile,
        ).map_err(JournalError::ControllerNative)
    }

    pub(crate) fn reserve_query_construction_v1(
        &mut self,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        bytes: u64,
    ) -> Result<(), JournalError> {
        self.native.reserve_delete_preaccept_additional_v1(
            controller.controller_coordinator_for_bank_v1()?, launch, profile,
            aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1::from_demand_v1(
                ResourceVector::ZERO.with(D::MemoryBytes, bytes),
            ),
        ).map_err(JournalError::ControllerNative)
    }

    /// Borrows the original scope's chronological native/currentness cause.
    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.native.failure()
    }

    /// Borrows saved Source rows while the actual exclusive C17 cut remains.
    ///
    /// # Errors
    /// Refuses the same failed/closed original; no view grants graph authority.
    pub(crate) fn historical_view_v1(&self)
        -> Result<aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerReadViewV1<'_>, JournalError>
    {
        self.native.historical_view_v1().map_err(JournalError::ControllerNative)
    }

    /// Checks the actual complete plan/model peak before its next pure growth.
    ///
    /// # Errors
    /// Preserves the same C17 capacity/original/Launch/profile refusal.
    pub(crate) fn require_delete_plan_demand_v1(&mut self, controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
        complete: ResourceVector,
    ) -> Result<(), JournalError> {
        self.native.require_complete_v1(controller.controller_coordinator_for_bank_v1()?, launch, profile,
            aos_sandbox_broker::controller_receiving::bank_launch::ControllerOperationIntakeDemandDataV1::from_demand_v1(complete))
            .map_err(JournalError::ControllerNative)
    }

    /// Prepays the complete reached upper model before entering its native port.
    ///
    /// The transaction must already be resident and paid by the actual C17
    /// caller. `complete` includes every other co-resident authorized/plan/input
    /// owner; no residual vector or supplied demand creates this borrower.
    /// Native decode/COMMIT readback uses the fixed future durable cut, the
    /// existing replay geometry and the same Source semantic shape recipe.
    ///
    /// # Errors
    /// Preserves overflow/currentness/financial refusal before allocation. An
    /// entered lower failure is returned inside the whole actual append owner.
    pub(crate) fn prepare_append_once_v1<'append>(
        &'append mut self,
        controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        transaction: &'append JournalTransaction,
        complete: ResourceVector,
    ) -> Result<SourceOperationSemanticAppendV1<'append, 'journal, 'original>, JournalError> {
        prepare_source_semantic_append_once_v1(
            SourceSemanticNativeScopeRefV1::Delete(&mut self.native),
            &mut self.semantic, &mut self.pending_completion,
            controller, launch, profile, transaction, complete,
        )
    }

    /// Prepays and plans an authenticated canonical Planned Source fence.
    ///
    /// This returns an exact transaction, not dependency/Root approval. The
    /// actual request, candidate operation and batch must already be resident
    /// under the caller's C17 complete demand before this next frontier.
    ///
    /// # Errors
    /// Retains canonical planning errors or refuses the same C17 complete cut
    /// before verifier, projection, auxiliary, transaction or graph copies.
    pub(crate) fn prepare_pending_plan_v1<'authorization>(
        &mut self, controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        request_scope: crate::controller::ControllerRequestScopeV1,
        authorization: crate::public_mutation_compiler::delete_admission::DeleteAuthorizationBindingV1<'authorization>,
        operation: crate::lifecycle::LifecycleOperationV1,
        batch: aos_sandbox_protocol::domain_ledger::delete_batch::LifecycleDeleteBatchV1,
        complete: ResourceVector,
    ) -> Result<crate::lifecycle::delete_pending::SourceDeletePendingPlanV1<'authorization>,
        crate::lifecycle::protected_journal::LifecycleProtectedJournalErrorV1>
    {
        let physical = usize::try_from(self.native.durable_end_data_v1())
            .map_err(|_| JournalError::LimitExceeded("Delete pending prefix"))?;
        let memory = crate::lifecycle::delete_pending::preparation_payload_bytes_v1(&operation, &batch, physical)?;
        let own = ResourceVector::ZERO
            .with(D::MemoryBytes, u64::try_from(memory).map_err(|_| JournalError::LimitExceeded("Delete pending representation"))?)
            // The two actual lifecycle keys and the fixed pending key coexist.
            .with(D::MetadataEntries, 3);
        let cuts = self.planning_cuts_receiving_demand_v2()?;
        let complete = complete.componentwise_max(authorization.demand())
            .checked_add(own).and_then(|demand| demand.checked_add(cuts))
            .map_err(JournalError::ReceivingAccounting)?;
        self.require_delete_plan_demand_v1(controller, launch, profile, complete)?;
        // The same protected owners recompute all three available cuts before
        // Planned is materialized. The complete six-owner collector is the
        // sole remaining producer of initial_six; this check cannot adopt it.
        self.require_planning_cuts_v2(controller, launch, profile, &authorization, &batch)?;
        let read = self.native.semantic_read_view_v1();
        crate::lifecycle::delete_pending::SourceDeletePendingPlanV1::prepare_v1(
            read.historical_view(), read.next_sequence(), controller.snapshot_sequence(),
            request_scope, authorization, complete, operation, batch,
        )
    }

    /// Enters exactly the pending transaction through the same retained engine.
    ///
    /// # Errors
    /// Refuses the actual reached complete/native prepay or an incomplete
    /// Source scope before entering its independently owed append interval.
    pub(crate) fn enter_pending_append_v1<'append>(
        &'append mut self, controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        plan: &'append crate::lifecycle::delete_pending::SourceDeletePendingPlanV1<'append>,
        complete: ResourceVector,
    ) -> Result<SourceOperationSemanticAppendV1<'append, 'journal, 'original>, JournalError> {
        if self.pending_prepare_entered {
            self.pending_completion = None;
            return Err(JournalError::ProtectedBoundary);
        }
        self.pending_prepare_entered = true;
        plan.require_sequences_v1(self.native.semantic_read_view_v1().next_sequence(),
            controller.snapshot_sequence())?;
        // The plan and its actual authorization/native prefix stay held.
        // Carry their complete cumulative traffic through this later gate;
        // caller DATA cannot replace it with an equal per-stage allowance.
        let complete = complete.componentwise_max(plan.complete_demand());
        let mut append = self.prepare_append_once_v1(controller, launch, profile,
            plan.transaction(), complete)?;
        append.pending = Some(plan);
        append.pending_native = Some(PendingNativeObserverV1::new(plan.transaction()));
        Ok(append)
    }

    /// Keeps the actual joint native completion through final upper disposal.
    ///
    /// This is only the existing native disposition token. It does not attest
    /// a durable Delete plan, Root floor, Controller acceptance or destruction.
    ///
    /// # Errors
    /// Refuses incomplete original Source/C posts or changed same-owner state.
    pub(crate) fn prepare_positive_disposal_v1<'disposal>(&'disposal mut self,
        controller: &'disposal Journal,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<aos_sandbox_broker::source_receiving::SourceDeleteScopeDisposalV1<'disposal, Selection>, JournalError> {
        // Pending acquisition is not completion of Delete. A real durable
        // terminal producer must settle it before this outer C17 releases.
        if self.pending_prepare_entered {
            return Err(JournalError::ProtectedBoundary);
        }
        self.native.prepare_positive_disposal_v1(controller.controller_coordinator_for_bank_read_v1()?, launch, profile)
            .map_err(JournalError::ControllerNative)
    }

    /// Finishes the original outer Source/C posts after local append disposition.
    ///
    /// # Errors
    /// Retains the original independent posts and rejects repeated completion.
    pub(crate) fn finish_native_once_v1(&mut self, controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), JournalError> {
        self.native.finish_native_once_v1(controller.controller_coordinator_for_bank_v1()?, launch, profile)
            .map_err(JournalError::ControllerNative)
    }
}

impl SourceOperationSemanticAppendV1<'_, '_, '_> {
    // Only the closed actual Execution Environment constructor installs these
    // borrows. Delete retains its exact old native/clock schedule through None.
    fn require_environment_frontier_once_v1(&mut self) -> Result<(), JournalError> {
        if let Some(clock) = self.readiness_clock.as_mut() {
            if self.environment_clock.is_some() { return Err(JournalError::ProtectedBoundary); }
            return clock.observe_frontier_v3();
        }
        if self.environment_clock_result.as_ref().is_some_and(Result::is_err) {
            return Err(JournalError::ProtectedBoundary);
        }
        let Some(clock) = self.environment_clock.as_deref_mut() else { return Ok(()); };
        let bound = self.environment_horizon.ok_or(JournalError::ProtectedBoundary)?;
        self.environment_clock_result = Some(clock.sample_v1()
            .map_err(|_| JournalError::ProtectedBoundary)
            .and_then(|sample| bound.require_later_sample_v1(sample)
                .map_err(|_| JournalError::ProtectedBoundary)));
        match &self.environment_clock_result {
            Some(Ok(())) => Ok(()),
            _ => Err(JournalError::ProtectedBoundary),
        }
    }

    /// Runs the sole semantic append core and actual canonical readback once.
    ///
    /// All body outcomes run the already prepared independent Source post.
    /// A returned marker is resolved only through this retained actual owner.
    ///
    /// # Errors
    /// Retains the earliest semantic/native/readback failure before owed posts.
    pub(crate) fn run_once_v1(&mut self) -> Result<(), JournalError> {
        if self.attempted {
            *self.pending_completion = None;
            self.reentry.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        self.attempted = true;
        let transaction = self.transaction;
        if self.native.primary_failure_v1().is_some() {
            self.primary = Some(Err(JournalError::SourceNative(
                aos_sandbox_broker::source_receiving::SourceNativeErrorV1::Closed,
            )));
        } else {
            self.primary = Some(engine::commit(self, transaction,
                AppendScope::default(),
                CacheMutationGateV1::Ordinary, None, None, None, None, None, None));
        }
        if matches!(self.primary, Some(Ok(_))) {
            let length = self.primary.as_ref().and_then(|result| result.as_ref().ok())
                .and_then(|result| usize::try_from(result.durable_bytes).ok());
            if let Some(length) = length {
                let read = self.require_environment_frontier_once_v1().and_then(|()| {
                    self.readback.resize(length, 0);
                    self.native.readback_published_once_v1(&mut self.readback).map_err(JournalError::SourceNative)
                });
                if read.is_ok() {
                    self.identity = Some(self.native.semantic_read_view_v1().file_identity());
                    if let Some(Ok(identity)) = self.identity.as_ref() {
                        self.replay = Some(replay_published_bytes_observed_v1(
                            self.readback.as_slice(), *identity,
                            self.native.semantic_read_view_v1().limits(),
                            self.pending_native.as_mut().map(DeploymentHistoryObserverV1::DeletePending)));

                        self.comparison = Some(self.compare_readback_v1());
                    }
                }
            } else {
                self.comparison = Some(Err(JournalError::JournalTooLarge));
            }
        }
        // Deliberately independent of every earlier body/readback result.
        self.native_after = Some(self.native.finish_native_once_v1());
        if matches!(self.primary, Some(Ok(_))) && matches!(self.comparison, Some(Ok(())))
            && matches!(self.native_after, Some(Ok(())))
        {
            let _final_horizon = self.require_environment_frontier_once_v1();
        }
        if self.failure().is_none() && matches!(self.comparison, Some(Ok(()))) {
            Ok(())
        } else {
            Err(JournalError::ProtectedBoundary)
        }
    }

    fn compare_readback_v1(&self) -> Result<(), JournalError> {
        let replay = self.replay.as_ref().and_then(|result| result.as_ref().ok())
            .ok_or(JournalError::ProtectedBoundary)?;
        let read = self.native.semantic_read_view_v1();
        if replay.durable_end != u64::try_from(self.readback.len()).map_err(|_| JournalError::JournalTooLarge)?
            || replay.next_sequence != read.next_sequence()
            || replay.committed_transactions != read.committed_transactions()
            || replay.native.transaction_ids_data_v1() != read.transaction_ids()
            || replay.native.state_data_v1() != read.state()
            || replay.native.idempotency_data_v1() != read.idempotency_index()
            || replay.native.materialized_bytes_data_v1() != read.materialized_bytes()
            || replay.source_original_replay.needs_closure()
            || replay.source_original_replay.has_dependencies()
            || replay.source_history_compacted != *self.semantic.source_history_compacted
            || replay.q04_lower_history_present != *self.semantic.q04_lower_history_present
            || replay.source_challenge_history.len() != self.semantic.source_challenge_history.len()
            || replay.source_challenge_history.iter().zip(self.semantic.source_challenge_history.iter()).any(|(replayed, original)| {
                replayed.key() != original.key() || replayed.value() != original.value()
                    || replayed.transaction_id() != original.transaction_id()
                    || replayed.frame_sequences() != original.frame_sequences()
                    || replayed.file_offsets() != original.file_offsets()
            })
        {
            return Err(JournalError::StaleAuthoritySnapshot);
        }
        Ok(())
    }

    /// Borrows exact body cause before independently owed post failures.
    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        if let Some(cause) = self.readiness_clock.as_ref().and_then(|clock| clock.failure()) {
            return Some(cause);
        }
        if let Some(Err(cause)) = &self.environment_clock_result {
            return self.environment_clock.as_deref().and_then(|clock| clock.failure())
                .or(Some(cause as _));
        }
        self.primary.as_ref().and_then(|result| result.as_ref().err()).map(|cause| -> &(dyn Error + 'static) {
            if matches!(cause, JournalError::SourceNative(aos_sandbox_broker::source_receiving::SourceNativeErrorV1::Closed)) {
                self.native.primary_failure_v1().unwrap_or(cause)
            } else { cause }
        }).or_else(|| self.native.primary_failure_v1())
            .or_else(|| self.identity.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.replay.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.comparison.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.native.failure())
            .or_else(|| self.native_after.as_ref().and_then(|result| result.as_ref().err()).map(|cause| cause as _))
            .or_else(|| self.reentry.as_ref().map(|cause| cause as _))
    }

    /// Compares and disposes a completed pending append before projecting DATA.
    ///
    /// The outer same C/Source scope remains exclusively held. This returned
    /// position is not an acceptance, a Root grant or a replacement native
    /// owner; later consumers must still borrow that actual pending scope.
    ///
    /// # Errors
    /// Retains semantic/native/readback/post failures without issuing a cut.
    pub(crate) fn complete_pending_readback_v1(&mut self)
        -> Result<SourceDeletePendingReadbackDataV1, JournalError>
    {
        if self.pending_completion.is_some() {
            *self.pending_completion = None;
            self.reentry.get_or_insert(JournalError::ProtectedBoundary);
            return Err(JournalError::ProtectedBoundary);
        }
        let plan = self.pending.ok_or(JournalError::ProtectedBoundary)?;
        if self.failure().is_some() || !matches!(self.comparison, Some(Ok(()))) {
            return Err(JournalError::ProtectedBoundary);
        }
        plan.require_saved_v1(self.native.semantic_read_view_v1().state())?;
        let committed = self.primary.as_ref().and_then(|result| result.as_ref().ok())
            .copied().ok_or(JournalError::ProtectedBoundary)?;
        let (project, operation, batch_digest) = plan.coordinates();
        let proof = self.pending_native.as_ref().and_then(PendingNativeObserverV1::completed)
            .copied().ok_or(JournalError::ProtectedBoundary)?;
        let end = u64::try_from(self.readback.len()).map_err(|_| JournalError::JournalTooLarge)?;
        self.prepare_positive_disposal_v1()?.complete_after_disposal_v1();
        // This marker is written only after actual local positive disposal and
        // remains inside this SAME scope. Returned position DATA is not input.
        *self.pending_completion = Some(PendingSourceCompletionV1::new(
            project, operation, batch_digest, committed, end, proof,
        ));
        Ok(SourceDeletePendingReadbackDataV1 { project, operation, batch_digest, committed })
    }

    /// Runs outer Source/C debt while a failed semantic append stays resident.
    ///
    /// # Errors
    /// Preserves the actual outer-post failure without replacing primary cause.
    pub(crate) fn finish_outer_scope_once_v1(&mut self, controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), JournalError> {
        self.native.finish_outer_scope_once_v1(controller.controller_coordinator_for_bank_v1()?, launch, profile)
            .map_err(JournalError::ControllerNative)
    }
}

impl<'append, 'journal, 'original> SourceOperationSemanticAppendV1<'append, 'journal, 'original> {
    /// Keeps the actual positive native token through upper replay disposal.
    ///
    /// # Errors
    /// Refuses any incomplete body, replay/comparison or independent native post.
    pub(crate) fn prepare_positive_disposal_v1<'disposal>(&'disposal mut self)
        -> Result<SourceOperationSemanticDisposalV1<'disposal, 'append, 'journal, 'original>, JournalError>
    {
        if !self.attempted || self.failure().is_some()
            || !matches!(self.primary, Some(Ok(_)))
            || !matches!(self.comparison, Some(Ok(())))
            || !matches!(self.native_after, Some(Ok(())))
        { return Err(JournalError::ProtectedBoundary); }
        let native = self.native.prepare_positive_disposal_v1().map_err(JournalError::SourceNative)?;
        Ok(SourceOperationSemanticDisposalV1 { native, readback: &mut self.readback, replay: &mut self.replay })
    }
}

/// Contains comparison DATA from one completed pending append.
///
/// No public constructor, owner adoption, append or effect method is exposed.
/// The actual Source scope, authorization and plan remain on their original
/// owners; a later Root/preaccept consumer must join those actual originals.
pub(crate) struct SourceDeletePendingReadbackDataV1 {
    pub(crate) project: aos_sandbox_model::ProjectId,
    pub(crate) operation: aos_sandbox_model::OperationId,
    pub(crate) batch_digest: aos_sandbox_model::ObjectDigest,
    pub(crate) committed: CommitResult,
}

/// Holds the same native completion while positive upper parser owners dispose.
#[must_use]
pub(crate) struct SourceOperationSemanticDisposalV1<'disposal, 'append, 'journal, 'original> {
    native: SourceSemanticNativeDisposalV1<'disposal, 'append, 'journal, 'original>,
    readback: &'disposal mut Vec<u8>,
    replay: &'disposal mut Option<Result<ObservedReplayStateV1, JournalError>>,
}

impl SourceOperationSemanticDisposalV1<'_, '_, '_, '_> {
    /// Disposes only the completed local append, retaining the outer scope.
    pub(crate) fn complete_after_disposal_v1(self) {
        drop(std::mem::take(self.readback));
        drop(self.replay.take());
        self.native.complete_after_disposal_v1();
    }
}

impl<'transaction> AppendContextV1<'transaction> for SourceOperationSemanticAppendV1<'_, '_, '_> {
    fn read(&self) -> CanonicalWriterReadViewV1<'_, Selection> {
        self.native.semantic_read_view_v1()
    }

    fn journal(&self) -> Result<&Journal, JournalError> {
        Err(JournalError::ProtectedBoundary)
    }

    fn first_successor_crossing(&mut self,
        _original: &source_tree_successor::FirstSuccessorNativeCutV3<'_, '_>,
        _transaction: &JournalTransaction, _phase: FirstSourceSuccessorNativePhaseV2,
    ) -> Result<(), JournalError> {
        // A D17 Source context cannot lend an ordinary whole-Journal crossing.
        Err(JournalError::ProtectedBoundary)
    }

    fn source_replay(&self) -> &source_history::replay::SourceOriginalReplayCacheV5 {
        self.semantic.source_original_replay
    }

    fn ensure_healthy(&self) -> Result<(), JournalError> {
        if self.native.failure().is_some() || self.read().is_poisoned() { Err(JournalError::Poisoned) } else { Ok(()) }
    }

    fn require_consumer_transition(&self, transaction: &JournalTransaction, capacity: bool, settling: Option<[u8; 32]>) -> Result<(), JournalError> {
        crate::attachment_effect_owner::validate_consumer_resource_transaction_read_v1(None, self.read().historical_view(), transaction, capacity, settling)
    }

    fn require_root_genesis_transition(&self, transaction: &JournalTransaction) -> Result<(), JournalError> {
        aos_sandbox_ledger_replay::replay::root_genesis_capacity::require_no_mutation_v1(transaction)
            .map_err(JournalError::from)
    }

    fn require_source_policy_transition(&self, transaction: &JournalTransaction) -> Result<(), JournalError> {
        if let Some(plan) = self.completion_plan {
            if self.pending.is_some() || self.readiness_plan.is_some() {
                return Err(JournalError::ProtectedBoundary);
            }
            return plan.require_transition_v4(self.read().state(), transaction);
        }
        if let Some(plan) = self.readiness_plan {
            if self.pending.is_some() { return Err(JournalError::ProtectedBoundary); }
            return plan.require_transition_v3(self.read().state(), transaction);
        }
        match self.pending {
            Some(plan) => plan.require_acquisition_v1(self.read().state(), transaction),
            None => super::super::source_domain_policy_hold::require_no_mutation(self.read().state(), transaction),
        }
    }

    fn require_mount_transition(&self, transaction: &JournalTransaction) -> Result<(), JournalError> {
        super::super::git_coverage_history::require_mount_transition_read_v1(self.read(), false, self.read().state(), transaction)
    }

    fn begin(&mut self, _transaction: &JournalTransaction, root: Option<&aos_sandbox_broker::receiving::RootJournalFinancialBorrowV1<'_>>) -> Result<(), JournalError> {
        if root.is_some() { return Err(JournalError::ProtectedBoundary); }
        Ok(())
    }

    fn prepare(&mut self, transaction: &'transaction JournalTransaction) -> Result<(), JournalError> {
        self.require_environment_frontier_once_v1()?;
        self.native.prepare_semantic_append_once_v1(transaction).map_err(JournalError::SourceNative)
    }

    fn projected_materialized_bytes(&self) -> Option<usize> {
        self.native.prepared_v1()?.projected_materialized_bytes()
    }

    fn coordinates(&mut self) -> Result<(u64, u64), JournalError> {
        self.require_environment_frontier_once_v1()?;
        self.native.coordinates_once_v1().map_err(JournalError::SourceNative)
    }


    fn expected_length(&mut self) -> Result<u64, JournalError> {
        self.require_environment_frontier_once_v1()?;
        self.native.expected_length_once_v1().map_err(JournalError::SourceNative)
    }

    fn before_cache_append(&self, gate: &mut CacheMutationGateV1<'_>) -> Result<Option<Journal>, JournalError> {
        // No Source constructor admits a Cache interlock. Refuse rather than
        // reconstruct a temporary Journal or silently drop a retained gate.
        if self.semantic.cache_policy_gate.is_some() || !matches!(gate, CacheMutationGateV1::Ordinary) {
            return Err(JournalError::ProtectedBoundary);
        }
        Ok(None)
    }

    fn append(&mut self) -> Result<u64, JournalError> {
        self.require_environment_frontier_once_v1()?;
        self.native.append_once_v1().map_err(JournalError::SourceNative)
    }

    fn apply_next_record(&mut self) -> Result<bool, JournalError> {
        self.native.apply_next_record_once_v1().map_err(JournalError::SourceNative)
    }

    fn publish(&mut self) -> Result<(), JournalError> {
        self.require_environment_frontier_once_v1()?;
        self.native.publish_once_v1().map(|_| ()).map_err(JournalError::SourceNative)
    }

    fn mark_q04(&mut self, transaction: &JournalTransaction) {
        *self.semantic.q04_lower_history_present |= transaction.records().iter().any(is_q04_lower_history_record_v1);
    }

    fn own_cache_successor(&mut self, gate: &mut CacheMutationGateV1<'_>, _transaction: &JournalTransaction, _sequence: u64, _bytes: u64) -> Result<(), JournalError> {
        if matches!(gate, CacheMutationGateV1::Ordinary) { Ok(()) } else { Err(JournalError::ProtectedBoundary) }
    }

    fn poison(&mut self) {
        self.native.poison_after_semantic_failure_v1();
    }

    fn is_ordinary(&self) -> bool {
        false
    }

    fn finish_ordinary(&mut self) -> Result<(), JournalError> {
        Err(JournalError::ProtectedBoundary)
    }

    fn finish_selected(&mut self, primary: Result<CommitResult, JournalError>) -> Result<CommitResult, JournalError> {
        primary
    }

    fn drop_stage(&mut self) {}
}


fn prepare_source_semantic_append_once_v1<'append, 'journal, 'original>(
    mut native_scope: SourceSemanticNativeScopeRefV1<'append, 'journal, 'original>,
    semantic_fields: &'append mut SourceSemanticFieldsV1<'journal>,
    pending_completion: &'append mut Option<PendingSourceCompletionV1>,
    controller: &mut Journal,
    launch: &ControllerBankLaunchOriginalV1,
    profile: &ControllerSelfProfileOriginalV1,
    transaction: &'append JournalTransaction,
    complete: ResourceVector,
) -> Result<SourceOperationSemanticAppendV1<'append, 'journal, 'original>, JournalError> {
        let read = native_scope.semantic_read_view_v1();
        let (stage, semantic, own) = source_semantic_append_geometry_v2(
            read, native_scope.durable_end_data_v1(), transaction, semantic_fields,
        )?;
        let invalid = || JournalError::LimitExceeded("Delete semantic append representation");
        // Carry every reached consumable dimension into the next closed
        // stage. Positive disposal reuses resident capacity, never traffic.
        // The lower names/post supplier adds only resident bytes/files/names;
        // its independently paid native append remains on the Source original.
        let continued_complete = complete.checked_add(
            aos_sandbox_model::component_receiving::operation_traffic_demand_v1(
                stage.checked_add(semantic).map_err(|_| invalid())?))
            .map_err(|_| invalid())?;
        let complete = complete.checked_add(stage).map_err(|_| invalid())?;
        let bytes = usize::try_from(own.get(D::MemoryBytes)).map_err(|_| invalid())?;
        let native = native_scope.enter_semantic_append_once_v1(
            controller.controller_coordinator_for_bank_v1()?, launch, profile,
            transaction, semantic, complete, bytes,
        ).map_err(JournalError::ControllerNative)?;
        // No output buffer, semantic preview or replay allocation precedes the
        // actual same-C complete check and the Source original's own prepay.
        Ok(SourceOperationSemanticAppendV1 {
            continued_complete,
            native,
            environment_clock: None,
            environment_horizon: None,
            environment_clock_result: None,
            semantic: semantic_fields,
            transaction,
            pending: None,
            pending_native: None,
            readiness_clock: None,
            readiness_plan: None,
            readiness_current: None,
            completion_plan: None,
            completion_current: None,
            pending_completion,
            primary: None,
            readback: Vec::new(),
            identity: None,
            replay: None,
            comparison: None,
            native_after: None,
            attempted: false,
            reentry: None,
        })
    }

// Shares the actual reached append/readback geometry with the fixed pending
// consumer's earlier additive reservation. This is DATA on the SAME read view;
// authority, V5 gate, actual native entry and original post order stay above.
fn source_semantic_append_geometry_v2(
    read: CanonicalWriterReadViewV1<'_, Selection>,
    durable_end: u64,
    transaction: &JournalTransaction,
    semantic_fields: &SourceSemanticFieldsV1<'_>,
) -> Result<(ResourceVector, ResourceVector, ResourceVector), JournalError> {
    // This lane appends lifecycle fence records, never V5 Source-capacity
    // transitions. Such history needs its real retained challenge writer;
    // a cached witness or replay with None cannot replace that original.
    if semantic_fields.source_original_replay.requires_history(read.state(), transaction) {
        return Err(JournalError::ProtectedBoundary);
    }
    let invalid = || JournalError::LimitExceeded("Delete semantic append representation");
    let future = durable_end
        .checked_add(encoded_transaction_append_bytes(transaction)?)
        .ok_or_else(invalid)?;
    let extent = protected_journal_preopen_replay_extent_for_prefix_v1(read.limits(), future)?;
    let native_replay = extent.dominant_native_receiving_demand_v1()?;
    // Final-map shapes omit historical PUTs later removed or replaced.
    // The full raw prefix reaches their typed models during readback.
    let semantic_replay = extent.dominant_semantic_receiving_demand_v1()?;
    let semantic = source_readonly_receiving::semantic_demand(read.state(), Some(transaction))?;
    let fixed = std::mem::size_of::<SourceOperationSemanticAppendV1<'_, '_, '_>>().checked_mul(3)
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<SourceOperationSemanticDisposalV1<'_, '_, '_, '_>>().checked_mul(2)?))
        .and_then(|bytes| bytes.checked_add(CanonicalWriterReadViewV1::<Selection>::receiving_construction_bytes_v1()?))
        .and_then(|bytes| bytes.checked_add(engine::receiving_frame_bytes_v1()?))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Result<
            (ResourceVector, ResourceVector, ResourceVector), JournalError>>().checked_mul(3)?))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<ObservedReplayStateV1>().checked_mul(2)?))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<&[u8]>().checked_mul(2)?))
        .and_then(|bytes| u64::try_from(bytes).ok()).ok_or_else(invalid)?;
    let fixed = fixed.checked_add(u64::try_from(std::mem::size_of::<SourceDeletePendingReadbackDataV1>()
        .checked_mul(3)
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<PendingNativeObserverV1<'_>>().checked_mul(3)?))
        .and_then(|bytes| bytes.checked_add(std::mem::size_of::<PendingSourceCompletionV1>().checked_mul(3)?))
        .ok_or_else(invalid)?).map_err(|_| invalid())?).ok_or_else(invalid)?;
    let own = ResourceVector::ZERO.with(D::MemoryBytes,
        fixed.checked_add(future.checked_mul(2).ok_or_else(invalid)?).ok_or_else(invalid)?);
    let stage = native_replay.checked_add(semantic_replay)
        .and_then(|demand| demand.checked_add(own))
        .map_err(|_| invalid())?;
    Ok((stage, semantic, own))
}

pub(crate) use aos_sandbox_ledger_replay::delete_graph::DeleteDependencyGraphDataV2;
