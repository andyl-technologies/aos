//! Borrows the actual Source semantic fields under the genuine Execution18 cut.
//!
//! Only the Environment publisher's privately prepared canonical transition can
//! enter an append. The native scope, semantic caches, COMMIT readback and owed
//! Source/C posts remain the same originals used by the existing Delete route.

use super::*;
use aos_sandbox_broker::source_receiving::{SourceExecutionScopeV1, SourceExecutionScopeDisposalV1,
    SourceExecutionReadViewV1, SourceExecutionCompleteBorrowV1};
use aos_sandbox_broker::controller_receiving::bank_launch::{ControllerCoordinatorWriterV1,
    ControllerOperationIntakeDemandDataV1, ControllerBankLaunchErrorV1};

/// Keeps the same writer and semantic fields through Environment publication.
pub(crate) struct SourceExecutionSemanticScopeV1<'journal, 'original> {
    native: SourceExecutionScopeV1<'journal, 'original, Selection>,
    semantic: SourceSemanticFieldsV1<'journal>,
    pending_completion: Option<PendingSourceCompletionV1>,
}

impl Journal {
    /// Prices the actual extra semantic scope before borrowing the Source writer.
    pub(crate) fn execution_semantic_scope_construction_bytes_v1() -> Option<usize> {
        std::mem::size_of::<SourceExecutionSemanticScopeV1<'_, '_>>().checked_mul(3)
    }

    /// Splits the same Source journal under its genuine Execution18 loan.
    ///
    /// # Errors
    /// Preserves native, original, Launch/profile and Source currentness refusals.
    pub(crate) fn borrow_execution_semantic_scope_v1<'journal, 'original>(
        &'journal mut self,
        receiving: &'journal mut ControllerOperationIntakeReceivingLoanV1<'original>,
        controller: &Journal, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<SourceExecutionSemanticScopeV1<'journal, 'original>, JournalError> {
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
        let native = source.borrow_execution_scope_v1(receiving,
            controller.controller_coordinator_for_bank_read_v1()?, launch, profile)
            .map_err(JournalError::ControllerNative)?;
        Ok(SourceExecutionSemanticScopeV1 { native, semantic, pending_completion: None })
    }
}

impl<'journal, 'original> SourceExecutionSemanticScopeV1<'journal, 'original> {
    pub(crate) fn begin_execution_cold_session_v2(&mut self,
        controller: &ControllerCoordinatorWriterV1<Selection>, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1, fixed: ResourceVector,
    ) -> Result<aos_sandbox_broker::controller_receiving::ControllerInitialSessionReceivingOriginalV1,
        ControllerBankLaunchErrorV1>
    {
        self.native.begin_execution_cold_session_v2(controller, launch, profile, fixed)
    }

    pub(crate) fn require_execution_cold_session_original_v2(&self,
        receiving: &aos_sandbox_broker::controller_receiving::ControllerInitialSessionReceivingOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.native.require_execution_cold_session_original_v2(receiving)
    }

    pub(crate) fn failure(&self) -> Option<&(dyn Error + 'static)> {
        self.native.failure()
    }

    pub(crate) fn historical_view_v1(&self)
        -> Result<aos_sandbox_protocol::domain_ledger::readonly::HistoricalLedgerReadViewV1<'_>, ControllerBankLaunchErrorV1>
    {
        self.native.historical_view_v1()
    }

    pub(crate) fn require_complete_v1(&mut self, controller: &mut ControllerCoordinatorWriterV1<Selection>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
        complete: ControllerOperationIntakeDemandDataV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.native.require_complete_v1(controller, launch, profile, complete)
    }

    pub(crate) fn finish_native_once_v1(&mut self, controller: &mut ControllerCoordinatorWriterV1<Selection>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<(), ControllerBankLaunchErrorV1> {
        self.native.finish_native_once_v1(controller, launch, profile)
    }

    pub(crate) fn prepare_positive_disposal_v1<'disposal>(&'disposal mut self,
        controller: &'disposal ControllerCoordinatorWriterV1<Selection>,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
    ) -> Result<SourceExecutionScopeDisposalV1<'disposal, Selection>, ControllerBankLaunchErrorV1> {
        self.native.prepare_positive_disposal_v1(controller, launch, profile)
    }

    pub(crate) fn split_execution_read_v1<'read>(&'read mut self)
        -> Result<(SourceExecutionReadViewV1<'read>, SourceExecutionCompleteBorrowV1<'read, 'original, Selection>), ControllerBankLaunchErrorV1>
    {
        self.native.split_execution_read_v1()
    }

    /// Enters only the canonical publication prepared by the held Root client.
    ///
    /// # Errors
    /// Preserves canonical, financial, native or semantic refusal. An entered
    /// negative append must retain this owner while its independent posts run.
    pub(crate) fn prepare_environment_append_once_v1<'append>(
        &'append mut self, controller: &mut Journal,
        launch: &ControllerBankLaunchOriginalV1, profile: &ControllerSelfProfileOriginalV1,
        publication: &'append crate::environment::deployment::PreparedEnvironmentPublicationV1,
        client: &crate::normal_root::RootEnvironmentClientOriginalV1,
        clock: &'append mut crate::controller_execution_operation::ControllerExecutionClockOriginalV1,
        complete: ResourceVector,
    ) -> Result<SourceOperationSemanticAppendV1<'append, 'journal, 'original>, JournalError> {
        publication.require_same_source_v1(self.native.historical_view_v1().map_err(JournalError::ControllerNative)?)?;
        let horizon = client.source_publication_horizon_data_v1()?;
        let sample = clock.sample_v1().map_err(|_| JournalError::ProtectedBoundary)?;
        horizon.require_later_sample_v1(sample).map_err(|_| JournalError::ProtectedBoundary)?;
        let mut append = prepare_source_semantic_append_once_v1(
            SourceSemanticNativeScopeRefV1::Execution(&mut self.native),
            &mut self.semantic, &mut self.pending_completion,
            controller, launch, profile, publication.transaction_v1(), complete,
        )?;
        append.environment_clock = Some(clock);
        append.environment_horizon = Some(horizon);
        Ok(append)
    }
}

/// Borrows current comparison rows only from the actual paid Execution scope.
///
/// No public map/native/index constructor exists. The actual Source/C originals
/// remain borrowed and their independently owed outer posts still gate success.
pub(crate) struct QualifiedEnvironmentSourceViewV1<'view> {
    read: CanonicalWriterReadViewV1<'view, Selection>,
}

impl<'view> QualifiedEnvironmentSourceViewV1<'view> {
    pub(crate) fn view_v1(&self) -> CanonicalWriterReadViewV1<'view, Selection> { self.read }
}

impl SourceExecutionSemanticScopeV1<'_, '_> {
    fn qualified_environment_view_v1(&self) -> Result<QualifiedEnvironmentSourceViewV1<'_>, JournalError> {
        self.native.historical_view_v1().map_err(JournalError::ControllerNative)?;
        if self.native.failure().is_some() { return Err(JournalError::ProtectedBoundary); }
        Ok(QualifiedEnvironmentSourceViewV1 { read: self.native.semantic_read_view_v1() })
    }
}

/// Contains comparison coordinates only after real X append positive disposal.
///
/// There is no public constructor, Clone or Copy implementation. The native
/// engine still owns and checks publication, exact readback and both posts.
pub(crate) struct CompletedEnvironmentSourceAppendV1 {
    committed: CommitResult,
    following: u64,
    transaction: [u8; 16],
}

impl CompletedEnvironmentSourceAppendV1 {
    pub(crate) fn comparison_data_v1(&self) -> (CommitResult, u64, [u8; 16]) {
        (self.committed, self.following, self.transaction)
    }
}

impl SourceOperationSemanticAppendV1<'_, '_, '_> {
    fn complete_environment_readback_v1(&mut self,
        publication: &crate::environment::deployment::PreparedEnvironmentPublicationV1,
    ) -> Result<CompletedEnvironmentSourceAppendV1, JournalError> {
        if !matches!(self.native, SourceSemanticNativeAppendV1::Execution(_))
            || !std::ptr::eq(self.transaction, publication.transaction_v1())
        { return Err(JournalError::ProtectedBoundary); }
        let committed = self.primary.as_ref().and_then(|value| value.as_ref().ok()).copied()
            .ok_or(JournalError::ProtectedBoundary)?;
        let following = self.native.semantic_read_view_v1().next_sequence();
        let transaction = *self.transaction.id();
        self.prepare_positive_disposal_v1()?.complete_after_disposal_v1();
        Ok(CompletedEnvironmentSourceAppendV1 { committed, following, transaction })
    }
}

impl SourceExecutionSemanticScopeV1<'_, '_> {
    /// Publishes only the actual held Root's generation and exact execution lease.
    ///
    /// All consuming pure planning/model peaks are paid before construction.
    /// An entered negative native append runs its local and outer Source/C
    /// posts while the original remains resident, then terminates before Drop.
    ///
    /// # Errors
    /// Returns pre-entry canonical/financial refusal. No arbitrary transaction,
    /// caller expected sequence or fabricated completion enters this method.
    pub(crate) fn publish_environment_once_v1(
        &mut self, controller: &mut Journal, launch: &ControllerBankLaunchOriginalV1,
        profile: &ControllerSelfProfileOriginalV1,
        client: &mut crate::normal_root::RootEnvironmentClientOriginalV1,
        publication: &mut crate::environment::deployment::EnvironmentSourcePublicationOriginalV1,
        clock: &mut crate::controller_execution_operation::ControllerExecutionClockOriginalV1,
        complete: &mut ResourceVector,
    ) -> Result<(), JournalError> {
        let source_models = crate::environment::execution_source_receiving_demand_v1(
            self.native.historical_view_v1().map_err(JournalError::ControllerNative)?)
            .map_err(|_| JournalError::ProtectedBoundary)?;
        let construction = std::mem::size_of::<crate::environment::deployment::EnvironmentSourcePublicationOriginalV1>()
            .checked_mul(3).and_then(|bytes| u64::try_from(bytes).ok()).ok_or(JournalError::JournalTooLarge)?;
        let next = complete.checked_add(source_models)
            .and_then(|value| value.checked_add(ResourceVector::ZERO.with(D::MemoryBytes, construction)))
            .map_err(|_| JournalError::JournalTooLarge)?;
        self.native.require_complete_v1(controller.controller_coordinator_for_bank_v1()?, launch, profile,
            ControllerOperationIntakeDemandDataV1::from_demand_v1(next)).map_err(JournalError::ControllerNative)?;
        *complete = next;
        // The initial minimum has exactly Generation plus four activation
        // phases. Repeated execution on the same observed generation needs
        // one Released-phase lease successor. No failed phase is retried.
        for _ in 0..5 {
            let now = clock.sample_v1().map_err(|_| JournalError::ProtectedBoundary)?;
            let prepared = publication.prepare_next_v1(client, self.qualified_environment_view_v1()?, now)
                .map_err(|_| JournalError::ProtectedBoundary)?;
            let Some(prepared) = prepared else {
                // A later Observe may borrow the exact still-active lease
                // already validated in this SAME native Source interval. It
                // creates no second lease, append or renewed expiry.
                return Ok(());
            };
            let mut append = self.prepare_environment_append_once_v1(
                controller, launch, profile, prepared, client, clock, *complete)?;
            // This exact traffic was already admitted by the common entry,
            // before native preparation. Carry it forward without resetting
            // the same C18 slot's cumulative consumable dimensions.
            *complete = append.continued_complete;
            if append.run_once_v1().is_err() {
                // This lower original retains the actual COMMIT/readback
                // ambiguity, not a replacement JournalError or new writer.
                // The failed native append must stay resident, but it cannot
                // suppress the already-paid independent Root peer after.
                client.finish_native_after_once_v1();
                let _ = append.finish_outer_scope_once_v1(controller, launch, profile);
                let _first = append.failure();
                std::process::abort();
            }
            let completed = match append.complete_environment_readback_v1(prepared) {
                Ok(completed) => completed,
                Err(_) => {
                    client.finish_native_after_once_v1();
                    let _ = append.finish_outer_scope_once_v1(controller, launch, profile);
                    std::process::abort();
                }
            };
            drop(append);
            if publication.complete_step_v1(completed).map_err(|_| JournalError::ProtectedBoundary)? {
                return Ok(());
            }
        }
        Err(JournalError::ProtectedBoundary)
    }
}
