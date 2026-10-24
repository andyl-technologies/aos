//! Runs an exported Target while its original Main body retains native custody.
//!
//! The runtime owns only the operation view and the original counted retirement
//! observer. Main keeps the constructor, aggregate, exact native loans and source
//! checkout. Actual Loop return and destruction precede native settlement.

use super::target_construction::{PendingTargetConstruction, finalize_target_terminal};
use super::*;
use crate::lifecycle_cleanup::PreparedSourceRetirement;
use crate::vm_lifecycle::MainSourceLifecycle;
use crate::{
    CapturedAttemptCheckpoint, ProductionFaultEvidenceSnapshot, ProductionVmNodeReplayLaunchProfile,
};
use crucible_engine::{
    Configuration, FingerprintSample, NodeId, QuantumOutcome, QuantumRequest,
    QuantumTerminalVerdict, SchedulerEventLogEntry, SelectionDecision, VirtualTime,
};
use crucible_qemu_protocol::SelectionReply;
use crucible_qemu_host::{QemuNodeSelectablePendingRequest, QemuParkedCampaignMarker};

/// Keeps terminal custody until its original source checkout is handed back.
pub(crate) struct TargetRetirement<F> {
    observer: Option<PreparedSourceRetirement>,
    terminal: Option<crate::ProductionVmConstructionPostBody>,
    source: Option<QemuHotForkSourceWorldLease>,
    factory: std::marker::PhantomData<fn() -> F>,
    history_reported: bool,
    completed: bool,
    source_supervision_restored: bool,
}

impl<F> TargetRetirement<F>
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    /// Moves the actual observer reserved before exporting the VM body.
    pub(crate) fn new(observer: PreparedSourceRetirement) -> Self {
        Self {
            observer: Some(observer),
            terminal: None,
            source: None,
            factory: std::marker::PhantomData,
            history_reported: false,
            completed: false,
            source_supervision_restored: false,
        }
    }

    /// Performs one bounded pass under the existing Main retirement owner.
    ///
    /// # Errors
    /// Moves this same counted observer into a report over the original cause
    /// when physical cleanup refused. No replacement owning error is allocated.
    pub(crate) fn poll(
        &mut self,
    ) -> Result<AttemptExecutionReconciliationStep, crate::ProductionVmConstructionCleanupError>
    {
        if self.completed {
            return Ok(AttemptExecutionReconciliationStep::Complete);
        }
        if let Some(observer) = self.observer.as_mut() {
            match observer.retry() {
                Ok(true) => {}
                Ok(false)
                | Err(crate::PreparedSourceRefusal::Pending)
                | Err(crate::PreparedSourceRefusal::Borrowed) => {
                    return Ok(AttemptExecutionReconciliationStep::Progressed);
                }
                Err(_) => {
                    return Err(crate::ProductionVmConstructionCleanupError::Prepared(
                        observer.report_failure("retire original Target body"),
                    ));
                }
            }
            let mut historical = false;
            if !observer.with_history(|_, _| historical = true) {
                return Ok(AttemptExecutionReconciliationStep::Progressed);
            }
            if historical && !self.history_reported {
                self.history_reported = true;
                return Err(crate::ProductionVmConstructionCleanupError::Prepared(
                    observer.report_failure("original Target cleanup retained history"),
                ));
            }
            let Some(observer) = self.observer.take() else {
                return Ok(AttemptExecutionReconciliationStep::Progressed);
            };
            match observer.finish() {
                Ok(body) => self.terminal = Some(body),
                Err(observer) => {
                    self.observer = Some(observer);
                    return Ok(AttemptExecutionReconciliationStep::Progressed);
                }
            }
        }
        let Some(body) = self.terminal.as_mut() else {
            return Err(crate::ProductionVmConstructionCleanupError::Retained(
                "Target terminal custody remains unavailable",
            ));
        };
        if self.source.is_none() {
            self.source = finalize_target_terminal::<F>(body);
        }
        if self.source.is_none() {
            return Ok(AttemptExecutionReconciliationStep::Progressed);
        }
        if !self.source_supervision_restored {
            // Native Target return and pure terminal metadata handback already
            // finished. Source validation may perform IO, so it runs here,
            // outside the terminal metadata projection and all Main cell locks.
            let Some(owner) = self
                .source
                .as_ref()
                .and_then(|source| source.source_owner())
            else {
                return Err(crate::ProductionVmConstructionCleanupError::Retained(
                    "original Source supervision owner is unavailable",
                ));
            };
            let Ok(mut source) = owner.try_lock() else {
                return Ok(AttemptExecutionReconciliationStep::Progressed);
            };
            source.restore_retained_service_supervisor()?;
            self.source_supervision_restored = true;
        }
        // The exact checkout is already retained above. Dispose terminal fields
        // and the same paid Main header before its provider can reuse Source.
        drop(self.terminal.take());
        self.completed = true;
        Ok(AttemptExecutionReconciliationStep::Complete)
    }

    /// Moves only the actually returned original source checkout.
    pub(crate) fn take_source(&mut self) -> Option<QemuHotForkSourceWorldLease> {
        self.source.take()
    }
}

/// Holds the live operation-only VM view before its original Main return.
pub(crate) struct PreparedTargetRuntime<F> {
    // Automatic destruction returns the actual body before dropping its observer.
    body: Option<MainSourceLifecycle>,
    retirement: TargetRetirement<F>,
    prepared: crate::PreparedSourceSelector,
    runtime_basis: crate::AttemptExecutionRuntimeBasis,
    shutdown_complete: bool,
    shutdown_events: Option<Vec<crucible_engine::SchedulerEventLogEntry>>,
    completed_quanta: u64,
    pending_network_output: usize,
    terminal_verdict: Option<crucible_engine::QuantumTerminalVerdict>,
    disposition: Option<AttemptExecutionDisposition>,
}

impl<F> PreparedTargetRuntime<F>
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    /// Moves existing owners after the original committed export succeeds.
    pub(crate) fn new(
        body: MainSourceLifecycle,
        prepared: crate::PreparedSourceSelector,
        retirement: TargetRetirement<F>,
        runtime_basis: crate::AttemptExecutionRuntimeBasis,
    ) -> Self {
        Self {
            body: Some(body),
            prepared,
            retirement,
            runtime_basis,
            shutdown_complete: false,
            shutdown_events: None,
            completed_quanta: 0,
            pending_network_output: 0,
            terminal_verdict: None,
            disposition: None,
        }
    }

    /// Copies total and maximum fork durations from the live original Main body.
    ///
    /// # Errors
    /// Refuses unavailable, borrowed or retiring original construction storage.
    #[cfg(test)]
    pub(crate) fn node_launch_timing_summary(
        &self,
    ) -> Result<Option<(u64, u64)>, crate::lifecycle_cleanup::ServiceMainPreclaimError> {
        self.prepared
            .typed::<PendingTargetConstruction<F>>()
            .with_prepared(|pending| pending.node_launch_timing_summary())
    }

    fn owner(&self) -> Result<&dyn QemuFreshAttemptLifecycleOwner, SchedulerError> {
        self.body
            .as_ref()
            .and_then(MainSourceLifecycle::lifecycle)
            .ok_or_else(returned_body)
    }

    fn owner_mut(&mut self) -> Result<&mut dyn QemuFreshAttemptLifecycleOwner, SchedulerError> {
        self.body
            .as_mut()
            .and_then(MainSourceLifecycle::lifecycle_mut)
            .ok_or_else(returned_body)
    }

    /// Returns the exact checkout only after factual native and terminal return.
    ///
    /// # Errors
    /// Returns this same runtime when retirement still owns any native obligation.
    pub(crate) fn into_source_lease(mut self) -> Result<QemuHotForkSourceWorldLease, Self> {
        match self.retirement.take_source() {
            Some(source) => Ok(source),
            None => Err(self),
        }
    }

    /// Promotes the same live Loop while retaining its original Target lineage.
    ///
    /// # Errors
    /// Refuses a returned or shut-down body, or actual source preparation. The
    /// original Main return pair retains every partial preparation on refusal.
    pub(crate) fn promote_into_descendant_template(
        mut self,
        ancestor: Option<Box<PreparedTargetLineage<F>>>,
    ) -> Result<
        (ProductionVmHotForkSourceWorld, PreparedTargetLineage<F>),
        crucible_control_api::LifecycleApiError,
    > {
        if self.shutdown_complete || self.shutdown_events.is_some() {
            return Err(crucible_control_api::LifecycleApiError::LoopFactory {
                message: String::from("Target promotion requires its live unreconciled body"),
            });
        }
        let lifecycle = self
            .body
            .take()
            .and_then(MainSourceLifecycle::into_lifecycle)
            .ok_or(crucible_control_api::LifecycleApiError::ConstructionCustodyUnavailable)?;
        let source = lifecycle
            .promote_hot_fork_child_source_world()
            .map_err(|failure| {
                // This original failure carries its own Main pair and routes its
                // whole partial Source back there when the report is disposed.
                drop(failure);
                crucible_control_api::LifecycleApiError::LoopFactory {
                    message: String::from("prepare original Target as descendant template"),
                }
            })?;
        Ok((
            source,
            PreparedTargetLineage {
                retirement: self.retirement,
                ancestor,
                parent: None,
                started: false,
                child_returned: false,
                completed: false,
            },
        ))
    }
}

/// Retains actual ancestor return obligations while a promoted child is live.
pub(crate) struct PreparedTargetLineage<F> {
    retirement: TargetRetirement<F>,
    ancestor: Option<Box<Self>>,
    parent: Option<QemuHotForkSourceWorldLease>,
    started: bool,
    child_returned: bool,
    completed: bool,
}

impl<F> PreparedTargetLineage<F>
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    /// Returns the actual promoted Source to its own original Main carrier.
    pub(crate) fn begin_retirement(&mut self, source: ProductionVmHotForkSourceWorld) {
        // Source's destructor performs its canonical Main handoff. It does not
        // run native cleanup under this caller or invent a Source-role grant.
        drop(source);
        self.started = true;
    }

    /// Advances one bounded descendant-to-ancestor retirement pass.
    ///
    /// # Errors
    /// Retains every actual observer and parent checkout on cleanup refusal.
    pub(crate) fn poll(&mut self) -> Result<bool, crate::ProductionVmConstructionCleanupError> {
        if self.completed {
            return Ok(true);
        }
        if !self.started {
            return Err(crate::ProductionVmConstructionCleanupError::Retained(
                "promoted Target source has not returned to Main",
            ));
        }
        if !self.child_returned {
            if self.retirement.poll()? != AttemptExecutionReconciliationStep::Complete {
                return Ok(false);
            }
            self.parent = self.retirement.take_source();
            if self.parent.is_none() {
                return Ok(false);
            }
            self.child_returned = true;
        }
        if let Some(parent) = self.parent.take() {
            match parent.into_exclusive_source() {
                Ok(parent) => match self.ancestor.as_mut() {
                    Some(ancestor) => ancestor.begin_retirement(parent),
                    None => drop(parent),
                },
                Err(parent) => {
                    self.parent = Some(parent);
                    return Ok(false);
                }
            }
        }
        if let Some(ancestor) = self.ancestor.as_mut() {
            if !ancestor.poll()? {
                return Ok(false);
            }
        }
        self.completed = true;
        Ok(true)
    }
}

fn returned_body() -> SchedulerError {
    SchedulerError::BoundaryViolation {
        message: String::from("Target lifecycle has returned to its original Main owner"),
    }
}

impl<F> QemuHotForkWorldLifecycleOwner for PreparedTargetRuntime<F>
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    fn runtime_basis(&self) -> crate::AttemptExecutionRuntimeBasis {
        self.runtime_basis
    }

    fn start_materialization(
        &self,
    ) -> Result<crate::QemuFreshStartMaterialization, SchedulerError> {
        self.body
            .as_ref()
            .and_then(|body| {
                body.with_lifecycle(crate::qemu_hot_fork_world::materialize_hot_fork_start)
            })
            .ok_or_else(returned_body)?
    }

    fn reconcile_execution_disposition(
        &mut self,
        disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, crate::ProductionVmConstructionCleanupError>
    {
        if !self.shutdown_complete {
            return Err(crate::ProductionVmConstructionCleanupError::Retained(
                "Target publication reconciliation preceded actual shutdown",
            ));
        }
        if self.disposition.is_some_and(|saved| saved != disposition) {
            return Err(crate::ProductionVmConstructionCleanupError::Retained(
                "Target publication disposition changed after its original return",
            ));
        }
        if let Some(body) = self.body.as_mut() {
            self.prepared
                .typed::<PendingTargetConstruction<F>>()
                .with_prepared(|pending| pending.record_disposition(disposition))
                .map_err(|_| {
                    crate::ProductionVmConstructionCleanupError::Retained(
                        "Target disposition projection remains unavailable",
                    )
                })??;
            self.disposition = Some(disposition);
            body.with_lifecycle_mut(|lifecycle| lifecycle.release_reaped_hot_fork_process_loans())
                .ok_or(crate::ProductionVmConstructionCleanupError::Retained(
                    "Target modeled process-loan body is absent",
                ))??;
            body.return_to_main();
            drop(self.body.take());
        }
        self.retirement.poll()
    }
}

impl<F> QemuFreshAttemptLifecycleOwner for PreparedTargetRuntime<F>
where
    F: QemuAttemptResourceGuardFactory + Send + 'static,
    F::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    fn enable_signal_fault_campaign_promotion(&mut self) {
        if let Ok(owner) = self.owner_mut() {
            owner.enable_signal_fault_campaign_promotion();
        }
    }

    fn set_attempt_stop_frontier(
        &mut self,
        frontier: Option<VirtualTime>,
    ) -> Result<(), SchedulerError> {
        self.owner_mut()?.set_attempt_stop_frontier(frontier)
    }

    fn set_live_network_choice_pause(&mut self, enabled: bool) {
        if let Ok(owner) = self.owner_mut() {
            owner.set_live_network_choice_pause(enabled);
        }
    }

    fn set_choice_free_parallel_boot(&mut self, enabled: bool) {
        if let Ok(owner) = self.owner_mut() {
            owner.set_choice_free_parallel_boot(enabled);
        }
    }

    fn live_network_preselection(&self) -> Option<crucible_engine::LiveNetworkPreselection> {
        self.owner()
            .ok()
            .and_then(|owner| owner.live_network_preselection())
    }

    fn select_live_network_preselection(
        &mut self,
        selection: SelectionDecision,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.owner_mut()?
            .select_live_network_preselection(selection)
    }

    fn settle_live_network_preselection(&mut self) -> Result<QuantumOutcome, SchedulerError> {
        self.owner_mut()?.settle_live_network_preselection()
    }

    fn handoff_live_network_preselection(
        &mut self,
        expected: &crucible_engine::LiveNetworkPreselection,
    ) -> Result<(), SchedulerError> {
        self.owner_mut()?
            .handoff_live_network_preselection(expected)
    }

    fn drive_quantum(&mut self, request: QuantumRequest) -> Result<QuantumOutcome, SchedulerError> {
        self.owner_mut()?.drive_quantum(request)
    }

    fn completed_quanta(&self) -> u64 {
        self.owner()
            .map_or(self.completed_quanta, |owner| owner.completed_quanta())
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<QuantumTerminalVerdict> {
        match self.owner_mut() {
            Ok(owner) => owner.terminal_verdict_for_stop(),
            Err(_) => self.terminal_verdict.clone(),
        }
    }

    fn prepare_terminal_checkpoint(
        &mut self,
        cause: crucible_engine::CheckpointTerminalCause,
    ) -> Result<(), SchedulerError> {
        self.owner_mut()?.prepare_terminal_checkpoint(cause)
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError> {
        self.owner_mut()?.exact_checkpoint_ready()
    }

    fn parked_campaign_marker(
        &mut self,
        node: &NodeId,
    ) -> Result<Option<QemuParkedCampaignMarker>, SchedulerError> {
        self.owner_mut()?.parked_campaign_marker(node)
    }

    fn release_parked_campaign_marker(
        &mut self,
        node: &NodeId,
        marker: &str,
        selected: ContentHash,
    ) -> Result<(), SchedulerError> {
        self.owner_mut()?
            .release_parked_campaign_marker(node, marker, selected)
    }

    fn campaign_marker_release_committed(
        &self,
        node: &NodeId,
        marker: &str,
        selected: ContentHash,
    ) -> Result<bool, SchedulerError> {
        self.owner()?
            .campaign_marker_release_committed(node, marker, selected)
    }

    fn campaign_network_queues_empty(&self) -> Result<bool, SchedulerError> {
        self.owner()?.campaign_network_queues_empty()
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<QemuNodeSelectablePendingRequest>, SchedulerError> {
        self.owner_mut()?.drain_pending_selectable_requests()
    }

    fn pending_selectable_request_time(
        &self,
        pending: &QemuNodeSelectablePendingRequest,
    ) -> Result<VirtualTime, SchedulerError> {
        self.owner()?.pending_selectable_request_time(pending)
    }

    fn apply_selectable_reply(
        &mut self,
        parent: &Configuration,
        decision: SelectionDecision,
        selected: &Configuration,
        pending: &QemuNodeSelectablePendingRequest,
        reply: &SelectionReply,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        self.owner_mut()?
            .apply_selectable_reply(parent, decision, selected, pending, reply)
    }

    fn capture_attempt_checkpoint(
        &mut self,
        context: &AttemptExecutionContext,
    ) -> Result<CapturedAttemptCheckpoint, SchedulerError> {
        self.owner_mut()?.capture_attempt_checkpoint(context)
    }

    fn replay_launch_profiles(
        &self,
    ) -> Result<Vec<ProductionVmNodeReplayLaunchProfile>, SchedulerError> {
        self.owner()?.replay_launch_profiles()
    }

    fn fault_evidence_snapshot(&self) -> Result<ProductionFaultEvidenceSnapshot, SchedulerError> {
        self.owner()?.fault_evidence_snapshot()
    }

    fn pending_network_output_count(&self) -> usize {
        self.owner().map_or(self.pending_network_output, |owner| {
            owner.pending_network_output_count()
        })
    }

    fn sample_fingerprint(&mut self, node: NodeId) -> Result<FingerprintSample, SchedulerError> {
        self.owner_mut()?.sample_fingerprint(node)
    }

    fn prepare_terminal_fingerprints(&mut self) -> Result<(), SchedulerError> {
        self.owner_mut()?.prepare_terminal_fingerprints()
    }

    fn resolved_effect_trace(&self) -> Result<Option<Vec<u8>>, SchedulerError> {
        self.owner()?.resolved_effect_trace()
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        if self.shutdown_complete {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("Target lifecycle was shut down more than once"),
            });
        }
        if self.shutdown_events.is_none() {
            self.shutdown_events = Some(self.owner_mut()?.shutdown()?);
            self.completed_quanta = self.owner()?.completed_quanta();
            self.pending_network_output = self.owner()?.pending_network_output_count();
            self.terminal_verdict = self.owner_mut()?.terminal_verdict_for_stop();
        }
        let accepted = self
            .prepared
            .typed::<PendingTargetConstruction<F>>()
            .with_prepared(|pending| match pending.finish_modeled_shutdown() {
                Ok(()) => true,
                Err(first) => {
                    pending.retain_api_failure(first);
                    false
                }
            })
            .map_err(|first| SchedulerError::BoundaryViolation {
                message: first.to_string(),
            })?;
        if !accepted {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("original Target retains its shutdown handoff failure"),
            });
        }
        self.shutdown_complete = true;
        self.shutdown_events.take().ok_or_else(returned_body)
    }
}
