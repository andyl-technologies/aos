//! Managed reset requests through the node's existing QMP connection.

use std::sync::Arc;

use super::*;

/// Holds observed reset custody until its sole fresh continuation succeeds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ResetResumeState {
    Requested,
    Observed,
    Reconciled,
    InFlight,
}

/// Retains the actual original operation through uncertain reset and continuation.
#[derive(Debug)]
pub(super) struct ResetResumeTransition {
    pub(super) state: ResetResumeState,
    pub(super) original: Arc<crucible_linux_resource::host_supervision::HostOperationGuard>,
}

impl QemuNode {
    /// Resets and abandons one exact stopped request after correlated completion.
    ///
    /// The caller retains the original VM and its uncertainty through all
    /// failures. The node retains the same already-admitted original Arc before
    /// issuing the command; uncertain refusals keep that transition closed.
    /// The terminal event and empty acknowledgement are both required
    /// before the host ledger changes; no guest reply is manufactured. The next
    /// bounded step publishes its ceiling before resuming this stopped VM.
    ///
    /// # Errors
    /// Returns the actual typed QMP error or channel admission/reconciliation
    /// cause. Unsupported native cohorts refuse before a reset is scheduled.
    pub fn reset_selectable_under_original(
        &mut self,
        pending: &crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest,
        original: &Arc<crucible_linux_resource::host_supervision::HostOperationGuard>,
    ) -> Result<crate::QmpSelectableResetComplete, crate::QmpError> {
        original
            .wait_slice()
            .map_err(|error| crate::QmpError::OperationalSupervision {
                operation: "crucible-selectable-reset-v1",
                message: error.to_string(),
            })?;
        if self.selectable_resume_pending || self.reset_resume_is_pending() {
            return Err(crate::QmpError::InvalidBound {
                operation: "a selectable or reset continuation is already pending",
            });
        }
        self.channels
            .shmem_hot_path
            .validate_selectable_reset(pending)
            .map_err(|source| crate::QmpError::SelectableResetBoundary { source })?;
        // Retain the already-admitted Arc before the fallible reset boundary.
        // Even an uncertain command refusal cannot replace this original.
        let transition = self.reset_resume_pending.insert(ResetResumeTransition {
            state: ResetResumeState::Requested,
            original: Arc::clone(original),
        });
        let completion = self
            .channels
            .qmp_machine_control
            .reset_selectable_under_original(pending, original)?;
        // Preserve the required controlled resume even if host reconciliation
        // refuses. The caller must quarantine the VM, not retry a second reset.
        transition.state = ResetResumeState::Observed;
        self.channels
            .shmem_hot_path
            .abandon_selectable_after_reset(pending)
            .map_err(|source| crate::QmpError::SelectableResetBoundary { source })?;
        original
            .wait_slice()
            .map_err(|error| crate::QmpError::OperationalSupervision {
                operation: "reconcile selectable reset",
                message: error.to_string(),
            })?;
        transition.state = ResetResumeState::Reconciled;
        Ok(completion)
    }

    /// Resumes a reconciled reset to a fresh idle boundary and captures its sample.
    ///
    /// This requires the same original Arc retained when reset was requested; a
    /// different live operation refuses before effects. Every continuation effect
    /// borrows the retained guard through the authenticated-idle scheduler and
    /// fresh capture. This creates no operation, clock, bank or Arc allocation.
    /// The sample still excludes an independent physical RAM/non-RAM oracle;
    /// callers separately validate the reset ROM output and full expected state.
    ///
    /// # Errors
    /// Refuses absent reset continuation, original supervision loss, a ceiling
    /// reached before idle, or an actual advance/capture/channel failure.
    pub fn resume_reset_to_fresh_idle_under_original(
        &mut self,
        liveness_ceiling: Icount,
        original: &Arc<crucible_linux_resource::host_supervision::HostOperationGuard>,
    ) -> Result<ExecutionFingerprint, QemuNodeError> {
        let retained = self.reset_resume_pending.as_ref().ok_or_else(|| {
            QemuNodeError::checkpoint("no reconciled reset awaits its controlled resume")
        })?;
        if !Arc::ptr_eq(&retained.original, original) {
            return Err(QemuNodeError::checkpoint(
                "reset continuation requires its retained original operation",
            ));
        }
        if retained.state != ResetResumeState::Reconciled {
            return Err(QemuNodeError::checkpoint(
                "no reconciled reset awaits its controlled resume",
            ));
        }
        // All effects borrow the retained original, rather than caller metadata.
        let original = Arc::clone(&retained.original);
        if self
            .channels
            .shmem_hot_path
            .selectable_catalog_plan()
            .is_none_or(|plan| plan.continuation().pending().is_some())
        {
            return Err(QemuNodeError::checkpoint(
                "reset host reconciliation did not complete",
            ));
        }
        original.wait_slice().map_err(|source| {
            QemuNodeError::from_async_driver(crate::QemuAsyncDriverError::Runtime(
                crate::QemuAsyncDriverRuntimeError::operational_supervision(
                    "resume reset to authenticated idle",
                    source,
                ),
            ))
        })?;
        if self.channels.shmem_hot_path.coverage_enabled()
            || self.bounded_scheduler_preemption.is_some()
        {
            return Err(QemuNodeError::checkpoint(
                "reset idle resume does not accept coverage or diagnostic preemption",
            ));
        }
        // A failed continuation retains this state. It must never be replayed
        // through an ordinary advance or used as checkpoint readiness.
        self.reset_resume_pending
            .as_mut()
            .ok_or_else(|| QemuNodeError::checkpoint("retained reset transition is unavailable"))?
            .state = ResetResumeState::InFlight;
        let report = self.advance_reset_under_original(liveness_ceiling, &original)?;
        if !report.emitted_frames.is_empty() {
            return Err(QemuNodeError::checkpoint(
                "reset idle resume produced an unexpected network boundary",
            ));
        }
        let outcome = self.finish_advance_report(liveness_ceiling, report)?;
        if outcome == AdvanceOutcome::ReachedHorizon || self.idle_state()?.next_deadline.is_none() {
            return Err(QemuNodeError::checkpoint(
                "reset reached its bound without a fresh authenticated idle",
            ));
        }
        let fingerprint = self.fresh_execution_fingerprint_under_original(&original)?;
        self.reset_resume_pending = None;
        Ok(fingerprint)
    }

    fn advance_reset_under_original(
        &mut self,
        ceiling: Icount,
        original: &crucible_linux_resource::host_supervision::HostOperationGuard,
    ) -> Result<crate::QemuAsyncNodeStepReport, QemuNodeError> {
        let mut target = QemuNodeAsyncStepTarget {
            #[cfg(any(test, feature = "test-support"))]
            block_completion_observer: self.block_completion_observer.clone(),
            ram_registration: self.host_io_runtime.ram_control_registration().cloned(),
            #[cfg(target_os = "linux")]
            ram_continuation: self.hot_fork_ram_continuation.as_deref(),
            child: &mut self.child,
            channels: &mut self.channels,
            lifecycle_state: &mut self.lifecycle_state,
            shutdown_policy: self.shutdown_policy,
            supervisor: self.host_io_runtime.host_operation_supervisor().cloned(),
            stop_condition: crate::QemuQuantumStopCondition::NextAuthenticatedIdle,
        };
        crate::async_driver::run_qemu_node_step_under_original(
            &mut target,
            self.host_io_runtime.as_mut(),
            self.async_policy,
            &self.crash_detector,
            ExecutionHorizon { icount: ceiling },
            |target, _pending| {
                target
                    .channels
                    .qmp_machine_control
                    .resume_after_checkpoint_under_original(original)
            },
            original,
        )
        .map_err(QemuNodeError::from_async_driver)
    }

    /// Forces and reads a fresh execution fingerprint under the original guard.
    ///
    /// A reset can change RAM without advancing icount. This method always
    /// requests a new capture before consulting the shared sample, so an older
    /// same-icount sample cannot satisfy the reset witness. The caller separately
    /// establishes reset completion and a fresh authenticated idle boundary.
    ///
    /// # Errors
    /// Returns the actual capture, supervision or shared-sample error. Unsupported
    /// runtimes refuse before effects; the original operation remains caller-owned.
    pub fn fresh_execution_fingerprint_under_original(
        &mut self,
        original: &crucible_linux_resource::host_supervision::HostOperationGuard,
    ) -> Result<ExecutionFingerprint, QemuNodeError> {
        self.host_io_runtime
            .publish_current_execution_fingerprint_under_original(original)
            .map_err(|source| {
                QemuNodeError::from_async_driver(crate::QemuAsyncDriverError::Runtime(source))
            })?;
        let fingerprint = self
            .channels
            .shmem_hot_path
            .execution_fingerprint()
            .map_err(|source| {
                QemuNodeError::from_channel(QemuNodeChannelPlane::ShmemHotPath, source)
            })?;
        original.wait_slice().map_err(|source| {
            QemuNodeError::from_async_driver(crate::QemuAsyncDriverError::Runtime(
                crate::QemuAsyncDriverRuntimeError::operational_supervision(
                    "fresh execution fingerprint",
                    source,
                ),
            ))
        })?;
        Ok(fingerprint)
    }
}
