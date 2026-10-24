//! Async quantum stepping and crash-triggered child shutdown adaptation.

use super::*;

pub(super) struct QemuNodeAsyncStepTarget<'a> {
    #[cfg(any(test, feature = "test-support"))]
    pub(super) block_completion_observer:
        Option<std::sync::Arc<dyn crate::QemuTestBlockCompletionObserver>>,
    pub(super) child: &'a mut QemuNodeProcessControl,
    pub(super) channels: &'a mut QemuNodeChannels,
    pub(super) lifecycle_state: &'a mut QemuNodeLifecycleState,
    pub(super) shutdown_policy: QemuShutdownPolicy,
    pub(super) child_shutdown: &'a mut super::shutdown_continuation::ChildShutdown,
    pub(super) ram_registration: Option<crate::ram_control::RamControlRegistration>,
    pub(super) supervisor:
        Option<crucible_host_resources::host_supervision::HostOperationSupervisor>,
    pub(super) stop_condition: crate::QemuQuantumStopCondition,
    #[cfg(target_os = "linux")]
    pub(super) ram_continuation: Option<&'a super::hot_fork_ram_stage::QemuHotForkRamContinuation>,
}

impl QemuAsyncCrashEscalationTarget for QemuNodeAsyncStepTarget<'_> {
    fn shutdown_after_crash(&mut self) -> Result<QemuShutdownReport, QemuAsyncDriverTargetError> {
        self.child_shutdown
            .close(
                self.child,
                self.channels,
                self.lifecycle_state,
                self.shutdown_policy,
                self.supervisor.as_ref(),
            )
            .map_err(|error| {
                QemuAsyncDriverTargetError::new("shutdown after crash", error.to_string())
            })
    }
}

impl QemuAsyncNodeStepTarget for QemuNodeAsyncStepTarget<'_> {
    type PendingQuantum = QemuNodePendingQuantum;

    fn operational_health(&self) -> Result<(), crate::QemuAsyncDriverHealthError> {
        super::operational_health::check_child_sources(self.child)?;
        super::operational_health::native_actor::check(self.ram_registration.as_ref())?;
        #[cfg(target_os = "linux")]
        if let Some(source) = self
            .ram_continuation
            .and_then(|continuation| continuation.source.as_ref())
        {
            source
                .check_health()
                .map_err(crate::QemuAsyncDriverHealthError::ram_source)?;
        }
        Ok(())
    }

    fn child_exit_status(
        &mut self,
    ) -> Result<Option<std::process::ExitStatus>, QemuAsyncDriverTargetError> {
        self.child
            .try_wait_natural_exit()
            .map_err(|error| QemuAsyncDriverTargetError::new("poll QEMU child", error.to_string()))
    }

    fn start_quantum(
        &mut self,
        horizon: ExecutionHorizon,
    ) -> Result<Self::PendingQuantum, QemuNodeChannelError> {
        self.channels
            .shmem_hot_path
            .start_quantum(horizon, self.stop_condition)
    }

    fn start_quantum_with_publication(
        &mut self,
        horizon: ExecutionHorizon,
        publication: Option<crate::QemuQuantumPublication<'_>>,
    ) -> Result<Self::PendingQuantum, QemuNodeChannelError> {
        self.channels.shmem_hot_path.start_quantum_with_publication(
            horizon,
            self.stop_condition,
            publication,
        )
    }

    fn advance_completion_fence(
        &self,
        pending: &Self::PendingQuantum,
    ) -> Option<QemuAdvanceCompletionFence> {
        pending.completion_fence()
    }

    fn finish_quantum(
        &mut self,
        pending: &mut Self::PendingQuantum,
    ) -> Result<QemuAsyncQuantumCompletion, QemuNodeChannelError> {
        #[cfg(any(test, feature = "test-support"))]
        super::block_completion_observation::observe_pending_completion(
            self.channels,
            self.block_completion_observer.as_deref(),
        )?;
        self.channels.shmem_hot_path.poll_quantum(pending)
    }
}
