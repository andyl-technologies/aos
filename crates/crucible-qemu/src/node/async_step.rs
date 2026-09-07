//! Async quantum stepping and crash-triggered child shutdown adaptation.

use super::*;

pub(super) struct QemuNodeAsyncStepTarget<'a> {
    pub(super) child: &'a mut QemuNodeProcessControl,
    pub(super) channels: &'a mut QemuNodeChannels,
    pub(super) lifecycle_state: &'a mut QemuNodeLifecycleState,
    pub(super) shutdown_policy: QemuShutdownPolicy,
}

impl QemuAsyncCrashEscalationTarget for QemuNodeAsyncStepTarget<'_> {
    fn shutdown_after_crash(&mut self) -> Result<QemuShutdownReport, QemuAsyncDriverTargetError> {
        shutdown_node_child(
            self.child,
            self.channels,
            self.lifecycle_state,
            self.shutdown_policy,
        )
        .map_err(|error| QemuAsyncDriverTargetError::new("shutdown after crash", error.to_string()))
    }
}

impl QemuAsyncNodeStepTarget for QemuNodeAsyncStepTarget<'_> {
    type PendingQuantum = QemuNodePendingQuantum;

    fn start_quantum(
        &mut self,
        horizon: ExecutionHorizon,
    ) -> Result<Self::PendingQuantum, QemuNodeChannelError> {
        self.channels.shmem_hot_path.start_quantum(horizon)
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
        self.channels.shmem_hot_path.poll_quantum(pending)
    }
}

pub(super) fn shutdown_node_child(
    child: &mut QemuNodeProcessControl,
    channels: &mut QemuNodeChannels,
    lifecycle_state: &mut QemuNodeLifecycleState,
    shutdown_policy: QemuShutdownPolicy,
) -> Result<QemuShutdownReport, QemuNodeError> {
    let report = if child.reaped() {
        QemuShutdownReport {
            attempts: Vec::new(),
            failures: Vec::new(),
            reaped: true,
            leaked: false,
        }
    } else {
        let mut target = QemuNodeShutdownTarget {
            child,
            plugin_control: channels.plugin_control.as_mut(),
            qmp_machine_control: channels.qmp_machine_control.as_mut(),
        };
        shutdown_qemu_child(&mut target, shutdown_policy).map_err(QemuNodeError::from_shutdown)?
    };

    channels
        .qmp_machine_control
        .retire_process_scoped_endpoints_after_reap();
    *lifecycle_state = QemuNodeLifecycleState::ShutdownRequested;
    Ok(report)
}
