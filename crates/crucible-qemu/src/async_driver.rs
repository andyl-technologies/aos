//! Bounded host-I/O bridge for QEMU node steps.
//!
//! The scheduler calls a synchronous node-step API, while QEMU lifecycle I/O is
//! host-real-time work: setup handshakes, QMP commands, child process events, and
//! the bounded wait for a plugin-published quantum completion. This module keeps
//! that boundary explicit without making host timing an ordering input. A node
//! step starts exactly one shared-memory quantum, awaits completion with an
//! explicit timeout budget, finishes the quantum from shared memory, and yields
//! back to the control plane at the quantum boundary.

use std::time::Duration;

use crucible::{AdvanceOutcome, ExecutionHorizon, Icount};
use crucible_shmem::DequeuedFaultResult;
use thiserror::Error;

use crate::{
    QemuCrashDetector, QemuNodeChannelError, QemuNodeRunStatus, QemuQuantumOperation,
    QemuQuantumOperationPlane, QemuQuantumReport, QemuShutdownReport,
};

const ADVANCE_COMPLETION_OPERATION: &str = "advance completion";

/// Timeout policy for QEMU host-I/O awaits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuAsyncDriverPolicy {
    /// Timeout for plugin setup handshakes.
    pub handshake_timeout: Duration,
    /// Timeout for QMP commands at lifecycle boundaries.
    pub qmp_command_timeout: Duration,
    /// Timeout for child process status awaits.
    pub process_event_timeout: Duration,
    /// Timeout for the plugin to publish one quantum completion report.
    pub advance_completion_timeout: Duration,
}

#[path = "async_driver/policy.rs"]
mod policy;

/// One class of host-I/O wait performed outside virtual time.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum QemuAsyncWait {
    /// Plugin setup handshake traffic.
    Handshake,
    /// QMP command or job-poll traffic at a lifecycle boundary.
    QmpCommand,
    /// Child process status or exit detection.
    ProcessEvent,
    /// Plugin publication of one shared-memory quantum completion.
    AdvanceCompletion,
}

impl QemuAsyncWait {
    fn operation(self) -> &'static str {
        match self {
            Self::Handshake => "handshake",
            Self::QmpCommand => "QMP command",
            Self::ProcessEvent => "process event",
            Self::AdvanceCompletion => ADVANCE_COMPLETION_OPERATION,
        }
    }
}

/// Result of one bounded host-I/O await.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuAsyncWaitOutcome {
    /// The awaited child event completed within its budget.
    Completed,
    /// The timeout budget expired.
    TimedOut,
}

/// One host-I/O runtime operation recorded by the async driver.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuAsyncDriverOperation {
    /// Yielded the host-I/O runtime back to the control plane.
    YieldToControlPlane,
    /// Awaited one child event with an explicit timeout.
    AwaitChild {
        /// Wait class.
        wait: QemuAsyncWait,
        /// Timeout used for the await.
        timeout: Duration,
        /// Await result.
        outcome: QemuAsyncWaitOutcome,
    },
    /// Requested shutdown escalation after a timeout crash.
    ShutdownAfterCrash,
}

/// Host-I/O runtime used by the bounded async driver.
pub trait QemuHostIoRuntime: Send {
    /// Arms the publication fence for the next advance-completion wait.
    ///
    /// Live runtimes retain the supplied pre-wake generation until the plugin
    /// publishes the scheduler input that invalidated its prior idle report.
    /// Runtimes without a live shared-memory executor ignore the fence.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when the runtime cannot arm the
    /// requested completion fence.
    fn arm_advance_completion_fence(
        &mut self,
        _fence: Option<QemuAdvanceCompletionFence>,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        Ok(())
    }

    /// Reports whether QEMU owns no in-flight device coroutine at this boundary.
    ///
    /// Runtimes without a live external executor are always quiescent. A live
    /// runtime overrides this method with an acquire snapshot of its shared
    /// node slot.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when the live node slot cannot be
    /// inspected consistently.
    fn checkpoint_device_io_is_quiescent(&mut self) -> Result<bool, QemuAsyncDriverRuntimeError> {
        Ok(true)
    }

    /// Probes QEMU's main-loop device boundary without requesting a pause.
    ///
    /// Live runtimes use this to expose device work queued behind an otherwise
    /// quiescent slot before the caller commits to an exact checkpoint
    /// coordinate. Runtimes without an external executor remain ready.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when the probe cannot be
    /// acknowledged or serviced within `timeout`.
    fn probe_checkpoint_device_io(
        &mut self,
        _timeout: Duration,
    ) -> Result<bool, QemuAsyncDriverRuntimeError> {
        self.checkpoint_device_io_is_quiescent()
    }

    /// Requests a coordinated shared-memory pause and waits for quiescence.
    ///
    /// Runtimes without a live external executor have nothing to pause. A live
    /// runtime overrides this method and must fail closed when the pause is not
    /// acknowledged within `timeout`.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when the pause cannot be
    /// requested, acknowledged, or serviced within the supplied bound.
    fn quiesce_for_checkpoint(
        &mut self,
        _timeout: Duration,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        Ok(())
    }

    /// Clears a coordinated plugin pause while QEMU is already stopped.
    ///
    /// This operation must not wake the plugin's scheduler futex or main-loop
    /// doorbell. A vCPU-idle callback owns QEMU's big lock while it waits on
    /// that futex; waking it while QMP deliberately holds the VM stopped can
    /// strand the following VMState command behind that lock.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when the live executor cannot
    /// clear the checkpoint barrier without making it runnable.
    fn clear_checkpoint_pause_while_stopped(&mut self) -> Result<(), QemuAsyncDriverRuntimeError> {
        Ok(())
    }

    /// Aborts a plugin checkpoint pause while QEMU may still be running.
    ///
    /// Unlike [`Self::clear_checkpoint_pause_while_stopped`], rollback must
    /// wake both plugin wait mechanisms so a failed pre-stop transaction cannot
    /// leave the process stranded behind a cleared flag.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when the live executor cannot
    /// clear and actively release the failed checkpoint barrier.
    fn abort_checkpoint_pause(&mut self) -> Result<(), QemuAsyncDriverRuntimeError> {
        Ok(())
    }

    /// Reports whether host-device work crosses the current scheduler boundary.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when live block queues or device
    /// continuation state cannot be inspected consistently.
    #[cfg(target_os = "linux")]
    fn has_pending_device_io(&mut self) -> Result<bool, QemuAsyncDriverRuntimeError> {
        Ok(false)
    }

    /// Captures the complete host-I/O continuation paired with QEMU VMState.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when the guest is not quiescent
    /// or an attached device or shared-memory ring cannot be snapshotted.
    fn checkpoint_host_io(
        &mut self,
        execution_binding: crucible::model::ContentHash,
    ) -> Result<crate::QemuHostIoCheckpoint, QemuAsyncDriverRuntimeError> {
        Ok(crate::QemuHostIoCheckpoint::without_devices(
            execution_binding,
        ))
    }

    /// Prevalidates a paired host-I/O restore without changing live state.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when the checkpoint identity or
    /// live device topology differs. The default runtime accepts only the
    /// explicit no-block topology.
    fn validate_host_io_checkpoint(
        &mut self,
        execution_binding: crucible::model::ContentHash,
        checkpoint: &crate::QemuHostIoCheckpoint,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        if checkpoint.execution_binding() == execution_binding
            && checkpoint.block().is_none()
            && checkpoint.ninep().is_none()
        {
            Ok(())
        } else {
            Err(QemuAsyncDriverRuntimeError::new(
                "validate host-I/O checkpoint",
                "checkpoint identity or device topology does not match this runtime",
            ))
        }
    }

    /// Commits a previously validated host-I/O continuation restore.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] under the same conditions as
    /// [`Self::validate_host_io_checkpoint`].
    fn restore_host_io_checkpoint(
        &mut self,
        execution_binding: crucible::model::ContentHash,
        checkpoint: &crate::QemuHostIoCheckpoint,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.validate_host_io_checkpoint(execution_binding, checkpoint)
    }

    /// Captures the block state needed to roll back one scheduler boundary.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when a runtime with an attached
    /// block device cannot capture its complete fault continuation.
    #[cfg(target_os = "linux")]
    fn checkpoint_block_boundary_state(
        &self,
    ) -> Result<Option<crucible_device::block::BlockFaultState>, QemuAsyncDriverRuntimeError> {
        Ok(None)
    }

    /// Returns the authoritative live block-device handle, when configured.
    #[cfg(target_os = "linux")]
    fn shared_block_device(&self) -> Option<crate::QemuSharedBlockDevice> {
        None
    }

    /// Restores block state captured before an uncommitted scheduler boundary.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when this runtime cannot restore
    /// the supplied state exactly.
    #[cfg(target_os = "linux")]
    fn restore_block_boundary_state(
        &mut self,
        state: Option<crucible_device::block::BlockFaultState>,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        if state.is_none() {
            Ok(())
        } else {
            Err(QemuAsyncDriverRuntimeError::new(
                "restore block boundary state",
                "host-I/O runtime does not implement block transaction rollback",
            ))
        }
    }

    /// Applies storage-targeted actions at one exact scheduler boundary.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when an attached block runtime
    /// cannot apply its matching actions atomically.
    #[cfg(target_os = "linux")]
    fn apply_block_boundary_actions(
        &mut self,
        _coordinate: crucible::model::FaultCoordinate,
        _evaluation_sequence: u64,
        actions: &[crucible::model::ResolvedBindingAction],
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        if actions.is_empty() {
            Ok(())
        } else {
            Err(QemuAsyncDriverRuntimeError::new(
                "apply block boundary actions",
                "host-I/O runtime does not implement signal-driven block boundary mutations",
            ))
        }
    }

    /// Installs the signal-driven coordinator for an attached live block device.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when this runtime has no live block
    /// device. A new coordinator atomically replaces the previous binding so a
    /// restored or relaunched node cannot retain a stale continuation owner.
    #[cfg(target_os = "linux")]
    fn install_block_fault_coordinator(
        &mut self,
        _coordinator: Box<dyn crate::supervision::QemuBlockFaultCoordinator>,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        Err(QemuAsyncDriverRuntimeError::new(
            "install block fault coordinator",
            "host-I/O runtime does not own a live block device",
        ))
    }

    /// Installs the signal-driven coordinator for an attached live 9p device.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when this runtime has no live 9p
    /// device or already has a continuation owner.
    #[cfg(target_os = "linux")]
    fn install_ninep_fault_coordinator(
        &mut self,
        _coordinator: Box<dyn crate::supervision::QemuNinepFaultCoordinator>,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        Err(QemuAsyncDriverRuntimeError::new(
            "install 9p fault coordinator",
            "host-I/O runtime does not own a live 9p device",
        ))
    }

    /// Yields once so control-plane work can run between quanta.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when the runtime cannot yield.
    fn yield_to_control_plane(&mut self) -> Result<(), QemuAsyncDriverRuntimeError>;

    /// Waits for one child event using `timeout` as a bounded budget.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when the runtime cannot execute
    /// the await operation.
    fn await_child(
        &mut self,
        wait: QemuAsyncWait,
        timeout: Duration,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError>;

    /// Polls an already-signaled child event again under the original budget.
    ///
    /// The runtime must retain the deadline established by
    /// [`Self::await_child`] and return [`QemuAsyncWaitOutcome::TimedOut`] when
    /// that original `timeout` budget expires. A repeated poll must not repeat
    /// one-shot side effects such as waking the plugin.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when the runtime cannot execute
    /// the repeated poll operation.
    fn repoll_child(
        &mut self,
        wait: QemuAsyncWait,
        timeout: Duration,
    ) -> Result<QemuAsyncWaitOutcome, QemuAsyncDriverRuntimeError>;

    /// Wakes QEMU and waits for one lossless fault-command result.
    ///
    /// Implementations must use `timeout` only as a host-liveness bound. The
    /// returned result carries the QEMU-observed virtual coordinate and is the
    /// sole mutation evidence used by the scheduler.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when the runtime cannot wake
    /// QEMU, the result transport is corrupt, or the bounded wait expires.
    fn await_fault_result(
        &mut self,
        _timeout: Duration,
    ) -> Result<DequeuedFaultResult, QemuAsyncDriverRuntimeError> {
        Err(QemuAsyncDriverRuntimeError::new(
            "await fault result",
            "host-I/O runtime does not own a QEMU fault-result transport",
        ))
    }
}

/// Error returned by a host-I/O runtime adapter.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("{operation} failed: {message}")]
pub struct QemuAsyncDriverRuntimeError {
    /// Operation being attempted.
    pub operation: &'static str,
    /// Deterministic failure detail.
    pub message: String,
}

impl QemuAsyncDriverRuntimeError {
    /// Creates a runtime adapter error.
    #[must_use]
    pub fn new(operation: &'static str, message: impl Into<String>) -> Self {
        Self {
            operation,
            message: message.into(),
        }
    }
}

/// Target that can shut a QEMU child down after an infrastructure crash.
pub trait QemuAsyncCrashEscalationTarget {
    /// Escalates shutdown after an infrastructure crash.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverTargetError`] when shutdown escalation cannot run
    /// to a report.
    fn shutdown_after_crash(&mut self) -> Result<QemuShutdownReport, QemuAsyncDriverTargetError>;
}

/// Target driven by one bounded async node-step.
pub trait QemuAsyncNodeStepTarget: QemuAsyncCrashEscalationTarget {
    /// Opaque token returned after publishing a scheduler ceiling.
    type PendingQuantum;

    /// Starts one shared-memory quantum.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the shared-memory hot path cannot
    /// publish the scheduler ceiling or wake the plugin.
    fn start_quantum(
        &mut self,
        horizon: ExecutionHorizon,
    ) -> Result<Self::PendingQuantum, QemuNodeChannelError>;

    /// Returns the plugin-publication fence carried by a pending quantum.
    #[must_use]
    fn advance_completion_fence(
        &self,
        _pending: &Self::PendingQuantum,
    ) -> Option<QemuAdvanceCompletionFence> {
        None
    }

    /// Finishes one quantum after the host-I/O runtime observed completion.
    ///
    /// # Errors
    ///
    /// Returns [`QemuNodeChannelError`] when the completion report or frame rings
    /// cannot be read.
    fn finish_quantum(
        &mut self,
        pending: &mut Self::PendingQuantum,
    ) -> Result<QemuAsyncQuantumCompletion, QemuNodeChannelError>;
}

/// Pre-wake generation that must be superseded before a quantum can complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuAdvanceCompletionFence {
    /// Plugin publish generation observed before scheduler input was released.
    pub initial_publish_generation: u32,
}

/// Quantum completion observed from the shared-memory hot path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuAsyncQuantumCompletion {
    /// Effective shared-memory ceiling published for this quantum.
    pub ceiling: Icount,
    /// Scheduler-facing advance result for this quantum.
    pub outcome: AdvanceOutcome,
    /// Attested node state at the completed quantum boundary.
    pub final_state: crate::QemuNodeIdleState,
    /// Scheduler-staged inbound frames consumed at this completed boundary.
    pub inbound_frames_consumed: usize,
    /// Guest-emitted frames drained while completing this quantum.
    pub emitted_frames: Vec<crate::QemuNodeEmittedFrame>,
    /// Hot-path operations observed during the quantum.
    pub operations: Vec<QemuQuantumOperation>,
}

impl From<QemuQuantumReport> for QemuAsyncQuantumCompletion {
    fn from(report: QemuQuantumReport) -> Self {
        Self {
            ceiling: report.ceiling,
            outcome: report.outcome,
            final_state: report.final_state,
            inbound_frames_consumed: report.inbound_frames_consumed,
            emitted_frames: report.emitted_frames,
            operations: report.operations,
        }
    }
}

/// Result of one bounded async node-step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QemuAsyncNodeStepOutcome {
    /// The quantum completed normally.
    Completed {
        /// Scheduler-facing advance result.
        advance: AdvanceOutcome,
    },
    /// A bounded await timed out and shutdown escalation ran.
    Crashed {
        /// Scheduler-facing crashed-node status.
        status: QemuNodeRunStatus,
        /// Shutdown escalation report.
        shutdown: QemuShutdownReport,
    },
}

/// Report produced by one bounded async node-step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuAsyncNodeStepReport {
    /// Effective shared-memory ceiling, absent when the bounded wait crashed.
    pub ceiling: Option<Icount>,
    /// Outcome of the node-step.
    pub outcome: QemuAsyncNodeStepOutcome,
    /// Attested state for a completed quantum, absent after a crash.
    pub final_state: Option<crate::QemuNodeIdleState>,
    /// Scheduler-staged inbound frames consumed at this completed boundary.
    pub inbound_frames_consumed: usize,
    /// Guest-emitted frames drained at this completed boundary.
    pub emitted_frames: Vec<crate::QemuNodeEmittedFrame>,
    /// Whether the driver yielded before starting this quantum.
    pub yielded_before_quantum: bool,
    /// Whether the driver yielded after finishing this quantum.
    pub yielded_after_quantum: bool,
    /// Shared-memory hot-path operations observed during the quantum.
    pub hot_path_operations: Vec<QemuQuantumOperation>,
    /// Host-I/O runtime operations performed around the quantum.
    pub async_operations: Vec<QemuAsyncDriverOperation>,
}

/// Result of one bounded lifecycle await.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum QemuAsyncLifecycleAwaitOutcome {
    /// The child event completed within its timeout budget.
    Completed,
    /// The child event timed out and shutdown escalation ran.
    Crashed {
        /// Scheduler-facing crashed-node status.
        status: QemuNodeRunStatus,
        /// Shutdown escalation report.
        shutdown: QemuShutdownReport,
    },
}

/// Report produced by one bounded lifecycle await.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuAsyncLifecycleAwaitReport {
    /// Wait class that was awaited.
    pub wait: QemuAsyncWait,
    /// Outcome of the lifecycle await.
    pub outcome: QemuAsyncLifecycleAwaitOutcome,
    /// Host-I/O runtime operations performed for this wait.
    pub async_operations: Vec<QemuAsyncDriverOperation>,
}

mod error;
pub use error::{QemuAsyncDriverError, QemuAsyncDriverTargetError};

mod driver;
pub use driver::{await_bounded_lifecycle_event, run_bounded_qemu_node_step};

#[cfg(test)]
#[path = "async_driver_test.rs"]
mod tests;

mod hot_path;

pub use hot_path::*;
