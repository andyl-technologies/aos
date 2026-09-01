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
use crucible_shmem::{DequeuedFaultEvent, DequeuedFaultResult};

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

#[path = "async_driver/host_io_runtime.rs"]
mod host_io_runtime;
pub use host_io_runtime::QemuHostIoRuntime;

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
pub use error::{QemuAsyncDriverError, QemuAsyncDriverRuntimeError, QemuAsyncDriverTargetError};

mod driver;
pub(crate) use driver::run_bounded_qemu_node_step_with_start_hook;
pub use driver::{await_bounded_lifecycle_event, run_bounded_qemu_node_step};

#[cfg(test)]
#[path = "async_driver_test.rs"]
mod tests;

mod hot_path;

pub use hot_path::*;
