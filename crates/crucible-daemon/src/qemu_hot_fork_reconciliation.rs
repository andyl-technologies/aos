//! Attempt-scoped ownership and reconciliation for one QEMU hot-fork child.
//!
//! A successful retained-template fork creates authorities in two process
//! hierarchies: the source QEMU remains the child's direct parent and owns its
//! exact `waitpid` result, while the target attempt owner retains the cgroup,
//! sticky cancellation signal, and an independent pidfd. This module keeps
//! those authorities, the private child QMP endpoint, the plugin control/wake
//! and shared-memory continuation, executor accounting basis, and publication
//! disposition in one linear state machine. No source record or
//! process-contract descriptor is released until child reap, target cgroup
//! cleanup, and the semantic publication outcome are all known.
//! The sole branch-private diagnostic reader moves into this owner at launch;
//! it is serviced independently of the reusable source template while live and
//! returned for exact source-side writer release at teardown.

use std::error::Error;
use std::fmt;
use std::os::unix::process::ExitStatusExt;
use std::process::ExitStatus;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crucible::{ContentHash, EventLog, EventLogOffset, NodeId};
// crucible-lint: allow host-nondeterminism-state -- node generations authenticate exact process ownership and carry no host timing into execution.
use crucible_api::ProductionVmNodeGeneration;
use crucible_campaign::{ExactCheckpointId, ObservationId};
use crucible_qemu::{
    LinuxQemuHotForkChildProcessAuthority, QemuAsyncDriverPolicy, QemuChildWait, QemuCrashDetector,
    QemuHotForkChildDiagnosticConsumer, QemuHotForkChildDiagnosticDrain, QemuHotForkChildLaunch,
    QemuHotForkChildProcessBasis, QemuHotForkChildProcessOwner, QemuHotForkChildQmpHandshakeError,
    QemuHotForkHostContinuation, QemuHotForkLaunchError, QemuHotForkSchedulerNodeContinuation,
    QemuHotForkTemplateIdentity, QemuNode, QemuNodeChannelError, QemuNodeExternalProcessControl,
    QemuPreparedHotForkTemplate, QemuProcessIdentity, QemuReap, QemuShutdownPolicy,
    QemuShutdownRung, QemuShutdownTargetError, QemuVmRealizationError, QmpHotForkChildProcessPhase,
    QmpHotForkChildProcessState,
};
use thiserror::Error;

use crate::CrucibleAttemptExecution;
use crate::qemu_hot_fork_world::QemuHotForkWorldAssemblyToken;
use crate::qemu_hot_fork_world_resource::{
    QemuHotForkWorldNodeTarget, QemuHotForkWorldResourceOwner,
};
use crate::supervision::ProcessDeadline;

/// Exact supervisor reservation owning one hot-fork realization.
pub type QemuHotForkAttemptBasis = crate::AttemptExecutionRuntimeBasis;

/// Authenticated installed-node and source-template basis retained by one child.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuHotForkWorldChildSourceBasis {
    node: NodeId,
    configuration: ContentHash,
    event_log_offset: EventLogOffset,
    process: QemuProcessIdentity,
}

impl QemuHotForkWorldChildSourceBasis {
    #[cfg(test)]
    pub(crate) const fn for_test(
        node: NodeId,
        configuration: ContentHash,
        event_log_offset: EventLogOffset,
        process: QemuProcessIdentity,
    ) -> Self {
        Self {
            node,
            configuration,
            event_log_offset,
            process,
        }
    }

    /// Returns the exact scheduler-node coordinate installed for this child.
    #[must_use]
    pub const fn node(&self) -> &NodeId {
        &self.node
    }

    /// Returns the exact modeled configuration of the source template.
    #[must_use]
    pub const fn configuration(&self) -> ContentHash {
        self.configuration
    }

    /// Returns the unified event-log offset cloned into the child branch.
    #[must_use]
    pub const fn event_log_offset(&self) -> EventLogOffset {
        self.event_log_offset
    }

    /// Returns the exact source-QEMU process incarnation.
    #[must_use]
    pub const fn process(&self) -> &QemuProcessIdentity {
        &self.process
    }
}

/// Parent-observed lifecycle of one exact hot-fork child.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuHotForkChildDisposition {
    /// The source QEMU has not reaped the child.
    Running,
    /// The source QEMU reaped a normal exit with this code.
    Exited(u8),
    /// The source QEMU reaped signal termination with this signal number.
    Signaled(u8),
}

/// Exact source-parent observation used by the reconciliation machine.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuHotForkChildObservation {
    generation: u64,
    process_id: u32,
    disposition: QemuHotForkChildDisposition,
}

impl QemuHotForkChildObservation {
    /// Builds one exact nonzero child-status observation.
    ///
    /// # Errors
    ///
    /// Returns [`QemuHotForkChildObservationError`] when the generation or PID
    /// is zero, or signal termination carries signal zero.
    pub fn new(
        generation: u64,
        process_id: u32,
        disposition: QemuHotForkChildDisposition,
    ) -> Result<Self, QemuHotForkChildObservationError> {
        if generation == 0 {
            return Err(QemuHotForkChildObservationError::ZeroGeneration);
        }
        if process_id == 0 || process_id > 2_147_483_647 {
            return Err(QemuHotForkChildObservationError::InvalidProcessId);
        }
        if disposition == QemuHotForkChildDisposition::Signaled(0) {
            return Err(QemuHotForkChildObservationError::ZeroSignal);
        }
        Ok(Self {
            generation,
            process_id,
            disposition,
        })
    }

    /// Returns the QEMU-owned child-status generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the exact child process identifier.
    #[must_use]
    pub const fn process_id(self) -> u32 {
        self.process_id
    }

    /// Returns the current parent-owned lifecycle disposition.
    #[must_use]
    pub const fn disposition(self) -> QemuHotForkChildDisposition {
        self.disposition
    }
}

/// Invalid source-parent child-status observation.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum QemuHotForkChildObservationError {
    /// The child-status generation is reserved and cannot identify a record.
    #[error("hot-fork child-status generation is zero")]
    ZeroGeneration,
    /// The process identifier is outside the supported positive Linux range.
    #[error("hot-fork child process identifier is outside the supported range")]
    InvalidProcessId,
    /// Signal termination must name a nonzero signal.
    #[error("hot-fork child signal disposition carries signal zero")]
    ZeroSignal,
}

/// Minimal exact child basis projected from the unforgeable launch authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuHotForkReconciliationChildBasis {
    generation: u64,
    process_id: u32,
}

impl QemuHotForkReconciliationChildBasis {
    /// Projects a validated source-status generation and process identifier.
    #[must_use]
    pub const fn new(generation: u64, process_id: u32) -> Self {
        Self {
            generation,
            process_id,
        }
    }

    /// Returns the source-QEMU status-record generation.
    #[must_use]
    pub const fn generation(self) -> u64 {
        self.generation
    }

    /// Returns the exact target process identifier.
    #[must_use]
    pub const fn process_id(self) -> u32 {
        self.process_id
    }
}

/// Semantic disposition that permits operational hot-fork records to retire.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuHotForkPublicationDisposition {
    /// The exact observation was reconciled with the executor supervisor.
    Observation(ObservationId),
    /// The exact paused checkpoint became the execution's durable origin.
    ExactCheckpoint(ExactCheckpointId),
    /// Cancellation won before an observation became authoritative.
    Canceled,
    /// A stable execution or publication failure was durably reconciled.
    TerminalFailure,
}

/// Monotonic phase of one hot-fork reconciliation owner.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuHotForkReconciliationPhase {
    /// The child exists but its private QMP endpoint is not authenticated.
    AwaitingChildAdmission,
    /// The private child channel is authenticated and modeled work may run.
    Live,
    /// Termination was requested through the exact retained pidfd.
    TerminationRequested,
    /// The source QEMU retained the child's final wait status.
    ParentReaped,
    /// Branch-private source-side channel and mapping stages were released.
    ChildResourcesReleased,
    /// The target watcher proved the cgroup empty and released its controls.
    TargetReleased,
    /// Operational cleanup is waiting for one semantic publication outcome.
    AwaitingPublication,
    /// The publication, cancellation, or terminal-failure outcome is retained.
    PublicationReconciled,
    /// The source QEMU released its exact child-status record.
    SourceStatusReleased,
    /// Every authority was reconciled and the source template may be recovered.
    Reconciled,
    /// Cleanup was transferred to fail-closed quarantine.
    Quarantined,
}

/// Result of one bounded reconciliation step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum QemuHotForkReconciliationStep {
    /// One nonblocking diagnostics drain completed before the next status poll.
    ChildDiagnosticsDrained,
    /// The source parent still reports the exact child running.
    ChildRunning,
    /// One durable public phase or backend-owned subphase completed.
    ///
    /// A backend subphase reports the unchanged public phase while preserving
    /// monotonic progress for the next call.
    Advanced(QemuHotForkReconciliationPhase),
    /// Operational cleanup is complete but semantic publication is unresolved.
    AwaitingPublication,
    /// Every source, target, accounting, and publication authority is reconciled.
    Complete,
}

/// Operations required by the linear reconciliation state machine.
///
/// Implementations must retain all authority after every error. In particular,
/// releasing child resources may make partial monotonic progress internally,
/// but a retry must resume at the first unreleased resource rather than replay
/// an acknowledged destructive operation.
pub trait QemuHotForkReconciliationBackend {
    /// Typed backend failure that preserves its owned authorities.
    type Error: Error + Send + Sync + 'static;

    /// Returns the exact source, child, and thirteen-generation fork basis.
    #[must_use]
    fn child_basis(&self) -> QemuHotForkReconciliationChildBasis;

    /// Consumes and authenticates the branch-private child QMP endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error when negotiation or the exact child basis fails.
    fn admit_child_channel(&mut self) -> Result<(), Self::Error>;

    /// Sends termination through the exact retained child authority.
    ///
    /// # Errors
    ///
    /// Returns an error when the pidfd or equivalent exact signal fails.
    fn terminate_child(&mut self) -> Result<(), Self::Error>;

    /// Drains every currently available branch-private diagnostic byte.
    ///
    /// Implementations retain one cumulative bounded capture and fail closed
    /// rather than truncate it.
    ///
    /// # Errors
    ///
    /// Returns an error when the exact diagnostics generation can no longer be
    /// captured completely. This is a terminal ownership failure.
    fn drain_child_diagnostics(&mut self) -> Result<(), Self::Error>;

    /// Queries one nonblocking source-parent child-status observation.
    ///
    /// # Errors
    ///
    /// Returns an error when the source channel or strict response fails.
    fn observe_child(&mut self) -> Result<QemuHotForkChildObservation, Self::Error>;

    /// Releases at most one branch-private channel, diagnostic, or mapping stage.
    ///
    /// Returns `true` only after every child-private stage is released. A
    /// `false` result records monotonic backend progress while leaving the
    /// public reconciliation phase unchanged.
    ///
    /// # Errors
    ///
    /// Returns an error while retaining every unreleased stage for retry.
    fn release_next_child_resource(&mut self) -> Result<bool, Self::Error>;

    /// Proves the target cgroup empty and releases its process controls.
    ///
    /// # Errors
    ///
    /// Returns an error while retaining retry or quarantine authority.
    fn release_target(&mut self) -> Result<(), Self::Error>;

    /// Releases the exact source-parent status record after semantic resolution.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained final status cannot be released
    /// exactly.
    fn release_source_status(
        &mut self,
        terminal: QemuHotForkChildObservation,
    ) -> Result<(), Self::Error>;

    /// Releases QEMU's retained target process-contract descriptors last.
    ///
    /// # Errors
    ///
    /// Returns an error when the exact one-shot contract cannot be released.
    fn release_process_contract(&mut self) -> Result<(), Self::Error>;

    /// Transfers incomplete process cleanup to a fail-closed owner.
    fn quarantine(&mut self);
}

/// Failure while advancing a hot-fork reconciliation state.
#[derive(Debug, Error)]
pub enum QemuHotForkAttemptReconciliationError<E>
where
    E: Error + 'static,
{
    /// The requested operation is not legal in the current monotonic phase.
    #[error("hot-fork operation {operation} is invalid in phase {phase:?}")]
    InvalidPhase {
        /// Stable operation name.
        operation: &'static str,
        /// Current reconciliation phase.
        phase: QemuHotForkReconciliationPhase,
    },
    /// The source observation does not match the retained launch basis.
    #[error("source QEMU returned a child status outside the retained hot-fork basis")]
    ChildBasisMismatch,
    /// A modeled result cannot be accepted for a child that never passed admission.
    #[error("hot-fork modeled result requires an admitted private child channel")]
    ModeledResultWithoutAdmission,
    /// A repeated callback supplied a different semantic disposition.
    #[error("hot-fork publication disposition changed during reconciliation")]
    PublicationDispositionMismatch,
    /// One backend operation failed while retaining reconciliation authority.
    #[error("hot-fork backend operation {operation} failed: {source}")]
    Operation {
        /// Stable operation name.
        operation: &'static str,
        /// Typed backend failure.
        #[source]
        source: E,
    },
}

/// Linear owner for one hot-fork child's complete operational lifecycle.
#[must_use = "drive the hot-fork child to reconciliation or quarantine"]
pub struct QemuHotForkAttemptReconciliation<B>
where
    B: QemuHotForkReconciliationBackend,
{
    attempt: QemuHotForkAttemptBasis,
    backend: Option<B>,
    phase: QemuHotForkReconciliationPhase,
    child_admitted: bool,
    terminal: Option<QemuHotForkChildObservation>,
    publication: Option<QemuHotForkPublicationDisposition>,
    diagnostics_drained: bool,
}

mod launch;
mod linux;
mod state;

pub use launch::{
    LinuxQemuHotForkAttemptLaunchError, LinuxQemuHotForkWorldAttemptLaunchError,
    LinuxQemuHotForkWorldAttemptLaunchFailure,
};
pub use linux::{
    LinuxQemuHotForkLiveChild, LinuxQemuHotForkNodeProcessControl,
    LinuxQemuHotForkReconciliationBackend, LinuxQemuHotForkReconciliationError,
};

#[cfg(test)]
mod tests;
