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

impl<B> QemuHotForkAttemptReconciliation<B>
where
    B: QemuHotForkReconciliationBackend,
{
    /// Begins ownership of one already-created exact child.
    pub fn new(attempt: QemuHotForkAttemptBasis, backend: B) -> Self {
        Self {
            attempt,
            backend: Some(backend),
            phase: QemuHotForkReconciliationPhase::AwaitingChildAdmission,
            child_admitted: false,
            terminal: None,
            publication: None,
            diagnostics_drained: false,
        }
    }

    pub(crate) fn from_reconciled_backend(
        attempt: QemuHotForkAttemptBasis,
        backend: B,
        terminal: Option<QemuHotForkChildObservation>,
        publication: Option<QemuHotForkPublicationDisposition>,
    ) -> Self {
        Self {
            attempt,
            backend: Some(backend),
            phase: QemuHotForkReconciliationPhase::Reconciled,
            child_admitted: true,
            terminal,
            publication,
            diagnostics_drained: true,
        }
    }

    /// Returns the exact supervisor reservation basis.
    #[must_use]
    pub const fn attempt(&self) -> QemuHotForkAttemptBasis {
        self.attempt
    }

    /// Returns the current monotonic phase.
    #[must_use]
    pub const fn phase(&self) -> QemuHotForkReconciliationPhase {
        self.phase
    }

    /// Returns the final parent-owned child status once observed.
    #[must_use]
    pub const fn terminal_observation(&self) -> Option<QemuHotForkChildObservation> {
        self.terminal
    }

    /// Returns the semantic publication disposition once reconciled.
    #[must_use]
    pub const fn publication(&self) -> Option<QemuHotForkPublicationDisposition> {
        self.publication
    }

    /// Authenticates the private child QMP channel before modeled execution.
    ///
    /// A failed handshake immediately quarantines the complete owner because
    /// the consumed private stream cannot be retried safely.
    ///
    /// # Errors
    ///
    /// Returns [`QemuHotForkAttemptReconciliationError::InvalidPhase`] unless
    /// the child awaits admission, or a backend error after quarantine.
    pub fn admit_child(&mut self) -> Result<(), QemuHotForkAttemptReconciliationError<B::Error>> {
        self.require_phase(
            "admit private child channel",
            QemuHotForkReconciliationPhase::AwaitingChildAdmission,
        )?;
        let drain = self.backend_mut()?.drain_child_diagnostics();
        if let Err(source) = drain {
            if let Some(backend) = self.backend.as_mut() {
                backend.quarantine();
            }
            self.phase = QemuHotForkReconciliationPhase::Quarantined;
            return Err(QemuHotForkAttemptReconciliationError::Operation {
                operation: "drain child diagnostics before admission",
                source,
            });
        }
        let admission = self.backend_mut()?.admit_child_channel();
        if let Err(source) = admission {
            if let Some(backend) = self.backend.as_mut() {
                backend.quarantine();
            }
            self.phase = QemuHotForkReconciliationPhase::Quarantined;
            return Err(QemuHotForkAttemptReconciliationError::Operation {
                operation: "admit private child channel",
                source,
            });
        }
        self.child_admitted = true;
        self.diagnostics_drained = false;
        self.phase = QemuHotForkReconciliationPhase::Live;
        Ok(())
    }

    /// Latches termination intent and signals the exact child pidfd.
    ///
    /// # Errors
    ///
    /// Returns an invalid-phase error after terminal reconciliation begins, or
    /// a backend error while retaining the latched termination phase for retry.
    pub fn request_termination(
        &mut self,
    ) -> Result<(), QemuHotForkAttemptReconciliationError<B::Error>> {
        match self.phase {
            QemuHotForkReconciliationPhase::AwaitingChildAdmission
            | QemuHotForkReconciliationPhase::Live
            | QemuHotForkReconciliationPhase::TerminationRequested => {}
            phase => {
                return Err(QemuHotForkAttemptReconciliationError::InvalidPhase {
                    operation: "request child termination",
                    phase,
                });
            }
        }
        self.phase = QemuHotForkReconciliationPhase::TerminationRequested;
        self.diagnostics_drained = false;
        self.backend_mut()?.terminate_child().map_err(|source| {
            QemuHotForkAttemptReconciliationError::Operation {
                operation: "request child termination",
                source,
            }
        })
    }

    /// Records the semantic outcome after target process cleanup.
    ///
    /// # Errors
    ///
    /// Returns an invalid-phase error unless operational cleanup is waiting for
    /// publication reconciliation.
    pub fn reconcile_publication(
        &mut self,
        disposition: QemuHotForkPublicationDisposition,
    ) -> Result<(), QemuHotForkAttemptReconciliationError<B::Error>> {
        self.require_phase(
            "reconcile semantic publication",
            QemuHotForkReconciliationPhase::AwaitingPublication,
        )?;
        if matches!(
            disposition,
            QemuHotForkPublicationDisposition::Observation(_)
                | QemuHotForkPublicationDisposition::ExactCheckpoint(_)
        ) && !self.child_admitted
        {
            return Err(QemuHotForkAttemptReconciliationError::ModeledResultWithoutAdmission);
        }
        self.publication = Some(disposition);
        self.phase = QemuHotForkReconciliationPhase::PublicationReconciled;
        Ok(())
    }

    /// Advances one worker-owned post-execution reconciliation subphase.
    ///
    /// The first call records the exact durable semantic disposition. Later
    /// calls require the same disposition and perform at most one backend
    /// operation through [`Self::reconcile_step`]. This is the direct adapter
    /// for [`crate::LocalAttemptWorker::reconcile_execution`].
    ///
    /// # Errors
    ///
    /// Returns a phase, admission, disposition, basis, or backend error while
    /// retaining the complete owner for exact retry or quarantine.
    pub fn reconcile_execution_disposition(
        &mut self,
        disposition: crate::AttemptExecutionDisposition,
    ) -> Result<
        crate::AttemptExecutionReconciliationStep,
        QemuHotForkAttemptReconciliationError<B::Error>,
    > {
        let publication = match disposition {
            crate::AttemptExecutionDisposition::Observation(observation) => {
                QemuHotForkPublicationDisposition::Observation(observation)
            }
            crate::AttemptExecutionDisposition::ExactCheckpoint(checkpoint) => {
                QemuHotForkPublicationDisposition::ExactCheckpoint(checkpoint)
            }
            crate::AttemptExecutionDisposition::Canceled => {
                QemuHotForkPublicationDisposition::Canceled
            }
            crate::AttemptExecutionDisposition::Failed => {
                QemuHotForkPublicationDisposition::TerminalFailure
            }
        };
        match self.publication {
            None => self.reconcile_publication(publication)?,
            Some(retained) if retained == publication => {}
            Some(_) => {
                return Err(QemuHotForkAttemptReconciliationError::PublicationDispositionMismatch);
            }
        }

        match self.reconcile_step()? {
            QemuHotForkReconciliationStep::Complete => {
                Ok(crate::AttemptExecutionReconciliationStep::Complete)
            }
            QemuHotForkReconciliationStep::Advanced(_)
            | QemuHotForkReconciliationStep::ChildDiagnosticsDrained
            | QemuHotForkReconciliationStep::ChildRunning
            | QemuHotForkReconciliationStep::AwaitingPublication => {
                Ok(crate::AttemptExecutionReconciliationStep::Progressed)
            }
        }
    }

    /// Performs at most one bounded reconciliation operation.
    ///
    /// The caller schedules subsequent calls without holding the executor
    /// supervisor actor. A live child alternates one nonblocking diagnostics
    /// drain with one parent-status query, so status cannot overtake stream
    /// service. Every destructive success advances the phase before returning,
    /// so retry never repeats an acknowledged release.
    ///
    /// # Errors
    ///
    /// Returns a typed backend error while retaining the same retryable phase,
    /// or a basis mismatch that requires caller-directed quarantine.
    pub fn reconcile_step(
        &mut self,
    ) -> Result<QemuHotForkReconciliationStep, QemuHotForkAttemptReconciliationError<B::Error>>
    {
        match self.phase {
            QemuHotForkReconciliationPhase::AwaitingChildAdmission
            | QemuHotForkReconciliationPhase::Live
            | QemuHotForkReconciliationPhase::TerminationRequested => {
                if !self.diagnostics_drained {
                    let drain = self.backend_mut()?.drain_child_diagnostics();
                    if let Err(source) = drain {
                        if let Some(backend) = self.backend.as_mut() {
                            backend.quarantine();
                        }
                        self.phase = QemuHotForkReconciliationPhase::Quarantined;
                        return Err(QemuHotForkAttemptReconciliationError::Operation {
                            operation: "drain branch-private child diagnostics",
                            source,
                        });
                    }
                    self.diagnostics_drained = true;
                    return Ok(QemuHotForkReconciliationStep::ChildDiagnosticsDrained);
                }
                self.diagnostics_drained = false;
                let observed = self.backend_mut()?.observe_child().map_err(|source| {
                    QemuHotForkAttemptReconciliationError::Operation {
                        operation: "query source-owned child status",
                        source,
                    }
                })?;
                let basis = self.backend_ref()?.child_basis();
                if observed.generation() != basis.generation()
                    || observed.process_id() != basis.process_id()
                {
                    return Err(QemuHotForkAttemptReconciliationError::ChildBasisMismatch);
                }
                if observed.disposition() == QemuHotForkChildDisposition::Running {
                    return Ok(QemuHotForkReconciliationStep::ChildRunning);
                }
                self.terminal = Some(observed);
                self.phase = QemuHotForkReconciliationPhase::ParentReaped;
                Ok(QemuHotForkReconciliationStep::Advanced(self.phase))
            }
            QemuHotForkReconciliationPhase::ParentReaped => {
                let complete =
                    self.backend_mut()?
                        .release_next_child_resource()
                        .map_err(|source| QemuHotForkAttemptReconciliationError::Operation {
                            operation: "release branch-private child resources",
                            source,
                        })?;
                if complete {
                    self.phase = QemuHotForkReconciliationPhase::ChildResourcesReleased;
                }
                Ok(QemuHotForkReconciliationStep::Advanced(self.phase))
            }
            QemuHotForkReconciliationPhase::ChildResourcesReleased => {
                self.backend_mut()?.release_target().map_err(|source| {
                    QemuHotForkAttemptReconciliationError::Operation {
                        operation: "release target process owner",
                        source,
                    }
                })?;
                self.phase = QemuHotForkReconciliationPhase::TargetReleased;
                Ok(QemuHotForkReconciliationStep::Advanced(self.phase))
            }
            QemuHotForkReconciliationPhase::TargetReleased => {
                self.phase = QemuHotForkReconciliationPhase::AwaitingPublication;
                Ok(QemuHotForkReconciliationStep::AwaitingPublication)
            }
            QemuHotForkReconciliationPhase::AwaitingPublication => {
                Ok(QemuHotForkReconciliationStep::AwaitingPublication)
            }
            QemuHotForkReconciliationPhase::PublicationReconciled => {
                let terminal = self
                    .terminal
                    .ok_or(QemuHotForkAttemptReconciliationError::ChildBasisMismatch)?;
                self.backend_mut()?
                    .release_source_status(terminal)
                    .map_err(|source| QemuHotForkAttemptReconciliationError::Operation {
                        operation: "release source-owned child status",
                        source,
                    })?;
                self.phase = QemuHotForkReconciliationPhase::SourceStatusReleased;
                Ok(QemuHotForkReconciliationStep::Advanced(self.phase))
            }
            QemuHotForkReconciliationPhase::SourceStatusReleased => {
                self.backend_mut()?
                    .release_process_contract()
                    .map_err(|source| QemuHotForkAttemptReconciliationError::Operation {
                        operation: "release child process contract",
                        source,
                    })?;
                self.phase = QemuHotForkReconciliationPhase::Reconciled;
                Ok(QemuHotForkReconciliationStep::Complete)
            }
            QemuHotForkReconciliationPhase::Reconciled => {
                Ok(QemuHotForkReconciliationStep::Complete)
            }
            QemuHotForkReconciliationPhase::Quarantined => {
                Err(QemuHotForkAttemptReconciliationError::InvalidPhase {
                    operation: "advance reconciliation",
                    phase: self.phase,
                })
            }
        }
    }

    /// Transfers every incomplete authority to fail-closed quarantine.
    pub fn quarantine(&mut self) {
        if self.phase == QemuHotForkReconciliationPhase::Reconciled
            || self.phase == QemuHotForkReconciliationPhase::Quarantined
        {
            return;
        }
        if let Some(backend) = self.backend.as_mut() {
            backend.quarantine();
        }
        self.phase = QemuHotForkReconciliationPhase::Quarantined;
    }

    /// Recovers the backend only after complete reconciliation.
    ///
    /// On an incomplete owner, returns the unchanged owner so no authority can
    /// escape the state machine.
    ///
    /// # Errors
    ///
    /// Returns the unchanged owner until its phase is
    /// [`QemuHotForkReconciliationPhase::Reconciled`].
    pub fn into_reconciled_backend(mut self) -> Result<B, Box<Self>> {
        if self.phase != QemuHotForkReconciliationPhase::Reconciled {
            return Err(Box::new(self));
        }
        match self.backend.take() {
            Some(backend) => Ok(backend),
            None => Err(Box::new(self)),
        }
    }

    fn require_phase(
        &self,
        operation: &'static str,
        expected: QemuHotForkReconciliationPhase,
    ) -> Result<(), QemuHotForkAttemptReconciliationError<B::Error>> {
        if self.phase != expected {
            return Err(QemuHotForkAttemptReconciliationError::InvalidPhase {
                operation,
                phase: self.phase,
            });
        }
        Ok(())
    }

    fn backend_ref(&self) -> Result<&B, QemuHotForkAttemptReconciliationError<B::Error>> {
        self.backend
            .as_ref()
            .ok_or(QemuHotForkAttemptReconciliationError::ChildBasisMismatch)
    }

    fn backend_mut(&mut self) -> Result<&mut B, QemuHotForkAttemptReconciliationError<B::Error>> {
        self.backend
            .as_mut()
            .ok_or(QemuHotForkAttemptReconciliationError::ChildBasisMismatch)
    }
}

impl<B> Drop for QemuHotForkAttemptReconciliation<B>
where
    B: QemuHotForkReconciliationBackend,
{
    fn drop(&mut self) {
        if !matches!(
            self.phase,
            QemuHotForkReconciliationPhase::Reconciled
                | QemuHotForkReconciliationPhase::Quarantined
        ) && let Some(backend) = self.backend.as_mut()
        {
            backend.quarantine();
        }
    }
}

/// Production backend failure while retaining source and target authorities.
#[derive(Debug, Error)]
pub enum LinuxQemuHotForkReconciliationError {
    /// Source-QEMU channel or resource-stage reconciliation failed.
    #[error(transparent)]
    Source(#[from] QemuNodeChannelError),
    /// The private child QMP endpoint failed exact authentication.
    #[error(transparent)]
    ChildQmp(#[from] QemuHotForkChildQmpHandshakeError),
    /// Target pidfd, watcher, or cgroup cleanup failed.
    #[error(transparent)]
    Target(#[from] QemuVmRealizationError),
    /// An acknowledged source response contradicted the retained exact basis.
    #[error("source QEMU contradicted the retained hot-fork lifecycle basis")]
    BasisMismatch,
    /// The in-process source-template owner was poisoned by an unwind.
    #[error("source QEMU ownership lock is poisoned")]
    SourceOwnerPoisoned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LinuxSourceReleasePhase {
    CloseChildChannel,
    PluginEndpoints,
    ChildQmp,
    Diagnostics,
    PrivateRing,
    Complete,
}

struct LinuxQemuHotForkProcessOwner {
    source: Mutex<Option<QemuNode>>,
    process: LinuxQemuHotForkChildProcessAuthority,
    reaped: AtomicBool,
}

impl LinuxQemuHotForkProcessOwner {
    fn observe_child(
        &self,
    ) -> Result<QmpHotForkChildProcessState, LinuxQemuHotForkReconciliationError> {
        let mut source = self
            .source
            .lock()
            .map_err(|_source| LinuxQemuHotForkReconciliationError::SourceOwnerPoisoned)?;
        let source = source
            .as_mut()
            .ok_or(LinuxQemuHotForkReconciliationError::BasisMismatch)?;
        let state = source.query_hot_fork_child_process(
            self.process.basis().request().child_process_generation(),
        )?;
        if state.generation() != self.process.basis().request().child_process_generation()
            || state.child_process_id() != self.process.basis().child_process_id()
        {
            return Err(LinuxQemuHotForkReconciliationError::BasisMismatch);
        }
        if state.phase() != QmpHotForkChildProcessPhase::Running {
            self.reaped.store(true, Ordering::Release);
        }
        Ok(state)
    }
}

/// Process-control loan joining a hot-fork pidfd to source-parent status.
///
/// Cloning this value duplicates no pidfd, cgroup, or wait authority. Every
/// clone points at the same outer lifecycle owner, which remains responsible
/// for releasing the source status record and target resources after modeled
/// execution has stopped.
#[derive(Clone)]
pub struct LinuxQemuHotForkNodeProcessControl {
    owner: Arc<LinuxQemuHotForkProcessOwner>,
}

impl fmt::Debug for LinuxQemuHotForkNodeProcessControl {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxQemuHotForkNodeProcessControl")
            .field("basis", &self.owner.process.basis())
            .field("reaped", &self.owner.reaped.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl LinuxQemuHotForkNodeProcessControl {
    fn new(owner: Arc<LinuxQemuHotForkProcessOwner>) -> Self {
        Self { owner }
    }

    fn observe_exit(&self) -> Result<Option<ExitStatus>, QemuShutdownTargetError> {
        let state = self.owner.observe_child().map_err(|source| {
            QemuShutdownTargetError::new(
                "query source-owned hot-fork child status",
                source.to_string(),
            )
        })?;
        match state.phase() {
            QmpHotForkChildProcessPhase::Running => Ok(None),
            QmpHotForkChildProcessPhase::Exited => {
                Ok(Some(ExitStatus::from_raw(i32::from(state.status()) << 8)))
            }
            QmpHotForkChildProcessPhase::Signaled if state.status() != 0 => {
                Ok(Some(ExitStatus::from_raw(i32::from(state.status()))))
            }
            QmpHotForkChildProcessPhase::Signaled => Err(QemuShutdownTargetError::new(
                "query source-owned hot-fork child status",
                "source parent reported a zero terminating signal",
            )),
        }
    }

    fn wait_until(&self, timeout: Duration) -> Result<bool, QemuShutdownTargetError> {
        let deadline = ProcessDeadline::after(timeout).ok_or_else(|| {
            QemuShutdownTargetError::new(
                "wait for source-owned hot-fork child",
                "child wait deadline overflowed",
            )
        })?;
        loop {
            if self.observe_exit()?.is_some() {
                return Ok(true);
            }
            if deadline.expired() {
                return Ok(false);
            }
            deadline.pause(Duration::from_millis(1));
        }
    }
}

impl QemuNodeExternalProcessControl for LinuxQemuHotForkNodeProcessControl {
    fn hot_fork_process_basis(&self) -> QemuHotForkChildProcessBasis {
        self.owner.process.basis()
    }

    fn process_id(&self) -> u32 {
        self.owner.process.basis().child_process_id()
    }

    fn reaped(&self) -> bool {
        self.owner.reaped.load(Ordering::Acquire)
    }

    fn try_wait_natural_exit(&mut self) -> Result<Option<ExitStatus>, QemuShutdownTargetError> {
        self.observe_exit()
    }

    fn send_sigterm(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.owner.process.terminate().map_err(|source| {
            QemuShutdownTargetError::new("terminate retained hot-fork child", source.to_string())
        })
    }

    fn send_sigkill(&mut self) -> Result<(), QemuShutdownTargetError> {
        self.owner.process.kill().map_err(|source| {
            QemuShutdownTargetError::new("kill retained hot-fork child", source.to_string())
        })
    }

    fn wait_for_exit(
        &mut self,
        _rung: QemuShutdownRung,
        timeout: Duration,
    ) -> Result<QemuChildWait, QemuShutdownTargetError> {
        self.wait_until(timeout).map(|exited| {
            if exited {
                QemuChildWait::Exited
            } else {
                QemuChildWait::StillRunning
            }
        })
    }

    fn reap(&mut self, timeout: Duration) -> Result<QemuReap, QemuShutdownTargetError> {
        self.wait_until(timeout).map(|reaped| {
            if reaped {
                QemuReap::Reaped
            } else {
                QemuReap::StillAlive
            }
        })
    }
}

/// Concrete source-QEMU, pidfd, cgroup, and private-channel owner.
pub struct LinuxQemuHotForkReconciliationBackend<G>
where
    G: crate::QemuAttemptResourceGuard,
{
    process_owner: Arc<LinuxQemuHotForkProcessOwner>,
    template_identity: QemuHotForkTemplateIdentity,
    input: CrucibleAttemptExecution,
    world_assembly: Option<QemuHotForkWorldAssemblyToken>,
    child_event_log: EventLog,
    target: G,
    basis: QemuHotForkChildProcessBasis,
    pending_child_qmp: Option<crucible_qemu::QemuHotForkChildQmpHostEndpoint>,
    scheduler_node: Option<QemuHotForkSchedulerNodeContinuation>,
    installed_node: Option<QemuNode>,
    installed_node_id: Option<NodeId>,
    diagnostics_consumer: QemuHotForkChildDiagnosticConsumer,
    host_continuation: Option<QemuHotForkHostContinuation>,
    source_release: LinuxSourceReleasePhase,
    diagnostics: Option<crucible_qemu::QemuHotForkChildDiagnosticCapture>,
}

/// Narrow live-child capability retained by one hot-fork reconciliation owner.
///
/// The capability keeps the diagnostic consumer and non-releasing operational
/// guard inseparable from the child QMP and plugin continuations. Every
/// operational-boundary check or quantum charge first drains all currently
/// available diagnostics. Direct QMP access is for bounded control exchange;
/// guest progress must remain behind the operational methods.
pub struct LinuxQemuHotForkLiveChild<'a> {
    input: &'a CrucibleAttemptExecution,
    diagnostics: &'a mut QemuHotForkChildDiagnosticConsumer,
    event_log: &'a mut EventLog,
    operational: &'a mut dyn crate::QemuAttemptOperationalBoundary,
}

impl fmt::Debug for LinuxQemuHotForkLiveChild<'_> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxQemuHotForkLiveChild")
            .field("diagnostics", &self.diagnostics)
            .finish_non_exhaustive()
    }
}

impl LinuxQemuHotForkLiveChild<'_> {
    /// Returns the exact resolved semantic input retained at child creation.
    #[must_use]
    pub const fn execution_input(&self) -> &CrucibleAttemptExecution {
        self.input
    }

    /// Borrows the branch-private clone of the source event-log prefix.
    #[must_use]
    pub fn event_log_mut(&mut self) -> &mut EventLog {
        self.event_log
    }

    /// Drains all currently available branch-private diagnostic bytes.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError::Executor`] when the exact bounded
    /// diagnostic stream cannot be retained without truncation.
    pub fn drain_diagnostics(
        &mut self,
    ) -> Result<QemuHotForkChildDiagnosticDrain, QemuVmRealizationError> {
        self.diagnostics
            .drain_available()
            .map_err(diagnostic_drain_realization_error)
    }
}

impl crate::QemuAttemptOperationalBoundary for LinuxQemuHotForkLiveChild<'_> {
    fn resource_limits(&self) -> crucible_campaign::AttemptResourceLimits {
        self.operational.resource_limits()
    }

    fn cancellation(&self) -> &crate::ExecutionCancellation {
        self.operational.cancellation()
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        self.drain_diagnostics()?;
        self.operational.check_operational_boundary()
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        self.drain_diagnostics()?;
        self.operational.charge_execution_quantum()
    }
}

fn diagnostic_drain_realization_error(source: QemuNodeChannelError) -> QemuVmRealizationError {
    QemuVmRealizationError::Executor {
        operation: "drain branch-private hot-fork child diagnostics",
        message: source.to_string(),
    }
}

impl<G> fmt::Debug for LinuxQemuHotForkReconciliationBackend<G>
where
    G: crate::QemuAttemptResourceGuard,
{
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxQemuHotForkReconciliationBackend")
            .field("basis", &self.basis)
            .field("world_assembly", &self.world_assembly.is_some())
            .field("pending_child_qmp", &self.pending_child_qmp.is_some())
            .field("scheduler_node_admitted", &self.scheduler_node.is_some())
            .field("scheduler_node_installed", &self.installed_node.is_some())
            .field("installed_node_id", &self.installed_node_id)
            .field("diagnostics_consumer", &self.diagnostics_consumer)
            .field("host_continuation", &self.host_continuation.is_some())
            .field("source_release", &self.source_release)
            .field("diagnostics", &self.diagnostics.is_some())
            .finish_non_exhaustive()
    }
}

impl<G> LinuxQemuHotForkReconciliationBackend<G>
where
    G: crate::QemuAttemptResourceGuard,
{
    fn from_launch(
        source: QemuNode,
        template_identity: QemuHotForkTemplateIdentity,
        input: CrucibleAttemptExecution,
        world_assembly: Option<QemuHotForkWorldAssemblyToken>,
        target: G,
        launch: QemuHotForkChildLaunch<LinuxQemuHotForkChildProcessAuthority>,
    ) -> Self {
        let (_parent, process, child_qmp, diagnostics_consumer, host_continuation) =
            launch.into_parts();
        let basis = process.basis();
        let process_owner = Arc::new(LinuxQemuHotForkProcessOwner {
            source: Mutex::new(Some(source)),
            process,
            reaped: AtomicBool::new(false),
        });
        let child_event_log = template_identity.fork_event_log();
        Self {
            process_owner,
            template_identity,
            input,
            world_assembly,
            child_event_log,
            target,
            basis,
            pending_child_qmp: Some(child_qmp),
            scheduler_node: None,
            installed_node: None,
            installed_node_id: None,
            diagnostics_consumer,
            host_continuation: Some(host_continuation),
            source_release: LinuxSourceReleasePhase::CloseChildChannel,
            diagnostics: None,
        }
    }

    fn live_child_mut(&mut self) -> Option<LinuxQemuHotForkLiveChild<'_>> {
        Some(LinuxQemuHotForkLiveChild {
            input: &self.input,
            diagnostics: &mut self.diagnostics_consumer,
            event_log: &mut self.child_event_log,
            operational: &mut self.target,
        })
    }

    fn with_source_mut<T>(
        &self,
        operation: impl FnOnce(&mut QemuNode) -> Result<T, QemuNodeChannelError>,
    ) -> Result<T, LinuxQemuHotForkReconciliationError> {
        let mut source = self
            .process_owner
            .source
            .lock()
            .map_err(|_source| LinuxQemuHotForkReconciliationError::SourceOwnerPoisoned)?;
        operation(
            source
                .as_mut()
                .ok_or(LinuxQemuHotForkReconciliationError::BasisMismatch)?,
        )
        .map_err(Into::into)
    }

    /// Returns the bounded final child diagnostic capture after source release.
    #[must_use]
    pub const fn diagnostics(&self) -> Option<&crucible_qemu::QemuHotForkChildDiagnosticCapture> {
        self.diagnostics.as_ref()
    }

    /// Creates a non-owning modeled-node process-control loan.
    #[must_use]
    pub fn node_process_control(&self) -> LinuxQemuHotForkNodeProcessControl {
        LinuxQemuHotForkNodeProcessControl::new(Arc::clone(&self.process_owner))
    }

    fn world_child_source_basis(
        &self,
    ) -> Result<QemuHotForkWorldChildSourceBasis, LinuxQemuHotForkReconciliationError> {
        let process = self.with_source_mut(|source| {
            source.process_identity().map_err(|error| {
                QemuNodeChannelError::new("authenticate hot-fork source process", error.to_string())
            })
        })?;
        Ok(QemuHotForkWorldChildSourceBasis {
            node: self
                .installed_node_id
                .clone()
                .ok_or(LinuxQemuHotForkReconciliationError::BasisMismatch)?,
            configuration: self.template_identity.configuration(),
            event_log_offset: self.template_identity.event_log().offset(),
            process,
        })
    }

    /// Installs the admitted branch-private continuation as one scheduler node.
    ///
    /// This operation consumes no source-parent, pidfd, or target-resource
    /// ownership. The installed node receives only a shared non-owning process
    /// control loan; terminal release remains ordered by this backend.
    ///
    /// # Errors
    ///
    /// Returns a fail-closed basis error when admission has not produced one
    /// exact continuation or a node is already installed. A process-basis
    /// mismatch restores the unchanged continuation for quarantine or retry.
    pub fn install_scheduler_node(
        &mut self,
        node: NodeId,
        shutdown_policy: QemuShutdownPolicy,
        async_policy: QemuAsyncDriverPolicy,
        crash_detector: QemuCrashDetector,
    ) -> Result<(), LinuxQemuHotForkReconciliationError> {
        if self.installed_node.is_some() {
            return Err(LinuxQemuHotForkReconciliationError::BasisMismatch);
        }
        let continuation = self
            .scheduler_node
            .take()
            .ok_or(LinuxQemuHotForkReconciliationError::BasisMismatch)?;
        match continuation.into_qemu_node(
            node.clone(),
            self.node_process_control(),
            shutdown_policy,
            async_policy,
            crash_detector,
        ) {
            Ok(installed_node) => {
                self.installed_node = Some(installed_node);
                self.installed_node_id = Some(node);
                Ok(())
            }
            Err(error) => {
                let (continuation, _process, source) = error.into_parts();
                self.scheduler_node = Some(continuation);
                Err(LinuxQemuHotForkReconciliationError::Source(source))
            }
        }
    }

    /// Borrows the exact installed process-neutral scheduler node.
    #[must_use]
    pub fn installed_scheduler_node_mut(&mut self) -> Option<&mut QemuNode> {
        self.installed_node.as_mut()
    }

    /// Consumes a reconciled backend into its reusable exact source template.
    ///
    /// # Errors
    ///
    /// Returns the unchanged backend when a modeled-node process-control loan
    /// still exists or the source ownership lock cannot be recovered exactly.
    pub fn into_source(mut self) -> Result<QemuPreparedHotForkTemplate<QemuNode>, Box<Self>> {
        if Arc::strong_count(&self.process_owner) != 1 {
            return Err(Box::new(self));
        }
        let source = Arc::get_mut(&mut self.process_owner)
            .and_then(|owner| owner.source.get_mut().ok())
            .and_then(Option::take);
        let Some(source) = source else {
            return Err(Box::new(self));
        };
        Ok(QemuPreparedHotForkTemplate::from_reconciled_parts(
            source,
            self.template_identity,
        ))
    }
}

impl<G> QemuHotForkReconciliationBackend for LinuxQemuHotForkReconciliationBackend<G>
where
    G: crate::QemuAttemptResourceGuard,
{
    type Error = LinuxQemuHotForkReconciliationError;

    fn child_basis(&self) -> QemuHotForkReconciliationChildBasis {
        QemuHotForkReconciliationChildBasis::new(
            self.basis.request().child_process_generation(),
            self.basis.child_process_id(),
        )
    }

    fn admit_child_channel(&mut self) -> Result<(), Self::Error> {
        let endpoint = self
            .pending_child_qmp
            .take()
            .ok_or(LinuxQemuHotForkReconciliationError::BasisMismatch)?;
        let continuation = self
            .host_continuation
            .take()
            .ok_or(LinuxQemuHotForkReconciliationError::BasisMismatch)?;
        match continuation.into_scheduler_node_continuation(endpoint) {
            Ok(scheduler_node) => {
                self.scheduler_node = Some(scheduler_node);
                Ok(())
            }
            Err(error) => {
                let (continuation, endpoint, source) = error.into_parts();
                self.host_continuation = Some(continuation);
                self.pending_child_qmp = endpoint;
                Err(LinuxQemuHotForkReconciliationError::Source(source))
            }
        }
    }

    fn terminate_child(&mut self) -> Result<(), Self::Error> {
        self.process_owner.process.kill().map_err(Into::into)
    }

    fn drain_child_diagnostics(&mut self) -> Result<(), Self::Error> {
        self.diagnostics_consumer
            .drain_available()
            .map(|_drain| ())
            .map_err(Into::into)
    }

    fn observe_child(&mut self) -> Result<QemuHotForkChildObservation, Self::Error> {
        let state = self.process_owner.observe_child()?;
        qmp_child_observation(state)
    }

    fn release_next_child_resource(&mut self) -> Result<bool, Self::Error> {
        loop {
            match self.source_release {
                LinuxSourceReleasePhase::CloseChildChannel => {
                    self.pending_child_qmp = None;
                    self.scheduler_node = None;
                    self.installed_node = None;
                    self.installed_node_id = None;
                    self.host_continuation = None;
                    self.source_release = LinuxSourceReleasePhase::PluginEndpoints;
                }
                LinuxSourceReleasePhase::PluginEndpoints => {
                    self.with_source_mut(|source| source.release_hot_fork_plugin_endpoints())?;
                    self.source_release = LinuxSourceReleasePhase::ChildQmp;
                    return Ok(false);
                }
                LinuxSourceReleasePhase::ChildQmp => {
                    self.with_source_mut(|source| source.release_hot_fork_child_qmp())?;
                    self.source_release = LinuxSourceReleasePhase::Diagnostics;
                    return Ok(false);
                }
                LinuxSourceReleasePhase::Diagnostics => {
                    let process_owner = Arc::clone(&self.process_owner);
                    let mut source = process_owner.source.lock().map_err(|_source| {
                        LinuxQemuHotForkReconciliationError::SourceOwnerPoisoned
                    })?;
                    let source = source
                        .as_mut()
                        .ok_or(LinuxQemuHotForkReconciliationError::BasisMismatch)?;
                    self.diagnostics =
                        Some(source.release_hot_fork_child_diagnostics_with_consumer(
                            &mut self.diagnostics_consumer,
                        )?);
                    self.source_release = LinuxSourceReleasePhase::PrivateRing;
                    return Ok(false);
                }
                LinuxSourceReleasePhase::PrivateRing => {
                    self.with_source_mut(|source| {
                        source.release_hot_fork_private_ring_mapping().map(drop)
                    })?;
                    self.source_release = LinuxSourceReleasePhase::Complete;
                    return Ok(true);
                }
                LinuxSourceReleasePhase::Complete => return Ok(true),
            }
        }
    }

    fn release_target(&mut self) -> Result<(), Self::Error> {
        self.target.finish().map_err(Into::into)
    }

    fn release_source_status(
        &mut self,
        terminal: QemuHotForkChildObservation,
    ) -> Result<(), Self::Error> {
        let released = self.with_source_mut(|source| {
            source.release_hot_fork_child_process(terminal.generation())
        })?;
        let observed = qmp_child_observation(released)?;
        if observed != terminal || released.retained() {
            return Err(LinuxQemuHotForkReconciliationError::BasisMismatch);
        }
        Ok(())
    }

    fn release_process_contract(&mut self) -> Result<(), Self::Error> {
        let state = self.with_source_mut(QemuNode::release_hot_fork_child_process_contract)?;
        if state.staged()
            || state.consumed()
            || state.generation() != self.basis.request().child_process_contract_generation()
        {
            return Err(LinuxQemuHotForkReconciliationError::BasisMismatch);
        }
        Ok(())
    }

    fn quarantine(&mut self) {
        let _ = self.process_owner.process.kill();
        self.target.quarantine();
    }
}

fn qmp_child_observation(
    state: QmpHotForkChildProcessState,
) -> Result<QemuHotForkChildObservation, LinuxQemuHotForkReconciliationError> {
    let disposition = match state.phase() {
        QmpHotForkChildProcessPhase::Running => QemuHotForkChildDisposition::Running,
        QmpHotForkChildProcessPhase::Exited => QemuHotForkChildDisposition::Exited(state.status()),
        QmpHotForkChildProcessPhase::Signaled if state.status() != 0 => {
            QemuHotForkChildDisposition::Signaled(state.status())
        }
        QmpHotForkChildProcessPhase::Signaled => {
            return Err(LinuxQemuHotForkReconciliationError::BasisMismatch);
        }
    };
    QemuHotForkChildObservation::new(state.generation(), state.child_process_id(), disposition)
        .map_err(|_source| LinuxQemuHotForkReconciliationError::BasisMismatch)
}

/// Launch failure retaining the reusable source and target attempt owner.
pub struct LinuxQemuHotForkAttemptLaunchError<G> {
    source: Box<QemuHotForkLaunchError>,
    template: Box<QemuPreparedHotForkTemplate<QemuNode>>,
    target: Box<G>,
}

impl<G> fmt::Debug for LinuxQemuHotForkAttemptLaunchError<G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxQemuHotForkAttemptLaunchError")
            .field("source", &self.source)
            .field("template_configuration", &self.template.configuration())
            .finish_non_exhaustive()
    }
}

impl<G> fmt::Display for LinuxQemuHotForkAttemptLaunchError<G> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "launch retained-template hot fork failed: {}",
            self.source
        )
    }
}

impl<G> Error for LinuxQemuHotForkAttemptLaunchError<G>
where
    G: 'static,
{
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

impl<G> LinuxQemuHotForkAttemptLaunchError<G> {
    /// Recovers the exact launch failure, source template, and target owner.
    pub fn into_parts(
        self,
    ) -> (
        QemuHotForkLaunchError,
        QemuPreparedHotForkTemplate<QemuNode>,
        G,
    ) {
        (*self.source, *self.template, *self.target)
    }
}

/// Failure to launch one child through an aggregate World resource owner.
#[derive(Debug, Error)]
pub enum LinuxQemuHotForkWorldAttemptLaunchFailure {
    /// The aggregate target owner rejected reservation or launch access.
    #[error("aggregate hot-fork World resource admission failed: {0}")]
    Target(#[source] QemuVmRealizationError),
    /// QEMU rejected or failed the retained-template fork transaction.
    #[error(transparent)]
    Launch(#[from] QemuHotForkLaunchError),
    /// An explicit no-child rejection could not roll back its reservation.
    #[error(
        "hot-fork launch was rejected before child creation, but target rollback failed: {rollback}"
    )]
    RejectedRollback {
        /// Original explicit no-child fork rejection.
        launch: QemuHotForkLaunchError,
        /// Aggregate target-reservation rollback failure.
        #[source]
        rollback: QemuVmRealizationError,
    },
}

/// Aggregate-World launch failure retaining the exact source template.
#[must_use = "recover or quarantine the returned source template"]
pub struct LinuxQemuHotForkWorldAttemptLaunchError {
    source: Box<LinuxQemuHotForkWorldAttemptLaunchFailure>,
    template: Box<QemuPreparedHotForkTemplate<QemuNode>>,
}

impl fmt::Debug for LinuxQemuHotForkWorldAttemptLaunchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxQemuHotForkWorldAttemptLaunchError")
            .field("source", &self.source)
            .field("template_configuration", &self.template.configuration())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for LinuxQemuHotForkWorldAttemptLaunchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "launch retained-template World child failed: {}",
            self.source
        )
    }
}

impl Error for LinuxQemuHotForkWorldAttemptLaunchError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

impl LinuxQemuHotForkWorldAttemptLaunchError {
    /// Recovers the exact launch failure and retained source template.
    pub fn into_parts(
        self,
    ) -> (
        LinuxQemuHotForkWorldAttemptLaunchFailure,
        QemuPreparedHotForkTemplate<QemuNode>,
    ) {
        (*self.source, *self.template)
    }
}

impl<G> QemuHotForkAttemptReconciliation<LinuxQemuHotForkReconciliationBackend<G>>
where
    G: crate::QemuAttemptProcessResourceGuard
        + QemuHotForkChildProcessOwner<Authority = LinuxQemuHotForkChildProcessAuthority>,
{
    /// Forks a retained source directly into one target reconciliation owner.
    ///
    /// The source derives the exact fork request from QEMU's retained template
    /// and child-resource reports. This operation obtains the target's sealed
    /// process contract, installs it into the exact prepared template, and
    /// rolls it back after an explicit pre-fork rejection. Callers therefore
    /// cannot omit or substitute the target containment basis or inject any
    /// generation value. No successful launch token is exposed outside the
    /// owner. Post-fork failures return both authorities in their already-
    /// quarantined state for caller-directed cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuHotForkAttemptLaunchError`] with the source and target
    /// authorities when QEMU rejects the request or launch ownership cannot be
    /// established exactly.
    pub fn launch(
        attempt: QemuHotForkAttemptBasis,
        input: &CrucibleAttemptExecution,
        template: QemuPreparedHotForkTemplate<QemuNode>,
        target: G,
    ) -> Result<Self, LinuxQemuHotForkAttemptLaunchError<G>> {
        Self::launch_inner(attempt, input, template, target, None)
    }

    fn launch_inner(
        attempt: QemuHotForkAttemptBasis,
        input: &CrucibleAttemptExecution,
        template: QemuPreparedHotForkTemplate<QemuNode>,
        mut target: G,
        world_assembly: Option<QemuHotForkWorldAssemblyToken>,
    ) -> Result<Self, LinuxQemuHotForkAttemptLaunchError<G>> {
        let (mut source_node, template_identity) = template.into_parts();
        match source_node.fork_prepared_hot_fork_template_into(&mut target, |target| {
            target.child_process_contract().map_err(|source| {
                QemuNodeChannelError::new(
                    "obtain target hot-fork process contract",
                    source.to_string(),
                )
            })
        }) {
            Ok(launch) => Ok(Self::new(
                attempt,
                LinuxQemuHotForkReconciliationBackend::from_launch(
                    source_node,
                    template_identity,
                    input.clone(),
                    world_assembly,
                    target,
                    launch,
                ),
            )),
            Err(source) => Err(LinuxQemuHotForkAttemptLaunchError {
                source: Box::new(source),
                template: Box::new(QemuPreparedHotForkTemplate::from_reconciled_parts(
                    source_node,
                    template_identity,
                )),
                target: Box::new(target),
            }),
        }
    }
}

impl<G>
    QemuHotForkAttemptReconciliation<
        LinuxQemuHotForkReconciliationBackend<QemuHotForkWorldNodeTarget<G>>,
    >
where
    G: crate::QemuAttemptProcessResourceGuard
        + QemuHotForkChildProcessOwner<Authority = LinuxQemuHotForkChildProcessAuthority>,
{
    /// Forks one node through the exact aggregate World target owner.
    ///
    /// The node target is reserved before QEMU can create a child. An explicit
    /// pre-fork rejection rolls that reservation back; every ambiguous or
    /// post-fork failure quarantines the complete aggregate owner. Success
    /// retains only a per-node release share in the reconciliation backend, so
    /// no child can independently release CPU, memory, storage, cancellation,
    /// or execution-quantum enforcement for the rest of the World.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuHotForkWorldAttemptLaunchError`] with the exact source
    /// template after target reservation, fork, or rollback failure. The target
    /// owner remains with the caller and is either reusable after a proven
    /// no-child rejection or terminally quarantined.
    pub fn launch_for_world(
        attempt: QemuHotForkAttemptBasis,
        input: &CrucibleAttemptExecution,
        template: QemuPreparedHotForkTemplate<QemuNode>,
        target: &mut QemuHotForkWorldResourceOwner<G>,
        node_generation: ProductionVmNodeGeneration,
        world_assembly: QemuHotForkWorldAssemblyToken,
    ) -> Result<Self, LinuxQemuHotForkWorldAttemptLaunchError> {
        let node_target = match target.reserve_node(node_generation) {
            Ok(node_target) => node_target,
            Err(source) => {
                return Err(LinuxQemuHotForkWorldAttemptLaunchError {
                    source: Box::new(LinuxQemuHotForkWorldAttemptLaunchFailure::Target(source)),
                    template: Box::new(template),
                });
            }
        };
        let (mut source_node, template_identity) = template.into_parts();
        let launched = target.with_guard_mut(|guard| {
            source_node.fork_prepared_hot_fork_template_into(guard, |guard| {
                guard.child_process_contract().map_err(|source| {
                    QemuNodeChannelError::new(
                        "obtain aggregate target hot-fork process contract",
                        source.to_string(),
                    )
                })
            })
        });
        let launch = match launched {
            Ok(Ok(launch)) => launch,
            Ok(Err(source @ QemuHotForkLaunchError::Rejected { .. })) => {
                let failure = match node_target.abort_without_child() {
                    Ok(()) => LinuxQemuHotForkWorldAttemptLaunchFailure::Launch(source),
                    Err(rollback) => {
                        target.quarantine();
                        LinuxQemuHotForkWorldAttemptLaunchFailure::RejectedRollback {
                            launch: source,
                            rollback,
                        }
                    }
                };
                return Err(LinuxQemuHotForkWorldAttemptLaunchError {
                    source: Box::new(failure),
                    template: Box::new(QemuPreparedHotForkTemplate::from_reconciled_parts(
                        source_node,
                        template_identity,
                    )),
                });
            }
            Ok(Err(source)) => {
                let mut node_target = node_target;
                crate::QemuAttemptResourceGuard::quarantine(&mut node_target);
                return Err(LinuxQemuHotForkWorldAttemptLaunchError {
                    source: Box::new(LinuxQemuHotForkWorldAttemptLaunchFailure::Launch(source)),
                    template: Box::new(QemuPreparedHotForkTemplate::from_reconciled_parts(
                        source_node,
                        template_identity,
                    )),
                });
            }
            Err(source) => {
                let rollback = node_target.abort_without_child();
                let failure = match rollback {
                    Ok(()) => LinuxQemuHotForkWorldAttemptLaunchFailure::Target(source),
                    Err(rollback) => {
                        target.quarantine();
                        LinuxQemuHotForkWorldAttemptLaunchFailure::Target(
                            QemuVmRealizationError::Executor {
                                operation: "roll back aggregate hot-fork target reservation",
                                message: format!(
                                    "launch access failed: {source}; rollback failed: {rollback}"
                                ),
                            },
                        )
                    }
                };
                return Err(LinuxQemuHotForkWorldAttemptLaunchError {
                    source: Box::new(failure),
                    template: Box::new(QemuPreparedHotForkTemplate::from_reconciled_parts(
                        source_node,
                        template_identity,
                    )),
                });
            }
        };

        Ok(Self::new(
            attempt,
            LinuxQemuHotForkReconciliationBackend::from_launch(
                source_node,
                template_identity,
                input.clone(),
                Some(world_assembly),
                node_target,
                launch,
            ),
        ))
    }
}

impl<G> QemuHotForkAttemptReconciliation<LinuxQemuHotForkReconciliationBackend<G>>
where
    G: crate::QemuAttemptResourceGuard,
{
    /// Borrows the admitted live-child capability while the child is live.
    ///
    /// The capability joins private QMP, plugin/host-I/O continuation,
    /// diagnostics service, and the non-releasing resource boundary. Modeled
    /// execution must charge progress through this value, which drains the
    /// branch-private diagnostic stream before every operational boundary.
    #[must_use]
    pub fn live_child_mut(&mut self) -> Option<LinuxQemuHotForkLiveChild<'_>> {
        if self.phase != QemuHotForkReconciliationPhase::Live {
            return None;
        }
        self.backend.as_mut()?.live_child_mut()
    }

    /// Installs the admitted continuation as an externally parented QEMU node.
    ///
    /// # Errors
    ///
    /// Returns an invalid-phase error before child admission or a backend
    /// error while retaining every source, target, and continuation authority.
    pub fn install_scheduler_node(
        &mut self,
        node: NodeId,
        shutdown_policy: QemuShutdownPolicy,
        async_policy: QemuAsyncDriverPolicy,
        crash_detector: QemuCrashDetector,
    ) -> Result<(), Box<QemuHotForkAttemptReconciliationError<LinuxQemuHotForkReconciliationError>>>
    {
        self.require_phase(
            "install hot-fork scheduler node",
            QemuHotForkReconciliationPhase::Live,
        )
        .map_err(Box::new)?;
        self.backend_mut()
            .map_err(Box::new)?
            .install_scheduler_node(node, shutdown_policy, async_policy, crash_detector)
            .map_err(|source| {
                Box::new(QemuHotForkAttemptReconciliationError::Operation {
                    operation: "install hot-fork scheduler node",
                    source,
                })
            })
    }

    /// Borrows the installed process-neutral QEMU node while the child is live.
    #[must_use]
    pub fn installed_scheduler_node_mut(&mut self) -> Option<&mut QemuNode> {
        if self.phase != QemuHotForkReconciliationPhase::Live {
            return None;
        }
        self.backend.as_mut()?.installed_scheduler_node_mut()
    }

    /// Returns the authenticated source basis for atomic world admission.
    ///
    /// The basis is available only while the exact child remains live and its
    /// process-neutral scheduler node has been installed. This prevents a
    /// world transaction from admitting a raw fork result whose private host
    /// continuation has not completed child-channel authentication.
    ///
    /// # Errors
    ///
    /// Returns a phase or backend error when the child is not ready for world
    /// admission or the retained source process can no longer be authenticated.
    pub fn world_child_source_basis(
        &self,
    ) -> Result<
        QemuHotForkWorldChildSourceBasis,
        Box<QemuHotForkAttemptReconciliationError<LinuxQemuHotForkReconciliationError>>,
    > {
        self.require_phase(
            "authenticate hot-fork child for world admission",
            QemuHotForkReconciliationPhase::Live,
        )
        .map_err(Box::new)?;
        let backend = self.backend_ref().map_err(Box::new)?;
        if backend.installed_node.is_none() {
            return Err(Box::new(
                QemuHotForkAttemptReconciliationError::InvalidPhase {
                    operation: "authenticate installed hot-fork scheduler node",
                    phase: self.phase,
                },
            ));
        }
        backend.world_child_source_basis().map_err(|source| {
            Box::new(QemuHotForkAttemptReconciliationError::Operation {
                operation: "authenticate hot-fork source basis",
                source,
            })
        })
    }

    /// Returns the exact atomic world assembly for which this child launched.
    ///
    /// Legacy single-node launches return `None` and therefore cannot be
    /// admitted into an atomic multi-node world.
    #[must_use]
    pub fn world_assembly_token(&self) -> Option<&QemuHotForkWorldAssemblyToken> {
        self.backend
            .as_ref()
            .and_then(|backend| backend.world_assembly.as_ref())
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
    #![allow(clippy::expect_used)]

    use std::collections::VecDeque;
    use std::io;
    use std::sync::{Arc, Mutex};

    use crucible_campaign::{AttemptId, CampaignLineageId, ExecutionId};

    use super::*;
    use crate::{
        AttemptExecutionDisposition, AttemptExecutionKey, AttemptExecutionReconciliationStep,
    };

    #[derive(Debug, Error)]
    #[error("injected reconciliation failure")]
    struct ScriptedError;

    struct ScriptedBackend {
        basis: QemuHotForkReconciliationChildBasis,
        observations: VecDeque<QemuHotForkChildObservation>,
        calls: Arc<Mutex<Vec<&'static str>>>,
        fail_drain_once: bool,
        fail_release_resources_once: bool,
        resource_substeps_before_complete: u8,
    }

    impl QemuHotForkReconciliationBackend for ScriptedBackend {
        type Error = ScriptedError;

        fn child_basis(&self) -> QemuHotForkReconciliationChildBasis {
            self.basis
        }

        fn admit_child_channel(&mut self) -> Result<(), Self::Error> {
            self.calls.lock().expect("calls").push("admit");
            Ok(())
        }

        fn terminate_child(&mut self) -> Result<(), Self::Error> {
            self.calls.lock().expect("calls").push("terminate");
            Ok(())
        }

        fn drain_child_diagnostics(&mut self) -> Result<(), Self::Error> {
            self.calls.lock().expect("calls").push("drain");
            if self.fail_drain_once {
                self.fail_drain_once = false;
                return Err(ScriptedError);
            }
            Ok(())
        }

        fn observe_child(&mut self) -> Result<QemuHotForkChildObservation, Self::Error> {
            self.calls.lock().expect("calls").push("observe");
            self.observations.pop_front().ok_or(ScriptedError)
        }

        fn release_next_child_resource(&mut self) -> Result<bool, Self::Error> {
            self.calls.lock().expect("calls").push("resources");
            if self.fail_release_resources_once {
                self.fail_release_resources_once = false;
                return Err(ScriptedError);
            }
            if self.resource_substeps_before_complete != 0 {
                self.resource_substeps_before_complete -= 1;
                return Ok(false);
            }
            Ok(true)
        }

        fn release_target(&mut self) -> Result<(), Self::Error> {
            self.calls.lock().expect("calls").push("target");
            Ok(())
        }

        fn release_source_status(
            &mut self,
            _terminal: QemuHotForkChildObservation,
        ) -> Result<(), Self::Error> {
            self.calls.lock().expect("calls").push("status");
            Ok(())
        }

        fn release_process_contract(&mut self) -> Result<(), Self::Error> {
            self.calls.lock().expect("calls").push("contract");
            Ok(())
        }

        fn quarantine(&mut self) {
            self.calls.lock().expect("calls").push("quarantine");
        }
    }

    fn basis() -> QemuHotForkReconciliationChildBasis {
        QemuHotForkReconciliationChildBasis::new(41, 4242)
    }

    fn attempt_basis() -> QemuHotForkAttemptBasis {
        QemuHotForkAttemptBasis::new(
            AttemptExecutionKey::new(
                CampaignLineageId::parse(&typed_id(
                    "crucible.campaign.lineage",
                    "campaign-fact",
                    0x31,
                ))
                .expect("lineage"),
                AttemptId::parse(&typed_id(
                    "crucible.campaign.attempt",
                    "campaign-fact",
                    0x32,
                ))
                .expect("attempt"),
            ),
            ExecutionId::from_bytes([0x33; 16]).expect("execution"),
        )
    }

    fn typed_id(tag: &str, kind: &str, byte: u8) -> String {
        format!("{tag}@{kind}.1.{}", encode_hex(&[byte; 32]))
    }

    fn encode_hex(bytes: &[u8]) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut encoded = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            encoded.push(HEX[(byte >> 4) as usize] as char);
            encoded.push(HEX[(byte & 0x0f) as usize] as char);
        }
        encoded
    }

    fn observed(
        basis: QemuHotForkReconciliationChildBasis,
        disposition: QemuHotForkChildDisposition,
    ) -> QemuHotForkChildObservation {
        QemuHotForkChildObservation::new(basis.generation(), basis.process_id(), disposition)
            .expect("valid child observation")
    }

    fn service_and_observe(
        owner: &mut QemuHotForkAttemptReconciliation<ScriptedBackend>,
    ) -> QemuHotForkReconciliationStep {
        assert_eq!(
            owner.reconcile_step().expect("service child diagnostics"),
            QemuHotForkReconciliationStep::ChildDiagnosticsDrained
        );
        owner.reconcile_step().expect("observe child status")
    }

    fn scripted(
        dispositions: impl IntoIterator<Item = QemuHotForkChildDisposition>,
        fail_release_resources_once: bool,
    ) -> (
        QemuHotForkAttemptReconciliation<ScriptedBackend>,
        Arc<Mutex<Vec<&'static str>>>,
    ) {
        scripted_with_resource_substeps(dispositions, fail_release_resources_once, 0)
    }

    fn scripted_with_resource_substeps(
        dispositions: impl IntoIterator<Item = QemuHotForkChildDisposition>,
        fail_release_resources_once: bool,
        resource_substeps_before_complete: u8,
    ) -> (
        QemuHotForkAttemptReconciliation<ScriptedBackend>,
        Arc<Mutex<Vec<&'static str>>>,
    ) {
        let basis = basis();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let observations = dispositions
            .into_iter()
            .map(|disposition| observed(basis, disposition))
            .collect();
        (
            QemuHotForkAttemptReconciliation::new(
                attempt_basis(),
                ScriptedBackend {
                    basis,
                    observations,
                    calls: Arc::clone(&calls),
                    fail_drain_once: false,
                    fail_release_resources_once,
                    resource_substeps_before_complete,
                },
            ),
            calls,
        )
    }

    #[test]
    fn exact_terminal_cleanup_waits_for_semantic_publication() {
        let (mut owner, calls) = scripted(
            [
                QemuHotForkChildDisposition::Running,
                QemuHotForkChildDisposition::Exited(0),
            ],
            false,
        );
        owner.admit_child().expect("admit child");
        assert_eq!(
            service_and_observe(&mut owner),
            QemuHotForkReconciliationStep::ChildRunning
        );
        assert_eq!(
            service_and_observe(&mut owner),
            QemuHotForkReconciliationStep::Advanced(QemuHotForkReconciliationPhase::ParentReaped)
        );
        assert_eq!(
            owner.reconcile_step().expect("release child resources"),
            QemuHotForkReconciliationStep::Advanced(
                QemuHotForkReconciliationPhase::ChildResourcesReleased
            )
        );
        assert_eq!(
            owner.reconcile_step().expect("release target"),
            QemuHotForkReconciliationStep::Advanced(QemuHotForkReconciliationPhase::TargetReleased)
        );
        assert_eq!(
            owner.reconcile_step().expect("await publication"),
            QemuHotForkReconciliationStep::AwaitingPublication
        );
        assert_eq!(
            calls.lock().expect("calls").as_slice(),
            [
                "drain",
                "admit",
                "drain",
                "observe",
                "drain",
                "observe",
                "resources",
                "target"
            ]
        );

        let observation = ObservationId::parse(&typed_id(
            "crucible.campaign.observation",
            "observation",
            0x44,
        ))
        .expect("observation");
        owner
            .reconcile_publication(QemuHotForkPublicationDisposition::Observation(observation))
            .expect("publication");
        assert_eq!(
            owner.reconcile_step().expect("release status"),
            QemuHotForkReconciliationStep::Advanced(
                QemuHotForkReconciliationPhase::SourceStatusReleased
            )
        );
        assert_eq!(
            owner.reconcile_step().expect("release contract"),
            QemuHotForkReconciliationStep::Complete
        );
        assert_eq!(
            calls.lock().expect("calls").as_slice(),
            [
                "drain",
                "admit",
                "drain",
                "observe",
                "drain",
                "observe",
                "resources",
                "target",
                "status",
                "contract",
            ]
        );
        let backend = match owner.into_reconciled_backend() {
            Ok(backend) => backend,
            Err(_owner) => panic!("expected a reconciled backend"),
        };
        drop(backend);
        assert!(!calls.lock().expect("calls").contains(&"quarantine"));
    }

    #[test]
    fn retry_resumes_at_the_first_unreleased_phase_without_rerunning_guest() {
        let (mut owner, calls) = scripted([QemuHotForkChildDisposition::Signaled(9)], true);
        owner.request_termination().expect("terminate");
        service_and_observe(&mut owner);
        assert!(owner.reconcile_step().is_err());
        assert_eq!(owner.phase(), QemuHotForkReconciliationPhase::ParentReaped);
        owner.reconcile_step().expect("retry resources");
        assert_eq!(
            calls.lock().expect("calls").as_slice(),
            ["terminate", "drain", "observe", "resources", "resources"]
        );
        owner.quarantine();
    }

    #[test]
    fn diagnostic_drain_failure_quarantines_before_status_observation() {
        let child_basis = basis();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut owner = QemuHotForkAttemptReconciliation::new(
            attempt_basis(),
            ScriptedBackend {
                basis: child_basis,
                observations: VecDeque::from([observed(
                    child_basis,
                    QemuHotForkChildDisposition::Running,
                )]),
                calls: Arc::clone(&calls),
                fail_drain_once: true,
                fail_release_resources_once: false,
                resource_substeps_before_complete: 0,
            },
        );

        assert!(matches!(
            owner.reconcile_step(),
            Err(QemuHotForkAttemptReconciliationError::Operation {
                operation: "drain branch-private child diagnostics",
                ..
            })
        ));
        assert_eq!(owner.phase(), QemuHotForkReconciliationPhase::Quarantined);
        assert_eq!(
            calls.lock().expect("calls").as_slice(),
            ["drain", "quarantine"]
        );
    }

    #[test]
    fn diagnostic_drain_failure_quarantines_before_child_admission() {
        let child_basis = basis();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut owner = QemuHotForkAttemptReconciliation::new(
            attempt_basis(),
            ScriptedBackend {
                basis: child_basis,
                observations: VecDeque::new(),
                calls: Arc::clone(&calls),
                fail_drain_once: true,
                fail_release_resources_once: false,
                resource_substeps_before_complete: 0,
            },
        );

        assert!(matches!(
            owner.admit_child(),
            Err(QemuHotForkAttemptReconciliationError::Operation {
                operation: "drain child diagnostics before admission",
                ..
            })
        ));
        assert_eq!(owner.phase(), QemuHotForkReconciliationPhase::Quarantined);
        assert_eq!(
            calls.lock().expect("calls").as_slice(),
            ["drain", "quarantine"]
        );
    }

    #[test]
    fn one_step_releases_at_most_one_backend_owned_child_resource() {
        let (mut owner, calls) =
            scripted_with_resource_substeps([QemuHotForkChildDisposition::Exited(0)], false, 2);
        service_and_observe(&mut owner);
        for _ in 0..2 {
            assert_eq!(
                owner.reconcile_step().expect("release one substep"),
                QemuHotForkReconciliationStep::Advanced(
                    QemuHotForkReconciliationPhase::ParentReaped
                )
            );
        }
        assert_eq!(
            owner.reconcile_step().expect("finish child resources"),
            QemuHotForkReconciliationStep::Advanced(
                QemuHotForkReconciliationPhase::ChildResourcesReleased
            )
        );
        assert_eq!(
            calls.lock().expect("calls").as_slice(),
            ["drain", "observe", "resources", "resources", "resources"]
        );
        owner.quarantine();
    }

    #[test]
    fn dropping_incomplete_owner_transfers_cleanup_to_quarantine() {
        let (owner, calls) = scripted([QemuHotForkChildDisposition::Running], false);
        drop(owner);
        assert_eq!(calls.lock().expect("calls").as_slice(), ["quarantine"]);
    }

    #[test]
    fn explicitly_quarantined_owner_does_not_transfer_twice_on_drop() {
        let (mut owner, calls) = scripted([QemuHotForkChildDisposition::Running], false);
        owner.quarantine();
        drop(owner);
        assert_eq!(calls.lock().expect("calls").as_slice(), ["quarantine"]);
    }

    #[test]
    fn unadmitted_child_cannot_publish_a_modeled_observation() {
        let (mut owner, _calls) = scripted([QemuHotForkChildDisposition::Signaled(9)], false);
        owner.request_termination().expect("terminate");
        service_and_observe(&mut owner);
        owner.reconcile_step().expect("release resources");
        owner.reconcile_step().expect("release target");
        owner.reconcile_step().expect("await publication");

        let observation = ObservationId::parse(&typed_id(
            "crucible.campaign.observation",
            "observation",
            0x45,
        ))
        .expect("observation");
        assert!(matches!(
            owner
                .reconcile_publication(QemuHotForkPublicationDisposition::Observation(observation)),
            Err(QemuHotForkAttemptReconciliationError::ModeledResultWithoutAdmission)
        ));
        owner
            .reconcile_publication(QemuHotForkPublicationDisposition::TerminalFailure)
            .expect("terminal failure disposition");
        owner.quarantine();
    }

    #[test]
    fn worker_disposition_drives_the_retained_owner_to_completion() {
        let (mut owner, calls) = scripted([QemuHotForkChildDisposition::Exited(0)], false);
        owner.admit_child().expect("admit child");
        service_and_observe(&mut owner);
        owner.reconcile_step().expect("release child resources");
        owner.reconcile_step().expect("release target");
        owner.reconcile_step().expect("await publication");

        let observation = observation_id(0x46);
        assert_eq!(
            owner
                .reconcile_execution_disposition(AttemptExecutionDisposition::Observation(
                    observation,
                ))
                .expect("release source status"),
            AttemptExecutionReconciliationStep::Progressed
        );
        assert!(matches!(
            owner.reconcile_execution_disposition(AttemptExecutionDisposition::Canceled),
            Err(QemuHotForkAttemptReconciliationError::PublicationDispositionMismatch)
        ));
        assert_eq!(
            owner
                .reconcile_execution_disposition(AttemptExecutionDisposition::Observation(
                    observation,
                ))
                .expect("release process contract"),
            AttemptExecutionReconciliationStep::Complete
        );
        assert_eq!(
            calls.lock().expect("calls").as_slice(),
            [
                "drain",
                "admit",
                "drain",
                "observe",
                "resources",
                "target",
                "status",
                "contract"
            ]
        );
        let Ok(backend) = owner.into_reconciled_backend() else {
            panic!("owner should be fully reconciled")
        };
        drop(backend);
    }

    #[test]
    fn a_foreign_parent_observation_fails_before_any_release() {
        let basis = basis();
        let calls = Arc::new(Mutex::new(Vec::new()));
        let mut owner = QemuHotForkAttemptReconciliation::new(
            attempt_basis(),
            ScriptedBackend {
                basis,
                observations: VecDeque::from([QemuHotForkChildObservation::new(
                    basis.generation(),
                    basis.process_id() + 1,
                    QemuHotForkChildDisposition::Exited(0),
                )
                .expect("foreign observation")]),
                calls: Arc::clone(&calls),
                fail_drain_once: false,
                fail_release_resources_once: false,
                resource_substeps_before_complete: 0,
            },
        );
        assert_eq!(
            owner.reconcile_step().expect("service child diagnostics"),
            QemuHotForkReconciliationStep::ChildDiagnosticsDrained
        );
        assert!(matches!(
            owner.reconcile_step(),
            Err(QemuHotForkAttemptReconciliationError::ChildBasisMismatch)
        ));
        assert_eq!(
            calls.lock().expect("calls").as_slice(),
            ["drain", "observe"]
        );
        owner.quarantine();
    }

    #[test]
    fn io_error_type_remains_send_sync_for_worker_ownership() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<io::Error>();
        assert_send_sync::<LinuxQemuHotForkReconciliationError>();
    }

    fn observation_id(byte: u8) -> ObservationId {
        ObservationId::parse(&typed_id(
            "crucible.campaign.observation",
            "observation",
            byte,
        ))
        .expect("observation")
    }
}
