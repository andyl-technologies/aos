//! Attempt-scoped ownership and reconciliation for one QEMU hot-fork child.
//!
//! A successful retained-template fork creates authorities in two process
//! hierarchies: the source QEMU remains the child's direct parent and owns its
//! exact `waitpid` result, while the target attempt owner retains the cgroup,
//! sticky cancellation signal, and an independent pidfd. This module keeps
//! those authorities, the private child QMP endpoint, executor accounting
//! basis, and publication disposition in one linear state machine. No source
//! record or process-contract descriptor is released until child reap, target
//! cgroup cleanup, and the semantic publication outcome are all known.

use std::error::Error;
use std::fmt;
use std::os::unix::net::UnixStream;

use crucible_campaign::{ExecutionId, ObservationId};
use crucible_qemu::{
    LinuxQemuAttemptProcessOwner, LinuxQemuHotForkChildProcessAuthority, QemuHotForkChildLaunch,
    QemuHotForkChildProcessBasis, QemuHotForkChildQmpHandshakeError, QemuHotForkLaunchError,
    QemuNode, QemuNodeChannelError, QemuQmpVmStateControlChannel, QemuVmRealizationError,
    QmpHotForkChildProcessPhase, QmpHotForkChildProcessState,
};
use thiserror::Error;

use crate::AttemptExecutionKey;

/// Exact supervisor reservation owning one hot-fork realization.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuHotForkAttemptBasis {
    key: AttemptExecutionKey,
    execution: ExecutionId,
}

impl QemuHotForkAttemptBasis {
    /// Binds one lineage-qualified attempt to its process-local execution.
    #[must_use]
    pub const fn new(key: AttemptExecutionKey, execution: ExecutionId) -> Self {
        Self { key, execution }
    }

    /// Returns the exact lineage-qualified semantic attempt.
    #[must_use]
    pub const fn key(self) -> AttemptExecutionKey {
        self.key
    }

    /// Returns the supervisor's process-local execution incarnation.
    #[must_use]
    pub const fn execution(self) -> ExecutionId {
        self.execution
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
    /// An observation cannot be accepted for a child that never passed admission.
    #[error("hot-fork observation publication requires an admitted private child channel")]
    ObservationWithoutAdmission,
    /// One backend operation failed while retaining reconciliation authority.
    #[error("hot-fork backend operation {operation} failed: {source}")]
    Backend {
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
        let admission = self.backend_mut()?.admit_child_channel();
        if let Err(source) = admission {
            if let Some(backend) = self.backend.as_mut() {
                backend.quarantine();
            }
            self.phase = QemuHotForkReconciliationPhase::Quarantined;
            return Err(QemuHotForkAttemptReconciliationError::Backend {
                operation: "admit private child channel",
                source,
            });
        }
        self.child_admitted = true;
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
        self.backend_mut()?.terminate_child().map_err(|source| {
            QemuHotForkAttemptReconciliationError::Backend {
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
        ) && !self.child_admitted
        {
            return Err(QemuHotForkAttemptReconciliationError::ObservationWithoutAdmission);
        }
        self.publication = Some(disposition);
        self.phase = QemuHotForkReconciliationPhase::PublicationReconciled;
        Ok(())
    }

    /// Performs at most one bounded reconciliation operation.
    ///
    /// The caller schedules subsequent calls without holding the executor
    /// supervisor actor. A running child performs only one nonblocking parent
    /// query. Every destructive success advances the phase before returning,
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
                let observed = self.backend_mut()?.observe_child().map_err(|source| {
                    QemuHotForkAttemptReconciliationError::Backend {
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
                        .map_err(|source| QemuHotForkAttemptReconciliationError::Backend {
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
                    QemuHotForkAttemptReconciliationError::Backend {
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
                    .map_err(|source| QemuHotForkAttemptReconciliationError::Backend {
                        operation: "release source-owned child status",
                        source,
                    })?;
                self.phase = QemuHotForkReconciliationPhase::SourceStatusReleased;
                Ok(QemuHotForkReconciliationStep::Advanced(self.phase))
            }
            QemuHotForkReconciliationPhase::SourceStatusReleased => {
                self.backend_mut()?
                    .release_process_contract()
                    .map_err(|source| QemuHotForkAttemptReconciliationError::Backend {
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

/// Concrete source-QEMU, pidfd, cgroup, and private-channel owner.
pub struct LinuxQemuHotForkReconciliationBackend {
    source: QemuNode,
    target: LinuxQemuAttemptProcessOwner,
    process: LinuxQemuHotForkChildProcessAuthority,
    basis: QemuHotForkChildProcessBasis,
    pending_child_qmp: Option<crucible_qemu::QemuHotForkChildQmpHostEndpoint>,
    child_qmp: Option<QemuQmpVmStateControlChannel<UnixStream>>,
    source_release: LinuxSourceReleasePhase,
    diagnostics: Option<crucible_qemu::QemuHotForkChildDiagnosticCapture>,
}

impl fmt::Debug for LinuxQemuHotForkReconciliationBackend {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxQemuHotForkReconciliationBackend")
            .field("basis", &self.basis)
            .field("pending_child_qmp", &self.pending_child_qmp.is_some())
            .field("child_qmp_admitted", &self.child_qmp.is_some())
            .field("source_release", &self.source_release)
            .field("diagnostics", &self.diagnostics.is_some())
            .finish_non_exhaustive()
    }
}

impl LinuxQemuHotForkReconciliationBackend {
    fn from_launch(
        source: QemuNode,
        target: LinuxQemuAttemptProcessOwner,
        launch: QemuHotForkChildLaunch<LinuxQemuHotForkChildProcessAuthority>,
    ) -> Self {
        let (_parent, process, child_qmp) = launch.into_parts();
        let basis = process.basis();
        Self {
            source,
            target,
            process,
            basis,
            pending_child_qmp: Some(child_qmp),
            child_qmp: None,
            source_release: LinuxSourceReleasePhase::CloseChildChannel,
            diagnostics: None,
        }
    }

    /// Returns mutable access to the authenticated private child QMP channel.
    #[must_use]
    pub fn child_qmp_mut(&mut self) -> Option<&mut QemuQmpVmStateControlChannel<UnixStream>> {
        self.child_qmp.as_mut()
    }

    /// Returns the bounded final child diagnostic capture after source release.
    #[must_use]
    pub const fn diagnostics(&self) -> Option<&crucible_qemu::QemuHotForkChildDiagnosticCapture> {
        self.diagnostics.as_ref()
    }

    /// Consumes a reconciled backend into its reusable source template.
    #[must_use]
    pub fn into_source(self) -> QemuNode {
        self.source
    }
}

impl QemuHotForkReconciliationBackend for LinuxQemuHotForkReconciliationBackend {
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
        self.child_qmp = Some(endpoint.connect()?);
        Ok(())
    }

    fn terminate_child(&mut self) -> Result<(), Self::Error> {
        self.process.kill().map_err(Into::into)
    }

    fn observe_child(&mut self) -> Result<QemuHotForkChildObservation, Self::Error> {
        let state = self
            .source
            .query_hot_fork_child_process(self.basis.request().child_process_generation())?;
        qmp_child_observation(state)
    }

    fn release_next_child_resource(&mut self) -> Result<bool, Self::Error> {
        loop {
            match self.source_release {
                LinuxSourceReleasePhase::CloseChildChannel => {
                    self.pending_child_qmp = None;
                    self.child_qmp = None;
                    self.source_release = LinuxSourceReleasePhase::PluginEndpoints;
                }
                LinuxSourceReleasePhase::PluginEndpoints => {
                    self.source.release_hot_fork_plugin_endpoints()?;
                    self.source_release = LinuxSourceReleasePhase::ChildQmp;
                    return Ok(false);
                }
                LinuxSourceReleasePhase::ChildQmp => {
                    self.source.release_hot_fork_child_qmp()?;
                    self.source_release = LinuxSourceReleasePhase::Diagnostics;
                    return Ok(false);
                }
                LinuxSourceReleasePhase::Diagnostics => {
                    self.diagnostics = Some(self.source.release_hot_fork_child_diagnostics()?);
                    self.source_release = LinuxSourceReleasePhase::PrivateRing;
                    return Ok(false);
                }
                LinuxSourceReleasePhase::PrivateRing => {
                    drop(self.source.release_hot_fork_private_ring_mapping()?);
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
        let released = self
            .source
            .release_hot_fork_child_process(terminal.generation())?;
        let observed = qmp_child_observation(released)?;
        if observed != terminal || released.retained() {
            return Err(LinuxQemuHotForkReconciliationError::BasisMismatch);
        }
        Ok(())
    }

    fn release_process_contract(&mut self) -> Result<(), Self::Error> {
        let state = self.source.release_hot_fork_child_process_contract()?;
        if state.staged()
            || state.consumed()
            || state.generation() != self.basis.request().child_process_contract_generation()
        {
            return Err(LinuxQemuHotForkReconciliationError::BasisMismatch);
        }
        Ok(())
    }

    fn quarantine(&mut self) {
        let _ = self.process.kill();
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
pub struct LinuxQemuHotForkAttemptLaunchError {
    source: Box<QemuHotForkLaunchError>,
    template: Box<QemuNode>,
    target: Box<LinuxQemuAttemptProcessOwner>,
}

impl fmt::Debug for LinuxQemuHotForkAttemptLaunchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LinuxQemuHotForkAttemptLaunchError")
            .field("source", &self.source)
            .field("template_process_id", &self.template.process_id())
            .finish_non_exhaustive()
    }
}

impl fmt::Display for LinuxQemuHotForkAttemptLaunchError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "launch retained-template hot fork failed: {}",
            self.source
        )
    }
}

impl Error for LinuxQemuHotForkAttemptLaunchError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.source.as_ref())
    }
}

impl LinuxQemuHotForkAttemptLaunchError {
    /// Recovers the exact launch failure, source template, and target owner.
    pub fn into_parts(
        self,
    ) -> (
        QemuHotForkLaunchError,
        QemuNode,
        LinuxQemuAttemptProcessOwner,
    ) {
        (*self.source, *self.template, *self.target)
    }
}

impl QemuHotForkAttemptReconciliation<LinuxQemuHotForkReconciliationBackend> {
    /// Forks a retained source directly into one target reconciliation owner.
    ///
    /// No successful launch token is exposed outside the owner. Explicit
    /// pre-fork rejection returns both reusable authorities; post-fork failures
    /// return them in their already-quarantined state for caller-directed
    /// cleanup.
    ///
    /// # Errors
    ///
    /// Returns [`LinuxQemuHotForkAttemptLaunchError`] with the source and target
    /// authorities when QEMU rejects the request or launch ownership cannot be
    /// established exactly.
    pub fn launch(
        attempt: QemuHotForkAttemptBasis,
        mut template: QemuNode,
        mut target: LinuxQemuAttemptProcessOwner,
        request: crucible_qemu::QmpHotForkRequest,
    ) -> Result<Self, LinuxQemuHotForkAttemptLaunchError> {
        match template.fork_hot_fork_template(request, &mut target) {
            Ok(launch) => Ok(Self::new(
                attempt,
                LinuxQemuHotForkReconciliationBackend::from_launch(template, target, launch),
            )),
            Err(source) => Err(LinuxQemuHotForkAttemptLaunchError {
                source: Box::new(source),
                template: Box::new(template),
                target: Box::new(target),
            }),
        }
    }

    /// Returns the admitted private child QMP channel while the child is live.
    #[must_use]
    pub fn child_qmp_mut(&mut self) -> Option<&mut QemuQmpVmStateControlChannel<UnixStream>> {
        self.backend.as_mut()?.child_qmp_mut()
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
    #![allow(clippy::expect_used)]

    use std::collections::VecDeque;
    use std::io;
    use std::sync::{Arc, Mutex};

    use crucible_campaign::{AttemptId, CampaignLineageId};

    use super::*;

    #[derive(Debug, Error)]
    #[error("injected reconciliation failure")]
    struct ScriptedError;

    struct ScriptedBackend {
        basis: QemuHotForkReconciliationChildBasis,
        observations: VecDeque<QemuHotForkChildObservation>,
        calls: Arc<Mutex<Vec<&'static str>>>,
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
            owner.reconcile_step().expect("running observation"),
            QemuHotForkReconciliationStep::ChildRunning
        );
        assert_eq!(
            owner.reconcile_step().expect("terminal observation"),
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
            ["admit", "observe", "observe", "resources", "target"]
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
                "admit",
                "observe",
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
        owner.reconcile_step().expect("observe reap");
        assert!(owner.reconcile_step().is_err());
        assert_eq!(owner.phase(), QemuHotForkReconciliationPhase::ParentReaped);
        owner.reconcile_step().expect("retry resources");
        assert_eq!(
            calls.lock().expect("calls").as_slice(),
            ["terminate", "observe", "resources", "resources"]
        );
        owner.quarantine();
    }

    #[test]
    fn one_step_releases_at_most_one_backend_owned_child_resource() {
        let (mut owner, calls) =
            scripted_with_resource_substeps([QemuHotForkChildDisposition::Exited(0)], false, 2);
        owner.reconcile_step().expect("observe reap");
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
            ["observe", "resources", "resources", "resources"]
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
        owner.reconcile_step().expect("observe reap");
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
            Err(QemuHotForkAttemptReconciliationError::ObservationWithoutAdmission)
        ));
        owner
            .reconcile_publication(QemuHotForkPublicationDisposition::TerminalFailure)
            .expect("terminal failure disposition");
        owner.quarantine();
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
                fail_release_resources_once: false,
                resource_substeps_before_complete: 0,
            },
        );
        assert!(matches!(
            owner.reconcile_step(),
            Err(QemuHotForkAttemptReconciliationError::ChildBasisMismatch)
        ));
        assert_eq!(calls.lock().expect("calls").as_slice(), ["observe"]);
        owner.quarantine();
    }

    #[test]
    fn io_error_type_remains_send_sync_for_worker_ownership() {
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<io::Error>();
        assert_send_sync::<LinuxQemuHotForkReconciliationError>();
    }
}
