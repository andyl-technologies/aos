//! Attempt-scoped live-QEMU session composition.
//!
//! The adapter in this module binds three independently testable authorities:
//! policy-controlled VM realization, an operational resource/cancellation
//! guard installed before launch, and a modeled attempt driver that receives
//! only the already-realized backend. Assignment IDs and daemon epochs never
//! cross this boundary.

use crucible::{
    AdvanceOutcome, BackendError, BackendInput, Configuration, EventLog, EventLogOffset,
    ExecutionFingerprint, ExecutionHorizon, Icount,
};
use crucible_campaign::{AttemptResourceLimits, ObservationCandidate};
use crucible_qemu::{
    QemuBakedGenesisRestoreAdmission, QemuLiveAttemptBackend, QemuLoadvmCommandAuthorization,
    QemuLoadvmRealizationAdmission, QemuVmLiveRealizationExecutor, QemuVmRealization,
    QemuVmRealizationError, QemuVmRealizationExecutor, QemuVmReplayRequest, QemuVmSnapshot,
};

use crate::{
    AttemptExecutionContext, AttemptWorkerFailure, CrucibleAttemptExecution, ExecutionCancellation,
    QemuCrucibleAttemptSession, QemuCrucibleSessionFactory,
};

/// Read-only operational boundary available to a modeled attempt driver.
///
/// This capability cannot release or quarantine resource enforcement.
pub trait QemuAttemptOperationalBoundary {
    /// Returns the exact hard ceilings installed for this attempt.
    #[must_use]
    fn resource_limits(&self) -> AttemptResourceLimits;

    /// Returns the process-local cancellation signal watched by the guard.
    #[must_use]
    fn cancellation(&self) -> &ExecutionCancellation;

    /// Checks cancellation and the remaining execution-quanta budget.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError::Canceled`] after cancellation and a
    /// stable executor error after a hard resource ceiling is exhausted.
    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError>;

    /// Charges one scheduler-authorized execution quantum before guest progress.
    ///
    /// # Errors
    ///
    /// Returns a stable executor error when the admitted quantum ceiling is
    /// exhausted, or [`QemuVmRealizationError::Canceled`] after cancellation.
    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError>;
}

/// Operational guard installed before one attempt can launch QEMU.
///
/// A conforming guard owns the host-side CPU, memory, writable-disk, and
/// execution-quanta enforcement for its lifetime. Its cancellation path must
/// be able to interrupt a blocked process operation rather than relying only
/// on caller polling.
pub trait QemuAttemptResourceGuard: QemuAttemptOperationalBoundary {
    /// Releases the installed resource controls after QEMU has been reaped.
    ///
    /// This operation must be idempotent. An error may report cleanup
    /// diagnostics only after the guard has completed its release ladder.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when cleanup completed with an
    /// operational diagnostic failure.
    fn finish(&mut self) -> Result<(), QemuVmRealizationError>;

    /// Transfers enforcement to a supervisor-owned quarantine after failed reap.
    ///
    /// This operation is infallible and idempotent. It must keep every resource
    /// ceiling active until the quarantine reaper attests that the process is
    /// gone; it must not release the guard in the calling session.
    fn quarantine(&mut self);
}

/// Factory for one pre-launch attempt resource guard.
pub trait QemuAttemptResourceGuardFactory {
    /// Guard retained for the complete process lifetime.
    type Guard: QemuAttemptResourceGuard;

    /// Installs the exact admitted resource and cancellation contract.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when the host cannot install every
    /// requested ceiling. Failure must leave no reservation or process behind.
    fn begin(
        &mut self,
        resources: AttemptResourceLimits,
        cancellation: ExecutionCancellation,
    ) -> Result<Self::Guard, QemuVmRealizationError>;
}

/// Candidate paired with the exact unified-log boundary it incorporates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLiveAttemptResult {
    candidate: ObservationCandidate,
    event_log: EventLogOffset,
}

impl QemuLiveAttemptResult {
    /// Binds a candidate to the live backend's current unified-log boundary.
    #[must_use]
    pub fn at_current_boundary(
        candidate: ObservationCandidate,
        backend: &dyn QemuLiveAttemptBackend,
    ) -> Self {
        Self {
            candidate,
            event_log: backend.event_log().offset(),
        }
    }

    /// Returns the exact unified-log boundary incorporated by the candidate.
    #[must_use]
    pub const fn event_log(&self) -> EventLogOffset {
        self.event_log
    }

    /// Consumes the binding into its canonical candidate.
    #[must_use]
    pub fn into_candidate(self) -> ObservationCandidate {
        self.candidate
    }
}

/// Modeled attempt driver over one already-realized live backend.
///
/// The driver may advance the backend only through the session-owned combined
/// capability, which charges the exact operational guard before every bounded
/// quantum. It returns canonical campaign evidence; realization tier and
/// resource telemetry remain operational and do not enter that evidence.
pub trait QemuLiveAttemptDriver {
    /// Driver-specific modeled-execution or result-construction failure.
    type Error;

    /// Drives the live backend to the attempt stop and constructs its result.
    ///
    /// [`QemuLiveAttemptBackend::event_log`] exposes the read-only unified log
    /// updated by every completed live quantum. The session drains once more
    /// after this method returns and rejects the candidate if that seal changes
    /// the log boundary.
    ///
    /// # Errors
    ///
    /// Returns a classified retryable, canceled, or terminal driver failure.
    fn run_attempt(
        &mut self,
        backend: &mut dyn QemuLiveAttemptExecution,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        realization: QemuVmRealization,
    ) -> Result<QemuLiveAttemptResult, AttemptWorkerFailure<Self::Error>>;
}

/// Live modeled-execution capability with mandatory operational charging.
///
/// The session supplies this combined facade instead of the realization
/// executor's raw backend. Every successful call to
/// [`QemuLiveAttemptBackend::advance_to_horizon`] spends one admitted execution
/// quantum before guest progress can begin.
pub trait QemuLiveAttemptExecution:
    QemuLiveAttemptBackend + QemuAttemptOperationalBoundary
{
}

impl<T> QemuLiveAttemptExecution for T where
    T: QemuLiveAttemptBackend + QemuAttemptOperationalBoundary + ?Sized
{
}

struct ChargedQemuLiveAttemptBackend<'a> {
    backend: &'a mut dyn QemuLiveAttemptBackend,
    boundary: &'a mut dyn QemuAttemptOperationalBoundary,
    operational_failure: Option<QemuVmRealizationError>,
}

impl ChargedQemuLiveAttemptBackend<'_> {
    fn reject_operational_failure(&mut self, error: QemuVmRealizationError) -> BackendError {
        let message = error.to_string();
        if self.operational_failure.is_none() {
            self.operational_failure = Some(error);
        }
        BackendError::Rejected { message }
    }

    fn take_operational_failure(&mut self) -> Option<QemuVmRealizationError> {
        self.operational_failure.take()
    }
}

impl QemuAttemptOperationalBoundary for ChargedQemuLiveAttemptBackend<'_> {
    fn resource_limits(&self) -> AttemptResourceLimits {
        self.boundary.resource_limits()
    }

    fn cancellation(&self) -> &ExecutionCancellation {
        self.boundary.cancellation()
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        self.boundary.check_operational_boundary()
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        self.boundary.charge_execution_quantum()
    }
}

impl QemuLiveAttemptBackend for ChargedQemuLiveAttemptBackend<'_> {
    fn advance_to_horizon(
        &mut self,
        horizon: ExecutionHorizon,
    ) -> Result<AdvanceOutcome, BackendError> {
        if self.operational_failure.is_some() {
            return Err(BackendError::Rejected {
                message: String::from("attempt operational boundary already failed"),
            });
        }
        if let Err(error) = self.boundary.charge_execution_quantum() {
            return Err(self.reject_operational_failure(error));
        }
        self.backend.advance_to_horizon(horizon)
    }

    fn fingerprint(&mut self) -> Result<ExecutionFingerprint, BackendError> {
        self.backend.fingerprint()
    }

    fn deliver_input(&mut self, input: BackendInput) -> Result<(), BackendError> {
        self.backend.deliver_input(input)
    }

    fn current_icount(&mut self) -> Result<Icount, BackendError> {
        self.backend.current_icount()
    }

    fn event_log(&self) -> &EventLog {
        self.backend.event_log()
    }
}

/// Realization executor whose blocking operations are bound to one guard.
///
/// Unlike the unguarded realization trait used by pure coordination tests,
/// every method here receives the exact attempt guard. Implementations must
/// attach launched processes to that guard before execution and must observe
/// cancellation during, not merely around, every blocking operation.
pub trait QemuGuardedLiveRealizationExecutor<G>: QemuVmLiveRealizationExecutor
where
    G: QemuAttemptResourceGuard,
{
    /// Loads an exact admitted snapshot under `guard`.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] on cancellation, launch, or restore failure.
    fn load_exact_snapshot_guarded(
        &mut self,
        guard: &mut G,
        config: &Configuration,
        snapshot: &QemuVmSnapshot,
        authorization: QemuLoadvmCommandAuthorization,
        admission: QemuLoadvmRealizationAdmission,
    ) -> Result<crucible::RuntimeState, QemuVmRealizationError>;

    /// Loads a replay-oracle probe under `guard`.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] on cancellation, launch, or restore failure.
    fn load_exact_snapshot_for_replay_oracle_probe_guarded(
        &mut self,
        guard: &mut G,
        config: &Configuration,
        snapshot: &QemuVmSnapshot,
        authorization: QemuLoadvmCommandAuthorization,
    ) -> Result<crucible::RuntimeState, QemuVmRealizationError>;

    /// Loads baked genesis under `guard`.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] on cancellation, launch, or restore failure.
    fn load_baked_genesis_guarded(
        &mut self,
        guard: &mut G,
        config: &Configuration,
        admission: QemuBakedGenesisRestoreAdmission<'_>,
    ) -> Result<crucible::RuntimeState, QemuVmRealizationError>;

    /// Replays one bounded quantum under `guard`.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] on cancellation or replay failure.
    fn replay_one_quantum_guarded(
        &mut self,
        guard: &mut G,
        runtime: crucible::RuntimeState,
        request: QemuVmReplayRequest,
    ) -> Result<crucible::RuntimeState, QemuVmRealizationError>;

    /// Reaps every process generation possibly launched by a failed operation.
    ///
    /// Returning success is an attestation that the failed guarded call either
    /// launched no process or reaped every process it launched, including a
    /// child that failed before installation as the active backend.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when reap cannot be attested. The
    /// session then transfers `guard` to quarantine and poisons this executor.
    fn reap_failed_realization_guarded(
        &mut self,
        guard: &mut G,
    ) -> Result<(), QemuVmRealizationError>;
}

/// Failure produced inside the composed live attempt session.
#[derive(Debug, thiserror::Error)]
pub enum QemuLiveAttemptSessionError<E> {
    /// The live backend or operational guard failed after realization began.
    #[error(transparent)]
    Operational(#[from] QemuVmRealizationError),
    /// The modeled attempt driver failed.
    #[error("live QEMU campaign attempt driver failed")]
    Driver(E),
}

/// Factory composing one live realization executor, driver, and resource guard.
pub struct QemuLiveAttemptSessionFactory<E, D, R> {
    executor: E,
    driver: D,
    resources: R,
}

impl<E, D, R> QemuLiveAttemptSessionFactory<E, D, R> {
    /// Creates a live attempt-session factory.
    #[must_use]
    pub const fn new(executor: E, driver: D, resources: R) -> Self {
        Self {
            executor,
            driver,
            resources,
        }
    }

    /// Returns the retained realization executor.
    #[must_use]
    pub const fn executor(&self) -> &E {
        &self.executor
    }

    /// Returns the retained attempt driver.
    #[must_use]
    pub const fn driver(&self) -> &D {
        &self.driver
    }

    /// Consumes the factory into its three component authorities.
    #[must_use]
    pub fn into_parts(self) -> (E, D, R) {
        (self.executor, self.driver, self.resources)
    }
}

/// One attempt-scoped live-QEMU session.
pub struct QemuLiveAttemptSession<'a, E, D, G>
where
    E: QemuGuardedLiveRealizationExecutor<G>,
    D: QemuLiveAttemptDriver,
    G: QemuAttemptResourceGuard,
{
    executor: &'a mut E,
    driver: &'a mut D,
    context: &'a AttemptExecutionContext,
    guard: G,
    realization_cleanup_required: bool,
    backend_reaped: bool,
    guard_terminal: bool,
}

impl<E, D, R> QemuCrucibleSessionFactory for QemuLiveAttemptSessionFactory<E, D, R>
where
    E: QemuGuardedLiveRealizationExecutor<R::Guard>,
    D: QemuLiveAttemptDriver,
    R: QemuAttemptResourceGuardFactory,
{
    type Error = QemuLiveAttemptSessionError<D::Error>;
    type Session<'a>
        = QemuLiveAttemptSession<'a, E, D, R::Guard>
    where
        Self: 'a;

    fn begin_attempt<'a>(
        &'a mut self,
        context: &'a AttemptExecutionContext,
    ) -> Result<Self::Session<'a>, QemuVmRealizationError> {
        if self.executor.live_backend_is_active() {
            return Err(QemuVmRealizationError::ExecutorUnavailable {
                operation: "begin campaign QEMU attempt",
                message: String::from("a prior live backend has not produced a reap attestation"),
            });
        }
        let mut guard = self
            .resources
            .begin(context.resources(), context.cancellation().clone())?;
        if guard.resource_limits() != context.resources()
            || !guard
                .cancellation()
                .same_incarnation(context.cancellation())
        {
            guard.finish()?;
            return Err(QemuVmRealizationError::Executor {
                operation: "install campaign QEMU attempt resources",
                message: String::from(
                    "resource guard did not install the exact admitted limits and cancellation signal",
                ),
            });
        }
        Ok(QemuLiveAttemptSession {
            executor: &mut self.executor,
            driver: &mut self.driver,
            context,
            guard,
            realization_cleanup_required: false,
            backend_reaped: false,
            guard_terminal: false,
        })
    }
}

impl<E, D, G> QemuVmRealizationExecutor for QemuLiveAttemptSession<'_, E, D, G>
where
    E: QemuGuardedLiveRealizationExecutor<G>,
    D: QemuLiveAttemptDriver,
    G: QemuAttemptResourceGuard,
{
    fn load_exact_snapshot(
        &mut self,
        config: &Configuration,
        snapshot: &QemuVmSnapshot,
        authorization: QemuLoadvmCommandAuthorization,
        admission: QemuLoadvmRealizationAdmission,
    ) -> Result<crucible::RuntimeState, QemuVmRealizationError> {
        self.guard.check_operational_boundary()?;
        let result = self.executor.load_exact_snapshot_guarded(
            &mut self.guard,
            config,
            snapshot,
            authorization,
            admission,
        );
        if result.is_err() {
            self.realization_cleanup_required = true;
        }
        self.guard.check_operational_boundary()?;
        result
    }

    fn load_exact_snapshot_for_replay_oracle_probe(
        &mut self,
        config: &Configuration,
        snapshot: &QemuVmSnapshot,
        authorization: QemuLoadvmCommandAuthorization,
    ) -> Result<crucible::RuntimeState, QemuVmRealizationError> {
        self.guard.check_operational_boundary()?;
        let result = self
            .executor
            .load_exact_snapshot_for_replay_oracle_probe_guarded(
                &mut self.guard,
                config,
                snapshot,
                authorization,
            );
        if result.is_err() {
            self.realization_cleanup_required = true;
        }
        self.guard.check_operational_boundary()?;
        result
    }

    fn load_baked_genesis(
        &mut self,
        config: &Configuration,
        admission: QemuBakedGenesisRestoreAdmission<'_>,
    ) -> Result<crucible::RuntimeState, QemuVmRealizationError> {
        self.guard.check_operational_boundary()?;
        let result = self
            .executor
            .load_baked_genesis_guarded(&mut self.guard, config, admission);
        if result.is_err() {
            self.realization_cleanup_required = true;
        }
        self.guard.check_operational_boundary()?;
        result
    }

    fn replay_one_quantum(
        &mut self,
        runtime: crucible::RuntimeState,
        request: QemuVmReplayRequest,
    ) -> Result<crucible::RuntimeState, QemuVmRealizationError> {
        self.guard.check_operational_boundary()?;
        self.guard.charge_execution_quantum()?;
        let result = self
            .executor
            .replay_one_quantum_guarded(&mut self.guard, runtime, request);
        if result.is_err() {
            self.realization_cleanup_required = true;
        }
        self.guard.check_operational_boundary()?;
        result
    }
}

impl<E, D, G> QemuCrucibleAttemptSession for QemuLiveAttemptSession<'_, E, D, G>
where
    E: QemuGuardedLiveRealizationExecutor<G>,
    D: QemuLiveAttemptDriver,
    G: QemuAttemptResourceGuard,
{
    type Error = QemuLiveAttemptSessionError<D::Error>;

    fn resource_limits(&self) -> AttemptResourceLimits {
        self.guard.resource_limits()
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        self.guard.check_operational_boundary()
    }

    fn run_attempt(
        &mut self,
        input: &CrucibleAttemptExecution,
        realization: QemuVmRealization,
    ) -> Result<ObservationCandidate, AttemptWorkerFailure<Self::Error>> {
        self.guard
            .check_operational_boundary()
            .map_err(classify_operational_failure)?;
        let backend = self
            .executor
            .live_backend_mut()
            .map_err(classify_operational_failure)?;
        let mut backend = ChargedQemuLiveAttemptBackend {
            backend,
            boundary: &mut self.guard,
            operational_failure: None,
        };
        let result = self
            .driver
            .run_attempt(&mut backend, input, self.context, realization)
            .map_err(map_live_driver_failure);
        if let Some(error) = backend.take_operational_failure() {
            return Err(classify_operational_failure(error));
        }
        if let Ok(candidate) = &result
            && !self
                .seal_result_event_log(candidate.event_log())
                .map_err(classify_operational_failure)?
        {
            return Err(AttemptWorkerFailure::Terminal(
                QemuLiveAttemptSessionError::Operational(QemuVmRealizationError::Executor {
                    operation: "seal campaign QEMU observation boundary",
                    message: String::from(
                        "the candidate does not incorporate the exact sealed unified event log",
                    ),
                }),
            ));
        }
        self.guard
            .check_operational_boundary()
            .map_err(classify_operational_failure)?;
        result.map(QemuLiveAttemptResult::into_candidate)
    }

    fn finish(mut self) -> Result<(), QemuVmRealizationError> {
        self.cleanup()
    }
}

impl<E, D, G> QemuLiveAttemptSession<'_, E, D, G>
where
    E: QemuGuardedLiveRealizationExecutor<G>,
    D: QemuLiveAttemptDriver,
    G: QemuAttemptResourceGuard,
{
    fn seal_result_event_log(
        &mut self,
        expected: EventLogOffset,
    ) -> Result<bool, QemuVmRealizationError> {
        let unchanged = self.executor.seal_live_observation_boundary()?;
        let sealed = self.executor.live_backend_mut()?.event_log().offset();
        Ok(unchanged && sealed == expected)
    }

    fn cleanup(&mut self) -> Result<(), QemuVmRealizationError> {
        let mut diagnostic = None;
        if !self.backend_reaped {
            let reap = if self.realization_cleanup_required {
                self.executor
                    .reap_failed_realization_guarded(&mut self.guard)
                    .map(|()| true)
            } else {
                self.executor
                    .shutdown_live_backend()
                    .map(|outcome| outcome.observation_boundary_unchanged())
            };
            match reap {
                Ok(unchanged) => {
                    self.backend_reaped = true;
                    if !unchanged {
                        diagnostic = Some(QemuVmRealizationError::Executor {
                            operation: "finish campaign QEMU attempt",
                            message: String::from(
                                "final shutdown drain changed the sealed observation boundary",
                            ),
                        });
                    }
                }
                Err(error) => {
                    if !self.guard_terminal {
                        self.guard.quarantine();
                        self.guard_terminal = true;
                    }
                    return Err(QemuVmRealizationError::ReapQuarantined {
                        operation: "finish campaign QEMU attempt",
                        message: error.to_string(),
                    });
                }
            }
        }
        if !self.guard_terminal {
            let result = self.guard.finish();
            self.guard_terminal = true;
            result?;
        }
        if let Some(error) = diagnostic {
            Err(error)
        } else {
            Ok(())
        }
    }
}

impl<E, D, G> Drop for QemuLiveAttemptSession<'_, E, D, G>
where
    E: QemuGuardedLiveRealizationExecutor<G>,
    D: QemuLiveAttemptDriver,
    G: QemuAttemptResourceGuard,
{
    fn drop(&mut self) {
        let _ = self.cleanup();
    }
}

fn classify_operational_failure<E>(
    error: QemuVmRealizationError,
) -> AttemptWorkerFailure<QemuLiveAttemptSessionError<E>> {
    let error = QemuLiveAttemptSessionError::Operational(error);
    match &error {
        QemuLiveAttemptSessionError::Operational(
            QemuVmRealizationError::StoreUnavailable { .. }
            | QemuVmRealizationError::ExecutorUnavailable { .. },
        ) => AttemptWorkerFailure::Retryable(error),
        QemuLiveAttemptSessionError::Operational(QemuVmRealizationError::Canceled { .. }) => {
            AttemptWorkerFailure::Canceled(error)
        }
        QemuLiveAttemptSessionError::Operational(_) | QemuLiveAttemptSessionError::Driver(_) => {
            AttemptWorkerFailure::Terminal(error)
        }
    }
}

fn map_live_driver_failure<E>(
    failure: AttemptWorkerFailure<E>,
) -> AttemptWorkerFailure<QemuLiveAttemptSessionError<E>> {
    match failure {
        AttemptWorkerFailure::Retryable(error) => {
            AttemptWorkerFailure::Retryable(QemuLiveAttemptSessionError::Driver(error))
        }
        AttemptWorkerFailure::Canceled(error) => {
            AttemptWorkerFailure::Canceled(QemuLiveAttemptSessionError::Driver(error))
        }
        AttemptWorkerFailure::Terminal(error) => {
            AttemptWorkerFailure::Terminal(QemuLiveAttemptSessionError::Driver(error))
        }
    }
}

#[cfg(test)]
mod tests;
