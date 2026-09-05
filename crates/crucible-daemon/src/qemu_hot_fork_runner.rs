//! Linear execution runner for one retained-template QEMU hot-fork child.
//!
//! The runner separates three authorities: a lifecycle factory owns template
//! selection and target-resource admission, a modeled driver can use only the
//! admitted live-child capability, and the runner alone orders termination,
//! target cleanup, durable semantic disposition, and template recovery. A
//! successful result therefore cannot release the source template early, and
//! a failed execution cannot overlap a retry with an unreconciled child.

use std::thread;
use std::time::Duration;

use crucible::EventLog;
use crucible_qemu::{
    QemuHotForkChildDiagnosticDrain, QemuHotForkChildProcessOwner, QemuVmRealizationError,
};

use crate::{
    AttemptExecutionContext, AttemptExecutionDisposition, AttemptExecutionProduct,
    AttemptExecutionReconciliationStep, AttemptExecutionRuntimeBasis, AttemptWorkerFailure,
    CrucibleAttemptExecution, CrucibleExecutionOutcome, CrucibleExecutionRunner,
    CrucibleMaterializationTier, LinuxQemuHotForkLiveChild, LinuxQemuHotForkReconciliationBackend,
    LinuxQemuHotForkReconciliationError, QemuAttemptOperationalBoundary,
    QemuAttemptProcessResourceGuard, QemuHotForkAttemptReconciliation,
    QemuHotForkAttemptReconciliationError, QemuHotForkReconciliationPhase,
    QemuHotForkReconciliationStep, QemuModeledAttemptLifecycle,
};

const MIN_QEMU_HOT_FORK_REAP_POLL_INTERVAL: Duration = Duration::from_millis(1);
const MAX_QEMU_HOT_FORK_REAP_POLL_INTERVAL: Duration = Duration::from_secs(1);
const MAX_QEMU_HOT_FORK_REAP_WAIT: Duration = Duration::from_secs(60 * 60);

/// Bounded parent-status polling policy after hot-fork child termination.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuHotForkChildExitPolicy {
    poll_interval: Duration,
    maximum_polls: u32,
}

impl QemuHotForkChildExitPolicy {
    /// Creates a finite child-exit polling policy.
    /// # Errors
    ///
    /// Returns [`QemuHotForkChildExitPolicyError`] when the interval is outside
    /// 1 millisecond through 1 second, the poll count is zero, or their checked
    /// product exceeds one hour.
    pub fn new(
        poll_interval: Duration,
        maximum_polls: u32,
    ) -> Result<Self, QemuHotForkChildExitPolicyError> {
        if poll_interval < MIN_QEMU_HOT_FORK_REAP_POLL_INTERVAL {
            return Err(QemuHotForkChildExitPolicyError::IntervalTooShort);
        }
        if poll_interval > MAX_QEMU_HOT_FORK_REAP_POLL_INTERVAL {
            return Err(QemuHotForkChildExitPolicyError::IntervalTooLong);
        }
        if maximum_polls == 0 {
            return Err(QemuHotForkChildExitPolicyError::ZeroPolls);
        }
        let wait = poll_interval
            .checked_mul(maximum_polls)
            .ok_or(QemuHotForkChildExitPolicyError::WaitTooLong)?;
        if wait > MAX_QEMU_HOT_FORK_REAP_WAIT {
            return Err(QemuHotForkChildExitPolicyError::WaitTooLong);
        }
        Ok(Self {
            poll_interval,
            maximum_polls,
        })
    }

    /// Returns the fixed interval between running-child observations.
    #[must_use]
    pub const fn poll_interval(self) -> Duration {
        self.poll_interval
    }

    /// Returns the maximum running-child observations before quarantine.
    #[must_use]
    pub const fn maximum_polls(self) -> u32 {
        self.maximum_polls
    }
}

/// Invalid hot-fork child-exit polling policy.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum QemuHotForkChildExitPolicyError {
    /// Polling more frequently than once per millisecond is not admitted.
    #[error("hot-fork child reap poll interval is shorter than one millisecond")]
    IntervalTooShort,
    /// A poll interval longer than one second is not control-responsive.
    #[error("hot-fork child reap poll interval exceeds one second")]
    IntervalTooLong,
    /// At least one parent-owned child-status observation is required.
    #[error("hot-fork child reap poll count is zero")]
    ZeroPolls,
    /// The aggregate child-exit wait is unrepresentable or exceeds one hour.
    #[error("hot-fork child reap wait exceeds one hour")]
    WaitTooLong,
}

/// Live branch-private capability lent to one modeled hot-fork driver.
///
/// This value cannot terminate the child, release the target guard, recover
/// the source template, or acknowledge semantic publication. Guest progress
/// must pass through [`QemuAttemptOperationalBoundary`]. Raw QMP and host-I/O
/// capabilities stay inside the reconciliation owner and reach modeled code
/// only after they have been assembled into the process-neutral lifecycle.
pub trait QemuHotForkLiveExecution: QemuAttemptOperationalBoundary {
    /// Borrows the assembled process-owner-neutral scheduler lifecycle.
    ///
    /// Raw child channels do not imply modeled execution readiness. The Linux
    /// hot-fork owner returns an error until it has atomically assembled the
    /// branch-private node/world continuation and installed every branch-local
    /// coordinator required by the scenario.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when the child has no complete modeled
    /// lifecycle or its assembly failed closed.
    fn modeled_lifecycle(
        &mut self,
    ) -> Result<&mut dyn QemuModeledAttemptLifecycle, QemuVmRealizationError> {
        Err(QemuVmRealizationError::Executor {
            operation: "borrow hot-fork modeled lifecycle",
            message: String::from(
                "branch-private process-owner-neutral lifecycle is not assembled",
            ),
        })
    }

    /// Borrows the branch-private clone of the source unified event prefix.
    ///
    /// The modeled driver must append every child observation to this one log;
    /// it must not create an empty or offset-only substitute.
    #[must_use]
    fn event_log_mut(&mut self) -> &mut EventLog;

    /// Drains every currently available child diagnostic byte.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] if complete bounded diagnostic
    /// retention can no longer be guaranteed.
    fn drain_diagnostics(
        &mut self,
    ) -> Result<QemuHotForkChildDiagnosticDrain, QemuVmRealizationError>;
}

impl QemuHotForkLiveExecution for LinuxQemuHotForkLiveChild<'_> {
    fn event_log_mut(&mut self) -> &mut EventLog {
        LinuxQemuHotForkLiveChild::event_log_mut(self)
    }

    fn drain_diagnostics(
        &mut self,
    ) -> Result<QemuHotForkChildDiagnosticDrain, QemuVmRealizationError> {
        LinuxQemuHotForkLiveChild::drain_diagnostics(self)
    }
}

/// Two-phase modeled driver for one admitted hot-fork child.
///
/// [`Self::drive`] reaches an exact paused modeled stop without constructing an
/// accepted result. [`Self::seal`] then drains and authenticates every
/// observation source at that same boundary. The runner terminates the child
/// only after sealing succeeds; termination must never resume guest execution.
pub trait QemuHotForkAttemptDriver {
    /// Driver state retained between the modeled stop and exact sealing.
    type Pending;
    /// Driver-specific modeled or result-construction failure.
    type Error;

    /// Drives one admitted child to an exact paused modeled stop.
    ///
    /// # Errors
    ///
    /// Returns a classified retryable, canceled, or terminal modeled failure.
    fn drive<L>(
        &mut self,
        live: &mut L,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<Self::Pending, AttemptWorkerFailure<Self::Error>>
    where
        L: QemuHotForkLiveExecution;

    /// Seals one complete immutable product at the paused child boundary.
    ///
    /// A successful implementation must incorporate or reject every observable
    /// guest, plugin, console, and host-I/O event before returning. It must not
    /// release process or template authority.
    ///
    /// # Errors
    ///
    /// Returns a classified failure when exact observation sealing cannot be
    /// completed without resuming guest execution.
    fn seal<L>(
        &mut self,
        pending: Self::Pending,
        live: &mut L,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>>
    where
        L: QemuHotForkLiveExecution;
}

/// Linear child/process lifecycle required by the hot-fork runner.
pub trait QemuHotForkAttemptLifecycle: Sized {
    /// Narrow admitted live-child capability.
    type Live<'a>: QemuHotForkLiveExecution
    where
        Self: 'a;
    /// Lifecycle and reconciliation failure.
    type Error;

    /// Returns the exact supervisor execution incarnation that owns this child.
    #[must_use]
    fn runtime_basis(&self) -> AttemptExecutionRuntimeBasis;

    /// Authenticates the private child channel before modeled execution.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle failure while retaining or quarantining every
    /// process authority.
    fn admit_child(&mut self) -> Result<(), Self::Error>;

    /// Borrows the admitted live child in its legal execution phase.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle failure if no exact admitted child is live.
    fn live_child(&mut self) -> Result<Self::Live<'_>, Self::Error>;

    /// Terminates, reaps, and releases target resources before publication.
    ///
    /// Success must leave the lifecycle waiting for one durable semantic
    /// disposition. The method must perform only finite, bounded waits.
    ///
    /// # Errors
    ///
    /// Returns a lifecycle failure while retaining every authority for
    /// fail-closed transfer to [`QemuHotForkAttemptLifecycleFactory::quarantine`].
    fn stop_before_publication(
        &mut self,
        exit_policy: QemuHotForkChildExitPolicy,
    ) -> Result<(), Self::Error>;

    /// Reconciles one bounded post-publication lifecycle phase.
    ///
    /// # Errors
    ///
    /// Returns a classified retryable failure with unchanged ownership, or a
    /// terminal/canceled failure requiring immediate quarantine transfer.
    fn reconcile_execution_disposition(
        &mut self,
        disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>>;

    /// Latches terminal cleanup and transfers process resources to quarantine.
    ///
    /// This operation is infallible and idempotent. The lifecycle object still
    /// owns the retained source-template authority afterward and must itself be
    /// transferred to the factory's nondroppable quarantine sink.
    fn quarantine(&mut self);
}

/// Factory and terminal owner for hot-fork lifecycle authorities.
///
/// The factory selects an authenticated source template, installs a fresh
/// target attempt guard, and returns one lifecycle. Recovery consumes only a
/// completely reconciled lifecycle. Quarantine is infallible and must transfer
/// source, child, target-resource, and namespace authority to a nondroppable
/// owner; retaining only a PID or path is not conforming.
pub trait QemuHotForkAttemptLifecycleFactory {
    /// Exact lifecycle created for one attempt.
    type Lifecycle: QemuHotForkAttemptLifecycle;
    /// Template-pool, resource-admission, or recovery failure.
    type Error;

    /// Starts one exact retained-template child lifecycle.
    ///
    /// # Errors
    ///
    /// Returns a classified failure only after proving that no child or target
    /// resource authority escaped the factory.
    fn start(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        runtime_basis: AttemptExecutionRuntimeBasis,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>>;

    /// Returns one completely reconciled source template to factory ownership.
    ///
    /// On error, the unchanged lifecycle is returned for exact retry. A
    /// commit-indeterminate insertion must therefore be idempotent under the
    /// same token.
    ///
    /// # Errors
    ///
    /// Returns the unchanged lifecycle and a classified failure when the
    /// factory cannot complete source-template reinsertion.
    fn recover(
        &mut self,
        lifecycle: Self::Lifecycle,
    ) -> Result<(), QemuHotForkAttemptLifecycleRecoveryError<Self::Lifecycle, Self::Error>>;

    /// Transfers an incomplete or invalid lifecycle to fail-closed quarantine.
    fn quarantine(&mut self, lifecycle: Self::Lifecycle);
}

/// Retryable source-template recovery error retaining the exact lifecycle.
#[must_use = "retry source-template recovery or transfer the lifecycle to quarantine"]
pub struct QemuHotForkAttemptLifecycleRecoveryError<L, E> {
    lifecycle: L,
    failure: AttemptWorkerFailure<E>,
}

impl<L, E> QemuHotForkAttemptLifecycleRecoveryError<L, E> {
    /// Retains one unchanged lifecycle and classified recovery failure.
    pub const fn new(lifecycle: L, failure: AttemptWorkerFailure<E>) -> Self {
        Self { lifecycle, failure }
    }

    /// Consumes the error into its exact retry token and failure.
    pub fn into_parts(self) -> (L, AttemptWorkerFailure<E>) {
        (self.lifecycle, self.failure)
    }
}

impl<L, E> std::fmt::Debug for QemuHotForkAttemptLifecycleRecoveryError<L, E>
where
    E: std::fmt::Debug,
{
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("QemuHotForkAttemptLifecycleRecoveryError")
            .field("failure", &self.failure)
            .finish_non_exhaustive()
    }
}

/// Concrete retained-source lifecycle failure.
#[derive(Debug, thiserror::Error)]
pub enum LinuxQemuHotForkAttemptLifecycleError {
    /// The underlying source/target reconciliation owner failed.
    #[error(transparent)]
    Reconciliation(
        #[from] QemuHotForkAttemptReconciliationError<LinuxQemuHotForkReconciliationError>,
    ),
    /// The parent did not reap the exact child within the admitted finite wait.
    #[error("source QEMU did not reap the hot-fork child within {maximum_polls} observations")]
    ReapPollLimit {
        /// Configured maximum running-child observations.
        maximum_polls: u32,
    },
    /// The lifecycle did not expose an admitted live child in its live phase.
    #[error("hot-fork lifecycle has no admitted child in phase {phase:?}")]
    LiveChildUnavailable {
        /// Current monotonic reconciliation phase.
        phase: QemuHotForkReconciliationPhase,
    },
}

impl<G> QemuHotForkAttemptLifecycle
    for QemuHotForkAttemptReconciliation<LinuxQemuHotForkReconciliationBackend<G>>
where
    G: QemuAttemptProcessResourceGuard
        + QemuHotForkChildProcessOwner<
            Authority = crucible_qemu::LinuxQemuHotForkChildProcessAuthority,
        >,
{
    type Live<'a>
        = LinuxQemuHotForkLiveChild<'a>
    where
        Self: 'a;
    type Error = LinuxQemuHotForkAttemptLifecycleError;

    fn runtime_basis(&self) -> AttemptExecutionRuntimeBasis {
        self.attempt()
    }

    fn admit_child(&mut self) -> Result<(), Self::Error> {
        QemuHotForkAttemptReconciliation::admit_child(self).map_err(Into::into)
    }

    fn live_child(&mut self) -> Result<Self::Live<'_>, Self::Error> {
        let phase = self.phase();
        self.live_child_mut()
            .ok_or(LinuxQemuHotForkAttemptLifecycleError::LiveChildUnavailable { phase })
    }

    fn stop_before_publication(
        &mut self,
        exit_policy: QemuHotForkChildExitPolicy,
    ) -> Result<(), Self::Error> {
        self.request_termination()?;
        let mut running_polls = 0u32;
        loop {
            match self.reconcile_step()? {
                QemuHotForkReconciliationStep::ChildRunning => {
                    running_polls = running_polls.saturating_add(1);
                    if running_polls >= exit_policy.maximum_polls() {
                        return Err(LinuxQemuHotForkAttemptLifecycleError::ReapPollLimit {
                            maximum_polls: exit_policy.maximum_polls(),
                        });
                    }
                    thread::sleep(exit_policy.poll_interval());
                }
                QemuHotForkReconciliationStep::AwaitingPublication => return Ok(()),
                QemuHotForkReconciliationStep::ChildDiagnosticsDrained
                | QemuHotForkReconciliationStep::Advanced(_) => {}
                QemuHotForkReconciliationStep::Complete => {
                    return Err(
                        LinuxQemuHotForkAttemptLifecycleError::LiveChildUnavailable {
                            phase: self.phase(),
                        },
                    );
                }
            }
        }
    }

    fn reconcile_execution_disposition(
        &mut self,
        disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
        QemuHotForkAttemptReconciliation::reconcile_execution_disposition(self, disposition)
            .map_err(classify_reconciliation_failure)
    }

    fn quarantine(&mut self) {
        QemuHotForkAttemptReconciliation::quarantine(self);
    }
}

fn classify_reconciliation_failure(
    error: QemuHotForkAttemptReconciliationError<LinuxQemuHotForkReconciliationError>,
) -> AttemptWorkerFailure<LinuxQemuHotForkAttemptLifecycleError> {
    let terminal = matches!(
        &error,
        QemuHotForkAttemptReconciliationError::InvalidPhase { .. }
            | QemuHotForkAttemptReconciliationError::ChildBasisMismatch
            | QemuHotForkAttemptReconciliationError::ModeledResultWithoutAdmission
            | QemuHotForkAttemptReconciliationError::PublicationDispositionMismatch
            | QemuHotForkAttemptReconciliationError::Operation {
                operation: "drain branch-private child diagnostics"
                    | "release target process owner",
                ..
            }
    );
    let error = LinuxQemuHotForkAttemptLifecycleError::Reconciliation(error);
    if terminal {
        AttemptWorkerFailure::Terminal(error)
    } else {
        AttemptWorkerFailure::Retryable(error)
    }
}

/// Retained-template runner with linear execution and publication ownership.
pub struct QemuHotForkExecutionRunner<F, D>
where
    F: QemuHotForkAttemptLifecycleFactory,
{
    factory: F,
    driver: D,
    exit_policy: QemuHotForkChildExitPolicy,
    pending: Option<F::Lifecycle>,
}

impl<F, D> QemuHotForkExecutionRunner<F, D>
where
    F: QemuHotForkAttemptLifecycleFactory,
{
    /// Creates one hot-fork runner from its lifecycle owner and modeled driver.
    #[must_use]
    pub const fn new(factory: F, driver: D, exit_policy: QemuHotForkChildExitPolicy) -> Self {
        Self {
            factory,
            driver,
            exit_policy,
            pending: None,
        }
    }

    /// Returns whether a completed execution still owns its source template.
    #[must_use]
    pub fn has_pending_reconciliation(&self) -> bool {
        self.pending.is_some()
    }
}

impl<F, D> Drop for QemuHotForkExecutionRunner<F, D>
where
    F: QemuHotForkAttemptLifecycleFactory,
{
    fn drop(&mut self) {
        if let Some(lifecycle) = self.pending.take() {
            self.factory.quarantine(lifecycle);
        }
    }
}

/// Failure from one retained-template runner phase.
#[derive(Debug, thiserror::Error)]
pub enum QemuHotForkExecutionRunnerError<F, L, D> {
    /// An exact durable resume root cannot be substituted with a hot fork.
    #[error("hot-fork runner cannot resume exact checkpoint `{0}`")]
    ResumeCheckpointUnsupported(crucible_campaign::ExactCheckpointId),
    /// Worker execution omitted its exact supervisor runtime basis.
    #[error("hot-fork runner requires an exact worker runtime basis")]
    MissingRuntimeBasis,
    /// The factory returned a child for another execution incarnation.
    #[error("hot-fork lifecycle runtime basis differs from the worker reservation")]
    RuntimeBasisMismatch,
    /// A previous successful execution still owns template authority.
    #[error("hot-fork runner still awaits prior semantic reconciliation")]
    PriorReconciliationPending,
    /// A callback was supplied without a successful pending execution.
    #[error("hot-fork runner received semantic reconciliation without pending authority")]
    NoPendingReconciliation,
    /// Lifecycle construction or source-template recovery failed.
    #[error("hot-fork lifecycle factory failed")]
    Factory(F),
    /// Child admission, teardown, or reconciliation failed.
    #[error("hot-fork child lifecycle failed")]
    Lifecycle(L),
    /// Modeled child driving or result sealing failed.
    #[error("hot-fork modeled child driver failed")]
    Driver(D),
    /// Cleanup failed after another execution phase had already failed.
    #[error("hot-fork cleanup failed after an earlier execution failure")]
    CleanupAfterExecution {
        /// Earlier classified execution failure.
        failure: Box<QemuHotForkExecutionRunnerError<F, L, D>>,
        /// Higher-priority cleanup failure.
        cleanup: L,
    },
}

impl<F, D> CrucibleExecutionRunner for QemuHotForkExecutionRunner<F, D>
where
    F: QemuHotForkAttemptLifecycleFactory,
    D: QemuHotForkAttemptDriver,
{
    type Error = QemuHotForkExecutionRunnerError<
        F::Error,
        <F::Lifecycle as QemuHotForkAttemptLifecycle>::Error,
        D::Error,
    >;

    fn execute(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        if let Some(checkpoint) = context.resume_checkpoint() {
            return Err(AttemptWorkerFailure::Terminal(
                Self::Error::ResumeCheckpointUnsupported(checkpoint),
            ));
        }
        let runtime_basis = context
            .runtime_basis()
            .ok_or_else(|| AttemptWorkerFailure::Terminal(Self::Error::MissingRuntimeBasis))?;
        if self.pending.is_some() {
            return Err(AttemptWorkerFailure::Terminal(
                Self::Error::PriorReconciliationPending,
            ));
        }

        let mut lifecycle = self
            .factory
            .start(input, context, runtime_basis)
            .map_err(map_factory_failure)?;
        if lifecycle.runtime_basis() != runtime_basis {
            self.factory.quarantine(lifecycle);
            return Err(AttemptWorkerFailure::Terminal(
                Self::Error::RuntimeBasisMismatch,
            ));
        }
        if let Err(error) = lifecycle.admit_child() {
            self.factory.quarantine(lifecycle);
            return Err(AttemptWorkerFailure::Terminal(Self::Error::Lifecycle(
                error,
            )));
        }

        let driven = {
            let live = lifecycle.live_child();
            match live {
                Ok(mut live) => self
                    .driver
                    .drive(&mut live, input, context)
                    .and_then(|pending| self.driver.seal(pending, &mut live, input, context))
                    .map_err(map_driver_failure),
                Err(error) => Err(AttemptWorkerFailure::Terminal(Self::Error::Lifecycle(
                    error,
                ))),
            }
        };
        if let Err(cleanup) = lifecycle.stop_before_publication(self.exit_policy) {
            self.factory.quarantine(lifecycle);
            return match driven {
                Ok(_) => Err(AttemptWorkerFailure::Terminal(Self::Error::Lifecycle(
                    cleanup,
                ))),
                Err(failure) => Err(AttemptWorkerFailure::Terminal(
                    Self::Error::CleanupAfterExecution {
                        failure: Box::new(failure.into_error()),
                        cleanup,
                    },
                )),
            };
        }

        match driven {
            Ok(product) => {
                self.pending = Some(lifecycle);
                Ok(CrucibleExecutionOutcome::new(
                    product,
                    CrucibleMaterializationTier::HotFork,
                ))
            }
            Err(failure) => {
                // No durable supervisor disposition exists for a runner error.
                // Releasing the source status here would fabricate one, so the
                // complete owner moves to quarantine before a retry can begin.
                self.factory.quarantine(lifecycle);
                Err(failure)
            }
        }
    }

    fn reconcile_execution(
        &mut self,
        disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
        let Some(mut lifecycle) = self.pending.take() else {
            return Err(AttemptWorkerFailure::Terminal(
                Self::Error::NoPendingReconciliation,
            ));
        };
        match lifecycle.reconcile_execution_disposition(disposition) {
            Ok(AttemptExecutionReconciliationStep::Progressed) => {
                self.pending = Some(lifecycle);
                Ok(AttemptExecutionReconciliationStep::Progressed)
            }
            Ok(AttemptExecutionReconciliationStep::Complete) => {
                match self.factory.recover(lifecycle) {
                    Ok(()) => Ok(AttemptExecutionReconciliationStep::Complete),
                    Err(error) => {
                        let (lifecycle, failure) = error.into_parts();
                        match failure {
                            AttemptWorkerFailure::Retryable(error) => {
                                self.pending = Some(lifecycle);
                                Err(AttemptWorkerFailure::Retryable(Self::Error::Factory(error)))
                            }
                            AttemptWorkerFailure::Canceled(error) => {
                                self.factory.quarantine(lifecycle);
                                Err(AttemptWorkerFailure::Canceled(Self::Error::Factory(error)))
                            }
                            AttemptWorkerFailure::Terminal(error) => {
                                self.factory.quarantine(lifecycle);
                                Err(AttemptWorkerFailure::Terminal(Self::Error::Factory(error)))
                            }
                        }
                    }
                }
            }
            Err(AttemptWorkerFailure::Retryable(error)) => {
                self.pending = Some(lifecycle);
                Err(AttemptWorkerFailure::Retryable(Self::Error::Lifecycle(
                    error,
                )))
            }
            Err(AttemptWorkerFailure::Canceled(error)) => {
                self.factory.quarantine(lifecycle);
                Err(AttemptWorkerFailure::Canceled(Self::Error::Lifecycle(
                    error,
                )))
            }
            Err(AttemptWorkerFailure::Terminal(error)) => {
                self.factory.quarantine(lifecycle);
                Err(AttemptWorkerFailure::Terminal(Self::Error::Lifecycle(
                    error,
                )))
            }
        }
    }
}

fn map_factory_failure<F, L, D>(
    failure: AttemptWorkerFailure<F>,
) -> AttemptWorkerFailure<QemuHotForkExecutionRunnerError<F, L, D>> {
    failure.map(QemuHotForkExecutionRunnerError::Factory)
}

fn map_driver_failure<F, L, D>(
    failure: AttemptWorkerFailure<D>,
) -> AttemptWorkerFailure<QemuHotForkExecutionRunnerError<F, L, D>> {
    failure.map(QemuHotForkExecutionRunnerError::Driver)
}

trait AttemptWorkerFailureExt<E> {
    fn map<T>(self, map: impl FnOnce(E) -> T) -> AttemptWorkerFailure<T>;
    fn into_error(self) -> E;
}

impl<E> AttemptWorkerFailureExt<E> for AttemptWorkerFailure<E> {
    fn map<T>(self, map: impl FnOnce(E) -> T) -> AttemptWorkerFailure<T> {
        match self {
            Self::Retryable(error) => AttemptWorkerFailure::Retryable(map(error)),
            Self::Canceled(error) => AttemptWorkerFailure::Canceled(map(error)),
            Self::Terminal(error) => AttemptWorkerFailure::Terminal(map(error)),
        }
    }

    fn into_error(self) -> E {
        match self {
            Self::Retryable(error) | Self::Canceled(error) | Self::Terminal(error) => error,
        }
    }
}

#[cfg(test)]
mod tests;
