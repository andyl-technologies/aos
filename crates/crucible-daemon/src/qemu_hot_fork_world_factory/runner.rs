//! Whole-world execution and durable publication reconciliation.

use super::*;

/// Whole-world runner result before durable publication reconciliation.
pub(crate) enum QemuHotForkWorldExecutionAttempt {
    /// No exact retained source was available; a lower tier may run.
    Declined,
    /// The retained source produced a complete candidate.
    Executed(CrucibleExecutionOutcome),
}

/// Production whole-world runner with publication-ordered source recovery.
pub struct QemuHotForkWorldExecutionRunner<F, D>
where
    F: QemuHotForkWorldLifecycleFactory,
{
    factory: F,
    driver: D,
    pending: Option<F::Lifecycle>,
}

impl<F, D> QemuHotForkWorldExecutionRunner<F, D>
where
    F: QemuHotForkWorldLifecycleFactory,
{
    /// Creates a whole-world runner from its lifecycle factory and modeled driver.
    #[must_use]
    pub const fn new(factory: F, driver: D) -> Self {
        Self {
            factory,
            driver,
            pending: None,
        }
    }

    /// Transfers a pending retained world to the factory's quarantine owner.
    pub(crate) fn quarantine_pending_execution(&mut self) {
        if let Some(lifecycle) = self.pending.take() {
            self.factory.quarantine(lifecycle);
        }
    }
}

/// Failure from one production whole-world execution phase.
#[derive(Debug)]
pub enum QemuHotForkWorldExecutionRunnerError<F, D> {
    /// A prior successful execution still owns publication authority.
    PriorReconciliationPending,
    /// The lifecycle factory failed after exact source selection.
    Factory(F),
    /// The factory returned a lifecycle for another supervisor incarnation.
    RuntimeBasisMismatch,
    /// The adopted start boundary could not be reconstructed exactly.
    Start(SchedulerError),
    /// The authenticated branch edge could not be applied at the captured parent.
    StartReplay(String),
    /// Modeled driving or result construction failed.
    Driver(D),
    /// A checkpoint result lacked a sticky supervisor request.
    UnsolicitedCheckpoint,
    /// Capturing a later exact checkpoint failed.
    CheckpointCapture(SchedulerError),
    /// Exact terminal execution fingerprint capture failed before teardown.
    TerminalFingerprintCapture(SchedulerError),
    /// Durable checkpoint handoff failed.
    CheckpointHandoff(CheckpointHandoffFailure),
    /// Final drain or adopted-node cleanup failed.
    Cleanup(SchedulerError),
    /// Cleanup failed after an earlier runner phase failed.
    CleanupAfterRunner {
        /// Earlier runner failure.
        failure: Box<QemuHotForkWorldExecutionRunnerError<F, D>>,
        /// Higher-priority cleanup failure.
        cleanup: SchedulerError,
    },
    /// Durable publication reconciliation failed.
    Reconciliation(crucible_api::LifecycleApiError),
    /// A reconciliation callback arrived without pending authority.
    NoPendingReconciliation,
    /// Complete source-world recovery contradicted lifecycle ownership.
    SourceRecovery,
}

impl<F, D> std::fmt::Display for QemuHotForkWorldExecutionRunnerError<F, D> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::PriorReconciliationPending => {
                formatter.write_str("hot-fork world still awaits prior semantic reconciliation")
            }
            Self::Factory(_) => {
                formatter.write_str("construct production hot-fork world lifecycle")
            }
            Self::RuntimeBasisMismatch => formatter.write_str(
                "production hot-fork world runtime basis differs from its worker reservation",
            ),
            Self::Start(error) => {
                write!(formatter, "materialize production hot-fork start: {error}")
            }
            Self::StartReplay(error) => {
                write!(formatter, "apply production hot-fork branch start: {error}")
            }
            Self::Driver(_) => formatter.write_str("drive production hot-fork world"),
            Self::UnsolicitedCheckpoint => {
                formatter.write_str("production hot-fork driver returned an unsolicited checkpoint")
            }
            Self::CheckpointCapture(error) => {
                write!(formatter, "capture production hot-fork checkpoint: {error}")
            }
            Self::TerminalFingerprintCapture(error) => {
                write!(
                    formatter,
                    "capture production hot-fork terminal fingerprints: {error}"
                )
            }
            Self::CheckpointHandoff(error) => {
                write!(formatter, "handoff production hot-fork checkpoint: {error}")
            }
            Self::Cleanup(error) => {
                write!(formatter, "clean up production hot-fork world: {error}")
            }
            Self::CleanupAfterRunner { cleanup, .. } => write!(
                formatter,
                "production hot-fork cleanup failed after a prior runner failure: {cleanup}"
            ),
            Self::Reconciliation(error) => {
                write!(
                    formatter,
                    "reconcile production hot-fork publication: {error}"
                )
            }
            Self::NoPendingReconciliation => {
                formatter.write_str("production hot-fork runner has no pending reconciliation")
            }
            Self::SourceRecovery => formatter.write_str("recover production hot-fork source world"),
        }
    }
}

impl<F, D> std::error::Error for QemuHotForkWorldExecutionRunnerError<F, D>
where
    F: std::error::Error + 'static,
    D: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Factory(error) => Some(error),
            Self::Start(error)
            | Self::CheckpointCapture(error)
            | Self::TerminalFingerprintCapture(error)
            | Self::Cleanup(error) => Some(error),
            Self::Driver(error) => Some(error),
            Self::CheckpointHandoff(error) => Some(error),
            Self::CleanupAfterRunner { failure, .. } => Some(failure.as_ref()),
            Self::Reconciliation(error) => Some(error),
            Self::PriorReconciliationPending
            | Self::RuntimeBasisMismatch
            | Self::StartReplay(_)
            | Self::UnsolicitedCheckpoint
            | Self::NoPendingReconciliation
            | Self::SourceRecovery => None,
        }
    }
}

type HotForkWorldRunnerFailure<F, D> = AttemptWorkerFailure<
    QemuHotForkWorldExecutionRunnerError<
        <F as QemuHotForkWorldLifecycleFactory>::Error,
        <D as QemuFreshAttemptDriver>::Error,
    >,
>;

enum HotForkRunnerResult<P> {
    Observation(P),
    Checkpoint(AttemptCheckpointResult),
}

impl<F, D> QemuHotForkWorldExecutionRunner<F, D>
where
    F: QemuHotForkWorldLifecycleFactory,
    D: QemuFreshAttemptDriver,
{
    /// Tries exact hot-fork execution without hiding a capability decline.
    ///
    /// # Errors
    ///
    /// Returns a classified failure after factory, modeled, cleanup, or source
    /// ownership failure. A returned error leaves no droppable live authority.
    pub fn try_execute(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<QemuHotForkWorldExecutionAttempt, HotForkWorldRunnerFailure<F, D>> {
        if self.pending.is_some() {
            return Err(AttemptWorkerFailure::Terminal(
                QemuHotForkWorldExecutionRunnerError::PriorReconciliationPending,
            ));
        }
        if matches!(
            input.start(),
            crate::CrucibleResolvedAttemptStart::AfterAttempt { .. }
        ) {
            return Ok(QemuHotForkWorldExecutionAttempt::Declined);
        }
        let mut lifecycle = match self
            .factory
            .try_start(input, context)
            .map_err(map_hot_fork_factory_failure)?
        {
            QemuHotForkWorldLifecycleStart::Declined => {
                return Ok(QemuHotForkWorldExecutionAttempt::Declined);
            }
            QemuHotForkWorldLifecycleStart::Started(lifecycle) => lifecycle,
        };
        if context.runtime_basis() != Some(lifecycle.runtime_basis()) {
            self.factory.quarantine(lifecycle);
            return Err(AttemptWorkerFailure::Terminal(
                QemuHotForkWorldExecutionRunnerError::RuntimeBasisMismatch,
            ));
        }
        let driven = lifecycle
            .start_materialization()
            .map_err(|error| {
                AttemptWorkerFailure::Terminal(QemuHotForkWorldExecutionRunnerError::Start(error))
            })
            .and_then(|materialization| {
                let (source, target) = match input.start() {
                    crate::CrucibleResolvedAttemptStart::Discover { configuration } => {
                        (configuration, configuration)
                    }
                    crate::CrucibleResolvedAttemptStart::Branch {
                        parent, selected, ..
                    } => (parent, selected),
                    crate::CrucibleResolvedAttemptStart::AfterAttempt { .. } => {
                        let boundary = input.start().configuration();
                        (boundary, boundary)
                    }
                };
                let materialization =
                    crate::qemu_campaign_lifecycle::materialize_start_from::<F::Error, D::Error>(
                        &mut lifecycle,
                        input,
                        source.clone(),
                        target,
                        context,
                        materialization,
                    )
                    .map_err(map_hot_fork_start_replay_failure)?;
                if input.attempt().stop().accepts_next_choice() {
                    lifecycle.enable_signal_fault_campaign_promotion();
                }
                let mut facade = QemuFreshAttemptLifecycle::new(&mut lifecycle);
                match self
                    .driver
                    .drive(&mut facade, input, context, materialization)
                    .map_err(map_hot_fork_driver_failure)?
                {
                    QemuFreshDriveOutcome::Observation(pending) => {
                        Ok(HotForkRunnerResult::Observation(pending))
                    }
                    QemuFreshDriveOutcome::CheckpointRequested => {
                        if !context.checkpoint_request().is_requested() {
                            return Err(AttemptWorkerFailure::Terminal(
                                QemuHotForkWorldExecutionRunnerError::UnsolicitedCheckpoint,
                            ));
                        }
                        let capture =
                            lifecycle
                                .capture_attempt_checkpoint(context)
                                .map_err(|error| {
                                    AttemptWorkerFailure::Terminal(
                                        QemuHotForkWorldExecutionRunnerError::CheckpointCapture(
                                            error,
                                        ),
                                    )
                                })?;
                        context
                            .prepare_and_stage_checkpoint(capture)
                            .map(HotForkRunnerResult::Checkpoint)
                            .map_err(map_hot_fork_checkpoint_handoff_failure)
                    }
                }
            });
        let driven = driven.and_then(|pending| {
            lifecycle
                .prepare_terminal_fingerprints()
                .map(|()| pending)
                .map_err(map_hot_fork_terminal_fingerprint_capture_failure)
        });
        let cleanup = lifecycle.shutdown();
        let (pending, final_events) = match (driven, cleanup) {
            (Ok(pending), Ok(events)) => (pending, events),
            (Err(failure), Ok(_)) => {
                self.factory.quarantine(lifecycle);
                return Err(failure);
            }
            (Ok(_), Err(cleanup)) => {
                self.factory.quarantine(lifecycle);
                return Err(AttemptWorkerFailure::Terminal(
                    QemuHotForkWorldExecutionRunnerError::Cleanup(cleanup),
                ));
            }
            (Err(failure), Err(cleanup)) => {
                self.factory.quarantine(lifecycle);
                return Err(AttemptWorkerFailure::Terminal(
                    QemuHotForkWorldExecutionRunnerError::CleanupAfterRunner {
                        failure: Box::new(failure.into_error()),
                        cleanup,
                    },
                ));
            }
        };
        let product = match pending {
            HotForkRunnerResult::Observation(pending) => {
                match self.driver.seal(pending, final_events) {
                    Ok(product) => product,
                    Err(failure) => {
                        self.factory.quarantine(lifecycle);
                        return Err(map_hot_fork_driver_failure(failure));
                    }
                }
            }
            HotForkRunnerResult::Checkpoint(checkpoint) => {
                AttemptExecutionProduct::exact_checkpoint(checkpoint)
            }
        };
        self.pending = Some(lifecycle);
        Ok(QemuHotForkWorldExecutionAttempt::Executed(
            CrucibleExecutionOutcome::new(product, CrucibleMaterializationTier::HotFork),
        ))
    }

    /// Reconciles one bounded publication phase and recovers its source world.
    ///
    /// # Errors
    ///
    /// Returns a classified retryable or terminal failure when no lifecycle
    /// awaits reconciliation, child reconciliation fails, or source recovery
    /// cannot be completed or quarantined.
    pub fn reconcile_execution(
        &mut self,
        disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, HotForkWorldRunnerFailure<F, D>> {
        let Some(mut lifecycle) = self.pending.take() else {
            return Err(AttemptWorkerFailure::Terminal(
                QemuHotForkWorldExecutionRunnerError::NoPendingReconciliation,
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
                    Err(lifecycle) => {
                        self.factory.quarantine(lifecycle);
                        Err(AttemptWorkerFailure::Terminal(
                            QemuHotForkWorldExecutionRunnerError::SourceRecovery,
                        ))
                    }
                }
            }
            Err(error) => {
                self.factory.quarantine(lifecycle);
                Err(AttemptWorkerFailure::Terminal(
                    QemuHotForkWorldExecutionRunnerError::Reconciliation(error),
                ))
            }
        }
    }
}

fn map_hot_fork_start_replay_failure<F, D>(
    failure: AttemptWorkerFailure<QemuFreshExecutionRunnerError<F, D>>,
) -> AttemptWorkerFailure<QemuHotForkWorldExecutionRunnerError<F, D>> {
    match failure {
        AttemptWorkerFailure::Retryable(error) => AttemptWorkerFailure::Retryable(
            QemuHotForkWorldExecutionRunnerError::StartReplay(start_replay_message(error)),
        ),
        AttemptWorkerFailure::Canceled(error) => AttemptWorkerFailure::Canceled(
            QemuHotForkWorldExecutionRunnerError::StartReplay(start_replay_message(error)),
        ),
        AttemptWorkerFailure::Terminal(error) => AttemptWorkerFailure::Terminal(
            QemuHotForkWorldExecutionRunnerError::StartReplay(start_replay_message(error)),
        ),
    }
}

fn start_replay_message<F, D>(error: QemuFreshExecutionRunnerError<F, D>) -> String {
    match error {
        QemuFreshExecutionRunnerError::StartReplay(source) => source.to_string(),
        _ => String::from("start replay returned an unrelated execution phase failure"),
    }
}

impl<F, D> Drop for QemuHotForkWorldExecutionRunner<F, D>
where
    F: QemuHotForkWorldLifecycleFactory,
{
    fn drop(&mut self) {
        self.quarantine_pending_execution();
    }
}

fn map_hot_fork_factory_failure<F, D>(
    failure: AttemptWorkerFailure<F>,
) -> AttemptWorkerFailure<QemuHotForkWorldExecutionRunnerError<F, D>> {
    failure.map(QemuHotForkWorldExecutionRunnerError::Factory)
}

fn map_hot_fork_driver_failure<F, D>(
    failure: AttemptWorkerFailure<D>,
) -> AttemptWorkerFailure<QemuHotForkWorldExecutionRunnerError<F, D>> {
    failure.map(QemuHotForkWorldExecutionRunnerError::Driver)
}

fn map_hot_fork_checkpoint_handoff_failure<F, D>(
    failure: AttemptWorkerFailure<CheckpointHandoffFailure>,
) -> AttemptWorkerFailure<QemuHotForkWorldExecutionRunnerError<F, D>> {
    failure.map(QemuHotForkWorldExecutionRunnerError::CheckpointHandoff)
}

fn map_hot_fork_terminal_fingerprint_capture_failure<F, D>(
    error: SchedulerError,
) -> AttemptWorkerFailure<QemuHotForkWorldExecutionRunnerError<F, D>> {
    let class = if let SchedulerError::OperationalBoundary { class, .. } = &error {
        Some(*class)
    } else {
        None
    };
    let error = QemuHotForkWorldExecutionRunnerError::TerminalFingerprintCapture(error);
    match class {
        Some(SchedulerOperationalFailureClass::Retryable) => AttemptWorkerFailure::Retryable(error),
        Some(SchedulerOperationalFailureClass::Canceled) => AttemptWorkerFailure::Canceled(error),
        Some(SchedulerOperationalFailureClass::Terminal) | None => {
            AttemptWorkerFailure::Terminal(error)
        }
    }
}

pub(crate) trait AttemptWorkerFailureExt<E> {
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
