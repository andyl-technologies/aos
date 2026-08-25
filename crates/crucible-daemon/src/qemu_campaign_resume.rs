//! Guarded version-four production-checkpoint resume for campaign attempts.
//!
//! This module keeps durable-root installation, multi-node process launch,
//! modeled driving, final drain, and result sealing in one linear owner. A
//! resumed attempt never enters the fresh replay path, and a raw replay-oracle
//! root is rejected before any attempt process guard is installed.

use std::sync::Arc;

use crucible::{
    Configuration, ScenarioDef, ScenarioDefForm, SchedulerError, SchedulerOperationalFailureClass,
};
use crucible_api::{ProductionVmLifecycleLoop, ProductionVmLifecycleResumeState};
use crucible_campaign::ExactCheckpointId;

use crate::qemu_campaign_lifecycle::classify_production_lifecycle_failure;
use crate::{
    AttemptCheckpointResult, AttemptExecutionContext, AttemptExecutionProduct,
    AttemptWorkerFailure, CheckpointHandoffFailure, CrucibleAttemptExecution,
    CrucibleExecutionOutcome, CrucibleExecutionRunner, CrucibleMaterializationTier,
    ExactCheckpointStore, MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES, MAX_QEMU_CAMPAIGN_EVENT_LOG_ENTRIES,
    QemuAttemptProcessResourceGuard, QemuAttemptProductionVmLifecycleFactory,
    QemuAttemptResourceGuardFactory, QemuFreshAttemptDriver, QemuFreshAttemptLifecycle,
    QemuFreshAttemptLifecycleOwner, QemuFreshDriveOutcome, QemuFreshStartMaterialization,
};

#[cfg(test)]
mod tests;

/// Runner-owned lifecycle operations required after exact production restore.
pub trait QemuProductionExactResumeLifecycleOwner: QemuFreshAttemptLifecycleOwner {
    /// Returns the exact scheduler/evidence boundary restored with this lifecycle.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the restored scheduler cannot project a
    /// coherent quiescence boundary.
    fn resume_state(&self) -> Result<ProductionVmLifecycleResumeState, SchedulerError>;
}

impl QemuProductionExactResumeLifecycleOwner for ProductionVmLifecycleLoop {
    fn resume_state(&self) -> Result<ProductionVmLifecycleResumeState, SchedulerError> {
        ProductionVmLifecycleLoop::resume_state(self)
    }
}

/// Factory for one replay-validated, exact-root production lifecycle.
pub trait QemuProductionExactResumeLifecycleFactory {
    /// Exact lifecycle owner created for one resumed attempt.
    type Lifecycle: QemuProductionExactResumeLifecycleOwner;
    /// Factory-specific installation or guarded-construction failure.
    type Error;

    /// Restores one exact root under the admitted operational context.
    ///
    /// Implementations must reject a missing, raw, foreign, or incomplete root
    /// without substituting fresh execution.
    ///
    /// # Errors
    ///
    /// Returns a classified failure for cancellation, temporary immutable-store
    /// unavailability, invalid resume basis, or guarded lifecycle construction.
    // crucible-lint: allow rust-allow -- the resume factory binds every independent semantic and operational basis explicitly.
    #[allow(clippy::too_many_arguments)]
    fn start_resume_lifecycle(
        &mut self,
        checkpoints: &ExactCheckpointStore,
        checkpoint: ExactCheckpointId,
        scenario: &ScenarioDef,
        source: &ScenarioDefForm,
        initial: &Configuration,
        post_selection: Option<&Configuration>,
        context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>>;
}

impl<R> QemuProductionExactResumeLifecycleFactory for QemuAttemptProductionVmLifecycleFactory<R>
where
    R: QemuAttemptResourceGuardFactory,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    type Lifecycle = ProductionVmLifecycleLoop;
    type Error = crate::QemuAttemptProductionVmLifecycleError;

    fn start_resume_lifecycle(
        &mut self,
        checkpoints: &ExactCheckpointStore,
        checkpoint: ExactCheckpointId,
        scenario: &ScenarioDef,
        source: &ScenarioDefForm,
        initial: &Configuration,
        post_selection: Option<&Configuration>,
        context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        self.begin_resume(
            checkpoints,
            checkpoint,
            scenario,
            source,
            initial,
            post_selection,
            context,
        )
        .map_err(classify_production_lifecycle_failure)
    }
}

/// Version-four exact-resume runner with runner-owned final drain and sealing.
pub struct QemuProductionExactResumeExecutionRunner<F, D> {
    checkpoints: Arc<ExactCheckpointStore>,
    lifecycles: F,
    driver: D,
}

impl<F, D> QemuProductionExactResumeExecutionRunner<F, D> {
    /// Creates a production resume runner from its immutable store and owners.
    #[must_use]
    pub const fn new(checkpoints: Arc<ExactCheckpointStore>, lifecycles: F, driver: D) -> Self {
        Self {
            checkpoints,
            lifecycles,
            driver,
        }
    }

    /// Returns the immutable exact-checkpoint store.
    #[must_use]
    pub fn checkpoints(&self) -> &Arc<ExactCheckpointStore> {
        &self.checkpoints
    }

    /// Returns the guarded lifecycle factory.
    #[must_use]
    pub const fn lifecycle_factory(&self) -> &F {
        &self.lifecycles
    }

    /// Returns the modeled attempt driver.
    #[must_use]
    pub const fn driver(&self) -> &D {
        &self.driver
    }

    /// Consumes the runner into its exact store, lifecycle factory, and driver.
    #[must_use]
    pub fn into_parts(self) -> (Arc<ExactCheckpointStore>, F, D) {
        (self.checkpoints, self.lifecycles, self.driver)
    }
}

/// Failure from one exact production-resume phase.
#[derive(Debug, thiserror::Error)]
pub enum QemuProductionExactResumeExecutionRunnerError<F, D> {
    /// The resume-only runner received an execution without a durable root.
    #[error("production exact-resume runner received no checkpoint root")]
    MissingCheckpoint,
    /// Exact closure installation or guarded lifecycle construction failed.
    #[error("restore production campaign lifecycle")]
    Lifecycle(F),
    /// The checkpoint retained only an event-log suffix.
    #[error("production checkpoint event log begins after {0} prior events")]
    IncompleteEventLog(u64),
    /// Restored cumulative event evidence exceeded a campaign bound.
    #[error("production checkpoint event log exceeded `{limit}`")]
    EventLogLimit {
        /// Stable name of the exceeded bound.
        limit: &'static str,
    },
    /// Modeled driving or result construction failed.
    #[error("resumed production campaign driver failed")]
    Driver(D),
    /// A checkpoint was returned without a sticky checkpoint request.
    #[error("resumed production campaign driver returned an unsolicited checkpoint")]
    UnsolicitedCheckpoint,
    /// Capturing a later exact checkpoint failed.
    #[error("capture resumed production checkpoint: {0}")]
    CheckpointCapture(#[source] SchedulerError),
    /// Durable root-before-write handoff for a later checkpoint failed.
    #[error("handoff resumed production checkpoint: {0}")]
    CheckpointHandoff(#[source] CheckpointHandoffFailure),
    /// Final drain or lifecycle cleanup failed.
    #[error("clean up resumed production campaign lifecycle: {0}")]
    Cleanup(#[source] SchedulerError),
    /// Cleanup failed after another runner-owned phase failed.
    #[error("resumed production cleanup failed after `{failure}`: {cleanup}")]
    CleanupAfterRunner {
        /// Original failure retained for diagnosis.
        failure: Box<QemuProductionExactResumeExecutionRunnerError<F, D>>,
        /// Higher-priority cleanup failure.
        cleanup: SchedulerError,
    },
}

enum ResumeRunnerResult<P> {
    Observation(P),
    Checkpoint(AttemptCheckpointResult),
}

impl<F, D> CrucibleExecutionRunner for QemuProductionExactResumeExecutionRunner<F, D>
where
    F: QemuProductionExactResumeLifecycleFactory,
    D: QemuFreshAttemptDriver,
{
    type Error = QemuProductionExactResumeExecutionRunnerError<F::Error, D::Error>;

    fn execute(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        let checkpoint = context
            .resume_checkpoint()
            .ok_or_else(|| AttemptWorkerFailure::Terminal(Self::Error::MissingCheckpoint))?;
        let scenario = input.scenario().scenario_def();
        let (initial, post_selection) = match input.start() {
            crate::CrucibleResolvedAttemptStart::Discover { configuration } => {
                (configuration, None)
            }
            crate::CrucibleResolvedAttemptStart::Branch {
                parent, selected, ..
            } => (parent, Some(selected)),
        };
        let mut lifecycle = self
            .lifecycles
            .start_resume_lifecycle(
                &self.checkpoints,
                checkpoint,
                &scenario,
                input.scenario(),
                initial,
                post_selection,
                context,
            )
            .map_err(map_resume_lifecycle_failure)?;
        let driven = resume_start_materialization(&lifecycle).and_then(|materialization| {
            let mut facade = QemuFreshAttemptLifecycle::new(&mut lifecycle);
            match self
                .driver
                .drive(&mut facade, input, context, materialization)
                .map_err(map_resume_driver_failure)?
            {
                QemuFreshDriveOutcome::Observation(pending) => {
                    Ok(ResumeRunnerResult::Observation(pending))
                }
                QemuFreshDriveOutcome::CheckpointRequested => {
                    if !context.checkpoint_request().is_requested() {
                        return Err(AttemptWorkerFailure::Terminal(
                            Self::Error::UnsolicitedCheckpoint,
                        ));
                    }
                    let capture = lifecycle
                        .capture_attempt_checkpoint(context)
                        .map_err(map_resume_checkpoint_capture_failure)?;
                    context
                        .prepare_and_stage_checkpoint(capture)
                        .map(ResumeRunnerResult::Checkpoint)
                        .map_err(map_resume_checkpoint_handoff_failure)
                }
            }
        });
        let cleanup = lifecycle.shutdown();
        let (pending, final_events) = match (driven, cleanup) {
            (Ok(pending), Ok(events)) => (pending, events),
            (Err(failure), Ok(_)) => return Err(failure),
            (Ok(_), Err(cleanup)) => {
                return Err(AttemptWorkerFailure::Terminal(Self::Error::Cleanup(
                    cleanup,
                )));
            }
            (Err(failure), Err(cleanup)) => {
                let failure = match failure {
                    AttemptWorkerFailure::Retryable(error)
                    | AttemptWorkerFailure::Canceled(error)
                    | AttemptWorkerFailure::Terminal(error) => error,
                };
                return Err(AttemptWorkerFailure::Terminal(
                    Self::Error::CleanupAfterRunner {
                        failure: Box::new(failure),
                        cleanup,
                    },
                ));
            }
        };
        let product = match pending {
            ResumeRunnerResult::Observation(pending) => self
                .driver
                .seal(pending, final_events)
                .map_err(map_resume_driver_failure)?,
            ResumeRunnerResult::Checkpoint(checkpoint) => {
                AttemptExecutionProduct::exact_checkpoint(checkpoint)
            }
        };
        Ok(CrucibleExecutionOutcome::new(
            product,
            CrucibleMaterializationTier::ExactRestore,
        ))
    }
}

fn resume_start_materialization<F, D>(
    lifecycle: &impl QemuProductionExactResumeLifecycleOwner,
) -> Result<
    QemuFreshStartMaterialization,
    AttemptWorkerFailure<QemuProductionExactResumeExecutionRunnerError<F, D>>,
> {
    let (events, base, quiescence, terminal) = lifecycle
        .resume_state()
        .map_err(map_resume_checkpoint_capture_failure)?
        .into_parts();
    if base != 0 {
        return Err(AttemptWorkerFailure::Terminal(
            QemuProductionExactResumeExecutionRunnerError::IncompleteEventLog(base),
        ));
    }
    if events.len() > MAX_QEMU_CAMPAIGN_EVENT_LOG_ENTRIES {
        return Err(resume_event_log_limit("campaign-event-log-entry-count"));
    }
    let bytes = events.iter().try_fold(0usize, |total, entry| {
        total
            .checked_add(entry.canonical_material_len())
            .ok_or_else(|| resume_event_log_limit("campaign-event-log-bytes"))
    })?;
    if bytes > MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES {
        return Err(resume_event_log_limit("campaign-event-log-bytes"));
    }
    Ok(QemuFreshStartMaterialization::from_resume_parts(
        events, bytes, quiescence, terminal,
    ))
}

fn resume_event_log_limit<F, D>(
    limit: &'static str,
) -> AttemptWorkerFailure<QemuProductionExactResumeExecutionRunnerError<F, D>> {
    AttemptWorkerFailure::Terminal(
        QemuProductionExactResumeExecutionRunnerError::EventLogLimit { limit },
    )
}

fn map_resume_lifecycle_failure<F, D>(
    failure: AttemptWorkerFailure<F>,
) -> AttemptWorkerFailure<QemuProductionExactResumeExecutionRunnerError<F, D>> {
    match failure {
        AttemptWorkerFailure::Retryable(error) => AttemptWorkerFailure::Retryable(
            QemuProductionExactResumeExecutionRunnerError::Lifecycle(error),
        ),
        AttemptWorkerFailure::Canceled(error) => AttemptWorkerFailure::Canceled(
            QemuProductionExactResumeExecutionRunnerError::Lifecycle(error),
        ),
        AttemptWorkerFailure::Terminal(error) => AttemptWorkerFailure::Terminal(
            QemuProductionExactResumeExecutionRunnerError::Lifecycle(error),
        ),
    }
}

fn map_resume_driver_failure<F, D>(
    failure: AttemptWorkerFailure<D>,
) -> AttemptWorkerFailure<QemuProductionExactResumeExecutionRunnerError<F, D>> {
    match failure {
        AttemptWorkerFailure::Retryable(error) => AttemptWorkerFailure::Retryable(
            QemuProductionExactResumeExecutionRunnerError::Driver(error),
        ),
        AttemptWorkerFailure::Canceled(error) => AttemptWorkerFailure::Canceled(
            QemuProductionExactResumeExecutionRunnerError::Driver(error),
        ),
        AttemptWorkerFailure::Terminal(error) => AttemptWorkerFailure::Terminal(
            QemuProductionExactResumeExecutionRunnerError::Driver(error),
        ),
    }
}

fn map_resume_checkpoint_capture_failure<F, D>(
    error: SchedulerError,
) -> AttemptWorkerFailure<QemuProductionExactResumeExecutionRunnerError<F, D>> {
    let class = match &error {
        SchedulerError::OperationalBoundary { class, .. } => Some(*class),
        SchedulerError::NotImplemented { .. }
        | SchedulerError::Backend(_)
        | SchedulerError::BoundaryViolation { .. }
        | SchedulerError::ResourceLimit { .. }
        | SchedulerError::TimeConversion(_)
        | SchedulerError::TopologyActivationInPast { .. } => None,
    };
    let error = QemuProductionExactResumeExecutionRunnerError::CheckpointCapture(error);
    match class {
        Some(SchedulerOperationalFailureClass::Retryable) => AttemptWorkerFailure::Retryable(error),
        Some(SchedulerOperationalFailureClass::Canceled) => AttemptWorkerFailure::Canceled(error),
        Some(SchedulerOperationalFailureClass::Terminal) | None => {
            AttemptWorkerFailure::Terminal(error)
        }
    }
}

fn map_resume_checkpoint_handoff_failure<F, D>(
    failure: AttemptWorkerFailure<CheckpointHandoffFailure>,
) -> AttemptWorkerFailure<QemuProductionExactResumeExecutionRunnerError<F, D>> {
    match failure {
        AttemptWorkerFailure::Retryable(error) => AttemptWorkerFailure::Retryable(
            QemuProductionExactResumeExecutionRunnerError::CheckpointHandoff(error),
        ),
        AttemptWorkerFailure::Canceled(error) => AttemptWorkerFailure::Canceled(
            QemuProductionExactResumeExecutionRunnerError::CheckpointHandoff(error),
        ),
        AttemptWorkerFailure::Terminal(error) => AttemptWorkerFailure::Terminal(
            QemuProductionExactResumeExecutionRunnerError::CheckpointHandoff(error),
        ),
    }
}
