//! Guarded version-four production-checkpoint resume for campaign attempts.
//!
//! This module keeps durable-root installation, multi-node process launch,
//! modeled driving, final drain, and result sealing in one linear owner. A
//! resumed attempt always obtains its execution outcome from the exact root;
//! independent fresh replay only authenticates its semantic basis and never
//! becomes an execution fallback. A raw replay-oracle root is rejected before
//! any attempt process guard is installed.
//!
//! An ordinary `EventCount` resume also receives an independently replayed
//! genesis-to-start event-prefix proof. Version-four exact-checkpoint envelopes
//! do not retain an attempt-local event count, so the runner authenticates that
//! prefix against the restored complete log and derives same-attempt progress by
//! subtraction. Other stop modes do not consume this count and remain compatible
//! with start decisions that the cold replay path cannot reconstruct.

use std::sync::Arc;

use crucible::{
    Configuration, ScenarioDef, ScenarioDefForm, SchedulerError, SchedulerOperationalFailureClass,
};
use crucible_api::{ProductionVmLifecycleLoop, ProductionVmLifecycleResumeState};
use crucible_campaign::ExactCheckpointId;
use crucible_cas::content_store::StoreError;

use crate::qemu_campaign_lifecycle::classify_production_lifecycle_failure;
use crate::{
    AttemptCheckpointResult, AttemptExecutionContext, AttemptExecutionProduct,
    AttemptWorkerFailure, CheckpointHandoffFailure, CrucibleAttemptExecution,
    CrucibleExecutionOutcome, CrucibleExecutionRunner, CrucibleMaterializationTier,
    ExactCheckpointStore, MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES, MAX_QEMU_CAMPAIGN_EVENT_LOG_ENTRIES,
    QemuAttemptProcessResourceGuard, QemuAttemptProductionVmLifecycleFactory,
    QemuAttemptResourceGuardFactory, QemuAttemptStartReplayProof, QemuFreshAttemptDriver,
    QemuFreshAttemptLifecycle, QemuFreshAttemptLifecycleOwner, QemuFreshDriveOutcome,
    QemuFreshStartMaterialization, QemuOrdinaryResumeRunner, QemuSavepointReplayProof,
    QemuSelectedOriginResumeRunner,
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

    /// Authenticates the checkpoint's modeled boundary without launching QEMU.
    ///
    /// # Errors
    ///
    /// Returns a classified source, integrity, cancellation, or compatibility failure.
    #[allow(clippy::too_many_arguments)]
    fn authenticate_resume_boundary(
        &mut self,
        checkpoints: &ExactCheckpointStore,
        checkpoint: ExactCheckpointId,
        scenario: &ScenarioDef,
        source: &ScenarioDefForm,
        initial: &Configuration,
        post_selection: Option<&Configuration>,
        context: &AttemptExecutionContext,
    ) -> Result<
        Option<crate::qemu_campaign_driver::QemuSelectedResumeBoundary>,
        AttemptWorkerFailure<Self::Error>,
    >;

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

    fn authenticate_resume_boundary(
        &mut self,
        checkpoints: &ExactCheckpointStore,
        checkpoint: ExactCheckpointId,
        scenario: &ScenarioDef,
        source: &ScenarioDefForm,
        initial: &Configuration,
        post_selection: Option<&Configuration>,
        context: &AttemptExecutionContext,
    ) -> Result<
        Option<crate::qemu_campaign_driver::QemuSelectedResumeBoundary>,
        AttemptWorkerFailure<Self::Error>,
    > {
        let result = QemuAttemptProductionVmLifecycleFactory::authenticate_resume_boundary(
            self,
            checkpoints,
            checkpoint,
            scenario,
            source,
            initial,
            post_selection,
            context,
        );
        match result {
            Ok(boundary) => Ok(Some(boundary)),
            Err(error) if initial_selected_source_is_absent(&error, checkpoint, context) => {
                Ok(None)
            }
            Err(error) => Err(classify_production_lifecycle_failure(error)),
        }
    }

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

fn initial_selected_source_is_absent(
    error: &crate::QemuAttemptProductionVmLifecycleError,
    checkpoint: ExactCheckpointId,
    context: &AttemptExecutionContext,
) -> bool {
    matches!(
        error,
        crate::QemuAttemptProductionVmLifecycleError::CheckpointRestore(
            crate::ProductionAttemptCheckpointRestoreError::Checkpoint(
                crate::ExactCheckpointStoreError::Store(StoreError::NotFound { id }),
            ),
        ) if *id == checkpoint.content_id()
    ) && matches!(
        context.execution_origin(),
        crate::AttemptExecutionOrigin::SelectedSavepoint { resume: None, .. }
    )
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
#[derive(Debug)]
pub enum QemuProductionExactResumeExecutionRunnerError<F, D> {
    /// The resume-only runner received an execution without a durable root.
    MissingCheckpoint,
    /// Exact closure installation or guarded lifecycle construction failed.
    Lifecycle(F),
    /// The checkpoint retained only an event-log suffix.
    IncompleteEventLog(u64),
    /// A selected continuation reached resume without an independent cold proof.
    MissingSelectedOriginProof,
    /// An ordinary attempt reached resume without an independent start-prefix proof.
    MissingAttemptStartProof,
    /// The restored physical source differs from the independently replayed boundary.
    SelectedOriginMismatch,
    /// The restored event log does not begin with the independently replayed start prefix.
    AttemptStartMismatch,
    /// Restored cumulative event evidence exceeded a campaign bound.
    EventLogLimit {
        /// Stable name of the exceeded bound.
        limit: &'static str,
    },
    /// Modeled driving or result construction failed.
    Driver(D),
    /// A checkpoint was returned without a sticky checkpoint request.
    UnsolicitedCheckpoint,
    /// Capturing a later exact checkpoint failed.
    CheckpointCapture(SchedulerError),
    /// Durable root-before-write handoff for a later checkpoint failed.
    CheckpointHandoff(CheckpointHandoffFailure),
    /// Final drain or lifecycle cleanup failed.
    Cleanup(SchedulerError),
    /// Cleanup failed after another runner-owned phase failed.
    CleanupAfterRunner {
        /// Original failure retained for diagnosis.
        failure: Box<QemuProductionExactResumeExecutionRunnerError<F, D>>,
        /// Higher-priority cleanup failure.
        cleanup: SchedulerError,
    },
}

type ExactResumeWorkerFailure<F, D> =
    AttemptWorkerFailure<QemuProductionExactResumeExecutionRunnerError<F, D>>;

impl<F, D> std::fmt::Display for QemuProductionExactResumeExecutionRunnerError<F, D> {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MissingCheckpoint => {
                formatter.write_str("production exact-resume runner received no checkpoint root")
            }
            Self::Lifecycle(_) => formatter.write_str("restore production campaign lifecycle"),
            Self::IncompleteEventLog(prior) => write!(
                formatter,
                "production checkpoint event log begins after {prior} prior events"
            ),
            Self::MissingSelectedOriginProof => formatter
                .write_str("selected continuation resume received no independent origin proof"),
            Self::MissingAttemptStartProof => formatter
                .write_str("ordinary attempt resume received no independent start-prefix proof"),
            Self::SelectedOriginMismatch => formatter
                .write_str("selected continuation physical source differs from cold replay"),
            Self::AttemptStartMismatch => formatter
                .write_str("ordinary attempt checkpoint differs from cold start-prefix replay"),
            Self::EventLogLimit { limit } => {
                write!(
                    formatter,
                    "production checkpoint event log exceeded `{limit}`"
                )
            }
            Self::Driver(_) => formatter.write_str("resumed production campaign driver failed"),
            Self::UnsolicitedCheckpoint => formatter
                .write_str("resumed production campaign driver returned an unsolicited checkpoint"),
            Self::CheckpointCapture(error) => {
                write!(formatter, "capture resumed production checkpoint: {error}")
            }
            Self::CheckpointHandoff(error) => {
                write!(formatter, "handoff resumed production checkpoint: {error}")
            }
            Self::Cleanup(error) => {
                write!(
                    formatter,
                    "clean up resumed production campaign lifecycle: {error}"
                )
            }
            Self::CleanupAfterRunner { cleanup, .. } => write!(
                formatter,
                "resumed production cleanup failed after a prior runner failure: {cleanup}"
            ),
        }
    }
}

impl<F, D> std::error::Error for QemuProductionExactResumeExecutionRunnerError<F, D>
where
    F: std::error::Error + 'static,
    D: std::error::Error + 'static,
{
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Lifecycle(error) => Some(error),
            Self::Driver(error) => Some(error),
            Self::CheckpointCapture(error) | Self::Cleanup(error) => Some(error),
            Self::CheckpointHandoff(error) => Some(error),
            Self::CleanupAfterRunner { failure, .. } => Some(failure.as_ref()),
            Self::MissingCheckpoint
            | Self::IncompleteEventLog(_)
            | Self::MissingSelectedOriginProof
            | Self::MissingAttemptStartProof
            | Self::SelectedOriginMismatch
            | Self::AttemptStartMismatch
            | Self::EventLogLimit { .. }
            | Self::UnsolicitedCheckpoint => None,
        }
    }
}

enum ResumeRunnerResult<P> {
    Observation(P),
    Checkpoint(AttemptCheckpointResult),
}

enum QemuResumeReplayProof {
    AttemptStart(Option<QemuAttemptStartReplayProof>),
    SelectedOrigin(QemuSavepointReplayProof),
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
        if context.resume_checkpoint().is_none() {
            return Err(AttemptWorkerFailure::Terminal(
                QemuProductionExactResumeExecutionRunnerError::MissingCheckpoint,
            ));
        }
        if matches!(
            input.start(),
            crate::CrucibleResolvedAttemptStart::AfterAttempt { .. }
        ) {
            return Err(AttemptWorkerFailure::Terminal(
                QemuProductionExactResumeExecutionRunnerError::MissingSelectedOriginProof,
            ));
        }
        if matches!(
            input.attempt().stop(),
            crucible_campaign::StopCondition::EventCount(_)
        ) {
            return Err(AttemptWorkerFailure::Terminal(
                QemuProductionExactResumeExecutionRunnerError::MissingAttemptStartProof,
            ));
        }

        self.execute_with_replay_proof(input, context, QemuResumeReplayProof::AttemptStart(None))
    }
}

impl<F, D> QemuSelectedOriginResumeRunner for QemuProductionExactResumeExecutionRunner<F, D>
where
    F: QemuProductionExactResumeLifecycleFactory,
    D: QemuFreshAttemptDriver,
{
    fn authenticate_selected_resume_boundary(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<
        Option<crate::qemu_campaign_driver::QemuSelectedResumeBoundary>,
        AttemptWorkerFailure<Self::Error>,
    > {
        let checkpoint = context.resume_checkpoint().ok_or_else(|| {
            AttemptWorkerFailure::Terminal(
                QemuProductionExactResumeExecutionRunnerError::MissingCheckpoint,
            )
        })?;
        let scenario = input.scenario().scenario_def();
        let (initial, post_selection) = attempt_resume_configurations(input);
        self.lifecycles
            .authenticate_resume_boundary(
                &self.checkpoints,
                checkpoint,
                &scenario,
                input.scenario(),
                initial,
                post_selection,
                context,
            )
            .map_err(map_resume_lifecycle_failure)
    }

    fn execute_verified_selected_origin(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        proof: QemuSavepointReplayProof,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        self.execute_with_replay_proof(input, context, QemuResumeReplayProof::SelectedOrigin(proof))
    }
}

impl<F, D> QemuOrdinaryResumeRunner for QemuProductionExactResumeExecutionRunner<F, D>
where
    F: QemuProductionExactResumeLifecycleFactory,
    D: QemuFreshAttemptDriver,
{
    fn execute_verified_attempt_start(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        proof: QemuAttemptStartReplayProof,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        self.execute_with_replay_proof(
            input,
            context,
            QemuResumeReplayProof::AttemptStart(Some(proof)),
        )
    }
}

impl<F, D> QemuProductionExactResumeExecutionRunner<F, D>
where
    F: QemuProductionExactResumeLifecycleFactory,
    D: QemuFreshAttemptDriver,
{
    fn execute_with_replay_proof(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
        replay_proof: QemuResumeReplayProof,
    ) -> Result<CrucibleExecutionOutcome, ExactResumeWorkerFailure<F::Error, D::Error>> {
        let checkpoint = context.resume_checkpoint().ok_or_else(|| {
            AttemptWorkerFailure::Terminal(
                QemuProductionExactResumeExecutionRunnerError::MissingCheckpoint,
            )
        })?;
        let proof_matches_start = matches!(
            (input.start(), &replay_proof),
            (
                crate::CrucibleResolvedAttemptStart::AfterAttempt { .. },
                QemuResumeReplayProof::SelectedOrigin(_),
            ) | (
                crate::CrucibleResolvedAttemptStart::Discover { .. }
                    | crate::CrucibleResolvedAttemptStart::Branch { .. },
                QemuResumeReplayProof::AttemptStart(_),
            )
        );
        if !proof_matches_start {
            let error = match input.start() {
                crate::CrucibleResolvedAttemptStart::AfterAttempt { .. } => {
                    QemuProductionExactResumeExecutionRunnerError::MissingSelectedOriginProof
                }
                crate::CrucibleResolvedAttemptStart::Discover { .. }
                | crate::CrucibleResolvedAttemptStart::Branch { .. } => {
                    QemuProductionExactResumeExecutionRunnerError::MissingAttemptStartProof
                }
            };
            return Err(AttemptWorkerFailure::Terminal(error));
        }
        let scenario = input.scenario().scenario_def();
        let (initial, post_selection) = attempt_resume_configurations(input);
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
        let driven =
            resume_start_materialization(&lifecycle, input.start().configuration(), replay_proof)
                .and_then(|materialization| {
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
                                let error = QemuProductionExactResumeExecutionRunnerError::
                                    UnsolicitedCheckpoint;
                                return Err(AttemptWorkerFailure::Terminal(error));
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
                return Err(AttemptWorkerFailure::Terminal(
                    QemuProductionExactResumeExecutionRunnerError::Cleanup(cleanup),
                ));
            }
            (Err(failure), Err(cleanup)) => {
                let failure = match failure {
                    AttemptWorkerFailure::Retryable(error)
                    | AttemptWorkerFailure::Canceled(error)
                    | AttemptWorkerFailure::Terminal(error) => error,
                };
                return Err(AttemptWorkerFailure::Terminal(
                    QemuProductionExactResumeExecutionRunnerError::CleanupAfterRunner {
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
    attempt_start: &Configuration,
    proof: QemuResumeReplayProof,
) -> Result<
    QemuFreshStartMaterialization,
    AttemptWorkerFailure<QemuProductionExactResumeExecutionRunnerError<F, D>>,
> {
    let (configuration, events, base, completed_quanta, frontier, quiescence, terminal) = lifecycle
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
    let attempt_event_count = match proof {
        QemuResumeReplayProof::AttemptStart(Some(proof)) => proof
            .attempt_event_count(attempt_start, &events)
            .ok_or(AttemptWorkerFailure::Terminal(
                QemuProductionExactResumeExecutionRunnerError::AttemptStartMismatch,
            ))?,
        QemuResumeReplayProof::AttemptStart(None) => 0,
        QemuResumeReplayProof::SelectedOrigin(proof) => {
            if !proof.matches_boundary(&configuration, completed_quanta, frontier, base, &events) {
                return Err(AttemptWorkerFailure::Terminal(
                    QemuProductionExactResumeExecutionRunnerError::SelectedOriginMismatch,
                ));
            }
            proof
                .attempt_event_count()
                .and_then(|count| usize::try_from(count).ok())
                .ok_or(AttemptWorkerFailure::Terminal(
                    QemuProductionExactResumeExecutionRunnerError::SelectedOriginMismatch,
                ))?
        }
    };
    Ok(QemuFreshStartMaterialization::from_resume_parts(
        configuration,
        events,
        bytes,
        completed_quanta,
        frontier,
        quiescence,
        terminal,
    )
    .with_attempt_event_count(attempt_event_count))
}

fn attempt_resume_configurations(
    input: &CrucibleAttemptExecution,
) -> (&Configuration, Option<&Configuration>) {
    match input.start() {
        crate::CrucibleResolvedAttemptStart::Discover { configuration } => (configuration, None),
        crate::CrucibleResolvedAttemptStart::Branch {
            parent, selected, ..
        } => (parent, Some(selected)),
        crate::CrucibleResolvedAttemptStart::AfterAttempt { .. } => {
            (input.start().configuration(), None)
        }
    }
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
