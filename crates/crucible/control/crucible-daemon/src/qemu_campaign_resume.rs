//! Guarded authenticated paged production-checkpoint resume for campaign attempts.
//!
//! This module keeps durable-root installation, multi-node process launch,
//! modeled driving, final drain, and result sealing in one linear owner. A
//! resumed attempt always obtains its execution outcome from the exact root;
//! independent fresh replay only authenticates its semantic basis and never
//! becomes an execution fallback. A raw replay-oracle root is rejected before
//! any attempt process guard is installed.
//!
//! An ordinary `EventCount` resume also receives an independently replayed
//! genesis-to-start event-prefix proof. Exact-checkpoint envelopes do not
//! retain an attempt-local event count, so the runner authenticates that
//! prefix against the restored complete log and derives same-attempt progress by
//! subtraction. Other stop modes do not consume this count and remain compatible
//! with start decisions that the cold replay path cannot reconstruct.

use std::sync::Arc;

use crate::{ProductionVmLifecycleLoop, ProductionVmLifecycleResumeState};
use crucible_engine::{
    Configuration, ScenarioDef, ScenarioDefForm, SchedulerError, SchedulerOperationalFailureClass,
};
use crucible_campaign::ExactCheckpointId;
use crucible_store::content_store::StoreError;

use crate::qemu_campaign_lifecycle::{
    QemuObservedFreshAttemptLifecycle, QemuObservedFreshAttemptLifecycleFactory,
    QemuObservedFreshAttemptLifecycleFactoryError, classify_production_lifecycle_failure,
    map_observed_evidence_failure, map_observed_inner_failure,
};
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
pub(crate) trait QemuProductionExactResumeLifecycleOwner:
    QemuFreshAttemptLifecycleOwner
{
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

impl<L> QemuProductionExactResumeLifecycleOwner for QemuObservedFreshAttemptLifecycle<L>
where
    L: QemuProductionExactResumeLifecycleOwner,
{
    fn resume_state(&self) -> Result<ProductionVmLifecycleResumeState, SchedulerError> {
        self.lifecycle().resume_state()
    }
}

/// Scenario and configuration identities authenticated for an exact resume.
#[derive(Clone, Copy)]
pub(crate) struct QemuExactResumeBasis<'a> {
    pub(crate) scenario: &'a ScenarioDef,
    pub(crate) source: &'a ScenarioDefForm,
    pub(crate) initial: &'a Configuration,
    pub(crate) post_selection: Option<&'a Configuration>,
}

impl<'a> QemuExactResumeBasis<'a> {
    /// Binds one scenario form to its exact resume configuration boundary.
    pub(crate) const fn new(
        scenario: &'a ScenarioDef,
        source: &'a ScenarioDefForm,
        initial: &'a Configuration,
        post_selection: Option<&'a Configuration>,
    ) -> Self {
        Self {
            scenario,
            source,
            initial,
            post_selection,
        }
    }
}

/// Factory for one replay-validated, exact-root production lifecycle.
pub(crate) trait QemuProductionExactResumeLifecycleFactory {
    /// Exact lifecycle owner created for one resumed attempt.
    type Lifecycle: QemuProductionExactResumeLifecycleOwner;
    /// Factory-specific installation or guarded-construction failure.
    type Error;

    /// Returns the complete lifecycle to its actual retained cleanup owner.
    ///
    /// # Errors
    /// Operational implementations retain the same owner if publication refuses.
    /// The default consumes only resource-free component lifecycle values.
    fn retire_lifecycle(&mut self, lifecycle: Self::Lifecycle) -> Result<(), Self::Error> {
        drop(lifecycle);
        Ok(())
    }

    /// Retries only cleanup already retained by this factory.
    ///
    /// # Errors
    /// Returns the actual retained-owner refusal without replacing its guards.
    fn try_retire_original(
        &mut self,
        _original: &crucible_host_resources::host_supervision::HostOperationGuard,
    ) -> Result<(), Self::Error> {
        Ok(())
    }

    /// Authenticates the checkpoint's modeled boundary without launching QEMU.
    ///
    /// # Errors
    ///
    /// Returns a classified source, integrity, cancellation, or compatibility failure.
    fn authenticate_resume_boundary(
        &mut self,
        checkpoints: &ExactCheckpointStore,
        checkpoint: ExactCheckpointId,
        basis: QemuExactResumeBasis<'_>,
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
    fn start_resume_lifecycle(
        &mut self,
        checkpoints: &ExactCheckpointStore,
        checkpoint: ExactCheckpointId,
        basis: QemuExactResumeBasis<'_>,
        context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>>;
}

impl<R> QemuProductionExactResumeLifecycleFactory for QemuAttemptProductionVmLifecycleFactory<R>
where
    R: QemuAttemptResourceGuardFactory + Send + 'static,
    R::Guard: QemuAttemptProcessResourceGuard + Send + 'static,
{
    type Lifecycle = ProductionVmLifecycleLoop;
    type Error = crate::QemuAttemptProductionVmLifecycleError;

    fn retire_lifecycle(&mut self, lifecycle: Self::Lifecycle) -> Result<(), Self::Error> {
        self.retain_returned_lifecycle(lifecycle)
    }

    fn try_retire_original(
        &mut self,
        _original: &crucible_host_resources::host_supervision::HostOperationGuard,
    ) -> Result<(), Self::Error> {
        self.retry_retained_source_installation()
    }

    fn authenticate_resume_boundary(
        &mut self,
        checkpoints: &ExactCheckpointStore,
        checkpoint: ExactCheckpointId,
        basis: QemuExactResumeBasis<'_>,
        context: &AttemptExecutionContext,
    ) -> Result<
        Option<crate::qemu_campaign_driver::QemuSelectedResumeBoundary>,
        AttemptWorkerFailure<Self::Error>,
    > {
        let result = QemuAttemptProductionVmLifecycleFactory::authenticate_resume_boundary(
            self,
            checkpoints,
            checkpoint,
            basis,
            context,
        );
        match result {
            Ok((boundary, _production_boundary)) => Ok(Some(boundary)),
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
        basis: QemuExactResumeBasis<'_>,
        context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        self.begin_resume(checkpoints, checkpoint, basis, context)
            .map_err(classify_production_lifecycle_failure)
    }
}

impl<F> QemuProductionExactResumeLifecycleFactory for QemuObservedFreshAttemptLifecycleFactory<F>
where
    F: QemuProductionExactResumeLifecycleFactory,
{
    type Lifecycle = QemuObservedFreshAttemptLifecycle<F::Lifecycle>;
    type Error = QemuObservedFreshAttemptLifecycleFactoryError<F::Error>;

    fn retire_lifecycle(&mut self, lifecycle: Self::Lifecycle) -> Result<(), Self::Error> {
        let (lifecycle, _, _) = lifecycle.into_recovery_parts();
        QemuProductionExactResumeLifecycleFactory::retire_lifecycle(self.inner_mut(), lifecycle)
            .map_err(QemuObservedFreshAttemptLifecycleFactoryError::Inner)
    }

    fn try_retire_original(
        &mut self,
        original: &crucible_host_resources::host_supervision::HostOperationGuard,
    ) -> Result<(), Self::Error> {
        QemuProductionExactResumeLifecycleFactory::try_retire_original(self.inner_mut(), original)
            .map_err(QemuObservedFreshAttemptLifecycleFactoryError::Inner)
    }

    fn authenticate_resume_boundary(
        &mut self,
        checkpoints: &ExactCheckpointStore,
        checkpoint: ExactCheckpointId,
        basis: QemuExactResumeBasis<'_>,
        context: &AttemptExecutionContext,
    ) -> Result<
        Option<crate::qemu_campaign_driver::QemuSelectedResumeBoundary>,
        AttemptWorkerFailure<Self::Error>,
    > {
        self.inner_mut()
            .authenticate_resume_boundary(checkpoints, checkpoint, basis, context)
            .map_err(map_observed_inner_failure)
    }

    fn start_resume_lifecycle(
        &mut self,
        checkpoints: &ExactCheckpointStore,
        checkpoint: ExactCheckpointId,
        basis: QemuExactResumeBasis<'_>,
        context: &AttemptExecutionContext,
    ) -> Result<Self::Lifecycle, AttemptWorkerFailure<Self::Error>> {
        let fingerprint_nodes = self
            .prepare_observation(basis.source)
            .map_err(map_observed_evidence_failure::<F::Error>)?;
        let lifecycle = self
            .inner_mut()
            .start_resume_lifecycle(checkpoints, checkpoint, basis, context)
            .map_err(map_observed_inner_failure)?;

        Ok(self.observe(lifecycle, fingerprint_nodes))
    }
}

fn initial_selected_source_is_absent(
    error: &crate::QemuAttemptProductionVmLifecycleError,
    checkpoint: ExactCheckpointId,
    context: &AttemptExecutionContext,
) -> bool {
    let absent_selected_root = match error {
        crate::QemuAttemptProductionVmLifecycleError::CheckpointRestore(source) => source
            .downcast_ref::<crate::ProductionAttemptCheckpointRestoreError>()
            .is_some_and(|source| {
                matches!(
                    source,
                    crate::ProductionAttemptCheckpointRestoreError::Checkpoint(
                        crate::ExactCheckpointStoreError::Store(StoreError::NotFound { id }),
                    ) if *id == checkpoint.content_id()
                )
            }),
        _ => false,
    };

    absent_selected_root
        && matches!(
            context.execution_origin(),
            crate::AttemptExecutionOrigin::SelectedSavepoint { resume: None, .. }
        )
}

/// Version-nine exact-resume runner with runner-owned final drain and sealing.
pub(crate) struct QemuProductionExactResumeExecutionRunner<F, D> {
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
}

mod error;

pub(crate) use error::{QemuProductionExactResumeExecutionRunnerError, ResumeFailure};
use error::{finish_resume_outcomes, wrap_resume_failure};

type ExactResumeWorkerFailure<F, D> =
    AttemptWorkerFailure<QemuProductionExactResumeExecutionRunnerError<F, D>>;

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

    fn try_retire_original(
        &mut self,
        original: &crucible_host_resources::host_supervision::HostOperationGuard,
    ) -> Result<(), Self::Error> {
        self.lifecycles
            .try_retire_original(original)
            .map_err(|first| ResumeFailure::Lifecycle(first).into())
    }

    fn execute(
        &mut self,
        input: &CrucibleAttemptExecution,
        context: &AttemptExecutionContext,
    ) -> Result<CrucibleExecutionOutcome, AttemptWorkerFailure<Self::Error>> {
        if context.resume_checkpoint().is_none() {
            return Err(AttemptWorkerFailure::Terminal(
                ResumeFailure::MissingCheckpoint.into(),
            ));
        }
        if matches!(
            input.start(),
            crate::CrucibleResolvedAttemptStart::AfterAttempt { .. }
        ) {
            return Err(AttemptWorkerFailure::Terminal(
                ResumeFailure::MissingSelectedOriginProof.into(),
            ));
        }
        if matches!(
            input.attempt().stop().primary(),
            crucible_campaign::StopCondition::EventCount(_)
        ) {
            return Err(AttemptWorkerFailure::Terminal(
                ResumeFailure::MissingAttemptStartProof.into(),
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
            AttemptWorkerFailure::Terminal(ResumeFailure::MissingCheckpoint.into())
        })?;
        let scenario = input.scenario().scenario_def();
        let (initial, post_selection) = attempt_resume_configurations(input);
        self.lifecycles
            .authenticate_resume_boundary(
                &self.checkpoints,
                checkpoint,
                QemuExactResumeBasis::new(&scenario, input.scenario(), initial, post_selection),
                context,
            )
            .map_err(map_resume_lifecycle_failure)
            .map_err(wrap_resume_failure)
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
            AttemptWorkerFailure::Terminal(ResumeFailure::MissingCheckpoint.into())
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
                    ResumeFailure::MissingSelectedOriginProof
                }
                crate::CrucibleResolvedAttemptStart::Discover { .. }
                | crate::CrucibleResolvedAttemptStart::Branch { .. } => {
                    ResumeFailure::MissingAttemptStartProof
                }
            };
            return Err(AttemptWorkerFailure::Terminal(error.into()));
        }
        let scenario = input.scenario().scenario_def();
        let (initial, post_selection) = attempt_resume_configurations(input);
        let mut lifecycle = self
            .lifecycles
            .start_resume_lifecycle(
                &self.checkpoints,
                checkpoint,
                QemuExactResumeBasis::new(&scenario, input.scenario(), initial, post_selection),
                context,
            )
            .map_err(map_resume_lifecycle_failure)
            .map_err(wrap_resume_failure)?;
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
                        QemuFreshDriveOutcome::CheckpointRequested(choices) => {
                            if !context.checkpoint_request().is_requested() {
                                let error = ResumeFailure::UnsolicitedCheckpoint;
                                return Err(AttemptWorkerFailure::Terminal(error));
                            }
                            let capture = lifecycle
                                .capture_attempt_checkpoint(context)
                                .map_err(map_resume_checkpoint_capture_failure)?;
                            let capture = choices
                                .bind_capture(input.scenario(), capture)
                                .map_err(map_resume_checkpoint_capture_failure)?;
                            context
                                .prepare_and_stage_checkpoint(capture)
                                .map(ResumeRunnerResult::Checkpoint)
                                .map_err(map_resume_checkpoint_handoff_failure)
                        }
                    }
                });
        let driven = driven.and_then(|pending| {
            lifecycle
                .prepare_terminal_fingerprints()
                .map(|()| pending)
                .map_err(map_resume_terminal_fingerprint_capture_failure)
        });
        let cleanup = lifecycle.shutdown();
        let retirement = self.lifecycles.retire_lifecycle(lifecycle);
        let (pending, final_events) = finish_resume_outcomes(driven, cleanup, retirement)?;
        let product = match pending {
            ResumeRunnerResult::Observation(pending) => self
                .driver
                .seal(pending, final_events)
                .map_err(map_resume_driver_failure)
                .map_err(wrap_resume_failure)?,
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
) -> Result<QemuFreshStartMaterialization, AttemptWorkerFailure<ResumeFailure<F, D>>> {
    let (configuration, events, base, completed_quanta, frontier, quiescence, terminal) = lifecycle
        .resume_state()
        .map_err(map_resume_checkpoint_capture_failure)?
        .into_parts();
    if base != 0 {
        return Err(AttemptWorkerFailure::Terminal(
            ResumeFailure::IncompleteEventLog(base),
        ));
    }
    if events.len() > MAX_QEMU_CAMPAIGN_EVENT_LOG_ENTRIES {
        return Err(resume_event_log_limit("campaign-event-log-entry-count"));
    }
    let bytes = events.iter().try_fold(0usize, |total, entry| {
        total
            .checked_add(entry.canonical_material_len().map_err(|source| {
                map_resume_checkpoint_capture_failure(SchedulerError::from(source))
            })?)
            .ok_or_else(|| resume_event_log_limit("campaign-event-log-bytes"))
    })?;
    if bytes > MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES {
        return Err(resume_event_log_limit("campaign-event-log-bytes"));
    }
    let attempt_event_count = match proof {
        QemuResumeReplayProof::AttemptStart(Some(proof)) => {
            proof.attempt_event_count(attempt_start, &events).ok_or(
                AttemptWorkerFailure::Terminal(ResumeFailure::AttemptStartMismatch),
            )?
        }
        QemuResumeReplayProof::AttemptStart(None) => 0,
        QemuResumeReplayProof::SelectedOrigin(proof) => {
            if !proof
                .matches_boundary(&configuration, completed_quanta, frontier, base, &events)
                .map_err(|source| {
                    map_resume_checkpoint_capture_failure(SchedulerError::from(source))
                })?
            {
                return Err(AttemptWorkerFailure::Terminal(
                    ResumeFailure::SelectedOriginMismatch,
                ));
            }
            proof
                .attempt_event_count()
                .and_then(|count| usize::try_from(count).ok())
                .ok_or(AttemptWorkerFailure::Terminal(
                    ResumeFailure::SelectedOriginMismatch,
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

fn resume_event_log_limit<F, D>(limit: &'static str) -> AttemptWorkerFailure<ResumeFailure<F, D>> {
    AttemptWorkerFailure::Terminal(ResumeFailure::EventLogLimit { limit })
}

fn map_resume_lifecycle_failure<F, D>(
    failure: AttemptWorkerFailure<F>,
) -> AttemptWorkerFailure<ResumeFailure<F, D>> {
    match failure {
        AttemptWorkerFailure::Retryable(error) => {
            AttemptWorkerFailure::Retryable(ResumeFailure::Lifecycle(error))
        }
        AttemptWorkerFailure::Canceled(error) => {
            AttemptWorkerFailure::Canceled(ResumeFailure::Lifecycle(error))
        }
        AttemptWorkerFailure::Terminal(error) => {
            AttemptWorkerFailure::Terminal(ResumeFailure::Lifecycle(error))
        }
    }
}

fn map_resume_driver_failure<F, D>(
    failure: AttemptWorkerFailure<D>,
) -> AttemptWorkerFailure<ResumeFailure<F, D>> {
    match failure {
        AttemptWorkerFailure::Retryable(error) => {
            AttemptWorkerFailure::Retryable(ResumeFailure::Driver(error))
        }
        AttemptWorkerFailure::Canceled(error) => {
            AttemptWorkerFailure::Canceled(ResumeFailure::Driver(error))
        }
        AttemptWorkerFailure::Terminal(error) => {
            AttemptWorkerFailure::Terminal(ResumeFailure::Driver(error))
        }
    }
}

fn map_resume_checkpoint_capture_failure<F, D>(
    error: SchedulerError,
) -> AttemptWorkerFailure<ResumeFailure<F, D>> {
    let class = error.operational_failure_class();
    let error = ResumeFailure::CheckpointCapture(error);
    match class {
        Some(SchedulerOperationalFailureClass::Retryable) => AttemptWorkerFailure::Retryable(error),
        Some(SchedulerOperationalFailureClass::Canceled) => AttemptWorkerFailure::Canceled(error),
        Some(SchedulerOperationalFailureClass::Terminal) | None => {
            AttemptWorkerFailure::Terminal(error)
        }
    }
}

fn map_resume_terminal_fingerprint_capture_failure<F, D>(
    error: SchedulerError,
) -> AttemptWorkerFailure<ResumeFailure<F, D>> {
    let class = error.operational_failure_class();
    let error = ResumeFailure::TerminalFingerprintCapture(error);
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
) -> AttemptWorkerFailure<ResumeFailure<F, D>> {
    match failure {
        AttemptWorkerFailure::Retryable(error) => {
            AttemptWorkerFailure::Retryable(ResumeFailure::CheckpointHandoff(error))
        }
        AttemptWorkerFailure::Canceled(error) => {
            AttemptWorkerFailure::Canceled(ResumeFailure::CheckpointHandoff(error))
        }
        AttemptWorkerFailure::Terminal(error) => {
            AttemptWorkerFailure::Terminal(ResumeFailure::CheckpointHandoff(error))
        }
    }
}
