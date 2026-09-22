//! Crash-safe replay-oracle promotion of paused attempt checkpoints.
//!
//! A freshly captured paused root deliberately carries `NotRun` replay-oracle
//! evidence and is not eligible for production resume. This module keeps QEMU
//! comparison and immutable-store work outside the local supervisor actor,
//! then uses linear phase tokens to establish the promoted root as a durable GC
//! root before its first write.

use std::collections::BTreeMap;
use std::path::Path;

use crucible::{Configuration, ScenarioDefForm, World};
use crucible_api::{LifecycleApiError, ProductionVmReplayExactNodeRestoreAdmission};
use crucible_campaign::{
    AttemptResourceLimits, AttemptStart, AttemptStartMode, CampaignExecutorStore,
    CampaignRepositoryError, ExactCheckpointId, ExecutionId,
    attempt_execution_basis_digest_for_start_mode,
};
use crucible_cas::content_store::ContentId;
use crucible_qemu::{QemuReplayValidationExecutor, QemuVmRealizationError};
use thiserror::Error;

use crate::exact_checkpoint_restore::QemuGuardedReplayOracleSession;
use crate::exact_checkpoint_restore::validate_materialized_start_configuration;
use crate::executor_supervisor::SelectedExactCheckpointRoot;
use crate::{
    AssignmentLedger, AttemptAdmissionValidator, AttemptExecutionKey,
    CheckpointPromotionCompletionOutcome, CheckpointPromotionRecovery,
    CheckpointPromotionRestartWork, CheckpointPromotionStageOutcome, CrucibleArtifactError,
    CrucibleAttemptExecution, CrucibleResolvedAttemptStart, ExactCheckpointStore,
    ExactCheckpointStoreError, ExecutionCancellation, LocalExecutorError, LocalExecutorSupervisor,
    PausedCheckpointPromotionRecovery, PreparedProductionAttemptReplayOraclePromotion,
    ProductionAttemptCheckpointRestoreError, ProductionBakedGenesisReplayStore,
    QemuAttemptOperationalBoundary, QemuAttemptProcessResourceGuard, QemuAttemptResourceGuard,
    acquire_production_exact_checkpoint_replay_oracle_promotion, decode_crucible_attempt_execution,
    install_attempt_production_exact_checkpoint,
    prepare_attempt_production_replay_oracle_promotion, resolve_attempt_execution_input,
};

/// Replay-validated replacement bound to one paused attempt execution.
#[derive(Debug)]
pub(crate) struct PreparedPausedCheckpointPromotion {
    key: AttemptExecutionKey,
    execution: ExecutionId,
    promotion: Box<PreparedProductionAttemptReplayOraclePromotion>,
}

/// Complete semantic and operational basis for one production-root comparison.
pub(crate) struct ProductionPausedCheckpointPromotionTarget<'a> {
    key: AttemptExecutionKey,
    execution: ExecutionId,
    raw: ExactCheckpointId,
    source: &'a ScenarioDefForm,
    initial: &'a Configuration,
    post_selection: Option<&'a Configuration>,
    run_state_root: &'a Path,
    cancellation: &'a ExecutionCancellation,
    resources: AttemptResourceLimits,
    start_mode: AttemptStartMode,
    attempt: &'a CrucibleAttemptExecution,
    selected_checkpoint: &'a mut Option<SelectedExactCheckpointRoot>,
}

/// Owned semantic input for restarting one raw paused-root comparison.
pub(crate) struct ResolvedProductionPausedCheckpointPromotionRecovery {
    key: AttemptExecutionKey,
    execution_id: ExecutionId,
    raw: ExactCheckpointId,
    promotion_basis: crate::CheckpointPromotionExecutionBasis,
    attempt: CrucibleAttemptExecution,
    cancellation: ExecutionCancellation,
}

impl ResolvedProductionPausedCheckpointPromotionRecovery {
    #[cfg(test)]
    pub(crate) fn matches_recovery(&self, recovery: &PausedCheckpointPromotionRecovery) -> bool {
        self.key == recovery.key()
            && self.execution_id == recovery.execution()
            && self.raw == recovery.source()
            && self.promotion_basis == recovery.promotion_basis()
    }

    /// Borrows the complete target for one guarded production comparison.
    #[must_use]
    pub(crate) fn target<'a>(
        &'a self,
        run_state_root: &'a Path,
        selected_checkpoint: &'a mut Option<SelectedExactCheckpointRoot>,
    ) -> ProductionPausedCheckpointPromotionTarget<'a> {
        let (initial, post_selection) = match self.attempt.start() {
            CrucibleResolvedAttemptStart::Discover { configuration } => (configuration, None),
            CrucibleResolvedAttemptStart::Branch {
                parent, selected, ..
            } => (parent, Some(selected)),
            CrucibleResolvedAttemptStart::AfterAttempt { .. } => {
                (self.attempt.start().configuration(), None)
            }
        };
        ProductionPausedCheckpointPromotionTarget {
            key: self.key,
            execution: self.execution_id,
            raw: self.raw,
            source: self.attempt.scenario(),
            initial,
            post_selection,
            run_state_root,
            cancellation: &self.cancellation,
            resources: self.promotion_basis.resources(),
            start_mode: self.promotion_basis.start_mode(),
            attempt: &self.attempt,
            selected_checkpoint,
        }
    }
}

/// Factory for node-specific guarded production replay-oracle sessions.
///
/// The factory installs one aggregate attempt guard for the complete root
/// comparison, then constructs each node's executor and realization store under
/// that retained guard. The caller verifies every executor node, runs both
/// realization paths, and structurally finishes the aggregate guard once.
pub(crate) trait ProductionPausedCheckpointReplayFactory {
    /// Attempt resource owner retained until comparison cleanup.
    type Guard: QemuAttemptProcessResourceGuard;

    /// Installs the single aggregate guard for one complete root comparison.
    ///
    /// # Errors
    ///
    /// Returns a failure that retains the selected root when no resource owner
    /// escaped and consumes it when cleanup required quarantine.
    fn begin_replay(
        &mut self,
        selected_checkpoint: SelectedExactCheckpointRoot,
        cancellation: &ExecutionCancellation,
        resources: AttemptResourceLimits,
    ) -> Result<Self::Guard, crate::crucible_qemu_session::QemuAttemptResourceGuardBeginFailure>;

    /// Prepares one node-specific replay executor under the aggregate guard.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when the baked semantic source or
    /// either replay leg cannot be admitted under the retained guard.
    fn begin_target(
        &mut self,
        world: &World,
        configuration: &Configuration,
        target: ProductionVmReplayExactNodeRestoreAdmission,
        guard: &mut Self::Guard,
    ) -> Result<ProductionPausedCheckpointReplaySession, QemuVmRealizationError>;

    /// Reexecutes one savepoint attempt and returns its reached modeled boundary.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when the attempt cannot be replayed
    /// under the supplied resource and cancellation authority or its exact
    /// reached boundary cannot be collected.
    fn replay_savepoint_capture(
        &mut self,
        attempt: &CrucibleAttemptExecution,
        run_state_root: &Path,
        cancellation: &ExecutionCancellation,
        resources: AttemptResourceLimits,
    ) -> Result<crate::QemuSavepointReplayProof, QemuVmRealizationError>;
}

/// Newly admitted node-specific replay session before either QEMU path starts.
///
/// The value keeps the realization store and fixed-node executor linear while
/// the caller retains the one aggregate attempt guard.
pub(crate) struct ProductionPausedCheckpointReplaySession {
    realization_store: ProductionBakedGenesisReplayStore,
    executor: QemuReplayValidationExecutor,
}

impl ProductionPausedCheckpointReplaySession {
    /// Binds one unopened fixed-node executor to its realization store.
    #[must_use]
    pub(crate) const fn new(
        realization_store: ProductionBakedGenesisReplayStore,
        executor: QemuReplayValidationExecutor,
    ) -> Self {
        Self {
            realization_store,
            executor,
        }
    }

    /// Consumes the admission into its linear realization capabilities.
    #[must_use]
    pub(crate) fn into_parts(
        self,
    ) -> (
        ProductionBakedGenesisReplayStore,
        QemuReplayValidationExecutor,
    ) {
        (self.realization_store, self.executor)
    }
}

impl PreparedPausedCheckpointPromotion {
    /// Binds one complete multi-node production replacement to its owner.
    ///
    /// The production token already proves that the installed raw root and
    /// every source-bound live-node replay result derive this exact no-write
    /// campaign replacement.
    #[must_use]
    pub(crate) fn new(
        key: AttemptExecutionKey,
        execution: ExecutionId,
        promotion: PreparedProductionAttemptReplayOraclePromotion,
    ) -> Self {
        Self {
            key,
            execution,
            promotion: Box::new(promotion),
        }
    }

    /// Returns the raw exact root compared by the replay oracle.
    #[must_use]
    pub(crate) const fn source(&self) -> ExactCheckpointId {
        self.promotion.source()
    }

    /// Returns the expected replacement root containing matching evidence.
    #[must_use]
    pub(crate) const fn promoted(&self) -> ExactCheckpointId {
        self.promotion.promoted()
    }

    pub(crate) fn retire_native_source(&self) -> Result<(), ExactCheckpointStoreError> {
        self.promotion.replacement().retire_native_source()
    }
}

/// Linear proof that both source and replacement are durable retention roots.
#[derive(Debug)]
pub(crate) struct StagedPausedCheckpointPromotion {
    prepared: PreparedPausedCheckpointPromotion,
}

impl StagedPausedCheckpointPromotion {
    pub(crate) fn retire_native_source(&self) -> Result<(), ExactCheckpointStoreError> {
        self.prepared.retire_native_source()
    }
}

/// Complete durable replacement awaiting the final paused-state CAS.
#[derive(Debug)]
pub(crate) struct PublishedPausedCheckpointPromotion {
    key: AttemptExecutionKey,
    execution: ExecutionId,
    source: ExactCheckpointId,
    promoted: ExactCheckpointId,
    evidence: ContentId,
}

impl PublishedPausedCheckpointPromotion {
    /// Returns the raw durable root replaced by this publication.
    #[must_use]
    pub(crate) const fn source(&self) -> ExactCheckpointId {
        self.source
    }

    /// Returns the replay-validated replacement root.
    #[must_use]
    pub(crate) const fn promoted(&self) -> ExactCheckpointId {
        self.promoted
    }
}

/// Result of the short supervisor staging phase.
#[derive(Debug)]
pub(crate) enum PausedCheckpointPromotionStageOutcome {
    /// Immutable publication may proceed outside the supervisor actor.
    Publish(Box<StagedPausedCheckpointPromotion>),
    /// Another idempotent or stale state won without further writes.
    Finished {
        /// Prepared token retained so redundant native state can be retired.
        prepared: Box<PreparedPausedCheckpointPromotion>,
        /// Durable staging disposition.
        outcome: CheckpointPromotionStageOutcome,
    },
}

/// QEMU comparison or no-write promotion preparation failure.
#[derive(Debug, Error)]
pub(crate) enum PausedCheckpointPromotionPreparationError {
    /// Production-root installation or no-write replacement preparation failed.
    #[error(transparent)]
    ProductionRestore(#[from] ProductionAttemptCheckpointRestoreError),
    /// The portable production closure could not stream one raw live target.
    #[error(transparent)]
    ProductionClosure(#[from] LifecycleApiError),
    /// Fat/thin realization, comparison, or mandatory cleanup failed.
    #[error(transparent)]
    Realization(#[from] QemuVmRealizationError),
    /// Independent execution did not reproduce the captured stop boundary.
    #[error("savepoint capture does not match an independent attempt-stop replay")]
    SavepointReplayMismatch,
}

/// Failure to resolve one durable raw pause into guarded comparison input.
#[derive(Debug, Error)]
pub(crate) enum PausedCheckpointPromotionRecoveryResolutionError {
    /// Immutable campaign input was unavailable or failed authentication.
    #[error(transparent)]
    Repository(#[from] CampaignRepositoryError),
    /// Nested Crucible scenario or configuration bytes failed strict decoding.
    #[error(transparent)]
    Artifact(#[from] CrucibleArtifactError),
    /// The durable resource/retention basis does not match the attempt key.
    #[error("paused checkpoint promotion execution basis is inconsistent")]
    ExecutionBasisMismatch,
    /// A capture basis does not name this discovery attempt's exact start artifact.
    #[error("paused checkpoint promotion capture start is inconsistent")]
    CaptureStartMismatch,
}

/// No-write restart result ready for a short supervisor or publication phase.
#[derive(Debug)]
pub(crate) enum PreparedPausedCheckpointPromotionRestart {
    /// A raw pause passed semantic resolution and guarded replay comparison.
    Stage(Box<PreparedPausedCheckpointPromotion>),
    /// A staged replacement was already complete and reauthenticated.
    Reconcile(Box<PublishedPausedCheckpointPromotion>),
}

/// Failure to prepare one durable promotion phase after restart.
#[derive(Debug, Error)]
pub(crate) enum PausedCheckpointPromotionRestartPreparationError {
    /// Raw-pause semantic input or its execution basis was invalid.
    #[error(transparent)]
    Resolution(#[from] PausedCheckpointPromotionRecoveryResolutionError),
    /// A staged pair's immutable attempt input was unavailable or invalid.
    #[error(transparent)]
    Repository(#[from] CampaignRepositoryError),
    /// A staged pair's nested Crucible input failed strict decoding.
    #[error(transparent)]
    Artifact(#[from] CrucibleArtifactError),
    /// Guarded raw-root comparison or no-write replacement preparation failed.
    #[error(transparent)]
    Preparation(#[from] Box<PausedCheckpointPromotionPreparationError>),
    /// A staged production source/replacement pair failed full authentication.
    #[error(transparent)]
    Staged(#[from] ProductionAttemptCheckpointRestoreError),
}

/// Resolves a durable raw pause into owned production-comparison input.
///
/// Repository and artifact authentication happen without supervisor ownership
/// and without writes. The caller supplies the fresh cancellation incarnation
/// that every guarded replay session must share during this recovery attempt.
///
/// # Errors
///
/// Returns [`PausedCheckpointPromotionRecoveryResolutionError`] when the
/// durable execution basis is inconsistent or any immutable semantic input
/// cannot be authenticated and strictly decoded.
pub(crate) fn resolve_production_paused_checkpoint_promotion_recovery(
    store: &CampaignExecutorStore,
    recovery: &PausedCheckpointPromotionRecovery,
    cancellation: ExecutionCancellation,
) -> Result<
    ResolvedProductionPausedCheckpointPromotionRecovery,
    PausedCheckpointPromotionRecoveryResolutionError,
> {
    let basis = recovery.promotion_basis();
    validate_promotion_execution_basis(recovery.key(), recovery.execution_basis(), basis)?;
    store.validate_execution_scope(
        recovery.key().lineage(),
        recovery.key().attempt(),
        basis.start_mode(),
    )?;
    let input = crate::resolve_attempt_execution_input_with_resources(
        store,
        recovery.key(),
        basis.resources(),
    )?;
    validate_capture_attempt_start(&input, basis.start_mode())?;
    let execution =
        crate::decode_crucible_attempt_execution_with_resources(store, &input, basis.resources())?;
    Ok(ResolvedProductionPausedCheckpointPromotionRecovery {
        key: recovery.key(),
        execution_id: recovery.execution(),
        raw: recovery.source(),
        promotion_basis: recovery.promotion_basis(),
        attempt: execution,
        cancellation,
    })
}

fn validate_promotion_execution_basis(
    key: AttemptExecutionKey,
    execution_basis: crucible_campaign::CampaignHash,
    basis: crate::CheckpointPromotionExecutionBasis,
) -> Result<(), PausedCheckpointPromotionRecoveryResolutionError> {
    if attempt_execution_basis_digest_for_start_mode(
        key.lineage(),
        key.attempt(),
        basis.resources(),
        basis.retention(),
        basis.start_mode(),
        basis.retention_policy(),
    ) != execution_basis
    {
        return Err(PausedCheckpointPromotionRecoveryResolutionError::ExecutionBasisMismatch);
    }

    Ok(())
}

fn validate_capture_attempt_start(
    input: &crate::AttemptExecutionInput,
    start_mode: AttemptStartMode,
) -> Result<(), PausedCheckpointPromotionRecoveryResolutionError> {
    let configuration = match start_mode {
        AttemptStartMode::Execute => return Ok(()),
        AttemptStartMode::CaptureMaterializedStart { configuration } => {
            let AttemptStart::Discover {
                configuration: resolved,
            } = input.attempt().start()
            else {
                return Err(PausedCheckpointPromotionRecoveryResolutionError::CaptureStartMismatch);
            };
            (resolved == configuration).then_some(configuration)
        }
        AttemptStartMode::SavepointCapture { configuration, .. } => {
            let resolved = match input.attempt().start() {
                AttemptStart::Discover { configuration } => configuration,
                AttemptStart::Branch { parent, .. } => parent,
                AttemptStart::AfterAttempt { reached, .. } => reached,
            };
            (resolved == configuration).then_some(configuration)
        }
        AttemptStartMode::SelectedSavepoint { .. } => {
            let AttemptStart::AfterAttempt { reached, .. } = input.attempt().start() else {
                return Err(PausedCheckpointPromotionRecoveryResolutionError::CaptureStartMismatch);
            };
            Some(reached)
        }
    };
    if configuration.is_none() {
        return Err(PausedCheckpointPromotionRecoveryResolutionError::CaptureStartMismatch);
    }

    Ok(())
}

/// Prepares one durable paused-root restart phase without supervisor ownership.
///
/// Raw pauses resolve their exact repository input and run the complete guarded
/// multi-node comparison. Staged pairs fully authenticate the published
/// source/replacement relationship and repeat the independent savepoint-boundary
/// replay when that start mode requires it. No path writes immutable objects or
/// operational ledger state.
///
/// # Errors
///
/// Returns [`PausedCheckpointPromotionRestartPreparationError`] when semantic
/// input, guarded comparison, or the staged production pair fails closed.
pub(crate) fn prepare_production_paused_checkpoint_promotion_restart<F>(
    store: &CampaignExecutorStore,
    checkpoints: &ExactCheckpointStore,
    work: &mut CheckpointPromotionRestartWork,
    run_state_root: &Path,
    cancellation: ExecutionCancellation,
    factory: &mut F,
) -> Result<
    PreparedPausedCheckpointPromotionRestart,
    PausedCheckpointPromotionRestartPreparationError,
>
where
    F: ProductionPausedCheckpointReplayFactory,
{
    match work {
        CheckpointPromotionRestartWork::Paused(recovery) => {
            let resolved = resolve_production_paused_checkpoint_promotion_recovery(
                store,
                recovery,
                cancellation,
            )?;
            let target = resolved.target(run_state_root, recovery.selected_checkpoint());
            let prepared = validate_and_prepare_production_paused_checkpoint_promotion(
                checkpoints,
                target,
                factory,
            )
            .map_err(Box::new)?;
            Ok(PreparedPausedCheckpointPromotionRestart::Stage(Box::new(
                prepared,
            )))
        }
        CheckpointPromotionRestartWork::Staged(recovery) => {
            let recovery = *recovery;
            let promotion_basis = recovery.promotion_basis();
            if let Some(basis) = promotion_basis {
                validate_promotion_execution_basis(
                    recovery.key(),
                    recovery.execution_basis(),
                    basis,
                )?;
                store.validate_execution_scope(
                    recovery.key().lineage(),
                    recovery.key().attempt(),
                    basis.start_mode(),
                )?;
            }
            let input = match promotion_basis {
                Some(basis) => crate::resolve_attempt_execution_input_with_resources(
                    store,
                    recovery.key(),
                    basis.resources(),
                )?,
                None => resolve_attempt_execution_input(store, recovery.key())?,
            };
            if let Some(basis) = promotion_basis {
                validate_capture_attempt_start(&input, basis.start_mode())?;
            }
            let execution = match promotion_basis {
                Some(basis) => crate::decode_crucible_attempt_execution_with_resources(
                    store,
                    &input,
                    basis.resources(),
                )?,
                None => decode_crucible_attempt_execution(store, &input)?,
            };
            if matches!(
                promotion_basis.map(|basis| basis.start_mode()),
                Some(AttemptStartMode::SavepointCapture { .. })
            ) {
                let (initial, post_selection) = execution_start_parts(&execution);
                let installed = install_attempt_production_exact_checkpoint(
                    checkpoints,
                    recovery.source(),
                    execution.scenario(),
                    initial,
                    post_selection,
                    run_state_root,
                    &cancellation,
                )
                .map_err(PausedCheckpointPromotionPreparationError::from)
                .map_err(Box::new)?;
                let replay = factory
                    .replay_savepoint_capture(
                        &execution,
                        run_state_root,
                        &cancellation,
                        promotion_basis
                            .ok_or(PausedCheckpointPromotionRecoveryResolutionError::ExecutionBasisMismatch)?
                            .resources(),
                    )
                    .map_err(PausedCheckpointPromotionPreparationError::from)
                    .map_err(Box::new)?;
                validate_savepoint_replay_boundary(
                    replay,
                    installed.configuration(),
                    installed.scheduler(),
                )
                .map_err(Box::new)?;
            }
            let materialized_start = match promotion_basis.map(|basis| basis.start_mode()) {
                Some(AttemptStartMode::CaptureMaterializedStart { .. }) => {
                    let CrucibleResolvedAttemptStart::Discover { configuration } =
                        execution.start()
                    else {
                        return Err(
                            PausedCheckpointPromotionRecoveryResolutionError::CaptureStartMismatch
                                .into(),
                        );
                    };
                    Some(configuration)
                }
                Some(AttemptStartMode::SavepointCapture { .. } | AttemptStartMode::Execute)
                | Some(AttemptStartMode::SelectedSavepoint { .. })
                | None => None,
            };
            let published = recover_published_production_paused_checkpoint_promotion(
                checkpoints,
                execution.scenario(),
                &cancellation,
                recovery,
                materialized_start,
            )?;
            Ok(PreparedPausedCheckpointPromotionRestart::Reconcile(
                Box::new(published),
            ))
        }
    }
}

fn execution_start_parts(
    execution: &CrucibleAttemptExecution,
) -> (&Configuration, Option<&Configuration>) {
    match execution.start() {
        CrucibleResolvedAttemptStart::Discover { configuration } => (configuration, None),
        CrucibleResolvedAttemptStart::Branch {
            parent, selected, ..
        } => (parent, Some(selected)),
        CrucibleResolvedAttemptStart::AfterAttempt { .. } => {
            (execution.start().configuration(), None)
        }
    }
}

/// Staging failure retaining the sole prepared promotion token.
#[derive(Debug, Error)]
#[error("paused exact-checkpoint promotion staging failed")]
pub(crate) struct PausedCheckpointPromotionStagingError<E> {
    /// Prepared promotion retained for exact actor retry or abandonment.
    pub prepared: Box<PreparedPausedCheckpointPromotion>,
    /// Supervisor or operational-ledger failure.
    pub source: E,
}

/// Immutable publication failure retaining the staged promotion token.
#[derive(Debug, Error)]
#[error("paused exact-checkpoint promotion publication failed")]
pub(crate) struct PausedCheckpointPromotionPublicationError {
    /// Staged promotion retained for exact publication retry or abandonment.
    pub staged: Box<StagedPausedCheckpointPromotion>,
    /// Immutable checkpoint-store failure.
    pub source: ExactCheckpointStoreError,
}

/// Final reconciliation failure retaining the complete published root token.
#[derive(Debug, Error)]
#[error("paused exact-checkpoint promotion reconciliation failed")]
pub(crate) struct PausedCheckpointPromotionReconcileError<E> {
    /// Published promotion retained for exact actor retry.
    pub published: Box<PublishedPausedCheckpointPromotion>,
    /// Supervisor or operational-ledger failure.
    pub source: E,
}

/// Validates every live node in one raw production root and prepares promotion.
///
/// The raw root first passes complete attempt-prefix installation. Its live
/// snapshot bodies are then streamed one at a time through a node-specific
/// guarded replay oracle. Each target's process authority is reaped or
/// quarantined before the next target is opened, and only compact source-bound
/// checks survive to prepare the replacement. This function changes neither
/// immutable campaign storage nor operational ledger state.
///
/// # Errors
///
/// Returns [`PausedCheckpointPromotionPreparationError`] when installation or
/// target streaming fails, cancellation wins, any node's fat/thin realization
/// differs or fails, mandatory cleanup cannot attest reap, or the no-write
/// replacement does not derive exactly from the raw root.
pub(crate) fn validate_and_prepare_production_paused_checkpoint_promotion<F>(
    checkpoints: &ExactCheckpointStore,
    target: ProductionPausedCheckpointPromotionTarget<'_>,
    factory: &mut F,
) -> Result<PreparedPausedCheckpointPromotion, PausedCheckpointPromotionPreparationError>
where
    F: ProductionPausedCheckpointReplayFactory,
{
    let mut installed = install_attempt_production_exact_checkpoint(
        checkpoints,
        target.raw,
        target.source,
        target.initial,
        target.post_selection,
        target.run_state_root,
        target.cancellation,
    )?;
    match target.start_mode {
        AttemptStartMode::CaptureMaterializedStart { .. } => {
            validate_materialized_start_configuration(
                target.raw,
                target.initial,
                installed.configuration().id(),
            )?;
        }
        AttemptStartMode::SavepointCapture { .. } => {
            let replay = factory.replay_savepoint_capture(
                target.attempt,
                target.run_state_root,
                target.cancellation,
                target.resources,
            )?;
            validate_savepoint_replay_boundary(
                replay,
                installed.configuration(),
                installed.scheduler(),
            )?;
        }
        AttemptStartMode::Execute => {}
        AttemptStartMode::SelectedSavepoint { .. } => {}
    }
    let mut targets = installed.take_node_restore_admissions().ok_or_else(|| {
        PausedCheckpointPromotionPreparationError::ProductionClosure(
            LifecycleApiError::LoopFactory {
                message: String::from(
                    "production replay-oracle checkpoint has no authenticated target admissions",
                ),
            },
        )
    })?;

    let selected_checkpoint = target.selected_checkpoint.take().ok_or_else(|| {
        QemuVmRealizationError::InvalidCheckpoint {
            role: "production replay exact root",
            message: String::from("durable paused-root selection authority was already consumed"),
        }
    })?;
    let mut guard =
        match factory.begin_replay(selected_checkpoint, target.cancellation, target.resources) {
            Ok(guard) => guard,
            Err(failure) => {
                let (error, selected_checkpoint) = failure.into_parts();
                *target.selected_checkpoint = selected_checkpoint;
                return Err(PausedCheckpointPromotionPreparationError::Realization(
                    error,
                ));
            }
        };
    if guard.resource_limits() != target.resources
        || !guard.cancellation().same_incarnation(target.cancellation)
    {
        let error = QemuVmRealizationError::Executor {
            operation: "admit production replay-oracle aggregate",
            message: String::from("resource guard does not match the requested aggregate basis"),
        };
        return Err(PausedCheckpointPromotionPreparationError::Realization(
            finish_replay_guard(&mut guard).unwrap_or(error),
        ));
    }

    let mut matches = BTreeMap::new();
    loop {
        let next = match targets.take_next() {
            Ok(next) => next,
            Err(error) => {
                let error = map_production_target_error(error, target.cancellation);
                let cleanup = finish_replay_guard(&mut guard);
                return cleanup.map_or(Err(error), |cleanup| Err(cleanup.into()));
            }
        };
        let Some(next) = next else {
            break;
        };
        let node = next.node().clone();
        let snapshot = next.snapshot().clone();
        let session = factory.begin_target(
            target.source.world(),
            installed.configuration(),
            next,
            &mut guard,
        );
        let (mut realization_store, mut executor) = match session {
            Ok(session) => session.into_parts(),
            Err(error) => {
                return Err(PausedCheckpointPromotionPreparationError::Realization(
                    finish_replay_guard(&mut guard).unwrap_or(error),
                ));
            }
        };
        if executor.node() != &node {
            let error = QemuVmRealizationError::Executor {
                operation: "admit production replay-oracle target",
                message: String::from("node executor does not match the requested target"),
            };
            return Err(finish_replay_guard(&mut guard).unwrap_or(error).into());
        }
        let baked = match realization_store
            .baked_genesis(target.source.world(), &installed.configuration().def)
        {
            Ok(baked) => baked,
            Err(error) => {
                return Err(finish_replay_guard(&mut guard).unwrap_or(error).into());
            }
        };
        let mut session = QemuGuardedReplayOracleSession::new(&mut executor, &mut guard);
        let comparison = session.check_snapshot_replay_oracle(
            target.source.world(),
            installed.configuration(),
            &snapshot,
            &baked,
        );
        let cleanup = session.finish();
        let matched = match (comparison, cleanup) {
            (_, Err(cleanup)) => {
                return Err(PausedCheckpointPromotionPreparationError::Realization(
                    cleanup,
                ));
            }
            (Err(comparison), Ok(())) => {
                return Err(PausedCheckpointPromotionPreparationError::Realization(
                    finish_replay_guard(&mut guard).unwrap_or(comparison),
                ));
            }
            (Ok(check), Ok(())) => check,
        };
        if matches.insert(node, matched).is_some() {
            let error = PausedCheckpointPromotionPreparationError::ProductionClosure(
                LifecycleApiError::LoopFactory {
                    message: String::from(
                        "production replay-oracle target set contains a duplicate node",
                    ),
                },
            );
            return match finish_replay_guard(&mut guard) {
                Some(cleanup) => Err(PausedCheckpointPromotionPreparationError::Realization(
                    cleanup,
                )),
                None => Err(error),
            };
        }
    }

    guard.finish()?;

    let promotion = prepare_attempt_production_replay_oracle_promotion(
        checkpoints,
        target.raw,
        &installed,
        matches,
        target.cancellation,
    )?;
    Ok(PreparedPausedCheckpointPromotion::new(
        target.key,
        target.execution,
        promotion,
    ))
}

fn finish_replay_guard(
    guard: &mut impl QemuAttemptProcessResourceGuard,
) -> Option<QemuVmRealizationError> {
    guard.finish().err()
}

fn validate_savepoint_replay_boundary(
    replay: crate::QemuSavepointReplayProof,
    configuration: &Configuration,
    scheduler: &crucible::SingleSchedulerCheckpoint,
) -> Result<(), PausedCheckpointPromotionPreparationError> {
    if replay.matches_checkpoint(configuration, scheduler) {
        Ok(())
    } else {
        Err(PausedCheckpointPromotionPreparationError::SavepointReplayMismatch)
    }
}

fn map_production_target_error(
    error: LifecycleApiError,
    cancellation: &ExecutionCancellation,
) -> PausedCheckpointPromotionPreparationError {
    if cancellation.is_canceled() {
        PausedCheckpointPromotionPreparationError::ProductionRestore(
            ProductionAttemptCheckpointRestoreError::Canceled,
        )
    } else {
        PausedCheckpointPromotionPreparationError::ProductionClosure(error)
    }
}

/// Installs both promotion roots with one short supervisor CAS.
///
/// # Errors
///
/// Returns [`PausedCheckpointPromotionStagingError`] with the complete token
/// when the ledger cannot safely establish the retained root pair.
pub(crate) fn stage_prepared_paused_checkpoint_promotion<L, V>(
    supervisor: &mut LocalExecutorSupervisor<L, V>,
    prepared: PreparedPausedCheckpointPromotion,
) -> Result<
    PausedCheckpointPromotionStageOutcome,
    PausedCheckpointPromotionStagingError<LocalExecutorError<L::Error>>,
>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let stage = match supervisor.stage_checkpoint_promotion(
        prepared.key,
        prepared.execution,
        prepared.source(),
        prepared.promoted(),
    ) {
        Ok(stage) => stage,
        Err(source) => {
            return Err(PausedCheckpointPromotionStagingError {
                prepared: Box::new(prepared),
                source,
            });
        }
    };
    match stage {
        CheckpointPromotionStageOutcome::Staged
        | CheckpointPromotionStageOutcome::AlreadyStaged => {
            Ok(PausedCheckpointPromotionStageOutcome::Publish(Box::new(
                StagedPausedCheckpointPromotion { prepared },
            )))
        }
        CheckpointPromotionStageOutcome::AlreadyPromoted
        | CheckpointPromotionStageOutcome::NotCurrent => {
            Ok(PausedCheckpointPromotionStageOutcome::Finished {
                prepared: Box::new(prepared),
                outcome: stage,
            })
        }
    }
}

/// Publishes a staged replacement outside supervisor ownership.
///
/// # Errors
///
/// Returns [`PausedCheckpointPromotionPublicationError`] with the staged token
/// when any durable immutable placement fails.
pub(crate) fn publish_staged_paused_checkpoint_promotion(
    checkpoints: &ExactCheckpointStore,
    staged: StagedPausedCheckpointPromotion,
) -> Result<PublishedPausedCheckpointPromotion, PausedCheckpointPromotionPublicationError> {
    let Some(evidence) = staged
        .prepared
        .promotion
        .replacement()
        .promotion_evidence_id()
    else {
        return Err(PausedCheckpointPromotionPublicationError {
            staged: Box::new(staged),
            source: ExactCheckpointStoreError::InvalidRoot {
                reason: "replay promotion has no matching evidence identity",
            },
        });
    };
    let publication = checkpoints
        .publish_production_closure(staged.prepared.promotion.replacement())
        .and_then(|_| {
            staged
                .prepared
                .promotion
                .replacement()
                .retire_native_source()
        });
    if let Err(source) = publication {
        return Err(PausedCheckpointPromotionPublicationError {
            staged: Box::new(staged),
            source,
        });
    }
    Ok(PublishedPausedCheckpointPromotion {
        key: staged.prepared.key,
        execution: staged.prepared.execution,
        source: staged.prepared.source(),
        promoted: staged.prepared.promoted(),
        evidence,
    })
}

/// Reconstructs a published production token from one durable staged pair.
///
/// Both version-four roots pass complete portable scenario validation without
/// writes, and every live-node snapshot must form the exact raw-to-matching
/// promotion relationship before the final supervisor CAS is allowed.
///
/// # Errors
///
/// Returns [`ProductionAttemptCheckpointRestoreError`] when cancellation wins,
/// either root is unavailable or invalid, the scenario differs, or any modeled,
/// artifact, lifecycle, or replay-oracle field changed unexpectedly.
pub(crate) fn recover_published_production_paused_checkpoint_promotion(
    checkpoints: &ExactCheckpointStore,
    source: &ScenarioDefForm,
    cancellation: &ExecutionCancellation,
    recovery: CheckpointPromotionRecovery,
    materialized_start: Option<&Configuration>,
) -> Result<PublishedPausedCheckpointPromotion, ProductionAttemptCheckpointRestoreError> {
    let claim = acquire_production_exact_checkpoint_replay_oracle_promotion(
        checkpoints,
        recovery.source(),
        recovery.promoted(),
        source,
        cancellation,
    )?;
    let evidence = claim.evidence();
    drop(claim);
    if let Some(materialized_start) = materialized_start {
        let raw = checkpoints
            .load_production_closure_with_cancellation(recovery.source(), cancellation)
            .map_err(map_staged_checkpoint_store_error)?;
        validate_materialized_start_configuration(
            recovery.source(),
            materialized_start,
            raw.configuration(),
        )?;
    }
    Ok(PublishedPausedCheckpointPromotion {
        key: recovery.key(),
        execution: recovery.execution(),
        source: recovery.source(),
        promoted: recovery.promoted(),
        evidence,
    })
}

fn map_staged_checkpoint_store_error(
    error: ExactCheckpointStoreError,
) -> ProductionAttemptCheckpointRestoreError {
    match error {
        ExactCheckpointStoreError::Canceled => ProductionAttemptCheckpointRestoreError::Canceled,
        error => ProductionAttemptCheckpointRestoreError::Checkpoint(error),
    }
}

/// Commits one complete replacement as the paused resume root.
///
/// # Errors
///
/// Returns [`PausedCheckpointPromotionReconcileError`] with the published token
/// when the final ledger CAS cannot be reconciled safely.
pub(crate) fn reconcile_published_paused_checkpoint_promotion<L, V>(
    checkpoints: &ExactCheckpointStore,
    supervisor: &mut LocalExecutorSupervisor<L, V>,
    published: PublishedPausedCheckpointPromotion,
) -> Result<
    CheckpointPromotionCompletionOutcome,
    PausedCheckpointPromotionReconcileError<LocalExecutorError<L::Error>>,
>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    let claim =
        match checkpoints.acquire_live_replay_promotion(published.promoted, published.evidence) {
            Ok(Some(claim)) => claim,
            Ok(None) | Err(_) => {
                return Err(PausedCheckpointPromotionReconcileError {
                    published: Box::new(published),
                    source: LocalExecutorError::LedgerInvariant {
                        reason: "replay promotion live authority is unavailable",
                    },
                });
            }
        };
    let outcome = supervisor.complete_checkpoint_promotion(
        published.key,
        published.execution,
        published.source,
        published.promoted,
    );
    match outcome {
        Ok(
            outcome @ (CheckpointPromotionCompletionOutcome::Promoted
            | CheckpointPromotionCompletionOutcome::AlreadyPromoted),
        ) => {
            claim
                .commit()
                .map(|()| outcome)
                .map_err(|_| PausedCheckpointPromotionReconcileError {
                    published: Box::new(published),
                    source: LocalExecutorError::LedgerInvariant {
                        reason: "replay promotion live authority could not be consumed",
                    },
                })
        }
        Ok(outcome) => Ok(outcome),
        Err(source) => Err(PausedCheckpointPromotionReconcileError {
            published: Box::new(published),
            source,
        }),
    }
}

/// Reverts an incomplete staged replacement to its retained raw source.
///
/// This operation is intended for stable publication failures. Retryable store
/// failures should retain and retry the staged token instead.
///
/// # Errors
///
/// Returns a supervisor error if the exact source/replacement pair cannot be
/// safely reconciled.
pub(crate) fn revert_staged_paused_checkpoint_promotion<L, V>(
    supervisor: &mut LocalExecutorSupervisor<L, V>,
    staged: &StagedPausedCheckpointPromotion,
) -> Result<CheckpointPromotionCompletionOutcome, LocalExecutorError<L::Error>>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    supervisor.revert_checkpoint_promotion(
        staged.prepared.key,
        staged.prepared.execution,
        staged.prepared.source(),
        staged.prepared.promoted(),
    )
}

/// Reverts an incomplete promotion discovered after restart.
///
/// Callers should use this only after classifying the promoted closure failure
/// as stable or authoritatively absent. Temporary store unavailability must
/// retain the staged pair for retry instead.
///
/// # Errors
///
/// Returns a supervisor error if the exact recovered pair cannot be safely
/// reconciled.
pub(crate) fn revert_recovered_paused_checkpoint_promotion<L, V>(
    supervisor: &mut LocalExecutorSupervisor<L, V>,
    recovery: CheckpointPromotionRecovery,
) -> Result<CheckpointPromotionCompletionOutcome, LocalExecutorError<L::Error>>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator,
{
    supervisor.revert_checkpoint_promotion(
        recovery.key(),
        recovery.execution(),
        recovery.source(),
        recovery.promoted(),
    )
}

#[cfg(test)]
mod tests;

#[cfg(test)]
pub(crate) use tests::promote_test_checkpoint_for_resume;
