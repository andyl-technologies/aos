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
use crucible_api::LifecycleApiError;
use crucible_campaign::{
    AttemptResourceLimits, CampaignExecutorStore, CampaignRepositoryError, ExactCheckpointId,
    ExecutionId, attempt_execution_basis_digest,
};
use crucible_qemu::{
    QemuFailedLaunchChildSource, QemuGuardedNodeRealizationLauncher,
    QemuGuardedThinNodeRealizationLauncher, QemuNodeRealizationExecutor, QemuVmRealizationError,
    QemuVmRealizationStore, check_qemu_snapshot_replay_oracle_bound,
};
use thiserror::Error;

use crate::{
    AssignmentLedger, AttemptAdmissionValidator, AttemptExecutionKey,
    CheckpointPromotionCompletionOutcome, CheckpointPromotionRecovery,
    CheckpointPromotionRestartWork, CheckpointPromotionStageOutcome, CrucibleArtifactError,
    CrucibleAttemptExecution, CrucibleResolvedAttemptStart, ExactCheckpointStore,
    ExactCheckpointStoreError, ExecutionCancellation, LocalExecutorError, LocalExecutorSupervisor,
    MaterializedAttemptCheckpoint, PausedCheckpointPromotionRecovery,
    PrepareReplayOraclePromotionError, PreparedProductionAttemptReplayOraclePromotion,
    PreparedReplayOraclePromotion, ProductionAttemptCheckpointRestoreError,
    QemuAttemptOperationalBoundary, QemuAttemptProcessResourceGuard, QemuAttemptResourceGuard,
    QemuGuardedReplayOracleSession,
    authenticate_production_exact_checkpoint_replay_oracle_promotion,
    decode_crucible_attempt_execution, install_attempt_production_exact_checkpoint,
    prepare_attempt_production_replay_oracle_promotion, resolve_attempt_execution_input,
};

/// Replay-validated replacement bound to one paused attempt execution.
#[derive(Debug)]
pub struct PreparedPausedCheckpointPromotion {
    key: AttemptExecutionKey,
    execution: ExecutionId,
    promotion: PreparedPausedCheckpointReplacement,
}

#[derive(Debug)]
enum PreparedPausedCheckpointReplacement {
    SingleNode(Box<PreparedReplayOraclePromotion>),
    Production(Box<PreparedProductionAttemptReplayOraclePromotion>),
}

/// Exact semantic and operational target for one paused-root validation.
#[derive(Clone, Copy)]
pub struct PausedCheckpointPromotionTarget<'a> {
    key: AttemptExecutionKey,
    execution: ExecutionId,
    world: &'a World,
    configuration: &'a Configuration,
    materialized: &'a MaterializedAttemptCheckpoint,
}

/// Complete semantic and operational basis for one production-root comparison.
#[derive(Clone, Copy)]
pub struct ProductionPausedCheckpointPromotionTarget<'a> {
    key: AttemptExecutionKey,
    execution: ExecutionId,
    raw: ExactCheckpointId,
    source: &'a ScenarioDefForm,
    initial: &'a Configuration,
    post_selection: Option<&'a Configuration>,
    run_state_root: &'a Path,
    cancellation: &'a ExecutionCancellation,
    resources: AttemptResourceLimits,
}

/// Owned semantic input for restarting one raw paused-root comparison.
pub struct ResolvedProductionPausedCheckpointPromotionRecovery {
    recovery: PausedCheckpointPromotionRecovery,
    execution: CrucibleAttemptExecution,
    cancellation: ExecutionCancellation,
}

impl ResolvedProductionPausedCheckpointPromotionRecovery {
    /// Returns the durable raw-pause identity being recovered.
    #[must_use]
    pub const fn recovery(&self) -> PausedCheckpointPromotionRecovery {
        self.recovery
    }

    /// Borrows the complete target for one guarded production comparison.
    #[must_use]
    pub fn target<'a>(
        &'a self,
        run_state_root: &'a Path,
    ) -> ProductionPausedCheckpointPromotionTarget<'a> {
        let (initial, post_selection) = match self.execution.start() {
            CrucibleResolvedAttemptStart::Discover { configuration } => (configuration, None),
            CrucibleResolvedAttemptStart::Branch {
                parent, selected, ..
            } => (parent, Some(selected)),
        };
        ProductionPausedCheckpointPromotionTarget::new(
            self.recovery.key(),
            self.recovery.execution(),
            self.recovery.source(),
            self.execution.scenario(),
            initial,
            post_selection,
            run_state_root,
            &self.cancellation,
            self.recovery.promotion_basis().resources(),
        )
    }
}

impl<'a> ProductionPausedCheckpointPromotionTarget<'a> {
    /// Binds one raw production root to its exact attempt and install authority.
    #[must_use]
    // crucible-lint: allow rust-allow -- every independent promotion basis is explicit at construction.
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        key: AttemptExecutionKey,
        execution: ExecutionId,
        raw: ExactCheckpointId,
        source: &'a ScenarioDefForm,
        initial: &'a Configuration,
        post_selection: Option<&'a Configuration>,
        run_state_root: &'a Path,
        cancellation: &'a ExecutionCancellation,
        resources: AttemptResourceLimits,
    ) -> Self {
        Self {
            key,
            execution,
            raw,
            source,
            initial,
            post_selection,
            run_state_root,
            cancellation,
            resources,
        }
    }

    /// Returns the raw exact root awaiting promotion.
    #[must_use]
    pub const fn raw(self) -> ExactCheckpointId {
        self.raw
    }

    /// Returns the authenticated Crucible scenario form.
    #[must_use]
    pub const fn source(self) -> &'a ScenarioDefForm {
        self.source
    }

    /// Returns the exact hard ceilings admitted for comparison recovery.
    #[must_use]
    pub const fn resources(self) -> AttemptResourceLimits {
        self.resources
    }
}

/// Factory for node-specific guarded production replay-oracle sessions.
///
/// Each call must construct an executor for exactly `node`, a realization store
/// scoped to the same world, and one newly installed attempt guard. The caller
/// verifies the executor node plus the guard's exact resource/cancellation
/// basis, runs both realization paths, and structurally finishes the guarded
/// session before asking for another node.
pub trait ProductionPausedCheckpointReplayFactory {
    /// Node-specific immutable realization lookup capability.
    type Store: QemuVmRealizationStore;
    /// Node-specific guarded fat/thin launcher.
    type Launcher: QemuGuardedNodeRealizationLauncher
        + QemuGuardedThinNodeRealizationLauncher
        + QemuFailedLaunchChildSource;
    /// Attempt resource owner retained until comparison cleanup.
    type Guard: QemuAttemptProcessResourceGuard;

    /// Installs one node-specific guarded comparison session.
    ///
    /// # Errors
    ///
    /// Returns [`QemuVmRealizationError`] when node-specific store, launcher,
    /// process containment, or resource admission cannot be established. An
    /// error return must leave no launched process or retained resource owner.
    // crucible-lint: allow rust-allow -- the explicit generic session is the linear store/executor/guard capability bundle.
    #[allow(clippy::type_complexity)]
    fn begin_target(
        &mut self,
        exact_root: ExactCheckpointId,
        world: &World,
        configuration: &Configuration,
        target: &crucible_api::ProductionExactCheckpointReplayTarget,
        cancellation: &ExecutionCancellation,
        resources: AttemptResourceLimits,
    ) -> Result<
        ProductionPausedCheckpointReplaySession<Self::Store, Self::Launcher, Self::Guard>,
        QemuVmRealizationError,
    >;
}

/// Newly admitted node-specific replay session before either QEMU path starts.
///
/// The value keeps the realization store, fixed-node executor, and exact
/// attempt resource guard linear across the factory/orchestrator boundary.
pub struct ProductionPausedCheckpointReplaySession<S, L, G>
where
    S: QemuVmRealizationStore,
    L: QemuGuardedNodeRealizationLauncher
        + QemuGuardedThinNodeRealizationLauncher
        + QemuFailedLaunchChildSource,
    G: QemuAttemptProcessResourceGuard,
{
    realization_store: S,
    executor: QemuNodeRealizationExecutor<L>,
    guard: G,
}

impl<S, L, G> ProductionPausedCheckpointReplaySession<S, L, G>
where
    S: QemuVmRealizationStore,
    L: QemuGuardedNodeRealizationLauncher
        + QemuGuardedThinNodeRealizationLauncher
        + QemuFailedLaunchChildSource,
    G: QemuAttemptProcessResourceGuard,
{
    /// Binds one unopened fixed-node executor to its store and attempt guard.
    #[must_use]
    pub const fn new(
        realization_store: S,
        executor: QemuNodeRealizationExecutor<L>,
        guard: G,
    ) -> Self {
        Self {
            realization_store,
            executor,
            guard,
        }
    }

    /// Consumes the admission into its linear realization capabilities.
    #[must_use]
    pub fn into_parts(self) -> (S, QemuNodeRealizationExecutor<L>, G) {
        (self.realization_store, self.executor, self.guard)
    }
}

impl<'a> PausedCheckpointPromotionTarget<'a> {
    /// Binds one materialized root to its paused execution and modeled target.
    #[must_use]
    pub const fn new(
        key: AttemptExecutionKey,
        execution: ExecutionId,
        world: &'a World,
        configuration: &'a Configuration,
        materialized: &'a MaterializedAttemptCheckpoint,
    ) -> Self {
        Self {
            key,
            execution,
            world,
            configuration,
            materialized,
        }
    }
}

impl PreparedPausedCheckpointPromotion {
    /// Binds one source-authenticated no-write replacement to its paused owner.
    ///
    /// The supervisor staging phase reauthenticates `key`, `execution`, and the
    /// exact source root before granting immutable publication authority.
    #[must_use]
    pub fn new(
        key: AttemptExecutionKey,
        execution: ExecutionId,
        promotion: PreparedReplayOraclePromotion,
    ) -> Self {
        Self {
            key,
            execution,
            promotion: PreparedPausedCheckpointReplacement::SingleNode(Box::new(promotion)),
        }
    }

    /// Binds one complete multi-node production replacement to its owner.
    ///
    /// The production token already proves that the installed raw root and
    /// every source-bound live-node replay result derive this exact no-write
    /// campaign replacement.
    #[must_use]
    pub fn new_production(
        key: AttemptExecutionKey,
        execution: ExecutionId,
        promotion: PreparedProductionAttemptReplayOraclePromotion,
    ) -> Self {
        Self {
            key,
            execution,
            promotion: PreparedPausedCheckpointReplacement::Production(Box::new(promotion)),
        }
    }

    /// Returns the exact lineage-qualified attempt key.
    #[must_use]
    pub const fn key(&self) -> AttemptExecutionKey {
        self.key
    }

    /// Returns the execution that produced the raw paused root.
    #[must_use]
    pub const fn execution(&self) -> ExecutionId {
        self.execution
    }

    /// Returns the raw exact root compared by the replay oracle.
    #[must_use]
    pub const fn source(&self) -> ExactCheckpointId {
        match &self.promotion {
            PreparedPausedCheckpointReplacement::SingleNode(promotion) => promotion.source(),
            PreparedPausedCheckpointReplacement::Production(promotion) => promotion.source(),
        }
    }

    /// Returns the expected replacement root containing matching evidence.
    #[must_use]
    pub const fn promoted(&self) -> ExactCheckpointId {
        match &self.promotion {
            PreparedPausedCheckpointReplacement::SingleNode(promotion) => promotion.promoted(),
            PreparedPausedCheckpointReplacement::Production(promotion) => promotion.promoted(),
        }
    }

    pub(crate) fn retire_native_source(&self) -> Result<(), ExactCheckpointStoreError> {
        match &self.promotion {
            PreparedPausedCheckpointReplacement::SingleNode(_) => Ok(()),
            PreparedPausedCheckpointReplacement::Production(promotion) => {
                promotion.replacement().retire_native_source()
            }
        }
    }
}

/// Linear proof that both source and replacement are durable retention roots.
#[derive(Debug)]
pub struct StagedPausedCheckpointPromotion {
    prepared: PreparedPausedCheckpointPromotion,
}

impl StagedPausedCheckpointPromotion {
    /// Returns the raw root retained throughout promotion.
    #[must_use]
    pub const fn source(&self) -> ExactCheckpointId {
        self.prepared.source()
    }

    /// Returns the staged replacement root.
    #[must_use]
    pub const fn promoted(&self) -> ExactCheckpointId {
        self.prepared.promoted()
    }

    pub(crate) fn retire_native_source(&self) -> Result<(), ExactCheckpointStoreError> {
        self.prepared.retire_native_source()
    }
}

/// Complete durable replacement awaiting the final paused-state CAS.
#[derive(Debug)]
pub struct PublishedPausedCheckpointPromotion {
    key: AttemptExecutionKey,
    execution: ExecutionId,
    source: ExactCheckpointId,
    promoted: ExactCheckpointId,
}

/// Result of the short supervisor staging phase.
#[derive(Debug)]
pub enum PausedCheckpointPromotionStageOutcome {
    /// Immutable publication may proceed outside the supervisor actor.
    Publish(Box<StagedPausedCheckpointPromotion>),
    /// Another idempotent or stale state won without further writes.
    Finished {
        /// Prepared token retained so redundant native state can be retired.
        prepared: Box<PreparedPausedCheckpointPromotion>,
        /// Durable staging disposition.
        outcome: CheckpointPromotionStageOutcome,
        /// Expected promoted root.
        promoted: ExactCheckpointId,
    },
}

/// QEMU comparison or no-write promotion preparation failure.
#[derive(Debug, Error)]
pub enum PausedCheckpointPromotionPreparationError {
    /// Production-root installation or no-write replacement preparation failed.
    #[error(transparent)]
    ProductionRestore(#[from] ProductionAttemptCheckpointRestoreError),
    /// The portable production closure could not stream one raw live target.
    #[error(transparent)]
    ProductionClosure(#[from] LifecycleApiError),
    /// Fat/thin realization, comparison, or mandatory cleanup failed.
    #[error(transparent)]
    Realization(#[from] QemuVmRealizationError),
    /// The source-bound immutable replacement could not be prepared.
    #[error(transparent)]
    Preparation(#[from] PrepareReplayOraclePromotionError),
}

/// Failure to resolve one durable raw pause into guarded comparison input.
#[derive(Debug, Error)]
pub enum PausedCheckpointPromotionRecoveryResolutionError {
    /// Immutable campaign input was unavailable or failed authentication.
    #[error(transparent)]
    Repository(#[from] CampaignRepositoryError),
    /// Nested Crucible scenario or configuration bytes failed strict decoding.
    #[error(transparent)]
    Artifact(#[from] CrucibleArtifactError),
    /// The durable resource/retention basis does not match the attempt key.
    #[error("paused checkpoint promotion execution basis is inconsistent")]
    ExecutionBasisMismatch,
}

/// No-write restart result ready for a short supervisor or publication phase.
#[derive(Debug)]
pub enum PreparedPausedCheckpointPromotionRestart {
    /// A raw pause passed semantic resolution and guarded replay comparison.
    Stage(Box<PreparedPausedCheckpointPromotion>),
    /// A staged replacement was already complete and reauthenticated.
    Reconcile(Box<PublishedPausedCheckpointPromotion>),
}

/// Failure to prepare one durable promotion phase after restart.
#[derive(Debug, Error)]
pub enum PausedCheckpointPromotionRestartPreparationError {
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
pub fn resolve_production_paused_checkpoint_promotion_recovery(
    store: &CampaignExecutorStore,
    recovery: PausedCheckpointPromotionRecovery,
    cancellation: ExecutionCancellation,
) -> Result<
    ResolvedProductionPausedCheckpointPromotionRecovery,
    PausedCheckpointPromotionRecoveryResolutionError,
> {
    let basis = recovery.promotion_basis();
    if attempt_execution_basis_digest(
        recovery.key().lineage(),
        recovery.key().attempt(),
        basis.resources(),
        basis.retention(),
    ) != recovery.execution_basis()
    {
        return Err(PausedCheckpointPromotionRecoveryResolutionError::ExecutionBasisMismatch);
    }
    let input = resolve_attempt_execution_input(store, recovery.key())?;
    let execution = decode_crucible_attempt_execution(store, &input)?;
    Ok(ResolvedProductionPausedCheckpointPromotionRecovery {
        recovery,
        execution,
        cancellation,
    })
}

/// Prepares one durable paused-root restart phase without supervisor ownership.
///
/// Raw pauses resolve their exact repository input and run the complete guarded
/// multi-node replay comparison. Staged pairs skip QEMU and fully authenticate
/// the already-published production source/replacement relationship. Neither
/// path writes immutable objects or operational ledger state.
///
/// # Errors
///
/// Returns [`PausedCheckpointPromotionRestartPreparationError`] when semantic
/// input, guarded comparison, or the staged production pair fails closed.
pub fn prepare_production_paused_checkpoint_promotion_restart<F>(
    store: &CampaignExecutorStore,
    checkpoints: &ExactCheckpointStore,
    work: CheckpointPromotionRestartWork,
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
            let prepared = validate_and_prepare_production_paused_checkpoint_promotion(
                checkpoints,
                resolved.target(run_state_root),
                factory,
            )
            .map_err(Box::new)?;
            Ok(PreparedPausedCheckpointPromotionRestart::Stage(Box::new(
                prepared,
            )))
        }
        CheckpointPromotionRestartWork::Staged(recovery) => {
            let input = resolve_attempt_execution_input(store, recovery.key())?;
            let execution = decode_crucible_attempt_execution(store, &input)?;
            let published = recover_published_production_paused_checkpoint_promotion(
                checkpoints,
                execution.scenario(),
                &cancellation,
                recovery,
            )?;
            Ok(PreparedPausedCheckpointPromotionRestart::Reconcile(
                Box::new(published),
            ))
        }
    }
}

/// Staging failure retaining the sole prepared promotion token.
#[derive(Debug, Error)]
#[error("paused exact-checkpoint promotion staging failed")]
pub struct PausedCheckpointPromotionStagingError<E> {
    /// Prepared promotion retained for exact actor retry or abandonment.
    pub prepared: Box<PreparedPausedCheckpointPromotion>,
    /// Supervisor or operational-ledger failure.
    pub source: E,
}

/// Immutable publication failure retaining the staged promotion token.
#[derive(Debug, Error)]
#[error("paused exact-checkpoint promotion publication failed")]
pub struct PausedCheckpointPromotionPublicationError {
    /// Staged promotion retained for exact publication retry or abandonment.
    pub staged: Box<StagedPausedCheckpointPromotion>,
    /// Immutable checkpoint-store failure.
    pub source: ExactCheckpointStoreError,
}

/// Final reconciliation failure retaining the complete published root token.
#[derive(Debug, Error)]
#[error("paused exact-checkpoint promotion reconciliation failed")]
pub struct PausedCheckpointPromotionReconcileError<E> {
    /// Published promotion retained for exact actor retry.
    pub published: Box<PublishedPausedCheckpointPromotion>,
    /// Supervisor or operational-ledger failure.
    pub source: E,
}

/// Validates one materialized paused root and prepares its replacement.
///
/// Fat and independent thin realizations share one attempt process guard. The
/// final live generation is reaped before the source-bound replacement is
/// prepared, and no immutable object or operational ledger state is changed by
/// this function.
///
/// # Errors
///
/// Returns [`PausedCheckpointPromotionPreparationError`] when the materialized
/// source does not match `configuration`, either realization fails or differs,
/// cleanup cannot attest reap, or replacement preparation fails.
pub fn validate_and_prepare_paused_checkpoint_promotion_guarded<S, L, G>(
    checkpoints: &ExactCheckpointStore,
    target: PausedCheckpointPromotionTarget<'_>,
    realization_store: &mut S,
    executor: &mut QemuNodeRealizationExecutor<L>,
    guard: G,
) -> Result<PreparedPausedCheckpointPromotion, PausedCheckpointPromotionPreparationError>
where
    S: QemuVmRealizationStore,
    L: QemuGuardedNodeRealizationLauncher
        + QemuGuardedThinNodeRealizationLauncher
        + QemuFailedLaunchChildSource,
    G: QemuAttemptProcessResourceGuard,
{
    let mut session = QemuGuardedReplayOracleSession::new(executor, guard);
    let comparison = check_qemu_snapshot_replay_oracle_bound(
        target.world,
        target.configuration,
        target.materialized.snapshot(),
        realization_store,
        &mut session,
        crucible_qemu::QemuExactSnapshotPolicy::production(),
    );
    let cleanup = session.finish();
    let check = match (comparison, cleanup) {
        (_, Err(cleanup)) => return Err(cleanup.into()),
        (Err(comparison), Ok(())) => return Err(comparison.into()),
        (Ok(check), Ok(())) => check,
    };
    let promotion =
        checkpoints.prepare_replay_oracle_promotion(target.materialized.checkpoint(), check)?;
    Ok(PreparedPausedCheckpointPromotion::new(
        target.key,
        target.execution,
        promotion,
    ))
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
pub fn validate_and_prepare_production_paused_checkpoint_promotion<F>(
    checkpoints: &ExactCheckpointStore,
    target: ProductionPausedCheckpointPromotionTarget<'_>,
    factory: &mut F,
) -> Result<PreparedPausedCheckpointPromotion, PausedCheckpointPromotionPreparationError>
where
    F: ProductionPausedCheckpointReplayFactory,
{
    let installed = install_attempt_production_exact_checkpoint(
        checkpoints,
        target.raw,
        target.source,
        target.initial,
        target.post_selection,
        target.run_state_root,
        target.cancellation,
    )?;
    let mut boundary = || {
        if target.cancellation.is_canceled() {
            Err(LifecycleApiError::LoopFactory {
                message: String::from("production replay-oracle target streaming canceled"),
            })
        } else {
            Ok(())
        }
    };
    let mut targets = installed
        .closure()
        .replay_oracle_targets_with_boundary(&mut boundary)
        .map_err(|error| map_production_target_error(error, target.cancellation))?;

    let mut checks = BTreeMap::new();
    loop {
        let next = targets
            .next_target_with_boundary(&mut boundary)
            .map_err(|error| map_production_target_error(error, target.cancellation))?;
        let Some(next) = next else {
            break;
        };
        let (mut realization_store, mut executor, mut guard) = factory
            .begin_target(
                installed.checkpoint(),
                target.source.world(),
                installed.configuration(),
                &next,
                target.cancellation,
                target.resources,
            )?
            .into_parts();
        if executor.node() != next.node()
            || guard.resource_limits() != target.resources
            || !guard.cancellation().same_incarnation(target.cancellation)
        {
            guard.finish()?;
            return Err(QemuVmRealizationError::Executor {
                operation: "admit production replay-oracle target",
                message: String::from(
                    "node executor or resource guard does not match the requested target",
                ),
            }
            .into());
        }
        let mut session = QemuGuardedReplayOracleSession::new(&mut executor, guard);
        let comparison = check_qemu_snapshot_replay_oracle_bound(
            target.source.world(),
            installed.configuration(),
            next.snapshot(),
            &mut realization_store,
            &mut session,
            crucible_qemu::QemuExactSnapshotPolicy::production(),
        );
        let cleanup = session.finish();
        let check = match (comparison, cleanup) {
            (_, Err(cleanup)) => return Err(cleanup.into()),
            (Err(comparison), Ok(())) => return Err(comparison.into()),
            (Ok(check), Ok(())) => check,
        };
        if checks.insert(next.node().clone(), check).is_some() {
            return Err(
                PausedCheckpointPromotionPreparationError::ProductionClosure(
                    LifecycleApiError::LoopFactory {
                        message: String::from(
                            "production replay-oracle target set contains a duplicate node",
                        ),
                    },
                ),
            );
        }
    }

    let promotion = prepare_attempt_production_replay_oracle_promotion(
        checkpoints,
        target.raw,
        &installed,
        &checks,
        target.cancellation,
    )?;
    Ok(PreparedPausedCheckpointPromotion::new_production(
        target.key,
        target.execution,
        promotion,
    ))
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
pub fn stage_prepared_paused_checkpoint_promotion<L, V>(
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
            let promoted = prepared.promoted();
            Ok(PausedCheckpointPromotionStageOutcome::Finished {
                prepared: Box::new(prepared),
                outcome: stage,
                promoted,
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
pub fn publish_staged_paused_checkpoint_promotion(
    checkpoints: &ExactCheckpointStore,
    staged: StagedPausedCheckpointPromotion,
) -> Result<PublishedPausedCheckpointPromotion, PausedCheckpointPromotionPublicationError> {
    let publication = match &staged.prepared.promotion {
        PreparedPausedCheckpointReplacement::SingleNode(promotion) => {
            checkpoints.publish(promotion.replacement()).map(|_| ())
        }
        PreparedPausedCheckpointReplacement::Production(promotion) => checkpoints
            .publish_production_closure(promotion.replacement())
            .and_then(|_| promotion.replacement().retire_native_source()),
    };
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
    })
}

/// Reconstructs a published token from one complete durable staged pair.
///
/// This restart path performs no writes and no QEMU work. Both roots are fully
/// authenticated, must share the exact VMState child, and must form the exact
/// raw-to-matching metadata transition before a final ledger CAS is allowed.
///
/// # Errors
///
/// Returns [`PrepareReplayOraclePromotionError`] when either root is missing or
/// invalid, or the durable pair is not an exact replay-oracle promotion.
pub fn recover_published_paused_checkpoint_promotion(
    checkpoints: &ExactCheckpointStore,
    recovery: CheckpointPromotionRecovery,
) -> Result<PublishedPausedCheckpointPromotion, PrepareReplayOraclePromotionError> {
    checkpoints.authenticate_replay_oracle_promotion(recovery.source(), recovery.promoted())?;
    Ok(PublishedPausedCheckpointPromotion {
        key: recovery.key(),
        execution: recovery.execution(),
        source: recovery.source(),
        promoted: recovery.promoted(),
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
pub fn recover_published_production_paused_checkpoint_promotion(
    checkpoints: &ExactCheckpointStore,
    source: &ScenarioDefForm,
    cancellation: &ExecutionCancellation,
    recovery: CheckpointPromotionRecovery,
) -> Result<PublishedPausedCheckpointPromotion, ProductionAttemptCheckpointRestoreError> {
    authenticate_production_exact_checkpoint_replay_oracle_promotion(
        checkpoints,
        recovery.source(),
        recovery.promoted(),
        source,
        cancellation,
    )?;
    Ok(PublishedPausedCheckpointPromotion {
        key: recovery.key(),
        execution: recovery.execution(),
        source: recovery.source(),
        promoted: recovery.promoted(),
    })
}

/// Commits one complete replacement as the paused resume root.
///
/// # Errors
///
/// Returns [`PausedCheckpointPromotionReconcileError`] with the published token
/// when the final ledger CAS cannot be reconciled safely.
pub fn reconcile_published_paused_checkpoint_promotion<L, V>(
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
    match supervisor.complete_checkpoint_promotion(
        published.key,
        published.execution,
        published.source,
        published.promoted,
    ) {
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
pub fn revert_staged_paused_checkpoint_promotion<L, V>(
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
pub fn revert_recovered_paused_checkpoint_promotion<L, V>(
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
