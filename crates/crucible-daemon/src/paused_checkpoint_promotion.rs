//! Crash-safe replay-oracle promotion of paused attempt checkpoints.
//!
//! A freshly captured paused root deliberately carries `NotRun` replay-oracle
//! evidence and is not eligible for production resume. This module keeps QEMU
//! comparison and immutable-store work outside the local supervisor actor,
//! then uses linear phase tokens to establish the promoted root as a durable GC
//! root before its first write.

use crucible::{Configuration, World};
use crucible_campaign::{ExactCheckpointId, ExecutionId};
use crucible_qemu::{
    QemuFailedLaunchChildSource, QemuGuardedNodeRealizationLauncher,
    QemuGuardedThinNodeRealizationLauncher, QemuNodeRealizationExecutor, QemuVmRealizationError,
    QemuVmRealizationStore, check_qemu_snapshot_replay_oracle_bound,
};
use thiserror::Error;

use crate::{
    AssignmentLedger, AttemptAdmissionValidator, AttemptExecutionKey,
    CheckpointPromotionCompletionOutcome, CheckpointPromotionRecovery,
    CheckpointPromotionStageOutcome, ExactCheckpointStore, ExactCheckpointStoreError,
    LocalExecutorError, LocalExecutorSupervisor, MaterializedAttemptCheckpoint,
    PrepareReplayOraclePromotionError, PreparedReplayOraclePromotion,
    QemuAttemptProcessResourceGuard, QemuGuardedReplayOracleSession,
};

/// Replay-validated replacement bound to one paused attempt execution.
#[derive(Debug)]
pub struct PreparedPausedCheckpointPromotion {
    key: AttemptExecutionKey,
    execution: ExecutionId,
    promotion: PreparedReplayOraclePromotion,
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
    pub const fn new(
        key: AttemptExecutionKey,
        execution: ExecutionId,
        promotion: PreparedReplayOraclePromotion,
    ) -> Self {
        Self {
            key,
            execution,
            promotion,
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
        self.promotion.source()
    }

    /// Returns the expected replacement root containing matching evidence.
    #[must_use]
    pub const fn promoted(&self) -> ExactCheckpointId {
        self.promotion.promoted()
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
        /// Durable staging disposition.
        outcome: CheckpointPromotionStageOutcome,
        /// Expected promoted root.
        promoted: ExactCheckpointId,
    },
}

/// QEMU comparison or no-write promotion preparation failure.
#[derive(Debug, Error)]
pub enum PausedCheckpointPromotionPreparationError {
    /// Fat/thin realization, comparison, or mandatory cleanup failed.
    #[error(transparent)]
    Realization(#[from] QemuVmRealizationError),
    /// The source-bound immutable replacement could not be prepared.
    #[error(transparent)]
    Preparation(#[from] PrepareReplayOraclePromotionError),
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
            Ok(PausedCheckpointPromotionStageOutcome::Finished {
                outcome: stage,
                promoted: prepared.promoted(),
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
    if let Err(source) = checkpoints.publish(staged.prepared.promotion.replacement()) {
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
