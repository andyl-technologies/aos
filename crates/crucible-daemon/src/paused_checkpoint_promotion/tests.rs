//! Test support and regressions for paused checkpoint promotion.

// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for exact failure localization.
#![allow(clippy::expect_used)]

use crucible::{
    Configuration, ScenarioDef, SchedulerLivenessScenario, Shift, SimInstant, SingleScheduler,
    VirtualTime,
};

use super::*;
use crate::executor_supervisor::AllowAllAttemptAdmission;
use crate::{
    AttemptExecutionContext, AttemptRuntimeState, AttemptStateCas,
    CheckpointPromotionExecutionBasis, ExecutorCapacity, MemoryAssignmentLedger,
};

impl<'a> ProductionPausedCheckpointPromotionTarget<'a> {
    fn from_test_recovery(
        recovery: &'a mut PausedCheckpointPromotionRecovery,
        attempt: &'a CrucibleAttemptExecution,
        initial: &'a Configuration,
        post_selection: Option<&'a Configuration>,
        run_state_root: &'a Path,
        cancellation: &'a ExecutionCancellation,
    ) -> Self {
        let key = recovery.key();
        let execution = recovery.execution();
        let raw = recovery.source();
        let basis = recovery.promotion_basis();
        let selected_checkpoint = recovery.selected_checkpoint();

        Self {
            key,
            execution,
            raw,
            source: attempt.scenario(),
            initial,
            post_selection,
            run_state_root,
            cancellation,
            resources: basis.resources(),
            start_mode: basis.start_mode(),
            attempt,
            selected_checkpoint,
        }
    }
}

/// Runs the production replay-oracle promotion path for one native test resume.
///
/// The returned root owns one unspent live promotion claim in `checkpoints`.
/// The caller must pass that root and store to exactly one production resume,
/// which authenticates and consumes the claim. Tests that need another
/// independent resume must repeat this complete guarded promotion in a fresh
/// store incarnation instead of reopening spent authority.
// crucible-lint: allow rust-allow -- this fixture preserves the complete production promotion input.
#[allow(clippy::too_many_arguments)]
pub(crate) fn promote_test_checkpoint_for_resume<F>(
    checkpoints: &ExactCheckpointStore,
    raw: ExactCheckpointId,
    attempt: &CrucibleAttemptExecution,
    initial: &Configuration,
    post_selection: Option<&Configuration>,
    run_state_root: &Path,
    context: &AttemptExecutionContext,
    factory: &mut F,
) -> ExactCheckpointId
where
    F: ProductionPausedCheckpointReplayFactory,
{
    let runtime = context
        .runtime_basis()
        .expect("native promotion fixture has an execution basis");
    let resources = context.resources();
    let retention = context.retention();
    let start_mode = context.start_mode();
    let retention_policy = context.retention_policy();
    let daemon_epoch = crucible_campaign::DaemonEpoch::from_bytes([0x5d; 16])
        .expect("native promotion fixture daemon epoch");
    let execution_basis = attempt_execution_basis_digest_for_start_mode(
        runtime.key().lineage(),
        runtime.key().attempt(),
        resources,
        retention,
        start_mode,
        retention_policy,
    );
    let state = AttemptRuntimeState::Paused {
        execution_basis,
        origin: context.execution_origin(),
        daemon_epoch,
        execution: runtime.execution(),
        checkpoint: raw,
        promotion_basis: Some(CheckpointPromotionExecutionBasis::new_for_start_mode(
            resources,
            retention,
            start_mode,
            retention_policy,
        )),
    };
    let mut ledger = MemoryAssignmentLedger::default();
    assert_eq!(
        ledger
            .compare_exchange_attempt(runtime.key(), None, Some(state))
            .expect("seed native paused checkpoint promotion"),
        AttemptStateCas::Advanced
    );
    let capacity = ExecutorCapacity::new(
        1,
        resources.maximum_vcpus(),
        resources.maximum_resident_bytes(),
        resources.maximum_disk_bytes(),
        resources.maximum_execution_quanta(),
    )
    .expect("native promotion fixture capacity");
    let mut supervisor =
        LocalExecutorSupervisor::new(ledger, AllowAllAttemptAdmission, daemon_epoch, capacity);
    let mut recovery = supervisor
        .paused_checkpoint_promotion_recovery(runtime.key())
        .expect("load native paused checkpoint promotion")
        .expect("native paused checkpoint is promotable");
    let target = ProductionPausedCheckpointPromotionTarget::from_test_recovery(
        &mut recovery,
        attempt,
        initial,
        post_selection,
        run_state_root,
        context.cancellation(),
    );
    let prepared =
        validate_and_prepare_production_paused_checkpoint_promotion(checkpoints, target, factory)
            .expect("validate native checkpoint against the production replay oracle");
    let staged = match stage_prepared_paused_checkpoint_promotion(&mut supervisor, prepared)
        .expect("stage native checkpoint replay promotion")
    {
        PausedCheckpointPromotionStageOutcome::Publish(staged) => staged,
        PausedCheckpointPromotionStageOutcome::Finished { .. } => {
            panic!("fresh native checkpoint promotion did not reach publication")
        }
    };
    publish_staged_paused_checkpoint_promotion(checkpoints, *staged)
        .expect("publish native replay-validated checkpoint")
        .promoted()
}

#[test]
fn promotion_boundary_check_rejects_mismatched_progress_before_store_work() {
    let scenario = ScenarioDef::from_canonical_material(
        "crucible.test.savepoint-promotion-progress",
        "quiet-progress",
    );
    let configuration = Configuration::genesis(scenario.clone());
    let scheduler = SingleScheduler::new(
        SchedulerLivenessScenario::from_canonical_material(
            "quiet-progress",
            Shift::new(0).expect("zero shift"),
            1,
            SimInstant { nanos: 1 },
            Vec::new(),
            Vec::new(),
        )
        .with_scenario_def(scenario),
    )
    .expect("quiet scheduler");
    let checkpoint = scheduler.checkpoint().expect("quiet checkpoint");
    let replay = crate::QemuSavepointReplayProof::from_reached_boundary(
        &configuration,
        100,
        VirtualTime { ticks: 100 },
        &[],
    )
    .expect("quiet replay proof");

    assert!(matches!(
        validate_savepoint_replay_boundary(replay, &configuration, &checkpoint),
        Err(PausedCheckpointPromotionPreparationError::SavepointReplayMismatch)
    ));
}
