//! Test support and regressions for paused checkpoint promotion.

// crucible-lint: allow panic-shortcut -- fixtures use panic shortcuts for exact failure localization.
#![allow(clippy::expect_used)]

use std::sync::Arc;

use crucible::{
    Configuration, ContentHash, ScenarioDef, SchedulerLivenessScenario, Shift, SimInstant,
    SingleScheduler, VirtualTime,
};
use crucible_api::build_authenticated_production_checkpoint_codec_fixture;
use crucible_campaign::{
    AttemptRetentionPolicyDisposition, CampaignHash, ExecutionRetentionIntent,
};
use crucible_cas::content_store::DirectoryBlobBackend;

use super::*;
use crate::executor_supervisor::AllowAllAttemptAdmission;
use crate::{
    AttemptExecutionContext, AttemptRuntimeState, AttemptStateCas,
    CheckpointPromotionExecutionBasis, ExecutorCapacity, MemoryAssignmentLedger,
};

pub(crate) struct RepositoryPromotionFixture {
    pub(crate) prepared: PreparedPausedCheckpointPromotion,
    pub(crate) key: AttemptExecutionKey,
    pub(crate) state: AttemptRuntimeState,
    pub(crate) daemon_epoch: crucible_campaign::DaemonEpoch,
    pub(crate) capacity: ExecutorCapacity,
    pub(crate) source: ScenarioDefForm,
    pub(crate) initial: Configuration,
}

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
            replay_store: None,
            selected_checkpoint,
        }
    }
}

/// Runs the production replay-oracle promotion path for one native test resume.
///
/// The returned root carries durable source-bound replay evidence. The caller
/// must separately supply one selected-root authority for each guarded launch;
/// production creates that authority only after durable attempt admission.
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

#[test]
fn repository_evidence_seals_stages_and_reconciles_after_native_retirement() {
    let repository = tempfile::tempdir().expect("create repository checkpoint fixture");
    let backend = Arc::new(DirectoryBlobBackend::new(
        "promotion-lifecycle-test",
        repository.path(),
    ));
    let checkpoints = ExactCheckpointStore::new(backend.clone(), 64 * 1024 * 1024)
        .expect("admit checkpoint store");
    let fixture = prepare_repository_promotion_fixture(&checkpoints);
    let mut ledger = MemoryAssignmentLedger::default();
    assert_eq!(
        ledger
            .compare_exchange_attempt(fixture.key, None, Some(fixture.state))
            .expect("seed raw paused checkpoint"),
        AttemptStateCas::Advanced
    );
    let mut supervisor = LocalExecutorSupervisor::new(
        ledger,
        AllowAllAttemptAdmission,
        fixture.daemon_epoch,
        fixture.capacity,
    );
    let staged = match stage_prepared_paused_checkpoint_promotion(&mut supervisor, fixture.prepared)
        .expect("stage replay promotion")
    {
        PausedCheckpointPromotionStageOutcome::Publish(staged) => staged,
        PausedCheckpointPromotionStageOutcome::Finished { outcome, .. } => {
            panic!("fresh replay promotion finished before publication: {outcome:?}")
        }
    };
    let published = publish_staged_paused_checkpoint_promotion(&checkpoints, *staged)
        .expect("publish replay promotion");
    let promoted = published.promoted();
    assert_eq!(
        reconcile_published_paused_checkpoint_promotion(&checkpoints, &mut supervisor, published,)
            .expect("reconcile replay promotion"),
        CheckpointPromotionCompletionOutcome::Promoted
    );

    let ledger = supervisor.into_ledger();
    assert!(matches!(
        ledger.load_attempt(fixture.key).expect("load promoted pause"),
        Some(AttemptRuntimeState::Paused {
            checkpoint,
            promotion_basis: None,
            ..
        }) if checkpoint == promoted
    ));

    let promoted_closure = checkpoints
        .load_production_closure(promoted)
        .expect("load promoted closure");
    let evidence = promoted_closure
        .promotion_evidence_id()
        .expect("promoted closure retains evidence identity");
    assert!(
        checkpoints
            .acquire_live_replay_promotion(
                fixture.key,
                fixture.state.execution(),
                promoted,
                evidence,
            )
            .expect("inspect spent promotion claim")
            .is_none(),
        "promotion reconciliation consumes its own publication claim"
    );

    let cancellation = ExecutionCancellation::default();
    crate::exact_checkpoint_restore::install_attempt_production_resume_checkpoint(
        &checkpoints,
        promoted,
        &fixture.source,
        &fixture.initial,
        None,
        &cancellation,
    )
    .expect("same-process restore authenticates promoted evidence after reconciliation");

    let reopened = ExactCheckpointStore::new(backend, 64 * 1024 * 1024)
        .expect("reopen durable checkpoint store");
    crate::exact_checkpoint_restore::install_attempt_production_resume_checkpoint(
        &reopened,
        promoted,
        &fixture.source,
        &fixture.initial,
        None,
        &cancellation,
    )
    .expect("restart restore authenticates durable promoted evidence");

    let raw = fixture.state.checkpoint().expect("raw paused checkpoint");
    assert!(matches!(
        crate::exact_checkpoint_restore::install_attempt_production_resume_checkpoint(
            &reopened,
            raw,
            &fixture.source,
            &fixture.initial,
            None,
            &cancellation,
        ),
        Err(crate::ProductionAttemptCheckpointRestoreError::ReplayOracleNotReady {
            checkpoint,
        }) if checkpoint == raw
    ));
}

#[test]
fn identical_replay_root_can_reconcile_a_later_pause_execution() {
    let repository = tempfile::tempdir().expect("create repository checkpoint fixture");
    let backend = Arc::new(DirectoryBlobBackend::new(
        "promotion-repeat-test",
        repository.path(),
    ));
    let checkpoints =
        ExactCheckpointStore::new(backend, 64 * 1024 * 1024).expect("admit checkpoint store");
    let first = prepare_repository_promotion_fixture(&checkpoints);
    let key = first.key;
    let first_execution = first.state.execution();
    let mut first_ledger = MemoryAssignmentLedger::default();
    assert_eq!(
        first_ledger
            .compare_exchange_attempt(key, None, Some(first.state))
            .expect("seed first paused execution"),
        AttemptStateCas::Advanced
    );
    let mut first_supervisor = LocalExecutorSupervisor::new(
        first_ledger,
        AllowAllAttemptAdmission,
        first.daemon_epoch,
        first.capacity,
    );
    let PausedCheckpointPromotionStageOutcome::Publish(first_staged) =
        stage_prepared_paused_checkpoint_promotion(&mut first_supervisor, first.prepared)
            .expect("stage first replay promotion")
    else {
        panic!("first replay promotion did not stage");
    };
    let first_published = publish_staged_paused_checkpoint_promotion(&checkpoints, *first_staged)
        .expect("publish first replay promotion");
    let promoted = first_published.promoted();
    assert_eq!(
        reconcile_published_paused_checkpoint_promotion(
            &checkpoints,
            &mut first_supervisor,
            first_published,
        )
        .expect("reconcile first replay promotion"),
        CheckpointPromotionCompletionOutcome::Promoted
    );

    let mut second = prepare_repository_promotion_fixture(&checkpoints);
    assert_eq!(second.key, key);
    assert_eq!(second.prepared.promoted(), promoted);
    let second_execution = ExecutionId::from_bytes([0x65; 16]).expect("later execution identity");
    let AttemptRuntimeState::Paused {
        execution_basis,
        origin,
        daemon_epoch,
        checkpoint,
        promotion_basis,
        ..
    } = second.state
    else {
        panic!("repository fixture is not paused");
    };
    second.state = AttemptRuntimeState::Paused {
        execution_basis,
        origin,
        daemon_epoch,
        execution: second_execution,
        checkpoint,
        promotion_basis,
    };
    second.prepared.execution = second_execution;

    let mut second_ledger = MemoryAssignmentLedger::default();
    assert_eq!(
        second_ledger
            .compare_exchange_attempt(key, None, Some(second.state))
            .expect("seed later paused execution"),
        AttemptStateCas::Advanced
    );
    let mut second_supervisor = LocalExecutorSupervisor::new(
        second_ledger,
        AllowAllAttemptAdmission,
        second.daemon_epoch,
        second.capacity,
    );
    let PausedCheckpointPromotionStageOutcome::Publish(second_staged) =
        stage_prepared_paused_checkpoint_promotion(&mut second_supervisor, second.prepared)
            .expect("stage later replay promotion")
    else {
        panic!("later replay promotion did not stage");
    };
    let second_published = publish_staged_paused_checkpoint_promotion(&checkpoints, *second_staged)
        .expect("publish identical root for later execution");
    assert_eq!(second_published.promoted(), promoted);
    assert_eq!(
        reconcile_published_paused_checkpoint_promotion(
            &checkpoints,
            &mut second_supervisor,
            second_published,
        )
        .expect("reconcile later replay promotion"),
        CheckpointPromotionCompletionOutcome::Promoted
    );

    let evidence = checkpoints
        .load_production_closure(promoted)
        .expect("load shared promoted root")
        .promotion_evidence_id()
        .expect("shared root has replay evidence");
    assert!(
        checkpoints
            .acquire_live_replay_promotion(key, first_execution, promoted, evidence)
            .expect("inspect first claim")
            .is_none()
    );
    assert!(
        checkpoints
            .acquire_live_replay_promotion(key, second_execution, promoted, evidence)
            .expect("inspect later claim")
            .is_none()
    );
}

#[test]
fn staged_promotion_reconstitutes_its_reconcile_claim_after_store_restart() {
    let repository = tempfile::tempdir().expect("create repository checkpoint fixture");
    let backend = Arc::new(DirectoryBlobBackend::new(
        "promotion-restart-test",
        repository.path(),
    ));
    let checkpoints = ExactCheckpointStore::new(backend.clone(), 64 * 1024 * 1024)
        .expect("admit checkpoint store");
    let fixture = prepare_repository_promotion_fixture(&checkpoints);
    let mut ledger = MemoryAssignmentLedger::default();
    assert_eq!(
        ledger
            .compare_exchange_attempt(fixture.key, None, Some(fixture.state))
            .expect("seed raw paused checkpoint"),
        AttemptStateCas::Advanced
    );
    let mut supervisor = LocalExecutorSupervisor::new(
        ledger,
        AllowAllAttemptAdmission,
        fixture.daemon_epoch,
        fixture.capacity,
    );
    let staged = match stage_prepared_paused_checkpoint_promotion(&mut supervisor, fixture.prepared)
        .expect("stage replay promotion")
    {
        PausedCheckpointPromotionStageOutcome::Publish(staged) => staged,
        PausedCheckpointPromotionStageOutcome::Finished { outcome, .. } => {
            panic!("fresh replay promotion finished before publication: {outcome:?}")
        }
    };
    let promoted = {
        let published = publish_staged_paused_checkpoint_promotion(&checkpoints, *staged)
            .expect("publish replay promotion");
        published.promoted()
    };
    drop(checkpoints);

    let reopened = ExactCheckpointStore::new(backend, 64 * 1024 * 1024)
        .expect("reopen checkpoint store after staged publication");
    let mut restarted = LocalExecutorSupervisor::new(
        supervisor.into_ledger(),
        AllowAllAttemptAdmission,
        fixture.daemon_epoch,
        fixture.capacity,
    );
    let mut restart_work = Vec::new();
    restarted
        .visit_checkpoint_promotion_restart_work(&mut |work| restart_work.push(work))
        .expect("enumerate durable staged promotion");
    let recovery = match restart_work.pop().expect("one staged recovery") {
        CheckpointPromotionRestartWork::Staged(recovery) => recovery,
        CheckpointPromotionRestartWork::Paused(_) => panic!("published pair lost its staged state"),
    };
    assert!(restart_work.is_empty());
    assert_eq!(recovery.promoted(), promoted);

    let recovered = recover_published_production_paused_checkpoint_promotion(
        &reopened,
        &fixture.source,
        &ExecutionCancellation::default(),
        recovery,
        None,
    )
    .expect("durable staged pair restores reconciliation authority");
    assert_eq!(
        reconcile_published_paused_checkpoint_promotion(&reopened, &mut restarted, recovered)
            .expect("reconcile after checkpoint-store restart"),
        CheckpointPromotionCompletionOutcome::Promoted
    );
    let ledger = restarted.into_ledger();
    assert!(matches!(
        ledger.load_attempt(fixture.key).expect("load promoted pause"),
        Some(AttemptRuntimeState::Paused { checkpoint, .. }) if checkpoint == promoted
    ));
    crate::exact_checkpoint_restore::install_attempt_production_resume_checkpoint(
        &reopened,
        promoted,
        &fixture.source,
        &fixture.initial,
        None,
        &ExecutionCancellation::default(),
    )
    .expect("restarted promotion result restores for an admitted resume");
}

#[test]
fn forged_staged_pair_cannot_reconstitute_a_reconcile_claim() {
    let repository = tempfile::tempdir().expect("create repository checkpoint fixture");
    let backend = Arc::new(DirectoryBlobBackend::new(
        "promotion-forged-pair-test",
        repository.path(),
    ));
    let checkpoints = ExactCheckpointStore::new(backend.clone(), 64 * 1024 * 1024)
        .expect("admit checkpoint store");
    let fixture = prepare_repository_promotion_fixture(&checkpoints);
    let raw = fixture.state.checkpoint().expect("raw paused checkpoint");
    let execution = fixture.state.execution();
    let mut ledger = MemoryAssignmentLedger::default();
    assert_eq!(
        ledger
            .compare_exchange_attempt(fixture.key, None, Some(fixture.state))
            .expect("seed raw paused checkpoint"),
        AttemptStateCas::Advanced
    );
    let mut supervisor = LocalExecutorSupervisor::new(
        ledger,
        AllowAllAttemptAdmission,
        fixture.daemon_epoch,
        fixture.capacity,
    );
    assert_eq!(
        supervisor
            .stage_checkpoint_promotion(fixture.key, execution, raw, raw)
            .expect("stage forged root pair"),
        CheckpointPromotionStageOutcome::Staged
    );
    drop(checkpoints);

    let reopened = ExactCheckpointStore::new(backend, 64 * 1024 * 1024)
        .expect("reopen checkpoint store after forged staging");
    let mut work = Vec::new();
    supervisor
        .visit_checkpoint_promotion_restart_work(&mut |item| work.push(item))
        .expect("enumerate forged staged pair");
    let recovery = match work.pop().expect("one staged recovery") {
        CheckpointPromotionRestartWork::Staged(recovery) => recovery,
        CheckpointPromotionRestartWork::Paused(_) => panic!("forged pair was not staged"),
    };
    assert!(matches!(
        recover_published_production_paused_checkpoint_promotion(
            &reopened,
            &fixture.source,
            &ExecutionCancellation::default(),
            recovery,
            None,
        ),
        Err(ProductionAttemptCheckpointRestoreError::ReplayOracleNotReady {
            checkpoint,
        }) if checkpoint == raw
    ));
    assert!(matches!(
        supervisor
            .into_ledger()
            .load_attempt(fixture.key)
            .expect("load rejected staged state"),
        Some(AttemptRuntimeState::CheckpointPromoting { .. })
    ));
}

pub(crate) fn prepare_repository_promotion_fixture(
    checkpoints: &ExactCheckpointStore,
) -> RepositoryPromotionFixture {
    let native = tempfile::tempdir().expect("create native checkpoint fixture");
    let fixture = build_authenticated_production_checkpoint_codec_fixture(native.path())
        .expect("build authenticated checkpoint fixture");
    let source = fixture.source().clone();
    let initial = Configuration::genesis(source.scenario_def());
    let raw = checkpoints
        .prepare_production_closure(fixture.closure().clone())
        .expect("prepare raw closure");
    let raw_root = raw.root();
    checkpoints
        .publish_production_closure(&raw)
        .expect("publish raw closure");
    raw.retire_native_source()
        .expect("retire native checkpoint catalog");

    let cancellation = ExecutionCancellation::default();
    let mut installed = install_attempt_production_exact_checkpoint(
        checkpoints,
        raw_root,
        &source,
        &initial,
        None,
        &cancellation,
    )
    .expect("install repository-backed raw closure");
    let mut admissions = installed
        .take_node_restore_admissions()
        .expect("take repository restore admissions");
    let mut matches = BTreeMap::new();
    while let Some(admission) = admissions.take_next().expect("take exact node admission") {
        let node = admission.node().clone();
        let matched = admission
            .into_replay_oracle_match_for_test(ContentHash::from_bytes(b"matching replay runtime"));
        assert!(matches.insert(node, matched).is_none());
    }
    let evidence = admissions
        .prepare_replay_oracle_promotion_with_boundary(raw_root, matches, &mut || Ok(()))
        .expect("seal repository replay evidence");
    let promotion = prepare_attempt_production_replay_oracle_promotion(
        checkpoints,
        raw_root,
        &installed,
        evidence,
        &cancellation,
    )
    .expect("prepare repository-backed promotion");

    let key = AttemptExecutionKey::new(
        crucible_campaign::CampaignLineageId::parse(&format!(
            "crucible.campaign.lineage@campaign-fact.1.{}",
            "61".repeat(32)
        ))
        .expect("lineage identity"),
        crucible_campaign::AttemptId::parse(&format!(
            "crucible.campaign.attempt@campaign-fact.9.{}",
            "62".repeat(32)
        ))
        .expect("attempt identity"),
    );
    let execution = ExecutionId::from_bytes([0x63; 16]).expect("execution identity");
    let daemon_epoch =
        crucible_campaign::DaemonEpoch::from_bytes([0x64; 16]).expect("daemon epoch");
    let resources =
        AttemptResourceLimits::new(1, 64 * 1024 * 1024, 0, 1_000).expect("attempt resources");
    let state = AttemptRuntimeState::Paused {
        execution_basis: CampaignHash::derive(
            "crucible.test.promotion-lifecycle.execution.v1",
            b"execution",
        ),
        origin: crate::AttemptExecutionOrigin::Initial,
        daemon_epoch,
        execution,
        checkpoint: raw_root,
        promotion_basis: Some(CheckpointPromotionExecutionBasis::new(
            resources,
            ExecutionRetentionIntent::RetainOnFailure,
            AttemptRetentionPolicyDisposition::Disabled,
        )),
    };
    let capacity =
        ExecutorCapacity::new(1, 1, 64 * 1024 * 1024, 0, 1_000).expect("executor capacity");
    let prepared = PreparedPausedCheckpointPromotion::new(key, execution, promotion);
    RepositoryPromotionFixture {
        prepared,
        key,
        state,
        daemon_epoch,
        capacity,
        source,
        initial,
    }
}
