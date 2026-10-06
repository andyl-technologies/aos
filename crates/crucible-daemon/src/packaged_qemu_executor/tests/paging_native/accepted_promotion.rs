//! Accepted native capture and replay promotion on the prepared executor ledger.
//!
//! A real repository worker captures and stages the original checkpoint before
//! QEMU teardown. Publication and replay run outside the actor; short durable
//! transitions use that same actor. The result contains the accepted request
//! and execution identity needed for an actual resumed worker admission.

use super::super::hot_fork_native::{fork_resources, native_repository, native_request};
use super::*;
use crate::executor_supervisor::CheckpointPromotionRestartWork;
use crate::packaged_qemu_executor::preparation::PackagedPreparation;
use crate::paused_checkpoint_promotion::{
    PausedCheckpointPromotionStageOutcome, PreparedPausedCheckpointPromotionRestart,
    prepare_production_paused_checkpoint_promotion_restart,
    publish_staged_paused_checkpoint_promotion, reconcile_published_paused_checkpoint_promotion,
    stage_prepared_paused_checkpoint_promotion,
};
use crate::{
    AttemptExecutionDisposition, AttemptExecutionModel, AttemptExecutionReconciliationStep,
    CheckpointResultStageOutcome, CrucibleExecutionModel, PreparedAttemptWorkResult,
    ProductionBakedGenesisReplayCatalogFactory, QemuFreshExecutionRunner, QemuFreshModeledDriver,
    RepositoryAttemptWorker, capture_production_baked_genesis, prepare_attempt_result,
    publish_staged_checkpoint_result, reconcile_published_checkpoint_result,
    stage_prepared_checkpoint_result,
};
use crucible_api::host_operational::HostOperationalError;
use crucible_campaign::{CampaignExecutorStore, ExecutorService, SubmitAttemptDisposition};

/// Genuine accepted identity after durable production replay promotion.
pub(in crate::packaged_qemu_executor::tests) struct AcceptedPromotion {
    pub(in crate::packaged_qemu_executor::tests) checkpoint: ExactCheckpointId,
    pub(in crate::packaged_qemu_executor::tests) request: SubmitAttemptRequest,
    pub(in crate::packaged_qemu_executor::tests) prior_execution: ExecutionId,
    pub(in crate::packaged_qemu_executor::tests) baked: crate::ProductionBakedGenesisCheckpoint,
}

/// Captures and promotes one actually accepted native campaign assignment.
pub(in crate::packaged_qemu_executor::tests) fn promote_accepted_checkpoint(
    prepared: &PackagedPreparation,
    config: &PackagedQemuExecutorConfig,
    repository: Arc<CampaignRepository>,
    source: &ScenarioDefForm,
) -> AcceptedPromotion {
    promote_accepted_checkpoint_with_model(prepared, config, repository, source, |host, store| {
        let factory = QemuAttemptProductionVmLifecycleFactory::new(
            config
                .admitted_lifecycle_config()
                .unwrap_or_else(|error| panic!("admitted native lifecycle projection: {error}"))
                .with_run_state_root(config.lifecycle.run_state_root().join("accepted-worker")),
            ComposedQemuAttemptResourceGuardFactory::new(host),
        )
        .with_terminal_checkpoints(Arc::clone(&prepared.checkpoints));
        NativeCaptureModel {
            inner: CrucibleExecutionModel::new(
                store,
                QemuFreshExecutionRunner::new(factory, QemuFreshModeledDriver),
            ),
        }
    })
    .0
}

/// Runs the same accepted capture/publication path with a native fixture driver.
///
/// The model receives the real repository worker context and must stage its
/// capture before reaping its world. Returning it after promotion exposes only
/// completed fixture evidence; the original execution owner has been released.
pub(super) fn promote_accepted_checkpoint_with_model<M: AttemptExecutionModel>(
    prepared: &PackagedPreparation,
    config: &PackagedQemuExecutorConfig,
    repository: Arc<CampaignRepository>,
    source: &ScenarioDefForm,
    model: impl FnOnce(
        SharedQemuAttemptHostResourceFactory<LinuxQemuAttemptHostResourceFactory>,
        CampaignExecutorStore,
    ) -> M,
) -> (AcceptedPromotion, RepositoryAttemptWorker<M>)
where
    M::Error: std::fmt::Debug,
{
    let host = SharedQemuAttemptHostResourceFactory::new(
        LinuxQemuAttemptHostResourceFactory::open(config.host.clone())
            .expect("real native resource allocator"),
    );
    let store = CampaignExecutorStore::new(Arc::clone(&repository));
    let mut baked_factory = QemuAttemptProductionVmLifecycleFactory::new(
        config
            .admitted_lifecycle_config()
            .unwrap_or_else(|error| panic!("admitted native lifecycle projection: {error}"))
            .with_run_state_root(config.lifecycle.run_state_root().join("accepted-baked")),
        ComposedQemuAttemptResourceGuardFactory::new(host.clone()),
    );
    let lineage_id = repository
        .head("packaged")
        .expect("durable campaign head")
        .snapshot()
        .lineage();
    let scenario_id = store
        .load_lineage(lineage_id)
        .expect("authenticated campaign lineage")
        .scenario_content();
    let baked = run_capture(prepared, config, source, |context| {
        extend_native_operations(context);
        capture_production_baked_genesis(&mut baked_factory, source, context).map_err(|source| {
            PackagedQemuExecutorError::BakedGenesis {
                scenario: scenario_id,
                source: Box::new(source),
            }
        })
    })
    .expect("actual independently captured native baked genesis");

    let request = native_request(&repository, config);
    let key = AttemptExecutionKey::for_request(&request);
    let mut queued = prepared
        .actor
        .with_supervisor(|actor| {
            let reply = actor
                .submit_attempt(&request)
                .map_err(|_| HostOperationalError::Unavailable)?;
            assert!(matches!(
                reply.disposition(),
                SubmitAttemptDisposition::Accepted { .. }
            ));
            let queued = actor
                .next_queued()
                .ok_or(HostOperationalError::Unavailable)?;
            actor
                .request_checkpoint(key, queued.execution())
                .map_err(|_| HostOperationalError::Unavailable)?;
            assert!(queued.checkpoint_request().is_requested());
            Ok(queued)
        })
        .expect("genuine accepted assignment and durable checkpoint request");
    let prior_execution = queued.execution();
    let cancellation = queued.cancellation().clone();
    prepared
        .actor
        .campaign_port()
        .install_checkpoint_handoff(&mut queued, Arc::clone(&prepared.checkpoints));

    let model = model(host.clone(), store.clone());
    let mut worker = RepositoryAttemptWorker::new(store.clone(), model);
    let work = worker.execute(queued);
    let captured = match prepare_attempt_result(&store, &prepared.checkpoints, work)
        .expect("real native worker checkpoint result")
    {
        PreparedAttemptWorkResult::ExactCheckpoint(captured) => *captured,
        other => panic!("checkpoint request must produce native capture: {other:?}"),
    };
    let raw = captured.root();
    let staged = prepared
        .actor
        .with_supervisor(|actor| Ok(stage_prepared_checkpoint_result(actor, captured)))
        .expect("same actor available")
        .expect("durable exact checkpoint stage");
    let staged = match staged {
        CheckpointResultStageOutcome::Publish(staged) => *staged,
        other => panic!("new accepted checkpoint must require publication: {other:?}"),
    };
    let published = publish_staged_checkpoint_result(&prepared.checkpoints, staged)
        .expect("durable native paged closure publication outside actor");
    prepared
        .actor
        .with_supervisor(|actor| Ok(reconcile_published_checkpoint_result(actor, published)))
        .expect("same original actor")
        .expect("durable paused state after physical reap");
    assert_eq!(
        worker
            .model_mut()
            .reconcile_execution(AttemptExecutionDisposition::ExactCheckpoint(raw))
            .expect("actual native execution cleanup"),
        AttemptExecutionReconciliationStep::Complete
    );

    let recovery = prepared
        .actor
        .with_supervisor(|actor| Ok(actor.paused_checkpoint_promotion_recovery(key)))
        .expect("same original actor")
        .expect("load durable paused recovery")
        .expect("raw pause requires promotion");
    let mut work = CheckpointPromotionRestartWork::Paused(recovery);
    let mut replay = ProductionBakedGenesisReplayCatalogFactory::new(
        [baked.clone()],
        ComposedQemuAttemptResourceGuardFactory::new(host),
    )
    .expect("real native baked replay catalog")
    .with_savepoint_replay_config(config.lifecycle.clone())
    .with_replay_services(
        crate::packaged_qemu_executor::RetainedTemplateServiceFactory::new(prepared, config),
    );
    let ready = prepare_production_paused_checkpoint_promotion_restart(
        &store,
        &prepared.checkpoints,
        &mut work,
        &config.lifecycle.run_state_root().join("accepted-promotion"),
        cancellation,
        &mut replay,
    )
    .expect("independent causal and exact/thin native replay comparison");
    let ready = match ready {
        PreparedPausedCheckpointPromotionRestart::Stage(ready) => *ready,
        other => panic!("new raw pause must require promotion staging: {other:?}"),
    };
    let staged = prepared
        .actor
        .with_supervisor(|actor| Ok(stage_prepared_paused_checkpoint_promotion(actor, ready)))
        .expect("same actor available")
        .expect("durable promotion pair stage");
    let staged = match staged {
        PausedCheckpointPromotionStageOutcome::Publish(staged) => *staged,
        other => panic!("new promotion must require publication: {other:?}"),
    };
    let published = publish_staged_paused_checkpoint_promotion(&prepared.checkpoints, staged)
        .expect("source-bound replay evidence publication outside actor");
    let checkpoint = published.promoted();
    prepared
        .actor
        .with_supervisor(|actor| {
            Ok(reconcile_published_paused_checkpoint_promotion(
                &prepared.checkpoints,
                actor,
                published,
            ))
        })
        .expect("same original actor")
        .expect("durable promoted root reconciliation");
    assert_ne!(raw, checkpoint);

    (
        AcceptedPromotion {
            checkpoint,
            request,
            prior_execution,
            baked,
        },
        worker,
    )
}

struct NativeCaptureModel<R> {
    inner: CrucibleExecutionModel<R>,
}

impl<R: crate::CrucibleExecutionRunner> AttemptExecutionModel for NativeCaptureModel<R> {
    type Error = <CrucibleExecutionModel<R> as AttemptExecutionModel>::Error;

    fn execute(
        &mut self,
        input: &crate::AttemptExecutionInput,
        context: &AttemptExecutionContext,
    ) -> Result<crate::AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        assert!(context.host_outer_cap_owner().is_some());
        extend_native_operations(context);
        self.inner.execute(input, context)
    }

    fn reconcile_execution(
        &mut self,
        disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
        self.inner.reconcile_execution(disposition)
    }
}

pub(super) fn extend_native_operations(context: &AttemptExecutionContext) {
    let supervisor = context
        .host_operation_supervisor()
        .expect("original admitted supervision");
    let (revision, mut budgets) = supervisor.budgets().expect("actual operation policy");
    for class in HostOperationClass::ALL {
        budgets.classes[class as usize] = HostOperationBudget::finite(Duration::from_secs(300));
    }
    supervisor
        .update_budgets(revision, budgets)
        .expect("live granular operation budgets");
}

#[test]
#[ignore = "requires isolated native paging VM, real project quotas and campaign assignment"]
fn production_accepted_checkpoint_promotion_has_genuine_resume_authority() {
    let source = paging_scenario();
    environment::with_native_repository_environment(
        "promotion",
        32_200,
        |root, storage| native_repository(&source, root, storage),
        fork_resources,
        |prepared, config, repository| {
            let promoted = promote_accepted_checkpoint(prepared, config, repository, &source);
            let selected = prepared
                .actor
                .with_supervisor(|actor| {
                    Ok(actor.select_reconciled_paused_checkpoint_root(
                        AttemptExecutionKey::for_request(&promoted.request),
                        promoted.checkpoint,
                    ))
                })
                .expect("same original actor")
                .expect("durable selection")
                .expect("genuine paused authority");
            assert!(selected.authorizes(promoted.checkpoint));
        },
    );
}
