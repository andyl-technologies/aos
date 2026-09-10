//! Fail-closed native child-fork and adoption acceptance cases.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use crucible::{Configuration, ContentHash};
use crucible_api::vm_lifecycle::{
    hot_fork_adoption_count_for_test, reset_hot_fork_adoption_count_for_test,
};
use crucible_campaign::DiscoveryRequest;
use rustix::event::{PollFd, PollFlags, poll};
use rustix::process::{Pid, PidfdFlags, Signal, kill_process, pidfd_open};
use rustix::time::Timespec;

use super::*;

struct FailOnceObservationBackend {
    inner: MemoryBlobBackend,
    failures: AtomicUsize,
}

impl FailOnceObservationBackend {
    fn new() -> Self {
        Self {
            inner: MemoryBlobBackend::new("native-atomic-world-publication", 64 * 1024 * 1024),
            failures: AtomicUsize::new(0),
        }
    }

    fn fail_next_observation(&self) {
        self.failures.store(1, Ordering::SeqCst);
    }
}

impl ImmutableBlobBackend for FailOnceObservationBackend {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.inner.contains(id)
    }

    fn read(&self, id: ContentId, range: Option<ByteRange>) -> Result<BlobHandle, StoreError> {
        self.inner.read(id, range)
    }

    fn put_if_absent(&self, id: ContentId, source: &BlobHandle) -> Result<PutReceipt, StoreError> {
        if id.kind() == ObjectKind::Observation
            && self
                .failures
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                    remaining.checked_sub(1)
                })
                .is_ok()
        {
            return Err(StoreError::Unavailable);
        }
        self.inner.put_if_absent(id, source)
    }
}

struct FinishFailingFactory<R> {
    inner: R,
    failures: Arc<AtomicUsize>,
}

struct FinishFailingGuard<G> {
    inner: G,
    failures: Arc<AtomicUsize>,
}

impl<R> QemuAttemptResourceGuardFactory for FinishFailingFactory<R>
where
    R: QemuAttemptResourceGuardFactory,
{
    type Guard = FinishFailingGuard<R::Guard>;

    fn begin(
        &mut self,
        resources: AttemptResourceLimits,
        cancellation: ExecutionCancellation,
    ) -> Result<Self::Guard, QemuVmRealizationError> {
        Ok(FinishFailingGuard {
            inner: self.inner.begin(resources, cancellation)?,
            failures: Arc::clone(&self.failures),
        })
    }
}

impl<G> QemuAttemptOperationalBoundary for FinishFailingGuard<G>
where
    G: QemuAttemptOperationalBoundary,
{
    fn resource_limits(&self) -> AttemptResourceLimits {
        self.inner.resource_limits()
    }

    fn cancellation(&self) -> &ExecutionCancellation {
        self.inner.cancellation()
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        self.inner.check_operational_boundary()
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        self.inner.charge_execution_quantum()
    }
}

impl<G> QemuAttemptResourceGuard for FinishFailingGuard<G>
where
    G: QemuAttemptResourceGuard,
{
    fn finish(&mut self) -> Result<(), QemuVmRealizationError> {
        if self
            .failures
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |remaining| {
                remaining.checked_sub(1)
            })
            .is_ok()
        {
            return Err(QemuVmRealizationError::Executor {
                operation: "finish native atomic-world target resources",
                message: String::from("injected target guard finish failure"),
            });
        }
        self.inner.finish()
    }

    fn quarantine(&mut self) {
        self.inner.quarantine();
    }
}

impl<G> QemuAttemptProcessResourceGuard for FinishFailingGuard<G>
where
    G: QemuAttemptProcessResourceGuard,
{
    fn child_process_contract(
        &self,
    ) -> Result<&crucible_qemu::QemuChildProcessContract, QemuVmRealizationError> {
        self.inner.child_process_contract()
    }

    fn prepare_generation_run_directory(
        &mut self,
        requirements: crucible_qemu::QemuLaunchResourceRequirements,
    ) -> Result<crucible_qemu::QemuPreparedRunDirectory, QemuVmRealizationError> {
        self.inner.prepare_generation_run_directory(requirements)
    }

    fn retain_failed_launch_child(&mut self, child: crucible_qemu::QemuNodeChild) {
        self.inner.retain_failed_launch_child(child);
    }
}

impl<G> crucible_qemu::QemuHotForkChildProcessOwner for FinishFailingGuard<G>
where
    G: crucible_qemu::QemuHotForkChildProcessOwner,
{
    type Authority = G::Authority;

    fn retain_hot_fork_child(
        &mut self,
        basis: crucible_qemu::QemuHotForkChildProcessBasis,
    ) -> Result<Self::Authority, crucible_qemu::QemuNodeChannelError> {
        self.inner.retain_hot_fork_child(basis)
    }
}

#[test]
#[ignore = "requires the packaged patched QEMU, cgroup v2, and project quotas"]
fn production_factory_exposes_no_world_when_second_real_fork_fails() {
    let paths = NativeGatePaths::from_environment();
    let prepared = prepare_native_source(&paths, "fork-failure", 0x72, 2_000);
    let failed_pid = prepared
        .world
        .continuation()
        .nodes()
        .iter()
        .find(|node| node.node().name == "nginx")
        .and_then(|node| node.process())
        .map(|identity| identity.process_id)
        .expect("nginx source process");
    let pid = Pid::from_raw(i32::try_from(failed_pid).expect("QEMU PID fits i32"))
        .expect("positive QEMU PID");
    kill_process(pid, Signal::KILL).expect("kill second running source process");
    std::thread::sleep(Duration::from_millis(50));

    let input = execution_input_for_scenario_configuration(prepared.source, prepared.configuration);
    let context = execution_context(&input, 0x73);
    let key =
        QemuHotForkSourceWorldKey::for_execution(&input, &context, execution_basis(&input, 0x73))
            .expect("derive exact source key");
    let provider = QemuSingleHotForkSourceWorldProvider::new(key, prepared.world);
    let target = open_host(&paths, "fork-failure-target", 2_100);
    let mut factory = QemuProductionHotForkWorldLifecycleFactory::new(
        provider,
        ComposedQemuAttemptResourceGuardFactory::new(target),
        paths.run_state_root.join("fork-failure").join("target"),
        crucible_qemu::QemuShutdownPolicy::fast_test(),
        crucible_qemu::QemuAsyncDriverPolicy::fast_test(),
    );

    reset_hot_fork_adoption_count_for_test();
    assert!(matches!(
        factory.try_start(&input, &context),
        Err(AttemptWorkerFailure::Retryable(
            QemuProductionHotForkWorldLifecycleFactoryError::Assembly(_)
        ))
    ));
    assert_eq!(hot_fork_adoption_count_for_test(), 0);
    assert!(!factory.sources().available());
    eprintln!(
        "atomic-world phase=fork-failure-complete failed_source_pid={failed_pid} public_world=false"
    );
}

#[test]
#[ignore = "requires the packaged patched QEMU, cgroup v2, and project quotas"]
fn production_source_preparation_failure_exposes_no_template() {
    let paths = NativeGatePaths::from_environment();
    let prepared = prepare_native_source(&paths, "preparation-failure", 0x7a, 5_500);
    let failed_pid = prepared
        .world
        .continuation()
        .nodes()
        .iter()
        .find(|node| node.node().name == "nginx")
        .and_then(|node| node.process())
        .map(|identity| identity.process_id)
        .expect("nginx source process");
    let mut lifecycle = prepared
        .world
        .recover()
        .expect("roll back the initially prepared source world");
    let pid = Pid::from_raw(i32::try_from(failed_pid).expect("QEMU PID fits i32"))
        .expect("positive QEMU PID");
    let pidfd = pidfd_open(pid, PidfdFlags::empty()).expect("open source process pidfd");
    kill_process(pid, Signal::KILL).expect("kill source before renewed preparation");
    let timeout = Timespec::try_from(Duration::from_secs(5)).expect("bounded pidfd timeout");
    let mut descriptors = [PollFd::new(&pidfd, PollFlags::IN)];
    assert_eq!(
        poll(&mut descriptors, Some(&timeout)).expect("observe source process death"),
        1,
        "source process did not become terminal within five seconds"
    );

    let failure = match lifecycle.prepare_hot_fork_source_world() {
        Ok(_) => panic!("dead source must reject complete-world preparation"),
        Err(failure) => failure,
    };
    assert!(failure.unreconciled_nodes().is_empty());
    lifecycle = failure
        .into_recovered_lifecycle()
        .expect("preparation failure retains recoverable lifecycle authority");
    QemuFreshAttemptLifecycleOwner::shutdown(&mut lifecycle)
        .expect("reap preparation-failure source world");

    eprintln!(
        "atomic-world phase=source-preparation-failure failed_source_pid={failed_pid} public_template=false"
    );
}

#[test]
#[ignore = "requires the packaged patched QEMU, cgroup v2, and project quotas"]
fn production_factory_exposes_no_world_when_second_real_adoption_fails() {
    let paths = NativeGatePaths::from_environment();
    let mut prepared = prepare_native_source(&paths, "adoption-failure", 0x74, 3_000);
    prepared
        .world
        .replace_immutable_root_for_test(
            &NodeId {
                name: String::from("nginx"),
            },
            ContentHash::from_bytes(b"native-adoption-mismatch"),
        )
        .expect("inject second-child immutable-root mismatch");

    let input = execution_input_for_scenario_configuration(prepared.source, prepared.configuration);
    let context = execution_context(&input, 0x75);
    let key =
        QemuHotForkSourceWorldKey::for_execution(&input, &context, execution_basis(&input, 0x75))
            .expect("derive exact source key");
    let provider = QemuSingleHotForkSourceWorldProvider::new(key, prepared.world);
    let target = open_host(&paths, "adoption-failure-target", 3_100);
    let mut factory = QemuProductionHotForkWorldLifecycleFactory::new(
        provider,
        ComposedQemuAttemptResourceGuardFactory::new(target),
        paths.run_state_root.join("adoption-failure").join("target"),
        crucible_qemu::QemuShutdownPolicy::fast_test(),
        crucible_qemu::QemuAsyncDriverPolicy::fast_test(),
    );

    reset_hot_fork_adoption_count_for_test();
    assert!(matches!(
        factory.try_start(&input, &context),
        Err(AttemptWorkerFailure::Terminal(
            QemuProductionHotForkWorldLifecycleFactoryError::Lifecycle(_)
        ))
    ));
    assert_eq!(hot_fork_adoption_count_for_test(), 1);
    assert!(!factory.sources().available());
    eprintln!(
        "atomic-world phase=adoption-failure-complete adopted_before_failure=1 public_world=false"
    );
}

#[test]
#[ignore = "requires the packaged patched QEMU, cgroup v2, and project quotas"]
fn production_factory_keeps_source_private_until_target_cleanup_retries() {
    let paths = NativeGatePaths::from_environment();
    let prepared = prepare_native_source(&paths, "cleanup-retry", 0x76, 4_000);
    let input = execution_input_for_scenario_configuration(prepared.source, prepared.configuration);
    let context = execution_context(&input, 0x77);
    let key =
        QemuHotForkSourceWorldKey::for_execution(&input, &context, execution_basis(&input, 0x77))
            .expect("derive exact source key");
    let provider = QemuSingleHotForkSourceWorldProvider::new(key, prepared.world);
    let target = open_host(&paths, "cleanup-retry-target", 4_100);
    let failures = Arc::new(AtomicUsize::new(1));
    let resources = FinishFailingFactory {
        inner: ComposedQemuAttemptResourceGuardFactory::new(target),
        failures: Arc::clone(&failures),
    };
    let mut factory = QemuProductionHotForkWorldLifecycleFactory::new(
        provider,
        resources,
        paths.run_state_root.join("cleanup-retry").join("target"),
        crucible_qemu::QemuShutdownPolicy::fast_test(),
        crucible_qemu::QemuAsyncDriverPolicy::fast_test(),
    );
    let mut lifecycle = match factory
        .try_start(&input, &context)
        .expect("assemble complete child world")
    {
        QemuHotForkWorldLifecycleStart::Started(lifecycle) => lifecycle,
        QemuHotForkWorldLifecycleStart::Declined => panic!("prepared source was declined"),
    };
    assert!(!factory.sources().available());
    QemuFreshAttemptLifecycleOwner::shutdown(&mut lifecycle).expect("shutdown child world");

    let mut observed_failure = false;
    for _ in 0..64 {
        match lifecycle.reconcile_execution_disposition(AttemptExecutionDisposition::Canceled) {
            Ok(AttemptExecutionReconciliationStep::Progressed) => {}
            Ok(AttemptExecutionReconciliationStep::Complete) => {
                panic!("target cleanup completed before the injected failure")
            }
            Err(_) => {
                observed_failure = true;
                break;
            }
        }
    }
    assert!(observed_failure);
    assert_eq!(failures.load(Ordering::SeqCst), 0);
    assert!(!factory.sources().available());
    eprintln!(
        "atomic-world phase=target-cleanup-failure source_reusable=false retry_authority=true"
    );

    reconcile_native_world(&mut lifecycle);
    assert!(factory.recover(lifecycle).is_ok());
    assert!(factory.sources().available());
    eprintln!("atomic-world phase=target-cleanup-retry-complete source_reusable=true");
}

#[test]
#[ignore = "requires the packaged patched QEMU, cgroup v2, and project quotas"]
fn production_factory_keeps_source_private_across_repository_publication_retry() {
    let paths = NativeGatePaths::from_environment();
    let prepared = prepare_native_source(&paths, "publication-failure", 0x78, 5_000);
    let publication = Arc::new(FailOnceObservationBackend::new());
    let (repository, store, lineage, attempt) = publication_campaign(
        Arc::clone(&publication),
        &prepared.source,
        &prepared.configuration,
    );
    let key = QemuHotForkSourceWorldKey::new(
        lineage.id().expect("publication lineage"),
        prepared.source.scenario_def().id(),
        prepared.configuration.id(),
        ExecutorCompatibilityProfile::from_lineage(&lineage),
    );
    let provider = QemuSingleHotForkSourceWorldProvider::new(key, prepared.world);
    let target = open_host(&paths, "publication-failure-target", 5_100);
    let factory = QemuProductionHotForkWorldLifecycleFactory::new(
        provider,
        ComposedQemuAttemptResourceGuardFactory::new(target),
        paths
            .run_state_root
            .join("publication-failure")
            .join("target"),
        crucible_qemu::QemuShutdownPolicy::fast_test(),
        crucible_qemu::QemuAsyncDriverPolicy::fast_test(),
    );
    let runner = QemuHotForkWorldExecutionRunner::new(factory, QemuFreshModeledDriver);
    let fallback_calls = Arc::new(AtomicUsize::new(0));
    let router = QemuHotFirstExecutionRouter::new(
        runner,
        NeverFallbackRunner {
            calls: Arc::clone(&fallback_calls),
        },
    );
    let model = CrucibleExecutionModel::new(store.clone(), router);
    let mut worker = RepositoryAttemptWorker::new(store.clone(), model);
    let profile = ExecutorCompatibilityProfile::from_lineage(&lineage);
    let epoch = DaemonEpoch::from_bytes([0x78; 16]).expect("publication daemon epoch");
    let resources =
        AttemptResourceLimits::new(8, 8 << 30, 8 << 30, 64).expect("publication attempt resources");
    let request = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x79; 16]).expect("publication assignment"),
        epoch,
        lineage.id().expect("publication lineage"),
        attempt,
        resources,
        ExecutionRetentionIntent::Discard,
    )
    .expect("publication submission");
    let admission = RepositoryAttemptAdmission::new(Arc::clone(&repository), profile);
    let mut supervisor = LocalExecutorSupervisor::new(
        MemoryAssignmentLedger::default(),
        admission,
        epoch,
        ExecutorCapacity::new(1, 8, 8 << 30, 8 << 30, 64).expect("publication executor capacity"),
    );
    let submitted = ExecutorService::submit_attempt(&mut supervisor, &request)
        .expect("submit publication attempt");
    assert!(matches!(
        submitted.disposition(),
        SubmitAttemptDisposition::Accepted { .. }
    ));
    let queued = supervisor
        .next_queued()
        .expect("queued publication attempt");

    let work = worker.execute(queued);
    let checkpoints = ExactCheckpointStore::new(
        Arc::new(TestDurableCheckpointBackend::new()),
        8 * 1024 * 1024,
    )
    .expect("publication checkpoint store");
    let prepared = prepare_attempt_result(&store, &checkpoints, work)
        .expect("prepare native publication result");
    let PreparedAttemptWorkResult::Observation(prepared) = prepared else {
        panic!("native publication execution returned an unexpected checkpoint")
    };
    let observation = prepared.observation();
    assert_eq!(fallback_calls.load(Ordering::SeqCst), 0);
    assert!(
        !worker
            .model()
            .runner()
            .hot_fork()
            .lifecycle_factory()
            .sources()
            .available()
    );

    let staged = stage_prepared_attempt_result(&mut supervisor, *prepared)
        .expect("stage native publication result");
    let AttemptResultStageOutcome::Publish(staged) = staged else {
        panic!("native publication result must require immutable publication")
    };
    publication.fail_next_observation();
    let failure = publish_prepared_attempt_result(&store, staged)
        .expect_err("inject repository observation publication failure");
    assert!(failure.source.is_retryable());
    assert!(matches!(
        repository.load_observation(observation),
        Err(crucible_campaign::CampaignRepositoryError::NotFound)
    ));
    assert!(
        !worker
            .model()
            .runner()
            .hot_fork()
            .lifecycle_factory()
            .sources()
            .available()
    );
    eprintln!(
        "atomic-world phase=repository-publication-failure observation_visible=false source_reusable=false"
    );

    let published = publish_prepared_attempt_result(&store, failure.staged)
        .expect("retry exact native publication");
    repository
        .load_observation(observation)
        .expect("load retried native observation");
    let reconciled = reconcile_published_attempt_result::<_, _, ()>(&mut supervisor, published)
        .expect("reconcile native publication");
    assert_eq!(
        reconciled,
        AttemptWorkerReconcileOutcome::Reconciled {
            observation,
            completion: CompletionOutcome::Completed,
        }
    );
    for _ in 0..64 {
        if LocalAttemptWorker::reconcile_execution(
            &mut worker,
            AttemptExecutionDisposition::Observation(observation),
        )
        .expect("reconcile native published world")
            == AttemptExecutionReconciliationStep::Complete
        {
            assert!(
                worker
                    .model()
                    .runner()
                    .hot_fork()
                    .lifecycle_factory()
                    .sources()
                    .available()
            );
            eprintln!(
                "atomic-world phase=repository-publication-complete observation_visible=true source_reusable=true"
            );
            return;
        }
    }
    panic!("native published child world did not reconcile within 64 steps");
}

fn publication_campaign(
    backend: Arc<FailOnceObservationBackend>,
    scenario: &ScenarioDefForm,
    configuration: &Configuration,
) -> (
    Arc<CampaignRepository>,
    CampaignExecutorStore,
    CampaignLineage,
    crucible_campaign::AttemptId,
) {
    const CAMPAIGN: &str = "native-atomic-world-publication";

    let repository = Arc::new(CampaignRepository::new(
        backend,
        Arc::new(MemoryRefBackend::new()),
    ));
    let scenario_artifact =
        encode_crucible_scenario_artifact(scenario).expect("encode publication scenario");
    let scenario_content = repository
        .publish_scenario_artifact(
            scenario_artifact.scenario(),
            scenario_artifact.payload_schema(),
            scenario_artifact.payload().to_vec(),
        )
        .expect("publish publication scenario");
    let configuration_artifact =
        encode_crucible_configuration_artifact(&scenario_artifact, &configuration.schedule)
            .expect("encode publication configuration");
    let configuration_content = repository
        .publish_configuration_artifact(
            configuration_artifact.scenario(),
            configuration_artifact.scenario_artifact(),
            configuration_artifact.configuration(),
            configuration_artifact.payload_schema(),
            configuration_artifact.payload().to_vec(),
        )
        .expect("publish publication configuration");
    let lineage = CampaignLineage::new(
        scenario_artifact.scenario(),
        scenario_content,
        configuration_artifact.configuration(),
        configuration_content,
        "crucible-test",
        "qemu-test",
        BTreeMap::from([(String::from("control"), 1)]),
        scenario_artifact.payload_schema(),
        1,
    )
    .expect("publication lineage");
    let widening = ProgressiveWideningPolicy::new(
        ExactRational::new(1, 1).expect("publication widening numerator"),
        ExactRational::new(1, 2).expect("publication widening exponent"),
        1,
        100,
        1,
    )
    .expect("publication widening policy");
    let policy = CampaignPolicy::new(
        scenario_artifact.scenario(),
        CampaignSeed::from_bytes([0x78; 32]),
        CampaignMode::Strict,
        ExplorerPolicy::TreeSearch {
            widening: Some(widening),
            puct: PuctPolicy::new(1_000_000, 1, 0),
        },
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeMap::new(),
        BTreeSet::new(),
        FairnessPolicy::new(0, 0).expect("publication fairness policy"),
        RetentionPolicy::new(true, 1, true, true),
        true,
    )
    .expect("publication campaign policy");
    let created = repository
        .create(CAMPAIGN, &lineage, &policy, &BTreeMap::new())
        .expect("create publication campaign");
    repository
        .apply_control(
            CAMPAIGN,
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "crucible.test.native-atomic-world-publication.budget.v1",
                    b"budget",
                )),
                expected_snapshot: created.snapshot_id(),
                action: CampaignControlAction::GrantBudget(
                    BudgetGrant::new(0, 1).expect("publication attempt budget"),
                ),
            },
        )
        .expect("fund publication campaign");
    let funded = repository.head(CAMPAIGN).expect("funded publication head");
    repository
        .apply_control(
            CAMPAIGN,
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "crucible.test.native-atomic-world-publication.resume.v1",
                    b"resume",
                )),
                expected_snapshot: funded.snapshot_id(),
                action: CampaignControlAction::Resume,
            },
        )
        .expect("resume publication campaign");
    let running = repository.head(CAMPAIGN).expect("running publication head");
    let request = DiscoveryRequest::new(
        CampaignCommandId::from_hash(CampaignHash::derive(
            "crucible.test.native-atomic-world-publication.discovery.v1",
            b"discover",
        )),
        running.snapshot_id(),
        configuration_content,
        StopCondition::EventCount(1),
    )
    .expect("publication discovery request");
    let discovered = repository
        .submit_discovery_request(CAMPAIGN, &request)
        .expect("admit publication discovery");
    let store = CampaignExecutorStore::new(Arc::clone(&repository));

    (repository, store, lineage, discovered.attempt)
}
