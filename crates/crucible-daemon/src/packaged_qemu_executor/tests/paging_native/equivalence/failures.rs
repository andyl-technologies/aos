//! Atomic native failure, retry, and quarantine under genuine campaign ownership.
//!
//! Every case first publishes and promotes an accepted capture, then borrows
//! an actual resumed worker and an independent source Service. Failure
//! injection decorates real Linux ownership; it never grants cleanup authority.

// crucible-lint: allow panic-shortcut -- native acceptance assertions abort on invalid fixture evidence.
#![allow(clippy::expect_used)]

use super::super::super::hot_fork_native::assert_resource_charge;
use super::failure_guards::FinishFailingFactory;
use super::*;
use crate::packaged_qemu_executor::hot_fork::retained_service::RetainedTemplateService;
use crate::{
    AttemptExecutionDisposition, AttemptResultStageOutcome, AttemptWorkerReconcileOutcome,
    CompletionOutcome, PreparedAttemptWorkResult, QemuFreshModeledDriver,
    QemuHotForkWorldExecutionRunner, QemuProductionHotForkWorldLifecycleFactory,
    prepare_attempt_result, publish_prepared_attempt_result, reconcile_published_attempt_result,
    stage_prepared_attempt_result,
};
use crucible_api::host_operational::{HostOperationalError, HostResourceVector};
use crucible_api::vm_lifecycle::{
    hot_fork_adoption_count_for_test, reset_hot_fork_adoption_count_for_test,
};
use crucible_cas::content_store::{
    BackendCapabilities, BlobHandle, ByteRange, ContentId, ImmutableBlobBackend, ObjectKind,
    PutReceipt, StoreError, StorePhysicalQuotaGuard,
};
use rustix::event::{PollFd, PollFlags, poll};
use rustix::process::{Pid, PidfdFlags, Signal, kill_process, pidfd_open};
use rustix::time::Timespec;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Selects one actual atomic failure and its retained ownership assertions.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum NativeAtomicFailureCase {
    Fork,
    Preparation,
    Adoption,
    Cleanup,
    Publication,
}

impl NativeAtomicFailureCase {
    fn lane(self) -> &'static str {
        match self {
            Self::Fork => "atomic-fork",
            Self::Preparation => "atomic-preparation",
            Self::Adoption => "atomic-adoption",
            Self::Cleanup => "atomic-cleanup",
            Self::Publication => "atomic-publication",
        }
    }
}

/// Runs an atomic negative case against the reviewed native traffic world.
pub(crate) fn run(
    source: ScenarioDefForm,
    lifecycle: ProductionVmLifecycleConfig,
    case: NativeAtomicFailureCase,
) {
    let cpus = source
        .world()
        .vm_nodes()
        .iter()
        .map(|node| u64::from(node.smp_vcpus))
        .sum::<u64>();
    let publication = Arc::new(AtomicUsize::new(0));
    let catalog = environment::NativeCatalogBudget {
        resources: HostResourceVector {
            resident_peak_bytes: 512 << 20,
            backing_peak_bytes: 8 << 30,
            metadata_bytes: 256 << 20,
            staging_bytes: 32 << 20,
            paging_io_slots: 1,
            cpu_slots: 1,
            task_slots: 1,
            file_descriptors: 128,
        },
        // Respects the existing bounded inode cleanup contract.
        maximum_inodes: 1_048_576,
        installation_capacity: Some(
            ExecutorCapacity::new(
                1,
                u32::try_from(cpus * 4 + 2).expect("bounded full world CPUs"),
                32 << 30,
                64 << 30,
                150_000,
            )
            .expect("complete installation envelope"),
        ),
        installation_operational_capacity: Some(
            crate::HostOperationalCapacity::new(32, 4096, 65_536, 8 << 30, 2 << 30)
                .expect("full metadata envelope"),
        ),
    };
    environment::with_native_repository_environment_with_catalog(
        case.lane(),
        42_000 + (case as u32) * 100,
        catalog,
        |root, storage| {
            let refs = Arc::clone(&storage.refs);
            let original = native_repository(&source, root, storage);
            Arc::new(CampaignRepository::new(
                Arc::new(FailOnceObservationBackend {
                    inner: original.blob_backend(),
                    failures: Arc::clone(&publication),
                }),
                refs,
            ))
        },
        |config| resources(config, &source, &lifecycle, NativeEquivalenceCase::Depth),
        |prepared, config, repository| {
            run_accepted_failure(prepared, config, repository, &source, case, &publication)
        },
    );
}

type ResourceFactory = FinishFailingFactory<
    ComposedQemuAttemptResourceGuardFactory<LinuxQemuAttemptHostResourceFactory>,
>;
type Factory = QemuProductionHotForkWorldLifecycleFactory<
    QemuSingleHotForkSourceWorldProvider,
    ResourceFactory,
>;
type Runner = QemuHotForkWorldExecutionRunner<Factory, QemuFreshModeledDriver>;

struct FailureModel<'a> {
    prepared: &'a PackagedPreparation,
    config: PackagedQemuExecutorConfig,
    store: CampaignExecutorStore,
    checkpoint: ExactCheckpointId,
    boundary: BoundaryEvidence,
    case: NativeAtomicFailureCase,
    runner: Option<Runner>,
    service: Option<Arc<RetainedTemplateService>>,
    complete: bool,
    quarantined: bool,
}

fn run_accepted_failure(
    prepared: &PackagedPreparation,
    config: &PackagedQemuExecutorConfig,
    repository: Arc<CampaignRepository>,
    source: &ScenarioDefForm,
    case: NativeAtomicFailureCase,
    publication: &AtomicUsize,
) {
    let (promoted, mut capture) = promote_accepted_checkpoint_with_model(
        prepared,
        config,
        Arc::clone(&repository),
        source,
        |_host, store| CaptureModel {
            config: config.clone(),
            store,
            depth: 0,
            case: NativeEquivalenceCase::Depth,
            captured: None,
        },
    );
    let boundary = capture
        .model_mut()
        .captured
        .take()
        .expect("actually captured source boundary")
        .boundary;
    let before = available(prepared);
    let queued = enqueue_promoted_resume(
        prepared,
        &promoted,
        AssignmentId::from_bytes([0xe9; 16]).expect("distinct resumed assignment"),
    );
    let store = CampaignExecutorStore::new(Arc::clone(&repository));
    let mut worker = RepositoryAttemptWorker::new(
        store.clone(),
        FailureModel {
            prepared,
            config: config.clone(),
            store: store.clone(),
            checkpoint: promoted.checkpoint,
            boundary,
            case,
            runner: None,
            service: None,
            complete: false,
            quarantined: false,
        },
    );
    let work = worker.execute(queued);
    if case == NativeAtomicFailureCase::Publication {
        let PreparedAttemptWorkResult::Observation(result) =
            prepare_attempt_result(&store, &prepared.checkpoints, work)
                .expect("actual native observation candidate")
        else {
            panic!("publication retry must produce an observation");
        };
        let observation = result.observation();
        let staged = prepared
            .actor
            .with_supervisor(|actor| Ok(stage_prepared_attempt_result(actor, *result)))
            .expect("same actor staging")
            .expect("durable publication stage");
        let AttemptResultStageOutcome::Publish(staged) = staged else {
            panic!("new observation needs publication");
        };
        publication.store(1, Ordering::SeqCst);
        let retained = available(prepared);
        let authenticator = crate::exact_checkpoint_store::ExactFindingCheckpointAuthenticator::new(
            &store,
            &prepared.checkpoints,
        );
        let failure = publish_prepared_attempt_result(&store, &authenticator, staged)
            .expect_err("actual immutable observation placement fails once");
        assert!(failure.source.is_retryable());
        assert!(matches!(
            repository.load_observation(observation),
            Err(crucible_campaign::CampaignRepositoryError::NotFound)
        ));
        assert_eq!(
            available(prepared),
            retained,
            "publication failure must retain every resource dimension"
        );
        assert!(
            !worker
                .model_mut()
                .runner
                .as_mut()
                .expect("pending native runner")
                .factory_mut_for_test()
                .source_provider_mut_for_test()
                .available()
        );
        println!(
            "atomic-world phase=repository-publication-failure observation_visible=false source_reusable=false"
        );

        let published = publish_prepared_attempt_result(&store, &authenticator, failure.staged)
            .expect("idempotent exact publication retry");
        repository
            .load_observation(observation)
            .expect("only complete observation becomes visible");
        let reconciled = prepared
            .actor
            .with_supervisor(|actor| {
                Ok(reconcile_published_attempt_result::<_, _, ()>(
                    actor, published,
                ))
            })
            .expect("original actor reconciliation")
            .expect("durable result reconcile");
        assert_eq!(
            reconciled,
            AttemptWorkerReconcileOutcome::Reconciled {
                observation,
                completion: CompletionOutcome::Completed
            }
        );
        for _ in 0..64 {
            if worker
                .model_mut()
                .reconcile_execution(AttemptExecutionDisposition::Observation(observation))
                .expect("publication-ordered physical world reconciliation")
                == AttemptExecutionReconciliationStep::Complete
            {
                assert!(worker.model().complete);
                assert_eq!(
                    available(prepared),
                    before,
                    "full source and child vectors discharge only after physical cleanup"
                );
                println!(
                    "atomic-world phase=repository-publication-complete observation_visible=true source_reusable=true"
                );
                return;
            }
        }
        panic!("native publication retry did not reconcile within 64 steps");
    }

    let (queued, result) = work.into_parts();
    assert!(matches!(result, Err(AttemptWorkerFailure::Canceled(_))));
    assert!(worker.model().complete);
    if worker.model().quarantined {
        // No cleanup receipt exists for this failed aggregate. Keep the real
        // Execution and Service physically charged instead of marking them done.
        let held = available(prepared);
        assert!(
            worker
                .model()
                .service
                .as_ref()
                .expect("retained Service")
                .release_after_world_cleanup()
                .is_err()
        );
        assert_eq!(available(prepared), held);
        println!("atomic-world quarantine_full_resources_retained=true");
    } else {
        prepared
            .actor
            .with_supervisor(|actor| {
                actor
                    .stage_and_reconcile_cancellation(&queued)
                    .map_err(|_| HostOperationalError::Unavailable)
            })
            .expect("durable cancellation after actual native cleanup");
        assert_eq!(
            available(prepared),
            before,
            "all eight resource dimensions restored"
        );
    }
}

impl AttemptExecutionModel for FailureModel<'_> {
    type Error = std::io::Error;

    fn execute(
        &mut self,
        input: &AttemptExecutionInput,
        context: &AttemptExecutionContext,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        extend_native_operations(context);
        let input = decode_crucible_attempt_execution(&self.store, input)
            .expect("genuine resumed campaign basis");
        let source = input.scenario();
        let before_source = available(self.prepared);
        let mut selected = context.take_selected_checkpoint();
        let service = Arc::new(
            RetainedTemplateServiceFactory::new(self.prepared, &self.config)
                .start_for_resume(source, self.checkpoint, context, &mut selected)
                .expect("independent complete source Service"),
        );
        assert!(selected.is_none());
        assert_resource_charge(
            before_source,
            available(self.prepared),
            self.config
                .retained_template_resources()
                .expect("authored full source vector"),
        );
        assert_ne!(
            context.host_ram_owner_id(),
            service.context().host_ram_owner_id()
        );
        extend_native_operations(service.context());
        self.service = Some(service.clone());
        let mut source_factory = fresh_factory(&self.config, "source");
        let mut parent = source_factory
            .begin_resume(
                &self.prepared.checkpoints,
                self.checkpoint,
                crate::QemuExactResumeBasis::new(
                    &source.scenario_def(),
                    source,
                    &self.boundary.configuration,
                    None,
                ),
                service.context(),
            )
            .expect("actual source consumes authenticated exact root");
        let pending = drain_exact_pending(&mut parent);
        let boundary = capture_boundary_evidence(
            &mut parent,
            source,
            self.boundary.configuration.clone(),
            pending,
            topology(source),
        );
        assert_eq!(boundary, self.boundary);
        let census = self
            .prepared
            .checkpoints
            .native_ram_closure_census(
                self.checkpoint,
                service
                    .context()
                    .host_operation_supervisor()
                    .expect("live source Service cap"),
            )
            .expect("authenticated leased RAM closure census before failure injection");
        assert!(census.roots > 0 && census.pages > 0 && census.logical_bytes > 0);
        census.print_evidence(self.case.lane());
        let mut world = parent
            .prepare_hot_fork_source_world()
            .expect("complete source pause barriers")
            .with_cleanup_observer(service.clone());
        if self.case == NativeAtomicFailureCase::Preparation {
            let pid = source_pid(&world);
            let mut parent = world
                .recover()
                .expect("return actual source lifecycle for re-preparation");
            kill_and_wait(pid);
            let failure = match parent.prepare_hot_fork_source_world() {
                Ok(_) => panic!("dead source cannot expose a template"),
                Err(failure) => failure,
            };
            assert!(failure.unreconciled_nodes().is_empty());
            parent = failure
                .into_recovered_lifecycle()
                .expect("recover exact source failure authority");
            parent
                .shutdown()
                .expect("reap all source processes after failed preparation");
            service
                .release_after_world_cleanup()
                .expect("real source join and full-vector discharge");
            println!(
                "atomic-world phase=source-preparation-failure failed_source_pid={pid} public_template=false"
            );
            self.complete = true;
            context.cancellation().cancel();
            return Err(AttemptWorkerFailure::Canceled(std::io::Error::other(
                "native preparation negative completed",
            )));
        }
        if self.case == NativeAtomicFailureCase::Fork {
            let pid = source_pid(&world);
            kill_and_wait(pid);
        }
        if self.case == NativeAtomicFailureCase::Adoption {
            let second = second_live_node(&world);
            world
                .replace_immutable_root_for_test(
                    &second,
                    ContentHash::from_bytes(b"native-adoption-mismatch"),
                )
                .expect("inject only second adopted root binding");
        }
        let child_config =
            concurrent::world_config(&self.config, "child", 48_000 + (self.case as u32) * 100);
        let failures = Arc::new(AtomicUsize::new(usize::from(
            self.case == NativeAtomicFailureCase::Cleanup,
        )));
        let mut factory = child_factory(&child_config, &input, context, world, failures.clone());
        reset_hot_fork_adoption_count_for_test();
        let retained = available(self.prepared);
        if matches!(
            self.case,
            NativeAtomicFailureCase::Fork | NativeAtomicFailureCase::Adoption
        ) {
            let result = factory.try_start(&input, context);
            match self.case {
                NativeAtomicFailureCase::Fork => assert!(matches!(
                    result,
                    Err(AttemptWorkerFailure::Retryable(
                        crate::qemu_hot_fork_world_factory::QemuProductionHotForkWorldLifecycleFactoryError::Assembly(_)
                    ))
                )),
                NativeAtomicFailureCase::Adoption => assert!(matches!(
                    result,
                    Err(AttemptWorkerFailure::Terminal(
                        crate::qemu_hot_fork_world_factory::QemuProductionHotForkWorldLifecycleFactoryError::Lifecycle(_)
                    ))
                )),
                _ => unreachable!(),
            }
            assert_eq!(
                hot_fork_adoption_count_for_test(),
                usize::from(self.case == NativeAtomicFailureCase::Adoption)
            );
            assert!(!factory.source_provider_mut_for_test().available());
            assert_eq!(
                available(self.prepared),
                retained,
                "failed assembly cannot release the full source/child reservations"
            );
            self.quarantined = true;
            self.complete = true;
            if self.case == NativeAtomicFailureCase::Fork {
                println!("atomic-world phase=fork-failure-complete public_world=false");
            } else {
                println!(
                    "atomic-world phase=adoption-failure-complete adopted_before_failure=1 public_world=false"
                );
            }
            context.cancellation().cancel();
            return Err(AttemptWorkerFailure::Canceled(std::io::Error::other(
                "native assembly quarantined",
            )));
        }
        if self.case == NativeAtomicFailureCase::Publication {
            let mut runner = QemuHotForkWorldExecutionRunner::new(factory, QemuFreshModeledDriver);
            let outcome = runner
                .try_execute(&input, context)
                .map_err(|failure| failure.map(|error| std::io::Error::other(error.to_string())))?;
            let crate::qemu_hot_fork_world_factory::QemuHotForkWorldExecutionAttempt::Executed(
                outcome,
            ) = outcome
            else {
                panic!("actual source must not enter any fallback tier");
            };
            self.runner = Some(runner);
            return Ok(outcome.into_parts().0);
        }

        let mut child = match factory
            .try_start(&input, context)
            .expect("complete child world")
        {
            QemuHotForkWorldLifecycleStart::Started(child) => child,
            QemuHotForkWorldLifecycleStart::Declined => {
                panic!("actual selected source must not decline")
            }
        };
        assert!(!factory.source_provider_mut_for_test().available());
        child
            .shutdown()
            .expect("child process and source workers physically terminal");
        let mut failed = false;
        for _ in 0..64 {
            match child.reconcile_execution_disposition(AttemptExecutionDisposition::Canceled) {
                Ok(AttemptExecutionReconciliationStep::Progressed) => {}
                Ok(AttemptExecutionReconciliationStep::Complete) => {
                    panic!("cleanup completed before injected failure")
                }
                Err(_) => {
                    failed = true;
                    break;
                }
            }
        }
        assert!(failed);
        assert_eq!(failures.load(Ordering::SeqCst), 0);
        assert!(!factory.source_provider_mut_for_test().available());
        assert_eq!(
            available(self.prepared),
            retained,
            "failed cleanup retains complete vectors without becoming reusable"
        );
        println!(
            "atomic-world phase=target-cleanup-failure source_reusable=false retry_authority=true"
        );
        let mut completed = false;
        for _ in 0..64 {
            if child
                .reconcile_execution_disposition(AttemptExecutionDisposition::Canceled)
                .expect("retry uses same child cleanup authority")
                == AttemptExecutionReconciliationStep::Complete
            {
                completed = true;
                break;
            }
        }
        assert!(completed);
        assert!(factory.recover(child).is_ok());
        assert!(factory.source_provider_mut_for_test().available());
        assert!(cgroup_processes(child_config.host.cgroup_root()).is_empty());
        close_source(&mut factory, &service);
        self.complete = true;
        println!("atomic-world phase=target-cleanup-retry-complete source_reusable=true");
        context.cancellation().cancel();
        Err(AttemptWorkerFailure::Canceled(std::io::Error::other(
            "native cleanup retry completed",
        )))
    }

    fn reconcile_execution(
        &mut self,
        disposition: AttemptExecutionDisposition,
    ) -> Result<AttemptExecutionReconciliationStep, AttemptWorkerFailure<Self::Error>> {
        let runner = self
            .runner
            .as_mut()
            .expect("actual pending publication runner");
        let step = runner
            .reconcile_execution(disposition)
            .map_err(|failure| failure.map(|error| std::io::Error::other(error.to_string())))?;
        if step == AttemptExecutionReconciliationStep::Complete {
            let factory = runner.factory_mut_for_test();
            assert!(factory.source_provider_mut_for_test().available());
            close_source(
                factory,
                self.service.as_ref().expect("retained source Service"),
            );
            self.complete = true;
        }
        Ok(step)
    }
}

fn child_factory(
    config: &PackagedQemuExecutorConfig,
    input: &CrucibleAttemptExecution,
    context: &AttemptExecutionContext,
    world: ProductionVmHotForkSourceWorld,
    failures: Arc<AtomicUsize>,
) -> Factory {
    let key = QemuHotForkSourceWorldKey::for_execution(
        input,
        context,
        context.runtime_basis().expect("actual execution basis"),
    )
    .expect("exact source identity");
    let host = LinuxQemuAttemptHostResourceFactory::open(config.host.clone())
        .expect("actual disjoint child containment");
    QemuProductionHotForkWorldLifecycleFactory::new(
        QemuSingleHotForkSourceWorldProvider::new(key, world),
        FinishFailingFactory {
            inner: ComposedQemuAttemptResourceGuardFactory::new(host),
            failures,
        },
        config.lifecycle.run_state_root(),
        QemuShutdownPolicy {
            control_quit_wait: Duration::from_secs(30),
            qmp_quit_wait: Duration::from_secs(30),
            sigterm_wait: Duration::from_secs(30),
            sigkill_wait: Duration::from_secs(30),
            reap_wait: Duration::from_secs(30),
        },
        QemuAsyncDriverPolicy::new(
            Duration::from_secs(300),
            Duration::from_secs(300),
            Duration::from_secs(300),
            Duration::from_secs(300),
        ),
    )
}

fn close_source(factory: &mut Factory, service: &RetainedTemplateService) {
    let world = factory
        .source_provider_mut_for_test()
        .take_available()
        .expect("only reconciled source may be recovered");
    let mut parent = world.recover().expect("exact source lifecycle ownership");
    parent.shutdown().expect("source nodes physically reaped");
    service
        .release_after_world_cleanup()
        .expect("source watcher and all retained loans closed");
}

fn second_live_node(world: &ProductionVmHotForkSourceWorld) -> crucible::NodeId {
    world
        .continuation()
        .nodes()
        .iter()
        .filter(|node| node.process().is_some())
        .nth(1)
        .expect("actual second live native source node")
        .node()
        .clone()
}

fn source_pid(world: &ProductionVmHotForkSourceWorld) -> u32 {
    let second = second_live_node(world);
    world
        .continuation()
        .nodes()
        .iter()
        .find(|node| node.node() == &second)
        .and_then(|node| node.process())
        .expect("actual second live native source process")
        .process_id
}

fn kill_and_wait(process: u32) {
    let pid = Pid::from_raw(i32::try_from(process).expect("actual PID fits Linux PID"))
        .expect("positive PID");
    let pidfd = pidfd_open(pid, PidfdFlags::empty()).expect("exact process handle before failure");
    kill_process(pid, Signal::KILL).expect("inject native source death");
    let timeout = Timespec::try_from(Duration::from_secs(5)).expect("bounded death observation");
    let mut descriptors = [PollFd::new(&pidfd, PollFlags::IN)];
    assert_eq!(
        poll(&mut descriptors, Some(&timeout)).expect("observe actual terminal process"),
        1
    );
}

fn available(prepared: &PackagedPreparation) -> HostResourceVector {
    prepared
        .actor
        .with_supervisor(|actor| {
            actor
                .host_resource_availability()
                .ok_or(HostOperationalError::Unavailable)
        })
        .expect("all eight dimensions of the genuine actor ledger")
}

struct FailOnceObservationBackend {
    inner: Arc<dyn ImmutableBlobBackend>,
    failures: Arc<AtomicUsize>,
}

impl ImmutableBlobBackend for FailOnceObservationBackend {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn capabilities(&self) -> BackendCapabilities {
        self.inner.capabilities()
    }

    fn metadata_resources(&self) -> Result<Arc<dyn StorePhysicalQuotaGuard>, StoreError> {
        self.inner.metadata_resources()
    }

    fn admit_object_graph(&self, objects: &[(ObjectKind, u64)]) -> Result<(), StoreError> {
        self.inner.admit_object_graph(objects)
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
                .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |left| {
                    left.checked_sub(1)
                })
                .is_ok()
        {
            return Err(StoreError::Unavailable);
        }
        self.inner.put_if_absent(id, source)
    }
}
