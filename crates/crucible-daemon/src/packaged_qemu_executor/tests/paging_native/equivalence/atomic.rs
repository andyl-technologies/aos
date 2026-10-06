//! Genuine mixed-state atomic worlds and real branch-file rejection.
//!
//! The original accepted worker captures the traffic and permanent-failure
//! boundary before reap. A separately charged Service consumes that promoted
//! root, and a real resumed worker owns the complete fresh-child allocation.

// crucible-lint: allow panic-shortcut -- native assertions reject incomplete physical evidence.
#![allow(clippy::expect_used)]

mod isolation;

use super::invalid_files::{ChildFileFault, InvalidChildFileFactory};
use super::*;
use crate::AttemptExecutionDisposition;
use crucible::{
    AssertionId, AssertionPhase, ObservableEventPayload, SchedulerEventLogPayload,
    SchedulingNodeKind,
};
use crucible_api::vm_lifecycle::{
    hot_fork_adoption_count_for_test, reset_hot_fork_adoption_count_for_test,
};
use crucible_campaign::SubmitAttemptDisposition;
use crucible_qemu::linux_process_identity;
use std::collections::BTreeMap;
use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};

/// Selects real mixed-world success or a corrupt pre-provisioned file roster.
#[derive(Clone, Copy)]
pub(crate) enum NativeAtomicWorldCase {
    Complete,
    Missing,
    Aliased,
    Idle,
    Isolation,
}

impl NativeAtomicWorldCase {
    fn lane(self) -> &'static str {
        match self {
            Self::Complete => "atomic-complete",
            Self::Missing => "atomic-file-omission",
            Self::Aliased => "atomic-file-alias",
            Self::Idle => "atomic-idle-prefix",
            Self::Isolation => "atomic-isolation",
        }
    }

    fn fault(self) -> Option<ChildFileFault> {
        match self {
            Self::Complete | Self::Idle | Self::Isolation => None,
            Self::Missing => Some(ChildFileFault::Missing),
            Self::Aliased => Some(ChildFileFault::Aliased),
        }
    }
}

/// Runs the reviewed traffic world under accepted original ownership.
pub(crate) fn run(
    source: ScenarioDefForm,
    lifecycle: ProductionVmLifecycleConfig,
    case: NativeAtomicWorldCase,
) {
    let cpus = source
        .world()
        .vm_nodes()
        .iter()
        .map(|node| u64::from(node.smp_vcpus))
        .sum::<u64>();
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
                u32::try_from(cpus * 4 + 2).expect("full world CPUs"),
                32 << 30,
                64 << 30,
                150_000,
            )
            .expect("complete installation envelope"),
        ),
        installation_operational_capacity: Some(
            crate::HostOperationalCapacity::new(32, 4096, 65_536, 8 << 30, 2 << 30)
                .expect("complete metadata envelope"),
        ),
    };
    environment::with_native_repository_environment_with_catalog(
        case.lane(),
        52_000 + (case as u32) * 100,
        catalog,
        |root, storage| native_repository(&source, root, storage),
        |config| resources(config, &source, &lifecycle, NativeEquivalenceCase::Depth),
        |prepared, config, repository| run_accepted(prepared, config, repository, &source, case),
    );
}

struct MixedBoundary {
    configuration: Configuration,
    fingerprints: BTreeMap<crucible::NodeId, crucible::FingerprintSample>,
    faults: crucible_api::ProductionFaultEvidenceSnapshot,
}

struct CaptureMixedWorld {
    config: PackagedQemuExecutorConfig,
    store: CampaignExecutorStore,
    captured: Option<MixedBoundary>,
}

impl AttemptExecutionModel for CaptureMixedWorld {
    type Error = std::io::Error;

    fn execute(
        &mut self,
        input: &AttemptExecutionInput,
        context: &AttemptExecutionContext,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        extend_native_operations(context);
        let input = decode_crucible_attempt_execution(&self.store, input)
            .expect("accepted mixed-world basis");
        let source = input.scenario();
        let mut factory = fresh_factory(&self.config, "capture");
        let mut world = factory
            .begin_fresh(&source.scenario_def(), source, context)
            .expect("actual admitted source");
        let mut configuration = Configuration::genesis(source.scenario_def());
        let mut milestones = [false; 4];
        for _ in 0..MAX_SOURCE_QUANTA {
            context
                .charge_execution_quantum()
                .expect("original native quantum ceiling");
            let outcome = world
                .drive_quantum(QuantumRequest {
                    configuration,
                    control: Vec::new(),
                })
                .expect("drive reviewed traffic world");
            for (observed, assertion) in milestones.iter_mut().zip([
                "curl-receives-http-200",
                "curl-block-read-complete",
                "io-probe-complete",
                "io-probe-fault-observed",
            ]) {
                *observed |= satisfied(&outcome.event_log_entries, assertion);
            }
            configuration = outcome.configuration;
            let evidence = world
                .fault_evidence_snapshot()
                .expect("actual source fault boundary");
            let failed = evidence.nodes.iter().any(|node| {
                node.node.name == "nginx" && node.service_state == "permanently_failed"
            });
            if milestones.into_iter().all(|observed| observed) && failed {
                break;
            }
        }
        assert!(
            milestones.into_iter().all(|observed| observed),
            "source must prove HTTP, block, 9p and injected 9p failure"
        );
        assert!(
            world
                .exact_checkpoint_ready()
                .expect("coherent mixed-state boundary")
        );
        let capture = world
            .capture_attempt_checkpoint(context)
            .expect("actual whole-world candidate");
        let staged = context
            .prepare_and_stage_checkpoint(capture)
            .expect("original actor stages exact root before native reap");
        let boundary = mixed_boundary(&mut world, configuration);
        assert_eq!(
            boundary
                .faults
                .nodes
                .iter()
                .filter(|node| node.service_state == "permanently_failed")
                .count(),
            1
        );
        world
            .shutdown()
            .expect("original accepted source physically reaped");
        self.captured = Some(boundary);
        Ok(AttemptExecutionProduct::exact_checkpoint(staged))
    }
}

fn mixed_boundary(
    world: &mut impl QemuFreshAttemptLifecycleOwner,
    configuration: Configuration,
) -> MixedBoundary {
    let faults = world
        .fault_evidence_snapshot()
        .expect("mixed state fault evidence");
    let fingerprints = faults
        .nodes
        .iter()
        .filter(|node| node.service_state == "running")
        .map(|node| {
            let id = node.node.clone();
            let sample = world
                .sample_fingerprint(id.clone())
                .expect("running source fingerprint");
            (id, sample)
        })
        .collect::<BTreeMap<_, _>>();
    assert_eq!(fingerprints.len(), 2);
    MixedBoundary {
        configuration,
        fingerprints,
        faults,
    }
}

fn run_accepted(
    prepared: &PackagedPreparation,
    config: &PackagedQemuExecutorConfig,
    repository: Arc<CampaignRepository>,
    source: &ScenarioDefForm,
    case: NativeAtomicWorldCase,
) {
    if matches!(case, NativeAtomicWorldCase::Idle) {
        run_idle(prepared, config, repository);
        return;
    }
    let (promoted, mut capture) = promote_accepted_checkpoint_with_model(
        prepared,
        config,
        Arc::clone(&repository),
        source,
        |_host, store| CaptureMixedWorld {
            config: config.clone(),
            store,
            captured: None,
        },
    );
    let boundary = capture
        .model_mut()
        .captured
        .take()
        .expect("captured actual mixed boundary");
    let before = available_resources(prepared);
    let queued = enqueue_promoted_resume(
        prepared,
        &promoted,
        AssignmentId::from_bytes([0xc6; 16]).expect("actual resumed assignment"),
    );
    let store = CampaignExecutorStore::new(repository);
    let mut worker = RepositoryAttemptWorker::new(
        store.clone(),
        MixedResume {
            prepared,
            config: config.clone(),
            store,
            checkpoint: promoted.checkpoint,
            boundary,
            case,
            completed: false,
        },
    );
    let (queued, result) = worker.execute(queued).into_parts();
    assert!(matches!(result, Err(AttemptWorkerFailure::Canceled(_))));
    assert!(worker.model().completed);
    prepared
        .actor
        .with_supervisor(|actor| {
            actor
                .stage_and_reconcile_cancellation(&queued)
                .map_err(|_| crucible_api::host_operational::HostOperationalError::Unavailable)
        })
        .expect("durable cancellation after source and child physical closure");
    assert_eq!(
        available_resources(prepared),
        before,
        "all eight dimensions discharge only after native closure"
    );
}

struct MixedResume<'a> {
    prepared: &'a PackagedPreparation,
    config: PackagedQemuExecutorConfig,
    store: CampaignExecutorStore,
    checkpoint: ExactCheckpointId,
    boundary: MixedBoundary,
    case: NativeAtomicWorldCase,
    completed: bool,
}

impl AttemptExecutionModel for MixedResume<'_> {
    type Error = std::io::Error;

    fn execute(
        &mut self,
        input: &AttemptExecutionInput,
        context: &AttemptExecutionContext,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        extend_native_operations(context);
        let input = decode_crucible_attempt_execution(&self.store, input)
            .expect("actual resumed mixed-world basis");
        let source = input.scenario();
        let before = available_resources(self.prepared);
        let mut selected = context.take_selected_checkpoint();
        let service = Arc::new(
            RetainedTemplateServiceFactory::new(self.prepared, &self.config)
                .start_for_resume(source, self.checkpoint, context, &mut selected)
                .expect("independent source Service consumes genuine selected claim"),
        );
        assert!(selected.is_none());
        assert_template_charge(
            self.prepared,
            before,
            self.config
                .retained_template_resources()
                .expect("authored source vector"),
            1,
        );
        extend_native_operations(service.context());
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
            .expect("authenticated complete mixed-state restore");
        let restored = mixed_boundary(&mut parent, self.boundary.configuration.clone());
        assert_eq!(restored.faults, self.boundary.faults);
        assert_eq!(restored.fingerprints, self.boundary.fingerprints);
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
            .expect("authenticated leased RAM closure census before source teardown");
        assert_eq!(census.roots, 2);
        assert!(census.pages > 0 && census.logical_bytes > 0 && census.object_reads > 0);
        census.print_evidence(self.case.lane());
        let world = parent
            .prepare_hot_fork_source_world()
            .expect("complete actual pause boundary")
            .with_cleanup_observer(service.clone());
        let running = assert_mixed_continuation(&world, &self.boundary.configuration);
        let source_processes = world
            .continuation()
            .nodes()
            .iter()
            .filter_map(|node| node.process().cloned())
            .collect::<Vec<_>>();
        assert_eq!(source_processes.len(), 2);
        if matches!(self.case, NativeAtomicWorldCase::Isolation) {
            isolation::run(self, world, service, before, &source_processes);
            context.cancellation().cancel();
            return Err(AttemptWorkerFailure::Canceled(std::io::Error::other(
                "actual seven-source isolation assertions completed",
            )));
        }
        let child_config =
            concurrent::world_config(&self.config, "child", 55_000 + (self.case as u32) * 100);
        let key = QemuHotForkSourceWorldKey::for_execution(
            &input,
            context,
            context.runtime_basis().expect("genuine runtime basis"),
        )
        .expect("exact accepted source identity");
        let host = LinuxQemuAttemptHostResourceFactory::open(child_config.host.clone())
            .expect("actual private child containment");
        let injected = Arc::new(AtomicUsize::new(0));
        let mut factory = QemuProductionHotForkWorldLifecycleFactory::new(
            QemuSingleHotForkSourceWorldProvider::new(key, world),
            InvalidChildFileFactory {
                inner: ComposedQemuAttemptResourceGuardFactory::new(host),
                fault: self.case.fault(),
                injected_files: injected.clone(),
            },
            child_config.lifecycle.run_state_root(),
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
        );
        reset_hot_fork_adoption_count_for_test();
        let started = operational_monotonic_nanoseconds();
        if let Some(fault) = self.case.fault() {
            let failure = match factory.try_start(&input, context) {
                Err(failure) => failure,
                Ok(_) => panic!("corrupt child file exposed a world"),
            };
            let AttemptWorkerFailure::Retryable(crate::qemu_hot_fork_world_factory::QemuProductionHotForkWorldLifecycleFactoryError::Assembly(message)) = failure else { panic!("wrong corrupt-file failure class") };
            let expected = match fault {
                ChildFileFault::Missing => "requires pre-provisioned device-state container",
                ChildFileFault::Aliased => "prepared device-state identity changed",
            };
            assert!(message.contains(expected), "wrong rejection: {message}");
            assert_eq!(injected.load(Ordering::SeqCst), 2);
            assert_eq!(hot_fork_adoption_count_for_test(), 0);
            assert!(factory.source_provider_mut_for_test().available());
            assert!(cgroup_processes(child_config.host.cgroup_root()).is_empty());
            for process in source_processes {
                assert_eq!(
                    linux_process_identity(process.process_id)
                        .expect("source identity lookup")
                        .expect("native source survives rejection"),
                    process
                );
            }
            println!(
                "native_real_resource_{}=child-vmstate-destination",
                fault.label()
            );
            println!("native_real_resource_{}_nodes=2", fault.label());
            println!(
                "native_real_resource_{}_rejected_before=child-readiness,world-publication",
                fault.label()
            );
            println!(
                "native_real_resource_{}_source_unchanged=true",
                fault.label()
            );
        } else {
            let mut child = match factory
                .try_start(&input, context)
                .expect("complete atomic child admission")
            {
                QemuHotForkWorldLifecycleStart::Started(child) => child,
                QemuHotForkWorldLifecycleStart::Declined => panic!("actual source was declined"),
            };
            assert!(!factory.source_provider_mut_for_test().available());
            assert_eq!(hot_fork_adoption_count_for_test(), 2);
            inspect_positive_child(
                &mut child,
                &child_config,
                &self.boundary.configuration,
                &running,
                Duration::from_nanos(
                    operational_monotonic_nanoseconds()
                        .checked_sub(started)
                        .expect("monotonic child readiness sample"),
                ),
            );
            child.shutdown().expect("actual child physical shutdown");
            let mut complete = false;
            for _ in 0..64 {
                if child
                    .reconcile_execution_disposition(AttemptExecutionDisposition::Canceled)
                    .expect("actual child disposition")
                    == AttemptExecutionReconciliationStep::Complete
                {
                    complete = true;
                    break;
                }
            }
            assert!(complete);
            assert!(factory.recover(child).is_ok());
            assert!(factory.source_provider_mut_for_test().available());
            assert!(cgroup_processes(child_config.host.cgroup_root()).is_empty());
        }
        let world = factory
            .source_provider_mut_for_test()
            .take_available()
            .expect("only reconciled source recovered");
        let mut parent = world.recover().expect("actual retained source lifecycle");
        parent
            .shutdown()
            .expect("mixed source processes physically reaped");
        service
            .release_after_world_cleanup()
            .expect("source workers, registry leases and watchdog terminal");
        assert_eq!(available_resources(self.prepared), before);
        self.completed = true;
        context.cancellation().cancel();
        Err(AttemptWorkerFailure::Canceled(std::io::Error::other(
            "actual mixed-world atomic assertions completed",
        )))
    }
}

fn assert_mixed_continuation(
    world: &ProductionVmHotForkSourceWorld,
    configuration: &Configuration,
) -> Vec<crucible::NodeId> {
    let continuation = world.continuation();
    assert_eq!(continuation.configuration(), configuration);
    assert_eq!(continuation.nodes().len(), 3);
    let running = continuation
        .nodes()
        .iter()
        .filter(|node| node.service_state() == ProductionVmHotForkNodeServiceState::Running)
        .map(|node| node.node().clone())
        .collect::<Vec<_>>();
    assert_eq!(running.len(), 2);
    assert_eq!(
        continuation
            .nodes()
            .iter()
            .filter(|node| node.service_state()
                == ProductionVmHotForkNodeServiceState::PermanentlyFailed)
            .count(),
        1
    );
    assert!(
        continuation
            .io_nodes()
            .iter()
            .any(|node| node.kind() == ProductionVmHotForkIoNodeKind::Block
                && node.owner_service_state() == ProductionVmHotForkNodeServiceState::Running)
    );
    assert!(
        continuation
            .io_nodes()
            .iter()
            .any(|node| node.kind() == ProductionVmHotForkIoNodeKind::NineP
                && node.owner_service_state() == ProductionVmHotForkNodeServiceState::Running)
    );
    running
}

fn inspect_positive_child<G: crate::QemuAttemptProcessResourceGuard>(
    lifecycle: &mut crate::QemuProductionHotForkWorldLifecycle<G>,
    config: &PackagedQemuExecutorConfig,
    configuration: &Configuration,
    running_nodes: &[crucible::NodeId],
    elapsed: Duration,
) {
    let child_ready_millis = elapsed.as_millis();
    let materialization = lifecycle
        .start_materialization()
        .expect("actual child initial materialization");
    let child_processes = cgroup_processes(config.host.cgroup_root());
    assert_eq!(child_processes.len(), 2, "two live target QEMU processes");
    let child_private_dirty_kib = child_processes
        .iter()
        .map(|process| process_status_kib(*process, "smaps_rollup", "Private_Dirty:"))
        .sum::<u64>();
    let child_private_clean_kib = child_processes
        .iter()
        .map(|process| process_status_kib(*process, "smaps_rollup", "Private_Clean:"))
        .sum::<u64>();
    let child_private_rss_kib = child_private_dirty_kib.saturating_add(child_private_clean_kib);
    let child_rss_anon_kib = child_processes
        .iter()
        .map(|process| process_status_kib(*process, "status", "RssAnon:"))
        .sum::<u64>();
    let child_allocated_bytes = allocated_tree_bytes(config.host.run_root());
    assert_eq!(
        materialization.restored_configuration(),
        Some(configuration)
    );
    let (start_events, _, start_quanta, start_frontier, _, _) = materialization.into_parts();
    eprintln!(
        "atomic-world phase=all-world-adopted quanta={start_quanta} frontier={} events={}",
        start_frontier.ticks,
        start_events.len()
    );
    let fingerprints_before_mutation = running_nodes
        .iter()
        .map(|node| {
            (
                node.clone(),
                QemuFreshAttemptLifecycleOwner::sample_fingerprint(lifecycle, node.clone())
                    .expect("sample running child before isolated mutation"),
            )
        })
        .collect::<std::collections::BTreeMap<_, _>>();

    let mut child_configuration = configuration.clone();
    let mut resumed = None;
    for offset in 0..16 {
        let outcome = lifecycle
            .drive_quantum(QuantumRequest {
                configuration: child_configuration,
                control: Vec::new(),
            })
            .expect("drive adopted child world");
        child_configuration = outcome.configuration;
        if outcome
            .advanced_node
            .as_ref()
            .is_some_and(|node| node.kind == SchedulingNodeKind::Vm)
        {
            resumed = Some((offset, outcome.frontier.ticks, outcome.advanced_node));
            break;
        }
    }
    let (offset, child_frontier, advanced_node) =
        resumed.expect("adopted child world must resume backend progress");
    let advanced_node = advanced_node.expect("resumed quantum omitted its advanced child");
    assert!(
        running_nodes.contains(&advanced_node.node),
        "scheduler advanced a VM outside the two running siblings"
    );
    eprintln!(
        "atomic-world phase=child-resumed offset={offset} frontier={child_frontier} node={advanced_node:?}"
    );
    for node in running_nodes {
        let after = QemuFreshAttemptLifecycleOwner::sample_fingerprint(lifecycle, node.clone())
            .expect("sample running child after isolated mutation");
        let before = fingerprints_before_mutation
            .get(node)
            .expect("running child omitted its baseline fingerprint");
        if node == &advanced_node.node {
            assert_ne!(&after, before, "advanced child fingerprint did not change");
        } else {
            assert_eq!(&after, before, "non-advanced running sibling changed");
        }
    }
    crate::qemu_hot_fork_world_factory::assert_native_atomic_resources_private(
        config.host.cgroup_root(),
        config.host.run_root(),
    )
    .expect("authenticate live child resource isolation");

    println!("atomic_world_started=true");
    println!("child_ready_millis={child_ready_millis}");
    println!("child_processes={}", child_processes.len());
    println!("child_private_dirty_kib={child_private_dirty_kib}");
    println!("child_private_rss_kib={child_private_rss_kib}");
    println!("child_rss_anon_kib={child_rss_anon_kib}");
    println!("child_allocated_bytes={child_allocated_bytes}");
    println!("source_running_nodes=2");
    println!("source_permanently_failed_nodes=1");
    println!("block_continuation=present");
    println!("ninep_running_owner_continuation=present");
    println!("native_device_isolation=network,9p");
    println!("native_resource_isolation=memfd,eventfd,writable-qcow2-root,serial");
    println!("native_temp_files_isolated=true");
    println!("ambient_outputs_rejected=pidfile,export-socket");
    println!("native_running_sibling_mutation_isolated=true");
    println!(
        "native_isolation_scopes=network-device,native-9p-device,writable-qcow2-root,serial,pidfile,export-socket,temp-files,native-running-sibling-mutation"
    );
}

fn process_status_kib(process: u32, file: &str, field: &str) -> u64 {
    let contents = fs::read_to_string(format!("/proc/{process}/{file}"))
        .unwrap_or_else(|error| panic!("read process {process} {file}: {error}"));
    contents
        .lines()
        .find_map(|line| line.strip_prefix(field))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|value| value.parse().ok())
        .unwrap_or_else(|| panic!("process {process} {file} lacks numeric field {field}"))
}

fn satisfied(entries: &[crucible::SchedulerEventLogEntry], assertion: &str) -> bool {
    entries.iter().any(|entry| {
        matches!(
            entry.payload(),
            SchedulerEventLogPayload::Observable(
                ObservableEventPayload::AssertionStateChanged { name, state }
            ) if name == &AssertionId::from_name(assertion) && *state == AssertionPhase::Satisfied
        )
    })
}

struct IdleModel {
    config: PackagedQemuExecutorConfig,
    store: CampaignExecutorStore,
    completed: bool,
}

impl AttemptExecutionModel for IdleModel {
    type Error = std::io::Error;

    fn execute(
        &mut self,
        input: &AttemptExecutionInput,
        context: &AttemptExecutionContext,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        extend_native_operations(context);
        let input = decode_crucible_attempt_execution(&self.store, input)
            .expect("accepted idle-prefix basis");
        let source = input.scenario();
        let mut factory = fresh_factory(&self.config, "idle");
        let mut lifecycle = factory
            .begin_fresh(&source.scenario_def(), source, context)
            .expect("actual accepted idle-prefix world");
        let mut configuration = Configuration::genesis(source.scenario_def());
        for quantum in 0..5 {
            context
                .charge_execution_quantum()
                .expect("original accepted quantum allowance");
            let outcome = lifecycle
                .drive_quantum(QuantumRequest {
                    configuration,
                    control: Vec::new(),
                })
                .expect("actual native idle prefix");
            eprintln!(
                "idle-prefix phase=source-quantum-exit quantum={quantum} frontier={}",
                outcome.frontier.ticks
            );
            configuration = outcome.configuration;
        }
        let trace_directory = environment::environment_path("CRUCIBLE_ATOMIC_WORLD_RUN_STATE")
            .join("idle-prefix-traces");
        let trace_count = copy_idle_prefix_traces(self.config.host.run_root(), &trace_directory);
        lifecycle
            .shutdown()
            .expect("actual source process/service cleanup");
        assert!(
            trace_count > 0,
            "source must emit a native RR diagnostic trace"
        );
        assert!(cgroup_processes(self.config.host.cgroup_root()).is_empty());
        self.completed = true;
        println!("idle_prefix_source_quanta=5");
        context.cancellation().cancel();
        Err(AttemptWorkerFailure::Canceled(std::io::Error::other(
            "idle prefix physically complete",
        )))
    }
}

fn run_idle(
    prepared: &PackagedPreparation,
    config: &PackagedQemuExecutorConfig,
    repository: Arc<CampaignRepository>,
) {
    use crucible_campaign::ExecutorService;
    let before = available_resources(prepared);
    let request = super::super::super::hot_fork_native::native_request(&repository, config);
    let queued = prepared
        .actor
        .with_supervisor(|actor| {
            let response = actor
                .submit_attempt(&request)
                .map_err(|_| crucible_api::host_operational::HostOperationalError::Unavailable)?;
            assert!(matches!(
                response.disposition(),
                SubmitAttemptDisposition::Accepted { .. }
            ));
            actor
                .next_queued()
                .ok_or(crucible_api::host_operational::HostOperationalError::Unavailable)
        })
        .expect("genuine original accepted idle-prefix assignment");
    let store = CampaignExecutorStore::new(repository);
    let mut worker = RepositoryAttemptWorker::new(
        store.clone(),
        IdleModel {
            config: config.clone(),
            store,
            completed: false,
        },
    );
    let (queued, result) = worker.execute(queued).into_parts();
    assert!(matches!(result, Err(AttemptWorkerFailure::Canceled(_))));
    assert!(worker.model().completed);
    prepared
        .actor
        .with_supervisor(|actor| {
            actor
                .stage_and_reconcile_cancellation(&queued)
                .map_err(|_| crucible_api::host_operational::HostOperationalError::Unavailable)
        })
        .expect("original actor discharges only after native idle cleanup");
    assert_eq!(available_resources(prepared), before);
}

fn copy_idle_prefix_traces(storage_root: &Path, trace_directory: &Path) -> usize {
    fs::create_dir(trace_directory).expect("create retained idle trace directory");
    let mut pending_directories = vec![storage_root.to_path_buf()];
    let mut copied = 0;

    while let Some(directory) = pending_directories.pop() {
        for entry in fs::read_dir(directory).expect("read source attempt directory") {
            let entry = entry.expect("read source attempt entry");
            let kind = entry.file_type().expect("read source attempt entry type");
            if kind.is_dir() {
                pending_directories.push(entry.path());
            } else if kind.is_file()
                && entry.file_name().to_str()
                    == Some(crucible_qemu::QEMU_RR_CONTROL_BOUNDARY_TRACE_FILE_NAME)
            {
                fs::copy(
                    entry.path(),
                    trace_directory.join(format!("{copied}.trace")),
                )
                .expect("retain source idle trace before owner cleanup");
                copied += 1;
            }
        }
    }

    copied
}
