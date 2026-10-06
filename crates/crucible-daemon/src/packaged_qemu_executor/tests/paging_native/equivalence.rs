//! Accepted native boundary, continuation, scaling, and performance comparisons.
//!
//! A repository worker stages the exact requested boundary before source reap.
//! Promotion authenticates that same root through production exact/thin replay.
//! A resumed worker retains its original cap while independently charged source
//! Services own each template and each child receives fresh production authority.

use super::super::hot_fork_native::{enqueue_promoted_resume, native_repository};
use super::accepted_promotion::{extend_native_operations, promote_accepted_checkpoint_with_model};
use super::*;
use crate::packaged_qemu_executor::RetainedTemplateServiceFactory;
use crate::packaged_qemu_executor::preparation::PackagedPreparation;
use crate::qemu_hot_fork_world_factory::{
    QemuHotForkSourceWorldKey, QemuHotForkWorldLifecycleFactory, QemuHotForkWorldLifecycleStart,
    QemuSingleHotForkSourceWorldProvider,
};
use crate::{
    AttemptExecutionInput, AttemptExecutionModel, AttemptExecutionProduct,
    AttemptExecutionReconciliationStep, CrucibleAttemptExecution, QemuFreshAttemptLifecycleOwner,
    RepositoryAttemptWorker, decode_crucible_attempt_execution,
    encode_crucible_configuration_artifact, encode_crucible_scenario_artifact,
};
use crucible_api::ProductionVmLifecycleConfig;
use crucible_api::host_operational::HostResourceVector;
use crucible_api::vm_lifecycle::{
    ProductionVmHotForkIoNodeKind, ProductionVmHotForkNodeServiceState,
    ProductionVmHotForkSourceWorld,
};
use crucible_campaign::CampaignExecutorStore;
use crucible_campaign::{
    CampaignMode, CampaignPolicy, ExplorerPolicy, FairnessPolicy, ProgressiveWideningPolicy,
    PuctPolicy, RetentionPolicy, StopCondition,
};
use crucible_campaign::{ChoiceValue, ExactRational, IntegerValue};
use crucible_qemu::{QemuAsyncDriverPolicy, QemuNodeSelectablePendingRequest, QemuShutdownPolicy};
use std::path::Path;

const MAX_SOURCE_QUANTA: u64 = 30_000;
const POST_CHOICE_QUANTA: u64 = 512;
const CHILD_READY_SAMPLE_COUNT: usize = 20;
const CHILD_READY_P95_LIMIT_NANOSECONDS: u64 = 100_000_000;

mod scenario {
    pub(super) const PERMANENT_FAILURE_NANOS: u64 = 30_000_000_000;
    pub(super) const NINEP_FAULT_WINDOW_NANOS: u64 = 5_000_000_000;
    pub(super) const INACTIVE_WORLD_NANOS: u64 = 80_000_000_000;
    pub(super) const REACTIVATION_NANOS: u64 = 81_000_000_000;
}

mod atomic;
mod dma;
pub(crate) use dma::run as run_dma_borrowers_native;
mod invalid_files;
pub(crate) use atomic::{NativeAtomicWorldCase, run as run_atomic_world_native};
mod campaign_perf;
mod concurrent;
mod evidence;
mod failure_guards;
mod failures;
pub(crate) use failures::{NativeAtomicFailureCase, run as run_atomic_failure_native};
mod generations;
mod operational;
mod siblings;
use evidence::{
    BoundaryEvidence, ContinuationEvidence, EquivalenceTopology, assert_continuation_equivalent,
    capture_boundary_evidence, continue_from_pending, drain_exact_pending,
    drive_configuration_to_pending_boundary, prepared_world_evidence, select_pending_configuration,
};
use operational::*;

/// Selects the explicit acceptance assertions for a reviewed native workload.
#[derive(Clone, Copy)]
pub(crate) enum NativeEquivalenceCase {
    Origins,
    ReadyLatency,
    Siblings,
    Depth,
    Memory(u32),
    Stress,
    Performance,
}

/// Runs the reviewed traffic workload with genuine aggregate ownership.
pub(crate) fn run(
    source: ScenarioDefForm,
    lifecycle: ProductionVmLifecycleConfig,
    case: NativeEquivalenceCase,
) {
    let depths = if matches!(
        case,
        NativeEquivalenceCase::Depth | NativeEquivalenceCase::Performance
    ) {
        3
    } else {
        1
    };
    let mut runs = Vec::new();
    for depth in 1..=depths {
        let (case_lane, case_project) = match case {
            NativeEquivalenceCase::Origins => {
                if source.world().vm_nodes().len() == 1 {
                    ("origins-single", 39_000)
                } else {
                    ("origins-multi", 40_000)
                }
            }
            NativeEquivalenceCase::ReadyLatency => ("ready", 41_000),
            NativeEquivalenceCase::Siblings => ("siblings", 48_000),
            NativeEquivalenceCase::Depth => ("depth", 42_000),
            NativeEquivalenceCase::Memory(64) => ("memory64", 43_000),
            NativeEquivalenceCase::Memory(256) => ("memory256", 44_000),
            NativeEquivalenceCase::Memory(512) => ("memory512", 45_000),
            NativeEquivalenceCase::Memory(_) => panic!("unsupported native memory profile"),
            NativeEquivalenceCase::Stress => ("stress", 46_000),
            NativeEquivalenceCase::Performance => ("performance", 47_000),
        };
        let lane = format!("equivalence-{case_lane}-{depth}");
        let cpus = source
            .world()
            .vm_nodes()
            .iter()
            .map(|node| u64::from(node.smp_vcpus))
            .sum::<u64>();
        let catalog = environment::NativeCatalogBudget {
            resources: crucible_api::host_operational::HostResourceVector {
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
                    u32::try_from(cpus * world_overlap(case) + 2).expect("explicit overlap CPUs"),
                    32 << 30,
                    if matches!(case, NativeEquivalenceCase::Siblings) {
                        96 << 30
                    } else {
                        64 << 30
                    },
                    150_000,
                )
                .expect("authored catalog installation capacity"),
            ),
            installation_operational_capacity: Some(
                crate::HostOperationalCapacity::new(
                    32,
                    4096,
                    65_536,
                    if matches!(case, NativeEquivalenceCase::Siblings) {
                        16 << 30
                    } else {
                        8 << 30
                    },
                    2 << 30,
                )
                .expect("authored catalog metadata installation capacity"),
            ),
        };
        let result = environment::with_native_repository_environment_with_catalog(
            &lane,
            case_project + u32::try_from(depth).expect("bounded semantic depth") * 100,
            catalog,
            |root, storage| native_repository(&source, root, storage),
            |config| resources(config, &source, &lifecycle, case),
            |prepared, config, repository| {
                run_accepted(
                    prepared,
                    config,
                    repository,
                    &source,
                    if matches!(case, NativeEquivalenceCase::Depth) {
                        depth
                    } else {
                        0
                    },
                    case,
                    depth - 1,
                )
            },
        );
        runs.push(result);
    }
    publish_case(case, &runs, source.world().vm_nodes().len());
}

fn resources(
    mut config: PackagedQemuExecutorConfig,
    source: &ScenarioDefForm,
    lifecycle: &ProductionVmLifecycleConfig,
    case: NativeEquivalenceCase,
) -> PackagedQemuExecutorConfig {
    let nodes = u64::try_from(source.world().vm_nodes().len()).expect("native node count");
    let cpus = source
        .world()
        .vm_nodes()
        .iter()
        .map(|node| u64::from(node.smp_vcpus))
        .sum::<u64>();
    // These are authored per-world acceptance envelopes. The actual engine
    // inventory still proves its floors before any process or RAM admission.
    let world = crucible_api::host_operational::HostResourceVector {
        resident_peak_bytes: nodes * (1536 << 20) + (1 << 20),
        backing_peak_bytes: nodes * (4 << 30),
        metadata_bytes: nodes * (512 << 20),
        staging_bytes: nodes * (32 << 20),
        paging_io_slots: nodes,
        cpu_slots: cpus,
        task_slots: nodes * 68 + 1,
        file_descriptors: nodes * 1056,
    };
    config.capacity = ExecutorCapacity::new(
        1,
        u32::try_from(cpus * world_overlap(case) + 2)
            .expect("complete comparison worlds and registry/catalog CPUs"),
        32 << 30,
        if matches!(case, NativeEquivalenceCase::Siblings) {
            96 << 30
        } else {
            64 << 30
        },
        150_000,
    )
    .expect("explicit whole-world overlap envelope");
    config.host_operational_capacity = crate::HostOperationalCapacity::new(
        32,
        4096,
        65_536,
        if matches!(case, NativeEquivalenceCase::Siblings) {
            16 << 30
        } else {
            8 << 30
        },
        2 << 30,
    )
    .expect("explicit native metadata and staging envelopes");
    // Native fixture assets are borrowed operator inputs. Their mutable copy
    // uses the installed catalog's original authority and retains child credit.
    let admitted_base = config
        .admitted_lifecycle_config()
        .expect("installed native catalog admits lifecycle metadata");
    let _input_scope = admitted_base.enter_input_custody();
    let provider = config
        .lifecycle
        .ram_catalog_provider()
        .expect("actual installed catalog provider")
        .clone();
    config.lifecycle = Arc::new(
        lifecycle
            .try_clone_admitted()
            .expect("original catalog authority admits native fixture assets")
            .with_run_state_root(config.lifecycle.run_state_root().join("equivalence"))
            .with_ram_catalog_provider(provider),
    );
    config
        .with_assignment_resources(
            world,
            AttemptResourceLimits::new(8, 8 << 30, 8 << 30, MAX_SOURCE_QUANTA)
                .expect("original reviewed semantic execution bounds"),
        )
        .expect("genuine assignment vector")
        .with_retained_template_resources(world)
        .expect("independent retained-template vector")
}

fn world_overlap(case: NativeEquivalenceCase) -> u64 {
    if matches!(case, NativeEquivalenceCase::Siblings) {
        17
    } else if matches!(
        case,
        NativeEquivalenceCase::Origins | NativeEquivalenceCase::Depth
    ) {
        4
    } else {
        2
    }
}

struct Captured {
    boundary: BoundaryEvidence,
    continuation: Option<ContinuationEvidence>,
}

struct CaptureModel {
    config: PackagedQemuExecutorConfig,
    store: CampaignExecutorStore,
    depth: usize,
    case: NativeEquivalenceCase,
    captured: Option<Captured>,
}

impl AttemptExecutionModel for CaptureModel {
    type Error = std::io::Error;

    fn execute(
        &mut self,
        input: &AttemptExecutionInput,
        context: &AttemptExecutionContext,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        extend_native_operations(context);
        let input = decode_crucible_attempt_execution(&self.store, input)
            .expect("accepted immutable scenario and execution basis");
        let source = input.scenario();
        let mut factory = fresh_factory(&self.config, "capture");
        let mut lifecycle = factory
            .begin_fresh(&source.scenario_def(), source, context)
            .expect("actual accepted capture world");
        let topology = topology(source);
        let pending = drive_to_depth(&mut lifecycle, source, self.depth, context);
        let capture = lifecycle
            .capture_attempt_checkpoint(context)
            .expect("coherent native capture at the requested semantic depth");
        let staged = context
            .prepare_and_stage_checkpoint(capture)
            .expect("same actor stages its original raw boundary before reap");
        // Device pre-save effects belong to the captured image. Compare the
        // continuation against this post-save boundary in every later lane.
        let boundary = capture_boundary_evidence(
            &mut lifecycle,
            source,
            pending.configuration,
            pending.pending,
            topology,
        );
        let continuation = if matches!(self.case, NativeEquivalenceCase::Depth) {
            None
        } else {
            Some(continue_from_pending(
                &mut lifecycle,
                source,
                boundary.configuration.clone(),
                boundary.pending.clone(),
                context,
            ))
        };
        lifecycle
            .shutdown()
            .expect("capture source physically reaped before publication");
        self.captured = Some(Captured {
            boundary,
            continuation,
        });
        Ok(AttemptExecutionProduct::exact_checkpoint(staged))
    }
}

fn run_accepted(
    prepared: &PackagedPreparation,
    config: &PackagedQemuExecutorConfig,
    repository: Arc<CampaignRepository>,
    source: &ScenarioDefForm,
    depth: usize,
    case: NativeEquivalenceCase,
    sample_index: usize,
) -> RunEvidence {
    let (promoted, mut captured) = promote_accepted_checkpoint_with_model(
        prepared,
        config,
        Arc::clone(&repository),
        source,
        |_host, store| CaptureModel {
            config: config.clone(),
            store,
            depth,
            case,
            captured: None,
        },
    );
    let captured = captured
        .model_mut()
        .captured
        .take()
        .expect("completed original boundary evidence");
    let queued = enqueue_promoted_resume(
        prepared,
        &promoted,
        AssignmentId::from_bytes([0xf1; 16]).expect("distinct real resumed assignment"),
    );
    let store = CampaignExecutorStore::new(repository);
    let mut worker = RepositoryAttemptWorker::new(
        store.clone(),
        ResumeModel {
            prepared,
            config: config.clone(),
            store,
            checkpoint: promoted.checkpoint,
            depth,
            case,
            sample_index,
            captured,
            baked: promoted.baked.clone(),
            result: None,
        },
    );
    let (queued, result) = worker.execute(queued).into_parts();
    assert!(matches!(result, Err(AttemptWorkerFailure::Canceled(_))));
    let evidence = worker
        .model_mut()
        .result
        .take()
        .expect("completed native child/reference assertions");
    prepared
        .actor
        .with_supervisor(|actor| {
            actor
                .stage_and_reconcile_cancellation(&queued)
                .map_err(|_| crucible_api::host_operational::HostOperationalError::Unavailable)
        })
        .expect("same actor releases assignment only after all native cleanup");
    evidence
}

struct ResumeModel<'a> {
    prepared: &'a PackagedPreparation,
    config: PackagedQemuExecutorConfig,
    store: CampaignExecutorStore,
    checkpoint: ExactCheckpointId,
    depth: usize,
    case: NativeEquivalenceCase,
    sample_index: usize,
    captured: Captured,
    baked: crate::ProductionBakedGenesisCheckpoint,
    result: Option<RunEvidence>,
}

#[derive(Default)]
struct RunEvidence {
    ready_samples: Vec<u64>,
    hot_setup: u64,
    exact_setup: u64,
    hot_continuation: u64,
    exact_continuation: u64,
    completed_children: usize,
    planner_queue: u64,
    descendant_generations: Vec<Vec<u64>>,
}

fn available_resources(prepared: &PackagedPreparation) -> HostResourceVector {
    prepared
        .actor
        .with_supervisor(|actor| {
            actor
                .host_resource_availability()
                .ok_or(crucible_api::host_operational::HostOperationalError::Unavailable)
        })
        .expect("actual eight-dimensional capacity authority")
}

fn assert_template_charge(
    prepared: &PackagedPreparation,
    before: HostResourceVector,
    template: HostResourceVector,
    count: u64,
) {
    let multiply = |value: u64| {
        value
            .checked_mul(count)
            .expect("bounded complete world charge")
    };
    let charge = HostResourceVector {
        resident_peak_bytes: multiply(template.resident_peak_bytes),
        backing_peak_bytes: multiply(template.backing_peak_bytes),
        metadata_bytes: multiply(template.metadata_bytes),
        staging_bytes: multiply(template.staging_bytes),
        paging_io_slots: multiply(template.paging_io_slots),
        cpu_slots: multiply(template.cpu_slots),
        task_slots: multiply(template.task_slots),
        file_descriptors: multiply(template.file_descriptors),
    };
    super::super::hot_fork_native::assert_resource_charge(
        before,
        available_resources(prepared),
        charge,
    );
}

fn topology(source: &ScenarioDefForm) -> EquivalenceTopology {
    if source.world().vm_nodes().len() == 1 {
        EquivalenceTopology::SingleNode
    } else {
        EquivalenceTopology::MultiNode
    }
}

fn fresh_factory(
    config: &PackagedQemuExecutorConfig,
    lane: &str,
) -> QemuAttemptProductionVmLifecycleFactory<
    ComposedQemuAttemptResourceGuardFactory<LinuxQemuAttemptHostResourceFactory>,
> {
    let host = LinuxQemuAttemptHostResourceFactory::open(config.host.clone())
        .expect("actual world cgroup and storage namespace");
    QemuAttemptProductionVmLifecycleFactory::new(
        config
            .admitted_lifecycle_config()
            .expect("native world projection retains its actual catalog metadata credit")
            .with_run_state_root(config.lifecycle.run_state_root().join(lane)),
        ComposedQemuAttemptResourceGuardFactory::new(host),
    )
}

fn drive_to_depth(
    lifecycle: &mut impl QemuFreshAttemptLifecycleOwner,
    source: &ScenarioDefForm,
    depth: usize,
    context: &AttemptExecutionContext,
) -> BoundaryEvidence {
    let mut configuration = Configuration::genesis(source.scenario_def());
    for _ in 0..depth {
        let boundary = drive_configuration_to_pending_boundary(
            lifecycle,
            source,
            configuration,
            topology(source),
            context,
        );
        configuration = select_pending_configuration(
            lifecycle,
            source,
            boundary.configuration,
            &boundary.pending,
        );
    }
    drive_configuration_to_pending_boundary(
        lifecycle,
        source,
        configuration,
        topology(source),
        context,
    )
}

impl AttemptExecutionModel for ResumeModel<'_> {
    type Error = std::io::Error;

    fn execute(
        &mut self,
        input: &AttemptExecutionInput,
        context: &AttemptExecutionContext,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        extend_native_operations(context);
        let input = decode_crucible_attempt_execution(&self.store, input)
            .expect("real resumed execution and promoted checkpoint basis");
        assert_eq!(context.resume_checkpoint(), Some(self.checkpoint));
        let source = input.scenario();
        if matches!(self.case, NativeEquivalenceCase::Siblings) {
            self.result = Some(siblings::run(self, &input, context));
            context.cancellation().cancel();
            return Err(AttemptWorkerFailure::Canceled(std::io::Error::other(
                "all native sibling cohorts physically reaped",
            )));
        }
        if matches!(self.case, NativeEquivalenceCase::Origins) {
            self.result = Some(concurrent::run(self, &input, context));
            context.cancellation().cancel();
            return Err(AttemptWorkerFailure::Canceled(std::io::Error::other(
                "simultaneous native comparison worlds reaped",
            )));
        }
        if matches!(self.case, NativeEquivalenceCase::Depth) {
            self.result = Some(generations::run(self, &input, context));
            context.cancellation().cancel();
            return Err(AttemptWorkerFailure::Canceled(std::io::Error::other(
                "three native descendant generations physically retired",
            )));
        }
        let mut result = RunEvidence::default();
        let available_before = available_resources(self.prepared);
        let mut selected = context.take_selected_checkpoint();
        let factory = RetainedTemplateServiceFactory::new(self.prepared, &self.config);
        {
            let service = Arc::new(
                factory
                    .start_for_resume(source, self.checkpoint, context, &mut selected)
                    .expect("independent source Service under this still-active assignment"),
            );
            assert_template_charge(
                self.prepared,
                available_before,
                self.config
                    .retained_template_resources()
                    .expect("full authored source vector"),
                1,
            );
            extend_native_operations(service.context());
            let mut source_factory = fresh_factory(&self.config, "exact-source");
            let started = operational_monotonic_nanoseconds();
            let mut parent = source_factory
                .begin_resume(
                    &self.prepared.checkpoints,
                    self.checkpoint,
                    crate::QemuExactResumeBasis::new(
                        &source.scenario_def(),
                        source,
                        &self.captured.boundary.configuration,
                        None,
                    ),
                    service.context(),
                )
                .expect("source consumes the genuine selected-root claim");
            let pending = drain_exact_pending(&mut parent);
            let boundary = capture_boundary_evidence(
                &mut parent,
                source,
                self.captured.boundary.configuration.clone(),
                pending,
                topology(source),
            );
            assert_eq!(
                boundary, self.captured.boundary,
                "exact source changed its captured boundary"
            );
            let setup = operational_monotonic_nanoseconds().saturating_sub(started);
            if matches!(self.case, NativeEquivalenceCase::Performance) {
                println!("corpus_{}_exact_setup_ns={setup}", self.sample_index);
            }
            let mut world = parent
                .prepare_hot_fork_source_world()
                .expect("complete retained template barriers")
                .with_cleanup_observer(service.clone());
            let processes = world
                .continuation()
                .nodes()
                .iter()
                .filter_map(|node| node.process().map(|process| process.process_id))
                .collect::<Vec<_>>();
            let initial_threads = count_process_entries(&processes, "task");
            let initial_descriptors = count_process_entries(&processes, "fd");
            let count = match self.case {
                NativeEquivalenceCase::ReadyLatency => CHILD_READY_SAMPLE_COUNT,
                NativeEquivalenceCase::Memory(_) => 4,
                NativeEquivalenceCase::Stress => 10_000,
                NativeEquivalenceCase::Performance => 1,
                _ => 1,
            };
            let mut warm = None;
            let mut final_hot = None;
            if matches!(self.case, NativeEquivalenceCase::Performance) {
                result.planner_queue = campaign_perf::measure_campaign_planner_queue_at_boundary(
                    source,
                    &input,
                    &boundary,
                    self.sample_index,
                );
                println!(
                    "corpus_{}_campaign_planner_queue_ns={}",
                    self.sample_index, result.planner_queue
                );
            }
            for sample in 0..count {
                let child_config = child_config(&self.config);
                let host = LinuxQemuAttemptHostResourceFactory::open(child_config.host.clone())
                    .expect("fresh child cgroup and quota authority");
                let key = QemuHotForkSourceWorldKey::for_execution(
                    &input,
                    context,
                    context.runtime_basis().expect("live accepted incarnation"),
                )
                .expect("actual captured configuration and runtime source key");
                let provider = QemuSingleHotForkSourceWorldProvider::new(key, world);
                let mut child_factory = QemuProductionHotForkWorldLifecycleFactory::new(
                    provider,
                    ComposedQemuAttemptResourceGuardFactory::new(host),
                    self.config.lifecycle.run_state_root().join("child"),
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
                let child_started = operational_monotonic_nanoseconds();
                let mut child = match child_factory
                    .try_start(&input, context)
                    .expect("fresh independently registered native child")
                {
                    QemuHotForkWorldLifecycleStart::Started(child) => child,
                    QemuHotForkWorldLifecycleStart::Declined => {
                        panic!("authenticated source unexpectedly declined")
                    }
                };
                let ready = operational_monotonic_nanoseconds().saturating_sub(child_started);
                result.ready_samples.push(ready);
                let child_processes = cgroup_processes(child_config.host.cgroup_root());
                assert_eq!(child_processes.len(), source.world().vm_nodes().len());
                let before = process_memory_evidence(&child_processes);
                let pending = drain_exact_pending(&mut child);
                let actual = capture_boundary_evidence(
                    &mut child,
                    source,
                    boundary.configuration.clone(),
                    pending,
                    topology(source),
                );
                assert_eq!(
                    actual, boundary,
                    "child reconstruction changed its exact initial boundary"
                );
                if let NativeEquivalenceCase::Memory(memory) = self.case {
                    assert!(before.private_rss_kib <= u64::from(memory) * 256 + 32 * 1024);
                    println!(
                        "ram_{memory}_sibling_{}_child_private_rss_kib={}",
                        sample + 1,
                        before.private_rss_kib
                    );
                    println!(
                        "ram_{memory}_sibling_{}_child_vm_pte_kib={}",
                        sample + 1,
                        before.vm_pte_kib
                    );
                }
                let continue_child = !matches!(
                    self.case,
                    NativeEquivalenceCase::ReadyLatency
                        | NativeEquivalenceCase::Stress
                        | NativeEquivalenceCase::Depth
                ) && (sample + 1 == count
                    || matches!(self.case, NativeEquivalenceCase::Performance));
                if continue_child {
                    let begun = operational_monotonic_nanoseconds();
                    let hot = continue_from_pending(
                        &mut child,
                        source,
                        actual.configuration,
                        actual.pending,
                        context,
                    );
                    let elapsed = operational_monotonic_nanoseconds().saturating_sub(begun);
                    assert_continuation_equivalent(
                        "hot child versus original causal execution",
                        &hot,
                        self.captured
                            .continuation
                            .as_ref()
                            .expect("original complete causal continuation"),
                    );
                    result.hot_continuation = result
                        .hot_continuation
                        .checked_add(elapsed)
                        .expect("bounded timing sum");
                    result.hot_setup = result
                        .hot_setup
                        .checked_add(ready)
                        .expect("bounded setup sum");
                    if matches!(self.case, NativeEquivalenceCase::Performance) {
                        let after = process_memory_evidence(&child_processes);
                        let dirty = after
                            .private_dirty_kib
                            .saturating_sub(before.private_dirty_kib);
                        assert!((2048..=4096 + 64 * 1024).contains(&dirty));
                        let node_times = child_factory.node_launch_nanoseconds();
                        let sum = node_times.iter().map(|(_, elapsed)| elapsed).sum::<u64>();
                        let maximum = node_times
                            .iter()
                            .map(|(_, elapsed)| *elapsed)
                            .max()
                            .expect("node timings");
                        assert!(sum > maximum);
                        assert!(ready <= maximum.saturating_add(250_000_000));
                        let corpus_index = self.sample_index;
                        println!("corpus_{corpus_index}_hot_setup_ns={ready}");
                        println!("corpus_{corpus_index}_hot_guest_continuation_ns={elapsed}");
                        println!("corpus_{corpus_index}_known_dirty_private_growth_kib={dirty}");
                        print_memory(corpus_index, before, after);
                    }
                    final_hot = Some(hot);
                }
                child
                    .shutdown()
                    .expect("actual child reap and independent source worker joins");
                let mut reconciled = false;
                for _ in 0..64 {
                    if child
                        .reconcile_execution_disposition(
                            crate::AttemptExecutionDisposition::Canceled,
                        )
                        .expect("real fork source cancellation reconciliation")
                        == AttemptExecutionReconciliationStep::Complete
                    {
                        reconciled = true;
                        break;
                    }
                }
                assert!(
                    reconciled,
                    "child cleanup proof must complete before source reuse"
                );
                assert!(child_factory.recover(child).is_ok());
                world = child_factory
                    .source_provider_mut_for_test()
                    .take_available()
                    .expect("source rollback returns the identical physical template");
                result.completed_children += 1;
                assert!(cgroup_processes(child_config.host.cgroup_root()).is_empty());
                if matches!(self.case, NativeEquivalenceCase::Stress) && (sample + 1) % 250 == 0 {
                    assert_eq!(count_process_entries(&processes, "task"), initial_threads);
                    assert_eq!(count_process_entries(&processes, "fd"), initial_descriptors);
                    let metrics = (
                        process_memory_evidence(&processes).private_dirty_kib,
                        allocated_tree_bytes(self.config.host.run_root()),
                        allocated_tree_bytes(self.config.lifecycle.run_state_root()),
                    );
                    if sample + 1 == count / 2 {
                        warm = Some(metrics);
                    }
                    if sample + 1 == count {
                        let midpoint = warm.expect("stress midpoint custody measurements");
                        assert!(metrics.0.saturating_sub(midpoint.0) <= 4096);
                        assert!(metrics.1 <= midpoint.1 && metrics.2 <= midpoint.2);
                    }
                    println!("stress_private_dirty_{}_kib={}", sample + 1, metrics.0);
                }
            }
            let mut exact_reference = world
                .recover()
                .expect("recover exact source before reference continuation");
            if let Some(hot) = final_hot {
                let pending = drain_exact_pending(&mut exact_reference);
                let begun = operational_monotonic_nanoseconds();
                let exact = continue_from_pending(
                    &mut exact_reference,
                    source,
                    boundary.configuration.clone(),
                    pending,
                    service.context(),
                );
                let elapsed = operational_monotonic_nanoseconds().saturating_sub(begun);
                if matches!(self.case, NativeEquivalenceCase::Performance) {
                    println!(
                        "corpus_{}_exact_guest_continuation_ns={elapsed}",
                        self.sample_index
                    );
                }
                assert_continuation_equivalent(
                    "hot child versus exact source continuation",
                    &hot,
                    &exact,
                );
                result.exact_continuation = result
                    .exact_continuation
                    .checked_add(elapsed)
                    .expect("bounded timing sum");
                result.exact_setup = result
                    .exact_setup
                    .checked_add(setup)
                    .expect("bounded setup sum");
            }
            exact_reference
                .shutdown()
                .expect("actual original source reap before Service discharge");
            service
                .release_after_world_cleanup()
                .expect("watcher join and same full-vector release");
        }
        assert_eq!(available_resources(self.prepared), available_before);
        self.result = Some(result);
        context.cancellation().cancel();
        Err(AttemptWorkerFailure::Canceled(std::io::Error::other(
            "native equivalence evidence complete after physical cleanup",
        )))
    }
}

fn child_config(config: &PackagedQemuExecutorConfig) -> PackagedQemuExecutorConfig {
    let mut child = config.clone();
    let host = &config.host;
    child.host = LinuxQemuAttemptHostConfig::new(
        host.cgroup_root().join("child"),
        host.run_root().join("child"),
        "equivalence-child",
        49_000,
        1,
        host.child_user_id(),
        host.child_group_id(),
        host.maximum_tasks(),
        host.maximum_file_descriptors(),
        host.maximum_node_host_service_tasks(),
        host.maximum_node_host_service_file_descriptors(),
        host.maximum_node_host_service_resident_bytes(),
        host.watcher_service_resident_bytes(),
        host.maximum_inodes(),
        Duration::from_secs(30),
    )
    .expect("child owns an independent process/storage namespace");
    child
}

fn satisfied(entries: &[SchedulerEventLogEntry], assertion: &str) -> bool {
    entries.iter().any(|entry| matches!(entry.payload(),
        crucible::SchedulerEventLogPayload::Observable(crucible::ObservableEventPayload::AssertionStateChanged { name, state })
        if name == &crucible::AssertionId::from_name(assertion) && *state == crucible::AssertionPhase::Satisfied))
}

fn nearest_rank_p95(samples: &[u64]) -> u64 {
    assert!(!samples.is_empty());
    let mut ordered = samples.to_vec();
    ordered.sort_unstable();
    ordered[(ordered.len() * 95).div_ceil(100) - 1]
}

fn publish_case(case: NativeEquivalenceCase, runs: &[RunEvidence], nodes: usize) {
    match case {
        NativeEquivalenceCase::Origins => {
            println!("hot_fork_equivalence=true");
            println!("template_origins=execution,exact-restore");
            println!("reference_tiers=thin-replay,exact-checkpoint");
            println!("child_boundary_matches_capture=true");
            println!("child_suffix_matches_exact_restore=true");
            println!("child_suffix_matches_genesis_replay=true");
            println!("locked_fault_replay_evidence_match=true");
            if nodes == 1 {
                println!("topology=single-node");
                println!("state=block,ninep,guest-choice,measurement");
            } else {
                println!("pre_event_queue_and_volatile_cache=true");
                println!("pre_event_exact_restore=true");
                println!("shared_effect_state_transition=true");
                println!("shared_cause=network,block,node");
                println!("ninep_fault_injection=true");
                println!("application_http_status=200");
                println!("inactive_world_reactivation=true");
                println!(
                    "state=network,block,ninep,guest-choice,measurement,signal,permanent-failure"
                );
            }
        }
        NativeEquivalenceCase::ReadyLatency => {
            let samples = &runs[0].ready_samples;
            assert_eq!(samples.len(), CHILD_READY_SAMPLE_COUNT);
            let p95 = nearest_rank_p95(samples);
            println!("child_ready_reference=single-vm-64mib-1vcpu");
            println!("child_ready_sample_count={CHILD_READY_SAMPLE_COUNT}");
            println!(
                "child_ready_samples_ns={}",
                samples
                    .iter()
                    .map(u64::to_string)
                    .collect::<Vec<_>>()
                    .join(",")
            );
            println!("child_ready_p95_ns={p95}");
            println!("child_ready_p95_limit_ns={CHILD_READY_P95_LIMIT_NANOSECONDS}");
            assert!(p95 < CHILD_READY_P95_LIMIT_NANOSECONDS);
        }
        NativeEquivalenceCase::Depth => {
            assert_eq!(runs.len(), 3);
            for run in runs {
                assert_eq!(run.descendant_generations.len(), 3);
                for pair in run.descendant_generations.windows(2) {
                    assert!(
                        pair[0]
                            .iter()
                            .zip(&pair[1])
                            .all(|(parent, child)| *child == parent + 1)
                    );
                }
            }
            println!("semantic_template_depth=3");
            println!("descendant_template_generations=3");
        }
        NativeEquivalenceCase::Memory(_) | NativeEquivalenceCase::Siblings => {}
        NativeEquivalenceCase::Stress => {
            assert_eq!(runs[0].completed_children, 10_000);
            println!("production_whole_world_lifecycles=10000");
            println!("qemu_child_pairing=exact_source_boundary");
            println!("source_threads_leaked=0");
            println!("source_descriptors_leaked=0");
            println!("source_private_dirty_late_growth_limit_kib=4096");
            println!("stress_final_qemu_processes=0");
        }
        NativeEquivalenceCase::Performance => {
            assert_eq!(runs.len(), 3);
            let sum = |field: fn(&RunEvidence) -> u64| runs.iter().map(field).sum::<u64>();
            let hot_setup = sum(|run| run.hot_setup);
            let exact_setup = sum(|run| run.exact_setup);
            let hot_continuation = sum(|run| run.hot_continuation);
            let exact_continuation = sum(|run| run.exact_continuation);
            let planner = sum(|run| run.planner_queue);
            assert!(exact_setup >= hot_setup.saturating_mul(5));
            assert!(hot_continuation.saturating_mul(100) <= exact_continuation.saturating_mul(110));
            assert!(
                planner.checked_mul(100).expect("bounded planner ratio")
                    < hot_continuation
                        .checked_mul(5)
                        .expect("bounded continuation ratio")
            );
            println!("campaign_planner_queue_total_ns={planner}");
            println!("hot_guest_continuation_total_ns={hot_continuation}");
            println!("exact_restore_corpus_size=3");
            println!("setup_speedup_minimum=5x");
            println!("steady_execution_overhead_limit_percent=10");
            println!("known_dirty_guest_pages=1024");
            println!("memory_metrics=VmPTE,VmData,AnonHugePages,numa_maps");
            println!("multi_node_launch_model=max-plus-bounded-orchestration");
        }
    }
}

#[test]
fn nearest_rank_p95_uses_the_nineteenth_of_twenty_samples() {
    assert_eq!(nearest_rank_p95(&(1..=20).rev().collect::<Vec<_>>()), 19);
    assert_eq!(nearest_rank_p95(&[42]), 42);
}
