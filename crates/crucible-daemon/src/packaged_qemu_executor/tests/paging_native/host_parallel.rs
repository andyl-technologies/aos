//! Accepted native host-parallel rounds and poisoned-round exact recovery.
//!
//! Every lane executes inside a real repository worker on the prepared actor.
//! The failed lane stages its coherent pre-failure capture before injecting the
//! physical error; production replay promotes that same durable checkpoint,
//! and a fresh accepted resume consumes its linear selected-root authority.

use super::super::hot_fork_native::{
    enqueue_promoted_resume, fork_resources, native_repository, native_request,
};
use super::accepted_promotion::{extend_native_operations, promote_accepted_checkpoint_with_model};
use super::*;
use crate::QemuExactResumeBasis;
use crate::packaged_qemu_executor::preparation::PackagedPreparation;
use crate::{
    AttemptExecutionInput, AttemptExecutionModel, AttemptExecutionProduct, RepositoryAttemptWorker,
    decode_crucible_attempt_execution,
};
use crucible::SchedulerQuiescence;
use crucible_api::host_operational::{HostOperationalError, HostResourceVector};
use crucible_campaign::{CampaignExecutorStore, ExecutorService, SubmitAttemptDisposition};

#[derive(Debug, PartialEq, Eq)]
struct CanonicalBoundary {
    logical: CanonicalLogicalBoundary,
    fingerprints: BTreeMap<NodeId, crucible::ExecutionFingerprint>,
}

#[derive(Debug, PartialEq, Eq)]
struct CanonicalLogicalBoundary {
    configuration: Configuration,
    event_log: Vec<SchedulerEventLogEntry>,
    event_log_base_events: u64,
    event_log_segments: Vec<crucible::ContentHash>,
    scheduler_checkpoint: Vec<u8>,
    scheduler_quanta: u64,
    scheduler_frontier: VirtualTime,
    scheduler_quiescence: SchedulerQuiescence,
    terminal_verdict: Option<QuantumTerminalVerdict>,
}

struct SuccessfulLane {
    boundary: CanonicalBoundary,
    evidence: crucible_qemu::QemuHostParallelismEvidence,
}

#[derive(Debug)]
struct FailureEvidence {
    healthy_peer_advanced: bool,
    logical_state_uncommitted: bool,
    retry_poisoned: bool,
    authenticated_exact_recovery: bool,
}

/// Runs the native assertions under real aggregate and assignment ownership.
pub(crate) fn run(source: ScenarioDefForm) {
    let serial = successful_lane(&source, "parallel-serial", 24_000, 1);
    let parallel = successful_lane(&source, "parallel-two", 24_100, 2);
    let state_identity = serial.boundary.logical.configuration
        == parallel.boundary.logical.configuration
        && serial.boundary.logical.scheduler_checkpoint
            == parallel.boundary.logical.scheduler_checkpoint
        && serial.boundary.fingerprints == parallel.boundary.fingerprints;
    let time_identity = serial.boundary.logical.scheduler_quanta
        == parallel.boundary.logical.scheduler_quanta
        && serial.boundary.logical.scheduler_frontier
            == parallel.boundary.logical.scheduler_frontier;
    let canonical_log_identity = serial.boundary.logical.event_log
        == parallel.boundary.logical.event_log
        && serial.boundary.logical.event_log_base_events
            == parallel.boundary.logical.event_log_base_events
        && serial.boundary.logical.event_log_segments
            == parallel.boundary.logical.event_log_segments;
    let worker_count_absent_from_checkpoint = serial.boundary.logical.scheduler_checkpoint
        == parallel.boundary.logical.scheduler_checkpoint;
    assert!(
        state_identity
            && time_identity
            && canonical_log_identity
            && worker_count_absent_from_checkpoint
    );
    assert_eq!(serial.boundary, parallel.boundary);
    let failure = failed_lane(&source);

    println!("PASS");
    println!("production_vm_lifecycle_path=true");
    println!(
        "production_host_parallel_requested_runs={}",
        parallel.evidence.requested_runs
    );
    println!(
        "production_host_parallel_maximum_workers={}",
        parallel.evidence.maximum_workers
    );
    println!(
        "production_host_parallel_realized_parallelism={}",
        parallel.evidence.realized_parallelism
    );
    println!(
        "production_host_parallel_commit_order={}",
        parallel
            .evidence
            .commit_order
            .iter()
            .map(|node| node.name.as_str())
            .collect::<Vec<_>>()
            .join(",")
    );
    println!("production_host_parallel_state_identity={state_identity}");
    println!("production_host_parallel_time_identity={time_identity}");
    println!("production_host_parallel_canonical_log_identity={canonical_log_identity}");
    println!(
        "production_host_parallel_worker_count_absent_from_checkpoint={worker_count_absent_from_checkpoint}"
    );
    println!(
        "production_host_parallel_failure_healthy_peer_advanced={}",
        failure.healthy_peer_advanced
    );
    println!(
        "production_host_parallel_failure_logical_state_uncommitted={}",
        failure.logical_state_uncommitted
    );
    println!(
        "production_host_parallel_failure_retry_poisoned={}",
        failure.retry_poisoned
    );
    println!(
        "production_host_parallel_authenticated_exact_recovery={}",
        failure.authenticated_exact_recovery
    );
}

fn resources(config: PackagedQemuExecutorConfig) -> PackagedQemuExecutorConfig {
    let mut config = fork_resources(config);
    config.capacity = ExecutorCapacity::new(1, 6, 8 << 30, 16 << 30, 150_000)
        .expect("two-node execution and independent replay Service peaks");
    config.host_operational_capacity = crate::HostOperationalCapacity::new(
        16,
        1024,
        16_384,
        2 * 1024 * 1024 * 1024,
        256 * 1024 * 1024,
    )
    .expect("explicit concurrent two-world metadata and staging entitlements");
    let world = HostResourceVector {
        resident_peak_bytes: 2049 * 1024 * 1024,
        backing_peak_bytes: 4 * 1024 * 1024 * 1024,
        metadata_bytes: 512 * 1024 * 1024,
        staging_bytes: 32 * 1024 * 1024,
        paging_io_slots: 2,
        cpu_slots: 2,
        task_slots: 137,
        file_descriptors: 2112,
    };
    config
        .with_assignment_resources(
            world,
            AttemptResourceLimits::new(2, 1024 * 1024 * 1024, 2 * 1024 * 1024 * 1024, 50_000)
                .expect("original two-node semantic bounds"),
        )
        .expect("complete two-node assignment envelope")
        .with_retained_template_resources(world)
        .expect("independent full-world replay envelope")
}

fn successful_lane(
    source: &ScenarioDefForm,
    lane: &str,
    project: u32,
    workers: usize,
) -> SuccessfulLane {
    environment::with_native_repository_environment(
        lane,
        project,
        |root, storage| native_repository(source, root, storage),
        resources,
        |prepared, config, repository| {
            let request = native_request(&repository, config);
            let queued = prepared
                .actor
                .with_supervisor(|actor| {
                    assert!(matches!(
                        actor
                            .submit_attempt(&request)
                            .map_err(|_| HostOperationalError::Unavailable)?
                            .disposition(),
                        SubmitAttemptDisposition::Accepted { .. }
                    ));
                    actor.next_queued().ok_or(HostOperationalError::Unavailable)
                })
                .expect("real serial/parallel assignment admission");
            let store = CampaignExecutorStore::new(repository);
            let model = RoundModel::new(config, store.clone(), workers, false);
            let mut worker = finish_canceled_fixture(prepared, store, queued, model);
            worker
                .model_mut()
                .lane
                .take()
                .expect("completed native round evidence")
        },
    )
}

fn failed_lane(source: &ScenarioDefForm) -> FailureEvidence {
    environment::with_native_repository_environment(
        "parallel-failure",
        24_200,
        |root, storage| native_repository(source, root, storage),
        resources,
        |prepared, config, repository| {
            let (promoted, mut captured) = promote_accepted_checkpoint_with_model(
                prepared,
                config,
                Arc::clone(&repository),
                source,
                |_host, store| RoundModel::new(config, store, 2, true),
            );
            let lane = captured
                .model_mut()
                .lane
                .take()
                .expect("coherent pre-failure boundary");
            let mut failure = captured
                .model_mut()
                .failure
                .take()
                .expect("physical failed-round evidence");
            let queued = enqueue_promoted_resume(
                prepared,
                &promoted,
                AssignmentId::from_bytes([0xe3; 16]).expect("fresh accepted recovery assignment"),
            );
            let store = CampaignExecutorStore::new(repository);
            let model = RecoveryModel {
                config: config.clone(),
                store: store.clone(),
                checkpoints: Arc::clone(&prepared.checkpoints),
                checkpoint: promoted.checkpoint,
                before: lane.boundary,
                recovered: false,
            };
            let worker = finish_canceled_fixture(prepared, store, queued, model);
            failure.authenticated_exact_recovery = worker.model().recovered;
            assert!(failure.authenticated_exact_recovery);
            failure
        },
    )
}

/// Reconciles cancellation only after the model proves actual native shutdown.
fn finish_canceled_fixture<M: AttemptExecutionModel>(
    prepared: &PackagedPreparation,
    store: CampaignExecutorStore,
    queued: QueuedAttempt,
    model: M,
) -> RepositoryAttemptWorker<M> {
    let mut worker = RepositoryAttemptWorker::new(store, model);
    let (queued, result) = worker.execute(queued).into_parts();
    assert!(matches!(result, Err(AttemptWorkerFailure::Canceled(_))));
    prepared
        .actor
        .with_supervisor(|actor| {
            actor
                .stage_and_reconcile_cancellation(&queued)
                .map_err(|_| HostOperationalError::Unavailable)
        })
        .expect("same actor reconciles cancellation after physical cleanup");
    worker
}

struct RoundModel {
    config: PackagedQemuExecutorConfig,
    store: CampaignExecutorStore,
    workers: usize,
    capture_failure: bool,
    lane: Option<SuccessfulLane>,
    failure: Option<FailureEvidence>,
}

impl RoundModel {
    fn new(
        config: &PackagedQemuExecutorConfig,
        store: CampaignExecutorStore,
        workers: usize,
        capture_failure: bool,
    ) -> Self {
        Self {
            config: config.clone(),
            store,
            workers,
            capture_failure,
            lane: None,
            failure: None,
        }
    }
}

impl AttemptExecutionModel for RoundModel {
    type Error = std::io::Error;

    fn execute(
        &mut self,
        input: &AttemptExecutionInput,
        context: &AttemptExecutionContext,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        assert!(context.host_outer_cap_owner().is_some());
        extend_native_operations(context);
        let input = decode_crucible_attempt_execution(&self.store, input)
            .expect("actual authenticated native scenario");
        let source = input.scenario();
        let host = LinuxQemuAttemptHostResourceFactory::open(self.config.host.clone())
            .expect("real cgroup and quota allocator");
        let mut factory = QemuAttemptProductionVmLifecycleFactory::new(
            self.config
                .lifecycle
                .clone()
                .with_maximum_host_workers(self.workers),
            ComposedQemuAttemptResourceGuardFactory::new(host),
        );
        let mut lifecycle = factory
            .begin_fresh(&source.scenario_def(), source, context)
            .expect("admitted production two-node world");
        drive_until_host_round(&mut lifecycle, source, self.workers, context);
        let evidence = lifecycle
            .host_parallelism_evidence()
            .cloned()
            .expect("real host-concurrent evidence");

        let captured = if self.capture_failure {
            assert!(context.checkpoint_request().is_requested());
            assert!(
                lifecycle
                    .exact_checkpoint_ready()
                    .expect("coherent pre-failure checkpoint boundary")
            );
            let capture = lifecycle
                .capture_attempt_checkpoint(context)
                .expect("actual pre-failure native capture");
            let staged = context
                .prepare_and_stage_checkpoint(capture)
                .expect("same-ledger checkpoint handoff before teardown");
            Some(staged)
        } else {
            None
        };
        // Device pre-save callbacks run during capture. Compare recovery to
        // the resulting coherent boundary, before the injected physical fault.
        let boundary = canonical_boundary(&mut lifecycle, source);
        if captured.is_some() {
            self.failure = Some(inject_failed_round(
                &mut lifecycle,
                source,
                &boundary,
                context,
            ));
        }
        lifecycle
            .shutdown()
            .expect("reap every production node before execution reconciliation");
        self.lane = Some(SuccessfulLane { boundary, evidence });

        if let Some(captured) = captured {
            return Ok(AttemptExecutionProduct::exact_checkpoint(captured));
        }
        context.cancellation().cancel();
        Err(AttemptWorkerFailure::Canceled(std::io::Error::other(
            "native host-parallel lane completed and reaped",
        )))
    }
}

fn inject_failed_round(
    lifecycle: &mut ProductionVmLifecycleLoop,
    source: &ScenarioDefForm,
    before: &CanonicalBoundary,
    context: &AttemptExecutionContext,
) -> FailureEvidence {
    let failed = source
        .world()
        .vm_nodes()
        .get(1)
        .expect("two-node source")
        .id
        .clone();
    let healthy = source
        .world()
        .vm_nodes()
        .first()
        .expect("healthy peer")
        .id
        .clone();
    lifecycle
        .quarantine_node(&failed)
        .expect("inject one production node failure");
    let request = QuantumRequest {
        configuration: before.logical.configuration.clone(),
        control: Vec::new(),
    };
    context
        .charge_execution_quantum()
        .expect("original failed-round quantum admission");
    let failure = lifecycle
        .drive_quantum(request.clone())
        .expect_err("failed node poisons the physical round");
    assert!(failure.to_string().contains("QEMU"));
    let healthy_peer_advanced = lifecycle
        .sample_fingerprint(healthy.clone())
        .expect("healthy peer physical state")
        .fingerprint
        != before.fingerprints[&healthy];
    let logical_state_uncommitted = canonical_logical_boundary(lifecycle) == before.logical;
    let retry_poisoned = lifecycle
        .drive_quantum(request)
        .expect_err("retry after an indeterminate round must refuse")
        .to_string()
        .contains("continuation is poisoned");
    assert!(healthy_peer_advanced && logical_state_uncommitted && retry_poisoned);
    FailureEvidence {
        healthy_peer_advanced,
        logical_state_uncommitted,
        retry_poisoned,
        authenticated_exact_recovery: false,
    }
}

struct RecoveryModel {
    config: PackagedQemuExecutorConfig,
    store: CampaignExecutorStore,
    checkpoints: Arc<ExactCheckpointStore>,
    checkpoint: ExactCheckpointId,
    before: CanonicalBoundary,
    recovered: bool,
}

impl AttemptExecutionModel for RecoveryModel {
    type Error = std::io::Error;

    fn execute(
        &mut self,
        input: &AttemptExecutionInput,
        context: &AttemptExecutionContext,
    ) -> Result<AttemptExecutionProduct, AttemptWorkerFailure<Self::Error>> {
        assert!(context.host_outer_cap_owner().is_some());
        extend_native_operations(context);
        assert_eq!(context.resume_checkpoint(), Some(self.checkpoint));
        let input = decode_crucible_attempt_execution(&self.store, input)
            .expect("actual accepted resume semantic basis");
        let source = input.scenario();
        let host = LinuxQemuAttemptHostResourceFactory::open(self.config.host.clone())
            .expect("genuine recovered world containment");
        let mut factory = QemuAttemptProductionVmLifecycleFactory::new(
            self.config.lifecycle.clone().with_maximum_host_workers(2),
            ComposedQemuAttemptResourceGuardFactory::new(host),
        );
        let scenario = source.scenario_def();
        let basis =
            QemuExactResumeBasis::new(&scenario, source, &self.before.logical.configuration, None);
        factory
            .authenticate_resume_boundary(&self.checkpoints, self.checkpoint, basis, context)
            .expect("actual selected-root preflight");
        let mut lifecycle = factory
            .begin_resume(
                &self.checkpoints,
                self.checkpoint,
                QemuExactResumeBasis::new(
                    &source.scenario_def(),
                    source,
                    &self.before.logical.configuration,
                    None,
                ),
                context,
            )
            .expect("production exact restore from accepted promoted root");
        self.recovered = canonical_boundary(&mut lifecycle, source) == self.before;
        assert!(self.recovered);
        drive_until_host_round(&mut lifecycle, source, 2, context);
        lifecycle
            .shutdown()
            .expect("reap restored world before actual cancellation");
        assert!(
            matches!(factory.authenticate_resume_boundary(&self.checkpoints, self.checkpoint, QemuExactResumeBasis::new(&source.scenario_def(), source, &self.before.logical.configuration, None), context), Err(QemuAttemptProductionVmLifecycleError::ResumeCheckpointUnsupported(rejected)) if rejected == self.checkpoint)
        );
        context.cancellation().cancel();
        Err(AttemptWorkerFailure::Canceled(std::io::Error::other(
            "native exact recovery completed and reaped",
        )))
    }
}

fn drive_until_host_round(
    lifecycle: &mut ProductionVmLifecycleLoop,
    source: &ScenarioDefForm,
    maximum_host_workers: usize,
    context: &AttemptExecutionContext,
) {
    let mut configuration = lifecycle
        .resume_state()
        .expect("read initial production boundary")
        .into_parts()
        .0;
    for _ in 0..16 {
        context
            .charge_execution_quantum()
            .expect("original accepted execution quantum budget");
        let outcome = QemuFreshAttemptLifecycleOwner::drive_quantum(
            lifecycle,
            QuantumRequest {
                configuration,
                control: Vec::new(),
            },
        )
        .expect("drive production VM lifecycle");
        configuration = outcome.configuration;
        let Some(evidence) = lifecycle.host_parallelism_evidence() else {
            continue;
        };
        if evidence.requested_runs != source.world().vm_nodes().len() {
            continue;
        }
        assert_eq!(evidence.maximum_workers, maximum_host_workers);
        assert_eq!(evidence.realized_parallelism, maximum_host_workers);
        assert_eq!(
            evidence.commit_order,
            source
                .world()
                .vm_nodes()
                .iter()
                .map(|node| node.id.clone())
                .collect::<Vec<_>>()
        );
        return;
    }
    panic!("production lifecycle did not execute a complete host-concurrent round");
}

fn canonical_boundary(
    lifecycle: &mut ProductionVmLifecycleLoop,
    source: &ScenarioDefForm,
) -> CanonicalBoundary {
    let fingerprints = source
        .world()
        .vm_nodes()
        .iter()
        .map(|node| {
            let sample =
                QemuFreshAttemptLifecycleOwner::sample_fingerprint(lifecycle, node.id.clone())
                    .expect("sample production node fingerprint");
            (node.id.clone(), sample.fingerprint)
        })
        .collect();
    CanonicalBoundary {
        logical: canonical_logical_boundary(lifecycle),
        fingerprints,
    }
}

fn canonical_logical_boundary(
    lifecycle: &mut ProductionVmLifecycleLoop,
) -> CanonicalLogicalBoundary {
    let (scheduler_checkpoint, event_log_segments) = lifecycle
        .canonical_scheduler_evidence()
        .expect("encode production scheduler evidence");
    let (
        configuration,
        event_log,
        event_log_base_events,
        scheduler_quanta,
        scheduler_frontier,
        scheduler_quiescence,
        terminal_verdict,
    ) = lifecycle
        .resume_state()
        .expect("capture production canonical boundary")
        .into_parts();
    assert_eq!(event_log_base_events, 0);

    CanonicalLogicalBoundary {
        configuration,
        event_log,
        event_log_base_events,
        event_log_segments,
        scheduler_checkpoint,
        scheduler_quanta,
        scheduler_frontier,
        scheduler_quiescence,
        terminal_verdict,
    }
}
