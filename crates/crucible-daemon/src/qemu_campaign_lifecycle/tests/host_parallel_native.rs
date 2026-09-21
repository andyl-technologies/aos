//! Real-QEMU production-lifecycle evidence for bounded host-concurrent rounds.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use crucible::model::WorldNodeDef;
use crucible::{Plan, Properties, QuantumRequest, Seed};
use crucible_campaign::{AssignmentId, CampaignHash, ExactCheckpointId};
use crucible_cas::content_store::{DirectoryBlobBackend, ImmutableBlobBackend};

use super::*;
use crate::{
    ComposedQemuAttemptResourceGuardFactory, ExactCheckpointStore, LinuxQemuAttemptHostConfig,
    LinuxQemuAttemptHostResourceFactory,
};

const RENDEZVOUS_ICOUNT: u64 = 8_000_000;
const MAX_CHECKPOINT_BYTES: u64 = 4 * 1024 * 1024 * 1024;

struct NativePaths {
    qemu: PathBuf,
    plugin: PathBuf,
    kernel: PathBuf,
    root_image: PathBuf,
    fixture: PathBuf,
    cgroup_root: PathBuf,
    storage_root: PathBuf,
    run_state_root: PathBuf,
    checkpoint_root: PathBuf,
    child_uid: u32,
    child_gid: u32,
}

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

struct FailureEvidence {
    healthy_peer_advanced: bool,
    logical_state_uncommitted: bool,
    retry_poisoned: bool,
    authenticated_exact_recovery: bool,
}

#[test]
#[ignore = "requires packaged QEMU, cgroup v2, and project quotas"]
fn production_lifecycle_host_parallel_rounds_are_canonical_and_recoverable() {
    let paths = NativePaths::from_environment();
    let source = two_node_source(&paths.fixture);
    let input = execution_input(source.clone());

    let serial = run_successful_lane(&paths, &source, &input, "host-serial", 24_000, 1);
    let parallel = run_successful_lane(&paths, &source, &input, "host-parallel", 24_100, 2);
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
    assert!(state_identity);
    assert!(time_identity);
    assert!(canonical_log_identity);
    assert!(worker_count_absent_from_checkpoint);
    assert_eq!(serial.boundary, parallel.boundary);

    let failure = run_failure_and_exact_recovery(&paths, &source, &input);

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

fn run_successful_lane(
    paths: &NativePaths,
    source: &ScenarioDefForm,
    input: &CrucibleAttemptExecution,
    lane: &str,
    project_id: u32,
    maximum_host_workers: usize,
) -> SuccessfulLane {
    let context = execution_context(
        input,
        u8::try_from(maximum_host_workers).expect("worker byte"),
    );
    let mut lifecycle = begin_fresh(
        paths,
        source,
        &context,
        lane,
        project_id,
        maximum_host_workers,
    );
    drive_until_host_round(&mut lifecycle, source, maximum_host_workers);
    let boundary = canonical_boundary(&mut lifecycle, source);
    let evidence = lifecycle
        .host_parallelism_evidence()
        .cloned()
        .expect("complete host-concurrent round evidence");

    QemuFreshAttemptLifecycleOwner::shutdown(&mut lifecycle)
        .expect("shutdown successful production host-parallel lane");
    SuccessfulLane { boundary, evidence }
}

fn run_failure_and_exact_recovery(
    paths: &NativePaths,
    source: &ScenarioDefForm,
    input: &CrucibleAttemptExecution,
) -> FailureEvidence {
    let context = execution_context(input, 3);
    let mut lifecycle = begin_fresh(paths, source, &context, "host-failure", 24_200, 2);
    drive_until_host_round(&mut lifecycle, source, 2);
    assert!(
        lifecycle
            .exact_checkpoint_ready()
            .expect("inspect pre-failure checkpoint boundary")
    );

    let checkpoint_store = checkpoint_store(&paths.checkpoint_root);
    let captured =
        QemuFreshAttemptLifecycleOwner::capture_attempt_checkpoint(&mut lifecycle, &context)
            .expect("capture pre-failure exact checkpoint");
    let prepared = checkpoint_store
        .prepare_attempt_checkpoint(&captured)
        .expect("prepare pre-failure exact checkpoint");
    let checkpoint = checkpoint_store
        .publish_attempt_checkpoint(&prepared)
        .expect("publish pre-failure exact checkpoint")
        .root();
    let before = canonical_boundary(&mut lifecycle, source);

    let failed_node = source
        .world()
        .vm_nodes()
        .get(1)
        .expect("two-node source")
        .id
        .clone();
    let healthy_node = source
        .world()
        .vm_nodes()
        .first()
        .expect("two-node source")
        .id
        .clone();
    lifecycle
        .quarantine_node(&failed_node)
        .expect("force one production node failure");
    let request = QuantumRequest {
        configuration: before.logical.configuration.clone(),
        control: Vec::new(),
    };
    let failure = QemuFreshAttemptLifecycleOwner::drive_quantum(&mut lifecycle, request.clone())
        .expect_err("one failed production node must poison the round");
    assert!(failure.to_string().contains("QEMU"));
    let healthy_peer_advanced =
        QemuFreshAttemptLifecycleOwner::sample_fingerprint(&mut lifecycle, healthy_node.clone())
            .expect("sample healthy peer after failed round")
            .fingerprint
            != before
                .fingerprints
                .get(&healthy_node)
                .expect("pre-round healthy fingerprint")
                .clone();
    assert!(healthy_peer_advanced);
    let logical_state_uncommitted = canonical_logical_boundary(&mut lifecycle) == before.logical;
    assert!(logical_state_uncommitted);
    let retry = QemuFreshAttemptLifecycleOwner::drive_quantum(&mut lifecycle, request)
        .expect_err("an indeterminate physical round must reject retry");
    let retry_poisoned = retry.to_string().contains("continuation is poisoned");
    assert!(retry_poisoned);
    QemuFreshAttemptLifecycleOwner::shutdown(&mut lifecycle)
        .expect("contain poisoned production lifecycle");

    let origin = exact_checkpoint_origin(checkpoint);
    let selected = Some(
        crate::executor_supervisor::SelectedExactCheckpointRoot::from_test_checkpoint(checkpoint),
    );
    let recovery_context = execution_context(input, 4)
        .with_execution_origin(origin)
        .install_selected_checkpoint(selected);
    let mut recovery_factory = QemuAttemptProductionVmLifecycleFactory::new(
        lifecycle_config(paths, "host-recovery", 2),
        ComposedQemuAttemptResourceGuardFactory::new(open_host(paths, "host-recovery", 24_300)),
    );
    let mut recovered = recovery_factory
        .begin_resume(
            &checkpoint_store,
            checkpoint,
            QemuExactResumeBasis::new(
                &source.scenario_def(),
                source,
                &before.logical.configuration,
                None,
            ),
            &recovery_context,
        )
        .expect("restore authenticated pre-failure exact checkpoint");
    let authenticated_exact_recovery = canonical_boundary(&mut recovered, source) == before;
    assert!(authenticated_exact_recovery);
    drive_until_host_round(&mut recovered, source, 2);
    QemuFreshAttemptLifecycleOwner::shutdown(&mut recovered)
        .expect("shutdown exact-recovered production lifecycle");

    FailureEvidence {
        healthy_peer_advanced,
        logical_state_uncommitted,
        retry_poisoned,
        authenticated_exact_recovery,
    }
}

fn drive_until_host_round(
    lifecycle: &mut ProductionVmLifecycleLoop,
    source: &ScenarioDefForm,
    maximum_host_workers: usize,
) {
    let mut configuration = lifecycle
        .resume_state()
        .expect("read initial production boundary")
        .into_parts()
        .0;
    for _ in 0..16 {
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

fn begin_fresh(
    paths: &NativePaths,
    source: &ScenarioDefForm,
    context: &AttemptExecutionContext,
    lane: &str,
    project_id: u32,
    maximum_host_workers: usize,
) -> ProductionVmLifecycleLoop {
    let mut factory = QemuAttemptProductionVmLifecycleFactory::new(
        lifecycle_config(paths, lane, maximum_host_workers),
        ComposedQemuAttemptResourceGuardFactory::new(open_host(paths, lane, project_id)),
    );
    factory
        .begin_fresh(&source.scenario_def(), source, context)
        .expect("launch production VM lifecycle")
}

fn lifecycle_config(
    paths: &NativePaths,
    lane: &str,
    maximum_host_workers: usize,
) -> ProductionVmLifecycleConfig {
    ProductionVmLifecycleConfig::new(
        &paths.qemu,
        &paths.plugin,
        &paths.kernel,
        &paths.root_image,
        paths.run_state_root.join(lane),
    )
    .with_root_image_format(crucible_qemu::QemuRootImageFormat::Raw)
    .with_kernel_cmdline_prefix("console=ttyS0 net.ifnames=0 root=/dev/vda rw init=/init")
    .with_run_ceiling_icount(50_000_000_000)
    .with_rendezvous_interval_icount(RENDEZVOUS_ICOUNT)
    .with_quantum_budget(64)
    .with_completion_timeout(Duration::from_secs(300))
    .with_maximum_host_workers(maximum_host_workers)
}

fn open_host(
    paths: &NativePaths,
    lane: &str,
    project_id: u32,
) -> LinuxQemuAttemptHostResourceFactory {
    let config = LinuxQemuAttemptHostConfig::new(
        paths.cgroup_root.join(lane),
        paths.storage_root.join(lane),
        format!("production-host-parallel-{lane}"),
        project_id,
        1,
        paths.child_uid,
        paths.child_gid,
        64,
        1024,
        Duration::from_secs(5),
    )
    .expect("build production host configuration");
    LinuxQemuAttemptHostResourceFactory::open(config).expect("open production host resources")
}

fn checkpoint_store(root: &Path) -> ExactCheckpointStore {
    let backend: Arc<dyn ImmutableBlobBackend> =
        Arc::new(DirectoryBlobBackend::new("host-parallel-recovery", root));
    ExactCheckpointStore::new(backend, MAX_CHECKPOINT_BYTES).expect("open exact checkpoint store")
}

fn two_node_source(fixture: &Path) -> ScenarioDefForm {
    let fixture = fs::read_to_string(fixture).expect("read production host-parallel scenario");
    let base = ScenarioDefForm::from_canonical_toml(&fixture).expect("parse scenario fixture");
    let nodes = base
        .world()
        .vm_nodes()
        .iter()
        .take(2)
        .cloned()
        .map(WorldNodeDef::Vm)
        .collect();
    let world = World::from_node_defs_and_links(nodes, Vec::new()).expect("build two-node world");
    ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(29),
    )
    .expect("build production host-parallel source")
}

fn execution_input(source: ScenarioDefForm) -> CrucibleAttemptExecution {
    let definition = source.scenario_def();
    let scenario_artifact = crate::encode_crucible_scenario_artifact(&source)
        .expect("encode host-parallel scenario artifact");
    let scenario_id = scenario_artifact.scenario();
    let scenario_content = scenario_artifact.id().expect("scenario artifact ID");
    let configuration = Configuration::genesis(definition);
    let configuration_artifact =
        crate::encode_crucible_configuration_artifact(&scenario_artifact, &configuration.schedule)
            .expect("encode host-parallel configuration artifact");
    let configuration_id = configuration_artifact.configuration();
    let configuration_content = configuration_artifact
        .id()
        .expect("configuration artifact ID");
    let lineage = CampaignLineage::new(
        scenario_id,
        scenario_content,
        configuration_id,
        configuration_content,
        "crucible-host-parallel",
        "qemu-production",
        BTreeMap::from([(String::from("control"), 1)]),
        scenario_artifact.payload_schema(),
        1,
    )
    .expect("build host-parallel lineage");
    let path = BranchPath::new(Vec::new()).expect("build genesis branch path");
    let attempt = Attempt::new(
        AttemptStart::Discover {
            configuration: configuration_content,
        },
        path.id().expect("branch path ID"),
        StopCondition::Terminal,
    )
    .expect("build host-parallel attempt");

    CrucibleAttemptExecution::from_test_parts(
        lineage,
        source,
        attempt,
        path,
        CrucibleResolvedAttemptStart::Discover { configuration },
    )
}

fn execution_context(input: &CrucibleAttemptExecution, byte: u8) -> AttemptExecutionContext {
    AttemptExecutionContext::new(
        AttemptResourceLimits::new(8, 8 << 30, 8 << 30, 128)
            .expect("host-parallel attempt resources"),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        ExecutionCheckpointRequest::default(),
        crucible_campaign::AttemptRetentionPolicyDisposition::Disabled,
    )
    .with_runtime_basis(crate::AttemptExecutionRuntimeBasis::new(
        crate::AttemptExecutionKey::new(
            input.lineage().id().expect("lineage ID"),
            input.attempt().id().expect("attempt ID"),
        ),
        ExecutionId::from_bytes([byte; 16]).expect("execution ID"),
    ))
}

fn exact_checkpoint_origin(checkpoint: ExactCheckpointId) -> AttemptExecutionOrigin {
    AttemptExecutionOrigin::ExactCheckpoint {
        assignment: AssignmentId::from_bytes([0x29; 16]).expect("assignment ID"),
        request_digest: CampaignHash::derive("crucible.perf.host-parallel.recovery.v1", b"resume"),
        prior_execution: ExecutionId::from_bytes([0x2a; 16]).expect("prior execution ID"),
        checkpoint,
    }
}

impl NativePaths {
    fn from_environment() -> Self {
        Self {
            qemu: required_path("CRUCIBLE_HOST_PARALLEL_QEMU"),
            plugin: required_path("CRUCIBLE_HOST_PARALLEL_PLUGIN"),
            kernel: required_path("CRUCIBLE_HOST_PARALLEL_KERNEL"),
            root_image: required_path("CRUCIBLE_HOST_PARALLEL_ROOT"),
            fixture: required_path("CRUCIBLE_HOST_PARALLEL_SCENARIO"),
            cgroup_root: required_path("CRUCIBLE_HOST_PARALLEL_CGROUP"),
            storage_root: required_path("CRUCIBLE_HOST_PARALLEL_STORAGE"),
            run_state_root: required_path("CRUCIBLE_HOST_PARALLEL_RUN_STATE"),
            checkpoint_root: required_path("CRUCIBLE_HOST_PARALLEL_CHECKPOINTS"),
            child_uid: required_number("CRUCIBLE_HOST_PARALLEL_UID"),
            child_gid: required_number("CRUCIBLE_HOST_PARALLEL_GID"),
        }
    }
}

fn required_path(name: &str) -> PathBuf {
    PathBuf::from(std::env::var_os(name).unwrap_or_else(|| panic!("{name} must be set")))
}

fn required_number(name: &str) -> u32 {
    std::env::var(name)
        .unwrap_or_else(|_| panic!("{name} must be set"))
        .parse()
        .unwrap_or_else(|_| panic!("{name} must be an unsigned integer"))
}
