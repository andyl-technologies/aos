//! Native real-QEMU acceptance for atomic production whole-world forks.

// crucible-lint: allow panic-shortcut -- ignored native gate assertions use panic shortcuts.
#![allow(clippy::expect_used)]

use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use crucible::model::DagStore;
use crucible::{
    AssertionId, AssertionPhase, Configuration, LocalDagStore, ObservableEventPayload,
    QuantumRequest, SchedulerEventLogPayload, SchedulingNodeKind,
};
use crucible_api::ProductionVmLifecycleConfig;
use crucible_api::vm_lifecycle::{
    ProductionVmHotForkIoNodeKind, ProductionVmHotForkNodeServiceState,
    ProductionVmHotForkSourceWorld,
};
use crucible_qemu::QemuRootImageFormat;
use rustix::time::{ClockId, clock_gettime};

use super::*;
use crate::{
    ComposedQemuAttemptResourceGuardFactory, LinuxQemuAttemptHostConfig,
    LinuxQemuAttemptHostResourceFactory, QemuAttemptProductionVmLifecycleFactory,
};

#[path = "native_acceptance/equivalence.rs"]
mod equivalence;
#[path = "native_acceptance/failures.rs"]
mod failures;
#[path = "native_acceptance/isolation_negative.rs"]
mod isolation_negative;
#[path = "native_acceptance/isolation_native_negative.rs"]
mod isolation_native_negative;
#[path = "native_acceptance/resource_isolation.rs"]
mod resource_isolation;
#[path = "native_acceptance/scenario.rs"]
mod scenario;

const MAX_SOURCE_QUANTA: u64 = 30_000;

struct NativeGatePaths {
    qemu: PathBuf,
    plugin: PathBuf,
    kernel: PathBuf,
    root_image: PathBuf,
    fixture: PathBuf,
    artifacts: PathBuf,
    cgroup_root: PathBuf,
    storage_root: PathBuf,
    run_state_root: PathBuf,
    child_uid: u32,
    child_gid: u32,
}

struct PreparedNativeSource {
    source: crucible::ScenarioDefForm,
    configuration: Configuration,
    world: ProductionVmHotForkSourceWorld,
}

impl NativeGatePaths {
    fn from_environment() -> Self {
        Self {
            qemu: required_path("CRUCIBLE_ATOMIC_WORLD_QEMU"),
            plugin: required_path("CRUCIBLE_ATOMIC_WORLD_PLUGIN"),
            kernel: required_path("CRUCIBLE_ATOMIC_WORLD_KERNEL"),
            root_image: required_path("CRUCIBLE_ATOMIC_WORLD_ROOT"),
            fixture: required_path("CRUCIBLE_ATOMIC_WORLD_SCENARIO"),
            artifacts: required_path("CRUCIBLE_ATOMIC_WORLD_ARTIFACTS"),
            cgroup_root: required_path("CRUCIBLE_ATOMIC_WORLD_CGROUP"),
            storage_root: required_path("CRUCIBLE_ATOMIC_WORLD_STORAGE"),
            run_state_root: required_path("CRUCIBLE_ATOMIC_WORLD_RUN_STATE"),
            child_uid: required_number("CRUCIBLE_ATOMIC_WORLD_UID"),
            child_gid: required_number("CRUCIBLE_ATOMIC_WORLD_GID"),
        }
    }
}

#[test]
#[ignore = "requires the packaged patched QEMU, cgroup v2, and project quotas"]
fn production_factory_forks_complete_live_world_atomically() {
    let paths = NativeGatePaths::from_environment();
    let fixture = fs::read_to_string(&paths.fixture).expect("read representative scenario");
    let artifacts: Arc<dyn DagStore> = Arc::new(LocalDagStore::new(&paths.artifacts));
    let (source, artifacts) = scenario::build(&fixture, artifacts).expect("build source scenario");
    let source_input = execution_input_for_scenario(source.clone());
    let source_context = execution_context(&source_input, 0x70);

    let source_host = open_host(&paths, "source", 1_000);
    let source_config = lifecycle_config(&paths, paths.run_state_root.join("source"), artifacts);
    let mut source_factory = QemuAttemptProductionVmLifecycleFactory::new(
        source_config,
        ComposedQemuAttemptResourceGuardFactory::new(source_host),
    );
    let mut source_lifecycle = source_factory
        .begin_fresh(&source.scenario_def(), &source, &source_context)
        .expect("launch production source world");
    let mut configuration = Configuration::genesis(source.scenario_def());
    let mut observed_http = false;
    let mut observed_block = false;
    let mut observed_ninep = false;
    let mut observed_ninep_fault = false;
    let mut source_quantum = 0;
    let mut source_frontier = 0;

    for quantum in 0..MAX_SOURCE_QUANTA {
        let outcome = source_lifecycle
            .drive_quantum(QuantumRequest {
                configuration,
                control: Vec::new(),
            })
            .expect("drive production source world");
        record_milestone(
            "source-http-satisfied",
            &mut observed_http,
            satisfied(&outcome.event_log_entries, "curl-receives-http-200"),
            quantum,
            outcome.frontier.ticks,
        );
        record_milestone(
            "source-block-satisfied",
            &mut observed_block,
            satisfied(&outcome.event_log_entries, "curl-block-read-complete"),
            quantum,
            outcome.frontier.ticks,
        );
        record_milestone(
            "source-ninep-satisfied",
            &mut observed_ninep,
            satisfied(&outcome.event_log_entries, "io-probe-complete"),
            quantum,
            outcome.frontier.ticks,
        );
        record_milestone(
            "source-ninep-fault-observed",
            &mut observed_ninep_fault,
            satisfied(&outcome.event_log_entries, "io-probe-fault-observed"),
            quantum,
            outcome.frontier.ticks,
        );
        configuration = outcome.configuration;
        source_quantum = quantum;
        source_frontier = outcome.frontier.ticks;

        let evidence = source_lifecycle
            .fault_evidence_snapshot()
            .expect("inspect source service state");
        let failed = evidence
            .nodes
            .iter()
            .any(|node| node.node.name == "nginx" && node.service_state == "permanently_failed");
        if observed_http && observed_block && observed_ninep && observed_ninep_fault && failed {
            eprintln!(
                "atomic-world phase=source-ready quantum={quantum} frontier={}",
                outcome.frontier.ticks
            );
            break;
        }
    }
    assert!(observed_http, "source produced HTTP traffic evidence");
    assert!(observed_block, "source completed the block read");
    assert!(observed_ninep, "source completed the 9p read");
    assert!(
        observed_ninep_fault,
        "source observed the injected 9p error"
    );

    let source_world = source_lifecycle
        .prepare_hot_fork_source_world()
        .expect("prepare complete production source world");
    eprintln!(
        "atomic-world phase=source-prepared quantum={source_quantum} frontier={source_frontier}"
    );
    let continuation = source_world.continuation();
    assert_eq!(continuation.configuration(), &configuration);
    assert_eq!(continuation.nodes().len(), 3);
    assert_eq!(
        continuation
            .nodes()
            .iter()
            .filter(|node| node.service_state() == ProductionVmHotForkNodeServiceState::Running)
            .count(),
        2,
    );
    assert_eq!(
        continuation
            .nodes()
            .iter()
            .filter(|node| {
                node.service_state() == ProductionVmHotForkNodeServiceState::PermanentlyFailed
            })
            .count(),
        1,
    );
    assert!(continuation.io_nodes().iter().any(|node| {
        node.kind() == ProductionVmHotForkIoNodeKind::Block
            && node.owner_service_state() == ProductionVmHotForkNodeServiceState::Running
    }));
    assert!(continuation.io_nodes().iter().any(|node| {
        node.kind() == ProductionVmHotForkIoNodeKind::NineP
            && node.owner_service_state() == ProductionVmHotForkNodeServiceState::Running
    }));
    let running_nodes = continuation
        .nodes()
        .iter()
        .filter(|node| node.service_state() == ProductionVmHotForkNodeServiceState::Running)
        .map(|node| node.node().clone())
        .collect::<Vec<_>>();

    let input = execution_input_for_scenario_configuration(source, configuration.clone());
    let context = execution_context(&input, 0x71);
    let key =
        QemuHotForkSourceWorldKey::for_execution(&input, &context, execution_basis(&input, 0x71))
            .expect("derive exact source key");
    let provider = QemuSingleHotForkSourceWorldProvider::new(key, source_world);
    let target_host = open_host(&paths, "target", 1_100);
    let mut factory = QemuProductionHotForkWorldLifecycleFactory::new(
        provider,
        ComposedQemuAttemptResourceGuardFactory::new(target_host),
        paths.run_state_root.join("target"),
        crucible_qemu::QemuShutdownPolicy::fast_test(),
        crucible_qemu::QemuAsyncDriverPolicy::fast_test(),
    );
    assert!(factory.sources.available());
    let fork_started = operational_monotonic_nanoseconds();
    let mut lifecycle = match factory
        .try_start(&input, &context)
        .expect("atomically fork the complete world")
    {
        QemuHotForkWorldLifecycleStart::Started(lifecycle) => lifecycle,
        QemuHotForkWorldLifecycleStart::Declined => panic!("prepared source was declined"),
    };
    assert!(!factory.sources.available());
    let materialization = lifecycle
        .start_materialization()
        .expect("inspect target start");
    let child_ready_millis = operational_elapsed_milliseconds(fork_started);
    let child_processes = cgroup_processes(&paths.cgroup_root.join("target"));
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
    let child_allocated_bytes = allocated_tree_bytes(&paths.storage_root.join("target"));
    assert_eq!(
        materialization.restored_configuration(),
        Some(&configuration)
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
                QemuFreshAttemptLifecycleOwner::sample_fingerprint(&mut lifecycle, node.clone())
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
    for node in &running_nodes {
        let after =
            QemuFreshAttemptLifecycleOwner::sample_fingerprint(&mut lifecycle, node.clone())
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
    resource_isolation::assert_live_children_are_physically_private(
        &paths.cgroup_root.join("target"),
        &paths.storage_root.join("target"),
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

    QemuFreshAttemptLifecycleOwner::shutdown(&mut lifecycle).expect("shutdown child world");
    reconcile_native_world(&mut lifecycle);
    assert!(factory.recover(lifecycle).is_ok());
    assert!(factory.sources.available());
    eprintln!("atomic-world phase=cleanup-complete source_reusable=true");
}

fn lifecycle_config(
    paths: &NativeGatePaths,
    run_state_root: PathBuf,
    artifacts: Arc<dyn DagStore>,
) -> ProductionVmLifecycleConfig {
    ProductionVmLifecycleConfig::new(
        &paths.qemu,
        &paths.plugin,
        &paths.kernel,
        &paths.root_image,
        run_state_root,
    )
    .with_root_image_format(QemuRootImageFormat::Raw)
    .with_kernel_cmdline_prefix("console=ttyS0 net.ifnames=0 root=/dev/vda rw init=/init")
    .with_world_artifacts(artifacts)
    .with_run_ceiling_icount(50_000_000_000)
    .with_quantum_budget(MAX_SOURCE_QUANTA)
    .with_completion_timeout(Duration::from_secs(300))
}

fn prepare_native_source(
    paths: &NativeGatePaths,
    lane: &str,
    execution_byte: u8,
    project_id_start: u32,
) -> PreparedNativeSource {
    let fixture = fs::read_to_string(&paths.fixture).expect("read representative scenario");
    let artifacts: Arc<dyn DagStore> = Arc::new(LocalDagStore::new(&paths.artifacts));
    let (source, artifacts) = scenario::build(&fixture, artifacts).expect("build source scenario");
    let input = execution_input_for_scenario(source.clone());
    let context = execution_context(&input, execution_byte);
    let host = open_host(paths, &format!("{lane}-source"), project_id_start);
    let config = lifecycle_config(
        paths,
        paths.run_state_root.join(lane).join("source"),
        artifacts,
    );
    let mut factory = QemuAttemptProductionVmLifecycleFactory::new(
        config,
        ComposedQemuAttemptResourceGuardFactory::new(host),
    );
    let mut lifecycle = factory
        .begin_fresh(&source.scenario_def(), &source, &context)
        .expect("launch production source world");
    let mut configuration = Configuration::genesis(source.scenario_def());
    let mut observed_http = false;
    let mut observed_block = false;
    let mut observed_ninep = false;
    let mut observed_ninep_fault = false;
    let mut failed = false;

    for quantum in 0..MAX_SOURCE_QUANTA {
        let outcome = lifecycle
            .drive_quantum(QuantumRequest {
                configuration,
                control: Vec::new(),
            })
            .expect("drive production source world");
        observed_http |= satisfied(&outcome.event_log_entries, "curl-receives-http-200");
        observed_block |= satisfied(&outcome.event_log_entries, "curl-block-read-complete");
        observed_ninep |= satisfied(&outcome.event_log_entries, "io-probe-complete");
        observed_ninep_fault |= satisfied(&outcome.event_log_entries, "io-probe-fault-observed");
        configuration = outcome.configuration;
        failed = lifecycle
            .fault_evidence_snapshot()
            .expect("inspect source service state")
            .nodes
            .iter()
            .any(|node| node.node.name == "nginx" && node.service_state == "permanently_failed");
        if observed_http && observed_block && observed_ninep && observed_ninep_fault && failed {
            eprintln!(
                "atomic-world phase=failure-source-ready lane={lane} quantum={quantum} frontier={}",
                outcome.frontier.ticks
            );
            break;
        }
    }
    assert!(observed_http && observed_block && observed_ninep && observed_ninep_fault && failed);
    let world = lifecycle
        .prepare_hot_fork_source_world()
        .expect("prepare complete production source world");

    PreparedNativeSource {
        source,
        configuration,
        world,
    }
}

fn open_host(
    paths: &NativeGatePaths,
    name: &str,
    project_id_start: u32,
) -> LinuxQemuAttemptHostResourceFactory {
    let config = LinuxQemuAttemptHostConfig::new(
        paths.cgroup_root.join(name),
        paths.storage_root.join(name),
        format!("atomic-world-{name}"),
        project_id_start,
        64,
        paths.child_uid,
        paths.child_gid,
        64,
        1024,
        Duration::from_secs(5),
    )
    .expect("build native host configuration");
    LinuxQemuAttemptHostResourceFactory::open(config).expect("open native host resources")
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

fn cgroup_processes(root: &std::path::Path) -> Vec<u32> {
    let mut processes: Vec<u32> = Vec::new();
    let entries = fs::read_dir(root)
        .unwrap_or_else(|error| panic!("read native target cgroup {}: {error}", root.display()));
    let process_list = fs::read_to_string(root.join("cgroup.procs"))
        .unwrap_or_else(|error| panic!("read native target processes {}: {error}", root.display()));
    processes.extend(process_list.lines().map(|process| {
        process
            .parse::<u32>()
            .unwrap_or_else(|_| panic!("invalid process ID"))
    }));
    for entry in entries {
        let entry = entry.unwrap_or_else(|error| panic!("read cgroup entry: {error}"));
        if entry
            .file_type()
            .unwrap_or_else(|error| panic!("read cgroup entry type: {error}"))
            .is_dir()
        {
            processes.extend(cgroup_processes(&entry.path()));
        }
    }
    processes.sort_unstable();
    processes.dedup();
    processes
}

// Host time is emitted only as operational gate evidence and never enters a
// scenario, decision, fingerprint, checkpoint, or other deterministic state.
fn operational_monotonic_nanoseconds() -> u64 {
    let now = clock_gettime(ClockId::Monotonic);
    let seconds = u64::try_from(now.tv_sec).expect("monotonic seconds fit u64");
    let nanoseconds = u64::try_from(now.tv_nsec).expect("monotonic nanoseconds fit u64");
    seconds
        .checked_mul(1_000_000_000)
        .and_then(|total| total.checked_add(nanoseconds))
        .expect("monotonic clock fits u64 nanoseconds")
}

fn operational_elapsed_milliseconds(start: u64) -> u64 {
    operational_monotonic_nanoseconds().saturating_sub(start) / 1_000_000
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

#[derive(Clone, Copy, Debug, Default)]
struct ProcessMemoryEvidence {
    private_dirty_kib: u64,
    private_rss_kib: u64,
    rss_anon_kib: u64,
    vm_pte_kib: u64,
    vm_data_kib: u64,
    anon_huge_pages_kib: u64,
    numa_resident_pages: u64,
    numa_nodes: usize,
}

fn process_memory_evidence(processes: &[u32]) -> ProcessMemoryEvidence {
    let mut evidence = ProcessMemoryEvidence::default();
    let mut numa_nodes = std::collections::BTreeSet::new();

    for process in processes {
        let private_dirty = process_status_kib(*process, "smaps_rollup", "Private_Dirty:");
        let private_clean = process_status_kib(*process, "smaps_rollup", "Private_Clean:");
        evidence.private_dirty_kib = evidence.private_dirty_kib.saturating_add(private_dirty);
        evidence.private_rss_kib = evidence
            .private_rss_kib
            .saturating_add(private_dirty.saturating_add(private_clean));
        evidence.rss_anon_kib = evidence
            .rss_anon_kib
            .saturating_add(process_status_kib(*process, "status", "RssAnon:"));
        evidence.vm_pte_kib = evidence
            .vm_pte_kib
            .saturating_add(process_status_kib(*process, "status", "VmPTE:"));
        evidence.vm_data_kib = evidence
            .vm_data_kib
            .saturating_add(process_status_kib(*process, "status", "VmData:"));
        evidence.anon_huge_pages_kib =
            evidence
                .anon_huge_pages_kib
                .saturating_add(process_status_kib(
                    *process,
                    "smaps_rollup",
                    "AnonHugePages:",
                ));

        let numa_maps = fs::read_to_string(format!("/proc/{process}/numa_maps"))
            .unwrap_or_else(|error| panic!("read process {process} numa_maps: {error}"));
        for token in numa_maps.split_whitespace() {
            let Some((node, pages)) = token.split_once('=') else {
                continue;
            };
            let Some(node) = node.strip_prefix('N') else {
                continue;
            };
            if node.chars().all(|character| character.is_ascii_digit()) {
                numa_nodes.insert(node.to_owned());
                evidence.numa_resident_pages = evidence
                    .numa_resident_pages
                    .saturating_add(pages.parse::<u64>().unwrap_or(0));
            }
        }
    }
    evidence.numa_nodes = numa_nodes.len();
    evidence
}

fn process_thread_count(processes: &[u32]) -> usize {
    processes
        .iter()
        .map(|process| {
            fs::read_dir(format!("/proc/{process}/task"))
                .unwrap_or_else(|error| panic!("read process {process} threads: {error}"))
                .count()
        })
        .sum()
}

fn process_descriptor_count(processes: &[u32]) -> usize {
    processes
        .iter()
        .map(|process| {
            fs::read_dir(format!("/proc/{process}/fd"))
                .unwrap_or_else(|error| panic!("read process {process} descriptors: {error}"))
                .count()
        })
        .sum()
}

fn allocated_tree_bytes(root: &std::path::Path) -> u64 {
    let metadata = fs::symlink_metadata(root)
        .unwrap_or_else(|error| panic!("inspect native storage {}: {error}", root.display()));
    let mut allocated = metadata.blocks().saturating_mul(512);
    if !metadata.is_dir() {
        return allocated;
    }
    for entry in fs::read_dir(root)
        .unwrap_or_else(|error| panic!("read native storage {}: {error}", root.display()))
    {
        let entry = entry.unwrap_or_else(|error| panic!("read native storage entry: {error}"));
        allocated = allocated.saturating_add(allocated_tree_bytes(&entry.path()));
    }
    allocated
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

fn record_milestone(phase: &str, observed: &mut bool, present: bool, quantum: u64, frontier: u64) {
    if !*observed && present {
        *observed = true;
        eprintln!("atomic-world phase={phase} quantum={quantum} frontier={frontier}");
    }
}

fn reconcile_native_world<G>(lifecycle: &mut QemuProductionHotForkWorldLifecycle<G>)
where
    G: QemuAttemptProcessResourceGuard,
{
    for _ in 0..64 {
        if lifecycle
            .reconcile_execution_disposition(AttemptExecutionDisposition::Canceled)
            .expect("reconcile native child world")
            == AttemptExecutionReconciliationStep::Complete
        {
            return;
        }
    }
    panic!("native child world did not reconcile within 64 steps");
}
