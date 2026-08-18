//! Production local-VM lifecycle loop construction.
//!
//! This module owns the process-local composition from a submitted
//! [`ScenarioDefForm`] to the authoritative [`SingleScheduler`], one live
//! scheduler-facing QEMU node per World VM, and the node-addressed backend loop
//! consumed by [`LifecycleControlPlane`](crate::LifecycleControlPlane).

use std::collections::BTreeMap;
use std::fs;
use std::fs::{File, OpenOptions};
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

use crate::vm_resume::{
    PRODUCTION_ROOT_OVERLAY_FILE_NAME, PRODUCTION_VMSTATE_FILE_NAME, ProductionAppRandomConfig,
    ProductionGdbstubChannelConfig, ProductionGuestArchitecture, ProductionLiveNodeStepGateConfig,
    ProductionNodeSet, ProductionPluginSwitch, ProductionRootImageFormat,
    launch_production_live_node, launch_production_live_node_exact_snapshot,
    launch_production_live_node_exact_snapshot_paused,
};
use crucible::model::{
    FaultCoordinate, HostFaultAdapterManifests, OwnedDagSignalArtifactProvider,
    ResolvedEffectTrace, SignalArtifactProvider, SignalBoundarySnapshot,
};
use crucible::{
    Action, AssertionPhase, BackendQuantumLoop, BlackBoxHostOracle, Checkpoint, CheckpointKind,
    CheckpointTerminalCause, ConditionEvaluationPass, ConditionLeaf, Configuration, ContentHash,
    ControlOperation, DagStore, DebugGdbEndpoint, DebugRetiredWorldCleanup,
    DebugRuntimeRepositionReport, DebugRuntimeRepositionRequest, Decision, EventFirings,
    EventGraph, EventGraphState, EventLogOffset, FingerprintSample, GdbAttachInfo, GdbListen,
    HostAssertionEvaluator, HostAssertionEvaluatorCheckpoint, HostAssertionOutcome,
    HostAssertionOutcomeKind, Icount, NodeId, NodeLifecycle, ObservableEvent, QuantumLoop,
    QuantumOutcome, QuantumRequest, QuantumTerminalVerdict, RuntimeState, ScenarioDef,
    ScenarioDefForm, Schedule, SchedulerError, SchedulerEventLogAppend, SchedulerEventLogEntry,
    SchedulerLivenessScenario, SchedulerNodeActivity, SchedulerState, SearchFrontierChoices, Seed,
    Shift, SimDuration, SimInstant, SimulationBackend, SingleScheduler, SingleSchedulerCheckpoint,
    VirtualTime, VmArchitecture, World,
};
use crucible_qemu::{
    ProductionFaultRuntime, ProductionFaultRuntimeCheckpoint, ProductionNetworkStateCheckpoint,
    QemuNode, QemuNodeLifecycleDecision, QemuProcessIdentity, QemuVmSnapshot,
    linux_process_identity, quarantine_orphaned_qemu_process,
};

use crate::LifecycleApiError;
use crate::debug_gateway::DebugGatewayProcess;

mod assets;
use assets::*;
mod checkpoint_store;
use checkpoint_store::{load_exact_checkpoint_set, persist_exact_checkpoint_set};
mod checkpoint_dependencies;
pub use checkpoint_dependencies::collect_signal_artifact_objects;
mod fault_implementation;

/// Default final icount available to one production CLI lifecycle session.
const DEFAULT_RUN_CEILING_ICOUNT: u64 = 16_000_000;
/// Default scheduler quantum budget for one production CLI lifecycle session.
const DEFAULT_QUANTUM_BUDGET: u64 = 4_096;
/// Per-direction shared-memory frame capacity for production VM nodes.
const PRODUCTION_QUEUE_CAPACITY: u32 = 1_024;
/// Maximum number of trigger batches admitted at one scheduler boundary.
const MAX_TRIGGER_SETTLE_BATCHES: usize = 1_024;

/// Immutable artifacts and bounds for local production QEMU execution.
#[derive(Clone)]
pub struct ProductionVmLifecycleConfig {
    executable: PathBuf,
    plugin: PathBuf,
    native_guest_architecture: VmArchitecture,
    guest_assets: BTreeMap<VmArchitecture, ProductionVmGuestAssets>,
    initrd: Option<PathBuf>,
    kernel_cmdline_prefix: Option<String>,
    root_image_format: ProductionRootImageFormat,
    run_state_root: PathBuf,
    run_ceiling_icount: u64,
    quantum_budget: u64,
    rendezvous_interval_icount: Option<u64>,
    completion_timeout: Duration,
    coverage: ProductionPluginSwitch,
    debug_gateway_executable: Option<PathBuf>,
    debug: Option<ProductionVmDebugConfig>,
    branch: Option<ProductionVmBranchConfig>,
    branch_network_choices: Vec<crucible::OverrideDecision>,
    signal_artifacts: Option<Arc<dyn DagStore>>,
    fault_replay: Option<ResolvedEffectTrace>,
    world_artifacts: Option<Arc<dyn DagStore>>,
    restore_checkpoint: Option<ProductionVmExactCheckpointSet>,
    validate_guest_asset_references: bool,
}

impl std::fmt::Debug for ProductionVmLifecycleConfig {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductionVmLifecycleConfig")
            .field("executable", &self.executable)
            .field("plugin", &self.plugin)
            .field("native_guest_architecture", &self.native_guest_architecture)
            .field("guest_assets", &self.guest_assets)
            .field("initrd", &self.initrd)
            .field("root_image_format", &self.root_image_format)
            .field("run_state_root", &self.run_state_root)
            .field("run_ceiling_icount", &self.run_ceiling_icount)
            .field("quantum_budget", &self.quantum_budget)
            .field("completion_timeout", &self.completion_timeout)
            .field("coverage", &self.coverage)
            .field("debug", &self.debug)
            .field("branch", &self.branch)
            .field("branch_network_choices", &self.branch_network_choices)
            .field(
                "signal_artifacts_configured",
                &self.signal_artifacts.is_some(),
            )
            .field("fault_replay_configured", &self.fault_replay.is_some())
            .field(
                "world_artifacts_configured",
                &self.world_artifacts.is_some(),
            )
            .field("restore_checkpoint", &self.restore_checkpoint.is_some())
            .finish()
    }
}

/// Debugger channel requested for one production QEMU lifecycle node.
#[derive(Clone, Debug)]
struct ProductionVmDebugConfig {
    node: Option<String>,
    operator_listen: String,
    all_nodes: bool,
    allow_requested_loopback_listen: bool,
}

#[derive(Clone, Debug)]
struct ProductionVmBranchConfig {
    base: Configuration,
    frontier: VirtualTime,
    decisions: Vec<Decision>,
    seed: Option<Seed>,
}

fn production_fault_search_overrides(
    branch: Option<&ProductionVmBranchConfig>,
) -> Result<
    BTreeMap<crucible::model::SearchChoiceId, crucible::model::SearchOverride>,
    LifecycleApiError,
> {
    let mut overrides = BTreeMap::new();
    let Some(branch) = branch else {
        return Ok(overrides);
    };
    for decision in &branch.decisions {
        let Decision::Override(decision) = decision else {
            continue;
        };
        if !decision.point.key.starts_with("signal-fault/") {
            continue;
        }
        let (id, search_override) =
            crucible::model::SearchOverride::from_override_decision(decision)
                .ok_or_else(|| loop_factory_error("malformed signal-fault branch override"))?;
        if search_override.parent_branch != Some(branch.base.id()) {
            return Err(loop_factory_error(
                "signal-fault branch override names a different parent configuration",
            ));
        }
        if overrides.insert(id, search_override).is_some() {
            return Err(loop_factory_error(
                "signal-fault branch repeats one search-choice identity",
            ));
        }
    }
    Ok(overrides)
}

/// Original live-execution evidence sampled at one scheduler boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ProductionVmDebugRuntimeEvidence {
    configuration: ContentHash,
    event_log: EventLogOffset,
    scheduler: SchedulerState,
    node_icounts: BTreeMap<NodeId, Icount>,
    node_times: BTreeMap<NodeId, VirtualTime>,
    fingerprints: BTreeMap<NodeId, FingerprintSample>,
    graph_runtimes: Vec<RuntimeState>,
    runtime: Option<RuntimeState>,
}

#[derive(Clone, Debug)]
struct ProductionVmExactCheckpointTarget {
    configuration: Configuration,
    counter: u64,
    scheduler_time: VirtualTime,
    snapshot: QemuVmSnapshot,
    overlay_artifact: ProductionCheckpointArtifact,
    vmstate_artifact: ProductionCheckpointArtifact,
    fault_checkpoint: ProductionFaultRuntimeCheckpoint,
    manifest_identity: crucible::ContentHash,
}

#[derive(Clone, Debug)]
struct ProductionCheckpointArtifact {
    source: ProductionCheckpointArtifactSource,
    identity: ContentHash,
    length: u64,
    chunks: Vec<ContentHash>,
}

#[derive(Clone, Debug)]
enum ProductionCheckpointArtifactSource {
    File(PathBuf),
    ChunkStore(PathBuf),
}

#[derive(Clone, Debug)]
struct ProductionVmExactCheckpointSet {
    identity: ContentHash,
    configuration: Configuration,
    scheduler: SingleSchedulerCheckpoint,
    event_log_objects: BTreeMap<ContentHash, Vec<u8>>,
    signal_artifact_objects: BTreeMap<ContentHash, Vec<u8>>,
    trigger_state: EventGraphState,
    assertion_state: HostAssertionEvaluatorCheckpoint,
    terminal_verdict: Option<QuantumTerminalVerdict>,
    terminal_cause: Option<CheckpointTerminalCause>,
    initial_lifecycle_observations_pending: bool,
    branch: Option<ProductionVmBranchConfig>,
    recorded_controls: Vec<ProductionVmRecordedControl>,
    fault_checkpoint: ProductionFaultRuntimeCheckpoint,
    targets: BTreeMap<NodeId, ProductionVmExactCheckpointTarget>,
    node_generations: BTreeMap<NodeId, u64>,
    node_service_states: BTreeMap<NodeId, ProductionNodeServiceState>,
}

fn validate_exact_checkpoint_artifact(
    artifact: &ProductionCheckpointArtifact,
    role: &str,
) -> Result<(), LifecycleApiError> {
    let observed = match &artifact.source {
        ProductionCheckpointArtifactSource::File(path) => hash_file(path).map_err(|error| {
            loop_factory_error(format!(
                "read exact checkpoint {role} artifact {}: {error}",
                path.display()
            ))
        })?,
        ProductionCheckpointArtifactSource::ChunkStore(directory) => {
            checkpoint_store::validate_chunked_artifact(directory, artifact)?
        }
    };
    if observed != artifact.identity {
        return Err(loop_factory_error(format!(
            "exact checkpoint {role} artifact failed content authentication"
        )));
    }
    Ok(())
}

fn validate_exact_checkpoint_target(
    node: &NodeId,
    target: &ProductionVmExactCheckpointTarget,
) -> Result<(), LifecycleApiError> {
    validate_exact_checkpoint_artifact(&target.overlay_artifact, "root overlay")?;
    validate_exact_checkpoint_artifact(&target.vmstate_artifact, "VMState")?;
    let observed = ContentHash::from_canonical_material(
        "crucible.production-vm-exact-checkpoint.v1",
        &format!(
            "configuration={}\nnode={}\ncounter={}\nscheduler_time={}\nsnapshot={}\nfault={}\noverlay={}\nvmstate={}",
            target.configuration.id().to_hex(),
            node.name,
            target.counter,
            target.scheduler_time.ticks,
            target.snapshot.id().to_hex(),
            target.fault_checkpoint.id().to_hex(),
            target.overlay_artifact.identity.to_hex(),
            target.vmstate_artifact.identity.to_hex(),
        ),
    );
    if observed != target.manifest_identity {
        return Err(loop_factory_error(format!(
            "exact checkpoint target for `{}` failed manifest authentication",
            node.name
        )));
    }
    Ok(())
}

fn copy_exact_checkpoint_artifact(
    source: &ProductionCheckpointArtifact,
    destination: &Path,
    role: &str,
) -> Result<(), LifecycleApiError> {
    checkpoint_store::materialize_checkpoint_artifact(source, destination, role)?;
    validate_exact_checkpoint_artifact(
        &ProductionCheckpointArtifact {
            source: ProductionCheckpointArtifactSource::File(destination.to_path_buf()),
            identity: source.identity,
            length: source.length,
            chunks: Vec::new(),
        },
        role,
    )
}

#[derive(Clone, Debug)]
struct ProductionVmRecordedControl {
    configuration: Configuration,
    node_times: BTreeMap<NodeId, VirtualTime>,
    control: Vec<ControlOperation>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProductionNodeServiceState {
    Running,
    PoweredOff,
    PermanentlyFailed,
}

/// Read-only evidence for one active production network outage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionNetworkOutageEvidence {
    /// Concrete World target whose route stages reject frames.
    pub target: crucible::model::ResolvedFaultTarget,
    /// Exclusive virtual-time end of the outage.
    pub unavailable_until_nanos: u64,
}

/// Read-only evidence for one live production network queue.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionNetworkQueueEvidence {
    /// Concrete World queue target owning the reservations.
    pub target: crucible::model::ResolvedFaultTarget,
    /// Number of frames currently reserved in the queue.
    pub reservations: usize,
    /// Canonical digest of the complete queue continuation.
    pub continuation_digest: ContentHash,
    /// Latest scheduled completion among current reservations.
    pub last_finish_nanos: Option<u64>,
}

/// Read-only evidence for one authoritative production block continuation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionBlockFaultEvidence {
    /// Immutable World identity of the attached block device.
    pub device: ContentHash,
    /// Number of currently live volatile-cache fragments.
    pub volatile_entries: usize,
    /// Canonical digest of the complete volatile-cache entry set.
    pub volatile_entries_digest: ContentHash,
    /// Exclusive durable write frontier.
    pub actual_durable_frontier: u64,
    /// Number of leading guest-visible bytes covered by `visible_prefix_digest`.
    pub visible_prefix_bytes: u32,
    /// Canonical digest of the bounded guest-visible prefix.
    pub visible_prefix_digest: ContentHash,
}

/// Read-only evidence for one production QEMU node continuation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionNodeFaultEvidence {
    /// World node identity.
    pub node: NodeId,
    /// Monotone process generation, incremented by terminal replacement.
    pub generation: u64,
    /// Stable service-state spelling used in evidence artifacts.
    pub service_state: &'static str,
}

/// Exact observable state of all production fault adapters at one boundary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProductionFaultEvidenceSnapshot {
    /// Scheduler frontier at which the snapshot was collected.
    pub frontier: VirtualTime,
    /// Committed replay trace, including pass work items.
    pub resolved_effect_trace: Option<ResolvedEffectTrace>,
    /// Committed locked-effect replay trace, including pass work items.
    pub locked_effect_trace: Option<ResolvedEffectTrace>,
    /// Signal events emitted in authoritative evaluation order.
    pub emitted_events: Vec<crucible::model::ReferencedSignalEvent>,
    /// Network outages active at `frontier`.
    pub network_outages: Vec<ProductionNetworkOutageEvidence>,
    /// Live network queues with at least one reservation.
    pub network_queues: Vec<ProductionNetworkQueueEvidence>,
    /// Authoritative live block continuations in device-identity order.
    pub block_devices: Vec<ProductionBlockFaultEvidence>,
    /// Live-QEMU service state in World node order.
    pub nodes: Vec<ProductionNodeFaultEvidence>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum ProductionLifecycleJournalPhase {
    Idle,
    Intent,
    Prepared,
    ExitsReaped,
    Committed,
    Quarantined,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct ProductionLifecycleJournalNode {
    node: String,
    current_process: QemuProcessIdentity,
    replacement_process: Option<QemuProcessIdentity>,
    current_generation: u64,
    next_generation: u64,
    transition: String,
    action_sha256: String,
    evidence_sha256: String,
    expected_exit_code: Option<i32>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct ProductionLifecycleCompletedExit {
    transaction: u64,
    node: String,
    process: QemuProcessIdentity,
    generation: u64,
    transition: String,
    action_sha256: String,
    evidence_sha256: String,
    expected_exit_code: i32,
    observed_exit_code: i32,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct ProductionLifecycleJournal {
    version: u32,
    transaction: u64,
    phase: ProductionLifecycleJournalPhase,
    nodes: Vec<ProductionLifecycleJournalNode>,
    completed_exits: Vec<ProductionLifecycleCompletedExit>,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct ProductionRunManifest {
    version: u32,
    scenario: String,
    owner: QemuProcessIdentity,
    processes: BTreeMap<String, QemuProcessIdentity>,
    staged_processes: BTreeMap<String, QemuProcessIdentity>,
    clean_shutdown: bool,
    recovered_after_host_exit: bool,
}

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
struct ProductionRunLockRecord {
    owner: QemuProcessIdentity,
}

struct ProductionRunLock {
    path: PathBuf,
}

impl Drop for ProductionRunLock {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.path);
    }
}

struct ProductionRunDirectory {
    path: PathBuf,
    _temporary: Option<tempfile::TempDir>,
}

impl ProductionRunDirectory {
    fn path(&self) -> &Path {
        &self.path
    }

    #[cfg(test)]
    fn temporary() -> Result<Self, std::io::Error> {
        let temporary = tempfile::tempdir()?;
        Ok(Self {
            path: temporary.path().to_path_buf(),
            _temporary: Some(temporary),
        })
    }
}

/// Lifecycle loop backed by an authoritative scheduler and live QEMU node set.
pub struct ProductionVmLifecycleLoop {
    inner:
        BackendQuantumLoop<SingleScheduler, ProductionNodeSet, ProductionFaultNetworkInterceptor>,
    trigger_graph: EventGraph,
    trigger_state: EventGraphState,
    trigger_world: World,
    assertion_evaluator: HostAssertionEvaluator,
    assertion_oracle: BlackBoxHostOracle,
    terminal_verdict: Option<QuantumTerminalVerdict>,
    checkpoint_terminal_cause: Option<CheckpointTerminalCause>,
    initial_lifecycle_observations_pending: bool,
    branch: Option<ProductionVmBranchConfig>,
    launch_configs: BTreeMap<NodeId, ProductionLiveNodeStepGateConfig>,
    block_bindings: BTreeMap<NodeId, storage_faults::ProductionBlockBinding>,
    ninep_bindings: BTreeMap<NodeId, storage_faults::ProductionNinepBinding>,
    block_devices: storage_faults::ProductionBlockDevices,
    storage_fault_observations: storage_faults::ProductionStorageObservations,
    fault_runtime: Arc<std::sync::Mutex<ProductionFaultRuntime>>,
    fault_replay_installed: bool,
    fault_search_overrides_installed: bool,
    fault_evaluation_cursor: network_faults::SharedProductionFaultEvaluationCursor,
    icount_shift: u8,
    node_indexes: BTreeMap<NodeId, usize>,
    node_run_directories: BTreeMap<NodeId, PathBuf>,
    node_generations: BTreeMap<NodeId, u64>,
    node_service_states: BTreeMap<NodeId, ProductionNodeServiceState>,
    lifecycle_journal: ProductionLifecycleJournal,
    run_manifest: ProductionRunManifest,
    scenario: ScenarioDef,
    source: ScenarioDefForm,
    config: ProductionVmLifecycleConfig,
    checkpoint_targets: BTreeMap<ContentHash, ContentHash>,
    recorded_controls: Vec<ProductionVmRecordedControl>,
    signal_artifact_objects: BTreeMap<ContentHash, Vec<u8>>,
    debug_backend_paths: BTreeMap<NodeId, PathBuf>,
    debug_gateway: Option<DebugGatewayProcess>,
    debug_attach: Option<GdbAttachInfo>,
    debug_gateway_teardown_required: bool,
    indeterminate_debug_candidate: Option<Box<ProductionVmLifecycleLoop>>,
    debug_runtime_evidence: Vec<ProductionVmDebugRuntimeEvidence>,
    _run_directory: ProductionRunDirectory,
}

mod config;
mod helpers;
mod network_faults;
mod quantum_loop;
mod runtime;
mod search;
mod storage_faults;

fn persist_atomic_json<T: serde::Serialize>(path: &Path, value: &T) -> Result<(), String> {
    let next = path.with_extension("json.next");
    let bytes = serde_json::to_vec_pretty(value)
        .map_err(|error| format!("encode {}: {error}", path.display()))?;
    let mut file =
        File::create(&next).map_err(|error| format!("create {}: {error}", next.display()))?;
    file.write_all(&bytes)
        .and_then(|()| file.sync_all())
        .map_err(|error| format!("flush {}: {error}", next.display()))?;
    fs::rename(&next, path).map_err(|error| format!("commit {}: {error}", path.display()))?;
    let parent = path
        .parent()
        .ok_or_else(|| format!("{} has no parent directory", path.display()))?;
    File::open(parent)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| format!("flush directory {}: {error}", parent.display()))
}

fn decode_run_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let bytes = fs::read(path).map_err(|error| format!("read {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes).map_err(|error| format!("decode {}: {error}", path.display()))
}

fn acquire_production_run_lock(
    scenario_directory: &Path,
) -> Result<ProductionRunLock, LifecycleApiError> {
    let path = scenario_directory.join("active-run.lock");
    let owner = linux_process_identity(std::process::id())
        .map_err(|error| loop_factory_error(format!("identify lifecycle process: {error}")))?
        .ok_or_else(|| loop_factory_error("lifecycle process has no Linux process identity"))?;
    let record = ProductionRunLockRecord {
        owner: owner.clone(),
    };
    for _ in 0..2 {
        match OpenOptions::new().write(true).create_new(true).open(&path) {
            Ok(mut file) => {
                let bytes = serde_json::to_vec_pretty(&record).map_err(|error| {
                    loop_factory_error(format!("encode lifecycle run lock: {error}"))
                })?;
                file.write_all(&bytes)
                    .and_then(|()| file.sync_all())
                    .map_err(|error| {
                        loop_factory_error(format!(
                            "persist lifecycle run lock {}: {error}",
                            path.display()
                        ))
                    })?;
                File::open(scenario_directory)
                    .and_then(|directory| directory.sync_all())
                    .map_err(|error| {
                        loop_factory_error(format!("flush lifecycle run-lock directory: {error}"))
                    })?;
                return Ok(ProductionRunLock { path });
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let existing: ProductionRunLockRecord =
                    decode_run_json(&path).map_err(|message| {
                        loop_factory_error(format!("invalid run lock: {message}"))
                    })?;
                let live = linux_process_identity(existing.owner.process_id).map_err(|error| {
                    loop_factory_error(format!("validate lifecycle run-lock owner: {error}"))
                })?;
                if live.as_ref() == Some(&existing.owner) {
                    return Err(loop_factory_error(format!(
                        "scenario already has an active production lifecycle owned by PID {}",
                        existing.owner.process_id
                    )));
                }
                fs::remove_file(&path).map_err(|remove_error| {
                    loop_factory_error(format!(
                        "remove stale lifecycle run lock {}: {remove_error}",
                        path.display()
                    ))
                })?;
            }
            Err(error) => {
                return Err(loop_factory_error(format!(
                    "create lifecycle run lock {}: {error}",
                    path.display()
                )));
            }
        }
    }
    Err(loop_factory_error(
        "lifecycle run-lock acquisition did not converge",
    ))
}

fn production_run_directory(
    scenario: &ScenarioDef,
    config: &ProductionVmLifecycleConfig,
) -> Result<
    (
        ProductionRunDirectory,
        ProductionRunManifest,
        ProductionLifecycleJournal,
    ),
    LifecycleApiError,
> {
    let scenario_identity = scenario.id().to_hex();
    // QEMU control channels use filesystem-backed AF_UNIX sockets. Leave room
    // below the caller-provided root for the run, node, role, and socket names
    // while retaining the complete identity in every run manifest. A prefix
    // collision therefore fails closed during manifest validation below.
    let scenario_directory = config.run_state_root.join(&scenario_identity[..32]);
    fs::create_dir_all(&scenario_directory).map_err(|error| {
        loop_factory_error(format!(
            "create durable lifecycle state directory {}: {error}",
            scenario_directory.display()
        ))
    })?;
    let lock = acquire_production_run_lock(&scenario_directory)?;
    let mut run_indexes = Vec::new();
    for entry in fs::read_dir(&scenario_directory)
        .map_err(|error| loop_factory_error(format!("enumerate prior lifecycle runs: {error}")))?
    {
        let entry = entry
            .map_err(|error| loop_factory_error(format!("read prior lifecycle run: {error}")))?;
        if !entry
            .file_type()
            .map_err(|error| loop_factory_error(format!("inspect prior lifecycle run: {error}")))?
            .is_dir()
        {
            continue;
        }
        let name = entry.file_name();
        let Some(index) = name
            .to_str()
            .and_then(|name| name.strip_prefix("run-"))
            .and_then(|index| index.parse::<u64>().ok())
        else {
            continue;
        };
        run_indexes.push((index, entry.path()));
    }
    run_indexes.sort_by_key(|(index, _)| *index);
    for (_, directory) in &run_indexes {
        let manifest_path = directory.join("run-manifest.json");
        let mut manifest: ProductionRunManifest =
            decode_run_json(&manifest_path).map_err(|message| {
                loop_factory_error(format!("invalid prior run manifest: {message}"))
            })?;
        if manifest.version != 2 || manifest.scenario != scenario_identity {
            return Err(loop_factory_error(format!(
                "prior run manifest {} has incompatible identity or version",
                manifest_path.display()
            )));
        }
        let journal_path = directory.join("lifecycle-journal.json");
        let mut journal: ProductionLifecycleJournal =
            decode_run_json(&journal_path).map_err(|message| {
                loop_factory_error(format!("invalid prior lifecycle journal: {message}"))
            })?;
        if journal.version != 1 {
            return Err(loop_factory_error(format!(
                "prior lifecycle journal {} has unsupported version {}",
                journal_path.display(),
                journal.version
            )));
        }
        if !manifest.clean_shutdown {
            let live_owner =
                linux_process_identity(manifest.owner.process_id).map_err(|error| {
                    loop_factory_error(format!("validate lifecycle run owner: {error}"))
                })?;
            if live_owner.as_ref() == Some(&manifest.owner) {
                continue;
            }
            for identity in manifest
                .processes
                .values()
                .chain(manifest.staged_processes.values())
            {
                quarantine_orphaned_qemu_process(identity, config.completion_timeout).map_err(
                    |error| {
                        loop_factory_error(format!(
                            "contain prior QEMU process {}: {error}",
                            identity.process_id
                        ))
                    },
                )?;
            }
            journal.phase = ProductionLifecycleJournalPhase::Quarantined;
            persist_atomic_json(&journal_path, &journal)
                .map_err(|message| loop_factory_error(format!("recover journal: {message}")))?;
            manifest.clean_shutdown = true;
            manifest.recovered_after_host_exit = true;
            persist_atomic_json(&manifest_path, &manifest)
                .map_err(|message| loop_factory_error(format!("recover manifest: {message}")))?;
        }
    }
    let next_index = run_indexes.last().map_or(Ok(0), |(index, _)| {
        index
            .checked_add(1)
            .ok_or_else(|| loop_factory_error("production lifecycle run sequence exhausted"))
    })?;
    let path = scenario_directory.join(format!("run-{next_index:020}"));
    fs::create_dir(&path).map_err(|error| {
        loop_factory_error(format!("create lifecycle run {}: {error}", path.display()))
    })?;
    let manifest = ProductionRunManifest {
        version: 2,
        scenario: scenario_identity,
        owner: linux_process_identity(std::process::id())
            .map_err(|error| loop_factory_error(format!("identify lifecycle owner: {error}")))?
            .ok_or_else(|| loop_factory_error("lifecycle process has no Linux process identity"))?,
        processes: BTreeMap::new(),
        staged_processes: BTreeMap::new(),
        clean_shutdown: false,
        recovered_after_host_exit: false,
    };
    let journal = ProductionLifecycleJournal {
        version: 1,
        transaction: 0,
        phase: ProductionLifecycleJournalPhase::Idle,
        nodes: Vec::new(),
        completed_exits: Vec::new(),
    };
    persist_atomic_json(&path.join("run-manifest.json"), &manifest)
        .map_err(|message| loop_factory_error(format!("initialize run manifest: {message}")))?;
    persist_atomic_json(&path.join("lifecycle-journal.json"), &journal).map_err(|message| {
        loop_factory_error(format!("initialize lifecycle journal: {message}"))
    })?;
    drop(lock);
    Ok((
        ProductionRunDirectory {
            path,
            _temporary: None,
        },
        manifest,
        journal,
    ))
}

use helpers::*;
use network_faults::{
    ProductionFaultEvaluationCursor, ProductionFaultNetworkInterceptor,
    SharedProductionFaultEvaluationCursor,
};
pub use search::production_vm_search_frontier;
use storage_faults::{ProductionBlockFaultCoordinator, block_binding_for_vm, ninep_binding_for_vm};

/// Builds a production lifecycle by directly restoring a durable fat checkpoint.
///
/// The checkpoint must have an exact execution closure below the configured run
/// state root. The closure and every referenced object are authenticated before
/// any replacement process is published, and this path never falls back to
/// replay.
///
/// # Errors
///
/// Returns [`LifecycleApiError::LoopFactory`] when the scenario/checkpoint pair
/// has no durable exact continuation or its authenticated artifacts and
/// scheduler identity cannot be restored as one transaction.
pub fn build_production_vm_lifecycle_loop_from_checkpoint(
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    config: &ProductionVmLifecycleConfig,
    checkpoint: &Checkpoint,
) -> Result<ProductionVmLifecycleLoop, LifecycleApiError> {
    if checkpoint.kind != CheckpointKind::Fat
        || checkpoint.scenario_ref != scenario.id()
        || checkpoint.configuration != checkpoint.id
    {
        return Err(loop_factory_error(
            "production direct restore requires a matching recorded fat checkpoint",
        ));
    }
    let closure = checkpoint.execution_closure.ok_or_else(|| {
        loop_factory_error("production direct restore requires a concrete execution closure")
    })?;
    let restored = load_exact_checkpoint_set(&config.run_state_root, scenario, source, closure)?;
    if restored.configuration.id() != checkpoint.configuration
        || restored.scheduler.frontier() != checkpoint.virtual_time
        || restored.identity != closure
    {
        return Err(loop_factory_error(
            "durable production continuation does not match checkpoint model state",
        ));
    }
    let mut restore_config = config.clone();
    restore_config.restore_checkpoint = Some(restored);
    build_production_vm_lifecycle_loop(scenario, source, &restore_config)
}

/// Builds a production local-QEMU lifecycle loop for `scenario`.
///
/// Every World VM receives an independent QEMU process and writable overlay.
/// The scheduler is admitted only after all nodes report the same primed
/// instruction boundary.
///
/// # Errors
///
/// Returns [`LifecycleApiError::LoopFactory`] when the World is empty, VM shifts
/// differ, time conversion overflows, a run directory or overlay cannot be
/// prepared, a live node cannot be launched, primed boundaries differ, or the
/// authoritative scheduler rejects the runtime scenario.
pub fn build_production_vm_lifecycle_loop(
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    config: &ProductionVmLifecycleConfig,
) -> Result<ProductionVmLifecycleLoop, LifecycleApiError> {
    let network_implementations = fault_implementation::network_effect_implementation_registry()
        .map_err(|error| {
            loop_factory_error(format!(
                "validate production network fault registry: {error}"
            ))
        })?;
    let storage_implementations = fault_implementation::storage_effect_implementation_registry()
        .map_err(|error| {
            loop_factory_error(format!(
                "validate production storage fault registry: {error}"
            ))
        })?;
    let host_fault_manifests = HostFaultAdapterManifests::from_registries(
        &network_implementations,
        &storage_implementations,
    )
    .map_err(|error| {
        loop_factory_error(format!(
            "derive production host fault capabilities from implementations: {error}"
        ))
    })?;
    let restore_checkpoint = config.restore_checkpoint.clone();
    let checkpoint_dag =
        checkpoint_store::checkpoint_dag_store(&config.run_state_root, scenario.id());
    if let Some(checkpoint) = &restore_checkpoint
        && (checkpoint.configuration.def.id() != scenario.id()
            || checkpoint.configuration.id()
                != checkpoint
                    .scheduler
                    .configuration_for(scenario)
                    .map_err(|error| {
                        loop_factory_error(format!(
                            "decode production scheduler checkpoint: {error}"
                        ))
                    })?
                    .id())
    {
        return Err(loop_factory_error(
            "production exact checkpoint does not match the requested scenario and scheduler configuration",
        ));
    }
    let nodes = source.world().vm_nodes();
    let first = nodes
        .first()
        .ok_or_else(|| loop_factory_error("scenario World has no VM nodes"))?;
    if nodes
        .iter()
        .any(|node| node.icount_shift != first.icount_shift)
    {
        return Err(loop_factory_error(
            "production QEMU lifecycle currently requires one shared icount shift",
        ));
    }
    if config.run_ceiling_icount == 0
        || config.quantum_budget == 0
        || config.rendezvous_interval_icount == Some(0)
    {
        return Err(loop_factory_error(
            "production QEMU lifecycle bounds must be nonzero",
        ));
    }
    if let Some(debug) = &config.debug
        && debug
            .node
            .as_ref()
            .is_some_and(|selected| !nodes.iter().any(|vm| vm.id.name == *selected))
    {
        return Err(loop_factory_error(format!(
            "debug node `{}` is not declared by the scenario World",
            debug.node.as_deref().unwrap_or_default()
        )));
    }
    if config.debug.is_some() && config.debug_gateway_executable.is_none() {
        return Err(loop_factory_error(
            "production QEMU debugging requires a standalone debugger gateway executable",
        ));
    }

    let (run_directory, mut run_manifest, lifecycle_journal) =
        production_run_directory(scenario, config)?;
    let mut backends = ProductionNodeSet::new();
    let mut launch_configs = BTreeMap::new();
    let mut block_bindings = BTreeMap::new();
    let mut ninep_bindings = BTreeMap::new();
    let mut node_indexes = BTreeMap::new();
    let mut node_run_directories = BTreeMap::new();
    let mut node_generations = BTreeMap::new();
    let mut node_service_states = BTreeMap::new();
    let mut debug_backend_paths = BTreeMap::new();
    let mut initial_ticks = None;
    let scenario_seed = scenario.seed().bytes();
    let mut launch_seed_bytes = [0_u8; 8];
    launch_seed_bytes.copy_from_slice(&scenario_seed[..8]);
    let launch_seed = u64::from_le_bytes(launch_seed_bytes);
    for (index, vm) in nodes.iter().enumerate() {
        let guest_assets = config.guest_assets.get(&vm.arch).ok_or_else(|| {
            loop_factory_error(format!(
                "production QEMU lifecycle has no boot artifacts for {:?}",
                vm.arch
            ))
        })?;
        if config.validate_guest_asset_references {
            validate_guest_asset_references(vm, guest_assets)?;
        }
        let node_directory = run_directory.path().join(format!("node-{index}"));
        fs::create_dir_all(&node_directory).map_err(|error| {
            loop_factory_error(format!(
                "create QEMU node run directory {}: {error}",
                node_directory.display()
            ))
        })?;
        let restore_target = restore_checkpoint
            .as_ref()
            .and_then(|checkpoint| checkpoint.targets.get(&vm.id));
        let restored_service_state = restore_checkpoint
            .as_ref()
            .and_then(|checkpoint| checkpoint.node_service_states.get(&vm.id))
            .copied();
        if restore_checkpoint.is_some()
            && restore_target.is_none()
            && restored_service_state != Some(ProductionNodeServiceState::PermanentlyFailed)
        {
            return Err(loop_factory_error(format!(
                "production exact checkpoint has no target for `{}`",
                vm.id.name
            )));
        }
        if let Some(target) = restore_target {
            validate_exact_checkpoint_target(&vm.id, target)?;
            copy_exact_checkpoint_artifact(
                &target.overlay_artifact,
                &node_directory.join(PRODUCTION_ROOT_OVERLAY_FILE_NAME),
                "root overlay",
            )?;
            copy_exact_checkpoint_artifact(
                &target.vmstate_artifact,
                &node_directory.join(PRODUCTION_VMSTATE_FILE_NAME),
                "VMState",
            )?;
        } else {
            prepare_root_overlay(
                &config.executable,
                &guest_assets.root_image,
                &node_directory,
            )?;
        }
        let kernel_cmdline_prefix = production_kernel_cmdline_prefix(config, vm.arch, guest_assets);
        let kernel_cmdline = match kernel_cmdline_prefix {
            Some(prefix) if !prefix.trim().is_empty() => {
                format!("{} {}", prefix.trim(), vm.cmdline.trim())
            }
            _ => vm.cmdline.clone(),
        };
        let whitebox = production_whitebox_switch(vm.white_box);
        let generation = restore_checkpoint
            .as_ref()
            .and_then(|checkpoint| checkpoint.node_generations.get(&vm.id))
            .copied()
            .unwrap_or(1);
        let qemu_executable = production_qemu_executable(&config.executable, vm.arch);
        let mut launch = ProductionLiveNodeStepGateConfig::new_with_root_image(
            qemu_executable,
            &config.plugin,
            &guest_assets.kernel,
            &guest_assets.root_image,
            &node_directory,
        )
        .with_guest_architecture(production_guest_architecture(vm.arch))
        .with_root_image_format(config.root_image_format)
        .with_kernel_cmdline(kernel_cmdline)
        .with_vm_shape(vm.memory_mib, vm.smp_vcpus, vm.icount_shift)
        .with_scenario_seed(launch_seed)
        .with_whitebox(whitebox)
        .with_coverage(config.coverage)
        .with_fingerprint(crucible_qemu::QemuLaunchPluginSwitch::On)
        .with_queue_capacity(PRODUCTION_QUEUE_CAPACITY)
        .with_completion_timeout(config.completion_timeout)
        .with_console_capture()
        .with_second_run_host_load(false)
        .with_process_generation(generation);
        if let Some(capabilities) = source
            .world()
            .fault_topology()
            .node_capabilities
            .iter()
            .find(|capabilities| capabilities.node.as_str() == vm.id.name.as_str())
        {
            if !capabilities.ready_markers.is_empty()
                && vm.white_box != crucible::WhiteBoxPolicy::Enabled
            {
                return Err(loop_factory_error(format!(
                    "QEMU node `{}` declares guest ready markers but its authenticated white-box guest event channel is disabled",
                    vm.id.name
                )));
            }
            launch = launch.with_fault_capabilities(capabilities.clone());
            if !capabilities.accelerators.is_empty() {
                launch = launch.with_accelerator();
            }
        }
        if vm.white_box == crucible::WhiteBoxPolicy::Enabled {
            let app_random = if let Some(checkpoint) = &restore_checkpoint {
                production_app_random_checkpoint_config(
                    &checkpoint.scheduler,
                    scenario,
                    checkpoint.branch.as_ref(),
                    &vm.id,
                )
                .map_err(|error| {
                    loop_factory_error(format!(
                        "restore app-random continuation for `{}`: {error}",
                        vm.id.name
                    ))
                })?
            } else {
                production_app_random_launch_config(scenario, config.branch.as_ref(), &vm.id)
            };
            launch = launch.with_app_random(app_random);
        }
        if !source.world().links().is_empty() {
            launch = launch.with_shmem_network_mac(crucible::deterministic_node_mac_string(&vm.id));
        }
        if let Some(target) = restore_target {
            let next_sequence = u32::try_from(
                target
                    .snapshot
                    .node_continuation()
                    .next_plugin_network_output_sequence(),
            )
            .map_err(|_error| {
                loop_factory_error(format!(
                    "restored network TX sequence for `{}` exceeds the plugin ABI",
                    vm.id.name
                ))
            })?;
            launch = launch.with_network_tx_next_sequence(next_sequence);
        }
        if restored_service_state != Some(ProductionNodeServiceState::PermanentlyFailed) {
            if let Some(block) =
                block_binding_for_vm(source.world(), &vm.id, config.world_artifacts.as_ref())?
            {
                launch = launch.with_shmem_block(block.base.clone(), block.durability.clone());
                block_bindings.insert(vm.id.clone(), block);
            }
            if let Some(ninep) =
                ninep_binding_for_vm(source.world(), &vm.id, config.world_artifacts.as_ref())?
            {
                launch = launch.with_shmem_ninep(ninep.tree.clone(), ninep.latency);
                ninep_bindings.insert(vm.id.clone(), ninep);
            }
        }
        if vm.initrd.is_some() && config.initrd.is_none() {
            return Err(loop_factory_error(format!(
                "QEMU node `{}` declares an initrd but no materialized initrd was configured",
                vm.id.name
            )));
        }
        if let Some(initrd) = &config.initrd {
            launch = launch.with_initrd(initrd);
        }
        if config.debug.as_ref().is_some_and(|debug| {
            debug.all_nodes
                || debug
                    .node
                    .as_deref()
                    .map_or(index == 0, |selected| selected == vm.id.name)
        }) {
            let debug = config.debug.as_ref().ok_or_else(|| {
                loop_factory_error("debug configuration disappeared during QEMU launch")
            })?;
            let backend_path = private_backend_gdbstub_path(&node_directory);
            let backend_listen = qemu_unix_gdbstub_endpoint(&backend_path)?;
            let gdbstub =
                ProductionGdbstubChannelConfig::new(backend_listen, debug.operator_listen.clone())
                    .map_err(|error| {
                        loop_factory_error(format!("configure QEMU gdbstub: {error}"))
                    })?;
            launch = launch.with_gdbstub(gdbstub);
            debug_backend_paths.insert(vm.id.clone(), backend_path);
        }
        launch_configs.insert(vm.id.clone(), launch.clone());
        node_indexes.insert(vm.id.clone(), index);
        node_run_directories.insert(vm.id.clone(), node_directory.clone());
        let service_state = restored_service_state.unwrap_or(ProductionNodeServiceState::Running);
        node_generations.insert(vm.id.clone(), generation);
        node_service_states.insert(vm.id.clone(), service_state);
        let launched = match (restore_target, service_state) {
            (Some(target), ProductionNodeServiceState::Running) => {
                launch_production_live_node_exact_snapshot(
                    &launch,
                    &node_directory,
                    &vm.id.name,
                    "crucible-router",
                    &format!("lifecycle-{}-generation-{generation}", vm.id.name),
                    &target.snapshot,
                )
            }
            (Some(target), ProductionNodeServiceState::PoweredOff) => {
                launch_production_live_node_exact_snapshot_paused(
                    &launch,
                    &node_directory,
                    &vm.id.name,
                    "crucible-router",
                    &format!("lifecycle-{}-generation-{generation}", vm.id.name),
                    &target.snapshot,
                )
            }
            (Some(_), ProductionNodeServiceState::PermanentlyFailed) => {
                return Err(loop_factory_error(format!(
                    "exact checkpoint for permanently failed node `{}` unexpectedly contains a live process target",
                    vm.id.name
                )));
            }
            (None, ProductionNodeServiceState::PermanentlyFailed) => continue,
            (None, _) => launch_production_live_node(
                &launch,
                &node_directory,
                &vm.id.name,
                "crucible-router",
                &format!("lifecycle-{}", vm.id.name),
            ),
        };
        let mut backend = launched.map_err(|error| {
            loop_factory_error(format!("launch QEMU node `{}`: {error}", vm.id.name))
        })?;
        let observed = SimulationBackend::now(&backend).ticks;
        if let Some(target) = restore_target {
            let restored_configuration = restore_checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.configuration.id());
            if Some(target.configuration.id()) != restored_configuration
                || target.counter != observed
            {
                let _ = SimulationBackend::shutdown(&mut backend);
                return Err(loop_factory_error(format!(
                    "QEMU node `{}` restored at unauthenticated instruction boundary {observed}",
                    vm.id.name
                )));
            }
            let Some(expected_fingerprint) = target.fault_checkpoint.qemu_fingerprint(&vm.id)
            else {
                let _ = SimulationBackend::shutdown(&mut backend);
                return Err(loop_factory_error(format!(
                    "exact checkpoint for `{}` has no authenticated QEMU fingerprint",
                    vm.id.name
                )));
            };
            let restored_fingerprint = match backend.execution_fingerprint() {
                Ok(fingerprint) => fingerprint.hash,
                Err(error) => {
                    let _ = SimulationBackend::shutdown(&mut backend);
                    return Err(loop_factory_error(format!(
                        "read restored QEMU fingerprint for `{}`: {error}",
                        vm.id.name
                    )));
                }
            };
            if restored_fingerprint != expected_fingerprint {
                let _ = SimulationBackend::shutdown(&mut backend);
                return Err(loop_factory_error(format!(
                    "QEMU node `{}` restored with an unauthenticated execution fingerprint: expected {}, observed {}",
                    vm.id.name,
                    expected_fingerprint.to_hex(),
                    restored_fingerprint.to_hex(),
                )));
            }
        } else if initial_ticks.is_some_and(|initial| initial != observed) {
            let _ = SimulationBackend::shutdown(&mut backend);
            return Err(loop_factory_error(format!(
                "QEMU node `{}` primed at {observed}, expected {}",
                vm.id.name,
                initial_ticks.unwrap_or_default()
            )));
        }
        if restore_target.is_none() {
            initial_ticks.get_or_insert(observed);
        }
        let process_identity = backend.process_identity().map_err(|error| {
            loop_factory_error(format!(
                "capture initial QEMU identity for `{}`: {error}",
                vm.id.name
            ))
        })?;
        if backends.insert(vm.id.clone(), backend).is_some() {
            return Err(loop_factory_error(format!(
                "duplicate QEMU node identity `{}`",
                vm.id.name
            )));
        }
        run_manifest
            .processes
            .insert(vm.id.name.clone(), process_identity);
        if let Err(message) = persist_atomic_json(
            &run_directory.path().join("run-manifest.json"),
            &run_manifest,
        ) {
            let _ = backends.shutdown();
            return Err(loop_factory_error(format!(
                "persist initial QEMU process ownership: {message}"
            )));
        }
    }

    let initial_ticks = initial_ticks.unwrap_or_default();
    if restore_checkpoint.is_none() && config.run_ceiling_icount <= initial_ticks {
        return Err(loop_factory_error(format!(
            "QEMU run ceiling {} does not exceed primed boundary {initial_ticks}",
            config.run_ceiling_icount
        )));
    }
    let shift = Shift::new(first.icount_shift)
        .map_err(|error| loop_factory_error(format!("validate icount shift: {error}")))?;
    let time_limit_nanos = config
        .run_ceiling_icount
        .checked_shl(u32::from(first.icount_shift))
        .ok_or_else(|| loop_factory_error("QEMU lifecycle time limit overflow"))?;
    let mut runtime_scenario = SchedulerLivenessScenario::from_runnable_world(
        &scenario.id().to_hex(),
        shift,
        config.quantum_budget,
        SimInstant {
            nanos: time_limit_nanos,
        },
        initial_ticks,
        source.world(),
    )
    .with_scenario_def(scenario.clone());
    if let Some(interval_icount) = config.rendezvous_interval_icount {
        let interval_nanos = interval_icount
            .checked_shl(u32::from(first.icount_shift))
            .ok_or_else(|| loop_factory_error("QEMU rendezvous interval overflow"))?;
        runtime_scenario = runtime_scenario
            .with_rendezvous_interval(SimDuration {
                nanos: interval_nanos,
            })
            .map_err(|error| loop_factory_error(format!("configure QEMU rendezvous: {error}")))?;
    }
    let mut scheduler = SingleScheduler::new_with_event_log_segment_store(
        runtime_scenario,
        Arc::clone(&checkpoint_dag),
    )
    .map_err(|error| loop_factory_error(format!("construct QEMU scheduler: {error}")))?;
    if let Some(checkpoint) = &restore_checkpoint {
        scheduler
            .attach_world_network_links(source.world())
            .map_err(|error| loop_factory_error(format!("attach QEMU World network: {error}")))?;
        checkpoint
            .scheduler
            .restore_into(&mut scheduler)
            .map_err(|error| {
                loop_factory_error(format!("restore exact scheduler continuation: {error}"))
            })?;
    } else {
        if let Some(branch) = &config.branch {
            scheduler
                .set_branch_frontier_cap(branch.frontier)
                .map_err(|error| {
                    loop_factory_error(format!("cap QEMU branch frontier: {error}"))
                })?;
        }
        scheduler
            .attach_world_network_links(source.world())
            .map_err(|error| loop_factory_error(format!("attach QEMU World network: {error}")))?;
        scheduler
            .install_branch_network_choices(config.branch_network_choices.clone())
            .map_err(|error| {
                loop_factory_error(format!("install QEMU network branch choices: {error}"))
            })?;
    }
    let trigger_graph = source
        .plan()
        .lower_to_event_graph_for_world(source.world())
        .map_err(|error| loop_factory_error(format!("lower scenario trigger plan: {error}")))?
        .into_event_graph();
    let signal_plan = source.plan().fault_signals().clone();
    let fault_search_overrides = production_fault_search_overrides(config.branch.as_ref())?;
    let signal_artifact_objects = if signal_plan.programs().is_empty() {
        BTreeMap::new()
    } else if let Some(checkpoint) = &restore_checkpoint {
        checkpoint.signal_artifact_objects.clone()
    } else {
        let store = config.signal_artifacts.as_ref().ok_or_else(|| {
            loop_factory_error(
                "a nonempty signal fault plan requires a production signal-artifact store",
            )
        })?;
        collect_signal_artifact_objects(&signal_plan, store.as_ref())?
    };
    let signal_artifacts: Option<Arc<dyn SignalArtifactProvider>> =
        if signal_plan.programs().is_empty() {
            None
        } else {
            let store = if restore_checkpoint.is_some() {
                Arc::clone(&checkpoint_dag)
            } else {
                config.signal_artifacts.clone().ok_or_else(|| {
                    loop_factory_error(
                        "a nonempty signal fault plan requires a production signal-artifact store",
                    )
                })?
            };
            Some(Arc::new(OwnedDagSignalArtifactProvider::new(store)))
        };
    let storage_fault_observations = Arc::new(std::sync::Mutex::new(
        storage_faults::ProductionFaultObservationJournal::default(),
    ));
    let (
        fault_runtime,
        fault_evaluation_cursor,
        network_interceptor,
        pending_network_outputs,
        restored_committed_frontier,
    ) = if let Some(checkpoint) = &restore_checkpoint {
        if checkpoint
            .targets
            .values()
            .any(|target| target.fault_checkpoint.id() != checkpoint.fault_checkpoint.id())
        {
            return Err(loop_factory_error(
                "production exact checkpoint targets disagree on the fault continuation",
            ));
        }
        for (node, target) in &checkpoint.targets {
            let scheduler_time = scheduler.scheduler_time_for_node(node).map_err(|error| {
                loop_factory_error(format!(
                    "read restored scheduler boundary for `{}`: {error}",
                    node.name
                ))
            })?;
            if scheduler_time != target.scheduler_time {
                return Err(loop_factory_error(format!(
                    "production exact checkpoint scheduler boundary differs for `{}`",
                    node.name
                )));
            }
        }
        let mut pending_outputs = Vec::new();
        let (interceptor, committed_frontier) = ProductionFaultNetworkInterceptor::restore(
            signal_plan,
            signal_artifacts,
            scenario.id(),
            checkpoint.fault_checkpoint.clone(),
            host_fault_manifests.clone(),
            &mut backends,
            source.world().fault_topology().clone(),
            source.world().links().to_vec(),
            &mut scheduler,
            &mut pending_outputs,
            Arc::clone(&storage_fault_observations),
        )
        .map_err(|error| {
            loop_factory_error(format!(
                "restore signal, network, and device continuation: {error}"
            ))
        })?;
        (
            interceptor.shared_runtime(),
            interceptor.shared_cursor(),
            interceptor,
            pending_outputs,
            committed_frontier,
        )
    } else {
        let mut runtime = ProductionFaultRuntime::new_with_search_overrides(
            signal_plan,
            signal_artifacts,
            SignalBoundarySnapshot::default(),
            scenario.id(),
            host_fault_manifests,
            &backends,
            fault_search_overrides.clone(),
        )
        .map_err(|error| loop_factory_error(format!("admit signal fault runtime: {error}")))?;
        if let Some(trace) = config.fault_replay.clone() {
            runtime.install_replay(trace).map_err(|error| {
                loop_factory_error(format!("install signal fault replay: {error}"))
            })?;
        }
        let runtime = Arc::new(std::sync::Mutex::new(runtime));
        let cursor: SharedProductionFaultEvaluationCursor = Arc::new(std::sync::Mutex::new(
            ProductionFaultEvaluationCursor::default(),
        ));
        let interceptor = ProductionFaultNetworkInterceptor::with_shared_runtime(
            Arc::clone(&runtime),
            Arc::clone(&cursor),
            Arc::clone(&storage_fault_observations),
            source.world().fault_topology().clone(),
            source.world().links().to_vec(),
        );
        (
            runtime,
            cursor,
            interceptor,
            Vec::new(),
            VirtualTime::default(),
        )
    };
    let fault_replay_installed = config.fault_replay.is_some();
    let fault_search_overrides_installed = fault_runtime
        .lock()
        .map_err(|_| loop_factory_error("production fault runtime lock is poisoned"))?
        .has_search_overrides();
    let mut block_device_map = BTreeMap::new();
    for (node, block) in &block_bindings {
        let handle = backends.shared_block_device(node).map_err(|error| {
            loop_factory_error(format!(
                "locate authoritative block device for `{}`: {error}",
                node.name
            ))
        })?;
        if block_device_map
            .insert(block.device_hash(), handle)
            .is_some()
        {
            return Err(loop_factory_error(format!(
                "World block target for `{}` aliases another live device",
                node.name
            )));
        }
    }
    let block_devices = Arc::new(std::sync::Mutex::new(block_device_map));
    for (node, block) in &block_bindings {
        backends
            .install_block_fault_coordinator(
                node,
                Box::new(ProductionBlockFaultCoordinator::new(
                    Arc::clone(&fault_runtime),
                    Arc::clone(&fault_evaluation_cursor),
                    Arc::clone(&storage_fault_observations),
                    Arc::clone(&block_devices),
                    source.world().clone(),
                    block.target.clone(),
                    source.plan().fault_signals(),
                    scenario.id(),
                    first.icount_shift,
                )),
            )
            .map_err(|error| {
                loop_factory_error(format!(
                    "attach signal-driven block coordinator to `{}`: {error}",
                    node.name
                ))
            })?;
    }
    for (node, ninep) in &ninep_bindings {
        backends
            .install_ninep_fault_coordinator(
                node,
                Box::new(storage_faults::ProductionNinepFaultCoordinator::new(
                    Arc::clone(&fault_runtime),
                    Arc::clone(&fault_evaluation_cursor),
                    Arc::clone(&storage_fault_observations),
                    source.world().clone(),
                    ninep.target.clone(),
                    first.icount_shift,
                )),
            )
            .map_err(|error| {
                loop_factory_error(format!(
                    "attach signal-driven 9p coordinator to `{}`: {error}",
                    node.name
                ))
            })?;
    }

    let active_branch = restore_checkpoint.as_ref().map_or_else(
        || config.branch.clone(),
        |checkpoint| checkpoint.branch.clone(),
    );
    let inner = if restore_checkpoint.is_some() {
        BackendQuantumLoop::from_restored_network_state(
            scheduler,
            backends,
            network_interceptor,
            pending_network_outputs,
            restored_committed_frontier,
        )
    } else {
        BackendQuantumLoop::with_network_output_interceptor(
            scheduler,
            backends,
            network_interceptor,
        )
    };
    let mut lifecycle = ProductionVmLifecycleLoop {
        inner,
        trigger_graph,
        trigger_state: restore_checkpoint
            .as_ref()
            .map_or_else(EventGraphState::default, |checkpoint| {
                checkpoint.trigger_state.clone()
            }),
        trigger_world: source.world().clone(),
        assertion_evaluator: HostAssertionEvaluator::new(source.properties())
            .with_world_white_box_policies(source.world()),
        assertion_oracle: BlackBoxHostOracle,
        terminal_verdict: restore_checkpoint
            .as_ref()
            .and_then(|checkpoint| checkpoint.terminal_verdict.clone()),
        checkpoint_terminal_cause: restore_checkpoint
            .as_ref()
            .and_then(|checkpoint| checkpoint.terminal_cause.clone()),
        initial_lifecycle_observations_pending: restore_checkpoint
            .as_ref()
            .is_none_or(|checkpoint| checkpoint.initial_lifecycle_observations_pending),
        branch: active_branch,
        launch_configs,
        block_bindings,
        ninep_bindings,
        block_devices,
        storage_fault_observations,
        fault_runtime,
        fault_replay_installed,
        fault_search_overrides_installed,
        fault_evaluation_cursor,
        icount_shift: first.icount_shift,
        node_indexes,
        node_run_directories,
        node_generations,
        node_service_states,
        lifecycle_journal,
        run_manifest,
        scenario: scenario.clone(),
        source: source.clone(),
        config: config.clone(),
        checkpoint_targets: BTreeMap::new(),
        recorded_controls: restore_checkpoint
            .as_ref()
            .map_or_else(Vec::new, |checkpoint| checkpoint.recorded_controls.clone()),
        signal_artifact_objects,
        debug_backend_paths,
        debug_gateway: None,
        debug_attach: None,
        debug_gateway_teardown_required: false,
        indeterminate_debug_candidate: None,
        debug_runtime_evidence: Vec::new(),
        _run_directory: run_directory,
    };
    if let Some(checkpoint) = &restore_checkpoint {
        let prefix = lifecycle
            .inner
            .loop_impl()
            .condition_event_log_prefix()
            .clone();
        if let Err(error) = checkpoint
            .assertion_state
            .restore_into(&mut lifecycle.assertion_evaluator, &prefix)
        {
            let _ = lifecycle.inner.shutdown();
            return Err(loop_factory_error(format!(
                "restore host assertion continuation: {error}"
            )));
        }
    }
    if let Err(error) = lifecycle.capture_debug_runtime_evidence() {
        let _ = lifecycle.inner.shutdown();
        return Err(loop_factory_error(format!(
            "capture initial debugger runtime evidence: {error}"
        )));
    }
    Ok(lifecycle)
}
