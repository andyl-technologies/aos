//! Production local-VM lifecycle loop construction.
//!
//! This module composes a submitted [`ScenarioDefForm`] into the authoritative
//! [`SingleScheduler`], one live QEMU node per World VM, and the node-addressed
//! backend loop consumed by [`LifecycleControlPlane`](crate::LifecycleControlPlane).

use crate::vm_resume::{
    PRODUCTION_ROOT_OVERLAY_FILE_NAME, PRODUCTION_VMSTATE_FILE_NAME, ProductionAppRandomConfig,
    ProductionGdbstubChannelConfig, ProductionGuestArchitecture, ProductionLiveNodeStepGateConfig,
    ProductionNodeSet, ProductionPluginSwitch, ProductionRootImageFormat,
    launch_production_live_node, launch_production_live_node_exact_snapshot,
    launch_production_live_node_exact_snapshot_paused,
};
use crate::{LifecycleApiError, debug_gateway::DebugGatewayProcess};
use crucible::model::{
    FaultCoordinate, FaultResourceLimits, HostFaultAdapterManifests,
    OwnedDagSignalArtifactProvider, ResolvedEffectTrace, SignalArtifactProvider,
    SignalBoundarySnapshot,
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
    SchedulerLivenessScenario, SchedulerNodeActivity, SchedulerQuiescence, SchedulerState,
    SearchFrontierChoices, Seed, Shift, SignalFaultCampaignReplayPlan, SimDuration, SimInstant,
    SimulationBackend, SingleScheduler, SingleSchedulerCheckpoint, VirtualTime, VmArchitecture,
    World,
};
use crucible_qemu::{
    ProductionFaultRuntime, ProductionFaultRuntimeCheckpoint, ProductionNetworkStateCheckpoint,
    QemuLaunchResourceRequirements, QemuNode, QemuNodeLifecycleDecision,
    QemuNodeLifecycleIntent as LifecycleMutationIntent, QemuProcessIdentity, QemuReplayOracleCheck,
    QemuReplayOracleValidation, QemuSharedBlockDevice, QemuVmSnapshot as ExactSnapshotHandle,
    linux_process_identity, quarantine_orphaned_qemu_process,
};
use quantum_loop::{
    DurableRunStateError, LifecycleStatePersistence, PRODUCTION_RUN_STATE_FILE,
    decode_prior_run_state, decode_run_json_bounded, persist_run_state_atomic,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Arc;
use std::time::Duration;

mod assets;
use assets::*;
mod checkpoint_store;
use checkpoint_store::load_exact_checkpoint_set;
pub use checkpoint_store::{
    PreparedProductionReplayOraclePromotion, ProductionExactCheckpointClosure,
    ProductionExactCheckpointObject, ProductionExactCheckpointReplayArtifact,
    ProductionExactCheckpointReplayCatalog, ProductionExactCheckpointReplayTarget,
    ProductionExactCheckpointReplayTargets, ProductionExactCheckpointResumeBasis,
    ProductionExactCheckpointRetirement, ProductionExactCheckpointRetirementError,
    ProductionExactCheckpointRetirementReport, ProductionExactCheckpointSource,
    authenticate_portable_exact_checkpoint_replay_oracle_promotion,
    authenticate_portable_exact_checkpoint_replay_oracle_promotion_with_boundary,
    install_exact_checkpoint_closure, install_exact_checkpoint_closure_with_boundary,
    install_exact_checkpoint_closure_with_boundary_and_admission, open_exact_checkpoint_closure,
    retire_production_exact_checkpoint_catalog,
};
mod checkpoint_dependencies;
pub use checkpoint_dependencies::collect_signal_artifact_objects;
mod fault_implementation;
pub use fault_implementation::{
    network_effect_implementation_registry, storage_effect_implementation_registry,
};
#[cfg(target_os = "linux")]
mod hot_fork;
#[cfg(target_os = "linux")]
pub use hot_fork::{
    ProductionVmHotForkNodeBoundary, ProductionVmHotForkNodeServiceState,
    ProductionVmHotForkWorldContinuation,
};

/// Default final icount available to one production CLI lifecycle session.
const DEFAULT_RUN_CEILING_ICOUNT: u64 = 16_000_000;
/// Default scheduler quantum budget for one production CLI lifecycle session.
const DEFAULT_QUANTUM_BUDGET: u64 = 4_096;
/// Per-direction shared-memory frame capacity for production VM nodes.
const PRODUCTION_QUEUE_CAPACITY: u32 = 1_024;
/// Maximum number of trigger batches admitted at one scheduler boundary.
const MAX_TRIGGER_SETTLE_BATCHES: usize = 1_024;

#[cfg(test)]
fn duplicate_network_fault_checkpoint_fixture(
    checkpoint: &ProductionFaultRuntimeCheckpoint,
    plan: &crucible::model::FaultSignalPlan,
) -> ProductionFaultRuntimeCheckpoint {
    let bytes = checkpoint
        .to_canonical_bytes()
        .unwrap_or_else(|error| panic!("checkpoint fixture should encode: {error}"));
    ProductionFaultRuntimeCheckpoint::from_canonical_bytes(
        &bytes,
        plan,
        ContentHash::from_bytes(b"production-availability-drop"),
    )
    .unwrap_or_else(|error| panic!("checkpoint fixture should decode: {error}"))
}

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
    signal_fault_replay: Option<SignalFaultCampaignReplayPlan>,
    branch_network_choices: Vec<crucible::OverrideDecision>,
    app_random_branch_selections: BTreeMap<ContentHash, crucible::SelectionDecision>,
    app_random_branch_plans:
        BTreeMap<NodeId, crucible_protocol::app_random_branch_plan::AppRandomBranchPlan>,
    signal_artifacts: Option<Arc<dyn DagStore>>,
    fault_replay: Option<ResolvedEffectTrace>,
    world_artifacts: Option<Arc<dyn DagStore>>,
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
            .field(
                "signal_fault_replay_branch_count",
                &self
                    .signal_fault_replay
                    .as_ref()
                    .map_or(0, |plan| plan.branches().len()),
            )
            .field("branch_network_choices", &self.branch_network_choices)
            .field(
                "app_random_branch_selection_count",
                &self.app_random_branch_selections.len(),
            )
            .field(
                "app_random_branch_plan_node_count",
                &self.app_random_branch_plans.len(),
            )
            .field(
                "signal_artifacts_configured",
                &self.signal_artifacts.is_some(),
            )
            .field("fault_replay_configured", &self.fault_replay.is_some())
            .field(
                "world_artifacts_configured",
                &self.world_artifacts.is_some(),
            )
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
    signal_fault_replay: Option<&SignalFaultCampaignReplayPlan>,
) -> Result<
    BTreeMap<crucible::model::SearchChoiceId, crucible::model::SearchOverride>,
    LifecycleApiError,
> {
    let mut overrides = BTreeMap::new();
    let mut insert_decisions = |parent: &Configuration,
                                decisions: &[Decision]|
     -> Result<(), LifecycleApiError> {
        for decision in decisions {
            let Decision::Override(decision) = decision else {
                continue;
            };
            if !decision.point.key.starts_with("signal-fault/") {
                continue;
            }
            let (id, search_override) =
                crucible::model::SearchOverride::from_override_decision(decision)
                    .ok_or_else(|| loop_factory_error("malformed signal-fault branch override"))?;
            if search_override.parent_branch != Some(parent.id()) {
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
        Ok(())
    };
    if let Some(branch) = branch {
        insert_decisions(&branch.base, &branch.decisions)?;
    }
    if let Some(replay) = signal_fault_replay {
        for branch in replay.branches() {
            insert_decisions(branch.parent(), branch.decisions())?;
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

#[derive(Debug)]
struct ProductionVmExactCheckpointTarget {
    configuration: Configuration,
    immutable_backing: Option<ContentHash>,
    counter: u64,
    scheduler_time: VirtualTime,
    snapshot: ExactSnapshotHandle,
    overlay_artifact: ProductionCheckpointArtifact,
    vmstate_artifact: ProductionCheckpointArtifact,
    manifest_identity: crucible::ContentHash,
}

#[derive(Clone, Debug)]
struct ProductionCheckpointArtifact {
    source: ProductionCheckpointArtifactSource,
    identity: ContentHash,
    length: u64,
    chunks: Vec<ContentHash>,
    sparse: bool,
    extents: Vec<checkpoint_store::ArtifactExtent>,
}

#[derive(Clone, Debug)]
enum ProductionCheckpointArtifactSource {
    File(PathBuf),
    ChunkStore(PathBuf),
}

#[derive(Debug)]
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
    selectable_catalog_plans:
        BTreeMap<NodeId, crucible_protocol::selectable_catalog_plan::SelectableCatalogPlan>,
    fault_checkpoint: Option<ProductionFaultRuntimeCheckpoint>,
    targets: BTreeMap<NodeId, ProductionVmExactCheckpointTarget>,
    node_generations: BTreeMap<NodeId, u64>,
    node_service_states: BTreeMap<NodeId, ProductionNodeServiceState>,
}

struct ProductionVmHotForkRestore {
    expected_times: BTreeMap<NodeId, VirtualTime>,
    adoptions: BTreeMap<NodeId, ProductionVmHotForkNodeAdoption>,
    immutable_root_images: BTreeMap<NodeId, ContentHash>,
    block_bindings: BTreeMap<NodeId, storage_faults::ProductionBlockBinding>,
    ninep_bindings: BTreeMap<NodeId, storage_faults::ProductionNinepBinding>,
}

struct ProductionVmHotForkRestoreParts {
    config: ProductionVmLifecycleConfig,
    checkpoint: ProductionVmExactCheckpointSet,
    immutable_root_images: BTreeMap<NodeId, ContentHash>,
    block_bindings: BTreeMap<NodeId, storage_faults::ProductionBlockBinding>,
    ninep_bindings: BTreeMap<NodeId, storage_faults::ProductionNinepBinding>,
}

struct HotForkAdoptionInventory {
    expected_times: BTreeMap<NodeId, VirtualTime>,
    node_generations: BTreeMap<NodeId, u64>,
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

fn copy_exact_checkpoint_artifact(
    source: &ProductionCheckpointArtifact,
    destination: &Path,
    role: &str,
) -> Result<(), LifecycleApiError> {
    checkpoint_store::materialize_checkpoint_artifact(source, destination, role)?;
    if source.sparse {
        // Sparse materialization authenticates every stored extent before it
        // writes into a new empty staging file; omitted ranges are created as
        // filesystem holes and therefore read as zeroes. Rehashing the dense
        // logical file here would make restore work proportional to virtual
        // disk size and would compare against the extent-map identity rather
        // than a dense byte-stream hash.
        return Ok(());
    }
    validate_exact_checkpoint_artifact(
        &ProductionCheckpointArtifact {
            source: ProductionCheckpointArtifactSource::File(destination.to_path_buf()),
            identity: source.identity,
            length: source.length,
            chunks: Vec::new(),
            sparse: false,
            extents: Vec::new(),
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
    /// Scheduler-owned activity at the evidence boundary.
    pub scheduler_activity: SchedulerNodeActivity,
    /// Whether the production backend retains a QEMU process for this node.
    pub backend_owned: bool,
    /// Exact relationship between backend, current manifest, and staged owner.
    pub process_ownership: &'static str,
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

#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ProductionRunState {
    version: u32,
    runtime_event_records: u64,
    runtime_event_log_bytes: u64,
    manifest: ProductionRunManifest,
    journal: ProductionLifecycleJournal,
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
    signal_fault_branches: VecDeque<crucible::SignalFaultCampaignBranch>,
    promote_signal_fault_campaign_choices: bool,
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
    immutable_root_images: BTreeMap<NodeId, ContentHash>,
    node_generations: BTreeMap<NodeId, u64>,
    node_leases: BTreeMap<NodeId, Box<dyn ProductionVmNodeLease>>,
    node_lease_cleanup_failed: bool,
    node_service_states: BTreeMap<NodeId, ProductionNodeServiceState>,
    lifecycle_journal: ProductionLifecycleJournal,
    lifecycle_persistence: LifecycleStatePersistence,
    run_manifest: ProductionRunManifest,
    scenario: ScenarioDef,
    source: ScenarioDefForm,
    config: ProductionVmLifecycleConfig,
    checkpoint_targets: BTreeMap<ContentHash, quantum_loop::ExactCheckpointPublicationState>,
    recorded_controls: Vec<ProductionVmRecordedControl>,
    signal_artifact_objects: BTreeMap<ContentHash, Vec<u8>>,
    debug_backend_paths: BTreeMap<NodeId, PathBuf>,
    debug_gateway: Option<DebugGatewayProcess>,
    debug_attach: Option<GdbAttachInfo>,
    debug_gateway_teardown_required: bool,
    indeterminate_debug_candidate: Option<Box<ProductionVmLifecycleLoop>>,
    debug_runtime_evidence: Vec<ProductionVmDebugRuntimeEvidence>,
    node_launcher: Box<dyn ProductionVmNodeLauncher>,
    _run_directory: ProductionRunDirectory,
}

/// Exact scheduler/evidence boundary exposed after production checkpoint restore.
#[derive(Clone, Debug)]
pub struct ProductionVmLifecycleResumeState {
    event_log: Vec<SchedulerEventLogEntry>,
    event_log_base_events: u64,
    scheduler_quiescence: SchedulerQuiescence,
    terminal_verdict: Option<QuantumTerminalVerdict>,
}

impl ProductionVmLifecycleResumeState {
    /// Binds one complete retained event history to its exact restored boundary.
    ///
    /// `event_log_base_events` records how many earlier events are absent from
    /// `event_log`. Callers that require cumulative attempt evidence must reject
    /// a nonzero value rather than silently treating the retained suffix as the
    /// whole run.
    #[must_use]
    pub fn new(
        event_log: Vec<SchedulerEventLogEntry>,
        event_log_base_events: u64,
        scheduler_quiescence: SchedulerQuiescence,
        terminal_verdict: Option<QuantumTerminalVerdict>,
    ) -> Self {
        Self {
            event_log,
            event_log_base_events,
            scheduler_quiescence,
            terminal_verdict,
        }
    }

    /// Consumes the state into its exact retained evidence and stop boundary.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        Vec<SchedulerEventLogEntry>,
        u64,
        SchedulerQuiescence,
        Option<QuantumTerminalVerdict>,
    ) {
        (
            self.event_log,
            self.event_log_base_events,
            self.scheduler_quiescence,
            self.terminal_verdict,
        )
    }
}

/// Process materialization requested by the authoritative production lifecycle.
#[derive(Clone, Copy, Debug)]
pub enum ProductionVmNodeLaunchKind<'a> {
    /// Starts one freshly provisioned node at its baked ready boundary.
    Fresh,
    /// Restores one authenticated exact snapshot.
    Exact {
        /// Snapshot paired with the scheduler and host-I/O continuation.
        snapshot: &'a ExactSnapshotHandle,
        /// Whether the restored node remains paused after installation.
        paused: bool,
    },
}

/// Immutable checkpoint artifact offered to one node-generation preparer.
///
/// The capability keeps the checkpoint store representation private while
/// allowing an injected preparation authority to authenticate and materialize
/// the exact bytes only after it has installed its writable-storage policy.
#[derive(Clone, Copy, Debug)]
pub struct ProductionVmNodeCheckpointArtifact<'a> {
    artifact: &'a ProductionCheckpointArtifact,
    role: &'static str,
}

impl ProductionVmNodeCheckpointArtifact<'_> {
    /// Returns the exact authenticated identity of the artifact.
    ///
    /// Dense artifacts identify their complete byte stream. Sparse overlays
    /// identify their logical length and canonical changed-chunk extent map;
    /// omitted chunks have the authenticated meaning of zeroes.
    #[must_use]
    pub const fn identity(&self) -> ContentHash {
        self.artifact.identity
    }

    /// Returns the exact logical byte length of the artifact.
    #[must_use]
    pub const fn length(&self) -> u64 {
        self.artifact.length
    }

    /// Streams and authenticates the complete artifact into `destination`.
    ///
    /// The method bounds its temporary memory independently of artifact size
    /// and validates both the declared length and authenticated identity before
    /// returning success. A destination may have received a partial prefix on
    /// failure; callers must use a fail-closed staging or linear materialization
    /// authority when partial output cannot be reused.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::LoopFactory`] when the retained source is
    /// unavailable or changed, a chunk closure is invalid, the destination
    /// rejects a write, or the final length or authenticated identity differs.
    pub fn stream_into(
        &self,
        destination: &mut impl std::io::Write,
    ) -> Result<(), LifecycleApiError> {
        checkpoint_store::stream_checkpoint_artifact(self.artifact, destination, self.role)
    }

    /// Materializes and reauthenticates the artifact at `destination`.
    ///
    /// The destination must not already exist. The copy is staged under its
    /// parent and durably published only after its length and authenticated
    /// identity match this capability.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::LoopFactory`] when source authentication,
    /// bounded copying, destination publication, or directory synchronization
    /// fails.
    pub fn materialize_into(&self, destination: &Path) -> Result<(), LifecycleApiError> {
        copy_exact_checkpoint_artifact(self.artifact, destination, self.role)
    }
}

/// Filesystem preparation requested for one production node generation.
#[derive(Clone, Copy, Debug)]
pub enum ProductionVmNodePreparationKind<'a> {
    /// Creates a fresh writable root overlay from one immutable root image.
    Fresh {
        /// QEMU executable whose adjacent `qemu-img` owns the image format.
        qemu_executable: &'a Path,
        /// Immutable root image used only as the overlay size and backing basis.
        root_image: &'a Path,
    },
    /// Materializes the two authenticated artifacts of an exact restore.
    Exact {
        /// Complete authenticated per-node checkpoint manifest identity.
        root: ContentHash,
        /// Exact writable-root overlay artifact.
        root_overlay: ProductionVmNodeCheckpointArtifact<'a>,
        /// Exact QEMU VMState artifact.
        vmstate: ProductionVmNodeCheckpointArtifact<'a>,
    },
    /// Clones the current generation's writable artifacts for replacement.
    Replacement {
        /// Exact prior generation directory owned by the same launcher.
        source_run_directory: &'a Path,
    },
}

#[derive(Clone, Copy, Debug)]
struct ProductionVmNodeLaunchBasis<'a> {
    launch: &'a ProductionLiveNodeStepGateConfig,
    run_directory: &'a Path,
    node: &'a NodeId,
    generation: u64,
}

impl<'a> ProductionVmNodeLaunchBasis<'a> {
    const fn new(
        launch: &'a ProductionLiveNodeStepGateConfig,
        run_directory: &'a Path,
        node: &'a NodeId,
        generation: u64,
    ) -> Self {
        Self {
            launch,
            run_directory,
            node,
            generation,
        }
    }
}

/// Borrowed launch request for one production lifecycle node generation.
#[derive(Clone, Copy, Debug)]
pub struct ProductionVmNodeLaunchRequest<'a> {
    launch: &'a ProductionLiveNodeStepGateConfig,
    run_directory: &'a Path,
    node: &'a NodeId,
    generation: u64,
    router_name: &'a str,
    crash_detector: &'a str,
    preparation: ProductionVmNodePreparationKind<'a>,
    kind: ProductionVmNodeLaunchKind<'a>,
}

impl<'a> ProductionVmNodeLaunchRequest<'a> {
    const fn new(
        basis: ProductionVmNodeLaunchBasis<'a>,
        router_name: &'a str,
        crash_detector: &'a str,
        preparation: ProductionVmNodePreparationKind<'a>,
        kind: ProductionVmNodeLaunchKind<'a>,
    ) -> Self {
        Self {
            launch: basis.launch,
            run_directory: basis.run_directory,
            node: basis.node,
            generation: basis.generation,
            router_name,
            crash_detector,
            preparation,
            kind,
        }
    }

    /// Returns the validated production launch profile.
    #[must_use]
    pub const fn launch(&self) -> &ProductionLiveNodeStepGateConfig {
        self.launch
    }

    /// Returns the descriptor-owning node run-directory path.
    #[must_use]
    pub const fn run_directory(&self) -> &Path {
        self.run_directory
    }

    /// Returns the exact scheduler node identity.
    #[must_use]
    pub const fn node(&self) -> &NodeId {
        self.node
    }

    /// Returns the scheduler node name.
    #[must_use]
    pub fn node_name(&self) -> &str {
        &self.node.name
    }

    /// Returns the positive process generation being materialized.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the deterministic router role name.
    #[must_use]
    pub const fn router_name(&self) -> &str {
        self.router_name
    }

    /// Returns the process-generation crash-detector label.
    #[must_use]
    pub const fn crash_detector(&self) -> &str {
        self.crash_detector
    }

    /// Returns the exact writable-artifact operation preceding process spawn.
    #[must_use]
    pub const fn preparation(&self) -> ProductionVmNodePreparationKind<'a> {
        self.preparation
    }

    /// Returns the fresh or exact process materialization request.
    #[must_use]
    pub const fn kind(&self) -> ProductionVmNodeLaunchKind<'a> {
        self.kind
    }
}

/// Exact lifecycle identity of one contained QEMU process generation.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ProductionVmNodeGeneration {
    node: NodeId,
    generation: u64,
}

impl ProductionVmNodeGeneration {
    /// Builds one positive node-generation identity.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::LoopFactory`] when `generation` is zero.
    pub fn new(node: NodeId, generation: u64) -> Result<Self, LifecycleApiError> {
        if generation == 0 {
            return Err(loop_factory_error(
                "production QEMU process generation must be positive",
            ));
        }
        Ok(Self { node, generation })
    }

    /// Returns the exact scheduler node identity.
    #[must_use]
    pub const fn node(&self) -> &NodeId {
        &self.node
    }

    /// Returns the positive process generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }
}

/// Linear containment lease retained for one launched QEMU generation.
///
/// A lease may own cgroup membership, filesystem-quota reservations, process
/// identities, or other attempt-scoped accounting. Its `Drop` path must retain
/// or transfer any unfinished authority to quarantine; dropping an unfinished
/// lease must never claim that resources were released.
pub trait ProductionVmNodeLease: Send {
    /// Returns the exact node generation owned by this lease.
    #[must_use]
    fn identity(&self) -> &ProductionVmNodeGeneration;

    /// Releases generation-specific authority after QEMU reap is attested.
    ///
    /// Implementations must be idempotent. An error must retain or transfer
    /// remaining authority to quarantine.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when containment release cannot be
    /// attested after the corresponding QEMU process was reaped.
    fn finish(&mut self) -> Result<(), LifecycleApiError>;
}

/// One live QEMU node paired with its exact linear containment lease.
#[must_use = "a launched QEMU node and its containment lease must remain jointly owned"]
pub struct ProductionVmNodeLaunch {
    node: QemuNode,
    lease: Box<dyn ProductionVmNodeLease>,
    run_directory: PathBuf,
}

/// One already-running hot-fork child offered for atomic lifecycle adoption.
///
/// Unlike [`ProductionVmNodeLaunch`], this value does not claim that the
/// lifecycle launcher created the process. A daemon constructs it only after
/// exact world assembly authenticated the child's source process,
/// configuration, event-log prefix, node coordinate, and generation. The
/// constructor captures the child process incarnation so lifecycle assembly
/// can reauthenticate it immediately before publication.
#[must_use = "install or retain the adopted QEMU node and its containment lease"]
pub struct ProductionVmHotForkNodeAdoption {
    identity: ProductionVmNodeGeneration,
    process: QemuProcessIdentity,
    node: QemuNode,
    lease: Box<dyn ProductionVmNodeLease>,
    run_directory: PathBuf,
}

impl ProductionVmHotForkNodeAdoption {
    /// Binds one assembled child to its exact generation and storage owner.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::LoopFactory`] when the lease names another
    /// generation, the run directory is empty, or the QEMU process incarnation
    /// cannot be authenticated.
    pub fn new<L>(
        identity: ProductionVmNodeGeneration,
        node: QemuNode,
        lease: L,
        run_directory: impl Into<PathBuf>,
    ) -> Result<Self, LifecycleApiError>
    where
        L: ProductionVmNodeLease + 'static,
    {
        if lease.identity() != &identity {
            return Err(loop_factory_error(
                "hot-fork QEMU node lease does not match its adopted generation",
            ));
        }
        let run_directory = run_directory.into();
        if run_directory.as_os_str().is_empty() {
            return Err(loop_factory_error(
                "hot-fork QEMU node adoption has an empty run directory",
            ));
        }
        #[cfg(not(target_os = "linux"))]
        return Err(loop_factory_error(
            "hot-fork QEMU node adoption requires a Linux host",
        ));
        #[cfg(target_os = "linux")]
        let process = node.process_identity().map_err(|error| {
            loop_factory_error(format!(
                "authenticate adopted hot-fork QEMU process: {error}"
            ))
        })?;
        Ok(Self {
            identity,
            process,
            node,
            lease: Box::new(lease),
            run_directory,
        })
    }

    /// Returns the exact node-generation identity.
    #[must_use]
    pub const fn identity(&self) -> &ProductionVmNodeGeneration {
        &self.identity
    }

    fn into_parts(
        self,
    ) -> (
        QemuProcessIdentity,
        QemuNode,
        Box<dyn ProductionVmNodeLease>,
        PathBuf,
    ) {
        (self.process, self.node, self.lease, self.run_directory)
    }
}

/// Immutable scenario-aware launch profile retained for background replay.
///
/// The profile is copied from the exact production lifecycle that produced a
/// checkpoint. It contains no process, run-directory, or resource authority.
/// A replay owner must install a fresh guarded directory and generation before
/// using [`Self::for_generation`].
#[derive(Clone, Debug)]
pub struct ProductionVmNodeReplayLaunchProfile {
    node: NodeId,
    launch: ProductionLiveNodeStepGateConfig,
}

impl ProductionVmNodeReplayLaunchProfile {
    /// Binds one immutable launch profile to its exact World node.
    #[must_use]
    pub fn new(node: NodeId, launch: ProductionLiveNodeStepGateConfig) -> Self {
        Self { node, launch }
    }

    /// Returns the exact World node described by this profile.
    #[must_use]
    pub const fn node(&self) -> &NodeId {
        &self.node
    }

    /// Installs a fresh replay run directory and process generation.
    ///
    /// Any operator gdbstub endpoint from the originating lifecycle is removed
    /// so a background replay cannot reuse its private socket or listener.
    #[must_use]
    pub fn for_generation(
        &self,
        run_directory: impl Into<PathBuf>,
        generation: u64,
    ) -> ProductionLiveNodeStepGateConfig {
        self.launch
            .clone()
            .with_run_directory(run_directory)
            .with_process_generation(generation)
            .without_gdbstub()
    }

    /// Returns the fixed resource baseline before a replay directory exists.
    #[must_use]
    pub const fn resource_requirements(&self) -> QemuLaunchResourceRequirements {
        self.launch.resource_requirements()
    }
}

impl ProductionVmNodeLaunch {
    /// Pairs a launched node with the lease for the exact request generation.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::LoopFactory`] when the lease names a
    /// different node or generation. The rejected node and lease are dropped
    /// through their fail-closed ownership paths.
    pub fn new<L>(
        request: ProductionVmNodeLaunchRequest<'_>,
        node: QemuNode,
        lease: L,
    ) -> Result<Self, LifecycleApiError>
    where
        L: ProductionVmNodeLease + 'static,
    {
        Self::new_in_run_directory(request, request.run_directory(), node, lease)
    }

    /// Pairs a launched node with its exact launcher-owned run directory.
    ///
    /// An attempt-owned launcher uses this constructor when its sealed storage
    /// allocator chooses a descriptor-pinned directory rather than trusting the
    /// lifecycle's diagnostic path hint.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError::LoopFactory`] when the lease names a
    /// different node or generation, or the chosen path is empty.
    pub fn new_in_run_directory<L>(
        request: ProductionVmNodeLaunchRequest<'_>,
        run_directory: impl Into<PathBuf>,
        node: QemuNode,
        lease: L,
    ) -> Result<Self, LifecycleApiError>
    where
        L: ProductionVmNodeLease + 'static,
    {
        let expected =
            ProductionVmNodeGeneration::new(request.node().clone(), request.generation())?;
        if lease.identity() != &expected {
            return Err(loop_factory_error(
                "production QEMU node lease does not match its launch request",
            ));
        }
        let run_directory = run_directory.into();
        if run_directory.as_os_str().is_empty() {
            return Err(loop_factory_error(
                "production QEMU node launch returned an empty run directory",
            ));
        }
        Ok(Self {
            node,
            lease: Box::new(lease),
            run_directory,
        })
    }

    /// Returns the exact directory retained for this launched generation.
    #[must_use]
    pub fn run_directory(&self) -> &Path {
        &self.run_directory
    }

    fn node(&self) -> &QemuNode {
        &self.node
    }

    fn node_mut(&mut self) -> &mut QemuNode {
        &mut self.node
    }

    fn into_parts(self) -> (QemuNode, Box<dyn ProductionVmNodeLease>) {
        (self.node, self.lease)
    }

    fn quarantine_and_finish(mut self) -> Result<(), SchedulerError> {
        self.node.force_quarantine_and_reap().map_err(|error| {
            SchedulerError::BoundaryViolation {
                message: format!("reap launched QEMU generation: {error}"),
            }
        })?;
        self.lease
            .finish()
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!("finish reaped QEMU generation lease: {error}"),
            })
    }
}

/// Attempt-owned authority for every QEMU generation in one production lifecycle.
///
/// Implementations may install cgroup, filesystem-quota, cancellation, and
/// process-reap ownership before delegating to the packaged QEMU launcher. An
/// error return must leave no unowned child process. The lifecycle retains this
/// authority for modeled crash/restart replacements instead of bypassing it
/// after the initial generation. Implementations must also retain or transfer
/// containment authority from their `Drop` path when lifecycle construction,
/// unwinding, or caller abandonment prevents an explicit [`Self::finish`].
pub trait ProductionVmNodeLauncher: Send {
    /// Admits one scheduler quantum under the retained attempt authority.
    ///
    /// Attempt-scoped launchers use this boundary to check sticky cancellation
    /// and atomically charge the aggregate execution-quantum ceiling before any
    /// scheduler, host-fault, or guest state can advance. The packaged launcher
    /// has no external attempt contract and therefore uses the default no-op.
    /// A failed admission must not consume modeled state or begin guest work.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] after cancellation, resource exhaustion,
    /// or loss of the retained attempt authority.
    fn begin_execution_quantum(&mut self) -> Result<(), LifecycleApiError>;

    /// Checks the retained attempt authority after one scheduler quantum.
    ///
    /// This post-boundary check makes cancellation or host-enforcement failure
    /// that raced the final guest operation observable before the lifecycle
    /// returns its modeled outcome. The packaged launcher uses the default
    /// no-op because it has no external attempt contract.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when the attempt became canceled or its
    /// resource enforcement can no longer be authenticated.
    fn check_operational_boundary(&mut self) -> Result<(), LifecycleApiError>;

    /// Launches one requested node generation.
    ///
    /// Before spawning any process, the implementation creates the generation
    /// run directory and performs [`ProductionVmNodeLaunchRequest::preparation`]
    /// under the same aggregate storage, cancellation, and cleanup authority.
    /// Success returns the node and a linear containment lease whose identity
    /// exactly matches the request. The lifecycle retains that lease until the
    /// corresponding child has been reaped.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when admission, namespace or artifact
    /// preparation, process launch, exact restore, or post-launch
    /// authentication fails. The implementation must retain or clean every
    /// partial artifact and retain or reap every process it may have spawned
    /// before returning.
    fn launch(
        &mut self,
        request: ProductionVmNodeLaunchRequest<'_>,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError>;

    /// Creates an independent authority for whole-world debugger replay.
    ///
    /// An attempt-scoped implementation may reject this operation when its
    /// resource contract cannot admit a second world. It must never silently
    /// substitute an unguarded launcher.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when replay process authority cannot be
    /// allocated under the same containment policy.
    fn replay_candidate(&self) -> Result<Box<dyn ProductionVmNodeLauncher>, LifecycleApiError>;

    /// Finalizes process-containment ownership after lifecycle node shutdown.
    ///
    /// The lifecycle calls this method after asking every retained QEMU node to
    /// shut down. Implementations must make it idempotent. Success attests that
    /// no child remains and that attempt resources may be released. An error
    /// must retain or transfer all remaining authority to quarantine. Dropping
    /// the authority without calling this method must provide the same
    /// fail-closed ownership transfer, without claiming resource release.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when reap or containment release cannot be
    /// attested. The caller reports this failure even when node shutdown also
    /// failed.
    fn finish(&mut self) -> Result<(), LifecycleApiError>;
}

#[derive(Clone, Copy, Debug, Default)]
struct PackagedProductionVmNodeLauncher;

struct PackagedProductionVmNodeLease {
    identity: ProductionVmNodeGeneration,
}

impl ProductionVmNodeLease for PackagedProductionVmNodeLease {
    fn identity(&self) -> &ProductionVmNodeGeneration {
        &self.identity
    }

    fn finish(&mut self) -> Result<(), LifecycleApiError> {
        Ok(())
    }
}

impl ProductionVmNodeLauncher for PackagedProductionVmNodeLauncher {
    fn begin_execution_quantum(&mut self) -> Result<(), LifecycleApiError> {
        Ok(())
    }

    fn check_operational_boundary(&mut self) -> Result<(), LifecycleApiError> {
        Ok(())
    }

    fn launch(
        &mut self,
        request: ProductionVmNodeLaunchRequest<'_>,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        fs::create_dir_all(request.run_directory()).map_err(|error| {
            loop_factory_error(format!(
                "create QEMU node run directory {}: {error}",
                request.run_directory().display()
            ))
        })?;
        match request.preparation() {
            ProductionVmNodePreparationKind::Fresh {
                qemu_executable,
                root_image,
            } => prepare_root_overlay(qemu_executable, root_image, request.run_directory()),
            ProductionVmNodePreparationKind::Exact {
                root: _,
                root_overlay,
                vmstate,
            } => {
                root_overlay.materialize_into(
                    &request
                        .run_directory()
                        .join(PRODUCTION_ROOT_OVERLAY_FILE_NAME),
                )?;
                vmstate
                    .materialize_into(&request.run_directory().join(PRODUCTION_VMSTATE_FILE_NAME))
            }
            ProductionVmNodePreparationKind::Replacement {
                source_run_directory,
            } => {
                for artifact in [
                    PRODUCTION_ROOT_OVERLAY_FILE_NAME,
                    PRODUCTION_VMSTATE_FILE_NAME,
                ] {
                    let source = source_run_directory.join(artifact);
                    let target = request.run_directory().join(artifact);
                    fs::copy(&source, &target).map_err(|error| {
                        loop_factory_error(format!(
                            "copy production lifecycle artifact {} to {}: {error}",
                            source.display(),
                            target.display()
                        ))
                    })?;
                }
                Ok(())
            }
        }?;
        let launched = match request.kind() {
            ProductionVmNodeLaunchKind::Fresh => launch_production_live_node(
                request.launch(),
                request.run_directory(),
                request.node_name(),
                request.router_name(),
                request.crash_detector(),
            ),
            ProductionVmNodeLaunchKind::Exact {
                snapshot,
                paused: false,
            } => launch_production_live_node_exact_snapshot(
                request.launch(),
                request.run_directory(),
                request.node_name(),
                request.router_name(),
                request.crash_detector(),
                snapshot,
            ),
            ProductionVmNodeLaunchKind::Exact {
                snapshot,
                paused: true,
            } => launch_production_live_node_exact_snapshot_paused(
                request.launch(),
                request.run_directory(),
                request.node_name(),
                request.router_name(),
                request.crash_detector(),
                snapshot,
            ),
        };
        let node = launched.map_err(|error| {
            loop_factory_error(format!(
                "launch QEMU node `{}` through packaged authority: {error}",
                request.node_name()
            ))
        })?;
        let identity =
            ProductionVmNodeGeneration::new(request.node().clone(), request.generation())?;
        ProductionVmNodeLaunch::new(request, node, PackagedProductionVmNodeLease { identity })
    }

    fn replay_candidate(&self) -> Result<Box<dyn ProductionVmNodeLauncher>, LifecycleApiError> {
        Ok(Box::new(Self))
    }

    fn finish(&mut self) -> Result<(), LifecycleApiError> {
        Ok(())
    }
}

fn launch_production_node_generation(
    launcher: &mut dyn ProductionVmNodeLauncher,
    basis: ProductionVmNodeLaunchBasis<'_>,
    crash_detector: &str,
    preparation: ProductionVmNodePreparationKind<'_>,
    kind: ProductionVmNodeLaunchKind<'_>,
) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
    ProductionVmNodeGeneration::new(basis.node.clone(), basis.generation)?;
    if !matches!(
        (preparation, kind),
        (
            ProductionVmNodePreparationKind::Fresh { .. },
            ProductionVmNodeLaunchKind::Fresh
        ) | (
            ProductionVmNodePreparationKind::Exact { .. }
                | ProductionVmNodePreparationKind::Replacement { .. },
            ProductionVmNodeLaunchKind::Exact { .. }
        )
    ) {
        return Err(loop_factory_error(
            "production QEMU node preparation does not match its launch kind",
        ));
    }
    launcher.launch(ProductionVmNodeLaunchRequest::new(
        basis,
        "crucible-router",
        crash_detector,
        preparation,
        kind,
    ))
}

fn finish_reaped_node_lease_map(
    node_generations: &BTreeMap<NodeId, u64>,
    node_leases: &mut BTreeMap<NodeId, Box<dyn ProductionVmNodeLease>>,
    nodes: &[NodeId],
) -> Result<(), SchedulerError> {
    let mut first_error = None;
    for node in nodes {
        let Some(generation) = node_generations.get(node).copied() else {
            if first_error.is_none() {
                first_error = Some(format!(
                    "reaped QEMU node `{}` has no authenticated generation",
                    node.name
                ));
            }
            continue;
        };
        let Some(mut lease) = node_leases.remove(node) else {
            if first_error.is_none() {
                first_error = Some(format!(
                    "reaped QEMU node `{}` has no generation lease",
                    node.name
                ));
            }
            continue;
        };
        if lease.identity().node() != node || lease.identity().generation() != generation {
            if first_error.is_none() {
                first_error = Some(format!(
                    "reaped QEMU node `{}` has a mismatched generation lease",
                    node.name
                ));
            }
            continue;
        }
        if let Err(error) = lease.finish()
            && first_error.is_none()
        {
            first_error = Some(format!(
                "finish reaped QEMU node `{}` generation {generation}: {error}",
                node.name
            ));
        }
    }
    first_error.map_or(Ok(()), |message| {
        Err(SchedulerError::BoundaryViolation { message })
    })
}

mod checkpoint_recovery;
use checkpoint_recovery::durable_run_state_api_error;
mod config;
mod helpers;
mod network_faults;
mod process_owners;
use process_owners::{
    ProductionLifecycleCompletedExit, ProductionLifecycleJournal, ProductionLifecycleJournalNode,
    ProductionLifecycleJournalPhase, ProductionRunManifest,
};
mod quantum_loop;
mod runtime;
mod search;
mod storage_faults;
// crucible-lint: allow stringly-error -- private run-directory decoding diagnostics are immediately wrapped in LifecycleApiError.
fn decode_run_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    decode_run_json_bounded(path, 1_048_576)
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
    resource_limits: FaultResourceLimits,
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
    let mut live_prior_run = false;
    for (_, directory) in &run_indexes {
        let (mut manifest, mut journal, runtime_event_records, runtime_event_log_bytes) =
            decode_prior_run_state(directory, &scenario_identity, resource_limits)
                .map_err(durable_run_state_api_error)?;
        let state_path = directory.join(PRODUCTION_RUN_STATE_FILE);
        if !manifest.clean_shutdown {
            let live_owner =
                linux_process_identity(manifest.owner.process_id).map_err(|error| {
                    loop_factory_error(format!("validate lifecycle run owner: {error}"))
                })?;
            if live_owner.as_ref() == Some(&manifest.owner) {
                live_prior_run = true;
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
            manifest.clean_shutdown = true;
            manifest.recovered_after_host_exit = true;
            persist_run_state_atomic(
                &state_path,
                &manifest,
                &journal,
                resource_limits,
                runtime_event_records,
                runtime_event_log_bytes,
            )
            .map_err(durable_run_state_api_error)?;
        }
        checkpoint_recovery::reconcile_abandoned_run_checkpoint_staging(directory)?;
    }
    if !live_prior_run {
        checkpoint_recovery::reconcile_abandoned_checkpoint_store_staging(
            &config.run_state_root,
            scenario.id(),
        )?;
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
        processes: process_owners::ProductionProcessOwners::new(),
        staged_processes: process_owners::ProductionProcessOwners::new(),
        clean_shutdown: false,
        recovered_after_host_exit: false,
    };
    let journal = ProductionLifecycleJournal {
        version: 1,
        transaction: 0,
        phase: ProductionLifecycleJournalPhase::Idle,
        nodes: Vec::new().into(),
        completed_exits: Vec::new().into(),
    };
    persist_run_state_atomic(
        &path.join(PRODUCTION_RUN_STATE_FILE),
        &manifest,
        &journal,
        resource_limits,
        0,
        0,
    )
    .map_err(durable_run_state_api_error)?;
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
    build_production_vm_lifecycle_loop_from_checkpoint_with_launcher(
        scenario,
        source,
        config,
        checkpoint,
        PackagedProductionVmNodeLauncher,
    )
}

/// Builds a production lifecycle from an exact checkpoint and launch authority.
///
/// The supplied authority owns every initial and modeled replacement QEMU
/// process generation. It is retained by the returned lifecycle.
///
/// # Errors
///
/// Returns [`LifecycleApiError::LoopFactory`] when the checkpoint closure is
/// invalid, materialization fails, or `launcher` cannot produce an exact
/// contained process generation.
pub fn build_production_vm_lifecycle_loop_from_checkpoint_with_launcher<L>(
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    config: &ProductionVmLifecycleConfig,
    checkpoint: &Checkpoint,
    launcher: L,
) -> Result<ProductionVmLifecycleLoop, LifecycleApiError>
where
    L: ProductionVmNodeLauncher + 'static,
{
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
    build_production_vm_lifecycle_loop_with_restore(
        scenario,
        source,
        config,
        Some(restored),
        Box::new(launcher),
        None,
    )
}

/// Builds a production lifecycle directly from one installed exact closure.
///
/// The closure identity must already name a complete native version-four
/// continuation below `config.run_state_root`. This boundary reauthenticates
/// the full scenario-aware closure and never substitutes fresh construction or
/// replay when it is absent.
///
/// # Errors
///
/// Returns [`LifecycleApiError::LoopFactory`] when the closure is unavailable,
/// corrupt, belongs to another scenario, or cannot restore a complete guarded
/// production lifecycle.
pub fn build_production_vm_lifecycle_loop_from_exact_closure(
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    config: &ProductionVmLifecycleConfig,
    closure: ContentHash,
) -> Result<ProductionVmLifecycleLoop, LifecycleApiError> {
    build_production_vm_lifecycle_loop_from_exact_closure_with_launcher(
        scenario,
        source,
        config,
        closure,
        PackagedProductionVmNodeLauncher,
    )
}

/// Builds a production lifecycle from one installed closure and launch authority.
///
/// The supplied authority owns every restored and later modeled replacement
/// generation. Closure loading and complete semantic validation finish before
/// any generation is offered to it.
///
/// # Errors
///
/// Returns [`LifecycleApiError::LoopFactory`] when closure authentication,
/// restore admission, or guarded node construction fails.
pub fn build_production_vm_lifecycle_loop_from_exact_closure_with_launcher<L>(
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    config: &ProductionVmLifecycleConfig,
    closure: ContentHash,
    launcher: L,
) -> Result<ProductionVmLifecycleLoop, LifecycleApiError>
where
    L: ProductionVmNodeLauncher + 'static,
{
    if source.scenario_def() != *scenario {
        return Err(loop_factory_error(
            "production exact closure source does not reconstruct the requested scenario",
        ));
    }
    let restored = load_exact_checkpoint_set(&config.run_state_root, scenario, source, closure)?;
    if restored.identity != closure {
        return Err(loop_factory_error(
            "production exact closure restored a different identity",
        ));
    }
    build_production_vm_lifecycle_loop_with_restore(
        scenario,
        source,
        config,
        Some(restored),
        Box::new(launcher),
        None,
    )
}

/// Adopts one completely assembled hot-fork child World as a lifecycle.
///
/// This boundary accepts no partial node set. Every running node in the opaque
/// host continuation must have exactly one already-authenticated child and
/// linear containment lease, while permanently failed nodes must have none.
/// Powered-off nodes currently fail closed because preserving their paused
/// restart image requires the still-open branch-private block/run-directory
/// handoff. The complete semantic and child inventories are validated before
/// the production run directory is created. Each retained process incarnation
/// is then reauthenticated before the lifecycle is published.
///
/// The continuation retains the exact source lifecycle configuration and
/// authenticated immutable/storage bindings. Only its durable run-state root
/// is replaced. The supplied launcher remains responsible for later modeled
/// process generations and must share the same aggregate attempt authority as
/// the adopted node leases.
///
/// # Errors
///
/// Returns [`LifecycleApiError::LoopFactory`] when the scenario, continuation,
/// node set, service-state policy, physical boundary, process incarnation,
/// lease, durable run-state root, or lifecycle construction differs from the
/// assembled World.
#[cfg(target_os = "linux")]
pub fn build_production_vm_lifecycle_loop_from_hot_fork_with_launcher<L>(
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    continuation: ProductionVmHotForkWorldContinuation,
    adoptions: Vec<ProductionVmHotForkNodeAdoption>,
    run_state_root: impl Into<PathBuf>,
    launcher: L,
) -> Result<ProductionVmLifecycleLoop, LifecycleApiError>
where
    L: ProductionVmNodeLauncher + 'static,
{
    if source.scenario_def() != *scenario || continuation.configuration().def.id() != scenario.id()
    {
        return Err(loop_factory_error(
            "hot-fork continuation does not reconstruct the requested scenario",
        ));
    }
    continuation
        .validate_complete_internal_state()
        .map_err(|error| loop_factory_error(format!("validate hot-fork continuation: {error}")))?;

    let source_nodes = source
        .world()
        .vm_nodes()
        .iter()
        .map(|node| node.id.clone())
        .collect::<BTreeSet<_>>();
    let continuation_nodes = continuation
        .nodes()
        .iter()
        .map(|boundary| boundary.node().clone())
        .collect::<BTreeSet<_>>();
    if source_nodes != continuation_nodes {
        return Err(loop_factory_error(
            "hot-fork continuation node set differs from the scenario World",
        ));
    }

    if adoptions.len() > source_nodes.len() {
        return Err(loop_factory_error(
            "hot-fork adopted child count exceeds the scenario World",
        ));
    }
    let mut adoptions_by_node = BTreeMap::new();
    for adoption in adoptions {
        let node = adoption.identity().node().clone();
        if adoptions_by_node.insert(node.clone(), adoption).is_some() {
            return Err(loop_factory_error(format!(
                "hot-fork World contains duplicate child `{}`",
                node.name
            )));
        }
    }
    let adoption_generations = adoptions_by_node
        .iter()
        .map(|(node, adoption)| (node.clone(), adoption.identity().generation()))
        .collect::<BTreeMap<_, _>>();
    let HotForkAdoptionInventory {
        expected_times,
        node_generations,
    } = validate_hot_fork_adoption_inventory(&continuation, &adoption_generations)?;

    let ProductionVmHotForkRestoreParts {
        config,
        checkpoint,
        immutable_root_images,
        block_bindings,
        ninep_bindings,
    } = continuation.into_restore_parts(node_generations, run_state_root);
    build_production_vm_lifecycle_loop_with_restore(
        scenario,
        source,
        &config,
        Some(checkpoint),
        Box::new(launcher),
        Some(ProductionVmHotForkRestore {
            expected_times,
            adoptions: adoptions_by_node,
            immutable_root_images,
            block_bindings,
            ninep_bindings,
        }),
    )
}

fn validate_hot_fork_adoption_inventory(
    continuation: &ProductionVmHotForkWorldContinuation,
    adoption_generations: &BTreeMap<NodeId, u64>,
) -> Result<HotForkAdoptionInventory, LifecycleApiError> {
    let mut expected_times = BTreeMap::new();
    let mut node_generations = BTreeMap::new();
    for boundary in continuation.nodes() {
        match boundary.service_state() {
            ProductionVmHotForkNodeServiceState::Running => {
                let generation = adoption_generations
                    .get(boundary.node())
                    .copied()
                    .ok_or_else(|| {
                        loop_factory_error(format!(
                            "hot-fork World has no adopted child for running node `{}`",
                            boundary.node().name
                        ))
                    })?;
                let expected_generation =
                    boundary.generation().checked_add(1).ok_or_else(|| {
                        loop_factory_error(format!(
                            "hot-fork source generation for `{}` cannot advance",
                            boundary.node().name
                        ))
                    })?;
                if generation != expected_generation {
                    return Err(loop_factory_error(format!(
                        "hot-fork child generation for `{}` is {generation}, expected {expected_generation}",
                        boundary.node().name
                    )));
                }
                let physical_time = boundary.physical_time().ok_or_else(|| {
                    loop_factory_error("running hot-fork node lost its physical boundary")
                })?;
                expected_times.insert(boundary.node().clone(), physical_time);
                node_generations.insert(boundary.node().clone(), generation);
            }
            ProductionVmHotForkNodeServiceState::PoweredOff => {
                return Err(loop_factory_error(format!(
                    "hot-fork lifecycle adoption does not yet support powered-off node `{}`",
                    boundary.node().name
                )));
            }
            ProductionVmHotForkNodeServiceState::PermanentlyFailed => {
                if adoption_generations.contains_key(boundary.node()) {
                    return Err(loop_factory_error(format!(
                        "permanently failed hot-fork node `{}` unexpectedly has a child",
                        boundary.node().name
                    )));
                }
                node_generations.insert(boundary.node().clone(), boundary.generation());
            }
        }
    }
    let expected_running = expected_times.keys().cloned().collect::<BTreeSet<_>>();
    if adoption_generations
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>()
        != expected_running
    {
        return Err(loop_factory_error(
            "hot-fork adopted child set differs from the running-node set",
        ));
    }
    Ok(HotForkAdoptionInventory {
        expected_times,
        node_generations,
    })
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
    build_production_vm_lifecycle_loop_with_launcher(
        scenario,
        source,
        config,
        PackagedProductionVmNodeLauncher,
    )
}

/// Builds a fresh production lifecycle under one retained launch authority.
///
/// The authority is invoked for every initial node and every later modeled
/// process replacement. This keeps an attempt-scoped containment policy on the
/// authoritative scheduler path for the lifecycle's complete process lifetime.
///
/// # Errors
///
/// Returns [`LifecycleApiError::LoopFactory`] when scenario validation,
/// run-directory preparation, launch admission, QEMU startup, or scheduler
/// construction fails.
pub fn build_production_vm_lifecycle_loop_with_launcher<L>(
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    config: &ProductionVmLifecycleConfig,
    launcher: L,
) -> Result<ProductionVmLifecycleLoop, LifecycleApiError>
where
    L: ProductionVmNodeLauncher + 'static,
{
    build_production_vm_lifecycle_loop_with_restore(
        scenario,
        source,
        config,
        None,
        Box::new(launcher),
        None,
    )
}

fn build_production_vm_lifecycle_loop_with_restore(
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    config: &ProductionVmLifecycleConfig,
    mut restore_checkpoint: Option<ProductionVmExactCheckpointSet>,
    mut node_launcher: Box<dyn ProductionVmNodeLauncher>,
    mut hot_fork_restore: Option<ProductionVmHotForkRestore>,
) -> Result<ProductionVmLifecycleLoop, LifecycleApiError> {
    if !cfg!(target_os = "linux") {
        return Err(loop_factory_error(
            "production local-QEMU lifecycle requires a Linux host",
        ));
    }

    if config.branch.is_some()
        && config
            .signal_fault_replay
            .as_ref()
            .is_some_and(|replay| !replay.branches().is_empty())
    {
        return Err(loop_factory_error(
            "raw production branch configuration cannot coexist with typed signal-fault replay",
        ));
    }
    if let Some(replay) = &config.signal_fault_replay
        && replay.target().def.id() != scenario.id()
    {
        return Err(loop_factory_error(
            "signal-fault replay target names a different scenario",
        ));
    }
    if restore_checkpoint.is_some()
        && config
            .signal_fault_replay
            .as_ref()
            .is_some_and(|replay| !replay.branches().is_empty())
    {
        return Err(loop_factory_error(
            "exact-checkpoint restore cannot install a fresh signal-fault replay plan",
        ));
    }
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
    validate_app_random_branch_replay_config(nodes, config)?;
    if let Some(checkpoint) = restore_checkpoint.as_ref() {
        let expected_selectable_nodes = nodes
            .iter()
            .filter(|node| {
                checkpoint.node_service_states.get(&node.id)
                    != Some(&ProductionNodeServiceState::PermanentlyFailed)
                    && source
                        .selectables()
                        .guest_declarations(&node.id)
                        .next()
                        .is_some()
            })
            .map(|node| node.id.clone())
            .collect::<BTreeSet<_>>();
        if checkpoint
            .selectable_catalog_plans
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>()
            != expected_selectable_nodes
        {
            return Err(loop_factory_error(
                "production exact checkpoint selectable catalog node set differs from the scenario",
            ));
        }
    }
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

    let (run_directory, mut run_manifest, lifecycle_journal) = production_run_directory(
        scenario,
        config,
        source.plan().fault_signals().resource_limits(),
    )?;
    let checkpoint_targets = checkpoint_recovery::recover_published_checkpoint_states(
        &config.run_state_root,
        scenario,
        source,
    )?;
    run_manifest
        .processes
        .try_reserve_exact(nodes.len())
        .map_err(|()| loop_factory_error("reserve initial QEMU process ownership"))?;
    let mut backends = ProductionNodeSet::new();
    let mut launch_configs = BTreeMap::new();
    let mut block_bindings = BTreeMap::new();
    let mut ninep_bindings = BTreeMap::new();
    let mut node_indexes = BTreeMap::new();
    let mut node_run_directories = BTreeMap::new();
    let mut node_generations = BTreeMap::new();
    let mut node_leases = BTreeMap::new();
    let mut node_service_states = BTreeMap::new();
    let mut immutable_root_images = BTreeMap::new();
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
        let immutable_root_image = hash_file(&guest_assets.root_image).map_err(|error| {
            loop_factory_error(format!(
                "hash immutable root image for production node `{}` from {}: {error}",
                vm.id.name,
                guest_assets.root_image.display()
            ))
        })?;
        let node_directory = run_directory.path().join(format!("node-{index}"));
        let restore_target = restore_checkpoint
            .as_ref()
            .and_then(|checkpoint| checkpoint.targets.get(&vm.id));
        let hot_fork_expected_time = hot_fork_restore
            .as_mut()
            .and_then(|restore| restore.expected_times.remove(&vm.id));
        let hot_fork_adoption = hot_fork_restore
            .as_mut()
            .and_then(|restore| restore.adoptions.remove(&vm.id));
        let hot_fork_immutable_root = hot_fork_restore
            .as_mut()
            .and_then(|restore| restore.immutable_root_images.remove(&vm.id));
        let restored_service_state = restore_checkpoint
            .as_ref()
            .and_then(|checkpoint| checkpoint.node_service_states.get(&vm.id))
            .copied();
        if restore_checkpoint.is_some()
            && restore_target.is_none()
            && hot_fork_adoption.is_none()
            && restored_service_state != Some(ProductionNodeServiceState::PermanentlyFailed)
        {
            return Err(loop_factory_error(format!(
                "production restore has no exact or hot-fork target for `{}`",
                vm.id.name
            )));
        }
        if let Some(target) = restore_target {
            let fault_identity = restore_checkpoint
                .as_ref()
                .and_then(|checkpoint| checkpoint.fault_checkpoint.as_ref())
                .map(ProductionFaultRuntimeCheckpoint::id)
                .ok_or_else(|| {
                    loop_factory_error("exact checkpoint target lost its fault continuation")
                })?;
            validate_exact_checkpoint_target(&vm.id, target, fault_identity)?;
            if let Some(expected) = target.immutable_backing
                && expected != immutable_root_image
            {
                return Err(loop_factory_error(format!(
                    "production exact checkpoint for `{}` names immutable backing {} but the selected root image hashes to {}",
                    vm.id.name,
                    expected.to_hex(),
                    immutable_root_image.to_hex()
                )));
            }
        }
        if hot_fork_restore.is_some() {
            let expected = hot_fork_immutable_root.ok_or_else(|| {
                loop_factory_error(format!(
                    "hot-fork continuation has no immutable root identity for `{}`",
                    vm.id.name
                ))
            })?;
            if expected != immutable_root_image {
                return Err(loop_factory_error(format!(
                    "hot-fork continuation for `{}` names immutable backing {} but the retained root image hashes to {}",
                    vm.id.name,
                    expected.to_hex(),
                    immutable_root_image.to_hex()
                )));
            }
        }
        immutable_root_images.insert(vm.id.clone(), immutable_root_image);
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
            &qemu_executable,
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
        .with_second_run_scheduler_preemption(false)
        .with_process_generation(generation)
        .with_fault_resource_limits(source.plan().fault_signals().resource_limits());
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
            let declarations = source
                .selectables()
                .guest_declarations(&vm.id)
                .map(|declaration| {
                    crucible_protocol::selectable_catalog_plan::SelectablePlanDeclaration::new(
                        declaration.name(),
                        declaration.domain().canonical_bytes(),
                        declaration.default().canonical_bytes(),
                        declaration.semantic_tags().iter().cloned().collect(),
                        if declaration.required() {
                            crucible_protocol::selectable_catalog_plan::SelectablePlanPresence::Required
                        } else {
                            crucible_protocol::selectable_catalog_plan::SelectablePlanPresence::Optional
                        },
                    )
                    .map_err(|error| {
                        loop_factory_error(format!(
                            "convert scenario selectable `{}` for `{}`: {error}",
                            declaration.name(), vm.id.name
                        ))
                    })
            })
            .collect::<Result<Vec<_>, LifecycleApiError>>()?;
            if !declarations.is_empty() {
                let limits = source.selectables().limits();
                let limits = crucible_protocol::selectable_catalog_plan::SelectablePlanLimits::new(
                    limits.declarations_per_node() as usize,
                    limits.requests_per_selectable(),
                    limits.requests_per_node(),
                )
                .map_err(|error| {
                    loop_factory_error(format!(
                        "convert scenario selectable limits for `{}`: {error}",
                        vm.id.name
                    ))
                })?;
                let cold_plan =
                    crucible_protocol::selectable_catalog_plan::SelectableCatalogPlan::new(
                    limits,
                    declarations,
                    crucible_protocol::selectable_catalog_plan::SelectablePlanContinuation::cold(),
                )
                .map_err(|error| {
                    loop_factory_error(format!(
                        "build scenario selectable catalog for `{}`: {error}",
                        vm.id.name
                    ))
                })?;
                let plan = if let Some(checkpoint) = restore_checkpoint.as_ref()
                    && restored_service_state != Some(ProductionNodeServiceState::PermanentlyFailed)
                {
                    let restored = checkpoint.selectable_catalog_plans.get(&vm.id).ok_or_else(
                        || {
                            loop_factory_error(format!(
                                "exact checkpoint has no selectable catalog continuation for `{}`",
                                vm.id.name
                            ))
                        },
                    )?;
                    if restored.limits() != cold_plan.limits()
                        || restored.declarations() != cold_plan.declarations()
                        || restored.continuation().phase()
                            != crucible_protocol::selectable_catalog_plan::SelectablePlanPhase::Frozen
                    {
                        return Err(loop_factory_error(format!(
                            "exact checkpoint selectable catalog basis differs for `{}`",
                            vm.id.name
                        )));
                    }
                    restored.clone()
                } else {
                    cold_plan
                };
                launch = launch.with_selectable_catalog_plan(plan);
            }
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
            }
            .with_branch_plan(
                config
                    .app_random_branch_plans
                    .get(&vm.id)
                    .cloned()
                    .unwrap_or_default(),
            );
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
            let block = if let Some(restore) = hot_fork_restore.as_mut() {
                restore.block_bindings.remove(&vm.id)
            } else {
                block_binding_for_vm(source.world(), &vm.id, config.world_artifacts.as_ref())?
            };
            if let Some(block) = block {
                launch = launch.with_shmem_block(block.base.clone(), block.durability.clone());
                block_bindings.insert(vm.id.clone(), block);
            }
            let ninep = if let Some(restore) = hot_fork_restore.as_mut() {
                restore.ninep_bindings.remove(&vm.id)
            } else {
                ninep_binding_for_vm(source.world(), &vm.id, config.world_artifacts.as_ref())?
            };
            if let Some(ninep) = ninep {
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
            let backend_listen = live_unix_gdbstub_endpoint(&backend_path)?;
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
        let crash_detector = format!("lifecycle-{}-generation-{generation}", vm.id.name);
        let preparation = match restore_target {
            Some(target) => ProductionVmNodePreparationKind::Exact {
                root: target.manifest_identity,
                root_overlay: ProductionVmNodeCheckpointArtifact {
                    artifact: &target.overlay_artifact,
                    role: "root overlay",
                },
                vmstate: ProductionVmNodeCheckpointArtifact {
                    artifact: &target.vmstate_artifact,
                    role: "VMState",
                },
            },
            None => ProductionVmNodePreparationKind::Fresh {
                qemu_executable: &qemu_executable,
                root_image: &guest_assets.root_image,
            },
        };
        let launched = if let Some(adoption) = hot_fork_adoption {
            if restore_target.is_some()
                || service_state != ProductionNodeServiceState::Running
                || hot_fork_expected_time.is_none()
            {
                return Err(loop_factory_error(format!(
                    "hot-fork child for `{}` conflicts with its restore state",
                    vm.id.name
                )));
            }
            let (process, node, lease, run_directory) = adoption.into_parts();
            if lease.identity().node() != &vm.id || lease.identity().generation() != generation {
                return Err(loop_factory_error(format!(
                    "hot-fork child lease for `{}` changed before adoption",
                    vm.id.name
                )));
            }
            Ok((
                ProductionVmNodeLaunch {
                    node,
                    lease,
                    run_directory,
                },
                Some(process),
            ))
        } else {
            match (restore_target, service_state) {
                (Some(target), ProductionNodeServiceState::Running) => {
                    launch_production_node_generation(
                        node_launcher.as_mut(),
                        ProductionVmNodeLaunchBasis::new(
                            &launch,
                            &node_directory,
                            &vm.id,
                            generation,
                        ),
                        &crash_detector,
                        preparation,
                        ProductionVmNodeLaunchKind::Exact {
                            snapshot: &target.snapshot,
                            paused: false,
                        },
                    )
                    .map(|launch| (launch, None))
                }
                (Some(target), ProductionNodeServiceState::PoweredOff) => {
                    launch_production_node_generation(
                        node_launcher.as_mut(),
                        ProductionVmNodeLaunchBasis::new(
                            &launch,
                            &node_directory,
                            &vm.id,
                            generation,
                        ),
                        &crash_detector,
                        preparation,
                        ProductionVmNodeLaunchKind::Exact {
                            snapshot: &target.snapshot,
                            paused: true,
                        },
                    )
                    .map(|launch| (launch, None))
                }
                (Some(_), ProductionNodeServiceState::PermanentlyFailed) => {
                    return Err(loop_factory_error(format!(
                        "exact checkpoint for permanently failed node `{}` unexpectedly contains a live process target",
                        vm.id.name
                    )));
                }
                (None, ProductionNodeServiceState::PermanentlyFailed) => continue,
                (None, _) => launch_production_node_generation(
                    node_launcher.as_mut(),
                    ProductionVmNodeLaunchBasis::new(&launch, &node_directory, &vm.id, generation),
                    &format!("lifecycle-{}", vm.id.name),
                    preparation,
                    ProductionVmNodeLaunchKind::Fresh,
                )
                .map(|launch| (launch, None)),
            }
        };
        let (mut launched, adopted_process) = launched?;
        let observed = SimulationBackend::now(launched.node()).ticks;
        if let Some(expected_time) = hot_fork_expected_time {
            if expected_time.ticks != observed {
                let _ = launched.quarantine_and_finish();
                return Err(loop_factory_error(format!(
                    "hot-fork QEMU node `{}` resumed at unauthenticated instruction boundary {observed}",
                    vm.id.name
                )));
            }
        } else if let Some(target) = restore_target {
            let restored_configuration = restore_checkpoint
                .as_ref()
                .map(|checkpoint| checkpoint.configuration.id());
            if Some(target.configuration.id()) != restored_configuration
                || target.counter != observed
            {
                let _ = launched.quarantine_and_finish();
                return Err(loop_factory_error(format!(
                    "QEMU node `{}` restored at unauthenticated instruction boundary {observed}",
                    vm.id.name
                )));
            }
            let Some(expected_fingerprint) = restore_checkpoint
                .as_ref()
                .and_then(|checkpoint| checkpoint.fault_checkpoint.as_ref())
                .and_then(|checkpoint| checkpoint.qemu_fingerprint(&vm.id))
            else {
                let _ = launched.quarantine_and_finish();
                return Err(loop_factory_error(format!(
                    "exact checkpoint for `{}` has no authenticated QEMU fingerprint",
                    vm.id.name
                )));
            };
            let restored_fingerprint = match launched.node_mut().execution_fingerprint() {
                Ok(fingerprint) => fingerprint.hash,
                Err(error) => {
                    let _ = launched.quarantine_and_finish();
                    return Err(loop_factory_error(format!(
                        "read restored QEMU fingerprint for `{}`: {error}",
                        vm.id.name
                    )));
                }
            };
            if restored_fingerprint != expected_fingerprint {
                let _ = launched.quarantine_and_finish();
                return Err(loop_factory_error(format!(
                    "QEMU node `{}` restored with an unauthenticated execution fingerprint: expected {}, observed {}",
                    vm.id.name,
                    expected_fingerprint.to_hex(),
                    restored_fingerprint.to_hex(),
                )));
            }
        } else if initial_ticks.is_some_and(|initial| initial != observed) {
            let _ = launched.quarantine_and_finish();
            return Err(loop_factory_error(format!(
                "QEMU node `{}` primed at {observed}, expected {}",
                vm.id.name,
                initial_ticks.unwrap_or_default()
            )));
        }
        if restore_target.is_none() && hot_fork_expected_time.is_none() {
            initial_ticks.get_or_insert(observed);
        }
        let process_identity = match launched.node().process_identity() {
            Ok(identity) => identity,
            Err(error) => {
                let containment = launched.quarantine_and_finish();
                return Err(loop_factory_error(format!(
                    "capture initial QEMU identity for `{}`: {error}; process containment: {}",
                    vm.id.name,
                    containment.map_or_else(
                        |failure| failure.to_string(),
                        |()| String::from("reaped and lease released")
                    )
                )));
            }
        };
        if adopted_process
            .as_ref()
            .is_some_and(|expected| expected != &process_identity)
        {
            let containment = launched.quarantine_and_finish();
            return Err(loop_factory_error(format!(
                "adopted hot-fork QEMU process for `{}` changed before lifecycle publication; process containment: {}",
                vm.id.name,
                containment.map_or_else(
                    |failure| failure.to_string(),
                    |()| String::from("reaped and lease released")
                )
            )));
        }
        let launched_run_directory = launched.run_directory().to_path_buf();
        node_run_directories.insert(vm.id.clone(), launched_run_directory.clone());
        launch_configs.insert(
            vm.id.clone(),
            launch.clone().with_run_directory(&launched_run_directory),
        );
        if debug_backend_paths.contains_key(&vm.id) {
            debug_backend_paths.insert(
                vm.id.clone(),
                private_backend_gdbstub_path(&launched_run_directory),
            );
        }
        let (backend, lease) = launched.into_parts();
        if backends.insert(vm.id.clone(), backend).is_some() {
            return Err(loop_factory_error(format!(
                "duplicate QEMU node identity `{}`",
                vm.id.name
            )));
        }
        if node_leases.insert(vm.id.clone(), lease).is_some() {
            return Err(loop_factory_error(format!(
                "duplicate QEMU node lease identity `{}`",
                vm.id.name
            )));
        }
        run_manifest
            .processes
            .insert_reserved(vm.id.name.clone(), process_identity)
            .map_err(|()| loop_factory_error("initial QEMU process reservation was exhausted"))?;
        if let Err(error) = persist_run_state_atomic(
            &run_directory.path().join(PRODUCTION_RUN_STATE_FILE),
            &run_manifest,
            &lifecycle_journal,
            source.plan().fault_signals().resource_limits(),
            0,
            0,
        ) {
            let backend_cleanup = backends.shutdown();
            let lease_cleanup = if backend_cleanup.is_ok() {
                let nodes = node_leases.keys().cloned().collect::<Vec<_>>();
                finish_reaped_node_lease_map(&node_generations, &mut node_leases, &nodes)
            } else {
                Ok(())
            };
            let launcher_cleanup = if backend_cleanup.is_ok() && lease_cleanup.is_ok() {
                node_launcher.finish()
            } else {
                Ok(())
            };
            return Err(loop_factory_error(format!(
                "persist initial QEMU process ownership: {error}; backend cleanup: {}; generation-lease cleanup: {}; launcher cleanup: {}",
                backend_cleanup
                    .map_or_else(|failure| failure.to_string(), |()| String::from("reaped")),
                lease_cleanup.map_or_else(
                    |failure| failure.to_string(),
                    |()| String::from("released or retained")
                ),
                launcher_cleanup
                    .map_or_else(|failure| failure.to_string(), |()| String::from("released"))
            )));
        }
    }

    if hot_fork_restore.as_ref().is_some_and(|restore| {
        !restore.expected_times.is_empty()
            || !restore.adoptions.is_empty()
            || !restore.immutable_root_images.is_empty()
            || !restore.block_bindings.is_empty()
            || !restore.ninep_bindings.is_empty()
    }) {
        return Err(loop_factory_error(
            "hot-fork lifecycle retained unconsumed child-world state",
        ));
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
        if let Some(frontier) = config
            .branch
            .as_ref()
            .map(|branch| branch.frontier)
            .or_else(|| {
                config
                    .signal_fault_replay
                    .as_ref()
                    .and_then(|replay| replay.branches().first())
                    .map(crucible::SignalFaultCampaignBranch::frontier)
            })
        {
            scheduler
                .set_branch_frontier_cap(frontier)
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
        scheduler
            .install_app_random_branch_selections(config.app_random_branch_selections.clone())
            .map_err(|error| {
                loop_factory_error(format!(
                    "install QEMU app-random branch selections: {error}"
                ))
            })?;
    }
    let trigger_graph = source
        .plan()
        .lower_to_event_graph_for_world(source.world())
        .map_err(|error| loop_factory_error(format!("lower scenario trigger plan: {error}")))?
        .into_event_graph();
    let signal_plan = source.plan().fault_signals().clone();
    let fault_search_overrides = production_fault_search_overrides(
        config.branch.as_ref(),
        config.signal_fault_replay.as_ref(),
    )?;
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
    ) = if let Some(checkpoint) = &mut restore_checkpoint {
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
        let fault_checkpoint = checkpoint.fault_checkpoint.take().ok_or_else(|| {
            loop_factory_error("production exact checkpoint lost its fault continuation")
        })?;
        let (interceptor, committed_frontier) = ProductionFaultNetworkInterceptor::restore(
            signal_plan,
            signal_artifacts,
            scenario.id(),
            fault_checkpoint,
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
            source.plan().fault_signals().resource_limits(),
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
                    source.plan().fault_signals().resource_limits(),
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
    let signal_fault_branches = if restore_checkpoint.is_some() {
        VecDeque::new()
    } else {
        config
            .signal_fault_replay
            .as_ref()
            .map_or_else(VecDeque::new, |replay| {
                replay.branches().iter().cloned().collect()
            })
    };
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
        signal_fault_branches,
        promote_signal_fault_campaign_choices: false,
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
        immutable_root_images,
        node_generations,
        node_leases,
        node_lease_cleanup_failed: false,
        node_service_states,
        lifecycle_journal,
        lifecycle_persistence: LifecycleStatePersistence::new(run_directory.path())
            .map_err(loop_factory_error)?,
        run_manifest,
        scenario: scenario.clone(),
        source: source.clone(),
        config: config.clone(),
        checkpoint_targets,
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
        node_launcher,
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
            let cleanup = QuantumLoop::shutdown(&mut lifecycle);
            return Err(loop_factory_error(format!(
                "restore host assertion continuation: {error}; lifecycle cleanup: {}",
                cleanup.map_or_else(
                    |failure| failure.to_string(),
                    |_: Vec<_>| String::from("reaped and released")
                )
            )));
        }
    }
    if let Err(error) = lifecycle.capture_debug_runtime_evidence() {
        let cleanup = QuantumLoop::shutdown(&mut lifecycle);
        return Err(loop_factory_error(format!(
            "capture initial debugger runtime evidence: {error}; lifecycle cleanup: {}",
            cleanup.map_or_else(
                |failure| failure.to_string(),
                |_: Vec<_>| String::from("reaped and released")
            )
        )));
    }
    Ok(lifecycle)
}

fn validate_app_random_branch_replay_config(
    nodes: &[crucible::WorldNode],
    config: &ProductionVmLifecycleConfig,
) -> Result<(), LifecycleApiError> {
    let mut planned_selection_ids = BTreeMap::<[u8; 32], usize>::new();
    let mut planned_count = 0_usize;
    for (node, plan) in &config.app_random_branch_plans {
        if !nodes
            .iter()
            .any(|vm| vm.id == *node && vm.white_box == crucible::WhiteBoxPolicy::Enabled)
        {
            return Err(loop_factory_error(format!(
                "app-random branch plan names missing or white-box-disabled node `{}`",
                node.name
            )));
        }
        for entry in plan.entries() {
            if !crucible_protocol::app_random_transport::app_random_stream_name_belongs_to_node(
                entry.stream_name(),
                &node.name,
            ) {
                return Err(loop_factory_error(format!(
                    "app-random branch plan for `{}` contains a foreign stream",
                    node.name
                )));
            }
            planned_count = planned_count
                .checked_add(1)
                .ok_or_else(|| loop_factory_error("app-random branch plan entry count overflow"))?;
            if planned_count
                > crucible_protocol::app_random_branch_plan::MAX_APP_RANDOM_BRANCH_PLAN_ENTRIES
            {
                return Err(loop_factory_error(
                    "app-random branch replay exceeds the aggregate selection bound",
                ));
            }
            let count = planned_selection_ids
                .entry(entry.selection_id())
                .or_default();
            *count = count.checked_add(1).ok_or_else(|| {
                loop_factory_error("app-random branch selection multiplicity overflow")
            })?;
        }
    }

    if planned_count != config.app_random_branch_selections.len() {
        return Err(loop_factory_error(
            "app-random scheduler selections and plugin plan entries differ in count",
        ));
    }
    for decision in config.app_random_branch_selections.values() {
        let selection = decision.selection().map_err(|error| {
            loop_factory_error(format!(
                "decode configured app-random branch selection: {error}"
            ))
        })?;
        let selection_id = selection
            .id()
            .map_err(|error| {
                loop_factory_error(format!(
                    "derive configured app-random branch selection identity: {error}"
                ))
            })?
            .content_id()
            .digest();
        let Some(count) = planned_selection_ids.get_mut(&selection_id) else {
            return Err(loop_factory_error(
                "app-random scheduler selection is absent from the plugin plans",
            ));
        };
        *count -= 1;
        if *count == 0 {
            planned_selection_ids.remove(&selection_id);
        }
    }
    if !planned_selection_ids.is_empty() {
        return Err(loop_factory_error(
            "app-random plugin plan contains an uninstalled scheduler selection",
        ));
    }
    Ok(())
}
