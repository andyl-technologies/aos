//! Production local-VM lifecycle loop construction.
//!
//! This module composes a submitted [`ScenarioDefForm`] into the authoritative
//! [`SingleScheduler`], one live QEMU node per World VM, and the node-addressed
//! backend loop consumed by [`LifecycleControlPlane`](crate::LifecycleControlPlane).

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
    EventGraph, EventGraphState, EventLogOffset, ExecutionFingerprint, FingerprintSample,
    GdbAttachInfo, GdbListen, HostAssertionEvaluator, HostAssertionEvaluatorCheckpoint,
    HostAssertionOutcome, HostAssertionOutcomeKind, Icount, NodeId, NodeLifecycle, ObservableEvent,
    QuantumLoop, QuantumOutcome, QuantumRequest, QuantumTerminalVerdict, RuntimeState, ScenarioDef,
    ScenarioDefForm, Schedule, SchedulerError, SchedulerEventLogAppend, SchedulerEventLogEntry,
    SchedulerLivenessScenario, SchedulerNodeActivity, SchedulerQuiescence, SchedulerState,
    SearchFrontierChoices, Seed, SelectionDecision, Shift, SignalFaultCampaignReplayPlan,
    SimDuration, SimInstant, SimulationBackend, SingleScheduler, SingleSchedulerCheckpoint,
    VirtualTime, VmArchitecture, World, WorldIoNodeKind,
};
pub use crucible_qemu::{
    BoundedSchedulerPreemptionEvidence, BoundedSchedulerPreemptionEvidenceSnapshot,
};
use crucible_qemu::{
    DEFAULT_ROOT_OVERLAY_FILE_NAME, LivePluginGuestArchitecture, QemuGdbstubChannelConfig,
    QemuLaunchAppRandomConfig, QemuLaunchPluginSwitch, QemuLiveNodeStepGateConfig, QemuNodeSet,
    QemuRootImageFormat,
};
use crucible_qemu::{
    ProductionFaultRuntime, ProductionFaultRuntimeCheckpoint, ProductionNetworkStateCheckpoint,
    QemuExactCheckpointCaptureResult, QemuHostIoCheckpoint, QemuLaunchResourceRequirements,
    QemuNode, QemuNodeLifecycleDecision, QemuNodeLifecycleIntent as LifecycleMutationIntent,
    QemuPreparedRunDirectory, QemuProcessIdentity, QemuReplayOracleMatch, QemuSharedBlockDevice,
    QemuVmSnapshot as ExactSnapshotHandle, QmpCheckpointIdentity, QmpCheckpointRamKind,
    linux_process_identity, quarantine_orphaned_qemu_process,
};
#[cfg(target_os = "linux")]
use crucible_qemu::{
    QemuExactCheckpointCaptureAdmission, QemuNodeSetPreparedHotForkSource,
    QemuNodeSetPreparedHotForkTemplate,
};
use quantum_loop::{
    DurableRunStateError, LifecycleStatePersistence, PRODUCTION_RUN_STATE_FILE,
    decode_prior_run_state, decode_run_json_bounded, persist_run_state_atomic,
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::fs::{self, File, OpenOptions};
use std::io::Write as _;
use std::net::SocketAddr;
#[cfg(target_os = "linux")]
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

mod assets;
use assets::{
    ProductionVmGuestAssets, production_kernel_cmdline_prefix, validate_guest_asset_references,
};
pub use assets::{ProductionVmPortableReplayAssetPaths, ProductionVmPortableReplayGuestAssetPaths};
mod checkpoint_store;
use checkpoint_store::load_exact_checkpoint_set;
#[cfg(feature = "test-support")]
pub use checkpoint_store::{
    AuthenticatedProductionCheckpointCodecFixture, AuthenticatedProductionExactRamCodecFixture,
    build_authenticated_production_checkpoint_codec_fixture,
    build_exact_ram_production_checkpoint_codec_fixture,
    build_streaming_production_checkpoint_codec_fixture,
};
pub use checkpoint_store::{
    DecodedProductionExactCheckpoint, PreparedProductionReplayOraclePromotion,
    ProductionBakedSnapshotCatalog, ProductionBakedSnapshotSet, ProductionExactCheckpointClosure,
    ProductionExactCheckpointObject, ProductionExactCheckpointRetirement,
    ProductionExactCheckpointRetirementError, ProductionExactCheckpointRetirementReport,
    ProductionVmExactNodeRestoreAdmissions, decode_authenticated_production_exact_checkpoint,
    open_exact_checkpoint_closure, retire_production_exact_checkpoint_catalog,
};
mod checkpoint_dependencies;
pub use checkpoint_dependencies::{
    collect_signal_artifact_objects, collect_signal_artifact_objects_bounded,
    collect_signal_artifact_objects_with_budget,
};
mod fault_implementation;
pub use fault_implementation::{
    network_effect_implementation_registry, storage_effect_implementation_registry,
};
#[cfg(target_os = "linux")]
mod hot_fork;
#[cfg(target_os = "linux")]
pub use hot_fork::{
    ProductionVmExactHotForkSourceBoundary, ProductionVmHotForkIoNodeBoundary,
    ProductionVmHotForkIoNodeKind, ProductionVmHotForkNodeBoundary,
    ProductionVmHotForkNodeServiceState, ProductionVmHotForkSourceWorld,
    ProductionVmHotForkSourceWorldPreparationFailure, ProductionVmHotForkSourceWorldResourceUsage,
    ProductionVmHotForkWorldContinuation,
};
#[cfg(all(target_os = "linux", any(test, feature = "test-support")))]
pub use hot_fork::{
    hot_fork_adoption_count_for_test, prepared_hot_fork_source_world_for_test,
    prepared_multi_node_hot_fork_source_world_for_scenario_for_test,
    prepared_multi_node_hot_fork_source_world_for_test,
    prepared_multi_node_hot_fork_source_world_with_powered_off_for_scenario_for_test,
    production_permanently_failed_loop_for_test, reset_hot_fork_adoption_count_for_test,
};

/// Default final icount available to one production CLI lifecycle session.
const DEFAULT_RUN_CEILING_ICOUNT: u64 = 16_000_000;
/// Default scheduler quantum budget for one production CLI lifecycle session.
const DEFAULT_QUANTUM_BUDGET: u64 = 4_096;
/// Per-direction shared-memory frame capacity for production VM nodes.
const PRODUCTION_QUEUE_CAPACITY: u32 = 1_024;
/// Maximum number of trigger batches admitted at one scheduler boundary.
const MAX_TRIGGER_SETTLE_BATCHES: usize = 1_024;

// Packaged execution captures baked genesis before its first modeled quantum,
// while the guest catalog is still exactly cold. Both lifecycle and event-log
// state bind that one boundary; configuration can remain genesis later. Any
// partial or later registration would make a fresh plugin repeat guest setup.
fn selectable_catalog_checkpoint_ready(
    configuration: &Configuration,
    initial_lifecycle_observations_pending: bool,
    event_log_events: u64,
    plan: &crucible_protocol::selectable_catalog_plan::SelectableCatalogPlan,
) -> bool {
    use crucible_protocol::selectable_catalog_plan::{
        SelectablePlanContinuation, SelectablePlanPhase,
    };

    match plan.continuation().phase() {
        SelectablePlanPhase::Frozen => true,
        SelectablePlanPhase::Registering => {
            initial_lifecycle_observations_pending
                && event_log_events == 0
                && configuration == &Configuration::genesis(configuration.def.clone())
                && plan.continuation() == &SelectablePlanContinuation::cold()
        }
    }
}

#[cfg(test)]
mod test_support;

/// Immutable artifacts and bounds for local production QEMU execution.
#[derive(Clone)]
pub struct ProductionVmLifecycleConfig {
    executable: PathBuf,
    plugin: PathBuf,
    native_guest_architecture: VmArchitecture,
    guest_assets: BTreeMap<VmArchitecture, ProductionVmGuestAssets>,
    initrd: Option<PathBuf>,
    kernel_cmdline_prefix: Option<String>,
    root_image_format: QemuRootImageFormat,
    run_state_root: PathBuf,
    run_ceiling_icount: u64,
    quantum_budget: u64,
    maximum_host_workers: usize,
    rendezvous_interval_icount: Option<u64>,
    completion_timeout: Duration,
    coverage: QemuLaunchPluginSwitch,
    debug_gateway_executable: Option<PathBuf>,
    debug: Option<ProductionVmDebugConfig>,
    branch: Option<ProductionVmBranchConfig>,
    continuation_branches: Vec<ProductionVmBranchConfig>,
    signal_fault_replay: Option<SignalFaultCampaignReplayPlan>,
    branch_network_choices: Vec<crucible::SelectionDecision>,
    app_random_branch_selections: BTreeMap<ContentHash, crucible::SelectionDecision>,
    app_random_branch_plans:
        BTreeMap<NodeId, crucible_protocol::app_random_branch_plan::AppRandomBranchPlan>,
    signal_artifacts: Option<Arc<dyn DagStore>>,
    fault_replay: Option<ResolvedEffectTrace>,
    world_artifacts: Option<Arc<dyn DagStore>>,
    bounded_scheduler_preemption: Option<BoundedSchedulerPreemptionFlights>,
}

#[derive(Clone)]
struct BoundedSchedulerPreemptionFlights {
    pending: Arc<Mutex<VecDeque<crucible_qemu::BoundedSchedulerPreemptionEvidence>>>,
}

#[derive(Debug, thiserror::Error)]
enum BoundedSchedulerPreemptionFlightError {
    #[error("bounded preemption flight queue was poisoned")]
    QueuePoisoned,
    #[error("bounded preemption flight queue was exhausted")]
    QueueExhausted,
    #[error("claim bounded preemption flight: {0}")]
    Evidence(#[from] crucible_qemu::BoundedSchedulerPreemptionEvidenceError),
}

impl BoundedSchedulerPreemptionFlights {
    fn new(evidence: Vec<crucible_qemu::BoundedSchedulerPreemptionEvidence>) -> Self {
        Self {
            pending: Arc::new(Mutex::new(evidence.into())),
        }
    }

    fn claim_next(
        &self,
    ) -> Result<
        crucible_qemu::BoundedSchedulerPreemptionEvidenceClaim,
        BoundedSchedulerPreemptionFlightError,
    > {
        let evidence = self
            .pending
            .lock()
            .map_err(|_poisoned| BoundedSchedulerPreemptionFlightError::QueuePoisoned)?
            .pop_front()
            .ok_or(BoundedSchedulerPreemptionFlightError::QueueExhausted)?;
        evidence.claim().map_err(Into::into)
    }
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
            .field("maximum_host_workers", &self.maximum_host_workers)
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
            .field(
                "bounded_scheduler_preemption_configured",
                &self.bounded_scheduler_preemption.is_some(),
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
    seed: Option<Seed>,
}

fn production_fault_search_overrides(
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
    configuration: Arc<Configuration>,
    immutable_backing: ContentHash,
    counter: u64,
    scheduler_time: VirtualTime,
    snapshot: ExactSnapshotHandle,
    materialization: ProductionVmExactCheckpointMaterialization,
}

#[derive(Debug)]
enum ProductionVmExactCheckpointMaterialization {
    Native {
        overlay_artifact: ProductionCheckpointArtifact,
        exact_ram: Box<ProductionExactRamCheckpoint>,
        manifest_identity: ContentHash,
    },
    Repository,
}

#[derive(Clone, Debug)]
struct ProductionExactRamPublishedParent {
    closure: ContentHash,
    targets: BTreeMap<NodeId, ProductionExactRamCheckpoint>,
}

impl ProductionVmExactCheckpointTarget {
    fn native_materialization(
        &self,
    ) -> Option<(
        &ProductionCheckpointArtifact,
        &ProductionExactRamCheckpoint,
        ContentHash,
    )> {
        let ProductionVmExactCheckpointMaterialization::Native {
            overlay_artifact,
            exact_ram,
            manifest_identity,
        } = &self.materialization
        else {
            return None;
        };
        Some((overlay_artifact, exact_ram, *manifest_identity))
    }

    fn native_exact_ram(&self) -> Option<&ProductionExactRamCheckpoint> {
        self.native_materialization()
            .map(|(_, exact_ram, _)| exact_ram)
    }

    fn machine_state_artifacts(&self) -> impl Iterator<Item = &ProductionCheckpointArtifact> {
        self.native_materialization()
            .into_iter()
            .flat_map(|(_, exact_ram, _)| {
                std::iter::once(&exact_ram.device_artifact)
                    .chain(exact_ram.layers.iter().map(|layer| &layer.artifact))
            })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ProductionExactRamKind {
    Direct,
    Delta,
}

impl From<QmpCheckpointRamKind> for ProductionExactRamKind {
    fn from(kind: QmpCheckpointRamKind) -> Self {
        match kind {
            QmpCheckpointRamKind::Direct => Self::Direct,
            QmpCheckpointRamKind::Delta => Self::Delta,
        }
    }
}

impl From<ProductionExactRamKind> for QmpCheckpointRamKind {
    fn from(kind: ProductionExactRamKind) -> Self {
        match kind {
            ProductionExactRamKind::Direct => Self::Direct,
            ProductionExactRamKind::Delta => Self::Delta,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ProductionExactCheckpointIdentity {
    checkpoint: ContentHash,
    target: ContentHash,
    frontier: ContentHash,
}

impl From<QmpCheckpointIdentity> for ProductionExactCheckpointIdentity {
    fn from(identity: QmpCheckpointIdentity) -> Self {
        Self {
            checkpoint: identity.checkpoint(),
            target: identity.target(),
            frontier: identity.frontier(),
        }
    }
}

impl From<ProductionExactCheckpointIdentity> for QmpCheckpointIdentity {
    fn from(identity: ProductionExactCheckpointIdentity) -> Self {
        Self::new(identity.checkpoint, identity.target, identity.frontier)
    }
}

#[derive(Clone, Debug)]
pub(super) struct ProductionExactRamLayer {
    kind: ProductionExactRamKind,
    identity: ProductionExactCheckpointIdentity,
    parent: Option<ProductionExactCheckpointIdentity>,
    topology: ContentHash,
    ram_regions: u64,
    ram_records: u64,
    content_sha256: ContentHash,
    artifact: ProductionCheckpointArtifact,
}

impl ProductionExactRamLayer {
    pub(super) fn from_capture(
        capture: &QemuExactCheckpointCaptureResult,
        content_sha256: ContentHash,
        artifact: ProductionCheckpointArtifact,
    ) -> Result<Self, SchedulerError> {
        if artifact.length != capture.ram_bytes() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "exact RAM artifact length differs from QEMU's capture report",
                ),
            });
        }

        Ok(Self {
            kind: capture.ram_kind().into(),
            identity: capture.identity().into(),
            parent: capture.parent().map(Into::into),
            topology: capture.topology(),
            ram_regions: capture.ram_regions(),
            ram_records: capture.ram_records(),
            content_sha256,
            artifact,
        })
    }
}

#[derive(Clone, Debug)]
pub(super) struct ProductionExactRamCheckpoint {
    parent_closure: Option<ContentHash>,
    identity: ProductionExactCheckpointIdentity,
    device_content_sha256: ContentHash,
    device_artifact: ProductionCheckpointArtifact,
    layers: Vec<ProductionExactRamLayer>,
}

impl ProductionExactRamCheckpoint {
    pub(super) fn new(
        parent_closure: Option<ContentHash>,
        device_content_sha256: ContentHash,
        device_artifact: ProductionCheckpointArtifact,
        layers: Vec<ProductionExactRamLayer>,
    ) -> Result<Self, SchedulerError> {
        let identity = layers.last().map(|layer| layer.identity).ok_or_else(|| {
            SchedulerError::BoundaryViolation {
                message: String::from("exact RAM checkpoint has no direct base"),
            }
        })?;
        let checkpoint = Self {
            parent_closure,
            identity,
            device_content_sha256,
            device_artifact,
            layers,
        };
        checkpoint.validate()?;

        Ok(checkpoint)
    }

    pub(super) fn validate(&self) -> Result<(), SchedulerError> {
        if self.layers.is_empty()
            || self.layers.len() > crucible::exact_checkpoint::MAX_EXACT_CHECKPOINT_RAM_LAYERS
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("exact RAM checkpoint has an invalid layer count"),
            });
        }
        let Some(first) = self.layers.first() else {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("exact RAM checkpoint has no direct base"),
            });
        };
        if first.kind != ProductionExactRamKind::Direct || first.parent.is_some() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "exact RAM checkpoint chain does not start with a direct layer",
                ),
            });
        }
        if (self.layers.len() > 1) != self.parent_closure.is_some() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "exact RAM parent-closure provenance differs from the retained chain",
                ),
            });
        }
        let topology = first.topology;
        for pair in self.layers.windows(2) {
            let [parent, child] = pair else {
                continue;
            };
            if child.kind != ProductionExactRamKind::Delta
                || child.parent != Some(parent.identity)
                || child.topology != topology
            {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from("exact RAM checkpoint delta chain is not contiguous"),
                });
            }
        }
        if self.layers.iter().any(|layer| {
            layer.ram_regions == 0 || layer.artifact.length == 0 || layer.artifact.sparse
        }) || self.device_artifact.length == 0
            || self.device_artifact.sparse
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("exact RAM checkpoint contains empty QEMU artifacts"),
            });
        }
        Ok(())
    }

    pub(super) const fn requires_direct_compaction(&self) -> bool {
        self.layers.len() >= crucible::exact_checkpoint::MAX_EXACT_CHECKPOINT_RAM_LAYERS
    }

    /// Builds the retained chain for one admitted direct or delta capture.
    ///
    /// A direct capture rebases the chain and deliberately drops all parent
    /// provenance. A delta capture appends to the authenticated parent chain.
    ///
    /// # Errors
    ///
    /// Returns an error when a delta has no retained parent, allocation fails,
    /// or the resulting direct-then-delta chain is invalid.
    pub(super) fn from_captured_layer(
        parent_closure: Option<ContentHash>,
        parent: Option<Self>,
        capture_kind: ProductionExactRamKind,
        device_content_sha256: ContentHash,
        device_artifact: ProductionCheckpointArtifact,
        layer: ProductionExactRamLayer,
    ) -> Result<Self, SchedulerError> {
        if capture_kind == ProductionExactRamKind::Direct {
            // A direct capture is a complete replacement. The published parent
            // owner remains live until durable publication, but it must not be
            // reachable from the replacement manifest.
            return Self::new(None, device_content_sha256, device_artifact, vec![layer]);
        }

        let mut layers = parent
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from("delta exact checkpoint lost its authenticated parent chain"),
            })?
            .layers;
        layers
            .try_reserve_exact(1)
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!("extend exact RAM checkpoint layers: {error}"),
            })?;
        layers.push(layer);

        Self::new(
            parent_closure,
            device_content_sha256,
            device_artifact,
            layers,
        )
    }
}

#[derive(Clone, Debug)]
pub(super) struct ProductionCheckpointArtifact {
    source: ProductionCheckpointArtifactSource,
    identity: ContentHash,
    length: u64,
    chunks: Vec<ContentHash>,
    sparse: bool,
    extents: Vec<checkpoint_store::ArtifactExtent>,
}

#[derive(Clone, Debug)]
enum ProductionCheckpointArtifactSource {
    #[cfg(any(test, feature = "test-support"))]
    File(PathBuf),
    /// Private capture staging whose bytes have not crossed durable publication.
    ChunkStore(PathBuf),
    /// Shared CAS storage guarded by authenticated inode metadata.
    RetainedChunkStore(Arc<RetainedChunkStoreLease>),
}

#[derive(Debug)]
struct RetainedChunkStoreLease {
    directory: PathBuf,
    objects: BTreeMap<ContentHash, RetainedCheckpointObject>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RetainedCheckpointObject {
    device: u64,
    inode: u64,
    length: u64,
    modified_seconds: i64,
    modified_nanoseconds: i64,
    changed_seconds: i64,
    changed_nanoseconds: i64,
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
    failed_host_io: BTreeMap<NodeId, ProductionFailedNodeState>,
    node_generations: BTreeMap<NodeId, u64>,
    node_service_states: BTreeMap<NodeId, ProductionNodeServiceState>,
    repository_restore: Option<RepositoryExactRestoreAuthority>,
}

struct RepositoryExactRestoreAuthority {
    targets: crucible::exact_checkpoint::ExactCheckpointTraversedClosureBinding,
    configuration: Arc<Configuration>,
    scheduler: Arc<SingleSchedulerCheckpoint>,
    open: Arc<dyn Fn(ContentHash) -> std::io::Result<Box<dyn std::io::Read + Send>> + Send + Sync>,
}

impl std::fmt::Debug for RepositoryExactRestoreAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RepositoryExactRestoreAuthority")
            .field("targets", &self.targets)
            .finish_non_exhaustive()
    }
}

impl RepositoryExactRestoreAuthority {
    fn take_node_admission(
        &mut self,
        node: &NodeId,
        snapshot: ExactSnapshotHandle,
        paused: bool,
    ) -> Result<ProductionVmExactNodeRestoreAdmission, LifecycleApiError> {
        let target = self.targets.take_target(node).map_err(|error| {
            loop_factory_error(format!("claim authenticated exact target: {error}"))
        })?;
        Ok(ProductionVmExactNodeRestoreAdmission {
            basis: ProductionVmExactNodeRestoreBasis {
                target,
                node: node.clone(),
                configuration: Arc::clone(&self.configuration),
                scheduler: Arc::clone(&self.scheduler),
                snapshot,
                paused,
                open: Arc::clone(&self.open),
            },
        })
    }

    fn take_replay_node_admission(
        &mut self,
        node: &NodeId,
        snapshot: ExactSnapshotHandle,
        paused: bool,
    ) -> Result<ProductionVmReplayExactNodeRestoreAdmission, LifecycleApiError> {
        let target = self.targets.take_target(node).map_err(|error| {
            loop_factory_error(format!("claim authenticated exact replay target: {error}"))
        })?;
        Ok(ProductionVmReplayExactNodeRestoreAdmission {
            basis: ProductionVmExactNodeRestoreBasis {
                target,
                node: node.clone(),
                configuration: Arc::clone(&self.configuration),
                scheduler: Arc::clone(&self.scheduler),
                snapshot,
                paused,
                open: Arc::clone(&self.open),
            },
        })
    }
}

/// Process-free authority retained after a node commits permanent failure.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ProductionFailedNodeState {
    host_io: QemuHostIoCheckpoint,
    fingerprint: FingerprintSample,
}

impl ProductionFailedNodeState {
    fn new(
        node: &NodeId,
        host_io: QemuHostIoCheckpoint,
        fingerprint: FingerprintSample,
    ) -> Result<Self, SchedulerError> {
        if fingerprint.node != *node {
            return Err(SchedulerError::BoundaryViolation {
                message: format!(
                    "failed-node fingerprint for `{}` names `{}`",
                    node.name, fingerprint.node.name
                ),
            });
        }

        Ok(Self {
            host_io,
            fingerprint,
        })
    }
}

struct ProductionVmHotForkRestore {
    expected_times: BTreeMap<NodeId, VirtualTime>,
    adoptions: BTreeMap<NodeId, ProductionVmHotForkNodeAdoption>,
    immutable_root_images: BTreeMap<NodeId, ContentHash>,
    block_bindings: BTreeMap<NodeId, storage_faults::ProductionBlockBinding>,
    ninep_bindings: BTreeMap<NodeId, storage_faults::ProductionNinepBinding>,
    active_host_io: BTreeMap<NodeId, QemuHostIoCheckpoint>,
}

struct ProductionVmHotForkRestoreParts {
    config: ProductionVmLifecycleConfig,
    checkpoint: ProductionVmExactCheckpointSet,
    immutable_root_images: BTreeMap<NodeId, ContentHash>,
    block_bindings: BTreeMap<NodeId, storage_faults::ProductionBlockBinding>,
    ninep_bindings: BTreeMap<NodeId, storage_faults::ProductionNinepBinding>,
    active_host_io: BTreeMap<NodeId, QemuHostIoCheckpoint>,
}

struct HotForkAdoptionInventory {
    expected_times: BTreeMap<NodeId, VirtualTime>,
    node_generations: BTreeMap<NodeId, u64>,
}

fn validate_failed_host_io_topology(
    source: &ScenarioDefForm,
    service_states: &BTreeMap<NodeId, ProductionNodeServiceState>,
    failed_host_io: &BTreeMap<NodeId, ProductionFailedNodeState>,
) -> Result<(), LifecycleApiError> {
    let expected_failed = service_states
        .iter()
        .filter_map(|(node, state)| {
            (*state == ProductionNodeServiceState::PermanentlyFailed).then_some(node)
        })
        .collect::<BTreeSet<_>>();
    if failed_host_io.keys().collect::<BTreeSet<_>>() != expected_failed {
        return Err(loop_factory_error(
            "failed-node host-I/O owner partition is incomplete",
        ));
    }

    for (owner, failed) in failed_host_io {
        if failed.fingerprint.node != *owner {
            return Err(loop_factory_error(format!(
                "failed-node fingerprint for `{}` names `{}`",
                owner.name, failed.fingerprint.node.name
            )));
        }
        let checkpoint = &failed.host_io;
        let block_node = source.world().io_nodes().find(|node| {
            node.owner == *owner && matches!(node.kind, WorldIoNodeKind::Block { .. })
        });
        let ninep_node = source.world().io_nodes().find(|node| {
            node.owner == *owner && matches!(node.kind, WorldIoNodeKind::NineP { .. })
        });
        if checkpoint.block().is_some() != block_node.is_some()
            || checkpoint.ninep().is_some() != ninep_node.is_some()
        {
            return Err(loop_factory_error(format!(
                "failed-node host-I/O topology differs for `{}`",
                owner.name
            )));
        }
        if let (Some(block), Some(node)) = (checkpoint.block(), block_node) {
            let WorldIoNodeKind::Block {
                base_image,
                base_length,
                ..
            } = &node.kind
            else {
                return Err(loop_factory_error("failed block node changed kind"));
            };
            if block.base_image() != base_image.hash() || block.device_length() != *base_length {
                return Err(loop_factory_error(format!(
                    "failed block continuation differs for `{}`",
                    node.id.name
                )));
            }
        }
        if let (Some(ninep), Some(node)) = (checkpoint.ninep(), ninep_node) {
            let WorldIoNodeKind::NineP { tree, .. } = &node.kind else {
                return Err(loop_factory_error("failed 9p node changed kind"));
            };
            if ninep.tree() != tree.hash() {
                return Err(loop_factory_error(format!(
                    "failed 9p continuation differs for `{}`",
                    node.id.name
                )));
            }
        }
    }
    Ok(())
}

fn validate_exact_checkpoint_artifact(
    artifact: &ProductionCheckpointArtifact,
    role: &str,
) -> Result<(), LifecycleApiError> {
    let observed = match &artifact.source {
        #[cfg(any(test, feature = "test-support"))]
        ProductionCheckpointArtifactSource::File(path) => hash_file(path).map_err(|error| {
            loop_factory_error(format!(
                "read exact checkpoint {role} artifact {}: {error}",
                path.display()
            ))
        })?,
        ProductionCheckpointArtifactSource::ChunkStore(directory) => {
            checkpoint_store::validate_chunked_artifact(directory, artifact)?
        }
        ProductionCheckpointArtifactSource::RetainedChunkStore(lease) => {
            let _ = lease;
            checkpoint_store::validate_retained_chunked_artifact_with_boundary(
                artifact,
                &mut || Ok(()),
            )?
        }
    };
    if observed != artifact.identity {
        return Err(loop_factory_error(format!(
            "exact checkpoint {role} artifact failed content authentication"
        )));
    }
    Ok(())
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

fn restored_node_paused(state: ProductionNodeServiceState) -> Result<bool, LifecycleApiError> {
    match state {
        ProductionNodeServiceState::Running => Ok(false),
        ProductionNodeServiceState::PoweredOff => Ok(true),
        ProductionNodeServiceState::PermanentlyFailed => Err(loop_factory_error(
            "permanently failed node cannot carry an exact restore target",
        )),
    }
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

    #[cfg(any(test, feature = "test-support"))]
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
    inner: BackendQuantumLoop<SingleScheduler, QemuNodeSet, ProductionFaultNetworkInterceptor>,
    trigger_graph: EventGraph,
    trigger_state: EventGraphState,
    trigger_world: World,
    assertion_evaluator: HostAssertionEvaluator,
    assertion_oracle: BlackBoxHostOracle,
    terminal_verdict: Option<QuantumTerminalVerdict>,
    checkpoint_terminal_cause: Option<CheckpointTerminalCause>,
    initial_lifecycle_observations_pending: bool,
    branch: Option<ProductionVmBranchConfig>,
    continuation_branches: VecDeque<ProductionVmBranchConfig>,
    signal_fault_branches: VecDeque<crucible::SignalFaultCampaignBranch>,
    promote_signal_fault_campaign_choices: bool,
    launch_configs: BTreeMap<NodeId, QemuLiveNodeStepGateConfig>,
    block_bindings: BTreeMap<NodeId, storage_faults::ProductionBlockBinding>,
    ninep_bindings: BTreeMap<NodeId, storage_faults::ProductionNinepBinding>,
    block_devices: storage_faults::ProductionBlockDevices,
    failed_host_io: BTreeMap<NodeId, ProductionFailedNodeState>,
    storage_fault_observations: storage_faults::ProductionStorageObservations,
    fault_runtime: Arc<std::sync::Mutex<ProductionFaultRuntime>>,
    fault_replay_installed: bool,
    fault_search_overrides_installed: bool,
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
    exact_ram_parents: BTreeMap<ContentHash, ProductionExactRamPublishedParent>,
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
    retained_resource_owners: Vec<Box<dyn Send>>,
}

/// Exact scheduler/evidence boundary exposed after production checkpoint restore.
#[derive(Clone, Debug)]
pub struct ProductionVmLifecycleResumeState {
    configuration: Configuration,
    event_log: Vec<SchedulerEventLogEntry>,
    event_log_base_events: u64,
    scheduler_quanta: u64,
    scheduler_frontier: VirtualTime,
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
        configuration: Configuration,
        event_log: Vec<SchedulerEventLogEntry>,
        event_log_base_events: u64,
        scheduler_quanta: u64,
        scheduler_frontier: VirtualTime,
        scheduler_quiescence: SchedulerQuiescence,
        terminal_verdict: Option<QuantumTerminalVerdict>,
    ) -> Self {
        Self {
            configuration,
            event_log,
            event_log_base_events,
            scheduler_quanta,
            scheduler_frontier,
            scheduler_quiescence,
            terminal_verdict,
        }
    }

    /// Returns the absolute scheduler-quantum coordinate at the restored boundary.
    #[must_use]
    pub const fn scheduler_quanta(&self) -> u64 {
        self.scheduler_quanta
    }

    /// Returns the absolute virtual-time coordinate at the restored boundary.
    #[must_use]
    pub const fn scheduler_frontier(&self) -> VirtualTime {
        self.scheduler_frontier
    }

    /// Consumes the state into its exact retained evidence and stop boundary.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        Configuration,
        Vec<SchedulerEventLogEntry>,
        u64,
        u64,
        VirtualTime,
        SchedulerQuiescence,
        Option<QuantumTerminalVerdict>,
    ) {
        (
            self.configuration,
            self.event_log,
            self.event_log_base_events,
            self.scheduler_quanta,
            self.scheduler_frontier,
            self.scheduler_quiescence,
            self.terminal_verdict,
        )
    }
}

/// One-shot exact-node restore admitted by complete API semantic validation.
#[must_use = "an authenticated node restore must be consumed by the guarded launcher"]
pub struct ProductionVmExactNodeRestoreAdmission {
    basis: ProductionVmExactNodeRestoreBasis,
}

struct ProductionVmExactNodeRestoreBasis {
    target: crucible::exact_checkpoint::ExactCheckpointStructuralTargetClaim,
    node: NodeId,
    configuration: Arc<Configuration>,
    scheduler: Arc<SingleSchedulerCheckpoint>,
    snapshot: ExactSnapshotHandle,
    paused: bool,
    open: Arc<dyn Fn(ContentHash) -> std::io::Result<Box<dyn std::io::Read + Send>> + Send + Sync>,
}

impl std::fmt::Debug for ProductionVmExactNodeRestoreAdmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductionVmExactNodeRestoreAdmission")
            .field("target", &self.basis.target)
            .field("snapshot", &self.basis.snapshot)
            .field("paused", &self.basis.paused)
            .finish_non_exhaustive()
    }
}

/// One-shot exact-node restore admitted only for replay validation.
#[must_use = "an authenticated replay restore must be consumed by the replay coordinator"]
pub struct ProductionVmReplayExactNodeRestoreAdmission {
    basis: ProductionVmExactNodeRestoreBasis,
}

impl std::fmt::Debug for ProductionVmReplayExactNodeRestoreAdmission {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProductionVmReplayExactNodeRestoreAdmission")
            .field("target", &self.basis.target)
            .field("snapshot", &self.basis.snapshot)
            .finish_non_exhaustive()
    }
}

/// Atomic exact restore whose final run state comes from authenticated lifecycle state.
#[must_use = "an authenticated exact restore must be launched or discarded"]
pub struct ProductionVmAtomicExactRestore {
    request: crucible_qemu::QemuProductionExactRestoreRequest,
    paused: bool,
}

impl ProductionVmAtomicExactRestore {
    /// Materializes and restores the exact node at its persisted service disposition.
    ///
    /// # Errors
    ///
    /// Returns [`crucible_qemu::QemuLiveNodeStepGateError`] when authenticated
    /// materialization, QEMU restore, or the persisted running transition fails.
    pub fn launch(
        self,
    ) -> Result<(QemuNode, QemuPreparedRunDirectory), crucible_qemu::QemuLiveNodeStepGateError>
    {
        let launched = self.request.launch()?;
        if self.paused {
            Ok(launched.into_node_and_run_directory())
        } else {
            launched.into_running_node_and_run_directory()
        }
    }
}

impl ProductionVmExactNodeRestoreAdmission {
    /// Authenticates the concrete node continuation and launches its atomic restore.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when the structural target differs from
    /// the decoded continuation, an authenticated object cannot be opened, or
    /// QEMU rejects materialization, sealing, restore, or disposition.
    pub fn into_atomic_restore(
        self,
        request: ProductionVmNodeLaunchRequest<'_>,
        run_directory: QemuPreparedRunDirectory,
        process_contract: &crucible_qemu::QemuChildProcessContract,
    ) -> Result<ProductionVmAtomicExactRestore, LifecycleApiError> {
        let paused = self.basis.paused;
        let launch = request
            .launch()
            .clone()
            .with_run_directory(run_directory.path());
        let request = admit_atomic_exact_restore(
            self.basis,
            launch,
            run_directory,
            process_contract,
            request.node().clone(),
            request.router_name(),
            request.crash_detector(),
        )?;
        Ok(ProductionVmAtomicExactRestore { request, paused })
    }
}

impl ProductionVmReplayExactNodeRestoreAdmission {
    /// Returns the authenticated World node identity used to select baked genesis.
    #[must_use]
    pub fn node(&self) -> &NodeId {
        &self.basis.node
    }

    /// Returns the authenticated modeled snapshot used by replay comparison.
    #[must_use]
    pub const fn snapshot(&self) -> &ExactSnapshotHandle {
        &self.basis.snapshot
    }

    /// Returns the authenticated modeled configuration identity.
    #[must_use]
    pub fn configuration_id(&self) -> ContentHash {
        self.basis.configuration.id()
    }

    /// Converts the admitted repository claim into a process-free replay match for tests.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn into_replay_oracle_match_for_test(
        self,
        runtime_hash: ContentHash,
    ) -> QemuReplayOracleMatch {
        let node = self.basis.node;
        let source = self.basis.target.into_verified_node_for_test();
        QemuReplayOracleMatch::from_authenticated_source_for_test(node, source, runtime_hash)
    }

    /// Consumes this admission into one replay-owned atomic exact restore.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when structural execution authentication
    /// or atomic QEMU restore admission fails.
    pub fn into_replay_admission(
        self,
        launch: QemuLiveNodeStepGateConfig,
        run_directory: QemuPreparedRunDirectory,
        process_contract: &crucible_qemu::QemuChildProcessContract,
        crash_detector: impl Into<String>,
    ) -> Result<crucible_qemu::QemuReplayValidationExactAdmission, LifecycleApiError> {
        let node = self.basis.node.clone();
        let snapshot = self.basis.snapshot.clone();
        let request = admit_atomic_exact_restore(
            self.basis,
            launch.clone(),
            run_directory,
            process_contract,
            node.clone(),
            "crucible-router",
            crash_detector,
        )?;
        crucible_qemu::QemuReplayValidationExactAdmission::admit_atomic(
            launch, request, &snapshot, node,
        )
        .map_err(|error| loop_factory_error(format!("admit exact replay executor: {error}")))
    }
}

fn admit_atomic_exact_restore(
    admission: ProductionVmExactNodeRestoreBasis,
    launch: QemuLiveNodeStepGateConfig,
    run_directory: QemuPreparedRunDirectory,
    process_contract: &crucible_qemu::QemuChildProcessContract,
    node: impl Into<NodeId>,
    router: impl Into<String>,
    crash_detector: impl Into<String>,
) -> Result<crucible_qemu::QemuProductionExactRestoreRequest, LifecycleApiError> {
    let snapshot = admission.snapshot;
    let (target, streams) = admission
        .target
        .authenticate_execution_and_open_streams(
            &admission.configuration,
            snapshot.checkpoint(),
            &admission.scheduler,
            move |identity| (admission.open)(identity),
        )
        .map_err(|error| loop_factory_error(format!("authenticate exact node: {error}")))?;
    crucible_qemu::QemuProductionExactRestoreRequest::new(
        crucible_qemu::QemuProductionExactRestoreProfile {
            config: launch,
            run_directory,
            snapshot,
            node: node.into(),
            router: router.into(),
            crash_detector: crash_detector.into(),
        },
        process_contract,
        target,
        streams,
    )
    .map_err(|error| loop_factory_error(format!("admit atomic exact restore: {error}")))
}

/// Process materialization requested by the authoritative production lifecycle.
#[derive(Debug)]
pub(crate) enum ProductionVmNodeLaunchKind {
    /// Starts one freshly provisioned node at its baked ready boundary.
    Fresh,
    /// Restores one authenticated exact snapshot.
    Exact(Box<ProductionVmExactNodeRestoreAdmission>),
}

/// Filesystem preparation requested for one production node generation.
#[derive(Clone, Copy, Debug)]
pub(crate) enum ProductionVmNodePreparationKind<'a> {
    /// Creates a fresh writable root overlay from one immutable root image.
    Fresh {
        /// QEMU executable whose adjacent `qemu-img` owns the image format.
        qemu_executable: &'a Path,
        /// Immutable root image used only as the overlay size and backing basis.
        root_image: &'a Path,
    },
    /// Uses the repository-authenticated state retained by the launcher.
    Exact,
}

#[derive(Clone, Copy, Debug)]
struct ProductionVmNodeLaunchBasis<'a> {
    launch: &'a QemuLiveNodeStepGateConfig,
    run_directory: &'a Path,
    node: &'a NodeId,
    generation: u64,
}

impl<'a> ProductionVmNodeLaunchBasis<'a> {
    const fn new(
        launch: &'a QemuLiveNodeStepGateConfig,
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
    launch: &'a QemuLiveNodeStepGateConfig,
    run_directory: &'a Path,
    node: &'a NodeId,
    generation: u64,
    router_name: &'a str,
    crash_detector: &'a str,
}

impl<'a> ProductionVmNodeLaunchRequest<'a> {
    const fn new(
        basis: ProductionVmNodeLaunchBasis<'a>,
        router_name: &'a str,
        crash_detector: &'a str,
    ) -> Self {
        Self {
            launch: basis.launch,
            run_directory: basis.run_directory,
            node: basis.node,
            generation: basis.generation,
            router_name,
            crash_detector,
        }
    }

    /// Returns the validated production launch profile.
    #[must_use]
    pub const fn launch(&self) -> &QemuLiveNodeStepGateConfig {
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

    /// Opens the exact pinned root overlay for a stopped checkpoint capture.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] if the generation cannot prove that the
    /// named overlay still matches its retained file authority.
    fn open_checkpoint_root_overlay(&self) -> Result<std::fs::File, LifecycleApiError>;

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
    launch: QemuLiveNodeStepGateConfig,
}

impl ProductionVmNodeReplayLaunchProfile {
    /// Binds one immutable launch profile to its exact World node.
    #[must_use]
    pub fn new(node: NodeId, launch: QemuLiveNodeStepGateConfig) -> Self {
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
    ) -> QemuLiveNodeStepGateConfig {
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

    /// Launches one freshly provisioned node generation.
    ///
    /// Before spawning any process, the implementation creates the generation
    /// run directory and performs the operation-specific artifact preparation
    /// under the same aggregate storage, cancellation, and cleanup authority.
    /// Success returns the node and a linear containment lease whose identity
    /// exactly matches the request. The lifecycle retains that lease until the
    /// corresponding child has been reaped.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when admission, namespace or artifact
    /// preparation, process launch, or post-launch authentication fails. The
    /// implementation must retain or clean every
    /// partial artifact and retain or reap every process it may have spawned
    /// before returning.
    fn launch_fresh(
        &mut self,
        request: ProductionVmNodeLaunchRequest<'_>,
        qemu_executable: &Path,
        root_image: &Path,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError>;

    /// Launches one descriptor-backed exact node generation.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] when exact artifact materialization,
    /// process launch, restore, or post-launch authentication fails.
    fn launch_restored(
        &mut self,
        request: ProductionVmNodeLaunchRequest<'_>,
        admission: ProductionVmExactNodeRestoreAdmission,
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

#[cfg(any(test, feature = "test-support"))]
#[derive(Clone, Copy, Debug, Default)]
struct PackagedProductionVmNodeLauncher;

#[cfg(any(test, feature = "test-support"))]
impl ProductionVmNodeLauncher for PackagedProductionVmNodeLauncher {
    fn begin_execution_quantum(&mut self) -> Result<(), LifecycleApiError> {
        Ok(())
    }

    fn check_operational_boundary(&mut self) -> Result<(), LifecycleApiError> {
        Ok(())
    }

    fn launch_fresh(
        &mut self,
        _request: ProductionVmNodeLaunchRequest<'_>,
        _qemu_executable: &Path,
        _root_image: &Path,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        Err(loop_factory_error(
            "test lifecycle has no production process authority",
        ))
    }

    fn launch_restored(
        &mut self,
        _request: ProductionVmNodeLaunchRequest<'_>,
        _admission: ProductionVmExactNodeRestoreAdmission,
    ) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
        Err(loop_factory_error(
            "test lifecycle has no production process authority",
        ))
    }

    fn replay_candidate(&self) -> Result<Box<dyn ProductionVmNodeLauncher>, LifecycleApiError> {
        Err(loop_factory_error(
            "test lifecycle has no production replay authority",
        ))
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
    kind: ProductionVmNodeLaunchKind,
) -> Result<ProductionVmNodeLaunch, LifecycleApiError> {
    ProductionVmNodeGeneration::new(basis.node.clone(), basis.generation)?;
    let request = ProductionVmNodeLaunchRequest::new(basis, "crucible-router", crash_detector);
    match (preparation, kind) {
        (
            ProductionVmNodePreparationKind::Fresh {
                qemu_executable,
                root_image,
            },
            ProductionVmNodeLaunchKind::Fresh,
        ) => launcher.launch_fresh(request, qemu_executable, root_image),
        (ProductionVmNodePreparationKind::Exact, ProductionVmNodeLaunchKind::Exact(admission)) => {
            launcher.launch_restored(request, *admission)
        }
        _ => Err(loop_factory_error(
            "production QEMU node preparation does not match its launch operation",
        )),
    }
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
mod construction;
use construction::build_production_vm_lifecycle_loop_with_restore;
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

/// Builds one exact-resume lifecycle from an authenticated repository admission.
///
/// # Errors
///
/// Returns [`LifecycleApiError`] when launcher construction or restored
/// lifecycle validation fails.
pub fn build_production_vm_exact_resume_lifecycle<L>(
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    config: &ProductionVmLifecycleConfig,
    decoded: DecodedProductionExactCheckpoint,
    launcher: L,
) -> Result<ProductionVmLifecycleLoop, LifecycleApiError>
where
    L: ProductionVmNodeLauncher + 'static,
{
    if source.scenario_def() != *scenario {
        return Err(loop_factory_error(
            "repository checkpoint source does not reconstruct the requested scenario",
        ));
    }
    build_production_vm_lifecycle_loop_with_restore(
        scenario,
        source,
        config,
        Some(decoded.into_checkpoint()),
        Box::new(launcher),
        None,
    )
}

/// Authenticates the exact scheduler and device boundary used by hot-fork capture.
///
/// The native closure is loaded and validated independently of the lifecycle
/// that will restore it. The returned opaque value can then verify that source
/// preparation preserved the closure's scheduler, evidence, fault, node, and
/// host-I/O continuation.
///
/// # Errors
///
/// Returns [`LifecycleApiError::LoopFactory`] when the closure is unavailable,
/// corrupt, belongs to another scenario, or cannot produce a complete source
/// boundary.
#[cfg(target_os = "linux")]
pub fn authenticate_production_vm_exact_hot_fork_source_boundary(
    run_state_root: &Path,
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    closure: ContentHash,
) -> Result<ProductionVmExactHotForkSourceBoundary, LifecycleApiError> {
    let checkpoint = load_exact_checkpoint_set(run_state_root, scenario, source, closure)?;
    ProductionVmExactHotForkSourceBoundary::from_exact_checkpoint(&checkpoint)
        .map_err(|error| loop_factory_error(format!("authenticate hot-fork boundary: {error}")))
}

/// Adopts one completely assembled hot-fork child World as a lifecycle.
///
/// This boundary accepts no partial node set. Every running or powered-off
/// node in the opaque host continuation must have exactly one authenticated
/// child and linear containment lease. Permanently failed nodes have none.
/// A powered-off child retains its paused process for a later modeled Boot.
/// The complete semantic and child inventories are validated before
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
    continuation
        .validate_world_io(source.world())
        .map_err(|error| loop_factory_error(format!("validate hot-fork World I/O: {error}")))?;

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
        active_host_io,
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
            active_host_io,
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
            ProductionVmHotForkNodeServiceState::Running
            | ProductionVmHotForkNodeServiceState::PoweredOff => {
                let generation = adoption_generations
                    .get(boundary.node())
                    .copied()
                    .ok_or_else(|| {
                        loop_factory_error(format!(
                            "hot-fork World has no adopted child for retained node `{}`",
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
                    loop_factory_error("retained hot-fork node lost its physical boundary")
                })?;
                expected_times.insert(boundary.node().clone(), physical_time);
                node_generations.insert(boundary.node().clone(), generation);
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
    let expected_retained = expected_times.keys().cloned().collect::<BTreeSet<_>>();
    if adoption_generations
        .keys()
        .cloned()
        .collect::<BTreeSet<_>>()
        != expected_retained
    {
        return Err(loop_factory_error(
            "hot-fork adopted child set differs from the retained-node set",
        ));
    }
    Ok(HotForkAdoptionInventory {
        expected_times,
        node_generations,
    })
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

fn validate_app_random_branch_replay_config(
    nodes: crucible::WorldVmNodes<'_>,
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
