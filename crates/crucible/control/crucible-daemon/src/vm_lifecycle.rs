//! Production local-VM lifecycle loop construction.
//!
//! This module composes a submitted [`ScenarioDefForm`] into the authoritative
//! [`SingleScheduler`], one live QEMU node per World VM, and the node-addressed
//! backend loop consumed by [`LifecycleControlPlane`](crucible_control_server::LifecycleControlPlane).

mod fault_evidence;
pub use fault_evidence::{
    ProductionBlockFaultEvidence, ProductionFaultEvidenceSnapshot, ProductionNetworkOutageEvidence,
    ProductionNetworkQueueEvidence, ProductionNodeFaultEvidence,
};

mod node_launcher;
#[cfg(any(test, feature = "test-support"))]
use node_launcher::PackagedProductionVmNodeLauncher;
pub use node_launcher::ProductionVmNodeLauncher;
use node_launcher::launch_production_node_generation;

use crucible_control_api::LifecycleApiError;
use crucible_control_server::debug_gateway::DebugGatewayProcess;
use crucible_engine::model::{
    FaultCoordinate, FaultResourceLimits, HostFaultAdapterManifests,
    OwnedDagSignalArtifactProvider, ResolvedEffectTrace, SignalArtifactProvider,
    SignalBoundarySnapshot,
};
use crucible_engine::{
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
    SearchFrontierChoices, Seed, SelectionDecision, SignalFaultCampaignReplayPlan, SimDuration,
    SimInstant, SimulationBackend, SingleScheduler, SingleSchedulerCheckpoint, VirtualTime,
    VmArchitecture, World, WorldIoNodeKind,
};
pub use crucible_qemu_host::{
    BoundedSchedulerPreemptionEvidence, BoundedSchedulerPreemptionEvidenceSnapshot,
};
use crucible_qemu_host::{
    DEFAULT_ROOT_OVERLAY_FILE_NAME, LivePluginGuestArchitecture, QemuGdbstubChannelConfig,
    QemuLaunchAppRandomConfig, QemuLaunchPluginSwitch, QemuLiveNodeStepGateConfig, QemuNodeSet,
    QemuRootImageFormat,
};
use crucible_qemu_host::{
    ProductionFaultRuntime, ProductionFaultRuntimeCheckpoint, ProductionNetworkStateCheckpoint,
    QemuHostIoCheckpoint, QemuLaunchResourceRequirements, QemuNode, QemuNodeLifecycleDecision,
    QemuNodeLifecycleIntent as LifecycleMutationIntent, QemuPreparedRunDirectory,
    QemuProcessIdentity, QemuReplayOracleMatch, QemuSharedBlockDevice,
    QemuVmSnapshot as ExactSnapshotHandle, QmpCheckpointIdentity, linux_process_identity,
    quarantine_orphaned_qemu_process,
};
#[cfg(target_os = "linux")]
use crucible_qemu_host::{
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
    ProductionVmGuestAssets, production_kernel_cmdline_prefix, selected_initrd_for_vm,
    validate_guest_asset_references,
};
pub use assets::{ProductionVmPortableReplayAssetPaths, ProductionVmPortableReplayGuestAssetPaths};
mod checkpoint_store;
use checkpoint_store::load_exact_checkpoint_set;
#[cfg(any(test, feature = "test-support"))]
pub use checkpoint_store::{
    AuthenticatedProductionCheckpointCodecFixture, AuthenticatedProductionExactRamCodecFixture,
    build_authenticated_production_checkpoint_codec_fixture,
    build_exact_ram_production_checkpoint_codec_fixture,
    build_streaming_production_checkpoint_codec_fixture,
};
pub use checkpoint_store::{
    DecodedProductionExactCheckpoint, OriginalCheckpointDecodeError,
    OriginalDecodedProductionExactCheckpoint, PreparedProductionReplayOraclePromotion,
    ProductionBakedSnapshotCatalog, ProductionBakedSnapshotSet, ProductionExactCheckpointClosure,
    ProductionExactCheckpointObject, ProductionExactCheckpointReadSources,
    ProductionExactCheckpointRetirement, ProductionExactCheckpointRetirementError,
    ProductionExactCheckpointRetirementReport, ProductionPagedRamSource,
    ProductionVmExactNodeRestoreAdmissions, decode_authenticated_production_exact_checkpoint,
    decode_authenticated_production_exact_checkpoint_under_original, open_exact_checkpoint_closure,
    retire_production_exact_checkpoint_catalog,
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
pub(crate) use hot_fork::TargetSourceBackends;
#[cfg(target_os = "linux")]
pub(crate) use hot_fork::{
    HotForkSourcePreparationError, MainSharedSource, PreparedSharedSource,
    SourcePreparationBoundary, SourceWorldPreparation,
};
#[cfg(target_os = "linux")]
pub use hot_fork::{
    ProductionHotForkCleanupObserver, ProductionVmExactHotForkSourceBoundary,
    ProductionVmHotForkContinuationUnavailable, ProductionVmHotForkIoNodeBoundary,
    ProductionVmHotForkIoNodeKind, ProductionVmHotForkNodeBoundary,
    ProductionVmHotForkNodeServiceState, ProductionVmHotForkSourceWorld,
    ProductionVmHotForkSourceWorldPreparationFailure, ProductionVmHotForkSourceWorldResourceUsage,
    ProductionVmHotForkWorldContinuation,
};
#[cfg(target_os = "linux")]
pub use hot_fork::{
    ProductionVmHotForkSourcePreparationError, ProductionVmHotForkSourcePreparationHistory,
};
#[cfg(all(target_os = "linux", any(test, feature = "test-support")))]
pub use hot_fork::{
    hot_fork_adoption_count_for_test, prepared_hot_fork_source_world_for_test,
    prepared_multi_node_hot_fork_source_world_for_scenario_for_test,
    prepared_multi_node_hot_fork_source_world_for_test,
    prepared_multi_node_hot_fork_source_world_with_powered_off_for_scenario_for_test,
    prepared_multi_node_hot_fork_source_world_with_time_limit_for_scenario_for_test,
    production_permanently_failed_loop_for_test, reset_hot_fork_adoption_count_for_test,
};
#[cfg(all(target_os = "linux", test))]
pub(crate) use hot_fork::{
    take_unissued_component_source, unissued_component_source, with_unique_component_source,
};

/// Default final logical tick available to one production lifecycle session.
const DEFAULT_RUN_CEILING_TICKS: u64 = 16_000_000;
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
    plan: &crucible_qemu_protocol::selectable_catalog_plan::SelectableCatalogPlan,
) -> bool {
    use crucible_qemu_protocol::selectable_catalog_plan::{
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

#[cfg(any(test, feature = "test-support"))]
mod block_completion_observation;
#[cfg(any(test, feature = "test-support"))]
pub use crucible_qemu_host::QemuTestBlockCompletionObserver as ProductionBlockCompletionObserver;
#[cfg(any(test, feature = "test-support"))]
mod ram_source_observation;
#[cfg(any(test, feature = "test-support"))]
pub use ram_source_observation::ProductionRamSourceDecorator;

/// Immutable artifacts and bounds for local production QEMU execution.
pub struct ProductionVmLifecycleConfig {
    host_ram_registration_factory: Option<Arc<dyn ProductionHostRamRegistrationFactory>>,
    ram_catalog_provider: Option<Arc<dyn ProductionRamCatalogProvider>>,
    #[cfg(any(test, feature = "test-support"))]
    ram_source_decorator: Option<Arc<dyn ProductionRamSourceDecorator>>,
    #[cfg(any(test, feature = "test-support"))]
    block_completion_observer: Option<Arc<dyn crucible_qemu_host::QemuTestBlockCompletionObserver>>,
    #[cfg(any(test, feature = "test-support"))]
    fault_actor_test_entitlement: Option<[u8; 32]>,
    executable: PathBuf,
    plugin: PathBuf,
    native_guest_architecture: VmArchitecture,
    guest_assets: BTreeMap<VmArchitecture, ProductionVmGuestAssets>,
    initrd: Option<PathBuf>,
    kernel_cmdline_prefix: Option<String>,
    root_image_format: QemuRootImageFormat,
    run_state_root: PathBuf,
    run_ceiling_ticks: u64,
    quantum_budget: u64,
    maximum_host_workers: usize,
    rendezvous_interval_ticks: Option<u64>,
    completion_timeout: Duration,
    host_operation_supervisor:
        Option<crucible_host_resources::host_supervision::HostOperationSupervisor>,
    unbounded_advance_completion: bool,
    coverage: QemuLaunchPluginSwitch,
    rr_control_boundary_trace: bool,
    debug_gateway_executable: Option<PathBuf>,
    debug: Option<ProductionVmDebugConfig>,
    branch: Option<ProductionVmBranchConfig>,
    continuation_branches: Vec<ProductionVmBranchConfig>,
    signal_fault_replay: Option<SignalFaultCampaignReplayPlan>,
    branch_network_choices: Vec<crucible_engine::SelectionDecision>,
    app_random_branch_selections: BTreeMap<ContentHash, crucible_engine::SelectionDecision>,
    app_random_branch_plans:
        BTreeMap<NodeId, crucible_qemu_protocol::app_random_branch_plan::AppRandomBranchPlan>,
    signal_artifacts: Option<Arc<dyn DagStore>>,
    fault_replay: Option<ResolvedEffectTrace>,
    world_artifacts: Option<Arc<dyn DagStore>>,
    bounded_scheduler_preemption: Option<BoundedSchedulerPreemptionFlights>,
    // Owning configuration members are destroyed before their original credits.
    decode_custody: Option<crucible_engine::owned_decode::DecodeCustody>,
}

/// Shared storage and descriptor custody for one durable native RAM catalog.
///
/// The provider returns clones of one cached tuple per catalog directory. This
/// keeps SQLite's retained descriptor lifetime and the shared deletion fence
/// inside the same service reservation, including between captures.
#[derive(Clone)]
pub struct ProductionRamCatalogStorage {
    /// Quota-verified backend with a single retained pair of SQLite connections.
    pub backend: Arc<dyn crucible_store::content_store::ImmutableBlobBackend>,
    /// Exact physical quota and independently retained service authority.
    pub quota: Arc<dyn crucible_store::content_store::StorePhysicalQuotaGuard>,
    /// Shared deletion exclusion held until authenticated catalog retirement.
    pub retention_fence: Arc<std::fs::File>,
    /// Unspent original namespace account used to admit independent RAM operations.
    pub original: crucible_store::owned_decode::DecodeBudget,
}

/// Retains catalog quota and service custody during authenticated deletion.
///
/// Dropping a receipt neither reopens catalog admission nor releases resource
/// ownership. A failed deletion remains pending and retryable in its provider.
pub trait ProductionRamCatalogRetirement: Send + Sync {
    /// Reauthenticates complete directory deletion before discharging custody.
    ///
    /// The enclosing persistent root service remains reserved while any durable
    /// catalog or checkpoint metadata survives. This only retires this catalog.
    ///
    /// # Errors
    /// Refuses incomplete or unauthenticated deletion, retained readers, namespace
    /// drift, or unavailable resource ownership authority.
    fn finish_deleted(&self) -> Result<(), crucible_store::content_store::StoreError>;
}

/// Retained physical quota and service authority for durable checkpoint catalogs.
///
/// Implementations own an independently admitted service until authenticated
/// retirement of their entire persistent root. Assignment completion and the
/// last reader dropping do not authorize releasing that reservation.
pub trait ProductionRamCatalogProvider: Send + Sync {
    /// Reserves resident allocation payloads before decoding retained root metadata.
    ///
    /// The returned credit retains the original service authority until the
    /// final decoded root and every source borrower are dropped.
    ///
    /// # Errors
    /// Refuses unavailable service capacity, closed catalog admission, namespace
    /// drift, or cancellation under the original service supervision.
    fn reserve_root_metadata(
        &self,
        directory: &Path,
        bytes: u64,
    ) -> Result<crucible_store::owned_decode::ResourceLoan, crucible_store::content_store::StoreError>;

    /// Creates or authenticates a catalog directory within the exact quota root.
    ///
    /// The provider excludes symlink, mount and project-identity escapes and
    /// retains an initial bounded descendant audit and continuing namespace
    /// exclusion. Created directories must inherit the authenticated project.
    /// The returned guard retains the service receipt and revalidates the quota.
    ///
    /// # Errors
    /// Refuses unavailable quota authority, mismatched paths or project identity,
    /// exhausted physical bytes/inodes, or canceled supervision.
    fn prepare_directory(
        &self,
        directory: &Path,
    ) -> Result<
        Arc<dyn crucible_store::content_store::StorePhysicalQuotaGuard>,
        crucible_store::content_store::StoreError,
    >;

    /// Opens or clones one cached backend and deletion fence for this directory.
    ///
    /// The implementation admits descriptors before any open, establishes shared
    /// deletion exclusion, and initializes SQLite using the verified quota and
    /// heap ceiling. It retains the cached tuple through durable catalog life;
    /// repeated captures never open another pair of connections or fence.
    ///
    /// # Errors
    /// Refuses unavailable service capacity, namespace or quota drift, missing
    /// deletion exclusion, or durable backend initialization failure.
    fn open_catalog(
        &self,
        directory: &Path,
    ) -> Result<ProductionRamCatalogStorage, crucible_store::content_store::StoreError>;

    /// Closes catalog admission and prepares an idle cached tuple for deletion.
    ///
    /// This atomically excludes new opens, refuses external backend/fence/source
    /// holders, and detaches the shared SQLite backend and fence. Quota, service
    /// and descriptor receipts stay retained in a pending provider record until
    /// authenticated deletion succeeds. Retrying returns that same authority.
    ///
    /// # Errors
    /// Refuses active readers/captures, unavailable ownership, or namespace drift.
    fn begin_catalog_retirement(
        &self,
        directory: &Path,
    ) -> Result<Arc<dyn ProductionRamCatalogRetirement>, crucible_store::content_store::StoreError>;

    /// Returns the independently reserved process-wide SQLite allocator ceiling.
    ///
    /// SQLite's hard heap ceiling is global and can only decrease through the
    /// catalog constructor. This entitlement covers all SQLite heaps in the
    /// process; Rust transport and metadata buffers need separate reservations.
    fn maximum_sqlite_heap_bytes(&self) -> u64;
}

/// Host-local allocator for exact live RAM ownership and admitted launch resources.
pub trait ProductionHostRamRegistrationFactory: Send + Sync {
    /// Partitions the complete admitted world before any node can be prepared.
    ///
    /// # Errors
    /// Refuses inconsistent repeated world shapes or a complete partition that
    /// cannot retain the required metadata, scratch, guest peak and backing.
    fn configure_world(
        &self,
        shapes: &[ProductionHostRamLaunchShape],
    ) -> Result<(), HostRamAdmissionError>;

    /// Binds the launch-scoped operational authority for one admitted node.
    ///
    /// # Errors
    /// Refuses an unknown node or replacement after its generation is prepared.
    fn bind_node_registrar(
        &self,
        node: &str,
        registrar: Arc<dyn crucible_qemu_host::ram_control::RamControlRegistrar>,
    ) -> Result<(), HostRamAdmissionError>;

    /// Returns disjoint native peaks after the complete world has been partitioned.
    ///
    /// # Errors
    /// Refuses an unconfigured world, arithmetic overflow or missing retained
    /// host and backing ownership.
    fn native_world_limits(
        &self,
    ) -> Result<ProductionHostRamNativeWorldLimits, HostRamAdmissionError>;

    /// Returns the retained operational owner and world allocation epoch.
    ///
    /// # Errors
    /// Refuses a missing or unconfigured original world assignment.
    fn native_world_identity(
        &self,
    ) -> Result<ProductionHostRamNativeWorldIdentity, HostRamAdmissionError>;

    /// Visits the exact configured node names and disjoint native requests.
    ///
    /// The callback borrows existing names; the allocator prepays any storage
    /// needed to retain these requests before a process can be created.
    ///
    /// # Errors
    /// Refuses missing launch geometry, incomplete partitions, arithmetic
    /// overflow, or the callback's original admission failure.
    fn visit_native_nodes(
        &self,
        visitor: &mut dyn FnMut(
            &str,
            ProductionHostRamNativeNodeLimits,
        ) -> Result<(), HostRamAdmissionError>,
    ) -> Result<(), HostRamAdmissionError>;

    /// Reserves the pinned controller descriptor before the native authority is created.
    ///
    /// # Errors
    /// Refuses missing world ownership or exhausted independently authored host
    /// service descriptor capacity. Non-native fixtures may return no lease.
    fn reserve_native_controller_resources(
        &self,
        node: &str,
    ) -> Result<
        Option<crucible_host_resources::host_services::HostServiceLease>,
        HostRamAdmissionError,
    >;

    /// Binds the same live kernel authority that enforces the native world peaks.
    ///
    /// # Errors
    /// Refuses absent native authority, a stale or different guard incarnation,
    /// or kernel ceilings inconsistent with the retained complete partition.
    fn bind_native_resource_controller(
        &self,
        node: &str,
        controller: Option<crucible_qemu_host::LinuxQemuNativeResourceController>,
    ) -> Result<(), HostRamAdmissionError>;

    /// Reserves one fresh generation before native launch and sealed-inventory checks.
    ///
    /// Declared RAM is an input bound, not proof of the realized native topology.
    /// The native startup handshake must validate the complete sealed inventory
    /// against the returned entitlement before the first guest instruction.
    ///
    /// # Errors
    /// Returns a diagnostic when exact ownership, metadata, staging, complete
    /// resident peak, backing, or worker/descriptor admission cannot be retained.
    fn prepare(
        &self,
        node: &str,
        process_generation: u64,
        declared_ram_bytes: u64,
        vcpus: u32,
    ) -> Result<crucible_qemu_host::ram_control::RamControlRegistration, HostRamAdmissionError>;
}

pub use crucible_control_api::host_operational::{
    HostRamAdmissionError, HostRamBootstrapLimits, HostRamProcessFamilyNativeAllowances,
    HostRamProcessFamilyPartition, HostRamProcessNativeAllowance,
    ProductionHostRamLaunchRequirements, ProductionHostRamLaunchShape,
    ProductionHostRamNativeNodeLimits, ProductionHostRamNativeWorldIdentity,
    ProductionHostRamNativeWorldLimits, ProductionHostRamPartition,
    partition_host_ram_launch_resources,
};

#[derive(Clone)]
struct BoundedSchedulerPreemptionFlights {
    pending: Arc<Mutex<VecDeque<crucible_qemu_host::BoundedSchedulerPreemptionEvidence>>>,
}

#[derive(Debug, thiserror::Error)]
enum BoundedSchedulerPreemptionFlightError {
    #[error("bounded preemption flight queue was poisoned")]
    QueuePoisoned,
    #[error("bounded preemption flight queue was exhausted")]
    QueueExhausted,
    #[error("claim bounded preemption flight: {0}")]
    Evidence(#[from] crucible_qemu_host::BoundedSchedulerPreemptionEvidenceError),
}

impl BoundedSchedulerPreemptionFlights {
    fn new(evidence: Vec<crucible_qemu_host::BoundedSchedulerPreemptionEvidence>) -> Self {
        Self {
            pending: Arc::new(Mutex::new(evidence.into())),
        }
    }

    fn claim_next(
        &self,
    ) -> Result<
        crucible_qemu_host::BoundedSchedulerPreemptionEvidenceClaim,
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
            .field("run_ceiling_ticks", &self.run_ceiling_ticks)
            .field("quantum_budget", &self.quantum_budget)
            .field("maximum_host_workers", &self.maximum_host_workers)
            .field("completion_timeout", &self.completion_timeout)
            .field("coverage", &self.coverage)
            .field("rr_control_boundary_trace", &self.rr_control_boundary_trace)
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

#[derive(Clone, Debug, PartialEq, Eq)]
struct ProductionVmBranchConfig {
    base: Configuration,
    frontier: VirtualTime,
    seed: Option<Seed>,
}

fn production_fault_search_overrides(
    signal_fault_replay: Option<&SignalFaultCampaignReplayPlan>,
) -> Result<
    BTreeMap<crucible_engine::model::SearchChoiceId, crucible_engine::model::SearchOverride>,
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
                crucible_engine::model::SearchOverride::from_override_decision(decision)
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
    // Semantic bytes authenticate a continuation without native materialization.
    Unmaterialized,
}

#[derive(Clone, Debug)]
struct ProductionExactRamPublishedParent {
    closure: ContentHash,
    targets: BTreeMap<NodeId, ProductionExactRamCheckpoint>,
}

#[derive(Clone, Debug)]
struct ProductionRepositoryExactRamRebase {
    targets: BTreeMap<NodeId, QmpCheckpointIdentity>,
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
            .flat_map(|(_, exact_ram, _)| std::iter::once(&exact_ram.device_artifact))
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
pub(super) struct ProductionExactRamCheckpoint {
    identity: ProductionExactCheckpointIdentity,
    device_content_sha256: ContentHash,
    device_artifact: ProductionCheckpointArtifact,
    catalog: checkpoint_store::paged::PagedRamCatalog,
    ram: crucible_store::ram::LeasedRamRoot,
}

impl ProductionExactRamCheckpoint {
    /// Binds one complete leased exact RAM image to the same native device cut.
    ///
    /// # Errors
    ///
    /// Returns an error when device VMState is empty or sparse, or the RAM
    /// image lacks exact coverage.
    fn from_paged_capture(
        identity: ProductionExactCheckpointIdentity,
        device_content_sha256: ContentHash,
        device_artifact: ProductionCheckpointArtifact,
        catalog: checkpoint_store::paged::PagedRamCatalog,
        ram: crucible_store::ram::LeasedRamRoot,
    ) -> Result<Self, SchedulerError> {
        let checkpoint = Self {
            identity,
            device_content_sha256,
            device_artifact,
            catalog,
            ram,
        };
        checkpoint.validate()?;
        Ok(checkpoint)
    }

    /// Validates the complete RAM and device realization shape.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty or sparse device artifact or wrong RAM scope.
    pub(super) fn validate(&self) -> Result<(), SchedulerError> {
        if self.device_artifact.length == 0 || self.device_artifact.sparse {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("exact checkpoint has an empty or sparse device VMState"),
            });
        }
        if self.ram.record().scope() != crucible_ram::Scope::Exact {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("exact checkpoint requires a complete exact-scope RAM root"),
            });
        }
        Ok(())
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

/// Retains decoded semantic state and the authenticated one-shot restore claims.
#[derive(Debug)]
pub(crate) struct ProductionVmExactCheckpointSet {
    identity: ContentHash,
    configuration: Configuration,
    scheduler: Arc<SingleSchedulerCheckpoint>,
    event_log_objects: Arc<BTreeMap<ContentHash, Vec<u8>>>,
    signal_artifact_objects: Arc<BTreeMap<ContentHash, Vec<u8>>>,
    trigger_state: EventGraphState,
    assertion_state: HostAssertionEvaluatorCheckpoint,
    terminal_verdict: Option<QuantumTerminalVerdict>,
    terminal_cause: Option<CheckpointTerminalCause>,
    initial_lifecycle_observations_pending: bool,
    branch: Option<ProductionVmBranchConfig>,
    recorded_controls: Vec<ProductionVmRecordedControl>,
    selectable_catalog_plans:
        BTreeMap<NodeId, crucible_qemu_protocol::selectable_catalog_plan::SelectableCatalogPlan>,
    fault_checkpoint: Option<ProductionFaultRuntimeCheckpoint>,
    targets: BTreeMap<NodeId, ProductionVmExactCheckpointTarget>,
    failed_host_io: BTreeMap<NodeId, ProductionFailedNodeState>,
    node_generations: BTreeMap<NodeId, u64>,
    node_service_states: BTreeMap<NodeId, ProductionNodeServiceState>,
    repository_restore: Option<RepositoryExactRestoreAuthority>,
}

struct RepositoryExactRestoreAuthority {
    targets: crucible_engine::exact_checkpoint::ExactCheckpointTraversedClosureBinding,
    configuration: Arc<Configuration>,
    scheduler: Arc<SingleSchedulerCheckpoint>,
    open: Arc<dyn Fn(ContentHash) -> std::io::Result<Box<dyn std::io::Read + Send>> + Send + Sync>,
    ram_sources: BTreeMap<NodeId, ProductionPagedRamSource>,
    #[cfg(any(test, feature = "test-support"))]
    ram_source_decorator: Option<Arc<dyn ProductionRamSourceDecorator>>,
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
                ram_source: self.ram_sources.remove(node).ok_or_else(|| {
                    loop_factory_error("exact restore lost its retained RAM source")
                })?,
                #[cfg(any(test, feature = "test-support"))]
                ram_source_decorator: self.ram_source_decorator.clone(),
            },
        })
    }

    fn take_replay_node_admission(
        &mut self,
        node: &NodeId,
        snapshot: ExactSnapshotHandle,
        paused: bool,
        process_generation: u64,
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
                ram_source: self.ram_sources.remove(node).ok_or_else(|| {
                    loop_factory_error("exact replay lost its retained RAM source")
                })?,
                #[cfg(any(test, feature = "test-support"))]
                ram_source_decorator: self.ram_source_decorator.clone(),
            },
            process_generation,
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
    disk_bases: BTreeMap<NodeId, hot_fork::disk_basis::ProductionVmHotForkDiskBasis>,
    block_bindings: BTreeMap<NodeId, storage_faults::ProductionBlockBinding>,
    ninep_bindings: BTreeMap<NodeId, storage_faults::ProductionNinepBinding>,
    active_host_io: BTreeMap<NodeId, QemuHostIoCheckpoint>,
}

struct ProductionVmHotForkRestoreParts {
    config: ProductionVmLifecycleConfig,
    checkpoint: ProductionVmExactCheckpointSet,
    immutable_root_images: BTreeMap<NodeId, ContentHash>,
    disk_bases: BTreeMap<NodeId, hot_fork::disk_basis::ProductionVmHotForkDiskBasis>,
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

#[derive(Clone, Debug, PartialEq, Eq)]
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
#[serde(deny_unknown_fields)]
struct ProductionRunLockRecord {
    version: u32,
    owner: QemuProcessIdentity,
}

const PRODUCTION_RUN_LOCK_VERSION: u32 = 1;

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
    runtime_progress: runtime::progress::RuntimeProgress,
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
    signal_fault_branches: VecDeque<crucible_engine::SignalFaultCampaignBranch>,
    promote_signal_fault_campaign_choices: bool,
    pending_live_network_prefix: Option<quantum_loop::PendingLiveNetworkPrefix>,
    pending_held_host_outcomes: Option<quantum_loop::PendingHeldHostOutcomes>,
    launch_configs: BTreeMap<NodeId, QemuLiveNodeStepGateConfig>,
    block_bindings: BTreeMap<NodeId, storage_faults::ProductionBlockBinding>,
    ninep_bindings: BTreeMap<NodeId, storage_faults::ProductionNinepBinding>,
    block_devices: storage_faults::ProductionBlockDevices,
    failed_host_io: BTreeMap<NodeId, ProductionFailedNodeState>,
    storage_fault_observations: storage_faults::ProductionStorageObservations,
    fault_runtime: Arc<std::sync::Mutex<ProductionFaultRuntime>>,
    fault_replay_installed: bool,
    fault_search_overrides_installed: bool,
    node_indexes: BTreeMap<NodeId, usize>,
    node_run_directories: BTreeMap<NodeId, PathBuf>,
    immutable_root_images: BTreeMap<NodeId, ContentHash>,
    node_generations: BTreeMap<NodeId, u64>,
    node_leases: BTreeMap<NodeId, Box<dyn ProductionVmNodeLease>>,
    node_lease_cleanup_failed: bool,
    retained_cleanup_failure: Option<ProductionVmConstructionCleanupError>,
    terminal_replacements: Vec<quantum_loop::PreparedTerminalReplacement>,
    terminal_replacement_values: Vec<Option<QemuNode>>,
    terminal_replacement_leases: BTreeMap<NodeId, Box<dyn ProductionVmNodeLease>>,
    node_service_states: BTreeMap<NodeId, ProductionNodeServiceState>,
    lifecycle_journal: ProductionLifecycleJournal,
    lifecycle_persistence: LifecycleStatePersistence,
    run_manifest: ProductionRunManifest,
    scenario: ScenarioDef,
    source: ScenarioDefForm,
    config: Arc<ProductionVmLifecycleConfig>,
    checkpoint_targets: BTreeMap<ContentHash, quantum_loop::ExactCheckpointPublicationState>,
    exact_ram_parents: BTreeMap<ContentHash, ProductionExactRamPublishedParent>,
    repository_exact_ram_rebase: Option<ProductionRepositoryExactRamRebase>,
    recorded_controls: Vec<ProductionVmRecordedControl>,
    signal_artifact_objects: Arc<BTreeMap<ContentHash, Vec<u8>>>,
    debug_backend_paths: BTreeMap<NodeId, PathBuf>,
    debug_gateway: Option<DebugGatewayProcess>,
    debug_attach: Option<GdbAttachInfo>,
    debug_gateway_teardown_required: bool,
    indeterminate_debug_candidate: Option<Box<ProductionVmLifecycleLoop>>,
    // A failed replay stays reachable before its diagnostic is rendered.
    retained_debug_construction: std::sync::Mutex<Option<construction::RetainedDebugConstruction>>,
    // The same before-effects Box follows success until whole-owner retirement.
    construction_custody: LifecycleConstructionCustody,
    debug_runtime_evidence: Vec<ProductionVmDebugRuntimeEvidence>,
    node_launcher: Box<dyn ProductionVmNodeLauncher>,
    _run_directory: ProductionRunDirectory,
    // Disk pins close after authenticated reap, before aggregate quota release.
    retained_hot_fork_disk_owners: Vec<Box<dyn Send>>,
    hot_fork_backing_files:
        BTreeMap<NodeId, Vec<hot_fork::disk_basis::ImmutableHotForkBackingFile>>,
    // External admission custody closes after every native and backing borrower.
    retained_resource_owners: Vec<Box<dyn Send>>,
    // Declared last so copied model storage closes before its original credits.
    input_decode_custody: Option<crucible_engine::owned_decode::DecodeCustody>,
}

// Main pairs the actual carrier and destination so native consuming teardown
// cannot observe a witness without its original body storage.
enum LifecycleConstructionCustody {
    Unissued(Option<Box<ProductionVmConstructionCustody>>),
    #[cfg(target_os = "linux")]
    Main {
        carrier: Box<ProductionVmConstructionCustody>,
        destination: crate::lifecycle_cleanup::SourceBodyReturn,
    },
}

#[cfg(test)]
impl LifecycleConstructionCustody {
    fn is_none(&self) -> bool {
        matches!(self, Self::Unissued(None))
    }

    fn as_deref(&self) -> Option<&ProductionVmConstructionCustody> {
        match self {
            Self::Unissued(carrier) => carrier.as_deref(),
            #[cfg(target_os = "linux")]
            Self::Main { carrier, .. } => Some(carrier.as_ref()),
        }
    }
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
    target: crucible_engine::exact_checkpoint::ExactCheckpointStructuralTargetClaim,
    node: NodeId,
    configuration: Arc<Configuration>,
    scheduler: Arc<SingleSchedulerCheckpoint>,
    snapshot: ExactSnapshotHandle,
    paused: bool,
    open: Arc<dyn Fn(ContentHash) -> std::io::Result<Box<dyn std::io::Read + Send>> + Send + Sync>,
    ram_source: ProductionPagedRamSource,
    #[cfg(any(test, feature = "test-support"))]
    ram_source_decorator: Option<Arc<dyn ProductionRamSourceDecorator>>,
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
    process_generation: u64,
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
    request: crucible_qemu_host::QemuProductionExactRestoreRequest,
    paused: bool,
}

impl ProductionVmAtomicExactRestore {
    /// Materializes and restores the exact node at its persisted service disposition.
    ///
    /// # Errors
    ///
    /// Returns [`crucible_qemu_host::QemuLiveNodeStepGateError`] when authenticated
    /// materialization, QEMU restore, or the persisted running transition fails.
    pub fn launch(
        self,
        issuer: impl FnOnce(
            crucible_qemu_host::QemuProductionExactRestoreRequest,
        ) -> Result<
            crucible_qemu_host::QemuProductionExactRestoreLaunch,
            crucible_qemu_host::QemuLiveNodeStepGateError,
        >,
    ) -> Result<(QemuNode, QemuPreparedRunDirectory), crucible_qemu_host::QemuLiveNodeStepGateError>
    {
        let launched = issuer(self.request)?;
        if self.paused {
            launched.into_node_and_run_directory()
        } else {
            launched.into_running_node_and_run_directory()
        }
    }
}

impl ProductionVmExactNodeRestoreAdmission {
    /// Returns the repository root that must seal this generation's process contract.
    #[must_use]
    pub fn repository_root(&self) -> ContentHash {
        ContentHash {
            bytes: self.basis.target.repository_root().content_id().digest(),
        }
    }

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
        process_contract: &crucible_qemu_host::QemuChildProcessContract,
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
    /// Returns the repository-authenticated QEMU lifecycle generation.
    #[must_use]
    pub const fn process_generation(&self) -> u64 {
        self.process_generation
    }

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
        process_contract: &crucible_qemu_host::QemuChildProcessContract,
        crash_detector: impl Into<String>,
    ) -> Result<crucible_qemu_host::QemuReplayValidationExactAdmission, LifecycleApiError> {
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
        crucible_qemu_host::QemuReplayValidationExactAdmission::admit_atomic(
            launch, request, &snapshot, node,
        )
        .map_err(|error| loop_factory_error(format!("admit exact replay executor: {error}")))
    }
}

fn admit_atomic_exact_restore(
    admission: ProductionVmExactNodeRestoreBasis,
    launch: QemuLiveNodeStepGateConfig,
    run_directory: QemuPreparedRunDirectory,
    process_contract: &crucible_qemu_host::QemuChildProcessContract,
    node: impl Into<NodeId>,
    router: impl Into<String>,
    crash_detector: impl Into<String>,
) -> Result<crucible_qemu_host::QemuProductionExactRestoreRequest, LifecycleApiError> {
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
    let backing: Arc<dyn crucible_qemu_host::ram_source::QemuRamBacking> =
        Arc::new(admission.ram_source);
    #[cfg(any(test, feature = "test-support"))]
    let backing = ram_source_observation::decorate_authenticated_backing(
        backing,
        admission.ram_source_decorator.as_deref(),
    )?;
    crucible_qemu_host::QemuProductionExactRestoreRequest::new(
        crucible_qemu_host::QemuProductionExactRestoreProfile {
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
        crucible_qemu_host::QemuPagedRamRestoreSource::new(backing)
            .map_err(|error| loop_factory_error(format!("admit leased RAM source: {error}")))?,
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

    /// Moves the owned coordinate without copying its node name.
    pub(crate) fn into_parts(self) -> (NodeId, u64) {
        (self.node, self.generation)
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

    /// Observes bounded diagnostics through this lease's existing ownership.
    ///
    /// The default does nothing. Implementations must remain nonblocking and
    /// retain diagnostic failures for reporting and ordered cleanup, without
    /// changing modeled execution or returning a new runtime failure.
    fn observe_operational_diagnostics(&mut self) {}

    /// Identifies a scripted lease whose QMP boundary intentionally models
    /// VMState-only preparation without a physical root file.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    fn scripted_vmstate_only_hot_fork(&self) -> bool {
        false
    }

    /// Opens the exact pinned root overlay for a stopped checkpoint capture.
    ///
    /// # Errors
    ///
    /// Returns [`LifecycleApiError`] if the generation cannot prove that the
    /// named overlay still matches its retained file authority.
    fn open_checkpoint_root_overlay(&self) -> Result<std::fs::File, LifecycleApiError>;

    /// Duplicates the original pinned VMState inode for hot-fork custody.
    ///
    /// # Errors
    ///
    /// Returns an error when this lease lacks authenticated VMState authority.
    fn open_hot_fork_vmstate(&self) -> Result<std::fs::File, LifecycleApiError> {
        Err(loop_factory_error(
            "generation lease has no pinned hot-fork VMState authority",
        ))
    }

    /// Creates an exclusively named empty qcow2 overlay under the generation's
    /// original process contract and returns its pinned inode and path.
    ///
    /// The default refuses; only a lease retaining the guarded run directory
    /// and source-built image tool can produce this physical file authority.
    ///
    /// # Errors
    ///
    /// Returns an error if the generation cannot retain a bounded helper and
    /// authenticate the resulting file, or if a prior attempt still owes cleanup.
    fn prepare_hot_fork_detached_root_overlay(
        &mut self,
        _original: &crucible_qemu_host::QemuHotForkSourceOriginal,
        _graph_generation: u64,
        _virtual_size: u64,
    ) -> Result<(std::fs::File, PathBuf), LifecycleApiError> {
        Err(loop_factory_error(
            "generation lease has no guarded detached-overlay authority",
        ))
    }

    /// Authenticates a relative overlay name under the original source cwd.
    ///
    /// # Errors
    ///
    /// Returns an error unless the lease retains the source directory and
    /// independently binds its actual cwd and named file to the admitted inode.
    fn authenticate_hot_fork_overlay_name(
        &self,
        _source_pid: u32,
        _file: &std::fs::File,
        _path: &Path,
    ) -> Result<PathBuf, LifecycleApiError> {
        Err(loop_factory_error(
            "generation lease has no authenticated hot-fork cwd authority",
        ))
    }

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
    /// Retains a child, its lease and the producer's expected process identity.
    ///
    /// This is an ownership transfer, not lifecycle admission. The constructor
    /// performs no fallible operation after accepting the live node. Lifecycle
    /// assembly verifies its generation, directory and actual process identity
    /// while retaining the complete joint owner on refusal.
    #[must_use]
    pub fn new<L>(
        identity: ProductionVmNodeGeneration,
        process: QemuProcessIdentity,
        node: QemuNode,
        lease: L,
        run_directory: PathBuf,
    ) -> Self
    where
        L: ProductionVmNodeLease + 'static,
    {
        Self {
            identity,
            process,
            node,
            lease: Box::new(lease),
            run_directory,
        }
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
        Self {
            node,
            // A replay profile retains immutable launch facts. Each replay
            // leg must acquire a fresh admitted operational owner at launch.
            launch: launch
                .without_ram_control_registration()
                .without_host_operation_supervisor(),
        }
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
    /// different node or generation. Refusal returns the same node and lease
    /// for retention by their existing owner.
    pub fn new<L>(
        request: ProductionVmNodeLaunchRequest<'_>,
        node: QemuNode,
        lease: L,
    ) -> Result<Self, (LifecycleApiError, Self)>
    where
        L: ProductionVmNodeLease + 'static,
    {
        Self::new_in_run_directory(request, request.run_directory(), node, lease)
    }

    /// Pairs a node and its existing lease without discarding refused inputs.
    ///
    /// # Errors
    /// Returns the original typed validation error and the same jointly owned
    /// node, lease and directory on a mismatched generation or empty path.
    /// The caller must retain that joint owner before returning the error.
    pub fn new_in_run_directory<L>(
        request: ProductionVmNodeLaunchRequest<'_>,
        run_directory: impl Into<PathBuf>,
        node: QemuNode,
        lease: L,
    ) -> Result<Self, (LifecycleApiError, Self)>
    where
        L: ProductionVmNodeLease + 'static,
    {
        // This is the successful pairing's existing lease allocation. The
        // refusal path moves this same body; it allocates no error carrier.
        let launch = Self {
            node,
            lease: Box::new(lease),
            run_directory: run_directory.into(),
        };
        let expected =
            match ProductionVmNodeGeneration::new(request.node().clone(), request.generation()) {
                Ok(expected) => expected,
                Err(first) => return Err((first, launch)),
            };
        if launch.lease.identity() != &expected {
            return Err((
                loop_factory_error("production QEMU node lease does not match its launch request"),
                launch,
            ));
        }
        if launch.run_directory.as_os_str().is_empty() {
            return Err((
                loop_factory_error("production QEMU node launch returned an empty run directory"),
                launch,
            ));
        }
        Ok(launch)
    }

    /// Moves a refused pairing's complete body to its retained launcher.
    #[must_use]
    pub fn into_retained_parts(self) -> (QemuNode, Box<dyn ProductionVmNodeLease>, PathBuf) {
        (self.node, self.lease, self.run_directory)
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

    fn quarantine_and_finish(&mut self) -> Result<(), SchedulerError> {
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

#[cfg(all(test, target_os = "linux"))]
mod node_lease_cleanup_tests;

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
        let Some(lease) = node_leases.get_mut(node) else {
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
        if let Err(error) = lease.finish() {
            if first_error.is_none() {
                first_error = Some(format!(
                    "finish reaped QEMU node `{}` generation {generation}: {error}",
                    node.name
                ));
            }
            continue;
        }
        // A refusal leaves this exact owner available for the same cleanup.
        // Only successful retirement permits destruction of the lease body.
        node_leases.remove(node);
    }
    first_error.map_or(Ok(()), |message| {
        Err(SchedulerError::BoundaryViolation { message })
    })
}

mod checkpoint_recovery;
use checkpoint_recovery::durable_run_state_api_error;
// The generic admitted-path constructor uses the existing driver format type.
type RootImageFormat = QemuRootImageFormat;

mod admitted_assets;
pub use admitted_assets::{ProductionVmGuestAssetAdmissionError, ProductionVmGuestAssetPaths};

mod admitted_clone;
mod config;
pub use admitted_clone::ProductionVmLifecycleConfigCloneError;
pub use crucible_control_api::{
    ProductionVmCleanupHandoff, ProductionVmCleanupOwner, ProductionVmCleanupReservation,
    ProductionVmCleanupStage,
};
mod construction;
use construction::build_production_vm_lifecycle_loop_with_restore;
pub(crate) use construction::{
    ExactRestoreExposure as RetainedConstructionExposure,
    prepare_from_custody as prepare_retained_construction,
};
#[cfg(target_os = "linux")]
pub use construction::{
    MainSourceLifecycle, MainSourceLifecycleFailure, MainSourceLifecycleRefusal,
};
pub use construction::{
    ProductionVmCleanupEarlierFailure, ProductionVmConstructionCleanupError,
    ProductionVmConstructionCustody, ProductionVmConstructionFailure,
};
mod helpers;
mod network_faults;
mod process_owners;
use process_owners::{
    ProductionLifecycleCompletedExit, ProductionLifecycleJournal, ProductionLifecycleJournalNode,
    ProductionLifecycleJournalPhase, ProductionRunManifest,
};
mod quantum_loop;
mod runtime;
#[cfg(all(target_os = "linux", any(test, feature = "test-support")))]
pub use runtime::checkpoint_consumer::CheckpointConsumerEpochEvidence;
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
        version: PRODUCTION_RUN_LOCK_VERSION,
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
                let existing = decode_production_run_lock(&path)?;
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

fn decode_production_run_lock(path: &Path) -> Result<ProductionRunLockRecord, LifecycleApiError> {
    let record: ProductionRunLockRecord = decode_run_json(path)
        .map_err(|message| loop_factory_error(format!("invalid run lock: {message}")))?;
    if record.version != PRODUCTION_RUN_LOCK_VERSION {
        return Err(loop_factory_error(format!(
            "unsupported run lock version {}",
            record.version
        )));
    }
    Ok(record)
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
/// Returns [`ProductionVmConstructionFailure`] retaining the exact inputs when
/// launcher construction or restored lifecycle validation fails.
pub fn build_production_vm_exact_resume_lifecycle(
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    config: &ProductionVmLifecycleConfig,
    decoded: DecodedProductionExactCheckpoint,
    launcher: Box<dyn ProductionVmNodeLauncher>,
) -> Result<ProductionVmLifecycleLoop, ProductionVmConstructionFailure> {
    let custody = construction::retain_construction_inputs(
        launcher,
        Some(decoded.into_checkpoint()),
        None,
        None,
        Vec::new(),
    )?;
    construction::build_from_custody(
        scenario,
        source,
        config,
        custody,
        construction::ExactRestoreExposure::Released,
    )
}

mod receiving_transfer;
pub use receiving_transfer::ProductionStoppedLifecycleError;

/// Owns a reconstructed World whose live native nodes remain stopped.
///
/// This owner deliberately exposes no scheduler, debug, or quantum interface.
/// It is not a destination Ready or execution-ownership grant. Read-only
/// verification and physical cleanup expose no executable lifecycle interface.
///
/// ```compile_fail,E0616
/// use crucible_daemon::ProductionVmStoppedLifecycle;
/// fn expose(world: ProductionVmStoppedLifecycle) {
///     let executable = world.lifecycle;
/// }
/// ```
pub struct ProductionVmStoppedLifecycle {
    lifecycle: Option<ProductionVmLifecycleLoop>,
}

impl ProductionVmStoppedLifecycle {
    /// Retains a fully validated lifecycle before ownership-commit exposure.
    pub(crate) fn from_retained_loop(lifecycle: ProductionVmLifecycleLoop) -> Self {
        Self {
            lifecycle: Some(lifecycle),
        }
    }

    /// Reaps the complete stopped World and joins its retained source workers.
    ///
    /// # Errors
    /// Keeps the entire World in this owner when cleanup is unproven. Dropping
    /// that owner quarantines its scheduler, roots and native custody together.
    pub fn shutdown(&mut self) -> Result<(), SchedulerError> {
        self.shutdown_before_main_return()?;
        if let Some(lifecycle) = self.lifecycle.take() {
            #[cfg(target_os = "linux")]
            lifecycle.retire_owned_body();
            #[cfg(not(target_os = "linux"))]
            drop(lifecycle);
        }
        Ok(())
    }

    /// Performs the same semantic shutdown while retaining its actual body.
    ///
    /// Receiving cleanup records an independent failure before adopting its
    /// actual alias owners into Main. Neither result publishes or drops this
    /// body, so adoption always precedes its canonical return.
    pub(crate) fn shutdown_before_main_return(&mut self) -> Result<(), SchedulerError> {
        if let Some(lifecycle) = self.lifecycle.as_mut() {
            lifecycle.abort_stopped_restore()?;
        }
        Ok(())
    }

    /// Observes the required private return pair without claiming body closure.
    #[cfg(target_os = "linux")]
    pub(crate) fn has_main_return(&self) -> bool {
        self.lifecycle
            .as_ref()
            .is_some_and(ProductionVmLifecycleLoop::has_main_return)
    }

    /// Corroborates the actual body destination against its input return owner.
    #[cfg(target_os = "linux")]
    pub(crate) fn matches_input_return(
        &self,
        input: &crate::lifecycle_cleanup::ServiceInputReturn,
    ) -> bool {
        self.lifecycle
            .as_ref()
            .is_some_and(|lifecycle| match &lifecycle.construction_custody {
                LifecycleConstructionCustody::Main { destination, .. } => {
                    destination.matches_input_return(input)
                }
                LifecycleConstructionCustody::Unissued(_) => false,
            })
    }

    /// Publishes a witnessed body after its actual alias input was adopted.
    ///
    /// A false result preserves the same unissued body. No semantic operation,
    /// destructor or fallible delivery runs after a native body is taken.
    #[cfg(target_os = "linux")]
    pub(crate) fn return_to_main(&mut self) -> bool {
        if !self.has_main_return() {
            return false;
        }
        if let Some(lifecycle) = self.lifecycle.take() {
            lifecycle.retire_owned_body();
            return true;
        }
        false
    }

    /// Borrows only the original body slot for a pure same-role custody return.
    pub(crate) fn retirement_loop_slot(&mut self) -> &mut Option<ProductionVmLifecycleLoop> {
        &mut self.lifecycle
    }
}

impl Drop for ProductionVmStoppedLifecycle {
    fn drop(&mut self) {
        if let Some(lifecycle) = self.lifecycle.take() {
            #[cfg(target_os = "linux")]
            if lifecycle.has_main_return() {
                lifecycle.retire_owned_body();
                return;
            }
            // Standalone callers must retain the same complete stopped World
            // as the daemon owner when physical retirement is not proven.
            std::mem::forget(lifecycle);
        }
    }
}

/// Reconstructs one complete exact World with every live native node stopped.
///
/// Logical Running, PoweredOff and PermanentlyFailed dispositions retain their
/// authenticated meanings. The caller must keep this lifecycle private until
/// its durable execution-ownership commit; physical reconstruction alone does
/// not authorize exposure, a scheduler quantum, or source destruction.
///
/// # Errors
///
/// Returns [`ProductionVmConstructionFailure`] retaining the exact inputs for a
/// different scenario, incomplete continuation, or unsuccessful native restore.
pub fn build_production_vm_exact_stopped_lifecycle(
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    config: &ProductionVmLifecycleConfig,
    decoded: DecodedProductionExactCheckpoint,
    launcher: Box<dyn ProductionVmNodeLauncher>,
) -> Result<ProductionVmStoppedLifecycle, ProductionVmConstructionFailure> {
    let custody = construction::retain_construction_inputs(
        launcher,
        Some(decoded.into_checkpoint()),
        None,
        None,
        Vec::new(),
    )?;
    construction::build_from_custody(
        scenario,
        source,
        config,
        custody,
        construction::ExactRestoreExposure::AwaitingOwnershipCommit,
    )
    .map(ProductionVmStoppedLifecycle::from_retained_loop)
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
    ram_catalog_provider: Option<&Arc<dyn ProductionRamCatalogProvider>>,
) -> Result<ProductionVmExactHotForkSourceBoundary, LifecycleApiError> {
    let checkpoint = load_exact_checkpoint_set(
        run_state_root,
        scenario,
        source,
        closure,
        ram_catalog_provider,
    )?;
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
/// Returns [`ProductionVmConstructionFailure`] retaining the continuation,
/// children and launcher when validation or lifecycle construction refuses.
#[cfg(target_os = "linux")]
pub fn build_production_vm_lifecycle_loop_from_hot_fork_with_launcher(
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    continuation: ProductionVmHotForkWorldContinuation,
    adoptions: Vec<ProductionVmHotForkNodeAdoption>,
    run_state_root: impl Into<PathBuf>,
    launcher: Box<dyn ProductionVmNodeLauncher>,
) -> Result<ProductionVmLifecycleLoop, ProductionVmConstructionFailure> {
    let mut custody = construction::retain_construction_inputs(
        launcher,
        None,
        None,
        Some(continuation),
        adoptions,
    )?;
    if let Err(first) = prepare_retained_hot_fork_construction(
        scenario,
        source,
        &mut custody,
        run_state_root.into(),
    ) {
        return Err(custody.into_failure(first));
    }
    custody.into_loop().map_err(|custody| {
        custody.into_failure(loop_factory_error(
            "construction lost its complete lifecycle",
        ))
    })
}

/// Builds a retained fork while its original owner keeps the actual carrier.
///
/// The launcher, continuation and adoptions must already be installed together.
/// A refused validation or physical operation leaves their partial state in the
/// same carrier. Export is a separate pure move after successful preparation.
///
/// # Errors
/// Returns the original validation or construction error without consuming the
/// carrier or allocating a replacement ownership frame.
#[cfg(target_os = "linux")]
pub(crate) fn prepare_retained_hot_fork_construction(
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    custody: &mut ProductionVmConstructionCustody,
    run_state_root: PathBuf,
) -> Result<(), LifecycleApiError> {
    let config = prepare_hot_fork_restore_inputs(scenario, source, custody, run_state_root)?;
    construction::prepare_from_custody(
        scenario,
        source,
        &config,
        custody,
        construction::ExactRestoreExposure::Released,
    )
}

/// Validates and stages the captured continuation without exporting its owners.
#[cfg(target_os = "linux")]
fn prepare_hot_fork_restore_inputs(
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    custody: &mut ProductionVmConstructionCustody,
    run_state_root: PathBuf,
) -> Result<Arc<ProductionVmLifecycleConfig>, LifecycleApiError> {
    let phase = custody.preparation_phase()?;
    let continuation = phase.hot_fork_continuation.as_ref().ok_or_else(|| {
        loop_factory_error("hot-fork continuation is absent from construction custody")
    })?;
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
    if phase.hot_fork_adoptions.len() > source_nodes.len() {
        return Err(loop_factory_error(
            "hot-fork adopted child count exceeds the scenario World",
        ));
    }
    // Validate identities while every actual child remains in its input slot.
    let mut adoption_generations = BTreeMap::new();
    for adoption in &phase.hot_fork_adoptions {
        let node = adoption.identity().node().clone();
        if adoption_generations
            .insert(node.clone(), adoption.identity().generation())
            .is_some()
        {
            return Err(loop_factory_error(format!(
                "hot-fork World contains duplicate child `{}`",
                node.name,
            )));
        }
    }
    let HotForkAdoptionInventory {
        expected_times,
        node_generations,
    } = validate_hot_fork_adoption_inventory(continuation, &adoption_generations)?;
    // The admitted copy can refuse while the original continuation is retained.
    let config = continuation.prepare_restore_config(run_state_root)?;
    let continuation = phase.hot_fork_continuation.take().ok_or_else(|| {
        loop_factory_error("hot-fork continuation disappeared from construction custody")
    })?;
    let ProductionVmHotForkRestoreParts {
        config,
        checkpoint,
        immutable_root_images,
        disk_bases,
        block_bindings,
        ninep_bindings,
        active_host_io,
    } = continuation.into_restore_parts(node_generations, config);
    phase.restore_checkpoint = Some(checkpoint);
    phase.retained_config = Some(Arc::new(config));
    phase.hot_fork_restore = Some(ProductionVmHotForkRestore {
        expected_times,
        adoptions: BTreeMap::new(),
        immutable_root_images,
        disk_bases,
        block_bindings,
        ninep_bindings,
        active_host_io,
    });

    while let Some(adoption) = phase.hot_fork_adoptions.pop() {
        phase.pending_adoption = Some(adoption);
        let node = phase
            .pending_adoption
            .as_ref()
            .ok_or_else(|| loop_factory_error("hot-fork pending adoption is absent"))?
            .identity()
            .node()
            .clone();
        let restore = phase
            .hot_fork_restore
            .as_mut()
            .ok_or_else(|| loop_factory_error("hot-fork restore custody is absent"))?;
        match restore.adoptions.entry(node) {
            std::collections::btree_map::Entry::Vacant(entry) => {
                if let Some(adoption) = phase.pending_adoption.take() {
                    entry.insert(adoption);
                }
            }
            std::collections::btree_map::Entry::Occupied(_) => {
                // Both the existing child and the incoming child stay retained.
                return Err(loop_factory_error("hot-fork adoption slot is occupied"));
            }
        }
    }
    phase
        .retained_config
        .as_ref()
        .map(Arc::clone)
        .ok_or_else(|| loop_factory_error("hot-fork admitted configuration is absent"))
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
/// Returns [`ProductionVmConstructionFailure`] with the actual inputs and
/// partial lifecycle retained when validation, admission, launch, or scheduler
/// construction fails.
pub fn build_production_vm_lifecycle_loop_with_launcher(
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    config: &ProductionVmLifecycleConfig,
    launcher: Box<dyn ProductionVmNodeLauncher>,
) -> Result<ProductionVmLifecycleLoop, ProductionVmConstructionFailure> {
    build_production_vm_lifecycle_loop_with_restore(scenario, source, config, None, launcher, None)
}

fn validate_app_random_branch_replay_config(
    nodes: crucible_engine::WorldVmNodes<'_>,
    config: &ProductionVmLifecycleConfig,
) -> Result<(), LifecycleApiError> {
    let mut planned_selection_ids = BTreeMap::<[u8; 32], usize>::new();
    let mut planned_count = 0_usize;
    for (node, plan) in &config.app_random_branch_plans {
        if !nodes
            .iter()
            .any(|vm| vm.id == *node && vm.white_box == crucible_engine::WhiteBoxPolicy::Enabled)
        {
            return Err(loop_factory_error(format!(
                "app-random branch plan names missing or white-box-disabled node `{}`",
                node.name
            )));
        }
        for entry in plan.entries() {
            if !crucible_qemu_protocol::app_random_transport::app_random_stream_name_belongs_to_node(
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
                > crucible_qemu_protocol::app_random_branch_plan::MAX_APP_RANDOM_BRANCH_PLAN_ENTRIES
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

#[cfg(test)]
mod run_lock_schema_tests {
    use super::*;

    #[test]
    fn run_lock_requires_current_version() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let path = directory.path().join("active-run.lock");
        let owner = linux_process_identity(std::process::id())?
            .ok_or_else(|| std::io::Error::other("current process has no identity"))?;
        let current = ProductionRunLockRecord {
            version: PRODUCTION_RUN_LOCK_VERSION,
            owner: owner.clone(),
        };
        fs::write(&path, serde_json::to_vec(&current)?)?;

        let decoded = decode_production_run_lock(&path)?;
        assert_eq!(decoded.version, PRODUCTION_RUN_LOCK_VERSION);
        assert_eq!(decoded.owner, owner);

        let registry =
            include_str!("../../../../../docs/rfcs/0020-crucible-campaigns/schema-registry.tsv");
        let registry_version = registry
            .lines()
            .find_map(|line| line.strip_prefix("crucible.production-run-lock\t"))
            .and_then(|fields| fields.split('\t').next())
            .ok_or_else(|| std::io::Error::other("missing production run lock registry row"))?
            .parse::<u32>()?;
        assert_eq!(registry_version, PRODUCTION_RUN_LOCK_VERSION);

        let unversioned = serde_json::json!({ "owner": owner.clone() });
        fs::write(&path, serde_json::to_vec(&unversioned)?)?;
        assert!(decode_production_run_lock(&path).is_err());

        let future = serde_json::json!({ "version": 2, "owner": owner });
        fs::write(&path, serde_json::to_vec(&future)?)?;
        assert!(decode_production_run_lock(&path).is_err());

        Ok(())
    }
}

#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
mod parent_park_drain;
#[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
pub use parent_park_drain::{
    ProductionVmParentParkDrain, ProductionVmParentParkDrainCause,
    ProductionVmParentParkDrainFailure, ProductionVmParentParkDrainRefusal,
    ProductionVmParentParkDrainRequest, ProductionVmParentParkStageAdmissionCause,
    ProductionVmParentParkStageEarlyCause, ProductionVmParentParkStageEnteredCause,
    ProductionVmParentParkStageFailure, ProductionVmParentParkStageOwnerCause,
    ProductionVmParentParkStageReborrowCause,
};

#[cfg(target_os = "linux")]
pub use hot_fork::{
    ProductionVmHotForkSourceRetirement, ProductionVmHotForkSourceRetirementFailure,
    ProductionVmHotForkSourceRetirementHistory, SourceRearmHistory, SourceRetirementCause,
    SourceRetirementRefusal,
};

/// Prices the existing terminal transaction buffers in their Source World.
pub(crate) fn terminal_replacement_control_bytes(
    selected: usize,
) -> Result<u64, LifecycleApiError> {
    let rows = std::alloc::Layout::array::<quantum_loop::PreparedTerminalReplacement>(selected)
        .map_err(|_| loop_factory_error("terminal replacement row extent overflows"))?;
    let values = std::alloc::Layout::array::<Option<QemuNode>>(selected)
        .map_err(|_| loop_factory_error("terminal replacement value extent overflows"))?;
    rows.size()
        .checked_add(values.size())
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or_else(|| loop_factory_error("terminal replacement transaction extent overflows"))
}
