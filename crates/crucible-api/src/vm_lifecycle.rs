//! Production local-VM lifecycle loop construction.
//!
//! This module owns the process-local composition from a submitted
//! [`ScenarioDefForm`] to the authoritative [`SingleScheduler`], one live
//! scheduler-facing QEMU node per World VM, and the node-addressed backend loop
//! consumed by [`LifecycleControlPlane`](crate::LifecycleControlPlane).

use std::collections::BTreeMap;
use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::vm_resume::{
    PRODUCTION_ROOT_OVERLAY_FILE_NAME, ProductionAppRandomConfig, ProductionGdbstubChannelConfig,
    ProductionGuestArchitecture, ProductionLiveNode, ProductionLiveNodeStepGateConfig,
    ProductionNodeSet, ProductionPluginSwitch, ProductionRootImageFormat,
    launch_production_live_node,
};
use crucible::{
    Action, AssertionPhase, BackendQuantumLoop, BlackBoxHostOracle, ConditionEvaluationPass,
    ConditionLeaf, Configuration, ContentHash, ControlOperation, DebugGdbEndpoint,
    DebugRetiredWorldCleanup, DebugRuntimeRepositionReport, DebugRuntimeRepositionRequest,
    Decision, EventFirings, EventGraph, EventGraphState, EventLogOffset, FingerprintSample,
    GdbAttachInfo, GdbListen, HostAssertionEvaluator, HostAssertionOutcome,
    HostAssertionOutcomeKind, Icount, NodeId, NodeLifecycle, ObservableEvent, QuantumLoop,
    QuantumOutcome, QuantumRequest, QuantumTerminalVerdict, RestartPolicy, RuntimeState,
    ScenarioDef, ScenarioDefForm, SchedulerError, SchedulerEventLogAppend, SchedulerEventLogEntry,
    SchedulerLivenessScenario, SchedulerState, SearchFrontierChoices, Seed, Shift, SimDuration,
    SimInstant, SimulationBackend, SingleScheduler, VirtualTime, VmArchitecture, World,
};

use crate::LifecycleApiError;
use crate::debug_gateway::DebugGatewayProcess;

mod assets;
use assets::*;

/// Default final icount available to one production CLI lifecycle session.
const DEFAULT_RUN_CEILING_ICOUNT: u64 = 16_000_000;
/// Default scheduler quantum budget for one production CLI lifecycle session.
const DEFAULT_QUANTUM_BUDGET: u64 = 4_096;
/// Per-direction shared-memory frame capacity for production VM nodes.
const PRODUCTION_QUEUE_CAPACITY: u32 = 1_024;
/// Maximum number of trigger batches admitted at one scheduler boundary.
const MAX_TRIGGER_SETTLE_BATCHES: usize = 1_024;

/// Immutable artifacts and bounds for local production QEMU execution.
#[derive(Clone, Debug)]
pub struct ProductionVmLifecycleConfig {
    executable: PathBuf,
    plugin: PathBuf,
    native_guest_architecture: VmArchitecture,
    guest_assets: BTreeMap<VmArchitecture, ProductionVmGuestAssets>,
    initrd: Option<PathBuf>,
    kernel_cmdline_prefix: Option<String>,
    root_image_format: ProductionRootImageFormat,
    run_ceiling_icount: u64,
    quantum_budget: u64,
    rendezvous_interval_icount: Option<u64>,
    completion_timeout: Duration,
    coverage: ProductionPluginSwitch,
    debug_gateway_executable: Option<PathBuf>,
    debug: Option<ProductionVmDebugConfig>,
    branch: Option<ProductionVmBranchConfig>,
    branch_fault_choices: Vec<Decision>,
    branch_network_choices: Vec<crucible::OverrideDecision>,
    validate_guest_asset_references: bool,
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

/// Single-node replacement retained while gateway ownership is indeterminate.
struct ProductionVmQuarantinedBackend {
    backend: ProductionLiveNode,
    run_directory: Option<tempfile::TempDir>,
}

#[derive(Clone, Debug)]
struct ProductionVmCheckpointReplayTarget {
    configuration: Configuration,
    counter: u64,
    scheduler_time: VirtualTime,
    control_count: usize,
}

#[derive(Clone, Debug)]
struct ProductionVmRecordedControl {
    configuration: Configuration,
    node_times: BTreeMap<NodeId, VirtualTime>,
    control: Vec<ControlOperation>,
}

/// Lifecycle loop backed by an authoritative scheduler and live QEMU node set.
pub struct ProductionVmLifecycleLoop {
    inner: BackendQuantumLoop<SingleScheduler, ProductionNodeSet>,
    trigger_graph: EventGraph,
    trigger_state: EventGraphState,
    trigger_world: World,
    assertion_evaluator: HostAssertionEvaluator,
    assertion_oracle: BlackBoxHostOracle,
    terminal_verdict: Option<QuantumTerminalVerdict>,
    initial_lifecycle_observations_pending: bool,
    branch: Option<ProductionVmBranchConfig>,
    launch_configs: BTreeMap<NodeId, ProductionLiveNodeStepGateConfig>,
    node_indexes: BTreeMap<NodeId, usize>,
    restart_generations: BTreeMap<NodeId, u64>,
    executable: PathBuf,
    root_images: BTreeMap<NodeId, PathBuf>,
    scenario: ScenarioDef,
    source: ScenarioDefForm,
    config: ProductionVmLifecycleConfig,
    checkpoint_targets: BTreeMap<NodeId, ProductionVmCheckpointReplayTarget>,
    recorded_controls: Vec<ProductionVmRecordedControl>,
    prelaunched_restarts: BTreeMap<NodeId, (RestartPolicy, u64)>,
    debug_backend_paths: BTreeMap<NodeId, PathBuf>,
    debug_gateway: Option<DebugGatewayProcess>,
    debug_attach: Option<GdbAttachInfo>,
    debug_gateway_teardown_required: bool,
    indeterminate_debug_candidate: Option<Box<ProductionVmLifecycleLoop>>,
    indeterminate_debug_backend: Option<ProductionVmQuarantinedBackend>,
    debug_runtime_evidence: Vec<ProductionVmDebugRuntimeEvidence>,
    retained_replay_directories: Vec<tempfile::TempDir>,
    reconciled_crashes: usize,
    reconciled_restarts: usize,
    _run_directory: tempfile::TempDir,
}

mod config;
mod helpers;
mod quantum_loop;
mod runtime;
mod search;

use helpers::*;
pub use search::production_vm_search_frontier;

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
    if !cfg!(target_os = "linux") {
        return Err(loop_factory_error(
            "production local-QEMU lifecycle requires a Linux host",
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

    let run_directory = tempfile::TempDir::new()
        .map_err(|error| loop_factory_error(format!("create QEMU run directory: {error}")))?;
    let mut backends = ProductionNodeSet::new();
    let mut launch_configs = BTreeMap::new();
    let mut node_indexes = BTreeMap::new();
    let mut root_images = BTreeMap::new();
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
        prepare_root_overlay(
            &config.executable,
            &guest_assets.root_image,
            &node_directory,
        )?;
        let kernel_cmdline_prefix = production_kernel_cmdline_prefix(config, vm.arch, guest_assets);
        let kernel_cmdline = match kernel_cmdline_prefix {
            Some(prefix) if !prefix.trim().is_empty() => {
                format!("{} {}", prefix.trim(), vm.cmdline.trim())
            }
            _ => vm.cmdline.clone(),
        };
        let whitebox = production_whitebox_switch(vm.white_box);
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
        .with_queue_capacity(PRODUCTION_QUEUE_CAPACITY)
        .with_completion_timeout(config.completion_timeout)
        .with_console_capture()
        .with_second_run_host_load(false);
        if vm.white_box == crucible::WhiteBoxPolicy::Enabled {
            launch = launch.with_app_random(production_app_random_launch_config(
                scenario,
                config.branch.as_ref(),
                &vm.id,
            ));
        }
        if !source.world().links().is_empty() {
            launch = launch.with_shmem_network_mac(crucible::deterministic_node_mac_string(&vm.id));
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
        root_images.insert(vm.id.clone(), guest_assets.root_image.clone());
        let mut backend = launch_production_live_node(
            &launch,
            &node_directory,
            &vm.id.name,
            "crucible-router",
            &format!("lifecycle-{}", vm.id.name),
        )
        .map_err(|error| {
            loop_factory_error(format!("launch QEMU node `{}`: {error}", vm.id.name))
        })?;
        let observed = SimulationBackend::now(&backend).ticks;
        if initial_ticks.is_some_and(|initial| initial != observed) {
            let _ = SimulationBackend::shutdown(&mut backend);
            return Err(loop_factory_error(format!(
                "QEMU node `{}` primed at {observed}, expected {}",
                vm.id.name,
                initial_ticks.unwrap_or_default()
            )));
        }
        initial_ticks.get_or_insert(observed);
        if backends.insert(vm.id.clone(), backend).is_some() {
            return Err(loop_factory_error(format!(
                "duplicate QEMU node identity `{}`",
                vm.id.name
            )));
        }
    }

    let initial_ticks = initial_ticks.unwrap_or_default();
    if config.run_ceiling_icount <= initial_ticks {
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
    let mut scheduler = SingleScheduler::new(runtime_scenario)
        .map_err(|error| loop_factory_error(format!("construct QEMU scheduler: {error}")))?;
    if let Some(branch) = &config.branch {
        scheduler
            .set_branch_frontier_cap(branch.frontier)
            .map_err(|error| loop_factory_error(format!("cap QEMU branch frontier: {error}")))?;
    }
    scheduler
        .attach_world_network_links(source.world())
        .map_err(|error| loop_factory_error(format!("attach QEMU World network: {error}")))?;
    scheduler
        .install_branch_fault_choices(config.branch_fault_choices.clone())
        .map_err(|error| loop_factory_error(format!("install QEMU branch choices: {error}")))?;
    scheduler
        .install_branch_network_choices(config.branch_network_choices.clone())
        .map_err(|error| {
            loop_factory_error(format!("install QEMU network branch choices: {error}"))
        })?;
    let trigger_graph = source
        .plan()
        .lower_to_event_graph_for_world(source.world())
        .map_err(|error| loop_factory_error(format!("lower scenario trigger plan: {error}")))?
        .into_event_graph();

    let mut lifecycle = ProductionVmLifecycleLoop {
        inner: BackendQuantumLoop::new(scheduler, backends),
        trigger_graph,
        trigger_state: EventGraphState::default(),
        trigger_world: source.world().clone(),
        assertion_evaluator: HostAssertionEvaluator::new(source.properties())
            .with_world_white_box_policies(source.world()),
        assertion_oracle: BlackBoxHostOracle,
        terminal_verdict: None,
        initial_lifecycle_observations_pending: true,
        branch: config.branch.clone(),
        launch_configs,
        node_indexes,
        restart_generations: BTreeMap::new(),
        executable: config.executable.clone(),
        root_images,
        scenario: scenario.clone(),
        source: source.clone(),
        config: config.clone(),
        checkpoint_targets: BTreeMap::new(),
        recorded_controls: Vec::new(),
        prelaunched_restarts: BTreeMap::new(),
        debug_backend_paths,
        debug_gateway: None,
        debug_attach: None,
        debug_gateway_teardown_required: false,
        indeterminate_debug_candidate: None,
        indeterminate_debug_backend: None,
        debug_runtime_evidence: Vec::new(),
        retained_replay_directories: Vec::new(),
        reconciled_crashes: 0,
        reconciled_restarts: 0,
        _run_directory: run_directory,
    };
    if let Err(error) = lifecycle.capture_debug_runtime_evidence() {
        let _ = lifecycle.inner.shutdown();
        return Err(loop_factory_error(format!(
            "capture initial debugger runtime evidence: {error}"
        )));
    }
    Ok(lifecycle)
}
