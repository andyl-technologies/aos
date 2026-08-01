//! Production local-VM lifecycle loop construction.
//!
//! This module owns the process-local composition from a submitted
//! [`ScenarioDefForm`] to the authoritative [`SingleScheduler`], one live
//! scheduler-facing QEMU node per World VM, and the node-addressed backend loop
//! consumed by [`LifecycleControlPlane`](crate::LifecycleControlPlane).

use std::collections::BTreeMap;
use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::Duration;

use crate::vm_resume::{
    PRODUCTION_ROOT_OVERLAY_FILE_NAME, ProductionAppRandomConfig, ProductionGdbstubChannelConfig,
    ProductionLiveNode, ProductionLiveNodeStepGateConfig, ProductionNodeSet,
    ProductionPluginSwitch, ProductionRootImageFormat, launch_production_live_node,
};
use crucible::{
    Action, BackendQuantumLoop, ConditionEvaluationPass, ConditionLeaf, Configuration,
    ControlOperation, Decision, EventFirings, EventGraph, EventGraphState, FingerprintSample,
    GdbAttachInfo, GdbListen, NodeId, QuantumLoop, QuantumOutcome, QuantumRequest,
    QuantumTerminalVerdict, RestartPolicy, ScenarioDef, ScenarioDefForm, SchedulerError,
    SchedulerEventLogAppend, SchedulerEventLogEntry, SchedulerLivenessScenario,
    SearchFrontierChoices, Seed, Shift, SimInstant, SimulationBackend, SingleScheduler,
    VirtualTime, World,
};

use crate::LifecycleApiError;

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
    kernel: PathBuf,
    root_image: PathBuf,
    initrd: Option<PathBuf>,
    kernel_cmdline_prefix: Option<String>,
    root_image_format: ProductionRootImageFormat,
    run_ceiling_icount: u64,
    quantum_budget: u64,
    completion_timeout: Duration,
    coverage: ProductionPluginSwitch,
    debug: Option<ProductionVmDebugConfig>,
    branch: Option<ProductionVmBranchConfig>,
    branch_fault_choices: Vec<Decision>,
    branch_network_choices: Vec<crucible::OverrideDecision>,
}

/// Debugger channel requested for one production QEMU lifecycle node.
#[derive(Clone, Debug)]
struct ProductionVmDebugConfig {
    node: Option<String>,
    operator_listen: String,
}

#[derive(Clone, Debug)]
struct ProductionVmBranchConfig {
    base: Configuration,
    frontier: VirtualTime,
    decisions: Vec<Decision>,
    seed: Option<Seed>,
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

impl ProductionVmLifecycleConfig {
    /// Builds a local-QEMU lifecycle configuration with bounded defaults.
    #[must_use]
    pub fn new(
        executable: impl Into<PathBuf>,
        plugin: impl Into<PathBuf>,
        kernel: impl Into<PathBuf>,
        root_image: impl Into<PathBuf>,
    ) -> Self {
        Self {
            executable: executable.into(),
            plugin: plugin.into(),
            kernel: kernel.into(),
            root_image: root_image.into(),
            initrd: None,
            kernel_cmdline_prefix: None,
            root_image_format: ProductionRootImageFormat::Qcow2,
            run_ceiling_icount: DEFAULT_RUN_CEILING_ICOUNT,
            quantum_budget: DEFAULT_QUANTUM_BUDGET,
            completion_timeout: Duration::from_secs(240),
            coverage: ProductionPluginSwitch::Off,
            debug: None,
            branch: None,
            branch_fault_choices: Vec::new(),
            branch_network_choices: Vec::new(),
        }
    }

    /// Returns this configuration with the materialized initrd passed to QEMU.
    #[must_use]
    pub fn with_initrd(mut self, initrd: impl Into<PathBuf>) -> Self {
        self.initrd = Some(initrd.into());
        self
    }

    /// Returns this configuration with package-owned kernel command-line pins.
    #[must_use]
    pub fn with_kernel_cmdline_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.kernel_cmdline_prefix = Some(prefix.into());
        self
    }

    /// Returns this configuration with the immutable root image's format.
    #[must_use]
    pub const fn with_root_image_format(mut self, format: ProductionRootImageFormat) -> Self {
        self.root_image_format = format;
        self
    }

    /// Returns this configuration with a different terminal icount ceiling.
    #[must_use]
    pub const fn with_run_ceiling_icount(mut self, ceiling: u64) -> Self {
        self.run_ceiling_icount = ceiling;
        self
    }

    /// Returns this configuration with a different scheduler quantum budget.
    #[must_use]
    pub const fn with_quantum_budget(mut self, budget: u64) -> Self {
        self.quantum_budget = budget;
        self
    }

    /// Returns this configuration with a different per-node completion timeout.
    #[must_use]
    pub const fn with_completion_timeout(mut self, timeout: Duration) -> Self {
        self.completion_timeout = timeout;
        self
    }

    /// Returns this configuration with observation-only basic-block coverage.
    #[must_use]
    pub const fn with_coverage(mut self, coverage: ProductionPluginSwitch) -> Self {
        self.coverage = coverage;
        self
    }

    /// Returns this configuration with one mediated QEMU gdbstub channel.
    ///
    /// `node` selects a World VM by canonical name. When omitted, the first VM
    /// owns the debugger channel. The operator listener accepts the same stable
    /// address syntax as [`GdbListen`], including `127.0.0.1:0`.
    #[must_use]
    pub fn with_debug_gdbstub(
        mut self,
        node: Option<String>,
        operator_listen: impl Into<String>,
    ) -> Self {
        self.debug = Some(ProductionVmDebugConfig {
            node,
            operator_listen: operator_listen.into(),
        });
        self
    }

    /// Returns this configuration with explorer overrides admitted at `frontier`.
    ///
    /// The lifecycle waits until deterministic replay reaches both the exact
    /// base configuration and saved frontier, then records the supplied
    /// overrides before any further backend advance.
    #[must_use]
    pub fn with_branch_prefix_overrides(
        mut self,
        base: Configuration,
        frontier: VirtualTime,
        decisions: Vec<Decision>,
    ) -> Self {
        self.branch = Some(ProductionVmBranchConfig {
            base,
            frontier,
            decisions,
            seed: None,
        });
        self
    }

    /// Returns this configuration with decision streams re-seeded at `frontier`.
    ///
    /// Prefix replay continues under the scenario seed. Once the authoritative
    /// scheduler reaches both `base` and the saved frontier, every future
    /// scheduler, network, block/9p, and live app-random decision stream
    /// restarts from cursor zero under `seed`.
    #[must_use]
    pub fn with_branch_reseed(
        mut self,
        base: Configuration,
        frontier: VirtualTime,
        seed: Seed,
    ) -> Self {
        self.branch = Some(ProductionVmBranchConfig {
            base,
            frontier,
            decisions: Vec::new(),
            seed: Some(seed),
        });
        self
    }

    /// Returns this configuration with exact probabilistic fault branch choices.
    ///
    /// The decisions are installed into the authoritative scheduler and consumed
    /// only at matching RESOLVE points. Invalid or unconsumed choices fail the
    /// lifecycle rather than silently falling back to the seeded default.
    #[must_use]
    pub fn with_branch_fault_choices(mut self, decisions: Vec<Decision>) -> Self {
        self.branch_fault_choices = decisions;
        self
    }

    /// Returns this configuration with exact live World-network branch choices.
    #[must_use]
    pub fn with_branch_network_choices(mut self, choices: Vec<crucible::OverrideDecision>) -> Self {
        self.branch_network_choices = choices;
        self
    }

    fn for_thin_replay(mut self) -> Self {
        self.debug = None;
        self
    }

    /// Returns a conservative bound for driving through the configured budget.
    ///
    /// The scheduler budget is already a count of authoritative quanta. The
    /// additional per-node pass covers scheduler-only boundaries and terminal
    /// settling after the final admitted quantum.
    #[must_use]
    pub fn maximum_scheduler_quanta(&self, node_count: usize) -> u64 {
        let node_count = u64::try_from(node_count).unwrap_or(u64::MAX).max(1);
        self.quantum_budget
            .saturating_add(node_count)
            .saturating_add(1)
    }
}

/// Lifecycle loop backed by an authoritative scheduler and live QEMU node set.
pub struct ProductionVmLifecycleLoop {
    inner: BackendQuantumLoop<SingleScheduler, ProductionNodeSet>,
    trigger_graph: EventGraph,
    trigger_state: EventGraphState,
    trigger_world: World,
    terminal_verdict: Option<QuantumTerminalVerdict>,
    branch: Option<ProductionVmBranchConfig>,
    launch_configs: BTreeMap<NodeId, ProductionLiveNodeStepGateConfig>,
    node_indexes: BTreeMap<NodeId, usize>,
    restart_generations: BTreeMap<NodeId, u64>,
    executable: PathBuf,
    root_image: PathBuf,
    scenario: ScenarioDef,
    source: ScenarioDefForm,
    config: ProductionVmLifecycleConfig,
    checkpoint_targets: BTreeMap<NodeId, ProductionVmCheckpointReplayTarget>,
    recorded_controls: Vec<ProductionVmRecordedControl>,
    prelaunched_restarts: BTreeMap<NodeId, (RestartPolicy, u64)>,
    retained_replay_directories: Vec<tempfile::TempDir>,
    reconciled_crashes: usize,
    reconciled_restarts: usize,
    _run_directory: tempfile::TempDir,
}

mod helpers;
mod quantum_loop;
mod runtime;

use helpers::*;

/// Derives the production scheduler's initial state-space search frontier.
///
/// The returned choices come from the same [`SingleScheduler`] construction
/// used by live QEMU execution. Backend processes are not launched by this
/// policy-only query; callers must execute every selected branch through
/// [`build_production_vm_lifecycle_loop`] to obtain runtime evidence.
///
/// # Errors
///
/// Returns [`LifecycleApiError::LoopFactory`] when the World is empty, VM
/// shifts differ, time conversion overflows, configured bounds are invalid, or
/// the authoritative scheduler rejects the scenario.
pub fn production_vm_search_frontier(
    scenario: &ScenarioDef,
    source: &ScenarioDefForm,
    config: &ProductionVmLifecycleConfig,
) -> Result<SearchFrontierChoices, LifecycleApiError> {
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
    if config.run_ceiling_icount == 0 || config.quantum_budget == 0 {
        return Err(loop_factory_error(
            "production QEMU lifecycle bounds must be nonzero",
        ));
    }
    let shift = Shift::new(first.icount_shift)
        .map_err(|error| loop_factory_error(format!("validate icount shift: {error}")))?;
    let time_limit_nanos = config
        .run_ceiling_icount
        .checked_shl(u32::from(first.icount_shift))
        .ok_or_else(|| loop_factory_error("QEMU lifecycle time limit overflow"))?;
    let runtime_scenario = SchedulerLivenessScenario::from_runnable_world(
        &scenario.id().to_hex(),
        shift,
        config.quantum_budget,
        SimInstant {
            nanos: time_limit_nanos,
        },
        0,
        source.world(),
    )
    .with_scenario_def(scenario.clone());
    let scheduler = SingleScheduler::new(runtime_scenario)
        .map_err(|error| loop_factory_error(format!("construct QEMU scheduler: {error}")))?;
    Ok(scheduler.materialized_scheduler_state().search_frontier)
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
    if config.run_ceiling_icount == 0 || config.quantum_budget == 0 {
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

    let run_directory = tempfile::TempDir::new()
        .map_err(|error| loop_factory_error(format!("create QEMU run directory: {error}")))?;
    let mut backends = ProductionNodeSet::new();
    let mut launch_configs = BTreeMap::new();
    let mut node_indexes = BTreeMap::new();
    let mut initial_ticks = None;
    let scenario_seed = scenario.seed().bytes();
    let mut launch_seed_bytes = [0_u8; 8];
    launch_seed_bytes.copy_from_slice(&scenario_seed[..8]);
    let launch_seed = u64::from_le_bytes(launch_seed_bytes);
    for (index, vm) in nodes.iter().enumerate() {
        if vm.arch != crucible::VmArchitecture::X86_64 {
            return Err(loop_factory_error(format!(
                "QEMU node `{}` uses unsupported architecture {:?}",
                vm.id.name, vm.arch
            )));
        }
        let node_directory = run_directory.path().join(format!("node-{index}"));
        fs::create_dir_all(&node_directory).map_err(|error| {
            loop_factory_error(format!(
                "create QEMU node run directory {}: {error}",
                node_directory.display()
            ))
        })?;
        prepare_root_overlay(&config.executable, &config.root_image, &node_directory)?;
        let kernel_cmdline = match &config.kernel_cmdline_prefix {
            Some(prefix) if !prefix.trim().is_empty() => {
                format!("{} {}", prefix.trim(), vm.cmdline.trim())
            }
            _ => vm.cmdline.clone(),
        };
        let mut launch = ProductionLiveNodeStepGateConfig::new_with_root_image(
            &config.executable,
            &config.plugin,
            &config.kernel,
            &config.root_image,
            &node_directory,
        )
        .with_root_image_format(config.root_image_format)
        .with_kernel_cmdline(kernel_cmdline)
        .with_vm_shape(vm.memory_mib, vm.smp_vcpus, vm.icount_shift)
        .with_scenario_seed(launch_seed)
        .with_whitebox(ProductionPluginSwitch::On)
        .with_app_random(production_app_random_launch_config(
            scenario,
            config.branch.as_ref(),
            &vm.id,
        ))
        .with_coverage(config.coverage)
        .with_queue_capacity(PRODUCTION_QUEUE_CAPACITY)
        .with_completion_timeout(config.completion_timeout)
        .with_second_run_host_load(false);
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
            debug
                .node
                .as_deref()
                .map_or(index == 0, |selected| selected == vm.id.name)
        }) {
            let debug = config.debug.as_ref().ok_or_else(|| {
                loop_factory_error("debug configuration disappeared during QEMU launch")
            })?;
            let backend_listen = reserve_backend_gdbstub_endpoint()?;
            let gdbstub =
                ProductionGdbstubChannelConfig::new(backend_listen, debug.operator_listen.clone())
                    .map_err(|error| {
                        loop_factory_error(format!("configure QEMU gdbstub: {error}"))
                    })?;
            launch = launch.with_gdbstub(gdbstub);
        }
        launch_configs.insert(vm.id.clone(), launch.clone());
        node_indexes.insert(vm.id.clone(), index);
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
    let runtime_scenario = SchedulerLivenessScenario::from_runnable_world(
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

    Ok(ProductionVmLifecycleLoop {
        inner: BackendQuantumLoop::new(scheduler, backends),
        trigger_graph,
        trigger_state: EventGraphState::default(),
        trigger_world: source.world().clone(),
        terminal_verdict: None,
        branch: config.branch.clone(),
        launch_configs,
        node_indexes,
        restart_generations: BTreeMap::new(),
        executable: config.executable.clone(),
        root_image: config.root_image.clone(),
        scenario: scenario.clone(),
        source: source.clone(),
        config: config.clone(),
        checkpoint_targets: BTreeMap::new(),
        recorded_controls: Vec::new(),
        prelaunched_restarts: BTreeMap::new(),
        retained_replay_directories: Vec::new(),
        reconciled_crashes: 0,
        reconciled_restarts: 0,
        _run_directory: run_directory,
    })
}
