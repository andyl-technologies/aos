//! First live [`QemuNode`] bring-up and bounded-step proof gate.
//!
//! This is the first gate that drives a real scheduler-facing [`QemuNode`]
//! against a live QEMU child. The M1 quantum and fingerprint gates drive the
//! mapped shared-memory hot path directly and never construct a node; this gate
//! stands the whole node up -- plugin IPC control, the mapped quantum hot path,
//! the production [`QemuLiveHostIoRuntime`], and a typed QMP VMState channel --
//! then advances it a bounded number of quanta through the public
//! [`QemuNode::advance_to_ceiling`] API.
//!
//! # Bring-up
//!
//! The launch/setup handshake mirrors the M1 quantum gate's `run_one_scenario`
//! with one deliberate divergence: the launch command adds a QMP endpoint and
//! the runner connects a [`QemuQmpVmStateControlChannel`] after setup, because
//! [`build_qemu_node_from_completed_setup`] requires a QMP machine-control
//! channel and the M1 quantum gate never wires QMP.
//!
//! ```text
//! spawn qemu-crucible (Rust plugin + QMP) -> complete plugin setup handshake
//!   -> QemuLiveHostIoRuntime::from_shmem_fd (independent read-only shmem view)
//!   -> publish the boot-barrier ceiling while the guest remains stopped
//!   -> authenticate and grant the sealed native RAM inventory
//!   -> authenticate QMP and the device projection, then acknowledge `cont`
//!   -> QemuNodeFactoryRuntime::new(...) -> build_qemu_node_from_completed_setup
//!   -> drive QemuNode::advance_to_ceiling over a busy-window ceiling schedule
//! ```
//!
//! # Busy-window determinism
//!
//! Every scheduled ceiling stays strictly below the diskless-firmware idle onset
//! (~15.8M icount), so the guest is always executing and each bounded step stops
//! exactly at the published ceiling. That avoids the open early-boot idle-warp
//! nondeterminism (which only occurs in idle windows) and lets the gate assert
//! that the two runs reach byte-identical completion icounts and a byte-identical
//! execution fingerprint. Because the window is busy, `start_quantum`'s
//! shared-memory futex wake is sufficient to release each step -- the separate
//! idle-wake eventfd signal the multi-quantum M1 scheduler needs after the guest
//! first idles is not required here.
//!
//! # Raw-versus-logical accounting
//!
//! Each step records its requested ceiling (the raw scheduler target) against the
//! node's published completion icount (the logical value the plugin reports). In
//! a busy window the plugin applies no idle-jump offset, so the logical offset
//! (`completion_icount - target_icount`) must be zero at every boundary. A
//! nonzero offset would mean an idle-jump offset leaked into a busy-window
//! boundary -- the M3 raw-versus-logical aggregation regression this accounting
//! guards against.

#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::os::fd::{AsFd as _, BorrowedFd};
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use crucible_device::block::{BaseImage, BlockDurabilityConfig, BlockLatency};
use crucible_device::{FsTree, NinepLatency};
use crucible_engine::model::FaultResourceLimits;
use crucible_engine::{
    BackendInput, BasicBlockCoverageConfig, Checkpoint, CheckpointKind, ContentHash, Icount,
    NodeId, SchedulerError, SchedulerNodeId, SchedulerSendAuthorization, SchedulerSendAuthorizer,
    VirtualTime,
};
use crucible_qemu_shmem::{
    FrameDeliveryState, RegionConfig, RegionLayout, SLOT_NET_ROUTER, mmap_setup_region,
};

use crate::QemuChildProcessContract;
use crate::console_observation::{QemuConsoleObservationReader, QemuConsoleObservationSpool};
use crate::node_factory::QemuNodeRestorePlan;
use crate::node_factory::{
    build_qemu_node_from_completed_setup, build_qemu_node_from_restored_checkpoint,
    build_qemu_node_from_restored_checkpoint_paused,
};
use crate::supervision::{
    BlockIoDiagnostics, NinepIoDiagnostics, QemuLive9pIoServicer, QemuLiveAcceleratorServicer,
    QemuLiveBlockIoServicer, QemuLiveHostIoRuntime,
};
use crate::{
    CrucibleAcceleratorDevice, CrucibleShmem9pDevice, CrucibleShmemBlockDevice,
    CrucibleShmemNetworkDevice, LaunchProfileCandidate, LaunchProfileError,
    LivePluginGuestArchitecture, QemuAsyncDriverPolicy, QemuCrashDetector,
    QemuExactCheckpointRestoreDescriptors, QemuGdbstubChannelConfig, QemuHostPluginSetupError,
    QemuLaunchAppRandomConfig, QemuLaunchArtifact, QemuLaunchCommandBuilder,
    QemuLaunchCommandError, QemuLaunchPluginConfig, QemuLaunchPluginSwitch,
    QemuMappedQuantumShmemHotPath, QemuMappedQuantumShmemHotPathError, QemuNode,
    QemuNodeChannelError, QemuNodeError, QemuNodeFactoryError, QemuNodeFactoryRuntime,
    QemuPreparedRunDirectory, QemuQmpChannelConfig, QemuQuantumShmemConfig, QemuRootImageFormat,
    QemuShmemHotPathChannel, QemuShutdownPolicy, QemuVmLaunchConfig, QemuVmSnapshot,
    QemuWhiteboxSetupError, QmpError, complete_qemu_host_plugin_setup_with_plugin_setup_plan,
    spawn_prepared_qemu_child_with_preexec,
};

use super::QemuLiveHostIoRuntimeError;

mod error;
pub use error::QemuLiveNodeStepGateError;
mod exact_snapshot;
mod paused_launch;
mod plugin_resources;
pub use exact_snapshot::{
    QemuLiveHotForkChildReport, QemuLiveHotForkChildStressReport,
    run_qemu_live_hot_fork_child_gate, run_qemu_live_hot_fork_child_stress_gate,
};
pub use paused_launch::PausedLiveNodeLaunch;

/// Content-addressing domain for node-step launch artifacts.
const GATE_DOMAIN: &str = "crucible.loaded-qemu-live-node-step.v1";
/// Stable node name for the single-VM node-step run.
const GATE_NODE: &str = "live-node-step-vm";
/// Default QEMU round-robin subdivision in node icount units.
const GATE_RR_SWITCH_QUANTUM: u64 = 4_096;
/// Stable router name reserved by the shared-memory hot path.
const GATE_ROUTER: &str = "live-node-step-router";
/// VM slot negotiated during the handshake.
const GATE_SLOT: u32 = 0;
/// Fixed inbound/outbound ring capacity for the single-node run.
const GATE_QUEUE_CAPACITY: u32 = 4;
/// Conservative guest memory size for the node-step run.
const GATE_MEMORY_MIB: u32 = 64;
/// The only supported QEMU instruction-count shift.
/// QMP socket file created in the run directory for VMState control.
const GATE_QMP_SOCKET_FILE_NAME: &str = "crucible-live-node-step-qmp.sock";
/// Inputs for one guarded live [`QemuNode`] launch.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLiveNodeStepGateConfig {
    architecture: LivePluginGuestArchitecture,
    doorbell_instruction_abi_version: u16,
    qemu_executable: PathBuf,
    plugin: PathBuf,
    kernel: PathBuf,
    firmware: PathBuf,
    firmware_boot: bool,
    root_image: Option<PathBuf>,
    root_image_format: QemuRootImageFormat,
    run_directory: PathBuf,
    initrd: Option<PathBuf>,
    kernel_cmdline: Option<String>,
    gdbstub: Option<QemuGdbstubChannelConfig>,
    memory_mib: u32,
    smp_vcpus: u16,
    rr_switch_quantum: u64,
    scenario_seed: u64,
    process_generation: u64,
    network_tx_next_sequence: u32,
    storage_completed_history_epochs: u64,
    storage_completed_history_gaps: u64,
    whitebox: QemuLaunchPluginSwitch,
    campaign_marker_parking: bool,
    app_random: Option<QemuLaunchAppRandomConfig>,
    selectable_catalog_plan:
        Option<crucible_qemu_protocol::selectable_catalog_plan::SelectableCatalogPlan>,
    coverage: QemuLaunchPluginSwitch,
    fingerprint: QemuLaunchPluginSwitch,
    shmem_network_mac: Option<String>,
    boot_network_backpressure_capture: Option<QemuLiveNodeStepNetworkCapture>,
    shmem_block: Option<QemuLiveNodeStepBlockConfig>,
    shmem_ninep: Option<QemuLiveNodeStepNinepConfig>,
    accelerator: bool,
    queue_capacity: u32,
    completion_timeout: Duration,
    host_operation_supervisor:
        Option<crucible_host_resources::host_supervision::HostOperationSupervisor>,
    ram_control_registration: Option<crate::ram_control::RamControlRegistration>,
    fault_actor_test_entitlement: Option<[u8; 32]>,
    unbounded_advance_completion: bool,
    console_capture: bool,
    rr_control_boundary_trace: bool,
    runtime_determinism_trace: bool,
    runtime_determinism_trace_budget_bytes: u64,
    runtime_liveness_trace: bool,
    fault_capabilities: Option<crucible_engine::model::WorldNodeFaultCapabilities>,
    exact_gate_fault_manifests: Option<crate::fault_capability::QemuExactFaultManifests>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct QemuLiveNodeStepBlockConfig {
    world_binding: Option<super::QemuWorldIoBinding>,
    base: BaseImage,
    durability: BlockDurabilityConfig,
    latency: BlockLatency,
    require_fault_directives: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct QemuLiveNodeStepNinepConfig {
    world_binding: Option<super::QemuWorldIoBinding>,
    tree: FsTree,
    latency: NinepLatency,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct QemuLiveNodeStepNetworkCapture {
    payload: Vec<u8>,
    capture_icount: u64,
}

impl QemuLiveNodeStepGateConfig {
    /// Compares immutable replay inputs while excluding process-local fields.
    #[must_use]
    pub(crate) fn has_same_replay_profile(&self, other: &Self) -> bool {
        let mut left = self.clone();
        left.run_directory = PathBuf::new();
        left.process_generation = 0;
        left.gdbstub = None;
        left.host_operation_supervisor = None;
        left.ram_control_registration = None;

        let mut right = other.clone();
        right.run_directory = PathBuf::new();
        right.process_generation = 0;
        right.gdbstub = None;
        right.host_operation_supervisor = None;
        right.ram_control_registration = None;

        left == right
    }

    /// Returns this launch configuration rooted in a fresh run directory.
    ///
    /// Intended crash/restart relaunches use a new directory so stale QMP
    /// sockets, shared-memory files, and writable overlays from the stopped
    /// process cannot leak into the restarted runtime.
    #[must_use]
    pub fn with_run_directory(mut self, run_directory: impl Into<PathBuf>) -> Self {
        self.run_directory = run_directory.into();
        self
    }

    /// Returns this launch profile without an operator debugger endpoint.
    ///
    /// Background bake and replay-oracle generations must not reuse a live
    /// attempt's private gdbstub socket path or operator listener. Removing the
    /// endpoint does not change modeled guest execution.
    #[must_use]
    pub fn without_gdbstub(mut self) -> Self {
        self.gdbstub = None;
        self
    }

    /// Returns the fixed host-resource baseline for this launch profile.
    ///
    /// The value is independent of the generation run-directory namespace and
    /// can therefore be admitted before that directory exists. The concrete
    /// launch command must reproduce this exact profile before guarded spawn.
    #[must_use]
    pub const fn resource_requirements(&self) -> crate::QemuLaunchResourceRequirements {
        let mut requirements = crate::QemuLaunchResourceRequirements::from_vm_shape(
            self.memory_mib,
            self.smp_vcpus,
            self.root_image.is_some(),
        );
        if self.rr_control_boundary_trace {
            requirements = requirements.with_diagnostic_trace_bytes(
                crate::launch::MAXIMUM_RR_CONTROL_BOUNDARY_TRACE_BYTES,
            );
        } else if self.runtime_determinism_trace {
            requirements = requirements
                .with_diagnostic_trace_bytes(self.runtime_determinism_trace_budget_bytes);
        } else if self.runtime_liveness_trace {
            requirements = requirements.with_diagnostic_trace_bytes(
                crate::launch::MAXIMUM_RUNTIME_DETERMINISM_TRACE_BYTES,
            );
        }
        requirements
    }

    /// Returns the exact QEMU executable selected by this launch profile.
    #[must_use]
    pub fn qemu_executable(&self) -> &Path {
        &self.qemu_executable
    }

    /// Borrows the exact plugin spelling passed to this launch's native loader.
    pub(crate) fn original_plugin_path(&self) -> &Path {
        &self.plugin
    }

    /// Returns the immutable root-image path selected by this launch profile.
    #[must_use]
    pub fn root_image(&self) -> Option<&Path> {
        self.root_image.as_deref()
    }

    /// Returns the generation run directory sealed into this launch profile.
    #[must_use]
    pub fn run_directory(&self) -> &Path {
        &self.run_directory
    }

    /// Builds a node-step configuration with bounded defaults.
    ///
    /// The gate always launches the diskless-firmware guest profile, so a pinned
    /// firmware image is required rather than a root disk.
    #[must_use]
    pub fn new(
        qemu_executable: impl Into<PathBuf>,
        plugin: impl Into<PathBuf>,
        kernel: impl Into<PathBuf>,
        firmware: impl Into<PathBuf>,
        run_directory: impl Into<PathBuf>,
    ) -> Self {
        Self {
            architecture: LivePluginGuestArchitecture::X86_64,
            doorbell_instruction_abi_version:
                crucible_qemu_protocol::WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION,
            qemu_executable: qemu_executable.into(),
            plugin: plugin.into(),
            kernel: kernel.into(),
            firmware: firmware.into(),
            firmware_boot: false,
            root_image: None,
            root_image_format: QemuRootImageFormat::Qcow2,
            run_directory: run_directory.into(),
            initrd: None,
            kernel_cmdline: None,
            gdbstub: None,
            memory_mib: GATE_MEMORY_MIB,
            smp_vcpus: 1,
            rr_switch_quantum: GATE_RR_SWITCH_QUANTUM,
            scenario_seed: 0,
            process_generation: 1,
            network_tx_next_sequence: 0,
            storage_completed_history_epochs: FaultResourceLimits::compiled_maximum()
                .storage_completed_history_epochs,
            storage_completed_history_gaps: FaultResourceLimits::compiled_maximum()
                .storage_completed_history_gaps,
            whitebox: QemuLaunchPluginSwitch::Off,
            campaign_marker_parking: false,
            app_random: None,
            selectable_catalog_plan: None,
            coverage: QemuLaunchPluginSwitch::Off,
            fingerprint: QemuLaunchPluginSwitch::Off,
            shmem_network_mac: None,
            boot_network_backpressure_capture: None,
            shmem_block: None,
            shmem_ninep: None,
            accelerator: false,
            queue_capacity: GATE_QUEUE_CAPACITY,
            completion_timeout: Duration::from_secs(240),
            host_operation_supervisor: None,
            ram_control_registration: None,
            fault_actor_test_entitlement: None,
            unbounded_advance_completion: false,
            console_capture: false,
            rr_control_boundary_trace: false,
            runtime_determinism_trace: false,
            runtime_determinism_trace_budget_bytes:
                crate::launch::MAXIMUM_RUNTIME_DETERMINISM_TRACE_BYTES,
            runtime_liveness_trace: false,
            fault_capabilities: None,
            exact_gate_fault_manifests: None,
        }
    }

    /// Builds a node-step configuration backed by an immutable root image.
    ///
    /// QEMU writes into the deterministic overlay file in each run directory;
    /// the supplied root image remains read-only launch material.
    #[must_use]
    pub fn new_with_root_image(
        qemu_executable: impl Into<PathBuf>,
        plugin: impl Into<PathBuf>,
        kernel: impl Into<PathBuf>,
        root_image: impl Into<PathBuf>,
        run_directory: impl Into<PathBuf>,
    ) -> Self {
        Self {
            architecture: LivePluginGuestArchitecture::X86_64,
            doorbell_instruction_abi_version:
                crucible_qemu_protocol::WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION,
            qemu_executable: qemu_executable.into(),
            plugin: plugin.into(),
            kernel: kernel.into(),
            firmware: PathBuf::new(),
            firmware_boot: false,
            root_image: Some(root_image.into()),
            root_image_format: QemuRootImageFormat::Qcow2,
            run_directory: run_directory.into(),
            initrd: None,
            kernel_cmdline: None,
            gdbstub: None,
            memory_mib: GATE_MEMORY_MIB,
            smp_vcpus: 1,
            rr_switch_quantum: GATE_RR_SWITCH_QUANTUM,
            scenario_seed: 0,
            process_generation: 1,
            network_tx_next_sequence: 0,
            storage_completed_history_epochs: FaultResourceLimits::compiled_maximum()
                .storage_completed_history_epochs,
            storage_completed_history_gaps: FaultResourceLimits::compiled_maximum()
                .storage_completed_history_gaps,
            whitebox: QemuLaunchPluginSwitch::Off,
            campaign_marker_parking: false,
            app_random: None,
            selectable_catalog_plan: None,
            coverage: QemuLaunchPluginSwitch::Off,
            fingerprint: QemuLaunchPluginSwitch::Off,
            shmem_network_mac: None,
            boot_network_backpressure_capture: None,
            shmem_block: None,
            shmem_ninep: None,
            accelerator: false,
            queue_capacity: GATE_QUEUE_CAPACITY,
            completion_timeout: Duration::from_secs(240),
            host_operation_supervisor: None,
            ram_control_registration: None,
            fault_actor_test_entitlement: None,
            unbounded_advance_completion: false,
            console_capture: false,
            rr_control_boundary_trace: false,
            runtime_determinism_trace: false,
            runtime_determinism_trace_budget_bytes:
                crate::launch::MAXIMUM_RUNTIME_DETERMINISM_TRACE_BYTES,
            runtime_liveness_trace: false,
            fault_capabilities: None,
            exact_gate_fault_manifests: None,
        }
    }

    /// Returns this configuration with the selected guest architecture.
    #[must_use]
    pub const fn with_guest_architecture(
        mut self,
        architecture: LivePluginGuestArchitecture,
    ) -> Self {
        self.architecture = architecture;
        self
    }

    /// Returns this configuration with the immutable root image's format.
    #[must_use]
    pub const fn with_root_image_format(mut self, format: QemuRootImageFormat) -> Self {
        self.root_image_format = format;
        self
    }

    /// Returns this configuration with a content-addressed initrd.
    #[must_use]
    pub fn with_initrd(mut self, initrd: impl Into<PathBuf>) -> Self {
        self.initrd = Some(initrd.into());
        self
    }

    /// Returns this configuration with firmware-managed boot device discovery.
    ///
    /// The launch omits QEMU's direct `-kernel` and `-initrd` payloads. Attached
    /// block devices are therefore reached through the firmware's normal boot
    /// path.
    #[must_use]
    pub const fn with_firmware_boot(mut self) -> Self {
        self.firmware_boot = true;
        self
    }

    /// Returns this configuration with an explicit guest kernel command line.
    #[must_use]
    pub fn with_kernel_cmdline(mut self, kernel_cmdline: impl Into<String>) -> Self {
        self.kernel_cmdline = Some(kernel_cmdline.into());
        self
    }

    /// Returns this configuration with a mediated debugger gdbstub channel.
    #[must_use]
    pub fn with_gdbstub(mut self, gdbstub: QemuGdbstubChannelConfig) -> Self {
        self.gdbstub = Some(gdbstub);
        self
    }

    /// Returns the guest RAM size in MiB this configuration launches with.
    #[must_use]
    pub const fn memory_mib(&self) -> u32 {
        self.memory_mib
    }

    /// Returns this configuration with the World-declared VM shape.
    #[must_use]
    pub const fn with_vm_shape(mut self, memory_mib: u32, smp_vcpus: u16) -> Self {
        self.memory_mib = memory_mib;
        self.smp_vcpus = smp_vcpus;
        self
    }

    /// Returns this configuration with the deterministic scenario seed.
    #[must_use]
    pub const fn with_scenario_seed(mut self, scenario_seed: u64) -> Self {
        self.scenario_seed = scenario_seed;
        self
    }

    /// Returns this configuration with the production white-box channel set.
    #[must_use]
    pub const fn with_whitebox(mut self, whitebox: QemuLaunchPluginSwitch) -> Self {
        self.whitebox = whitebox;
        self
    }

    /// Enables exact parking at the declared network-campaign guest markers.
    #[must_use]
    pub const fn with_campaign_marker_parking(mut self) -> Self {
        self.campaign_marker_parking = true;
        self
    }

    /// Returns this configuration with the seeded app-random source set.
    #[must_use]
    pub fn with_app_random(mut self, app_random: QemuLaunchAppRandomConfig) -> Self {
        self.app_random = Some(app_random);
        self
    }

    /// Returns this configuration with a node-local guest-selectable catalog plan.
    #[must_use]
    pub fn with_selectable_catalog_plan(
        mut self,
        plan: crucible_qemu_protocol::selectable_catalog_plan::SelectableCatalogPlan,
    ) -> Self {
        self.selectable_catalog_plan = Some(plan);
        self
    }

    /// Returns the configured guest-selectable catalog plan, if present.
    #[must_use]
    pub const fn selectable_catalog_plan(
        &self,
    ) -> Option<&crucible_qemu_protocol::selectable_catalog_plan::SelectableCatalogPlan> {
        self.selectable_catalog_plan.as_ref()
    }

    /// Returns whether this launch enables the app-random white-box source.
    #[must_use]
    pub const fn app_random_configured(&self) -> bool {
        self.app_random.is_some()
    }

    /// Returns the configured app-random continuation, if enabled.
    #[must_use]
    pub const fn app_random_configuration(&self) -> Option<&QemuLaunchAppRandomConfig> {
        self.app_random.as_ref()
    }

    /// Returns this configuration with observation-only basic-block coverage.
    #[must_use]
    pub const fn with_coverage(mut self, coverage: QemuLaunchPluginSwitch) -> Self {
        self.coverage = coverage;
        self
    }

    #[cfg(target_os = "linux")]
    pub(crate) const fn requires_device_digest_workspace(&self) -> bool {
        matches!(self.fingerprint, QemuLaunchPluginSwitch::On)
    }

    pub(crate) fn original_setup_region_config(&self) -> RegionConfig {
        RegionConfig::new(1, self.queue_capacity)
    }

    #[cfg(target_os = "linux")]
    pub(crate) const fn original_process_generation(&self) -> u64 {
        self.process_generation
    }

    /// Returns this configuration with black-box execution fingerprinting set.
    #[must_use]
    pub const fn with_fingerprint(mut self, fingerprint: QemuLaunchPluginSwitch) -> Self {
        self.fingerprint = fingerprint;
        self
    }

    /// Returns this configuration with a hostless shared-memory NIC.
    #[must_use]
    pub fn with_shmem_network_mac(mut self, mac: impl Into<String>) -> Self {
        self.shmem_network_mac = Some(mac.into());
        self
    }

    /// Returns this configuration with one World-backed shared-memory block device.
    ///
    /// The immutable base image and durability contract are retained together so
    /// launch, servicing, checkpoint, and restart cannot accidentally select
    /// different storage identities.
    #[must_use]
    pub fn with_shmem_block(mut self, base: BaseImage, durability: BlockDurabilityConfig) -> Self {
        self.shmem_block = Some(QemuLiveNodeStepBlockConfig {
            world_binding: None,
            base,
            durability,
            latency: BlockLatency::default(),
            require_fault_directives: true,
        });
        self
    }

    /// Returns this configuration with an explicitly fault-free block device.
    ///
    /// Setup-time and live servicing both use the authored fault-free path, so
    /// no request can outrun a later coordinator installation.
    #[must_use]
    pub fn with_fault_free_shmem_block(
        mut self,
        base: BaseImage,
        durability: BlockDurabilityConfig,
    ) -> Self {
        self.shmem_block = Some(QemuLiveNodeStepBlockConfig {
            world_binding: None,
            base,
            durability,
            latency: BlockLatency::default(),
            require_fault_directives: false,
        });
        self
    }

    /// Returns this configuration with one World-backed shared-memory 9p device.
    #[must_use]
    pub fn with_shmem_ninep(mut self, tree: FsTree, latency: NinepLatency) -> Self {
        self.shmem_ninep = Some(QemuLiveNodeStepNinepConfig {
            world_binding: None,
            tree,
            latency,
        });
        self
    }

    /// Retains the actual World binding for the configured block queue.
    #[must_use]
    pub fn with_world_shmem_block(
        mut self,
        binding: super::QemuWorldIoBinding,
        base: BaseImage,
        durability: BlockDurabilityConfig,
    ) -> Self {
        self = self.with_shmem_block(base, durability);
        if let Some(block) = &mut self.shmem_block {
            block.world_binding = Some(binding);
        }
        self
    }

    /// Retains the actual World binding for the configured 9p queue.
    #[must_use]
    pub fn with_world_shmem_ninep(
        mut self,
        binding: super::QemuWorldIoBinding,
        tree: FsTree,
        latency: NinepLatency,
    ) -> Self {
        self = self.with_shmem_ninep(tree, latency);
        if let Some(ninep) = &mut self.shmem_ninep {
            ninep.world_binding = Some(binding);
        }
        self
    }

    /// Returns this configuration with the production accelerator device and host adapter.
    #[must_use]
    pub const fn with_accelerator(mut self) -> Self {
        self.accelerator = true;
        self
    }

    /// Returns this configuration with a per-direction shared-memory queue capacity.
    ///
    /// `capacity` must be a nonzero power of two; region construction validates
    /// the bound before QEMU is launched.
    #[must_use]
    pub const fn with_queue_capacity(mut self, capacity: u32) -> Self {
        self.queue_capacity = capacity;
        self
    }

    /// Returns this configuration with a QEMU round-robin subdivision size.
    ///
    /// The value is expressed in node icount units and becomes part of the
    /// validated deterministic launch profile used by capture and restore.
    #[must_use]
    pub const fn with_rr_switch_quantum(mut self, quantum: u64) -> Self {
        self.rr_switch_quantum = quantum;
        self
    }

    /// Returns this configuration with a different per-step completion bound.
    #[must_use]
    pub const fn with_completion_timeout(mut self, completion_timeout: Duration) -> Self {
        self.completion_timeout = completion_timeout;
        self
    }

    /// Attaches the shared execution supervisor without changing replay inputs.
    #[must_use]
    pub fn with_host_operation_supervisor(
        mut self,
        supervisor: crucible_host_resources::host_supervision::HostOperationSupervisor,
    ) -> Self {
        self.host_operation_supervisor = Some(supervisor);
        self
    }

    /// Removes originating deadline authority from an immutable replay profile.
    #[must_use]
    pub fn without_host_operation_supervisor(mut self) -> Self {
        self.host_operation_supervisor = None;
        self
    }

    /// Attaches an independently admitted live RAM owner without changing replay inputs.
    #[must_use]
    pub fn with_ram_control_registration(
        mut self,
        registration: crate::ram_control::RamControlRegistration,
    ) -> Self {
        self.ram_control_registration = Some(registration);
        self
    }

    /// Installs a separate explicit terminal-request entitlement for native tests.
    ///
    /// # Errors
    /// Rejects a zero nonce. Actual launch additionally requires an admitted RAM
    /// registration; fresh fork children never inherit this entitlement.
    #[cfg(any(test, feature = "test-support"))]
    pub fn with_fault_actor_test_entitlement(
        mut self,
        entitlement: [u8; 32],
    ) -> Result<Self, crucible_qemu_protocol::ram_control::RamControlError> {
        if entitlement == [0; 32] {
            return Err(crucible_qemu_protocol::ram_control::RamControlError::InvalidFrame);
        }
        self.fault_actor_test_entitlement = Some(entitlement);
        Ok(self)
    }

    /// Returns the explicitly authored native-test launch entitlement.
    #[cfg(any(test, feature = "test-support"))]
    #[must_use]
    pub fn fault_actor_test_entitlement(&self) -> Option<[u8; 32]> {
        self.fault_actor_test_entitlement
    }

    /// Returns the exact admitted operational launch owner.
    #[must_use]
    pub fn ram_control_registration(&self) -> Option<&crate::ram_control::RamControlRegistration> {
        self.ram_control_registration.as_ref()
    }

    /// Removes originating node ownership before a replay service admits its own launch.
    #[must_use]
    pub fn without_ram_control_registration(mut self) -> Self {
        self.ram_control_registration = None;
        self
    }

    /// Selects renewable advance polling while keeping lifecycle waits bounded.
    #[must_use]
    pub const fn with_unbounded_advance_completion(mut self, enabled: bool) -> Self {
        self.unbounded_advance_completion = enabled;
        self
    }

    /// Returns this configuration with output-only serial console capture enabled.
    #[must_use]
    pub const fn with_console_capture(mut self) -> Self {
        self.console_capture = true;
        self
    }

    /// Returns this configuration with the native RR control-boundary trace enabled.
    ///
    /// The trace is written to the fixed
    /// [`crate::QEMU_RR_CONTROL_BOUNDARY_TRACE_FILE_NAME`] beneath the pinned
    /// generation directory and is included in the authenticated command line.
    #[must_use]
    pub const fn with_rr_control_boundary_trace(mut self) -> Self {
        self.rr_control_boundary_trace = true;
        self.runtime_determinism_trace = false;
        self.runtime_liveness_trace = false;
        self
    }

    /// Returns this configuration with runtime-determinism diagnostics enabled.
    ///
    /// The fixed trace records native idle-advance and virtual-timer ordering in
    /// the pinned generation directory. It is mutually exclusive with the RR
    /// control-boundary trace and remains part of authenticated launch identity.
    #[must_use]
    pub const fn with_runtime_determinism_trace(mut self) -> Self {
        self.rr_control_boundary_trace = false;
        self.runtime_determinism_trace = true;
        self.runtime_liveness_trace = false;
        self
    }

    /// Returns this trace configuration with a pre-admitted byte ceiling.
    ///
    /// The caller must use the same ceiling when inspecting the complete
    /// pinned trace after clean QEMU reap. The global maximum is 256 MiB.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveNodeStepGateError`] if `bytes` is zero or exceeds
    /// the finite maximum.
    pub fn with_runtime_determinism_trace_budget(
        mut self,
        bytes: u64,
    ) -> Result<Self, QemuLiveNodeStepGateError> {
        if bytes == 0 || bytes > crate::launch::MAXIMUM_STREAMED_RUNTIME_DETERMINISM_TRACE_BYTES {
            return Err(QemuLiveNodeStepGateError::InvalidRuntimeTraceBudget {
                requested: bytes,
                maximum: crate::launch::MAXIMUM_STREAMED_RUNTIME_DETERMINISM_TRACE_BYTES,
            });
        }
        self.runtime_determinism_trace_budget_bytes = bytes;
        Ok(self)
    }

    /// Returns this configuration with fixed QMP monitor diagnostics.
    ///
    /// The trace shows monitor command receipt, queueing, dispatch, and reply
    /// needed to localize a bounded QMP timeout.
    #[must_use]
    pub const fn with_runtime_liveness_trace(mut self) -> Self {
        self.rr_control_boundary_trace = false;
        self.runtime_determinism_trace = false;
        self.runtime_liveness_trace = true;
        self
    }

    fn apply_diagnostic_trace(
        &self,
        command: QemuLaunchCommandBuilder,
    ) -> QemuLaunchCommandBuilder {
        if self.rr_control_boundary_trace {
            command.with_rr_control_boundary_trace()
        } else if self.runtime_determinism_trace {
            command
                .with_runtime_determinism_trace()
                .with_runtime_determinism_trace_budget(self.runtime_determinism_trace_budget_bytes)
        } else if self.runtime_liveness_trace {
            command.with_runtime_liveness_trace()
        } else {
            command
        }
    }

    /// Returns this configuration bound to one exact World fault manifest.
    #[must_use]
    pub fn with_fault_capabilities(
        mut self,
        capabilities: crucible_engine::model::WorldNodeFaultCapabilities,
    ) -> Self {
        self.fault_capabilities = Some(capabilities);
        self
    }
}

/// Borrowed exact RAM, device-state, and cancellation inputs for one restore.
///
/// The launcher duplicates `cancellation_descriptor` before it enters the
/// synchronous QMP restore and installs that same eventfd identity on the
/// returned [`QemuNode`]. The descriptor must be the attempt contract's
/// concurrently signalable cancellation event.
#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug)]
pub(crate) struct QemuExactCheckpointRestore<'a> {
    request: &'a crate::QmpCheckpointRestoreRequest,
    root_descriptor: BorrowedFd<'a>,
    device_descriptor: BorrowedFd<'a>,
    cancellation_descriptor: BorrowedFd<'a>,
}

#[cfg(target_os = "linux")]
impl<'a> QemuExactCheckpointRestore<'a> {
    /// Binds an authenticated request and its ordered descriptors.
    #[must_use]
    pub(crate) const fn new(
        request: &'a crate::QmpCheckpointRestoreRequest,
        root_descriptor: BorrowedFd<'a>,
        device_descriptor: BorrowedFd<'a>,
        cancellation_descriptor: BorrowedFd<'a>,
    ) -> Self {
        Self {
            request,
            root_descriptor,
            device_descriptor,
            cancellation_descriptor,
        }
    }
}

/// Complete validated basis for one guarded lazy RAM and device-state restore.
#[cfg(target_os = "linux")]
#[derive(Debug)]
pub(crate) struct AtomicExactRestoreAdmission<'a> {
    run_directory: &'a QemuPreparedRunDirectory,
    process_contract: &'a QemuChildProcessContract,
    identity: QemuLiveNodeIdentity<'a>,
    snapshot: &'a QemuVmSnapshot,
    ram_inputs: &'a crate::spawn::SealedAtomicExactRestoreInputs,
    device_file: File,
    cancellation_descriptor: BorrowedFd<'a>,
    exact_binding: crate::spawn::QemuExactDeviceStateBinding,
}

/// Complete borrowed basis for one guarded fresh node launch.
#[derive(Clone, Copy, Debug)]
pub struct QemuProductionFreshLaunchAdmission<'a> {
    run_directory: &'a QemuPreparedRunDirectory,
    process_contract: &'a QemuChildProcessContract,
    identity: QemuLiveNodeIdentity<'a>,
}

impl<'a> QemuProductionFreshLaunchAdmission<'a> {
    #[cfg(target_os = "linux")]
    pub(crate) fn original_node_basis(
        self,
    ) -> (&'a QemuPreparedRunDirectory, QemuLiveNodeIdentity<'a>) {
        (self.run_directory, self.identity)
    }

    pub(crate) const fn installed_process_contract(&self) -> &'a QemuChildProcessContract {
        self.process_contract
    }

    /// Seals the prepared storage, process contract, and scheduler-name basis.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveNodeStepGateError`] when the prepared directory lacks
    /// fresh artifacts or differs from the launch profile's pinned directory.
    pub fn admit(
        config: &QemuLiveNodeStepGateConfig,
        run_directory: &'a QemuPreparedRunDirectory,
        process_contract: &'a QemuChildProcessContract,
        identity: QemuLiveNodeIdentity<'a>,
    ) -> Result<Self, QemuLiveNodeStepGateError> {
        run_directory
            .require_fresh_artifacts()
            .map_err(|source| QemuLiveNodeStepGateError::Spawn { source })?;
        if run_directory.path() != config.run_directory() {
            return Err(QemuLiveNodeStepGateError::PreparedRunDirectoryMismatch {
                configured: config.run_directory().to_path_buf(),
                prepared: run_directory.path().to_path_buf(),
            });
        }
        Ok(Self {
            run_directory,
            process_contract,
            identity,
        })
    }
}

/// Launches one freshly provisioned node through a pinned process contract.
///
/// The VMState container and optional root overlay must already have been
/// created by the guarded image-tool path and sealed as fresh artifacts.
///
/// # Errors
///
/// Returns [`QemuLiveNodeStepGateError`] when fresh artifacts or launch
/// admission changed, guarded white-box setup is unavailable, process spawn or
/// setup fails, or mandatory failed-launch cleanup cannot be attested.
pub fn launch_qemu_production_fresh_node(
    config: &QemuLiveNodeStepGateConfig,
    request: QemuProductionFreshLaunchAdmission<'_>,
) -> Result<QemuNode, QemuLiveNodeStepGateError> {
    build_live_node_with_authority(
        config,
        LiveNodeAssembly {
            run_directory: request.run_directory,
            process_contract: request.process_contract,
            identity: request.identity,
            restore: None,
            resume_restored: true,
            exact_binding: None,
            #[cfg(target_os = "linux")]
            original_native_binding: None,
            #[cfg(target_os = "linux")]
            original_workspace: None,
        },
    )
}

// The original host issuer creates this witness from its live admitted slot.
// It enters the actual launch body before child or Node exposure, rather than
// authorizing a caller-supplied process identity after construction.
#[cfg(target_os = "linux")]
pub(crate) fn launch_qemu_original_fresh_node(
    config: &QemuLiveNodeStepGateConfig,
    request: QemuProductionFreshLaunchAdmission<'_>,
    binding: crate::linux_attempt_host::OriginalNativeNodeBinding,
    workspace: Option<crate::spawn::OriginalDeviceDigestWorkspace>,
) -> Result<QemuNode, QemuLiveNodeStepGateError> {
    prepare_qemu_original_fresh_node(config, request, binding, workspace)?.prime_and_build()
}

#[cfg(target_os = "linux")]
pub(crate) fn prepare_qemu_original_fresh_node<'a>(
    config: &'a QemuLiveNodeStepGateConfig,
    request: QemuProductionFreshLaunchAdmission<'a>,
    binding: crate::linux_attempt_host::OriginalNativeNodeBinding,
    workspace: Option<crate::spawn::OriginalDeviceDigestWorkspace>,
) -> Result<PausedLiveNodeLaunch<'a>, QemuLiveNodeStepGateError> {
    prepare_paused_live_node(
        config,
        LiveNodeAssembly {
            run_directory: request.run_directory,
            process_contract: request.process_contract,
            identity: request.identity,
            restore: None,
            resume_restored: true,
            exact_binding: None,
            original_native_binding: Some(binding),
            original_workspace: workspace,
        },
    )
}

#[cfg(target_os = "linux")]
impl<'a> AtomicExactRestoreAdmission<'a> {
    /// Validates and binds the prepared storage, process, snapshot, and inputs.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveNodeStepGateError`] when the prepared transaction is
    /// incomplete or any sealed input, request identity, or snapshot differs.
    pub(crate) fn admit(
        run_directory: &'a mut QemuPreparedRunDirectory,
        process_contract: &'a QemuChildProcessContract,
        identity: QemuLiveNodeIdentity<'a>,
        snapshot: &'a QemuVmSnapshot,
        snapshot_object: ContentHash,
        ram_inputs: &'a crate::spawn::SealedAtomicExactRestoreInputs,
        cancellation_descriptor: BorrowedFd<'a>,
    ) -> Result<Self, QemuLiveNodeStepGateError> {
        let exact_binding = ram_inputs.binding();
        let target = ram_inputs.target();
        if target.snapshot() != snapshot_object || target.node() != identity.node {
            return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                reason: String::from(
                    "repository-rooted target does not bind the launched node and snapshot",
                ),
            });
        }
        Self::new_with_binding(
            run_directory,
            process_contract,
            identity,
            snapshot,
            ram_inputs,
            cancellation_descriptor,
            exact_binding,
        )
    }

    pub(crate) fn new_with_binding(
        run_directory: &'a mut QemuPreparedRunDirectory,
        process_contract: &'a QemuChildProcessContract,
        identity: QemuLiveNodeIdentity<'a>,
        snapshot: &'a QemuVmSnapshot,
        ram_inputs: &'a crate::spawn::SealedAtomicExactRestoreInputs,
        cancellation_descriptor: BorrowedFd<'a>,
        exact_binding: crate::spawn::QemuExactDeviceStateBinding,
    ) -> Result<Self, QemuLiveNodeStepGateError> {
        let request = ram_inputs.request();
        if exact_binding.snapshot() != Some(ram_inputs.target().snapshot()) {
            return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                reason: String::from(
                    "authenticated exact-checkpoint root does not bind the restored snapshot",
                ),
            });
        }
        run_directory
            .validate_exact_ram_inputs(exact_binding, ram_inputs)
            .map_err(|source| QemuLiveNodeStepGateError::Spawn { source })?;
        run_directory
            .claim_exact_checkpoint_materialization(process_contract, exact_binding)
            .map_err(|source| QemuLiveNodeStepGateError::Spawn { source })?;
        let device_file = run_directory
            .exact_device_state_input(exact_binding)
            .map_err(|source| QemuLiveNodeStepGateError::Spawn { source })?;
        let restore = QemuExactCheckpointRestore::new(
            request,
            ram_inputs.root_descriptor(),
            device_file.as_fd(),
            cancellation_descriptor,
        );
        validate_exact_checkpoint_restore(snapshot, restore)?;

        Ok(Self {
            run_directory,
            process_contract,
            identity,
            snapshot,
            ram_inputs,
            device_file,
            cancellation_descriptor,
            exact_binding,
        })
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn launch_atomic_exact_restore(
    config: &QemuLiveNodeStepGateConfig,
    request: AtomicExactRestoreAdmission<'_>,
    resume_restored: bool,
    original_native_binding: crate::linux_attempt_host::OriginalNativeNodeBinding,
    original_workspace: Option<crate::spawn::OriginalDeviceDigestWorkspace>,
) -> Result<crate::node::IssuedLaunchOwner, QemuLiveNodeStepGateError> {
    let descriptors = QemuExactCheckpointRestoreDescriptors::new(
        request.ram_inputs.root_descriptor(),
        request.device_file.as_fd(),
        request.cancellation_descriptor,
    );
    let restore = QemuNodeRestorePlan::exact_checkpoint(
        request.snapshot,
        request.ram_inputs.request(),
        descriptors,
        request.ram_inputs.topology(),
        request.ram_inputs.source(),
    );
    validate_restore_descriptors(&restore)?;
    let node = prepare_paused_live_node(
        config,
        LiveNodeAssembly {
            run_directory: request.run_directory,
            process_contract: request.process_contract,
            identity: request.identity,
            restore: Some(restore),
            resume_restored,
            exact_binding: Some(request.exact_binding),
            #[cfg(target_os = "linux")]
            original_native_binding: Some(original_native_binding),
            #[cfg(target_os = "linux")]
            original_workspace,
        },
    )?
    .prime_and_build_issued()?;
    Ok(node)
}

#[cfg(target_os = "linux")]
fn validate_exact_checkpoint_restore(
    snapshot: &QemuVmSnapshot,
    restore: QemuExactCheckpointRestore<'_>,
) -> Result<(), QemuLiveNodeStepGateError> {
    validate_live_exact_snapshot(snapshot)?;
    validate_exact_checkpoint_restore_binding(snapshot, restore.request)?;
    QemuExactCheckpointRestoreDescriptors::new(
        restore.root_descriptor,
        restore.device_descriptor,
        restore.cancellation_descriptor,
    )
    .validate_immutable()
    .map_err(|error| QemuLiveNodeStepGateError::ExactSnapshotInvariant {
        reason: format!("invalid exact checkpoint descriptor set: {error}"),
    })
}

fn validate_restore_descriptors(
    restore: &QemuNodeRestorePlan<'_>,
) -> Result<(), QemuLiveNodeStepGateError> {
    restore.validate_immutable_descriptors().map_err(|error| {
        QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!("invalid exact checkpoint descriptor set: {error}"),
        }
    })
}

fn validate_live_exact_snapshot(
    snapshot: &QemuVmSnapshot,
) -> Result<(), QemuLiveNodeStepGateError> {
    let binding = snapshot.checkpoint().id;
    if !snapshot.is_live_capture()
        || !snapshot.has_valid_identity()
        || snapshot.host_io().execution_binding() != binding
        || snapshot.node_continuation().execution_binding() != binding
    {
        return Err(QemuLiveNodeStepGateError::InvalidExactSnapshot);
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_exact_checkpoint_restore_binding(
    snapshot: &QemuVmSnapshot,
    request: &crate::QmpCheckpointRestoreRequest,
) -> Result<(), QemuLiveNodeStepGateError> {
    if request.identity().checkpoint() != snapshot.checkpoint().id {
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: String::from(
                "exact RAM request identity does not name the restored host checkpoint",
            ),
        });
    }
    Ok(())
}

/// Deterministic scheduler-facing names for one live QEMU node generation.
#[derive(Clone, Copy, Debug)]
pub struct QemuLiveNodeIdentity<'a> {
    pub(super) node: &'a str,
    pub(super) router: &'a str,
    pub(super) crash_detector: &'a str,
}

impl<'a> QemuLiveNodeIdentity<'a> {
    /// Creates the three exact names consumed by a live node launch.
    #[must_use]
    pub const fn new(node: &'a str, router: &'a str, crash_detector: &'a str) -> Self {
        Self {
            node,
            router,
            crash_detector,
        }
    }
}

struct LiveNodeAssembly<'a> {
    run_directory: &'a QemuPreparedRunDirectory,
    process_contract: &'a QemuChildProcessContract,
    identity: QemuLiveNodeIdentity<'a>,
    restore: Option<QemuNodeRestorePlan<'a>>,
    resume_restored: bool,
    exact_binding: Option<crate::spawn::QemuExactDeviceStateBinding>,
    #[cfg(target_os = "linux")]
    original_native_binding: Option<crate::linux_attempt_host::OriginalNativeNodeBinding>,
    #[cfg(target_os = "linux")]
    original_workspace: Option<crate::spawn::OriginalDeviceDigestWorkspace>,
}

fn build_live_node_with_authority<'a>(
    config: &'a QemuLiveNodeStepGateConfig,
    assembly: LiveNodeAssembly<'a>,
) -> Result<QemuNode, QemuLiveNodeStepGateError> {
    prepare_paused_live_node(config, assembly)?.prime_and_build()
}

fn prepare_paused_live_node<'a>(
    config: &'a QemuLiveNodeStepGateConfig,
    assembly: LiveNodeAssembly<'a>,
) -> Result<PausedLiveNodeLaunch<'a>, QemuLiveNodeStepGateError> {
    let LiveNodeAssembly {
        run_directory,
        process_contract,
        identity,
        restore,
        resume_restored,
        exact_binding,
        #[cfg(target_os = "linux")]
        original_native_binding,
        #[cfg(target_os = "linux")]
        original_workspace,
    } = assembly;
    #[cfg(target_os = "linux")]
    let has_workspace = original_workspace.is_some();
    #[cfg(not(target_os = "linux"))]
    let has_workspace = false;
    if config.fingerprint == QemuLaunchPluginSwitch::On && !has_workspace {
        return Err(QemuLiveNodeStepGateError::DeviceDigestWorkspaceUnavailable);
    }
    // Keep the final cleanup declaration outside all later physical owners.
    let mut launch_cleanup = None;
    let enclosing_supervisor = match &config.host_operation_supervisor {
        Some(supervisor) => supervisor.clone(),
        None => {
            use crucible_host_resources::host_supervision::{
                HostOperationBudget, HostOperationBudgets, HostOperationClass,
                HostOperationSupervisor,
            };
            let mut budgets = HostOperationBudgets::default();
            budgets.classes[HostOperationClass::Quantum as usize] =
                if config.unbounded_advance_completion {
                    HostOperationBudget::unlimited_quantum()
                } else {
                    HostOperationBudget::finite(config.completion_timeout)
                };
            HostOperationSupervisor::new(budgets, None).map_err(|source| {
                QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                    reason: format!("configure host operation supervision: {source}"),
                }
            })?
        }
    };
    let budgets = match config.ram_control_registration.as_ref() {
        Some(registration) => registration.initial_policy.latency,
        None => {
            enclosing_supervisor
                .budgets()
                .map_err(|source| QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                    reason: format!("observe original resident node budgets: {source}"),
                })?
                .1
        }
    };
    #[cfg(target_os = "linux")]
    let source_admission = original_native_binding
        .as_ref()
        .map(|binding| {
            binding.prepare_source_admission(
                process_contract,
                &enclosing_supervisor,
                config.process_generation,
                budgets,
            )
        })
        .transpose()
        .map_err(|source| {
            QemuLiveNodeStepGateError::PluginStartup(
                crate::spawn::OriginalPluginStartup::admission_refusal(source),
            )
        })?;
    #[cfg(target_os = "linux")]
    let operation_supervisor = source_admission.as_ref().map_or_else(
        || enclosing_supervisor.clone(),
        |source| source.supervisor().clone(),
    );
    #[cfg(not(target_os = "linux"))]
    let operation_supervisor = enclosing_supervisor;
    #[cfg(target_os = "linux")]
    if let Some(admission) = source_admission.as_ref() {
        launch_cleanup = Some(
            crate::launch_cleanup::LaunchCleanup::new_source(
                config.ram_control_registration.as_ref(),
                admission,
            )
            .map_err(|source| QemuLiveNodeStepGateError::OriginalNativeAccount { source })?,
        );
        original_native_binding
            .as_ref()
            .ok_or(QemuLiveNodeStepGateError::DeviceDigestWorkspaceUnavailable)?
            .retain_launch_cleanup(
                launch_cleanup
                    .as_ref()
                    .ok_or(QemuLiveNodeStepGateError::DeviceDigestWorkspaceUnavailable)?,
            )
            .map_err(|source| QemuLiveNodeStepGateError::OriginalNativeAccount { source })?;
    } else if let Some(registration) = config.ram_control_registration.as_ref() {
        launch_cleanup = Some(crate::launch_cleanup::LaunchCleanup::new(registration));
    }
    // Selected initial Source uses its actual admission in every RAM mode.
    // Component launches retain their ordinary supervision and issue no token.
    #[cfg(target_os = "linux")]
    let mut original_plugin_startup = source_admission
        .as_ref()
        .map(|admission| {
            crate::spawn::OriginalPluginStartup::prepare(
                &operation_supervisor,
                process_contract,
                config.ram_control_registration.as_ref(),
                config.process_generation,
                original_native_binding.as_ref(),
                Some(admission),
            )
        })
        .transpose()
        .map_err(QemuLiveNodeStepGateError::PluginStartup)?;
    #[cfg(not(target_os = "linux"))]
    let mut original_plugin_startup: Option<crate::spawn::OriginalPluginStartup> = None;
    #[cfg(target_os = "linux")]
    if let Some(workspace) = original_workspace {
        let startup = original_plugin_startup
            .as_mut()
            .ok_or(QemuLiveNodeStepGateError::DeviceDigestWorkspaceUnavailable)?;
        startup.retain_workspace(workspace)?;
    }
    let restoring_checkpoint = restore.is_some();
    let run_directory_path = run_directory.path();
    #[cfg(target_os = "linux")]
    let checkpoint_cancellation = retain_checkpoint_operation_cancellation(
        process_contract,
        restore
            .as_ref()
            .map(QemuNodeRestorePlan::exact_checkpoint_cancellation),
    )?;
    if let Some(exact_binding) = exact_binding {
        run_directory
            .require_exact_device_state(exact_binding)
            .map_err(|source| QemuLiveNodeStepGateError::Spawn { source })?;
        if config.resource_requirements().has_root_overlay() {
            run_directory
                .require_exact_root_overlay(exact_binding)
                .map_err(|source| QemuLiveNodeStepGateError::Spawn { source })?;
        }
    } else {
        run_directory
            .require_fresh_artifacts()
            .map_err(|source| QemuLiveNodeStepGateError::Spawn { source })?;
    }
    if run_directory_path != config.run_directory() {
        return Err(QemuLiveNodeStepGateError::PreparedRunDirectoryMismatch {
            configured: config.run_directory().to_path_buf(),
            prepared: run_directory_path.to_path_buf(),
        });
    }
    let debug_guest_activation_listener = (config.whitebox == QemuLaunchPluginSwitch::On)
        .then(|| {
            run_directory
                .bind_child_owned_socket(crate::QEMU_DEBUG_GUEST_ACTIVATION_SOCKET_FILE_NAME)
                .map_err(|source| std::io::Error::other(source.to_string()))
        })
        .transpose()
        .map_err(|source| {
            QemuLiveNodeStepGateError::prime(
                "bind debug guest activation listener",
                QemuNodeChannelError::new(
                    "bind debug guest activation listener",
                    source.to_string(),
                ),
            )
        })?;

    let mut candidate = launch_profile_candidate(config.architecture)
        .with_memory_mib(config.memory_mib)
        .with_smp_vcpus(config.smp_vcpus)
        .with_rr_switch_quantum(config.rr_switch_quantum)
        .with_scenario_seed(config.scenario_seed);
    if let Some(cmdline) = &config.kernel_cmdline {
        candidate = candidate.with_kernel_cmdline(cmdline.clone());
    }
    let profile = candidate
        .try_into_deterministic()
        .map_err(|source| QemuLiveNodeStepGateError::LaunchProfile { source })?;
    profile
        .guest_entropy_seed_file()
        .write_to_dir(run_directory_path)
        .map_err(|source| QemuLiveNodeStepGateError::GuestEntropySeed {
            path: run_directory_path.to_path_buf(),
            source,
        })?;

    let qmp_config = QemuQmpChannelConfig::new(GATE_QMP_SOCKET_FILE_NAME)
        .map_err(|source| QemuLiveNodeStepGateError::QmpChannelConfig { source })?;
    let vm = vm_launch_config(config, identity.node);
    let mut plugin = live_node_plugin_config(
        config,
        &profile,
        &vm,
        identity.node,
        Some((run_directory, process_contract)),
    )?;
    if let Some(startup) = &original_plugin_startup {
        plugin = plugin.with_original_startup(startup)?;
    }
    if let Some(registration) = &config.ram_control_registration {
        use std::io::Read;
        let mut session = [0; 32];
        std::fs::File::open("/dev/urandom")
            .and_then(|mut entropy| entropy.read_exact(&mut session))
            .map_err(|source| QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                reason: format!("create independent RAM controller session: {source}"),
            })?;
        plugin = plugin
            .with_fault_actor_test_entitlement(config.fault_actor_test_entitlement)
            .with_ram_resources(registration.resources)
            .with_ram_spill_quota(registration.spill_quota_bytes)
            .with_ram_control(crate::QemuRamControlLaunch {
                session,
                target: crate::ram_control::target_to_wire(registration.target),
            });
    }
    let mut command = match (
        &config.fault_capabilities,
        &config.exact_gate_fault_manifests,
    ) {
        (Some(capabilities), None) => {
            let requirement = crate::QemuFaultCapabilityRequirement::current_v1_for_node(
                capabilities,
            )
            .map_err(|_source| QemuLiveNodeStepGateError::LaunchCommand {
                source: QemuLaunchCommandError::InvalidFaultCapabilityRequirement,
            })?;
            QemuLaunchCommandBuilder::new(
                profile,
                vm,
                path_text(&config.qemu_executable),
                plugin,
                requirement,
            )
        }
        (None, Some(manifests)) => {
            let requirement = crate::QemuFaultCapabilityRequirement::exact_live_gate_v1(
                config.architecture,
                profile.cpu_model().to_owned(),
                identity.node,
                manifests,
            )
            .map_err(|_source| QemuLiveNodeStepGateError::LaunchCommand {
                source: QemuLaunchCommandError::InvalidFaultCapabilityRequirement,
            })?;
            QemuLaunchCommandBuilder::new_for_exact_live_gate(
                profile,
                vm,
                path_text(&config.qemu_executable),
                plugin,
                requirement,
            )
            .map_err(|source| QemuLiveNodeStepGateError::LaunchCommand { source })?
        }
        (None, None) => QemuLaunchCommandBuilder::new_for_live_gate(
            profile,
            vm,
            path_text(&config.qemu_executable),
            plugin,
            config.architecture,
        ),
        (Some(_), Some(_)) => {
            return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                reason: String::from(
                    "World and gate-replay capability manifests were both configured",
                ),
            });
        }
    }
    .with_qmp(qmp_config.clone());
    if config.whitebox == QemuLaunchPluginSwitch::On {
        command = command.with_debug_guest_activation_endpoint();
    }
    if let Some(gdbstub) = &config.gdbstub {
        command = command.with_gdbstub(gdbstub.clone());
    }
    if config.console_capture {
        command = command.with_console_capture();
    }
    command = config.apply_diagnostic_trace(command);
    let command = command
        .build()
        .map_err(|source| QemuLiveNodeStepGateError::LaunchCommand { source })?;
    if config.rr_control_boundary_trace {
        run_directory
            .prepare_rr_control_boundary_trace()
            .map_err(|source| QemuLiveNodeStepGateError::Spawn { source })?;
    } else if config.runtime_determinism_trace || config.runtime_liveness_trace {
        run_directory
            .prepare_runtime_determinism_trace()
            .map_err(|source| QemuLiveNodeStepGateError::Spawn { source })?;
    }

    let region_config = config.original_setup_region_config();
    let layout = crucible_qemu_shmem::validate_layout_target()
        .and_then(|()| RegionLayout::for_config(region_config))
        .map_err(|source| QemuLiveNodeStepGateError::RegionLayout { source })?;
    #[cfg(target_os = "linux")]
    if let Some(startup) = original_plugin_startup.as_mut() {
        startup.begin_workspace_handover()?;
    }
    let preexec = match (
        original_plugin_startup.as_ref(),
        original_native_binding.as_ref(),
        config.ram_control_registration.as_ref(),
    ) {
        (Some(startup), Some(binding), registration) => {
            Some(crate::spawn::preexec_setup::BorrowedPreexecSetup {
                startup,
                binding,
                registration,
                supervisor: &operation_supervisor,
                region_config,
            })
        }
        (None, None, None) => None,
        _ => return Err(QemuLiveNodeStepGateError::DeviceDigestWorkspaceUnavailable),
    };
    let mut child_return = launch_cleanup
        .as_ref()
        .ok_or(QemuLiveNodeStepGateError::OriginalNativeAccount {
            source: crate::OriginalActorAccountError::Unavailable,
        })?
        .reserve_source_child_owner(operation_supervisor.clone())
        .map_err(|source| QemuLiveNodeStepGateError::OriginalNativeAccount { source })?;
    let spawned = spawn_prepared_qemu_child_with_preexec(
        &command,
        run_directory,
        layout.region_size,
        process_contract,
        config
            .ram_control_registration
            .as_ref()
            .map(|registration| &registration.host_services),
        launch_cleanup.clone(),
        preexec,
        Some(&mut child_return),
    )
    .map_err(|source| QemuLiveNodeStepGateError::Spawn { source })?;
    let (child, mut resources) = spawned.into_parts();
    let mut child = child_return.born(child);
    // Publish successful birth before any later host cut can refuse.
    if let Some(startup) = original_plugin_startup.take() {
        child
            .child_mut()
            .map_err(|first| {
                QemuLiveNodeStepGateError::node_op("retain issued child startup", first)
            })?
            .retain_original_plugin_startup(startup);
    }
    let launch_service_lease = resources.host_service_lease().cloned();
    let ram_control_endpoint = resources.take_ram_control_socket();
    if let Some(restore) = &restore {
        let socket = resources.take_ram_source_socket().ok_or_else(|| {
            QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                reason: String::from("restored process has no owned RAM source transport"),
            }
        });
        let socket = match socket {
            Ok(socket) => socket,
            Err(error) => {
                return Err(reap_failed_live_node_child(child, error));
            }
        };
        let source = restore.ram_source();
        match child.publish_ram_source(
            socket,
            source.backing(),
            source.binding(),
            operation_supervisor.clone(),
            config
                .ram_control_registration
                .as_ref()
                .ok_or_else(|| QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                    reason: String::from("restored process lacks admitted host service capacity"),
                })?
                .host_services
                .clone(),
        ) {
            Ok(()) => {}
            Err(error) => {
                return Err(reap_failed_live_node_child(
                    child,
                    QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                        reason: format!("start retained RAM source: {error}"),
                    },
                ));
            }
        }
    }

    let mut admitted_registration = config.ram_control_registration.clone();
    #[cfg(target_os = "linux")]
    match child
        .child_mut()
        .map_err(|first| QemuLiveNodeStepGateError::node_op("borrow issued child startup", first))?
        .device_digest_workspace_setup_view()
    {
        Ok(Some(body)) => resources.retain_device_digest_workspace(body),
        Ok(None) => {}
        Err(source) => {
            return Err(reap_failed_live_node_child(
                child,
                QemuLiveNodeStepGateError::PluginStartup(source),
            ));
        }
    }
    let (mut child, setup) = complete_host_setup_or_reap(child, || {
        complete_qemu_host_plugin_setup_with_plugin_setup_plan(
            resources.into_setup_resources(),
            region_config,
            GATE_SLOT,
            command.fault_capability_requirement(),
            command.plugin_setup_plan(),
        )
    })?;

    macro_rules! launch_try {
        ($result:expr) => {
            match $result {
                Ok(value) => value,
                Err(primary) => return Err(reap_failed_live_node_child(child, primary)),
            }
        };
    }

    let debug_guest_activation_stream = launch_try!(
        debug_guest_activation_listener
            .map(|listener| listener.accept_from(child.process_id()))
            .transpose()
            .map_err(|source| {
                QemuLiveNodeStepGateError::prime(
                    "accept debug guest activation stream",
                    QemuNodeChannelError::new(
                        "accept debug guest activation stream",
                        source.to_string(),
                    ),
                )
            })
    );
    let console_observation = launch_try!(
        config
            .console_capture
            .then(|| {
                // QEMU realizes chardevs before the plugin publishes its setup ACK,
                // so a missing socket here is a launch failure rather than a race.
                crate::unix_socket_path::connect(
                    &run_directory_path.join(crate::QEMU_CONSOLE_SOCKET_FILE_NAME),
                )
            })
            .transpose()
            .map_err(|source| {
                QemuLiveNodeStepGateError::prime(
                    "connect console observation",
                    QemuNodeChannelError::new("connect QEMU console stream", source.to_string()),
                )
            })
    );

    let console_spool = console_observation
        .as_ref()
        .map(|_stream| QemuConsoleObservationSpool::new());
    let runtime = launch_try!(
        QemuLiveHostIoRuntime::from_shmem_fd(
            setup.shmem_as_fd(),
            setup.wake_as_fd(),
            setup.region().region_len,
            GATE_SLOT,
        )
        .map_err(|source| QemuLiveNodeStepGateError::HostIoRuntime { source })
    );
    #[cfg(target_os = "linux")]
    let runtime = match launch_try!(
        child
            .child_mut()
            .map_err(|source| {
                QemuLiveNodeStepGateError::node_op("borrow issued child Source", source)
            })
            .and_then(|child| {
                child
                    .standing_source_supervision()
                    .map_err(QemuLiveNodeStepGateError::PluginStartup)
            })
    ) {
        Some(source) => launch_try!(runtime.with_source_supervision(source).map_err(|error| {
            QemuLiveNodeStepGateError::prime(
                "bind action Source",
                QemuNodeChannelError::new("bind action Source", error.to_string()),
            )
        })),
        None => runtime,
    };
    let runtime = runtime
        .with_host_operation_supervisor(operation_supervisor.clone())
        .with_launch_cleanup(launch_cleanup.clone());
    let mut runtime = match (console_observation, console_spool.as_ref()) {
        (Some(output), Some(spool)) => {
            let reader = launch_try!(
                QemuConsoleObservationReader::new(output, spool.clone()).map_err(|source| {
                    QemuLiveNodeStepGateError::prime(
                        "configure console observation",
                        QemuNodeChannelError::new(
                            "configure QEMU console stream",
                            source.to_string(),
                        ),
                    )
                })
            );
            launch_try!(
                runtime
                    .with_console_observation(reader)
                    .map_err(|source| QemuLiveNodeStepGateError::HostIoRuntime { source })
            )
        }
        (None, None) => runtime,
        _ => {
            return Err(reap_failed_live_node_child(
                child,
                QemuLiveNodeStepGateError::prime(
                    "configure console observation",
                    QemuNodeChannelError::new(
                        "configure QEMU console stream",
                        "console stream and staging spool disagreed",
                    ),
                ),
            ));
        }
    };
    let block_servicer = if let Some(block) = &config.shmem_block {
        let mut servicer = launch_try!(
            match &block.world_binding {
                Some(binding) =>
                    QemuLiveBlockIoServicer::from_shmem_fd_with_base_and_latency_and_binding(
                        setup.shmem_as_fd(),
                        setup.region().region_len,
                        GATE_SLOT,
                        block.base.clone(),
                        BlockLatency::default(),
                        binding.clone(),
                    ),
                None => QemuLiveBlockIoServicer::from_shmem_fd_with_base(
                    setup.shmem_as_fd(),
                    setup.region().region_len,
                    GATE_SLOT,
                    block.base.clone(),
                ),
            }
            .map_err(|source| QemuLiveNodeStepGateError::BlockServicer { source })
        );
        launch_try!(
            servicer
                .configure_storage_faults(block.durability.clone(), block.require_fault_directives)
                .map_err(|source| QemuLiveNodeStepGateError::BlockServicer { source })
        );
        Some(servicer)
    } else {
        None
    };
    let ninep_servicer = launch_try!(
        config
            .shmem_ninep
            .as_ref()
            .map(|ninep| {
                match &ninep.world_binding {
                    Some(binding) => QemuLive9pIoServicer::from_shmem_fd_with_tree_and_binding(
                        setup.shmem_as_fd(),
                        setup.region().region_len,
                        GATE_SLOT,
                        ninep.tree.clone(),
                        ninep.latency,
                        binding.clone(),
                    ),
                    None => QemuLive9pIoServicer::from_shmem_fd_with_tree(
                        setup.shmem_as_fd(),
                        setup.region().region_len,
                        GATE_SLOT,
                        ninep.tree.clone(),
                        ninep.latency,
                    ),
                }
            })
            .transpose()
            .map_err(|source| QemuLiveNodeStepGateError::NinepServicer { source })
    );
    let accelerator_servicer = launch_try!(
        config
            .accelerator
            .then(|| {
                QemuLiveAcceleratorServicer::from_shmem_fd(
                    setup.shmem_as_fd(),
                    setup.region().region_len,
                    GATE_SLOT,
                )
            })
            .transpose()
            .map_err(|source| QemuLiveNodeStepGateError::AcceleratorServicer { source })
    );
    let boot_backpressure_payload = (!restoring_checkpoint)
        .then_some(config.boot_network_backpressure_capture.as_ref())
        .flatten()
        .map(|capture| capture.payload.as_slice());
    let prepared_priming = launch_try!(prepare_guest_prime(
        &setup,
        identity,
        config.coverage,
        boot_backpressure_payload,
    ));
    // Callback registration installs the RAM controller only after SIM setup.
    // Its inventory is sealed at machine_creation_done, which cannot run until
    // the mapped plugin boot barrier is released. The first ceiling above only
    // releases that installation barrier: QEMU remains stopped by -S until the
    // authenticated inventory grant and QMP validation below have completed.
    let mut ram_controller = if let Some(registration) = &admitted_registration {
        let client = ram_control_endpoint
            .map(|(stream, launch)| {
                crate::ram_control::RamControlClient::connect_supervised(
                    stream,
                    launch.session,
                    registration.target,
                    operation_supervisor.clone(),
                )
            })
            .transpose()
            .map_err(|source| QemuLiveNodeStepGateError::RamAdmission {
                operation: "authenticate independent RAM controller",
                source,
            });
        match client {
            Ok(client) => client,
            Err(error) => {
                return Err(reap_failed_live_node_child(child, error));
            }
        }
    } else {
        None
    };
    if let (Some(client), Some(cleanup)) = (&mut ram_controller, &launch_cleanup) {
        client.retain_launch_cleanup(cleanup.clone());
    }

    if let Some(registration) = admitted_registration.as_mut() {
        let grant = (|| {
            let client = ram_controller.as_mut().ok_or_else(|| {
                QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                    reason: String::from("admitted process has no independent RAM controller"),
                }
            })?;
            client
                .retain_host_service_lease(launch_service_lease.clone().ok_or_else(|| {
                    QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                        reason: String::from(
                            "RAM controller lacks retained host descriptor authority",
                        ),
                    }
                })?)
                .map_err(|source| QemuLiveNodeStepGateError::RamAdmission {
                    operation: "retain RAM control descriptor authority",
                    source,
                })?;
            let inventory =
                client
                    .inventory()
                    .map_err(|source| QemuLiveNodeStepGateError::RamAdmission {
                        operation: "authenticate complete native RAM inventory",
                        source,
                    })?;
            let resources = registration
                .registrar
                .admit_inventory(crate::ram_control::RamInventoryAdmission {
                    target: registration.target,
                    expected_initial: registration.resources,
                    declared_ram_bytes: registration.initial_policy.resident_target_bytes,
                    topology: &inventory.topology,
                    native_metadata_bytes: inventory.report.native_metadata_bytes,
                    native_scratch_bytes: inventory.report.native_scratch_bytes,
                    rust_metadata_required_bytes: inventory.report.rust_metadata_required_bytes,
                    owner_resources: inventory.report.owner_resources,
                })
                .map_err(|source| QemuLiveNodeStepGateError::RamAdmission {
                    operation: "admit actual native RAM inventory",
                    source,
                })?;
            if let Some(cleanup) = &launch_cleanup {
                cleanup.update_resources(resources).map_err(|source| {
                    QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                        reason: format!("retain exact unpublished RAM grant: {source}"),
                    }
                })?;
            }
            let spill_quota_bytes = crate::ram_admission::private_spill_quota_bytes(
                &inventory.topology,
            )
            .map_err(|source| QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                reason: format!("retain exact native spill partition: {source}"),
            })?;
            client
                .grant_inventory(&inventory, resources, spill_quota_bytes)
                .map_err(|source| QemuLiveNodeStepGateError::RamAdmission {
                    operation: "grant admitted native RAM resources",
                    source,
                })?;
            Ok((resources, spill_quota_bytes))
        })();
        match grant {
            Ok((resources, spill_quota_bytes)) => {
                registration.resources = resources;
                registration.spill_quota_bytes = spill_quota_bytes;
            }
            Err(error) => {
                return Err(reap_failed_live_node_child(child, error));
            }
        }
    }

    if let Some(registration) = &admitted_registration {
        runtime = runtime.with_ram_control_registration(registration.clone());
    }

    let mut qmp = launch_try!(
        crate::QemuQmpVmStateControlChannel::connect_unix_socket_supervised_with_policies(
            qmp_config.socket_path(run_directory_path),
            crate::QmpJobPollPolicy::default(),
            crate::QmpIoTimeoutPolicy::from_command_timeout(config.completion_timeout),
            operation_supervisor.clone(),
        )
        .map_err(|source| QemuLiveNodeStepGateError::QmpConnect { source })
    );
    if command.resource_requirements().has_root_overlay() {
        // Sealing must reopen the admitted root read-only through its original
        // RO/RW fdset pair. The same channel retires that pair after sealing.
        qmp.retain_guarded_launch_fdsets_until_disk_seal();
    } else {
        launch_try!(
            qmp.adopt_guarded_launch_fdsets(false)
                .map_err(|source| QemuLiveNodeStepGateError::QmpLaunchFdsetAdoption { source })
        );
    }
    let realized_projection_manifest = launch_try!(
        qmp.query_fingerprint_projection_manifest()
            .map_err(|source| QemuLiveNodeStepGateError::FingerprintProjectionManifest { source })
    );
    let expected_projection_manifest = command.fingerprint_projection_manifest();
    if &realized_projection_manifest != expected_projection_manifest {
        return Err(reap_failed_live_node_child(
            child,
            QemuLiveNodeStepGateError::FingerprintProjectionManifest {
                source: QemuNodeChannelError::new(
                    "authenticate realized fingerprint projection manifest",
                    format!(
                        "expected schema/count/digest {}/{}/{}, observed {}/{}/{}; first difference: {}",
                        expected_projection_manifest.schema_version,
                        expected_projection_manifest.sections,
                        expected_projection_manifest.digest,
                        realized_projection_manifest.schema_version,
                        realized_projection_manifest.sections,
                        realized_projection_manifest.digest,
                        expected_projection_manifest
                            .first_difference(&realized_projection_manifest),
                    ),
                ),
            },
        ));
    }
    Ok(PausedLiveNodeLaunch {
        child,
        setup,
        qmp,
        runtime,
        block_servicer,
        ninep_servicer,
        accelerator_servicer,
        prepared_priming,
        debug_guest_activation_stream,
        console_spool,
        ram_controller,
        admitted_registration,
        operation_supervisor,
        #[cfg(target_os = "linux")]
        original_native_binding,
        #[cfg(target_os = "linux")]
        checkpoint_cancellation,
        config,
        identity,
        restore,
        resume_restored,
        restoring_checkpoint,
        boot_backpressure_payload,
        launch_cleanup,
    })
}

#[cfg(target_os = "linux")]
fn retain_checkpoint_operation_cancellation(
    process_contract: &QemuChildProcessContract,
    exact_restore_cancellation: Option<BorrowedFd<'_>>,
) -> Result<std::os::fd::OwnedFd, QemuLiveNodeStepGateError> {
    let retained = process_contract
        .try_clone_cancellation_event()
        .map_err(|source| QemuLiveNodeStepGateError::Spawn { source })?;
    if let Some(restore) = exact_restore_cancellation {
        require_same_checkpoint_cancellation(retained.as_fd(), restore)?;
    }
    Ok(retained)
}

#[cfg(target_os = "linux")]
fn require_same_checkpoint_cancellation(
    retained: BorrowedFd<'_>,
    restore: BorrowedFd<'_>,
) -> Result<(), QemuLiveNodeStepGateError> {
    use std::os::fd::AsRawFd as _;

    let retained_identity = crate::node::eventfd_id(retained.as_raw_fd())
        .map_err(|source| QemuLiveNodeStepGateError::CheckpointCancellation { source })?;
    let restore_identity = crate::node::eventfd_id(restore.as_raw_fd())
        .map_err(|source| QemuLiveNodeStepGateError::CheckpointCancellation { source })?;
    if retained_identity != restore_identity {
        return Err(QemuLiveNodeStepGateError::CheckpointCancellation {
            source: std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "exact restore cancellation differs from the process contract",
            ),
        });
    }
    Ok(())
}

fn reap_failed_live_node_child(
    mut child: crate::node::IssuedLaunchOwner,
    primary: QemuLiveNodeStepGateError,
) -> QemuLiveNodeStepGateError {
    match child.retry_cleanup() {
        Ok(()) => primary,
        Err(cleanup) => child.retain_cleanup_failure(QemuLiveNodeStepGateError::FailedCleanup {
            primary: Box::new(primary),
            cleanup,
        }),
    }
}

fn complete_host_setup_or_reap<T>(
    child: crate::node::IssuedLaunchOwner,
    complete: impl FnOnce() -> Result<T, QemuHostPluginSetupError>,
) -> Result<(crate::node::IssuedLaunchOwner, T), QemuLiveNodeStepGateError> {
    match complete() {
        Ok(setup) => Ok((child, setup)),
        Err(source) => Err(reap_failed_live_node_child(
            child,
            QemuLiveNodeStepGateError::HostSetup { source },
        )),
    }
}

pub(crate) fn resume_restored_exact_node(
    mut owner: crate::node::IssuedLaunchOwner,
) -> Result<crate::node::IssuedLaunchOwner, QemuLiveNodeStepGateError> {
    let result = owner.node_mut().and_then(QemuNode::resume_after_restore);
    if let Err(source) = result {
        let primary = QemuLiveNodeStepGateError::Step {
            operation: "resume repository-restored exact node",
            source,
        };
        return Err(reap_failed_live_node_child(owner, primary));
    }
    Ok(owner)
}

#[path = "node_step_gate/support.rs"]
mod support;

#[cfg(test)]
#[path = "node_step_gate/setup_failure_tests.rs"]
mod setup_failure_tests;

use support::*;
