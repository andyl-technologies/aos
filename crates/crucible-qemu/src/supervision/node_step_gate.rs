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
//!   -> connect QemuQmpVmStateControlChannel over the QMP unix socket
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

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crucible::model::{FaultActionCommitError, FaultActionSink, FaultResourceLimits};
use crucible::{
    AdvanceOutcome, BackendInput, BasicBlockCoverageConfig, Checkpoint, CheckpointKind,
    ContentHash, ExecutionFingerprint, Icount, NodeId, SchedulerError, SchedulerNodeId,
    SchedulerSendAuthorization, SchedulerSendAuthorizer, VirtualTime,
};
use crucible_device::block::{BaseImage, BlockDurabilityConfig, BlockLatency};
use crucible_device::{FsTree, NinepLatency};
use crucible_shmem::{
    DequeuedFaultResult, FAULT_COMMAND_ABI_MAJOR, FAULT_COMMAND_ABI_MINOR, FAULT_COMMAND_FLAG_NONE,
    FAULT_COMMAND_FLAG_PREPARE_ONLY, FAULT_COMMAND_SEMANTIC_VERSION, FaultBoundaryPhase,
    FaultCommandHeaderV1, FaultCommandKind, FaultResultStatus, FrameDeliveryState,
    NODE_FAULT_POLICY_JSON_MAGIC_V1, NodeFaultEvidenceV1, NodeFaultFieldV1, NodeFaultOperationV1,
    NodeFaultPayloadV1, NodeFaultTargetKindV1, RegionAllocation, RegionConfig, SLOT_NET_ROUTER,
    mmap_setup_region, node_fault_field,
};

use crate::console_observation::{QemuConsoleObservationReader, QemuConsoleObservationSpool};
use crate::supervision::{
    BlockIoDiagnostics, NinepIoDiagnostics, QemuLive9pIoServicer, QemuLiveAcceleratorServicer,
    QemuLiveBlockIoServicer, QemuLiveHostIoRuntime,
};
use crate::{
    CrucibleAcceleratorDevice, CrucibleShmem9pDevice, CrucibleShmemBlockDevice,
    CrucibleShmemNetworkDevice, IcountShiftSetting, LaunchProfileCandidate, LaunchProfileError,
    LivePluginGuestArchitecture, ProductionFaultActionSink, ProductionFaultRuntime,
    QemuAsyncDriverPolicy, QemuCrashDetector, QemuGdbstubChannelConfig, QemuHostPluginSetupError,
    QemuLaunchAppRandomConfig, QemuLaunchArtifact, QemuLaunchCommandBuilder,
    QemuLaunchCommandError, QemuLaunchPluginConfig, QemuLaunchPluginSwitch,
    QemuMappedQuantumShmemHotPath, QemuMappedQuantumShmemHotPathError, QemuNode,
    QemuNodeChannelError, QemuNodeError, QemuNodeFactoryError, QemuNodeFactoryRuntime,
    QemuNodeRestorePlan, QemuNodeSet, QemuQmpChannelConfig, QemuQuantumShmemConfig,
    QemuRootImageFormat, QemuShmemHotPathChannel, QemuShutdownPolicy, QemuVmLaunchConfig,
    QemuVmSnapshot, QemuWhiteboxSetupError, QmpError, build_qemu_node_from_completed_setup,
    build_qemu_node_from_restored_checkpoint, build_qemu_node_from_restored_checkpoint_paused,
    complete_qemu_host_plugin_setup, spawn_qemu_child_with_fds_in_directory,
};

use super::QemuLiveHostIoRuntimeError;

mod error;
pub use error::QemuLiveNodeStepGateError;
mod exact_snapshot;
pub use exact_snapshot::{
    QemuLiveRetainedNetworkSnapshotReport, run_qemu_live_exact_snapshot_gate,
    run_qemu_live_retained_network_snapshot_gate,
};

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
/// QMP socket file created in the run directory for VMState control.
const GATE_QMP_SOCKET_FILE_NAME: &str = "crucible-live-node-step-qmp.sock";
/// Stable crash-detector node identifier.
const GATE_CRASH_NODE_ID: &str = "live-node-step";
/// Bound on how many times one ceiling may be re-issued before the runner treats
/// a stalled step as a wake defect rather than looping indefinitely.
const MAX_REISSUES_PER_CEILING: u32 = 64;
/// Cadence at which the QMP-connect primer pulses the plugin wake eventfd to keep
/// the QEMU main loop iterating so it can service the capabilities handshake.
const QMP_PRIMER_WAKE_INTERVAL: Duration = Duration::from_millis(10);
/// Ceiling for the boot-barrier priming quantum. Small relative to the first busy
/// ceiling so the node's first real advance is a normal forward step, but nonzero
/// so the guest actually executes off the boot barrier and parks between quanta
/// (which releases the BQL and lets QEMU's main loop service QMP).
const PRIME_CEILING_ICOUNT: u64 = 1_000_000;
/// Host poll interval while waiting for the priming quantum to reach its ceiling.
const PRIME_POLL_INTERVAL: Duration = Duration::from_millis(1);

/// The busy-window ceiling schedule that drives one node-step scenario.
///
/// The schedule produces ceilings `step, 2*step, ..., count*step`, all of which
/// must stay strictly below [`Self::busy_cap_icount`] so the guest never idles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuLiveNodeStepSchedule {
    /// Fixed icount increment between successive busy-window ceilings.
    pub ceiling_step_icount: u64,
    /// Number of bounded steps the runner drives.
    pub step_count: u32,
    /// Exclusive upper bound every ceiling must stay below to remain busy.
    pub busy_cap_icount: u64,
}

impl QemuLiveNodeStepSchedule {
    /// Builds a schedule tuned for the diskless-firmware idle onset (~15.8M).
    ///
    /// The default drives four busy steps at 3M/6M/9M/12M icount, all below the
    /// 15M busy cap that keeps the guest executing rather than idling.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ceiling_step_icount: 3_000_000,
            step_count: 4,
            busy_cap_icount: 15_000_000,
        }
    }

    /// Returns the ordered busy-window ceilings, or an error if any exceeds the cap.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveNodeStepGateError::ZeroSchedule`] when the step size or
    /// count is zero, or [`QemuLiveNodeStepGateError::CeilingAboveBusyCap`] when a
    /// scheduled ceiling reaches the busy cap (which would let the guest idle and
    /// forfeit determinism).
    fn ceilings(self) -> Result<Vec<u64>, QemuLiveNodeStepGateError> {
        if self.ceiling_step_icount == 0 || self.step_count == 0 {
            return Err(QemuLiveNodeStepGateError::ZeroSchedule);
        }
        let mut ceilings = Vec::with_capacity(self.step_count as usize);
        for multiplier in 1..=u64::from(self.step_count) {
            let ceiling = self
                .ceiling_step_icount
                .checked_mul(multiplier)
                .ok_or(QemuLiveNodeStepGateError::ZeroSchedule)?;
            if ceiling >= self.busy_cap_icount {
                return Err(QemuLiveNodeStepGateError::CeilingAboveBusyCap {
                    ceiling_icount: ceiling,
                    busy_cap_icount: self.busy_cap_icount,
                });
            }
            ceilings.push(ceiling);
        }
        Ok(ceilings)
    }
}

impl Default for QemuLiveNodeStepSchedule {
    fn default() -> Self {
        Self::new()
    }
}

/// Inputs for one live [`QemuNode`] bounded-step gate run.
#[derive(Clone, Debug)]
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
    icount_shift: u8,
    rr_switch_quantum: u64,
    scenario_seed: u64,
    process_generation: u64,
    network_tx_next_sequence: u32,
    whitebox: QemuLaunchPluginSwitch,
    app_random: Option<QemuLaunchAppRandomConfig>,
    coverage: QemuLaunchPluginSwitch,
    fingerprint: QemuLaunchPluginSwitch,
    shmem_network_mac: Option<String>,
    boot_network_backpressure_capture: Option<QemuLiveNodeStepNetworkCapture>,
    shmem_block: Option<QemuLiveNodeStepBlockConfig>,
    shmem_ninep: Option<QemuLiveNodeStepNinepConfig>,
    accelerator: bool,
    queue_capacity: u32,
    schedule: QemuLiveNodeStepSchedule,
    completion_timeout: Duration,
    second_run_scheduler_preemption: bool,
    console_capture: bool,
    fault_capabilities: Option<crucible::model::WorldNodeFaultCapabilities>,
    exact_gate_fault_manifests: Option<crate::fault_capability::QemuExactFaultManifests>,
}

#[derive(Clone, Debug)]
struct QemuLiveNodeStepBlockConfig {
    base: BaseImage,
    durability: BlockDurabilityConfig,
    latency: BlockLatency,
    require_fault_directives: bool,
}

#[derive(Clone, Debug)]
struct QemuLiveNodeStepNinepConfig {
    tree: FsTree,
    latency: NinepLatency,
}

#[derive(Clone, Debug)]
struct QemuLiveNodeStepNetworkCapture {
    payload: Vec<u8>,
    capture_icount: u64,
}

impl QemuLiveNodeStepGateConfig {
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
                crucible_protocol::WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION,
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
            icount_shift: 0,
            rr_switch_quantum: GATE_RR_SWITCH_QUANTUM,
            scenario_seed: 0,
            process_generation: 1,
            network_tx_next_sequence: 0,
            whitebox: QemuLaunchPluginSwitch::Off,
            app_random: None,
            coverage: QemuLaunchPluginSwitch::Off,
            fingerprint: QemuLaunchPluginSwitch::Off,
            shmem_network_mac: None,
            boot_network_backpressure_capture: None,
            shmem_block: None,
            shmem_ninep: None,
            accelerator: false,
            queue_capacity: GATE_QUEUE_CAPACITY,
            schedule: QemuLiveNodeStepSchedule::new(),
            completion_timeout: Duration::from_secs(240),
            second_run_scheduler_preemption: true,
            console_capture: false,
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
                crucible_protocol::WHITEBOX_DOORBELL_INSTRUCTION_ABI_VERSION,
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
            icount_shift: 0,
            rr_switch_quantum: GATE_RR_SWITCH_QUANTUM,
            scenario_seed: 0,
            process_generation: 1,
            network_tx_next_sequence: 0,
            whitebox: QemuLaunchPluginSwitch::Off,
            app_random: None,
            coverage: QemuLaunchPluginSwitch::Off,
            fingerprint: QemuLaunchPluginSwitch::Off,
            shmem_network_mac: None,
            boot_network_backpressure_capture: None,
            shmem_block: None,
            shmem_ninep: None,
            accelerator: false,
            queue_capacity: GATE_QUEUE_CAPACITY,
            schedule: QemuLiveNodeStepSchedule::new(),
            completion_timeout: Duration::from_secs(240),
            second_run_scheduler_preemption: true,
            console_capture: false,
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

    /// Returns this configuration with the retained guest's doorbell instruction ABI.
    #[must_use]
    pub const fn with_doorbell_instruction_abi_version(mut self, version: u16) -> Self {
        self.doorbell_instruction_abi_version = version;
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

    /// Returns this configuration with the World-declared VM shape.
    #[must_use]
    pub const fn with_vm_shape(
        mut self,
        memory_mib: u32,
        smp_vcpus: u16,
        icount_shift: u8,
    ) -> Self {
        self.memory_mib = memory_mib;
        self.smp_vcpus = smp_vcpus;
        self.icount_shift = icount_shift;
        self
    }

    /// Returns this configuration with the deterministic scenario seed.
    #[must_use]
    pub const fn with_scenario_seed(mut self, scenario_seed: u64) -> Self {
        self.scenario_seed = scenario_seed;
        self
    }

    /// Returns this configuration with its immutable process generation.
    #[must_use]
    pub const fn with_process_generation(mut self, process_generation: u64) -> Self {
        self.process_generation = process_generation;
        self
    }

    /// Returns this configuration with the restored plugin network TX cursor.
    #[must_use]
    pub const fn with_network_tx_next_sequence(mut self, next_sequence: u32) -> Self {
        self.network_tx_next_sequence = next_sequence;
        self
    }

    /// Returns this configuration with the production white-box channel set.
    #[must_use]
    pub const fn with_whitebox(mut self, whitebox: QemuLaunchPluginSwitch) -> Self {
        self.whitebox = whitebox;
        self
    }

    /// Returns this configuration with the seeded app-random source set.
    #[must_use]
    pub fn with_app_random(mut self, app_random: QemuLaunchAppRandomConfig) -> Self {
        self.app_random = Some(app_random);
        self
    }

    /// Returns this configuration with observation-only basic-block coverage.
    #[must_use]
    pub const fn with_coverage(mut self, coverage: QemuLaunchPluginSwitch) -> Self {
        self.coverage = coverage;
        self
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

    /// Returns this configuration with one exact-boundary boot RX canary.
    ///
    /// This is reserved for the fresh-process retained-network checkpoint gate.
    /// The canary is published at icount 1 and the initial process advances it
    /// through canonical retries to `capture_icount`. A restore launch does not
    /// republish the canary because it comes from the authenticated node
    /// continuation.
    #[must_use]
    pub fn with_boot_network_backpressure_capture_at(
        mut self,
        payload: Vec<u8>,
        capture_icount: u64,
    ) -> Self {
        self.boot_network_backpressure_capture = Some(QemuLiveNodeStepNetworkCapture {
            payload,
            capture_icount,
        });
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
            base,
            durability,
            latency: BlockLatency::default(),
            require_fault_directives: true,
        });
        self
    }

    /// Returns this configuration with a timed shared-memory block device.
    ///
    /// The latency model is deterministic virtual time, not host delay. It is
    /// retained in exact snapshots with the device continuation.
    #[must_use]
    pub fn with_shmem_block_and_latency(
        mut self,
        base: BaseImage,
        durability: BlockDurabilityConfig,
        latency: BlockLatency,
    ) -> Self {
        self.shmem_block = Some(QemuLiveNodeStepBlockConfig {
            base,
            durability,
            latency,
            require_fault_directives: true,
        });
        self
    }

    /// Returns this configuration with a fault-free timed block device.
    ///
    /// This selects the production block core's autonomous fault-free policy for
    /// gates that certify transport or checkpoint behavior without evaluating a
    /// fault graph. Production lifecycle launches use [`Self::with_shmem_block`]
    /// and install their required signal coordinator before workload I/O.
    #[must_use]
    pub fn with_fault_free_shmem_block_and_latency(
        mut self,
        base: BaseImage,
        durability: BlockDurabilityConfig,
        latency: BlockLatency,
    ) -> Self {
        self.shmem_block = Some(QemuLiveNodeStepBlockConfig {
            base,
            durability,
            latency,
            require_fault_directives: false,
        });
        self
    }

    /// Returns this configuration with one World-backed shared-memory 9p device.
    #[must_use]
    pub fn with_shmem_ninep(mut self, tree: FsTree, latency: NinepLatency) -> Self {
        self.shmem_ninep = Some(QemuLiveNodeStepNinepConfig { tree, latency });
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

    /// Returns this configuration with a different busy-window schedule.
    #[must_use]
    pub const fn with_schedule(mut self, schedule: QemuLiveNodeStepSchedule) -> Self {
        self.schedule = schedule;
        self
    }

    /// Returns this configuration with a different per-step completion bound.
    #[must_use]
    pub const fn with_completion_timeout(mut self, completion_timeout: Duration) -> Self {
        self.completion_timeout = completion_timeout;
        self
    }

    /// Returns this configuration with bounded scheduler preemption on the second run toggled.
    #[must_use]
    pub const fn with_second_run_scheduler_preemption(
        mut self,
        second_run_scheduler_preemption: bool,
    ) -> Self {
        self.second_run_scheduler_preemption = second_run_scheduler_preemption;
        self
    }

    /// Returns this configuration with output-only serial console capture enabled.
    #[must_use]
    pub const fn with_console_capture(mut self) -> Self {
        self.console_capture = true;
        self
    }

    /// Returns this configuration bound to one exact World fault manifest.
    #[must_use]
    pub fn with_fault_capabilities(
        mut self,
        capabilities: crucible::model::WorldNodeFaultCapabilities,
    ) -> Self {
        self.fault_capabilities = Some(capabilities);
        self
    }

    pub(super) fn run_directory(&self) -> &Path {
        &self.run_directory
    }
}

/// Raw-versus-logical accounting for one bounded node step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QemuLiveNodeStepQuantum {
    /// Scheduler-requested ceiling for this step (the raw target).
    pub target_icount: u64,
    /// Node-published completion icount at the boundary (the logical value).
    pub completion_icount: u64,
    /// `completion_icount - target_icount`; must be zero in a busy window.
    pub logical_offset: u64,
    /// Times the ceiling was re-issued before the boundary was reached.
    pub reissue_count: u32,
    /// Whether the step reached the horizon rather than parking idle early.
    pub reached_horizon: bool,
}

/// The outcome of one full node-step run (bring-up, steps, teardown).
#[derive(Clone, Debug, PartialEq, Eq)]
struct NodeStepOutcome {
    quanta: Vec<QemuLiveNodeStepQuantum>,
    fingerprint: ExecutionFingerprint,
    orderly_child_exit: bool,
}

/// Successful evidence from the live [`QemuNode`] bounded-step gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLiveNodeStepReport {
    /// Per-step raw-versus-logical accounting from the reference (first) run.
    pub quanta: Vec<QemuLiveNodeStepQuantum>,
    /// Execution fingerprint the node published at the final boundary.
    pub execution_fingerprint: ExecutionFingerprint,
    /// The QEMU child exited cleanly after the node's shutdown escalation.
    pub orderly_child_exit: bool,
    /// The second run, under bounded scheduler preemption, matched the first byte for byte.
    pub deterministic_under_scheduler_preemption: bool,
    /// Bounded scheduler preemption was actually applied during the second run.
    pub scheduler_preemption_applied: bool,
    /// Every busy-window step's logical offset was zero.
    pub busy_window_logical_offset_zero: bool,
}

/// Evidence from a real QEMU save, process crash, load, and continuation run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLiveExactSnapshotReport {
    /// Number of serialized round-robin vCPUs exercised by the restore.
    pub smp_vcpus: u16,
    /// Raw node icount at the captured completed quantum boundary.
    pub capture_icount: u64,
    /// Raw node icount observed immediately after restore.
    pub restored_icount: u64,
    /// Serialized RR vCPU selected at the captured boundary.
    pub capture_rr_current_vcpu: u32,
    /// Nonzero instruction offset within the captured RR turn.
    pub capture_rr_position_in_quantum: u64,
    /// Fixed RR turn length serialized with the captured cursor.
    pub capture_rr_switch_quantum: u64,
    /// Raw node icount reached by the restored and independently replayed suffix.
    pub suffix_icount: u64,
    /// Captured logical icount minus QEMU's raw icount at the save boundary.
    pub capture_logical_time_offset: u64,
    /// Execution fingerprint at capture and immediately after restore.
    pub capture_fingerprint: ContentHash,
    /// Execution fingerprint after the post-restore suffix.
    pub suffix_fingerprint: ContentHash,
    /// Aggregate VMState, host-I/O, and wrapper identity matched independent replay.
    pub replay_oracle_pair_match: bool,
    /// The old QEMU process was force-killed and reaped before artifact staging.
    pub old_process_force_crashed: bool,
    /// The captured block continuation contained pending work.
    pub pending_block_io_captured: bool,
    /// Production admission rejected an otherwise identical fingerprint whose
    /// RR position was reset to zero.
    pub rr_cursor_negative_control_rejected: bool,
}

/// Evidence from one signal-driven lifecycle effect applied by live patched QEMU.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLiveNodeLifecycleFaultReport {
    /// QEMU instruction coordinate at which the command was committed.
    pub observed_icount: u64,
    /// Authenticated action identity carried by command and occurrence evidence.
    pub action: ContentHash,
    /// Authenticated typed evidence identity returned by QEMU.
    pub evidence: ContentHash,
    /// Transition-specific QEMU process exit status.
    pub exit_code: i32,
    /// The signal runtime committed exactly one node-lifecycle impulse.
    pub lifecycle_impulse_committed: bool,
    /// A separately launched QEMU process reproduced every discovered target
    /// manifest and derived capability row exactly before the fault ran.
    pub exact_manifest_replay_admitted: bool,
    /// A real guest-state change between PREPARE and APPLY produced the typed
    /// precondition-mismatch status while the QEMU process remained live.
    pub changed_state_precondition_rejected: bool,
    /// Corrupting the authentic command result was rejected while the authentic
    /// occurrence event remained independently valid.
    pub corrupt_result_rejected_with_valid_event: bool,
    /// Corrupting the authentic occurrence event was rejected while the
    /// authentic command result remained independently valid.
    pub corrupt_event_rejected_with_valid_result: bool,
    /// One event source atomically committed network, storage, and node actions
    /// into their production adapter ledgers.
    ///
    /// This is an adapter-routing and commit-order proof. The network and
    /// storage impulses still require exact device opportunities before their
    /// mutations become externally visible.
    pub cross_adapter_actions_committed: bool,
    /// A live QEMU precondition rejection left the prepared host adapter state
    /// byte-identical and empty.
    pub cross_adapter_rejection_rolled_back: bool,
}

/// Drives the first live [`QemuNode`] through a bounded busy-window step schedule.
///
/// Boots the diskless-firmware guest with the Rust control plugin and QMP,
/// assembles a real [`QemuNode`] over the production host-I/O runtime, advances
/// it through the schedule's busy-window ceilings, and repeats the whole run --
/// the second time under bounded scheduler preemption -- requiring the
/// two runs to be byte-identical.
///
/// # Errors
///
/// Returns [`QemuLiveNodeStepGateError`] when the schedule is invalid, launch
/// preparation fails, the plugin handshake fails, the host-I/O runtime cannot map
/// the region, QMP cannot connect, the node cannot be assembled, a bounded step
/// stalls or diverges from its ceiling, teardown fails, or the two runs disagree.
pub fn run_qemu_live_node_step_gate(
    config: &QemuLiveNodeStepGateConfig,
) -> Result<QemuLiveNodeStepReport, QemuLiveNodeStepGateError> {
    let ceilings = config.schedule.ceilings()?;

    let reference = run_one_scenario(config, &ceilings, RunRole::Reference)?;
    let (second, scheduler_preemption_applied) = if config.second_run_scheduler_preemption {
        (run_one_scenario(config, &ceilings, RunRole::Hostile)?, true)
    } else {
        (run_one_scenario(config, &ceilings, RunRole::Repeat)?, false)
    };

    assert_runs_match(&reference, &second)?;

    let busy_window_logical_offset_zero = reference
        .quanta
        .iter()
        .all(|quantum| quantum.logical_offset == 0);

    Ok(QemuLiveNodeStepReport {
        quanta: reference.quanta,
        execution_fingerprint: reference.fingerprint,
        orderly_child_exit: reference.orderly_child_exit,
        deterministic_under_scheduler_preemption: true,
        scheduler_preemption_applied,
        busy_window_logical_offset_zero,
    })
}

/// Applies one signal-driven crash impulse to a real patched-QEMU process.
///
/// This gate exercises the production path end to end: the typed event source,
/// binding evaluator, production capability manifest, action encoder, shared
/// command ring, QEMU safe-boundary dispatcher, typed occurrence event, and
/// bounded process supervision. It does not synthesize command bytes or use a
/// backend double.
///
/// # Errors
///
/// Returns [`QemuLiveNodeStepGateError`] when launch, signal admission,
/// boundary evaluation, QEMU evidence validation, terminal authorization, or
/// process supervision fails.
pub fn run_qemu_live_node_lifecycle_fault_gate(
    config: &QemuLiveNodeStepGateConfig,
) -> Result<QemuLiveNodeLifecycleFaultReport, QemuLiveNodeStepGateError> {
    let discovery_directory = config
        .run_directory
        .join("signal-node-lifecycle-manifest-discovery");
    let run_directory = config.run_directory.join("signal-node-lifecycle-exact");
    fs::create_dir_all(&run_directory).map_err(|source| {
        QemuLiveNodeStepGateError::PrepareRunDirectory {
            path: run_directory.clone(),
            source,
        }
    })?;

    let mut discovery_config = config.clone();
    discovery_config.fault_capabilities = None;
    discovery_config.exact_gate_fault_manifests = None;
    let mut discovery_node = build_live_node(
        &discovery_config,
        &discovery_directory,
        LiveNodeIdentity {
            node: GATE_NODE,
            router: GATE_ROUTER,
            crash_detector: "signal-node-lifecycle-manifest-discovery",
        },
        None,
        true,
    )?;
    let manifests = discovery_node
        .exact_fault_manifests()
        .cloned()
        .ok_or_else(|| fault_gate_invariant("live manifest discovery was incomplete"))?;
    let shutdown = discovery_node
        .shutdown_child()
        .map_err(|source| QemuLiveNodeStepGateError::Shutdown { source })?;
    if !shutdown.reaped || shutdown.leaked {
        return Err(fault_gate_invariant(
            "manifest-discovery process did not shut down cleanly",
        ));
    }
    let mut exact_config = config.clone();
    exact_config.fault_capabilities = None;
    exact_config.exact_gate_fault_manifests = Some(manifests);

    let channel_proof_directory = config
        .run_directory
        .join("signal-node-lifecycle-channel-corruption");
    let mut channel_proof_node = build_live_node(
        &exact_config,
        &channel_proof_directory,
        LiveNodeIdentity {
            node: GATE_NODE,
            router: GATE_ROUTER,
            crash_detector: "signal-node-lifecycle-channel-corruption",
        },
        None,
        true,
    )?;
    prove_lifecycle_channel_corruption_rejection(&mut channel_proof_node)?;
    let channel_proof_shutdown = channel_proof_node
        .shutdown_child()
        .map_err(|source| QemuLiveNodeStepGateError::Shutdown { source })?;
    if !channel_proof_shutdown.reaped || channel_proof_shutdown.leaked {
        return Err(fault_gate_invariant(
            "channel-corruption proof process did not shut down cleanly",
        ));
    }

    let identity = node_id(GATE_NODE);
    let mut node = build_live_node(
        &exact_config,
        &run_directory,
        LiveNodeIdentity {
            node: GATE_NODE,
            router: GATE_ROUTER,
            crash_detector: "signal-node-lifecycle",
        },
        None,
        true,
    )?;
    prove_lifecycle_precondition_rejection(&mut node)?;
    let observed_icount = node
        .current_icount()
        .map_err(|source| QemuLiveNodeStepGateError::node_op("read lifecycle boundary", source))?
        .retired;
    let mut nodes = QemuNodeSet::new();
    if nodes.insert(identity.clone(), node).is_some() {
        return Err(fault_gate_invariant(
            "live lifecycle node identity collided",
        ));
    }

    let plan = shared_power_crash_plan(GATE_NODE)?;
    let store: Arc<dyn crucible::model::DagStore> =
        Arc::new(crucible::model::MemoryDagStore::new());
    let artifacts: Arc<dyn crucible::model::SignalArtifactProvider> =
        Arc::new(crucible::model::OwnedDagSignalArtifactProvider::new(store));
    let mut runtime = ProductionFaultRuntime::new(
        plan,
        Some(artifacts),
        crucible::model::SignalBoundarySnapshot::default(),
        ContentHash::from_canonical_material(
            "crucible.live-node-lifecycle-fault-gate.v1",
            GATE_NODE,
        ),
        crucible::model::production_host_fault_adapter_manifests().map_err(|error| {
            fault_gate_invariant(format!(
                "derive production host manifests from implementation registries: {error}"
            ))
        })?,
        &nodes,
    )
    .map_err(|error| fault_gate_invariant(format!("admit lifecycle plan: {error}")))?;
    let evaluation = runtime
        .evaluate_boundary(
            crucible::model::FaultCoordinate {
                virtual_nanos: 1,
                retired_instructions: Some(observed_icount),
            },
            0,
            &mut nodes,
        )
        .map_err(|error| fault_gate_invariant(format!("apply lifecycle boundary: {error}")))?;
    let [decision] = runtime.node_lifecycle_decisions() else {
        return Err(fault_gate_invariant(format!(
            "lifecycle boundary returned {} terminal decisions",
            runtime.node_lifecycle_decisions().len()
        )));
    };
    let decision = decision.clone();
    let host_impulses = runtime.drain_host_impulses();
    let lifecycle_impulse_committed = evaluation
        .actions
        .iter()
        .filter(|action| action.effect.kind() == crucible::model::EffectKind::NodeLifecycle)
        .count()
        == 1;
    let cross_adapter_actions_committed = lifecycle_impulse_committed
        && evaluation.actions.len() == 3
        && host_impulses.len() == 2
        && host_impulses.iter().any(|action| {
            action.effect.kind() == crucible::model::EffectKind::NetworkForwarderLifecycle
        })
        && host_impulses.iter().any(|action| {
            action.effect.kind() == crucible::model::EffectKind::StorageVolatileCacheLoss
        })
        && evaluation
            .actions
            .iter()
            .all(|action| action.coordinate.virtual_nanos == 1);
    if !cross_adapter_actions_committed {
        return Err(fault_gate_invariant(
            "shared power event did not atomically commit network, storage, and node actions",
        ));
    }
    prove_cross_adapter_rejection_rollback(&exact_config, &evaluation.actions)?;
    if decision.requested_transition != crucible::model::NodeLifecycleTransition::Crash
        || decision.effective_transition != crucible::model::NodeLifecycleTransition::Crash
        || decision.observed_icount != observed_icount
    {
        return Err(fault_gate_invariant(
            "lifecycle evidence did not retain the requested crash boundary",
        ));
    }
    let expected_exit_code = decision
        .expected_exit_code
        .ok_or_else(|| fault_gate_invariant("crash evidence did not require a process exit"))?;
    let action = decision.action;
    let evidence = decision.event_evidence;
    nodes
        .complete_terminal_lifecycle_exit(&identity, action, evidence, config.process_generation)
        .map_err(|error| fault_gate_invariant(format!("authorize lifecycle exit: {error}")))?;
    let exit_code = nodes
        .await_intended_lifecycle_exit(&identity, expected_exit_code, action)
        .map_err(|error| fault_gate_invariant(format!("supervise lifecycle exit: {error}")))?;
    runtime.acknowledge_node_lifecycle_decisions();

    Ok(QemuLiveNodeLifecycleFaultReport {
        observed_icount,
        action,
        evidence,
        exit_code,
        lifecycle_impulse_committed,
        exact_manifest_replay_admitted: true,
        changed_state_precondition_rejected: true,
        corrupt_result_rejected_with_valid_event: true,
        corrupt_event_rejected_with_valid_result: true,
        cross_adapter_actions_committed,
        cross_adapter_rejection_rolled_back: true,
    })
}

fn prove_cross_adapter_rejection_rollback(
    config: &QemuLiveNodeStepGateConfig,
    committed_actions: &[crucible::model::ResolvedBindingAction],
) -> Result<(), QemuLiveNodeStepGateError> {
    let run_directory = config.run_directory.join("signal-rollback");
    let mut node = build_live_node(
        config,
        &run_directory,
        LiveNodeIdentity {
            node: GATE_NODE,
            router: GATE_ROUTER,
            crash_detector: "signal-rollback",
        },
        None,
        true,
    )?;
    let observed_icount = node
        .current_icount()
        .map_err(|source| QemuLiveNodeStepGateError::node_op("read rejection boundary", source))?
        .retired;
    let mut nodes = QemuNodeSet::new();
    if nodes.insert(node_id(GATE_NODE), node).is_some() {
        return Err(fault_gate_invariant(
            "cross-adapter rejection node identity collided",
        ));
    }

    let mut actions = committed_actions.to_vec();
    let mut node_actions = 0_usize;
    for action in &mut actions {
        action.coordinate.retired_instructions = Some(observed_icount);
        if action.effect.kind().descriptor().adapter == crucible::model::FaultAdapter::Node {
            node_actions += 1;
            action.expected_precondition = Some(ContentHash::from_bytes(
                b"deliberately-wrong-live-node-precondition",
            ));
        }
    }
    if node_actions != 1 {
        return Err(fault_gate_invariant(format!(
            "cross-adapter rejection expected one node action, observed {node_actions}"
        )));
    }

    let mut host =
        crucible::model::HostFaultActionSink::new(crucible::model::FaultResourceLimits::default());
    let before = host.state().canonical_bytes().map_err(|error| {
        fault_gate_invariant(format!("encode host state before rejection: {error}"))
    })?;
    let before_digest = host.state().digest();
    let mut sink =
        ProductionFaultActionSink::new(&mut host, &mut nodes, FaultResourceLimits::default());
    let prepared = sink.prepare_batch(&actions).map_err(|error| {
        fault_gate_invariant(format!("prepare rejection transaction: {}", error.error))
    })?;
    let rejected = matches!(
        sink.commit_batch(prepared.transaction),
        Err(FaultActionCommitError::Rejected(_))
    );
    drop(sink);
    let after = host.state().canonical_bytes().map_err(|error| {
        fault_gate_invariant(format!("encode host state after rejection: {error}"))
    })?;
    if !rejected
        || !host.state().is_empty()
        || host.state().digest() != before_digest
        || after != before
    {
        return Err(fault_gate_invariant(
            "live QEMU rejection made prepared host adapter state visible",
        ));
    }

    let mut node = nodes
        .take(&node_id(GATE_NODE))
        .ok_or_else(|| fault_gate_invariant("cross-adapter rejection node disappeared"))?;
    let shutdown = node
        .shutdown_child()
        .map_err(|error| fault_gate_invariant(format!("shut down rejection node: {error}")))?;
    if !shutdown.reaped || shutdown.leaked {
        return Err(fault_gate_invariant(
            "cross-adapter rejection process did not shut down cleanly",
        ));
    }
    Ok(())
}

fn prove_lifecycle_channel_corruption_rejection(
    node: &mut QemuNode,
) -> Result<(), QemuLiveNodeStepGateError> {
    let payload = lifecycle_gate_payload(node)?;
    let coordinate = node
        .current_icount()
        .map_err(|source| {
            QemuLiveNodeStepGateError::node_op("read channel-proof boundary", source)
        })?
        .retired;
    let prepare_sequence = node.reserve_fault_command_sequence().map_err(|source| {
        QemuLiveNodeStepGateError::node_op("reserve channel-proof PREPARE sequence", source)
    })?;
    let prepare = lifecycle_gate_command(
        coordinate,
        prepare_sequence,
        FAULT_COMMAND_FLAG_PREPARE_ONLY,
        [0; 32],
        &payload,
    );
    let DequeuedFaultResult::Valid {
        header: prepare_header,
        payload: prepare_payload,
    } = node
        .apply_fault_command_at_current_boundary(prepare, &payload)
        .map_err(|source| {
            QemuLiveNodeStepGateError::node_op("prepare channel-proof lifecycle", source)
        })?
    else {
        return Err(fault_gate_invariant(
            "channel-proof PREPARE returned an invalid result",
        ));
    };
    if prepare_header.status != FaultResultStatus::Prepared {
        return Err(fault_gate_invariant(format!(
            "channel-proof PREPARE returned {:?}",
            prepare_header.status
        )));
    }
    let preparation = validate_live_node_result(
        &payload,
        prepare_header.clone(),
        prepare_payload,
        FaultResultStatus::Prepared,
    )?;

    let apply_sequence = node.reserve_fault_command_sequence().map_err(|source| {
        QemuLiveNodeStepGateError::node_op("reserve channel-proof APPLY sequence", source)
    })?;
    let apply = lifecycle_gate_command(
        coordinate,
        apply_sequence,
        FAULT_COMMAND_FLAG_NONE,
        preparation.before_sha256,
        &payload,
    );
    let DequeuedFaultResult::Valid {
        header: apply_header,
        payload: apply_payload,
    } = node
        .apply_fault_command_at_current_boundary(apply, &payload)
        .map_err(|source| {
            QemuLiveNodeStepGateError::node_op("apply channel-proof lifecycle", source)
        })?
    else {
        return Err(fault_gate_invariant(
            "channel-proof APPLY returned an invalid result",
        ));
    };
    if apply_header.status != FaultResultStatus::Applied {
        return Err(fault_gate_invariant(format!(
            "channel-proof APPLY returned {:?}",
            apply_header.status
        )));
    }
    let result = validate_live_node_result(
        &payload,
        apply_header.clone(),
        apply_payload.clone(),
        FaultResultStatus::Applied,
    )?;

    let mut events = Vec::new();
    node.drain_fault_events(&mut events).map_err(|source| {
        QemuLiveNodeStepGateError::node_op("drain channel-proof occurrence", source)
    })?;
    let [event] = events.as_slice() else {
        return Err(fault_gate_invariant(format!(
            "channel-proof APPLY emitted {} occurrence events",
            events.len()
        )));
    };
    let sequence_matches = event.header.rule_command_sequence == apply_sequence;
    let kind_matches = event.header.command_kind == FaultCommandKind::NodeLifecycle;
    let before_matches = event.header.before_hash == result.before_sha256;
    let after_matches = event.header.after_hash == result.after_sha256;
    let evidence_valid = crate::production_fault_runtime::validate_live_gate_lifecycle_event(event);
    if !(sequence_matches && kind_matches && before_matches && after_matches && evidence_valid) {
        let evidence_diagnostic =
            crate::production_fault_runtime::live_gate_lifecycle_event_diagnostic(event);
        return Err(fault_gate_invariant(format!(
            "authentic channel-proof join failed: sequence={sequence_matches} kind={kind_matches} before={before_matches} after={after_matches} evidence={evidence_valid}; {evidence_diagnostic}"
        )));
    }

    let mut corrupt_result = apply_payload.clone();
    corrupt_result[0] ^= 1;
    if validate_live_node_result(
        &payload,
        apply_header.clone(),
        corrupt_result,
        FaultResultStatus::Applied,
    )
    .is_ok()
        || !crate::production_fault_runtime::validate_live_gate_lifecycle_event(event)
    {
        return Err(fault_gate_invariant(
            "corrupt result was accepted or invalidated the authentic occurrence",
        ));
    }
    let mut corrupt_event = event.clone();
    corrupt_event.payload[10..12].fill(0);
    if validate_live_node_result(
        &payload,
        apply_header,
        apply_payload,
        FaultResultStatus::Applied,
    )
    .is_err()
        || crate::production_fault_runtime::validate_live_gate_lifecycle_event(&corrupt_event)
    {
        return Err(fault_gate_invariant(
            "corrupt occurrence was accepted or invalidated the authentic result",
        ));
    }
    Ok(())
}

fn validate_live_node_result(
    request_payload: &[u8],
    header: crucible_shmem::FaultResultHeaderV1,
    payload: Vec<u8>,
    expected_status: FaultResultStatus,
) -> Result<NodeFaultEvidenceV1, QemuLiveNodeStepGateError> {
    crate::fault_action_sink::validate_typed_node_result(
        request_payload,
        DequeuedFaultResult::Valid { header, payload },
        expected_status,
    )
    .map_err(|error| fault_gate_invariant(format!("production typed result rejection: {error}")))
}

fn prove_lifecycle_precondition_rejection(
    node: &mut QemuNode,
) -> Result<(), QemuLiveNodeStepGateError> {
    let payload = lifecycle_gate_payload(node)?;
    let before_coordinate = node
        .current_icount()
        .map_err(|source| QemuLiveNodeStepGateError::node_op("read PREPARE boundary", source))?
        .retired;
    let prepare_sequence = node
        .reserve_fault_command_sequence()
        .map_err(|source| QemuLiveNodeStepGateError::node_op("reserve PREPARE sequence", source))?;
    let prepare = lifecycle_gate_command(
        before_coordinate,
        prepare_sequence,
        FAULT_COMMAND_FLAG_PREPARE_ONLY,
        [0; 32],
        &payload,
    );
    let DequeuedFaultResult::Valid {
        header: prepare_header,
        payload: prepare_payload,
    } = node
        .apply_fault_command_at_current_boundary(prepare, &payload)
        .map_err(|source| {
            QemuLiveNodeStepGateError::node_op("prepare lifecycle negative", source)
        })?
    else {
        return Err(fault_gate_invariant(
            "lifecycle PREPARE returned an invalid result",
        ));
    };
    if prepare_header.status != FaultResultStatus::Prepared {
        return Err(fault_gate_invariant(format!(
            "lifecycle PREPARE returned {:?}",
            prepare_header.status
        )));
    }
    let preparation = validate_live_node_result(
        &payload,
        prepare_header,
        prepare_payload,
        FaultResultStatus::Prepared,
    )?;
    if preparation.before_sha256 != preparation.after_sha256 {
        return Err(fault_gate_invariant("lifecycle PREPARE changed state"));
    }

    node.advance_to_ceiling(Icount {
        retired: before_coordinate
            .checked_add(1)
            .ok_or_else(|| fault_gate_invariant("lifecycle negative icount overflow"))?,
    })
    .map_err(|source| {
        QemuLiveNodeStepGateError::node_op("change live state after PREPARE", source)
    })?;
    let apply_coordinate = node
        .current_icount()
        .map_err(|source| QemuLiveNodeStepGateError::node_op("read APPLY boundary", source))?
        .retired;
    if apply_coordinate == before_coordinate {
        return Err(fault_gate_invariant(
            "guest state did not advance between lifecycle PREPARE and APPLY",
        ));
    }
    let apply_sequence = node
        .reserve_fault_command_sequence()
        .map_err(|source| QemuLiveNodeStepGateError::node_op("reserve APPLY sequence", source))?;
    let apply = lifecycle_gate_command(
        apply_coordinate,
        apply_sequence,
        FAULT_COMMAND_FLAG_NONE,
        preparation.before_sha256,
        &payload,
    );
    let DequeuedFaultResult::Valid { header, .. } = node
        .apply_fault_command_at_current_boundary(apply, &payload)
        .map_err(|source| QemuLiveNodeStepGateError::node_op("apply lifecycle negative", source))?
    else {
        return Err(fault_gate_invariant(
            "lifecycle mismatch APPLY returned an invalid result",
        ));
    };
    if header.status != FaultResultStatus::PreconditionMismatch {
        return Err(fault_gate_invariant(format!(
            "changed lifecycle state returned {:?} instead of precondition mismatch",
            header.status
        )));
    }
    node.current_icount().map_err(|source| {
        QemuLiveNodeStepGateError::node_op("prove QEMU survived rejection", source)
    })?;
    Ok(())
}

fn lifecycle_gate_payload(node: &QemuNode) -> Result<Vec<u8>, QemuLiveNodeStepGateError> {
    let capability = node
        .fault_capabilities()
        .iter()
        .find(|row| row.command_kind == FaultCommandKind::NodeLifecycle)
        .ok_or_else(|| fault_gate_invariant("live node omitted lifecycle capability"))?;
    let mut boot_policy = NODE_FAULT_POLICY_JSON_MAGIC_V1.to_vec();
    boot_policy.extend_from_slice(br#"{"kind":"immediate"}"#);
    NodeFaultPayloadV1 {
        command_kind: FaultCommandKind::NodeLifecycle,
        operation: NodeFaultOperationV1::Apply,
        target_kind: NodeFaultTargetKindV1::Node,
        model_phase: 9,
        generation: 1,
        action_hash: ContentHash::from_bytes(b"live-lifecycle-precondition-action").bytes,
        target_hash: ContentHash::from_bytes(b"live-lifecycle-precondition-target").bytes,
        schema_hash: capability.capability_hash,
        fields: vec![
            NodeFaultFieldV1::u32(node_fault_field::P1, 2),
            NodeFaultFieldV1::u64(node_fault_field::P2, 1),
            NodeFaultFieldV1::bytes(node_fault_field::P3, boot_policy),
            NodeFaultFieldV1::u32(node_fault_field::P4, 1),
            NodeFaultFieldV1::u32(node_fault_field::P5, 2),
        ],
    }
    .encode()
    .map_err(|error| fault_gate_invariant(format!("encode lifecycle negative: {error}")))
}

fn lifecycle_gate_command(
    coordinate: u64,
    sequence: u64,
    flags: u16,
    expected_precondition_hash: [u8; 32],
    payload: &[u8],
) -> FaultCommandHeaderV1 {
    FaultCommandHeaderV1 {
        abi_major: FAULT_COMMAND_ABI_MAJOR,
        abi_minor: FAULT_COMMAND_ABI_MINOR,
        command_kind: FaultCommandKind::NodeLifecycle,
        command_flags: flags,
        phase: FaultBoundaryPhase::NodeBoundary,
        semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
        command_sequence: sequence,
        target_node_hash: crate::qemu_fault_target_hash(GATE_NODE),
        target_icount: coordinate,
        authorization_ceiling_icount: coordinate,
        binding_hash: ContentHash::from_bytes(b"live-lifecycle-precondition-binding").bytes,
        opportunity_hash: [0; 32],
        expected_precondition_hash,
        payload_hash: *blake3::hash(payload).as_bytes(),
        payload_offset: 0,
        payload_length: u32::try_from(payload.len()).unwrap_or(u32::MAX),
    }
}

fn shared_power_crash_plan(
    node_name: &str,
) -> Result<crucible::model::FaultSignalPlan, QemuLiveNodeStepGateError> {
    use crucible::model::{
        BindingEventParent, BindingMapping, BindingObservabilityPolicy, BindingSampling,
        BindingSearchPolicy, EFFECT_SEMANTIC_VERSION, EffectLifetime, EffectRequest,
        EffectSpecification, FaultBinding, FaultObjectId, FaultPhase, FaultResourceLimits,
        NetworkEffectSpecification, NetworkForwarderTransition, NetworkStatePolicy, NodeBootPolicy,
        NodeEffectSpecification, NodeLifecycleTransition, NodeStatePolicy, ResolvedFaultTarget,
        ResolvedTargetSet, SignalCoordinate, SignalDomain, SignalId, SignalNode, SignalNodeKind,
        SignalPoint, SignalProgram, SignalResourceLimits, SignalShape, SignalSourceSpecification,
        SignalUnit, SignalValue, SignalValueType, StorageEffectSpecification,
        StorageVolatileCacheLossKind, StorageVolatileCacheLossSelector, TargetSelector,
    };

    let parse_signal = |value: &str| {
        SignalId::parse(value)
            .map_err(|error| fault_gate_invariant(format!("signal ID `{value}`: {error}")))
    };
    let parse_object = |value: &str| {
        FaultObjectId::parse(value)
            .map_err(|error| fault_gate_invariant(format!("object ID `{value}`: {error}")))
    };
    let output = parse_signal("live-crash-event")?;
    let schema = parse_signal("node-lifecycle-event")?;
    let program = SignalProgram::new(
        vec![SignalNode {
            id: output.clone(),
            domain: SignalDomain::Event,
            output: SignalShape::new(
                SignalValueType::Event(schema.clone()),
                SignalUnit::Dimensionless,
                0,
            )
            .map_err(|error| fault_gate_invariant(format!("event shape: {error}")))?,
            inputs: Vec::new(),
            kind: SignalNodeKind::Source(SignalSourceSpecification::EventSequence {
                events: vec![SignalPoint {
                    coordinate: SignalCoordinate::Event {
                        parent: Box::new(SignalCoordinate::VirtualTime { nanos: 1 }),
                        sequence: 0,
                    },
                    sequence: 0,
                    value: SignalValue::Event {
                        schema,
                        payload: Vec::new(),
                    },
                }],
            }),
        }],
        vec![output.clone()],
        SignalResourceLimits::default(),
    )
    .map_err(|error| fault_gate_invariant(format!("event program: {error}")))?;
    let binding = |id: &str,
                   target: ResolvedFaultTarget,
                   specification: EffectSpecification|
     -> Result<FaultBinding, QemuLiveNodeStepGateError> {
        let targets = ResolvedTargetSet::new(vec![target], false)
            .map_err(|error| fault_gate_invariant(format!("{id} target: {error}")))?;
        let effect = EffectRequest::new(
            EFFECT_SEMANTIC_VERSION,
            EffectLifetime::Impulse,
            specification,
        )
        .map_err(|error| fault_gate_invariant(format!("{id} effect: {error}")))?;
        FaultBinding::new(
            parse_object(id)?,
            vec![output.clone()],
            BindingSampling::AtEvent(BindingEventParent::VirtualTime),
            BindingMapping::ImpulseOnEvent,
            TargetSelector::Exact(targets),
            [FaultPhase::Boundary].into_iter().collect(),
            effect,
            None,
            BindingSearchPolicy::Fixed,
            BindingObservabilityPolicy::default(),
            &program,
        )
        .map_err(|error| fault_gate_invariant(format!("{id} binding: {error}")))
    };
    let network = binding(
        "shared-power-forwarder-binding",
        ResolvedFaultTarget::NetworkForwarder {
            forwarder: parse_object("rack-forwarder")?,
        },
        EffectSpecification::Network(NetworkEffectSpecification::ForwarderLifecycle {
            transition: NetworkForwarderTransition::PowerLoss,
            downtime_nanos: crucible::model::PositiveU64::new("downtime_nanos", 1)
                .map_err(|error| fault_gate_invariant(format!("network downtime: {error}")))?,
            queue_policy: NetworkStatePolicy::Clear,
            table_policy: NetworkStatePolicy::Clear,
        }),
    )?;
    let storage = binding(
        "shared-power-storage-binding",
        ResolvedFaultTarget::BlockDevice {
            device: ContentHash::from_bytes(b"rack-storage-device"),
        },
        EffectSpecification::Storage(StorageEffectSpecification::VolatileCacheLoss {
            selector: StorageVolatileCacheLossSelector::All,
            loss: StorageVolatileCacheLossKind::PowerLoss,
        }),
    )?;
    let node = binding(
        "shared-power-node-binding",
        ResolvedFaultTarget::Node {
            node: parse_object(node_name)?,
        },
        EffectSpecification::Node(NodeEffectSpecification::Lifecycle {
            transition: NodeLifecycleTransition::Crash,
            downtime_nanos: 1,
            boot_policy: NodeBootPolicy::Immediate,
            volatile_state_policy: NodeStatePolicy::Preserve,
            device_state_policy: NodeStatePolicy::Clear,
        }),
    )?;
    crucible::model::FaultSignalPlan::new(
        vec![program],
        vec![network, storage, node],
        FaultResourceLimits::default(),
    )
    .map_err(|error| fault_gate_invariant(format!("shared power plan: {error}")))
}

fn fault_gate_invariant(reason: impl Into<String>) -> QemuLiveNodeStepGateError {
    QemuLiveNodeStepGateError::ExactSnapshotInvariant {
        reason: reason.into(),
    }
}

/// Launches one scheduler-facing live QEMU node.
///
/// The returned node has already crossed the plugin setup handshake, completed
/// its bounded boot-barrier priming quantum, connected QMP, and synchronized its
/// scheduler-facing time mirror to the primed guest icount.
///
/// # Errors
///
/// Returns [`QemuLiveNodeStepGateError`] when launch preparation, plugin setup,
/// boot-barrier priming, QMP connection, node assembly, or time synchronization
/// fails.
pub fn launch_qemu_live_node(
    config: &QemuLiveNodeStepGateConfig,
    run_directory: impl AsRef<Path>,
    node: &str,
    router: &str,
    crash_detector: &str,
) -> Result<QemuNode, QemuLiveNodeStepGateError> {
    build_live_node(
        config,
        run_directory.as_ref(),
        LiveNodeIdentity {
            node,
            router,
            crash_detector,
        },
        None,
        true,
    )
}

/// Launches one scheduler-facing live node with authorized VMState restored.
///
/// The QMP `loadvm` command runs before the scheduler-facing node is assembled,
/// preserving the realization admission boundary used by resume and fork.
///
/// # Errors
///
/// Returns [`QemuLiveNodeStepGateError`] when launch, setup, the authorized
/// restore, node assembly, or time synchronization fails.
pub fn launch_qemu_live_node_restored(
    config: &QemuLiveNodeStepGateConfig,
    run_directory: impl AsRef<Path>,
    node: &str,
    router: &str,
    crash_detector: &str,
    restore: QemuNodeRestorePlan<'_>,
) -> Result<QemuNode, QemuLiveNodeStepGateError> {
    build_live_node(
        config,
        run_directory.as_ref(),
        LiveNodeIdentity {
            node,
            router,
            crash_detector,
        },
        Some(restore),
        true,
    )
}

/// Launches one scheduler-facing node from a complete live exact snapshot.
///
/// This is the production restore surface. It validates the opaque live-capture
/// provenance and all three execution bindings before constructing the private
/// low-level VMState restore plan.
///
/// # Errors
///
/// Returns [`QemuLiveNodeStepGateError`] when the snapshot is not an authentic
/// live capture or when launch, QMP restore, host restore, or node assembly fails.
pub fn launch_qemu_live_node_exact_snapshot(
    config: &QemuLiveNodeStepGateConfig,
    run_directory: impl AsRef<Path>,
    node: &str,
    router: &str,
    crash_detector: &str,
    snapshot: &QemuVmSnapshot,
) -> Result<QemuNode, QemuLiveNodeStepGateError> {
    let binding = snapshot.checkpoint().id;
    if !snapshot.is_live_capture()
        || !snapshot.has_valid_identity()
        || snapshot.host_io().execution_binding() != binding
        || snapshot.node_continuation().execution_binding() != binding
    {
        return Err(QemuLiveNodeStepGateError::InvalidExactSnapshot);
    }
    build_live_node(
        config,
        run_directory.as_ref(),
        LiveNodeIdentity {
            node,
            router,
            crash_detector,
        },
        Some(QemuNodeRestorePlan::captured_exact(snapshot)),
        true,
    )
}

/// Launches one exact-snapshot node and leaves its guest natively paused.
///
/// The returned process has completed setup, restore, and logical-time
/// calibration. It is suitable for an authenticated power-off generation and
/// cannot execute guest work until the scheduler explicitly boots it.
///
/// # Errors
///
/// Returns [`QemuLiveNodeStepGateError`] under the same conditions as
/// [`launch_qemu_live_node_exact_snapshot`].
pub fn launch_qemu_live_node_exact_snapshot_paused(
    config: &QemuLiveNodeStepGateConfig,
    run_directory: impl AsRef<Path>,
    node: &str,
    router: &str,
    crash_detector: &str,
    snapshot: &QemuVmSnapshot,
) -> Result<QemuNode, QemuLiveNodeStepGateError> {
    let binding = snapshot.checkpoint().id;
    if !snapshot.is_live_capture()
        || !snapshot.has_valid_identity()
        || snapshot.host_io().execution_binding() != binding
        || snapshot.node_continuation().execution_binding() != binding
    {
        return Err(QemuLiveNodeStepGateError::InvalidExactSnapshot);
    }
    build_live_node(
        config,
        run_directory.as_ref(),
        LiveNodeIdentity {
            node,
            router,
            crash_detector,
        },
        Some(QemuNodeRestorePlan::captured_exact(snapshot)),
        false,
    )
}

/// Which scenario run this is, controlling the run subdirectory and scheduler preemption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunRole {
    Reference,
    Hostile,
    Repeat,
}

impl RunRole {
    const fn subdir(self) -> &'static str {
        match self {
            Self::Reference => "run-reference",
            Self::Hostile => "run-scheduler-preemption",
            Self::Repeat => "run-repeat",
        }
    }

    const fn applies_scheduler_preemption(self) -> bool {
        matches!(self, Self::Hostile)
    }
}

fn run_one_scenario(
    config: &QemuLiveNodeStepGateConfig,
    ceilings: &[u64],
    role: RunRole,
) -> Result<NodeStepOutcome, QemuLiveNodeStepGateError> {
    let run_directory = config.run_directory.join(role.subdir());
    let mut node = build_live_node(
        config,
        &run_directory,
        LiveNodeIdentity {
            node: GATE_NODE,
            router: GATE_ROUTER,
            crash_detector: GATE_CRASH_NODE_ID,
        },
        None,
        true,
    )?;

    // `build_live_node` has released the boot barrier. Spend the finite
    // preemption budget only across the compared busy-window quanta.
    let mut host_adversary =
        HostAdversary::start_if(role.applies_scheduler_preemption(), node.process_id())
            .map_err(|source| QemuLiveNodeStepGateError::SchedulerPreemption { source })?;
    let quanta = drive_busy_window_steps(&mut node, ceilings, &mut host_adversary)?;
    let fingerprint = node
        .execution_fingerprint()
        .map_err(|source| QemuLiveNodeStepGateError::ExecutionFingerprint { source })?;
    HostAdversary::finish_if_present(&mut host_adversary)
        .map_err(|source| QemuLiveNodeStepGateError::SchedulerPreemption { source })?;

    let shutdown = node
        .shutdown_child()
        .map_err(|source| QemuLiveNodeStepGateError::Shutdown { source })?;
    let orderly_child_exit = shutdown.reaped && !shutdown.leaked;

    drop(node);

    Ok(NodeStepOutcome {
        quanta,
        fingerprint,
        orderly_child_exit,
    })
}

#[derive(Clone, Copy)]
pub(super) struct LiveNodeIdentity<'a> {
    pub(super) node: &'a str,
    pub(super) router: &'a str,
    pub(super) crash_detector: &'a str,
}

pub(super) fn build_live_node(
    config: &QemuLiveNodeStepGateConfig,
    run_directory: &Path,
    identity: LiveNodeIdentity<'_>,
    restore: Option<QemuNodeRestorePlan<'_>>,
    resume_restored: bool,
) -> Result<QemuNode, QemuLiveNodeStepGateError> {
    fs::create_dir_all(run_directory).map_err(|source| {
        QemuLiveNodeStepGateError::PrepareRunDirectory {
            path: run_directory.to_path_buf(),
            source,
        }
    })?;
    let debug_guest_activation_listener = (config.whitebox == QemuLaunchPluginSwitch::On)
        .then(|| {
            crate::unix_socket_path::bind(
                &run_directory.join(crate::QEMU_DEBUG_GUEST_ACTIVATION_SOCKET_FILE_NAME),
            )
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
        .with_icount_shift(IcountShiftSetting::Fixed(config.icount_shift))
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
        .write_to_dir(run_directory)
        .map_err(|source| QemuLiveNodeStepGateError::GuestEntropySeed {
            path: run_directory.to_path_buf(),
            source,
        })?;

    let qmp_config = QemuQmpChannelConfig::new(GATE_QMP_SOCKET_FILE_NAME)
        .map_err(|source| QemuLiveNodeStepGateError::QmpChannelConfig { source })?;
    let vm = vm_launch_config(config, identity.node);
    let plugin = live_node_plugin_config(config, &profile, &vm, run_directory, identity.node)?;
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
            return Err(fault_gate_invariant(
                "World and gate-replay capability manifests were both configured",
            ));
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
    let command = command
        .build()
        .map_err(|source| QemuLiveNodeStepGateError::LaunchCommand { source })?;

    let region_config = RegionConfig::new(1, config.queue_capacity, 0);
    let allocation = RegionAllocation::new(region_config)
        .map_err(|source| QemuLiveNodeStepGateError::RegionLayout { source })?;
    let spawned = spawn_qemu_child_with_fds_in_directory(
        &command,
        run_directory,
        allocation.layout().region_size,
    )
    .map_err(|source| QemuLiveNodeStepGateError::Spawn { source })?;
    let (child, resources) = spawned.into_parts();
    let setup = complete_qemu_host_plugin_setup(
        resources.into_setup_resources(),
        region_config,
        GATE_SLOT,
        command.fault_capability_requirement(),
    )
    .map_err(|source| QemuLiveNodeStepGateError::HostSetup { source })?;
    if !setup.setup_ack().can_schedule() {
        return Err(QemuLiveNodeStepGateError::SetupAckNotReady);
    }
    let debug_guest_activation_stream = debug_guest_activation_listener
        .map(|listener| listener.accept().map(|(stream, _address)| stream))
        .transpose()
        .map_err(|source| {
            QemuLiveNodeStepGateError::prime(
                "accept debug guest activation stream",
                QemuNodeChannelError::new(
                    "accept debug guest activation stream",
                    source.to_string(),
                ),
            )
        })?;
    let console_observation = config
        .console_capture
        .then(|| {
            // QEMU realizes chardevs before the plugin publishes its setup ACK,
            // so a missing socket here is a launch failure rather than a race.
            crate::unix_socket_path::connect(
                &run_directory.join(crate::QEMU_CONSOLE_SOCKET_FILE_NAME),
            )
        })
        .transpose()
        .map_err(|source| {
            QemuLiveNodeStepGateError::prime(
                "connect console observation",
                QemuNodeChannelError::new("connect QEMU console stream", source.to_string()),
            )
        })?;

    let console_spool = console_observation
        .as_ref()
        .map(|_stream| QemuConsoleObservationSpool::new());
    let runtime = QemuLiveHostIoRuntime::from_shmem_fd(
        setup.shmem_as_fd(),
        setup.wake_as_fd(),
        setup.region().region_len,
        GATE_SLOT,
    )
    .map_err(|source| QemuLiveNodeStepGateError::HostIoRuntime { source })?;
    let mut runtime = match (console_observation, console_spool.as_ref()) {
        (Some(output), Some(spool)) => {
            let reader =
                QemuConsoleObservationReader::new(output, spool.clone()).map_err(|source| {
                    QemuLiveNodeStepGateError::prime(
                        "configure console observation",
                        QemuNodeChannelError::new(
                            "configure QEMU console stream",
                            source.to_string(),
                        ),
                    )
                })?;
            runtime
                .with_console_observation(reader)
                .map_err(|source| QemuLiveNodeStepGateError::HostIoRuntime { source })?
        }
        (None, None) => runtime,
        _ => {
            return Err(QemuLiveNodeStepGateError::prime(
                "configure console observation",
                QemuNodeChannelError::new(
                    "configure QEMU console stream",
                    "console stream and staging spool disagreed",
                ),
            ));
        }
    };
    let mut block_servicer = if let Some(block) = &config.shmem_block {
        let mut servicer = QemuLiveBlockIoServicer::from_shmem_fd_with_base(
            setup.shmem_as_fd(),
            setup.region().region_len,
            GATE_SLOT,
            config.icount_shift,
            block.base.clone(),
        )
        .map_err(|source| QemuLiveNodeStepGateError::BlockServicer { source })?;
        servicer
            .configure_storage_faults(block.durability.clone(), block.require_fault_directives)
            .map_err(|source| QemuLiveNodeStepGateError::BlockServicer { source })?;
        Some(servicer)
    } else {
        None
    };
    let mut ninep_servicer = config
        .shmem_ninep
        .as_ref()
        .map(|ninep| {
            QemuLive9pIoServicer::from_shmem_fd_with_tree(
                setup.shmem_as_fd(),
                setup.region().region_len,
                GATE_SLOT,
                config.icount_shift,
                ninep.tree.clone(),
                ninep.latency,
            )
        })
        .transpose()
        .map_err(|source| QemuLiveNodeStepGateError::NinepServicer { source })?;
    let accelerator_servicer = config
        .accelerator
        .then(|| {
            QemuLiveAcceleratorServicer::from_shmem_fd(
                setup.shmem_as_fd(),
                setup.region().region_len,
                GATE_SLOT,
            )
        })
        .transpose()
        .map_err(|source| QemuLiveNodeStepGateError::AcceleratorServicer { source })?;
    let restoring_checkpoint = restore.is_some();
    let mut priming = prime_guest_off_boot_barrier(
        &setup,
        config.completion_timeout,
        identity,
        config.coverage,
        block_servicer.as_mut(),
        ninep_servicer.as_mut(),
        (!restoring_checkpoint)
            .then_some(config.boot_network_backpressure_capture.as_ref())
            .flatten()
            .map(|capture| capture.payload.as_slice()),
    )?;
    let qmp = connect_qmp_priming_main_loop(
        &setup,
        &qmp_config.socket_path(run_directory),
        config.completion_timeout,
    )
    .map_err(|source| QemuLiveNodeStepGateError::QmpConnect { source })?;
    if !restoring_checkpoint
        && let Some(capture) = config.boot_network_backpressure_capture.as_ref()
        && capture.capture_icount > 1
    {
        let initial_network = priming.retained_network.take().ok_or_else(|| {
            QemuLiveNodeStepGateError::ExactSnapshotInvariant {
                reason: String::from(
                    "boot backpressure continuation lost its icount-1 transport state",
                ),
            }
        })?;
        priming = continue_boot_network_backpressure_capture(
            &setup,
            config.completion_timeout,
            identity,
            config.coverage,
            BootNetworkBackpressureContinuation {
                block: block_servicer.as_mut(),
                ninep: ninep_servicer.as_mut(),
                payload: capture.payload.as_slice(),
                capture_icount: capture.capture_icount,
                initial_network,
                emitted_frames: priming.emitted_frames,
            },
        )?;
    }
    if let (Some(servicer), Some(block)) = (block_servicer.as_mut(), config.shmem_block.as_ref()) {
        servicer
            .set_latency_model(block.latency)
            .map_err(|source| QemuLiveNodeStepGateError::BlockServicer { source })?;
    }
    if let Some(servicer) = block_servicer {
        runtime = runtime
            .with_block_servicer(servicer, BlockIoDiagnostics::shared())
            .map_err(|source| QemuLiveNodeStepGateError::BlockServicer { source })?;
    }
    if let Some(servicer) = ninep_servicer {
        runtime = runtime.with_ninep_servicer(servicer, NinepIoDiagnostics::shared());
    }
    if let Some(servicer) = accelerator_servicer {
        runtime = runtime.with_accelerator_servicer(servicer);
    }
    let qmp = if config.whitebox == QemuLaunchPluginSwitch::On {
        qmp.with_predeclared_debug_guest_endpoint()
            .with_debug_guest_activation_stream(debug_guest_activation_stream.ok_or_else(|| {
                QemuLiveNodeStepGateError::prime(
                    "configure debug guest activation stream",
                    QemuNodeChannelError::new(
                        "configure debug guest activation stream",
                        "white-box launch omitted its activation stream",
                    ),
                )
            })?)
    } else {
        qmp
    };

    let shmem_config = QemuQuantumShmemConfig::new(node_id(identity.node), GATE_SLOT)
        .with_router(node_id(identity.router), SLOT_NET_ROUTER as u32)
        .with_coverage(basic_block_coverage_config(config.coverage));
    let factory_runtime = QemuNodeFactoryRuntime::new(
        shmem_config,
        GateSendAuthorizer,
        gate_shutdown_policy(),
        gate_async_policy(config.completion_timeout),
        QemuCrashDetector::new(identity.crash_detector),
        runtime,
    );
    let mut node = match restore {
        Some(restore) if resume_restored => {
            build_qemu_node_from_restored_checkpoint(child, setup, qmp, restore, factory_runtime)
        }
        Some(restore) => build_qemu_node_from_restored_checkpoint_paused(
            child,
            setup,
            qmp,
            restore,
            factory_runtime,
        ),
        None => build_qemu_node_from_completed_setup(child, setup, qmp, factory_runtime),
    }
    .map_err(|source| QemuLiveNodeStepGateError::NodeFactory { source })?;
    if let Some(gdbstub) = &config.gdbstub {
        node = node.with_gdbstub(gdbstub.clone());
    }
    if let Some(console_spool) = console_spool {
        node = node.with_console_observation(node_id(identity.node), console_spool);
    }
    if !restoring_checkpoint {
        node.retain_priming_network_outputs(priming.emitted_frames)
            .map_err(|source| {
                QemuLiveNodeStepGateError::node_op("retain priming network outputs", source)
            })?;
    }
    if let Some(network) = &priming.retained_network {
        node.restore_network_transport_for_gate(network)
            .map_err(|source| {
                QemuLiveNodeStepGateError::node_op(
                    "bind retained priming network continuation",
                    source,
                )
            })?;
    }
    node.synchronize_observed_time().map_err(|source| {
        QemuLiveNodeStepGateError::node_op("synchronize primed icount", source)
    })?;
    Ok(node)
}

#[path = "node_step_gate/support.rs"]
mod support;

use support::*;
