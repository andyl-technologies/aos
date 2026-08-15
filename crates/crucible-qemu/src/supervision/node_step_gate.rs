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

use std::fs;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crucible::{
    AdvanceOutcome, BasicBlockCoverageConfig, Checkpoint, CheckpointKind, ContentHash,
    ExecutionFingerprint, Icount, NodeId, SchedulerError, SchedulerNodeId,
    SchedulerSendAuthorization, SchedulerSendAuthorizer, VirtualTime,
};
use crucible_device::block::{BaseImage, BlockDurabilityConfig, BlockLatency};
use crucible_device::{FsTree, NinepLatency};
use crucible_shmem::{RegionAllocation, RegionConfig, SLOT_NET_ROUTER, mmap_setup_region};

use crate::console_observation::{QemuConsoleObservationReader, QemuConsoleObservationSpool};
use crate::supervision::{
    BlockIoDiagnostics, NinepIoDiagnostics, QemuLive9pIoServicer, QemuLiveAcceleratorServicer,
    QemuLiveBlockIoServicer, QemuLiveHostIoRuntime,
};
use crate::{
    CrucibleAcceleratorDevice, CrucibleShmem9pDevice, CrucibleShmemBlockDevice,
    CrucibleShmemNetworkDevice, IcountShiftSetting, LaunchProfileCandidate, LaunchProfileError,
    LivePluginGuestArchitecture, ProductionFaultRuntime, QemuAsyncDriverPolicy, QemuCrashDetector,
    QemuGdbstubChannelConfig, QemuHostPluginSetupError, QemuLaunchAppRandomConfig,
    QemuLaunchArtifact, QemuLaunchCommandBuilder, QemuLaunchCommandError, QemuLaunchPluginConfig,
    QemuLaunchPluginSwitch, QemuMappedQuantumShmemHotPath, QemuMappedQuantumShmemHotPathError,
    QemuNode, QemuNodeChannelError, QemuNodeError, QemuNodeFactoryError, QemuNodeFactoryRuntime,
    QemuNodeRestorePlan, QemuNodeSet, QemuQmpChannelConfig, QemuQuantumShmemConfig,
    QemuRootImageFormat, QemuShmemHotPathChannel, QemuShutdownPolicy, QemuVmLaunchConfig,
    QemuVmSnapshot, QemuWhiteboxSetupError, QmpError, build_qemu_node_from_completed_setup,
    build_qemu_node_from_restored_checkpoint, build_qemu_node_from_restored_checkpoint_paused,
    complete_qemu_host_plugin_setup, spawn_qemu_child_with_fds_in_directory,
};

use super::QemuLiveHostIoRuntimeError;

mod error;
pub use error::QemuLiveNodeStepGateError;

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
/// Number of background threads used to stress host scheduling on the load run.
const HOST_LOAD_WORKERS: usize = 4;
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
    whitebox: QemuLaunchPluginSwitch,
    app_random: Option<QemuLaunchAppRandomConfig>,
    coverage: QemuLaunchPluginSwitch,
    shmem_network_mac: Option<String>,
    shmem_block: Option<QemuLiveNodeStepBlockConfig>,
    shmem_ninep: Option<QemuLiveNodeStepNinepConfig>,
    accelerator: bool,
    queue_capacity: u32,
    schedule: QemuLiveNodeStepSchedule,
    completion_timeout: Duration,
    second_run_host_load: bool,
    console_capture: bool,
    fault_capabilities: Option<crucible::model::WorldNodeFaultCapabilities>,
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
            whitebox: QemuLaunchPluginSwitch::Off,
            app_random: None,
            coverage: QemuLaunchPluginSwitch::Off,
            shmem_network_mac: None,
            shmem_block: None,
            shmem_ninep: None,
            accelerator: false,
            queue_capacity: GATE_QUEUE_CAPACITY,
            schedule: QemuLiveNodeStepSchedule::new(),
            completion_timeout: Duration::from_secs(240),
            second_run_host_load: true,
            console_capture: false,
            fault_capabilities: None,
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
            whitebox: QemuLaunchPluginSwitch::Off,
            app_random: None,
            coverage: QemuLaunchPluginSwitch::Off,
            shmem_network_mac: None,
            shmem_block: None,
            shmem_ninep: None,
            accelerator: false,
            queue_capacity: GATE_QUEUE_CAPACITY,
            schedule: QemuLiveNodeStepSchedule::new(),
            completion_timeout: Duration::from_secs(240),
            second_run_host_load: true,
            console_capture: false,
            fault_capabilities: None,
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

    /// Returns this configuration with host CPU load on the second run toggled.
    #[must_use]
    pub const fn with_second_run_host_load(mut self, second_run_host_load: bool) -> Self {
        self.second_run_host_load = second_run_host_load;
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
    /// The second run, under host CPU load, matched the first byte for byte.
    pub deterministic_under_host_load: bool,
    /// Host CPU load was actually applied during the second run.
    pub host_load_applied: bool,
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
    /// Raw node icount reached by the restored and independently replayed suffix.
    pub suffix_icount: u64,
    /// Captured logical icount minus QEMU's raw icount after an idle jump.
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
    /// The signal runtime emitted exactly one lifecycle impulse.
    pub signal_impulse_applied: bool,
}

/// Drives the first live [`QemuNode`] through a bounded busy-window step schedule.
///
/// Boots the diskless-firmware guest with the Rust control plugin and QMP,
/// assembles a real [`QemuNode`] over the production host-I/O runtime, advances
/// it through the schedule's busy-window ceilings, and repeats the whole run --
/// the second time under host CPU load -- requiring the two runs to be
/// byte-identical.
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
    let (second, host_load_applied) = if config.second_run_host_load {
        (
            run_one_scenario(config, &ceilings, RunRole::HostLoad)?,
            true,
        )
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
        deterministic_under_host_load: true,
        host_load_applied,
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
    let run_directory = config.run_directory.join("signal-node-lifecycle");
    fs::create_dir_all(&run_directory).map_err(|source| {
        QemuLiveNodeStepGateError::PrepareRunDirectory {
            path: run_directory.clone(),
            source,
        }
    })?;

    let identity = node_id(GATE_NODE);
    let mut node = build_live_node(
        config,
        &run_directory,
        LiveNodeIdentity {
            node: GATE_NODE,
            router: GATE_ROUTER,
            crash_detector: "signal-node-lifecycle",
        },
        None,
        true,
    )?;
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

    let plan = lifecycle_crash_plan(GATE_NODE)?;
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
        signal_impulse_applied: evaluation.actions.len() == 1,
    })
}

fn lifecycle_crash_plan(
    node_name: &str,
) -> Result<crucible::model::FaultSignalPlan, QemuLiveNodeStepGateError> {
    use crucible::model::{
        BindingEventParent, BindingMapping, BindingObservabilityPolicy, BindingSampling,
        BindingSearchPolicy, EFFECT_SEMANTIC_VERSION, EffectLifetime, EffectRequest,
        EffectSpecification, FaultBinding, FaultObjectId, FaultPhase, FaultResourceLimits,
        NodeBootPolicy, NodeEffectSpecification, NodeLifecycleTransition, NodeStatePolicy,
        ResolvedFaultTarget, ResolvedTargetSet, SignalCoordinate, SignalDomain, SignalId,
        SignalNode, SignalNodeKind, SignalPoint, SignalProgram, SignalResourceLimits, SignalShape,
        SignalSourceSpecification, SignalUnit, SignalValue, SignalValueType, TargetSelector,
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
    let targets = ResolvedTargetSet::new(
        vec![ResolvedFaultTarget::Node {
            node: parse_object(node_name)?,
        }],
        false,
    )
    .map_err(|error| fault_gate_invariant(format!("node target: {error}")))?;
    let effect = EffectRequest::new(
        EFFECT_SEMANTIC_VERSION,
        EffectLifetime::Impulse,
        EffectSpecification::Node(NodeEffectSpecification::Lifecycle {
            transition: NodeLifecycleTransition::Crash,
            downtime_nanos: 1,
            boot_policy: NodeBootPolicy::Immediate,
            volatile_state_policy: NodeStatePolicy::Preserve,
            device_state_policy: NodeStatePolicy::Clear,
        }),
    )
    .map_err(|error| fault_gate_invariant(format!("lifecycle effect: {error}")))?;
    let binding = FaultBinding::new(
        parse_object("live-node-lifecycle-binding")?,
        vec![output],
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
    .map_err(|error| fault_gate_invariant(format!("lifecycle binding: {error}")))?;
    crucible::model::FaultSignalPlan::new(
        vec![program],
        vec![binding],
        FaultResourceLimits::default(),
    )
    .map_err(|error| fault_gate_invariant(format!("lifecycle plan: {error}")))
}

fn fault_gate_invariant(reason: impl Into<String>) -> QemuLiveNodeStepGateError {
    QemuLiveNodeStepGateError::ExactSnapshotInvariant {
        reason: reason.into(),
    }
}

/// Runs an exact live snapshot through save, crash, load, and continued execution.
///
/// The capture process is force-killed before its VMState file is copied into a
/// fresh run directory. The restored suffix is compared with a separately
/// launched execution that reaches the same capture boundary without loading
/// the snapshot. When `require_pending_block_io` is true, the function stops at
/// the first completed quantum whose production block continuation contains
/// a guest-completed storage mutation still pending in the Apache-side
/// durability continuation. The transport itself is quiescent so QEMU savevm
/// can drain without waiting on an active virtio request.
///
/// # Errors
///
/// Returns [`QemuLiveNodeStepGateError`] when launch, bounded execution, paired
/// capture, forced crash, artifact copy, restore, replay, or any identity and
/// fingerprint comparison fails.
pub fn run_qemu_live_exact_snapshot_gate(
    config: &QemuLiveNodeStepGateConfig,
    capture_ceiling: u64,
    suffix_increment: u64,
    require_pending_block_io: bool,
) -> Result<QemuLiveExactSnapshotReport, QemuLiveNodeStepGateError> {
    if capture_ceiling <= PRIME_CEILING_ICOUNT || suffix_increment == 0 {
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: String::from(
                "capture ceiling must follow priming and suffix increment must be nonzero",
            ),
        });
    }
    if config.root_image.is_some() {
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: String::from(
                "the live exact-snapshot gate accepts firmware plus shared-memory devices, not a separately managed root overlay",
            ),
        });
    }

    let capture_directory = config.run_directory.join("exact-capture");
    let restore_directory = config.run_directory.join("exact-restore");
    let replay_directory = config.run_directory.join("exact-replay");
    for directory in [&capture_directory, &restore_directory, &replay_directory] {
        fs::create_dir_all(directory).map_err(|source| {
            QemuLiveNodeStepGateError::PrepareRunDirectory {
                path: directory.clone(),
                source,
            }
        })?;
    }

    let identity = node_id(GATE_NODE);
    let mut capture_node = build_live_node(
        config,
        &capture_directory,
        LiveNodeIdentity {
            node: GATE_NODE,
            router: GATE_ROUTER,
            crash_detector: "live-exact-capture",
        },
        None,
        true,
    )?;
    let (capture_icount, pending_block_io_captured) = if require_pending_block_io {
        drive_to_pending_block_boundary(&mut capture_node, capture_ceiling)?
    } else {
        let quantum = advance_to_busy_ceiling(&mut capture_node, capture_ceiling)?;
        (quantum.completion_icount, false)
    };
    let checkpoint = exact_gate_checkpoint(&identity, capture_icount, require_pending_block_io);
    let snapshot = capture_node
        .capture_exact_snapshot(&identity, checkpoint.clone())
        .map_err(|source| QemuLiveNodeStepGateError::node_op("capture exact snapshot", source))?;
    let capture_logical_time_offset = snapshot
        .node_continuation()
        .logical_time_calibration()
        .offset()
        .map_err(|source| QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!("captured logical-time calibration is invalid: {source}"),
        })?;
    if !require_pending_block_io && capture_logical_time_offset == 0 {
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: String::from(
                "diskless exact restore did not capture a nonzero idle-jump logical-time offset",
            ),
        });
    }
    let capture_fingerprint = capture_node
        .execution_fingerprint()
        .map_err(|source| QemuLiveNodeStepGateError::ExecutionFingerprint { source })?
        .hash;
    capture_node
        .force_crash_and_reap_for_gate()
        .map_err(|source| {
            QemuLiveNodeStepGateError::node_op("force crash after capture", source)
        })?;
    drop(capture_node);

    copy_exact_gate_artifact(
        &capture_directory.join(crate::DEFAULT_VMSTATE_FILE_NAME),
        &restore_directory.join(crate::DEFAULT_VMSTATE_FILE_NAME),
    )?;
    let restore_config = config.clone().with_run_directory(&restore_directory);
    let mut restored = launch_qemu_live_node_exact_snapshot(
        &restore_config,
        &restore_directory,
        GATE_NODE,
        GATE_ROUTER,
        "live-exact-restore",
        &snapshot,
    )?;
    let restored_icount = restored
        .current_icount()
        .map_err(|source| QemuLiveNodeStepGateError::node_op("read restored icount", source))?
        .retired;
    let restored_fingerprint = restored
        .execution_fingerprint()
        .map_err(|source| QemuLiveNodeStepGateError::ExecutionFingerprint { source })?
        .hash;
    if restored_icount != capture_icount || restored_fingerprint != capture_fingerprint {
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!(
                "restore boundary differs: icount {restored_icount}/{capture_icount}, fingerprint {}/{}",
                restored_fingerprint.to_hex(),
                capture_fingerprint.to_hex()
            ),
        });
    }
    let suffix_icount = capture_icount
        .checked_add(suffix_increment)
        .ok_or_else(|| QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: String::from("post-restore suffix ceiling overflowed"),
        })?;
    advance_to_busy_ceiling(&mut restored, suffix_icount)?;
    let suffix_fingerprint = restored
        .execution_fingerprint()
        .map_err(|source| QemuLiveNodeStepGateError::ExecutionFingerprint { source })?
        .hash;
    restored
        .shutdown_child()
        .map_err(|source| QemuLiveNodeStepGateError::Shutdown { source })?;

    let replay_config = config.clone().with_run_directory(&replay_directory);
    let mut replay = build_live_node(
        &replay_config,
        &replay_directory,
        LiveNodeIdentity {
            node: GATE_NODE,
            router: GATE_ROUTER,
            crash_detector: "live-exact-replay",
        },
        None,
        true,
    )?;
    advance_to_busy_ceiling(&mut replay, capture_icount)?;
    let replay_snapshot = replay
        .capture_exact_snapshot(&identity, checkpoint)
        .map_err(|source| QemuLiveNodeStepGateError::node_op("capture replay oracle", source))?;
    let replay_oracle_pair_match = replay_snapshot.id() == snapshot.id();
    if !replay_oracle_pair_match {
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!(
                "paired snapshot identity differs from replay: {} != {}",
                snapshot.id().to_hex(),
                replay_snapshot.id().to_hex()
            ),
        });
    }
    advance_to_busy_ceiling(&mut replay, suffix_icount)?;
    let replay_suffix_fingerprint = replay
        .execution_fingerprint()
        .map_err(|source| QemuLiveNodeStepGateError::ExecutionFingerprint { source })?
        .hash;
    if replay_suffix_fingerprint != suffix_fingerprint {
        return Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
            reason: format!(
                "restored suffix fingerprint {} differs from replay {}",
                suffix_fingerprint.to_hex(),
                replay_suffix_fingerprint.to_hex()
            ),
        });
    }
    replay
        .shutdown_child()
        .map_err(|source| QemuLiveNodeStepGateError::Shutdown { source })?;

    Ok(QemuLiveExactSnapshotReport {
        smp_vcpus: config.smp_vcpus,
        capture_icount,
        restored_icount,
        suffix_icount,
        capture_logical_time_offset,
        capture_fingerprint,
        suffix_fingerprint,
        replay_oracle_pair_match,
        old_process_force_crashed: true,
        pending_block_io_captured,
    })
}

fn drive_to_pending_block_boundary(
    node: &mut QemuNode,
    ceiling: u64,
) -> Result<(u64, bool), QemuLiveNodeStepGateError> {
    // Keep each live QEMU await comfortably below the bounded host timeout.
    // The block workload's configured ceiling is only a search limit; issuing
    // that entire span as one quantum can spend minutes in TCG before the host
    // gets the next deterministic opportunity to inspect real transport state.
    const PENDING_SEARCH_QUANTUM_ICOUNT: u64 = 10_000_000;
    const MAX_PENDING_SEARCH_QUANTA: usize = 8_192;
    let mut quiescent_continuation_observed = false;
    let mut last = node
        .current_icount()
        .map_err(|source| QemuLiveNodeStepGateError::node_op("read block search icount", source))?
        .retired;
    for _ in 0..MAX_PENDING_SEARCH_QUANTA {
        let search_ceiling = last
            .saturating_add(PENDING_SEARCH_QUANTUM_ICOUNT)
            .min(ceiling);
        let _ = node
            .advance_to_ceiling(Icount {
                retired: search_ceiling,
            })
            .map_err(|source| {
                QemuLiveNodeStepGateError::node_op("advance toward pending block boundary", source)
            })?;
        let current = node
            .current_icount()
            .map_err(|source| {
                QemuLiveNodeStepGateError::node_op("read pending block boundary", source)
            })?
            .retired;
        let pending = node.has_pending_device_io_for_gate().map_err(|source| {
            QemuLiveNodeStepGateError::node_op("inspect pending block continuation", source)
        })?;
        if pending && quiescent_continuation_observed {
            return Ok((current, true));
        }
        if pending {
            // Consuming the response frame makes the transport appear empty
            // just before QEMU's block coroutine returns. Require another full
            // scheduler/main-loop rendezvous before savevm so block graph drain
            // cannot race that final coroutine unwind.
            quiescent_continuation_observed = true;
        } else {
            quiescent_continuation_observed = false;
        }
        if current >= ceiling || (current <= last && !quiescent_continuation_observed) {
            break;
        }
        last = current;
    }
    Err(QemuLiveNodeStepGateError::ExactSnapshotInvariant {
        reason: format!(
            "no quiescent production block durability continuation was observed before ceiling {ceiling}"
        ),
    })
}

fn exact_gate_checkpoint(node: &NodeId, icount: u64, block: bool) -> Checkpoint {
    let identity = ContentHash::from_canonical_material(
        "crucible.qemu.live-exact-snapshot-gate.v1",
        &format!("node={}\nicount={icount}\nblock={block}", node.name),
    );
    let mut checkpoint = Checkpoint::new(identity, identity, CheckpointKind::Fat);
    checkpoint.virtual_time = VirtualTime { ticks: icount };
    checkpoint
        .node_icounts
        .insert(node.clone(), Icount { retired: icount });
    checkpoint
}

fn copy_exact_gate_artifact(
    source_path: &Path,
    destination_path: &Path,
) -> Result<(), QemuLiveNodeStepGateError> {
    fs::copy(source_path, destination_path).map_err(|source| {
        QemuLiveNodeStepGateError::SnapshotArtifactCopy {
            source_path: source_path.to_path_buf(),
            destination_path: destination_path.to_path_buf(),
            source,
        }
    })?;
    Ok(())
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

/// Which scenario run this is, controlling the run subdirectory and host load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunRole {
    Reference,
    HostLoad,
    Repeat,
}

impl RunRole {
    const fn subdir(self) -> &'static str {
        match self {
            Self::Reference => "run-reference",
            Self::HostLoad => "run-host-load",
            Self::Repeat => "run-repeat",
        }
    }

    const fn applies_host_load(self) -> bool {
        matches!(self, Self::HostLoad)
    }
}

fn run_one_scenario(
    config: &QemuLiveNodeStepGateConfig,
    ceilings: &[u64],
    role: RunRole,
) -> Result<NodeStepOutcome, QemuLiveNodeStepGateError> {
    let run_directory = config.run_directory.join(role.subdir());
    let host_load = HostLoad::start_if(role.applies_host_load());
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

    let quanta = drive_busy_window_steps(&mut node, ceilings)?;
    let fingerprint = node
        .execution_fingerprint()
        .map_err(|source| QemuLiveNodeStepGateError::ExecutionFingerprint { source })?;

    let shutdown = node
        .shutdown_child()
        .map_err(|source| QemuLiveNodeStepGateError::Shutdown { source })?;
    let orderly_child_exit = shutdown.reaped && !shutdown.leaked;

    drop(node);
    drop(host_load);

    Ok(NodeStepOutcome {
        quanta,
        fingerprint,
        orderly_child_exit,
    })
}

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
            UnixListener::bind(
                run_directory.join(crate::QEMU_DEBUG_GUEST_ACTIVATION_SOCKET_FILE_NAME),
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
    let mut command = match &config.fault_capabilities {
        Some(capabilities) => {
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
        None => QemuLaunchCommandBuilder::new_for_live_gate(
            profile,
            vm,
            path_text(&config.qemu_executable),
            plugin,
            config.architecture,
        ),
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
            UnixStream::connect(run_directory.join(crate::QEMU_CONSOLE_SOCKET_FILE_NAME))
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
    let priming_network_outputs = prime_guest_off_boot_barrier(
        &setup,
        config.completion_timeout,
        identity.node,
        identity.router,
        config.coverage,
        block_servicer.as_mut(),
        ninep_servicer.as_mut(),
    )?;
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
    let qmp = connect_qmp_priming_main_loop(
        &setup,
        &qmp_config.socket_path(run_directory),
        config.completion_timeout,
    )
    .map_err(|source| QemuLiveNodeStepGateError::QmpConnect { source })?;
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
    let restoring_checkpoint = restore.is_some();
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
        node.retain_priming_network_outputs(priming_network_outputs);
    }
    node.synchronize_observed_time().map_err(|source| {
        QemuLiveNodeStepGateError::node_op("synchronize primed icount", source)
    })?;
    Ok(node)
}

#[path = "node_step_gate/support.rs"]
mod support;

use support::*;
