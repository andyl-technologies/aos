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
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crucible::{
    AdvanceOutcome, BasicBlockCoverageConfig, ExecutionFingerprint, Icount, NodeId, SchedulerError,
    SchedulerNodeId, SchedulerSendAuthorization, SchedulerSendAuthorizer,
};
use crucible_device::block::{BaseImage, BlockDurabilityConfig};
use crucible_shmem::{RegionAllocation, RegionConfig, SLOT_NET_ROUTER, mmap_setup_region};

use crate::supervision::{BlockIoDiagnostics, QemuLiveBlockIoServicer, QemuLiveHostIoRuntime};
use crate::{
    CrucibleShmemBlockDevice, CrucibleShmemNetworkDevice, IcountShiftSetting,
    LaunchProfileCandidate, LaunchProfileError, QemuAsyncDriverPolicy, QemuCrashDetector,
    QemuGdbstubChannelConfig, QemuHostPluginSetupError, QemuLaunchAppRandomConfig,
    QemuLaunchArtifact, QemuLaunchCommandBuilder, QemuLaunchCommandError, QemuLaunchPluginConfig,
    QemuLaunchPluginSwitch, QemuMappedQuantumShmemHotPath, QemuMappedQuantumShmemHotPathError,
    QemuNode, QemuNodeChannelError, QemuNodeError, QemuNodeFactoryError, QemuNodeFactoryRuntime,
    QemuNodeRestorePlan, QemuQmpChannelConfig, QemuQuantumShmemConfig, QemuRootImageFormat,
    QemuShmemHotPathChannel, QemuShutdownPolicy, QemuVmLaunchConfig, QemuWhiteboxSetupError,
    QmpError, build_qemu_node_from_completed_setup, build_qemu_node_from_restored_checkpoint,
    complete_qemu_host_plugin_setup, spawn_qemu_child_with_fds_in_directory,
};

use super::QemuLiveHostIoRuntimeError;

mod error;
pub use error::QemuLiveNodeStepGateError;

/// Content-addressing domain for node-step launch artifacts.
const GATE_DOMAIN: &str = "crucible.loaded-qemu-live-node-step.v1";
/// Stable node name for the single-VM node-step run.
const GATE_NODE: &str = "live-node-step-vm";
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
    qemu_executable: PathBuf,
    plugin: PathBuf,
    kernel: PathBuf,
    firmware: PathBuf,
    root_image: Option<PathBuf>,
    root_image_format: QemuRootImageFormat,
    run_directory: PathBuf,
    initrd: Option<PathBuf>,
    kernel_cmdline: Option<String>,
    gdbstub: Option<QemuGdbstubChannelConfig>,
    memory_mib: u32,
    smp_vcpus: u16,
    icount_shift: u8,
    scenario_seed: u64,
    whitebox: QemuLaunchPluginSwitch,
    app_random: Option<QemuLaunchAppRandomConfig>,
    coverage: QemuLaunchPluginSwitch,
    shmem_network_mac: Option<String>,
    shmem_block: Option<QemuLiveNodeStepBlockConfig>,
    queue_capacity: u32,
    schedule: QemuLiveNodeStepSchedule,
    completion_timeout: Duration,
    second_run_host_load: bool,
    console_capture: bool,
}

#[derive(Clone, Debug)]
struct QemuLiveNodeStepBlockConfig {
    base: BaseImage,
    durability: BlockDurabilityConfig,
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
            qemu_executable: qemu_executable.into(),
            plugin: plugin.into(),
            kernel: kernel.into(),
            firmware: firmware.into(),
            root_image: None,
            root_image_format: QemuRootImageFormat::Qcow2,
            run_directory: run_directory.into(),
            initrd: None,
            kernel_cmdline: None,
            gdbstub: None,
            memory_mib: GATE_MEMORY_MIB,
            smp_vcpus: 1,
            icount_shift: 0,
            scenario_seed: 0,
            whitebox: QemuLaunchPluginSwitch::Off,
            app_random: None,
            coverage: QemuLaunchPluginSwitch::Off,
            shmem_network_mac: None,
            shmem_block: None,
            queue_capacity: GATE_QUEUE_CAPACITY,
            schedule: QemuLiveNodeStepSchedule::new(),
            completion_timeout: Duration::from_secs(240),
            second_run_host_load: true,
            console_capture: false,
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
            qemu_executable: qemu_executable.into(),
            plugin: plugin.into(),
            kernel: kernel.into(),
            firmware: PathBuf::new(),
            root_image: Some(root_image.into()),
            root_image_format: QemuRootImageFormat::Qcow2,
            run_directory: run_directory.into(),
            initrd: None,
            kernel_cmdline: None,
            gdbstub: None,
            memory_mib: GATE_MEMORY_MIB,
            smp_vcpus: 1,
            icount_shift: 0,
            scenario_seed: 0,
            whitebox: QemuLaunchPluginSwitch::Off,
            app_random: None,
            coverage: QemuLaunchPluginSwitch::Off,
            shmem_network_mac: None,
            shmem_block: None,
            queue_capacity: GATE_QUEUE_CAPACITY,
            schedule: QemuLiveNodeStepSchedule::new(),
            completion_timeout: Duration::from_secs(240),
            second_run_host_load: true,
            console_capture: false,
        }
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
        self.shmem_block = Some(QemuLiveNodeStepBlockConfig { base, durability });
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
) -> Result<QemuNode, QemuLiveNodeStepGateError> {
    fs::create_dir_all(run_directory).map_err(|source| {
        QemuLiveNodeStepGateError::PrepareRunDirectory {
            path: run_directory.to_path_buf(),
            source,
        }
    })?;

    let mut candidate = LaunchProfileCandidate::default()
        .with_memory_mib(config.memory_mib)
        .with_smp_vcpus(config.smp_vcpus)
        .with_icount_shift(IcountShiftSetting::Fixed(config.icount_shift))
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
    let mut command =
        QemuLaunchCommandBuilder::new(profile, vm, path_text(&config.qemu_executable), plugin)
            .with_qmp(qmp_config.clone());
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

    let mut runtime = QemuLiveHostIoRuntime::from_shmem_fd(
        setup.shmem_as_fd(),
        setup.wake_as_fd(),
        setup.region().region_len,
        GATE_SLOT,
    )
    .map_err(|source| QemuLiveNodeStepGateError::HostIoRuntime { source })?;
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
            .configure_storage_faults(block.durability.clone(), true)
            .map_err(|source| QemuLiveNodeStepGateError::BlockServicer { source })?;
        Some(servicer)
    } else {
        None
    };
    let priming_network_outputs = prime_guest_off_boot_barrier(
        &setup,
        config.completion_timeout,
        identity.node,
        identity.router,
        config.coverage,
        block_servicer.as_mut(),
    )?;
    if let Some(servicer) = block_servicer {
        runtime = runtime.with_block_servicer(servicer, BlockIoDiagnostics::shared());
    }
    let qmp = connect_qmp_priming_main_loop(&setup, &qmp_config.socket_path(run_directory))
        .map_err(|source| QemuLiveNodeStepGateError::QmpConnect { source })?;

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
        Some(restore) => {
            build_qemu_node_from_restored_checkpoint(child, setup, qmp, restore, factory_runtime)
        }
        None => build_qemu_node_from_completed_setup(child, setup, qmp, factory_runtime),
    }
    .map_err(|source| QemuLiveNodeStepGateError::NodeFactory { source })?;
    if let Some(gdbstub) = &config.gdbstub {
        node = node.with_gdbstub(gdbstub.clone());
    }
    if let Some(console_observation) = console_observation {
        node = node
            .with_console_observation(node_id(identity.node), console_observation)
            .map_err(|source| {
                QemuLiveNodeStepGateError::prime("configure console observation", source)
            })?;
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
