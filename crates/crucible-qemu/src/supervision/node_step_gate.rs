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
    AdvanceOutcome, ExecutionFingerprint, Icount, NodeId, SchedulerError, SchedulerNodeId,
    SchedulerSendAuthorization, SchedulerSendAuthorizer,
};
use crucible_shmem::{RegionAllocation, RegionConfig, SLOT_NET_ROUTER, mmap_setup_region};

use crate::supervision::QemuLiveHostIoRuntime;
use crate::{
    LaunchProfileCandidate, LaunchProfileError, QemuAsyncDriverPolicy, QemuCrashDetector,
    QemuHostPluginSetupError, QemuLaunchArtifact, QemuLaunchCommandBuilder, QemuLaunchCommandError,
    QemuLaunchPluginConfig, QemuMappedQuantumShmemHotPath, QemuMappedQuantumShmemHotPathError,
    QemuNode, QemuNodeChannelError, QemuNodeError, QemuNodeFactoryError, QemuNodeFactoryRuntime,
    QemuQmpChannelConfig, QemuQuantumShmemConfig, QemuShmemHotPathChannel, QemuShutdownPolicy,
    QemuVmLaunchConfig, QmpError, build_qemu_node_from_completed_setup,
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
    run_directory: PathBuf,
    initrd: Option<PathBuf>,
    kernel_cmdline: Option<String>,
    schedule: QemuLiveNodeStepSchedule,
    completion_timeout: Duration,
    second_run_host_load: bool,
}

impl QemuLiveNodeStepGateConfig {
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
            run_directory: run_directory.into(),
            initrd: None,
            kernel_cmdline: None,
            schedule: QemuLiveNodeStepSchedule::new(),
            completion_timeout: Duration::from_secs(240),
            second_run_host_load: true,
        }
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
) -> Result<QemuNode, QemuLiveNodeStepGateError> {
    fs::create_dir_all(run_directory).map_err(|source| {
        QemuLiveNodeStepGateError::PrepareRunDirectory {
            path: run_directory.to_path_buf(),
            source,
        }
    })?;

    let mut candidate = LaunchProfileCandidate::default().with_memory_mib(GATE_MEMORY_MIB);
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
    let plugin = QemuLaunchPluginConfig::new(path_text(&config.plugin), GATE_SLOT);
    let command = QemuLaunchCommandBuilder::new(
        profile,
        vm_launch_config(config, identity.node),
        path_text(&config.qemu_executable),
        plugin,
    )
    .with_qmp(qmp_config.clone())
    .build()
    .map_err(|source| QemuLiveNodeStepGateError::LaunchCommand { source })?;

    let region_config = RegionConfig::new(1, GATE_QUEUE_CAPACITY, 0);
    let allocation = RegionAllocation::new(region_config)
        .map_err(|source| QemuLiveNodeStepGateError::RegionLayout { source })?;
    let spawned = spawn_qemu_child_with_fds_in_directory(
        &command,
        run_directory,
        allocation.layout().region_size,
    )
    .map_err(|source| QemuLiveNodeStepGateError::Spawn { source })?;
    let (child, resources) = spawned.into_parts();
    let setup =
        complete_qemu_host_plugin_setup(resources.into_setup_resources(), region_config, GATE_SLOT)
            .map_err(|source| QemuLiveNodeStepGateError::HostSetup { source })?;
    if !setup.setup_ack().can_schedule() {
        return Err(QemuLiveNodeStepGateError::SetupAckNotReady);
    }

    let runtime = QemuLiveHostIoRuntime::from_shmem_fd(
        setup.shmem_as_fd(),
        setup.wake_as_fd(),
        setup.region().region_len,
        GATE_SLOT,
    )
    .map_err(|source| QemuLiveNodeStepGateError::HostIoRuntime { source })?;
    prime_guest_off_boot_barrier(
        &setup,
        config.completion_timeout,
        identity.node,
        identity.router,
    )?;
    let qmp = connect_qmp_priming_main_loop(&setup, &qmp_config.socket_path(run_directory))
        .map_err(|source| QemuLiveNodeStepGateError::QmpConnect { source })?;

    let shmem_config = QemuQuantumShmemConfig::new(node_id(identity.node), GATE_SLOT)
        .with_router(node_id(identity.router), SLOT_NET_ROUTER as u32);
    let factory_runtime = QemuNodeFactoryRuntime::new(
        shmem_config,
        GateSendAuthorizer,
        gate_shutdown_policy(),
        gate_async_policy(config.completion_timeout),
        QemuCrashDetector::new(identity.crash_detector),
        runtime,
    );
    build_qemu_node_from_completed_setup(child, setup, qmp, factory_runtime)
        .map_err(|source| QemuLiveNodeStepGateError::NodeFactory { source })
}

/// Advances the node through each busy-window ceiling with a caller re-issue loop.
///
/// [`QemuNode::advance_to_ceiling`] drives a single bounded quantum, so a step
/// interrupted by queued work (the patch-0025 reset/advance drain interaction)
/// returns [`AdvanceOutcome::Paused`] before the ceiling. The re-issue loop
/// republishes the same ceiling until the node reaches it, treating a step that
/// makes no progress across the re-issue bound as a stall rather than looping
/// forever.
fn drive_busy_window_steps(
    node: &mut QemuNode,
    ceilings: &[u64],
) -> Result<Vec<QemuLiveNodeStepQuantum>, QemuLiveNodeStepGateError> {
    let mut quanta = Vec::with_capacity(ceilings.len());
    for &ceiling in ceilings {
        let quantum = advance_to_busy_ceiling(node, ceiling)?;
        quanta.push(quantum);
    }
    Ok(quanta)
}

fn advance_to_busy_ceiling(
    node: &mut QemuNode,
    ceiling: u64,
) -> Result<QemuLiveNodeStepQuantum, QemuLiveNodeStepGateError> {
    let mut reissue_count = 0;
    let mut last_icount = node
        .current_icount()
        .map_err(|source| QemuLiveNodeStepGateError::node_op("read pre-advance icount", source))?
        .retired;
    loop {
        let outcome = node
            .advance_to_ceiling(Icount { retired: ceiling })
            .map_err(|source| QemuLiveNodeStepGateError::node_op("advance to ceiling", source))?;
        let current = node
            .current_icount()
            .map_err(|source| {
                QemuLiveNodeStepGateError::node_op("read post-advance icount", source)
            })?
            .retired;

        let reached_horizon = matches!(outcome, AdvanceOutcome::ReachedHorizon);
        if current >= ceiling {
            return Ok(QemuLiveNodeStepQuantum {
                target_icount: ceiling,
                completion_icount: current,
                logical_offset: current - ceiling,
                reissue_count,
                reached_horizon,
            });
        }

        // The step parked below the ceiling. In a busy window this only happens
        // when queued work interrupts the advance, so re-issue the same ceiling.
        // If the node made no forward progress across a re-issue, the guest is
        // stalled -- the wake defect the first live node user is expected to
        // surface -- so fail loudly rather than spin.
        if current <= last_icount || reissue_count >= MAX_REISSUES_PER_CEILING {
            return Err(QemuLiveNodeStepGateError::StepStalled {
                ceiling_icount: ceiling,
                last_icount: current,
                reissue_count,
            });
        }
        last_icount = current;
        reissue_count += 1;
    }
}

/// Requires the load run to reproduce the reference run byte for byte.
fn assert_runs_match(
    reference: &NodeStepOutcome,
    second: &NodeStepOutcome,
) -> Result<(), QemuLiveNodeStepGateError> {
    if reference.quanta != second.quanta {
        return Err(QemuLiveNodeStepGateError::SecondRunDiverged {
            reason: format!(
                "per-step accounting differed: {:?} vs {:?}",
                reference.quanta, second.quanta
            ),
        });
    }
    if reference.fingerprint != second.fingerprint {
        return Err(QemuLiveNodeStepGateError::SecondRunDiverged {
            reason: format!(
                "execution fingerprint differed: {} vs {}",
                reference.fingerprint.hash.to_hex(),
                second.fingerprint.hash.to_hex()
            ),
        });
    }
    Ok(())
}

/// Drives one bounded priming quantum to move the guest off the boot barrier.
///
/// The node's own hot path does not exist yet -- it is built only after QMP
/// connects -- so this maps a temporary hot path over the same shared-memory
/// region. Publishing the first ceiling releases the boot barrier exactly as the
/// M1 install gate does (`start_quantum` alone, no eventfd wake); the guest
/// executes to the ceiling and parks between quanta, releasing the BQL so QEMU's
/// main loop can service QMP. The temporary hot path is dropped before the node
/// maps its own view of the region.
///
/// # Errors
///
/// Returns [`QemuLiveNodeStepGateError`] when the region cannot be mapped, the
/// hot path cannot bind, a quantum boundary cannot be published or read, or the
/// guest never reaches the priming ceiling within `timeout`.
fn prime_guest_off_boot_barrier(
    setup: &crate::QemuHostPluginSetup,
    timeout: Duration,
    node_name: &str,
    router_name: &str,
) -> Result<(), QemuLiveNodeStepGateError> {
    let region = mmap_setup_region(setup.shmem_as_fd(), setup.region().region_len)
        .map_err(|source| QemuLiveNodeStepGateError::PrimeRegionMap { source })?;
    let shmem_config = QemuQuantumShmemConfig::new(node_id(node_name), GATE_SLOT)
        .with_router(node_id(router_name), SLOT_NET_ROUTER as u32);
    let mut hot_path = QemuMappedQuantumShmemHotPath::new(shmem_config, region, GateSendAuthorizer)
        .map_err(|source| QemuLiveNodeStepGateError::PrimeHotPath { source })?;

    let horizon = crucible::ExecutionHorizon {
        icount: Icount {
            retired: PRIME_CEILING_ICOUNT,
        },
    };
    let pending = QemuShmemHotPathChannel::start_quantum(&mut hot_path, horizon)
        .map_err(|source| QemuLiveNodeStepGateError::prime("start priming quantum", source))?;

    let max_polls = bounded_prime_polls(timeout);
    let mut reached = false;
    for _ in 0..max_polls {
        let current = QemuShmemHotPathChannel::current_icount(&mut hot_path)
            .map_err(|source| QemuLiveNodeStepGateError::prime("poll priming icount", source))?
            .retired;
        if current >= PRIME_CEILING_ICOUNT {
            reached = true;
            break;
        }
        thread::sleep(PRIME_POLL_INTERVAL);
    }

    if !reached {
        return Err(QemuLiveNodeStepGateError::PrimeStalled {
            ceiling_icount: PRIME_CEILING_ICOUNT,
        });
    }
    QemuShmemHotPathChannel::finish_quantum(&mut hot_path, pending)
        .map_err(|source| QemuLiveNodeStepGateError::prime("finish priming quantum", source))?;
    Ok(())
}

/// Returns the number of priming polls that fit within `timeout`, at least one.
fn bounded_prime_polls(timeout: Duration) -> u64 {
    let interval = PRIME_POLL_INTERVAL.as_micros().max(1);
    let budget = timeout.as_micros();
    u64::try_from(budget / interval).unwrap_or(u64::MAX).max(1)
}

/// Connects the typed QMP VMState channel while pulsing the plugin wake eventfd.
///
/// Right after the setup handshake the QEMU main loop parks with no host timeout
/// (the plugin holds time control and no ceiling is published), so it never
/// services the QMP `qmp_capabilities` command and a plain connect times out. A
/// short-lived primer thread pulses the plugin wake -- the same eventfd signal
/// the M1 scheduler raises each quantum -- to cycle the main loop until the
/// capabilities handshake completes. No ceiling is published, so the guest never
/// advances past the boot barrier while priming.
///
/// # Errors
///
/// Returns [`QmpError`] when the QMP capabilities handshake still cannot complete
/// (for example if QEMU never opens the socket or exits during priming).
fn connect_qmp_priming_main_loop(
    setup: &crate::QemuHostPluginSetup,
    socket_path: &Path,
) -> Result<crate::QemuQmpVmStateControlChannel<UnixStream>, QmpError> {
    let stop = AtomicBool::new(false);
    thread::scope(|scope| {
        let primer = scope.spawn(|| {
            while !stop.load(Ordering::Relaxed) {
                // Transient wake failures are ignored: the QMP connect result is
                // the authority on whether the main loop became reachable.
                let _ = setup.signal_plugin_wake();
                thread::sleep(QMP_PRIMER_WAKE_INTERVAL);
            }
        });
        let result = crate::QemuQmpVmStateControlChannel::connect_unix_socket(socket_path);
        stop.store(true, Ordering::Relaxed);
        let _ = primer.join();
        result
    })
}

/// Builds the diskless-firmware VM launch config for the node-step run.
fn vm_launch_config(config: &QemuLiveNodeStepGateConfig, node_name: &str) -> QemuVmLaunchConfig {
    let kernel = launch_artifact("kernel", &config.kernel);
    let vm = QemuVmLaunchConfig::new_diskless(
        node_name,
        kernel,
        launch_artifact("firmware", &config.firmware),
    );
    match &config.initrd {
        Some(initrd) => vm.with_initrd(launch_artifact("initrd", initrd)),
        None => vm,
    }
}

/// Returns a shutdown policy with real bounded waits for a gate teardown.
fn gate_shutdown_policy() -> QemuShutdownPolicy {
    QemuShutdownPolicy {
        control_quit_wait: Duration::from_secs(2),
        qmp_quit_wait: Duration::from_secs(5),
        sigterm_wait: Duration::from_secs(5),
        sigkill_wait: Duration::from_secs(5),
        reap_wait: Duration::from_secs(5),
    }
}

/// Returns an async-driver policy whose advance budget is the per-step timeout.
fn gate_async_policy(completion_timeout: Duration) -> QemuAsyncDriverPolicy {
    QemuAsyncDriverPolicy::new(
        Duration::from_secs(5),
        Duration::from_secs(5),
        Duration::from_secs(5),
        completion_timeout,
    )
}

fn launch_artifact(kind: &str, path: &Path) -> QemuLaunchArtifact {
    let path = path_text(path);
    QemuLaunchArtifact::new(
        crucible::ContentHash::from_canonical_material(GATE_DOMAIN, &format!("{kind}={path}")),
        path,
    )
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn node_id(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

/// A background host-CPU load generator that stresses scheduling around a run.
///
/// The busy threads consume CPU without touching the guest, the plugin, or the
/// shared-memory region, so a deterministic, icount-owning node must produce an
/// identical fingerprint whether or not the load is present.
struct HostLoad {
    stop: Arc<AtomicBool>,
    workers: Vec<thread::JoinHandle<()>>,
}

impl HostLoad {
    fn start_if(enabled: bool) -> Option<Self> {
        if !enabled {
            return None;
        }
        let stop = Arc::new(AtomicBool::new(false));
        let mut workers = Vec::with_capacity(HOST_LOAD_WORKERS);
        for _ in 0..HOST_LOAD_WORKERS {
            let stop = Arc::clone(&stop);
            workers.push(thread::spawn(move || {
                let mut accumulator: u64 = 0;
                while !stop.load(Ordering::Relaxed) {
                    for value in 0..4096_u64 {
                        accumulator = accumulator
                            .wrapping_mul(6_364_136_223_846_793_005)
                            .wrapping_add(value);
                    }
                    std::hint::black_box(accumulator);
                }
            }));
        }
        Some(Self { stop, workers })
    }
}

impl Drop for HostLoad {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        for worker in self.workers.drain(..) {
            let _ = worker.join();
        }
    }
}

/// Send authorizer for the single-node run.
///
/// The gate has one VM and one router slot and never routes a real cross-node
/// frame, so authorization is unconditional.
struct GateSendAuthorizer;

impl SchedulerSendAuthorizer for GateSendAuthorizer {
    fn authorize_cross_node_send(
        &self,
        producer: &SchedulerNodeId,
        consumer: &SchedulerNodeId,
    ) -> Result<SchedulerSendAuthorization, SchedulerError> {
        Ok(SchedulerSendAuthorization {
            producer: producer.clone(),
            consumer: consumer.clone(),
            topology_epoch: 0,
        })
    }
}
