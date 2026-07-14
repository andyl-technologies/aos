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
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crucible::{
    AdvanceOutcome, ExecutionFingerprint, Icount, NodeId, SchedulerError, SchedulerNodeId,
    SchedulerSendAuthorization, SchedulerSendAuthorizer,
};
use crucible_shmem::{RegionAllocation, RegionConfig, SLOT_NET_ROUTER};
use thiserror::Error;

use crate::supervision::QemuLiveHostIoRuntime;
use crate::{
    LaunchProfileCandidate, LaunchProfileError, QemuAsyncDriverPolicy, QemuCrashDetector,
    QemuHostPluginSetupError, QemuLaunchArtifact, QemuLaunchCommandBuilder, QemuLaunchCommandError,
    QemuLaunchPluginConfig, QemuNode, QemuNodeError, QemuNodeFactoryError, QemuNodeFactoryRuntime,
    QemuQmpChannelConfig, QemuQuantumShmemConfig, QemuShutdownPolicy, QemuVmLaunchConfig, QmpError,
    build_qemu_node_from_completed_setup, complete_qemu_host_plugin_setup,
    spawn_qemu_child_with_fds_in_directory,
};

use super::QemuLiveHostIoRuntimeError;

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
    fs::create_dir_all(&run_directory).map_err(|source| {
        QemuLiveNodeStepGateError::PrepareRunDirectory {
            path: run_directory.clone(),
            source,
        }
    })?;

    let host_load = HostLoad::start_if(role.applies_host_load());

    // Diskless-firmware profile with a QMP endpoint. The QMP endpoint is the one
    // deliberate divergence from the M1 quantum gate: the node factory requires a
    // typed VMState channel, which the M1 quantum gate never wires.
    let mut candidate = LaunchProfileCandidate::default().with_memory_mib(GATE_MEMORY_MIB);
    if let Some(cmdline) = &config.kernel_cmdline {
        candidate = candidate.with_kernel_cmdline(cmdline.clone());
    }
    let profile = candidate
        .try_into_deterministic()
        .map_err(|source| QemuLiveNodeStepGateError::LaunchProfile { source })?;
    profile
        .guest_entropy_seed_file()
        .write_to_dir(&run_directory)
        .map_err(|source| QemuLiveNodeStepGateError::GuestEntropySeed {
            path: run_directory.clone(),
            source,
        })?;

    let qmp_config = QemuQmpChannelConfig::new(GATE_QMP_SOCKET_FILE_NAME)
        .map_err(|source| QemuLiveNodeStepGateError::QmpChannelConfig { source })?;
    let plugin = QemuLaunchPluginConfig::new(path_text(&config.plugin), GATE_SLOT);
    // Build the command through the builder rather than `qemu_launch_command` so
    // the QMP endpoint can be attached: `build_qemu_node_from_completed_setup`
    // requires a typed VMState channel, which the M1 quantum gate never wires.
    let command = QemuLaunchCommandBuilder::new(
        profile,
        vm_launch_config(config),
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
        &run_directory,
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

    // The production host-I/O runtime maps an INDEPENDENT read-only view of the
    // same shmem descriptor the node's hot-path channel writes; the node keeps
    // its own owning mapping, so no channel-ownership refactor is needed.
    let runtime = QemuLiveHostIoRuntime::from_shmem_fd(
        setup.shmem_as_fd(),
        setup.region().region_len,
        GATE_SLOT,
    )
    .map_err(|source| QemuLiveNodeStepGateError::HostIoRuntime { source })?;

    let qmp = crate::QemuQmpVmStateControlChannel::connect_unix_socket(
        qmp_config.socket_path(&run_directory),
    )
    .map_err(|source| QemuLiveNodeStepGateError::QmpConnect { source })?;

    let shmem_config = QemuQuantumShmemConfig::new(node_id(GATE_NODE), GATE_SLOT)
        .with_router(node_id(GATE_ROUTER), SLOT_NET_ROUTER as u32);
    let factory_runtime = QemuNodeFactoryRuntime::new(
        shmem_config,
        GateSendAuthorizer,
        gate_shutdown_policy(),
        gate_async_policy(config.completion_timeout),
        QemuCrashDetector::new(GATE_CRASH_NODE_ID),
        runtime,
    );
    let mut node = build_qemu_node_from_completed_setup(child, setup, qmp, factory_runtime)
        .map_err(|source| QemuLiveNodeStepGateError::NodeFactory { source })?;

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

/// Builds the diskless-firmware VM launch config for the node-step run.
fn vm_launch_config(config: &QemuLiveNodeStepGateConfig) -> QemuVmLaunchConfig {
    let kernel = launch_artifact("kernel", &config.kernel);
    let vm = QemuVmLaunchConfig::new_diskless(
        GATE_NODE,
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

/// Error returned by the live [`QemuNode`] bounded-step gate.
#[derive(Debug, Error)]
pub enum QemuLiveNodeStepGateError {
    /// The busy-window schedule had a zero step size or count.
    #[error("live node-step schedule must have a nonzero step size and count")]
    ZeroSchedule,
    /// A scheduled ceiling reached or exceeded the busy cap.
    #[error(
        "scheduled ceiling {ceiling_icount} reaches busy cap {busy_cap_icount}; the guest would idle and forfeit determinism"
    )]
    CeilingAboveBusyCap {
        /// Offending scheduled ceiling.
        ceiling_icount: u64,
        /// Exclusive busy-window upper bound.
        busy_cap_icount: u64,
    },
    /// The run subdirectory could not be created.
    #[error("prepare run directory {path} failed")]
    PrepareRunDirectory {
        /// Run subdirectory path.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The deterministic launch profile could not be derived.
    #[error("derive deterministic launch profile failed")]
    LaunchProfile {
        /// Underlying launch-profile error.
        source: LaunchProfileError,
    },
    /// The guest entropy seed file could not be written.
    #[error("write guest entropy seed under {path} failed")]
    GuestEntropySeed {
        /// Run subdirectory path.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The QMP channel configuration was rejected.
    #[error("build QMP channel config failed")]
    QmpChannelConfig {
        /// Underlying launch-command error.
        source: QemuLaunchCommandError,
    },
    /// The QEMU launch command could not be built.
    #[error("build QEMU launch command failed")]
    LaunchCommand {
        /// Underlying launch-command error.
        source: QemuLaunchCommandError,
    },
    /// The shared-memory region layout could not be computed.
    #[error("compute shared-memory region layout failed")]
    RegionLayout {
        /// Underlying region-layout error.
        source: crucible_shmem::RegionLayoutError,
    },
    /// QEMU could not be spawned with the negotiated descriptors.
    #[error("spawn QEMU child failed")]
    Spawn {
        /// Underlying spawn error.
        source: crate::QemuSpawnError,
    },
    /// The plugin setup handshake failed.
    #[error("complete QEMU plugin setup handshake failed")]
    HostSetup {
        /// Underlying host-setup error.
        source: QemuHostPluginSetupError,
    },
    /// The plugin setup acknowledgement did not permit scheduling.
    #[error("plugin setup acknowledgement did not permit scheduling")]
    SetupAckNotReady,
    /// The production host-I/O runtime could not map the shared-memory region.
    #[error("build live host-I/O runtime failed")]
    HostIoRuntime {
        /// Underlying host-I/O runtime error.
        source: QemuLiveHostIoRuntimeError,
    },
    /// The typed QMP VMState channel could not connect.
    #[error("connect QMP VMState channel failed")]
    QmpConnect {
        /// Underlying QMP error.
        source: QmpError,
    },
    /// The scheduler-facing node could not be assembled.
    #[error("assemble live QEMU node failed")]
    NodeFactory {
        /// Underlying node-factory error.
        source: QemuNodeFactoryError,
    },
    /// A bounded node step failed.
    #[error("{operation} failed")]
    Step {
        /// Node operation that failed.
        operation: &'static str,
        /// Underlying node error.
        source: QemuNodeError,
    },
    /// A bounded step made no progress toward its ceiling.
    ///
    /// This is the signal that the guest parked below the ceiling and the node's
    /// advance path did not rouse it -- the wake defect the first live node user
    /// is expected to surface if a busy window ever hits an idle wait.
    #[error(
        "node step for ceiling {ceiling_icount} stalled at {last_icount} after {reissue_count} re-issues"
    )]
    StepStalled {
        /// Ceiling the step was driving toward.
        ceiling_icount: u64,
        /// Last observed node icount.
        last_icount: u64,
        /// Re-issues attempted before the stall was declared.
        reissue_count: u32,
    },
    /// Reading the terminal execution fingerprint failed.
    #[error("read execution fingerprint failed")]
    ExecutionFingerprint {
        /// Underlying node error.
        source: QemuNodeError,
    },
    /// Node shutdown escalation failed.
    #[error("shut down live QEMU node failed")]
    Shutdown {
        /// Underlying node error.
        source: QemuNodeError,
    },
    /// The second run diverged from the reference run.
    #[error("second run diverged from the reference run: {reason}")]
    SecondRunDiverged {
        /// Human-readable divergence detail.
        reason: String,
    },
}

impl QemuLiveNodeStepGateError {
    /// Builds a [`QemuLiveNodeStepGateError::Step`] for a node operation.
    fn node_op(operation: &'static str, source: QemuNodeError) -> Self {
        Self::Step { operation, source }
    }
}
