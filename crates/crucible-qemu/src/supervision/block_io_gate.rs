//! Diagnostic live block-I/O gate for a QEMU node over `SLOT_BLK_IO`.
//!
//! This is the first gate that drives real guest block I/O through a live
//! [`QemuNode`]. It attaches a `crucible-shmem` virtio-blk device to the diskless
//! guest, stands the node up exactly as the M4 node-step gate does (boot-barrier
//! priming, wake-signalling runtime, QMP), but wires a [`QemuLiveBlockIoServicer`]
//! into the runtime's advance poll loop so the guest's virtio-blk probe reads on
//! `SLOT_BLK_IO` are actually serviced.
//!
//! It is deliberately *diagnostic*: rather than assume the plugin already
//! idle-jumps a guest blocked on device I/O to the host-computed completion
//! icount, it advances the node once toward a busy ceiling and REPORTS what
//! happened -- how many request frames were serviced, the device completion
//! horizon computed for the first request, whether the guest progressed to the
//! ceiling or stalled, and the guest slot's published device-I/O state. That
//! turns the open device-horizon question into an observed outcome. The whole
//! run is repeated (the second time under host CPU load) and the two runs' block
//! observations must match, per the servicer's determinism invariant.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use std::os::unix::net::UnixStream;

use crucible::{
    AdvanceOutcome, Icount, NodeId, SchedulerError, SchedulerNodeId, SchedulerSendAuthorization,
    SchedulerSendAuthorizer,
};
use crucible_shmem::{RegionAllocation, RegionConfig, SLOT_NET_ROUTER, mmap_setup_region};
use thiserror::Error;

use super::block_io_servicer::{
    BlockIoDiagnostics, BlockIoDiagnosticsSnapshot, QemuLiveBlockIoServicer,
    QemuLiveBlockIoServicerError,
};
use super::{QemuLiveHostIoRuntime, QemuLiveHostIoRuntimeError};
use crate::{
    CrucibleShmemBlockDevice, LaunchProfileCandidate, LaunchProfileError, QemuAsyncDriverPolicy,
    QemuCrashDetector, QemuHostPluginSetup, QemuHostPluginSetupError, QemuLaunchArtifact,
    QemuLaunchCommandBuilder, QemuLaunchCommandError, QemuLaunchPluginConfig,
    QemuMappedQuantumShmemHotPath, QemuMappedQuantumShmemHotPathError, QemuNode,
    QemuNodeChannelError, QemuNodeError, QemuNodeFactoryError, QemuNodeFactoryRuntime,
    QemuQmpChannelConfig, QemuQmpVmStateControlChannel, QemuQuantumShmemConfig,
    QemuShmemHotPathChannel, QemuShutdownPolicy, QemuVmLaunchConfig, QmpError,
    build_qemu_node_from_completed_setup, complete_qemu_host_plugin_setup,
    spawn_qemu_child_with_fds_in_directory,
};

/// Content-addressing domain for block-I/O launch artifacts.
const GATE_DOMAIN: &str = "crucible.loaded-qemu-live-block-io.v1";
/// Stable node name for the single-VM block-I/O run.
const GATE_NODE: &str = "live-block-io-vm";
/// Stable router name reserved by the shared-memory hot path.
const GATE_ROUTER: &str = "live-block-io-router";
/// VM slot negotiated during the handshake.
const GATE_SLOT: u32 = 0;
/// Fixed inbound/outbound ring capacity for the single-node run.
const GATE_QUEUE_CAPACITY: u32 = 4;
/// Conservative guest memory size for the block-I/O run.
const GATE_MEMORY_MIB: u32 = 64;
/// QMP socket file created in the run directory for VMState control.
const GATE_QMP_SOCKET_FILE_NAME: &str = "crucible-live-block-io-qmp.sock";
/// Stable crash-detector node identifier.
const GATE_CRASH_NODE_ID: &str = "live-block-io";
/// Number of background threads used to stress host scheduling on the load run.
const HOST_LOAD_WORKERS: usize = 4;
/// Ceiling for the boot-barrier priming quantum, below the first busy ceiling.
const PRIME_CEILING_ICOUNT: u64 = 1_000_000;
/// Host poll interval while waiting for the priming quantum to reach its ceiling.
const PRIME_POLL_INTERVAL: Duration = Duration::from_millis(1);
/// Cadence at which the QMP-connect primer pulses the plugin wake eventfd.
const QMP_PRIMER_WAKE_INTERVAL: Duration = Duration::from_millis(10);
/// Default crucible-shmem device length: 4 MiB, a whole sector multiple.
const DEFAULT_DEVICE_SIZE_BYTES: u64 = 4 * 1024 * 1024;
/// Default busy-window ceiling the run advances the node toward.
const DEFAULT_BUSY_CEILING_ICOUNT: u64 = 12_000_000;

/// Inputs for one diagnostic live block-I/O gate run.
#[derive(Clone, Debug)]
pub struct QemuLiveBlockIoGateConfig {
    qemu_executable: PathBuf,
    plugin: PathBuf,
    kernel: PathBuf,
    firmware: PathBuf,
    run_directory: PathBuf,
    initrd: Option<PathBuf>,
    kernel_cmdline: Option<String>,
    device_size_bytes: u64,
    busy_ceiling_icount: u64,
    completion_timeout: Duration,
    second_run_host_load: bool,
}

impl QemuLiveBlockIoGateConfig {
    /// Builds a block-I/O gate configuration with bounded defaults.
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
            device_size_bytes: DEFAULT_DEVICE_SIZE_BYTES,
            busy_ceiling_icount: DEFAULT_BUSY_CEILING_ICOUNT,
            completion_timeout: Duration::from_secs(120),
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

    /// Returns this configuration with a different crucible-shmem device length.
    #[must_use]
    pub const fn with_device_size_bytes(mut self, device_size_bytes: u64) -> Self {
        self.device_size_bytes = device_size_bytes;
        self
    }

    /// Returns this configuration with a different busy-window advance ceiling.
    #[must_use]
    pub const fn with_busy_ceiling_icount(mut self, busy_ceiling_icount: u64) -> Self {
        self.busy_ceiling_icount = busy_ceiling_icount;
        self
    }

    /// Returns this configuration with a different per-advance completion bound.
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

/// How the node's single busy-window advance terminated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum BlockIoAdvanceOutcome {
    /// The guest reached the busy ceiling (progressed past the block probe).
    ReachedCeiling {
        /// Node icount reached at the ceiling.
        icount: u64,
    },
    /// The guest parked below the ceiling (stalled on device I/O or idled).
    PausedBelowCeiling {
        /// Node icount where the guest parked.
        icount: u64,
    },
    /// The advance timed out or the child crashed before the ceiling.
    Failed {
        /// Human-readable failure detail.
        detail: String,
    },
}

/// The diagnostic outcome of one full block-I/O run.
#[derive(Clone, Debug, PartialEq, Eq)]
struct BlockIoRunOutcome {
    advance: BlockIoAdvanceOutcome,
    diagnostics: BlockIoDiagnosticsSnapshot,
    orderly_child_exit: bool,
}

/// Diagnostic evidence from the live block-I/O gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLiveBlockIoReport {
    /// How the reference run's advance terminated.
    pub advance: BlockIoAdvanceOutcome,
    /// The reference run's accumulated block-I/O observations.
    pub diagnostics: BlockIoDiagnosticsSnapshot,
    /// The reference run's node shut down cleanly.
    pub orderly_child_exit: bool,
    /// The second run (under host CPU load) matched the first observation.
    pub deterministic_under_host_load: bool,
    /// Host CPU load was actually applied during the second run.
    pub host_load_applied: bool,
}

/// Drives the diagnostic live block-I/O gate and reports the observed behaviour.
///
/// Boots the diskless-firmware guest with a `crucible-shmem` virtio-blk device,
/// stands up a live node whose host-I/O runtime services `SLOT_BLK_IO`, advances
/// the node once toward the busy ceiling, and records what the servicing observed.
/// The run is repeated under host load and the two runs' block observations must
/// match.
///
/// # Errors
///
/// Returns [`QemuLiveBlockIoGateError`] when launch preparation, the plugin
/// handshake, the host-I/O runtime, QMP, or node assembly fails, or when the two
/// runs' block observations diverge.
pub fn run_qemu_live_block_io_gate(
    config: &QemuLiveBlockIoGateConfig,
) -> Result<QemuLiveBlockIoReport, QemuLiveBlockIoGateError> {
    let reference = run_one_scenario(config, RunRole::Reference)?;
    let (second, host_load_applied) = if config.second_run_host_load {
        (run_one_scenario(config, RunRole::HostLoad)?, true)
    } else {
        (run_one_scenario(config, RunRole::Repeat)?, false)
    };

    assert_runs_match(&reference, &second)?;

    Ok(QemuLiveBlockIoReport {
        advance: reference.advance,
        diagnostics: reference.diagnostics,
        orderly_child_exit: reference.orderly_child_exit,
        deterministic_under_host_load: true,
        host_load_applied,
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
    config: &QemuLiveBlockIoGateConfig,
    role: RunRole,
) -> Result<BlockIoRunOutcome, QemuLiveBlockIoGateError> {
    let run_directory = config.run_directory.join(role.subdir());
    fs::create_dir_all(&run_directory).map_err(|source| {
        QemuLiveBlockIoGateError::PrepareRunDirectory {
            path: run_directory.clone(),
            source,
        }
    })?;

    let host_load = HostLoad::start_if(role.applies_host_load());

    let mut candidate = LaunchProfileCandidate::default().with_memory_mib(GATE_MEMORY_MIB);
    if let Some(cmdline) = &config.kernel_cmdline {
        candidate = candidate.with_kernel_cmdline(cmdline.clone());
    }
    let profile = candidate
        .try_into_deterministic()
        .map_err(|source| QemuLiveBlockIoGateError::LaunchProfile { source })?;
    let icount_shift = profile.icount_shift();
    profile
        .guest_entropy_seed_file()
        .write_to_dir(&run_directory)
        .map_err(|source| QemuLiveBlockIoGateError::GuestEntropySeed {
            path: run_directory.clone(),
            source,
        })?;

    let qmp_config = QemuQmpChannelConfig::new(GATE_QMP_SOCKET_FILE_NAME)
        .map_err(|source| QemuLiveBlockIoGateError::QmpChannelConfig { source })?;
    let plugin = QemuLaunchPluginConfig::new(path_text(&config.plugin), GATE_SLOT);
    let command = QemuLaunchCommandBuilder::new(
        profile,
        vm_launch_config(config),
        path_text(&config.qemu_executable),
        plugin,
    )
    .with_qmp(qmp_config.clone())
    .build()
    .map_err(|source| QemuLiveBlockIoGateError::LaunchCommand { source })?;

    let region_config = RegionConfig::new(1, GATE_QUEUE_CAPACITY, 0);
    let allocation = RegionAllocation::new(region_config)
        .map_err(|source| QemuLiveBlockIoGateError::RegionLayout { source })?;
    let spawned = spawn_qemu_child_with_fds_in_directory(
        &command,
        &run_directory,
        allocation.layout().region_size,
    )
    .map_err(|source| QemuLiveBlockIoGateError::Spawn { source })?;
    let (child, resources) = spawned.into_parts();

    let setup =
        complete_qemu_host_plugin_setup(resources.into_setup_resources(), region_config, GATE_SLOT)
            .map_err(|source| QemuLiveBlockIoGateError::HostSetup { source })?;
    if !setup.setup_ack().can_schedule() {
        return Err(QemuLiveBlockIoGateError::SetupAckNotReady);
    }

    // The block servicer owns a separate writable mapping confined to SLOT_BLK_IO;
    // the runtime keeps its own read-only observer view. Diagnostics is shared so
    // the run can read the servicing observations after the node is torn down.
    let diagnostics = BlockIoDiagnostics::shared();
    let servicer = QemuLiveBlockIoServicer::from_shmem_fd(
        setup.shmem_as_fd(),
        setup.region().region_len,
        GATE_SLOT,
        icount_shift,
        config.device_size_bytes,
    )
    .map_err(|source| QemuLiveBlockIoGateError::BlockServicer { source })?;
    let runtime = QemuLiveHostIoRuntime::from_shmem_fd(
        setup.shmem_as_fd(),
        setup.wake_as_fd(),
        setup.region().region_len,
        GATE_SLOT,
    )
    .map_err(|source| QemuLiveBlockIoGateError::HostIoRuntime { source })?
    .with_block_servicer(servicer, Arc::clone(&diagnostics));

    // Prime the guest off the boot barrier before QMP connect (same bug as the
    // node-step gate: the boot-barrier park holds the BQL until a real ceiling is
    // published, starving QMP).
    prime_guest_off_boot_barrier(&setup, config.completion_timeout)?;
    let qmp = connect_qmp_priming_main_loop(&setup, &qmp_config.socket_path(&run_directory))
        .map_err(|source| QemuLiveBlockIoGateError::QmpConnect { source })?;

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
        .map_err(|source| QemuLiveBlockIoGateError::NodeFactory { source })?;

    // Advance once toward the busy ceiling. The block servicer runs inside the
    // runtime's poll loop, so a guest that blocks on a probe read has its request
    // serviced; whether it then progresses to the ceiling is the diagnostic.
    let advance = drive_busy_advance(&mut node, config.busy_ceiling_icount);

    let shutdown = node.shutdown_child();
    let orderly_child_exit = shutdown
        .as_ref()
        .map(|report| report.reaped && !report.leaked)
        .unwrap_or(false);

    drop(node);
    drop(host_load);

    Ok(BlockIoRunOutcome {
        advance,
        diagnostics: diagnostics.snapshot(),
        orderly_child_exit,
    })
}

/// Advances the node once toward `ceiling`, classifying the terminal state.
///
/// A failed advance (timeout or crash) is captured rather than propagated: the
/// diagnostic value is observing that a guest blocked on device I/O did not reach
/// the ceiling, which must be reported, not hidden behind an error.
fn drive_busy_advance(node: &mut QemuNode, ceiling: u64) -> BlockIoAdvanceOutcome {
    match node.advance_to_ceiling(Icount { retired: ceiling }) {
        Ok(AdvanceOutcome::ReachedHorizon) => {
            let icount = node
                .current_icount()
                .map(|icount| icount.retired)
                .unwrap_or(ceiling);
            BlockIoAdvanceOutcome::ReachedCeiling { icount }
        }
        Ok(AdvanceOutcome::Paused { at }) => {
            BlockIoAdvanceOutcome::PausedBelowCeiling { icount: at.retired }
        }
        Err(error) => BlockIoAdvanceOutcome::Failed {
            detail: error.to_string(),
        },
    }
}

/// Requires the load run to reproduce the reference run's block observations.
fn assert_runs_match(
    reference: &BlockIoRunOutcome,
    second: &BlockIoRunOutcome,
) -> Result<(), QemuLiveBlockIoGateError> {
    if reference.advance != second.advance {
        return Err(QemuLiveBlockIoGateError::SecondRunDiverged {
            reason: format!(
                "advance outcome differed: {:?} vs {:?}",
                reference.advance, second.advance
            ),
        });
    }
    if reference.diagnostics != second.diagnostics {
        return Err(QemuLiveBlockIoGateError::SecondRunDiverged {
            reason: format!(
                "block observations differed: {:?} vs {:?}",
                reference.diagnostics, second.diagnostics
            ),
        });
    }
    Ok(())
}

/// Drives one bounded priming quantum to move the guest off the boot barrier.
fn prime_guest_off_boot_barrier(
    setup: &QemuHostPluginSetup,
    timeout: Duration,
) -> Result<(), QemuLiveBlockIoGateError> {
    let region = mmap_setup_region(setup.shmem_as_fd(), setup.region().region_len)
        .map_err(|source| QemuLiveBlockIoGateError::PrimeRegionMap { source })?;
    let shmem_config = QemuQuantumShmemConfig::new(node_id(GATE_NODE), GATE_SLOT)
        .with_router(node_id(GATE_ROUTER), SLOT_NET_ROUTER as u32);
    let mut hot_path = QemuMappedQuantumShmemHotPath::new(shmem_config, region, GateSendAuthorizer)
        .map_err(|source| QemuLiveBlockIoGateError::PrimeHotPath { source })?;

    let horizon = crucible::ExecutionHorizon {
        icount: Icount {
            retired: PRIME_CEILING_ICOUNT,
        },
    };
    let pending = QemuShmemHotPathChannel::start_quantum(&mut hot_path, horizon)
        .map_err(|source| QemuLiveBlockIoGateError::prime("start priming quantum", source))?;

    let max_polls = bounded_prime_polls(timeout);
    let mut reached = false;
    for _ in 0..max_polls {
        let current = QemuShmemHotPathChannel::current_icount(&mut hot_path)
            .map_err(|source| QemuLiveBlockIoGateError::prime("poll priming icount", source))?
            .retired;
        if current >= PRIME_CEILING_ICOUNT {
            reached = true;
            break;
        }
        thread::sleep(PRIME_POLL_INTERVAL);
    }

    if !reached {
        return Err(QemuLiveBlockIoGateError::PrimeStalled {
            ceiling_icount: PRIME_CEILING_ICOUNT,
        });
    }
    QemuShmemHotPathChannel::finish_quantum(&mut hot_path, pending)
        .map_err(|source| QemuLiveBlockIoGateError::prime("finish priming quantum", source))?;
    Ok(())
}

/// Returns the number of priming polls that fit within `timeout`, at least one.
fn bounded_prime_polls(timeout: Duration) -> u64 {
    let interval = PRIME_POLL_INTERVAL.as_micros().max(1);
    let budget = timeout.as_micros();
    u64::try_from(budget / interval).unwrap_or(u64::MAX).max(1)
}

/// Connects the QMP VMState channel while pulsing the plugin wake eventfd.
fn connect_qmp_priming_main_loop(
    setup: &QemuHostPluginSetup,
    socket_path: &Path,
) -> Result<QemuQmpVmStateControlChannel<UnixStream>, QmpError> {
    let stop = AtomicBool::new(false);
    thread::scope(|scope| {
        let primer = scope.spawn(|| {
            while !stop.load(Ordering::Relaxed) {
                let _ = setup.signal_plugin_wake();
                thread::sleep(QMP_PRIMER_WAKE_INTERVAL);
            }
        });
        let result = QemuQmpVmStateControlChannel::connect_unix_socket(socket_path);
        stop.store(true, Ordering::Relaxed);
        let _ = primer.join();
        result
    })
}

/// Builds the diskless-firmware VM launch config with a crucible-shmem block device.
fn vm_launch_config(config: &QemuLiveBlockIoGateConfig) -> QemuVmLaunchConfig {
    let kernel = launch_artifact("kernel", &config.kernel);
    let vm = QemuVmLaunchConfig::new_diskless(
        GATE_NODE,
        kernel,
        launch_artifact("firmware", &config.firmware),
    )
    .with_crucible_shmem_block(CrucibleShmemBlockDevice::new(config.device_size_bytes));
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

/// Returns an async-driver policy whose advance budget is the completion timeout.
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

/// Send authorizer for the single-node block-I/O run.
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

/// Error returned by the diagnostic live block-I/O gate.
#[derive(Debug, Error)]
pub enum QemuLiveBlockIoGateError {
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
    /// The block-I/O servicer could not be built.
    #[error("build block-I/O servicer failed")]
    BlockServicer {
        /// Underlying block-servicer error.
        source: QemuLiveBlockIoServicerError,
    },
    /// The production host-I/O runtime could not map the shared-memory region.
    #[error("build live host-I/O runtime failed")]
    HostIoRuntime {
        /// Underlying host-I/O runtime error.
        source: QemuLiveHostIoRuntimeError,
    },
    /// The priming hot path could not map the shared-memory region.
    #[error("map priming shared-memory region failed")]
    PrimeRegionMap {
        /// Underlying setup-region mapping error.
        source: crucible_shmem::SetupRegionMapError,
    },
    /// The priming mapped hot-path adapter could not bind the region.
    #[error("bind priming mapped hot path failed")]
    PrimeHotPath {
        /// Underlying mapped hot-path binding error.
        source: QemuMappedQuantumShmemHotPathError,
    },
    /// A priming quantum boundary could not be published or read.
    #[error("{operation} failed")]
    Prime {
        /// Priming operation that failed.
        operation: &'static str,
        /// Underlying shared-memory channel error.
        source: QemuNodeChannelError,
    },
    /// The guest never reached the priming ceiling off the boot barrier.
    #[error("priming quantum did not reach ceiling {ceiling_icount} off the boot barrier")]
    PrimeStalled {
        /// Priming ceiling the guest failed to reach.
        ceiling_icount: u64,
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

impl QemuLiveBlockIoGateError {
    /// Builds a [`QemuLiveBlockIoGateError::Prime`] for a priming operation.
    fn prime(operation: &'static str, source: QemuNodeChannelError) -> Self {
        Self::Prime { operation, source }
    }
}
