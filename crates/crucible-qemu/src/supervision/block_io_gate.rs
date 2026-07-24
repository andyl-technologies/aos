//! Certifying live block-I/O gate for QEMU over `SLOT_BLK_IO`.
//!
//! The gate attaches a `crucible-shmem` virtio-blk device to a diskless guest,
//! completes the production-plugin handshake, and drives the mapped quantum
//! hot path while a [`QemuLiveBlockIoServicer`] services the guest's probe reads.
//!
//! The plugin must advance an I/O-blocked guest to the host-published completion
//! horizon, expose the response, and continue to the scheduler ceiling. A second
//! run adds host CPU load and deliberately delays the due response's physical
//! ring write after logical time reaches its horizon. Both runs must produce
//! identical block observations, proving host timing changes only wall-clock
//! parking duration.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crucible::{
    Icount, NodeId, SchedulerError, SchedulerNodeId, SchedulerSendAuthorization,
    SchedulerSendAuthorizer,
};
use crucible_shmem::{RegionAllocation, RegionConfig, SLOT_NET_ROUTER, mmap_setup_region};
use thiserror::Error;

use super::block_io_servicer::{
    BlockIoDiagnostics, BlockIoDiagnosticsSnapshot, QemuLiveBlockIoServicer,
    QemuLiveBlockIoServicerError,
};
use crate::{
    CrucibleShmemBlockDevice, LaunchProfileCandidate, LaunchProfileError, QemuHostPluginSetup,
    QemuHostPluginSetupError, QemuLaunchArtifact, QemuLaunchCommandBuilder, QemuLaunchCommandError,
    QemuLaunchPluginConfig, QemuMappedQuantumShmemHotPath, QemuMappedQuantumShmemHotPathError,
    QemuNodeChannelError, QemuNodeChild, QemuPluginIpcControlChannel, QemuQuantumShmemConfig,
    QemuShmemHotPathChannel, QemuVmLaunchConfig, complete_qemu_host_plugin_setup,
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
/// Number of background threads used to stress host scheduling on the load run.
const HOST_LOAD_WORKERS: usize = 4;
/// Host poll interval while driving and servicing the guest.
const PRIME_POLL_INTERVAL: Duration = Duration::from_millis(1);
/// Consecutive no-progress polls (at [`PRIME_POLL_INTERVAL`]) before the drive
/// declares the guest stalled on device I/O rather than merely executing slowly.
const DRIVE_STALL_POLLS: u64 = 5_000;
/// Wall delay injected after virtual time reaches a pending response horizon.
const DELAYED_RESPONSE_WALL_TIME: Duration = Duration::from_millis(100);
/// Default crucible-shmem device length: 4 MiB, a whole sector multiple.
const DEFAULT_DEVICE_SIZE_BYTES: u64 = 4 * 1024 * 1024;
/// Default busy-window ceiling the run advances the node toward.
const DEFAULT_BUSY_CEILING_ICOUNT: u64 = 12_000_000;

/// Inputs for one certifying live block-I/O gate run.
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
            completion_timeout: Duration::from_secs(60),
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

/// The outcome of one full block-I/O run.
#[derive(Clone, Debug, PartialEq, Eq)]
struct BlockIoRunOutcome {
    advance: BlockIoAdvanceOutcome,
    diagnostics: BlockIoDiagnosticsSnapshot,
    orderly_child_exit: bool,
    response_delay_applied: bool,
}

/// Certifying evidence from the live block-I/O gate.
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
    /// The second run delayed a due host response without changing observations.
    pub delayed_response_applied: bool,
}

/// Drives the certifying live block-I/O gate and reports the observed behaviour.
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
/// handshake, the host-I/O runtime, shared-memory driving, or child supervision
/// fails, or when the two runs' block observations diverge.
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
        delayed_response_applied: second.response_delay_applied,
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

    const fn response_wall_delay(self) -> Duration {
        match self {
            Self::HostLoad => DELAYED_RESPONSE_WALL_TIME,
            Self::Reference | Self::Repeat => Duration::ZERO,
        }
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

    let plugin = QemuLaunchPluginConfig::new(path_text(&config.plugin), GATE_SLOT);
    // No QMP and no QemuNode here: this gate drives a raw hot path so the
    // block ring can be serviced concurrently with getting the guest off the boot
    // barrier. With a block device attached, unserviced SLOT_BLK_IO blocks the
    // guest in early boot, so the node-step priming quantum (which does not
    // service block I/O) cannot even release the boot barrier -- the node bring-up
    // is infeasible until this device-horizon behaviour is understood.
    let command = QemuLaunchCommandBuilder::new(
        profile,
        vm_launch_config(config),
        path_text(&config.qemu_executable),
        plugin,
    )
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
    let (mut child, resources) = spawned.into_parts();

    let mut setup =
        complete_qemu_host_plugin_setup(resources.into_setup_resources(), region_config, GATE_SLOT)
            .map_err(|source| QemuLiveBlockIoGateError::HostSetup { source })?;
    if !setup.setup_ack().can_schedule() {
        return Err(QemuLiveBlockIoGateError::SetupAckNotReady);
    }

    // The block servicer owns a writable mapping confined to the SLOT_BLK_IO ring
    // pair (it never writes the guest node slot's observed fields). Diagnostics is
    // shared so the observations survive teardown.
    let diagnostics = BlockIoDiagnostics::shared();
    let mut servicer = QemuLiveBlockIoServicer::from_shmem_fd(
        setup.shmem_as_fd(),
        setup.region().region_len,
        GATE_SLOT,
        icount_shift,
        config.device_size_bytes,
    )
    .map_err(|source| QemuLiveBlockIoGateError::BlockServicer { source })?;

    let region = mmap_setup_region(setup.shmem_as_fd(), setup.region().region_len)
        .map_err(|source| QemuLiveBlockIoGateError::DriveRegionMap { source })?;
    let shmem_config = QemuQuantumShmemConfig::new(node_id(GATE_NODE), GATE_SLOT)
        .with_router(node_id(GATE_ROUTER), SLOT_NET_ROUTER as u32);
    let mut hot_path = QemuMappedQuantumShmemHotPath::new(shmem_config, region, GateSendAuthorizer)
        .map_err(|source| QemuLiveBlockIoGateError::DriveHotPath { source })?;

    let (advance, response_delay_applied) = drive_and_service(
        &mut hot_path,
        &mut servicer,
        &diagnostics,
        &setup,
        &mut child,
        DriveOptions {
            ceiling: config.busy_ceiling_icount,
            timeout: config.completion_timeout,
            response_wall_delay: role.response_wall_delay(),
        },
    )?;

    // Teardown: ask the plugin to quit, then reap. Dropping the child force-kills
    // if it is still alive, so no QEMU is orphaned on an early return.
    let _ = QemuPluginIpcControlChannel::send_quit(&mut setup);
    let orderly_child_exit = reap_child(&mut child, config.completion_timeout);

    drop(hot_path);
    drop(setup);
    drop(child);
    drop(host_load);

    Ok(BlockIoRunOutcome {
        advance,
        diagnostics: diagnostics.snapshot(),
        orderly_child_exit,
        response_delay_applied,
    })
}

/// Drives the guest toward `ceiling` on a raw hot path while servicing block I/O.
///
/// Publishes the ceiling (releasing the boot barrier via the shared-memory futex
/// wake), then each poll pulses the plugin wake, reads the guest slot, services
/// `SLOT_BLK_IO` at the observed icount, and records the observation. It
/// terminates when the guest reaches the ceiling, stalls (no icount progress for
/// [`DRIVE_STALL_POLLS`] polls, i.e. blocked on device I/O the plugin never
/// advances past), the child exits, or the poll budget lapses. A stall is
/// returned as an outcome so the certifying caller can report the exact stall.
///
/// # Errors
///
/// Returns [`QemuLiveBlockIoGateError`] only when the quantum cannot be published
/// or the guest slot cannot be read; a stalled guest is a normal outcome.
struct DriveOptions {
    ceiling: u64,
    timeout: Duration,
    response_wall_delay: Duration,
}

fn drive_and_service(
    hot_path: &mut QemuMappedQuantumShmemHotPath,
    servicer: &mut QemuLiveBlockIoServicer,
    diagnostics: &BlockIoDiagnostics,
    setup: &QemuHostPluginSetup,
    child: &mut QemuNodeChild,
    options: DriveOptions,
) -> Result<(BlockIoAdvanceOutcome, bool), QemuLiveBlockIoGateError> {
    let pending = QemuShmemHotPathChannel::start_quantum(
        hot_path,
        crucible::ExecutionHorizon {
            icount: Icount {
                retired: options.ceiling,
            },
        },
    )
    .map_err(|source| QemuLiveBlockIoGateError::drive("start block-io drive quantum", source))?;

    let max_polls = bounded_drive_polls(options.timeout);
    let mut last_icount = 0_u64;
    let mut stall_polls = 0_u64;
    let mut response_delay_applied = false;
    let mut outcome = BlockIoAdvanceOutcome::PausedBelowCeiling { icount: 0 };
    for _ in 0..max_polls {
        let _ = setup.signal_plugin_wake();
        let snapshot = servicer
            .vm_node_snapshot()
            .map_err(|source| QemuLiveBlockIoGateError::BlockServicer { source })?;
        if !response_delay_applied
            && !options.response_wall_delay.is_zero()
            && servicer
                .next_completion_icount()
                .is_some_and(|deadline| snapshot.current_icount >= deadline)
        {
            // This wall-only delay forces QEMU to re-poll at an already reached
            // delivery icount before the response ring write becomes visible.
            // The guest remains parked at the same logical time throughout.
            thread::sleep(options.response_wall_delay);
            response_delay_applied = true;
        }
        let serviced = servicer
            .service(snapshot.current_icount)
            .map_err(|source| QemuLiveBlockIoGateError::BlockServicer { source })?;
        diagnostics.record(
            snapshot.current_icount,
            snapshot.device_io_active != 0,
            snapshot.idle_wake_icount,
            &serviced,
        );

        if snapshot.current_icount >= options.ceiling {
            outcome = BlockIoAdvanceOutcome::ReachedCeiling {
                icount: snapshot.current_icount,
            };
            break;
        }
        if let Some(status) = child
            .try_wait_natural_exit()
            .map_err(|source| QemuLiveBlockIoGateError::ChildWait { source })?
        {
            outcome = BlockIoAdvanceOutcome::Failed {
                detail: format!("child exited during drive: {status}"),
            };
            break;
        }
        if snapshot.current_icount > last_icount {
            last_icount = snapshot.current_icount;
            stall_polls = 0;
        } else {
            stall_polls += 1;
            if stall_polls >= DRIVE_STALL_POLLS {
                outcome = BlockIoAdvanceOutcome::PausedBelowCeiling {
                    icount: snapshot.current_icount,
                };
                break;
            }
        }
        thread::sleep(PRIME_POLL_INTERVAL);
    }

    let _ = QemuShmemHotPathChannel::finish_quantum(hot_path, pending);
    Ok((outcome, response_delay_applied))
}

/// Reaps the child within a bounded poll budget, force-killing on drop otherwise.
fn reap_child(child: &mut QemuNodeChild, timeout: Duration) -> bool {
    let max_polls = bounded_drive_polls(timeout);
    for _ in 0..max_polls {
        match child.try_wait_natural_exit() {
            Ok(Some(status)) => return status.success(),
            Ok(None) => thread::sleep(PRIME_POLL_INTERVAL),
            Err(_) => return false,
        }
    }
    false
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

/// Returns the number of drive polls that fit within `timeout`, at least one.
fn bounded_drive_polls(timeout: Duration) -> u64 {
    let interval = PRIME_POLL_INTERVAL.as_micros().max(1);
    let budget = timeout.as_micros();
    u64::try_from(budget / interval).unwrap_or(u64::MAX).max(1)
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

/// Error returned by the certifying live block-I/O gate.
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
    /// The drive hot path could not map the shared-memory region.
    #[error("map drive shared-memory region failed")]
    DriveRegionMap {
        /// Underlying setup-region mapping error.
        source: crucible_shmem::SetupRegionMapError,
    },
    /// The drive mapped hot-path adapter could not bind the region.
    #[error("bind drive mapped hot path failed")]
    DriveHotPath {
        /// Underlying mapped hot-path binding error.
        source: QemuMappedQuantumShmemHotPathError,
    },
    /// A drive quantum boundary could not be published.
    #[error("{operation} failed")]
    Drive {
        /// Drive operation that failed.
        operation: &'static str,
        /// Underlying shared-memory channel error.
        source: QemuNodeChannelError,
    },
    /// Waiting on the child's natural exit failed during the drive.
    #[error("wait on QEMU child exit failed")]
    ChildWait {
        /// Underlying child-wait error.
        source: crate::QemuShutdownTargetError,
    },
    /// The second run diverged from the reference run.
    #[error("second run diverged from the reference run: {reason}")]
    SecondRunDiverged {
        /// Human-readable divergence detail.
        reason: String,
    },
}

impl QemuLiveBlockIoGateError {
    /// Builds a [`QemuLiveBlockIoGateError::Drive`] for a drive operation.
    fn drive(operation: &'static str, source: QemuNodeChannelError) -> Self {
        Self::Drive { operation, source }
    }
}
