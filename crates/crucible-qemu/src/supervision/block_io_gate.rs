//! Certifying live block-I/O gate for QEMU over `SLOT_BLK_IO`.
//!
//! The gate attaches a `crucible-shmem` virtio-blk device to a diskless guest,
//! completes the production-plugin handshake, and drives the mapped quantum
//! hot path while a [`QemuLiveBlockIoServicer`] services the guest's probe reads.
//!
//! The gate compares three executions: fully synchronous servicing, asynchronous
//! host work forced to finish before the guest reaches the pinned completion,
//! and asynchronous host work forced to finish after the guest reaches it. All
//! three must produce identical completion coordinates and canonical I/O logs.

use std::collections::VecDeque;
use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use crucible::{
    EventLog, Icount, IoEventKind, NodeId, ObservableEvent, SchedulerError, VirtualTime,
};
use crucible_shmem::{
    MappedSetupRegion, RegionAllocation, RegionConfig, SLOT_NET_ROUTER, mmap_setup_region,
};

use self::support::{GateSendAuthorizer, HostLoad};
use super::block_io_servicer::{
    BlockIoDiagnostics, BlockIoDiagnosticsSnapshot, QemuLiveBlockIoServiceStep,
    QemuLiveBlockIoServicer, QemuLiveBlockIoServicerError,
};
use super::device_host_work::{
    QemuDeviceHostWorkDelay, QemuLiveBlockHostWorkPool, QemuLiveBlockHostWorkPoolError,
};
use crate::{
    CrucibleShmemBlockDevice, LaunchProfileCandidate, LaunchProfileError, QemuHostPluginSetup,
    QemuHostPluginSetupError, QemuLaunchArtifact, QemuLaunchCommandBuilder, QemuLaunchCommandError,
    QemuLaunchPluginConfig, QemuMappedQuantumShmemHotPath, QemuMappedQuantumShmemHotPathError,
    QemuNodeChannelError, QemuNodeChild, QemuPluginIpcControlChannel, QemuQuantumShmemConfig,
    QemuShmemHotPathChannel, QemuVmLaunchConfig, complete_qemu_host_plugin_setup,
    spawn_qemu_child_with_fds_in_directory,
};

mod error;
mod support;
pub use error::QemuLiveBlockIoGateError;
mod evidence;
use evidence::*;

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
const GATE_MEMORY_MIB: u32 = 128;
/// Number of background threads used to stress host scheduling on the load run.
const HOST_LOAD_WORKERS: usize = 4;
/// Host poll interval while driving and servicing the guest.
const PRIME_POLL_INTERVAL: Duration = Duration::from_millis(1);
/// Consecutive no-progress polls (at [`PRIME_POLL_INTERVAL`]) before the drive
/// declares the guest stalled on device I/O rather than merely executing slowly.
const DRIVE_STALL_POLLS: u64 = 5_000;
/// Wall delay that forces the guest to win the host-work race.
const DELAYED_RESPONSE_WALL_TIME: Duration = Duration::from_millis(100);
/// Default crucible-shmem device length: 4 MiB, a whole sector multiple.
const DEFAULT_DEVICE_SIZE_BYTES: u64 = 4 * 1024 * 1024;
/// Default busy-window ceiling the run advances the node toward.
const DEFAULT_BUSY_CEILING_ICOUNT: u64 = 12_000_000;
/// Maximum successive scheduler windows used to complete a userspace write.
const MAX_BLOCK_IO_QUANTA: u64 = 8;

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
    race: DeviceHostWorkRaceEvidence,
    completion_observations: Vec<BlockCompletionObservation>,
    canonical_log: Vec<u8>,
}

/// Host-race evidence accumulated by one gate leg.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct DeviceHostWorkRaceEvidence {
    completion_pinned_before_dispatch: bool,
    host_won_race: bool,
    guest_won_race: bool,
    async_dispatches: usize,
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
    /// The host-wins leg finished COMPUTE before the guest reached completion.
    pub host_wins_race_proven: bool,
    /// The guest-wins leg reached completion before host COMPUTE finished.
    pub guest_wins_race_proven: bool,
    /// Every asynchronous request had its completion pinned before dispatch.
    pub completion_pinned_before_dispatch: bool,
    /// All three legs produced byte-identical canonical I/O logs.
    pub canonical_logs_identical: bool,
}

/// Drives the certifying live block-I/O gate and reports the observed behaviour.
///
/// Boots the diskless-firmware guest with a `crucible-shmem` virtio-blk device,
/// stands up a live node whose host-I/O runtime services `SLOT_BLK_IO`, advances
/// the node once toward the busy ceiling, and records what the servicing observed.
/// The run is repeated in synchronous, host-wins, and guest-wins modes. Their
/// block observations and canonical I/O logs must match exactly.
///
/// # Errors
///
/// Returns [`QemuLiveBlockIoGateError`] when launch preparation, the plugin
/// handshake, the host-I/O runtime, shared-memory driving, or child supervision
/// fails, or when any race leg diverges.
pub fn run_qemu_live_block_io_gate(
    config: &QemuLiveBlockIoGateConfig,
) -> Result<QemuLiveBlockIoReport, QemuLiveBlockIoGateError> {
    let reference = run_one_scenario(config, RunRole::Synchronous)?;
    let host_wins = run_one_scenario(config, RunRole::HostWins)?;
    let guest_wins = run_one_scenario(config, RunRole::GuestWins)?;

    assert_runs_match(&reference, &host_wins, "host-wins")?;
    assert_runs_match(&reference, &guest_wins, "guest-wins")?;
    if !host_wins.race.host_won_race {
        return Err(QemuLiveBlockIoGateError::RaceNotForced {
            role: "host-wins",
            evidence: format!("{:?}", host_wins.race),
        });
    }
    if !guest_wins.race.guest_won_race {
        return Err(QemuLiveBlockIoGateError::RaceNotForced {
            role: "guest-wins",
            evidence: format!("{:?}", guest_wins.race),
        });
    }
    let completion_pinned_before_dispatch = host_wins.race.completion_pinned_before_dispatch
        && guest_wins.race.completion_pinned_before_dispatch;

    Ok(QemuLiveBlockIoReport {
        advance: reference.advance,
        diagnostics: reference.diagnostics,
        orderly_child_exit: reference.orderly_child_exit,
        deterministic_under_host_load: true,
        host_load_applied: config.second_run_host_load,
        delayed_response_applied: guest_wins.race.guest_won_race,
        host_wins_race_proven: true,
        guest_wins_race_proven: true,
        completion_pinned_before_dispatch,
        canonical_logs_identical: true,
    })
}

/// Which scenario run this is, controlling the run subdirectory and host load.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunRole {
    Synchronous,
    HostWins,
    GuestWins,
}

impl RunRole {
    const fn subdir(self) -> &'static str {
        match self {
            Self::Synchronous => "run-synchronous",
            Self::HostWins => "run-host-wins",
            Self::GuestWins => "run-guest-wins",
        }
    }

    const fn applies_host_load(self) -> bool {
        matches!(self, Self::GuestWins)
    }

    const fn worker_delay(self) -> QemuDeviceHostWorkDelay {
        match self {
            Self::GuestWins => QemuDeviceHostWorkDelay::Wall(DELAYED_RESPONSE_WALL_TIME),
            Self::Synchronous | Self::HostWins => QemuDeviceHostWorkDelay::None,
        }
    }
}

enum BlockServiceMode {
    Synchronous(Box<QemuLiveBlockIoServicer>),
    Asynchronous(QemuLiveBlockHostWorkPool),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct BlockCompletionObservation {
    request_icount: u64,
    completion_icount: u64,
    write: bool,
}

#[derive(Debug, Default)]
struct BlockCompletionLogState {
    pending: VecDeque<BlockCompletionObservation>,
    delivered: Vec<BlockCompletionObservation>,
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

    let host_load = HostLoad::start_if(role.applies_host_load() && config.second_run_host_load);

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

    let mut setup = complete_qemu_host_plugin_setup(
        resources.into_setup_resources(),
        region_config,
        GATE_SLOT,
        &crate::QemuFaultCapabilityRequirement::abi_boundary_v1(),
    )
    .map_err(|source| QemuLiveBlockIoGateError::HostSetup { source })?;
    if !setup.setup_ack().can_schedule() {
        return Err(QemuLiveBlockIoGateError::SetupAckNotReady);
    }

    let diagnostics = BlockIoDiagnostics::shared();
    let mut service_mode = match role {
        RunRole::Synchronous => BlockServiceMode::Synchronous(Box::new(
            QemuLiveBlockIoServicer::from_shmem_fd(
                setup.shmem_as_fd(),
                setup.region().region_len,
                GATE_SLOT,
                icount_shift,
                config.device_size_bytes,
            )
            .map_err(|source| QemuLiveBlockIoGateError::BlockServicer { source })?,
        )),
        RunRole::HostWins | RunRole::GuestWins => BlockServiceMode::Asynchronous(
            QemuLiveBlockHostWorkPool::from_shmem_fd(
                setup.shmem_as_fd(),
                setup.region().region_len,
                GATE_SLOT,
                icount_shift,
                config.device_size_bytes,
            )
            .map_err(|source| QemuLiveBlockIoGateError::HostWorkPool { source })?,
        ),
    };

    let region = mmap_setup_region(setup.shmem_as_fd(), setup.region().region_len)
        .map_err(|source| QemuLiveBlockIoGateError::DriveRegionMap { source })?;
    let shmem_config = QemuQuantumShmemConfig::new(node_id(GATE_NODE), GATE_SLOT)
        .with_router(node_id(GATE_ROUTER), SLOT_NET_ROUTER as u32);
    let mut hot_path = QemuMappedQuantumShmemHotPath::new(shmem_config, region, GateSendAuthorizer)
        .map_err(|source| QemuLiveBlockIoGateError::DriveHotPath { source })?;
    let observer = mmap_setup_region(setup.shmem_as_fd(), setup.region().region_len)
        .map_err(|source| QemuLiveBlockIoGateError::DriveRegionMap { source })?;

    let mut advance = BlockIoAdvanceOutcome::PausedBelowCeiling { icount: 0 };
    let mut race = DeviceHostWorkRaceEvidence::default();
    let mut completion_log = BlockCompletionLogState::default();
    for quantum in 1..=MAX_BLOCK_IO_QUANTA {
        let ceiling = config.busy_ceiling_icount.saturating_mul(quantum);
        advance = drive_and_service(
            &mut hot_path,
            &observer,
            &mut service_mode,
            &diagnostics,
            &setup,
            &mut child,
            role,
            &mut race,
            &mut completion_log,
            DriveOptions {
                ceiling,
                timeout: config.completion_timeout,
            },
        )?;
        if matches!(advance, BlockIoAdvanceOutcome::Failed { .. }) {
            break;
        }
    }

    // Teardown: ask the plugin to quit, then reap. Dropping the child force-kills
    // if it is still alive, so no QEMU is orphaned on an early return.
    let _ = QemuPluginIpcControlChannel::send_quit(&mut setup);
    let orderly_child_exit = reap_child(&mut child, config.completion_timeout);

    drop(hot_path);
    drop(setup);
    drop(child);
    drop(host_load);

    let canonical_log = canonical_block_io_log(&completion_log.delivered)?;
    Ok(BlockIoRunOutcome {
        advance,
        diagnostics: diagnostics.snapshot(),
        orderly_child_exit,
        race,
        completion_observations: completion_log.delivered,
        canonical_log,
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
}

// crucible-lint: allow rust-allow -- the drive boundary joins distinct launch, shared-memory, service, evidence, and scheduling owners.
#[allow(
    clippy::too_many_arguments,
    reason = "the drive boundary joins distinct launch, shared-memory, service, evidence, and scheduling owners"
)]
fn drive_and_service(
    hot_path: &mut QemuMappedQuantumShmemHotPath,
    observer: &MappedSetupRegion,
    service_mode: &mut BlockServiceMode,
    diagnostics: &BlockIoDiagnostics,
    setup: &QemuHostPluginSetup,
    child: &mut QemuNodeChild,
    role: RunRole,
    race: &mut DeviceHostWorkRaceEvidence,
    completion_log: &mut BlockCompletionLogState,
    options: DriveOptions,
) -> Result<BlockIoAdvanceOutcome, QemuLiveBlockIoGateError> {
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
    let mut outcome = BlockIoAdvanceOutcome::PausedBelowCeiling { icount: 0 };
    for _ in 0..max_polls {
        let snapshot = observer
            .node_slot(GATE_SLOT)
            .map_err(|source| QemuLiveBlockIoGateError::DriveSlot { source })?
            .snapshot();
        diagnostics.observe_slot(
            snapshot.current_icount,
            snapshot.device_io_active != 0,
            snapshot.idle_wake_icount,
        );
        let mut worker_busy = false;
        let mut signal_guest = snapshot.device_io_active == 0;
        match service_mode {
            BlockServiceMode::Synchronous(servicer) => {
                let pin = servicer
                    .pin_next_request_completion()
                    .map_err(|source| QemuLiveBlockIoGateError::BlockServicer { source })?;
                let new_request = pin.observed.is_some();
                let delivery_due = pin
                    .next_completion_icount
                    .is_some_and(|deadline| snapshot.current_icount >= deadline);
                if new_request || delivery_due {
                    let serviced = servicer
                        .service(snapshot.current_icount)
                        .map_err(|source| QemuLiveBlockIoGateError::BlockServicer { source })?;
                    signal_guest |= new_request || serviced.delivered > 0;
                    record_service_step(diagnostics, &snapshot, &serviced, completion_log);
                }
            }
            BlockServiceMode::Asynchronous(pool) => {
                if let Some(serviced) = pool
                    .try_complete()
                    .map_err(|source| QemuLiveBlockIoGateError::HostWorkPool { source })?
                {
                    if let Some(completion_icount) = serviced.computed_completion_icount {
                        if snapshot.current_icount < completion_icount {
                            race.host_won_race = true;
                        } else {
                            race.guest_won_race = true;
                        }
                        signal_guest |= matches!(role, RunRole::HostWins);
                    }
                    signal_guest |= serviced.delivered > 0;
                    record_service_step(diagnostics, &snapshot, &serviced, completion_log);
                }
                worker_busy = pool.work_in_flight();
                if !worker_busy {
                    let pin = pool
                        .pin_next_request_completion()
                        .map_err(|source| QemuLiveBlockIoGateError::HostWorkPool { source })?;
                    let new_request = pin.observed.is_some();
                    let delivery_due = pin
                        .next_completion_icount
                        .is_some_and(|deadline| snapshot.current_icount >= deadline);
                    if new_request || delivery_due {
                        if let Some(observed) = pin.observed {
                            if pin
                                .next_completion_icount
                                .is_none_or(|deadline| deadline > observed.completion_icount)
                            {
                                return Err(QemuLiveBlockIoGateError::PinMismatch {
                                    observed_completion_icount: observed.completion_icount,
                                    published_completion_icount: pin.next_completion_icount,
                                });
                            }
                            race.completion_pinned_before_dispatch = true;
                        }
                        let delay = if new_request && !race.guest_won_race {
                            role.worker_delay()
                        } else {
                            QemuDeviceHostWorkDelay::None
                        };
                        pool.dispatch(snapshot.current_icount, delay)
                            .map_err(|source| QemuLiveBlockIoGateError::HostWorkPool { source })?;
                        race.async_dispatches += 1;
                        worker_busy = true;
                        signal_guest |= new_request && matches!(role, RunRole::GuestWins);
                    }
                }
            }
        }
        if signal_guest {
            let _ = setup.signal_plugin_wake();
        }

        if snapshot.current_icount >= options.ceiling
            && !worker_busy
            && snapshot.device_io_active == 0
        {
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
    Ok(outcome)
}

fn record_service_step(
    diagnostics: &BlockIoDiagnostics,
    snapshot: &crucible_shmem::NodeSlotSnapshot,
    serviced: &QemuLiveBlockIoServiceStep,
    completion_log: &mut BlockCompletionLogState,
) {
    diagnostics.record(
        snapshot.current_icount,
        snapshot.device_io_active != 0,
        snapshot.idle_wake_icount,
        serviced,
    );
    if let (Some(request_icount), Some(completion_icount)) = (
        serviced.first_request_icount,
        serviced.computed_completion_icount,
    ) {
        completion_log
            .pending
            .push_back(BlockCompletionObservation {
                request_icount,
                completion_icount,
                write: serviced.write_frames_processed > 0,
            });
    }
    for _ in 0..serviced.delivered {
        if let Some(delivered) = completion_log.pending.pop_front() {
            completion_log.delivered.push(delivered);
        }
    }
}
