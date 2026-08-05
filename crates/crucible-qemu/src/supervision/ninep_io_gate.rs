//! Certifying live 9p-I/O gate for QEMU over `SLOT_9P_IO`.
//!
//! This is the 9p analogue of [`crate::supervision::run_qemu_live_block_io_gate`]
//! and the first vehicle that drives real guest 9p I/O through the crucible
//! shared-memory rings. It attaches a `crucible-shmem` virtio-9p device (the
//! [`CrucibleShmem9pDevice`] synth-backed launch glue) to a diskless guest whose
//! PID 1 loads the 9p modules and `mount -t 9p`s the crucible export, then
//! drives a raw shared-memory hot path toward a busy ceiling while a
//! [`QemuLive9pIoServicer`] services `SLOT_9P_IO` each poll.
//!
//! Unlike virtio-blk -- whose probe reads fire at device realize before the
//! guest executes any instruction -- a virtio-9p filesystem is untouched until
//! userspace mounts it, so the guest here first boots to userspace and only then
//! issues 9p ops. The gate requires those operations to cross `SLOT_9P_IO`,
//! complete at deterministic device horizons, and let the guest continue to the
//! scheduler ceiling. A second run adds host CPU load and delays a due response's
//! physical ring write; both runs must retain identical icount-domain results.

use std::fs;
use std::os::unix::net::UnixStream;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crucible::Icount;
use crucible_shmem::{
    NodeSlotSnapshot, RegionAllocation, RegionConfig, SLOT_NET_ROUTER, STATUS_IDLE,
    mmap_setup_region,
};

pub use self::error::QemuLive9pIoGateError;
use self::support::{
    GateSendAuthorizer, HostLoad, bounded_drive_polls, deterministic_projection, node_id,
    path_text, vm_launch_config,
};
use super::ninep_io_servicer::{
    NinepIoDiagnostics, NinepIoDiagnosticsSnapshot, QemuLive9pIoServicer, QemuLive9pIoServicerError,
};
use crate::{
    CrucibleShmem9pDevice, LaunchProfileCandidate, QemuHostPluginSetup, QemuLaunchCommandBuilder,
    QemuLaunchPluginConfig, QemuMappedQuantumShmemHotPath, QemuNodeChild,
    QemuPluginIpcControlChannel, QemuQmpChannelConfig, QemuQmpVmStateControlChannel,
    QemuQuantumShmemConfig, QemuShmemHotPathChannel, QmpError, complete_qemu_host_plugin_setup,
    spawn_qemu_child_with_fds_in_directory,
};

mod error;
mod support;

/// Content-addressing domain for 9p-I/O launch artifacts.
const GATE_DOMAIN: &str = "crucible.loaded-qemu-live-9p-io.v1";
/// Stable node name for the single-VM 9p-I/O run.
const GATE_NODE: &str = "live-9p-io-vm";
/// Stable router name reserved by the shared-memory hot path.
const GATE_ROUTER: &str = "live-9p-io-router";
/// VM slot negotiated during the handshake.
const GATE_SLOT: u32 = 0;
/// Fixed inbound/outbound ring capacity for the single-node run.
const GATE_QUEUE_CAPACITY: u32 = 4;
/// Stable QMP endpoint used to synchronize the post-boot-barrier main loop.
const GATE_QMP_SOCKET_FILE_NAME: &str = "crucible-live-9p-io-qmp.sock";
/// Guest memory size for the 9p-I/O run.
///
/// Larger than the block gate's 64 MiB: this guest boots a full kernel and runs
/// a `mount -t 9p` workload, and 64 MiB left too little contiguous room for the
/// early-boot decompression under the sim accelerator. 128 MiB boots reliably
/// under both the sim accelerator (the reference leg) and TCG (the control leg).
const GATE_MEMORY_MIB: u32 = 128;
/// Number of background threads used to stress host scheduling on the load run.
const HOST_LOAD_WORKERS: usize = 4;
/// Host poll interval while driving and servicing the guest.
const DRIVE_POLL_INTERVAL: Duration = Duration::from_millis(1);
/// Consecutive no-progress polls (at [`DRIVE_POLL_INTERVAL`]) before the drive
/// declares the guest stalled on device I/O rather than merely executing slowly.
const DRIVE_STALL_POLLS: u64 = 5_000;
/// First ceiling used to release the plugin boot barrier.
const PRIME_CEILING_ICOUNT: u64 = 1_000_000;
/// Cadence for wake pulses while QMP proves the main loop is reachable.
const QMP_PRIMER_WAKE_INTERVAL: Duration = Duration::from_millis(10);
/// Wall delay injected after virtual time reaches a pending 9p response horizon.
const DELAYED_RESPONSE_WALL_TIME: Duration = Duration::from_millis(100);
/// Default busy-window ceiling the run advances the node toward.
///
/// Above the observed first Linux 9p negotiation (~3.33 billion instructions),
/// because the guest must boot to userspace and run its module-load +
/// `mount -t 9p` sequence before it touches 9p.
const DEFAULT_BUSY_CEILING_ICOUNT: u64 = 4_000_000_000;

/// Inputs for one certifying live 9p-I/O gate run.
#[derive(Clone, Debug)]
pub struct QemuLive9pIoGateConfig {
    qemu_executable: PathBuf,
    plugin: PathBuf,
    kernel: PathBuf,
    firmware: PathBuf,
    run_directory: PathBuf,
    initrd: Option<PathBuf>,
    kernel_cmdline: Option<String>,
    busy_ceiling_icount: u64,
    completion_timeout: Duration,
    second_run_host_load: bool,
}

impl QemuLive9pIoGateConfig {
    /// Builds a 9p-I/O gate configuration with bounded defaults.
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
            busy_ceiling_icount: DEFAULT_BUSY_CEILING_ICOUNT,
            completion_timeout: Duration::from_secs(60),
            second_run_host_load: true,
        }
    }

    /// Returns this configuration with a content-addressed initrd.
    ///
    /// The 9p gate requires an initrd whose PID 1 mounts the crucible export;
    /// without one the guest never issues 9p I/O.
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
pub enum NinepIoAdvanceOutcome {
    /// The guest reached the busy ceiling (progressed past the 9p mount).
    ReachedCeiling {
        /// Node icount reached at the ceiling.
        icount: u64,
    },
    /// The guest completed 9p I/O and parked with no wake due through the ceiling.
    QuiescentThroughCeiling {
        /// Node icount where the guest became idle.
        icount: u64,
        /// First deterministic local wake, strictly beyond the scheduler ceiling.
        idle_wake_icount: u64,
    },
    /// The guest parked below the ceiling (stalled on 9p I/O or idled).
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

/// The outcome of one full 9p-I/O run.
#[derive(Clone, Debug, PartialEq, Eq)]
struct NinepIoRunOutcome {
    advance: NinepIoAdvanceOutcome,
    diagnostics: NinepIoDiagnosticsSnapshot,
    orderly_child_exit: bool,
    response_delay_applied: bool,
}

/// Certifying evidence from the live 9p-I/O gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct QemuLive9pIoReport {
    /// How the reference (sim) run's advance terminated.
    pub advance: NinepIoAdvanceOutcome,
    /// The reference (sim) run's accumulated 9p-I/O observations.
    pub diagnostics: NinepIoDiagnosticsSnapshot,
    /// The reference run's node shut down cleanly.
    pub orderly_child_exit: bool,
    /// The second sim run (under host CPU load) matched the first observation.
    pub deterministic_under_host_load: bool,
    /// Host CPU load was actually applied during the second sim run.
    pub host_load_applied: bool,
    /// The second run delayed a due response without changing observations.
    pub delayed_response_applied: bool,
    /// The TCG control leg saw the guest issue a real 9p op (QEMU's `msize`
    /// warning) absent the sim accelerator, independently validating the guest
    /// workload.
    pub tcg_control_issued_9p: bool,
}

/// Drives the certifying live 9p-I/O gate and reports the observed behaviour.
///
/// This gate runs three legs:
///
/// - **Reference (sim) leg.** Boots the guest with a `crucible-shmem` virtio-9p
///   device and a `mount -t 9p` initrd on the sim+plugin raw hot path, services
///   `SLOT_9P_IO`, and requires a request and response before the guest reaches
///   its busy ceiling.
/// - **Host-load sim leg.** Repeats the reference while stressing host scheduling
///   and delays the due response in wall time after virtual time reaches its
///   horizon. The request/response counts and modeled completion latency must
///   remain identical.
/// - **TCG control leg.** Boots the same guest + 9p device under TCG with no
///   plugin, and confirms the guest actually issues a 9p op (QEMU emits its
///   `msize` degraded-performance warning only when its 9p device receives a
///   PDU). This independently proves the guest workload issues 9p traffic.
///
/// # Errors
///
/// Returns [`QemuLive9pIoGateError`] when launch preparation, the plugin
/// handshake, the 9p servicer, or the drive fails; when the two sim runs' 9p
/// observations diverge; when either sim leg fails its forwarding, completion,
/// or progress requirements; or when the TCG control leg does not observe the
/// guest issuing a 9p op.
pub fn run_qemu_live_9p_io_gate(
    config: &QemuLive9pIoGateConfig,
) -> Result<QemuLive9pIoReport, QemuLive9pIoGateError> {
    let reference = run_one_scenario(config, RunRole::Reference)?;
    let (second, host_load_applied) = if config.second_run_host_load {
        (run_one_scenario(config, RunRole::HostLoad)?, true)
    } else {
        (run_one_scenario(config, RunRole::Repeat)?, false)
    };

    assert_runs_match(&reference, &second)?;
    certify_run("reference", &reference, false)?;
    certify_run(
        if config.second_run_host_load {
            "host-load"
        } else {
            "repeat"
        },
        &second,
        config.second_run_host_load,
    )?;

    // Control: the same guest independently issues a real 9p op under TCG.
    let tcg_control_issued_9p = run_tcg_control_leg(config)?;
    if !tcg_control_issued_9p {
        return Err(QemuLive9pIoGateError::ControlDidNotIssue9p);
    }

    Ok(QemuLive9pIoReport {
        advance: reference.advance,
        diagnostics: reference.diagnostics,
        orderly_child_exit: reference.orderly_child_exit,
        deterministic_under_host_load: true,
        host_load_applied,
        delayed_response_applied: second.response_delay_applied,
        tcg_control_issued_9p,
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
    config: &QemuLive9pIoGateConfig,
    role: RunRole,
) -> Result<NinepIoRunOutcome, QemuLive9pIoGateError> {
    let run_directory = config.run_directory.join(role.subdir());
    fs::create_dir_all(&run_directory).map_err(|source| {
        QemuLive9pIoGateError::PrepareRunDirectory {
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
        .map_err(|source| QemuLive9pIoGateError::LaunchProfile { source })?;
    let icount_shift = profile.icount_shift();
    profile
        .guest_entropy_seed_file()
        .write_to_dir(&run_directory)
        .map_err(|source| QemuLive9pIoGateError::GuestEntropySeed {
            path: run_directory.clone(),
            source,
        })?;

    let qmp_config = QemuQmpChannelConfig::new(GATE_QMP_SOCKET_FILE_NAME)
        .map_err(|source| QemuLive9pIoGateError::LaunchCommand { source })?;
    let plugin = QemuLaunchPluginConfig::new(path_text(&config.plugin), GATE_SLOT);
    // QMP connects after the no-wake priming quantum releases the plugin boot
    // barrier and lets the guest park between quanta with the BQL released.
    let command = QemuLaunchCommandBuilder::new(
        profile,
        vm_launch_config(config),
        path_text(&config.qemu_executable),
        plugin,
    )
    .with_qmp(qmp_config.clone())
    .build()
    .map_err(|source| QemuLive9pIoGateError::LaunchCommand { source })?;

    let region_config = RegionConfig::new(1, GATE_QUEUE_CAPACITY, 0);
    let allocation = RegionAllocation::new(region_config)
        .map_err(|source| QemuLive9pIoGateError::RegionLayout { source })?;
    let spawned = spawn_qemu_child_with_fds_in_directory(
        &command,
        &run_directory,
        allocation.layout().region_size,
    )
    .map_err(|source| QemuLive9pIoGateError::Spawn { source })?;
    let (mut child, resources) = spawned.into_parts();

    let mut setup = complete_qemu_host_plugin_setup(
        resources.into_setup_resources(),
        region_config,
        GATE_SLOT,
        &crate::QemuFaultCapabilityRequirement::abi_boundary_v1(),
    )
    .map_err(|source| QemuLive9pIoGateError::HostSetup { source })?;
    if !setup.setup_ack().can_schedule() {
        return Err(QemuLive9pIoGateError::SetupAckNotReady);
    }

    // The 9p servicer owns a writable mapping confined to the SLOT_9P_IO ring
    // pair (it publishes only the device-completion deadline into the guest node
    // slot, never the guest's observed fields). Diagnostics is shared so the
    // observations survive teardown.
    let diagnostics = NinepIoDiagnostics::shared();
    let mut servicer = QemuLive9pIoServicer::from_shmem_fd(
        setup.shmem_as_fd(),
        setup.region().region_len,
        GATE_SLOT,
        icount_shift,
    )
    .map_err(|source| QemuLive9pIoGateError::NinepServicer { source })?;

    let region = mmap_setup_region(setup.shmem_as_fd(), setup.region().region_len)
        .map_err(|source| QemuLive9pIoGateError::DriveRegionMap { source })?;
    let shmem_config = QemuQuantumShmemConfig::new(node_id(GATE_NODE), GATE_SLOT)
        .with_router(node_id(GATE_ROUTER), SLOT_NET_ROUTER as u32);
    let mut hot_path = QemuMappedQuantumShmemHotPath::new(shmem_config, region, GateSendAuthorizer)
        .map_err(|source| QemuLive9pIoGateError::DriveHotPath { source })?;

    prime_guest_off_boot_barrier(
        &mut hot_path,
        &mut servicer,
        &diagnostics,
        &mut child,
        config.completion_timeout,
    )?;
    let qmp = connect_qmp_priming_main_loop(&setup, &qmp_config.socket_path(&run_directory))
        .map_err(|source| QemuLive9pIoGateError::QmpConnect { source })?;
    let mut qmp = qmp.into_inner();
    let run_state = qmp
        .query_status()
        .map_err(|source| QemuLive9pIoGateError::QmpConnect { source })?;
    if !run_state.running {
        return Err(QemuLive9pIoGateError::QmpNotRunning {
            status: format!("{:?}", run_state.status),
        });
    }
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

    Ok(NinepIoRunOutcome {
        advance,
        diagnostics: diagnostics.snapshot(),
        orderly_child_exit,
        response_delay_applied,
    })
}

/// Boots the same guest + 9p device under TCG with no plugin and reports whether
/// the guest issued a real 9p op.
///
/// This is a plain QEMU spawn -- no plugin, no shared memory, no icount time
/// control -- so the guest runs at wall speed under TCG and its `mount -t 9p`
/// reaches QEMU's stock virtio-9p device, which emits a `msize`
/// degraded-performance warning to stderr the first time it receives a 9p PDU.
/// Observing that warning within the bounded budget proves the guest issues a 9p
/// op absent the sim accelerator; its absence means the guest never mounted.
///
/// # Errors
///
/// Returns [`QemuLive9pIoGateError`] when the control run directory or its
/// captured stderr file cannot be created, or the QEMU child cannot be spawned.
fn run_tcg_control_leg(config: &QemuLive9pIoGateConfig) -> Result<bool, QemuLive9pIoGateError> {
    let run_directory = config.run_directory.join("run-tcg-control");
    fs::create_dir_all(&run_directory).map_err(|source| {
        QemuLive9pIoGateError::ControlRunDirectory {
            path: run_directory.clone(),
            source,
        }
    })?;
    let stderr_path = run_directory.join("qemu-stderr.log");
    let stderr_file =
        fs::File::create(&stderr_path).map_err(|source| QemuLive9pIoGateError::ControlStderr {
            path: stderr_path.clone(),
            source,
        })?;

    let memory = format!("{GATE_MEMORY_MIB}M");
    let mut command = Command::new(&config.qemu_executable);
    command.args([
        "-nodefaults",
        "-no-user-config",
        "-display",
        "none",
        "-monitor",
        "none",
        "-serial",
        "none",
        "-parallel",
        "none",
        "-machine",
        "pc-q35-9.2",
        "-m",
        &memory,
        "-accel",
        "tcg,thread=single",
        "-cpu",
        "qemu64,-rdrand,-rdseed",
        "-smp",
        "1",
        "-kernel",
        &path_text(&config.kernel),
        "-bios",
        &path_text(&config.firmware),
        "-append",
        "console=ttyS0 reboot=k panic=1",
    ]);
    if let Some(initrd) = &config.initrd {
        command.args(["-initrd", &path_text(initrd)]);
    }
    let mut device_args = Vec::new();
    CrucibleShmem9pDevice::new().append_qemu_args(&mut device_args);
    command.args(&device_args);
    command
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(stderr_file);

    let mut child = command
        .spawn()
        .map_err(|source| QemuLive9pIoGateError::ControlSpawn { source })?;

    let max_polls = bounded_drive_polls(config.completion_timeout);
    let mut issued = false;
    for _ in 0..max_polls {
        if control_stderr_shows_ninep_op(&stderr_path) {
            issued = true;
            break;
        }
        if matches!(child.try_wait(), Ok(Some(_))) {
            break;
        }
        thread::sleep(DRIVE_POLL_INTERVAL);
    }
    // Final read, in case the op landed just before QEMU exited or the budget lapsed.
    if !issued {
        issued = control_stderr_shows_ninep_op(&stderr_path);
    }

    let _ = child.kill();
    let _ = child.wait();
    Ok(issued)
}

/// Returns whether the captured control-QEMU stderr shows a 9p op was received.
///
/// QEMU's stock virtio-9p device logs a `msize` degraded-performance warning the
/// first time it handles a 9p PDU, so its presence is a faithful marker that the
/// guest issued at least one 9p request.
fn control_stderr_shows_ninep_op(stderr_path: &Path) -> bool {
    fs::read_to_string(stderr_path).is_ok_and(|text| text.contains("msize"))
}

/// Releases the plugin boot barrier without signaling the idle-wake eventfd.
///
/// Publishing the first ceiling wakes the boot-barrier futex by itself. An
/// eventfd signal at this boundary can run the all-halted idle path before QEMU
/// has scheduled the boot CPU and jump directly to the ceiling at icount 1.
/// This priming path therefore mirrors the proven node-step gate: it only polls
/// the guest slot and services any early 9p traffic until real instruction
/// execution reaches the small priming ceiling.
///
/// # Errors
///
/// Returns [`QemuLive9pIoGateError`] when the quantum cannot be published or
/// observed, servicing fails, the child exits, or the guest does not reach the
/// priming ceiling within `timeout`.
fn prime_guest_off_boot_barrier(
    hot_path: &mut QemuMappedQuantumShmemHotPath,
    servicer: &mut QemuLive9pIoServicer,
    diagnostics: &NinepIoDiagnostics,
    child: &mut QemuNodeChild,
    timeout: Duration,
) -> Result<(), QemuLive9pIoGateError> {
    let pending = QemuShmemHotPathChannel::start_quantum(
        hot_path,
        crucible::ExecutionHorizon {
            icount: Icount {
                retired: PRIME_CEILING_ICOUNT,
            },
        },
    )
    .map_err(|source| QemuLive9pIoGateError::drive("start 9p priming quantum", source))?;

    let mut outcome = String::from("timed out below priming ceiling");
    let mut reached = false;
    for _ in 0..bounded_drive_polls(timeout) {
        let snapshot = servicer
            .vm_node_snapshot()
            .map_err(|source| QemuLive9pIoGateError::NinepServicer { source })?;
        let serviced = servicer
            .service(snapshot.current_icount)
            .map_err(|source| QemuLive9pIoGateError::NinepServicer { source })?;
        diagnostics.record(
            snapshot.current_icount,
            snapshot.device_io_active != 0,
            snapshot.idle_wake_icount,
            &serviced,
        );
        if snapshot.current_icount >= PRIME_CEILING_ICOUNT {
            reached = true;
            break;
        }
        if let Some(status) = child
            .try_wait_natural_exit()
            .map_err(|source| QemuLive9pIoGateError::ChildWait { source })?
        {
            outcome = format!("child exited during priming: {status}");
            break;
        }
        thread::sleep(DRIVE_POLL_INTERVAL);
    }

    let _ = QemuShmemHotPathChannel::finish_quantum(hot_path, pending);
    if reached {
        Ok(())
    } else {
        Err(QemuLive9pIoGateError::PrimeDidNotReach { advance: outcome })
    }
}

/// Drives the guest toward `ceiling` on a raw hot path while servicing 9p I/O.
///
/// Publishes the ceiling (releasing the boot barrier via the shared-memory futex
/// wake), then each poll pulses the plugin wake, reads the guest slot, services
/// `SLOT_9P_IO` at the observed icount, and records the observation. It
/// terminates when the guest reaches the ceiling, stalls (no icount progress for
/// [`DRIVE_STALL_POLLS`] polls, i.e. blocked on 9p I/O the plugin never advances
/// past), the child exits, or the poll budget lapses. A stall is returned as an
/// outcome so the certifying caller can report the exact failure.
///
/// # Errors
///
/// Returns [`QemuLive9pIoGateError`] only when the quantum cannot be published or
/// the guest slot cannot be read; a stalled guest is a normal outcome.
struct DriveOptions {
    ceiling: u64,
    timeout: Duration,
    response_wall_delay: Duration,
}

fn drive_and_service(
    hot_path: &mut QemuMappedQuantumShmemHotPath,
    servicer: &mut QemuLive9pIoServicer,
    diagnostics: &NinepIoDiagnostics,
    setup: &QemuHostPluginSetup,
    child: &mut QemuNodeChild,
    options: DriveOptions,
) -> Result<(NinepIoAdvanceOutcome, bool), QemuLive9pIoGateError> {
    let pending = QemuShmemHotPathChannel::start_quantum(
        hot_path,
        crucible::ExecutionHorizon {
            icount: Icount {
                retired: options.ceiling,
            },
        },
    )
    .map_err(|source| QemuLive9pIoGateError::drive("start 9p-io drive quantum", source))?;

    let max_polls = bounded_drive_polls(options.timeout);
    let mut last_icount = 0_u64;
    let mut stall_polls = 0_u64;
    let mut response_delay_applied = false;
    let mut outcome = NinepIoAdvanceOutcome::PausedBelowCeiling { icount: 0 };
    for _ in 0..max_polls {
        let _ = setup.signal_plugin_wake();
        let snapshot = servicer
            .vm_node_snapshot()
            .map_err(|source| QemuLive9pIoGateError::NinepServicer { source })?;
        if !response_delay_applied
            && !options.response_wall_delay.is_zero()
            && servicer
                .next_completion_icount()
                .is_some_and(|deadline| snapshot.current_icount >= deadline)
        {
            // Force a repoll at an already reached delivery icount before the
            // response ring write is visible. The guest stays parked at the
            // same logical time while this wall-only delay elapses.
            thread::sleep(options.response_wall_delay);
            response_delay_applied = true;
        }
        let serviced = servicer
            .service_with_before_delivery(
                snapshot.current_icount,
                |processed, computed_deadline| {
                    if !response_delay_applied
                        && !options.response_wall_delay.is_zero()
                        && processed > 0
                        && computed_deadline
                            .is_some_and(|deadline| snapshot.current_icount >= deadline)
                    {
                        // The host first observed this request after its horizon.
                        // Delay between COMPUTE and DELIVER so the certification
                        // still proves wall time cannot change logical timing.
                        thread::sleep(options.response_wall_delay);
                        response_delay_applied = true;
                    }
                },
            )
            .map_err(|source| QemuLive9pIoGateError::NinepServicer { source })?;
        diagnostics.record(
            snapshot.current_icount,
            snapshot.device_io_active != 0,
            snapshot.idle_wake_icount,
            &serviced,
        );

        // Reaching the scheduler boundary is not sufficient while a
        // just-serviced completion is still crossing back into QEMU. Wait for
        // the plugin to consume the response and release its device-I/O hold
        // before teardown; otherwise shutdown can make the callback return -1
        // and turn a valid response into a spurious virtio I/O error.
        if let Some(closed) = completed_ceiling_outcome(&snapshot, &serviced, options.ceiling) {
            outcome = closed;
            break;
        }
        if let Some(status) = child
            .try_wait_natural_exit()
            .map_err(|source| QemuLive9pIoGateError::ChildWait { source })?
        {
            outcome = NinepIoAdvanceOutcome::Failed {
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
                outcome = NinepIoAdvanceOutcome::PausedBelowCeiling {
                    icount: snapshot.current_icount,
                };
                break;
            }
        }
        thread::sleep(DRIVE_POLL_INTERVAL);
    }

    let _ = QemuShmemHotPathChannel::finish_quantum(hot_path, pending);
    Ok((outcome, response_delay_applied))
}

/// Classifies a fully drained guest observation that closes the scheduler ceiling.
fn completed_ceiling_outcome(
    snapshot: &NodeSlotSnapshot,
    serviced: &super::ninep_io_servicer::QemuLive9pIoServiceStep,
    ceiling: u64,
) -> Option<NinepIoAdvanceOutcome> {
    if snapshot.device_io_active != 0 || serviced.processed != 0 || serviced.delivered != 0 {
        return None;
    }
    if snapshot.current_icount >= ceiling {
        return Some(NinepIoAdvanceOutcome::ReachedCeiling {
            icount: snapshot.current_icount,
        });
    }
    // An idle node whose earliest deterministic wake lies beyond the ceiling
    // has also closed this quantum: no guest work is eligible before the
    // scheduler boundary. Host polling may observe either this publication or
    // the preceding busy retirement, so both are valid closure modes and
    // neither depends on wall-clock timing.
    (snapshot.status == STATUS_IDLE && snapshot.idle_wake_icount > ceiling).then_some(
        NinepIoAdvanceOutcome::QuiescentThroughCeiling {
            icount: snapshot.current_icount,
            idle_wake_icount: snapshot.idle_wake_icount,
        },
    )
}

/// Connects QMP while pulsing the plugin wake fd after the priming quantum.
///
/// Priming has moved the guest off the startup barrier and parked it between
/// quanta, so the main loop can service QMP without advancing guest time.
///
/// # Errors
///
/// Returns [`QmpError`] when QEMU never exposes or services the QMP socket.
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

/// Reaps the child within a bounded poll budget, force-killing on drop otherwise.
fn reap_child(child: &mut QemuNodeChild, timeout: Duration) -> bool {
    let max_polls = bounded_drive_polls(timeout);
    for _ in 0..max_polls {
        match child.try_wait_natural_exit() {
            Ok(Some(status)) => return status.success(),
            Ok(None) => thread::sleep(DRIVE_POLL_INTERVAL),
            Err(_) => return false,
        }
    }
    false
}

/// Requires the load run to reproduce the reference run's deterministic 9p
/// observations.
///
/// Only the *icount-domain* observations are compared: whether a 9p request and
/// response crossed the rings, the latency from the first request to its exact
/// device-completion horizon, and whether the guest slot last advertised active
/// device I/O. These are pure functions of the guest's icount-deterministic
/// execution and the servicer's deterministic latency model, so they must match
/// byte-for-byte across runs.
///
/// Wall-clock-dependent fields are deliberately excluded: `service_calls` counts
/// host poll iterations (a function of how fast the plugin advanced virtual time
/// between polls), the cumulative frame count can include a second request
/// drained after the guest has already reached the terminal ceiling, and the
/// guest's resting icount / advance outcome can land on either side of the busy
/// ceiling depending on which poll observes the idle jump. Those never affect
/// the certified first request/response or guest state within the horizon, so
/// folding them into the comparison would make host polling part of canonical
/// state. (Unlike the block gate, whose guest freezes at icount 0 the instant it
/// blocks, a 9p guest boots to userspace before it mounts.)
fn assert_runs_match(
    reference: &NinepIoRunOutcome,
    second: &NinepIoRunOutcome,
) -> Result<(), QemuLive9pIoGateError> {
    let a = deterministic_projection(&reference.diagnostics);
    let b = deterministic_projection(&second.diagnostics);
    if a != b {
        return Err(QemuLive9pIoGateError::SecondRunDiverged {
            reason: format!("9p deterministic device observations differed: {a:?} vs {b:?}"),
        });
    }
    Ok(())
}

/// Requires one sim leg to prove forwarding, deterministic completion, and
/// progress past the guest's 9p request.
fn certify_run(
    run: &'static str,
    outcome: &NinepIoRunOutcome,
    require_response_delay: bool,
) -> Result<(), QemuLive9pIoGateError> {
    let observations = &outcome.diagnostics;
    let failure = if observations.frames_processed == 0 {
        Some("no guest 9p request reached SLOT_9P_IO")
    } else if observations.frames_delivered == 0 {
        Some("no deterministic 9p response was delivered")
    } else if observations.first_request_icount.is_none() {
        Some("the first 9p request has no icount observation")
    } else if observations.first_completion_horizon.is_none() {
        Some("the first 9p request published no completion horizon")
    } else if matches!(
        (
            observations.first_request_icount,
            observations.first_completion_horizon,
        ),
        (Some(request), Some(horizon)) if horizon <= request
    ) {
        Some("the first 9p completion horizon was not in the future")
    } else if observations.last_device_io_active {
        Some("device I/O remained active after the response")
    } else if matches!(
        (
            observations.last_current_icount,
            observations.first_completion_horizon,
        ),
        (current, Some(horizon)) if current <= horizon
    ) {
        Some("the guest did not progress past the first 9p completion horizon")
    } else if !matches!(
        &outcome.advance,
        NinepIoAdvanceOutcome::ReachedCeiling { .. }
            | NinepIoAdvanceOutcome::QuiescentThroughCeiling { .. }
    ) {
        Some("the guest did not close the scheduler ceiling")
    } else if require_response_delay && !outcome.response_delay_applied {
        Some("the host-load leg never injected its due-response wall delay")
    } else {
        None
    };
    if let Some(reason) = failure {
        return Err(QemuLive9pIoGateError::CertificationFailed {
            run,
            reason,
            advance: format!("{:?}", outcome.advance),
            diagnostics: format!("{:?}", outcome.diagnostics),
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests;
