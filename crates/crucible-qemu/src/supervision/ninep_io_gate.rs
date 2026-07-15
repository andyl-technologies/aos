//! Diagnostic live 9p-I/O gate for a QEMU node over `SLOT_9P_IO`.
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
//! issues 9p ops. The gate is deliberately *diagnostic*: it advances once toward
//! the ceiling and REPORTS what the servicing observed (how many 9p request
//! frames were serviced, the device completion horizon computed for the first
//! request, whether the guest progressed to the ceiling or stalled on the 9p
//! completion horizon, and the guest slot's published device-I/O state). The run
//! repeats under host CPU load and the two runs' 9p observations must match, per
//! the servicer's determinism invariant.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
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

use super::ninep_io_servicer::{
    NinepIoDiagnostics, NinepIoDiagnosticsSnapshot, QemuLive9pIoServicer,
    QemuLive9pIoServicerError,
};
use crate::{
    CrucibleShmem9pDevice, LaunchProfileCandidate, LaunchProfileError, QemuHostPluginSetup,
    QemuHostPluginSetupError, QemuLaunchArtifact, QemuLaunchCommandBuilder, QemuLaunchCommandError,
    QemuLaunchPluginConfig, QemuMappedQuantumShmemHotPath, QemuMappedQuantumShmemHotPathError,
    QemuNodeChannelError, QemuNodeChild, QemuPluginIpcControlChannel, QemuQuantumShmemConfig,
    QemuShmemHotPathChannel, QemuVmLaunchConfig, complete_qemu_host_plugin_setup,
    spawn_qemu_child_with_fds_in_directory,
};

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
/// Default busy-window ceiling the run advances the node toward.
///
/// Well above the diskless idle onset (~15.8M), because the guest must boot to
/// userspace and run its module-load + `mount -t 9p` sequence before it touches
/// 9p at all; the first 9p op therefore lands far later than a virtio-blk probe.
const DEFAULT_BUSY_CEILING_ICOUNT: u64 = 100_000_000;

/// Inputs for one diagnostic live 9p-I/O gate run.
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

/// The diagnostic outcome of one full 9p-I/O run.
#[derive(Clone, Debug, PartialEq, Eq)]
struct NinepIoRunOutcome {
    advance: NinepIoAdvanceOutcome,
    diagnostics: NinepIoDiagnosticsSnapshot,
    orderly_child_exit: bool,
}

/// Diagnostic evidence from the live 9p-I/O gate.
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
    /// The TCG control leg saw the guest issue a real 9p op (QEMU's `msize`
    /// warning) absent the sim accelerator — proving the sim-leg zero is a
    /// forward gap, not a broken guest.
    pub tcg_control_issued_9p: bool,
}

/// Drives the diagnostic live 9p-I/O gate and reports the observed behaviour.
///
/// This gate documents a currently-open gap: under the sim accelerator a guest's
/// 9p mount does not reach the crucible `SLOT_9P_IO` substrate, though the guest
/// boots and the identical mount reaches QEMU's 9p device under TCG. It runs two
/// legs and asserts that signature so the gap is pinned by CI:
///
/// - **Reference (sim) leg.** Boots the guest with a `crucible-shmem` virtio-9p
///   device and a `mount -t 9p` initrd on the sim+plugin raw hot path, services
///   `SLOT_9P_IO`, and drives once toward the busy ceiling. The guest boots
///   (idle-jumps to the ceiling once its mount blocks) but `frames_processed`
///   is 0 — the mount op never reaches the host servicer. Repeated under host
///   load; the two runs' icount-domain observations must match. The day the
///   C-side forward fix lands (`frames_processed` becomes nonzero) this leg's
///   assertion fails on purpose, flagging that the gate must be upgraded to
///   assert forwarding + post-0039 progress.
/// - **TCG control leg.** Boots the same guest + 9p device under TCG with no
///   plugin, and confirms the guest actually issues a 9p op (QEMU emits its
///   `msize` degraded-performance warning only when its 9p device receives a
///   PDU). This proves the sim-leg zero is a *forward* gap under sim, not a
///   guest that never mounts.
///
/// # Errors
///
/// Returns [`QemuLive9pIoGateError`] when launch preparation, the plugin
/// handshake, the 9p servicer, or the drive fails; when the two sim runs' 9p
/// observations diverge; when the sim leg's `frames_processed` is nonzero (the
/// forward gap has closed — upgrade the gate) or the guest failed to boot; or
/// when the TCG control leg does not observe the guest issuing a 9p op.
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

    // Documented forward gap: the mount op does not reach SLOT_9P_IO under sim.
    // A nonzero count means the C-side forward fix has landed and this gate must
    // be upgraded to assert forwarding (and post-0039 guest progress).
    if reference.diagnostics.frames_processed != 0 {
        return Err(QemuLive9pIoGateError::ForwardGapClosed {
            frames_processed: reference.diagnostics.frames_processed,
        });
    }
    // The guest must nonetheless boot: it idle-jumps to the ceiling once its
    // mount blocks. A guest that never boots would stall below the ceiling, and
    // then a zero frame count would be meaningless.
    if !matches!(reference.advance, NinepIoAdvanceOutcome::ReachedCeiling { .. }) {
        return Err(QemuLive9pIoGateError::GuestDidNotBoot {
            advance: format!("{:?}", reference.advance),
        });
    }

    // Control: the same guest issues a real 9p op under TCG (sim absent), so the
    // sim-leg zero is a forward gap rather than a guest that never mounts.
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

    let plugin = QemuLaunchPluginConfig::new(path_text(&config.plugin), GATE_SLOT);
    // No QMP and no QemuNode here: this diagnostic drives a raw hot path so the
    // 9p ring can be serviced concurrently with the guest's boot-to-mount. The
    // node-based 9p harness weaves the same servicer into a real QemuNode; this
    // raw drive is the lighter-weight observation companion (peer to the block
    // block_io_gate) that first establishes the launch contract and the pre-0039
    // stall signature.
    let command = QemuLaunchCommandBuilder::new(
        profile,
        vm_launch_config(config),
        path_text(&config.qemu_executable),
        plugin,
    )
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

    let mut setup =
        complete_qemu_host_plugin_setup(resources.into_setup_resources(), region_config, GATE_SLOT)
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

    let advance = drive_and_service(
        &mut hot_path,
        &mut servicer,
        &diagnostics,
        &setup,
        &mut child,
        config.busy_ceiling_icount,
        config.completion_timeout,
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

/// Drives the guest toward `ceiling` on a raw hot path while servicing 9p I/O.
///
/// Publishes the ceiling (releasing the boot barrier via the shared-memory futex
/// wake), then each poll pulses the plugin wake, reads the guest slot, services
/// `SLOT_9P_IO` at the observed icount, and records the observation. It
/// terminates when the guest reaches the ceiling, stalls (no icount progress for
/// [`DRIVE_STALL_POLLS`] polls, i.e. blocked on 9p I/O the plugin never advances
/// past), the child exits, or the poll budget lapses. A stall is returned as an
/// outcome, never an error -- observing it IS the diagnostic.
///
/// # Errors
///
/// Returns [`QemuLive9pIoGateError`] only when the quantum cannot be published or
/// the guest slot cannot be read; a stalled guest is a normal outcome.
fn drive_and_service(
    hot_path: &mut QemuMappedQuantumShmemHotPath,
    servicer: &mut QemuLive9pIoServicer,
    diagnostics: &NinepIoDiagnostics,
    setup: &QemuHostPluginSetup,
    child: &mut QemuNodeChild,
    ceiling: u64,
    timeout: Duration,
) -> Result<NinepIoAdvanceOutcome, QemuLive9pIoGateError> {
    let pending = QemuShmemHotPathChannel::start_quantum(
        hot_path,
        crucible::ExecutionHorizon {
            icount: Icount { retired: ceiling },
        },
    )
    .map_err(|source| QemuLive9pIoGateError::drive("start 9p-io drive quantum", source))?;

    let max_polls = bounded_drive_polls(timeout);
    let mut last_icount = 0_u64;
    let mut stall_polls = 0_u64;
    let mut outcome = NinepIoAdvanceOutcome::PausedBelowCeiling { icount: 0 };
    for _ in 0..max_polls {
        let _ = setup.signal_plugin_wake();
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

        if snapshot.current_icount >= ceiling {
            outcome = NinepIoAdvanceOutcome::ReachedCeiling {
                icount: snapshot.current_icount,
            };
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
    Ok(outcome)
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
/// Only the *icount-domain* observations are compared: how many 9p request
/// frames the servicer processed and delivered, the icount at which the guest
/// issued its first 9p request, the device-completion horizon computed for it,
/// and whether the guest slot last advertised active device I/O. These are pure
/// functions of the guest's icount-deterministic execution and the servicer's
/// deterministic latency model, so they must match byte-for-byte across runs.
///
/// Wall-clock-dependent fields are deliberately excluded: `service_calls` counts
/// host poll iterations (a function of how fast the plugin advanced virtual time
/// between polls), and the guest's resting icount / advance outcome can land on
/// either side of the busy ceiling depending on which poll observes the idle
/// jump. Those never reflect a determinism violation, so folding them into the
/// comparison would make the gate flaky. (Unlike the block gate, whose guest
/// freezes at icount 0 the instant it blocks -- making even its poll count
/// converge -- a 9p guest boots to userspace before it mounts, so its poll count
/// genuinely varies run to run.)
fn assert_runs_match(
    reference: &NinepIoRunOutcome,
    second: &NinepIoRunOutcome,
) -> Result<(), QemuLive9pIoGateError> {
    let a = deterministic_projection(&reference.diagnostics);
    let b = deterministic_projection(&second.diagnostics);
    if a != b {
        return Err(QemuLive9pIoGateError::SecondRunDiverged {
            reason: format!("9p icount-domain observations differed: {a:?} vs {b:?}"),
        });
    }
    Ok(())
}

/// The determinism-relevant, icount-domain subset of a run's 9p observations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NinepDeterministicObservations {
    frames_processed: usize,
    frames_delivered: usize,
    first_request_icount: Option<u64>,
    first_completion_horizon: Option<u64>,
    last_device_io_active: bool,
}

/// Projects the deterministic, icount-domain subset out of a full snapshot.
fn deterministic_projection(
    snapshot: &NinepIoDiagnosticsSnapshot,
) -> NinepDeterministicObservations {
    NinepDeterministicObservations {
        frames_processed: snapshot.frames_processed,
        frames_delivered: snapshot.frames_delivered,
        first_request_icount: snapshot.first_request_icount,
        first_completion_horizon: snapshot.first_completion_horizon,
        last_device_io_active: snapshot.last_device_io_active,
    }
}

/// Returns the number of drive polls that fit within `timeout`, at least one.
fn bounded_drive_polls(timeout: Duration) -> u64 {
    let interval = DRIVE_POLL_INTERVAL.as_micros().max(1);
    let budget = timeout.as_micros();
    u64::try_from(budget / interval).unwrap_or(u64::MAX).max(1)
}

/// Builds the diskless-firmware VM launch config with a crucible-shmem 9p device.
fn vm_launch_config(config: &QemuLive9pIoGateConfig) -> QemuVmLaunchConfig {
    let kernel = launch_artifact("kernel", &config.kernel);
    let vm = QemuVmLaunchConfig::new_diskless(
        GATE_NODE,
        kernel,
        launch_artifact("firmware", &config.firmware),
    )
    .with_crucible_shmem_9p(CrucibleShmem9pDevice::new());
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

/// Send authorizer for the single-node 9p-I/O run.
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

/// Error returned by the diagnostic live 9p-I/O gate.
#[derive(Debug, Error)]
pub enum QemuLive9pIoGateError {
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
    /// The 9p-I/O servicer could not be built or serviced.
    #[error("9p-I/O servicer failed")]
    NinepServicer {
        /// Underlying 9p-servicer error.
        source: QemuLive9pIoServicerError,
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
    /// The sim leg forwarded a 9p frame -- the documented forward gap has closed.
    #[error(
        "9p forward gap has closed: sim leg processed {frames_processed} frame(s); \
         upgrade this gate to assert forwarding and post-0039 guest progress"
    )]
    ForwardGapClosed {
        /// Number of 9p request frames the sim leg's servicer processed.
        frames_processed: usize,
    },
    /// The sim-leg guest never reached the busy ceiling, so it did not boot.
    #[error("sim-leg guest did not boot to the ceiling: {advance}")]
    GuestDidNotBoot {
        /// Debug rendering of the observed advance outcome.
        advance: String,
    },
    /// The TCG control leg never observed the guest issue a 9p op.
    #[error("TCG control leg did not observe the guest issue a 9p op (no msize warning)")]
    ControlDidNotIssue9p,
    /// The TCG control run subdirectory could not be created.
    #[error("prepare TCG control run directory {path} failed")]
    ControlRunDirectory {
        /// Control run subdirectory path.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The TCG control stderr capture file could not be created.
    #[error("create TCG control stderr capture {path} failed")]
    ControlStderr {
        /// Stderr capture file path.
        path: PathBuf,
        /// Underlying I/O error.
        source: std::io::Error,
    },
    /// The TCG control QEMU child could not be spawned.
    #[error("spawn TCG control QEMU child failed")]
    ControlSpawn {
        /// Underlying spawn error.
        source: std::io::Error,
    },
}

impl QemuLive9pIoGateError {
    /// Builds a [`QemuLive9pIoGateError::Drive`] for a drive operation.
    fn drive(operation: &'static str, source: QemuNodeChannelError) -> Self {
        Self::Drive { operation, source }
    }
}
