//! Loaded-QEMU proof that the Rust control plugin owns virtual time end to end.
//!
//! This module owns the production integration gate that boots the patched QEMU
//! binary once with the real Rust control plugin loaded, then drives a
//! multi-quantum scheduler that proves the plugin is the sole virtual-time
//! authority through its idle-loop, deadline-introspection, and idle-jump paths.
//!
//! Unlike [`crate::run_live_plugin_install_gate`], which proves a single exact
//! boot-barrier quantum, this gate advances the guest through several quanta:
//!
//! 1. **Boot phase.** The scheduler raises the ceiling in fixed steps while the
//!    guest is busy. Each busy quantum stops exactly at the host-published
//!    ceiling, which is only possible if the plugin honors the max-advance
//!    ceiling as time authority.
//! 2. **Idle observation.** The first quantum whose guest parks in an idle
//!    `sti; hlt` wait pauses with the node reported `IDLE` and a computed
//!    `next_deadline` beyond the ceiling. That is the live proof the plugin read
//!    QEMU's exact virtual-timer deadline and published a deterministic idle
//!    wake (T-PLUG-5/6, T-TIME-6).
//! 3. **Idle-jump advancement.** A single wide quantum then lets the parked
//!    guest idle-jump toward a far ceiling. The plugin advances virtual time in
//!    O(1) timer-deadline jumps rather than the per-instruction wall-clock crawl
//!    of the busy boot phase, which the gate measures and asserts (T-PLUG-7,
//!    T-TIME-5/7). This step is gated by
//!    [`LivePluginQuantumGateConfig::with_prove_idle_jump`] and is currently
//!    **descoped** (`prove_idle_jump = false`): live tracing showed the plugin
//!    reads the deadline, releases, enqueues, and arms the advance correctly, but
//!    the QEMU-side queued-time-advance completion never commits, so the parked
//!    guest does not advance. The scenario therefore stops at the idle
//!    observation and reports `idle_jump_proven = false` until that QEMU-patch
//!    defect is fixed, at which point flipping the flag re-enables the assertion.
//!
//! The whole scenario runs twice — the second run under deliberate host CPU
//! load — and the two runs must produce byte-identical execution fingerprints
//! and identical idle observations. Determinism under host timing is the proof
//! that virtual time is icount-derived and host-time-independent, i.e. that the
//! Rust plugin, not the host or wall clock, owns the clock (T-PLUG-4, T-TIME-5).
//!
//! The emitted report records idle and advancement evidence plus `time_authority=rust-plugin`
//! so the Rust plugin remains the sole time owner.

mod errors;
mod preemption_gate;
mod scheduler;

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread;
use std::time::Duration;

use crucible::{
    ExecutionFingerprint, ExecutionHorizon, Icount, NodeId, SchedulerError, SchedulerNodeId,
    SchedulerSendAuthorization, SchedulerSendAuthorizer, SimDouble, SimDoubleConfig,
    SimDoubleError, SimDoubleHostScheduleEvent, SimInstructionScript, SimInstructionStep,
    sim_double_host_schedule_canonical_bytes,
};
use crucible_protocol::{
    CONTROL_PROTOCOL_VERSION, HostMsg, PluginMsg, SETUP_ACK_STATUS_READY,
    control_decode_plugin_msg, control_encode_host_msg,
};
use crucible_shmem::{
    ABI_VERSION, RegionAllocation, RegionConfig, SLOT_NET_ROUTER, mmap_setup_region,
};

use crate::{
    LaunchProfileCandidate, QemuLaunchArtifact, QemuLaunchPluginConfig,
    QemuMappedQuantumShmemHotPath, QemuNodeChannelError, QemuPluginIpcControlChannel,
    QemuQuantumShmemConfig, QemuShmemHotPathChannel, QemuVmLaunchConfig,
    complete_qemu_host_plugin_setup, spawn_qemu_child_with_fds_in_directory,
};

pub use errors::LivePluginQuantumGateError;
pub use preemption_gate::{LivePluginPreemptionReport, run_live_plugin_preemption_gate};

/// Content-addressing domain for quantum-gate launch artifacts.
const GATE_DOMAIN: &str = "crucible.loaded-qemu-plugin-quantum.v1";
/// Stable node name for the single-VM quantum run.
const GATE_NODE: &str = "plugin-quantum-gate-vm";
/// Stable router name reserved by the shared-memory hot path.
const GATE_ROUTER: &str = "plugin-quantum-gate-router";
/// VM slot negotiated during the handshake.
const GATE_SLOT: u32 = 0;
/// Fixed inbound/outbound ring capacity for the single-node quantum run.
const GATE_QUEUE_CAPACITY: u32 = 4;
/// Conservative guest memory size for the quantum run.
const GATE_MEMORY_MIB: u32 = 64;
/// Number of background threads used to stress host scheduling on the load run.
const HOST_LOAD_WORKERS: usize = 4;

/// Tuning parameters for the multi-quantum scheduler that drives one scenario.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LivePluginQuantumSchedule {
    /// Fixed icount increment added to the ceiling for each boot-phase quantum.
    pub ceiling_step_icount: u64,
    /// Upper bound on the boot search; the gate fails if the guest never idles
    /// before the ceiling reaches this icount.
    pub max_search_icount: u64,
    /// Additional icount span beyond the idle onset that the single idle-jump
    /// quantum advances the parked guest toward.
    pub idle_horizon_margin_icount: u64,
    /// Minimum ratio by which the idle-jump advancement rate must exceed the
    /// busy boot advancement rate for the idle-jump proof to hold.
    pub min_idle_speedup_ratio: u64,
}

impl LivePluginQuantumSchedule {
    /// Builds a schedule with conservative defaults tuned for the s11 Linux guest.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            ceiling_step_icount: 4_000_000,
            max_search_icount: 600_000_000,
            idle_horizon_margin_icount: 200_000_000,
            min_idle_speedup_ratio: 4,
        }
    }
}

impl Default for LivePluginQuantumSchedule {
    fn default() -> Self {
        Self::new()
    }
}

/// Inputs for one production loaded-QEMU plugin quantum lifecycle run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LivePluginQuantumGateConfig {
    qemu_executable: PathBuf,
    plugin: PathBuf,
    kernel: PathBuf,
    root_image: PathBuf,
    run_directory: PathBuf,
    initrd: Option<PathBuf>,
    firmware: Option<PathBuf>,
    kernel_cmdline: Option<String>,
    schedule: LivePluginQuantumSchedule,
    completion_timeout: Duration,
    second_run_host_load: bool,
    prove_idle_jump: bool,
}

impl LivePluginQuantumGateConfig {
    /// Builds a quantum-gate configuration with bounded defaults.
    #[must_use]
    pub fn new(
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
            root_image: root_image.into(),
            run_directory: run_directory.into(),
            initrd: None,
            firmware: None,
            kernel_cmdline: None,
            schedule: LivePluginQuantumSchedule::new(),
            completion_timeout: Duration::from_secs(240),
            second_run_host_load: true,
            prove_idle_jump: false,
        }
    }

    /// Returns this configuration with a content-addressed initrd.
    #[must_use]
    pub fn with_initrd(mut self, initrd: impl Into<PathBuf>) -> Self {
        self.initrd = Some(initrd.into());
        self
    }

    /// Returns this configuration with a pinned diskless guest firmware image.
    ///
    /// Setting a firmware selects the diskless launch shape (no virtio-blk root
    /// disk), which a Linux guest requires here because the multi-quantum runner
    /// does not service block I/O.
    #[must_use]
    pub fn with_firmware(mut self, firmware: impl Into<PathBuf>) -> Self {
        self.firmware = Some(firmware.into());
        self
    }

    /// Returns this configuration with an explicit guest kernel command line.
    #[must_use]
    pub fn with_kernel_cmdline(mut self, kernel_cmdline: impl Into<String>) -> Self {
        self.kernel_cmdline = Some(kernel_cmdline.into());
        self
    }

    /// Returns this configuration with a different multi-quantum schedule.
    #[must_use]
    pub const fn with_schedule(mut self, schedule: LivePluginQuantumSchedule) -> Self {
        self.schedule = schedule;
        self
    }

    /// Returns this configuration with a different host-side completion bound.
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

    /// Returns this configuration with idle-jump advancement proof toggled.
    ///
    /// While the QEMU-side queued-time-advance completion defect is open, this
    /// stays `false`: the gate proves ceiling ownership, idle park, and deadline
    /// introspection (T-PLUG-4/5/6) but stops at the idle observation without
    /// requiring the plugin to advance the parked guest (T-PLUG-7). Set `true`
    /// once the completion defect is fixed to also assert the idle-jump.
    #[must_use]
    pub const fn with_prove_idle_jump(mut self, prove_idle_jump: bool) -> Self {
        self.prove_idle_jump = prove_idle_jump;
        self
    }

    /// Returns the multi-quantum schedule that drives one scenario.
    #[must_use]
    pub(crate) const fn schedule(&self) -> LivePluginQuantumSchedule {
        self.schedule
    }

    /// Returns the host-side per-quantum completion bound.
    #[must_use]
    pub(crate) const fn completion_timeout(&self) -> Duration {
        self.completion_timeout
    }

    /// Returns whether the scenario asserts idle-jump advancement (T-PLUG-7).
    #[must_use]
    pub(crate) const fn prove_idle_jump(&self) -> bool {
        self.prove_idle_jump
    }
}

/// The idle observation captured at the first parked-idle quantum.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LivePluginIdleObservation {
    /// Node icount at which the guest first parked in an idle wait.
    pub idle_onset_icount: u64,
    /// Computed next virtual-timer deadline the plugin published while idle.
    pub next_deadline_icount: u64,
    /// Ceiling in force when the idle observation was captured.
    pub ceiling_icount: u64,
    /// Number of busy boot quanta the scheduler ran before the guest idled.
    pub boot_quantum_count: u32,
}

/// Advancement-rate evidence distinguishing busy boot from idle-jump.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LivePluginAdvancementRates {
    /// Busy boot icount advanced from cold start to the idle onset.
    pub boot_icount_span: u64,
    /// Wall-clock microseconds spent advancing the boot span.
    pub boot_wall_micros: u128,
    /// Idle icount advanced by the single idle-jump quantum.
    pub idle_icount_span: u64,
    /// Wall-clock microseconds spent advancing the idle span.
    pub idle_wall_micros: u128,
    /// Terminal node icount the idle-jump quantum reached.
    pub terminal_icount: u64,
}

impl LivePluginAdvancementRates {
    /// Returns whole-icount-per-second boot advancement, saturating at zero wall.
    #[must_use]
    pub fn boot_icount_per_second(&self) -> u128 {
        rate_per_second(self.boot_icount_span, self.boot_wall_micros)
    }

    /// Returns whole-icount-per-second idle advancement, saturating at zero wall.
    #[must_use]
    pub fn idle_icount_per_second(&self) -> u128 {
        rate_per_second(self.idle_icount_span, self.idle_wall_micros)
    }
}

/// The outcome of one full scenario run (boot, idle, idle-jump, teardown).
#[derive(Clone, Debug, PartialEq, Eq)]
struct ScenarioOutcome {
    idle: LivePluginIdleObservation,
    rates: LivePluginAdvancementRates,
    fingerprint: ExecutionFingerprint,
    host_observable_schedule: Vec<SimDoubleHostScheduleEvent>,
}

/// Successful evidence from the production loaded-QEMU plugin quantum gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LivePluginQuantumReport {
    /// Idle observation from the reference (first) run.
    pub idle: LivePluginIdleObservation,
    /// Advancement rates from the reference (first) run.
    pub rates: LivePluginAdvancementRates,
    /// Execution fingerprint the plugin published at the terminal boundary.
    pub execution_fingerprint: ExecutionFingerprint,
    /// The second run, under host CPU load, matched the first byte for byte.
    pub deterministic_under_host_load: bool,
    /// Host CPU load was actually applied during the second run.
    pub host_load_applied: bool,
    /// The live production-plugin schedule replayed byte-for-byte through
    /// [`SimDouble`].
    pub sim_double_schedule_matches: bool,
    /// Number of host-observable schedule entries compared on each side.
    pub host_observable_schedule_len: usize,
    /// The idle-jump advancement rate exceeded the boot rate by the required
    /// factor, proving O(1) idle advancement rather than a per-instruction crawl.
    pub idle_jump_proven: bool,
    /// No plugin other than the Rust control plugin owned time control.
    pub time_authority_is_rust_plugin: bool,
}

/// Runs the Rust control plugin through the full idle/time-authority lifecycle.
///
/// The scenario boots the standalone guest, observes its idle park with a
/// computed timer deadline, idle-jumps toward a far ceiling in O(1), and tears
/// the plugin down cleanly. It then repeats under host CPU load and requires the
/// two runs to be byte-identical.
///
/// # Errors
///
/// Returns [`LivePluginQuantumGateError`] when launch preparation, the live
/// plugin handshake, the multi-quantum scheduler, the idle observation, the
/// idle-jump advancement bound, cross-run determinism, teardown, or child
/// reaping fails.
pub fn run_live_plugin_quantum_gate(
    config: &LivePluginQuantumGateConfig,
) -> Result<LivePluginQuantumReport, LivePluginQuantumGateError> {
    if config.schedule.ceiling_step_icount == 0 {
        return Err(LivePluginQuantumGateError::ZeroCeilingStep);
    }

    let reference = run_one_scenario(config, RunRole::Reference)?;
    let (second, host_load_applied) = if config.second_run_host_load {
        (run_one_scenario(config, RunRole::HostLoad)?, true)
    } else {
        (run_one_scenario(config, RunRole::Repeat)?, false)
    };

    assert_runs_match(&reference, &second)?;
    assert_sim_double_schedule_matches(&reference.host_observable_schedule)?;

    // Idle-jump advancement (T-PLUG-7) is proven only when it was actually
    // driven and the idle advancement rate exceeds the busy boot rate by the
    // required factor. When descoped, the idle-jump quantum is not run, so this
    // is unconditionally false and the emitted evidence records the open defect.
    let idle_jump_proven = config.prove_idle_jump
        && reference.rates.idle_icount_per_second()
            >= reference
                .rates
                .boot_icount_per_second()
                .saturating_mul(u128::from(config.schedule.min_idle_speedup_ratio));

    Ok(LivePluginQuantumReport {
        idle: reference.idle,
        rates: reference.rates,
        execution_fingerprint: reference.fingerprint,
        deterministic_under_host_load: true,
        host_load_applied,
        sim_double_schedule_matches: true,
        host_observable_schedule_len: reference.host_observable_schedule.len(),
        idle_jump_proven,
        time_authority_is_rust_plugin: true,
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
    config: &LivePluginQuantumGateConfig,
    role: RunRole,
) -> Result<ScenarioOutcome, LivePluginQuantumGateError> {
    let run_directory = config.run_directory.join(role.subdir());
    fs::create_dir_all(&run_directory).map_err(|source| {
        LivePluginQuantumGateError::PrepareRunDirectory {
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
        .map_err(|source| LivePluginQuantumGateError::LaunchProfile { source })?;
    profile
        .guest_entropy_seed_file()
        .write_to_dir(&run_directory)
        .map_err(|source| LivePluginQuantumGateError::GuestEntropySeed {
            path: run_directory.clone(),
            source,
        })?;

    // A single production control plugin, no observation plugin: the Rust plugin
    // is the sole sim_shmem dispatch authority for virtual-time advancement.
    let plugin = QemuLaunchPluginConfig::new(path_text(&config.plugin), GATE_SLOT);
    let command = profile
        .qemu_launch_command(
            vm_launch_config(config),
            path_text(&config.qemu_executable),
            plugin,
        )
        .map_err(|source| LivePluginQuantumGateError::LaunchCommand { source })?;

    let region_config = RegionConfig::new(1, GATE_QUEUE_CAPACITY, 0);
    let allocation = RegionAllocation::new(region_config)
        .map_err(|source| LivePluginQuantumGateError::RegionLayout { source })?;
    let spawned = spawn_qemu_child_with_fds_in_directory(
        &command,
        &run_directory,
        allocation.layout().region_size,
    )
    .map_err(|source| LivePluginQuantumGateError::Spawn { source })?;
    let (mut child, resources) = spawned.into_parts();

    let mut setup =
        complete_qemu_host_plugin_setup(resources.into_setup_resources(), region_config, GATE_SLOT)
            .map_err(|source| LivePluginQuantumGateError::HostSetup { source })?;
    if !setup.setup_ack().can_schedule() {
        return Err(LivePluginQuantumGateError::SetupAckNotReady);
    }

    let region = mmap_setup_region(setup.shmem_as_fd(), setup.region().region_len)
        .map_err(|source| LivePluginQuantumGateError::RegionMap { source })?;
    let hot_path_config = QemuQuantumShmemConfig::new(node_id(GATE_NODE), GATE_SLOT)
        .with_router(node_id(GATE_ROUTER), SLOT_NET_ROUTER as u32);
    let mut hot_path =
        QemuMappedQuantumShmemHotPath::new(hot_path_config, region, GateSendAuthorizer)
            .map_err(|source| LivePluginQuantumGateError::MappedHotPath { source })?;

    let (idle, rates, host_observable_schedule) =
        scheduler::drive_scenario(&mut hot_path, &mut child, &setup, config)?;
    let fingerprint = QemuShmemHotPathChannel::execution_fingerprint(&mut hot_path)
        .map_err(|source| channel_error("read execution fingerprint", source))?;

    setup
        .assert_run_control_silent()
        .map_err(|source| channel_error("prove run control silence", source))?;

    QemuPluginIpcControlChannel::send_quit(&mut setup)
        .map_err(|source| channel_error("send plugin Quit", source))?;
    scheduler::wait_for_plugin_teardown(&hot_path, config)?;
    let exit_status = scheduler::wait_for_natural_child_exit(&mut child, config)?;
    if !exit_status.success() {
        return Err(LivePluginQuantumGateError::ChildExitUnclean {
            status: exit_status.to_string(),
        });
    }
    drop(setup);
    drop(child);
    drop(host_load);

    Ok(ScenarioOutcome {
        idle,
        rates,
        fingerprint,
        host_observable_schedule,
    })
}

/// Requires the load run to reproduce the reference run byte for byte.
fn assert_runs_match(
    reference: &ScenarioOutcome,
    second: &ScenarioOutcome,
) -> Result<(), LivePluginQuantumGateError> {
    if reference.idle != second.idle {
        return Err(LivePluginQuantumGateError::SecondRunDiverged {
            reason: format!(
                "idle observation differed: {:?} vs {:?}",
                reference.idle, second.idle
            ),
        });
    }
    if reference.rates.terminal_icount != second.rates.terminal_icount {
        return Err(LivePluginQuantumGateError::SecondRunDiverged {
            reason: format!(
                "terminal icount differed: {} vs {}",
                reference.rates.terminal_icount, second.rates.terminal_icount
            ),
        });
    }
    if reference.fingerprint != second.fingerprint {
        return Err(LivePluginQuantumGateError::SecondRunDiverged {
            reason: format!(
                "execution fingerprint differed: {} vs {}",
                reference.fingerprint.hash.to_hex(),
                second.fingerprint.hash.to_hex()
            ),
        });
    }
    if reference.host_observable_schedule != second.host_observable_schedule {
        return Err(LivePluginQuantumGateError::SecondRunDiverged {
            reason: format!(
                "host-observable schedule differed: {:?} vs {:?}",
                reference.host_observable_schedule, second.host_observable_schedule
            ),
        });
    }
    Ok(())
}

/// Replays a production-plugin host schedule through the in-process double.
fn assert_sim_double_schedule_matches(
    live_schedule: &[SimDoubleHostScheduleEvent],
) -> Result<(), LivePluginQuantumGateError> {
    let steps = live_schedule
        .iter()
        .map(|event| match event {
            SimDoubleHostScheduleEvent::HorizonAdvance {
                from_icount,
                reached_icount,
                ..
            } => Ok(SimInstructionStep::budget(
                reached_icount.checked_sub(*from_icount).ok_or_else(|| {
                    LivePluginQuantumGateError::SimDoubleScheduleMismatch {
                        reason: format!(
                            "live schedule moved backward from {from_icount} to {reached_icount}"
                        ),
                    }
                })?,
            )),
            other => Err(LivePluginQuantumGateError::SimDoubleScheduleMismatch {
                reason: format!("quantum gate emitted unsupported live event {other:?}"),
            }),
        })
        .collect::<Result<Vec<_>, _>>()?;
    let mut double = SimDouble::new(SimDoubleConfig {
        slot_index: GATE_SLOT,
        vm_node_count: 1,
        queue_capacity: GATE_QUEUE_CAPACITY,
        icount_shift: 0,
        script: SimInstructionScript::new(steps),
    })
    .map_err(sim_double_error)?;
    complete_sim_double_setup(&mut double)?;

    for expected in live_schedule {
        let SimDoubleHostScheduleEvent::HorizonAdvance {
            requested_icount,
            outcome,
            ..
        } = expected
        else {
            return Err(LivePluginQuantumGateError::SimDoubleScheduleMismatch {
                reason: format!("quantum gate emitted unsupported live event {expected:?}"),
            });
        };
        let actual = double
            .advance_scripted_quantum(
                ExecutionHorizon {
                    icount: Icount {
                        retired: *requested_icount,
                    },
                },
                &GateSendAuthorizer,
            )
            .map_err(sim_double_error)?;
        if &actual != outcome {
            return Err(LivePluginQuantumGateError::SimDoubleScheduleMismatch {
                reason: format!("double outcome {actual:?} did not match live outcome {outcome:?}"),
            });
        }
    }

    let live_bytes = sim_double_host_schedule_canonical_bytes(live_schedule);
    let double_bytes = sim_double_host_schedule_canonical_bytes(double.host_observable_schedule());
    if live_bytes != double_bytes {
        return Err(LivePluginQuantumGateError::SimDoubleScheduleMismatch {
            reason: format!(
                "live schedule {:?} did not match SimDouble schedule {:?} byte-for-byte",
                live_schedule,
                double.host_observable_schedule()
            ),
        });
    }
    Ok(())
}

fn complete_sim_double_setup(double: &mut SimDouble) -> Result<(), LivePluginQuantumGateError> {
    let hello_ack = control_encode_host_msg(&HostMsg::HelloAck {
        proto_version: CONTROL_PROTOCOL_VERSION,
        abi_version: ABI_VERSION,
        slot_index: GATE_SLOT,
        node_count: double.shmem_layout().node_count,
    });
    double
        .accept_host_control_frame(&hello_ack)
        .map_err(sim_double_error)?;
    let setup = control_encode_host_msg(&HostMsg::Setup {
        region_len: double.shmem_layout().region_size,
    });
    let setup_ack = double
        .accept_host_control_frame(&setup)
        .map_err(sim_double_error)?
        .ok_or_else(|| LivePluginQuantumGateError::SimDoubleScheduleMismatch {
            reason: String::from("SimDouble setup emitted no SetupAck"),
        })?;
    let message = control_decode_plugin_msg(&setup_ack).map_err(|error| {
        LivePluginQuantumGateError::SimDoubleScheduleMismatch {
            reason: format!("decode SimDouble SetupAck failed: {error}"),
        }
    })?;
    if message
        != (PluginMsg::SetupAck {
            status: SETUP_ACK_STATUS_READY,
        })
    {
        return Err(LivePluginQuantumGateError::SimDoubleScheduleMismatch {
            reason: format!("SimDouble setup returned unexpected message {message:?}"),
        });
    }
    Ok(())
}

fn sim_double_error(source: SimDoubleError) -> LivePluginQuantumGateError {
    LivePluginQuantumGateError::SimDoubleScheduleMismatch {
        reason: source.to_string(),
    }
}

/// A background host-CPU load generator that stresses scheduling around a run.
///
/// The busy threads consume CPU without touching the guest, the plugin, or the
/// shared-memory region, so a deterministic, icount-owning plugin must produce
/// an identical fingerprint whether or not the load is present.
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

fn rate_per_second(icount_span: u64, wall_micros: u128) -> u128 {
    if wall_micros == 0 {
        return u128::from(icount_span).saturating_mul(1_000_000);
    }
    u128::from(icount_span)
        .saturating_mul(1_000_000)
        .checked_div(wall_micros)
        .unwrap_or(0)
}

fn vm_launch_config(config: &LivePluginQuantumGateConfig) -> QemuVmLaunchConfig {
    let kernel = launch_artifact("kernel", &config.kernel);
    let vm = match &config.firmware {
        Some(firmware) => QemuVmLaunchConfig::new_diskless(
            GATE_NODE,
            kernel,
            launch_artifact("firmware", firmware),
        ),
        None => QemuVmLaunchConfig::new(
            GATE_NODE,
            kernel,
            launch_artifact("root-image", &config.root_image),
        ),
    };
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

fn channel_error(
    operation: &'static str,
    source: QemuNodeChannelError,
) -> LivePluginQuantumGateError {
    LivePluginQuantumGateError::channel(operation, source)
}

/// Send authorizer for the single-node quantum run.
///
/// The quantum gate has one VM and one router slot and never routes a real
/// cross-node frame, so authorization is unconditional.
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
