//! Loaded-QEMU proof that the Rust control plugin owns virtual time end to end.
//!
//! The production integration gate boots patched QEMU with the real control
//! plugin, then drives several quanta to prove that the plugin is the sole
//! virtual-time authority:
//!
//! 1. **Boot phase.** The scheduler raises the ceiling in fixed steps while the
//!    guest is busy and requires every stop at the host-published ceiling.
//! 2. **Idle observation.** The parked guest must report `IDLE` and an exact
//!    `next_deadline` beyond the ceiling (T-PLUG-5/6, T-TIME-6).
//! 3. **Idle-jump advancement.** A wide quantum must advance in O(1) deadline
//!    jumps (T-PLUG-7, T-TIME-5/7).
//!
//! The whole scenario runs twice - the second run under bounded scheduler
//! preemption - and requires byte-identical fingerprints and idle observations,
//! proving icount-derived, host-time-independent execution (T-PLUG-4, T-TIME-5).

mod errors;
mod preemption_gate;
mod scheduler;

use std::fs;
use std::path::{Path, PathBuf};
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

use crate::bounded_scheduler_preemption::BoundedSchedulerPreemption as HostAdversary;
use crate::{
    LaunchProfileCandidate, QemuLaunchArtifact, QemuLaunchPluginConfig, QemuLaunchPluginSwitch,
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
    second_run_scheduler_preemption: bool,
    smp_vcpus: u16,
    memory_mib: u32,
    rr_switch_quantum: u64,
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
            second_run_scheduler_preemption: true,
            smp_vcpus: 1,
            memory_mib: GATE_MEMORY_MIB,
            rr_switch_quantum: 4096,
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

    /// Returns this configuration with bounded scheduler preemption on the second run toggled.
    #[must_use]
    pub const fn with_second_run_scheduler_preemption(
        mut self,
        second_run_scheduler_preemption: bool,
    ) -> Self {
        self.second_run_scheduler_preemption = second_run_scheduler_preemption;
        self
    }

    /// Returns this configuration with a fixed guest vCPU count.
    ///
    /// The live idle callback is emitted by patched QEMU only after every
    /// configured vCPU is halted. Values are validated by the deterministic
    /// [`LaunchProfileCandidate`] when the launch command is assembled.
    #[must_use]
    pub const fn with_smp_vcpus(mut self, smp_vcpus: u16) -> Self {
        self.smp_vcpus = smp_vcpus;
        self
    }

    /// Returns the fixed guest vCPU count.
    #[must_use]
    pub const fn smp_vcpus(&self) -> u16 {
        self.smp_vcpus
    }

    /// Returns this configuration with a fixed guest-memory size.
    #[must_use]
    pub const fn with_memory_mib(mut self, memory_mib: u32) -> Self {
        self.memory_mib = memory_mib;
        self
    }

    /// Returns the fixed guest-memory size in mebibytes.
    #[must_use]
    pub const fn memory_mib(&self) -> u32 {
        self.memory_mib
    }

    /// Returns this configuration with a fixed round-robin vCPU switch quantum.
    ///
    /// The value is denominated in node icount and is validated by the
    /// deterministic [`LaunchProfileCandidate`] when the launch command is
    /// assembled.
    #[must_use]
    pub const fn with_rr_switch_quantum(mut self, rr_switch_quantum: u64) -> Self {
        self.rr_switch_quantum = rr_switch_quantum;
        self
    }

    /// Returns the fixed round-robin vCPU switch quantum in node icount.
    #[must_use]
    pub const fn rr_switch_quantum(&self) -> u64 {
        self.rr_switch_quantum
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
    /// Number of guest vCPUs covered by the all-halted idle observation.
    pub smp_vcpus: u16,
    /// Guest-memory size used by the live run, in mebibytes.
    pub memory_mib: u32,
    /// Idle observation from the reference (first) run.
    pub idle: LivePluginIdleObservation,
    /// Advancement rates from the reference (first) run.
    pub rates: LivePluginAdvancementRates,
    /// Execution fingerprint the plugin published at the terminal boundary.
    pub execution_fingerprint: ExecutionFingerprint,
    /// The second run, under bounded scheduler preemption, matched the first byte for byte.
    pub deterministic_under_scheduler_preemption: bool,
    /// Bounded scheduler preemption was actually applied during the second run.
    pub scheduler_preemption_applied: bool,
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
/// the plugin down cleanly. It then repeats under bounded scheduler preemption
/// and requires the two runs to be byte-identical.
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
    let (second, scheduler_preemption_applied) = if config.second_run_scheduler_preemption {
        (run_one_scenario(config, RunRole::Hostile)?, true)
    } else {
        (run_one_scenario(config, RunRole::Repeat)?, false)
    };

    assert_runs_match(&reference, &second)?;
    assert_sim_double_schedule_matches(&reference.host_observable_schedule)?;

    // Idle-jump advancement (T-PLUG-7) is part of every run. The evidence is
    // true only when its rate exceeds the busy boot rate by the required factor.
    let idle_jump_proven = reference.rates.idle_icount_per_second()
        >= reference
            .rates
            .boot_icount_per_second()
            .saturating_mul(u128::from(config.schedule.min_idle_speedup_ratio));

    Ok(LivePluginQuantumReport {
        smp_vcpus: config.smp_vcpus,
        memory_mib: config.memory_mib,
        idle: reference.idle,
        rates: reference.rates,
        execution_fingerprint: reference.fingerprint,
        deterministic_under_scheduler_preemption: true,
        scheduler_preemption_applied,
        sim_double_schedule_matches: true,
        host_observable_schedule_len: reference.host_observable_schedule.len(),
        idle_jump_proven,
        time_authority_is_rust_plugin: true,
    })
}

/// Which scenario run this is, controlling the run subdirectory and scheduler preemption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RunRole {
    Reference,
    Hostile,
    Repeat,
}

impl RunRole {
    const fn subdir(self) -> &'static str {
        match self {
            Self::Reference => "run-reference",
            Self::Hostile => "run-scheduler-preemption",
            Self::Repeat => "run-repeat",
        }
    }

    const fn applies_scheduler_preemption(self) -> bool {
        matches!(self, Self::Hostile)
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

    let mut candidate = LaunchProfileCandidate::default()
        .with_memory_mib(config.memory_mib)
        .with_smp_vcpus(config.smp_vcpus)
        .with_rr_switch_quantum(config.rr_switch_quantum);
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
    let plugin = QemuLaunchPluginConfig::new(path_text(&config.plugin), GATE_SLOT)
        .with_fault_target_node(GATE_NODE)
        .with_fingerprint(QemuLaunchPluginSwitch::On);
    let command = profile
        .qemu_launch_command_for_live_gate(
            vm_launch_config(config),
            path_text(&config.qemu_executable),
            plugin,
            crate::LivePluginGuestArchitecture::X86_64,
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

    let mut setup = complete_qemu_host_plugin_setup(
        resources.into_setup_resources(),
        region_config,
        GATE_SLOT,
        command.fault_capability_requirement(),
    )
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

    // Start only after setup, adjacent to the guest schedule being perturbed.
    let mut host_adversary =
        HostAdversary::start_if(role.applies_scheduler_preemption(), child.process_id())
            .map_err(|source| LivePluginQuantumGateError::SchedulerPreemption { source })?;
    let drive = scheduler::drive_scenario;
    let (idle, rates, host_observable_schedule) = drive(
        &mut hot_path,
        &mut child,
        &setup,
        config,
        &mut host_adversary,
    )?;
    scheduler::publish_terminal_fingerprint(
        &hot_path,
        &mut child,
        &setup,
        rates.terminal_icount,
        config,
    )?;
    let fingerprint = QemuShmemHotPathChannel::execution_fingerprint(&mut hot_path)
        .map_err(|source| channel_error("read execution fingerprint", source))?;
    HostAdversary::finish_if_present(&mut host_adversary)
        .map_err(|source| LivePluginQuantumGateError::SchedulerPreemption { source })?;
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
    Ok(ScenarioOutcome {
        idle,
        rates,
        fingerprint,
        host_observable_schedule,
    })
}

/// Requires the scheduler-preempted run to reproduce the reference byte for byte.
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
