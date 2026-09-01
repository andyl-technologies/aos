//! Loaded-QEMU proof for live scheduler-commanded preemptions.

use std::fs;

use crucible::{ExecutionFingerprint, SimDoubleHostScheduleEvent};
use crucible_protocol::deterministic_ipi_delivery_icount;
use crucible_shmem::{
    FingerprintSample, RegionAllocation, RegionConfig, SLOT_NET_ROUTER, SchedulerPreemptionCommand,
    SchedulerPreemptionKind, mmap_setup_region,
};

use crate::{
    LaunchProfileCandidate, QemuLaunchPluginConfig, QemuLaunchPluginSwitch,
    QemuMappedQuantumShmemHotPath, QemuPluginIpcControlChannel, QemuQuantumShmemConfig,
    QemuShmemHotPathChannel, complete_qemu_host_plugin_setup,
    spawn_qemu_child_with_fds_in_directory,
};

use super::scheduler::QuantumStop;
use super::{
    GATE_MEMORY_MIB, GATE_NODE, GATE_QUEUE_CAPACITY, GATE_ROUTER, GATE_SLOT, GateSendAuthorizer,
    HostAdversary, LivePluginQuantumGateConfig, LivePluginQuantumGateError,
    assert_sim_double_schedule_matches, channel_error, node_id, path_text, scheduler,
    vm_launch_config,
};

/// Successful evidence from the live patched-QEMU preemption gate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LivePluginPreemptionReport {
    /// Exact node icount at which the vCPU switch was commanded.
    pub switch_icount: u64,
    /// vCPU that was current when the switch command was authored.
    pub switch_from_vcpu: u32,
    /// vCPU selected by the commanded switch.
    pub switch_to_vcpu: u32,
    /// Mailbox sequence acknowledged after QEMU accepted the switch.
    pub switch_consumed_sequence: u32,
    /// Exact node icount at which the interrupt was commanded.
    pub interrupt_icount: u64,
    /// Node icount at which the sender emitted the modeled IPI.
    pub ipi_send_icount: u64,
    /// Fixed node-icount latency applied before RR-boundary rounding.
    pub ipi_fixed_latency_icount: u64,
    /// Earliest IPI delivery before RR-boundary rounding.
    pub ipi_earliest_delivery_icount: u64,
    /// Fixed round-robin quantum used to round IPI delivery.
    pub ipi_rr_switch_quantum: u64,
    /// vCPU that emitted the modeled IPI.
    pub interrupt_sender_vcpu: u32,
    /// vCPU targeted by the commanded interrupt.
    pub interrupt_target_vcpu: u32,
    /// Interrupt vector delivered through patched QEMU.
    pub interrupt_vector: u32,
    /// Mailbox sequence acknowledged after QEMU accepted the interrupt.
    pub interrupt_consumed_sequence: u32,
    /// Terminal exact ceiling reached after both commands became due.
    pub terminal_icount: u64,
    /// Final execution fingerprint shared by both runs.
    pub execution_fingerprint: ExecutionFingerprint,
    /// Both commands and the final fingerprint reproduced under bounded scheduler preemption.
    pub deterministic_under_scheduler_preemption: bool,
    /// The second run actually applied bounded scheduler preemption.
    pub scheduler_preemption_applied: bool,
    /// The three live RUN boundaries replayed byte-for-byte through `SimDouble`.
    pub sim_double_schedule_matches: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PreemptionScenarioOutcome {
    switch_icount: u64,
    switch_from_vcpu: u32,
    switch_to_vcpu: u32,
    switch_consumed_sequence: u32,
    interrupt_icount: u64,
    ipi_send_icount: u64,
    ipi_fixed_latency_icount: u64,
    ipi_earliest_delivery_icount: u64,
    ipi_rr_switch_quantum: u64,
    interrupt_sender_vcpu: u32,
    interrupt_target_vcpu: u32,
    interrupt_vector: u32,
    interrupt_consumed_sequence: u32,
    terminal_icount: u64,
    execution_fingerprint: ExecutionFingerprint,
    final_sample: FingerprintSample,
    host_observable_schedule: Vec<SimDoubleHostScheduleEvent>,
}

/// Runs live vCPU-switch and interrupt commands twice through patched QEMU.
///
/// Each command is published before its owning RUN, acknowledged only after
/// QEMU accepts it, and then allowed to become due. Patched QEMU aborts if
/// either command misses its exact icount or names the wrong current vCPU, so
/// survival to the following exact ceiling is the application proof.
///
/// # Errors
///
/// Returns [`LivePluginQuantumGateError`] when launch or setup fails, a RUN does
/// not reach its exact ceiling, either command is rejected or unacknowledged,
/// fingerprint sampling fails, the scheduler-preemption run diverges, or teardown fails.
pub fn run_live_plugin_preemption_gate(
    config: &LivePluginQuantumGateConfig,
) -> Result<LivePluginPreemptionReport, LivePluginQuantumGateError> {
    let ceiling_stride = config.schedule.ceiling_step_icount;
    if ceiling_stride < 2 {
        return Err(probe_error(
            "preemption gate requires a ceiling step of at least two icount",
        ));
    }
    let reference = run_preemption_scenario(config, "preemption-reference", false)?;
    let scheduler_preemption_applied = config.second_run_scheduler_preemption;
    let second = run_preemption_scenario(
        config,
        if scheduler_preemption_applied {
            "preemption-scheduler-preemption"
        } else {
            "preemption-repeat"
        },
        scheduler_preemption_applied,
    )?;
    if reference != second {
        return Err(LivePluginQuantumGateError::SecondRunDiverged {
            reason: format!("live preemption evidence differed: {reference:?} vs {second:?}"),
        });
    }
    assert_sim_double_schedule_matches(&reference.host_observable_schedule)?;

    Ok(LivePluginPreemptionReport {
        switch_icount: reference.switch_icount,
        switch_from_vcpu: reference.switch_from_vcpu,
        switch_to_vcpu: reference.switch_to_vcpu,
        switch_consumed_sequence: reference.switch_consumed_sequence,
        interrupt_icount: reference.interrupt_icount,
        ipi_send_icount: reference.ipi_send_icount,
        ipi_fixed_latency_icount: reference.ipi_fixed_latency_icount,
        ipi_earliest_delivery_icount: reference.ipi_earliest_delivery_icount,
        ipi_rr_switch_quantum: reference.ipi_rr_switch_quantum,
        interrupt_sender_vcpu: reference.interrupt_sender_vcpu,
        interrupt_target_vcpu: reference.interrupt_target_vcpu,
        interrupt_vector: reference.interrupt_vector,
        interrupt_consumed_sequence: reference.interrupt_consumed_sequence,
        terminal_icount: reference.terminal_icount,
        execution_fingerprint: reference.execution_fingerprint,
        deterministic_under_scheduler_preemption: true,
        scheduler_preemption_applied,
        sim_double_schedule_matches: true,
    })
}

fn run_preemption_scenario(
    config: &LivePluginQuantumGateConfig,
    run_name: &str,
    apply_scheduler_preemption: bool,
) -> Result<PreemptionScenarioOutcome, LivePluginQuantumGateError> {
    let run_directory = config.run_directory.join(run_name);
    fs::create_dir_all(&run_directory).map_err(|source| {
        LivePluginQuantumGateError::PrepareRunDirectory {
            path: run_directory.clone(),
            source,
        }
    })?;
    let mut candidate = LaunchProfileCandidate::default()
        .with_memory_mib(GATE_MEMORY_MIB)
        .with_smp_vcpus(2)
        .with_rr_switch_quantum(config.rr_switch_quantum());
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

    // Setup is outside the compared schedule. Start the finite contention
    // budget only once the guest is ready for its commanded RUN boundaries.
    let mut host_adversary =
        HostAdversary::start_if(apply_scheduler_preemption, child.process_id())
            .map_err(|source| LivePluginQuantumGateError::SchedulerPreemption { source })?;

    let ceiling_stride = config.schedule.ceiling_step_icount;
    let mut host_observable_schedule = Vec::with_capacity(3);
    let (first_stop, first_event) = scheduler::run_quantum(
        &mut hot_path,
        &mut child,
        &setup,
        ceiling_stride,
        config,
        &mut host_adversary,
    )?;
    require_reached_ceiling(first_stop, ceiling_stride)?;
    host_observable_schedule.push(first_event);
    let first_sample = required_sample(&hot_path, &mut child, config, ceiling_stride)?;
    let switch_from_vcpu = first_sample.rr_current_vcpu;
    let switch_to_vcpu = 1_u32.saturating_sub(switch_from_vcpu);
    let switch_icount = ceiling_stride.saturating_add(1);
    let switch_ceiling = ceiling_stride.saturating_mul(2);
    let switch_sequence = hot_path
        .publish_preemption_command(SchedulerPreemptionCommand {
            at_icount: switch_icount,
            deadline_icount: switch_icount,
            ceiling_icount: switch_ceiling,
            kind: SchedulerPreemptionKind::VcpuSwitch {
                from_vcpu: switch_from_vcpu,
                to_vcpu: switch_to_vcpu,
            },
        })
        .map_err(|source| LivePluginQuantumGateError::MappedHotPath { source })?;
    let (switch_stop, switch_event) = scheduler::run_quantum(
        &mut hot_path,
        &mut child,
        &setup,
        switch_ceiling,
        config,
        &mut host_adversary,
    )?;
    require_reached_ceiling(switch_stop, switch_ceiling)?;
    require_consumed(&hot_path, switch_sequence, "vCPU switch")?;
    host_observable_schedule.push(switch_event);

    let switch_sample = required_sample(&hot_path, &mut child, config, switch_ceiling)?;
    let interrupt_sender_vcpu = switch_sample.rr_current_vcpu;
    let interrupt_target_vcpu = 1_u32.saturating_sub(interrupt_sender_vcpu);
    let interrupt_vector = 0xf1;
    let ipi_send_icount = switch_ceiling;
    let ipi_fixed_latency_icount = 17;
    let ipi_earliest_delivery_icount = ipi_send_icount
        .checked_add(ipi_fixed_latency_icount)
        .ok_or_else(|| probe_error("live IPI earliest-delivery icount overflowed"))?;
    let ipi_rr_switch_quantum = switch_sample.rr_switch_quantum;
    let interrupt_icount = deterministic_ipi_delivery_icount(
        ipi_send_icount,
        ipi_fixed_latency_icount,
        ipi_rr_switch_quantum,
    )
    .ok_or_else(|| probe_error("live IPI RR-boundary delivery icount overflowed"))?;
    let interrupt_ceiling = ceiling_stride.saturating_mul(3);
    if interrupt_icount > interrupt_ceiling {
        return Err(probe_error(format!(
            "live IPI delivery {interrupt_icount} exceeds terminal ceiling {interrupt_ceiling}"
        )));
    }
    let interrupt_sequence = hot_path
        .publish_preemption_command(SchedulerPreemptionCommand {
            at_icount: interrupt_icount,
            deadline_icount: interrupt_icount,
            ceiling_icount: interrupt_ceiling,
            kind: SchedulerPreemptionKind::InterruptAt {
                target_vcpu: interrupt_target_vcpu,
                irq: interrupt_vector,
            },
        })
        .map_err(|source| LivePluginQuantumGateError::MappedHotPath { source })?;
    let (interrupt_stop, interrupt_event) = scheduler::run_quantum(
        &mut hot_path,
        &mut child,
        &setup,
        interrupt_ceiling,
        config,
        &mut host_adversary,
    )?;
    require_reached_ceiling(interrupt_stop, interrupt_ceiling)?;
    require_consumed(&hot_path, interrupt_sequence, "interrupt")?;
    host_observable_schedule.push(interrupt_event);
    let final_sample = required_sample(&hot_path, &mut child, config, interrupt_ceiling)?;
    let execution_fingerprint = QemuShmemHotPathChannel::execution_fingerprint(&mut hot_path)
        .map_err(|source| channel_error("read preemption execution fingerprint", source))?;

    HostAdversary::finish_if_present(&mut host_adversary)
        .map_err(|source| LivePluginQuantumGateError::SchedulerPreemption { source })?;
    setup
        .assert_run_control_silent()
        .map_err(|source| channel_error("prove preemption run control silence", source))?;
    QemuPluginIpcControlChannel::send_quit(&mut setup)
        .map_err(|source| channel_error("send preemption plugin Quit", source))?;
    scheduler::wait_for_plugin_teardown(&hot_path, config)?;
    let exit_status = scheduler::wait_for_natural_child_exit(&mut child, config)?;
    if !exit_status.success() {
        return Err(LivePluginQuantumGateError::ChildExitUnclean {
            status: exit_status.to_string(),
        });
    }
    drop(setup);
    drop(child);

    Ok(PreemptionScenarioOutcome {
        switch_icount,
        switch_from_vcpu,
        switch_to_vcpu,
        switch_consumed_sequence: switch_sequence,
        interrupt_icount,
        ipi_send_icount,
        ipi_fixed_latency_icount,
        ipi_earliest_delivery_icount,
        ipi_rr_switch_quantum,
        interrupt_sender_vcpu,
        interrupt_target_vcpu,
        interrupt_vector,
        interrupt_consumed_sequence: interrupt_sequence,
        terminal_icount: interrupt_ceiling,
        execution_fingerprint,
        final_sample,
        host_observable_schedule,
    })
}

fn required_sample(
    hot_path: &QemuMappedQuantumShmemHotPath,
    child: &mut crate::QemuNodeChild,
    config: &LivePluginQuantumGateConfig,
    expected_icount: u64,
) -> Result<FingerprintSample, LivePluginQuantumGateError> {
    let sample = scheduler::wait_for_fingerprint_sample(hot_path, child, expected_icount, config)?;
    if sample.vcpu_count != 2 || sample.component_failures != 0 || sample.rr_current_vcpu >= 2 {
        return Err(probe_error(format!(
            "invalid preemption boundary sample at {expected_icount}: {sample:?}"
        )));
    }
    Ok(sample)
}

fn require_reached_ceiling(
    stop: QuantumStop,
    expected: u64,
) -> Result<(), LivePluginQuantumGateError> {
    match stop {
        QuantumStop::ReachedCeiling { icount } if icount == expected => Ok(()),
        other => Err(probe_error(format!(
            "preemption RUN expected exact ceiling {expected}, got {other:?}"
        ))),
    }
}

fn require_consumed(
    hot_path: &QemuMappedQuantumShmemHotPath,
    expected: u32,
    kind: &str,
) -> Result<(), LivePluginQuantumGateError> {
    let consumed = hot_path
        .consumed_preemption_sequence()
        .map_err(|source| LivePluginQuantumGateError::MappedHotPath { source })?;
    if consumed != expected {
        return Err(probe_error(format!(
            "{kind} preemption sequence {expected} was not acknowledged; consumed {consumed}"
        )));
    }
    Ok(())
}

fn probe_error(reason: impl Into<String>) -> LivePluginQuantumGateError {
    LivePluginQuantumGateError::SecondRunDiverged {
        reason: reason.into(),
    }
}
