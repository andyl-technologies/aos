//! Real-device block recovery and hot-fork preparation proof.

use std::error::Error;
use std::path::Path;
use std::time::Duration;

use crucible::{AdvanceOutcome, ObservableEventPayload, SimulationBackend, VirtualTime};
use crucible_device::block::{
    BaseImage, BlockDurabilityConfig, BlockFaultResult, BlockTransitionPending,
    BlockTransitionResolved, BlockTransitionState, BlockTransitionTopology,
    BlockTransitionUnadmitted, BlockTransitionUndelivered, BlockTransportRequestIds,
    ResolvedBlockControllerTransition,
};
use crucible_qemu::{
    LinuxQemuAttemptHostFactory, QemuLiveNodeIdentity, QemuLiveNodeStepGateConfig,
    QemuProductionFreshLaunchAdmission, launch_qemu_production_fresh_node,
};

use super::{
    DISK_BYTES, FLIGHT_ICOUNT_SHIFT, MEMORY_BYTES, RR_SWITCH_QUANTUM,
    prepare_live_hot_fork_template,
};

const BLOCK_BYTES: u64 = 4 * 1024 * 1024;
const COMPLETION_CEILING: u64 = 100_000_000_000;
// The guest starts this sleep immediately after publishing the readiness
// marker. Serial observation can trail publication by one readiness slice, so
// the recovery interval must leave a strict margin before the guest writes.
const GUEST_RECOVERY_WAIT_NANOS: u64 = 10_000_000_000;
const RECOVERY_NANOS: u64 = 5_000_000_000;
const READINESS_SLICE_NANOS: u64 = 4_000_000_000;
// Paused publications can consume no logical time, so bound marker search
// independently of the virtual-time ceiling.
const READINESS_ADVANCE_LIMIT: usize = 100_000;
const MARKER_ADVANCE_LIMIT: usize = 10_000;
const MARKER_CONSOLE_BYTE_LIMIT: usize = 4 * 1024 * 1024;
const COMPLETION_STEP_NANOS: u64 = 10_000_000;
const CONSECUTIVE_STALLED_ADVANCE_LIMIT: usize = 4;
pub(super) const BLOCK_RECOVERY_READY_MARKER: &[u8] = b"CRUCIBLE_BLOCK_RECOVERY_READY";
pub(super) const BLOCK_COMPLETE_MARKER: &[u8] = b"CRUCIBLE_BLOCK_WRITE_COMPLETE";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct BlockRecoveryHotForkEvidence {
    pub(super) template_generation: u64,
    pub(super) recovery_started_nanos: u64,
    pub(super) recovery_nanos: u64,
    pub(super) pause_logical_icount: u64,
    pub(super) pause_raw_icount: u64,
}

// crucible-lint: allow rust-allow -- the production subflight receives each authenticated executable and guest artifact explicitly.
#[allow(clippy::too_many_arguments)]
pub(super) fn run(
    factory: &mut LinuxQemuAttemptHostFactory,
    qemu: &Path,
    plugin: &Path,
    kernel: &Path,
    initrd: &Path,
    firmware: &Path,
    run_root: &Path,
    diagnostic_liveness_trace: bool,
) -> Result<BlockRecoveryHotForkEvidence, Box<dyn Error>> {
    recovery_timing_margin_nanos(
        GUEST_RECOVERY_WAIT_NANOS,
        READINESS_SLICE_NANOS,
        RECOVERY_NANOS,
    )
    .ok_or("block recovery timing does not precede the guest write")?;

    let config = QemuLiveNodeStepGateConfig::new(qemu, plugin, kernel, firmware, run_root)
        .with_initrd(initrd)
        .with_vm_shape(128, 1, FLIGHT_ICOUNT_SHIFT)
        .with_rr_switch_quantum(RR_SWITCH_QUANTUM)
        .with_fault_free_shmem_block(
            BaseImage::new(vec![0; usize::try_from(BLOCK_BYTES)?]),
            BlockDurabilityConfig::write_through(BLOCK_BYTES),
        )
        .with_console_capture()
        .with_completion_timeout(Duration::from_secs(60));
    let config = if diagnostic_liveness_trace {
        config.with_runtime_liveness_trace()
    } else {
        config
    };
    let mut owner = factory.begin(1, MEMORY_BYTES, DISK_BYTES)?;
    let mut directory = owner.prepare_generation_run_directory(config.resource_requirements())?;
    directory.prepare_fresh_artifacts_guarded(qemu, None, owner.process_contract()?)?;
    let launch = config.with_run_directory(directory.path());
    let mut node = launch_qemu_production_fresh_node(
        &launch,
        QemuProductionFreshLaunchAdmission::admit(
            &launch,
            &directory,
            owner.process_contract()?,
            QemuLiveNodeIdentity::new(
                "block-recovery-hot-fork-node",
                "block-recovery-hot-fork-router",
                "block-recovery-hot-fork-crash",
            ),
        )?,
    )?;

    // Apply recovery only after the guest has opened the device. This makes
    // the recovery interval causal: the kernel's earlier probe traffic cannot
    // cross a transition that the host has not started yet.
    let recovery_started_nanos = await_recovery_readiness(&mut node)?;
    let block = node
        .shared_block_device()
        .ok_or("block recovery subflight omitted its live device")?;
    block.apply_storage_boundary_mutations(
        &[],
        &[(recovery_transition(), recovery_started_nanos)],
    )?;
    let recovery_deadline_nanos = recovery_started_nanos
        .checked_add(RECOVERY_NANOS)
        .ok_or("block recovery deadline overflowed virtual time")?;

    let primary = exercise_recovery_and_prepare_hot_fork(&mut node, recovery_deadline_nanos);
    let shutdown = node.shutdown_child().map_err(|error| error.to_string());
    drop(node);
    let trace = match &shutdown {
        Ok(report) if diagnostic_liveness_trace && report.reaped && !report.leaked => Some(
            directory
                .retain_runtime_liveness_trace_tail_after_reap()
                .map_err(|error| error.to_string()),
        ),
        _ if diagnostic_liveness_trace => Some(Err(String::from(
            "trace unavailable because clean QEMU reap was not proven",
        ))),
        _ => None,
    };
    drop(directory);
    let finish = owner.finish().map_err(|error| error.to_string());

    let primary = primary.map_err(|error| {
        let trace = trace.map_or_else(String::new, |trace| match trace {
            Ok(trace) => format!(
                "; retained_scheduler_liveness_trace_tail_begin\n{trace}\n\
                 retained_scheduler_liveness_trace_tail_end"
            ),
            Err(error) => format!("; retained_scheduler_liveness_trace_tail_error={error}"),
        });
        format!(
            "{error}{trace}; \
             diagnostic_shutdown={shutdown:?}; diagnostic_finish={finish:?}"
        )
    })?;
    let shutdown = shutdown.map_err(|error| format!("block recovery shutdown: {error}"))?;
    if !shutdown.reaped || shutdown.leaked {
        return Err(format!("block recovery QEMU did not reap cleanly: {shutdown:?}").into());
    }
    finish.map_err(|error| format!("block recovery attempt finish: {error}"))?;

    Ok(BlockRecoveryHotForkEvidence {
        template_generation: primary.template_generation,
        recovery_started_nanos,
        recovery_nanos: RECOVERY_NANOS,
        pause_logical_icount: primary.pause_logical_icount,
        pause_raw_icount: primary.pause_raw_icount,
    })
}

fn await_recovery_readiness(node: &mut crucible_qemu::QemuNode) -> Result<u64, Box<dyn Error>> {
    let readiness_slice_icount = virtual_nanos_to_icount_ceiling(READINESS_SLICE_NANOS)?;
    let mut console = Vec::new();
    let mut last_reached = node.now().ticks;
    let mut next_target = last_reached
        .checked_add(readiness_slice_icount)
        .ok_or("block recovery readiness target overflowed virtual time")?;

    for _ in 0..READINESS_ADVANCE_LIMIT {
        if next_target >= COMPLETION_CEILING {
            return Err("block recovery readiness reached its liveness ceiling".into());
        }
        let observation = SimulationBackend::step_to(node, VirtualTime { ticks: next_target })?;
        if observation.reached.ticks < last_reached || observation.reached.ticks > next_target {
            return Err(format!(
                "block recovery readiness returned an invalid boundary: {observation:?}"
            )
            .into());
        }

        let events = SimulationBackend::drain_observable_events(node)?;
        append_console_bytes(&mut console, &events)?;
        let ready_markers = console_marker_count(&console, BLOCK_RECOVERY_READY_MARKER);
        let complete_markers = console_marker_count(&console, BLOCK_COMPLETE_MARKER);
        if ready_markers > 1 {
            return Err("block recovery readiness marker was published more than once".into());
        }
        if complete_markers != 0 {
            return Err("block write completed before recovery began".into());
        }
        if ready_markers == 1 {
            let AdvanceOutcome::Paused { at } = observation.outcome else {
                return Err(format!(
                    "block recovery readiness marker was not observed at a paused boundary: {observation:?}"
                )
                .into());
            };
            if at.retired != observation.reached.ticks {
                return Err(format!(
                    "block recovery readiness pause was incoherent: {observation:?}"
                )
                .into());
            }
            let calibration = node.logical_time_calibration()?;
            if calibration.logical_icount != at.retired {
                return Err(format!(
                    "block recovery readiness calibration was incoherent: {calibration:?}"
                )
                .into());
            }

            return at
                .retired
                .checked_shl(u32::from(FLIGHT_ICOUNT_SHIFT))
                .ok_or_else(|| "block recovery readiness overflowed virtual time".into());
        }

        match observation.outcome {
            AdvanceOutcome::ReachedHorizon => {
                if observation.reached.ticks != next_target {
                    return Err(format!(
                        "block recovery readiness missed its exact ceiling: {observation:?}"
                    )
                    .into());
                }
            }
            AdvanceOutcome::Paused { at } => {
                if at.retired != observation.reached.ticks {
                    return Err(format!(
                        "block recovery readiness pause was incoherent: {observation:?}"
                    )
                    .into());
                }
            }
        }
        last_reached = observation.reached.ticks;
        next_target = observation
            .reached
            .ticks
            .checked_add(readiness_slice_icount)
            .ok_or("block recovery readiness target overflowed virtual time")?;
    }

    Err("block recovery readiness exceeded its bounded advances".into())
}

fn recovery_timing_margin_nanos(
    guest_wait_nanos: u64,
    observation_lag_nanos: u64,
    recovery_nanos: u64,
) -> Option<u64> {
    let required_nanos = observation_lag_nanos.checked_add(recovery_nanos)?;
    guest_wait_nanos
        .checked_sub(required_nanos)
        .filter(|margin| *margin != 0)
}

#[derive(Clone, Copy)]
struct PrimaryEvidence {
    template_generation: u64,
    pause_logical_icount: u64,
    pause_raw_icount: u64,
}

fn exercise_recovery_and_prepare_hot_fork(
    node: &mut crucible_qemu::QemuNode,
    recovery_deadline_nanos: u64,
) -> Result<PrimaryEvidence, Box<dyn Error>> {
    let mut console = Vec::new();
    let mut completed_at = None;
    let mut target_nanos = recovery_deadline_nanos;
    let mut last_reached = node.now().ticks;
    let mut consecutive_stalled_advances = 0;
    for _ in 0..MARKER_ADVANCE_LIMIT {
        target_nanos = target_nanos
            .checked_add(COMPLETION_STEP_NANOS)
            .ok_or("block recovery completion target overflowed virtual time")?;
        let target_icount = virtual_nanos_to_icount_ceiling(target_nanos)?;
        if target_icount >= COMPLETION_CEILING {
            return Err("block recovery completion reached its liveness ceiling".into());
        }

        let observation = SimulationBackend::step_to(
            node,
            VirtualTime {
                ticks: target_icount,
            },
        )?;
        if observation.reached.ticks < last_reached || observation.reached.ticks > target_icount {
            return Err(
                format!("block recovery returned an invalid boundary: {observation:?}").into(),
            );
        }
        if observation.reached.ticks == last_reached {
            consecutive_stalled_advances += 1;
            if consecutive_stalled_advances > CONSECUTIVE_STALLED_ADVANCE_LIMIT {
                return Err("block recovery completion made no logical-time progress".into());
            }
        } else {
            last_reached = observation.reached.ticks;
            consecutive_stalled_advances = 0;
        }

        let events = SimulationBackend::drain_observable_events(node)?;
        append_console_bytes(&mut console, &events)?;
        let complete_markers = console_marker_count(&console, BLOCK_COMPLETE_MARKER);
        if complete_markers > 1 {
            return Err("block recovery published more than one write-complete marker".into());
        }
        if complete_markers == 1
            && let AdvanceOutcome::Paused { at } = observation.outcome
        {
            if at.retired != observation.reached.ticks {
                return Err(format!(
                    "block recovery completion pause was incoherent: {observation:?}"
                )
                .into());
            }
            completed_at = Some(at);
            break;
        }
    }
    let at = completed_at.ok_or("block recovery exceeded its bounded completion advances")?;

    let diagnostics = node
        .block_io_diagnostics()
        .ok_or("block recovery diagnostics disappeared")?;
    if diagnostics.write_frames_processed != 1
        || diagnostics.frames_processed == 0
        || diagnostics.frames_delivered != diagnostics.frames_processed
        || diagnostics.last_device_io_active
        || diagnostics.last_current_icount != at.retired
    {
        return Err(format!("block recovery did not settle exactly: {diagnostics:?}").into());
    }
    let visible = node
        .shared_block_device()
        .ok_or("block recovery device disappeared")?
        .inspect_storage_visible(0, 512)?;
    let expected = (0..512)
        .map(|index| (index as u8) ^ 0x37)
        .collect::<Vec<_>>();
    if visible != expected {
        return Err("block recovery did not retain the guest write".into());
    }
    let calibration = node.logical_time_calibration()?;
    if calibration.logical_icount != at.retired {
        return Err(
            format!("block recovery pause calibration was incoherent: {calibration:?}").into(),
        );
    }

    let template_generation = prepare_live_hot_fork_template(node)?;
    Ok(PrimaryEvidence {
        template_generation,
        pause_logical_icount: at.retired,
        pause_raw_icount: calibration.raw_icount,
    })
}

fn virtual_nanos_to_icount_ceiling(nanos: u64) -> Result<u64, Box<dyn Error>> {
    let scale = 1_u64 << u32::from(FLIGHT_ICOUNT_SHIFT);
    nanos
        .checked_add(scale - 1)
        .map(|rounded| rounded / scale)
        .ok_or_else(|| "block recovery virtual-time conversion overflowed".into())
}

pub(super) fn recovery_transition() -> ResolvedBlockControllerTransition {
    ResolvedBlockControllerTransition {
        failure_result: BlockFaultResult::IoError,
        unadmitted: BlockTransitionUnadmitted::WaitForRecovery,
        queued: BlockTransitionPending::RetryNewId,
        executing: BlockTransitionPending::RetryNewId,
        resolved: BlockTransitionResolved::RetryNewId,
        completed_undelivered: BlockTransitionUndelivered::RetryNewId,
        controller_buffer: BlockTransitionState::Preserve,
        volatile_cache: BlockTransitionState::Preserve,
        request_ids: BlockTransportRequestIds::PreserveMonotonic,
        duplicate_history: BlockTransitionState::Lose,
        topology: BlockTransitionTopology::Preserve,
        recovery_nanos: RECOVERY_NANOS,
    }
}

fn append_console_bytes(
    console: &mut Vec<u8>,
    events: &[crucible::ObservableEvent],
) -> Result<(), Box<dyn Error>> {
    for bytes in events.iter().filter_map(|event| match event.payload() {
        ObservableEventPayload::ConsoleOutput { bytes, .. } => Some(bytes.as_slice()),
        _ => None,
    }) {
        if bytes.len() > MARKER_CONSOLE_BYTE_LIMIT.saturating_sub(console.len()) {
            return Err("block recovery marker search exceeded its console-byte limit".into());
        }
        console.extend_from_slice(bytes);
    }

    Ok(())
}

pub(super) fn console_marker_count(console: &[u8], marker: &[u8]) -> usize {
    console
        .windows(marker.len())
        .filter(|window| *window == marker)
        .count()
}

#[cfg(test)]
mod timing_tests {
    use super::*;

    #[test]
    fn recovery_finishes_before_the_guest_write_with_a_strict_margin() {
        assert_eq!(
            recovery_timing_margin_nanos(
                GUEST_RECOVERY_WAIT_NANOS,
                READINESS_SLICE_NANOS,
                RECOVERY_NANOS,
            ),
            Some(1_000_000_000)
        );
    }

    #[test]
    fn recovery_timing_rejects_equal_or_overlapping_windows() {
        assert_eq!(recovery_timing_margin_nanos(10, 4, 6), None);
        assert_eq!(recovery_timing_margin_nanos(10, 4, 7), None);
        assert_eq!(recovery_timing_margin_nanos(u64::MAX, 1, u64::MAX), None);
    }
}
