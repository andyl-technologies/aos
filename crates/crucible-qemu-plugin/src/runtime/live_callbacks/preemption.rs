//! Logical preemption projection for the live sim-loop ceiling callback.
//!
//! The callback converts scheduler-owned logical ticks to raw retired
//! instructions before injecting and acknowledging a pending mailbox command.

use std::sync::atomic::{AtomicBool, Ordering};

use crucible_shmem::SchedulerPreemptionKind;

use super::{LiveVcpuTimeCallbackError, LiveVcpuTimeCallbackState};
use crate::{
    IdleHotLoopError, PluginPreemptionDecision, PluginShmemOrdering, PreemptionWindow,
    SchedulerCeiling,
};

struct PreemptionEnqueueGuard<'a>(&'a AtomicBool);

impl Drop for PreemptionEnqueueGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

impl LiveVcpuTimeCallbackState {
    /// Returns the scheduler ceiling expressed in raw retired-instruction units.
    ///
    /// QEMU's sim-loop budget clamp compares this value against
    /// `qemu_plugin_icount_raw()` (raw retired instructions), whereas the
    /// scheduler ceiling published in shared memory is a *logical* icount that
    /// includes the accumulated idle-jump offset (`logical = raw + offset`). The
    /// clamp only stops the guest at the authorized horizon when both operands
    /// share a space, so the logical ceiling is translated back to raw by
    /// subtracting the current offset. On the busy path the offset is zero and
    /// this is the ceiling unchanged; after an idle jump advanced virtual time
    /// without retiring instructions, the offset is positive and this stops the
    /// guest from retiring instructions past its logical authorization.
    /// Returns how far QEMU's sim loop may advance the guest, in raw icount.
    ///
    /// This is the callback the live TCG sim loop actually queries to bound a
    /// running guest (registered via `register_sim_shmem_dispatch`); it is the
    /// live advance seam, not [`crate::compute_idle_wake_plan`], which the sim loop
    /// never calls. The budget is the scheduler ceiling minus this node's
    /// logical icount offset.
    ///
    /// When a device-I/O request is in flight, the budget freezes at the current
    /// coordinate until the host publishes the deterministic completion
    /// deadline, then advances at most to that deadline. This closes the
    /// request-observation race: host wall time may delay publication, but the
    /// guest cannot retire instructions between the request callback and the
    /// publication that pins its completion. A past deadline likewise
    /// saturates the budget to zero. A queued time jump similarly freezes the
    /// budget at its raw request coordinate until completion commits the new
    /// logical offset. The distinct case of a guest *halted* on device I/O
    /// (where the sim loop stops querying this callback altogether) is closed
    /// separately by the device-wait callback of the SCHED-8 delivery patch.
    pub(super) fn max_advance_icount(&self) -> Result<u64, LiveVcpuTimeCallbackError> {
        let raw_icount = (self.icount_raw)();
        if self.publish_pause_for_boundary(raw_icount, true, false, None, "max-advance")? {
            return Ok(raw_icount);
        }
        if let Some(raw_icount_at_request) = self.pending_idle_advance_clamp(raw_icount)? {
            return Ok(raw_icount_at_request);
        }
        let _fault_pump_drained = self.pump_fault_commands(raw_icount)?;
        let (ceiling, _) =
            PluginShmemOrdering::load_scheduler_advance(self.slot.get()).map_err(|source| {
                LiveVcpuTimeCallbackError::IdleHotLoop {
                    source: IdleHotLoopError::AdvanceStopCondition { source },
                }
            })?;
        let current_icount = self.logical_icount_for_raw(raw_icount)?;
        let offset = self.logical_icount_offset.load(Ordering::Acquire);
        if current_icount > ceiling {
            return Err(LiveVcpuTimeCallbackError::IcountBeyondCeiling {
                current_icount,
                ceiling_icount: ceiling,
            });
        }
        let effective_ceiling = if PluginShmemOrdering::device_io_active(self.slot.get()) {
            match PluginShmemOrdering::device_completion_deadline_tick(self.slot.get()) {
                0 => ceiling.min(self.last_icount.load(Ordering::Acquire)),
                deadline => ceiling.min(deadline),
            }
        } else {
            ceiling
        };
        let raw_ceiling =
            effective_ceiling.saturating_sub(offset) / crucible_shmem::TICKS_PER_INSTRUCTION;
        if self
            .preemption_enqueue_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            // QEMU validates a newly enqueued command by querying this callback.
            // That nested query must observe the scheduler ceiling without
            // attempting to enqueue the same mailbox command recursively.
            return Ok(raw_ceiling);
        }
        let _guard = PreemptionEnqueueGuard(&self.preemption_enqueue_active);
        let Some(published) = self
            .slot
            .get()
            .pending_preemption_command()
            .map_err(|source| LiveVcpuTimeCallbackError::PreemptionMailbox { source })?
        else {
            return Ok(raw_ceiling);
        };
        let command = published.command;
        let raw_at = logical_preemption_icount_to_raw("at", command.at_tick, offset)?;
        let raw_deadline = logical_preemption_deadline_to_raw(command.deadline_tick, offset)?;
        let raw_command_ceiling = logical_preemption_ceiling_to_raw(command.ceiling_tick, offset)?;
        if raw_command_ceiling > raw_ceiling {
            // The mailbox is published before the RUN that owns it. Keep the
            // command pending until that RUN's ceiling is visible, then inject
            // it before QEMU may retire past the commanded coordinate.
            return Ok(raw_ceiling);
        }
        let window =
            PreemptionWindow::new(raw_deadline, SchedulerCeiling::new(raw_command_ceiling))
                .map_err(|source| LiveVcpuTimeCallbackError::Preemption { source })?;
        let decision = match command.kind {
            SchedulerPreemptionKind::VcpuSwitch { from_vcpu, to_vcpu } => {
                PluginPreemptionDecision::vcpu_switch(raw_at, from_vcpu, to_vcpu)
            }
            SchedulerPreemptionKind::InterruptAt { target_vcpu, irq } => {
                PluginPreemptionDecision::interrupt_at(raw_at, target_vcpu, irq)
            }
        };
        self.preemption_injector
            .enqueue_decision(decision, window, self.vcpu_count)
            .map_err(|source| LiveVcpuTimeCallbackError::Preemption { source })?;
        self.slot
            .get()
            .acknowledge_preemption_command(published.sequence)
            .map_err(|source| LiveVcpuTimeCallbackError::PreemptionMailbox { source })?;
        Ok(raw_ceiling.min(raw_at))
    }
}

fn logical_preemption_icount_to_raw(
    field: &'static str,
    logical_icount: u64,
    logical_icount_offset: u64,
) -> Result<u64, LiveVcpuTimeCallbackError> {
    let raw_tick = preemption_tick_since_raw_origin(field, logical_icount, logical_icount_offset)?;
    if !raw_tick.is_multiple_of(crucible_shmem::TICKS_PER_INSTRUCTION) {
        return Err(
            LiveVcpuTimeCallbackError::PreemptionIcountBetweenRetirements {
                field,
                logical_icount,
            },
        );
    }
    Ok(raw_tick / crucible_shmem::TICKS_PER_INSTRUCTION)
}

pub(super) fn logical_preemption_deadline_to_raw(
    logical_icount: u64,
    logical_icount_offset: u64,
) -> Result<u64, LiveVcpuTimeCallbackError> {
    let raw_tick =
        preemption_tick_since_raw_origin("deadline", logical_icount, logical_icount_offset)?;
    // Rounding the lower bound up cannot authorize an earlier preemption.
    Ok(raw_tick.div_ceil(crucible_shmem::TICKS_PER_INSTRUCTION))
}

pub(super) fn logical_preemption_ceiling_to_raw(
    logical_icount: u64,
    logical_icount_offset: u64,
) -> Result<u64, LiveVcpuTimeCallbackError> {
    let raw_tick =
        preemption_tick_since_raw_origin("ceiling", logical_icount, logical_icount_offset)?;
    // Rounding the upper bound down cannot pass the scheduler's RUN ceiling.
    Ok(raw_tick / crucible_shmem::TICKS_PER_INSTRUCTION)
}

fn preemption_tick_since_raw_origin(
    field: &'static str,
    logical_icount: u64,
    logical_icount_offset: u64,
) -> Result<u64, LiveVcpuTimeCallbackError> {
    logical_icount.checked_sub(logical_icount_offset).ok_or(
        LiveVcpuTimeCallbackError::PreemptionIcountBeforeRawOrigin {
            field,
            logical_icount,
            logical_icount_offset,
        },
    )
}
