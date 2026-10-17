//! Logical preemption projection for the live sim-loop ceiling callback.
//!
//! The callback passes scheduler-owned logical ticks directly to QEMU's exact
//! preemption API before acknowledging a pending mailbox command.

use std::sync::atomic::{AtomicBool, Ordering};

use crucible_shmem::SchedulerPreemptionKind;

use super::{LiveVcpuTimeCallbackError, LiveVcpuTimeCallbackState};
use crate::runtime::installed_console::{DispatchAdvance, DispatchResult};
use crate::{
    IdleHotLoopError, PluginPreemptionDecision, PluginShmemOrdering, PreemptionWindow,
    SchedulerCeiling,
};

#[cfg(test)]
thread_local! {
    // Models an intervening consumer between the empty preflight and admission.
    pub(super) static PREFLIGHT_CONSUMER: std::cell::RefCell<Option<Box<dyn FnOnce()>>> =
        const { std::cell::RefCell::new(None) };
}

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
        self.max_advance_budget((self.icount_raw)(), None)
            .map(|(raw, _logical)| raw)
    }

    // The ordinary path retains its original scheduler read and ordering.
    // A native joined read supplies its already coherent ceiling/body; there
    // is no second scalar read that could stamp a different authorization.
    fn max_advance_budget(
        &self,
        raw_icount: u64,
        joined_ceiling: Option<(u64, u64, &[u8; 128])>,
    ) -> Result<(u64, u64), LiveVcpuTimeCallbackError> {
        if self.publish_pause_for_boundary(raw_icount, true, false, None, "max-advance")? {
            return Ok((
                raw_icount,
                joined_ceiling.map_or(0, |(_ceiling, logical, _authorization)| logical),
            ));
        }
        if let Some(raw_icount_at_request) = self.pending_idle_advance_clamp(raw_icount)? {
            return Ok((
                raw_icount_at_request,
                joined_ceiling.map_or(0, |(_ceiling, logical, _authorization)| logical),
            ));
        }
        let _fault_pump_drained = self.pump_fault_commands(raw_icount)?;
        let ceiling = match joined_ceiling {
            Some((ceiling, _logical, _authorization)) => ceiling,
            None => {
                PluginShmemOrdering::load_scheduler_advance(self.slot.get())
                    .map_err(|source| LiveVcpuTimeCallbackError::IdleHotLoop {
                        source: IdleHotLoopError::AdvanceStopCondition { source },
                    })?
                    .0
            }
        };
        let current_icount = self.logical_icount_for_raw(raw_icount)?;
        if let Some((_ceiling, logical_start, _authorization)) = joined_ceiling
            && current_icount != logical_start
        {
            // Fault/restore effects must not silently restamp the retained RR
            // receipt. The original clock observation must still match the
            // native pair captured at this same BQL-owned budget seam.
            return Err(LiveVcpuTimeCallbackError::ConsoleDispatch {
                source: crucible_protocol::native_console::NativeConsoleError::Binding,
            });
        }
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
        if let Some((_ceiling, _logical_start, authorization)) = joined_ceiling
            && (raw_ceiling > raw_icount || effective_ceiling > current_icount)
            && *authorization == [0; 128]
        {
            // A missing native-owned body must refuse before even a pending
            // mailbox command can be admitted or acknowledged. Use the same
            // original read and computed device/idle clamp; no second read or
            // scalar reconstruction may create authorization.
            return Err(LiveVcpuTimeCallbackError::ConsoleDispatch {
                source: crucible_protocol::native_console::NativeConsoleError::Binding,
            });
        }
        if self.preemption_enqueue_active.load(Ordering::Acquire) {
            // A synchronous QEMU admission query must leave the outer enqueue
            // owner and its still-pending mailbox command untouched.
            return Ok((raw_ceiling, effective_ceiling));
        }
        if !self.slot.get().has_pending_preemption_command() {
            // The host publishes a command before its owning RUN grant. An
            // empty acquire observation leaves later publication pending for
            // the next query; it needs no enqueue ownership or atomic RMW.
            return Ok((raw_ceiling, effective_ceiling));
        }
        #[cfg(test)]
        if let Some(consume) = PREFLIGHT_CONSUMER.with_borrow_mut(Option::take) {
            consume();
        }
        if self
            .preemption_enqueue_active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            // QEMU validates a newly enqueued command by querying this callback.
            // That nested query must observe the scheduler ceiling without
            // attempting to enqueue the same mailbox command recursively.
            return Ok((raw_ceiling, effective_ceiling));
        }
        let _guard = PreemptionEnqueueGuard(&self.preemption_enqueue_active);
        // Only the admitted owner may decode and validate command fields. An
        // intervening consumer may acknowledge the advisory sequence hint and
        // let the host replace those fields before our CAS succeeds.
        let Some(published) = self
            .slot
            .get()
            .pending_preemption_command()
            .map_err(|source| LiveVcpuTimeCallbackError::PreemptionMailbox { source })?
        else {
            return Ok((raw_ceiling, effective_ceiling));
        };
        let command = published.command;
        if command.ceiling_tick > effective_ceiling {
            // The mailbox is published before the RUN that owns it. Keep the
            // command pending until that RUN's ceiling is visible, then inject
            // it before QEMU may retire past the commanded coordinate.
            return Ok((raw_ceiling, effective_ceiling));
        }
        let window = PreemptionWindow::new(
            command.deadline_tick,
            SchedulerCeiling::new(command.ceiling_tick),
        )
        .map_err(|source| LiveVcpuTimeCallbackError::Preemption { source })?;
        let decision = match command.kind {
            SchedulerPreemptionKind::VcpuSwitch { from_vcpu, to_vcpu } => {
                PluginPreemptionDecision::vcpu_switch(command.at_tick, from_vcpu, to_vcpu)
            }
            SchedulerPreemptionKind::InterruptAt { target_vcpu, irq } => {
                PluginPreemptionDecision::interrupt_at(command.at_tick, target_vcpu, irq)
            }
        };
        self.preemption_injector
            .enqueue_decision(decision, window, self.vcpu_count)
            .map_err(|source| LiveVcpuTimeCallbackError::Preemption { source })?;
        self.slot
            .get()
            .acknowledge_preemption_command(published.sequence)
            .map_err(|source| LiveVcpuTimeCallbackError::PreemptionMailbox { source })?;
        // A fractional command is enforced by QEMU's exact boundary. The raw
        // budget must retain the scheduler grant, not round the command down.
        Ok((raw_ceiling, effective_ceiling))
    }

    /// Joins the actual native read to the original budget computation once.
    ///
    /// # Errors
    ///
    /// Returns original callback errors, a drifted native clock pair, or a
    /// forward raw or logical budget lacking the native-owned authorization body.
    pub(super) fn console_dispatch_budget(
        &self,
        result: &mut DispatchResult,
        read: impl FnOnce() -> Result<
            DispatchAdvance,
            crucible_protocol::native_console::NativeConsoleError,
        >,
    ) -> Result<(), LiveVcpuTimeCallbackError> {
        let (ceiling, authorization) =
            match read().map_err(|source| LiveVcpuTimeCallbackError::ConsoleDispatch { source })? {
                DispatchAdvance::Unavailable => {
                    result.unavailable();
                    return Ok(());
                }
                DispatchAdvance::Unowned { ceiling } => (ceiling, [0; 128]),
                DispatchAdvance::Owned {
                    ceiling,
                    authorization,
                } => (ceiling, authorization),
            };
        let (raw_ceiling, logical_ceiling) = self.max_advance_budget(
            result.raw_start,
            Some((ceiling, result.logical_start, &authorization)),
        )?;
        if (raw_ceiling > result.raw_start || logical_ceiling > result.logical_start)
            && authorization == [0; 128]
        {
            // A coherent but unowned positive horizon must refuse before the
            // native caller clamps a budget, jumps idle time or enters TCG.
            return Err(LiveVcpuTimeCallbackError::ConsoleDispatch {
                source: crucible_protocol::native_console::NativeConsoleError::Binding,
            });
        }
        result.raw_ceiling = raw_ceiling;
        result.logical_ceiling = logical_ceiling;
        result.authorization = authorization;
        Ok(())
    }
}

/// Supplies one joined original ceiling/AUTH receipt to the GPL native RR seam.
///
/// # Safety
///
/// Native registration retains the original pinned callback userdata and passes
/// an exclusively borrowed, initialized result with its coherent raw/logical
/// start. This private ABI is never stored in shared memory.
pub(in crate::runtime) unsafe extern "C" fn crucible_qemu_plugin_live_console_dispatch_cb(
    userdata: *mut std::ffi::c_void,
    result: *mut DispatchResult,
) -> bool {
    // SAFETY: the registered native caller supplies the initialized exclusive
    // result. A null pointer is refusal and cannot create a runnable receipt.
    let Some(result) = (unsafe { result.as_mut() }) else {
        return false;
    };
    let state = super::callback_userdata_or_abort(userdata);
    let Some(_in_flight) = state.callback_guard() else {
        result.unavailable();
        return true;
    };
    let Some(installed) = state.native_console else {
        return false;
    };
    match state.console_dispatch_budget(result, || installed.dispatch_advance()) {
        Ok(()) => true,
        Err(error) => super::abort_live_callback(error),
    }
}
