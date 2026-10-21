//! Existing block waiter decisions with optional original-value observations.

use super::*;

impl LiveVcpuTimeCallbackState {
    pub(super) fn on_block_wait(&self, request_id: u32) -> Result<(), LiveVcpuTimeCallbackError> {
        let mut observation = self
            .device_wait_witness
            .request(request_id, self.control_stage_identity);
        self.device_wait_witness.emit(
            observation,
            "entered",
            (None, None, None),
            (None, None),
            "pending",
        );
        let result = (|| {
            if self.idle_advance_is_pending() {
                self.device_wait_witness.emit(
                    observation,
                    "pending",
                    (None, None, None),
                    (None, None),
                    "deferred",
                );
                return Ok(());
            }
            if !self.all_vcpus_halted_for_device_wait()? {
                self.device_wait_witness.emit(
                    observation,
                    "vcpu-running",
                    (None, None, None),
                    (None, None),
                    "retry",
                );
                // The guest still owns time: it advances by retiring
                // instructions until the device deadline or until every vCPU
                // halts, when the all-halted idle path plans the same wake.
                return Ok(());
            }

            // Keep the one live sample: the jump below may arm only there.
            let raw_icount_at_entry = self.last_raw_icount.load(Ordering::Acquire);
            let sampled_raw_icount = (self.icount_raw)();
            let current_icount = self.publish_callback_icount_without_pause(
                raw_icount_at_entry,
                sampled_raw_icount,
                "device-current",
            )?;
            let device_deadline =
                PluginShmemOrdering::device_completion_deadline_tick(self.slot.get());
            if let Some(observation) = observation.as_mut() {
                observation.current = Some(current_icount);
                observation.deadline = Some(device_deadline);
            }
            if device_deadline == 0 {
                self.device_wait_witness.emit(
                    observation,
                    "no-deadline",
                    (None, None, None),
                    (None, None),
                    "retry",
                );
                // The host publishes the deterministic deadline before signalling
                // the wake fd. QEMU re-fires this callback after that wake, so this
                // wall-time race changes only how long the coroutine stays parked.
                return Ok(());
            }
            let ceiling_icount = self.scheduler_idle_ceiling(device_deadline)?;
            let exact_deadline = self
                .exact_deadline
                .read_next_deadline()
                .map_err(|source| LiveVcpuTimeCallbackError::ExactDeadlineRead { source })?;
            if let Some(observation) = observation.as_mut() {
                observation.exact_deadline = Some(exact_deadline);
            }
            let plan = compute_idle_wake_plan(
                current_icount,
                exact_deadline,
                None,
                SchedulerCeiling::new(ceiling_icount),
                true,
                Some(device_deadline),
            )
            .map_err(|source| LiveVcpuTimeCallbackError::IdleHotLoop { source })?;
            // A block coroutine can park before the vCPU gets another opportunity
            // to query `max_advance_icount`. A wake beyond the current ceiling
            // leaves the clock where it is: the ceiling is a bound, not a target
            // (RFC-0010 SCHED-12). The idle path settles the parked node, and the
            // host wake after publishing a later ceiling re-fires this hook.
            let target_icount = plan.desired_wake_icount();
            if target_icount > ceiling_icount {
                self.device_wait_witness.emit(
                    observation,
                    "beyond-ceiling",
                    (None, Some(target_icount), None),
                    (None, None),
                    "retry",
                );
                return Ok(());
            }
            if target_icount <= current_icount {
                self.device_wait_witness.emit(
                    observation,
                    "already-due",
                    (None, Some(target_icount), None),
                    (None, None),
                    "retry",
                );
                // Virtual time already admits the response. If its ring write is
                // still physically pending, the next host wake retries the poll at
                // this same icount without exposing host timing to the guest.
                return Ok(());
            }
            // Arm only at the live raw coordinate. A sample that was not
            // committed (a preserved output stop, a superseded publication)
            // leaves the published raw count apart from QEMU's, and a jump
            // pinned there would fail the pending-jump invariant on the next
            // read.
            let raw_icount = self.last_raw_icount.load(Ordering::Acquire);
            if raw_icount != sampled_raw_icount {
                self.device_wait_witness.emit(
                    observation,
                    "stale-raw",
                    (Some(raw_icount), Some(target_icount), None),
                    (None, None),
                    "retry",
                );
                return Ok(());
            }
            self.arm_and_enqueue_idle_advance_observed(
                raw_icount,
                target_icount,
                None,
                observation,
            )?;
            Ok(())
        })();
        if result.is_err() {
            self.device_wait_witness.emit(
                observation,
                "error",
                (None, None, None),
                (None, None),
                "error",
            );
        }
        result
    }

    /// Reports whether every vCPU is halted and parked, so an idle jump may move time.
    ///
    /// The block coroutine runs on QEMU's main loop, while the RR thread
    /// executes guest code with the BQL released. An idle advance armed while
    /// a vCPU can run pins a raw coordinate that the vCPU keeps retiring past,
    /// which breaks the queued jump's invariant. A vCPU whose resume deferred
    /// its wake publication keeps its halt bit but is dispatchable, so the
    /// predicate requires parked vCPUs, not just halt bits. Halt tracking
    /// changes only in BQL-held RR callbacks and this callback holds the BQL,
    /// so the answer stays true until QEMU's advance barrier freezes dispatch.
    /// A borrowed tracker counts as not parked: the waiter retries and no time
    /// moves.
    fn all_vcpus_halted_for_device_wait(&self) -> Result<bool, LiveVcpuTimeCallbackError> {
        match self.try_halted_vcpus() {
            Ok(halted_vcpus) => Ok(halted_vcpus.all_halted_and_parked()),
            Err(LiveVcpuTimeCallbackError::HaltStateBorrowed) => Ok(false),
            Err(error) => Err(error),
        }
    }
}
