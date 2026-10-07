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

            let current_icount = self.callback_current_icount_without_pause()?;
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
            // to query `max_advance_icount`. Advance only to the currently authorized
            // scheduler boundary when the device completion lies in a later quantum;
            // the host wake after publishing that later ceiling re-fires this hook.
            let target_icount = plan.desired_wake_icount().min(ceiling_icount);
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
            self.arm_and_enqueue_idle_advance_observed(
                self.last_raw_icount.load(Ordering::Acquire),
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
}
