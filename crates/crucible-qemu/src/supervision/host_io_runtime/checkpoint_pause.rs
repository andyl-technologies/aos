//! Shared checkpoint handoff with ordinary or borrowed original admission.
//!
//! The pause request, current-coordinate ceiling and control acknowledgement are
//! the existing plugin-to-native stop path. Original callers lend one operation
//! through the device probe and pause; they never create or complete another.

use super::*;

impl QemuLiveHostIoRuntime {
    pub(super) fn probe_checkpoint_device_boundary(
        &mut self,
        deadline: &OperationPollBudget<'_>,
        timeout: Duration,
    ) -> Result<bool, QemuAsyncDriverRuntimeError> {
        check_borrowed_quiescence(deadline)?;
        let request = self.signal_wake(None)?;
        let mut last_observed = None;
        loop {
            if deadline
                .remaining("probe checkpoint device boundary")?
                .is_none()
            {
                break;
            }

            self.drain_fault_events_for_operation(
                self.fault_event_staging_limit,
                deadline,
                timeout,
                "probe checkpoint device boundary",
            )?;
            check_borrowed_quiescence(deadline)?;
            self.service_console_output()?;
            let snapshot = self
                .region
                .node_slot(self.vm_slot)
                .map_err(map_slot_error)?
                .snapshot();
            check_borrowed_quiescence(deadline)?;
            let block_progress = self.service_block_io(&snapshot)?;
            check_borrowed_quiescence(deadline)?;
            let ninep_progress = self.service_ninep_io(&snapshot)?;
            check_borrowed_quiescence(deadline)?;
            let accelerator_progress = self.service_accelerator_io(&snapshot)?;
            let device_progress = block_progress || ninep_progress || accelerator_progress;
            check_borrowed_quiescence(deadline)?;
            self.publish_device_completion_deadline()?;
            last_observed = Some((
                snapshot.control_boundary_ack,
                snapshot.current_icount,
                snapshot.device_io_active,
                device_progress,
            ));
            if control_boundary_request_is_acknowledged(request, &snapshot) {
                deadline.complete("probe checkpoint device boundary")?;
                return Ok(!device_progress && snapshot.device_io_active == 0);
            }
            {
                self.performance.pending_sleep();
                deadline.wait(self.poll_interval, "probe checkpoint device boundary")?;
            }
        }
        Err(QemuAsyncDriverRuntimeError::new(
            "probe checkpoint device boundary",
            format!(
                "QEMU did not acknowledge control token {} within {timeout:?}; last observation {}",
                request.generation,
                last_observed.map_or_else(
                    || String::from("none"),
                    |(ack, current, active, progress)| format!(
                        "token {ack}, current icount {current}, device I/O active {active}, device progress {progress}"
                    ),
                )
            ),
        ))
    }

    pub(super) fn pause_checkpoint_boundary(
        &mut self,
        deadline: &OperationPollBudget<'_>,
        timeout: Duration,
        original: Option<&crucible_linux_resource::host_supervision::HostOperationGuard>,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        check_borrowed_quiescence(deadline)?;
        let mut initial_snapshot = self
            .region
            .node_slot(self.vm_slot)
            .map_err(map_slot_error)?
            .snapshot();
        let reached_boundary_control_wake = initial_snapshot.status != STATUS_IDLE;

        if reached_boundary_control_wake {
            // Warm realization pulses the main-loop doorbell while connecting
            // QMP. Its final two-pass callback can still own QEMU's coalescing
            // token after the primer thread joins. Fence that ordinary control
            // work before publishing pause; otherwise the old callback can run
            // before pause is visible, clear the token, and strand the reached-
            // ceiling vCPU on its condition variable indefinitely.
            if original.is_some() {
                self.probe_checkpoint_device_boundary(deadline, timeout)?;
            } else {
                self.probe_checkpoint_device_io(timeout)?;
            }
            initial_snapshot = self
                .region
                .node_slot(self.vm_slot)
                .map_err(map_slot_error)?
                .snapshot();
        }
        let remaining = deadline
            .remaining("quiesce for checkpoint")?
            .unwrap_or_default();
        if remaining.is_zero() {
            return Err(QemuAsyncDriverRuntimeError::new(
                "quiesce for checkpoint",
                "pre-pause control fence exhausted the checkpoint pause timeout",
            ));
        }
        let slot = self
            .region
            .node_slot(self.vm_slot)
            .map_err(map_slot_error)?;
        let initial_publish_gen = initial_snapshot.publish_gen;
        check_borrowed_quiescence(deadline)?;
        if let Err(source) = self.region.header().request_pause([slot]) {
            return self.fail_checkpoint_pause(QemuAsyncDriverRuntimeError::new(
                "request checkpoint pause",
                source.to_string(),
            ));
        }
        // Revoke the unused tail of the preceding quantum. Publishing this
        // ceiling also wakes the scheduler futex, so the plugin observes the
        // already-visible pause without a main-loop eventfd wake. A later
        // normal quantum must publish a fresh ceiling.
        let checkpoint_ceiling = authorize_advance_ceiling(
            initial_snapshot.current_icount,
            initial_snapshot.current_icount,
            None,
        )
        .map_err(|source| {
            QemuAsyncDriverRuntimeError::new("clamp checkpoint ceiling", source.to_string())
        });
        let checkpoint_ceiling = match checkpoint_ceiling {
            Ok(ceiling) => ceiling,
            Err(source) => return self.fail_checkpoint_pause(source),
        };
        if let Err(source) = check_borrowed_quiescence(deadline) {
            return self.fail_checkpoint_pause(source);
        }
        if let Err(source) = slot.publish_scheduler_advance(
            checkpoint_ceiling,
            crucible_shmem::AdvanceStopCondition::Ceiling,
        ) {
            return self.fail_checkpoint_pause(QemuAsyncDriverRuntimeError::new(
                "publish checkpoint ceiling",
                source.to_string(),
            ));
        }
        let device_servicers_attached =
            self.block.is_some() || self.ninep.is_some() || self.accelerator.is_some();
        let zero_length_idle_control_wake = device_servicers_attached
            && initial_snapshot.status == STATUS_IDLE
            && initial_snapshot.idle_wake_icount == initial_snapshot.current_icount;
        let tokenized_checkpoint_control_wake =
            reached_boundary_control_wake || zero_length_idle_control_wake;
        if tokenized_checkpoint_control_wake
            || checkpoint_pause_requires_control_doorbell(
                &initial_snapshot,
                device_servicers_attached,
            )
        {
            // A reached-ceiling publication is parked on QEMU's condition
            // variable rather than the scheduler futex, so the clamped ceiling
            // cannot make it observe the pause. The pre-pause fence publishes
            // an idle-looking control boundary without changing that underlying
            // wait, so preserve the original reached-state provenance here.
            // Ring the main-loop doorbell in that state even with devices
            // attached: QEMU's two-pass control boundary orders any resulting
            // device bottom half before it publishes quiescence. An originally
            // idle device VM with a future deadline retains the stricter
            // no-doorbell path to avoid admitting a latent waiter. A zero-length
            // idle publication has no futex edge left to observe pause and uses
            // the same tokenized two-pass handoff as a reached boundary.
            if let Err(source) = check_borrowed_quiescence(deadline) {
                return self.fail_checkpoint_pause(source);
            }
            let wake = if tokenized_checkpoint_control_wake {
                // The paired token makes a vCPU resume callback yield without
                // interpreting this control edge as guest authorization.
                self.signal_wake(None).map(|_request| ())
            } else {
                self.write_wake_doorbell()
            };
            if let Err(source) = wake {
                return self.fail_checkpoint_pause(source);
            }
        }
        let mut last_observed = None;
        let mut attempt = 0_u64;
        loop {
            match deadline.remaining("quiesce for checkpoint") {
                Ok(Some(_)) => {}
                Ok(None) => break,
                Err(source) => return self.fail_checkpoint_pause(source),
            }

            let snapshot = match self.region.node_slot(self.vm_slot).map_err(map_slot_error) {
                Ok(slot) => slot.snapshot(),
                Err(source) => return self.fail_checkpoint_pause(source),
            };
            // A request can enter QEMU's device coroutine in the main-loop
            // slice between the plugin's exact pause publication and native
            // stop consuming its queued request. The RR fence prevents any
            // further guest dispatch, while servicing here lets QEMU's normal
            // block/ninep/accelerator drain reach the same quiescent boundary.
            if let Err(source) = check_borrowed_quiescence(deadline) {
                return self.fail_checkpoint_pause(source);
            }
            let block_progress = match self.service_block_io(&snapshot) {
                Ok(progress) => progress,
                Err(source) => return self.fail_checkpoint_pause(source),
            };
            if let Err(source) = check_borrowed_quiescence(deadline) {
                return self.fail_checkpoint_pause(source);
            }
            let ninep_progress = match self.service_ninep_io(&snapshot) {
                Ok(progress) => progress,
                Err(source) => return self.fail_checkpoint_pause(source),
            };
            if let Err(source) = check_borrowed_quiescence(deadline) {
                return self.fail_checkpoint_pause(source);
            }
            let accelerator_progress = match self.service_accelerator_io(&snapshot) {
                Ok(progress) => progress,
                Err(source) => return self.fail_checkpoint_pause(source),
            };
            let device_progress = block_progress || ninep_progress || accelerator_progress;
            if let Err(source) = check_borrowed_quiescence(deadline) {
                return self.fail_checkpoint_pause(source);
            }
            if let Err(source) = self.publish_device_completion_deadline() {
                return self.fail_checkpoint_pause(source);
            }
            // Servicing a device or publishing its next completion deadline can
            // wake QEMU and cause a fresh plugin boundary after `snapshot` was
            // read. Decide only from a post-service acquire snapshot; using the
            // stale pre-service state allowed checkpoint assembly to observe a
            // transient reached slot immediately after this method returned.
            let settled_snapshot = match self.region.node_slot(self.vm_slot).map_err(map_slot_error)
            {
                Ok(slot) => slot.snapshot(),
                Err(source) => return self.fail_checkpoint_pause(source),
            };
            last_observed = Some((
                settled_snapshot.publish_gen,
                settled_snapshot.status,
                settled_snapshot.current_icount,
                settled_snapshot.idle_wake_icount,
                settled_snapshot.device_io_active,
                settled_snapshot.control_boundary_ack,
                self.region.header().pause_requested(),
            ));
            if settled_snapshot.publish_gen != initial_publish_gen
                && !device_progress
                && settled_snapshot.status == crucible_shmem::STATUS_IDLE
                && settled_snapshot.idle_wake_icount == settled_snapshot.current_icount
                && settled_snapshot.device_io_active == 0
            {
                // The plugin has queued native VM stop from the exact futex
                // callback. Wake QEMU's main loop so it can consume that
                // request and release the BQL to QMP. The patched block driver
                // suppresses request-coroutine wakeups while this stop is
                // pending, so the handoff cannot admit post-pause I/O.
                self.write_wake_doorbell()?;
                if let Err(source) = deadline.complete("quiesce for checkpoint") {
                    return self.fail_checkpoint_pause(source);
                }
                return Ok(());
            }
            {
                // Publishing the clamped ceiling already wakes the plugin's
                // scheduler futex. Do not ring the main-loop eventfd here: a
                // control-only wake can admit a latent block poll after the
                // readiness probe and create a future completion that cannot
                // retire at the frozen checkpoint coordinate. A reached
                // boundary is different: QMP-connect wake pulsing may have
                // consumed the coalesced callback token just before the pause
                // request. Re-publish its acknowledged token periodically so
                // coalescing cannot lose the required handoff.
                if tokenized_checkpoint_control_wake
                    && attempt % 16 == 15
                    && let Err(source) = self.signal_wake(None)
                {
                    return self.fail_checkpoint_pause(source);
                }
                self.performance.pending_sleep();
                if let Err(source) = deadline.wait(self.poll_interval, "quiesce for checkpoint") {
                    return self.fail_checkpoint_pause(source);
                }
                attempt = attempt.wrapping_add(1);
            }
        }
        let detail = last_observed.map_or_else(
            || String::from("no node-slot snapshot was observed"),
            |(
                publish_gen,
                status,
                current_icount,
                idle_wake_icount,
                device_io_active,
                control_ack,
                pause_requested,
            )| {
                format!(
                    "initial publish generation {initial_publish_gen}, last publish generation {publish_gen}, status {status}, current icount {current_icount}, idle wake icount {idle_wake_icount}, device I/O active {device_io_active}, control serial {control_ack}, pause requested {pause_requested}"
                )
            },
        );
        self.fail_checkpoint_pause(QemuAsyncDriverRuntimeError::new(
            "await checkpoint pause",
            format!("plugin did not acknowledge an exact boundary within {remaining:?}: {detail}"),
        ))
    }
}

fn check_borrowed_quiescence(
    deadline: &OperationPollBudget<'_>,
) -> Result<(), QemuAsyncDriverRuntimeError> {
    if let OperationPollBudget::Borrowed(original) = deadline {
        original.wait_slice().map_err(|source| {
            QemuAsyncDriverRuntimeError::operational_supervision("quiesce for checkpoint", source)
        })?;
    }
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    if let OperationPollBudget::BorrowedPair(_, _) = deadline {
        deadline.remaining("quiesce for checkpoint")?;
    }
    Ok(())
}
