//! Exact fingerprint publication under an owned or borrowed live operation.

use super::*;

impl QemuLiveHostIoRuntime {
    pub(super) fn capture_execution_fingerprint(
        &mut self,
        deadline: &OperationPollBudget<'_>,
        timeout: Duration,
        fingerprint_request: u32,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let fingerprint_acknowledgement = fingerprint_request.wrapping_add(1);
        let request = self.signal_wake(Some(fingerprint_request))?;
        let mut last_observed = None;
        let mut attempt = 0_u64;
        loop {
            if deadline
                .remaining("publish current execution fingerprint")?
                .is_none()
            {
                break;
            }

            self.drain_fault_events_for_operation(
                self.fault_event_staging_limit,
                deadline,
                timeout,
                "publish current execution fingerprint",
            )?;
            self.service_console_output()?;
            let snapshot = self
                .region
                .node_slot(self.vm_slot)
                .map_err(map_slot_error)?
                .snapshot();
            let fingerprint_ack = self
                .region
                .fingerprint_sample(self.vm_slot)
                .map_err(map_slot_error)?
                .capture_request_generation();
            last_observed = Some((
                snapshot.control_boundary_ack,
                snapshot.current_icount,
                snapshot.status,
                fingerprint_ack,
            ));
            if control_boundary_request_is_acknowledged(request, &snapshot) {
                if fingerprint_ack == fingerprint_acknowledgement {
                    // The digest worker publishes the sample before its release
                    // acknowledgement. This acquire load therefore makes the
                    // exact sample visible through the independent mapping.
                    deadline.complete("publish current execution fingerprint")?;
                    return Ok(());
                }
                if fingerprint_ack != fingerprint_request {
                    return Err(QemuAsyncDriverRuntimeError::new(
                        "publish current execution fingerprint",
                        format!(
                            "plugin acknowledged control token {} for fingerprint request {fingerprint_request}, but observed unrelated fingerprint generation {fingerprint_ack}",
                            request.generation,
                        ),
                    ));
                }
            }
            {
                if attempt % 16 == 15 {
                    self.write_wake_doorbell()?;
                }
                self.performance.pending_sleep();
                deadline.wait(self.poll_interval, "publish current execution fingerprint")?;
                attempt = attempt.wrapping_add(1);
            }
        }

        Err(QemuAsyncDriverRuntimeError::new(
            "publish current execution fingerprint",
            format!(
                "QEMU did not acknowledge fingerprint control token {} within {timeout:?}; last observation {}",
                request.generation,
                last_observed.map_or_else(
                    || String::from("none"),
                    |(ack, current, status, fingerprint)| {
                        format!(
                            "token {ack}, current icount {current}, status {status}, fingerprint generation {fingerprint}"
                        )
                    },
                )
            ),
        ))
    }
}
