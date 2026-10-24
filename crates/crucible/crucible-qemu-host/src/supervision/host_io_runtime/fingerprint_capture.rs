//! Exact fingerprint publication under an owned or borrowed live operation.

use super::action_scope::{ControlActionScope, SourceControlAction};
use super::control::PendingControlBoundary;
use super::*;

impl QemuLiveHostIoRuntime {
    fn signal_fingerprint_capture(
        &mut self,
        _deadline: &OperationPollBudget<'_>,
        fingerprint_request: u32,
    ) -> Result<PendingControlBoundary, QemuAsyncDriverRuntimeError> {
        #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
        if let OperationPollBudget::BorrowedPair(_, _) = _deadline {
            let pending =
                self.publish_paired_fingerprint_control(_deadline, fingerprint_request)?;
            return self.wake_paired_fingerprint_control(_deadline, pending);
        }
        self.signal_wake(Some(fingerprint_request))
    }

    pub(super) fn capture_execution_fingerprint(
        &mut self,
        deadline: &OperationPollBudget<'_>,
        timeout: Duration,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.capture_execution_fingerprint_with_actions(
            deadline,
            timeout,
            &mut SourceControlAction::default(),
        )
    }

    pub(super) fn capture_execution_fingerprint_with_actions(
        &mut self,
        deadline: &OperationPollBudget<'_>,
        timeout: Duration,
        actions: &mut impl ControlActionScope,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let operation = "publish current execution fingerprint";
        check_paired_capture(deadline)?;
        let observed = self
            .region
            .as_ref()
            .ok_or_else(region_missing)?
            .fingerprint_sample(self.vm_slot)
            .map_err(map_slot_error)?
            .capture_request_generation();
        // Exhaustion must refuse before the real Source retains any loan or
        // seals a publication attempt whose acknowledgement would wrap.
        let fingerprint_request =
            crucible_qemu_shmem::FingerprintSampleSlot::checked_fresh_capture_successor_v1(
                observed,
            )
            .map_err(|source| QemuAsyncDriverRuntimeError::fingerprint_sample(operation, source))?;
        // Check the independent control generation before the sampler or the
        // actual Source acquires any publication debt. The real publication
        // still validates the same tuple at its own mutation cut.
        let mapping = self.region.as_ref().ok_or_else(region_missing)?;
        let frontier = mapping
            .fault_command_write_index(self.vm_slot)
            .map_err(map_slot_error)?;
        mapping
            .node_slot(self.vm_slot)
            .map_err(map_slot_error)?
            .preview_action_token(frontier, Some(fingerprint_request))
            .map_err(|source| QemuAsyncDriverRuntimeError::boundary_action(operation, source))?;
        let loan = actions.lend(self, deadline, Some(fingerprint_request))?;
        deadline.remaining(operation)?.ok_or_else(|| {
            QemuAsyncDriverRuntimeError::new(operation, "capture operation has expired")
        })?;
        if let Some(source) = &mut self.source_supervision {
            // The sampler generation is externally visible before its paired
            // token. Even CAS refusal keeps this attempted publication sealed.
            source
                .begin_capture_publication(
                    self.region.as_ref().ok_or_else(region_missing)?,
                    self.vm_slot,
                    fingerprint_request,
                )
                .map_err(|source| {
                    QemuAsyncDriverRuntimeError::operational_supervision(
                        "begin fingerprint request publication",
                        source,
                    )
                })?;
        }
        // Admission owns the proposed successor before it becomes visible.
        // The exact compare-and-exchange also rejects a completed intervening
        // capture rather than publishing an unowned replacement generation.
        self.region
            .as_ref()
            .ok_or_else(region_missing)?
            .fingerprint_sample(self.vm_slot)
            .map_err(map_slot_error)?
            .request_fresh_capture_from_v1(observed)
            .map_err(|source| QemuAsyncDriverRuntimeError::fingerprint_sample(operation, source))?;
        let fingerprint_acknowledgement = fingerprint_request + 1;
        let request = self.signal_fingerprint_capture(deadline, fingerprint_request)?;
        actions.validate(request)?;
        let mut last_observed = None;
        let mut attempt = 0_u64;
        loop {
            // The collector publishes an actual terminal cancellation row even
            // when the caller's next original check will refuse continuation.
            if loan {
                actions.refresh(self)?;
            }
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
            check_paired_capture(deadline)?;
            self.service_console_output()?;
            check_paired_capture(deadline)?;
            let snapshot = self
                .region
                .as_ref()
                .ok_or_else(region_missing)?
                .node_slot(self.vm_slot)
                .map_err(map_slot_error)?
                .snapshot();
            let fingerprint_ack = self
                .region
                .as_ref()
                .ok_or_else(region_missing)?
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
                    if !loan || actions.finish(self)? {
                        deadline.complete("publish current execution fingerprint")?;
                        return Ok(());
                    }
                }
                if fingerprint_ack != fingerprint_request
                    && fingerprint_ack != fingerprint_acknowledgement
                {
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
                    check_paired_capture(deadline)?;
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

// Paired capture carries both subscriptions through every separate service/wake cut.
fn check_paired_capture(
    _deadline: &OperationPollBudget<'_>,
) -> Result<(), QemuAsyncDriverRuntimeError> {
    #[cfg(all(target_os = "linux", feature = "private-measurement-domain"))]
    if let OperationPollBudget::BorrowedPair(_, _) = _deadline {
        _deadline.remaining("publish current execution fingerprint")?;
    }
    Ok(())
}
