//! Tokenized control-boundary publication and pause rollback.

use std::io::Write;

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PendingControlBoundary {
    pub(super) generation: u32,
    pub(super) fault_command_frontier: u64,
    pub(super) fingerprint_capture_request: Option<u32>,
}

impl QemuLiveHostIoRuntime {
    /// Attaches an output-only QEMU console reader and its boundary spool.
    ///
    /// The stream is drained during every in-flight advance poll so guest
    /// console backpressure cannot prevent QEMU from reaching its scheduler
    /// ceiling. Bytes remain in `spool` until the node emits them at that exact
    /// completed boundary.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveHostIoRuntimeError::DuplicateConsole`] when a console
    /// is already attached.
    pub(crate) fn with_console_observation(
        mut self,
        reader: QemuConsoleObservationReader,
    ) -> Result<Self, QemuLiveHostIoRuntimeError> {
        if self.console.is_some() {
            return Err(QemuLiveHostIoRuntimeError::DuplicateConsole);
        }
        self.console = Some(reader);
        Ok(self)
    }

    /// Drains all currently available console bytes into boundary staging.
    pub(super) fn service_console_output(&mut self) -> Result<(), QemuAsyncDriverRuntimeError> {
        let Some(console) = &mut self.console else {
            return Ok(());
        };
        console.drain_available()
    }

    /// Signals QEMU's plugin wake eventfd with the exact eight-byte counter write.
    pub(super) fn write_wake_doorbell(&self) -> Result<(), QemuAsyncDriverRuntimeError> {
        let mut wake = self.wake.as_ref();
        wake.write_all(&1_u64.to_ne_bytes()).map_err(|error| {
            QemuAsyncDriverRuntimeError::new("signal plugin wake", error.to_string())
        })
    }

    /// Publishes a frontier-bound control request and rings QEMU's eventfd.
    ///
    /// The mutable runtime borrow is the host-side single-producer admission.
    /// Once published, the request's command frontier and fingerprint
    /// generation are immutable. A later command publication intentionally
    /// leaves that request unacknowledged so it cannot capture a mixed epoch.
    pub(super) fn signal_wake(
        &mut self,
        fingerprint_capture_request: Option<u32>,
    ) -> Result<PendingControlBoundary, QemuAsyncDriverRuntimeError> {
        let fault_command_frontier = self
            .region
            .fault_command_write_index(self.vm_slot)
            .map_err(map_slot_error)?;
        let generation = self
            .region
            .node_slot(self.vm_slot)
            .map_err(map_slot_error)?
            .request_control_boundary(fault_command_frontier, fingerprint_capture_request)
            .map_err(|source| {
                QemuAsyncDriverRuntimeError::new(
                    "request plugin control boundary",
                    source.to_string(),
                )
            })?;
        self.write_wake_doorbell()?;
        Ok(PendingControlBoundary {
            generation,
            fault_command_frontier,
            fingerprint_capture_request,
        })
    }

    /// Aborts a coordinated pause and wakes both plugin wait mechanisms.
    pub(super) fn abort_checkpoint_pause_with_wake(
        &mut self,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.region.header().clear_pause();
        let futex_result = self
            .region
            .node_slot(self.vm_slot)
            .map_err(map_slot_error)
            .and_then(|slot| {
                slot.wake_for_frame_delivery().map_err(|source| {
                    QemuAsyncDriverRuntimeError::new(
                        "resume from checkpoint pause",
                        source.to_string(),
                    )
                })
            });
        let doorbell_result = self.signal_wake(None);
        match (futex_result, doorbell_result) {
            (Ok(_), Ok(_)) => Ok(()),
            (Err(futex), Ok(_)) => Err(futex),
            (Ok(_), Err(doorbell)) => Err(doorbell),
            (Err(futex), Err(doorbell)) => Err(QemuAsyncDriverRuntimeError::new(
                "resume from checkpoint pause",
                format!("futex wake failed: {futex}; doorbell wake failed: {doorbell}"),
            )),
        }
    }

    /// Releases a failed pause transaction while retaining both diagnostics.
    pub(super) fn fail_checkpoint_pause(
        &mut self,
        primary: QemuAsyncDriverRuntimeError,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        match self.abort_checkpoint_pause_with_wake() {
            Ok(()) => Err(primary),
            Err(cleanup) => Err(QemuAsyncDriverRuntimeError::new(
                "rollback failed checkpoint pause",
                format!("primary failure: {primary}; pause release failure: {cleanup}"),
            )),
        }
    }

    /// Fences setup-time activity before the node enters ordinary scheduling.
    ///
    /// Guest priming uses a temporary quantum channel over this runtime's shared
    /// region. Its completion proves the guest reached the first ceiling, but a
    /// wake-drained device or control callback may still be queued in QEMU's
    /// main loop. This acknowledged clamp transfers the region to the live
    /// runtime only after those callbacks and their fault-event publications are
    /// settled at the primed coordinate.
    ///
    /// # Errors
    ///
    /// Returns [`QemuAsyncDriverRuntimeError`] when the primed slot cannot be
    /// read or QEMU does not acknowledge the exact post-device clamp.
    pub(crate) fn fence_priming_handoff(
        &mut self,
        timeout: Duration,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let snapshot = self
            .region
            .node_slot(self.vm_slot)
            .map_err(map_slot_error)?
            .snapshot();
        self.clamp_completed_quantum(&snapshot, timeout)
    }

    /// Revokes the unused tail of a completed quantum before returning it.
    ///
    /// A reached boundary already equals its ceiling. An early idle boundary
    /// can retain a future ceiling, however, and QEMU may otherwise consume it
    /// after the host records completion. Clamping makes every authorization
    /// single-use; the next quantum must explicitly publish its own ceiling.
    pub(super) fn clamp_completed_quantum(
        &mut self,
        snapshot: &crucible_shmem::NodeSlotSnapshot,
        timeout: Duration,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let ceiling =
            authorize_advance_ceiling(snapshot.current_icount, snapshot.current_icount, None)
                .map_err(|source| {
                    QemuAsyncDriverRuntimeError::new("clamp completed quantum", source.to_string())
                })?;
        self.region
            .node_slot(self.vm_slot)
            .map_err(map_slot_error)?
            .publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
            .map(|_| ())
            .map_err(|source| {
                QemuAsyncDriverRuntimeError::new(
                    "publish completed-quantum ceiling",
                    source.to_string(),
                )
            })?;

        // The futex publication revokes TCG dispatch, but QEMU's main loop can
        // still own a device bottom half queued by the completed slice. Probe
        // the drained eventfd boundary after the clamp and wait for its paired
        // post-device publication. This makes the later read-only checkpoint
        // readiness observation stable: any newly submitted coroutine is
        // already represented by `device_io_active` before the quantum returns.
        let request = self.signal_wake(None)?;
        // Boundary discovery and revocation acknowledgement are distinct
        // liveness phases. A quantum may consume nearly all of its discovery
        // budget under a heavily loaded TCG host; carrying only the residual
        // milliseconds into this mandatory odd-token handshake would make a
        // correct guest outcome depend on host contention. Give the handshake
        // its own bounded policy interval. Neither interval enters canonical
        // state or changes the exact guest coordinate.
        let deadline = HostSupervisionDeadline::start(timeout);
        let mut last_observed_state;
        let mut boundary_acknowledged = false;
        let initial_fault_event_indices = self.fault_event_ring_indices()?;
        let mut last_fault_event_indices;
        let mut drained_fault_events = 0;
        let initial_idle_wake_icount = if snapshot.status == STATUS_IDLE {
            snapshot.idle_wake_icount
        } else {
            snapshot.current_icount
        };
        let mut device_progress_observed = false;
        loop {
            drained_fault_events += self.drain_fault_events_for_pump(
                self.fault_event_staging_limit,
                &deadline,
                timeout,
                "acknowledge completed-quantum clamp",
            )?;
            last_fault_event_indices = self.fault_event_ring_indices()?;
            self.service_console_output()?;
            let observed = self
                .region
                .node_slot(self.vm_slot)
                .map_err(map_slot_error)?
                .snapshot();
            let block_progress = self.service_block_io(&observed)?;
            let ninep_progress = self.service_ninep_io(&observed)?;
            let accelerator_progress = self.service_accelerator_io(&observed)?;
            let device_progress = block_progress || ninep_progress || accelerator_progress;
            device_progress_observed |= device_progress;
            let expected_idle_wake_icount = if device_progress_observed {
                snapshot.current_icount
            } else {
                initial_idle_wake_icount
            };
            last_observed_state = (observed, device_progress);
            if device_progress {
                self.publish_device_completion_deadline()?;
            }
            let request_acknowledged = control_boundary_request_is_acknowledged(request, &observed);
            let boundary_exactly_acknowledged = request_acknowledged
                && observed.control_boundary_ack == request.generation.wrapping_add(1);
            if request_acknowledged {
                boundary_acknowledged = true;
            }
            // The control callback publishes the exact clamped coordinate
            // before release-acknowledging the request. A node that retained a
            // future idle deadline may only tighten it. A node with no retained
            // future may immediately republish QEMU's fresh exact deadline from
            // its re-armed all-halted callback; accepting both states prevents
            // host observation timing from selecting liveness. Servicing device
            // work invalidates the retained deadline and requires another
            // observation after the current-coordinate fence.
            if completed_quantum_clamp_is_settled(
                boundary_acknowledged,
                boundary_exactly_acknowledged,
                snapshot.current_icount,
                expected_idle_wake_icount,
                device_progress,
                &observed,
            ) {
                return Ok(());
            }
            let Some(remaining) = deadline.remaining() else {
                break;
            };
            self.wait_for_poll_interval(remaining);
        }
        Err(QemuAsyncDriverRuntimeError::new(
            "acknowledge completed-quantum clamp",
            format!(
                "QEMU did not publish the post-device control boundary within {timeout:?}: requested token {}, expected current icount {}, retained-or-current idle wake icount {}, fault-event ring initial read/write {}/{}, last read/write {}/{}, drained records {}, last observation {}",
                request.generation,
                snapshot.current_icount,
                if device_progress_observed {
                    snapshot.current_icount
                } else {
                    initial_idle_wake_icount
                },
                initial_fault_event_indices.0,
                initial_fault_event_indices.1,
                last_fault_event_indices.0,
                last_fault_event_indices.1,
                drained_fault_events,
                {
                    let (observed, device_progress) = last_observed_state;
                    format!(
                        "token {}, wake signal {}, publish generation {}, current icount {}, raw icount {}, max advance icount {}, idle wake icount {}, status {}, device I/O active {}, fault-command frontier {}, fingerprint capture request {}, device progress {device_progress}",
                        observed.control_boundary_ack,
                        observed.wake_signal,
                        observed.publish_gen,
                        observed.current_icount,
                        observed.logical_time_raw_icount,
                        observed.max_advance_icount,
                        observed.idle_wake_icount,
                        observed.status,
                        observed.device_io_active,
                        observed.control_boundary_fault_command_frontier,
                        observed.control_boundary_capture_request,
                    )
                }
            ),
        ))
    }
}
