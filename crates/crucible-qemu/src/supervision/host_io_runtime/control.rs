//! Tokenized control-boundary publication and pause rollback.

use std::io::Write;

use super::*;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct PendingControlBoundary {
    pub(super) generation: u32,
    pub(super) fault_command_frontier: u64,
    pub(super) fingerprint_capture_request: Option<u32>,
}

/// Borrows the sole original setup-time devices until their runtime handoff.
struct PrimingConsoleDevices<'a> {
    block: Option<&'a mut QemuLiveBlockIoServicer>,
    ninep: Option<&'a mut QemuLive9pIoServicer>,
}

impl PrimingConsoleDevices<'_> {
    fn service(
        &mut self,
        current: u64,
    ) -> Result<(bool, Option<u64>), QemuAsyncDriverRuntimeError> {
        let block = self
            .block
            .as_deref_mut()
            .map(|servicer| {
                servicer
                    .service_fault_free_initialization(current)
                    .map_err(|source| {
                        QemuAsyncDriverRuntimeError::new(
                            "service priming block io",
                            source.to_string(),
                        )
                    })
            })
            .transpose()?;
        let ninep = self
            .ninep
            .as_deref_mut()
            .map(|servicer| {
                servicer.service(current).map_err(|source| {
                    QemuAsyncDriverRuntimeError::new("service priming 9p io", source.to_string())
                })
            })
            .transpose()?;
        let progress = block.is_some_and(|step| step.processed > 0 || step.delivered > 0)
            || ninep.is_some_and(|step| step.processed > 0 || step.delivered > 0);
        let next_completion = block
            .and_then(|step| step.next_completion_icount)
            .into_iter()
            .chain(ninep.and_then(|step| step.next_completion_icount))
            .min();
        Ok((progress, next_completion))
    }
}

impl QemuLiveHostIoRuntime {
    #[cfg(target_os = "linux")]
    pub(crate) fn retain_console_launch(
        &mut self,
        setup: &crate::QemuHostPluginSetup,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        if let Some(custody) = &setup.console_custody {
            custody
                .validate_mapping(&self.region, self.vm_slot)
                .map_err(|source| {
                    QemuAsyncDriverRuntimeError::new("retain console launch", source.to_string())
                })?;
        }
        self.console_custody = setup.console_custody.clone();
        Ok(())
    }

    /// Restores the one-millisecond ACK baseline for controlled comparisons.
    #[cfg(feature = "test-support")]
    pub(crate) fn use_slow_clamp_ack_poll_for_test(&mut self) {
        self.slow_clamp_ack_poll = true;
    }

    // The callback observes genuine claim refusal; it cannot supply a request,
    // replace a deadline or grant native phase authority.
    #[cfg(test)]
    pub(crate) fn on_native_publication_unavailable_for_test(
        &mut self,
        rendezvous: impl FnOnce(&HostSupervisionDeadline) + Send + 'static,
    ) {
        self.control_publication_unavailable_for_test = Some(Box::new(rendezvous));
    }

    // Borrows the same deadline only after an actual native claim refusal. The
    // test may observe expiry; it cannot replace the budget or supply custody.
    #[cfg(test)]
    fn observe_native_publication_unavailable_for_test(
        &mut self,
        deadline: &HostSupervisionDeadline,
    ) {
        if !std::mem::take(&mut self.control_publication_unavailable_seen_for_test) {
            return;
        }
        if let Some(rendezvous) = self.control_publication_unavailable_for_test.take() {
            rendezvous(deadline);
        }
    }

    pub(super) fn clamp_ack_poll_interval(&self, remaining: Duration) -> Duration {
        let cap = Duration::from_micros(100);
        #[cfg(feature = "test-support")]
        let cap = if self.slow_clamp_ack_poll {
            Duration::from_millis(1)
        } else {
            cap
        };
        self.poll_interval.min(remaining).min(cap)
    }

    fn wait_for_clamp_ack_poll(&mut self, remaining: Duration) {
        self.wait_for_poll_interval_capped(remaining, self.clamp_ack_poll_interval(remaining));
    }

    /// Signals QEMU's plugin wake eventfd with the exact eight-byte counter write.
    pub(super) fn write_wake_doorbell(&mut self) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.performance.wake_write();
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
        self.try_signal_wake(fingerprint_capture_request)?
            .ok_or_else(|| {
                QemuAsyncDriverRuntimeError::new(
                    "retain console request",
                    crate::native_console_owner::ConsoleOwnerError::PublicationUnavailable
                        .to_string(),
                )
            })
    }

    // Only the completed-clamp pump defers native-writer acquisition under its
    // existing deadline. Other callers retain their immediate failure behavior.
    fn try_signal_wake(
        &mut self,
        fingerprint_capture_request: Option<u32>,
    ) -> Result<Option<PendingControlBoundary>, QemuAsyncDriverRuntimeError> {
        let fault_command_frontier = self
            .region
            .fault_command_write_index(self.vm_slot)
            .map_err(map_slot_error)?;
        let slot = self
            .region
            .node_slot(self.vm_slot)
            .map_err(map_slot_error)?;
        #[cfg(target_os = "linux")]
        let generation = if let Some(custody) = &self.console_custody {
            match custody.request_boundary(
                &self.region,
                fault_command_frontier,
                fingerprint_capture_request,
            ) {
                Ok(generation) => generation,
                // Both refusals precede the paired-field commit and request
                // CAS, so the dropped lease leaves nothing to reconcile.
                Err(
                    crate::native_console_owner::ConsoleOwnerError::PublicationUnavailable
                    | crate::native_console_owner::ConsoleOwnerError::Unavailable,
                ) => {
                    #[cfg(test)]
                    {
                        self.control_publication_unavailable_seen_for_test = true;
                    }
                    return Ok(None);
                }
                Err(source) => {
                    return Err(QemuAsyncDriverRuntimeError::new(
                        "retain console request",
                        source.to_string(),
                    ));
                }
            }
        } else {
            slot.request_control_boundary(fault_command_frontier, fingerprint_capture_request)
                .map_err(|source| {
                    QemuAsyncDriverRuntimeError::new(
                        "request plugin control boundary",
                        source.to_string(),
                    )
                })?
        };
        #[cfg(not(target_os = "linux"))]
        let generation = slot
            .request_control_boundary(fault_command_frontier, fingerprint_capture_request)
            .map_err(|source| {
                QemuAsyncDriverRuntimeError::new(
                    "request plugin control boundary",
                    source.to_string(),
                )
            })?;
        self.write_wake_doorbell()?;
        Ok(Some(PendingControlBoundary {
            generation,
            fault_command_frontier,
            fingerprint_capture_request,
        }))
    }

    /// Re-notifies the original clamp after its consumer frees event capacity.
    ///
    /// Callback delivery can finish while event publication remains pending.
    /// Actual event consumption gives that same request another opportunity
    /// to settle. Device servicing already owns its progress notification.
    ///
    /// # Errors
    ///
    /// Returns the original mapping or doorbell error without replacing the request.
    pub(super) fn renotify_clamp_after_event_drain(
        &mut self,
        request: PendingControlBoundary,
        drained_events: usize,
        device_progress: bool,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        if drained_events == 0 || device_progress || request.generation & 1 != 0 {
            return Ok(());
        }
        let Some(observed) = self.try_node_snapshot()? else {
            return Ok(());
        };
        if observed.control_boundary_ack != request.generation
            || observed.control_boundary_fault_command_frontier != request.fault_command_frontier
            || observed.control_boundary_capture_request
                != request.fingerprint_capture_request.unwrap_or(0)
            || self
                .region
                .fault_command_write_index(self.vm_slot)
                .map_err(map_slot_error)?
                != request.fault_command_frontier
        {
            return Ok(());
        }

        // An ACK racing this write may leave one redundant doorbell. It never
        // creates a new request or changes the bound producer/capture epoch.
        self.write_wake_doorbell()
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
        let deadline = HostSupervisionDeadline::start(timeout);
        // A coherent publication retains the original clamp behavior even for
        // a zero budget. Only unavailable authority needs acquisition waiting.
        let snapshot = match self.try_node_snapshot()? {
            Some(snapshot) => snapshot,
            None => self
                .wait_node_snapshot(|| deadline.remaining())?
                .ok_or_else(|| {
                    QemuAsyncDriverRuntimeError::new(
                        "fence priming handoff",
                        "publication acquisition exhausted the handoff timeout",
                    )
                })?,
        };
        self.clamp_completed_quantum(&snapshot, deadline.remaining().unwrap_or_default())
    }

    /// Accepts a completed console prefix under the original priming deadline.
    ///
    /// Ordinary launches perform no extra shared-memory reads or control work.
    /// A console completion must retain its exact logical coordinate through
    /// the existing fault/device/control clamp before priming can regrant.
    pub(in crate::supervision) fn fence_priming_console_completion(
        &mut self,
        completed: crucible::Icount,
        deadline: &HostSupervisionDeadline,
        block: Option<&mut QemuLiveBlockIoServicer>,
        ninep: Option<&mut QemuLive9pIoServicer>,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        #[cfg(target_os = "linux")]
        if self.console_custody.is_some() {
            let snapshot = self
                .wait_node_snapshot(|| deadline.remaining())?
                .ok_or_else(|| {
                    QemuAsyncDriverRuntimeError::new(
                        "accept priming console completion",
                        "publication acquisition exhausted the original priming deadline",
                    )
                })?;
            if snapshot.current_icount != completed.retired {
                return Err(QemuAsyncDriverRuntimeError::new(
                    "accept priming console completion",
                    "completed quantum coordinate changed before its exact clamp",
                ));
            }
            return self.clamp_completed_quantum_with_deadline(
                &snapshot,
                deadline.remaining().unwrap_or_default(),
                Some(deadline),
                Some(PrimingConsoleDevices { block, ninep }),
            );
        }
        #[cfg(not(target_os = "linux"))]
        let _ = (completed, deadline, block, ninep);
        Ok(())
    }

    /// Revokes the unused tail of a completed quantum before returning it.
    ///
    /// A reached boundary already equals its ceiling. An early idle boundary
    /// can retain a future ceiling, however, and QEMU may otherwise consume it
    /// after the host records completion. Clamping makes every authorization
    /// single-use; the next quantum must explicitly publish its own ceiling.
    fn publish_completed_ceiling(
        &self,
        ceiling: crucible_shmem::AdvanceCeiling,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        let slot = self
            .region
            .node_slot(self.vm_slot)
            .map_err(map_slot_error)?;
        #[cfg(target_os = "linux")]
        if let Some(custody) = &self.console_custody {
            return custody.publish_clamp(slot, ceiling).map_err(|source| {
                QemuAsyncDriverRuntimeError::new("retain console clamp", source.to_string())
            });
        }
        slot.publish_scheduler_advance(ceiling, crucible_shmem::AdvanceStopCondition::Ceiling)
            .map(|_| ())
            .map_err(|source| {
                QemuAsyncDriverRuntimeError::new(
                    "publish completed-quantum ceiling",
                    source.to_string(),
                )
            })
    }

    // Gives the mapped interleaving control the exact ordinary clamp entry.
    #[cfg(test)]
    pub(crate) fn clamp_completed_quantum_for_test(
        &mut self,
        snapshot: &crucible_shmem::NodeSlotSnapshot,
        timeout: Duration,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.clamp_completed_quantum(snapshot, timeout)
    }

    pub(super) fn clamp_completed_quantum(
        &mut self,
        snapshot: &crucible_shmem::NodeSlotSnapshot,
        timeout: Duration,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.clamp_completed_quantum_with_deadline(snapshot, timeout, None, None)
    }

    /// Borrows the terminal caller's single deadline for the original full body.
    pub(super) fn fence_terminal_console_completion(
        &mut self,
        snapshot: &crucible_shmem::NodeSlotSnapshot,
        deadline: &HostSupervisionDeadline,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.clamp_completed_quantum_with_deadline(
            snapshot,
            deadline.remaining().unwrap_or_default(),
            Some(deadline),
            None,
        )
    }

    fn clamp_completed_quantum_with_deadline(
        &mut self,
        snapshot: &crucible_shmem::NodeSlotSnapshot,
        timeout: Duration,
        original_deadline: Option<&HostSupervisionDeadline>,
        mut priming_devices: Option<PrimingConsoleDevices<'_>>,
    ) -> Result<(), QemuAsyncDriverRuntimeError> {
        self.performance.boundary(self.vm_slot);
        let ceiling =
            authorize_advance_ceiling(snapshot.current_icount, snapshot.current_icount, None)
                .map_err(|source| {
                    QemuAsyncDriverRuntimeError::new("clamp completed quantum", source.to_string())
                })?;
        self.publish_completed_ceiling(ceiling)?;

        // The futex publication revokes TCG dispatch, but QEMU's main loop can
        // still own a device bottom half queued by the completed slice. Probe
        // the drained eventfd boundary after the clamp and wait for its paired
        // post-device publication. This makes the later read-only checkpoint
        // readiness observation stable: any newly submitted coroutine is
        // already represented by `device_io_active` before the quantum returns.
        // Boundary discovery and revocation acknowledgement are distinct
        // liveness phases. A quantum may consume nearly all of its discovery
        // budget under a heavily loaded TCG host; carrying only the residual
        // milliseconds into this mandatory odd-token handshake would make a
        // correct guest outcome depend on host contention. Give the handshake
        // its own bounded policy interval. Neither interval enters canonical
        // state or changes the exact guest coordinate. Setup-time console
        // settlement instead keeps the caller's original absolute deadline.
        let handoff_deadline;
        let deadline = match original_deadline {
            Some(deadline) => deadline,
            None => {
                handoff_deadline = HostSupervisionDeadline::start(timeout);
                &handoff_deadline
            }
        };
        // Keep the ordinary first attempt (including its zero-budget final
        // observation), but never start an admission after an already-expired
        // borrowed priming deadline. Native contention cannot renew either.
        let mut request = if original_deadline.is_none() || deadline.has_time_remaining() {
            self.try_signal_wake(None)?
        } else {
            None
        };
        #[cfg(test)]
        if request.is_none() {
            self.observe_native_publication_unavailable_for_test(deadline);
        }
        self.wait_observation.begin_clamp(timeout);
        let mut last_observed_state = None;
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
            let drained_this_poll = self.drain_fault_events_for_pump(
                self.fault_event_staging_limit,
                deadline,
                timeout,
                "acknowledge completed-quantum clamp",
            )?;
            drained_fault_events += drained_this_poll;
            last_fault_event_indices = self.fault_event_ring_indices()?;
            if request.is_none() {
                // An empty fault ring does not check the deadline. Test it
                // before reacquiring so a late native release cannot publish
                // a new request after the original interval has expired.
                if !deadline.has_time_remaining() {
                    break;
                }
                request = self.try_signal_wake(None)?;
                #[cfg(test)]
                if request.is_none() {
                    self.observe_native_publication_unavailable_for_test(deadline);
                }
                if request.is_none() {
                    let Some(remaining) = deadline.remaining() else {
                        break;
                    };
                    self.wait_for_clamp_ack_poll(remaining);
                    continue;
                }
            }
            let observed = match self.try_node_snapshot()? {
                Some(observed) => observed,
                None => {
                    let Some(observed) = self.wait_node_snapshot(|| deadline.remaining())? else {
                        break;
                    };
                    observed
                }
            };
            // Before handoff, borrow the existing priming servicers; never
            // create shadow devices or process a request through two owners.
            let priming = priming_devices
                .as_mut()
                .map(|devices| devices.service(observed.current_icount))
                .transpose()?;
            let block_progress = if priming.is_none() {
                self.service_block_io(&observed)?
            } else {
                false
            };
            let ninep_progress = if priming.is_none() {
                self.service_ninep_io(&observed)?
            } else {
                false
            };
            let accelerator_progress = self.service_accelerator_io(&observed)?;
            let priming_progress = priming.is_some_and(|(progress, _)| progress);
            if priming_progress {
                self.write_wake_doorbell()?;
            }
            let device_progress =
                block_progress || ninep_progress || accelerator_progress || priming_progress;
            device_progress_observed |= device_progress;
            let expected_idle_wake_icount = if device_progress_observed {
                snapshot.current_icount
            } else {
                initial_idle_wake_icount
            };
            last_observed_state = Some((observed, device_progress));
            if device_progress {
                if let Some((_, next_completion)) = priming {
                    // These are the exact deadlines computed by the original
                    // borrowed providers, not a clamp-coordinate substitute.
                    self.region
                        .node_slot(self.vm_slot)
                        .map_err(map_slot_error)?
                        .store_device_completion_deadline_tick(next_completion.unwrap_or(0));
                } else {
                    self.publish_device_completion_deadline()?;
                }
            }
            let request_acknowledged = request.is_some_and(|request| {
                control_boundary_request_is_acknowledged(request, &observed)
            });
            let boundary_exactly_acknowledged = request.is_some_and(|request| {
                request_acknowledged
                    && observed.control_boundary_ack == request.generation.wrapping_add(1)
            });
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
                let request = request.ok_or_else(|| {
                    QemuAsyncDriverRuntimeError::new(
                        "acknowledge completed-quantum clamp",
                        "settled clamp has no original published control request",
                    )
                })?;
                self.completed_boundary = crate::QemuCompletedQuantumBoundary::accepted(
                    self.region.backing_identity(),
                    self.vm_slot,
                    *snapshot,
                    request.generation,
                    request.fault_command_frontier,
                    observed,
                );
                #[cfg(target_os = "linux")]
                let console_accepted = if let Some(custody) = &self.console_custody {
                    let boundary = self.completed_boundary.ok_or_else(|| {
                        QemuAsyncDriverRuntimeError::new(
                            "accept completed console prefix",
                            "console clamp lacks its exact original accepted publication",
                        )
                    })?;
                    match custody.accept_completed_with_stop(
                        &self.region,
                        boundary,
                        self.console_stop,
                    ) {
                        Ok(crate::native_console_owner::CompletedConsoleControl::Accepted) => {
                            if let Some(stop) = self.console_stop {
                                self.completed_boundary = Some(boundary.with_console_output(stop));
                            }
                            // The original accepted boundary retains the stop.
                            // Release only this runtime's consumed discovery.
                            self.console_stop = None;
                            true
                        }
                        Ok(crate::native_console_owner::CompletedConsoleControl::Observed) => {
                            // No new prefix was consumed. A retained old stop
                            // must not become another console-output completion.
                            true
                        }
                        Err(crate::native_console_owner::ConsoleOwnerError::Unavailable) => false,
                        Err(source) => {
                            return Err(QemuAsyncDriverRuntimeError::new(
                                "accept completed console prefix",
                                source.to_string(),
                            ));
                        }
                    }
                } else {
                    true
                };
                #[cfg(not(target_os = "linux"))]
                let console_accepted = true;
                if console_accepted {
                    self.performance.finish(self.vm_slot, "acknowledged");
                    return Ok(());
                }
            }
            let Some(remaining) = deadline.remaining() else {
                break;
            };
            if let Some(request) = request {
                self.renotify_clamp_after_event_drain(request, drained_this_poll, device_progress)?;
            }
            self.observe_pending_wait(
                "clamp-ack-pending",
                &observed,
                request.map(|request| wait_observation::ClampExpectation {
                    request,
                    current_ps: snapshot.current_icount,
                    idle_ps: expected_idle_wake_icount,
                    acknowledgement_seen: boundary_acknowledged,
                    device_progress,
                }),
                remaining,
            );
            self.wait_for_clamp_ack_poll(remaining);
        }

        let fault_command_indices = match self.region.fault_command_transport_mut(self.vm_slot) {
            Ok(transport) => {
                format!(
                    "{}/{}",
                    transport.ring.read_index(),
                    transport.ring.write_index()
                )
            }
            Err(source) => format!("unavailable ({source})"),
        };
        self.performance.finish(self.vm_slot, "timeout");
        Err(QemuAsyncDriverRuntimeError::new(
            "acknowledge completed-quantum clamp",
            format!(
                "QEMU did not publish the post-device control boundary within {timeout:?}: requested token {}, bound fault-command frontier {}, observed fault-command ring read/write {fault_command_indices}, expected current icount {}, retained-or-current idle wake icount {}, device progress observed {device_progress_observed}, fault-event ring initial read/write {}/{}, last read/write {}/{}, drained records {}, last observation {}",
                request.map_or_else(|| String::from("unpublished"), |request| request.generation.to_string()),
                request.map_or_else(|| String::from("unpublished"), |request| request.fault_command_frontier.to_string()),
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
                last_observed_state.map_or_else(|| String::from("unavailable"), |(observed, device_progress)| {
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
                })
            ),
        ))
    }
}
