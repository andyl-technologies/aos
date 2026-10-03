//! Authenticated guest-stop release and retained physical peer publication.
//!
//! Replies and marker releases join the engine's original held-stop witness;
//! completed causal peer outcomes remain owned until the lifecycle publishes
//! their effects once. No live controller capability is serialized or inferred
//! from a guest request or clock value.

use super::*;

impl ProductionVmLifecycleLoop {
    /// Drains node-qualified guest selectable requests at the paused boundary.
    ///
    /// The returned requests remain untrusted guest input. Callers must bind
    /// each one to the authenticated scenario declaration and choose a legal
    /// value before enqueueing a reply or advancing another quantum.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when any node's shared-memory request stream
    /// is malformed or violates the one-pending-request contract.
    pub fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<crucible_qemu::QemuNodeSelectablePendingRequest>, SchedulerError> {
        if self.pending_held_host_outcomes.is_some()
            || self.inner.live_network_preselection().is_some()
        {
            return Ok(Vec::new());
        }
        let witness = self.inner.held_host_stop_witness();
        if let Some(witness) = &witness {
            self.inner.validate_held_host_stop(witness)?;
        } else if self.inner.has_unsettled_host_continuation() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "guest requests cannot bypass an unsettled physical continuation",
                ),
            });
        }
        let mut pending = self
            .inner
            .backend_mut()
            .drain_pending_selectable_requests()?;
        if let Some(witness) = witness {
            // A peer's physical pause is private until canonical publication.
            pending.retain(|request| {
                witness.kind() == crucible::HeldHostStopKind::GuestSelectable
                    && request.node() == witness.node()
            });
        }
        Ok(pending)
    }

    /// Projects a retained selectable pause into the shared scheduler clock.
    ///
    /// # Errors
    ///
    /// Rejects an overflowing pause or a node without an admitted counter mapping.
    pub fn pending_selectable_request_time(
        &self,
        pending: &crucible_qemu::QemuNodeSelectablePendingRequest,
    ) -> Result<VirtualTime, SchedulerError> {
        let ticks = pending
            .pending()
            .trap_tick_ps()
            .checked_add(
                crucible_protocol::selectable_catalog_plan::SELECTABLE_NATIVE_HANDOFF_TICKS_PS,
            )
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from("guest selectable pause boundary overflowed"),
            })?;
        self.inner
            .backend_network_output_time(pending.node(), Icount { retired: ticks })
    }

    /// Applies one exact host-authorized selectable reply at the scheduler frontier.
    ///
    /// The scheduler stages its event-log transition before publishing the reply
    /// to QEMU and rolls that stage back if transport publication fails. Its
    /// authoritative configuration and resumed counter mapping advance only
    /// after publication succeeds. Frames emitted before the pause retain their
    /// original logical emission time across the mapping change.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the decision does not exactly match the
    /// pending request and reply, the parent or selected configuration is not
    /// the scheduler's exact transition, event-log append fails, the node
    /// generation is absent, the physical pause counter or a pending frame
    /// cannot be projected, or shared-memory transport rejects the binding.
    pub fn apply_selectable_reply(
        &mut self,
        parent: &Configuration,
        decision: SelectionDecision,
        selected: &Configuration,
        pending: &crucible_qemu::QemuNodeSelectablePendingRequest,
        reply: &crucible_protocol::SelectionReply,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        validate_selectable_reply_pairing(&decision, pending.pending(), reply)?;
        if self.pending_held_host_outcomes.is_some() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("guest reply preceded retained peer publication"),
            });
        }
        let witness = self.inner.held_host_stop_witness();
        if let Some(witness) = &witness {
            if witness.node() != pending.node()
                || witness.kind() != crucible::HeldHostStopKind::GuestSelectable
            {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from("guest reply differs from the canonical held stop"),
                });
            }
        } else if self.inner.has_unsettled_host_continuation() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "guest reply cannot bypass an unsettled physical continuation",
                ),
            });
        }
        let release = |scheduler: &mut SingleScheduler, backend: &mut QemuNodeSet| {
            let physical = backend
                .node_now(pending.node())
                .map_err(SchedulerError::Backend)?;
            let pause_tick = pending
                .pending()
                .trap_tick_ps()
                .checked_add(
                    crucible_protocol::selectable_catalog_plan::SELECTABLE_NATIVE_HANDOFF_TICKS_PS,
                )
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: String::from("guest selectable pause boundary overflowed"),
                })?;
            if physical.ticks != pause_tick {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "guest selectable physical counter {} differs from retained pause boundary {pause_tick}",
                        physical.ticks
                    ),
                });
            }
            scheduler.apply_external_selection_with_counter_rebase(
                pending.node(),
                crucible::NodeCounter {
                    ticks: physical.ticks,
                },
                parent,
                decision,
                selected,
                || {
                    backend
                        .enqueue_selectable_reply(pending, reply)
                        .map_err(SchedulerError::Backend)
                },
            )
        };
        let (append, outcomes) = if let Some(witness) = witness {
            self.inner
                .settle_held_host_stop(&witness, |scheduler, backend, _| {
                    release(scheduler, backend)
                })?
        } else {
            // Admission and restored pending requests have no concurrent RUN loan.
            let frozen = self
                .inner
                .pending_network_output_times_for_node(pending.node())?;
            let (scheduler, backend) = self.inner.parts_mut();
            let append = release(scheduler, backend)?;
            self.inner
                .retain_pending_network_output_times(pending.node(), frozen);
            (append, Vec::new())
        };
        self.retain_released_host_outcomes(selected.clone(), outcomes)?;
        Ok(append.entries)
    }

    /// Reads one VM's physical marker park for an atomic network fault boundary.
    ///
    /// # Errors
    ///
    /// Returns an error when QEMU cannot authenticate the stopped node's
    /// physical instruction count.
    pub fn parked_campaign_marker(
        &mut self,
        node: &NodeId,
    ) -> Result<Option<crucible_qemu::QemuParkedCampaignMarker>, SchedulerError> {
        Ok(self.inner.backend_mut().parked_campaign_marker(node)?)
    }

    /// Releases one VM only after its atomic network selection is committed.
    ///
    /// # Errors
    ///
    /// Returns an error when the retained park is absent, stale, or names a
    /// different phase marker.
    pub fn release_parked_campaign_marker(
        &mut self,
        node: &NodeId,
        marker: &str,
        selected: ContentHash,
    ) -> Result<(), SchedulerError> {
        let proof = self
            .inner
            .backend_mut()
            .parked_campaign_marker(node)?
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from("selected network marker park vanished before release"),
            })?;
        if proof.marker != marker {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("selected network marker phase changed before release"),
            });
        }
        self.inner
            .network_output_interceptor()
            .validate_campaign_marker_release(
                node,
                marker,
                proof.marker_icount,
                proof.physical_raw_icount,
                proof.physical_icount,
                selected,
            )?;
        if self.pending_held_host_outcomes.is_some() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("marker release preceded retained peer publication"),
            });
        }
        let witness = self.inner.held_host_stop_witness();
        if let Some(witness) = &witness {
            if witness.node() != node
                || witness.kind() != crucible::HeldHostStopKind::CampaignMarker
            {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from("marker release differs from the canonical held stop"),
                });
            }
        } else if self.inner.has_unsettled_host_continuation() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "marker release cannot bypass an unsettled physical continuation",
                ),
            });
        }
        let released_configuration = self.inner.loop_impl().configuration().clone();
        let release = |backend: &mut QemuNodeSet,
                       network: &mut ProductionFaultNetworkInterceptor| {
            // The ledger advances only after the genuine backend release succeeds.
            release_then_record_campaign_marker(
                || {
                    backend.release_parked_campaign_marker(node, marker)?;
                    Ok(())
                },
                || {
                    network.record_campaign_marker_release(
                        node,
                        marker,
                        proof.marker_icount,
                        proof.physical_raw_icount,
                        proof.physical_icount,
                        selected,
                    )
                },
            )
        };
        let outcomes = if let Some(witness) = witness {
            self.inner
                .settle_held_host_stop(&witness, |_, backend, network| release(backend, network))?
                .1
        } else {
            let (backend, network) = self.inner.backend_and_network_output_interceptor_mut();
            release(backend, network)?;
            Vec::new()
        };
        self.retain_released_host_outcomes(released_configuration, outcomes)?;
        Ok(())
    }

    fn retain_released_host_outcomes(
        &mut self,
        released_configuration: Configuration,
        outcomes: Vec<QuantumOutcome>,
    ) -> Result<(), SchedulerError> {
        let Some(last) = outcomes.last() else {
            return Ok(());
        };
        let inconsistent = last.configuration != *self.inner.loop_impl().configuration()
            || last.event_log_offset != self.inner.loop_impl().event_log_offset();
        self.pending_held_host_outcomes = Some(quantum_loop::PendingHeldHostOutcomes {
            released_configuration,
            outcomes,
            // An inconsistent physical publication must remain owned for retirement.
            publication_started: inconsistent,
        });
        if inconsistent {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "retained peer outcomes differ from the authoritative settled prefix",
                ),
            });
        }
        Ok(())
    }

    /// Rejects physical capture until retained host execution is published.
    pub(in crate::vm_lifecycle) fn require_published_host_continuation(
        &self,
    ) -> Result<(), SchedulerError> {
        if self.pending_held_host_outcomes.is_some() || self.inner.has_unsettled_host_continuation()
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "physical checkpoint cannot retain held or unpublished host RUN outcomes",
                ),
            });
        }
        Ok(())
    }
}
