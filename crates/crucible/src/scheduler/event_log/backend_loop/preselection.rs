//! Exact live-network choice reservation between backend admission and a stop.

use super::*;

/// Backend evidence held after the first unselected World-network route.
#[derive(Clone, Debug)]
pub(super) struct BackendPendingPreselection {
    pub(super) choice: LiveNetworkPreselection,
    pub(super) remaining_outputs: Vec<BackendNetworkOutput>,
    /// Drained physical TX suffix left unintercepted for selected thin replay.
    pub(super) remaining_unintercepted_outputs: Vec<BackendNetworkOutput>,
    pub(super) rng_evidence: Vec<BackendRngEvidence>,
    pub(super) observations: Vec<ObservableEvent>,
    pub(super) outcome: QuantumOutcome,
    pub(super) handed_off: bool,
}

impl<L, B, I> BackendQuantumLoop<L, B, I> {
    /// Enables an exact preselection stop for the current choice-search attempt.
    ///
    /// The backend prepares one canonical RUN at a time while this is enabled,
    /// so no other QEMU worker can advance beyond the offered parent.
    pub fn set_live_network_choice_pause(&mut self, enabled: bool) {
        self.pause_before_live_network_choice = enabled;
    }

    /// Returns the currently offered World-network choice, if any.
    #[must_use]
    pub fn live_network_preselection(&self) -> Option<&LiveNetworkPreselection> {
        self.preselection.as_ref().map(|pending| &pending.choice)
    }
}

impl<L, B, I> BackendQuantumLoop<L, B, I>
where
    L: QuantumLoop,
    B: SimulationBackend,
    I: BackendNetworkOutputInterceptor<L, B>,
{
    /// Resolves the reserved frame through the ordinary default path.
    ///
    /// A higher-priority terminal or budget stop calls this before it seals its
    /// observation, preserving the same decision order as an uninterrupted RUN.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] if the reservation changed or the remaining
    /// network and backend evidence cannot be committed exactly.
    pub fn settle_live_network_preselection(&mut self) -> Result<QuantumOutcome, SchedulerError> {
        let pending =
            self.preselection
                .take()
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: String::from("no live-network preselection is pending"),
                })?;
        let result = self.settle_live_network_preselection_inner(pending);
        result.map_err(|error| self.poison_continuation(error))
    }

    fn settle_live_network_preselection_inner(
        &mut self,
        pending: BackendPendingPreselection,
    ) -> Result<QuantumOutcome, SchedulerError> {
        let mut outcome = pending.outcome;
        if outcome.discovered_choices.pop() != Some(pending.choice.discovery.clone()) {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "live-network preselection discovery changed before default settlement",
                ),
            });
        }
        let (decisions, discoveries, configuration, append) = self
            .loop_impl
            .append_backend_network_outputs(pending.remaining_outputs)?;
        let opportunity = pending
            .choice
            .discovery
            .opportunity()
            .id()
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!("reserved live-network opportunity is invalid: {error}"),
            })?;
        if discoveries.first() != Some(&pending.choice.discovery)
            || !decisions.iter().any(|decision| {
                matches!(decision, Decision::Selection(selection)
                if selection.selection().is_ok_and(|selection| {
                    selection.opportunity() == opportunity
                        && selection.origin() == crucible_campaign::SelectionOrigin::Default
                }))
            })
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "live-network default did not resolve its reserved opportunity",
                ),
            });
        }
        outcome.decisions.extend(decisions);
        outcome.discovered_choices.extend(discoveries);
        outcome.configuration = configuration;
        append_to_outcome(&mut outcome, append);

        for output in pending.remaining_unintercepted_outputs {
            let mut outputs = vec![output];
            let appends = self.network_output_interceptor.intercept_network_outputs(
                &mut self.loop_impl,
                &mut self.backend,
                outcome.frontier,
                &mut self.pending_network_outputs,
                &mut outputs,
            )?;
            for append in appends {
                append_to_outcome(&mut outcome, append);
            }
            if outputs.is_empty() {
                continue;
            }
            let (decisions, discoveries, configuration, append) =
                self.loop_impl.append_backend_network_outputs(outputs)?;
            outcome.decisions.extend(decisions);
            outcome.discovered_choices.extend(discoveries);
            outcome.configuration = configuration;
            append_to_outcome(&mut outcome, append);
        }

        if !pending.rng_evidence.is_empty() {
            let (decisions, discoveries, configuration, append) = self
                .loop_impl
                .append_backend_rng_evidence(pending.rng_evidence)?;
            outcome.decisions.extend(decisions);
            outcome.discovered_choices.extend(discoveries);
            outcome.configuration = configuration;
            append_to_outcome(&mut outcome, append);
        }
        let observations = pending
            .observations
            .into_iter()
            .map(|event| {
                let Some(node) = event.backend_node() else {
                    return Ok(event);
                };
                let at = self.loop_impl.backend_observation_time(node, event.at())?;
                Ok(event.with_scheduler_time(at))
            })
            .collect::<Result<Vec<_>, SchedulerError>>()?;
        self.pending_observations.extend(observations);
        self.pending_observations.sort_by_key(ObservableEvent::at);
        let committed = self
            .pending_observations
            .partition_point(|event| event.at().ticks <= outcome.frontier.ticks);
        let observations = self
            .pending_observations
            .drain(..committed)
            .collect::<Vec<_>>();
        if !observations.is_empty() {
            let append = self
                .loop_impl
                .append_backend_observations_at_boundary(observations, outcome.frontier)?;
            append_to_outcome(&mut outcome, append);
        }
        Ok(outcome)
    }

    /// Authenticates a preselection observation and reserves it for teardown.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when the requested choice or parent does not
    /// match the pending frame, or unrelated backend outputs remain pending.
    pub fn handoff_live_network_preselection(
        &mut self,
        expected: &LiveNetworkPreselection,
    ) -> Result<(), SchedulerError> {
        let pending =
            self.preselection
                .as_mut()
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: String::from("no live-network preselection can be handed off"),
                })?;
        if pending.choice != *expected
            || pending.handed_off
            || !self.pending_network_outputs.is_empty()
            || !self.pending_observations.is_empty()
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "live-network preselection handoff disagrees with the exact boundary",
                ),
            });
        }
        pending.handed_off = true;
        Ok(())
    }

    pub(super) fn shutdown_preselection(
        &mut self,
    ) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        // No exact checkpoint may capture this reservation. The offered branch
        // reruns an admitted ancestor and regenerates this withheld TX suffix.
        let pending =
            self.preselection
                .take()
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: String::from("preselection shutdown has no reservation"),
                })?;
        let outputs = self.backend.drain_network_outputs();
        let rng_evidence = self.backend.drain_rng_evidence();
        let observations = self.backend.drain_observable_events();
        let loop_result = self.loop_impl.shutdown();
        let backend_result = self.backend.shutdown().map_err(SchedulerError::from);

        let outputs = outputs.map_err(SchedulerError::from)?;
        let rng_evidence = rng_evidence.map_err(SchedulerError::from)?;
        let observations = observations.map_err(SchedulerError::from)?;
        let loop_entries = loop_result?;
        backend_result?;
        if !pending.handed_off
            || !self.pending_network_outputs.is_empty()
            || !self.pending_observations.is_empty()
            || !outputs.is_empty()
            || !rng_evidence.is_empty()
            || !observations.is_empty()
            || !loop_entries.is_empty()
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "live-network preselection teardown has unhanded or unrelated evidence",
                ),
            });
        }
        Ok(Vec::new())
    }
}

fn append_to_outcome(outcome: &mut QuantumOutcome, append: SchedulerEventLogAppend) {
    outcome.event_log_entries.extend(append.entries);
    outcome.event_log_segment_bytes = append.segment_bytes;
    outcome.event_log_segment_text = append.segment_text;
    outcome.event_log_segment_hash = append.segment_hash;
    outcome.event_log_offset = append.offset;
}
