//! Exact live-network choice reservation between backend admission and a stop.

use super::*;

/// Backend evidence held after the first unselected World-network route.
#[derive(Clone, Debug)]
pub(super) struct BackendPendingPreselection {
    pub(super) choice: LiveNetworkPreselection,
    pub(super) remaining_outputs: Vec<BackendNetworkOutput>,
    /// Drained physical TX suffix left unintercepted for selected thin replay.
    pub(super) remaining_unintercepted_outputs: Vec<BackendNetworkOutput>,
    /// Future routed frames withheld with the branchable backend suffix.
    pub(super) pending_network_outputs: Vec<BackendNetworkOutput>,
    /// Previously queued observations retain ordinary post-network ordering.
    pub(super) pending_observations: Vec<ObservableEvent>,
    pub(super) rng_evidence: Vec<BackendRngEvidence>,
    /// Observations projected and stamped at their original poll boundary.
    pub(super) observations: Vec<ObservableEvent>,
    pub(super) outcome: QuantumOutcome,
    pub(super) handed_off: bool,
    pub(super) selected: Option<SelectionDecision>,
    pub(super) selected_decision_count: usize,
    pub(super) selected_event_count: usize,
}

impl<L, B, I> BackendQuantumLoop<L, B, I> {
    /// Enables an exact preselection stop for the current choice-search attempt.
    ///
    /// The backend prepares one canonical RUN at a time while this is enabled,
    /// so no other QEMU worker can advance beyond the offered parent.
    pub fn set_live_network_choice_pause(&mut self, enabled: bool) {
        self.pause_before_live_network_choice = enabled;
        if !enabled {
            self.parallel_choice_free_boot = false;
        }
    }

    /// Allows concurrent boot RUNs while retaining live-network choice interception.
    ///
    /// A choice found in a parallel batch aborts the unpublished continuation.
    /// The caller must arm ordinary single-RUN pauses before its first permitted
    /// choice boundary.
    pub fn set_choice_free_parallel_boot(&mut self, enabled: bool) {
        self.parallel_choice_free_boot = enabled && self.pause_before_live_network_choice;
    }

    /// Reports whether the caller still owns a proven choice-free boot prefix.
    #[must_use]
    pub fn choice_free_parallel_boot(&self) -> bool {
        self.parallel_choice_free_boot
    }

    /// Returns the currently offered World-network choice, if any.
    #[must_use]
    pub fn live_network_preselection(&self) -> Option<&LiveNetworkPreselection> {
        self.preselection.as_ref().map(|pending| &pending.choice)
    }

    /// Returns whether replay has committed the offered selection while its
    /// physical network suffix remains reserved.
    #[must_use]
    pub fn selected_live_network_preselection(&self) -> bool {
        self.preselection
            .as_ref()
            .is_some_and(|pending| pending.selected.is_some())
    }

    /// Poisons an unpublished reservation after its enclosing boundary fails.
    ///
    /// The withheld suffix remains owned by the unhanded reservation, so
    /// teardown rejects it rather than publishing evidence from a failed RUN.
    pub fn abort_live_network_preselection(&mut self) {
        if self.preselection.is_some() {
            self.continuation_poisoned = true;
        }
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
        if self.continuation_poisoned {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("backend continuation is poisoned"),
            });
        }
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
        self.pending_network_outputs = pending.pending_network_outputs;
        self.pending_observations = pending.pending_observations;
        let mut outcome = pending.outcome;
        if outcome.discovered_choices.pop() != Some(pending.choice.discovery.clone()) {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "live-network preselection discovery changed before default settlement",
                ),
            });
        }
        let (decisions, discoveries, configuration, append) = match &pending.selected {
            Some(selection) => self
                .loop_impl
                .append_backend_network_outputs_after_selection(
                    pending.remaining_outputs,
                    &pending.choice.parent,
                    selection,
                )?,
            None => self
                .loop_impl
                .append_backend_network_outputs(pending.remaining_outputs)?,
        };
        let opportunity = pending
            .choice
            .discovery
            .opportunity()
            .id()
            .map_err(|error| SchedulerError::BoundaryViolation {
                message: format!("reserved live-network opportunity is invalid: {error}"),
            })?;
        if pending.selected.is_none()
            && (discoveries.first() != Some(&pending.choice.discovery)
                || !decisions.iter().any(|decision| {
                    matches!(decision, Decision::Selection(selection)
                    if selection.selection().is_ok_and(|selection| {
                        selection.opportunity() == opportunity
                            && selection.origin() == crucible_campaign::SelectionOrigin::Default
                    }))
                }))
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
        self.pending_observations.extend(pending.observations);
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
        if pending.selected.is_some() {
            outcome.decisions.drain(..pending.selected_decision_count);
            outcome
                .event_log_entries
                .drain(..pending.selected_event_count);
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
        if self.continuation_poisoned {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("backend continuation is poisoned"),
            });
        }
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

impl<B, I> BackendQuantumLoop<SingleScheduler, B, I> {
    /// Commits one authenticated branch selection while retaining its emitted
    /// frame and the physical RUN suffix for the next scheduler operation.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] if the selection is not an offered branch at
    /// this exact parent or the reservation has already been consumed.
    pub fn select_live_network_preselection(
        &mut self,
        selection: SelectionDecision,
    ) -> Result<SchedulerEventLogAppend, SchedulerError> {
        let pending =
            self.preselection
                .as_mut()
                .ok_or_else(|| SchedulerError::BoundaryViolation {
                    message: String::from("no live-network preselection can be selected"),
                })?;
        if pending.handed_off
            || pending.selected.is_some()
            || !pending
                .choice
                .frontier
                .choices
                .choices()
                .iter()
                .any(|choice| {
                    choice.decisions().first() == Some(&Decision::Selection(selection.clone()))
                })
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "replay selection differs from the reserved live-network offer",
                ),
            });
        }

        let parent = &pending.choice.parent;
        let selected =
            try_step(parent, Decision::Selection(selection.clone())).map_err(|source| {
                SchedulerError::BoundaryViolation {
                    message: format!(
                        "reserved live-network selection violates the scenario: {source}"
                    ),
                }
            })?;
        let append = self.loop_impl.apply_external_selection(
            parent,
            selection.clone(),
            &selected,
            || Ok(()),
        )?;
        pending.outcome.configuration = selected;
        pending
            .outcome
            .decisions
            .push(Decision::Selection(selection.clone()));
        append_to_outcome(&mut pending.outcome, append.clone());
        pending.selected_decision_count = pending.outcome.decisions.len();
        pending.selected_event_count = pending.outcome.event_log_entries.len();
        pending.selected = Some(selection);
        Ok(append)
    }
}

pub(super) fn append_to_outcome(outcome: &mut QuantumOutcome, append: SchedulerEventLogAppend) {
    outcome.event_log_entries.extend(append.entries);
    outcome.event_log_segment_bytes = append.segment_bytes;
    outcome.event_log_segment_text = append.segment_text;
    outcome.event_log_segment_hash = append.segment_hash;
    outcome.event_log_offset = append.offset;
}
