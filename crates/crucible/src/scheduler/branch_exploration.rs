//! Explorer-selected scheduler branch admission and replay choices.

use super::*;

impl SingleScheduler {
    /// Returns the seed that owns every future authoritative decision stream.
    #[must_use]
    pub const fn future_decision_seed(&self) -> Seed {
        self.decision_seed
    }

    /// Returns the authoritative future decision-stream cursors.
    #[must_use]
    pub const fn future_decision_rng_state(&self) -> &DecisionRngState {
        &self.decision_rng_cursor
    }

    /// Re-seeds every future authoritative decision stream at a branch boundary.
    ///
    /// The recorded configuration prefix remains unchanged. Scheduler, World
    /// network, app-random, and block/9p streams restart from cursor zero;
    /// already-resolved device completions remain frozen as prefix state.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when explorer-selected
    /// branch choices or uncommitted World-network decisions are pending.
    pub fn reseed_future_decisions(&mut self, seed: Seed) -> Result<(), SchedulerError> {
        if !self.branch_network_choices.is_empty() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "cannot re-seed while explicit scheduler branch choices are pending",
                ),
            });
        }
        if !self.world_network_decisions.is_empty() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("cannot re-seed while World-network decisions await commit"),
            });
        }
        self.decision_seed = seed;
        self.decision_rng_cursor = DecisionRngState::empty();
        for position in self.world_network_rng_positions.values_mut() {
            *position = 0;
        }
        Ok(())
    }

    /// Returns the number of installed branch effect choices not yet resolved.
    #[must_use]
    pub fn pending_branch_effect_choice_count(&self) -> usize {
        self.branch_network_choices.len()
    }

    /// Installs explorer-selected World-network outcomes for exact frame emissions.
    ///
    /// Only overrides created by the scheduler's live network frontier are
    /// accepted. Each override is consumed at the matching link, frame, stream
    /// cursor, and source boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when an override does not
    /// name a live World-network choice or duplicates an installed point.
    pub fn install_branch_network_choices(
        &mut self,
        choices: Vec<OverrideDecision>,
    ) -> Result<(), SchedulerError> {
        for choice in &choices {
            if !choice.point.key.starts_with("live-world-network/")
                || !liveness::is_live_network_branch_choice_name(&choice.choice.name)
            {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "unsupported live World-network branch choice `{}` at `{}`",
                        choice.choice.name, choice.point.key
                    ),
                });
            }
            if self
                .branch_network_choices
                .iter()
                .any(|existing| existing.point == choice.point)
            {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "duplicate live World-network branch point `{}`",
                        choice.point.key
                    ),
                });
            }
        }
        self.branch_network_choices = choices;
        Ok(())
    }

    /// Returns live World-network frontiers captured in execution order.
    #[must_use]
    pub fn search_frontiers(&self) -> &[SearchRuntimeFrontier] {
        &self.search_frontiers
    }

    /// Appends explorer-selected override decisions at the current boundary.
    ///
    /// This admission path is intentionally narrower than normal scheduler
    /// resolution. It accepts only [`Decision::Override`] values, records them
    /// in the authoritative configuration and event log, and does not advance a
    /// backend node. Concrete fault, delivery, RNG, and preemption choices must
    /// still be resolved by their owning scheduler paths.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when any supplied decision
    /// is not an explorer override, or when event-log recording fails.
    pub fn append_branch_prefix_overrides(
        &mut self,
        decisions: Vec<Decision>,
    ) -> Result<(Configuration, SchedulerEventLogAppend), SchedulerError> {
        if decisions
            .iter()
            .any(|decision| !matches!(decision, Decision::Override(_)))
        {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "branch-prefix admission accepts only explorer override decisions",
                ),
            });
        }
        let configuration = self.step_quantum(&decisions);
        let at = SimInstant {
            nanos: self.frontier.ticks,
        };
        let append = self.emit_quantum_event_log(&[], &decisions, &[], at, true)?;
        self.configuration = configuration.clone();
        self.quanta = self.quanta.saturating_add(1);
        self.yield_to_control_inbox();
        Ok((configuration, append))
    }

    pub(super) fn emit_quantum_decisions(
        &mut self,
        resolved_events: &[ScheduledEvent],
        preemptions: &[PlannedPreemptionApplication],
        device_decisions: &[Decision],
        at: SimInstant,
    ) -> Result<Vec<Decision>, SchedulerError> {
        let mut decisions = Vec::new();
        if !resolved_events.is_empty() {
            let decision = Decision::DeliveryOrder(DeliveryOrderDecision {
                at: VirtualTime { ticks: at.nanos },
                order: resolved_events
                    .iter()
                    .map(|event| EventKey {
                        virtual_time: event.key.virtual_time(),
                        consumer: event.key.consumer().clone(),
                        producer: event.key.producer().clone(),
                        sequence: event.key.sequence(),
                    })
                    .collect(),
            });
            decisions.push(decision);
        }
        let network_decisions = std::mem::take(&mut self.world_network_decisions);
        for decision in &network_decisions {
            if let Decision::RngDraw(draw) = decision {
                self.advance_decision_rng_cursor_for(draw.stream.clone());
            }
        }
        decisions.extend(network_decisions);

        // Device I/O completions may carry deterministic raw draws. Each draw
        // advances the owning stream cursor when it becomes visible.
        for decision in device_decisions {
            if let Decision::RngDraw(draw) = decision {
                self.advance_decision_rng_cursor_for(draw.stream.clone());
            }
        }
        decisions.extend(device_decisions.iter().cloned());
        decisions.extend(
            preemptions
                .iter()
                .map(|application| Decision::Preemption(application.decision.clone())),
        );
        let preemption_times = preemption_event_times(preemptions);
        scheduler_ordered_decisions(decisions, at, self.timeline.shift(), &preemption_times)
    }
}
