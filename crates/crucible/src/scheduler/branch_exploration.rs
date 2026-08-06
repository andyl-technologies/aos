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
        if !self.branch_fault_choices.is_empty() || !self.branch_network_choices.is_empty() {
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
        for sub_nodes in self.device_sub_nodes.values_mut() {
            for sub_node in sub_nodes {
                sub_node.reseed_future_decisions(seed);
            }
        }
        Ok(())
    }

    /// Installs explorer-selected probabilistic fault outcomes for exact RESOLVE points.
    ///
    /// Decisions must be supplied as adjacent `RngDraw`, `FaultFires` pairs.
    /// Each pair is consumed only when the authoritative scheduler reaches the
    /// matching fault, virtual time, and RNG stream.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when the decision sequence
    /// is not made exclusively of adjacent RNG/fault pairs or contains a
    /// duplicate fault resolution point.
    pub fn install_branch_fault_choices(
        &mut self,
        decisions: Vec<Decision>,
    ) -> Result<(), SchedulerError> {
        let mut chunks = decisions.chunks_exact(2);
        let mut choices = Vec::new();
        for pair in &mut chunks {
            let (Decision::RngDraw(draw), Decision::FaultFires(fault)) = (&pair[0], &pair[1])
            else {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from(
                        "branch fault choices must be adjacent RngDraw/FaultFires pairs",
                    ),
                });
            };
            if choices.iter().any(
                |(existing_draw, existing_fault): &(RngDecision, FaultDecision)| {
                    existing_draw.stream == draw.stream
                        && existing_fault.at == fault.at
                        && existing_fault.fault == fault.fault
                },
            ) {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "duplicate branch fault choice for {} at {}",
                        fault.fault.name, fault.at.ticks
                    ),
                });
            }
            choices.push((draw.clone(), fault.clone()));
        }
        if !chunks.remainder().is_empty() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "branch fault choices must contain complete RngDraw/FaultFires pairs",
                ),
            });
        }
        self.branch_fault_choices = choices;
        Ok(())
    }

    /// Returns the number of installed branch fault choices not yet resolved.
    #[must_use]
    pub fn pending_branch_fault_choice_count(&self) -> usize {
        self.branch_fault_choices
            .len()
            .saturating_add(self.branch_network_choices.len())
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

    /// Returns probabilistic RESOLVE frontiers captured in execution order.
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

    pub(super) fn apply_branch_fault_choices(
        &mut self,
        resolved_events: &[ScheduledEvent],
        decisions: &mut [Decision],
    ) -> Result<(), SchedulerError> {
        if self.branch_fault_choices.is_empty() {
            return Ok(());
        }
        let mut decision_offset = 0;
        for event in ordered_scheduled_events(resolved_events) {
            let ScheduledEventPayload::ProbabilisticFault(choice) = &event.payload else {
                continue;
            };
            let Some(default_pair) = decisions.get(decision_offset..decision_offset + 2) else {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from(
                        "probabilistic RESOLVE did not produce one RNG/fault decision pair",
                    ),
                });
            };
            if !matches!(
                default_pair,
                [Decision::RngDraw(_), Decision::FaultFires(_)]
            ) {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from(
                        "probabilistic RESOLVE decision pair has an unexpected shape",
                    ),
                });
            }
            if let Some(index) = self.branch_fault_choices.iter().position(|(draw, fault)| {
                draw.stream == choice.stream
                    && fault.at == event.key.virtual_time()
                    && fault.fault == choice.fault
            }) {
                let (draw, fault) = self.branch_fault_choices.remove(index);
                if choice.rate.fires_on_draw(draw.value) != fault.fired {
                    return Err(SchedulerError::BoundaryViolation {
                        message: format!(
                            "branch fault choice for {} at {} is inconsistent with its RNG draw",
                            fault.fault.name, fault.at.ticks
                        ),
                    });
                }
                decisions[decision_offset] = Decision::RngDraw(draw);
                decisions[decision_offset + 1] = Decision::FaultFires(fault);
            }
            decision_offset += 2;
        }
        Ok(())
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
            let branch_configuration = self.step_quantum(&decisions);
            let choices = search_frontier_choices_from_scheduled_events(
                branch_configuration.clone(),
                resolved_events,
            );
            if !choices.is_empty() {
                self.search_frontiers.push(SearchRuntimeFrontier {
                    configuration: branch_configuration,
                    at: VirtualTime { ticks: at.nanos },
                    choices,
                });
            }
            let mut probabilistic = resolve_probabilistic_decisions_from_seed(
                self.configuration.clone(),
                resolved_events,
                self.decision_seed,
                &self.decision_rng_cursor,
            );
            self.apply_branch_fault_choices(resolved_events, &mut probabilistic.decisions)?;
            for decision in &probabilistic.decisions {
                if let Decision::RngDraw(draw) = decision {
                    self.advance_decision_rng_cursor_for(draw.stream.clone());
                }
            }
            decisions.extend(probabilistic.decisions);
        }
        let network_decisions = std::mem::take(&mut self.world_network_decisions);
        for decision in &network_decisions {
            if let Decision::RngDraw(draw) = decision {
                self.advance_decision_rng_cursor_for(draw.stream.clone());
            }
        }
        decisions.extend(network_decisions);

        // Device I/O completions drew their fault decisions (RngDraw + FaultFires)
        // at COMPUTE and buffered them; they are appended on the LIVE RESOLVE path
        // in delivery order ([SCHED-30]). Each device RngDraw advances the owning
        // stream's decision-RNG cursor exactly as a probabilistic RESOLVE draw does.
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
