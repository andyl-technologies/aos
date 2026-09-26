//! Explorer-selected scheduler branch admission and replay choices.

use super::*;
use crate::model::{BindingSearchChoice, FaultCoordinate};
use crate::{SelectionDecision, SignalFaultCampaignBranch, SignalFaultSelectable};
use crucible_protocol::app_random_branch_plan::MAX_APP_RANDOM_BRANCH_PLAN_ENTRIES;

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
        if !self.branch_network_choices.is_empty() || !self.app_random_branch_selections.is_empty()
        {
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
        self.branch_network_choices
            .len()
            .saturating_add(self.app_random_branch_selections.len())
    }

    /// Installs authenticated app-random selections for exact branch parents.
    ///
    /// Each key is the configuration after the live seeded [`Decision::RngDraw`]
    /// and immediately before the corresponding [`Decision::Selection`]. The
    /// scheduler consumes a selection only after replay validation succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when a decision is not a
    /// campaign-branch selection or a parent is duplicated.
    pub fn install_app_random_branch_selections(
        &mut self,
        selections: impl IntoIterator<Item = (ContentHash, SelectionDecision)>,
    ) -> Result<(), SchedulerError> {
        let mut installed = BTreeMap::new();
        for (parent, selection) in selections {
            if installed.len() >= MAX_APP_RANDOM_BRANCH_PLAN_ENTRIES {
                return Err(SchedulerError::BoundaryViolation {
                    message: format!(
                        "app-random replay plan exceeds {} selections",
                        MAX_APP_RANDOM_BRANCH_PLAN_ENTRIES
                    ),
                });
            }
            if !selection.is_campaign_branch() {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from(
                        "app-random replay plan contains a non-campaign selection",
                    ),
                });
            }
            if installed.insert(parent, selection).is_some() {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from(
                        "app-random replay plan contains a duplicate branch parent",
                    ),
                });
            }
        }
        self.app_random_branch_selections = installed;
        Ok(())
    }

    /// Installs explorer-selected World-network outcomes for exact frame emissions.
    ///
    /// Each campaign selection is consumed only after the scheduler reconstructs
    /// and validates the matching live-network opportunity at the exact parent.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when a selection is not a
    /// campaign branch or duplicates an installed opportunity.
    pub fn install_branch_network_choices(
        &mut self,
        choices: Vec<SelectionDecision>,
    ) -> Result<(), SchedulerError> {
        for choice in &choices {
            if !choice.is_campaign_branch() {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from(
                        "live World-network replay input is not a campaign-branch selection",
                    ),
                });
            }
            let selection =
                choice
                    .selection()
                    .map_err(|error| SchedulerError::BoundaryViolation {
                        message: format!("live World-network replay selection is invalid: {error}"),
                    })?;
            if self
                .branch_network_choices
                .iter()
                .filter_map(|existing| existing.selection().ok())
                .any(|existing| existing.opportunity() == selection.opportunity())
            {
                return Err(SchedulerError::BoundaryViolation {
                    message: String::from(
                        "duplicate live World-network branch selection opportunity",
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

    /// Records finite signal-fault choices at their pre-evaluation boundary.
    ///
    /// Each binding choice remains a separate frontier because its candidate
    /// digest and one-shot identity have independent locked-replay semantics.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when a choice has no
    /// candidates or the supplied configuration is not the current parent.
    pub fn record_signal_fault_search_frontiers(
        &mut self,
        parent: &Configuration,
        at: VirtualTime,
        choices: &[BindingSearchChoice],
    ) -> Result<(), SchedulerError> {
        if parent != &self.configuration {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "signal-fault search frontier does not match the scheduler parent",
                ),
            });
        }
        for choice in choices.iter().filter(|choice| !choice.overridden) {
            let selectable = SignalFaultSelectable::from_binding_choice(parent, at, choice)
                .map_err(|error| SchedulerError::BoundaryViolation {
                    message: format!("invalid signal-fault search choice: {error}"),
                })?;
            let decisions = selectable.frontier_decision_sequences().map_err(|error| {
                SchedulerError::BoundaryViolation {
                    message: format!("invalid signal-fault search choice: {error}"),
                }
            })?;
            self.search_frontiers.push(SearchRuntimeFrontier {
                configuration: parent.clone(),
                at,
                choices: SearchFrontierChoices::from_decision_sequences(decisions),
            });
        }
        Ok(())
    }

    /// Records signal-fault choices whose owning device committed after the
    /// boundary evaluator ran.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] under the same conditions
    /// as [`Self::record_signal_fault_search_frontiers`].
    pub fn record_pending_signal_fault_search_frontiers(
        &mut self,
        choices: Vec<(FaultCoordinate, Vec<BindingSearchChoice>)>,
    ) -> Result<(), SchedulerError> {
        let parent = self.configuration.clone();
        for (coordinate, choices) in choices {
            self.record_signal_fault_search_frontiers(
                &parent,
                VirtualTime {
                    ticks: coordinate.virtual_ticks,
                },
                &choices,
            )?;
        }
        Ok(())
    }

    /// Records an exact continuation boundary without applying a choice.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError`] when event-log recording fails.
    pub fn append_branch_boundary(&mut self) -> Result<SchedulerEventLogAppend, SchedulerError> {
        let at = SimInstant {
            ticks: self.frontier.ticks,
        };
        let append = self.emit_quantum_event_log(&[], &[], &[], at, true)?;
        self.quanta = self.quanta.saturating_add(1);
        self.yield_to_control_inbox();
        Ok(append)
    }

    /// Appends one authenticated promoted signal-fault campaign branch.
    ///
    /// This path admits the typed campaign `Selection` and its optional
    /// producer override together.
    /// The opaque branch can only be constructed from the standardized
    /// signal-fault producer contract, and must name this scheduler's exact
    /// configuration and frontier before any decision is recorded.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when the branch names a
    /// different parent or virtual-time boundary, or when event-log recording
    /// fails.
    pub fn append_signal_fault_campaign_branch(
        &mut self,
        branch: &SignalFaultCampaignBranch,
    ) -> Result<(Configuration, SchedulerEventLogAppend), SchedulerError> {
        if self.configuration != *branch.parent() || self.frontier != branch.frontier() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "signal-fault campaign branch does not match the current scheduler boundary",
                ),
            });
        }
        let configuration = self.step_quantum(branch.decisions())?;
        if configuration != *branch.selected() {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "signal-fault campaign branch selected configuration is inconsistent",
                ),
            });
        }
        let at = SimInstant {
            ticks: self.frontier.ticks,
        };
        let append = self.emit_quantum_event_log(&[], branch.decisions(), &[], at, true)?;
        self.configuration = configuration.clone();
        self.quanta = self.quanta.saturating_add(1);
        self.yield_to_control_inbox();
        Ok((configuration, append))
    }

    /// Appends one externally resolved selection at the current scheduler boundary.
    ///
    /// Guest selectables are resolved outside the scheduler after QEMU publishes a
    /// typed pending request. This boundary authenticates the parent, the typed
    /// selection decision, and its claimed child before the scheduler advances.
    /// It records no quantum boundary because resolving a paused guest request does
    /// not consume execution progress.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerError::BoundaryViolation`] when `parent` is not the
    /// current scheduler configuration or `selected` is not the exact result of
    /// applying `decision`, when event-log append fails, or when `publish`
    /// rejects the external transport operation. A publisher error restores the
    /// exact prior event-log state before it is returned.
    ///
    /// # Panics
    ///
    /// Propagates a panic from `publish` after restoring the prior event log.
    pub fn apply_external_selection<F>(
        &mut self,
        parent: &Configuration,
        decision: SelectionDecision,
        selected: &Configuration,
        publish: F,
    ) -> Result<SchedulerEventLogAppend, SchedulerError>
    where
        F: FnOnce() -> Result<(), SchedulerError>,
    {
        if self.configuration != *parent {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "external selection parent is not the current scheduler configuration",
                ),
            });
        }

        let configuration =
            try_step(parent, Decision::Selection(decision.clone())).map_err(|source| {
                SchedulerError::BoundaryViolation {
                    message: format!("external selection violated the scenario model: {source}"),
                }
            })?;
        if configuration != *selected {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from(
                    "external selection child is inconsistent with its typed decision",
                ),
            });
        }

        let at = SimInstant {
            ticks: self
                .frontier
                .ticks
                .max(self.event_log.condition_prefix().point().at().ticks),
        };
        let previous_event_log = self.event_log.clone();
        let append =
            self.emit_quantum_event_log(&[], &[Decision::Selection(decision)], &[], at, false)?;
        match std::panic::catch_unwind(std::panic::AssertUnwindSafe(publish)) {
            Ok(Ok(())) => {}
            Ok(Err(error)) => {
                self.event_log = previous_event_log;
                return Err(error);
            }
            Err(payload) => {
                self.event_log = previous_event_log;
                std::panic::resume_unwind(payload);
            }
        }
        self.configuration = configuration;
        Ok(append)
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
                at: VirtualTime { ticks: at.ticks },
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
        scheduler_ordered_decisions(decisions, at, &preemption_times)
    }
}
