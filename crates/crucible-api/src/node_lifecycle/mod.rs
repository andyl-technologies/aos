//! Shared world trigger settlement and debugger boundary orchestration.
//!
//! [`WorldTriggerLifecycle`] borrows the authoritative scheduler and trigger state
//! for one control boundary. It owns no native processes, simulator callbacks,
//! launch inputs, restore permissions, leases or cleanup authority. Native adapters
//! provide ordered initial observations and retain realization and capture custody.
//! [`DebuggerListenerPolicy`] validates gateway listener requests independently
//! of the implementation's debugger transport.

use crucible::{
    Action, AssertionPhase, BlackBoxHostOracle, ConditionEvaluationPass, ConditionLeaf,
    EventFirings, EventGraph, EventGraphState, HostAssertionEvaluator, HostAssertionOutcome,
    HostAssertionOutcomeKind, ObservableEvent, QuantumTerminalVerdict, SchedulerError,
    SchedulerEventLogAppend, SingleScheduler, VirtualTime, World,
};

mod debug_evidence;
mod debugger;

pub(crate) use debug_evidence::RecordedDebugBoundary;
pub use debugger::DebuggerListenerPolicy;

const MAX_TRIGGER_SETTLE_BATCHES: usize = 1_024;

/// Borrows the world-owned continuation used for trigger settlement.
///
/// These are references to existing authoritative fields, not a second state
/// copy. The caller must supply the graph, world and assertion continuation of
/// the scheduler's admitted scenario.
pub struct WorldTriggerState<'a> {
    /// Admitted authored trigger graph.
    pub trigger_graph: &'a EventGraph,
    /// Original trigger firing and deadline continuation.
    pub trigger_state: &'a mut EventGraphState,
    /// Admitted world metadata and observation policies.
    pub trigger_world: &'a World,
    /// Original host assertion evaluation continuation.
    pub assertion_evaluator: &'a mut HostAssertionEvaluator,
    /// Original host assertion observation oracle.
    pub assertion_oracle: &'a mut BlackBoxHostOracle,
    /// Original modeled terminal verdict.
    pub terminal_verdict: &'a mut Option<QuantumTerminalVerdict>,
    /// Original pending-initial-observations flag preserved by checkpoints.
    pub initial_lifecycle_observations_pending: &'a mut bool,
}

/// Settles world semantics without acquiring native materialization authority.
pub struct WorldTriggerLifecycle<'a> {
    scheduler: &'a mut SingleScheduler,
    state: WorldTriggerState<'a>,
}

impl<'a> WorldTriggerLifecycle<'a> {
    /// Borrows one admitted scheduler and its original world continuation.
    pub fn new(scheduler: &'a mut SingleScheduler, state: WorldTriggerState<'a>) -> Self {
        Self { scheduler, state }
    }

    fn terminal_settlement_target(&self) -> Option<VirtualTime> {
        terminal_settlement_target(
            self.state.trigger_graph,
            self.state.trigger_state,
            self.state.terminal_verdict.as_ref(),
        )
    }

    /// Reports whether the shared frontier has settled the terminal trigger.
    pub fn terminal_stop_ready(&self) -> bool {
        self.state.terminal_verdict.is_some()
            && self
                .terminal_settlement_target()
                .is_some_and(|at| self.scheduler.frontier() >= at)
    }

    /// Settles authored entrypoints before initial node observations.
    ///
    /// # Errors
    ///
    /// Returns an error if the pending initial prefix is no longer genesis, or
    /// scheduler quiescence, trigger effects or topology settlement fail.
    pub fn settle_genesis_entrypoints(
        &mut self,
    ) -> Result<Option<SchedulerEventLogAppend>, SchedulerError> {
        if !*self.state.initial_lifecycle_observations_pending {
            return Ok(None);
        }
        // Initial node-state and fault observations turn the prefix into an
        // event boundary. Entrypoints must run first; conditional events still
        // wait for the ordinary pass over those initial observations.
        let entrypoints = EventGraph::new_for_world(
            self.state
                .trigger_graph
                .events()
                .iter()
                .filter(|event| event.trigger.is_none())
                .cloned()
                .collect(),
            self.state.trigger_world,
        )
        .map_err(|error| SchedulerError::BoundaryViolation {
            message: format!("isolate initial trigger entrypoints: {error}"),
        })?;
        if entrypoints.events().is_empty() {
            return Ok(None);
        }
        let scheduler = &*self.scheduler;
        let prefix = scheduler.condition_event_log_prefix();
        if prefix.point().kind() != crucible::EventEvaluationKind::Genesis {
            return Err(SchedulerError::BoundaryViolation {
                message: String::from("initial trigger entrypoints lost their genesis boundary"),
            });
        }
        let mut pass = ConditionEvaluationPass::from_log_prefix_ref(prefix, no_named_trigger_leaf)
            .with_timer_fires(scheduler.trigger_actions().armed_timers.clone())
            .with_scheduler_quiescence(scheduler.quiescence()?)
            .with_world_white_box_policies(self.state.trigger_world);
        let firings = pass.evaluate_event_graph(&entrypoints, self.state.trigger_state);
        if firings.is_empty() {
            return Ok(None);
        }
        merge_terminal_verdict(self.state.terminal_verdict, &firings);
        let append = self.scheduler.apply_trigger_firings(&firings)?;
        self.scheduler.apply_queued_topology_changes_at_boundary()?;
        Ok(Some(append))
    }

    /// Settles initial observations, assertions and trigger firings at the boundary.
    ///
    /// The adapter supplies initial observations in its existing canonical node
    /// order. The callback runs only while initial observations remain pending.
    /// Restored trigger state reconstructs wakeup deadlines before evaluation.
    ///
    /// # Errors
    ///
    /// Returns an error for inconsistent terminal evidence, invalid scheduler
    /// effects or deadlines, or failure to settle within the bounded batch count.
    pub fn settle_trigger_graph(
        &mut self,
        initial_events: impl FnOnce(VirtualTime) -> Vec<ObservableEvent>,
    ) -> Result<Vec<SchedulerEventLogAppend>, SchedulerError> {
        let mut appends = Vec::new();
        if *self.state.initial_lifecycle_observations_pending {
            let at = self.scheduler.frontier();
            let initial_events = initial_events(at);
            appends.push(self.scheduler.append_observable_events(initial_events)?);
            *self.state.initial_lifecycle_observations_pending = false;
        }
        for _ in 0..MAX_TRIGGER_SETTLE_BATCHES {
            // Rebuild this derived horizon from restored/settled authority before
            // quiescence evaluation. In particular, a consumed deadline must not
            // remain a stale blocker, and a newly armed timer must cap the next RUN.
            let scheduler = &*self.scheduler;
            let (wakeup, activation) = if self.state.terminal_verdict.is_some() {
                let target = self.terminal_settlement_target().ok_or_else(|| {
                    SchedulerError::BoundaryViolation {
                        message: String::from(
                            "terminal verdict has no checkpointed trigger firing",
                        ),
                    }
                })?;
                let wakeup = (target > scheduler.frontier()).then_some(target);
                // A terminal pulse from a leading node is observable before the
                // shared frontier reaches it. Keep the scheduler capped at that
                // point until earlier network outputs are committed.
                (wakeup, None)
            } else {
                let wakeup = self.state.trigger_state.next_evaluation_deadline(
                    self.state.trigger_graph,
                    &scheduler.trigger_actions().armed_timers,
                    scheduler.frontier(),
                )?;
                let activation = self.state.trigger_state.next_activation_deadline(
                    self.state.trigger_graph,
                    &scheduler.trigger_actions().armed_timers,
                    scheduler.frontier(),
                )?;
                (wakeup, activation)
            };
            self.scheduler.set_trigger_wakeup(wakeup, activation)?;
            if self.state.terminal_verdict.is_some() {
                return Ok(appends);
            }
            let assertion_outcomes = self.state.assertion_evaluator.observe_prefix(
                self.scheduler.condition_event_log_prefix(),
                self.state.assertion_oracle,
            );
            let assertion_events = assertion_outcomes
                .iter()
                .filter_map(assertion_state_event_from_outcome)
                .collect::<Vec<_>>();
            let assertions_changed = !assertion_events.is_empty();
            if assertions_changed {
                appends.push(self.scheduler.append_observable_events(assertion_events)?);
            }

            let scheduler = &*self.scheduler;
            let mut pass = ConditionEvaluationPass::from_log_prefix_ref(
                scheduler.condition_event_log_prefix(),
                no_named_trigger_leaf,
            )
            .with_timer_fires(scheduler.trigger_actions().armed_timers.clone())
            .with_scheduler_quiescence(scheduler.quiescence()?)
            .with_world_white_box_policies(self.state.trigger_world);
            let firings = pass.evaluate_event_graph_at_frontier(
                self.state.trigger_graph,
                self.state.trigger_state,
                scheduler.frontier(),
            );
            if firings.is_empty() && !assertions_changed {
                return Ok(appends);
            }
            if !firings.is_empty() {
                merge_terminal_verdict(self.state.terminal_verdict, &firings);
                let append = self.scheduler.apply_trigger_firings(&firings)?;
                appends.push(append);
                self.scheduler.apply_queued_topology_changes_at_boundary()?;
            }
        }
        Err(SchedulerError::BoundaryViolation {
            message: format!(
                "trigger graph did not settle within {MAX_TRIGGER_SETTLE_BATCHES} batches"
            ),
        })
    }
}

pub(crate) fn terminal_settlement_target(
    graph: &EventGraph,
    state: &EventGraphState,
    terminal_verdict: Option<&QuantumTerminalVerdict>,
) -> Option<VirtualTime> {
    terminal_verdict?;

    graph
        .events()
        .iter()
        .filter_map(|event| {
            let mut passed = false;
            let mut violations = Vec::new();
            collect_terminal_actions(&event.action, &mut passed, &mut violations);
            (passed || !violations.is_empty())
                .then(|| state.last_firing(&event.id))
                .flatten()
        })
        .max()
}

pub(crate) fn no_named_trigger_leaf(_leaf: ConditionLeaf<'_>) -> bool {
    false
}

pub(crate) fn merge_terminal_verdict(
    terminal_verdict: &mut Option<QuantumTerminalVerdict>,
    firings: &EventFirings,
) {
    let mut passed = false;
    let mut violations = Vec::new();
    for firing in firings.iter() {
        collect_terminal_actions(firing.action(), &mut passed, &mut violations);
    }
    match (passed, violations.is_empty()) {
        (_, false) => match terminal_verdict {
            Some(QuantumTerminalVerdict::Failed(existing)) => existing.extend(violations),
            _ => *terminal_verdict = Some(QuantumTerminalVerdict::Failed(violations)),
        },
        (true, true) if terminal_verdict.is_none() => {
            *terminal_verdict = Some(QuantumTerminalVerdict::Passed);
        }
        _ => {}
    }
}

pub(crate) fn collect_terminal_actions(
    action: &Action,
    passed: &mut bool,
    violations: &mut Vec<String>,
) {
    match action {
        Action::Pass => *passed = true,
        Action::Fail { reason } => violations.push(reason.clone()),
        Action::Group(actions) => {
            for action in actions {
                collect_terminal_actions(action, passed, violations);
            }
        }
        Action::ArmTimer { .. }
        | Action::CancelTimer { .. }
        | Action::StartNode { .. }
        | Action::StopNode { .. }
        | Action::CreateSavepoint { .. }
        | Action::Fork { .. }
        | Action::Log { .. } => {}
    }
}

pub(crate) fn assertion_state_event_from_outcome(
    outcome: &HostAssertionOutcome,
) -> Option<ObservableEvent> {
    let state = match outcome.kind {
        HostAssertionOutcomeKind::Satisfied => AssertionPhase::Satisfied,
        HostAssertionOutcomeKind::Violated => AssertionPhase::Violated,
        HostAssertionOutcomeKind::Passed
        | HostAssertionOutcomeKind::Warning
        | HostAssertionOutcomeKind::NeverEvaluated
        | HostAssertionOutcomeKind::NeverTriggered
        | HostAssertionOutcomeKind::NeverReachedWarn
        | HostAssertionOutcomeKind::NeverReachedFail => return None,
    };
    Some(ObservableEvent::assertion_state_changed(
        outcome.at,
        outcome.assertion.clone(),
        state,
    ))
}

#[cfg(test)]
mod tests;
