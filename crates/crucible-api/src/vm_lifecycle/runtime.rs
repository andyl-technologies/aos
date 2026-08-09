//! Runtime observation and trigger settlement for production VM lifecycles.

use super::*;

impl ProductionVmLifecycleLoop {
    /// Returns the number of QEMU processes currently owned by this lifecycle.
    #[must_use]
    pub fn live_node_count(&self) -> usize {
        self.inner.backend().len()
    }

    pub(super) fn settle_trigger_graph(
        &mut self,
    ) -> Result<Vec<SchedulerEventLogAppend>, SchedulerError> {
        let mut appends = Vec::new();
        for _ in 0..MAX_TRIGGER_SETTLE_BATCHES {
            let assertion_outcomes = self.assertion_evaluator.observe_prefix(
                self.inner.loop_impl().condition_event_log_prefix(),
                &mut self.assertion_oracle,
            );
            let assertion_events = assertion_outcomes
                .iter()
                .filter_map(assertion_state_event_from_outcome)
                .collect::<Vec<_>>();
            let assertions_changed = !assertion_events.is_empty();
            if assertions_changed {
                appends.push(
                    self.inner
                        .loop_impl_mut()
                        .append_observable_events(assertion_events)?,
                );
            }

            let scheduler = self.inner.loop_impl();
            let mut pass = ConditionEvaluationPass::from_log_prefix(
                scheduler.condition_event_log_prefix().clone(),
                no_named_trigger_leaf,
            )
            .with_timer_fires(scheduler.trigger_actions().armed_timers.clone())
            .with_scheduler_quiescence(scheduler.quiescence()?)
            .with_world_white_box_policies(&self.trigger_world);
            let firings = pass.evaluate_event_graph(&self.trigger_graph, &mut self.trigger_state);
            if firings.is_empty() && !assertions_changed {
                return Ok(appends);
            }
            if !firings.is_empty() {
                merge_terminal_verdict(&mut self.terminal_verdict, &firings);
                let append = self.inner.loop_impl_mut().apply_trigger_firings(&firings)?;
                appends.push(append);
                self.inner
                    .loop_impl_mut()
                    .apply_queued_topology_changes_at_boundary()?;
            }
        }
        Err(SchedulerError::BoundaryViolation {
            message: format!(
                "trigger graph did not settle within {MAX_TRIGGER_SETTLE_BATCHES} batches"
            ),
        })
    }
}

fn assertion_state_event_from_outcome(outcome: &HostAssertionOutcome) -> Option<ObservableEvent> {
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
