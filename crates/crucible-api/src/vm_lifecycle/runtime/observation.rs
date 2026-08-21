//! Projection of lifecycle and assertion state into observable events.

use super::*;

pub(super) fn initial_node_state_events(
    source: &ScenarioDefForm,
    at: VirtualTime,
) -> Vec<ObservableEvent> {
    source
        .world()
        .vm_nodes()
        .iter()
        .map(|node| ObservableEvent::node_state(at, node.id.clone(), NodeLifecycle::Started))
        .collect()
}

pub(super) fn assertion_state_event_from_outcome(
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
