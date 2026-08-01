// crucible-lint: allow rust-allow -- shared test builders intentionally expose more helpers than each test uses.
#![allow(dead_code)]

use crucible::{
    ConditionEvaluationPass, ConditionEventLogPrefix, ConditionLeafOracle, EventFirings,
    EventGraph, EventGraphState, ObservableEvent, SchedulerEventLogEntry, VirtualTime,
};

pub fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

pub fn quantum_prefix(ticks: u64) -> ConditionEventLogPrefix {
    crucible::test_support::condition_prefix_at_quantum_boundary_for_test(ticks)
}

pub fn observable_prefix(ticks: u64, events: Vec<ObservableEvent>) -> ConditionEventLogPrefix {
    crucible::test_support::condition_prefix_from_observable_events_for_test(ticks, events)
        .expect("test scheduler event-log entries should form a checked prefix")
}

pub fn prefix_from_entries(entries: Vec<SchedulerEventLogEntry>) -> ConditionEventLogPrefix {
    crucible::test_support::condition_prefix_from_scheduler_entries_for_test(entries)
        .expect("test scheduler event-log entries should form a checked prefix")
}

pub fn evaluation_at<O>(ticks: u64, oracle: O) -> ConditionEvaluationPass<O> {
    ConditionEvaluationPass::from_log_prefix(quantum_prefix(ticks), oracle)
}

pub fn evaluation_at_genesis<O>(oracle: O) -> ConditionEvaluationPass<O> {
    ConditionEvaluationPass::from_log_prefix(ConditionEventLogPrefix::genesis(), oracle)
}

pub fn evaluation_with_observables<O>(
    ticks: u64,
    events: Vec<ObservableEvent>,
    oracle: O,
) -> ConditionEvaluationPass<O> {
    ConditionEvaluationPass::from_log_prefix(observable_prefix(ticks, events), oracle)
}

pub fn evaluate_graph<O>(
    graph: &EventGraph,
    state: &mut EventGraphState,
    mut pass: ConditionEvaluationPass<O>,
) -> EventFirings
where
    O: ConditionLeafOracle,
{
    pass.evaluate_event_graph(graph, state)
}
