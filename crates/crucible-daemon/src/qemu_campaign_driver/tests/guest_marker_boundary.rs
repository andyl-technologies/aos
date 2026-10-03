//! Guest marker identity and coincident terminal-action stop precedence.

use super::*;
use crucible::{Action, ConditionEvaluationPass, EventGraph, EventGraphState};

const SELECTED_MARKER: &str = "selected-fast-q7";
const COMPLETION_MARKER: &str = "selected-fast-q7-progress-000003";

fn marker_graph(world: &World) -> EventGraph {
    EventGraph::builder()
        .event("single.selected")
        .entrypoint()
        .when(Predicate::once(Predicate::guest_marker(
            MarkerId::from_name(SELECTED_MARKER),
        )))
        .action(Action::Group(Vec::new()))
        .event("single.complete")
        .when(Predicate::once(Predicate::guest_marker(
            MarkerId::from_name(COMPLETION_MARKER),
        )))
        .action(Action::Pass)
        .build_for_world(world)
        .expect("selected guest marker graph")
}

fn bounded_marker(name: &str) -> StopCondition {
    StopCondition::Bounded {
        primary: Box::new(StopCondition::NamedBoundary(name.to_owned())),
        virtual_time_picoseconds: Some(2_000_000_000_000),
        execution_quanta: Some(2),
    }
}

#[test]
fn selected_guest_marker_stops_before_the_completion_action() {
    let (input, marker_node) = input_with_guest_selectable(bounded_marker(SELECTED_MARKER));
    let graph = marker_graph(input.scenario().world());
    let mut log = EventLog::new();
    let append = log
        .append_observable_events([ObservableEvent::guest_marker(
            Icount { retired: 1 },
            marker_node,
            MarkerId::from_name(SELECTED_MARKER),
        )])
        .expect("selected guest marker");
    let mut pass = ConditionEvaluationPass::from_log_prefix_ref(
        log.condition_prefix(),
        |_: crucible::ConditionLeaf<'_>| false,
    )
    .with_world_white_box_policies(input.scenario().world());
    let firings = pass.evaluate_event_graph(&graph, &mut EventGraphState::new());
    assert_eq!(firings.len(), 1);
    assert_eq!(firings[0].event().name, "single.selected");
    assert_eq!(firings[0].action(), &Action::Group(Vec::new()));

    let configuration = starting_configuration(&input);
    let mut owner = FakeLifecycle {
        outcomes: VecDeque::from([
            Ok(outcome(
                configuration.clone(),
                append.entries,
                append.offset,
                1,
            )),
            Ok(outcome(configuration, Vec::new(), log.offset(), 2)),
        ]),
        terminal: None,
        initial_quanta: 0,
        drives: 0,
    };
    let pending = expect_observation(
        QemuFreshModeledDriver::new()
            .drive(
                &mut QemuFreshAttemptLifecycle::new(&mut owner),
                &input,
                &context(),
                QemuFreshStartMaterialization::genesis(),
            )
            .expect("selected guest boundary"),
    );

    assert!(
        matches!(pending.stop, ModeledStop::BoundedPrimaryReached { proof, .. }
        if proof.frontier_picoseconds() == 1 && proof.completed_quanta() == 1)
    );
    assert_eq!(owner.drives, 1);
}

#[test]
fn completion_action_pass_preempts_the_same_quantum_marker_stop() {
    let (input, marker_node) = input_with_guest_selectable(bounded_marker(COMPLETION_MARKER));
    let graph = marker_graph(input.scenario().world());
    let mut log = EventLog::new();
    let append = log
        .append_observable_events([ObservableEvent::guest_marker(
            Icount { retired: 1 },
            marker_node,
            MarkerId::from_name(COMPLETION_MARKER),
        )])
        .expect("completion guest marker");
    let mut pass = ConditionEvaluationPass::from_log_prefix_ref(
        log.condition_prefix(),
        |_: crucible::ConditionLeaf<'_>| false,
    )
    .with_world_white_box_policies(input.scenario().world());
    let firings = pass.evaluate_event_graph(&graph, &mut EventGraphState::new());
    assert_eq!(firings.len(), 1);
    assert_eq!(firings[0].event().name, "single.complete");
    assert_eq!(firings[0].action(), &Action::Pass);

    let configuration = starting_configuration(&input);
    let mut owner = FakeLifecycle {
        outcomes: VecDeque::from([Ok(outcome(configuration, append.entries, append.offset, 1))]),
        terminal: firings
            .iter()
            .any(|firing| firing.action() == &Action::Pass)
            .then_some(QuantumTerminalVerdict::Passed),
        initial_quanta: 0,
        drives: 0,
    };
    let pending = expect_observation(
        QemuFreshModeledDriver::new()
            .drive(
                &mut QemuFreshAttemptLifecycle::new(&mut owner),
                &input,
                &context(),
                QemuFreshStartMaterialization::genesis(),
            )
            .expect("completion marker and terminal action"),
    );

    assert!(matches!(pending.stop, ModeledStop::TerminalPassed));
    assert_eq!(owner.drives, 1);
}
