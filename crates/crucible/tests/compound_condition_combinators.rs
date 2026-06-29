//! Checks T-TRIG-9 compound condition combinators and `Once` latching.

#![forbid(unsafe_code)]

use crucible::{
    Action, AssertionDef, AssertionId, ConditionEvaluation, ConditionLeaf, ConditionLeafOracle,
    EngineError, Event, EventEvaluationPoint, EventFiring, EventGraph, EventGraphError,
    EventGraphState, EventId, LogLevel, Predicate, Properties, Property, ReachabilityExpectation,
    ReachableDisposition, VirtualTime, World,
};

fn event_id(name: &str) -> EventId {
    EventId::from_name(name)
}

fn assertion_id(name: &str) -> AssertionId {
    AssertionId::from_name(name)
}

fn point(ticks: u64) -> EventEvaluationPoint {
    EventEvaluationPoint::boundary(VirtualTime { ticks })
}

fn evaluator<'a>(
    point: EventEvaluationPoint,
    true_names: &'a [&'a str],
) -> ConditionEvaluation<TrueNames<'a>> {
    ConditionEvaluation::new(point, TrueNames { true_names })
}

fn fired_ids(firings: &[EventFiring]) -> Vec<&str> {
    firings
        .iter()
        .map(|firing| firing.event().name.as_str())
        .collect()
}

struct TrueNames<'a> {
    true_names: &'a [&'a str],
}

impl ConditionLeafOracle for TrueNames<'_> {
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { name, .. } => self.true_names.contains(&name),
            ConditionLeaf::GuestMarker { marker } => {
                self.true_names.contains(&marker.name.as_str())
            }
        }
    }
}

#[test]
fn compound_combinators_nest_arbitrarily() {
    let condition = Predicate::all_of(vec![
        Predicate::not(Predicate::named("blocked")),
        Predicate::any_of(vec![
            Predicate::named("ready"),
            Predicate::all_of(vec![
                Predicate::named("warm"),
                Predicate::not(Predicate::named("cold")),
            ]),
        ]),
    ]);

    assert!(evaluator(point(1), &["ready"]).evaluate_condition(&condition));
    assert!(evaluator(point(1), &["warm"]).evaluate_condition(&condition));
    assert!(!evaluator(point(1), &["ready", "blocked"]).evaluate_condition(&condition));
    assert!(!evaluator(point(1), &["warm", "cold"]).evaluate_condition(&condition));
}

#[test]
fn once_latches_after_inner_was_true_even_when_all_of_was_false() {
    let graph = EventGraph::new(vec![Event::once(
        event_id("fire-after-gate-and-past-pulse"),
        Some(Predicate::all_of(vec![
            Predicate::named("gate"),
            Predicate::once(Predicate::named("pulse")),
        ])),
        Action::Pass,
    )])
    .expect("compound graph should build");
    let mut state = EventGraphState::new();

    let before_gate = state.evaluate(&graph, &mut evaluator(point(10), &["pulse"]));
    assert!(before_gate.is_empty());

    let after_gate = state.evaluate(&graph, &mut evaluator(point(11), &["gate"]));
    assert_eq!(
        fired_ids(&after_gate),
        vec!["fire-after-gate-and-past-pulse"]
    );
}

#[test]
fn once_inside_any_of_observes_non_short_circuited_branch() {
    let graph = EventGraph::new(vec![Event::repeatable(
        event_id("pulse-or-gate"),
        Some(Predicate::any_of(vec![
            Predicate::named("gate"),
            Predicate::once(Predicate::named("pulse")),
        ])),
        Action::Log {
            level: LogLevel::Info,
            message: String::from("pulse or gate"),
        },
    )])
    .expect("compound graph should build");
    let mut state = EventGraphState::new();

    let first = state.evaluate(&graph, &mut evaluator(point(20), &["gate", "pulse"]));
    assert_eq!(fired_ids(&first), vec!["pulse-or-gate"]);

    let no_inputs = state.evaluate(&graph, &mut evaluator(point(21), &[]));
    assert!(no_inputs.is_empty());

    let gate_again = state.evaluate(&graph, &mut evaluator(point(22), &["gate"]));
    assert!(
        gate_again.is_empty(),
        "latched Once keeps the repeatable condition continuously true"
    );
}

#[test]
fn equivalent_once_conditions_share_latch_state_across_events() {
    let graph = EventGraph::new(vec![
        Event::repeatable(
            event_id("pulse-seen"),
            Some(Predicate::once(Predicate::named("pulse"))),
            Action::Log {
                level: LogLevel::Info,
                message: String::from("pulse seen"),
            },
        ),
        Event::repeatable(
            event_id("gate-after-pulse"),
            Some(Predicate::all_of(vec![
                Predicate::named("gate"),
                Predicate::once(Predicate::named("pulse")),
            ])),
            Action::Pass,
        ),
    ])
    .expect("compound graph should build");
    let mut state = EventGraphState::new();

    let pulse_only = state.evaluate(&graph, &mut evaluator(point(30), &["pulse"]));
    assert_eq!(fired_ids(&pulse_only), vec!["pulse-seen"]);

    let gate_after_pulse = state.evaluate(&graph, &mut evaluator(point(31), &["gate"]));
    assert_eq!(fired_ids(&gate_after_pulse), vec!["gate-after-pulse"]);
}

#[test]
fn event_graph_rejects_empty_all_of_and_any_of_at_build_time() {
    let empty_all = EventGraph::new(vec![Event::once(
        event_id("empty-all"),
        Some(Predicate::all_of(Vec::new())),
        Action::Pass,
    )]);
    assert_eq!(
        empty_all,
        Err(EventGraphError::EmptyCompound {
            event: event_id("empty-all"),
            kind: "all-of",
        })
    );

    let nested_empty_any = EventGraph::new(vec![Event::once(
        event_id("nested-empty-any"),
        Some(Predicate::not(Predicate::any_of(Vec::new()))),
        Action::Pass,
    )]);
    assert_eq!(
        nested_empty_any,
        Err(EventGraphError::EmptyCompound {
            event: event_id("nested-empty-any"),
            kind: "any-of",
        })
    );
}

#[test]
fn properties_reject_empty_all_of_and_any_of_at_build_time() {
    let world = World::from_nodes(Vec::new()).expect("empty world should build");
    let empty_all = Properties::from_assertions_for_world(
        &world,
        vec![AssertionDef {
            id: assertion_id("empty-all"),
            message: String::from("empty all"),
            property: Property::Reachable {
                predicate: Predicate::all_of(Vec::new()),
                expectation: ReachabilityExpectation::Reachable {
                    on_unreached: ReachableDisposition::Fail,
                },
            },
        }],
    );
    assert_eq!(
        empty_all,
        Err(EngineError::PropertyPredicateEmptyCompound { kind: "all-of" })
    );

    let empty_any = Properties::from_assertions_for_world(
        &world,
        vec![AssertionDef {
            id: assertion_id("empty-any"),
            message: String::from("empty any"),
            property: Property::Sometimes {
                predicate: Predicate::not(Predicate::any_of(Vec::new())),
            },
        }],
    );
    assert_eq!(
        empty_any,
        Err(EngineError::PropertyPredicateEmptyCompound { kind: "any-of" })
    );
}
