//! Checks T-TRIG-3 virtual-time condition leaves.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use std::collections::BTreeMap;

use crucible::{
    Action, AssertionDef, AssertionId, ConditionEvaluationPass, ConditionLeaf, ConditionLeafOracle,
    EngineError, Event, EventGraph, EventGraphError, EventGraphState, EventId, LogLevel, Predicate,
    Properties, Property, SimDuration, TimerId, VirtualTime, World,
};

fn event_id(name: &str) -> EventId {
    EventId::from_name(name)
}

fn timer_id(name: &str) -> TimerId {
    TimerId {
        name: String::from(name),
    }
}

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

fn duration(nanos: u64) -> SimDuration {
    SimDuration { nanos }
}

fn evaluator(ticks: u64) -> ConditionEvaluationPass<NoLeaves> {
    support::evaluation_at(ticks, NoLeaves)
}

fn assertion(id: &str, predicate: Predicate) -> AssertionDef {
    AssertionDef {
        id: AssertionId::from_name(id),
        message: format!("{id} observed"),
        property: Property::Always { predicate },
    }
}

struct NoLeaves;

impl ConditionLeafOracle for NoLeaves {
    fn leaf_is_true(&mut self, _leaf: ConditionLeaf<'_>) -> bool {
        false
    }
}

#[test]
fn at_leaf_is_true_only_at_the_exact_virtual_time() {
    let condition = Predicate::at(time(10));

    let mut before = evaluator(9);
    let mut exact = evaluator(10);
    let mut after = evaluator(11);

    assert!(!before.evaluate_assertion_condition(&condition));
    assert!(exact.evaluate_assertion_condition(&condition));
    assert!(!after.evaluate_assertion_condition(&condition));
}

#[test]
fn after_leaf_is_relative_to_known_event_firing_history() {
    let anchor = event_id("bootstrap");
    let condition = Predicate::after(duration(5), anchor.clone());
    let mut firings = BTreeMap::new();
    firings.insert(anchor, time(7));

    let mut due = evaluator(12).with_event_firings(firings.clone());
    let mut early = evaluator(11).with_event_firings(firings.clone());
    let mut late = evaluator(13).with_event_firings(firings);
    let mut no_history = evaluator(12);

    assert!(due.evaluate_assertion_condition(&condition));
    assert!(!early.evaluate_assertion_condition(&condition));
    assert!(!late.evaluate_assertion_condition(&condition));
    assert!(!no_history.evaluate_assertion_condition(&condition));
}

#[test]
fn timer_leaf_is_true_at_evaluator_supplied_timer_fire_time() {
    let timer = timer_id("stabilize");
    let condition = Predicate::timer(timer.clone());
    let mut timers = BTreeMap::new();
    timers.insert(timer, time(30));

    let mut due = evaluator(30).with_timer_fires(timers.clone());
    let mut early = evaluator(29).with_timer_fires(timers.clone());
    let mut late = evaluator(31).with_timer_fires(timers);
    let mut no_timer = evaluator(30);

    assert!(due.evaluate_assertion_condition(&condition));
    assert!(!early.evaluate_assertion_condition(&condition));
    assert!(!late.evaluate_assertion_condition(&condition));
    assert!(!no_timer.evaluate_assertion_condition(&condition));
}

#[test]
fn at_leaf_round_trips_through_properties_serialization() {
    let world = World::from_nodes(Vec::new()).expect("empty world should build");
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![assertion("exact-time", Predicate::at(time(42)))],
    )
    .expect("At is a pure-time assertion predicate");

    let toml = properties
        .to_canonical_toml()
        .expect("properties TOML should serialize");
    assert!(toml.contains("kind = \"at\""));
    let from_toml = Properties::from_canonical_toml_for_world(&world, &toml)
        .expect("properties TOML should parse");
    let binary = properties.to_compact_binary();
    let from_binary = Properties::from_compact_binary_for_world(&world, &binary)
        .expect("properties binary should parse");

    assert_eq!(from_toml, properties);
    assert_eq!(from_binary, properties);
    assert_eq!(from_toml.content_hash(), properties.content_hash());
    assert_eq!(from_binary.content_hash(), properties.content_hash());
}

#[test]
fn properties_reject_edge_shaped_after_and_timer_leaves() {
    let world = World::from_nodes(Vec::new()).expect("empty world should build");

    let after = Properties::from_assertions_for_world(
        &world,
        vec![assertion(
            "after-edge",
            Predicate::after(duration(5), event_id("bootstrap")),
        )],
    );
    let timer = Properties::from_assertions_for_world(
        &world,
        vec![assertion(
            "timer-edge",
            Predicate::not(Predicate::timer(timer_id("settled"))),
        )],
    );

    assert_eq!(
        after,
        Err(EngineError::PropertyPredicateTriggerOnly { kind: "after" })
    );
    assert_eq!(
        timer,
        Err(EngineError::PropertyPredicateTriggerOnly { kind: "timer" })
    );
}

#[test]
fn event_graph_supplies_last_firing_history_to_after_leaves() {
    let bootstrap = Event::once(
        event_id("bootstrap"),
        None,
        Action::Log {
            level: LogLevel::Info,
            message: String::from("bootstrapped"),
        },
    );
    let delayed = Event::once(
        event_id("delayed"),
        Some(Predicate::after(duration(5), bootstrap.id.clone())),
        Action::Pass,
    );
    let graph = EventGraph::new(vec![bootstrap.clone(), delayed.clone()])
        .expect("declared event references should build");
    let mut state = EventGraphState::new();

    let genesis =
        support::evaluate_graph(&graph, &mut state, support::evaluation_at_genesis(NoLeaves));
    assert_eq!(genesis.len(), 1);
    assert_eq!(genesis[0].event(), &bootstrap.id);
    assert_eq!(state.last_firing(&bootstrap.id), Some(time(0)));

    let early = support::evaluate_graph(&graph, &mut state, evaluator(4));
    assert!(early.is_empty());

    let due = support::evaluate_graph(&graph, &mut state, evaluator(5));
    assert_eq!(due.len(), 1);
    assert_eq!(due[0].event(), &delayed.id);
    assert_eq!(due[0].at(), time(5));
    assert_eq!(state.last_firing(&delayed.id), Some(time(5)));
}

#[test]
fn event_graph_validates_after_references_declared_events() {
    let missing = event_id("missing");
    let event = Event::once(
        event_id("delayed"),
        Some(Predicate::after(duration(1), missing.clone())),
        Action::Pass,
    );

    let error = EventGraph::new(vec![event]).expect_err("unknown event reference should fail");

    assert_eq!(
        error,
        EventGraphError::UnknownEventReference {
            event: event_id("delayed"),
            reference: missing
        }
    );
}

#[test]
fn event_graph_validates_timer_references_armable_timers() {
    let missing = timer_id("missing");
    let event = Event::once(
        event_id("timer-fired"),
        Some(Predicate::timer(missing.clone())),
        Action::Pass,
    );

    let error = EventGraph::new(vec![event]).expect_err("unknown timer reference should fail");

    assert_eq!(
        error,
        EventGraphError::UnknownTimerReference {
            event: event_id("timer-fired"),
            timer: missing
        }
    );
}

#[test]
fn event_graph_accepts_timer_reference_to_grouped_arm_timer_action() {
    let timer = timer_id("settled");
    let graph = EventGraph::new(vec![
        Event::once(
            event_id("arm-timer"),
            None,
            Action::Group(vec![
                Action::Log {
                    level: LogLevel::Info,
                    message: String::from("arming timer"),
                },
                Action::ArmTimer {
                    name: timer.clone(),
                    after: duration(3),
                },
            ]),
        ),
        Event::once(
            event_id("timer-fired"),
            Some(Predicate::timer(timer)),
            Action::Pass,
        ),
    ])
    .expect("timer reference backed by grouped ArmTimer should build");

    assert_eq!(graph.events().len(), 2);
}
