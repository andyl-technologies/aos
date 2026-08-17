//! Checks T-TRIG-1 event-graph control flow after fault actions moved to bindings.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use crucible::{
    Action, Condition, ConditionEvaluationPass, ConditionLeaf, ConditionLeafOracle, Event,
    EventEvaluationKind, EventFiring, EventGraph, EventGraphError, EventGraphState, EventId,
    FirePolicy, LogLevel, NodeId, SimDuration, TimerId, VirtualTime,
};

fn event_id(name: &str) -> EventId {
    EventId::from_name(name)
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: String::from(name),
    }
}

fn timer(name: &str) -> TimerId {
    TimerId {
        name: String::from(name),
    }
}

fn evaluator<'a>(ticks: u64, true_names: &'a [&'a str]) -> ConditionEvaluationPass<TrueNames<'a>> {
    support::evaluation_at(ticks, TrueNames { true_names })
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

fn firing_records(firings: &[EventFiring]) -> Vec<(EventId, VirtualTime, Action)> {
    firings
        .iter()
        .map(|firing| (firing.event().clone(), firing.at(), firing.action().clone()))
        .collect()
}

#[test]
fn event_graph_evaluates_entrypoints_named_triggers_and_fire_policies() {
    let bootstrap = Event::once(event_id("bootstrap"), None, Action::Pass);
    let ready_log = Event::once(
        event_id("log-on-ready"),
        Some(Condition::named("ready")),
        Action::Log {
            level: LogLevel::Info,
            message: String::from("ready observed"),
        },
    );
    let pulse_log = Event::repeatable(
        event_id("log-on-pulse"),
        Some(Condition::named("pulse")),
        Action::Log {
            level: LogLevel::Info,
            message: String::from("pulse observed"),
        },
    );
    let graph = EventGraph::new(vec![
        bootstrap.clone(),
        ready_log.clone(),
        pulse_log.clone(),
    ])
    .expect("unique reachable event ids should build");
    let mut state = EventGraphState::new();
    let boundary = support::quantum_prefix(10).point();
    assert_eq!(boundary.at(), VirtualTime { ticks: 10 });
    assert_eq!(boundary.kind(), EventEvaluationKind::QuantumBoundary);

    let genesis = support::evaluate_graph(
        &graph,
        &mut state,
        support::evaluation_at_genesis(TrueNames { true_names: &[] }),
    );
    assert_eq!(
        firing_records(&genesis),
        vec![(
            bootstrap.id.clone(),
            VirtualTime { ticks: 0 },
            bootstrap.action.clone(),
        )]
    );

    assert!(support::evaluate_graph(&graph, &mut state, evaluator(10, &[])).is_empty());
    assert_eq!(
        firing_records(&support::evaluate_graph(
            &graph,
            &mut state,
            evaluator(11, &["ready"]),
        )),
        vec![(
            ready_log.id.clone(),
            VirtualTime { ticks: 11 },
            ready_log.action.clone(),
        )]
    );
    assert!(support::evaluate_graph(&graph, &mut state, evaluator(12, &["ready"])).is_empty());

    assert_eq!(
        firing_records(&support::evaluate_graph(
            &graph,
            &mut state,
            evaluator(13, &["pulse"]),
        )),
        vec![(
            pulse_log.id.clone(),
            VirtualTime { ticks: 13 },
            pulse_log.action.clone(),
        )]
    );
    assert!(support::evaluate_graph(&graph, &mut state, evaluator(14, &["pulse"])).is_empty());
    assert!(support::evaluate_graph(&graph, &mut state, evaluator(15, &[])).is_empty());
    assert_eq!(
        firing_records(&support::evaluate_graph(
            &graph,
            &mut state,
            evaluator(16, &["pulse"]),
        )),
        vec![(
            pulse_log.id.clone(),
            VirtualTime { ticks: 16 },
            pulse_log.action.clone(),
        )]
    );
}

#[test]
fn event_graph_rejects_duplicate_event_ids() {
    let duplicate_id = event_id("duplicate");
    let graph = EventGraph::new(vec![
        Event::once(
            duplicate_id.clone(),
            Some(Condition::named("left")),
            Action::Pass,
        ),
        Event::once(
            duplicate_id.clone(),
            Some(Condition::named("right")),
            Action::Fail {
                reason: String::from("right fired"),
            },
        ),
    ]);

    assert_eq!(
        graph,
        Err(EventGraphError::DuplicateEventId {
            event: duplicate_id,
        })
    );
}

#[test]
fn event_graph_rejects_repeatable_entrypoints() {
    let invalid_id = event_id("repeatable-entrypoint");
    let graph = EventGraph::new(vec![Event::repeatable(
        invalid_id.clone(),
        None,
        Action::Pass,
    )]);

    assert_eq!(
        graph,
        Err(EventGraphError::RepeatableEntrypoint { event: invalid_id })
    );
}

#[test]
fn event_graph_preserves_declared_order_for_simultaneous_triggers() {
    let graph = EventGraph::new(vec![
        Event::once(
            event_id("third-name-first-declared"),
            Some(Condition::named("shared")),
            Action::Log {
                level: LogLevel::Info,
                message: String::from("first"),
            },
        ),
        Event::once(
            event_id("first-name-second-declared"),
            Some(Condition::named("shared")),
            Action::Log {
                level: LogLevel::Info,
                message: String::from("second"),
            },
        ),
        Event::once(
            event_id("second-name-third-declared"),
            Some(Condition::named("shared")),
            Action::Log {
                level: LogLevel::Info,
                message: String::from("third"),
            },
        ),
    ])
    .expect("unique reachable event ids should build");
    let mut state = EventGraphState::new();

    let fired = support::evaluate_graph(&graph, &mut state, evaluator(99, &["shared"]));
    let fired_ids = fired
        .iter()
        .map(|firing| firing.event().name.as_str())
        .collect::<Vec<_>>();

    assert_eq!(
        fired_ids,
        vec![
            "third-name-first-declared",
            "first-name-second-declared",
            "second-name-third-declared",
        ]
    );
}

#[test]
fn event_graph_action_spine_names_specified_control_actions() {
    let actions = vec![
        Action::ArmTimer {
            name: timer("recover-after"),
            after: SimDuration { nanos: 30 },
        },
        Action::CancelTimer {
            name: timer("recover-after"),
        },
        Action::StartNode { node: node("db-0") },
        Action::StopNode { node: node("db-0") },
        Action::CreateSavepoint {
            label: Some(String::from("before-fork")),
        },
        Action::Fork {
            label: Some(String::from("explore-recovery")),
        },
        Action::Pass,
        Action::Fail {
            reason: String::from("predicate violated"),
        },
        Action::Log {
            level: LogLevel::Info,
            message: String::from("diagnostic"),
        },
        Action::Group(vec![Action::StopNode { node: node("db-1") }, Action::Pass]),
    ];

    assert_eq!(actions.len(), 10);
    assert!(matches!(actions[0], Action::ArmTimer { .. }));
    assert!(matches!(actions[1], Action::CancelTimer { .. }));
    assert!(matches!(actions[2], Action::StartNode { .. }));
    assert!(matches!(actions[3], Action::StopNode { .. }));
    assert!(matches!(actions[4], Action::CreateSavepoint { .. }));
    assert!(matches!(actions[5], Action::Fork { .. }));
    assert!(matches!(actions[6], Action::Pass));
    assert!(matches!(actions[7], Action::Fail { .. }));
    assert!(matches!(actions[8], Action::Log { .. }));
    assert!(matches!(actions[9], Action::Group(_)));

    let repeatable = Event::repeatable(
        event_id("pulse"),
        Some(Condition::named("pulse")),
        actions[8].clone(),
    );
    assert_eq!(repeatable.policy, FirePolicy::Repeatable);
    let once = Event::once(event_id("entry"), None, actions[6].clone());
    assert_eq!(once.policy, FirePolicy::Once);
}
