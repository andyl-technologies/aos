//! Checks T-TRIG-1 event-graph control flow.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use crucible::ConditionLeafOracle;
use crucible::{
    Action, Condition, ConditionEvaluationPass, ConditionLeaf, Event, EventEvaluationKind,
    EventFiring, EventGraph, EventGraphError, EventGraphState, EventId, FaultTag, FirePolicy,
    Icount, LinkDef, LogLevel, MembershipFault, NodeId, NodeTemplate, PartitionDirection,
    ReadyPoint, RestartPolicy, SimDuration, TimerId, VirtualTime, VmArchitecture, WhiteBoxPolicy,
    World, WorldNode,
};

fn event_id(name: &str) -> EventId {
    EventId::from_name(name)
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: String::from(name),
    }
}

fn ready_node(name: &str) -> WorldNode {
    WorldNode {
        id: node(name),
        arch: VmArchitecture::X86_64,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }
}

fn partition_world() -> World {
    World::from_nodes_and_links(
        vec![ready_node("db-0"), ready_node("db-1")],
        vec![LinkDef::new(node("db-0"), node("db-1")).expect("test link should build")],
    )
    .expect("partition test world should build")
}

fn tag(name: &str) -> FaultTag {
    FaultTag::from_name(name)
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

fn partition_fault() -> MembershipFault {
    MembershipFault::Partition {
        endpoint_a: node("db-0"),
        endpoint_b: node("db-1"),
        direction: PartitionDirection::Bidirectional,
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
    let ready_injection = Event::once(
        event_id("inject-on-ready"),
        Some(Condition::named("ready")),
        Action::InjectFault {
            tag: tag("split"),
            fault: partition_fault(),
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
    let graph = EventGraph::new_for_world(
        vec![
            bootstrap.clone(),
            ready_injection.clone(),
            pulse_log.clone(),
        ],
        &partition_world(),
    )
    .expect("unique event ids should build");
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
            bootstrap.action.clone()
        )]
    );

    let ready_false = support::evaluate_graph(&graph, &mut state, evaluator(10, &[]));
    assert!(ready_false.is_empty());

    let ready_true = support::evaluate_graph(&graph, &mut state, evaluator(11, &["ready"]));
    assert_eq!(
        firing_records(&ready_true),
        vec![(
            ready_injection.id.clone(),
            VirtualTime { ticks: 11 },
            ready_injection.action.clone()
        )]
    );

    let ready_still_true = support::evaluate_graph(&graph, &mut state, evaluator(12, &["ready"]));
    assert!(ready_still_true.is_empty());

    let pulse_true = support::evaluate_graph(&graph, &mut state, evaluator(13, &["pulse"]));
    assert_eq!(
        firing_records(&pulse_true),
        vec![(
            pulse_log.id.clone(),
            VirtualTime { ticks: 13 },
            pulse_log.action.clone()
        )]
    );

    let pulse_still_true = support::evaluate_graph(&graph, &mut state, evaluator(14, &["pulse"]));
    assert!(pulse_still_true.is_empty());

    let pulse_false = support::evaluate_graph(&graph, &mut state, evaluator(15, &[]));
    assert!(pulse_false.is_empty());

    let pulse_true_again = support::evaluate_graph(&graph, &mut state, evaluator(16, &["pulse"]));
    assert_eq!(
        firing_records(&pulse_true_again),
        vec![(
            pulse_log.id.clone(),
            VirtualTime { ticks: 16 },
            pulse_log.action.clone()
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
            event: duplicate_id
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
    .expect("unique event ids should build");
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
        Action::InjectFault {
            tag: tag("split"),
            fault: partition_fault(),
        },
        Action::HealFault { tag: tag("split") },
        Action::ArmTimer {
            name: timer("heal-after"),
            after: SimDuration { nanos: 30 },
        },
        Action::CancelTimer {
            name: timer("heal-after"),
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
        Action::Group(vec![
            Action::StopNode { node: node("db-1") },
            Action::HealFault { tag: tag("split") },
        ]),
    ];

    assert_eq!(actions.len(), 12);
    assert!(matches!(actions[0], Action::InjectFault { .. }));
    assert!(matches!(actions[1], Action::HealFault { .. }));
    assert!(matches!(actions[2], Action::ArmTimer { .. }));
    assert!(matches!(actions[3], Action::CancelTimer { .. }));
    assert!(matches!(actions[4], Action::StartNode { .. }));
    assert!(matches!(actions[5], Action::StopNode { .. }));
    assert!(matches!(actions[6], Action::CreateSavepoint { .. }));
    assert!(matches!(actions[7], Action::Fork { .. }));
    assert!(matches!(actions[8], Action::Pass));
    assert!(matches!(actions[9], Action::Fail { .. }));
    assert!(matches!(actions[10], Action::Log { .. }));
    assert!(matches!(actions[11], Action::Group(_)));

    let repeatable = Event::repeatable(
        event_id("pulse"),
        Some(Condition::named("pulse")),
        actions[10].clone(),
    );
    assert_eq!(repeatable.policy, FirePolicy::Repeatable);
    let once = Event::once(event_id("entry"), None, actions[8].clone());
    assert_eq!(once.policy, FirePolicy::Once);

    let crash = Action::InjectFault {
        tag: tag("crash"),
        fault: MembershipFault::Crash {
            node: node("db-2"),
            restart: RestartPolicy::StayDown,
        },
    };
    assert!(matches!(crash, Action::InjectFault { .. }));
}
