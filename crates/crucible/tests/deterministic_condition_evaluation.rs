//! Checks T-TRIG-10 deterministic condition-evaluation points and prefixes.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    Action, ConditionEvaluationError, ConditionEvaluationPass, ConditionLeaf, ConditionLeafOracle,
    ContentHash, Event, EventEvaluationKind, EventEvaluationPoint, EventGraph, EventGraphState,
    EventId, Icount, NodeId, NodeLifecycle, NodeTemplate, ObservableEvent, Predicate, ReadyPoint,
    SchedulerEvaluationBoundaryKind, VirtualTime, VmArchitecture, WhiteBoxPolicy, World, WorldNode,
};

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

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

struct NoNamedLeaves;

impl ConditionLeafOracle for NoNamedLeaves {
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { .. } | ConditionLeaf::GuestMarker { .. } => {
                panic!("deterministic evaluation tests use event-log backed leaves")
            }
        }
    }
}

#[test]
fn evaluation_points_name_deterministic_boundary_sources() {
    let observed = ObservableEvent::node_state(time(3), node("db-0"), NodeLifecycle::Started);
    let event_entry = crucible::test_support::condition_observation_entry_for_test(0, &observed);
    let quantum_entry = crucible::test_support::condition_boundary_entry_for_test(
        0,
        time(5),
        SchedulerEvaluationBoundaryKind::Quantum,
    );
    let rendezvous_entry = crucible::test_support::condition_boundary_entry_for_test(
        0,
        time(8),
        SchedulerEvaluationBoundaryKind::Rendezvous,
    );

    assert_eq!(
        EventEvaluationPoint::event_log_entry(&event_entry).kind(),
        EventEvaluationKind::EventBoundary
    );
    assert_eq!(
        EventEvaluationPoint::event_log_entry(&quantum_entry).kind(),
        EventEvaluationKind::QuantumBoundary
    );
    assert_eq!(
        EventEvaluationPoint::event_log_entry(&rendezvous_entry).kind(),
        EventEvaluationKind::RendezvousBoundary
    );
    assert_eq!(
        crucible::test_support::condition_prefix_from_scheduler_entries_for_test(vec![
            quantum_entry
        ])
        .expect("quantum boundary should form a checked prefix")
        .point()
        .at(),
        time(5)
    );
}

#[test]
fn log_prefix_rejects_invalid_scheduler_prefixes() {
    let future = ObservableEvent::node_state(time(11), node("db-0"), NodeLifecycle::Started);
    let invalid_hash = crucible::test_support::condition_entry_with_content_hash_for_test(
        crucible::test_support::condition_boundary_entry_for_test(
            0,
            time(10),
            SchedulerEvaluationBoundaryKind::Quantum,
        ),
        ContentHash::default(),
    );

    assert_eq!(
        crucible::test_support::condition_prefix_from_scheduler_entries_for_test(Vec::new()),
        Err(ConditionEvaluationError::EmptyEventLogPrefix)
    );
    assert_eq!(
        crucible::test_support::condition_prefix_from_scheduler_entries_for_test(vec![
            crucible::test_support::condition_boundary_entry_for_test(
                1,
                time(10),
                SchedulerEvaluationBoundaryKind::Quantum,
            )
        ]),
        Err(ConditionEvaluationError::NonPrefixEventLogSequence {
            expected: 0,
            actual: 1,
        })
    );
    assert_eq!(
        crucible::test_support::condition_prefix_from_scheduler_entries_for_test(vec![
            invalid_hash
        ]),
        Err(ConditionEvaluationError::InvalidEventLogEntryHash { sequence: 0 })
    );
    assert_eq!(
        crucible::test_support::condition_prefix_from_scheduler_entries_for_test(vec![
            crucible::test_support::condition_observation_entry_for_test(0, &future),
            crucible::test_support::condition_boundary_entry_for_test(
                1,
                time(10),
                SchedulerEvaluationBoundaryKind::Quantum,
            ),
        ]),
        Err(ConditionEvaluationError::FutureEventLogEntry {
            point: time(10),
            sequence: 0,
            event_at: time(11),
        })
    );
}

#[test]
fn shared_pass_evaluates_assertions_and_triggers_over_one_prefix() {
    let event = ObservableEvent::node_state(time(44), node("db-0"), NodeLifecycle::Started);
    let prefix = crucible::test_support::condition_prefix_from_scheduler_entries_for_test(vec![
        crucible::test_support::condition_observation_entry_for_test(0, &event),
    ])
    .expect("observable scheduler entry should form a checked prefix");
    let point = prefix.point();
    let condition = Predicate::node_state(node("db-0"), NodeLifecycle::Started);
    let world =
        World::from_nodes(vec![ready_node("db-0")]).expect("node-state test world should build");
    let graph = EventGraph::new_for_world(
        vec![Event::once(
            EventId::from_name("pass-when-started"),
            Some(condition.clone()),
            Action::Pass,
        )],
        &world,
    )
    .expect("node-state trigger graph should build");
    let mut graph_state = EventGraphState::new();
    let mut pass = ConditionEvaluationPass::from_log_prefix(prefix, NoNamedLeaves);

    assert_eq!(pass.point(), point);
    assert!(pass.evaluate_assertion_condition(&condition));

    let firings = pass.evaluate_event_graph(&graph, &mut graph_state);
    assert_eq!(firings.len(), 1);
    assert_eq!(firings[0].event().name, "pass-when-started");
    assert_eq!(firings[0].at(), time(44));
}

#[test]
fn condition_evaluation_uses_checked_prefix_events_only() {
    let previous = ObservableEvent::node_state(time(49), node("db-0"), NodeLifecycle::Started);
    let current = ObservableEvent::node_state(time(50), node("db-1"), NodeLifecycle::Started);
    let prefix = crucible::test_support::condition_prefix_from_scheduler_entries_for_test(vec![
        crucible::test_support::condition_observation_entry_for_test(0, &previous),
        crucible::test_support::condition_observation_entry_for_test(1, &current),
    ])
    .expect("past and current entries are part of the prefix");
    let mut evaluation = ConditionEvaluationPass::from_log_prefix(prefix, NoNamedLeaves);

    assert!(
        !evaluation.evaluate_assertion_condition(&Predicate::node_state(
            node("db-0"),
            NodeLifecycle::Started,
        )),
        "event-backed leaves fire at the current evaluation point, not earlier prefix entries"
    );
    assert!(
        evaluation.evaluate_assertion_condition(&Predicate::node_state(
            node("db-1"),
            NodeLifecycle::Started,
        ))
    );
}
