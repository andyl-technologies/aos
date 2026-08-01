//! Checks T-TRIG-4 black-box observable condition leaves.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use crucible::{
    Action, AssertionDef, AssertionId, ConditionEvaluationError, ConditionEvaluationPass,
    ConditionLeaf, ConditionLeafOracle, EngineError, Event, EventGraph, EventGraphError,
    EventGraphState, FramePredicate, Icount, IoEventKind, LinkId, LogLevel, NodeId, NodeLifecycle,
    NodeTemplate, ObservableEvent, Predicate, Properties, Property, ReadyPoint, RegexProgram,
    SchedulerEvaluationBoundaryKind, VirtualTime, VmArchitecture, WhiteBoxPolicy, World, WorldNode,
};

fn node(name: &str) -> NodeId {
    NodeId {
        name: String::from(name),
    }
}

fn link(name: &str) -> LinkId {
    LinkId::from_name(name)
}

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

fn evaluator(ticks: u64, events: Vec<ObservableEvent>) -> ConditionEvaluationPass<NoNamedLeaves> {
    support::evaluation_with_observables(ticks, events, NoNamedLeaves)
}

fn assertion(id: &str, predicate: Predicate) -> AssertionDef {
    AssertionDef {
        id: AssertionId::from_name(id),
        message: format!("{id} observed"),
        property: Property::Always { predicate },
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

fn observable_world() -> World {
    World::from_nodes(vec![
        ready_node("server"),
        ready_node("db-0"),
        ready_node("worker"),
    ])
    .expect("observable test world should build")
}

fn properties_for(predicate: Predicate) -> Properties {
    Properties::from_assertions_for_world(
        &observable_world(),
        vec![assertion("observed", predicate)],
    )
    .expect("observable properties should validate")
}

struct NoNamedLeaves;

impl ConditionLeafOracle for NoNamedLeaves {
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { .. } | ConditionLeaf::GuestMarker { .. } => {
                panic!("observable leaves must not require named or guest-marker leaf resolution")
            }
        }
    }
}

#[test]
fn network_match_observes_delivered_frame_payload_at_the_evaluation_point() {
    let condition = Predicate::network_match(
        Some(link("client-server")),
        FramePredicate::contains(b"HTTP/1.1 200".to_vec()),
    );
    let matching = ObservableEvent::network_delivered(
        time(20),
        Some(link("client-server")),
        b"GET / HTTP/1.1\r\nHTTP/1.1 200 OK\r\n".to_vec(),
    );
    let wrong_link = ObservableEvent::network_delivered(
        time(20),
        Some(link("replica-sync")),
        b"HTTP/1.1 200 OK\r\n".to_vec(),
    );
    let wrong_time = ObservableEvent::network_delivered(
        time(19),
        Some(link("client-server")),
        b"HTTP/1.1 200 OK\r\n".to_vec(),
    );

    assert!(
        evaluator(20, vec![wrong_time, wrong_link, matching])
            .evaluate_assertion_condition(&condition)
    );
    let future = ObservableEvent::network_delivered(
        time(20),
        Some(link("client-server")),
        b"HTTP/1.1 200 OK\r\n".to_vec(),
    );
    assert_eq!(
        crucible::test_support::condition_prefix_from_scheduler_entries_for_test(vec![
            crucible::test_support::condition_observation_entry_for_test(0, &future),
            crucible::test_support::condition_boundary_entry_for_test(
                1,
                time(19),
                SchedulerEvaluationBoundaryKind::Quantum,
            ),
        ]),
        Err(ConditionEvaluationError::FutureEventLogEntry {
            point: time(19),
            sequence: 0,
            event_at: time(20),
        })
    );
}

#[test]
fn network_match_can_observe_any_link() {
    let condition = Predicate::network_match(None, FramePredicate::prefix(b"raft".to_vec()));
    let event = ObservableEvent::network_delivered(
        time(3),
        Some(link("replica-a-b")),
        b"raft-append-entries".to_vec(),
    );

    assert!(evaluator(3, vec![event]).evaluate_assertion_condition(&condition));
}

#[test]
fn console_match_uses_host_side_regex_over_captured_console_bytes() {
    let condition = Predicate::console_match(
        node("server"),
        RegexProgram::from_pattern("ready to accept connections"),
    );
    let event = ObservableEvent::console_output(
        time(9),
        node("server"),
        b"boot complete\nready to accept connections\n".to_vec(),
    );
    let wrong_node = ObservableEvent::console_output(
        time(9),
        node("client"),
        b"ready to accept connections\n".to_vec(),
    );

    assert!(evaluator(9, vec![wrong_node, event]).evaluate_assertion_condition(&condition));
}

#[test]
fn console_match_spans_chunks_and_fires_when_match_completes_at_point() {
    let condition = Predicate::console_match(
        node("server"),
        RegexProgram::from_pattern("ready to accept"),
    );
    let first = ObservableEvent::console_output(time(8), node("server"), b"ready to ".to_vec());
    let second = ObservableEvent::console_output(time(9), node("server"), b"accept\n".to_vec());

    assert!(!evaluator(8, vec![first.clone()]).evaluate_assertion_condition(&condition));
    assert!(
        evaluator(9, vec![first.clone(), second.clone()]).evaluate_assertion_condition(&condition)
    );
    assert!(!evaluator(10, vec![first, second]).evaluate_assertion_condition(&condition));
}

#[test]
fn invalid_console_regex_is_rejected_by_graph_and_properties() {
    let invalid = RegexProgram::from_pattern("[");
    let event_id = crucible::EventId::from_name("bad-console-regex");
    let graph = EventGraph::new_for_world(
        vec![Event::once(
            event_id.clone(),
            Some(Predicate::console_match(node("server"), invalid.clone())),
            Action::Pass,
        )],
        &observable_world(),
    );
    let properties = Properties::from_assertions_for_world(
        &observable_world(),
        vec![assertion(
            "bad-console-regex",
            Predicate::console_match(node("server"), invalid),
        )],
    );

    match graph {
        Err(EventGraphError::InvalidRegex { event, pattern, .. }) => {
            assert_eq!(event, event_id);
            assert_eq!(pattern, "[");
        }
        other => panic!("invalid regex should fail event graph construction: {other:?}"),
    }
    match properties {
        Err(EngineError::PropertyPredicateInvalidRegex { pattern, .. }) => {
            assert_eq!(pattern, "[");
        }
        other => panic!("invalid regex should fail property validation: {other:?}"),
    }
}

#[test]
fn io_pattern_observes_deterministic_io_completion_kind() {
    let condition = Predicate::io_pattern(node("db-0"), IoEventKind::Fsync);
    let event =
        ObservableEvent::io_completion(time(11), node("db-0"), IoEventKind::Fsync, b"ok".to_vec());
    let wrong_kind = ObservableEvent::io_completion(
        time(11),
        node("db-0"),
        IoEventKind::BlockWrite,
        b"ok".to_vec(),
    );

    assert!(evaluator(11, vec![wrong_kind, event]).evaluate_assertion_condition(&condition));
}

#[test]
fn io_pattern_any_matches_any_completion_kind_for_the_node() {
    let condition = Predicate::io_pattern(node("db-0"), IoEventKind::Any);
    let event = ObservableEvent::io_completion(
        time(12),
        node("db-0"),
        IoEventKind::BlockWrite,
        b"sector=12".to_vec(),
    );

    assert!(evaluator(12, vec![event]).evaluate_assertion_condition(&condition));
}

#[test]
fn node_state_observes_lifecycle_transition() {
    let condition = Predicate::node_state(node("worker"), NodeLifecycle::Exited);
    let event = ObservableEvent::node_state(time(14), node("worker"), NodeLifecycle::Exited);
    let earlier = ObservableEvent::node_state(time(13), node("worker"), NodeLifecycle::Exited);

    assert!(evaluator(14, vec![earlier, event]).evaluate_assertion_condition(&condition));
}

#[test]
fn event_graph_fires_from_observable_condition_without_guest_marker_support() {
    let graph = EventGraph::new_for_world(
        vec![Event::once(
            crucible::EventId::from_name("pass-on-console-ready"),
            Some(Predicate::console_match(
                node("server"),
                RegexProgram::from_pattern("listening on 0\\.0\\.0\\.0:8080"),
            )),
            Action::Group(vec![
                Action::Log {
                    level: LogLevel::Info,
                    message: String::from("server ready"),
                },
                Action::Pass,
            ]),
        )],
        &observable_world(),
    )
    .expect("observable console event graph should build");
    let mut state = EventGraphState::new();
    let events = vec![ObservableEvent::console_output(
        time(33),
        node("server"),
        b"server listening on 0.0.0.0:8080\n".to_vec(),
    )];

    let firings = support::evaluate_graph(&graph, &mut state, evaluator(33, events));

    assert_eq!(firings.len(), 1);
    assert_eq!(firings[0].event().name, "pass-on-console-ready");
}

#[test]
fn observable_leaves_round_trip_through_properties_serialization() {
    let world = observable_world();
    let predicate = Predicate::all_of(vec![
        Predicate::network_match(None, FramePredicate::contains(b"HTTP/1.1 200".to_vec())),
        Predicate::console_match(node("server"), RegexProgram::from_pattern("ready")),
        Predicate::io_pattern(node("db-0"), IoEventKind::Fsync),
        Predicate::node_state(node("worker"), NodeLifecycle::Exited),
    ]);
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![assertion("observable-leaves", predicate)],
    )
    .expect("observable properties should validate");

    let toml = properties
        .to_canonical_toml()
        .expect("properties TOML should serialize");
    assert!(toml.contains("kind = \"network_match\""));
    assert!(toml.contains("io_kind = \"fsync\""));
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
fn observable_leaf_material_distinguishes_predicate_payloads() {
    let network_ok = properties_for(Predicate::network_match(
        None,
        FramePredicate::contains(b"ok".to_vec()),
    ));
    let network_err = properties_for(Predicate::network_match(
        None,
        FramePredicate::contains(b"err".to_vec()),
    ));
    let console_ready = properties_for(Predicate::console_match(
        node("server"),
        RegexProgram::from_pattern("ready"),
    ));
    let console_done = properties_for(Predicate::console_match(
        node("server"),
        RegexProgram::from_pattern("done"),
    ));
    let io_fsync = properties_for(Predicate::io_pattern(node("db-0"), IoEventKind::Fsync));
    let io_write = properties_for(Predicate::io_pattern(node("db-0"), IoEventKind::BlockWrite));
    let node_exited = properties_for(Predicate::node_state(node("worker"), NodeLifecycle::Exited));
    let node_crashed = properties_for(Predicate::node_state(
        node("worker"),
        NodeLifecycle::Crashed,
    ));

    assert_ne!(network_ok.content_hash(), network_err.content_hash());
    assert_ne!(console_ready.content_hash(), console_done.content_hash());
    assert_ne!(io_fsync.content_hash(), io_write.content_hash());
    assert_ne!(node_exited.content_hash(), node_crashed.content_hash());
}
