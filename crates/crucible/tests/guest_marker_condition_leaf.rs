//! Checks T-TRIG-8 optional white-box guest-marker leaves.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use crucible::{
    Action, AssertionDef, AssertionId, ConditionEvaluationPass, ConditionLeaf, ConditionLeafOracle,
    EngineError, Event, EventGraph, EventGraphError, EventGraphState, EventId, Icount, MarkerId,
    NodeId, NodeTemplate, ObservableEvent, ObservableEventPayload, Predicate, Properties, Property,
    ReachabilityExpectation, ReachableDisposition, ReadyPoint, SchedulerQuiescence, VirtualTime,
    VmArchitecture, WhiteBoxPolicy, World, WorldNode,
};

fn assertion_id(name: &str) -> AssertionId {
    AssertionId::from_name(name)
}

fn marker(name: &str) -> MarkerId {
    MarkerId::from_name(name)
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: String::from(name),
    }
}

fn icount(retired: u64) -> Icount {
    Icount { retired }
}

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

fn evaluator(ticks: u64, events: Vec<ObservableEvent>) -> ConditionEvaluationPass<NoLeafFallback> {
    support::evaluation_with_observables(ticks, events, NoLeafFallback)
}

fn ready_node(name: &str, white_box: WhiteBoxPolicy) -> WorldNode {
    WorldNode {
        id: node(name),
        arch: VmArchitecture::X86_64,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount { icount: icount(1) },
        white_box,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }
}

fn world() -> World {
    world_with(vec![("guest", WhiteBoxPolicy::Enabled)])
}

fn disabled_world() -> World {
    world_with(vec![("guest", WhiteBoxPolicy::Disabled)])
}

fn multi_node_world() -> World {
    world_with(vec![
        ("guest", WhiteBoxPolicy::Enabled),
        ("observer", WhiteBoxPolicy::Enabled),
        ("blackbox", WhiteBoxPolicy::Disabled),
    ])
}

fn world_with(nodes: Vec<(&str, WhiteBoxPolicy)>) -> World {
    World::from_nodes(
        nodes
            .into_iter()
            .map(|(name, white_box)| ready_node(name, white_box))
            .collect(),
    )
    .expect("guest-marker test world should build")
}

fn assertion(id: &str, predicate: Predicate) -> AssertionDef {
    AssertionDef {
        id: assertion_id(id),
        message: format!("{id} observed"),
        property: Property::Reachable {
            predicate,
            expectation: ReachabilityExpectation::Reachable {
                on_unreached: ReachableDisposition::Warn,
            },
        },
    }
}

struct NoLeafFallback;

impl ConditionLeafOracle for NoLeafFallback {
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { .. } | ConditionLeaf::GuestMarker { .. } => {
                panic!("guest-marker leaf must be event-backed, not leaf-oracle backed")
            }
        }
    }
}

#[test]
fn guest_marker_observes_enabled_doorbell_marker_at_retirement_icount() {
    let world = world();
    let condition = Predicate::guest_marker(marker("commit"));
    let matching = ObservableEvent::guest_marker(icount(44), node("guest"), marker("commit"));
    let wrong_marker = ObservableEvent::guest_marker(icount(44), node("guest"), marker("flush"));
    let wrong_time = ObservableEvent::guest_marker(icount(43), node("guest"), marker("commit"));

    assert!(
        evaluator(44, vec![wrong_marker, wrong_time, matching])
            .with_world_white_box_policies(&world)
            .evaluate_assertion_condition(&condition)
    );
}

#[test]
fn guest_marker_rejects_wrong_marker_disabled_opt_in_and_wrong_time_in_isolation() {
    let condition = Predicate::guest_marker(marker("commit"));
    let enabled = world();
    let disabled = disabled_world();

    assert!(
        !evaluator(
            44,
            vec![ObservableEvent::guest_marker(
                icount(44),
                node("guest"),
                marker("flush")
            )],
        )
        .with_world_white_box_policies(&enabled)
        .evaluate_assertion_condition(&condition)
    );
    assert!(
        !evaluator(
            44,
            vec![ObservableEvent::guest_marker(
                icount(44),
                node("guest"),
                marker("commit")
            )],
        )
        .with_world_white_box_policies(&disabled)
        .evaluate_assertion_condition(&condition)
    );
    assert!(
        !evaluator(
            44,
            vec![ObservableEvent::guest_marker(
                icount(43),
                node("guest"),
                marker("commit")
            )],
        )
        .with_world_white_box_policies(&enabled)
        .evaluate_assertion_condition(&condition)
    );
    assert!(
        !evaluator(
            44,
            vec![ObservableEvent::guest_marker(
                icount(44),
                node("guest"),
                marker("commit")
            )],
        )
        .evaluate_assertion_condition(&condition)
    );
}

#[test]
fn guest_marker_names_are_global_but_emitting_node_must_be_opted_in() {
    let world = multi_node_world();
    let condition = Predicate::guest_marker(marker("commit"));

    assert!(
        evaluator(
            50,
            vec![ObservableEvent::guest_marker(
                icount(50),
                node("observer"),
                marker("commit")
            )],
        )
        .with_world_white_box_policies(&world)
        .evaluate_assertion_condition(&condition)
    );
    assert!(
        !evaluator(
            50,
            vec![ObservableEvent::guest_marker(
                icount(50),
                node("blackbox"),
                marker("commit")
            )],
        )
        .with_world_white_box_policies(&world)
        .evaluate_assertion_condition(&condition)
    );
}

#[test]
fn guest_marker_event_point_is_doorbell_retirement_icount() {
    let event = ObservableEvent::guest_marker(icount(77), node("guest"), marker("checkpoint"));

    assert_eq!(event.at(), time(77));
    match event.payload() {
        ObservableEventPayload::GuestMarker {
            retired_icount,
            node,
            marker,
        } => {
            assert_eq!(retired_icount.retired, 77);
            assert_eq!(node.name, "guest");
            assert_eq!(marker.name, "checkpoint");
        }
        other => panic!("guest-marker constructor should build marker payload: {other:?}"),
    }
}

#[test]
fn event_graph_fires_from_guest_marker_without_named_leaf_fallback() {
    let world = world();
    let graph = EventGraph::new_for_world(
        vec![Event::once(
            EventId::from_name("pass-on-commit"),
            Some(Predicate::guest_marker(marker("commit"))),
            Action::Pass,
        )],
        &world,
    )
    .expect("guest-marker event graph should build");
    let mut state = EventGraphState::new();
    let events = vec![ObservableEvent::guest_marker(
        icount(91),
        node("guest"),
        marker("commit"),
    )];

    let firings = support::evaluate_graph(
        &graph,
        &mut state,
        evaluator(91, events).with_world_white_box_policies(&world),
    );

    assert_eq!(firings.len(), 1);
    assert_eq!(firings[0].event().name, "pass-on-commit");
}

#[test]
fn event_graph_rejects_guest_marker_without_white_box_world() {
    let result = EventGraph::new_for_world(
        vec![Event::once(
            EventId::from_name("pass-on-commit"),
            Some(Predicate::guest_marker(marker("commit"))),
            Action::Pass,
        )],
        &disabled_world(),
    );

    match result {
        Err(EventGraphError::GuestMarkerWithoutWhiteBoxOptIn { event, marker }) => {
            assert_eq!(event.name, "pass-on-commit");
            assert_eq!(marker.name, "commit");
        }
        other => panic!("guest-marker graph should reject disabled white-box world: {other:?}"),
    }
}

#[test]
fn event_graph_rejects_guest_marker_without_world_backed_constructor() {
    let event = Event::once(
        EventId::from_name("pass-on-commit"),
        Some(Predicate::guest_marker(marker("commit"))),
        Action::Pass,
    );

    match EventGraph::new(vec![event.clone()]) {
        Err(EventGraphError::GuestMarkerWithoutWhiteBoxOptIn { event, marker }) => {
            assert_eq!(event.name, "pass-on-commit");
            assert_eq!(marker.name, "commit");
        }
        other => panic!("no-world graph should reject guest-marker trigger: {other:?}"),
    }

    match EventGraph::new_with_assertions(vec![event], []) {
        Err(EventGraphError::GuestMarkerWithoutWhiteBoxOptIn { event, marker }) => {
            assert_eq!(event.name, "pass-on-commit");
            assert_eq!(marker.name, "commit");
        }
        other => panic!("assertion-only graph should reject guest-marker trigger: {other:?}"),
    }
}

#[test]
fn zero_guest_marker_conditions_run_without_guest_marker_support() {
    let graph = EventGraph::new(vec![Event::once(
        EventId::from_name("pass-at-boundary"),
        Some(Predicate::at(time(12))),
        Action::Pass,
    )])
    .expect("zero-guest-marker event graph should build");
    let mut state = EventGraphState::new();

    let firings = support::evaluate_graph(&graph, &mut state, evaluator(12, Vec::new()));

    assert_eq!(firings.len(), 1);
    assert_eq!(firings[0].event().name, "pass-at-boundary");
}

#[test]
fn zero_guest_marker_conditions_ignore_guest_marker_events() {
    let condition = Predicate::quiescent();
    let mut evaluation = evaluator(
        20,
        vec![ObservableEvent::guest_marker(
            icount(20),
            node("guest"),
            marker("commit"),
        )],
    )
    .with_scheduler_quiescence(SchedulerQuiescence::default());

    assert!(evaluation.evaluate_assertion_condition(&condition));
}

#[test]
fn guest_marker_round_trips_through_properties_serialization() {
    let world = world();
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![assertion(
            "commit-reached",
            Predicate::guest_marker(marker("commit")),
        )],
    )
    .expect("guest-marker properties should validate");

    let toml = properties
        .to_canonical_toml()
        .expect("properties TOML should serialize");
    assert!(toml.contains("kind = \"guest_marker\""));
    assert!(toml.contains("marker = \"commit\""));
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
fn guest_marker_properties_require_a_white_box_enabled_world() {
    let result = Properties::from_assertions_for_world(
        &disabled_world(),
        vec![assertion(
            "commit-reached",
            Predicate::guest_marker(marker("commit")),
        )],
    );

    match result {
        Err(EngineError::PropertyPredicateGuestMarkerRequiresWhiteBoxOptIn { marker }) => {
            assert_eq!(marker.name, "commit");
        }
        other => panic!("guest-marker property should reject disabled white-box world: {other:?}"),
    }
}

#[test]
fn guest_marker_material_distinguishes_marker_names() {
    let world = world();
    let commit = Properties::from_assertions_for_world(
        &world,
        vec![assertion(
            "marker",
            Predicate::guest_marker(marker("commit")),
        )],
    )
    .expect("commit marker properties should validate");
    let flush = Properties::from_assertions_for_world(
        &world,
        vec![assertion(
            "marker",
            Predicate::guest_marker(marker("flush")),
        )],
    )
    .expect("flush marker properties should validate");

    assert_ne!(commit.content_hash(), flush.content_hash());
}
