//! Checks T-TRIG-5 basic-block coverage condition leaves.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use crucible::{
    Action, AssertionDef, AssertionId, CodePoint, ConditionEvaluationPass, ConditionLeaf,
    ConditionLeafOracle, EngineError, Event, EventGraph, EventGraphState, Icount, NodeId,
    NodeTemplate, ObservableEvent, Predicate, Properties, Property, ReadyPoint, ResolvedCodePoint,
    VirtualTime, VmArchitecture, WhiteBoxPolicy, World, WorldNode,
};

fn node(name: &str) -> NodeId {
    NodeId {
        name: String::from(name),
    }
}

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

fn icount(retired: u64) -> Icount {
    Icount { retired }
}

fn evaluator(ticks: u64, events: Vec<ObservableEvent>) -> ConditionEvaluationPass<NoNamedLeaves> {
    support::evaluation_with_observables(ticks, events, NoNamedLeaves)
}

fn evaluator_with_resolution(
    ticks: u64,
    events: Vec<ObservableEvent>,
    resolutions: Vec<((NodeId, CodePoint), ResolvedCodePoint)>,
) -> ConditionEvaluationPass<NoNamedLeaves> {
    evaluator(ticks, events).with_resolved_code_points(resolutions)
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

fn coverage_world() -> World {
    World::from_nodes(vec![ready_node("server"), ready_node("db-0")])
        .expect("coverage test world should build")
}

fn properties_for(predicate: Predicate) -> Properties {
    Properties::from_assertions_for_world(&coverage_world(), vec![assertion("observed", predicate)])
        .expect("coverage properties should validate")
}

struct NoNamedLeaves;

impl ConditionLeafOracle for NoNamedLeaves {
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { .. } | ConditionLeaf::GuestMarker { .. } => {
                panic!("coverage leaves must not require named or guest-marker leaf resolution")
            }
        }
    }
}

#[test]
fn coverage_point_observes_current_basic_block_execution_event() {
    let condition = Predicate::coverage_point(node("server"), CodePoint::guest_address(0x4010));
    let matching_block = ObservableEvent::coverage_block(icount(7), node("server"), 0x4000, 0x20);
    let wrong_node = ObservableEvent::coverage_block(icount(7), node("db-0"), 0x4000, 0x20);
    let wrong_block = ObservableEvent::coverage_block(icount(7), node("server"), 0x5000, 0x20);

    assert!(
        evaluator(7, vec![wrong_node, wrong_block, matching_block])
            .evaluate_assertion_condition(&condition)
    );
    assert!(
        !evaluator(
            8,
            vec![ObservableEvent::coverage_block(
                icount(7),
                node("server"),
                0x4000,
                0x20,
            )],
        )
        .evaluate_assertion_condition(&condition)
    );
}

#[test]
fn coverage_point_does_not_rematch_after_prior_block_execution() {
    let condition = Predicate::coverage_point(node("server"), CodePoint::guest_address(0x4010));
    let first_block = ObservableEvent::coverage_block(icount(6), node("server"), 0x4000, 0x20);
    let repeat_block = ObservableEvent::coverage_block(icount(7), node("server"), 0x4000, 0x20);

    assert!(
        !evaluator(7, vec![first_block, repeat_block]).evaluate_assertion_condition(&condition)
    );
}

#[test]
fn coverage_point_resolves_symbols_host_side_without_guest_marker_support() {
    let point_ref = CodePoint::symbol("cluster_join_complete");
    let condition = Predicate::coverage_point(node("server"), point_ref.clone());
    let block = ObservableEvent::coverage_block(icount(10), node("server"), 0x5000, 0x40);
    let resolution = (
        (node("server"), point_ref.clone()),
        ResolvedCodePoint::guest_address(0x5020),
    );

    assert!(
        evaluator_with_resolution(10, vec![block.clone()], vec![resolution])
            .evaluate_assertion_condition(&condition)
    );
    assert!(!evaluator(10, vec![block]).evaluate_assertion_condition(&condition));
}

#[test]
fn coverage_point_raw_guest_address_ignores_symbol_resolution_table() {
    let condition = Predicate::coverage_point(node("server"), CodePoint::guest_address(0x4010));
    let block = ObservableEvent::coverage_block(icount(7), node("server"), 0x5000, 0x20);
    let bogus_resolution = (
        (node("server"), CodePoint::guest_address(0x4010)),
        ResolvedCodePoint::guest_address(0x5000),
    );

    assert!(
        !evaluator_with_resolution(7, vec![block], vec![bogus_resolution])
            .evaluate_assertion_condition(&condition)
    );
}

#[test]
fn coverage_block_event_point_is_derived_from_execution_icount() {
    let event = ObservableEvent::coverage_block(icount(42), node("server"), 0x4000, 0x20);

    assert_eq!(event.at(), time(42));
    match event.payload() {
        crucible::ObservableEventPayload::CoverageBlock {
            execution_icount, ..
        } => assert_eq!(execution_icount.retired, 42),
        other => panic!("coverage constructor should build coverage payload: {other:?}"),
    }
}

#[test]
fn event_graph_fires_from_coverage_point_without_named_leaf_fallback() {
    let graph = EventGraph::new_for_world(
        vec![Event::once(
            crucible::EventId::from_name("pass-on-recovery-path"),
            Some(Predicate::coverage_point(
                node("server"),
                CodePoint::symbol("recovery_entered"),
            )),
            Action::Pass,
        )],
        &coverage_world(),
    )
    .expect("coverage event graph should build");
    let mut state = EventGraphState::new();
    let events = vec![ObservableEvent::coverage_block(
        icount(33),
        node("server"),
        0x8000,
        0x20,
    )];
    let resolution = (
        (node("server"), CodePoint::symbol("recovery_entered")),
        ResolvedCodePoint::guest_address(0x8000),
    );

    let firings = support::evaluate_graph(
        &graph,
        &mut state,
        evaluator_with_resolution(33, events, vec![resolution]),
    );

    assert_eq!(firings.len(), 1);
    assert_eq!(firings[0].event().name, "pass-on-recovery-path");
}

#[test]
fn coverage_point_properties_validate_referenced_nodes() {
    let properties = Properties::from_assertions_for_world(
        &coverage_world(),
        vec![assertion(
            "missing-node",
            Predicate::coverage_point(node("missing"), CodePoint::guest_address(0x4000)),
        )],
    );

    match properties {
        Err(EngineError::PropertyPredicateUnknownNode { node }) => {
            assert_eq!(node.name, "missing");
        }
        other => panic!("coverage property should reject unknown node: {other:?}"),
    }
}

#[test]
fn coverage_point_round_trips_through_properties_serialization() {
    let world = coverage_world();
    let predicate = Predicate::all_of(vec![
        Predicate::coverage_point(node("server"), CodePoint::guest_address(0x4010)),
        Predicate::coverage_point(node("db-0"), CodePoint::symbol("wal_replayed")),
    ]);
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![assertion("coverage-points", predicate)],
    )
    .expect("coverage properties should validate");

    let toml = properties
        .to_canonical_toml()
        .expect("properties TOML should serialize");
    assert!(toml.contains("kind = \"coverage_point\""));
    assert!(toml.contains("kind = \"guest_address\""));
    assert!(toml.contains("kind = \"symbol\""));
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
fn coverage_point_material_distinguishes_addresses_and_symbols() {
    let address_a = properties_for(Predicate::coverage_point(
        node("server"),
        CodePoint::guest_address(0x4010),
    ));
    let address_b = properties_for(Predicate::coverage_point(
        node("server"),
        CodePoint::guest_address(0x4020),
    ));
    let symbol_a = properties_for(Predicate::coverage_point(
        node("server"),
        CodePoint::symbol("ready_path"),
    ));
    let symbol_b = properties_for(Predicate::coverage_point(
        node("server"),
        CodePoint::symbol("recovery_path"),
    ));

    assert_ne!(address_a.content_hash(), address_b.content_hash());
    assert_ne!(symbol_a.content_hash(), symbol_b.content_hash());
    assert_ne!(address_a.content_hash(), symbol_a.content_hash());
}
