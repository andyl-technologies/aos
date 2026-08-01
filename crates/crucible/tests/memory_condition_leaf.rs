//! Checks T-TRIG-6 deterministic memory/register condition leaves.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

mod support;

use crucible::{
    Action, AssertionDef, AssertionId, ConditionEvaluationPass, ConditionLeaf, ConditionLeafOracle,
    EngineError, Event, EventGraph, EventGraphState, Icount, MemPlace, MemoryCmp, MemoryWidth,
    NodeId, NodeTemplate, ObservableEvent, Predicate, Properties, Property, ReadyPoint,
    ResolvedMemPlace, VirtualTime, VmArchitecture, WhiteBoxPolicy, World, WorldNode,
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
    resolutions: Vec<((NodeId, MemPlace), ResolvedMemPlace)>,
) -> ConditionEvaluationPass<NoNamedLeaves> {
    evaluator(ticks, events).with_resolved_mem_places(resolutions)
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

fn memory_world() -> World {
    World::from_nodes(vec![ready_node("server"), ready_node("db-0")])
        .expect("memory test world should build")
}

fn properties_for(predicate: Predicate) -> Properties {
    Properties::from_assertions_for_world(&memory_world(), vec![assertion("observed", predicate)])
        .expect("memory properties should validate")
}

struct NoNamedLeaves;

impl ConditionLeafOracle for NoNamedLeaves {
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { .. } | ConditionLeaf::GuestMarker { .. } => {
                panic!("memory predicates must not require named or guest-marker leaf resolution")
            }
        }
    }
}

#[test]
fn memory_predicate_observes_current_physical_sample() {
    let place = MemPlace::physical_address(0x1000, MemoryWidth::U32);
    let condition = Predicate::memory_predicate(node("server"), place, MemoryCmp::Eq, 0xfeed);
    let matching = ObservableEvent::memory_sample(
        time(21),
        icount(21),
        node("server"),
        ResolvedMemPlace::physical_address(0x1000, 4),
        0xfeed,
    );
    let wrong_place = ObservableEvent::memory_sample(
        time(21),
        icount(21),
        node("server"),
        ResolvedMemPlace::physical_address(0x2000, 4),
        0xfeed,
    );
    let wrong_time = ObservableEvent::memory_sample(
        time(20),
        icount(20),
        node("server"),
        ResolvedMemPlace::physical_address(0x1000, 4),
        0xfeed,
    );

    assert!(
        evaluator(21, vec![wrong_place, wrong_time, matching])
            .evaluate_assertion_condition(&condition)
    );
}

#[test]
fn memory_predicate_comparisons_are_unsigned_and_deterministic() {
    let place = MemPlace::register("rax", MemoryWidth::U64);
    let sample = ObservableEvent::memory_sample(
        time(5),
        icount(5),
        node("server"),
        ResolvedMemPlace::register("rax", 8),
        10,
    );

    assert!(
        evaluator(5, vec![sample.clone()]).evaluate_assertion_condition(
            &Predicate::memory_predicate(node("server"), place.clone(), MemoryCmp::Ge, 10),
        )
    );
    assert!(
        evaluator(5, vec![sample.clone()]).evaluate_assertion_condition(
            &Predicate::memory_predicate(node("server"), place.clone(), MemoryCmp::Lt, 11),
        )
    );
    assert!(!evaluator(5, vec![sample]).evaluate_assertion_condition(
        &Predicate::memory_predicate(node("server"), place, MemoryCmp::Gt, 10),
    ));
}

#[test]
fn memory_predicate_resolves_symbols_host_side() {
    let place = MemPlace::symbol("cluster_state", MemoryWidth::U8);
    let condition = Predicate::memory_predicate(node("server"), place.clone(), MemoryCmp::Eq, 2);
    let sample = ObservableEvent::memory_sample(
        time(33),
        icount(33),
        node("server"),
        ResolvedMemPlace::virtual_address(0x7000, 1),
        2,
    );
    let resolution = (
        (node("server"), place.clone()),
        ResolvedMemPlace::virtual_address(0x7000, 1),
    );

    assert!(
        evaluator_with_resolution(33, vec![sample.clone()], vec![resolution])
            .evaluate_assertion_condition(&condition)
    );
    assert!(!evaluator(33, vec![sample]).evaluate_assertion_condition(&condition));
}

#[test]
fn memory_predicate_virtual_address_requires_host_resolution() {
    let place = MemPlace::virtual_address(0x7000, MemoryWidth::U8);
    let condition = Predicate::memory_predicate(node("server"), place.clone(), MemoryCmp::Eq, 2);
    let sample = ObservableEvent::memory_sample(
        time(34),
        icount(34),
        node("server"),
        ResolvedMemPlace::virtual_address(0x7000, 1),
        2,
    );
    let resolution = (
        (node("server"), place.clone()),
        ResolvedMemPlace::virtual_address(0x7000, 1),
    );

    assert!(!evaluator(34, vec![sample.clone()]).evaluate_assertion_condition(&condition));
    assert!(
        evaluator_with_resolution(34, vec![sample], vec![resolution])
            .evaluate_assertion_condition(&condition)
    );
}

#[test]
fn memory_sample_event_keeps_sample_icount_and_explicit_evaluation_time() {
    let event = ObservableEvent::memory_sample(
        time(99),
        icount(44),
        node("server"),
        ResolvedMemPlace::physical_address(0x1000, 8),
        0,
    );

    assert_eq!(event.at(), time(99));
    match event.payload() {
        crucible::ObservableEventPayload::MemorySample { sample_icount, .. } => {
            assert_eq!(sample_icount.retired, 44);
        }
        other => panic!("memory constructor should build memory payload: {other:?}"),
    }
}

#[test]
fn event_graph_fires_from_memory_predicate_without_guest_marker_support() {
    let graph = EventGraph::new_for_world(
        vec![Event::once(
            crucible::EventId::from_name("pass-on-state"),
            Some(Predicate::memory_predicate(
                node("server"),
                MemPlace::register("rax", MemoryWidth::U64),
                MemoryCmp::Eq,
                3,
            )),
            Action::Pass,
        )],
        &memory_world(),
    )
    .expect("memory event graph should build");
    let mut state = EventGraphState::new();
    let events = vec![ObservableEvent::memory_sample(
        time(55),
        icount(55),
        node("server"),
        ResolvedMemPlace::register("rax", 8),
        3,
    )];

    let firings = support::evaluate_graph(&graph, &mut state, evaluator(55, events));

    assert_eq!(firings.len(), 1);
    assert_eq!(firings[0].event().name, "pass-on-state");
}

#[test]
fn memory_predicate_properties_validate_referenced_nodes() {
    let properties = Properties::from_assertions_for_world(
        &memory_world(),
        vec![assertion(
            "missing-node",
            Predicate::memory_predicate(
                node("missing"),
                MemPlace::physical_address(0x1000, MemoryWidth::U8),
                MemoryCmp::Eq,
                1,
            ),
        )],
    );

    match properties {
        Err(EngineError::PropertyPredicateUnknownNode { node }) => {
            assert_eq!(node.name, "missing");
        }
        other => panic!("memory property should reject unknown node: {other:?}"),
    }
}

#[test]
fn memory_predicate_round_trips_through_properties_serialization() {
    let world = memory_world();
    let predicate = Predicate::all_of(vec![
        Predicate::memory_predicate(
            node("server"),
            MemPlace::physical_address(0x1000, MemoryWidth::U32),
            MemoryCmp::Eq,
            0xfeed,
        ),
        Predicate::memory_predicate(
            node("db-0"),
            MemPlace::symbol("wal_state", MemoryWidth::U8),
            MemoryCmp::Ge,
            2,
        ),
    ]);
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![assertion("memory-predicates", predicate)],
    )
    .expect("memory properties should validate");

    let toml = properties
        .to_canonical_toml()
        .expect("properties TOML should serialize");
    assert!(toml.contains("kind = \"memory_predicate\""));
    assert!(toml.contains("kind = \"physical_address\""));
    assert!(toml.contains("kind = \"symbol\""));
    assert!(toml.contains("cmp = \"ge\""));
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
fn memory_predicate_material_distinguishes_place_cmp_and_value() {
    let address_a = properties_for(Predicate::memory_predicate(
        node("server"),
        MemPlace::physical_address(0x1000, MemoryWidth::U32),
        MemoryCmp::Eq,
        1,
    ));
    let address_b = properties_for(Predicate::memory_predicate(
        node("server"),
        MemPlace::physical_address(0x2000, MemoryWidth::U32),
        MemoryCmp::Eq,
        1,
    ));
    let cmp_b = properties_for(Predicate::memory_predicate(
        node("server"),
        MemPlace::physical_address(0x1000, MemoryWidth::U32),
        MemoryCmp::Ne,
        1,
    ));
    let value_b = properties_for(Predicate::memory_predicate(
        node("server"),
        MemPlace::physical_address(0x1000, MemoryWidth::U32),
        MemoryCmp::Eq,
        2,
    ));

    assert_ne!(address_a.content_hash(), address_b.content_hash());
    assert_ne!(address_a.content_hash(), cmp_b.content_hash());
    assert_ne!(address_a.content_hash(), value_b.content_hash());
}
