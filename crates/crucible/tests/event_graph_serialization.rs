//! Checks T-TRIG-18 graph-native plan authoring and serialization.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    Action, AssertionDef, AssertionId, AssertionPhase, Condition, ContentHash, EngineError,
    EventGraph, EventId, FaultTag, Icount, LinkDef, LogLevel, MembershipFault, NodeId,
    NodeLifecycle, PartitionDirection, Plan, Properties, Property, ReadyPoint, RegexProgram,
    ScenarioDefForm, Seed, SimDuration, World, WorldNode,
};

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_string(),
    }
}

fn event(name: &str) -> EventId {
    EventId::from_name(name)
}

fn tag(name: &str) -> FaultTag {
    FaultTag {
        name: name.to_string(),
    }
}

fn timer(name: &str) -> crucible::TimerId {
    crucible::TimerId {
        name: name.to_string(),
    }
}

fn assertion(name: &str) -> AssertionId {
    AssertionId::from_name(name)
}

fn world_node(name: &str, ready_at: u64) -> WorldNode {
    WorldNode {
        id: node(name),
        arch: crucible::VmArchitecture::X86_64,
        memory_mib: 128,
        cmdline: String::new(),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: ready_at },
        },
        white_box: crucible::WhiteBoxPolicy::Disabled,
        smp_vcpus: 1,
        icount_shift: 0,
        kernel: None,
        root_image: None,
        initrd: None,
    }
}

fn world() -> World {
    World::from_nodes_and_links(
        vec![world_node("db-0", 10), world_node("db-1", 11)],
        vec![LinkDef::new(node("db-0"), node("db-1")).expect("test link should be valid")],
    )
    .expect("test world should be valid")
}

fn compatible_changed_world() -> World {
    World::from_nodes_and_links(
        vec![world_node("db-0", 12), world_node("db-1", 13)],
        vec![LinkDef::new(node("db-0"), node("db-1")).expect("test link should be valid")],
    )
    .expect("changed test world should be valid")
}

fn properties() -> Properties {
    Properties::from_assertions_for_world(
        &world(),
        vec![AssertionDef {
            id: assertion("cluster-safe"),
            message: String::from("cluster eventually reports safe state"),
            property: Property::Always {
                predicate: Condition::node_state(node("db-0"), NodeLifecycle::Started),
            },
        }],
    )
    .expect("test properties should be valid")
}

fn graph(world: &World) -> EventGraph {
    EventGraph::builder()
        .event("bootstrap")
        .action(Action::group(vec![
            Action::inject_fault(
                tag("split"),
                MembershipFault::Partition {
                    endpoint_a: node("db-0"),
                    endpoint_b: node("db-1"),
                    direction: PartitionDirection::Bidirectional,
                },
            ),
            Action::arm_timer(timer("heal-after"), SimDuration { nanos: 30 }),
            Action::log(LogLevel::Info, "split armed"),
        ]))
        .event("heal")
        .when(Condition::timer(timer("heal-after")))
        .action(Action::heal_fault(tag("split")))
        .event("pass-when-safe")
        .when(Condition::all_of(vec![
            Condition::assertion_state(assertion("cluster-safe"), AssertionPhase::Satisfied),
            Condition::console_match(
                node("db-0"),
                RegexProgram {
                    pattern: String::from("converged"),
                },
            ),
        ]))
        .action(Action::pass())
        .build_with_assertions_for_world([assertion("cluster-safe")], world)
        .expect("event graph builder should validate")
}

#[test]
fn event_graph_builder_validates_before_plan_hashing() {
    let world = world();
    let graph = graph(&world);
    assert_eq!(graph.events().len(), 3);
    assert_eq!(graph.events()[0].id, event("bootstrap"));

    let invalid = EventGraph::builder()
        .event("invalid")
        .repeatable()
        .action(Action::pass())
        .build_for_world(&world);
    assert!(matches!(
        invalid,
        Err(crucible::EventGraphError::RepeatableEntrypoint { event: id })
            if id == event("invalid")
    ));
}

#[test]
fn event_graph_plan_round_trips_through_toml_and_binary() {
    let world = world();
    let graph = graph(&world);
    let plan = Plan::from_event_graph_with_assertions_for_world(
        &world,
        [assertion("cluster-safe")],
        graph.clone(),
    )
    .expect("graph plan should validate");

    assert!(plan.entries().is_empty());
    assert_eq!(plan.event_graph(), Some(&graph));
    assert_eq!(
        plan.content_hash(),
        ContentHash::from_canonical_material(
            "crucible.model.plan.v3",
            &String::from_utf8(plan.canonical_bytes())
                .expect("plan canonical bytes should be UTF-8"),
        )
    );

    let toml = plan
        .to_canonical_toml()
        .expect("graph plan TOML should serialize");
    assert!(toml.contains("kind = \"event_graph\""));
    assert!(toml.contains("[[event]]"));
    assert!(!toml.contains("[[entry]]"));

    let parsed_toml = Plan::from_canonical_toml_with_assertions_for_world(
        &world,
        [assertion("cluster-safe")],
        &toml,
    )
    .expect("graph plan TOML should parse");
    assert_eq!(parsed_toml, plan);
    assert_eq!(parsed_toml.canonical_bytes(), plan.canonical_bytes());

    let parsed_binary = Plan::from_compact_binary_with_assertions_for_world(
        &world,
        [assertion("cluster-safe")],
        &plan.to_compact_binary(),
    )
    .expect("graph plan binary should parse");
    assert_eq!(parsed_binary, plan);
    assert_eq!(parsed_binary.to_compact_binary(), plan.to_compact_binary());
}

#[test]
fn graph_plan_lowering_keeps_assertion_state_triggers_valid() {
    let world = world();
    let plan = Plan::from_event_graph_with_assertions_for_world(
        &world,
        [assertion("cluster-safe")],
        graph(&world),
    )
    .expect("graph plan should validate with its assertion namespace");

    let lowered = plan
        .lower_to_event_graph_for_world(&world)
        .expect("graph-native lowering should preserve assertion-state triggers");

    assert_eq!(lowered.event_graph(), plan.event_graph().unwrap());
    assert_eq!(lowered.content_hash(), plan.content_hash());
    assert_eq!(lowered.canonical_bytes(), plan.canonical_bytes().as_slice());
}

#[test]
fn graph_plan_is_the_scenario_plan_component() {
    let world = world();
    let properties = properties();
    let plan = Plan::from_event_graph_with_assertions_for_world(
        &world,
        [assertion("cluster-safe")],
        graph(&world),
    )
    .expect("graph plan should validate");
    let form =
        ScenarioDefForm::from_components(&world, &plan, &properties, Seed::from_u64(0x0010_0018))
            .expect("graph scenario form should build");

    assert_eq!(form.plan(), &plan);
    assert_eq!(form.plan().event_graph(), plan.event_graph());

    let scenario_toml = form
        .to_canonical_toml()
        .expect("scenario TOML should serialize");
    assert!(scenario_toml.contains("[[plan.event]]"));
    assert!(scenario_toml.contains("kind = \"event_graph\""));
    let parsed_toml =
        ScenarioDefForm::from_canonical_toml(&scenario_toml).expect("scenario TOML should parse");
    assert_eq!(parsed_toml, form);

    let parsed_binary = ScenarioDefForm::from_compact_binary(&form.to_compact_binary())
        .expect("scenario binary should parse");
    assert_eq!(parsed_binary, form);

    let changed_properties = Properties::from_assertions_for_world(
        &world,
        vec![AssertionDef {
            id: assertion("cluster-safe"),
            message: String::from("same id, different predicate"),
            property: Property::Always {
                predicate: Condition::node_state(node("db-1"), NodeLifecycle::Started),
            },
        }],
    )
    .expect("changed properties should be valid");
    let changed_properties_form = ScenarioDefForm::from_components(
        &world,
        &plan,
        &changed_properties,
        Seed::from_u64(0x0010_0018),
    )
    .expect("changed properties form should build");
    assert_eq!(
        changed_properties_form.plan().content_hash(),
        plan.content_hash()
    );
    assert_ne!(
        changed_properties_form.properties().content_hash(),
        properties.content_hash()
    );
    assert_ne!(changed_properties_form.id(), form.id());

    let changed_world = compatible_changed_world();
    let changed_world_plan = Plan::from_event_graph_with_assertions_for_world(
        &changed_world,
        [assertion("cluster-safe")],
        graph(&changed_world),
    )
    .expect("same graph should validate against compatible changed world");
    assert_eq!(changed_world_plan.content_hash(), plan.content_hash());
    let changed_world_form = ScenarioDefForm::from_components(
        &changed_world,
        &changed_world_plan,
        &changed_properties,
        Seed::from_u64(0x0010_0018),
    )
    .expect("changed world form should build");
    assert_ne!(changed_world_form.id(), changed_properties_form.id());
}

#[test]
fn assertion_references_are_validated_when_plan_enters_scenario_form() {
    let world = world();
    let graph = EventGraph::builder()
        .event("pass")
        .when(Condition::assertion_state(
            assertion("missing"),
            AssertionPhase::Satisfied,
        ))
        .action(Action::pass())
        .build_with_assertions_for_world([assertion("missing")], &world)
        .expect("graph can be built with its declared assertion namespace");

    let plan_without_assertions = Plan::from_event_graph_for_world(&world, graph.clone());
    assert!(matches!(
        plan_without_assertions,
        Err(EngineError::ScenarioSerialization { reason })
            if reason.contains("event graph plan validation failed")
    ));

    let plan =
        Plan::from_event_graph_with_assertions_for_world(&world, [assertion("missing")], graph)
            .expect("plan should build with matching assertion namespace");
    let form = ScenarioDefForm::from_components(
        &world,
        &plan,
        &Properties::empty(),
        Seed::from_u64(0x0010_0019),
    );
    assert!(matches!(
        form,
        Err(EngineError::ScenarioSerialization { reason })
            if reason.contains("UnknownAssertionReference")
                || reason.contains("unknown assertion")
                || reason.contains("event graph plan validation failed")
    ));
}
