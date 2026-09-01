//! Checks T-ASRT-17 predicate DSL desugaring.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used)]

use crucible::{
    Action, AssertionDef, AssertionId, Event, EventGraph, NodeLifecycle, Plan, Predicate,
    Properties, Property,
};

fn always(predicate: Predicate) -> Property {
    Property::Always { predicate }
}

#[test]
fn predicate_dsl_desugars_supported_world_predicates_and_preserves_host_extensions() {
    let fixture = crucible::happy_path_scenario().expect("happy-path fixture should build");
    let world = fixture.scenario.world();
    let plan = Plan::empty();
    let server = world.vm_nodes()[0].id.clone();
    let dsl = Properties::from_assertions_for_world_and_plan(
        world,
        &plan,
        vec![
            AssertionDef {
                id: AssertionId::from_name("no-crashes"),
                message: String::from("nodes remain available"),
                property: always(Predicate::named("no_crashed_nodes")),
            },
            AssertionDef {
                id: AssertionId::from_name("server-alive"),
                message: String::from("server remains alive"),
                property: always(Predicate::named(format!("node_alive:{}", server.name))),
            },
            AssertionDef {
                id: AssertionId::from_name("custom-host"),
                message: String::from("uncovered predicates remain host-extensible"),
                property: always(Predicate::named("custom-host")),
            },
        ],
    )
    .expect("DSL properties should resolve");

    let expanded = Properties::from_assertions_for_world(
        world,
        vec![
            AssertionDef {
                id: AssertionId::from_name("no-crashes"),
                message: String::from("nodes remain available"),
                property: always(Predicate::not(Predicate::any_of(
                    world
                        .vm_nodes()
                        .iter()
                        .map(|node| Predicate::node_state(node.id.clone(), NodeLifecycle::Crashed))
                        .collect(),
                ))),
            },
            AssertionDef {
                id: AssertionId::from_name("server-alive"),
                message: String::from("server remains alive"),
                property: always(Predicate::not(Predicate::node_state(
                    server,
                    NodeLifecycle::Crashed,
                ))),
            },
            AssertionDef {
                id: AssertionId::from_name("custom-host"),
                message: String::from("uncovered predicates remain host-extensible"),
                property: always(Predicate::named("custom-host")),
            },
        ],
    )
    .expect("expanded properties should validate");

    assert_eq!(dsl, expanded);
}

#[test]
fn predicate_dsl_string_toml_parses_for_properties_and_triggers() {
    let fixture = crucible::happy_path_scenario().expect("happy-path fixture should build");
    let world = fixture.scenario.world();
    let plan = Plan::empty();
    let expected = Properties::from_assertions_for_world_and_plan(
        world,
        &plan,
        vec![AssertionDef {
            id: AssertionId::from_name("quiet"),
            message: String::from("world becomes quiescent"),
            property: always(Predicate::named("quiescent")),
        }],
    )
    .expect("expected DSL properties should resolve");
    let properties_toml = format!(
        "id = \"blake3:{}\"\n\n[[assertion]]\nid = \"quiet\"\nmessage = \"world becomes quiescent\"\n\n[assertion.property]\nkind = \"always\"\npredicate = \"quiescent\"\n",
        expected.content_hash().to_hex()
    );
    let parsed = Properties::from_canonical_toml_for_world_and_plan(world, &plan, &properties_toml)
        .expect("plan-aware TOML DSL should parse");
    assert_eq!(parsed, expected);

    let graph = EventGraph::new_for_world(
        vec![Event::once(
            crucible::EventId::from_name("pass-on-quiet"),
            Some(Predicate::named("quiescent")),
            Action::pass(),
        )],
        world,
    )
    .expect("raw graph should validate");
    let resolved = Plan::from_event_graph_for_world(world, graph)
        .expect("trigger DSL should resolve against the World");
    assert!(matches!(
        resolved.event_graph().events()[0].trigger,
        Some(Predicate::Quiescent)
    ));
}
