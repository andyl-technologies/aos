//! Checks T-ASRT-17 predicate DSL desugaring.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    Action, AssertionDef, AssertionId, ConditionEvaluationPass, Event, EventGraph, EventGraphState,
    FaultTag, Icount, LinkDef, MembershipFault, NodeId, NodeLifecycle, NodeTemplate, Plan,
    PlanEntry, Predicate, Properties, Property, ReadyPoint, RestartPolicy, VirtualTime,
    VmArchitecture, WhiteBoxPolicy, World, WorldNode,
};

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn tag(name: &str) -> FaultTag {
    FaultTag::from_name(name)
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

fn world() -> World {
    World::from_nodes_and_links(
        vec![ready_node("db-0"), ready_node("db-1")],
        vec![LinkDef::new(node("db-0"), node("db-1")).expect("test link should build")],
    )
    .expect("predicate DSL test world should build")
}

fn plan(world: &World) -> Plan {
    Plan::from_entries_for_world(
        world,
        vec![PlanEntry::Activate {
            at: VirtualTime { ticks: 5 },
            tag: tag("split"),
            fault: MembershipFault::Crash {
                node: node("db-1"),
                restart: RestartPolicy::StayDown,
            },
        }],
    )
    .expect("predicate DSL test plan should build")
}

fn assertion(id: &str, message: &str, property: Property) -> AssertionDef {
    AssertionDef {
        id: AssertionId::from_name(id),
        message: message.to_owned(),
        property,
    }
}

fn always(predicate: Predicate) -> Property {
    Property::Always { predicate }
}

fn false_leaf(_leaf: crucible::ConditionLeaf<'_>) -> bool {
    false
}

fn active_split_entry(sequence: u64) -> crucible::SchedulerEventLogEntry {
    crucible::test_support::condition_payload_entry_for_test(
        sequence,
        VirtualTime { ticks: 7 },
        crucible::SchedulerEventLogPayload::TriggerActionApplied(
            crucible::TriggerActionApplication {
                sequence: 0,
                event: crucible::EventId::from_name("inject-split"),
                at: VirtualTime { ticks: 7 },
                path: Vec::new(),
                action: Action::inject_fault(
                    tag("split"),
                    MembershipFault::Crash {
                        node: node("db-1"),
                        restart: RestartPolicy::StayDown,
                    },
                ),
            },
        ),
    )
}

#[test]
fn predicate_dsl_desugars_to_concrete_conditions_for_properties() {
    let world = world();
    let plan = plan(&world);
    let dsl = Properties::from_assertions_for_world_and_plan(
        &world,
        &plan,
        vec![
            assertion(
                "no-crashed-nodes",
                "cluster has no crashed nodes",
                always(Predicate::named("no_crashed_nodes")),
            ),
            assertion(
                "quiescent",
                "cluster is quiescent",
                always(Predicate::named("quiescent")),
            ),
            assertion(
                "no-active-faults",
                "cluster has no active faults",
                always(Predicate::named("no_active_faults")),
            ),
            assertion(
                "node-alive",
                "db-0 stays alive",
                always(Predicate::named("node_alive:db-0")),
            ),
            assertion(
                "node-crashed",
                "db-1 crashed at least once",
                always(Predicate::named("node_crashed:db-1")),
            ),
            assertion(
                "custom-host",
                "uncovered predicates remain host-extensible",
                always(Predicate::named("custom-host")),
            ),
        ],
    )
    .expect("DSL properties should resolve");

    let expanded = Properties::from_assertions_for_world(
        &world,
        vec![
            assertion(
                "no-crashed-nodes",
                "cluster has no crashed nodes",
                always(Predicate::not(Predicate::any_of(vec![
                    Predicate::node_state(node("db-0"), NodeLifecycle::Crashed),
                    Predicate::node_state(node("db-1"), NodeLifecycle::Crashed),
                ]))),
            ),
            assertion(
                "quiescent",
                "cluster is quiescent",
                always(Predicate::quiescent()),
            ),
            assertion(
                "no-active-faults",
                "cluster has no active faults",
                always(Predicate::not(Predicate::any_of(vec![
                    Predicate::fault_active(tag("split")),
                ]))),
            ),
            assertion(
                "node-alive",
                "db-0 stays alive",
                always(Predicate::not(Predicate::node_state(
                    node("db-0"),
                    NodeLifecycle::Crashed,
                ))),
            ),
            assertion(
                "node-crashed",
                "db-1 crashed at least once",
                always(Predicate::once(Predicate::node_state(
                    node("db-1"),
                    NodeLifecycle::Crashed,
                ))),
            ),
            assertion(
                "custom-host",
                "uncovered predicates remain host-extensible",
                always(Predicate::named("custom-host")),
            ),
        ],
    )
    .expect("expanded properties should validate");

    assert_eq!(
        dsl, expanded,
        "DSL properties must hash as the concrete expanded condition tree"
    );
}

#[test]
fn predicate_dsl_string_toml_parses_for_properties_and_triggers() {
    let world = world();
    let expected_properties = Properties::from_assertions_for_world_and_plan(
        &world,
        &plan(&world),
        vec![assertion(
            "toml-no-active-faults",
            "cluster has no active faults",
            always(Predicate::named("no_active_faults")),
        )],
    )
    .expect("expected DSL properties should resolve");
    let properties_toml = format!(
        r#"
id = "blake3:{}"

[[assertion]]
id = "toml-no-active-faults"
message = "cluster has no active faults"

[assertion.property]
kind = "always"
predicate = "no_active_faults"
"#,
        expected_properties.content_hash().to_hex()
    );
    let parsed_properties =
        Properties::from_canonical_toml_for_world_and_plan(&world, &plan(&world), &properties_toml)
            .expect("string-authored DSL properties TOML should parse");
    assert_eq!(parsed_properties, expected_properties);

    let raw_graph = EventGraph::new_for_world(
        vec![Event::once(
            crucible::EventId::from_name("pass-on-quiet"),
            Some(Predicate::named("quiescent")),
            Action::pass(),
        )],
        &world,
    )
    .expect("raw graph with host-style named trigger should validate");
    let expected_plan = Plan::from_event_graph_for_world(&world, raw_graph)
        .expect("graph plan should resolve DSL trigger");
    let plan_toml = format!(
        r#"
id = "blake3:{}"
kind = "event_graph"

[[event]]
id = "pass-on-quiet"
trigger = "quiescent"
action = {{ kind = "pass" }}
"#,
        expected_plan.content_hash().to_hex()
    );
    let parsed_plan = Plan::from_canonical_toml_for_world(&world, &plan_toml)
        .expect("string-authored DSL trigger TOML should parse");

    assert_eq!(parsed_plan, expected_plan);
}

#[test]
fn fault_active_condition_uses_recorded_fault_facts() {
    let graph = EventGraph::new_for_world(
        vec![
            Event::once(
                crucible::EventId::from_name("inject-split"),
                None,
                Action::inject_fault(
                    tag("split"),
                    MembershipFault::Crash {
                        node: node("db-1"),
                        restart: RestartPolicy::StayDown,
                    },
                ),
            ),
            Event::once(
                crucible::EventId::from_name("pass-when-split-active"),
                Some(Predicate::fault_active(tag("split"))),
                Action::pass(),
            ),
        ],
        &world(),
    )
    .expect("fault-active trigger should validate against injected tags");
    let mut state = EventGraphState::new();
    let prefix = crucible::test_support::condition_prefix_from_scheduler_entries_for_test(vec![
        active_split_entry(0),
    ])
    .expect("fault-active prefix should validate");
    let mut pass = ConditionEvaluationPass::from_log_prefix(prefix, false_leaf);
    let firings = pass.evaluate_event_graph(&graph, &mut state);

    assert_eq!(firings.len(), 1);
    assert_eq!(
        firings[0].event(),
        &crucible::EventId::from_name("pass-when-split-active")
    );
}
