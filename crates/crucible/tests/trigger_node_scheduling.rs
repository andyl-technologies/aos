//! Checks T-TRIG-13 trigger node scheduling against static world topology.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    Action, ConditionEvaluationPass, ConditionLeaf, ConditionLeafOracle, Event, EventGraph,
    EventGraphError, EventGraphState, EventId, Icount, NodeId, NodeLifecycle, NodeTemplate,
    ReadyPoint, SchedulerLivenessScenario, Shift, SimInstant, SingleScheduler, VmArchitecture,
    WhiteBoxPolicy, World, WorldNode,
};

fn event_id(name: &str) -> EventId {
    EventId::from_name(name)
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: String::from(name),
    }
}

fn shift(bits: u8) -> Shift {
    Shift { bits }
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

fn world_with(nodes: &[&str]) -> World {
    World::from_nodes(nodes.iter().copied().map(ready_node).collect())
        .expect("trigger node scheduling test world should build")
}

fn scenario_without_world(name: &str) -> SchedulerLivenessScenario {
    SchedulerLivenessScenario::from_canonical_material(
        name,
        shift(0),
        8,
        SimInstant { nanos: 20 },
        Vec::new(),
        Vec::new(),
    )
}

fn scenario_for_world(name: &str, world: &World) -> SchedulerLivenessScenario {
    scenario_without_world(name).with_trigger_world(world)
}

struct NoLeaves;

impl ConditionLeafOracle for NoLeaves {
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { .. } | ConditionLeaf::GuestMarker { .. } => {
                panic!("entrypoint node scheduling test should not evaluate leaves")
            }
        }
    }
}

fn evaluate_genesis(graph: &EventGraph, scheduler: &SingleScheduler) -> crucible::EventFirings {
    let mut state = EventGraphState::new();
    let mut pass = ConditionEvaluationPass::from_log_prefix(
        scheduler.condition_event_log_prefix().clone(),
        NoLeaves,
    );
    pass.evaluate_event_graph(graph, &mut state)
}

#[test]
fn start_stop_schedule_declared_baked_nodes_without_topology_mutation() {
    let world = world_with(&["db-0", "db-1", "standby"]);
    let graph = EventGraph::new_for_world(
        vec![Event::once(
            event_id("node-lifecycle"),
            None,
            Action::Group(vec![
                Action::StartNode {
                    node: node("standby"),
                },
                Action::StopNode { node: node("db-1") },
            ]),
        )],
        &world,
    )
    .expect("declared baked node schedule graph should build");
    let mut scheduler = SingleScheduler::new(scenario_for_world("trigger-node-scheduling", &world))
        .expect("scheduler builds");
    let before_schedule = scheduler.configuration().schedule.clone();
    let world_topology = world.static_topology();
    let before_topology = scheduler
        .trigger_static_topology()
        .cloned()
        .expect("scheduler should carry trigger static topology");

    assert_eq!(before_topology, world_topology);

    let firings = evaluate_genesis(&graph, &scheduler);
    scheduler
        .apply_trigger_firings(&firings)
        .expect("declared baked nodes should schedule");

    assert_eq!(scheduler.configuration().schedule, before_schedule);
    assert_eq!(
        scheduler
            .trigger_actions()
            .node_states
            .get(&node("standby")),
        Some(&NodeLifecycle::Started)
    );
    assert_eq!(
        scheduler.trigger_actions().node_states.get(&node("db-1")),
        Some(&NodeLifecycle::Exited)
    );

    let after_topology = scheduler
        .trigger_static_topology()
        .expect("scheduler should retain trigger static topology");
    assert_eq!(after_topology, &before_topology);
    assert_eq!(after_topology.participants, world_topology.participants);
    assert_eq!(after_topology.rng_streams, world_topology.rng_streams);
    assert_eq!(
        after_topology.lookahead_graph,
        world_topology.lookahead_graph
    );
    assert_eq!(after_topology.bake_nodes, world_topology.bake_nodes);
    assert_eq!(world.static_topology(), world_topology);
}

#[test]
fn start_stop_without_world_static_topology_is_rejected_atomically() {
    let graph_world = world_with(&["standby"]);
    let graph = EventGraph::new_for_world(
        vec![Event::once(
            event_id("start-without-world"),
            None,
            Action::StartNode {
                node: node("standby"),
            },
        )],
        &graph_world,
    )
    .expect("world-aware graph construction should build");
    let mut scheduler = SingleScheduler::new(scenario_without_world("trigger-node-no-world"))
        .expect("scheduler builds");
    let before_actions = scheduler.trigger_actions().clone();
    let before_offset = scheduler.event_log_offset();
    let firings = evaluate_genesis(&graph, &scheduler);

    let error = scheduler
        .apply_trigger_firings(&firings)
        .expect_err("node scheduling without world topology should fail");

    assert!(
        error.to_string().contains("no world static topology"),
        "unexpected error: {error}"
    );
    assert_eq!(scheduler.trigger_static_topology(), None);
    assert_eq!(scheduler.trigger_actions(), &before_actions);
    assert_eq!(scheduler.event_log_offset(), before_offset);
}

#[test]
fn scheduler_rejects_undeclared_node_schedule_target_atomically() {
    let scheduler_world = world_with(&["db-0"]);
    let graph_world = world_with(&["missing"]);
    let graph = EventGraph::new_for_world(
        vec![Event::once(
            event_id("start-missing"),
            None,
            Action::StartNode {
                node: node("missing"),
            },
        )],
        &graph_world,
    )
    .expect("graph world declares the node schedule target");
    let mut scheduler = SingleScheduler::new(scenario_for_world(
        "trigger-node-undeclared",
        &scheduler_world,
    ))
    .expect("scheduler builds");
    let before_actions = scheduler.trigger_actions().clone();
    let before_offset = scheduler.event_log_offset();
    let firings = evaluate_genesis(&graph, &scheduler);

    let error = scheduler
        .apply_trigger_firings(&firings)
        .expect_err("undeclared node schedule target should fail");

    assert!(
        error.to_string().contains("undeclared node `missing`"),
        "unexpected error: {error}"
    );
    assert_eq!(
        scheduler.trigger_static_topology(),
        Some(&scheduler_world.static_topology())
    );
    assert_eq!(scheduler.trigger_actions(), &before_actions);
    assert_eq!(scheduler.event_log_offset(), before_offset);
}

#[test]
fn event_graph_requires_world_for_start_stop_targets() {
    let cases = vec![
        (
            "start-without-world",
            Action::StartNode {
                node: node("standby"),
            },
            "standby",
        ),
        (
            "stop-without-world",
            Action::StopNode { node: node("db-0") },
            "db-0",
        ),
    ];

    for (event_name, action, node_name) in cases {
        let error = EventGraph::new(vec![Event::once(event_id(event_name), None, action)])
            .expect_err("world-agnostic graph construction should reject node scheduling");

        match error {
            EventGraphError::NodeScheduleTargetRequiresWorld {
                event,
                node: missing_world_node,
            } => {
                assert_eq!(event, event_id(event_name));
                assert_eq!(missing_world_node, node(node_name));
            }
            other => panic!("unexpected error for {event_name}: {other}"),
        }
    }
}

#[test]
fn event_graph_for_world_rejects_undeclared_start_stop_targets() {
    let world = world_with(&["db-0"]);
    let cases = vec![
        (
            "start-missing",
            Action::StartNode {
                node: node("missing-start"),
            },
            "missing-start",
        ),
        (
            "stop-missing",
            Action::StopNode {
                node: node("missing-stop"),
            },
            "missing-stop",
        ),
    ];

    for (event_name, action, node_name) in cases {
        let error = EventGraph::new_for_world(
            vec![Event::once(event_id(event_name), None, action)],
            &world,
        )
        .expect_err("world-aware graph construction should reject unknown nodes");

        match error {
            EventGraphError::UndeclaredNodeScheduleTarget {
                event,
                node: missing_node,
            } => {
                assert_eq!(event, event_id(event_name));
                assert_eq!(missing_node, node(node_name));
            }
            other => panic!("unexpected error for {event_name}: {other}"),
        }
    }
}
