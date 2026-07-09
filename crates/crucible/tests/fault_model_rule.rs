//! Checks T-FAULT-2 modeled-only fault application.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    Action, ConditionLeaf, ConditionLeafOracle, Event, EventGraph, EventGraphState, EventId,
    FaultTag, Icount, LinkDef, MembershipFault, NodeId, NodeTemplate, PartitionDirection,
    Predicate, ReadyPoint, SchedulerEvaluationBoundaryKind, SchedulerEventLogClass,
    SchedulerEventLogPayload, SchedulerLivenessScenario, Shift, SimDuration, SimInstant,
    SingleScheduler, TimerId, VmArchitecture, WhiteBoxPolicy, World, WorldNode,
};

fn event_id(name: &str) -> EventId {
    EventId::from_name(name)
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: String::from(name),
    }
}

fn tag(name: &str) -> FaultTag {
    FaultTag::from_name(name)
}

fn timer(name: &str) -> TimerId {
    TimerId {
        name: String::from(name),
    }
}

fn duration(nanos: u64) -> SimDuration {
    SimDuration { nanos }
}

fn time(ticks: u64) -> crucible::VirtualTime {
    crucible::VirtualTime { ticks }
}

fn split_fault() -> MembershipFault {
    MembershipFault::Partition {
        endpoint_a: node("db-0"),
        endpoint_b: node("db-1"),
        direction: PartitionDirection::Bidirectional,
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

fn fault_world() -> World {
    World::from_nodes_and_links(
        vec![ready_node("db-0"), ready_node("db-1")],
        vec![LinkDef::new(node("db-0"), node("db-1")).expect("test link should build")],
    )
    .expect("fault model rule world should build")
}

fn scenario(name: &str, world: &World) -> SchedulerLivenessScenario {
    SchedulerLivenessScenario::from_canonical_material(
        name,
        Shift { bits: 0 },
        8,
        SimInstant { nanos: 20 },
        Vec::new(),
        Vec::new(),
    )
    .with_trigger_world(world)
}

fn fault_graph(world: &World) -> EventGraph {
    let heal_timer = timer("heal-split");
    EventGraph::new_for_world(
        vec![
            Event::once(
                event_id("inject-split"),
                None,
                Action::Group(vec![
                    Action::InjectFault {
                        tag: tag("split"),
                        fault: split_fault(),
                    },
                    Action::ArmTimer {
                        name: heal_timer.clone(),
                        after: duration(5),
                    },
                ]),
            ),
            Event::once(
                event_id("heal-split"),
                Some(Predicate::timer(heal_timer)),
                Action::HealFault { tag: tag("split") },
            ),
        ],
        world,
    )
    .expect("fault model rule graph should build")
}

struct NoLeaves;

impl ConditionLeafOracle for NoLeaves {
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { .. } | ConditionLeaf::GuestMarker { .. } => {
                panic!("fault model rule test should not evaluate external leaves")
            }
        }
    }
}

fn fired_names(firings: &crucible::EventFirings) -> Vec<&str> {
    firings
        .iter()
        .map(|firing| firing.event().name.as_str())
        .collect()
}

#[test]
fn fault_application_changes_active_faults_not_schedule_or_static_topology() {
    let world = fault_world();
    let graph = fault_graph(&world);
    let mut graph_state = EventGraphState::new();
    let mut scheduler =
        SingleScheduler::new(scenario("fault-model-rule", &world)).expect("scheduler builds");
    let before_schedule = scheduler.configuration().schedule.clone();
    let before_topology = scheduler
        .trigger_static_topology()
        .cloned()
        .expect("scheduler should carry world-derived topology");
    let before_world_topology = world.static_topology();

    let inject = scheduler.evaluate_event_graph(&graph, &mut graph_state, NoLeaves);
    assert_eq!(fired_names(&inject), vec!["inject-split"]);
    let inject_append = scheduler
        .apply_trigger_firings(&inject)
        .expect("fault injection should apply");

    assert_eq!(scheduler.configuration().schedule, before_schedule);
    assert_eq!(
        scheduler.trigger_actions().active_faults.get(&tag("split")),
        Some(&split_fault())
    );
    assert_eq!(scheduler.trigger_static_topology(), Some(&before_topology));
    assert_eq!(world.static_topology(), before_world_topology);
    assert!(
        inject_append
            .entries
            .iter()
            .all(|entry| !matches!(entry.payload(), SchedulerEventLogPayload::Decision(_))),
        "fault trigger application must not append Schedule decisions"
    );
    assert!(inject_append.entries.iter().any(|entry| {
        matches!(
            entry.payload(),
            SchedulerEventLogPayload::TriggerActionApplied(application)
                if matches!(application.action, Action::InjectFault { .. })
                    && entry.class() == SchedulerEventLogClass::Causal
        )
    }));

    scheduler
        .append_evaluation_boundary(time(5), SchedulerEvaluationBoundaryKind::Quantum)
        .expect("timer evaluation boundary should append");
    let heal = scheduler.evaluate_event_graph(&graph, &mut graph_state, NoLeaves);
    assert_eq!(fired_names(&heal), vec!["heal-split"]);
    let heal_append = scheduler
        .apply_trigger_firings(&heal)
        .expect("fault heal should apply");

    assert_eq!(scheduler.configuration().schedule, before_schedule);
    assert!(scheduler.trigger_actions().active_faults.is_empty());
    assert_eq!(scheduler.trigger_static_topology(), Some(&before_topology));
    assert_eq!(world.static_topology(), before_world_topology);
    assert!(heal_append.entries.iter().any(|entry| {
        matches!(
            entry.payload(),
            SchedulerEventLogPayload::TriggerActionApplied(application)
                if matches!(application.action, Action::HealFault { .. })
                    && entry.class() == SchedulerEventLogClass::Causal
        )
    }));
}
