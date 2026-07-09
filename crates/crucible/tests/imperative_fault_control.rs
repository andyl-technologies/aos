//! Checks T-FAULT-11 imperative fault control at scheduler boundaries.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    ControlFaultAction, ControlOperation, ControlOperationKind, Decision, ExactLocalEvent, Fault,
    FaultSlowdownFactorBasisPoints, FaultTag, Icount, LinkDef, LinkId, NetworkFault,
    NetworkLookahead, NodeCounter, NodeFault, NodeId, NodeTemplate, PartitionDirection,
    QuantumLoop, QuantumRequest, ReadyPoint, Schedule, SchedulerLivenessScenario,
    SchedulerLookaheadEdge, SchedulerNodeActivity, SchedulerNodeId, SchedulerScenarioNode,
    SchedulerTopologyChangeTrigger, SchedulingNodeKind, Shift, SimDuration, SimInstant,
    SingleScheduler, VmArchitecture, WhiteBoxPolicy, World, WorldNode,
};

#[test]
fn imperative_inject_records_decision_and_applies_at_boundary() {
    let tag = tag("slow-db0");
    let fault = slowdown_fault("db-0", 20_000);
    let mut scheduler = SingleScheduler::new(single_idle_node_scenario("imperative-inject-slow"))
        .expect("scheduler should build");

    let outcome = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: vec![control(
                7,
                ControlOperationKind::InjectFault {
                    tag: tag.clone(),
                    fault: fault.clone(),
                },
            )],
        })
        .expect("imperative inject should apply");

    assert_eq!(
        control_fault_decisions(&outcome.decisions),
        vec![ControlFaultAction::Inject {
            tag: tag.clone(),
            fault: fault.clone(),
        }]
    );
    assert_eq!(
        scheduler.trigger_actions().active_taxonomy_faults.get(&tag),
        Some(&fault)
    );
    assert_eq!(
        scheduler
            .node_timing_projection(&node("db-0"))
            .expect("node projection should compute")
            .slow_factor,
        slowdown(20_000)
    );
    assert_eq!(scheduler.control_applications().len(), 1);
    assert_eq!(
        scheduler.configuration().schedule.decisions(),
        outcome.configuration.schedule.decisions()
    );
}

#[test]
fn imperative_heal_records_decision_and_is_noop_for_unknown_tag() {
    let tag = tag("missing");
    let mut scheduler = SingleScheduler::new(single_idle_node_scenario("imperative-heal-missing"))
        .expect("scheduler should build");

    let outcome = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: vec![control(
                3,
                ControlOperationKind::HealFault { tag: tag.clone() },
            )],
        })
        .expect("imperative heal should record even when nothing is active");

    assert_eq!(
        control_fault_decisions(&outcome.decisions),
        vec![ControlFaultAction::Heal { tag }]
    );
    assert!(scheduler.trigger_actions().active_faults.is_empty());
    assert!(
        scheduler
            .trigger_actions()
            .active_taxonomy_faults
            .is_empty()
    );
    assert!(scheduler.topology_change_applications().is_empty());
}

#[test]
fn imperative_fault_controls_are_sorted_and_reduce_to_final_boundary_state() {
    let tag = tag("slow-db0");
    let fault = slowdown_fault("db-0", 15_000);
    let mut scheduler = SingleScheduler::new(single_idle_node_scenario("imperative-sort-and-heal"))
        .expect("scheduler should build");

    let outcome = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: vec![
                control(20, ControlOperationKind::HealFault { tag: tag.clone() }),
                control(
                    10,
                    ControlOperationKind::InjectFault {
                        tag: tag.clone(),
                        fault,
                    },
                ),
            ],
        })
        .expect("imperative controls should apply in deterministic order");

    let decisions = outcome
        .decisions
        .iter()
        .filter_map(|decision| match decision {
            Decision::ControlFault(control) => Some((control.sequence, control.action.clone())),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(decisions.len(), 2);
    assert_eq!(decisions[0].0, 10);
    assert!(matches!(decisions[0].1, ControlFaultAction::Inject { .. }));
    assert_eq!(decisions[1], (20, ControlFaultAction::Heal { tag }));
    assert!(scheduler.trigger_actions().active_faults.is_empty());
    assert!(
        scheduler
            .trigger_actions()
            .active_taxonomy_faults
            .is_empty()
    );
}

#[test]
fn imperative_partition_recomputes_topology_at_the_same_boundary() {
    let world = runtime_topology_world();
    let tag = tag("split");
    let fault = Fault::Network(NetworkFault::Partition {
        link: link_id("db-0", "db-1"),
        direction: PartitionDirection::Bidirectional,
    });
    let mut scheduler = SingleScheduler::new(topology_scenario("imperative-partition", &world))
        .expect("scheduler should build");

    let outcome = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: vec![control(
                11,
                ControlOperationKind::InjectFault {
                    tag,
                    fault: fault.clone(),
                },
            )],
        })
        .expect("imperative partition should apply");

    assert!(matches!(
        control_fault_decisions(&outcome.decisions).as_slice(),
        [ControlFaultAction::Inject { fault: recorded, .. }] if recorded == &fault
    ));
    let application = scheduler
        .topology_change_applications()
        .first()
        .expect("partition should recompute topology at this boundary");
    assert_eq!(
        application.trigger,
        SchedulerTopologyChangeTrigger::FaultActivation
    );
    assert!(
        scheduler
            .authorize_cross_node_send(&scheduler_node("db-0"), &scheduler_node("db-1"))
            .is_err(),
        "partitioned link should be removed before PICK"
    );
    assert!(
        scheduler
            .authorize_cross_node_send(&scheduler_node("db-2"), &scheduler_node("db-1"))
            .is_ok(),
        "unrelated links should remain live"
    );
}

#[test]
fn recorded_control_fault_schedule_prefix_rehydrates_active_faults() {
    let tag = tag("slow-db0");
    let fault = slowdown_fault("db-0", 20_000);
    let mut scheduler =
        SingleScheduler::new(single_idle_node_scenario("imperative-rehydrate-slow"))
            .expect("scheduler should build");
    let outcome = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: vec![control(
                7,
                ControlOperationKind::InjectFault {
                    tag: tag.clone(),
                    fault: fault.clone(),
                },
            )],
        })
        .expect("imperative inject should apply");

    let mut replay_scenario = single_idle_node_scenario("imperative-rehydrate-slow");
    replay_scenario.configuration = outcome.configuration;
    let replayed = SingleScheduler::new(replay_scenario)
        .expect("recorded control-fault schedule should hydrate");

    assert_eq!(
        replayed.trigger_actions().active_taxonomy_faults.get(&tag),
        Some(&fault)
    );
    assert_eq!(
        replayed
            .node_timing_projection(&node("db-0"))
            .expect("node projection should compute")
            .slow_factor,
        slowdown(20_000)
    );
}

#[test]
fn recorded_control_partition_schedule_prefix_rehydrates_topology() {
    let world = runtime_topology_world();
    let fault = Fault::Network(NetworkFault::Partition {
        link: link_id("db-0", "db-1"),
        direction: PartitionDirection::Bidirectional,
    });
    let mut scheduler =
        SingleScheduler::new(topology_scenario("imperative-rehydrate-partition", &world))
            .expect("scheduler should build");
    let outcome = scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: vec![control(
                11,
                ControlOperationKind::InjectFault {
                    tag: tag("split"),
                    fault,
                },
            )],
        })
        .expect("imperative partition should apply");

    let mut replay_scenario = topology_scenario("imperative-rehydrate-partition", &world);
    replay_scenario.configuration = outcome.configuration;
    let replayed = SingleScheduler::new(replay_scenario)
        .expect("recorded control-fault partition should hydrate");

    assert!(
        replayed
            .authorize_cross_node_send(&scheduler_node("db-0"), &scheduler_node("db-1"))
            .is_err(),
        "recorded partition should remove the link without resubmitting control"
    );
    assert!(
        replayed
            .authorize_cross_node_send(&scheduler_node("db-2"), &scheduler_node("db-1"))
            .is_ok(),
        "recorded partition should preserve unrelated topology edges"
    );
}

#[test]
fn control_fault_decisions_round_trip_through_schedule_binary_and_hash() {
    let tag = tag("slow-db0");
    let fault = slowdown_fault("db-0", 15_000);
    let inject = Decision::ControlFault(crucible::ControlFaultDecision {
        at: crucible::VirtualTime { ticks: 5 },
        sequence: 9,
        action: ControlFaultAction::Inject {
            tag: tag.clone(),
            fault: fault.clone(),
        },
    });
    let heal = Decision::ControlFault(crucible::ControlFaultDecision {
        at: crucible::VirtualTime { ticks: 8 },
        sequence: 10,
        action: ControlFaultAction::Heal { tag: tag.clone() },
    });
    let schedule = Schedule::empty()
        .appended(inject.clone())
        .appended(heal.clone());

    let round_trip = Schedule::from_compact_binary(&schedule.to_compact_binary())
        .expect("control-fault schedule should round trip");
    assert_eq!(round_trip, schedule);

    let changed =
        Schedule::empty().appended(Decision::ControlFault(crucible::ControlFaultDecision {
            at: crucible::VirtualTime { ticks: 5 },
            sequence: 9,
            action: ControlFaultAction::Inject {
                tag,
                fault: slowdown_fault("db-0", 12_500),
            },
        }));
    assert_ne!(
        schedule.content_hash(),
        changed.content_hash(),
        "fault taxonomy material must contribute to schedule identity"
    );
    assert_eq!(schedule.decisions(), &[inject, heal]);
}

fn control(sequence: u64, kind: ControlOperationKind) -> ControlOperation {
    ControlOperation { sequence, kind }
}

fn control_fault_decisions(decisions: &[Decision]) -> Vec<ControlFaultAction> {
    decisions
        .iter()
        .filter_map(|decision| match decision {
            Decision::ControlFault(control) => Some(control.action.clone()),
            _ => None,
        })
        .collect()
}

fn single_idle_node_scenario(name: &str) -> SchedulerLivenessScenario {
    SchedulerLivenessScenario::from_canonical_material(
        name,
        shift(0),
        8,
        SimInstant { nanos: 20 },
        vec![scenario_node(
            "db-0",
            0,
            SchedulerNodeActivity::Idle,
            NetworkLookahead::Infinite,
        )],
        Vec::new(),
    )
}

fn topology_scenario(name: &str, world: &World) -> SchedulerLivenessScenario {
    let db_0 = scheduler_node("db-0");
    let db_1 = scheduler_node("db-1");
    let db_2 = scheduler_node("db-2");
    SchedulerLivenessScenario::from_canonical_material(
        name,
        shift(0),
        8,
        SimInstant { nanos: 20 },
        vec![scenario_node(
            "db-1",
            0,
            SchedulerNodeActivity::Runnable,
            NetworkLookahead::Finite(sim_duration(5)),
        )],
        Vec::new(),
    )
    .with_trigger_world(world)
    .with_effective_topology_edges(vec![
        edge(&db_0, &db_1, 5),
        edge(&db_1, &db_0, 5),
        edge(&db_2, &db_1, 5),
        edge(&db_1, &db_2, 5),
    ])
}

fn runtime_topology_world() -> World {
    World::from_nodes_and_links(
        vec![ready_node("db-0"), ready_node("db-1"), ready_node("db-2")],
        vec![
            LinkDef::new(node("db-0"), node("db-1")).expect("test link should build"),
            LinkDef::new(node("db-1"), node("db-2")).expect("test link should build"),
        ],
    )
    .expect("imperative fault-control world should build")
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

fn scenario_node(
    name: &str,
    counter: u64,
    activity: SchedulerNodeActivity,
    network_lookahead: NetworkLookahead,
) -> SchedulerScenarioNode {
    SchedulerScenarioNode {
        id: scheduler_node(name),
        counter: NodeCounter { ticks: counter },
        activity,
        network_lookahead,
        exact_local_event: ExactLocalEvent::NoArmedTimer,
    }
}

fn scheduler_node(name: &str) -> SchedulerNodeId {
    SchedulerNodeId {
        node: node(name),
        kind: SchedulingNodeKind::Vm,
    }
}

fn edge(from: &SchedulerNodeId, to: &SchedulerNodeId, latency_ns: u64) -> SchedulerLookaheadEdge {
    SchedulerLookaheadEdge::new(from.clone(), to.clone(), sim_duration(latency_ns))
}

fn slowdown_fault(node_name: &str, basis_points: u32) -> Fault {
    Fault::Node(NodeFault::Slow {
        node: node(node_name),
        factor: slowdown(basis_points),
    })
}

fn slowdown(basis_points: u32) -> FaultSlowdownFactorBasisPoints {
    FaultSlowdownFactorBasisPoints::from_basis_points(basis_points)
        .unwrap_or_else(|error| panic!("valid slowdown factor: {error}"))
}

fn tag(name: &str) -> FaultTag {
    FaultTag::from_name(name)
}

fn link_id(left: &str, right: &str) -> LinkId {
    LinkId::from_name(format!("{left}--{right}"))
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn shift(bits: u8) -> Shift {
    Shift { bits }
}

fn sim_duration(nanos: u64) -> SimDuration {
    SimDuration { nanos }
}
