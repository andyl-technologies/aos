//! Checks T-FAULT-13 materialized active-fault tables.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;

use crucible::{
    Action, ActiveFaultTable, ActiveNetworkEdgeDirection, ActiveNetworkEdgeKey, BlockFault,
    Checkpoint, CheckpointKind, CombinedFaults, ConditionLeaf, ConditionLeafOracle, Configuration,
    ControlFaultAction, ControlFaultDecision, Decision, DecisionRngState, DeviceId, Event,
    EventGraph, EventGraphState, EventId, EventLogOffset, ExactLocalEvent, Fault, FaultDuration,
    FaultRateBasisPoints, FaultSlowdownFactorBasisPoints, FaultTag, Icount, LinkDef, LinkId,
    MaterializedState, MembershipFault, NetworkFault, NetworkLookahead, NinePFault, NodeCounter,
    NodeFault, NodeId, NodeTemplate, PartitionDirection, Predicate, ReadyPoint, RestartPolicy,
    ScenarioDef, Schedule, SchedulerEvaluationBoundaryKind, SchedulerLivenessScenario,
    SchedulerNodeActivity, SchedulerNodeId, SchedulerScenarioNode, SchedulingNodeKind, Shift,
    SimInstant, SingleScheduler, VirtualTime, VmArchitecture, WhiteBoxPolicy, World, WorldNode,
};

#[test]
fn schedule_replay_recomputes_active_fault_table() {
    let slow = slow_fault("db-0", 20_000);
    let loss = loss_fault("db-0", "db-1", 1_500);
    let schedule = Schedule::empty()
        .appended(control_inject(0, 1, "slow", slow.clone()))
        .appended(control_inject(0, 2, "loss", loss.clone()));

    let state = crucible::SchedulerState::from_schedule(&schedule);

    assert_eq!(
        state
            .active_fault_table
            .combined
            .node
            .get(&node("db-0"))
            .and_then(|faults| faults.slow_factor),
        Some(slow_factor(20_000))
    );
    assert_eq!(
        state
            .active_fault_table
            .combined
            .network
            .get(&link_id("db-0", "db-1"))
            .map(|faults| faults.loss_rates.as_slice()),
        Some([rate(1_500)].as_slice())
    );
    assert_eq!(
        state
            .active_fault_table
            .network_edges
            .get(&network_edge(
                "db-0",
                "db-1",
                ActiveNetworkEdgeDirection::EndpointAToEndpointB
            ))
            .map(|faults| faults.loss_rates.as_slice()),
        Some([rate(1_500)].as_slice())
    );

    let healed = state_after(&schedule.appended(control_heal(1, 3, "slow")));
    assert!(
        !healed
            .active_fault_table
            .combined
            .node
            .contains_key(&node("db-0"))
    );
    assert!(
        healed
            .active_fault_table
            .combined
            .network
            .contains_key(&link_id("db-0", "db-1"))
    );
}

#[test]
fn declarative_trigger_capture_materializes_combined_active_fault_table() {
    let slow = slow_fault("db-0", 20_000);
    let loss = loss_fault("db-0", "db-1", 1_500);
    let world = world();
    let mut scheduler =
        SingleScheduler::new(scenario("declarative-active-table")).expect("scheduler should build");
    let graph = EventGraph::new_for_world(
        vec![
            Event::once(
                event_id("slow"),
                Some(Predicate::At { at: time(0) }),
                Action::InjectFault {
                    tag: tag("slow"),
                    fault: MembershipFault::taxonomy(slow.clone()),
                },
            ),
            Event::once(
                event_id("loss"),
                Some(Predicate::At { at: time(0) }),
                Action::InjectFault {
                    tag: tag("loss"),
                    fault: MembershipFault::taxonomy(loss.clone()),
                },
            ),
        ],
        &world,
    )
    .expect("event graph should validate");
    let mut event_state = EventGraphState::new();

    scheduler
        .append_evaluation_boundary(time(0), SchedulerEvaluationBoundaryKind::Quantum)
        .expect("boundary should append");
    let firings = scheduler.evaluate_event_graph(&graph, &mut event_state, NoLeaves);
    scheduler
        .apply_trigger_firings(&firings)
        .expect("trigger faults should apply");

    let materialized = scheduler.materialized_scheduler_state();
    assert_eq!(
        materialized.active_fault_table.combined,
        CombinedFaults::from_faults(&[slow, loss])
    );
}

#[test]
fn legacy_declarative_faults_enter_combined_table_and_directed_edges() {
    let world = world();
    let mut scheduler =
        SingleScheduler::new(scenario("legacy-active-table")).expect("scheduler should build");
    let graph = EventGraph::new_for_world(
        vec![
            Event::once(
                event_id("crash"),
                Some(Predicate::At { at: time(0) }),
                Action::InjectFault {
                    tag: tag("crash"),
                    fault: MembershipFault::Crash {
                        node: node("db-0"),
                        restart: RestartPolicy::StayDown,
                    },
                },
            ),
            Event::once(
                event_id("split"),
                Some(Predicate::At { at: time(0) }),
                Action::InjectFault {
                    tag: tag("split"),
                    fault: MembershipFault::Partition {
                        endpoint_a: node("db-0"),
                        endpoint_b: node("db-1"),
                        direction: PartitionDirection::EndpointAToEndpointB,
                    },
                },
            ),
        ],
        &world,
    )
    .expect("legacy graph should validate");
    let mut event_state = EventGraphState::new();

    scheduler
        .append_evaluation_boundary(time(0), SchedulerEvaluationBoundaryKind::Quantum)
        .expect("boundary should append");
    let firings = scheduler.evaluate_event_graph(&graph, &mut event_state, NoLeaves);
    scheduler
        .apply_trigger_firings(&firings)
        .expect("legacy trigger faults should apply");

    let materialized = scheduler.materialized_scheduler_state();
    assert!(materialized.active_fault_table.combined.node[&node("db-0")].is_crashed());
    let forward = &materialized.active_fault_table.network_edges[&network_edge(
        "db-0",
        "db-1",
        ActiveNetworkEdgeDirection::EndpointAToEndpointB,
    )];
    assert!(
        forward
            .partition
            .expect("forward edge should be partitioned")
            .endpoint_a_to_endpoint_b
    );
    let reverse = &materialized.active_fault_table.network_edges[&network_edge(
        "db-0",
        "db-1",
        ActiveNetworkEdgeDirection::EndpointBToEndpointA,
    )];
    assert!(reverse.partition.is_none());
}

#[test]
fn legacy_partition_projection_preserves_reversed_endpoint_direction() {
    let world = world();
    let mut scheduler = SingleScheduler::new(scenario("reversed-legacy-partition"))
        .expect("scheduler should build");
    let graph = EventGraph::new_for_world(
        vec![Event::once(
            event_id("split"),
            Some(Predicate::At { at: time(0) }),
            Action::InjectFault {
                tag: tag("split"),
                fault: MembershipFault::Partition {
                    endpoint_a: node("db-1"),
                    endpoint_b: node("db-0"),
                    direction: PartitionDirection::EndpointAToEndpointB,
                },
            },
        )],
        &world,
    )
    .expect("legacy graph should validate");
    let mut event_state = EventGraphState::new();

    scheduler
        .append_evaluation_boundary(time(0), SchedulerEvaluationBoundaryKind::Quantum)
        .expect("boundary should append");
    let firings = scheduler.evaluate_event_graph(&graph, &mut event_state, NoLeaves);
    scheduler
        .apply_trigger_firings(&firings)
        .expect("legacy trigger faults should apply");

    let materialized = scheduler.materialized_scheduler_state();
    let forward = &materialized.active_fault_table.network_edges[&network_edge(
        "db-0",
        "db-1",
        ActiveNetworkEdgeDirection::EndpointAToEndpointB,
    )];
    assert!(forward.partition.is_none());
    let reverse = &materialized.active_fault_table.network_edges[&network_edge(
        "db-0",
        "db-1",
        ActiveNetworkEdgeDirection::EndpointBToEndpointA,
    )];
    assert!(
        reverse
            .partition
            .expect("reverse edge should be partitioned")
            .endpoint_b_to_endpoint_a
    );
}

#[test]
fn non_projectable_legacy_faults_remain_in_legacy_membership_table() {
    let world = world();
    let mut scheduler =
        SingleScheduler::new(scenario("non-projectable-legacy")).expect("scheduler should build");
    let graph = EventGraph::new_for_world(
        vec![
            Event::once(
                event_id("isolate"),
                Some(Predicate::At { at: time(0) }),
                Action::InjectFault {
                    tag: tag("isolate"),
                    fault: MembershipFault::Isolate { node: node("db-0") },
                },
            ),
            Event::once(
                event_id("not-yet-joined"),
                Some(Predicate::At { at: time(0) }),
                Action::InjectFault {
                    tag: tag("not-yet-joined"),
                    fault: MembershipFault::NotYetJoined { node: node("db-1") },
                },
            ),
        ],
        &world,
    )
    .expect("legacy graph should validate");
    let mut event_state = EventGraphState::new();

    scheduler
        .append_evaluation_boundary(time(0), SchedulerEvaluationBoundaryKind::Quantum)
        .expect("boundary should append");
    let firings = scheduler.evaluate_event_graph(&graph, &mut event_state, NoLeaves);
    scheduler
        .apply_trigger_firings(&firings)
        .expect("legacy trigger faults should apply");

    let materialized = scheduler.materialized_scheduler_state();
    assert_eq!(
        materialized.active_fault_table.combined,
        CombinedFaults::default()
    );
    assert!(materialized.active_fault_table.network_edges.is_empty());
    assert!(matches!(
        materialized
            .active_fault_table
            .legacy_membership
            .get(&tag("isolate")),
        Some(MembershipFault::Isolate { node: isolated }) if isolated == &node("db-0")
    ));
    assert!(matches!(
        materialized
            .active_fault_table
            .legacy_membership
            .get(&tag("not-yet-joined")),
        Some(MembershipFault::NotYetJoined { node: waiting }) if waiting == &node("db-1")
    ));
}

#[test]
fn block_and_9p_faults_enter_materialized_active_table() {
    let disk = device("disk-a");
    let fs = device("fs-a");
    let schedule = Schedule::empty()
        .appended(control_inject(
            0,
            1,
            "block",
            Fault::Block(BlockFault::Latency {
                device: disk.clone(),
                extra: FaultDuration::from_nanos(7),
                jitter: FaultDuration::ZERO,
            }),
        ))
        .appended(control_inject(
            0,
            2,
            "ninep",
            Fault::NineP(NinePFault::Latency {
                device: fs.clone(),
                extra: FaultDuration::from_nanos(11),
                jitter: FaultDuration::ZERO,
            }),
        ));
    let state = crucible::SchedulerState::from_schedule(&schedule);

    assert_eq!(
        state.active_fault_table.combined.block[&disk].latency_extra,
        FaultDuration::from_nanos(7)
    );
    assert_eq!(
        state.active_fault_table.combined.ninep[&fs].latency_extra,
        FaultDuration::from_nanos(11)
    );
}

#[test]
fn direct_fat_checkpoint_materializes_active_fault_table_from_schedule() {
    let scenario = ScenarioDef::from_canonical_material("crucible.test.active-table", "node=db-0");
    let genesis = Configuration::genesis(scenario.clone());
    let config = Configuration {
        def: scenario,
        schedule: Schedule::empty().appended(control_inject(
            0,
            1,
            "slow",
            slow_fault("db-0", 20_000),
        )),
    };
    let checkpoint = Checkpoint::from_recorded_configuration(
        &config,
        Some(&genesis),
        VirtualTime::default(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .expect("checkpoint should build");
    let state = checkpoint
        .state
        .as_ref()
        .expect("fat checkpoint should carry materialized state");

    assert_eq!(
        state
            .scheduler
            .active_fault_table
            .combined
            .node
            .get(&node("db-0"))
            .and_then(|faults| faults.slow_factor),
        Some(slow_factor(20_000))
    );
}

#[test]
fn active_fault_table_contributes_to_materialized_state_identity() {
    let schedule =
        Schedule::empty().appended(control_inject(0, 1, "slow", slow_fault("db-0", 20_000)));
    let with_table = crucible::SchedulerState::from_schedule(&schedule);
    let mut without_table = with_table.clone();
    without_table.active_fault_table = ActiveFaultTable::default();
    let with_table_state = materialized(with_table.clone());
    let same = materialized(with_table);
    let without_table_state = materialized(without_table);

    assert_eq!(with_table_state.id, same.id);
    assert_ne!(with_table_state.id, without_table_state.id);
}

fn state_after(schedule: &Schedule) -> crucible::SchedulerState {
    crucible::SchedulerState::from_schedule(schedule)
}

fn materialized(scheduler: crucible::SchedulerState) -> MaterializedState {
    MaterializedState::from_components(
        BTreeMap::new(),
        BTreeMap::new(),
        scheduler,
        DecisionRngState::empty(),
        EventLogOffset::default(),
    )
}

fn control_inject(at: u64, sequence: u64, name: &str, fault: Fault) -> Decision {
    Decision::ControlFault(ControlFaultDecision {
        at: time(at),
        sequence,
        action: ControlFaultAction::Inject {
            tag: tag(name),
            fault,
        },
    })
}

fn control_heal(at: u64, sequence: u64, name: &str) -> Decision {
    Decision::ControlFault(ControlFaultDecision {
        at: time(at),
        sequence,
        action: ControlFaultAction::Heal { tag: tag(name) },
    })
}

fn scenario(name: &str) -> SchedulerLivenessScenario {
    SchedulerLivenessScenario::from_canonical_material(
        name,
        Shift { bits: 0 },
        8,
        SimInstant { nanos: 20 },
        vec![SchedulerScenarioNode {
            id: SchedulerNodeId {
                node: node("db-0"),
                kind: SchedulingNodeKind::Vm,
            },
            counter: NodeCounter { ticks: 0 },
            activity: SchedulerNodeActivity::Idle,
            network_lookahead: NetworkLookahead::Infinite,
            exact_local_event: ExactLocalEvent::NoArmedTimer,
        }],
        Vec::new(),
    )
}

fn world() -> World {
    World::from_nodes_and_links(
        vec![ready_node("db-0"), ready_node("db-1")],
        vec![LinkDef::new(node("db-0"), node("db-1")).expect("test link should build")],
    )
    .expect("test world should build")
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

fn slow_fault(node_name: &str, basis_points: u32) -> Fault {
    Fault::Node(NodeFault::Slow {
        node: node(node_name),
        factor: slow_factor(basis_points),
    })
}

fn slow_factor(basis_points: u32) -> FaultSlowdownFactorBasisPoints {
    FaultSlowdownFactorBasisPoints::from_basis_points(basis_points)
        .unwrap_or_else(|error| panic!("valid slowdown factor: {error}"))
}

fn loss_fault(left: &str, right: &str, basis_points: u32) -> Fault {
    Fault::Network(NetworkFault::Loss {
        link: link_id(left, right),
        rate: rate(basis_points),
    })
}

fn rate(basis_points: u32) -> FaultRateBasisPoints {
    FaultRateBasisPoints::from_basis_points(basis_points)
        .unwrap_or_else(|error| panic!("valid rate: {error}"))
}

fn link_id(left: &str, right: &str) -> LinkId {
    let (endpoint_a, endpoint_b) = if left <= right {
        (left, right)
    } else {
        (right, left)
    };
    LinkId::from_name(format!(
        "link_endpoint_a_len={}\nlink_endpoint_a={}\nlink_endpoint_b_len={}\nlink_endpoint_b={}",
        endpoint_a.len(),
        endpoint_a,
        endpoint_b.len(),
        endpoint_b
    ))
}

fn network_edge(
    left: &str,
    right: &str,
    direction: ActiveNetworkEdgeDirection,
) -> ActiveNetworkEdgeKey {
    ActiveNetworkEdgeKey::new(link_id(left, right), direction)
}

fn device(name: &str) -> DeviceId {
    DeviceId {
        name: name.to_owned(),
    }
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn tag(name: &str) -> FaultTag {
    FaultTag::from_name(name)
}

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

fn event_id(name: &str) -> EventId {
    EventId::from_name(name)
}

struct NoLeaves;

impl ConditionLeafOracle for NoLeaves {
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { .. } | ConditionLeaf::GuestMarker { .. } => {
                panic!("active-fault-table tests use only At leaves")
            }
        }
    }
}
