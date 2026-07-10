//! Checks T-FAULT-10 declarative full-taxonomy fault plans.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    Action, BlockFault, ConditionLeaf, ConditionLeafOracle, DeviceId, EngineError, Event,
    EventGraph, EventGraphError, EventGraphState, EventId, ExactLocalEvent, Fault, FaultDuration,
    FaultPlan, FaultPlanEntry, FaultRateBasisPoints, FaultSlowdownFactorBasisPoints, FaultTag,
    Icount, LinkDef, LinkId, MembershipFault, NetworkFault, NetworkLinkDirection, NetworkLookahead,
    NinePFault, NodeCounter, NodeFault, NodeId, NodeTemplate, PartitionDirection, Plan, Predicate,
    QuantumLoop, QuantumRequest, ReadyPoint, RestartPolicy, SchedulerEvaluationBoundaryKind,
    SchedulerLivenessScenario, SchedulerLookaheadEdge, SchedulerNodeActivity, SchedulerNodeId,
    SchedulerScenarioNode, SchedulerTopologyChangeTrigger, SchedulingNodeKind, Shift, SimDuration,
    SimInstant, SingleScheduler, VirtualTime, VmArchitecture, WhiteBoxPolicy, World, WorldNode,
};
use crucible_device::{Frame, FrameDraws, LinkFaults, NetLink, PastDeliveryPolicy};

fn event_id(name: &str) -> EventId {
    EventId::from_name(name)
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

fn shift(bits: u8) -> Shift {
    Shift { bits }
}

fn sim_duration(nanos: u64) -> SimDuration {
    SimDuration { nanos }
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

fn legacy_link_id(left: &str, right: &str) -> LinkId {
    let (endpoint_a, endpoint_b) = if left <= right {
        (left, right)
    } else {
        (right, left)
    };
    LinkId::from_name(format!("{endpoint_a}--{endpoint_b}"))
}

fn device(name: &str) -> DeviceId {
    DeviceId {
        name: name.to_owned(),
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

fn world() -> World {
    World::from_nodes_and_links(
        vec![ready_node("db-0"), ready_node("db-1")],
        vec![LinkDef::new(node("db-0"), node("db-1")).expect("test link should build")],
    )
    .expect("fault-plan test world should build")
}

fn runtime_topology_world() -> World {
    World::from_nodes_and_links(
        vec![ready_node("db-0"), ready_node("db-1"), ready_node("db-2")],
        vec![
            LinkDef::new(node("db-0"), node("db-1")).expect("test link should build"),
            LinkDef::new(node("db-1"), node("db-2")).expect("test link should build"),
        ],
    )
    .expect("fault-plan runtime topology world should build")
}

fn scenario(name: &str, world: &World) -> SchedulerLivenessScenario {
    SchedulerLivenessScenario::from_canonical_material(
        name,
        shift(0),
        16,
        SimInstant { nanos: 100 },
        vec![
            scenario_node(
                "db-0",
                0,
                SchedulerNodeActivity::Idle,
                NetworkLookahead::Infinite,
            ),
            scenario_node(
                "db-1",
                0,
                SchedulerNodeActivity::Idle,
                NetworkLookahead::Infinite,
            ),
        ],
        Vec::new(),
    )
    .with_trigger_world(world)
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

fn drive_one_quantum(scheduler: &mut SingleScheduler) -> crucible::QuantumOutcome {
    scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: Vec::new(),
        })
        .expect("scheduler should drive one quantum")
}

fn slowdown_fault() -> Fault {
    Fault::Node(NodeFault::Slow {
        node: node("db-0"),
        factor: FaultSlowdownFactorBasisPoints::from_basis_points(20_000)
            .expect("slowdown factor should be in range"),
    })
}

fn loss_fault() -> Fault {
    Fault::Network(NetworkFault::Loss {
        link: link_id("db-0", "db-1"),
        rate: FaultRateBasisPoints::from_basis_points(1_500).expect("loss rate should be in range"),
    })
}

struct NoLeaves;

impl ConditionLeafOracle for NoLeaves {
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { .. } | ConditionLeaf::GuestMarker { .. } => {
                panic!("fault-plan lowering should evaluate only At leaves")
            }
        }
    }
}

#[test]
fn fault_plan_canonicalizes_and_lowers_to_pure_at_fault_events() {
    let world = world();
    let plan = Plan::from_fault_plan_for_world(
        &world,
        FaultPlan::from_entries(vec![
            FaultPlanEntry::Heal {
                at: time(9),
                tag: tag("loss"),
            },
            FaultPlanEntry::At {
                at: time(3),
                duration: FaultDuration::from_nanos(4),
                tag: tag("slow"),
                fault: slowdown_fault(),
            },
            FaultPlanEntry::PermanentAt {
                at: time(5),
                tag: tag("loss"),
                fault: loss_fault(),
            },
        ]),
    )
    .expect("fault plan should validate");

    let fault_plan = plan.fault_plan().expect("plan should carry a FaultPlan");
    assert!(matches!(fault_plan.entries()[0], FaultPlanEntry::At { .. }));
    assert!(matches!(
        fault_plan.entries()[1],
        FaultPlanEntry::PermanentAt { .. }
    ));
    assert!(matches!(
        fault_plan.entries()[2],
        FaultPlanEntry::Heal { .. }
    ));

    let lowered = plan
        .lower_to_event_graph_for_world(&world)
        .expect("fault plan should lower");
    let graph = lowered.event_graph();

    assert_eq!(lowered.content_hash(), plan.content_hash());
    assert_eq!(lowered.canonical_bytes(), plan.canonical_bytes());
    assert_eq!(
        lowered.evaluation_times(),
        &[time(3), time(5), time(7), time(9)]
    );
    assert_eq!(graph.events().len(), 4);
    assert_eq!(
        graph.events()[0].id.name,
        "plan:0000000000000000:inject:slow"
    );
    assert_eq!(
        graph.events()[0].trigger,
        Some(Predicate::At { at: time(3) })
    );
    assert_eq!(
        graph.events()[0].action,
        Action::InjectFault {
            tag: tag("slow"),
            fault: MembershipFault::taxonomy(slowdown_fault()),
        }
    );
    assert_eq!(graph.events()[2].id.name, "plan:0000000000000002:heal:slow");
    assert_eq!(
        graph.events()[2].action,
        Action::HealFault { tag: tag("slow") }
    );
    assert!(
        graph
            .events()
            .iter()
            .all(|event| matches!(event.trigger, Some(Predicate::At { .. })))
    );
    assert!(graph.events().iter().all(|event| matches!(
        event.action,
        Action::InjectFault { .. } | Action::HealFault { .. }
    )));
}

#[test]
fn fault_plan_same_time_heal_fires_after_inject() {
    let world = world();
    let plan = Plan::from_fault_plan_for_world(
        &world,
        FaultPlan::from_entries(vec![
            FaultPlanEntry::PermanentAt {
                at: time(10),
                tag: tag("loss"),
                fault: loss_fault(),
            },
            FaultPlanEntry::Heal {
                at: time(10),
                tag: tag("loss"),
            },
        ]),
    )
    .expect("same-time inject/heal should validate by total order");

    let lowered = plan
        .lower_to_event_graph_for_world(&world)
        .expect("fault plan should lower");
    let actions = lowered
        .event_graph()
        .events()
        .iter()
        .map(|event| &event.action)
        .collect::<Vec<_>>();

    assert!(matches!(actions[0], Action::InjectFault { .. }));
    assert_eq!(actions[1], &Action::HealFault { tag: tag("loss") });
}

#[test]
fn lowered_fault_plan_updates_trigger_combined_faults() {
    let world = world();
    let link = link_id("db-0", "db-1");
    let plan = Plan::from_fault_plan_for_world(
        &world,
        FaultPlan::from_entries(vec![
            FaultPlanEntry::At {
                at: time(3),
                duration: FaultDuration::from_nanos(4),
                tag: tag("slow"),
                fault: slowdown_fault(),
            },
            FaultPlanEntry::PermanentAt {
                at: time(5),
                tag: tag("loss"),
                fault: loss_fault(),
            },
            FaultPlanEntry::Heal {
                at: time(9),
                tag: tag("loss"),
            },
        ]),
    )
    .expect("fault plan should validate");
    let lowered = plan
        .lower_to_event_graph_for_world(&world)
        .expect("fault plan should lower");
    let graph = lowered.event_graph();
    let mut scheduler = SingleScheduler::new(scenario("fault-plan-combined-faults", &world))
        .expect("scheduler should build");
    let mut state = EventGraphState::new();

    for at in lowered.evaluation_times() {
        scheduler
            .append_evaluation_boundary(*at, SchedulerEvaluationBoundaryKind::Quantum)
            .expect("evaluation boundary should append");
        let firings = scheduler.evaluate_event_graph(graph, &mut state, NoLeaves);
        scheduler
            .apply_trigger_firings(&firings)
            .expect("fault-plan firings should apply");
        let combined = scheduler.trigger_actions().combined_faults();

        match at.ticks {
            3 => {
                assert_eq!(
                    combined
                        .node
                        .get(&node("db-0"))
                        .and_then(|faults| faults.slow_factor),
                    Some(
                        FaultSlowdownFactorBasisPoints::from_basis_points(20_000)
                            .expect("slowdown factor should be in range")
                    )
                );
                assert!(combined.network.is_empty());
            }
            5 => {
                assert!(combined.node.contains_key(&node("db-0")));
                assert_eq!(
                    combined
                        .network
                        .get(&link)
                        .map(|faults| faults.loss_rates.as_slice()),
                    Some(
                        [FaultRateBasisPoints::from_basis_points(1_500)
                            .expect("loss rate should be in range")]
                        .as_slice()
                    )
                );
            }
            7 => {
                assert!(combined.node.is_empty(), "auto-heal should remove slowdown");
                assert!(combined.network.contains_key(&link));
            }
            9 => {
                assert!(combined.node.is_empty());
                assert!(
                    combined.network.is_empty(),
                    "explicit heal should remove loss"
                );
            }
            other => panic!("unexpected evaluation time {other}"),
        }
    }
}

#[test]
fn lowered_partition_fault_plan_queues_topology_recompute() {
    let world = runtime_topology_world();
    let plan = Plan::from_fault_plan_for_world(
        &world,
        FaultPlan::from_entries(vec![FaultPlanEntry::PermanentAt {
            at: time(0),
            tag: tag("split"),
            fault: Fault::Network(NetworkFault::Partition {
                link: link_id("db-0", "db-1"),
                direction: PartitionDirection::Bidirectional,
            }),
        }]),
    )
    .expect("fault plan should validate");
    let lowered = plan
        .lower_to_event_graph_for_world(&world)
        .expect("fault plan should lower");
    let mut scheduler = SingleScheduler::new(topology_scenario("fault-plan-topology", &world))
        .expect("scheduler should build");
    let mut state = EventGraphState::new();

    scheduler
        .append_evaluation_boundary(time(0), SchedulerEvaluationBoundaryKind::Quantum)
        .expect("evaluation boundary should append");
    let firings = scheduler.evaluate_event_graph(lowered.event_graph(), &mut state, NoLeaves);
    scheduler
        .apply_trigger_firings(&firings)
        .expect("partition fault firing should apply");

    assert!(scheduler.topology_change_applications().is_empty());
    let _ = drive_one_quantum(&mut scheduler);

    let application = scheduler
        .topology_change_applications()
        .first()
        .expect("partition should queue and apply a topology recompute");
    assert_eq!(
        application.trigger,
        SchedulerTopologyChangeTrigger::FaultActivation
    );
    assert!(
        scheduler
            .authorize_cross_node_send(&scheduler_node("db-0"), &scheduler_node("db-1"))
            .is_err(),
        "the partitioned link should be removed from the effective topology"
    );
    assert!(
        scheduler
            .authorize_cross_node_send(&scheduler_node("db-2"), &scheduler_node("db-1"))
            .is_ok(),
        "unrelated static links should remain live after the replacement"
    );
}

#[test]
fn lowered_network_loss_fault_plan_applies_to_live_netlink() {
    let world = world();
    let plan = Plan::from_fault_plan_for_world(
        &world,
        FaultPlan::from_entries(vec![FaultPlanEntry::PermanentAt {
            at: time(0),
            tag: tag("loss"),
            fault: Fault::Network(NetworkFault::Loss {
                link: link_id("db-0", "db-1"),
                rate: FaultRateBasisPoints::from_basis_points(10_000)
                    .expect("loss rate should be in range"),
            }),
        }]),
    )
    .expect("fault plan should validate");
    let lowered = plan
        .lower_to_event_graph_for_world(&world)
        .expect("fault plan should lower");
    let mut scheduler = SingleScheduler::new(scenario("fault-plan-live-link-loss", &world))
        .expect("scheduler should build");
    let mut state = EventGraphState::new();

    scheduler
        .append_evaluation_boundary(time(0), SchedulerEvaluationBoundaryKind::Quantum)
        .expect("evaluation boundary should append");
    let firings = scheduler.evaluate_event_graph(lowered.event_graph(), &mut state, NoLeaves);
    scheduler
        .apply_trigger_firings(&firings)
        .expect("loss fault firing should apply");

    let mut link = NetLink::new(0, 1, 10, 1, LinkFaults::none()).expect("link should build");
    let application = scheduler
        .apply_trigger_network_faults_to_link(
            2,
            &link_id("db-0", "db-1"),
            scheduler_node("db-0"),
            scheduler_node("db-1"),
            &mut link,
            NetworkLinkDirection::EndpointAToEndpointB,
            Vec::new(),
        )
        .expect("trigger network faults should apply to live link");

    assert!(application.link_faults.loss.fires(0));
    assert!(application.topology_changes.is_empty());
    let outcome = link
        .emit(
            &Frame::new(0, 1, vec![1, 2, 3]),
            &FrameDraws::default(),
            PastDeliveryPolicy::FailLoud,
        )
        .expect("link emit should resolve");
    assert!(
        outcome.deliveries.is_empty(),
        "the trigger-owned loss fault should affect live link delivery"
    );
}

#[test]
fn canonical_network_fault_plan_applies_through_legacy_live_link_id() {
    let world = world();
    let plan = Plan::from_fault_plan_for_world(
        &world,
        FaultPlan::from_entries(vec![FaultPlanEntry::PermanentAt {
            at: time(0),
            tag: tag("loss"),
            fault: Fault::Network(NetworkFault::Loss {
                link: link_id("db-0", "db-1"),
                rate: FaultRateBasisPoints::from_basis_points(10_000)
                    .expect("loss rate should be in range"),
            }),
        }]),
    )
    .expect("fault plan should validate");
    let lowered = plan
        .lower_to_event_graph_for_world(&world)
        .expect("fault plan should lower");
    let mut scheduler = SingleScheduler::new(scenario("canonical-fault-legacy-link", &world))
        .expect("scheduler should build");
    let mut state = EventGraphState::new();

    scheduler
        .append_evaluation_boundary(time(0), SchedulerEvaluationBoundaryKind::Quantum)
        .expect("evaluation boundary should append");
    let firings = scheduler.evaluate_event_graph(lowered.event_graph(), &mut state, NoLeaves);
    scheduler
        .apply_trigger_firings(&firings)
        .expect("loss fault firing should apply");

    let mut link = NetLink::new(0, 1, 10, 1, LinkFaults::none()).expect("link should build");
    let application = scheduler
        .apply_trigger_network_faults_to_link(
            2,
            &legacy_link_id("db-0", "db-1"),
            scheduler_node("db-0"),
            scheduler_node("db-1"),
            &mut link,
            NetworkLinkDirection::EndpointAToEndpointB,
            Vec::new(),
        )
        .expect("canonical trigger fault should apply through legacy live link id");

    assert!(application.link_faults.loss.fires(0));
}

#[test]
fn lowered_network_latency_fault_plan_queues_link_recompute() {
    let world = runtime_topology_world();
    let plan = Plan::from_fault_plan_for_world(
        &world,
        FaultPlan::from_entries(vec![FaultPlanEntry::PermanentAt {
            at: time(0),
            tag: tag("latency"),
            fault: Fault::Network(NetworkFault::LatencyBump {
                link: link_id("db-0", "db-1"),
                extra: FaultDuration::from_nanos(7),
            }),
        }]),
    )
    .expect("fault plan should validate");
    let lowered = plan
        .lower_to_event_graph_for_world(&world)
        .expect("fault plan should lower");
    let mut scheduler =
        SingleScheduler::new(topology_scenario("fault-plan-live-link-latency", &world))
            .expect("scheduler should build");
    let mut state = EventGraphState::new();

    scheduler
        .append_evaluation_boundary(time(0), SchedulerEvaluationBoundaryKind::Quantum)
        .expect("evaluation boundary should append");
    let firings = scheduler.evaluate_event_graph(lowered.event_graph(), &mut state, NoLeaves);
    scheduler
        .apply_trigger_firings(&firings)
        .expect("latency fault firing should apply");

    let mut link = NetLink::new(0, 1, 5, 1, LinkFaults::none()).expect("link should build");
    let application = scheduler
        .apply_trigger_network_faults_to_link(
            3,
            &link_id("db-0", "db-1"),
            scheduler_node("db-0"),
            scheduler_node("db-1"),
            &mut link,
            NetworkLinkDirection::EndpointAToEndpointB,
            Vec::new(),
        )
        .expect("trigger latency fault should apply to live link");

    assert_eq!(application.link_faults.added_latency_ns, 7);
    assert_eq!(link.effective_latency_ns(), 12);
    let _ = drive_one_quantum(&mut scheduler);
    assert!(
        scheduler
            .topology_change_applications()
            .iter()
            .any(|application| application.trigger == SchedulerTopologyChangeTrigger::LatencyChange),
        "the live link latency change should queue a scheduler recompute"
    );
}

#[test]
fn legacy_inject_with_same_tag_clears_active_taxonomy_fault() {
    let world = world();
    let mut scheduler = SingleScheduler::new(scenario("fault-plan-same-tag-replacement", &world))
        .expect("scheduler should build");
    let graph = EventGraph::new_for_world(
        vec![
            Event::once(
                event_id("taxonomy-slow"),
                Some(Predicate::At { at: time(0) }),
                Action::InjectFault {
                    tag: tag("shared"),
                    fault: MembershipFault::taxonomy(slowdown_fault()),
                },
            ),
            Event::once(
                event_id("legacy-crash"),
                Some(Predicate::At { at: time(1) }),
                Action::InjectFault {
                    tag: tag("shared"),
                    fault: MembershipFault::Crash {
                        node: node("db-0"),
                        restart: RestartPolicy::StayDown,
                    },
                },
            ),
        ],
        &world,
    )
    .expect("replacement graph should validate");
    let mut state = EventGraphState::new();

    scheduler
        .append_evaluation_boundary(time(0), SchedulerEvaluationBoundaryKind::Quantum)
        .expect("evaluation boundary should append");
    let taxonomy_firings = scheduler.evaluate_event_graph(&graph, &mut state, NoLeaves);
    scheduler
        .apply_trigger_firings(&taxonomy_firings)
        .expect("taxonomy firing should apply");
    assert!(
        scheduler
            .trigger_actions()
            .combined_faults()
            .node
            .contains_key(&node("db-0"))
    );

    scheduler
        .append_evaluation_boundary(time(1), SchedulerEvaluationBoundaryKind::Quantum)
        .expect("evaluation boundary should append");
    let legacy_firings = scheduler.evaluate_event_graph(&graph, &mut state, NoLeaves);
    scheduler
        .apply_trigger_firings(&legacy_firings)
        .expect("same-tag legacy firing should apply");

    let actions = scheduler.trigger_actions();
    assert!(
        actions.active_taxonomy_faults.is_empty(),
        "replacing a taxonomy fault with a legacy fault under the same tag should clear taxonomy state"
    );
    assert_eq!(
        actions
            .combined_faults()
            .node
            .get(&node("db-0"))
            .and_then(|faults| faults.crash_restart),
        Some(RestartPolicy::StayDown),
        "legacy crash replacement should remain visible to the active fault table"
    );
    assert!(matches!(
        actions.active_faults.get(&tag("shared")),
        Some(MembershipFault::Crash {
            node: crashed_node,
            restart: RestartPolicy::StayDown,
        }) if crashed_node == &node("db-0")
    ));
}

#[test]
fn graph_native_taxonomy_inject_rejects_undeclared_device_refs() {
    let world = world();
    let block = EventGraph::new_for_world(
        vec![Event::once(
            event_id("block-device"),
            None,
            Action::InjectFault {
                tag: tag("block"),
                fault: MembershipFault::taxonomy(Fault::Block(BlockFault::Latency {
                    device: device("disk-a"),
                    extra: FaultDuration::from_nanos(1),
                    jitter: FaultDuration::ZERO,
                })),
            },
        )],
        &world,
    );
    assert_eq!(
        block,
        Err(EventGraphError::UnknownDeviceReference {
            event: event_id("block-device"),
            device: device("disk-a"),
        })
    );

    let ninep = EventGraph::new_for_world(
        vec![Event::once(
            event_id("ninep-device"),
            None,
            Action::InjectFault {
                tag: tag("ninep"),
                fault: MembershipFault::taxonomy(Fault::NineP(NinePFault::Latency {
                    device: device("share-a"),
                    extra: FaultDuration::from_nanos(1),
                    jitter: FaultDuration::ZERO,
                })),
            },
        )],
        &world,
    );
    assert_eq!(
        ninep,
        Err(EventGraphError::UnknownDeviceReference {
            event: event_id("ninep-device"),
            device: device("share-a"),
        })
    );
}

#[test]
fn fault_plan_hash_matches_equivalent_pure_at_event_graph() {
    let world = world();
    let plan = Plan::from_fault_plan_for_world(
        &world,
        FaultPlan::from_entries(vec![
            FaultPlanEntry::At {
                at: time(3),
                duration: FaultDuration::from_nanos(4),
                tag: tag("slow"),
                fault: slowdown_fault(),
            },
            FaultPlanEntry::PermanentAt {
                at: time(5),
                tag: tag("loss"),
                fault: loss_fault(),
            },
        ]),
    )
    .expect("fault plan should validate");
    let lowered = plan
        .lower_to_event_graph_for_world(&world)
        .expect("fault plan should lower");
    let graph_plan = Plan::from_event_graph_for_world(&world, lowered.event_graph().clone())
        .expect("lowered graph should validate as a graph-native plan");

    assert_eq!(plan.content_hash(), graph_plan.content_hash());
    assert_eq!(plan.canonical_bytes(), graph_plan.canonical_bytes());
}

#[test]
fn fault_plan_rejects_undeclared_or_unordered_references() {
    let world = world();
    let missing_link = Plan::from_fault_plan_for_world(
        &world,
        FaultPlan::from_entries(vec![FaultPlanEntry::PermanentAt {
            at: time(0),
            tag: tag("missing-link"),
            fault: Fault::Network(NetworkFault::Loss {
                link: link_id("db-0", "db-2"),
                rate: FaultRateBasisPoints::ONE,
            }),
        }]),
    );
    assert!(matches!(
        missing_link,
        Err(EngineError::PlanFaultUnknownLinkId { .. })
    ));

    let unknown_heal = Plan::from_fault_plan_for_world(
        &world,
        FaultPlan::from_entries(vec![FaultPlanEntry::Heal {
            at: time(1),
            tag: tag("missing"),
        }]),
    );
    assert!(matches!(
        unknown_heal,
        Err(EngineError::PlanHealUnknownTag { .. })
    ));

    let missing_device = Plan::from_fault_plan_for_world(
        &world,
        FaultPlan::from_entries(vec![FaultPlanEntry::PermanentAt {
            at: time(0),
            tag: tag("missing-device"),
            fault: Fault::Block(BlockFault::Latency {
                device: device("disk-a"),
                extra: FaultDuration::from_nanos(1),
                jitter: FaultDuration::ZERO,
            }),
        }]),
    );
    assert!(matches!(
        missing_device,
        Err(EngineError::PlanFaultUnknownDevice { .. })
    ));

    let before_inject = Plan::from_fault_plan_for_world(
        &world,
        FaultPlan::from_entries(vec![
            FaultPlanEntry::PermanentAt {
                at: time(5),
                tag: tag("loss"),
                fault: loss_fault(),
            },
            FaultPlanEntry::Heal {
                at: time(4),
                tag: tag("loss"),
            },
        ]),
    );
    assert!(matches!(
        before_inject,
        Err(EngineError::PlanHealBeforeActivate { .. })
    ));

    let overflow = Plan::from_fault_plan_for_world(
        &world,
        FaultPlan::from_entries(vec![FaultPlanEntry::At {
            at: time(u64::MAX),
            duration: FaultDuration::from_nanos(1),
            tag: tag("overflow"),
            fault: loss_fault(),
        }]),
    );
    assert!(matches!(
        overflow,
        Err(EngineError::PlanFaultDurationOverflow { .. })
    ));
}

#[test]
fn fault_plan_rejects_ambiguous_legacy_link_ids() {
    let world = World::from_nodes_and_links(
        vec![
            ready_node("a"),
            ready_node("b--c"),
            ready_node("a--b"),
            ready_node("c"),
        ],
        vec![
            LinkDef::new(node("a"), node("b--c")).expect("first link should build"),
            LinkDef::new(node("a--b"), node("c")).expect("second link should build"),
        ],
    )
    .expect("adversarial link-name World should validate");
    let ambiguous = Plan::from_fault_plan_for_world(
        &world,
        FaultPlan::from_entries(vec![FaultPlanEntry::PermanentAt {
            at: time(0),
            tag: tag("ambiguous-link"),
            fault: Fault::Network(NetworkFault::Loss {
                link: LinkId::from_name("a--b--c"),
                rate: FaultRateBasisPoints::ONE,
            }),
        }]),
    );

    assert!(matches!(
        ambiguous,
        Err(EngineError::PlanFaultUnknownLinkId { .. })
    ));
    for canonical in [link_id("a", "b--c"), link_id("a--b", "c")] {
        Plan::from_fault_plan_for_world(
            &world,
            FaultPlan::from_entries(vec![FaultPlanEntry::PermanentAt {
                at: time(0),
                tag: FaultTag::from_name(format!("canonical-{}", canonical.name)),
                fault: Fault::Network(NetworkFault::Loss {
                    link: canonical,
                    rate: FaultRateBasisPoints::ONE,
                }),
            }]),
        )
        .expect("each canonical structured link id should remain valid");
    }
}

#[test]
fn fault_plan_round_trips_through_canonical_toml_and_binary() {
    let world = world();
    let plan = Plan::from_fault_plan_for_world(
        &world,
        FaultPlan::from_entries(vec![
            FaultPlanEntry::At {
                at: time(2),
                duration: FaultDuration::from_nanos(8),
                tag: tag("slow"),
                fault: slowdown_fault(),
            },
            FaultPlanEntry::PermanentAt {
                at: time(3),
                tag: tag("partition"),
                fault: Fault::Network(NetworkFault::Partition {
                    link: link_id("db-0", "db-1"),
                    direction: PartitionDirection::Bidirectional,
                }),
            },
        ]),
    )
    .expect("fault plan should validate");

    let toml = plan
        .to_canonical_toml()
        .expect("fault plan should serialize as TOML");
    assert!(toml.contains("kind = \"fault_plan\""));
    assert!(toml.contains("[[fault_entry]]"));
    let parsed_toml =
        Plan::from_canonical_toml_for_world(&world, &toml).expect("fault plan TOML should parse");
    assert_eq!(parsed_toml, plan);

    let binary = plan.to_compact_binary();
    let parsed_binary = Plan::from_compact_binary_for_world(&world, &binary)
        .expect("fault plan binary should parse");
    assert_eq!(parsed_binary, plan);
}

#[test]
fn fault_plan_toml_rejects_out_of_range_integer_params() {
    let world = world();
    let input = r#"
id = "blake3:0000000000000000000000000000000000000000000000000000000000000000"
kind = "fault_plan"

[[fault_entry]]
kind = "permanent_at"
at_ticks = 0
tag = "bad-rate"

[fault_entry.fault]
kind = "network_loss"
link = "db-0--db-1"
rate_basis_points = 10001
"#;

    let parsed = Plan::from_canonical_toml_for_world(&world, input);
    assert!(matches!(
        parsed,
        Err(EngineError::FaultRateBasisPointsOutOfRange { .. })
    ));
}
