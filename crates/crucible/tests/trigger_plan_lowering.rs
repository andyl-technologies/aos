//! Checks T-TRIG-16 Plan lowering into pure `At` event graphs.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;

use crucible::{
    Action, ConditionLeaf, ConditionLeafOracle, Event, EventGraph, EventGraphState, EventId,
    ExactLocalEvent, FaultTag, Icount, LinkDef, LogLevel, MembershipFault, NetworkLookahead,
    NodeCounter, NodeId, NodeTemplate, PartitionDirection, Plan, PlanEntry, Predicate, ReadyPoint,
    RegexProgram, RestartPolicy, SchedulerEvaluationBoundaryKind, SchedulerLivenessScenario,
    SchedulerNodeActivity, SchedulerNodeId, SchedulerScenarioNode, SchedulingNodeKind, Shift,
    SimInstant, SingleScheduler, VirtualTime, VmArchitecture, WhiteBoxPolicy, World, WorldNode,
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

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
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

fn lowering_world() -> World {
    World::from_nodes_and_links(
        vec![ready_node("db-0"), ready_node("db-1")],
        vec![LinkDef::new(node("db-0"), node("db-1")).expect("test link should build")],
    )
    .expect("Plan lowering test world should build")
}

fn scenario(name: &str, world: &World) -> SchedulerLivenessScenario {
    SchedulerLivenessScenario::from_canonical_material(
        name,
        shift(0),
        16,
        SimInstant { nanos: 100 },
        vec![scenario_node("db-0"), scenario_node("db-1")],
        Vec::new(),
    )
    .with_trigger_world(world)
}

fn scenario_node(name: &str) -> SchedulerScenarioNode {
    SchedulerScenarioNode {
        id: scheduler_node(name),
        counter: NodeCounter { ticks: 0 },
        activity: SchedulerNodeActivity::Idle,
        network_lookahead: NetworkLookahead::Infinite,
        exact_local_event: ExactLocalEvent::NoArmedTimer,
    }
}

fn scheduler_node(name: &str) -> SchedulerNodeId {
    SchedulerNodeId {
        node: node(name),
        kind: SchedulingNodeKind::Vm,
    }
}

fn split_fault() -> MembershipFault {
    MembershipFault::Partition {
        endpoint_a: node("db-0"),
        endpoint_b: node("db-1"),
        direction: PartitionDirection::Bidirectional,
    }
}

fn crash_fault() -> MembershipFault {
    MembershipFault::Crash {
        node: node("db-0"),
        restart: RestartPolicy::StayDown,
    }
}

fn lowering_plan(world: &World) -> Plan {
    Plan::from_entries_for_world(
        world,
        vec![
            PlanEntry::Heal {
                at: time(11),
                tag: tag("crash-db-0"),
            },
            PlanEntry::Activate {
                at: time(7),
                tag: tag("crash-db-0"),
                fault: crash_fault(),
            },
            PlanEntry::Activate {
                at: time(5),
                tag: tag("split"),
                fault: split_fault(),
            },
            PlanEntry::Activate {
                at: time(9),
                tag: tag("crash-db-1"),
                fault: MembershipFault::Crash {
                    node: node("db-1"),
                    restart: RestartPolicy::StayDown,
                },
            },
            PlanEntry::Heal {
                at: time(9),
                tag: tag("split"),
            },
        ],
    )
    .expect("Plan should validate and canonicalize")
}

fn plan_active_faults_at(plan: &Plan, at: VirtualTime) -> BTreeMap<FaultTag, MembershipFault> {
    let mut active = BTreeMap::new();
    for entry in plan.entries() {
        match entry {
            PlanEntry::Activate {
                at: activate_at,
                tag,
                fault,
            } if *activate_at <= at => {
                active.insert(tag.clone(), fault.clone());
            }
            PlanEntry::Heal { at: heal_at, tag } if *heal_at <= at => {
                active.remove(tag);
            }
            PlanEntry::Activate { .. } | PlanEntry::Heal { .. } => {}
        }
    }
    active
}

struct NoLeaves;

impl ConditionLeafOracle for NoLeaves {
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { .. } | ConditionLeaf::GuestMarker { .. } => {
                panic!("pure Plan lowering should evaluate only At leaves")
            }
        }
    }
}

#[test]
fn plan_lowers_to_identity_preserving_at_triggered_fault_events() {
    let world = lowering_world();
    let plan = lowering_plan(&world);
    let lowered = plan
        .lower_to_event_graph_for_world(&world)
        .expect("Plan should lower to a world-validated event graph");
    let graph = lowered.event_graph();

    assert_eq!(lowered.content_hash(), plan.content_hash());
    assert_eq!(lowered.canonical_bytes(), plan.canonical_bytes());
    assert_eq!(
        lowered.evaluation_times(),
        &[time(5), time(7), time(9), time(11)]
    );
    assert_eq!(graph.events().len(), plan.entries().len());

    assert_eq!(
        graph.events()[0].id.name,
        "plan:0000000000000000:activate:split"
    );
    assert_eq!(
        graph.events()[0].trigger,
        Some(Predicate::At { at: time(5) })
    );
    assert_eq!(
        graph.events()[0].action,
        Action::InjectFault {
            tag: tag("split"),
            fault: split_fault(),
        }
    );
    assert_eq!(
        graph.events()[1].id.name,
        "plan:0000000000000001:activate:crash-db-0"
    );
    assert_eq!(
        graph.events()[2].id.name,
        "plan:0000000000000002:activate:crash-db-1"
    );
    assert_eq!(
        graph.events()[2].trigger,
        Some(Predicate::At { at: time(9) })
    );
    assert_eq!(
        graph.events()[2].action,
        Action::InjectFault {
            tag: tag("crash-db-1"),
            fault: MembershipFault::Crash {
                node: node("db-1"),
                restart: RestartPolicy::StayDown,
            },
        }
    );
    assert_eq!(
        graph.events()[3].action,
        Action::HealFault { tag: tag("split") }
    );
    assert_eq!(
        graph.events()[4].action,
        Action::HealFault {
            tag: tag("crash-db-0"),
        }
    );

    let mut extended_events = graph.events().to_vec();
    let lowered_prefix = extended_events.clone();
    extended_events.push(Event::once(
        event_id("observe-ready"),
        Some(Predicate::console_match(
            node("db-0"),
            RegexProgram::from_pattern("ready"),
        )),
        Action::Log {
            level: LogLevel::Info,
            message: String::from("observed readiness"),
        },
    ));
    let extended = EventGraph::new_for_world(extended_events, &world)
        .expect("observation-anchored event should compose with lowered Plan events");

    assert_eq!(
        &extended.events()[..lowered_prefix.len()],
        lowered_prefix.as_slice()
    );
    assert_eq!(lowered.content_hash(), plan.content_hash());
}

#[test]
fn lowered_plan_graph_reduces_to_the_same_fault_state_as_plan_entries() {
    let world = lowering_world();
    let plan = lowering_plan(&world);
    let lowered = plan
        .lower_to_event_graph_for_world(&world)
        .expect("Plan should lower to an event graph");
    let graph = lowered.event_graph();
    let mut scheduler = SingleScheduler::new(scenario("plan-lowering-reduces", &world))
        .expect("scheduler should build");
    let mut state = EventGraphState::new();

    for at in lowered.evaluation_times() {
        scheduler
            .append_evaluation_boundary(*at, SchedulerEvaluationBoundaryKind::Quantum)
            .expect("evaluation boundary should append");
        let application_count_before = scheduler.trigger_actions().applications.len();
        let firings = scheduler.evaluate_event_graph(graph, &mut state, NoLeaves);
        if *at == time(9) {
            let fired_events = firings
                .iter()
                .map(|firing| firing.event().name.as_str())
                .collect::<Vec<_>>();
            assert_eq!(
                fired_events,
                vec![
                    "plan:0000000000000002:activate:crash-db-1",
                    "plan:0000000000000003:heal:split",
                ],
                "same-time Plan entries must fire in canonical lowered order"
            );
        }
        scheduler
            .apply_trigger_firings(&firings)
            .expect("lowered Plan firings should apply");
        if *at == time(9) {
            let applied = &scheduler.trigger_actions().applications[application_count_before..];
            assert_eq!(applied.len(), 2);
            assert_eq!(
                applied[0].event.name,
                "plan:0000000000000002:activate:crash-db-1"
            );
            assert_eq!(
                applied[0].action,
                Action::InjectFault {
                    tag: tag("crash-db-1"),
                    fault: MembershipFault::Crash {
                        node: node("db-1"),
                        restart: RestartPolicy::StayDown,
                    },
                }
            );
            assert_eq!(applied[1].event.name, "plan:0000000000000003:heal:split");
            assert_eq!(applied[1].action, Action::HealFault { tag: tag("split") });
        }
        assert_eq!(
            scheduler.trigger_actions().active_faults,
            plan_active_faults_at(&plan, *at),
            "lowered event graph should match Plan active faults at t={}",
            at.ticks
        );
    }
}
