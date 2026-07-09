//! Checks T-TRIG-11 trigger firings are causal event-log entries, not decisions.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    Action, Condition, ConditionEvaluationPass, ConditionLeaf, ConditionLeafOracle, Event,
    EventEvaluationKind, EventGraph, EventGraphState, EventId, FaultTag, Icount, LinkDef, LogLevel,
    MembershipFault, NodeId, NodeTemplate, PartitionDirection, ReadyPoint, RestartPolicy,
    SchedulerEventLogClass, SchedulerEventLogPayload, SchedulerLivenessScenario, Shift, SimInstant,
    SingleScheduler, VirtualTime, VmArchitecture, WhiteBoxPolicy, World, WorldNode,
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

fn scenario(name: &str) -> SchedulerLivenessScenario {
    SchedulerLivenessScenario::from_canonical_material(
        name,
        shift(0),
        8,
        SimInstant { nanos: 20 },
        Vec::new(),
        Vec::new(),
    )
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
    .expect("trigger firing test world should build")
}

fn trigger_graph() -> EventGraph {
    EventGraph::new_for_world(
        vec![Event::once(
            event_id("activate-split"),
            None,
            Action::InjectFault {
                tag: tag("split"),
                fault: MembershipFault::Partition {
                    endpoint_a: node("db-0"),
                    endpoint_b: node("db-1"),
                    direction: PartitionDirection::Bidirectional,
                },
            },
        )],
        &fault_world(),
    )
    .expect("entrypoint trigger graph should build")
}

struct NoLeaves;

impl ConditionLeafOracle for NoLeaves {
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { .. } | ConditionLeaf::GuestMarker { .. } => {
                panic!("entrypoint trigger firing test should not evaluate leaves")
            }
        }
    }
}

fn evaluate_with_oracle<O>(
    graph: &EventGraph,
    scheduler: &SingleScheduler,
    oracle: O,
) -> crucible::EventFirings
where
    O: ConditionLeafOracle,
{
    let mut state = EventGraphState::new();
    let mut pass = ConditionEvaluationPass::from_log_prefix(
        scheduler.condition_event_log_prefix().clone(),
        oracle,
    );
    pass.evaluate_event_graph(graph, &mut state)
}

fn evaluate_genesis(graph: &EventGraph, scheduler: &SingleScheduler) -> crucible::EventFirings {
    evaluate_with_oracle(graph, scheduler, NoLeaves)
}

struct TrueAgain;

impl ConditionLeafOracle for TrueAgain {
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { name, .. } => name == "again",
            ConditionLeaf::GuestMarker { .. } => false,
        }
    }
}

#[test]
fn trigger_firing_is_causal_event_log_entry_not_schedule_decision() {
    let graph = trigger_graph();
    let mut scheduler =
        SingleScheduler::new(scenario("trigger-firing-causal-log")).expect("scheduler builds");
    let before_schedule = scheduler.configuration().schedule.clone();
    let firings = evaluate_genesis(&graph, &scheduler);

    assert_eq!(firings.point().kind(), EventEvaluationKind::Genesis);
    assert_eq!(firings.len(), 1);
    assert_eq!(firings[0].event().name, "activate-split");

    let append = scheduler
        .append_trigger_firings(&firings)
        .expect("trigger firing should append as causal event-log entry");

    assert_eq!(scheduler.configuration().schedule, before_schedule);
    assert_eq!(append.entries.len(), 1);
    assert_eq!(append.entries[0].class(), SchedulerEventLogClass::Causal);
    assert!(append.segment_hash.is_some());
    assert_eq!(append.offset.events, 1);
    assert_eq!(
        scheduler.condition_event_log_prefix().point().kind(),
        EventEvaluationKind::EventBoundary
    );
    assert_eq!(scheduler.condition_event_log_prefix().point().at(), time(0));

    match append.entries[0].payload() {
        SchedulerEventLogPayload::TriggerFired(firing) => {
            assert_eq!(firing.event().name, "activate-split");
            assert_eq!(firing.at(), time(0));
            assert_eq!(firing.condition_summary(), "entrypoint");
            assert_eq!(firing.action(), firings[0].action());
        }
        SchedulerEventLogPayload::Decision(_) => {
            panic!("trigger firing must not be recorded as a Decision")
        }
        other => panic!("expected trigger_fired payload, got {other:?}"),
    }

    let duplicate = scheduler
        .append_trigger_firings(&firings)
        .expect_err("stale genesis firing batch should not append twice");
    assert!(
        duplicate
            .to_string()
            .contains("trigger firings were evaluated"),
        "{duplicate}"
    );
}

#[test]
fn stale_event_boundary_firing_batch_cannot_be_reappended() {
    let graph = trigger_graph();
    let mut scheduler = SingleScheduler::new(scenario("trigger-firing-stale-event-boundary"))
        .expect("scheduler builds");
    let genesis_firings = evaluate_genesis(&graph, &scheduler);
    scheduler
        .append_trigger_firings(&genesis_firings)
        .expect("first trigger firing should append");

    let event_boundary_graph = EventGraph::new(vec![Event::once(
        event_id("event-boundary-firing"),
        Some(Condition::named("again")),
        Action::Log {
            level: LogLevel::Info,
            message: String::from("event boundary fired"),
        },
    )])
    .expect("event-boundary trigger graph should build");
    let event_boundary_firings = evaluate_with_oracle(&event_boundary_graph, &scheduler, TrueAgain);

    assert_eq!(
        event_boundary_firings.point().kind(),
        EventEvaluationKind::EventBoundary
    );
    assert_eq!(
        event_boundary_firings.event_log_offset(),
        scheduler.event_log_offset()
    );
    let event_boundary_append = scheduler
        .append_trigger_firings(&event_boundary_firings)
        .expect("event-boundary firing should append once");
    let event_boundary_entry = event_boundary_append
        .entries
        .last()
        .expect("event-boundary firing should be appended");
    assert_eq!(event_boundary_entry.event_payload().kind(), "trigger_fired");
    assert_eq!(
        event_boundary_entry.event_payload().string("condition"),
        Some("predicate=named\npredicate_name_len=5\npredicate_name=again\npredicate_nodes=0")
    );
    assert!(
        event_boundary_append
            .entries
            .iter()
            .all(|entry| entry.event_payload().kind() != "condition_evaluated"),
        "condition truth is evaluated for firing, not appended as its own event kind"
    );
    assert_eq!(
        scheduler.condition_event_log_prefix().point().kind(),
        EventEvaluationKind::EventBoundary,
        "appending a trigger_fired entry at the same tick keeps the point kind stable"
    );

    let duplicate = scheduler
        .append_trigger_firings(&event_boundary_firings)
        .expect_err("same event-boundary firing batch should be stale after append");
    assert!(
        duplicate.to_string().contains("event-log offset"),
        "{duplicate}"
    );
}

#[test]
fn forked_same_prefix_rederives_identical_trigger_firing_entries() {
    let graph = trigger_graph();
    let mut left =
        SingleScheduler::new(scenario("trigger-firing-fork-left")).expect("left scheduler builds");
    let mut right =
        SingleScheduler::new(scenario("trigger-firing-fork-left")).expect("right scheduler builds");

    let left_firings = evaluate_genesis(&graph, &left);
    let right_firings = evaluate_genesis(&graph, &right);
    assert_eq!(left_firings, right_firings);

    let left_append = left
        .append_trigger_firings(&left_firings)
        .expect("left trigger firing append should succeed");
    let right_append = right
        .append_trigger_firings(&right_firings)
        .expect("right trigger firing append should succeed");

    assert_eq!(left_append.entries, right_append.entries);
    assert_eq!(
        left_append.segment_bytes, right_append.segment_bytes,
        "same schedule prefix must produce byte-identical causal trigger entries"
    );
    assert_eq!(left_append.segment_hash, right_append.segment_hash);
    assert_eq!(left_append.offset, right_append.offset);
    assert_eq!(left.event_log_offset(), right.event_log_offset());
}

#[test]
fn trigger_firing_for_probabilistic_fault_action_is_not_a_fault_outcome_decision() {
    let graph = EventGraph::new_for_world(
        vec![Event::once(
            event_id("activate-crash"),
            None,
            Action::InjectFault {
                tag: tag("crash"),
                fault: MembershipFault::Crash {
                    node: node("db-0"),
                    restart: RestartPolicy::FromReadyPoint,
                },
            },
        )],
        &fault_world(),
    )
    .expect("crash trigger graph should build");
    let mut scheduler = SingleScheduler::new(scenario("trigger-firing-probabilistic-action"))
        .expect("scheduler builds");
    let firings = evaluate_genesis(&graph, &scheduler);
    let append = scheduler
        .append_trigger_firings(&firings)
        .expect("trigger firing should append");

    assert!(
        append
            .entries
            .iter()
            .all(|entry| !matches!(entry.payload(), SchedulerEventLogPayload::Decision(_))),
        "the deterministic trigger firing is separate from later probabilistic fault decisions"
    );
}
