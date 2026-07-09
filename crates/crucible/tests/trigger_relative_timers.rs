//! Checks T-TRIG-14 relative trigger timers and `After` sugar.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;

use crucible::{
    Action, CodePoint, ConditionEvaluationPass, ConditionLeaf, ConditionLeafOracle, Event,
    EventFirings, EventGraph, EventGraphState, EventId, FaultTag, Icount, LinkDef, LogLevel,
    MembershipFault, NodeId, NodeTemplate, ObservableEvent, PartitionDirection, Predicate,
    ReadyPoint, RegexProgram, SchedulerEvaluationBoundaryKind, SchedulerEventLogAppend,
    SchedulerEventLogPayload, SchedulerLivenessScenario, Shift, SimDuration, SimInstant,
    SingleScheduler, TimerId, TriggerActionState, VirtualTime, VmArchitecture, WhiteBoxPolicy,
    World, WorldNode,
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

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

fn icount(retired: u64) -> Icount {
    Icount { retired }
}

fn duration(nanos: u64) -> SimDuration {
    SimDuration { nanos }
}

fn shift(bits: u8) -> Shift {
    Shift { bits }
}

fn scenario(name: &str) -> SchedulerLivenessScenario {
    SchedulerLivenessScenario::from_canonical_material(
        name,
        shift(0),
        16,
        SimInstant { nanos: 100 },
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

fn recovery_world() -> World {
    World::from_nodes_and_links(
        vec![ready_node("db-0"), ready_node("db-1")],
        vec![LinkDef::new(node("db-0"), node("db-1")).expect("test link should build")],
    )
    .expect("relative timer test world should build")
}

fn split_fault() -> MembershipFault {
    MembershipFault::Partition {
        endpoint_a: node("db-0"),
        endpoint_b: node("db-1"),
        direction: PartitionDirection::Bidirectional,
    }
}

fn ready_condition() -> Predicate {
    Predicate::all_of(vec![
        Predicate::console_match(
            node("db-0"),
            RegexProgram::from_pattern("ready to accept connections"),
        ),
        Predicate::console_match(
            node("db-1"),
            RegexProgram::from_pattern("ready to accept connections"),
        ),
        Predicate::once(Predicate::coverage_point(
            node("db-0"),
            CodePoint::guest_address(0x4010),
        )),
    ])
}

fn recovery_observations() -> Vec<ObservableEvent> {
    vec![
        ObservableEvent::console_output(
            time(10),
            node("db-0"),
            b"db-0 ready to accept connections\n".to_vec(),
        ),
        ObservableEvent::console_output(
            time(10),
            node("db-1"),
            b"db-1 ready to accept connections\n".to_vec(),
        ),
        ObservableEvent::coverage_block(icount(10), node("db-0"), 0x4000, 0x20),
    ]
}

fn timer_recovery_graph() -> EventGraph {
    let heal_timer = timer("heal-after");
    EventGraph::new_for_world(
        vec![
            Event::once(
                event_id("wait-ready"),
                Some(ready_condition()),
                Action::Group(vec![
                    Action::InjectFault {
                        tag: tag("split"),
                        fault: split_fault(),
                    },
                    Action::ArmTimer {
                        name: heal_timer.clone(),
                        after: duration(30),
                    },
                ]),
            ),
            Event::once(
                event_id("heal"),
                Some(Predicate::timer(heal_timer)),
                Action::HealFault { tag: tag("split") },
            ),
        ],
        &recovery_world(),
    )
    .expect("timer recovery graph should build")
}

fn after_recovery_graph() -> EventGraph {
    EventGraph::new_for_world(
        vec![
            Event::once(
                event_id("wait-ready"),
                Some(ready_condition()),
                Action::InjectFault {
                    tag: tag("split"),
                    fault: split_fault(),
                },
            ),
            Event::once(
                event_id("heal"),
                Some(Predicate::after(duration(30), event_id("wait-ready"))),
                Action::HealFault { tag: tag("split") },
            ),
        ],
        &recovery_world(),
    )
    .expect("after recovery graph should build")
}

fn cancel_timer_graph() -> EventGraph {
    let heal_timer = timer("heal-after");
    EventGraph::new(vec![
        Event::once(
            event_id("arm-and-cancel"),
            None,
            Action::Group(vec![
                Action::ArmTimer {
                    name: heal_timer.clone(),
                    after: duration(5),
                },
                Action::CancelTimer {
                    name: heal_timer.clone(),
                },
            ]),
        ),
        Event::once(
            event_id("timer-fired"),
            Some(Predicate::timer(heal_timer)),
            Action::Fail {
                reason: String::from("cancelled timer fired"),
            },
        ),
    ])
    .expect("cancel timer graph should build")
}

struct NoLeaves;

impl ConditionLeafOracle for NoLeaves {
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { .. } | ConditionLeaf::GuestMarker { .. } => {
                panic!("relative timer scenario should use only black-box observable leaves")
            }
        }
    }
}

fn evaluate(
    scheduler: &SingleScheduler,
    graph: &EventGraph,
    state: &mut EventGraphState,
) -> EventFirings {
    scheduler.evaluate_event_graph(graph, state, NoLeaves)
}

fn evaluate_without_scheduler_timer_state(
    scheduler: &SingleScheduler,
    graph: &EventGraph,
    state: &mut EventGraphState,
) -> EventFirings {
    let mut pass = ConditionEvaluationPass::from_log_prefix(
        scheduler.condition_event_log_prefix().clone(),
        NoLeaves,
    )
    .with_timer_fires(BTreeMap::new());
    pass.evaluate_event_graph(graph, state)
}

fn fired_names(firings: &EventFirings) -> Vec<&str> {
    firings
        .iter()
        .map(|firing| firing.event().name.as_str())
        .collect()
}

fn append_boundary(scheduler: &mut SingleScheduler, ticks: u64) -> SchedulerEventLogAppend {
    scheduler
        .append_evaluation_boundary(time(ticks), SchedulerEvaluationBoundaryKind::Quantum)
        .expect("evaluation boundary should append")
}

#[derive(Debug, PartialEq, Eq)]
struct RecoveryRun {
    trigger_actions: TriggerActionState,
    event_log_offset: crucible::EventLogOffset,
    segment_bytes: Vec<Vec<u8>>,
}

fn run_timer_recovery(name: &str) -> RecoveryRun {
    let graph = timer_recovery_graph();
    let mut graph_state = EventGraphState::new();
    let mut scheduler = SingleScheduler::new(scenario(name)).expect("scheduler should build");
    let mut segment_bytes = Vec::new();

    let observations = scheduler
        .append_observable_events(recovery_observations())
        .expect("observations should append");
    segment_bytes.push(observations.segment_bytes);

    let ready = evaluate(&scheduler, &graph, &mut graph_state);
    assert_eq!(fired_names(&ready), vec!["wait-ready"]);
    let ready_append = scheduler
        .apply_trigger_firings(&ready)
        .expect("ready trigger actions should apply");
    segment_bytes.push(ready_append.segment_bytes);
    assert_eq!(
        scheduler.trigger_actions().active_faults.get(&tag("split")),
        Some(&split_fault())
    );
    assert_eq!(
        scheduler
            .trigger_actions()
            .armed_timers
            .get(&timer("heal-after")),
        Some(&time(40))
    );

    segment_bytes.push(append_boundary(&mut scheduler, 39).segment_bytes);
    let early = evaluate(&scheduler, &graph, &mut graph_state);
    assert!(early.is_empty());

    segment_bytes.push(append_boundary(&mut scheduler, 40).segment_bytes);
    let heal = evaluate(&scheduler, &graph, &mut graph_state);
    assert_eq!(fired_names(&heal), vec!["heal"]);
    assert_eq!(heal[0].at(), time(40));
    let heal_append = scheduler
        .apply_trigger_firings(&heal)
        .expect("heal trigger action should apply");
    segment_bytes.push(heal_append.segment_bytes);
    assert!(scheduler.trigger_actions().active_faults.is_empty());
    assert!(
        scheduler
            .trigger_actions()
            .applications
            .iter()
            .any(|application| matches!(application.action, Action::ArmTimer { .. }))
    );
    assert!(
        scheduler
            .trigger_actions()
            .applications
            .iter()
            .any(|application| matches!(application.action, Action::HealFault { .. }))
    );

    RecoveryRun {
        trigger_actions: scheduler.trigger_actions().clone(),
        event_log_offset: scheduler.event_log_offset(),
        segment_bytes,
    }
}

#[test]
fn arm_timer_timer_leaf_heals_at_relative_virtual_time_and_replays_identically() {
    let left = run_timer_recovery("timer-recovery");
    let right = run_timer_recovery("timer-recovery");

    assert_eq!(left, right);
}

#[test]
fn after_sugar_heals_at_the_same_relative_virtual_time() {
    let graph = after_recovery_graph();
    let mut graph_state = EventGraphState::new();
    let mut scheduler =
        SingleScheduler::new(scenario("after-recovery")).expect("scheduler should build");

    scheduler
        .append_observable_events(recovery_observations())
        .expect("observations should append");
    let ready = evaluate(&scheduler, &graph, &mut graph_state);
    assert_eq!(fired_names(&ready), vec!["wait-ready"]);
    scheduler
        .apply_trigger_firings(&ready)
        .expect("ready action should apply");

    append_boundary(&mut scheduler, 39);
    let early = evaluate(&scheduler, &graph, &mut graph_state);
    assert!(early.is_empty());

    append_boundary(&mut scheduler, 40);
    let heal = evaluate(&scheduler, &graph, &mut graph_state);
    assert_eq!(fired_names(&heal), vec!["heal"]);
    assert_eq!(heal[0].at(), time(40));
    scheduler
        .apply_trigger_firings(&heal)
        .expect("after heal should apply");
    assert!(scheduler.trigger_actions().active_faults.is_empty());
    assert!(scheduler.trigger_actions().armed_timers.is_empty());
}

#[test]
fn cancelled_timer_does_not_fire_at_its_former_deadline() {
    let graph = cancel_timer_graph();
    let mut graph_state = EventGraphState::new();
    let mut scheduler =
        SingleScheduler::new(scenario("cancelled-timer")).expect("scheduler should build");

    let arm_and_cancel = evaluate(&scheduler, &graph, &mut graph_state);
    assert_eq!(fired_names(&arm_and_cancel), vec!["arm-and-cancel"]);
    scheduler
        .apply_trigger_firings(&arm_and_cancel)
        .expect("arm and cancel should apply");
    assert!(scheduler.trigger_actions().armed_timers.is_empty());

    append_boundary(&mut scheduler, 5);
    let timer_firing = evaluate(&scheduler, &graph, &mut graph_state);
    assert!(
        timer_firing.is_empty(),
        "cancelled timer must not make the Timer leaf true"
    );
    assert!(
        scheduler
            .trigger_actions()
            .applications
            .iter()
            .all(|application| !matches!(application.action, Action::Fail { .. })),
        "cancelled timer path must not apply the guarded failure action"
    );
}

#[test]
fn scheduler_rejects_timer_firings_evaluated_without_scheduler_timer_state() {
    let graph = timer_recovery_graph();
    let mut graph_state = EventGraphState::new();
    let mut scheduler =
        SingleScheduler::new(scenario("timer-evaluation-bypass")).expect("scheduler should build");

    scheduler
        .append_observable_events(recovery_observations())
        .expect("observations should append");
    let ready = evaluate(&scheduler, &graph, &mut graph_state);
    assert_eq!(fired_names(&ready), vec!["wait-ready"]);
    scheduler
        .apply_trigger_firings(&ready)
        .expect("ready trigger actions should apply");
    assert_eq!(
        scheduler
            .trigger_actions()
            .armed_timers
            .get(&timer("heal-after")),
        Some(&time(40))
    );

    append_boundary(&mut scheduler, 40);
    let mut bypass_state = graph_state.clone();
    let bypass = evaluate_without_scheduler_timer_state(&scheduler, &graph, &mut bypass_state);
    assert!(bypass.is_empty());
    let error = scheduler
        .apply_trigger_firings(&bypass)
        .expect_err("scheduler must reject firings evaluated without its timer state");
    assert!(
        error
            .to_string()
            .contains("timer state that does not match scheduler trigger action state"),
        "unexpected error: {error}"
    );

    let heal = evaluate(&scheduler, &graph, &mut graph_state);
    assert_eq!(fired_names(&heal), vec!["heal"]);
}

#[test]
fn log_action_remains_observational_inside_relative_timer_run() {
    let graph = EventGraph::new(vec![Event::once(
        event_id("log-then-arm"),
        None,
        Action::Group(vec![
            Action::Log {
                level: LogLevel::Info,
                message: String::from("arming"),
            },
            Action::ArmTimer {
                name: timer("diagnostic"),
                after: duration(1),
            },
        ]),
    )])
    .expect("log plus timer graph should build");
    let mut graph_state = EventGraphState::new();
    let mut scheduler =
        SingleScheduler::new(scenario("timer-log")).expect("scheduler should build");
    let firings = evaluate(&scheduler, &graph, &mut graph_state);
    let append = scheduler
        .apply_trigger_firings(&firings)
        .expect("log plus timer should apply");

    assert!(append.entries.iter().any(|entry| matches!(
        entry.payload(),
        SchedulerEventLogPayload::TriggerActionApplied(application)
            if application.is_observational()
    )));
}
