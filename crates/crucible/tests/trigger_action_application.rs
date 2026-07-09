//! Checks T-TRIG-12 deterministic trigger action application.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use crucible::{
    Action, ConditionEvaluationPass, ConditionLeaf, ConditionLeafOracle, Event, EventGraph,
    EventGraphState, EventId, FaultTag, Icount, LinkDef, LogLevel, MembershipFault, NodeId,
    NodeLifecycle, NodeTemplate, PartitionDirection, ReadyPoint, SchedulerEventLogClass,
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
    .with_trigger_world(&action_world())
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

fn action_world() -> World {
    World::from_nodes_and_links(
        vec![
            ready_node("db-0"),
            ready_node("db-1"),
            ready_node("standby"),
        ],
        vec![LinkDef::new(node("db-0"), node("db-1")).expect("test link should build")],
    )
    .expect("action test world should build")
}

fn full_action_set() -> Action {
    Action::Group(vec![
        Action::InjectFault {
            tag: tag("split"),
            fault: MembershipFault::Partition {
                endpoint_a: node("db-0"),
                endpoint_b: node("db-1"),
                direction: PartitionDirection::Bidirectional,
            },
        },
        Action::HealFault { tag: tag("split") },
        Action::Group(vec![
            Action::ArmTimer {
                name: timer("heal-delay"),
                after: SimDuration { nanos: 5 },
            },
            Action::CancelTimer {
                name: timer("heal-delay"),
            },
            Action::StartNode {
                node: node("standby"),
            },
            Action::StopNode { node: node("db-1") },
        ]),
        Action::CreateSavepoint {
            label: Some(String::from("before-fork")),
        },
        Action::Fork {
            label: Some(String::from("explore")),
        },
        Action::Pass,
        Action::Fail {
            reason: String::from("terminal failure wins until T-TRIG-17 composition"),
        },
        Action::Log {
            level: LogLevel::Warn,
            message: String::from("action group applied"),
        },
    ])
}

fn action_graph() -> EventGraph {
    EventGraph::new_for_world(
        vec![Event::once(
            event_id("all-actions"),
            None,
            full_action_set(),
        )],
        &action_world(),
    )
    .expect("full action graph should build")
}

struct NoLeaves;

impl ConditionLeafOracle for NoLeaves {
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { .. } | ConditionLeaf::GuestMarker { .. } => {
                panic!("entrypoint action test should not evaluate leaves")
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
fn trigger_actions_apply_full_set_in_group_order_without_schedule_decisions() {
    let graph = action_graph();
    let mut scheduler =
        SingleScheduler::new(scenario("trigger-action-application")).expect("scheduler builds");
    let before_schedule = scheduler.configuration().schedule.clone();
    let firings = evaluate_genesis(&graph, &scheduler);

    let append = scheduler
        .apply_trigger_firings(&firings)
        .expect("trigger actions should apply");

    assert_eq!(scheduler.configuration().schedule, before_schedule);
    assert_eq!(append.entries.len(), 12);
    assert!(matches!(
        append.entries[0].payload(),
        SchedulerEventLogPayload::TriggerFired(_)
    ));
    assert_eq!(append.entries[0].class(), SchedulerEventLogClass::Causal);
    assert_eq!(
        append
            .entries
            .iter()
            .filter(|entry| matches!(
                entry.payload(),
                SchedulerEventLogPayload::TriggerActionApplied(_)
            ))
            .count(),
        11
    );
    assert!(
        append
            .entries
            .iter()
            .all(|entry| !matches!(entry.payload(), SchedulerEventLogPayload::Decision(_))),
        "trigger actions must not append Schedule decisions"
    );

    let state = scheduler.trigger_actions();
    assert!(state.active_faults.is_empty());
    assert!(state.armed_timers.is_empty());
    assert_eq!(
        state.node_states.get(&node("standby")),
        Some(&NodeLifecycle::Started)
    );
    assert_eq!(
        state.node_states.get(&node("db-1")),
        Some(&NodeLifecycle::Exited)
    );
    assert_eq!(state.savepoints[0].label.as_deref(), Some("before-fork"));
    assert_eq!(state.forks[0].label.as_deref(), Some("explore"));
    assert_eq!(
        state
            .verdict
            .as_ref()
            .and_then(|verdict| verdict.failed_reason.as_deref()),
        Some("terminal failure wins until T-TRIG-17 composition")
    );
    assert_eq!(state.diagnostics[0].level, LogLevel::Warn);
    assert_eq!(state.diagnostics[0].message, "action group applied");

    let paths = state
        .applications
        .iter()
        .map(|application| application.path.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        paths,
        vec![
            vec![0],
            vec![1],
            vec![2, 0],
            vec![2, 1],
            vec![2, 2],
            vec![2, 3],
            vec![3],
            vec![4],
            vec![5],
            vec![6],
            vec![7],
        ]
    );
    for (index, application) in state.applications.iter().enumerate() {
        assert_eq!(application.sequence, index as u64);
        assert_eq!(application.event.name, "all-actions");
        assert_eq!(application.at.ticks, 0);
    }

    let log_entries = append
        .entries
        .iter()
        .filter(|entry| {
            matches!(
                entry.payload(),
                SchedulerEventLogPayload::TriggerActionApplied(application)
                    if application.is_observational()
            )
        })
        .collect::<Vec<_>>();
    assert_eq!(log_entries.len(), 1);
    assert_eq!(
        log_entries[0].class(),
        SchedulerEventLogClass::Observational
    );
}

#[test]
fn forked_same_prefix_rederives_identical_action_state_and_bytes() {
    let graph = action_graph();
    let mut left =
        SingleScheduler::new(scenario("trigger-action-fork")).expect("left scheduler builds");
    let mut right =
        SingleScheduler::new(scenario("trigger-action-fork")).expect("right scheduler builds");
    let left_firings = evaluate_genesis(&graph, &left);
    let right_firings = evaluate_genesis(&graph, &right);

    let left_append = left
        .apply_trigger_firings(&left_firings)
        .expect("left actions should apply");
    let right_append = right
        .apply_trigger_firings(&right_firings)
        .expect("right actions should apply");

    assert_eq!(left.trigger_actions(), right.trigger_actions());
    assert_eq!(left_append.entries, right_append.entries);
    assert_eq!(left_append.segment_bytes, right_append.segment_bytes);
    assert_eq!(left_append.segment_hash, right_append.segment_hash);
    assert_eq!(left.event_log_offset(), right.event_log_offset());
}

#[test]
fn stale_firing_batch_cannot_apply_actions_twice() {
    let graph = action_graph();
    let mut scheduler =
        SingleScheduler::new(scenario("trigger-action-stale-batch")).expect("scheduler builds");
    let firings = evaluate_genesis(&graph, &scheduler);

    scheduler
        .apply_trigger_firings(&firings)
        .expect("first action application should succeed");
    let applications_after_first_apply = scheduler.trigger_actions().applications.clone();
    let stale = scheduler
        .apply_trigger_firings(&firings)
        .expect_err("stale action firing batch should not apply twice");

    assert!(stale.to_string().contains("trigger firings were evaluated"));
    assert_eq!(
        scheduler.trigger_actions().applications,
        applications_after_first_apply,
        "stale apply rejection must leave trigger action state unchanged"
    );
}
