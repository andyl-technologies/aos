//! Checks T-FAULT-12 tag-based activation and materialized active tags.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;

use crucible::{
    Action, Checkpoint, CheckpointKind, ConditionLeaf, ConditionLeafOracle, Configuration,
    ControlFaultAction, ControlFaultDecision, ControlOperation, ControlOperationKind, Decision,
    DecisionRngState, EngineError, Event, EventGraph, EventGraphState, EventId, EventLogOffset,
    ExactLocalEvent, Fault, FaultPlan, FaultPlanEntry, FaultSlowdownFactorBasisPoints, FaultTag,
    GenesisCheckpoint, Icount, MaterializedState, MembershipFault, NetworkLookahead, NodeCounter,
    NodeFault, NodeId, NodeTemplate, Plan, Predicate, QuantumLoop, QuantumRequest, ReadyPoint,
    ScenarioDef, SchedulerEvaluationBoundaryKind, SchedulerLivenessScenario, SchedulerNodeActivity,
    SchedulerNodeId, SchedulerScenarioNode, SchedulingNodeKind, Shift, SimInstant, SingleScheduler,
    TemporalGraph, VirtualTime, VmArchitecture, WhiteBoxPolicy, World, WorldNode, step,
};

#[test]
fn reinjecting_same_tag_replaces_prior_fault_and_materializes_binding() {
    let tag = tag("shared");
    let original = slowdown_fault("db-0", 20_000);
    let replacement = slowdown_fault("db-0", 12_500);
    let mut scheduler = SingleScheduler::new(single_idle_node_scenario("tag-replace"))
        .expect("scheduler should build");

    scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: vec![
                control(
                    1,
                    ControlOperationKind::InjectFault {
                        tag: tag.clone(),
                        fault: original,
                    },
                ),
                control(
                    2,
                    ControlOperationKind::InjectFault {
                        tag: tag.clone(),
                        fault: replacement.clone(),
                    },
                ),
            ],
        })
        .expect("same-tag reinject should apply");

    let actions = scheduler.trigger_actions();
    assert_eq!(actions.active_taxonomy_faults.get(&tag), Some(&replacement));
    assert_eq!(
        actions.active_faults.get(&tag),
        Some(&MembershipFault::taxonomy(replacement.clone()))
    );

    let mut scheduler_state = crucible::SchedulerState::empty();
    scheduler_state.active_fault_tags = actions.active_faults.clone();
    let tagged = MaterializedState::from_components(
        BTreeMap::new(),
        BTreeMap::new(),
        scheduler_state,
        DecisionRngState::empty(),
        EventLogOffset::default(),
    );

    assert_eq!(
        tagged.scheduler.active_fault_tags.get(&tag),
        Some(&MembershipFault::taxonomy(replacement))
    );
    assert_ne!(
        tagged.id,
        MaterializedState::empty().id,
        "active fault tags must contribute to materialized-state identity"
    );
}

#[test]
fn heal_by_tag_removes_only_the_named_active_fault() {
    let slow = tag("slow");
    let slower = tag("slower");
    let slow_fault = slowdown_fault("db-0", 15_000);
    let slower_fault = slowdown_fault("db-0", 25_000);
    let mut scheduler = SingleScheduler::new(single_idle_node_scenario("tag-heal-one"))
        .expect("scheduler should build");

    scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: vec![
                control(
                    1,
                    ControlOperationKind::InjectFault {
                        tag: slow.clone(),
                        fault: slow_fault,
                    },
                ),
                control(
                    2,
                    ControlOperationKind::InjectFault {
                        tag: slower.clone(),
                        fault: slower_fault.clone(),
                    },
                ),
                control(3, ControlOperationKind::HealFault { tag: slow.clone() }),
            ],
        })
        .expect("tagged heal should apply");

    let actions = scheduler.trigger_actions();
    assert!(!actions.active_taxonomy_faults.contains_key(&slow));
    assert!(!actions.active_faults.contains_key(&slow));
    assert_eq!(
        actions.active_taxonomy_faults.get(&slower),
        Some(&slower_fault)
    );
    assert_eq!(
        actions.active_faults.get(&slower),
        Some(&MembershipFault::taxonomy(slower_fault))
    );
}

#[test]
fn declarative_unknown_heal_is_rejected_but_imperative_unknown_heal_noops() {
    let missing = tag("missing");
    let rejected = Plan::from_fault_plan_for_world(
        &world(),
        FaultPlan::from_entries(vec![FaultPlanEntry::Heal {
            at: time(1),
            tag: missing.clone(),
        }]),
    );
    assert!(matches!(
        rejected,
        Err(EngineError::PlanHealUnknownTag { tag }) if tag == missing
    ));

    let mut scheduler = SingleScheduler::new(single_idle_node_scenario("unknown-heal-noop"))
        .expect("scheduler should build");
    scheduler
        .drive_quantum(QuantumRequest {
            configuration: scheduler.configuration().clone(),
            control: vec![control(
                1,
                ControlOperationKind::HealFault {
                    tag: tag("runtime-missing"),
                },
            )],
        })
        .expect("imperative unknown heal should be a no-op");

    assert!(scheduler.trigger_actions().active_faults.is_empty());
    assert!(
        scheduler
            .trigger_actions()
            .active_taxonomy_faults
            .is_empty()
    );
}

#[test]
fn materialized_active_fault_tags_hash_tag_and_replacement_fault() {
    let shared = tag("shared");
    let first = materialized_state_with_active_tag(&shared, slowdown_fault("db-0", 20_000));
    let same = materialized_state_with_active_tag(&shared, slowdown_fault("db-0", 20_000));
    let changed_fault = materialized_state_with_active_tag(&shared, slowdown_fault("db-0", 12_500));
    let changed_tag =
        materialized_state_with_active_tag(&tag("other"), slowdown_fault("db-0", 20_000));

    assert_eq!(first.id, same.id);
    assert_ne!(first.id, changed_fault.id);
    assert_ne!(first.id, changed_tag.id);
}

#[test]
fn materialized_scheduler_state_captures_declarative_trigger_tags() {
    let tag = tag("declarative-slow");
    let fault = slowdown_fault("db-0", 18_000);
    let world = world();
    let mut scheduler = SingleScheduler::new(single_idle_node_scenario("declarative-tag-state"))
        .expect("scheduler should build");
    let graph = EventGraph::new_for_world(
        vec![Event::once(
            event_id("inject-slow"),
            Some(Predicate::At { at: time(0) }),
            Action::InjectFault {
                tag: tag.clone(),
                fault: MembershipFault::taxonomy(fault.clone()),
            },
        )],
        &world,
    )
    .expect("declarative graph should validate");
    let mut event_state = EventGraphState::new();

    scheduler
        .append_evaluation_boundary(time(0), SchedulerEvaluationBoundaryKind::Quantum)
        .expect("boundary should append");
    let firings = scheduler.evaluate_event_graph(&graph, &mut event_state, NoLeaves);
    scheduler
        .apply_trigger_firings(&firings)
        .expect("declarative inject should apply");
    let materialized = scheduler.materialized_scheduler_state();

    assert_eq!(
        materialized.active_fault_tags.get(&tag),
        Some(&MembershipFault::taxonomy(fault))
    );
}

#[test]
fn fat_checkpoint_materialization_populates_active_tags_from_schedule() {
    let scenario =
        ScenarioDef::from_canonical_material("crucible.test.fault-tag-state", "node=db-0");
    let genesis = Configuration::genesis(scenario.clone());
    let genesis_checkpoint = Checkpoint::from_recorded_configuration(
        &genesis,
        None,
        VirtualTime::default(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .expect("genesis checkpoint should be constructible");
    let mut graph = TemporalGraph::empty()
        .with_baked_genesis(
            &scenario,
            GenesisCheckpoint {
                checkpoint: genesis_checkpoint,
            },
        )
        .expect("baked genesis should validate");
    let tag = tag("checkpoint-active");
    let fault = slowdown_fault("db-0", 18_000);
    let config = step(
        &genesis,
        Decision::ControlFault(ControlFaultDecision {
            at: time(5),
            sequence: 1,
            action: ControlFaultAction::Inject {
                tag: tag.clone(),
                fault: fault.clone(),
            },
        }),
    );
    let direct_checkpoint = Checkpoint::from_recorded_configuration(
        &config,
        Some(&genesis),
        VirtualTime::default(),
        BTreeMap::new(),
        CheckpointKind::Fat,
        BTreeMap::new(),
    )
    .expect("direct fat checkpoint should be constructible");
    assert_eq!(
        direct_checkpoint
            .state
            .as_ref()
            .expect("direct fat checkpoint should carry state")
            .scheduler
            .active_fault_tags
            .get(&tag),
        Some(&MembershipFault::taxonomy(fault.clone()))
    );

    let checkpoint = graph
        .materialize_checkpoint(&config)
        .expect("fat checkpoint should materialize from recorded schedule");
    let state = checkpoint
        .state
        .as_ref()
        .expect("fat checkpoint should carry materialized state");

    assert_eq!(
        state.scheduler.active_fault_tags.get(&tag),
        Some(&MembershipFault::taxonomy(fault))
    );
}

fn materialized_state_with_active_tag(tag: &FaultTag, fault: Fault) -> MaterializedState {
    let mut scheduler = crucible::SchedulerState::empty();
    scheduler
        .active_fault_tags
        .insert(tag.clone(), MembershipFault::taxonomy(fault));
    MaterializedState::from_components(
        BTreeMap::new(),
        BTreeMap::new(),
        scheduler,
        DecisionRngState::empty(),
        EventLogOffset::default(),
    )
}

fn control(sequence: u64, kind: ControlOperationKind) -> ControlOperation {
    ControlOperation { sequence, kind }
}

fn single_idle_node_scenario(name: &str) -> SchedulerLivenessScenario {
    SchedulerLivenessScenario::from_canonical_material(
        name,
        Shift { bits: 0 },
        8,
        SimInstant { nanos: 20 },
        vec![scenario_node("db-0")],
        Vec::new(),
    )
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

fn world() -> World {
    World::from_nodes_and_links(vec![ready_node("db-0")], Vec::new())
        .expect("single-node test world should build")
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

fn slowdown_fault(node_name: &str, basis_points: u32) -> Fault {
    Fault::Node(NodeFault::Slow {
        node: node(node_name),
        factor: FaultSlowdownFactorBasisPoints::from_basis_points(basis_points)
            .unwrap_or_else(|error| panic!("valid slowdown factor: {error}")),
    })
}

fn tag(name: &str) -> FaultTag {
    FaultTag::from_name(name)
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn time(ticks: u64) -> crucible::VirtualTime {
    crucible::VirtualTime { ticks }
}

fn event_id(name: &str) -> EventId {
    EventId::from_name(name)
}

struct NoLeaves;

impl ConditionLeafOracle for NoLeaves {
    fn leaf_is_true(&mut self, leaf: ConditionLeaf<'_>) -> bool {
        match leaf {
            ConditionLeaf::Named { .. } | ConditionLeaf::GuestMarker { .. } => {
                panic!("fault-tag-state tests use only At leaves")
            }
        }
    }
}
