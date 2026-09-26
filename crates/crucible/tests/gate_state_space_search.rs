//! Implements `gate:state-space-search` over temporal graph frontier expansion.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use crucible::{
    Checkpoint, CheckpointKind, Configuration, ContentHash, Decision, DeliveryOrderDecision,
    EngineError, EventKey, FrontierReductionPolicy, GenesisCheckpoint, Icount,
    MaterializationPolicy, MaterializationTrigger, MaterializedState, NodeId, NodeTemplate,
    PendingFrame, ReadyPoint, RngDecision, RngStreamId, Schedule, SchedulerNodeId, SchedulerState,
    SchedulingNodeKind, SearchFrontierChoices, SelectionDecision, TemporalGraph, VirtualTime,
    WhiteBoxPolicy, World, WorldNode, bake, instantiate, try_step,
};
use crucible_campaign::{
    BooleanDomain, CampaignHash, ChoiceClassContext, ChoiceCoordinate, ChoiceDomain,
    ChoiceOpportunity, ChoiceSource, ChoiceValue, ConfigurationId, ScenarioDefId,
    SelectableDeclaration, Selection,
};

#[test]
fn gate_state_space_search_expands_genuine_decisions_and_dedups_by_content_address()
-> Result<(), Box<dyn Error>> {
    let world = single_node_world("frontier-dedup")?;
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let mut decisions = captured_frontier_decisions("frontier");
    decisions.push(decisions[2].clone());
    let baked = bake_with_search_frontier_choices(&world, decisions.clone())?;
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, baked)?;

    let search = graph.search(
        &genesis,
        FrontierReductionPolicy::none(),
        MaterializationPolicy::thin_only(),
        MaterializationTrigger::Cold,
    )?;
    let genuine_sequences = typed_frontier_sequences(&genesis, decisions.clone());
    let genuine_frontier = SearchFrontierChoices::from_decision_sequences(genuine_sequences);
    let genuine_decisions = genuine_frontier.decisions().to_vec();

    assert_eq!(decisions.len(), 6);
    assert_eq!(genuine_decisions.len(), 4);
    assert_eq!(search.frontier, genesis.id());
    assert_eq!(search.frontier_runtime.configuration, genesis.id());
    assert_eq!(
        search.frontier_runtime.runtime,
        instantiate(&graph, &genesis)?
    );
    assert_eq!(search.frontier_report.explored.len(), 3);
    assert!(search.frontier_report.covered.is_empty());
    assert!(
        search
            .frontier_report
            .explored
            .iter()
            .all(|child| !child.already_recorded)
    );
    assert!(
        search
            .frontier_report
            .explored
            .iter()
            .all(|child| matches!(child.decision, Decision::Selection(_)))
    );
    let explored_ids = search
        .frontier_report
        .explored
        .iter()
        .map(|child| child.configuration.id())
        .collect::<Vec<_>>();
    let mut sorted_ids = explored_ids.clone();
    sorted_ids.sort();
    let expected_ids = genuine_frontier
        .choices()
        .iter()
        .map(|choice| choice.decisions().iter().cloned())
        .map(|mut sequence| {
            sequence
                .try_fold(genesis.clone(), |configuration, decision| {
                    try_step(&configuration, decision)
                })
                .map(|child| child.id())
        })
        .collect::<Result<BTreeSet<_>, EngineError>>()?;

    assert_eq!(explored_ids, sorted_ids);
    assert_eq!(
        explored_ids.iter().copied().collect::<BTreeSet<_>>(),
        expected_ids
    );
    assert_eq!(
        search.materialized.len(),
        search.frontier_report.explored.len()
    );
    assert!(
        search
            .materialized
            .iter()
            .all(|checkpoint| checkpoint.kind == CheckpointKind::Thin)
    );

    for child in &search.frontier_report.explored {
        let chain = graph.checkpoint_parent_chain(child.configuration.id())?;
        assert_eq!(chain.len(), 3);
        assert_eq!(chain[0].id, genesis.id());
        assert_eq!(chain[1].parent, Some(genesis.id()));
        assert_eq!(chain[2].id, child.configuration.id());
        assert_eq!(chain[2].parent, Some(chain[1].id));
        assert_eq!(chain[2].kind, CheckpointKind::Thin);
    }

    let replayed = graph.search(
        &genesis,
        FrontierReductionPolicy::none(),
        MaterializationPolicy::thin_only(),
        MaterializationTrigger::Cold,
    )?;
    assert_eq!(replayed.frontier_report.explored.len(), 3);
    assert!(
        replayed
            .frontier_report
            .explored
            .iter()
            .all(|child| child.already_recorded)
    );

    Ok(())
}

#[test]
fn gate_state_space_search_derives_choices_from_materialized_scheduler_state()
-> Result<(), Box<dyn Error>> {
    let world = search_world("scheduler-derived", &["search-node", "peer-a", "peer-b"])?;
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let scheduler = scheduler_state_with_captured_frontier_choices(&genesis, "derived");
    let baked = bake_with_scheduler_state(&world, scheduler)?;
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, baked)?;

    let search = graph.search(
        &genesis,
        FrontierReductionPolicy::none(),
        MaterializationPolicy::thin_only(),
        MaterializationTrigger::Cold,
    )?;

    assert_eq!(search.frontier_report.explored.len(), 2);
    assert_eq!(
        search
            .frontier_report
            .explored
            .iter()
            .filter(|child| matches!(child.decision, Decision::Selection(_)))
            .count(),
        2
    );

    Ok(())
}

#[test]
fn gate_state_space_search_materializes_captured_frontier_under_budget()
-> Result<(), Box<dyn Error>> {
    let world = single_node_world("frontier-budget")?;
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let baked = bake_with_search_frontier_choices(
        &world,
        vec![
            rng_decision("frontier-budget/a", 0),
            rng_decision("frontier-budget/b", 2),
            rng_decision("frontier-budget/c", 7),
        ],
    )?;
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, baked)?;

    let search = graph.search(
        &genesis,
        FrontierReductionPolicy::none(),
        MaterializationPolicy::with_budget(2),
        MaterializationTrigger::SharedReplayPath,
    )?;

    assert_eq!(search.frontier, genesis.id());
    assert_eq!(search.frontier_runtime.configuration, genesis.id());
    assert_eq!(
        search.frontier_runtime.runtime,
        instantiate(&graph, &genesis)?
    );
    assert_eq!(search.frontier_report.explored.len(), 3);
    assert_eq!(search.materialized.len(), 3);
    assert_eq!(
        search
            .materialized
            .iter()
            .filter(|checkpoint| checkpoint.kind == CheckpointKind::Fat)
            .count(),
        2
    );
    assert_eq!(
        search
            .materialized
            .iter()
            .filter(|checkpoint| checkpoint.kind == CheckpointKind::Thin)
            .count(),
        1
    );

    Ok(())
}

#[test]
fn gate_state_space_search_realizes_frontier_from_cached_ancestor_without_stale_choices()
-> Result<(), Box<dyn Error>> {
    let world = single_node_world("frontier-realization")?;
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let baked = bake_with_search_frontier_choices(&world, vec![rng_decision("stale-ancestor", 1)])?;
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, baked)?;
    let base = try_step(&genesis, rng_decision("cached-ancestor/base", 1))?;
    let frontier = try_step(&base, rng_decision("cached-ancestor/frontier", 1))?;
    let base_snapshot = graph.materialize_checkpoint(&base)?;
    let expected_frontier_runtime = instantiate(&graph, &frontier)?;

    assert_eq!(base_snapshot.kind, CheckpointKind::Fat);
    assert!(graph.cached_snapshot(&base).is_some());
    assert!(graph.cached_snapshot(&frontier).is_none());

    let search = graph.search(
        &frontier,
        FrontierReductionPolicy::none(),
        MaterializationPolicy::with_budget(2),
        MaterializationTrigger::SharedReplayPath,
    )?;

    assert_eq!(search.frontier, frontier.id());
    assert_eq!(search.frontier_runtime.configuration, frontier.id());
    assert_eq!(search.frontier_runtime.runtime, expected_frontier_runtime);
    assert!(graph.cached_snapshot(&base).is_some());
    assert!(graph.cached_snapshot(&frontier).is_none());
    assert!(search.frontier_report.explored.is_empty());
    assert!(search.materialized.is_empty());

    Ok(())
}

fn bake_with_search_frontier_choices(
    world: &World,
    decisions: Vec<Decision>,
) -> Result<GenesisCheckpoint, EngineError> {
    let mut baked = bake(world)?;
    let parent = Configuration::genesis(world.scenario_def());
    baked.checkpoint =
        checkpoint_with_search_frontier_choices(baked.checkpoint, &parent, decisions);
    Ok(baked)
}

fn bake_with_scheduler_state(
    world: &World,
    scheduler: SchedulerState,
) -> Result<GenesisCheckpoint, EngineError> {
    let mut baked = bake(world)?;
    baked.checkpoint = checkpoint_with_scheduler_state(baked.checkpoint, scheduler);
    Ok(baked)
}

fn checkpoint_with_search_frontier_choices(
    mut checkpoint: Checkpoint,
    parent: &Configuration,
    decisions: Vec<Decision>,
) -> Checkpoint {
    let state = checkpoint
        .state
        .as_ref()
        .expect("test checkpoint must be materialized");
    let mut scheduler = state.scheduler.clone();
    scheduler.search_frontier =
        SearchFrontierChoices::from_decision_sequences(typed_frontier_sequences(parent, decisions));
    checkpoint.state = Some(MaterializedState::from_components_with_event_log_segments(
        state.vm_snapshots.clone(),
        state.device_overlays.clone(),
        scheduler,
        state.decision_rng.clone(),
        state.event_log,
        state.event_log_segments.clone(),
    ));
    checkpoint
}

fn checkpoint_with_scheduler_state(
    mut checkpoint: Checkpoint,
    scheduler: SchedulerState,
) -> Checkpoint {
    let state = checkpoint
        .state
        .as_ref()
        .expect("test checkpoint must be materialized");
    checkpoint.state = Some(MaterializedState::from_components_with_event_log_segments(
        state.vm_snapshots.clone(),
        state.device_overlays.clone(),
        scheduler,
        state.decision_rng.clone(),
        state.event_log,
        state.event_log_segments.clone(),
    ));
    checkpoint
}

fn single_node_world(label: &str) -> Result<World, EngineError> {
    search_world(label, &["search-node"])
}

fn search_world(label: &str, nodes: &[&str]) -> Result<World, EngineError> {
    World::from_nodes(
        nodes
            .iter()
            .map(|node| search_world_node(label, node))
            .collect(),
    )
}

fn search_world_node(label: &str, node: &str) -> WorldNode {
    WorldNode {
        id: node_id(node),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: format!("crucible-state-space-search={label}:{node}"),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 100 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        kernel: None,
        root_image: None,
        initrd: None,
    }
}

fn scheduler_state_with_captured_frontier_choices(
    parent: &Configuration,
    label: &str,
) -> SchedulerState {
    let mut scheduler = SchedulerState::empty();
    scheduler.pending_frames = BTreeMap::from([(
        node_id("search-node"),
        vec![
            pending_frame("peer-a", 0, 21, label),
            pending_frame("peer-b", 1, 21, label),
        ],
    )]);
    scheduler.search_frontier =
        SearchFrontierChoices::from_decision_sequences(typed_frontier_sequences(
            parent,
            vec![
                rng_decision(format!("{label}/captured-signal-choice"), 0),
                rng_decision(format!("{label}/captured-signal-choice"), 1),
            ],
        ));
    scheduler
}

fn pending_frame(source: &str, sequence: u64, delivery_icount: u64, label: &str) -> PendingFrame {
    PendingFrame {
        source: node_id(source),
        sequence,
        delivery_icount: Icount {
            retired: delivery_icount,
        },
        payload: ContentHash::from_canonical_material(
            "crucible.test.state-space-search.pending-frame",
            &format!("{label}/{source}/{sequence}"),
        ),
    }
}

fn captured_frontier_decisions(label: &str) -> Vec<Decision> {
    let mut decisions = genuine_frontier_decisions(label);
    decisions.push(non_genuine_delivery_decision(label, 13, 0));
    decisions.push(non_genuine_delivery_decision(label, 14, 1));
    decisions
}

fn genuine_frontier_decisions(label: &str) -> Vec<Decision> {
    vec![
        rng_decision(format!("{label}/packet-loss"), 1),
        rng_decision(format!("{label}/decision-rng"), 0xa5a5_5a5a),
        rng_decision(format!("{label}/scheduler-choice"), 7),
    ]
}

fn typed_frontier_sequences(
    parent: &Configuration,
    decisions: Vec<Decision>,
) -> Vec<Vec<Decision>> {
    decisions
        .into_iter()
        .map(|decision| match decision {
            Decision::RngDraw(_) | Decision::Preemption(_) => {
                let identity = Schedule::from_decisions([decision.clone()]).content_hash();
                let domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("valid domain"));
                let declaration = SelectableDeclaration::new(
                    "state-space-search-test-choice",
                    ChoiceSource::Scheduler {
                        producer: String::from("crucible.test.state-space-search.v1"),
                    },
                    domain.clone(),
                    ChoiceValue::Boolean(false),
                    ChoiceClassContext::new(BTreeSet::new()).expect("valid class context"),
                    BTreeSet::new(),
                    false,
                )
                .expect("valid selectable");
                let opportunity = ChoiceOpportunity::new(
                    ScenarioDefId::from_hash(CampaignHash::from_bytes(parent.def.id().bytes)),
                    &declaration,
                    &domain,
                    ChoiceCoordinate {
                        scheduler: CampaignHash::from_bytes(parent.id().bytes),
                        producer: CampaignHash::from_bytes(identity.bytes),
                    },
                    format!("choice-{}", identity.to_hex()),
                    None,
                )
                .expect("valid opportunity");
                let selection = Selection::new_campaign_branch(
                    &opportunity,
                    &domain,
                    ChoiceValue::Boolean(true),
                    opportunity.branch_point_id(ConfigurationId::from_hash(
                        CampaignHash::from_bytes(parent.id().bytes),
                    )),
                )
                .expect("valid branch selection");

                vec![
                    Decision::Selection(SelectionDecision::new(&selection)),
                    decision,
                ]
            }
            _ => vec![decision],
        })
        .collect()
}

fn non_genuine_delivery_decision(label: &str, ticks: u64, sequence: u64) -> Decision {
    Decision::DeliveryOrder(DeliveryOrderDecision {
        at: time(ticks),
        order: vec![event_key(label, ticks, sequence)],
    })
}

fn rng_decision(stream: impl Into<String>, value: u64) -> Decision {
    Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name(stream),
        value,
    })
}

fn event_key(label: &str, virtual_time: u64, sequence: u64) -> EventKey {
    EventKey::new(
        time(virtual_time),
        scheduler_node(format!("{label}/consumer")),
        scheduler_node(format!("{label}/producer")),
        sequence,
    )
}

fn scheduler_node(name: impl Into<String>) -> SchedulerNodeId {
    SchedulerNodeId {
        node: node_id(name),
        kind: SchedulingNodeKind::Vm,
    }
}

fn node_id(name: impl Into<String>) -> NodeId {
    NodeId { name: name.into() }
}

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}
