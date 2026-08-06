//! Implements `gate:search-reductions` over graph-level search reductions.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::error::Error;

use crucible::{
    Checkpoint, CheckpointKind, Configuration, ContentHash, Decision, DecisionRngState,
    EffectOutcomeDecision, EngineError, EventLogOffset, FaultId, FrontierReductionPolicy,
    FrontierReductionReason, GenesisCheckpoint, Icount, IrqVector, MaterializationPolicy,
    MaterializationTrigger, MaterializedState, NodeBlobRef, NodeId, PartialOrderReductionPolicy,
    PreemptionDecision, PreemptionKind, Schedule, SchedulerState, SearchBudget,
    SearchFrontierChoices, SearchStrategy, SymmetryClassId, SymmetryReductionClasses,
    TemporalGraph, VcpuId, VirtualTime, VmSnapshotRef, World, bake, step,
};

#[test]
fn gate_search_reductions_partial_order_records_canonical_representative_on_demand()
-> Result<(), Box<dyn Error>> {
    let world = World::from_content_hash(ContentHash::from_canonical_material(
        "crucible.test.search-reductions.world",
        "partial-order-on-demand",
    ));
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, bake(&world)?)?;
    let left = preemption_decision("node-a", 21);
    let right = preemption_decision("node-b", 21);
    let (first, second) = if left.reduction_order_key() < right.reduction_order_key() {
        (right, left)
    } else {
        (left, right)
    };
    let noncanonical_frontier = step(&genesis, first.clone());
    let canonical_frontier = step(&genesis, second.clone());
    let covered = step(&noncanonical_frontier, second.clone());
    let representative = Configuration {
        def: scenario,
        schedule: Schedule::empty()
            .appended(second.clone())
            .appended(first.clone()),
    };
    let policy = FrontierReductionPolicy::none().with_partial_order(
        PartialOrderReductionPolicy::new().with_independent_pair(&first, &second),
    );

    graph.record_step(&genesis, first.clone())?;
    graph.record_step(&genesis, second.clone())?;
    assert!(!graph.contains_configuration(&representative));

    let noncanonical =
        graph.enumerate_frontier_reduced(&noncanonical_frontier, [second], policy.clone())?;

    assert!(noncanonical.explored.is_empty());
    assert_eq!(noncanonical.covered.len(), 1);
    assert_eq!(
        noncanonical.covered[0].reason,
        FrontierReductionReason::PartialOrder
    );
    assert_eq!(noncanonical.covered[0].configuration.id(), covered.id());
    assert_eq!(noncanonical.covered[0].representative, representative.id());
    assert!(graph.contains_configuration(&representative));
    assert!(!graph.contains_configuration(&covered));

    let canonical = graph.enumerate_frontier_reduced(&canonical_frontier, [first], policy)?;
    assert_eq!(canonical.explored.len(), 1);
    assert!(canonical.covered.is_empty());
    assert_eq!(
        canonical.explored[0].configuration.id(),
        representative.id()
    );
    assert!(canonical.explored[0].already_recorded);
    assert!(!graph.contains_configuration(&covered));

    Ok(())
}

#[test]
fn gate_search_reductions_symmetry_uses_graph_level_representative() -> Result<(), Box<dyn Error>> {
    let world = World::from_content_hash(ContentHash::from_canonical_material(
        "crucible.test.search-reductions.world",
        "symmetry-graph-level",
    ));
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, bake(&world)?)?;
    let replica_a = node_id("replica-a");
    let replica_b = node_id("replica-b");
    let symmetry_classes = SymmetryReductionClasses::new()
        .with_node_class(replica_a.clone(), symmetry_class("replicas"))
        .with_node_class(replica_b.clone(), symmetry_class("replicas"));
    let base = node_blob("symmetry/base");
    let dirty = node_blob("symmetry/dirty");
    let coverage = ContentHash::from_canonical_material(
        "crucible.test.search-reductions.coverage",
        "symmetry-class",
    );
    let representative_decision = preemption_decision("replica-a", 11);
    let covered_decision = preemption_decision("replica-b", 11);
    let representative = step(&genesis, representative_decision);
    let covered = step(&genesis, covered_decision.clone());
    let representative_checkpoint = fat_checkpoint_with_coverage(
        &representative,
        &genesis,
        coverage,
        BTreeMap::from([
            (replica_a.clone(), dirty.clone()),
            (replica_b.clone(), base.clone()),
        ]),
    )?;
    let covered_checkpoint = fat_checkpoint_with_coverage(
        &covered,
        &genesis,
        coverage,
        BTreeMap::from([(replica_a, base), (replica_b, dirty)]),
    )?;

    graph.cache_snapshot(&representative, representative_checkpoint)?;
    graph.cache_snapshot(&covered, covered_checkpoint)?;

    let report = graph.enumerate_frontier_reduced(
        &genesis,
        [covered_decision],
        FrontierReductionPolicy::none().with_symmetry_classes(symmetry_classes),
    )?;

    assert!(report.explored.is_empty());
    assert_eq!(report.covered.len(), 1);
    assert_eq!(report.covered[0].reason, FrontierReductionReason::Symmetry);
    assert_eq!(report.covered[0].configuration.id(), covered.id());
    assert_eq!(report.covered[0].representative, representative.id());

    Ok(())
}

#[test]
fn gate_search_reductions_reduced_strategy_schedules_covered_representative()
-> Result<(), Box<dyn Error>> {
    let covered_decision = fault_decision("symmetry-covered", true);
    let representative_decision = fault_decision("symmetry-representative", false);
    let world = World::from_content_hash(ContentHash::from_canonical_material(
        "crucible.test.search-reductions.world",
        "strategy-schedules-covered-representative",
    ));
    let scenario = world.scenario_def();
    let genesis = Configuration::genesis(scenario.clone());
    let baked = bake_with_search_frontier_decisions(&world, vec![covered_decision.clone()])?;
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, baked)?;
    let replica_a = node_id("strategy-replica-a");
    let replica_b = node_id("strategy-replica-b");
    let symmetry_classes = SymmetryReductionClasses::new()
        .with_node_class(replica_a.clone(), symmetry_class("strategy-replicas"))
        .with_node_class(replica_b.clone(), symmetry_class("strategy-replicas"));
    let base = node_blob("strategy/base");
    let dirty = node_blob("strategy/dirty");
    let coverage = ContentHash::from_canonical_material(
        "crucible.test.search-reductions.coverage",
        "strategy-symmetry-class",
    );
    let representative = step(&genesis, representative_decision);
    let covered = step(&genesis, covered_decision);
    let representative_checkpoint = fat_checkpoint_with_coverage(
        &representative,
        &genesis,
        coverage,
        BTreeMap::from([
            (replica_a.clone(), dirty.clone()),
            (replica_b.clone(), base.clone()),
        ]),
    )?;
    let covered_checkpoint = fat_checkpoint_with_coverage(
        &covered,
        &genesis,
        coverage,
        BTreeMap::from([(replica_a, base), (replica_b, dirty)]),
    )?;

    graph.cache_snapshot(&representative, representative_checkpoint)?;
    graph.cache_snapshot(&covered, covered_checkpoint)?;

    let run = graph.search_with_strategy_reduced(
        &genesis,
        SearchStrategy::BreadthFirst,
        SearchBudget::new(1),
        FrontierReductionPolicy::none().with_symmetry_classes(symmetry_classes),
        MaterializationPolicy::thin_only(),
        MaterializationTrigger::Cold,
    )?;

    assert_eq!(run.expansions.len(), 1);
    assert_eq!(run.expansions[0].frontier, genesis.id());
    assert!(run.expansions[0].search.frontier_report.explored.is_empty());
    assert_eq!(run.expansions[0].search.frontier_report.covered.len(), 1);
    assert_eq!(
        run.expansions[0].search.frontier_report.covered[0]
            .configuration
            .id(),
        covered.id()
    );
    assert_eq!(
        run.expansions[0].search.frontier_report.covered[0].representative,
        representative.id()
    );
    assert!(run.explored_graph.contains(&representative.id()));
    assert!(!run.explored_graph.contains(&covered.id()));
    assert!(!run.exhausted);

    Ok(())
}

fn node_id(name: &str) -> NodeId {
    NodeId {
        name: String::from(name),
    }
}

fn symmetry_class(name: &str) -> SymmetryClassId {
    SymmetryClassId {
        name: String::from(name),
    }
}

fn node_blob(material: &str) -> NodeBlobRef {
    NodeBlobRef::baked(ContentHash::from_canonical_material(
        "crucible.test.search-reductions.node-blob",
        material,
    ))
}

fn preemption_decision(node: &str, retired: u64) -> Decision {
    Decision::Preemption(PreemptionDecision {
        node: node_id(node),
        at: Icount { retired },
        kind: PreemptionKind::InterruptAt {
            target_vcpu: VcpuId { index: 0 },
            irq: IrqVector { vector: 32 },
        },
    })
}

fn fault_decision(name: &str, fired: bool) -> Decision {
    Decision::EffectOutcome(EffectOutcomeDecision {
        at: VirtualTime { ticks: 17 },
        fault: FaultId {
            name: String::from(name),
        },
        fired,
    })
}

fn bake_with_search_frontier_decisions(
    world: &World,
    decisions: Vec<Decision>,
) -> Result<GenesisCheckpoint, EngineError> {
    let mut baked = bake(world)?;
    let state = baked.checkpoint.state.as_ref().ok_or(
        EngineError::CheckpointMaterializedStateIncomplete {
            checkpoint: baked.checkpoint.id,
            reason: "missing-test-genesis-state",
        },
    )?;
    let mut scheduler = state.scheduler.clone();
    scheduler.search_frontier = SearchFrontierChoices::from_decisions(decisions);
    baked.checkpoint.state = Some(MaterializedState::from_components_with_event_log_segments(
        state.vm_snapshots.clone(),
        state.device_overlays.clone(),
        scheduler,
        state.decision_rng.clone(),
        state.event_log,
        state.event_log_segments.clone(),
    ));
    Ok(baked)
}

fn fat_checkpoint_with_coverage(
    configuration: &Configuration,
    parent: &Configuration,
    coverage: ContentHash,
    node_blobs: BTreeMap<NodeId, NodeBlobRef>,
) -> Result<Checkpoint, Box<dyn Error>> {
    let node_icounts = node_blobs
        .keys()
        .cloned()
        .map(|node| (node, Icount { retired: 99 }))
        .collect::<BTreeMap<_, _>>();
    let state = MaterializedState::from_components(
        materialized_snapshots_for_blobs(&node_blobs, &node_icounts),
        BTreeMap::new(),
        SchedulerState::empty(),
        DecisionRngState::empty(),
        EventLogOffset::default(),
    );
    Ok(Checkpoint::from_recorded_configuration(
        configuration,
        Some(parent),
        VirtualTime::default(),
        node_icounts,
        CheckpointKind::Fat,
        node_blobs,
    )?
    .with_materialized_state(Some(state))
    .with_coverage_fingerprint(coverage))
}

fn materialized_snapshots_for_blobs(
    node_blobs: &BTreeMap<NodeId, NodeBlobRef>,
    node_icounts: &BTreeMap<NodeId, Icount>,
) -> BTreeMap<NodeId, VmSnapshotRef> {
    node_blobs
        .iter()
        .map(|(node, blob)| {
            (
                node.clone(),
                VmSnapshotRef::new(
                    blob.clone(),
                    node_icounts.get(node).copied().unwrap_or_default(),
                ),
            )
        })
        .collect()
}
