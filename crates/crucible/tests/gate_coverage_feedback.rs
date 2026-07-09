//! Implements `gate:coverage-feedback` across event-log coverage and search.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::BTreeMap;
use std::error::Error;

use crucible::{
    Configuration, ContentHash, Decision, EngineError, EventLogCoverageFeedback,
    EventLogCoverageFeedbackConsumer, GenesisCheckpoint, Icount, MarkerId, MaterializationPolicy,
    MaterializationTrigger, NodeId, NodeTemplate, ObservableEvent, ReadyPoint, RngDecision,
    RngStreamId, SchedulerEvaluationBoundaryKind, SchedulerEventLogEntry, SchedulerEventLogPayload,
    SearchBudget, SearchFrontierChoices, SearchStrategy, TemporalGraph, VirtualTime,
    WhiteBoxPolicy, World, WorldNode, bake, compare_event_log_determinism,
    coverage_fingerprint_from_event_log, event_log_coverage_projection, reduce, try_step,
};

#[test]
fn gate_coverage_feedback_flows_from_event_log_projection_to_search() -> Result<(), Box<dyn Error>>
{
    let mut fixture = coverage_feedback_fixture()?;
    let expected = fixture
        .children
        .iter()
        .min_by_key(|child| fixture.coverage_fingerprints[&child.id()])
        .expect("fixture should contain children")
        .clone();

    let run = fixture.graph.search_with_strategy(
        &fixture.root,
        SearchStrategy::CoverageGuided,
        SearchBudget::new(2),
        MaterializationPolicy::thin_only(),
        MaterializationTrigger::Cold,
    )?;

    assert_eq!(run.expansions[0].frontier, fixture.root.id());
    assert_eq!(run.expansions[1].frontier, expected.id());
    assert_eq!(
        fixture
            .graph
            .checkpoint_node(expected.id())
            .map(|checkpoint| checkpoint.coverage_fingerprint),
        Some(fixture.coverage_fingerprints[&expected.id()])
    );
    assert_eq!(
        fixture
            .graph
            .checkpoint_node(expected.id())
            .map(|checkpoint| checkpoint.id),
        Some(expected.id())
    );

    Ok(())
}

#[test]
fn gate_coverage_feedback_never_affects_reduce() -> Result<(), Box<dyn Error>> {
    let world = feedback_world("read-only-reduce")?;
    let scenario = world.scenario_def();
    let root = Configuration::genesis(scenario.clone());
    let child = try_step(&root, feedback_decision(0))?;
    let first_log = coverage_log("guest-a", 0x7000, "first");
    let second_log = coverage_log("guest-a", 0x7100, "second");
    let first_projection = event_log_coverage_projection(&first_log);
    let second_projection = event_log_coverage_projection(&second_log);
    let feedback = EventLogCoverageFeedback::from_event_log(&first_log);
    let reduced_before = reduce(&child.def, &child.schedule)?;
    let checkpoint = TemporalGraph::empty()
        .with_baked_genesis(&scenario, bake(&world)?)?
        .materialize_checkpoint(&child)?;
    let first_checkpoint = checkpoint.clone().with_coverage_from_event_log(&first_log);
    let second_checkpoint = checkpoint.with_coverage_from_event_log(&second_log);
    let reduced_after = reduce(&child.def, &child.schedule)?;

    assert_ne!(first_projection.content_hash(), ContentHash::default());
    assert_ne!(second_projection.content_hash(), ContentHash::default());
    assert_ne!(
        first_projection.content_hash(),
        second_projection.content_hash()
    );
    assert_eq!(feedback.projection(), &first_projection);
    assert_eq!(
        feedback.fingerprint_for(EventLogCoverageFeedbackConsumer::Search),
        first_projection.content_hash()
    );
    assert_eq!(
        feedback.fingerprint_for(EventLogCoverageFeedbackConsumer::CoverageGuidedFuzzing),
        first_projection.content_hash()
    );
    assert_eq!(
        first_checkpoint.coverage_fingerprint,
        coverage_fingerprint_from_event_log(&first_log)
    );
    assert_eq!(
        second_checkpoint.coverage_fingerprint,
        coverage_fingerprint_from_event_log(&second_log)
    );
    assert_eq!(first_checkpoint.id, child.id());
    assert_eq!(second_checkpoint.id, child.id());
    assert_eq!(reduced_before.id, reduced_after.id);

    let baseline = vec![rng_entry(0, 1, 11), boundary_entry(1, 2)];
    let with_coverage = vec![
        rng_entry(0, 1, 11),
        observation_entry(
            1,
            &ObservableEvent::coverage_block(icount(2), node("guest-a"), 0x7000, 0x20),
        ),
        boundary_entry(2, 2),
    ];
    assert!(compare_event_log_determinism(&baseline, &with_coverage).passes());

    Ok(())
}

struct CoverageFeedbackFixture {
    graph: TemporalGraph,
    root: Configuration,
    children: Vec<Configuration>,
    coverage_fingerprints: BTreeMap<ContentHash, ContentHash>,
}

fn coverage_feedback_fixture() -> Result<CoverageFeedbackFixture, EngineError> {
    let world = feedback_world("search-feedback")?;
    let scenario = world.scenario_def();
    let root = Configuration::genesis(scenario.clone());
    let decisions = vec![
        feedback_decision(0),
        feedback_decision(1),
        feedback_decision(2),
    ];
    let baked = bake_with_search_frontier_choices(&world, decisions.clone())?;
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, baked)?;
    let mut children = Vec::new();
    let mut coverage_fingerprints = BTreeMap::new();

    for (index, decision) in decisions.into_iter().enumerate() {
        let child = try_step(&root, decision)?;
        let checkpoint = graph.materialize_checkpoint(&child)?;
        let event_log = coverage_log(
            "guest-a",
            0x4000 + ((index as u64) * 0x100),
            &format!("child-{index}"),
        );
        let fingerprint = coverage_fingerprint_from_event_log(&event_log);
        graph.cache_snapshot_with_event_log_coverage(&child, checkpoint, &event_log)?;
        coverage_fingerprints.insert(child.id(), fingerprint);
        children.push(child);
    }

    Ok(CoverageFeedbackFixture {
        graph,
        root,
        children,
        coverage_fingerprints,
    })
}

fn bake_with_search_frontier_choices(
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
    baked.checkpoint.state = Some(
        crucible::MaterializedState::from_components_with_event_log_segments(
            state.vm_snapshots.clone(),
            state.device_overlays.clone(),
            scheduler,
            state.decision_rng.clone(),
            state.event_log,
            state.event_log_segments.clone(),
        ),
    );
    Ok(baked)
}

fn coverage_log(node_name: &str, guest_pc: u64, marker_name: &str) -> Vec<SchedulerEventLogEntry> {
    let node = node(node_name);
    vec![
        observation_entry(
            0,
            &ObservableEvent::coverage_block(icount(10), node.clone(), guest_pc, 0x20),
        ),
        observation_entry(
            1,
            &ObservableEvent::coverage_marker(icount(11), node, marker(marker_name)),
        ),
    ]
}

fn observation_entry(sequence: u64, event: &ObservableEvent) -> SchedulerEventLogEntry {
    crucible::test_support::condition_observation_entry_for_test(sequence, event)
}

fn rng_entry(sequence: u64, ticks: u64, value: u64) -> SchedulerEventLogEntry {
    crucible::test_support::condition_payload_entry_for_test(
        sequence,
        time(ticks),
        SchedulerEventLogPayload::Decision(Decision::RngDraw(RngDecision {
            stream: RngStreamId::from_name("coverage-feedback"),
            value,
        })),
    )
}

fn boundary_entry(sequence: u64, ticks: u64) -> SchedulerEventLogEntry {
    crucible::test_support::condition_boundary_entry_for_test(
        sequence,
        time(ticks),
        SchedulerEvaluationBoundaryKind::Quantum,
    )
}

fn feedback_world(label: &str) -> Result<World, EngineError> {
    World::from_nodes(vec![WorldNode {
        id: node("guest-a"),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: format!("crucible-coverage-feedback={label}"),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 100 },
        },
        white_box: WhiteBoxPolicy::Disabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
}

fn feedback_decision(index: u64) -> Decision {
    Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name(format!("coverage-feedback-{index}")),
        value: index,
    })
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn marker(name: &str) -> MarkerId {
    MarkerId::from_name(name)
}

fn icount(retired: u64) -> Icount {
    Icount { retired }
}

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}
