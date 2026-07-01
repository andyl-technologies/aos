//! Implements `gate:search-strategies` over deterministic frontier ordering.

#![forbid(unsafe_code)]

use std::collections::BTreeSet;
use std::error::Error;

use crucible::{
    ChoiceTag, Configuration, ContentHash, Decision, EngineError, FaultDecision, FaultId,
    GenesisCheckpoint, Icount, MaterializationPolicy, MaterializationTrigger, NodeId, NodeTemplate,
    OverrideDecision, ReadyPoint, RngDecision, RngStreamId, SchedulingPoint, SearchBudget,
    SearchDiscoveredFailure, SearchFailureOracle, SearchFrontierChoices, SearchStrategy,
    TemporalGraph, TemporalGraphSearchRun, VirtualTime, WhiteBoxPolicy, World, WorldNode, bake,
    try_step,
};

#[test]
fn gate_search_strategies_are_reproducible_for_identical_inputs() -> Result<(), Box<dyn Error>> {
    for strategy in search_strategies() {
        let first = run_strategy(strategy, SearchBudget::new(4))?.run;
        let second = run_strategy(strategy, SearchBudget::new(4))?.run;

        assert_eq!(expansion_order(&first), expansion_order(&second));
        assert_eq!(first.explored_graph, second.explored_graph);
        assert_eq!(first.discovered_failures, second.discovered_failures);
        assert_eq!(first.strategy, strategy);
        assert_eq!(first.budget, SearchBudget::new(4));
    }

    Ok(())
}

#[test]
fn gate_search_strategies_reach_same_graph_under_complete_budget() -> Result<(), Box<dyn Error>> {
    let runs = search_strategies()
        .into_iter()
        .map(|strategy| run_strategy(strategy, SearchBudget::new(4)))
        .collect::<Result<Vec<_>, EngineError>>()?;
    let expected_graph = runs[0].run.explored_graph.clone();

    for fixture in &runs {
        assert_eq!(fixture.run.explored_graph, expected_graph);
        assert_eq!(
            fixture.run.explored_graph,
            expected_reached_graph(&fixture.root, &fixture.children)
        );
        assert!(fixture.run.discovered_failures.is_empty());
        assert_eq!(fixture.run.expansions.len(), 4);
        assert_eq!(fixture.run.expansions[0].frontier, fixture.run.root);
        assert!(fixture.run.exhausted);
    }

    Ok(())
}

#[test]
fn gate_breadth_first_breaks_equal_depth_ties_by_content_address() -> Result<(), Box<dyn Error>> {
    let fixture = run_strategy(SearchStrategy::BreadthFirst, SearchBudget::new(4))?;
    let mut sorted_children = fixture
        .children
        .iter()
        .map(Configuration::id)
        .collect::<Vec<_>>();
    sorted_children.sort();

    assert_eq!(
        expansion_order(&fixture.run)
            .into_iter()
            .skip(1)
            .collect::<Vec<_>>(),
        sorted_children
    );

    Ok(())
}

#[test]
fn gate_priority_and_coverage_guided_break_equal_score_ties_by_content_address()
-> Result<(), Box<dyn Error>> {
    let priority = run_strategy(
        SearchStrategy::Priority {
            seed: crucible::Seed::from_u64(0x5eed),
        },
        SearchBudget::new(4),
    )?;
    assert_eq!(
        expansion_order(&priority.run)
            .into_iter()
            .skip(1)
            .collect::<Vec<_>>(),
        sorted_child_ids(&priority.children)
    );

    let coverage = run_strategy_with_coverage_mode(
        SearchStrategy::CoverageGuided,
        SearchBudget::new(4),
        CoverageFixtureMode::EqualKnown,
        &SearchFailureOracle::none(),
    )?;
    assert_eq!(
        expansion_order(&coverage.run)
            .into_iter()
            .skip(1)
            .collect::<Vec<_>>(),
        sorted_child_ids(&coverage.children)
    );

    Ok(())
}

#[test]
fn gate_coverage_guided_prefers_recorded_coverage_feedback() -> Result<(), Box<dyn Error>> {
    let fixture = run_strategy(SearchStrategy::CoverageGuided, SearchBudget::new(2))?;
    let selected = fixture.run.expansions[1].frontier;

    assert!(fixture.covered_children.contains(&selected));
    assert_eq!(
        fixture.run.explored_graph,
        expected_reached_graph(&fixture.root, &fixture.children)
    );

    Ok(())
}

#[test]
fn gate_search_strategies_report_discovered_failures_deterministically()
-> Result<(), Box<dyn Error>> {
    let reference = strategy_fixture()?;
    let failed_configuration = reference.children[1].id();
    let fingerprint = ContentHash::from_canonical_material(
        "crucible.test.search-strategy.failure.v1",
        "assertion=packet-loss-observed",
    );
    let failure_oracle =
        SearchFailureOracle::none().with_failure(failed_configuration, fingerprint);
    let expected = vec![SearchDiscoveredFailure {
        configuration: failed_configuration,
        fingerprint,
    }];

    for strategy in search_strategies() {
        let first = run_strategy_with_coverage_mode(
            strategy,
            SearchBudget::new(4),
            CoverageFixtureMode::Mixed,
            &failure_oracle,
        )?
        .run;
        let second = run_strategy_with_coverage_mode(
            strategy,
            SearchBudget::new(4),
            CoverageFixtureMode::Mixed,
            &failure_oracle,
        )?
        .run;

        assert_eq!(first.discovered_failures, expected);
        assert_eq!(first.discovered_failures, second.discovered_failures);
    }

    Ok(())
}

fn run_strategy(
    strategy: SearchStrategy,
    budget: SearchBudget,
) -> Result<StrategyRunFixture, EngineError> {
    run_strategy_with_coverage_mode(
        strategy,
        budget,
        CoverageFixtureMode::Mixed,
        &SearchFailureOracle::none(),
    )
}

fn run_strategy_with_coverage_mode(
    strategy: SearchStrategy,
    budget: SearchBudget,
    coverage_mode: CoverageFixtureMode,
    failure_oracle: &SearchFailureOracle,
) -> Result<StrategyRunFixture, EngineError> {
    let mut fixture = strategy_fixture_with_coverage_mode(coverage_mode)?;
    let run = fixture.graph.search_with_strategy_and_failure_oracle(
        &fixture.root,
        strategy,
        budget,
        MaterializationPolicy::thin_only(),
        MaterializationTrigger::Cold,
        failure_oracle,
    )?;
    Ok(StrategyRunFixture {
        run,
        root: fixture.root,
        children: fixture.children,
        covered_children: fixture.covered_children,
    })
}

fn sorted_child_ids(children: &[Configuration]) -> Vec<ContentHash> {
    let mut sorted = children.iter().map(Configuration::id).collect::<Vec<_>>();
    sorted.sort();
    sorted
}

fn search_strategies() -> Vec<SearchStrategy> {
    vec![
        SearchStrategy::BreadthFirst,
        SearchStrategy::DepthFirst,
        SearchStrategy::Priority {
            seed: crucible::Seed::from_u64(0x5eed),
        },
        SearchStrategy::CoverageGuided,
    ]
}

fn expansion_order(run: &TemporalGraphSearchRun) -> Vec<ContentHash> {
    run.expansions
        .iter()
        .map(|expansion| expansion.frontier)
        .collect()
}

fn expected_reached_graph(
    root: &Configuration,
    children: &[Configuration],
) -> BTreeSet<ContentHash> {
    let mut graph = BTreeSet::from([root.id()]);
    graph.extend(children.iter().map(Configuration::id));
    graph
}

struct StrategyRunFixture {
    run: TemporalGraphSearchRun,
    root: Configuration,
    children: Vec<Configuration>,
    covered_children: BTreeSet<ContentHash>,
}

struct StrategyFixture {
    graph: TemporalGraph,
    root: Configuration,
    children: Vec<Configuration>,
    covered_children: BTreeSet<ContentHash>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CoverageFixtureMode {
    Mixed,
    EqualKnown,
}

fn strategy_fixture() -> Result<StrategyFixture, EngineError> {
    strategy_fixture_with_coverage_mode(CoverageFixtureMode::Mixed)
}

fn strategy_fixture_with_coverage_mode(
    coverage_mode: CoverageFixtureMode,
) -> Result<StrategyFixture, EngineError> {
    let world = single_node_world("search-strategy")?;
    let scenario = world.scenario_def();
    let root = Configuration::genesis(scenario.clone());
    let root_decisions = strategy_root_decisions();
    let baked = bake_with_search_frontier_choices(&world, root_decisions.clone())?;
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario, baked)?;
    let mut children = Vec::new();
    let mut covered_children = BTreeSet::new();

    for (index, decision) in root_decisions.into_iter().enumerate() {
        let child = try_step(&root, decision)?;
        let mut checkpoint = graph.materialize_checkpoint(&child)?;
        let coverage = match coverage_mode {
            CoverageFixtureMode::Mixed if index == 2 => None,
            CoverageFixtureMode::Mixed => Some(ContentHash::from_canonical_material(
                "crucible.test.search-strategy.coverage.v1",
                &format!("child={index}"),
            )),
            CoverageFixtureMode::EqualKnown => Some(ContentHash::from_canonical_material(
                "crucible.test.search-strategy.coverage.v1",
                "equal-known-coverage",
            )),
        };
        if let Some(coverage) = coverage {
            checkpoint = checkpoint.with_coverage_fingerprint(coverage);
            covered_children.insert(child.id());
        }
        graph.cache_snapshot(&child, checkpoint)?;
        children.push(child);
    }

    Ok(StrategyFixture {
        graph,
        root,
        children,
        covered_children,
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

fn single_node_world(label: &str) -> Result<World, EngineError> {
    World::from_nodes(vec![WorldNode {
        id: node_id("search-node"),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: format!("crucible-search-strategy={label}"),
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

fn strategy_root_decisions() -> Vec<Decision> {
    vec![
        fault_decision("search-strategy/packet-loss", true),
        rng_decision("search-strategy/decision-rng", 0xa5a5_5a5a),
        override_decision("search-strategy/scheduler-point", "non-default-choice"),
    ]
}

fn fault_decision(fault: impl Into<String>, fired: bool) -> Decision {
    Decision::FaultFires(FaultDecision {
        at: time(12),
        fault: FaultId { name: fault.into() },
        fired,
    })
}

fn rng_decision(stream: impl Into<String>, value: u64) -> Decision {
    Decision::RngDraw(RngDecision {
        stream: RngStreamId::from_name(stream),
        value,
    })
}

fn override_decision(point: impl Into<String>, choice: impl Into<String>) -> Decision {
    Decision::Override(OverrideDecision {
        point: SchedulingPoint { key: point.into() },
        choice: ChoiceTag {
            name: choice.into(),
        },
    })
}

fn node_id(name: impl Into<String>) -> NodeId {
    NodeId { name: name.into() }
}

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}
