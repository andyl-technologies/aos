//! Implements `gate:fleet-equivalence` for distributed continuous exploration.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::error::Error;

use crucible::{
    ChoiceTag, Configuration, ContentHash, Decision, EngineError, FleetEquivalenceReport,
    FleetWorkStealingConfig, GenesisCheckpoint, Icount, MaterializationPolicy,
    MaterializationTrigger, NodeId, NodeTemplate, OverrideDecision, Plan, Properties, ReadyPoint,
    RngDecision, RngStreamId, ScenarioDefForm, SchedulingPoint, SearchBudget, SearchFailureOracle,
    SearchFrontierChoices, SearchStrategy, Seed, TemporalGraph, WhiteBoxPolicy, World, WorldNode,
    bake, try_step,
};
use crucible_harness::adversarial::{canonical_host_adversary_matrix, run_profiled_tasks};

#[test]
fn gate_fleet_equivalence_matches_single_host_finding_set_and_artifacts()
-> Result<(), Box<dyn Error>> {
    let budget = SearchBudget::new(4);
    let reference = fleet_equivalence_fixture()?;
    let failed_a = reference.children[0].id();
    let failed_b = reference.children[2].id();
    let failure_oracle = SearchFailureOracle::none()
        .with_failure(
            failed_a,
            failure_fingerprint("packet-loss-finding", failed_a),
        )
        .with_failure(failed_b, failure_fingerprint("override-finding", failed_b));

    let mut single = fleet_equivalence_fixture()?;
    let single_run = single.graph.search_with_strategy_and_failure_oracle(
        &single.scenario,
        &single.root,
        SearchStrategy::BreadthFirst,
        budget,
        MaterializationPolicy::thin_only(),
        MaterializationTrigger::Cold,
        &failure_oracle,
    )?;

    let mut fleet = fleet_equivalence_fixture()?;
    let fleet_run = fleet.graph.search_with_work_stealing_fleet(
        &fleet.scenario,
        &fleet.root,
        FleetWorkStealingConfig::new(budget, 4, Seed::from_u64(0xdce8)),
        MaterializationPolicy::thin_only(),
        MaterializationTrigger::Cold,
        &failure_oracle,
    )?;

    let report = FleetEquivalenceReport::compare(&single_run, &fleet_run);
    assert!(report.passes(), "{report:?}");
    assert!(report.root_equal);
    assert!(report.budget_equal);
    assert!(report.explored_graph_equal);
    assert!(report.both_exhausted);
    assert_eq!(report.single_finding_set.len(), 2);
    assert_eq!(report.single_finding_set, report.fleet_finding_set);
    assert!(report.artifacts_byte_identical);
    assert_eq!(single_run.explored_graph, fleet_run.explored_graph);
    assert!(single_run.exhausted);
    assert!(fleet_run.exhausted);
    assert!(fleet_run.claims.iter().any(|claim| claim.host_index != 0));

    let mut reordered_fleet_run = fleet_run.clone();
    reordered_fleet_run.discovered_failures.reverse();
    let reordered_report = FleetEquivalenceReport::compare(&single_run, &reordered_fleet_run);
    assert!(reordered_report.passes(), "{reordered_report:?}");
    assert!(!reordered_report.discovery_order_equal);

    Ok(())
}

#[test]
fn gate_fleet_equivalence_drives_work_stealing_fleet_under_adversarial_host_profiles()
-> Result<(), Box<dyn Error>> {
    let profiles = canonical_host_adversary_matrix();
    assert!(
        profiles.len() > 1,
        "fleet equivalence must run under the shared adversarial host matrix"
    );

    let mut baseline = None;
    for profile in profiles {
        let witnesses = run_profiled_tasks(*profile, 4, |task| {
            let mut fixture = fleet_equivalence_fixture()
                .unwrap_or_else(|error| panic!("fleet fixture should build: {error}"));
            let config = FleetWorkStealingConfig::new(
                SearchBudget::new(4),
                4,
                Seed::from_u64(0xdce8_0000 + task.index as u64),
            );
            fixture
                .graph
                .search_with_work_stealing_fleet(
                    &fixture.scenario,
                    &fixture.root,
                    config,
                    MaterializationPolicy::thin_only(),
                    MaterializationTrigger::Cold,
                    &SearchFailureOracle::none(),
                )
                .unwrap_or_else(|error| panic!("fleet search should complete: {error}"))
        })?;

        if let Some(baseline) = &baseline {
            assert_eq!(
                baseline, &witnesses,
                "profile {} changed the work-stealing fleet witness",
                profile.name
            );
        } else {
            baseline = Some(witnesses);
        }
    }

    let baseline = baseline.ok_or("adversarial profile matrix must not be empty")?;
    assert_eq!(baseline.len(), 4);
    assert!(baseline.iter().all(|run| run.exhausted));
    assert!(
        baseline
            .iter()
            .all(|run| run.claims.iter().any(|claim| claim.host_index != 0))
    );

    Ok(())
}

#[test]
fn gate_fleet_equivalence_localizes_mismatched_finding_sets() -> Result<(), Box<dyn Error>> {
    let budget = SearchBudget::new(4);
    let reference = fleet_equivalence_fixture()?;
    let failed = reference.children[1].id();
    let failure_oracle = SearchFailureOracle::none()
        .with_failure(failed, failure_fingerprint("rng-finding", failed));

    let mut single = fleet_equivalence_fixture()?;
    let single_run = single.graph.search_with_strategy_and_failure_oracle(
        &single.scenario,
        &single.root,
        SearchStrategy::BreadthFirst,
        budget,
        MaterializationPolicy::thin_only(),
        MaterializationTrigger::Cold,
        &failure_oracle,
    )?;

    let mut fleet = fleet_equivalence_fixture()?;
    let mut fleet_run = fleet.graph.search_with_work_stealing_fleet(
        &fleet.scenario,
        &fleet.root,
        FleetWorkStealingConfig::new(budget, 3, Seed::from_u64(0xfeed_dce8)),
        MaterializationPolicy::thin_only(),
        MaterializationTrigger::Cold,
        &failure_oracle,
    )?;
    fleet_run.discovered_failures.clear();

    let report = FleetEquivalenceReport::compare(&single_run, &fleet_run);
    assert!(!report.passes());
    let divergence = report
        .divergence
        .as_ref()
        .ok_or("mismatch must carry bisection handoff")?;
    assert_eq!(divergence.reason, "missing-from-fleet");
    assert_eq!(divergence.configuration, Some(failed));
    assert_eq!(
        divergence.bisection.reason,
        "fleet-equivalence-missing-from-fleet"
    );
    assert_eq!(divergence.bisection.checkpoint, failed);

    Ok(())
}

#[test]
fn gate_fleet_equivalence_rejects_non_exhaustive_budget() -> Result<(), Box<dyn Error>> {
    let budget = SearchBudget::new(1);

    let mut single = fleet_equivalence_fixture()?;
    let single_run = single.graph.search_with_strategy_and_failure_oracle(
        &single.scenario,
        &single.root,
        SearchStrategy::BreadthFirst,
        budget,
        MaterializationPolicy::thin_only(),
        MaterializationTrigger::Cold,
        &SearchFailureOracle::none(),
    )?;

    let mut fleet = fleet_equivalence_fixture()?;
    let fleet_run = fleet.graph.search_with_work_stealing_fleet(
        &fleet.scenario,
        &fleet.root,
        FleetWorkStealingConfig::new(budget, 4, Seed::from_u64(0xdce8)),
        MaterializationPolicy::thin_only(),
        MaterializationTrigger::Cold,
        &SearchFailureOracle::none(),
    )?;

    let report = FleetEquivalenceReport::compare(&single_run, &fleet_run);
    assert!(!report.passes());
    assert!(!report.both_exhausted);
    let divergence = report
        .divergence
        .as_ref()
        .ok_or("non-exhaustive run must carry bisection handoff")?;
    assert_eq!(divergence.reason, "not-exhausted");
    assert_eq!(
        divergence.bisection.reason,
        "fleet-equivalence-not-exhausted"
    );

    Ok(())
}

fn fleet_equivalence_fixture() -> Result<FleetEquivalenceFixture, EngineError> {
    let world = single_node_world("fleet-equivalence")?;
    let scenario = ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::default(),
    )?;
    let scenario_def = scenario.scenario_def();
    let root = Configuration::genesis(scenario_def.clone());
    let root_decisions = fleet_root_decisions();
    let baked = bake_with_search_frontier_choices(&world, root_decisions.clone())?;
    let graph = TemporalGraph::empty().with_baked_genesis(&scenario_def, baked)?;
    let mut children = Vec::new();

    for decision in root_decisions {
        let child = try_step(&root, decision)?;
        children.push(child);
    }

    Ok(FleetEquivalenceFixture {
        graph,
        scenario,
        root,
        children,
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

fn failure_fingerprint(label: &str, configuration: ContentHash) -> ContentHash {
    ContentHash::from_canonical_material(
        "crucible.test.fleet-equivalence.failure.v1",
        &format!("label={label}\nconfiguration={}\n", configuration.to_hex()),
    )
}

fn single_node_world(label: &str) -> Result<World, EngineError> {
    World::from_nodes(vec![WorldNode {
        id: node_id("fleet-equivalence-node"),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: format!("crucible-{label}=true"),
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

fn fleet_root_decisions() -> Vec<Decision> {
    vec![
        rng_decision("fleet-equivalence/packet-loss", 1),
        rng_decision("fleet-equivalence/decision-rng", 0xdce8_0001),
        override_decision("fleet-equivalence/scheduler-point", "fleet-choice"),
    ]
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

struct FleetEquivalenceFixture {
    graph: TemporalGraph,
    scenario: ScenarioDefForm,
    root: Configuration,
    children: Vec<Configuration>,
}
