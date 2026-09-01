//! Implements `gate:search-strategies` over deterministic frontier ordering.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use crucible::{
    AssertionDef, AssertionId, ChoiceTag, CodePoint, Configuration, ContentHash, Decision,
    DeliveryOrderDecision, EngineError, EventLogOffset, FindingDiscoveryPath, FrontierChild,
    FrontierReductionReport, GenesisCheckpoint, GuestAssertionDetail, GuestAssertionKind,
    GuestAssertionMarker, Icount, MarkerId, MaterializationPolicy, MaterializationTrigger,
    MemPlace, MemoryCmp, MemoryWidth, NodeId, NodeTemplate, ObservableEvent, OverrideDecision,
    Plan, Predicate, Properties, Property, ReachabilityExpectation, ReachableDisposition,
    ReadyPoint, RecordedAssertionLog, ResolvedCodePoint, ResolvedMemPlace, RngDecision,
    RngStreamId, RuntimeState, ScenarioDefForm, Schedule, SchedulerEvaluationBoundaryKind,
    SchedulerQuiescence, SchedulerQuiescenceBlocker, SchedulerState, SchedulingPoint, SearchBudget,
    SearchExpansion, SearchFailureOracle, SearchFrontierChoices, SearchReplayOracleSamplingConfig,
    SearchRetainedLogAssertionEvidence, SearchRetainedLogPredicateResolutions,
    SearchScheduleNamedPredicateKey, SearchScheduleNamedPredicateTruths, SearchStrategy, Seed,
    TemporalGraph, TemporalGraphRuntime, TemporalGraphSearch, TemporalGraphSearchRun, VirtualTime,
    WhiteBoxPolicy, World, WorldNode, bake, try_step,
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
fn gate_search_strategies_depth_bound_stops_before_exhaustion() -> Result<(), Box<dyn Error>> {
    let mut fixture = strategy_fixture()?;
    let run = fixture
        .graph
        .search_with_strategy_and_failure_oracle_bounded_depth(
            &fixture.scenario,
            &fixture.root,
            SearchStrategy::BreadthFirst,
            SearchBudget::new(4),
            MaterializationPolicy::thin_only(),
            MaterializationTrigger::Cold,
            &SearchFailureOracle::none(),
            Some(1),
        )?;

    assert_eq!(run.expansions.len(), 1);
    assert_eq!(run.expansions[0].frontier, run.root);
    assert_eq!(run.expansions[0].depth, 0);
    assert_eq!(
        run.explored_graph,
        expected_reached_graph(&fixture.root, &fixture.children)
    );
    assert!(!run.exhausted);

    Ok(())
}

#[test]
fn gate_search_strategies_sample_replay_oracle_checks() -> Result<(), Box<dyn Error>> {
    let mut fixture = strategy_fixture()?;
    let config = SearchReplayOracleSamplingConfig::new(
        1,
        1,
        "gate-search-strategies-sampled-replay-oracle",
    )?;
    let sampled = fixture
        .graph
        .search_with_strategy_and_failure_oracle_bounded_depth_sampled(
            &fixture.scenario,
            &fixture.root,
            SearchStrategy::BreadthFirst,
            SearchBudget::new(1),
            MaterializationPolicy::with_budget(4),
            MaterializationTrigger::RepeatedForkSource,
            &SearchFailureOracle::none(),
            None,
            &config,
        )?;

    assert_eq!(sampled.run.expansions.len(), 1);
    assert_eq!(
        sampled.replay_oracle_sampling.considered,
        fixture.children.len()
    );
    assert_eq!(
        sampled.replay_oracle_sampling.sampled,
        fixture.children.len()
    );
    assert_eq!(sampled.replay_oracle_sampling.skipped, 0);
    assert_eq!(
        sampled.replay_oracle_sampling.sampled_checkpoints.len(),
        fixture.children.len()
    );

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

        assert_eq!(first.discovered_failures.len(), 1);
        let failure = first
            .discovered_failures
            .first()
            .ok_or("expected one discovered failure")?;
        assert_eq!(failure.configuration, failed_configuration);
        assert_eq!(failure.fingerprint, fingerprint);
        assert_eq!(
            failure.reproduction_artifact().discovery_path,
            FindingDiscoveryPath::StateSpaceSearch
        );
        assert_eq!(
            failure.reproduction_artifact().finding_fingerprint,
            fingerprint
        );
        assert_eq!(
            failure.reproduction_artifact().configuration,
            failed_configuration
        );
        assert_eq!(
            failure.reproduction_artifact().artifact.schedule(),
            &reference.children[1].schedule
        );
        assert_eq!(first.discovered_failures, second.discovered_failures);
    }

    Ok(())
}

#[test]
fn gate_search_failure_oracle_lowers_prefix_safe_assertion_violations() -> Result<(), Box<dyn Error>>
{
    let liveness_scenario = assertion_lowering_scenario(Property::Sometimes {
        predicate: Predicate::named("never-satisfied-by-black-box-oracle"),
    })?;
    let liveness_root = Configuration::genesis(liveness_scenario.scenario_def());
    let liveness_run = empty_search_run_for_root(&liveness_root);
    let liveness_oracle = SearchFailureOracle::from_search_assertion_violations(
        &liveness_scenario,
        &liveness_root,
        &liveness_run,
    )?;

    assert!(liveness_oracle.is_empty());

    let named_safety_scenario = assertion_lowering_scenario(Property::Always {
        predicate: Predicate::named("requires-external-host-oracle"),
    })?;
    let named_safety_root = Configuration::genesis(named_safety_scenario.scenario_def());
    let named_safety_run = empty_search_run_for_root(&named_safety_root);
    let named_safety_oracle = SearchFailureOracle::from_search_assertion_violations(
        &named_safety_scenario,
        &named_safety_root,
        &named_safety_run,
    )?;

    assert!(named_safety_oracle.is_empty());

    let empty_named_truths = SearchScheduleNamedPredicateTruths::new();
    let named_safety_with_missing_truth =
        SearchFailureOracle::from_search_assertion_violations_with_named_predicates(
            &named_safety_scenario,
            &named_safety_root,
            &named_safety_run,
            &empty_named_truths,
        )?;

    assert!(named_safety_with_missing_truth.is_empty());

    let named_false_truths = SearchScheduleNamedPredicateTruths::new().with_truth(
        SearchScheduleNamedPredicateKey::new("requires-external-host-oracle", Vec::new()),
        false,
    );
    let named_safety_with_false_truth =
        SearchFailureOracle::from_search_assertion_violations_with_named_predicates(
            &named_safety_scenario,
            &named_safety_root,
            &named_safety_run,
            &named_false_truths,
        )?;

    assert!(
        named_safety_with_false_truth
            .failure_for(named_safety_root.id())
            .is_some()
    );

    let named_true_truths = SearchScheduleNamedPredicateTruths::new().with_truth(
        SearchScheduleNamedPredicateKey::new("requires-external-host-oracle", Vec::new()),
        true,
    );
    let named_safety_with_true_truth =
        SearchFailureOracle::from_search_assertion_violations_with_named_predicates(
            &named_safety_scenario,
            &named_safety_root,
            &named_safety_run,
            &named_true_truths,
        )?;

    assert!(named_safety_with_true_truth.is_empty());

    let timed_safety_scenario = assertion_lowering_scenario(Property::Always {
        predicate: Predicate::not(Predicate::at(time(0))),
    })?;
    let timed_safety_root = Configuration {
        def: timed_safety_scenario.scenario_def(),
        schedule: Schedule::from_decisions([timed_delivery_decision(time(100))]),
    };
    let timed_safety_run = empty_search_run_for_root(&timed_safety_root);
    let timed_safety_oracle = SearchFailureOracle::from_search_assertion_violations(
        &timed_safety_scenario,
        &timed_safety_root,
        &timed_safety_run,
    )?;

    assert!(timed_safety_oracle.is_empty());

    let timed_safety_with_named_truths =
        SearchFailureOracle::from_search_assertion_violations_with_named_predicates(
            &timed_safety_scenario,
            &timed_safety_root,
            &timed_safety_run,
            &named_false_truths,
        )?;

    assert!(timed_safety_with_named_truths.is_empty());

    let marker = MarkerId::from_name("forbidden-search-marker");
    let retained_log_scenario = assertion_lowering_scenario_with_world(
        Property::Always {
            predicate: Predicate::not(Predicate::guest_marker(marker.clone())),
        },
        single_node_world_with_white_box(
            "retained-log-assertion-lowering",
            WhiteBoxPolicy::Enabled,
        )?,
    )?;
    let retained_log_root = Configuration::genesis(retained_log_scenario.scenario_def());
    let retained_log_run = empty_search_run_for_root(&retained_log_root);
    let schedule_only_guest_marker_oracle = SearchFailureOracle::from_search_assertion_violations(
        &retained_log_scenario,
        &retained_log_root,
        &retained_log_run,
    )?;

    assert!(schedule_only_guest_marker_oracle.is_empty());

    let missing_retained_log_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_logs(
            &retained_log_scenario,
            &retained_log_root,
            &retained_log_run,
            |_configuration| None,
        )?;

    assert!(missing_retained_log_oracle.is_empty());

    let retained_log = retained_guest_marker_log(marker)?;
    let retained_guest_marker_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_logs(
            &retained_log_scenario,
            &retained_log_root,
            &retained_log_run,
            |configuration| {
                (configuration.id() == retained_log_root.id()).then(|| retained_log.clone())
            },
        )?;

    assert!(
        retained_guest_marker_oracle
            .failure_for(retained_log_root.id())
            .is_some()
    );

    let raw_coverage_scenario = assertion_lowering_scenario(Property::Always {
        predicate: Predicate::not(Predicate::coverage_point(
            node_id("search-node"),
            CodePoint::guest_address(0x4010),
        )),
    })?;
    let raw_coverage_root = Configuration::genesis(raw_coverage_scenario.scenario_def());
    let raw_coverage_run = empty_search_run_for_root(&raw_coverage_root);
    let schedule_only_raw_coverage_oracle = SearchFailureOracle::from_search_assertion_violations(
        &raw_coverage_scenario,
        &raw_coverage_root,
        &raw_coverage_run,
    )?;

    assert!(schedule_only_raw_coverage_oracle.is_empty());

    let retained_raw_coverage_log = retained_observable_log(ObservableEvent::coverage_block(
        icount(11),
        node_id("search-node"),
        0x4000,
        0x20,
    ))?;
    let retained_raw_coverage_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_logs(
            &raw_coverage_scenario,
            &raw_coverage_root,
            &raw_coverage_run,
            |configuration| {
                (configuration.id() == raw_coverage_root.id())
                    .then(|| retained_raw_coverage_log.clone())
            },
        )?;

    assert!(
        retained_raw_coverage_oracle
            .failure_for(raw_coverage_root.id())
            .is_some()
    );

    let unsupported_symbol_coverage_scenario = assertion_lowering_scenario(Property::Always {
        predicate: Predicate::not(Predicate::coverage_point(
            node_id("search-node"),
            CodePoint::symbol("needs-symbol-resolution"),
        )),
    })?;
    let unsupported_symbol_coverage_root =
        Configuration::genesis(unsupported_symbol_coverage_scenario.scenario_def());
    let unsupported_symbol_coverage_run =
        empty_search_run_for_root(&unsupported_symbol_coverage_root);
    let unsupported_symbol_coverage_log = retained_observable_log(
        ObservableEvent::coverage_block(icount(12), node_id("search-node"), 0x4000, 0x20),
    )?;
    let unsupported_symbol_coverage_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_logs(
            &unsupported_symbol_coverage_scenario,
            &unsupported_symbol_coverage_root,
            &unsupported_symbol_coverage_run,
            |configuration| {
                (configuration.id() == unsupported_symbol_coverage_root.id())
                    .then(|| unsupported_symbol_coverage_log.clone())
            },
        )?;

    assert!(unsupported_symbol_coverage_oracle.is_empty());

    let nonmatching_symbol_coverage_resolutions = SearchRetainedLogPredicateResolutions::new()
        .with_code_point(
            node_id("other-node"),
            CodePoint::symbol("needs-symbol-resolution"),
            ResolvedCodePoint::guest_address(0x4010),
        )
        .with_code_point(
            node_id("search-node"),
            CodePoint::symbol("other-symbol"),
            ResolvedCodePoint::guest_address(0x4010),
        );
    let nonmatching_symbol_coverage_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_logs_and_resolutions(
            &unsupported_symbol_coverage_scenario,
            &unsupported_symbol_coverage_root,
            &unsupported_symbol_coverage_run,
            &nonmatching_symbol_coverage_resolutions,
            |configuration| {
                (configuration.id() == unsupported_symbol_coverage_root.id())
                    .then(|| unsupported_symbol_coverage_log.clone())
            },
        )?;

    assert!(nonmatching_symbol_coverage_oracle.is_empty());

    let symbol_coverage_resolutions = SearchRetainedLogPredicateResolutions::new().with_code_point(
        node_id("search-node"),
        CodePoint::symbol("needs-symbol-resolution"),
        ResolvedCodePoint::guest_address(0x4010),
    );
    let resolved_symbol_coverage_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_logs_and_resolutions(
            &unsupported_symbol_coverage_scenario,
            &unsupported_symbol_coverage_root,
            &unsupported_symbol_coverage_run,
            &symbol_coverage_resolutions,
            |configuration| {
                (configuration.id() == unsupported_symbol_coverage_root.id())
                    .then(|| unsupported_symbol_coverage_log.clone())
            },
        )?;

    assert!(
        resolved_symbol_coverage_oracle
            .failure_for(unsupported_symbol_coverage_root.id())
            .is_some()
    );

    let evidence_symbol_coverage_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
            &unsupported_symbol_coverage_scenario,
            &unsupported_symbol_coverage_root,
            &unsupported_symbol_coverage_run,
            |configuration| {
                (configuration.id() == unsupported_symbol_coverage_root.id()).then(|| {
                    SearchRetainedLogAssertionEvidence::new(unsupported_symbol_coverage_log.clone())
                        .with_resolutions(symbol_coverage_resolutions.clone())
                })
            },
        )?;

    assert!(
        evidence_symbol_coverage_oracle
            .failure_for(unsupported_symbol_coverage_root.id())
            .is_some()
    );

    let evidence_child_coverage_log = retained_observable_log(ObservableEvent::coverage_block(
        icount(13),
        node_id("search-node"),
        0x5000,
        0x20,
    ))?;
    let evidence_child_coverage_resolutions = SearchRetainedLogPredicateResolutions::new()
        .with_code_point(
            node_id("search-node"),
            CodePoint::symbol("needs-symbol-resolution"),
            ResolvedCodePoint::guest_address(0x5010),
        );
    let (evidence_child_configuration, evidence_multi_configuration_run) =
        search_run_for_root_decision(
            &unsupported_symbol_coverage_root,
            rng_decision("search-evidence/child", 1),
        )?;
    let evidence_per_configuration_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
            &unsupported_symbol_coverage_scenario,
            &unsupported_symbol_coverage_root,
            &evidence_multi_configuration_run,
            |configuration| {
                if configuration.id() == unsupported_symbol_coverage_root.id() {
                    Some(
                        SearchRetainedLogAssertionEvidence::new(
                            unsupported_symbol_coverage_log.clone(),
                        )
                        .with_resolutions(symbol_coverage_resolutions.clone()),
                    )
                } else if configuration.id() == evidence_child_configuration.id() {
                    Some(
                        SearchRetainedLogAssertionEvidence::new(
                            evidence_child_coverage_log.clone(),
                        )
                        .with_resolutions(evidence_child_coverage_resolutions.clone()),
                    )
                } else {
                    None
                }
            },
        )?;

    assert!(
        evidence_per_configuration_oracle
            .failure_for(unsupported_symbol_coverage_root.id())
            .is_some()
    );
    assert!(
        evidence_per_configuration_oracle
            .failure_for(evidence_child_configuration.id())
            .is_some()
    );

    let physical_memory_scenario = assertion_lowering_scenario(Property::Always {
        predicate: Predicate::not(Predicate::memory_predicate(
            node_id("search-node"),
            MemPlace::physical_address(0x1000, MemoryWidth::U32),
            MemoryCmp::Eq,
            0xfeed,
        )),
    })?;
    let physical_memory_root = Configuration::genesis(physical_memory_scenario.scenario_def());
    let physical_memory_run = empty_search_run_for_root(&physical_memory_root);
    let schedule_only_physical_memory_oracle =
        SearchFailureOracle::from_search_assertion_violations(
            &physical_memory_scenario,
            &physical_memory_root,
            &physical_memory_run,
        )?;

    assert!(schedule_only_physical_memory_oracle.is_empty());

    let retained_physical_memory_log = retained_observable_log(ObservableEvent::memory_sample(
        time(21),
        icount(21),
        node_id("search-node"),
        ResolvedMemPlace::physical_address(0x1000, 4),
        0xfeed,
    ))?;
    let retained_physical_memory_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_logs(
            &physical_memory_scenario,
            &physical_memory_root,
            &physical_memory_run,
            |configuration| {
                (configuration.id() == physical_memory_root.id())
                    .then(|| retained_physical_memory_log.clone())
            },
        )?;

    assert!(
        retained_physical_memory_oracle
            .failure_for(physical_memory_root.id())
            .is_some()
    );

    let register_memory_scenario = assertion_lowering_scenario(Property::Always {
        predicate: Predicate::not(Predicate::memory_predicate(
            node_id("search-node"),
            MemPlace::register("rax", MemoryWidth::U64),
            MemoryCmp::Ge,
            10,
        )),
    })?;
    let register_memory_root = Configuration::genesis(register_memory_scenario.scenario_def());
    let register_memory_run = empty_search_run_for_root(&register_memory_root);
    let retained_register_memory_log = retained_observable_log(ObservableEvent::memory_sample(
        time(22),
        icount(22),
        node_id("search-node"),
        ResolvedMemPlace::register("rax", 8),
        10,
    ))?;
    let retained_register_memory_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_logs(
            &register_memory_scenario,
            &register_memory_root,
            &register_memory_run,
            |configuration| {
                (configuration.id() == register_memory_root.id())
                    .then(|| retained_register_memory_log.clone())
            },
        )?;

    assert!(
        retained_register_memory_oracle
            .failure_for(register_memory_root.id())
            .is_some()
    );

    let unsupported_symbol_memory_scenario = assertion_lowering_scenario(Property::Always {
        predicate: Predicate::not(Predicate::memory_predicate(
            node_id("search-node"),
            MemPlace::symbol("needs-memory-resolution", MemoryWidth::U8),
            MemoryCmp::Eq,
            2,
        )),
    })?;
    let unsupported_symbol_memory_root =
        Configuration::genesis(unsupported_symbol_memory_scenario.scenario_def());
    let unsupported_symbol_memory_run = empty_search_run_for_root(&unsupported_symbol_memory_root);
    let unsupported_symbol_memory_log = retained_observable_log(ObservableEvent::memory_sample(
        time(33),
        icount(33),
        node_id("search-node"),
        ResolvedMemPlace::virtual_address(0x7000, 1),
        2,
    ))?;
    let unsupported_symbol_memory_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_logs(
            &unsupported_symbol_memory_scenario,
            &unsupported_symbol_memory_root,
            &unsupported_symbol_memory_run,
            |configuration| {
                (configuration.id() == unsupported_symbol_memory_root.id())
                    .then(|| unsupported_symbol_memory_log.clone())
            },
        )?;

    assert!(unsupported_symbol_memory_oracle.is_empty());

    let nonmatching_symbol_memory_resolutions = SearchRetainedLogPredicateResolutions::new()
        .with_mem_place(
            node_id("search-node"),
            MemPlace::symbol("other-memory-symbol", MemoryWidth::U8),
            ResolvedMemPlace::virtual_address(0x7000, 1),
        );
    let nonmatching_symbol_memory_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_logs_and_resolutions(
            &unsupported_symbol_memory_scenario,
            &unsupported_symbol_memory_root,
            &unsupported_symbol_memory_run,
            &nonmatching_symbol_memory_resolutions,
            |configuration| {
                (configuration.id() == unsupported_symbol_memory_root.id())
                    .then(|| unsupported_symbol_memory_log.clone())
            },
        )?;

    assert!(nonmatching_symbol_memory_oracle.is_empty());

    let symbol_memory_resolutions = SearchRetainedLogPredicateResolutions::new().with_mem_place(
        node_id("search-node"),
        MemPlace::symbol("needs-memory-resolution", MemoryWidth::U8),
        ResolvedMemPlace::virtual_address(0x7000, 1),
    );
    let resolved_symbol_memory_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_logs_and_resolutions(
            &unsupported_symbol_memory_scenario,
            &unsupported_symbol_memory_root,
            &unsupported_symbol_memory_run,
            &symbol_memory_resolutions,
            |configuration| {
                (configuration.id() == unsupported_symbol_memory_root.id())
                    .then(|| unsupported_symbol_memory_log.clone())
            },
        )?;

    assert!(
        resolved_symbol_memory_oracle
            .failure_for(unsupported_symbol_memory_root.id())
            .is_some()
    );

    let evidence_nonmatching_symbol_memory_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
            &unsupported_symbol_memory_scenario,
            &unsupported_symbol_memory_root,
            &unsupported_symbol_memory_run,
            |configuration| {
                (configuration.id() == unsupported_symbol_memory_root.id()).then(|| {
                    SearchRetainedLogAssertionEvidence::new(unsupported_symbol_memory_log.clone())
                        .with_resolutions(nonmatching_symbol_memory_resolutions.clone())
                })
            },
        )?;

    assert!(evidence_nonmatching_symbol_memory_oracle.is_empty());

    let evidence_symbol_memory_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
            &unsupported_symbol_memory_scenario,
            &unsupported_symbol_memory_root,
            &unsupported_symbol_memory_run,
            |configuration| {
                (configuration.id() == unsupported_symbol_memory_root.id()).then(|| {
                    SearchRetainedLogAssertionEvidence::new(unsupported_symbol_memory_log.clone())
                        .with_resolutions(symbol_memory_resolutions.clone())
                })
            },
        )?;

    assert!(
        evidence_symbol_memory_oracle
            .failure_for(unsupported_symbol_memory_root.id())
            .is_some()
    );

    let unsupported_virtual_memory_scenario = assertion_lowering_scenario(Property::Always {
        predicate: Predicate::not(Predicate::memory_predicate(
            node_id("search-node"),
            MemPlace::virtual_address(0x7000, MemoryWidth::U8),
            MemoryCmp::Eq,
            2,
        )),
    })?;
    let unsupported_virtual_memory_root =
        Configuration::genesis(unsupported_virtual_memory_scenario.scenario_def());
    let unsupported_virtual_memory_run =
        empty_search_run_for_root(&unsupported_virtual_memory_root);
    let unsupported_virtual_memory_log = retained_observable_log(ObservableEvent::memory_sample(
        time(34),
        icount(34),
        node_id("search-node"),
        ResolvedMemPlace::virtual_address(0x7000, 1),
        2,
    ))?;
    let unsupported_virtual_memory_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_logs(
            &unsupported_virtual_memory_scenario,
            &unsupported_virtual_memory_root,
            &unsupported_virtual_memory_run,
            |configuration| {
                (configuration.id() == unsupported_virtual_memory_root.id())
                    .then(|| unsupported_virtual_memory_log.clone())
            },
        )?;

    assert!(unsupported_virtual_memory_oracle.is_empty());

    let nonmatching_virtual_memory_resolutions = SearchRetainedLogPredicateResolutions::new()
        .with_mem_place(
            node_id("search-node"),
            MemPlace::virtual_address(0x7001, MemoryWidth::U8),
            ResolvedMemPlace::virtual_address(0x7000, 1),
        );
    let nonmatching_virtual_memory_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_logs_and_resolutions(
            &unsupported_virtual_memory_scenario,
            &unsupported_virtual_memory_root,
            &unsupported_virtual_memory_run,
            &nonmatching_virtual_memory_resolutions,
            |configuration| {
                (configuration.id() == unsupported_virtual_memory_root.id())
                    .then(|| unsupported_virtual_memory_log.clone())
            },
        )?;

    assert!(nonmatching_virtual_memory_oracle.is_empty());

    let virtual_memory_resolutions = SearchRetainedLogPredicateResolutions::new().with_mem_place(
        node_id("search-node"),
        MemPlace::virtual_address(0x7000, MemoryWidth::U8),
        ResolvedMemPlace::virtual_address(0x7000, 1),
    );
    let resolved_virtual_memory_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_logs_and_resolutions(
            &unsupported_virtual_memory_scenario,
            &unsupported_virtual_memory_root,
            &unsupported_virtual_memory_run,
            &virtual_memory_resolutions,
            |configuration| {
                (configuration.id() == unsupported_virtual_memory_root.id())
                    .then(|| unsupported_virtual_memory_log.clone())
            },
        )?;

    assert!(
        resolved_virtual_memory_oracle
            .failure_for(unsupported_virtual_memory_root.id())
            .is_some()
    );

    let evidence_nonmatching_virtual_memory_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
            &unsupported_virtual_memory_scenario,
            &unsupported_virtual_memory_root,
            &unsupported_virtual_memory_run,
            |configuration| {
                (configuration.id() == unsupported_virtual_memory_root.id()).then(|| {
                    SearchRetainedLogAssertionEvidence::new(unsupported_virtual_memory_log.clone())
                        .with_resolutions(nonmatching_virtual_memory_resolutions.clone())
                })
            },
        )?;

    assert!(evidence_nonmatching_virtual_memory_oracle.is_empty());

    let evidence_virtual_memory_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
            &unsupported_virtual_memory_scenario,
            &unsupported_virtual_memory_root,
            &unsupported_virtual_memory_run,
            |configuration| {
                (configuration.id() == unsupported_virtual_memory_root.id()).then(|| {
                    SearchRetainedLogAssertionEvidence::new(unsupported_virtual_memory_log.clone())
                        .with_resolutions(virtual_memory_resolutions.clone())
                })
            },
        )?;

    assert!(
        evidence_virtual_memory_oracle
            .failure_for(unsupported_virtual_memory_root.id())
            .is_some()
    );

    let unsupported_quiescence_scenario = assertion_lowering_scenario(Property::Always {
        predicate: Predicate::Quiescent,
    })?;
    let unsupported_quiescence_root =
        Configuration::genesis(unsupported_quiescence_scenario.scenario_def());
    let unsupported_quiescence_run = empty_search_run_for_root(&unsupported_quiescence_root);
    let unsupported_quiescence_log = retained_boundary_log(time(0))?;
    let unsupported_quiescence_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_logs(
            &unsupported_quiescence_scenario,
            &unsupported_quiescence_root,
            &unsupported_quiescence_run,
            |configuration| {
                (configuration.id() == unsupported_quiescence_root.id())
                    .then(|| unsupported_quiescence_log.clone())
            },
        )?;

    assert!(unsupported_quiescence_oracle.is_empty());

    let unsupported_quiescence_with_terminal_quiescence_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
            &unsupported_quiescence_scenario,
            &unsupported_quiescence_root,
            &unsupported_quiescence_run,
            |configuration| {
                (configuration.id() == unsupported_quiescence_root.id()).then(|| {
                    SearchRetainedLogAssertionEvidence::new(unsupported_quiescence_log.clone())
                        .with_terminal_scheduler_quiescence(SchedulerQuiescence::default())
                })
            },
        )?;

    assert!(unsupported_quiescence_with_terminal_quiescence_oracle.is_empty());

    let unreachable_quiescence_scenario = assertion_lowering_scenario(Property::Reachable {
        predicate: Predicate::not(Predicate::Quiescent),
        expectation: ReachabilityExpectation::Unreachable,
    })?;
    let unreachable_quiescence_root =
        Configuration::genesis(unreachable_quiescence_scenario.scenario_def());
    let unreachable_quiescence_run = empty_search_run_for_root(&unreachable_quiescence_root);
    let unreachable_quiescence_log = retained_boundary_log(time(1))?;
    let unreachable_quiescence_with_terminal_quiescence_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
            &unreachable_quiescence_scenario,
            &unreachable_quiescence_root,
            &unreachable_quiescence_run,
            |configuration| {
                (configuration.id() == unreachable_quiescence_root.id()).then(|| {
                    SearchRetainedLogAssertionEvidence::new(unreachable_quiescence_log.clone())
                        .with_terminal_scheduler_quiescence(SchedulerQuiescence::default())
                })
            },
        )?;

    assert!(unreachable_quiescence_with_terminal_quiescence_oracle.is_empty());

    let after_quiescence_scenario = assertion_lowering_scenario(Property::AfterQuiescence {
        predicate: Predicate::not(Predicate::Quiescent),
    })?;
    let after_quiescence_root = Configuration::genesis(after_quiescence_scenario.scenario_def());
    let after_quiescence_run = empty_search_run_for_root(&after_quiescence_root);
    let after_quiescence_log = retained_boundary_log(time(40))?;
    let after_quiescence_without_terminal_quiescence_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
            &after_quiescence_scenario,
            &after_quiescence_root,
            &after_quiescence_run,
            |configuration| {
                (configuration.id() == after_quiescence_root.id())
                    .then(|| SearchRetainedLogAssertionEvidence::new(after_quiescence_log.clone()))
            },
        )?;

    assert!(after_quiescence_without_terminal_quiescence_oracle.is_empty());

    let after_quiescence_with_terminal_quiescence_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
            &after_quiescence_scenario,
            &after_quiescence_root,
            &after_quiescence_run,
            |configuration| {
                (configuration.id() == after_quiescence_root.id()).then(|| {
                    SearchRetainedLogAssertionEvidence::new(after_quiescence_log.clone())
                        .with_terminal_scheduler_quiescence(SchedulerQuiescence::default())
                })
            },
        )?;

    assert!(
        after_quiescence_with_terminal_quiescence_oracle
            .failure_for(after_quiescence_root.id())
            .is_some()
    );

    let retained_sometimes_marker = MarkerId::from_name("never-retained-marker");
    let retained_sometimes_scenario = assertion_lowering_scenario_with_world(
        Property::Sometimes {
            predicate: Predicate::guest_marker(retained_sometimes_marker),
        },
        single_node_world_with_white_box(
            "retained-log-sometimes-lowering",
            WhiteBoxPolicy::Enabled,
        )?,
    )?;
    let retained_sometimes_root =
        Configuration::genesis(retained_sometimes_scenario.scenario_def());
    let retained_sometimes_run = empty_search_run_for_root(&retained_sometimes_root);
    let retained_sometimes_log = retained_boundary_log(time(50))?;
    let retained_sometimes_without_terminal_quiescence_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
            &retained_sometimes_scenario,
            &retained_sometimes_root,
            &retained_sometimes_run,
            |configuration| {
                (configuration.id() == retained_sometimes_root.id()).then(|| {
                    SearchRetainedLogAssertionEvidence::new(retained_sometimes_log.clone())
                })
            },
        )?;

    assert!(retained_sometimes_without_terminal_quiescence_oracle.is_empty());

    let retained_sometimes_with_blocked_terminal_quiescence_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
            &retained_sometimes_scenario,
            &retained_sometimes_root,
            &retained_sometimes_run,
            |configuration| {
                (configuration.id() == retained_sometimes_root.id()).then(|| {
                    SearchRetainedLogAssertionEvidence::new(retained_sometimes_log.clone())
                        .with_terminal_scheduler_quiescence(SchedulerQuiescence {
                            blockers: vec![SchedulerQuiescenceBlocker::DeviceCompletionInFlight {
                                target: node_id("search-node"),
                            }],
                        })
                })
            },
        )?;

    assert!(retained_sometimes_with_blocked_terminal_quiescence_oracle.is_empty());

    let retained_sometimes_with_terminal_quiescence_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
            &retained_sometimes_scenario,
            &retained_sometimes_root,
            &retained_sometimes_run,
            |configuration| {
                (configuration.id() == retained_sometimes_root.id()).then(|| {
                    SearchRetainedLogAssertionEvidence::new(retained_sometimes_log.clone())
                        .with_terminal_scheduler_quiescence(SchedulerQuiescence::default())
                })
            },
        )?;

    assert!(
        retained_sometimes_with_terminal_quiescence_oracle
            .failure_for(retained_sometimes_root.id())
            .is_some()
    );

    let sometimes_quiescence_scenario = assertion_lowering_scenario(Property::Sometimes {
        predicate: Predicate::Quiescent,
    })?;
    let sometimes_quiescence_root =
        Configuration::genesis(sometimes_quiescence_scenario.scenario_def());
    let sometimes_quiescence_run = empty_search_run_for_root(&sometimes_quiescence_root);
    let sometimes_quiescence_log = retained_boundary_log(time(60))?;
    let sometimes_quiescence_with_terminal_quiescence_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
            &sometimes_quiescence_scenario,
            &sometimes_quiescence_root,
            &sometimes_quiescence_run,
            |configuration| {
                (configuration.id() == sometimes_quiescence_root.id()).then(|| {
                    SearchRetainedLogAssertionEvidence::new(sometimes_quiescence_log.clone())
                        .with_terminal_scheduler_quiescence(SchedulerQuiescence::default())
                })
            },
        )?;

    assert!(sometimes_quiescence_with_terminal_quiescence_oracle.is_empty());

    let retained_eventually_marker = MarkerId::from_name("never-eventually-marker");
    let retained_eventually_scenario = assertion_lowering_scenario_with_world(
        Property::Eventually {
            trigger: Predicate::at(time(70)),
            property: Predicate::guest_marker(retained_eventually_marker),
            deadline: time(5),
        },
        single_node_world_with_white_box(
            "retained-log-eventually-lowering",
            WhiteBoxPolicy::Enabled,
        )?,
    )?;
    let retained_eventually_root =
        Configuration::genesis(retained_eventually_scenario.scenario_def());
    let retained_eventually_run = empty_search_run_for_root(&retained_eventually_root);
    let retained_eventually_log = retained_boundary_log(time(70))?;
    let retained_eventually_without_terminal_quiescence_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
            &retained_eventually_scenario,
            &retained_eventually_root,
            &retained_eventually_run,
            |configuration| {
                (configuration.id() == retained_eventually_root.id()).then(|| {
                    SearchRetainedLogAssertionEvidence::new(retained_eventually_log.clone())
                })
            },
        )?;

    assert!(retained_eventually_without_terminal_quiescence_oracle.is_empty());

    let retained_eventually_with_blocked_terminal_quiescence_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
            &retained_eventually_scenario,
            &retained_eventually_root,
            &retained_eventually_run,
            |configuration| {
                (configuration.id() == retained_eventually_root.id()).then(|| {
                    SearchRetainedLogAssertionEvidence::new(retained_eventually_log.clone())
                        .with_terminal_scheduler_quiescence(SchedulerQuiescence {
                            blockers: vec![SchedulerQuiescenceBlocker::DeviceCompletionInFlight {
                                target: node_id("search-node"),
                            }],
                        })
                })
            },
        )?;

    assert!(retained_eventually_with_blocked_terminal_quiescence_oracle.is_empty());

    let retained_eventually_with_terminal_quiescence_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
            &retained_eventually_scenario,
            &retained_eventually_root,
            &retained_eventually_run,
            |configuration| {
                (configuration.id() == retained_eventually_root.id()).then(|| {
                    SearchRetainedLogAssertionEvidence::new(retained_eventually_log.clone())
                        .with_terminal_scheduler_quiescence(SchedulerQuiescence::default())
                })
            },
        )?;

    assert!(
        retained_eventually_with_terminal_quiescence_oracle
            .failure_for(retained_eventually_root.id())
            .is_some()
    );

    let eventually_quiescence_scenario = assertion_lowering_scenario(Property::Eventually {
        trigger: Predicate::at(time(80)),
        property: Predicate::Quiescent,
        deadline: time(5),
    })?;
    let eventually_quiescence_root =
        Configuration::genesis(eventually_quiescence_scenario.scenario_def());
    let eventually_quiescence_run = empty_search_run_for_root(&eventually_quiescence_root);
    let eventually_quiescence_log = retained_boundary_log(time(80))?;
    let eventually_quiescence_with_terminal_quiescence_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
            &eventually_quiescence_scenario,
            &eventually_quiescence_root,
            &eventually_quiescence_run,
            |configuration| {
                (configuration.id() == eventually_quiescence_root.id()).then(|| {
                    SearchRetainedLogAssertionEvidence::new(eventually_quiescence_log.clone())
                        .with_terminal_scheduler_quiescence(SchedulerQuiescence::default())
                })
            },
        )?;

    assert!(eventually_quiescence_with_terminal_quiescence_oracle.is_empty());

    let eventually_quiescence_trigger_marker =
        MarkerId::from_name("eventually-quiescence-trigger-marker");
    let eventually_quiescence_trigger_scenario = assertion_lowering_scenario_with_world(
        Property::Eventually {
            trigger: Predicate::not(Predicate::Quiescent),
            property: Predicate::guest_marker(eventually_quiescence_trigger_marker),
            deadline: time(5),
        },
        single_node_world_with_white_box(
            "retained-log-eventually-trigger-guard",
            WhiteBoxPolicy::Enabled,
        )?,
    )?;
    let eventually_quiescence_trigger_root =
        Configuration::genesis(eventually_quiescence_trigger_scenario.scenario_def());
    let eventually_quiescence_trigger_run =
        empty_search_run_for_root(&eventually_quiescence_trigger_root);
    let eventually_quiescence_trigger_log = retained_boundary_log(time(90))?;
    let eventually_quiescence_trigger_with_terminal_quiescence_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
            &eventually_quiescence_trigger_scenario,
            &eventually_quiescence_trigger_root,
            &eventually_quiescence_trigger_run,
            |configuration| {
                (configuration.id() == eventually_quiescence_trigger_root.id()).then(|| {
                    SearchRetainedLogAssertionEvidence::new(
                        eventually_quiescence_trigger_log.clone(),
                    )
                    .with_terminal_scheduler_quiescence(SchedulerQuiescence::default())
                })
            },
        )?;

    assert!(eventually_quiescence_trigger_with_terminal_quiescence_oracle.is_empty());

    let retained_reachable_marker = MarkerId::from_name("never-reachable-marker");
    let retained_reachable_scenario = assertion_lowering_scenario_with_world(
        Property::Reachable {
            predicate: Predicate::guest_marker(retained_reachable_marker),
            expectation: ReachabilityExpectation::Reachable {
                on_unreached: ReachableDisposition::Fail,
            },
        },
        single_node_world_with_white_box(
            "retained-log-reachable-lowering",
            WhiteBoxPolicy::Enabled,
        )?,
    )?;
    let retained_reachable_root =
        Configuration::genesis(retained_reachable_scenario.scenario_def());
    let retained_reachable_run = empty_search_run_for_root(&retained_reachable_root);
    let retained_reachable_log = retained_boundary_log(time(100))?;
    let retained_reachable_without_terminal_quiescence_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
            &retained_reachable_scenario,
            &retained_reachable_root,
            &retained_reachable_run,
            |configuration| {
                (configuration.id() == retained_reachable_root.id()).then(|| {
                    SearchRetainedLogAssertionEvidence::new(retained_reachable_log.clone())
                })
            },
        )?;

    assert!(retained_reachable_without_terminal_quiescence_oracle.is_empty());

    let retained_reachable_with_blocked_terminal_quiescence_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
            &retained_reachable_scenario,
            &retained_reachable_root,
            &retained_reachable_run,
            |configuration| {
                (configuration.id() == retained_reachable_root.id()).then(|| {
                    SearchRetainedLogAssertionEvidence::new(retained_reachable_log.clone())
                        .with_terminal_scheduler_quiescence(SchedulerQuiescence {
                            blockers: vec![SchedulerQuiescenceBlocker::DeviceCompletionInFlight {
                                target: node_id("search-node"),
                            }],
                        })
                })
            },
        )?;

    assert!(retained_reachable_with_blocked_terminal_quiescence_oracle.is_empty());

    let retained_reachable_with_terminal_quiescence_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
            &retained_reachable_scenario,
            &retained_reachable_root,
            &retained_reachable_run,
            |configuration| {
                (configuration.id() == retained_reachable_root.id()).then(|| {
                    SearchRetainedLogAssertionEvidence::new(retained_reachable_log.clone())
                        .with_terminal_scheduler_quiescence(SchedulerQuiescence::default())
                })
            },
        )?;

    assert!(
        retained_reachable_with_terminal_quiescence_oracle
            .failure_for(retained_reachable_root.id())
            .is_some()
    );

    let retained_reachable_warn_marker = MarkerId::from_name("never-reachable-warn-marker");
    let retained_reachable_warn_scenario = assertion_lowering_scenario_with_world(
        Property::Reachable {
            predicate: Predicate::guest_marker(retained_reachable_warn_marker),
            expectation: ReachabilityExpectation::Reachable {
                on_unreached: ReachableDisposition::Warn,
            },
        },
        single_node_world_with_white_box(
            "retained-log-reachable-warn-guard",
            WhiteBoxPolicy::Enabled,
        )?,
    )?;
    let retained_reachable_warn_root =
        Configuration::genesis(retained_reachable_warn_scenario.scenario_def());
    let retained_reachable_warn_run = empty_search_run_for_root(&retained_reachable_warn_root);
    let retained_reachable_warn_log = retained_boundary_log(time(105))?;
    let retained_reachable_warn_with_terminal_quiescence_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
            &retained_reachable_warn_scenario,
            &retained_reachable_warn_root,
            &retained_reachable_warn_run,
            |configuration| {
                (configuration.id() == retained_reachable_warn_root.id()).then(|| {
                    SearchRetainedLogAssertionEvidence::new(retained_reachable_warn_log.clone())
                        .with_terminal_scheduler_quiescence(SchedulerQuiescence::default())
                })
            },
        )?;

    assert!(retained_reachable_warn_with_terminal_quiescence_oracle.is_empty());

    let reachable_quiescence_scenario = assertion_lowering_scenario(Property::Reachable {
        predicate: Predicate::Quiescent,
        expectation: ReachabilityExpectation::Reachable {
            on_unreached: ReachableDisposition::Fail,
        },
    })?;
    let reachable_quiescence_root =
        Configuration::genesis(reachable_quiescence_scenario.scenario_def());
    let reachable_quiescence_run = empty_search_run_for_root(&reachable_quiescence_root);
    let reachable_quiescence_log = retained_boundary_log(time(110))?;
    let reachable_quiescence_with_terminal_quiescence_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
            &reachable_quiescence_scenario,
            &reachable_quiescence_root,
            &reachable_quiescence_run,
            |configuration| {
                (configuration.id() == reachable_quiescence_root.id()).then(|| {
                    SearchRetainedLogAssertionEvidence::new(reachable_quiescence_log.clone())
                        .with_terminal_scheduler_quiescence(SchedulerQuiescence::default())
                })
            },
        )?;

    assert!(reachable_quiescence_with_terminal_quiescence_oracle.is_empty());

    let guest_marker_scenario = assertion_lowering_scenario_with_world(
        Property::Always {
            predicate: Predicate::not(Predicate::at(time(u64::MAX))),
        },
        single_node_world_with_white_box(
            "retained-log-guest-assertion-lowering",
            WhiteBoxPolicy::Enabled,
        )?,
    )?;
    let guest_marker_root = Configuration::genesis(guest_marker_scenario.scenario_def());
    let guest_marker_run = empty_search_run_for_root(&guest_marker_root);
    let guest_always_false_log = retained_guest_assertion_marker_log(
        "guest-always-false",
        GuestAssertionKind::Always,
        false,
        true,
    )?;
    let guest_always_false_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_logs(
            &guest_marker_scenario,
            &guest_marker_root,
            &guest_marker_run,
            |configuration| {
                (configuration.id() == guest_marker_root.id())
                    .then(|| guest_always_false_log.clone())
            },
        )?;

    assert!(
        guest_always_false_oracle
            .failure_for(guest_marker_root.id())
            .is_some()
    );

    let guest_unreachable_true_log = retained_guest_assertion_marker_log(
        "guest-unreachable-true",
        GuestAssertionKind::Unreachable,
        true,
        true,
    )?;
    let guest_unreachable_true_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_logs(
            &guest_marker_scenario,
            &guest_marker_root,
            &guest_marker_run,
            |configuration| {
                (configuration.id() == guest_marker_root.id())
                    .then(|| guest_unreachable_true_log.clone())
            },
        )?;

    assert!(
        guest_unreachable_true_oracle
            .failure_for(guest_marker_root.id())
            .is_some()
    );

    let guest_sometimes_false_log = retained_guest_assertion_marker_log(
        "guest-sometimes-false",
        GuestAssertionKind::Sometimes,
        false,
        true,
    )?;
    let guest_sometimes_without_terminal_quiescence_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
            &guest_marker_scenario,
            &guest_marker_root,
            &guest_marker_run,
            |configuration| {
                (configuration.id() == guest_marker_root.id()).then(|| {
                    SearchRetainedLogAssertionEvidence::new(guest_sometimes_false_log.clone())
                })
            },
        )?;

    assert!(guest_sometimes_without_terminal_quiescence_oracle.is_empty());

    let guest_sometimes_with_blocked_terminal_quiescence_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
            &guest_marker_scenario,
            &guest_marker_root,
            &guest_marker_run,
            |configuration| {
                (configuration.id() == guest_marker_root.id()).then(|| {
                    SearchRetainedLogAssertionEvidence::new(guest_sometimes_false_log.clone())
                        .with_terminal_scheduler_quiescence(SchedulerQuiescence {
                            blockers: vec![SchedulerQuiescenceBlocker::DeviceCompletionInFlight {
                                target: node_id("search-node"),
                            }],
                        })
                })
            },
        )?;

    assert!(guest_sometimes_with_blocked_terminal_quiescence_oracle.is_empty());

    let guest_sometimes_with_terminal_quiescence_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
            &guest_marker_scenario,
            &guest_marker_root,
            &guest_marker_run,
            |configuration| {
                (configuration.id() == guest_marker_root.id()).then(|| {
                    SearchRetainedLogAssertionEvidence::new(guest_sometimes_false_log.clone())
                        .with_terminal_scheduler_quiescence(SchedulerQuiescence::default())
                })
            },
        )?;

    assert!(
        guest_sometimes_with_terminal_quiescence_oracle
            .failure_for(guest_marker_root.id())
            .is_some()
    );

    let guest_reachable_required_false_log = retained_guest_assertion_marker_log(
        "guest-reachable-required-false",
        GuestAssertionKind::Reachable,
        false,
        true,
    )?;
    let guest_reachable_required_without_terminal_quiescence_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
            &guest_marker_scenario,
            &guest_marker_root,
            &guest_marker_run,
            |configuration| {
                (configuration.id() == guest_marker_root.id()).then(|| {
                    SearchRetainedLogAssertionEvidence::new(
                        guest_reachable_required_false_log.clone(),
                    )
                })
            },
        )?;

    assert!(guest_reachable_required_without_terminal_quiescence_oracle.is_empty());

    let guest_reachable_kind_mismatch_log = retained_observable_events_log(vec![
        guest_assertion_marker_event(
            7,
            "guest-reachable-kind-mismatch",
            GuestAssertionKind::Reachable,
            false,
            true,
        ),
        guest_assertion_marker_event(
            8,
            "guest-reachable-kind-mismatch",
            GuestAssertionKind::Always,
            false,
            true,
        ),
    ])?;
    let guest_reachable_kind_mismatch_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
            &guest_marker_scenario,
            &guest_marker_root,
            &guest_marker_run,
            |configuration| {
                (configuration.id() == guest_marker_root.id()).then(|| {
                    SearchRetainedLogAssertionEvidence::new(
                        guest_reachable_kind_mismatch_log.clone(),
                    )
                })
            },
        )?;

    assert!(guest_reachable_kind_mismatch_oracle.is_empty());

    let guest_reachable_required_with_blocked_terminal_quiescence_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
            &guest_marker_scenario,
            &guest_marker_root,
            &guest_marker_run,
            |configuration| {
                (configuration.id() == guest_marker_root.id()).then(|| {
                    SearchRetainedLogAssertionEvidence::new(
                        guest_reachable_required_false_log.clone(),
                    )
                    .with_terminal_scheduler_quiescence(SchedulerQuiescence {
                        blockers: vec![SchedulerQuiescenceBlocker::DeviceCompletionInFlight {
                            target: node_id("search-node"),
                        }],
                    })
                })
            },
        )?;

    assert!(guest_reachable_required_with_blocked_terminal_quiescence_oracle.is_empty());

    let guest_reachable_required_with_terminal_quiescence_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
            &guest_marker_scenario,
            &guest_marker_root,
            &guest_marker_run,
            |configuration| {
                (configuration.id() == guest_marker_root.id()).then(|| {
                    SearchRetainedLogAssertionEvidence::new(
                        guest_reachable_required_false_log.clone(),
                    )
                    .with_terminal_scheduler_quiescence(SchedulerQuiescence::default())
                })
            },
        )?;

    assert!(
        guest_reachable_required_with_terminal_quiescence_oracle
            .failure_for(guest_marker_root.id())
            .is_some()
    );

    let guest_reachable_warn_false_log = retained_guest_assertion_marker_log(
        "guest-reachable-warn-false",
        GuestAssertionKind::Reachable,
        false,
        false,
    )?;
    let guest_reachable_warn_with_terminal_quiescence_oracle =
        SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
            &guest_marker_scenario,
            &guest_marker_root,
            &guest_marker_run,
            |configuration| {
                (configuration.id() == guest_marker_root.id()).then(|| {
                    SearchRetainedLogAssertionEvidence::new(guest_reachable_warn_false_log.clone())
                        .with_terminal_scheduler_quiescence(SchedulerQuiescence::default())
                })
            },
        )?;

    assert!(guest_reachable_warn_with_terminal_quiescence_oracle.is_empty());

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
        &fixture.scenario,
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
    scenario: ScenarioDefForm,
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
    let scenario = ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::default(),
    )?;
    let scenario_def = scenario.scenario_def();
    let root = Configuration::genesis(scenario_def.clone());
    let root_decisions = strategy_root_decisions();
    let baked = bake_with_search_frontier_choices(&world, root_decisions.clone())?;
    let mut graph = TemporalGraph::empty().with_baked_genesis(&scenario_def, baked)?;
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
        scenario,
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
    single_node_world_with_white_box(label, WhiteBoxPolicy::Disabled)
}

fn single_node_world_with_white_box(
    label: &str,
    white_box: WhiteBoxPolicy,
) -> Result<World, EngineError> {
    World::from_nodes(vec![WorldNode {
        id: node_id("search-node"),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: format!("crucible-search-strategy={label}"),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 100 },
        },
        white_box,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
}

fn strategy_root_decisions() -> Vec<Decision> {
    vec![
        rng_decision("search-strategy/packet-loss", 1),
        rng_decision("search-strategy/decision-rng", 0xa5a5_5a5a),
        override_decision("search-strategy/scheduler-point", "non-default-choice"),
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

fn assertion_lowering_scenario(property: Property) -> Result<ScenarioDefForm, EngineError> {
    assertion_lowering_scenario_with_world(property, single_node_world("assertion-lowering")?)
}

fn assertion_lowering_scenario_with_world(
    property: Property,
    world: World,
) -> Result<ScenarioDefForm, EngineError> {
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![AssertionDef {
            id: AssertionId::from_name("search-assertion-lowering"),
            message: String::from("search assertion lowering test"),
            property,
        }],
    )?;
    ScenarioDefForm::from_components(&world, &Plan::empty(), &properties, Seed::default())
}

fn retained_guest_marker_log(marker: MarkerId) -> Result<RecordedAssertionLog, EngineError> {
    retained_observable_log(ObservableEvent::guest_marker(
        icount(7),
        node_id("search-node"),
        marker,
    ))
}

fn retained_guest_assertion_marker_log(
    id: &str,
    kind: GuestAssertionKind,
    condition: bool,
    must_hit: bool,
) -> Result<RecordedAssertionLog, EngineError> {
    retained_observable_log(guest_assertion_marker_event(
        7, id, kind, condition, must_hit,
    ))
}

fn guest_assertion_marker_event(
    at: u64,
    id: &str,
    kind: GuestAssertionKind,
    condition: bool,
    must_hit: bool,
) -> ObservableEvent {
    ObservableEvent::guest_assertion_marker(
        icount(at),
        node_id("search-node"),
        GuestAssertionMarker::new(
            AssertionId::from_name(id),
            format!("guest assertion marker {id}"),
            kind,
            condition,
            must_hit,
            vec![GuestAssertionDetail::new("case", id)],
            "gate_search_strategies.rs:guest-marker",
        ),
    )
}

fn retained_observable_log(event: ObservableEvent) -> Result<RecordedAssertionLog, EngineError> {
    retained_observable_events_log(vec![event])
}

fn retained_observable_events_log(
    events: Vec<ObservableEvent>,
) -> Result<RecordedAssertionLog, EngineError> {
    let boundary_at = time(
        events
            .iter()
            .map(|event| event.at().ticks)
            .max()
            .unwrap_or_default()
            .saturating_add(1),
    );
    let mut segment = Vec::new();
    for (index, event) in events.iter().enumerate() {
        segment.push(
            crucible::test_support::condition_observation_entry_for_test(index as u64, event),
        );
    }
    segment.push(crucible::test_support::condition_boundary_entry_for_test(
        segment.len() as u64,
        boundary_at,
        SchedulerEvaluationBoundaryKind::Quantum,
    ));
    RecordedAssertionLog::from_segments(vec![segment]).map_err(|source| {
        EngineError::ScenarioSerialization {
            reason: format!("search retained assertion log failed: {source}"),
        }
    })
}

fn retained_boundary_log(at: VirtualTime) -> Result<RecordedAssertionLog, EngineError> {
    let segment = vec![crucible::test_support::condition_boundary_entry_for_test(
        0,
        at,
        SchedulerEvaluationBoundaryKind::Quantum,
    )];
    RecordedAssertionLog::from_segments(vec![segment]).map_err(|source| {
        EngineError::ScenarioSerialization {
            reason: format!("search retained boundary assertion log failed: {source}"),
        }
    })
}

fn empty_search_run_for_root(root: &Configuration) -> TemporalGraphSearchRun {
    TemporalGraphSearchRun {
        root: root.id(),
        strategy: SearchStrategy::BreadthFirst,
        budget: SearchBudget::new(1),
        explored_graph: BTreeSet::from([root.id()]),
        expansions: Vec::new(),
        discovered_failures: Vec::new(),
        exhausted: true,
    }
}

fn search_run_for_root_decision(
    root: &Configuration,
    decision: Decision,
) -> Result<(Configuration, TemporalGraphSearchRun), EngineError> {
    let child = try_step(root, decision.clone())?;
    let runtime = RuntimeState {
        id: root.id(),
        configuration: root.id(),
        node_blobs: BTreeMap::new(),
        node_icounts: BTreeMap::new(),
        scheduler: SchedulerState::empty(),
        event_log: EventLogOffset::default(),
    };
    let run = TemporalGraphSearchRun {
        root: root.id(),
        strategy: SearchStrategy::BreadthFirst,
        budget: SearchBudget::new(1),
        explored_graph: BTreeSet::from([root.id(), child.id()]),
        expansions: vec![SearchExpansion {
            sequence: 0,
            frontier: root.id(),
            depth: root.schedule.len(),
            search: TemporalGraphSearch {
                frontier: root.id(),
                frontier_runtime: TemporalGraphRuntime {
                    configuration: root.id(),
                    checkpoint: root.id(),
                    runtime,
                },
                frontier_report: FrontierReductionReport {
                    explored: vec![FrontierChild {
                        decision,
                        configuration: child.clone(),
                        already_recorded: false,
                    }],
                    covered: Vec::new(),
                },
                materialized: Vec::new(),
                replay_oracle_sampling: None,
            },
        }],
        discovered_failures: Vec::new(),
        exhausted: true,
    };
    Ok((child, run))
}

fn timed_delivery_decision(at: VirtualTime) -> Decision {
    Decision::DeliveryOrder(DeliveryOrderDecision {
        at,
        order: Vec::new(),
    })
}

fn node_id(name: impl Into<String>) -> NodeId {
    NodeId { name: name.into() }
}

fn time(ticks: u64) -> VirtualTime {
    VirtualTime { ticks }
}

fn icount(retired: u64) -> Icount {
    Icount { retired }
}
