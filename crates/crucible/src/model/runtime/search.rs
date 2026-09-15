//! Temporal-graph frontier search and failure discovery.

use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(in crate::model) struct SearchFrontierCandidate {
    pub(in crate::model) configuration: Configuration,
    pub(in crate::model) depth: usize,
}

impl SearchFrontierCandidate {
    pub(in crate::model) fn new(configuration: Configuration) -> Self {
        let depth = configuration.schedule.len();
        Self {
            configuration,
            depth,
        }
    }

    pub(in crate::model) fn id(&self) -> ContentHash {
        self.configuration.id()
    }
}

pub(in crate::model) fn select_search_frontier_candidate(
    graph: &TemporalGraph,
    worklist: &[SearchFrontierCandidate],
    strategy: SearchStrategy,
    max_depth: Option<u64>,
    guidance: Option<(&GuidanceSearchConfig, &GuidanceSearchState)>,
) -> Option<usize> {
    worklist
        .iter()
        .enumerate()
        .filter(|(_, candidate)| search_depth_allows_expansion(max_depth, candidate.depth))
        .min_by(|(_, left), (_, right)| match (strategy, guidance) {
            (SearchStrategy::CoverageGuided, Some((config, state))) => {
                compare_guided_search_frontier_candidates(graph, left, right, config, state)
            }
            _ => compare_search_frontier_candidates(graph, left, right, strategy),
        })
        .map(|(index, _)| index)
}

pub(in crate::model) fn search_depth_allows_expansion(
    max_depth: Option<u64>,
    depth: usize,
) -> bool {
    match max_depth {
        Some(max_depth) => (depth as u64) < max_depth,
        None => true,
    }
}

pub(in crate::model) fn select_fleet_work_stealing_candidate(
    worklist: &[SearchFrontierCandidate],
    host_count: u64,
    seed: Seed,
    sequence: u64,
) -> Option<usize> {
    let host_index = fleet_claim_host_index(host_count, seed, sequence);
    worklist
        .iter()
        .enumerate()
        .min_by_key(|(_, candidate)| {
            (
                fleet_work_stealing_score(seed, sequence, host_index, candidate),
                candidate.depth,
                candidate.id(),
            )
        })
        .map(|(index, _)| index)
}

pub(in crate::model) fn fleet_claim_host_index(host_count: u64, seed: Seed, sequence: u64) -> u64 {
    let host_count = host_count.max(1);
    let hash = ContentHash::from_canonical_material(
        "crucible.fleet-equivalence.claim-host.v1",
        &format!("seed={}\nsequence={sequence}\n", seed.to_hex()),
    );
    content_hash_low_u64(hash) % host_count
}

pub(in crate::model) fn fleet_work_stealing_score(
    seed: Seed,
    sequence: u64,
    host_index: u64,
    candidate: &SearchFrontierCandidate,
) -> ContentHash {
    ContentHash::from_canonical_material(
        "crucible.fleet-equivalence.claim-score.v1",
        &format!(
            "seed={}\nsequence={sequence}\nhost={host_index}\ndepth={}\nfrontier={}\n",
            seed.to_hex(),
            candidate.depth,
            candidate.id().to_hex()
        ),
    )
}

pub(in crate::model) fn compare_search_frontier_candidates(
    graph: &TemporalGraph,
    left: &SearchFrontierCandidate,
    right: &SearchFrontierCandidate,
    strategy: SearchStrategy,
) -> std::cmp::Ordering {
    match strategy {
        SearchStrategy::BreadthFirst => left
            .depth
            .cmp(&right.depth)
            .then_with(|| left.id().cmp(&right.id())),
        SearchStrategy::DepthFirst => right
            .depth
            .cmp(&left.depth)
            .then_with(|| left.id().cmp(&right.id())),
        SearchStrategy::Priority { seed } => search_priority_score(seed, left)
            .cmp(&search_priority_score(seed, right))
            .then_with(|| left.id().cmp(&right.id())),
        SearchStrategy::CoverageGuided => search_coverage_guided_key(graph, left)
            .cmp(&search_coverage_guided_key(graph, right))
            .then_with(|| left.id().cmp(&right.id())),
    }
}

pub(in crate::model) fn fleet_artifacts_are_byte_identical(
    single: &TemporalGraphSearchRun,
    fleet: &FleetWorkStealingSearchRun,
    single_finding_set: &BTreeSet<FleetFindingSetEntry>,
    fleet_finding_set: &BTreeSet<FleetFindingSetEntry>,
) -> bool {
    if single_finding_set != fleet_finding_set {
        return false;
    }
    let fleet_by_finding = fleet
        .discovered_failures
        .iter()
        .map(|failure| ((failure.fingerprint, failure.configuration), failure))
        .collect::<BTreeMap<_, _>>();

    single.discovered_failures.iter().all(|single_failure| {
        let key = (single_failure.fingerprint, single_failure.configuration);
        fleet_by_finding.get(&key).is_some_and(|fleet_failure| {
            single_failure
                .reproduction_artifact
                .artifact
                .canonical_bytes()
                == fleet_failure
                    .reproduction_artifact
                    .artifact
                    .canonical_bytes()
        })
    })
}

pub(in crate::model) fn fleet_equivalence_divergence(
    single: &TemporalGraphSearchRun,
    fleet: &FleetWorkStealingSearchRun,
    single_finding_set: &BTreeSet<FleetFindingSetEntry>,
    fleet_finding_set: &BTreeSet<FleetFindingSetEntry>,
) -> FleetEquivalenceDivergence {
    if single.root != fleet.root {
        return FleetEquivalenceDivergence {
            reason: "root-differs",
            fingerprint: None,
            configuration: Some(single.root),
            single_artifact: None,
            fleet_artifact: None,
            bisection: fleet_equivalence_bisection(single.root, "fleet-equivalence-root-differs"),
        };
    }
    if single.budget != fleet.config.total_budget {
        return FleetEquivalenceDivergence {
            reason: "budget-differs",
            fingerprint: None,
            configuration: Some(single.root),
            single_artifact: None,
            fleet_artifact: None,
            bisection: fleet_equivalence_bisection(single.root, "fleet-equivalence-budget-differs"),
        };
    }
    if single.explored_graph != fleet.explored_graph {
        let configuration = single
            .explored_graph
            .symmetric_difference(&fleet.explored_graph)
            .next()
            .copied()
            .unwrap_or(single.root);
        return FleetEquivalenceDivergence {
            reason: "explored-graph-differs",
            fingerprint: None,
            configuration: Some(configuration),
            single_artifact: None,
            fleet_artifact: None,
            bisection: fleet_equivalence_bisection(
                configuration,
                "fleet-equivalence-explored-graph-differs",
            ),
        };
    }
    if !single.exhausted || !fleet.exhausted {
        return FleetEquivalenceDivergence {
            reason: "not-exhausted",
            fingerprint: None,
            configuration: Some(single.root),
            single_artifact: None,
            fleet_artifact: None,
            bisection: fleet_equivalence_bisection(single.root, "fleet-equivalence-not-exhausted"),
        };
    }

    let single_by_finding = single
        .discovered_failures
        .iter()
        .map(|failure| ((failure.fingerprint, failure.configuration), failure))
        .collect::<BTreeMap<_, _>>();
    let fleet_by_finding = fleet
        .discovered_failures
        .iter()
        .map(|failure| ((failure.fingerprint, failure.configuration), failure))
        .collect::<BTreeMap<_, _>>();

    let mut keys = single_by_finding
        .keys()
        .chain(fleet_by_finding.keys())
        .copied()
        .collect::<BTreeSet<_>>();
    if keys.is_empty() {
        keys.extend(
            single_finding_set
                .iter()
                .chain(fleet_finding_set.iter())
                .map(|entry| (entry.fingerprint, entry.configuration)),
        );
    }

    for (fingerprint, configuration) in keys {
        let single_failure = single_by_finding.get(&(fingerprint, configuration));
        let fleet_failure = fleet_by_finding.get(&(fingerprint, configuration));
        match (single_failure, fleet_failure) {
            (Some(single_failure), Some(fleet_failure))
                if single_failure
                    .reproduction_artifact
                    .artifact
                    .canonical_bytes()
                    != fleet_failure
                        .reproduction_artifact
                        .artifact
                        .canonical_bytes() =>
            {
                return FleetEquivalenceDivergence {
                    reason: "artifact-bytes-differ",
                    fingerprint: Some(fingerprint),
                    configuration: Some(configuration),
                    single_artifact: Some(single_failure.reproduction_artifact.artifact.id()),
                    fleet_artifact: Some(fleet_failure.reproduction_artifact.artifact.id()),
                    bisection: fleet_equivalence_bisection(
                        configuration,
                        "fleet-equivalence-artifact-bytes-differ",
                    ),
                };
            }
            (Some(single_failure), None) => {
                return FleetEquivalenceDivergence {
                    reason: "missing-from-fleet",
                    fingerprint: Some(fingerprint),
                    configuration: Some(configuration),
                    single_artifact: Some(single_failure.reproduction_artifact.artifact.id()),
                    fleet_artifact: None,
                    bisection: fleet_equivalence_bisection(
                        configuration,
                        "fleet-equivalence-missing-from-fleet",
                    ),
                };
            }
            (None, Some(fleet_failure)) => {
                return FleetEquivalenceDivergence {
                    reason: "extra-in-fleet",
                    fingerprint: Some(fingerprint),
                    configuration: Some(configuration),
                    single_artifact: None,
                    fleet_artifact: Some(fleet_failure.reproduction_artifact.artifact.id()),
                    bisection: fleet_equivalence_bisection(
                        configuration,
                        "fleet-equivalence-extra-in-fleet",
                    ),
                };
            }
            (Some(_), Some(_)) | (None, None) => {}
        }
    }

    FleetEquivalenceDivergence {
        reason: "finding-set-differs",
        fingerprint: None,
        configuration: None,
        single_artifact: None,
        fleet_artifact: None,
        bisection: fleet_equivalence_bisection(
            single.root,
            "fleet-equivalence-finding-set-differs",
        ),
    }
}

pub(in crate::model) fn fleet_equivalence_bisection(
    configuration: ContentHash,
    reason: &'static str,
) -> SearchReplayOracleBisectionRequest {
    SearchReplayOracleBisectionRequest {
        sequence: 0,
        checkpoint: configuration,
        reason,
    }
}

pub(in crate::model) fn search_priority_score(
    seed: Seed,
    candidate: &SearchFrontierCandidate,
) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    hash = fold_fnv_bytes(hash, SEARCH_PRIORITY_SCORE_DOMAIN);
    hash = fold_fnv_bytes(hash, &seed.bytes());
    fold_fnv_bytes(hash, &(candidate.depth as u64).to_le_bytes())
}

pub(in crate::model) fn search_coverage_guided_key(
    graph: &TemporalGraph,
    candidate: &SearchFrontierCandidate,
) -> (u8, ContentHash) {
    let coverage = search_candidate_coverage_fingerprint(graph, &candidate.configuration);
    CoverageGuidanceSignal.search_order_key(GuidanceSignalInput {
        coverage_fingerprint: coverage,
        ..GuidanceSignalInput::default()
    })
}

pub(in crate::model) fn search_candidate_coverage_fingerprint(
    graph: &TemporalGraph,
    configuration: &Configuration,
) -> ContentHash {
    graph
        .cached_snapshots
        .get(&configuration.id())
        .or_else(|| graph.checkpoint_nodes.get(&configuration.id()))
        .map(|checkpoint| checkpoint.coverage_fingerprint)
        .unwrap_or_default()
}

pub(in crate::model) fn search_run_reached_configurations(
    root: &Configuration,
    run: &TemporalGraphSearchRun,
) -> Vec<Configuration> {
    let mut configurations = BTreeMap::from([(root.id(), root.clone())]);
    for expansion in &run.expansions {
        for child in &expansion.search.frontier_report.explored {
            configurations
                .entry(child.configuration.id())
                .or_insert_with(|| child.configuration.clone());
        }
        for covered in &expansion.search.frontier_report.covered {
            configurations
                .entry(covered.configuration.id())
                .or_insert_with(|| covered.configuration.clone());
        }
    }
    configurations.into_values().collect()
}

pub(in crate::model) fn search_assertion_failure_fingerprint<O>(
    scenario: &ScenarioDefForm,
    configuration: &Configuration,
    oracle: &mut O,
    predicate_scope: SearchAssertionPredicateScope,
) -> Result<Option<ContentHash>, EngineError>
where
    O: HostAssertionOracle + ?Sized,
{
    let recorded = recorded_assertion_log_from_schedule_for_search(&configuration.schedule)
        .map_err(|source| {
            scenario_serialization_error(format!(
                "search assertion retained log reconstruction failed: {source}"
            ))
        })?;
    search_assertion_failure_fingerprint_from_recorded_log(
        scenario,
        configuration,
        &recorded,
        oracle,
        predicate_scope,
    )
}

pub(in crate::model) fn validate_search_configuration_scenario(
    scenario: &ScenarioDefForm,
    configuration: &Configuration,
) -> Result<(), EngineError> {
    let scenario_id = scenario.scenario_def().id;
    if configuration.def.id != scenario_id {
        return Err(EngineError::ReproductionScenarioMismatch {
            expected: scenario_id,
            actual: configuration.def.id,
        });
    }
    Ok(())
}

pub(in crate::model) fn search_assertion_finding<O>(
    scenario: &ScenarioDefForm,
    configuration: &Configuration,
    oracle: &mut O,
    predicate_scope: SearchAssertionPredicateScope,
) -> Result<Option<SearchAssertionFinding>, EngineError>
where
    O: HostAssertionOracle + ?Sized,
{
    let recorded = recorded_assertion_log_from_schedule_for_search(&configuration.schedule)
        .map_err(|source| {
            scenario_serialization_error(format!(
                "search assertion retained log reconstruction failed: {source}"
            ))
        })?;
    search_assertion_finding_from_recorded_log(
        scenario,
        configuration,
        &recorded,
        oracle,
        predicate_scope,
    )
}

fn search_assertion_finding_from_recorded_log<O>(
    scenario: &ScenarioDefForm,
    configuration: &Configuration,
    recorded: &RecordedAssertionLog,
    oracle: &mut O,
    predicate_scope: SearchAssertionPredicateScope,
) -> Result<Option<SearchAssertionFinding>, EngineError>
where
    O: HostAssertionOracle + ?Sized,
{
    let report = OfflineAssertionChecker::new()
        .with_world_white_box_policies(scenario.world())
        .check_run_with_oracle(scenario.properties(), recorded, oracle)
        .map_err(|source| {
            scenario_serialization_error(format!("search assertion check failed: {source}"))
        })?;
    search_assertion_finding_from_report(
        scenario,
        configuration,
        &report,
        predicate_scope,
        None,
        false,
    )
}

pub(in crate::model) fn search_assertion_finding_from_retained_log(
    scenario: &ScenarioDefForm,
    configuration: &Configuration,
    recorded: &RecordedAssertionLog,
    resolutions: &SearchRetainedLogPredicateResolutions,
    terminal_quiescence: Option<&SchedulerQuiescence>,
) -> Result<Option<SearchAssertionFinding>, EngineError> {
    let mut checker = OfflineAssertionChecker::new()
        .with_world_white_box_policies(scenario.world())
        .with_resolved_code_points(
            resolutions
                .code_points
                .iter()
                .map(|(key, value)| ((key.0.clone(), key.1.clone()), *value)),
        )
        .with_resolved_mem_places(
            resolutions
                .mem_places
                .iter()
                .map(|(key, value)| ((key.0.clone(), key.1.clone()), value.clone())),
        );
    if let Some(quiescence) = terminal_quiescence.cloned() {
        checker = checker.with_terminal_scheduler_quiescence(quiescence);
    }
    let report = checker
        .check_run(scenario.properties(), recorded.entries())
        .map_err(|source| {
            scenario_serialization_error(format!(
                "search retained assertion check failed: {source}"
            ))
        })?;
    search_assertion_finding_from_report(
        scenario,
        configuration,
        &report,
        SearchAssertionPredicateScope::RetainedLog,
        Some(resolutions),
        terminal_quiescence.is_some_and(SchedulerQuiescence::is_quiescent),
    )
}

fn search_assertion_finding_from_report(
    scenario: &ScenarioDefForm,
    configuration: &Configuration,
    report: &HostAssertionReport,
    predicate_scope: SearchAssertionPredicateScope,
    resolutions: Option<&SearchRetainedLogPredicateResolutions>,
    terminal_quiescent: bool,
) -> Result<Option<SearchAssertionFinding>, EngineError> {
    let Some(outcome) = report.outcomes().iter().find(|outcome| {
        prefix_safe_search_assertion_failure(
            scenario.properties(),
            outcome,
            predicate_scope,
            resolutions,
            terminal_quiescent,
        )
    }) else {
        return Ok(None);
    };
    let mut violation = report
        .violations()
        .iter()
        .find(|violation| violation.assertion == outcome.assertion)
        .cloned()
        .ok_or_else(|| {
            unified_operation_evidence_mismatch(
                "search-assertion-evaluation",
                "failure-outcome-without-violation",
            )
        })?;
    violation.reproduction_artifact = ContentHash::default();
    Ok(Some(SearchAssertionFinding {
        fingerprint: search_assertion_outcome_fingerprint(configuration.id(), outcome),
        violation,
    }))
}

pub(in crate::model) fn search_assertion_failure_fingerprint_from_recorded_log<O>(
    scenario: &ScenarioDefForm,
    configuration: &Configuration,
    recorded: &RecordedAssertionLog,
    oracle: &mut O,
    predicate_scope: SearchAssertionPredicateScope,
) -> Result<Option<ContentHash>, EngineError>
where
    O: HostAssertionOracle + ?Sized,
{
    let report = OfflineAssertionChecker::new()
        .with_world_white_box_policies(scenario.world())
        .check_run_with_oracle(scenario.properties(), recorded, oracle)
        .map_err(|source| {
            scenario_serialization_error(format!("search assertion check failed: {source}"))
        })?;
    Ok(report
        .outcomes()
        .iter()
        .find(|outcome| {
            prefix_safe_search_assertion_failure(
                scenario.properties(),
                outcome,
                predicate_scope,
                None,
                false,
            )
        })
        .map(|outcome| search_assertion_outcome_fingerprint(configuration.id(), outcome)))
}

pub(in crate::model) fn search_assertion_failure_fingerprint_from_retained_log(
    scenario: &ScenarioDefForm,
    configuration: &Configuration,
    recorded: &RecordedAssertionLog,
    resolutions: &SearchRetainedLogPredicateResolutions,
    terminal_quiescence: Option<&SchedulerQuiescence>,
) -> Result<Option<ContentHash>, EngineError> {
    let mut checker = OfflineAssertionChecker::new()
        .with_world_white_box_policies(scenario.world())
        .with_resolved_code_points(
            resolutions
                .code_points
                .iter()
                .map(|(key, value)| ((key.0.clone(), key.1.clone()), *value)),
        )
        .with_resolved_mem_places(
            resolutions
                .mem_places
                .iter()
                .map(|(key, value)| ((key.0.clone(), key.1.clone()), value.clone())),
        );
    if let Some(quiescence) = terminal_quiescence.cloned() {
        checker = checker.with_terminal_scheduler_quiescence(quiescence);
    }
    let report = checker
        .check_run(scenario.properties(), recorded.entries())
        .map_err(|source| {
            scenario_serialization_error(format!(
                "search retained assertion check failed: {source}"
            ))
        })?;
    Ok(report
        .outcomes()
        .iter()
        .find(|outcome| {
            prefix_safe_search_assertion_failure(
                scenario.properties(),
                outcome,
                SearchAssertionPredicateScope::RetainedLog,
                Some(resolutions),
                terminal_quiescence.is_some_and(SchedulerQuiescence::is_quiescent),
            )
        })
        .map(|outcome| search_assertion_outcome_fingerprint(configuration.id(), outcome)))
}

pub(in crate::model) fn search_assertion_failure_fingerprint_with_named_truths(
    scenario: &ScenarioDefForm,
    configuration: &Configuration,
    oracle: &mut SearchScheduleNamedPredicateHostOracle<'_>,
) -> Result<Option<ContentHash>, EngineError> {
    oracle.clear_missing_truths();
    let fingerprint = search_assertion_failure_fingerprint(
        scenario,
        configuration,
        oracle,
        SearchAssertionPredicateScope::ScheduleAndNamedTruths,
    )?;
    if oracle.has_missing_truths() {
        return Ok(None);
    }
    Ok(fingerprint)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(in crate::model) enum SearchAssertionPredicateScope {
    ScheduleOnly,
    ScheduleAndNamedTruths,
    RetainedLog,
}

pub(in crate::model) fn prefix_safe_search_assertion_failure(
    properties: &Properties,
    outcome: &HostAssertionOutcome,
    predicate_scope: SearchAssertionPredicateScope,
    resolutions: Option<&SearchRetainedLogPredicateResolutions>,
    terminal_quiescent: bool,
) -> bool {
    let retained_scope = predicate_scope == SearchAssertionPredicateScope::RetainedLog;
    let terminal_complete_retained_quantifier = predicate_scope
        == SearchAssertionPredicateScope::RetainedLog
        && terminal_quiescent
        && matches!(
            outcome.quantifier,
            AssertionQuantifierKind::AfterQuiescence
                | AssertionQuantifierKind::Sometimes
                | AssertionQuantifierKind::Eventually
                | AssertionQuantifierKind::GuestSometimes
        );
    let supported_quantifier = matches!(
        outcome.quantifier,
        AssertionQuantifierKind::Always | AssertionQuantifierKind::Reachable
    ) || terminal_complete_retained_quantifier;
    let terminal_complete_retained_reachability_failure = predicate_scope
        == SearchAssertionPredicateScope::RetainedLog
        && terminal_quiescent
        && matches!(
            outcome.quantifier,
            AssertionQuantifierKind::Reachable | AssertionQuantifierKind::GuestReachable
        )
        && outcome.kind == HostAssertionOutcomeKind::NeverReachedFail;
    let supported_failure_kind = outcome.kind == HostAssertionOutcomeKind::Violated
        || terminal_complete_retained_reachability_failure;
    let event_backed_retained_guest_marker_failure = retained_scope
        && matches!(
            outcome.quantifier,
            AssertionQuantifierKind::GuestAlways | AssertionQuantifierKind::GuestUnreachable
        )
        && outcome.kind == HostAssertionOutcomeKind::Violated;
    let terminal_retained_guest_marker_failure = retained_scope
        && terminal_quiescent
        && (outcome.quantifier == AssertionQuantifierKind::GuestSometimes
            && outcome.kind == HostAssertionOutcomeKind::Violated
            || outcome.quantifier == AssertionQuantifierKind::GuestReachable
                && outcome.kind == HostAssertionOutcomeKind::NeverReachedFail);
    let retained_guest_marker_failure =
        event_backed_retained_guest_marker_failure || terminal_retained_guest_marker_failure;
    let allow_terminal_quiescence_predicates = predicate_scope
        == SearchAssertionPredicateScope::RetainedLog
        && terminal_quiescent
        && outcome.quantifier == AssertionQuantifierKind::AfterQuiescence;
    supported_failure_kind
        && (retained_guest_marker_failure
            || supported_quantifier
                && assertion_uses_only_search_schedule_predicates(
                    properties,
                    &outcome.assertion,
                    predicate_scope,
                    resolutions,
                    allow_terminal_quiescence_predicates,
                ))
}

pub(in crate::model) fn assertion_uses_only_search_schedule_predicates(
    properties: &Properties,
    assertion: &AssertionId,
    predicate_scope: SearchAssertionPredicateScope,
    resolutions: Option<&SearchRetainedLogPredicateResolutions>,
    allow_terminal_quiescence_predicates: bool,
) -> bool {
    properties
        .assertions()
        .iter()
        .find(|candidate| &candidate.id == assertion)
        .is_some_and(|candidate| {
            property_uses_only_search_schedule_predicates(
                &candidate.property,
                predicate_scope,
                resolutions,
                allow_terminal_quiescence_predicates,
            )
        })
}

pub(in crate::model) fn property_uses_only_search_schedule_predicates(
    property: &Property,
    predicate_scope: SearchAssertionPredicateScope,
    resolutions: Option<&SearchRetainedLogPredicateResolutions>,
    allow_terminal_quiescence_predicates: bool,
) -> bool {
    match property {
        Property::Always { predicate }
        | Property::Sometimes { predicate }
        | Property::Reachable { predicate, .. } => predicate_uses_only_search_schedule_predicates(
            predicate,
            predicate_scope,
            resolutions,
            false,
        ),
        Property::AfterQuiescence { predicate } => predicate_uses_only_search_schedule_predicates(
            predicate,
            predicate_scope,
            resolutions,
            allow_terminal_quiescence_predicates,
        ),
        Property::Eventually {
            trigger, property, ..
        } => {
            predicate_uses_only_search_schedule_predicates(
                trigger,
                predicate_scope,
                resolutions,
                false,
            ) && predicate_uses_only_search_schedule_predicates(
                property,
                predicate_scope,
                resolutions,
                false,
            )
        }
    }
}

pub(in crate::model) fn predicate_uses_only_search_schedule_predicates(
    predicate: &Predicate,
    predicate_scope: SearchAssertionPredicateScope,
    resolutions: Option<&SearchRetainedLogPredicateResolutions>,
    allow_terminal_quiescence_predicates: bool,
) -> bool {
    match predicate {
        Predicate::Named { .. } => {
            predicate_scope == SearchAssertionPredicateScope::ScheduleAndNamedTruths
        }
        Predicate::AllOf { predicates } | Predicate::AnyOf { predicates } => {
            predicates.iter().all(|predicate| {
                predicate_uses_only_search_schedule_predicates(
                    predicate,
                    predicate_scope,
                    resolutions,
                    allow_terminal_quiescence_predicates,
                )
            })
        }
        Predicate::Once { predicate } | Predicate::Not { predicate } => {
            predicate_uses_only_search_schedule_predicates(
                predicate,
                predicate_scope,
                resolutions,
                allow_terminal_quiescence_predicates,
            )
        }
        Predicate::At { .. }
        | Predicate::After { .. }
        | Predicate::Timer { .. }
        | Predicate::NetworkMatch { .. }
        | Predicate::ConsoleMatch { .. }
        | Predicate::IoPattern { .. }
        | Predicate::NodeState { .. }
        | Predicate::AssertionState { .. }
        | Predicate::GuestMarker { .. } => {
            predicate_scope == SearchAssertionPredicateScope::RetainedLog
        }
        Predicate::CoveragePoint {
            point: CodePoint::GuestAddress { .. },
            ..
        } => predicate_scope == SearchAssertionPredicateScope::RetainedLog,
        Predicate::CoveragePoint { node, point } => {
            predicate_scope == SearchAssertionPredicateScope::RetainedLog
                && resolutions
                    .is_some_and(|resolutions| resolutions.resolves_code_point(node, point))
        }
        Predicate::MemoryPredicate {
            place: MemPlace::PhysicalAddress { .. } | MemPlace::Register { .. },
            ..
        } => predicate_scope == SearchAssertionPredicateScope::RetainedLog,
        Predicate::MemoryPredicate { node, place, .. } => {
            predicate_scope == SearchAssertionPredicateScope::RetainedLog
                && resolutions
                    .is_some_and(|resolutions| resolutions.resolves_mem_place(node, place))
        }
        Predicate::Quiescent => {
            predicate_scope == SearchAssertionPredicateScope::RetainedLog
                && allow_terminal_quiescence_predicates
        }
    }
}

pub(in crate::model) fn search_assertion_outcome_fingerprint(
    configuration: ContentHash,
    outcome: &HostAssertionOutcome,
) -> ContentHash {
    ContentHash::from_canonical_material(
        "crucible.search.assertion-failure.v1",
        &search_assertion_outcome_fingerprint_material(configuration, outcome),
    )
}

pub(in crate::model) fn search_assertion_outcome_fingerprint_material(
    configuration: ContentHash,
    outcome: &HostAssertionOutcome,
) -> String {
    format!(
        "configuration={}\nassertion={}\nquantifier={}\nkind={:?}\nlifecycle={:?}\nat={}\nmessage={}\nreason={}",
        content_hash_hex(configuration),
        outcome.assertion.name,
        failure_assertion_quantifier_label(outcome.quantifier),
        outcome.kind,
        outcome.lifecycle,
        outcome.at.ticks,
        outcome.message,
        outcome.reason
    )
}

pub(in crate::model) fn record_search_discovered_failure(
    configuration: &Configuration,
    scenario: Option<&ScenarioDefForm>,
    failure_oracle: &SearchFailureOracle,
    discovered_configurations: &mut BTreeSet<ContentHash>,
    discovered_failures: &mut Vec<SearchDiscoveredFailure>,
) -> Result<(), EngineError> {
    let configuration_id = configuration.id();
    if let Some(fingerprint) = failure_oracle.failure_for(configuration_id)
        && discovered_configurations.insert(configuration_id)
    {
        let scenario = scenario.ok_or(EngineError::ReproductionScenarioMismatch {
            expected: configuration.def.id,
            actual: ContentHash::default(),
        })?;
        let reproduction_artifact = FindingReproductionArtifact::capture(
            FindingDiscoveryPath::StateSpaceSearch,
            fingerprint,
            scenario,
            configuration,
        )?;
        discovered_failures.push(SearchDiscoveredFailure {
            configuration: configuration_id,
            fingerprint,
            reproduction_artifact,
        });
    }
    Ok(())
}

pub(in crate::model) fn search_frontier_choices(
    runtime: &RuntimeState,
) -> Vec<SearchFrontierChoice> {
    runtime.scheduler.search_frontier.choices().to_vec()
}

pub(in crate::model) fn is_genuine_search_frontier_decision(decision: &Decision) -> bool {
    match decision {
        Decision::DeliveryOrder(_) => false,
        Decision::RngDraw(_) | Decision::Override(_) => true,
        Decision::Preemption(_) | Decision::Selection(_) => false,
    }
}
