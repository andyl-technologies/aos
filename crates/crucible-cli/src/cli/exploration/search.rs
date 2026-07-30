//! Temporal-graph search, failure-oracle, and counterexample reporting.

use super::*;

#[cfg(any(test, feature = "test-double"))]
pub(crate) fn run_local_double_search_workflow(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    plan: &SearchDriverPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let scenario = plan.scenario.scenario_def().clone();
    let root = crucible::Configuration::genesis(scenario.clone());
    let mut graph = save_validation_graph(&scenario)?;
    run_local_double_search_workflow_with_graph(
        thin_plan,
        backend_plan,
        ergonomics_plan,
        plan,
        &root,
        &mut graph,
    )
}

#[cfg(any(test, feature = "test-double"))]
pub(crate) fn run_local_double_search_workflow_with_graph(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    plan: &SearchDriverPlan,
    // crucible-lint: allow host-nondeterminism-state -- the supplied canonical root is validated by the temporal graph before exploration.
    root: &crucible::Configuration,
    graph: &mut ValidationDag,
) -> Result<BackendCommandOutcome, CliError> {
    run_search_workflow_with_graph(thin_plan, backend_plan, ergonomics_plan, plan, root, graph)
        .map(|(outcome, _)| outcome)
}

#[cfg(any(test, feature = "test-double"))]
pub(crate) fn run_search_workflow_with_graph(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    plan: &SearchDriverPlan,
    // crucible-lint: allow host-nondeterminism-state -- the canonical root crosses only into the replay-validated graph driver.
    root: &crucible::Configuration,
    graph: &mut ValidationDag,
) -> Result<(BackendCommandOutcome, crucible::TemporalGraphSearchRun), CliError> {
    let empty_failure_oracle = SearchFailureOracle::none();
    let assertion_discovery_run = graph
        .search_with_strategy_and_failure_oracle_bounded_depth(
            plan.scenario.scenario_form(),
            root,
            plan.engine_strategy,
            plan.budget,
            MaterializationPolicy::with_budget(search_materialization_budget(plan.max_states)),
            MaterializationTrigger::RepeatedForkSource,
            &empty_failure_oracle,
            plan.max_depth,
        )
        .map_err(|error| backend_error(format!("local-double assertion search failed: {error}")))?;
    let failure_oracle = match (&plan.schedule_named_truths, &plan.retained_evidence) {
        (None, Some(retained_evidence)) => {
            let schedule_oracle = SearchFailureOracle::from_search_assertion_violations(
                plan.scenario.scenario_form(),
                root,
                &assertion_discovery_run,
            )
            .map_err(|error| {
                backend_error(format!("local-double assertion lowering failed: {error}"))
            })?;
            let retained_oracle =
                SearchFailureOracle::from_search_assertion_violations_with_retained_log_evidence(
                    plan.scenario.scenario_form(),
                    root,
                    &assertion_discovery_run,
                    |configuration| retained_evidence.evidence.get(&configuration.id()).cloned(),
                )
                .map_err(|error| {
                    backend_error(format!("local-double assertion lowering failed: {error}"))
                })?;
            merge_search_failure_oracles(
                std::iter::once(root.id())
                    .chain(assertion_discovery_run.explored_graph.iter().copied()),
                &schedule_oracle,
                &retained_oracle,
            )
        }
        (Some(named_truths), None) => {
            SearchFailureOracle::from_search_assertion_violations_with_named_predicates(
                plan.scenario.scenario_form(),
                root,
                &assertion_discovery_run,
                &named_truths.truths,
            )
            .map_err(|error| {
                backend_error(format!("local-double assertion lowering failed: {error}"))
            })?
        }
        (None, None) => SearchFailureOracle::from_search_assertion_violations(
            plan.scenario.scenario_form(),
            root,
            &assertion_discovery_run,
        )
        .map_err(|error| {
            backend_error(format!("local-double assertion lowering failed: {error}"))
        })?,
        (Some(_), Some(_)) => {
            return Err(backend_error(
                "local-double search retained evidence cannot be combined with schedule-named truths",
            ));
        }
    };
    let failure_oracle_label = if failure_oracle.is_empty() {
        "none"
    } else if plan.retained_evidence.is_some() {
        "scenario-assertions+retained-evidence"
    } else if plan.schedule_named_truths.is_some() {
        "scenario-assertions+schedule-named-truths"
    } else {
        "scenario-assertions"
    };
    run_search_workflow_with_graph_and_failure_oracle(
        thin_plan,
        backend_plan,
        ergonomics_plan,
        plan,
        root,
        graph,
        &failure_oracle,
        failure_oracle_label,
    )
}

#[cfg(any(test, feature = "test-double"))]
pub(crate) fn merge_search_failure_oracles<I>(
    reached: I,
    schedule_oracle: &SearchFailureOracle,
    retained_oracle: &SearchFailureOracle,
) -> SearchFailureOracle
where
    I: IntoIterator<Item = crucible::ContentHash>,
{
    let mut merged = SearchFailureOracle::none();
    for configuration in reached {
        if let Some(fingerprint) = schedule_oracle.failure_for(configuration) {
            merged = merged.with_failure(configuration, fingerprint);
        }
        if let Some(fingerprint) = retained_oracle.failure_for(configuration) {
            merged = merged.with_failure(configuration, fingerprint);
        }
    }
    merged
}

#[cfg(test)]
// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_local_double_search_workflow_with_graph_and_failure_oracle(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    plan: &SearchDriverPlan,
    root: &crucible::Configuration,
    graph: &mut ValidationDag,
    failure_oracle: &SearchFailureOracle,
    failure_oracle_label: &str,
) -> Result<BackendCommandOutcome, CliError> {
    run_search_workflow_with_graph_and_failure_oracle(
        thin_plan,
        backend_plan,
        ergonomics_plan,
        plan,
        root,
        graph,
        failure_oracle,
        failure_oracle_label,
    )
    .map(|(outcome, _)| outcome)
}

#[cfg(any(test, feature = "test-double"))]
// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::too_many_arguments)]
pub(crate) fn run_search_workflow_with_graph_and_failure_oracle(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    plan: &SearchDriverPlan,
    root: &crucible::Configuration,
    graph: &mut ValidationDag,
    failure_oracle: &SearchFailureOracle,
    failure_oracle_label: &str,
) -> Result<(BackendCommandOutcome, crucible::TemporalGraphSearchRun), CliError> {
    let sampling_config =
        crucible::SearchReplayOracleSamplingConfig::new(1, 1, "cli-local-double-search")
            .map_err(|error| backend_error(format!("local-double search setup failed: {error}")))?;
    let sampled = graph
        .search_with_strategy_and_failure_oracle_bounded_depth_sampled(
            plan.scenario.scenario_form(),
            root,
            plan.engine_strategy,
            plan.budget,
            MaterializationPolicy::with_budget(search_materialization_budget(plan.max_states)),
            MaterializationTrigger::RepeatedForkSource,
            failure_oracle,
            plan.max_depth,
            &sampling_config,
        )
        .map_err(|error| backend_error(format!("local-double search failed: {error}")))?;
    let run = sampled.run;
    let counterexample_artifact = run
        .discovered_failures
        .first()
        .map(|failure| search_failure_reproduction_artifact_bytes(backend_plan, plan, failure))
        .transpose()?;
    let counterexample = run
        .discovered_failures
        .first()
        .zip(counterexample_artifact.as_ref())
        .map(|(failure, artifact)| LocalDoubleSearchCounterexample {
            configuration: failure.configuration,
            fingerprint: failure.fingerprint,
            artifact_digest: content_address_bytes(artifact),
        });
    let report = LocalDoubleSearchReport {
        root: run.root,
        expansions: run.expansions.len(),
        explored: run.explored_graph.len(),
        failures: run.discovered_failures.len(),
        exhausted: run.exhausted,
        failure_oracle: failure_oracle_label.to_string(),
        schedule_named_truths: plan
            .schedule_named_truths
            .as_ref()
            .map(|source| source.path.display().to_string())
            .unwrap_or_else(|| String::from("none")),
        schedule_named_truths_digest: plan
            .schedule_named_truths
            .as_ref()
            .map(|source| source.digest.clone())
            .unwrap_or_else(|| String::from("none")),
        retained_evidence: plan
            .retained_evidence
            .as_ref()
            .map(|source| source.path.display().to_string())
            .unwrap_or_else(|| String::from("none")),
        retained_evidence_digest: plan
            .retained_evidence
            .as_ref()
            .map(|source| source.digest.clone())
            .unwrap_or_else(|| String::from("none")),
        counterexample,
        replay_oracle_considered: sampled.replay_oracle_sampling.considered,
        replay_oracle_sampled: sampled.replay_oracle_sampling.sampled,
        replay_oracle_skipped: sampled.replay_oracle_sampling.skipped,
    };
    let mut outcome = backend_command_outcome(thin_plan, backend_plan, ergonomics_plan);
    if let Some(artifact) = counterexample_artifact {
        outcome.artifact_digest = content_address_bytes(&artifact);
        outcome.reproduction_artifact = Some(artifact);
    }
    apply_local_double_search_report(&mut outcome, plan, &report);
    Ok((outcome, run))
}

#[cfg(any(test, feature = "test-double"))]
pub(crate) fn search_materialization_budget(max_states: u64) -> usize {
    match usize::try_from(max_states) {
        Ok(max_states) => max_states,
        Err(_) => usize::MAX,
    }
}

pub(crate) fn search_failure_reproduction_artifact_bytes(
    backend_plan: &BackendSelectionPlan,
    plan: &SearchDriverPlan,
    failure: &SearchDiscoveredFailure,
) -> Result<Vec<u8>, CliError> {
    let mut canonical_log = canonical_log_entries_from_search_failure(failure);
    let mut extra_payloads = search_extra_artifact_payloads(plan, &mut canonical_log);
    extra_payloads.extend(model_reproduction_artifact_payloads(
        &failure.reproduction_artifact.artifact,
        failure.reproduction_artifact.replay.state,
    ));
    let fingerprint_digest = cli_digest_from_engine_hash(failure.fingerprint);
    let fingerprint_samples = vec![VerifyFingerprintSample {
        index: 0,
        instruction: 0,
        node: String::from("search"),
        digest: fingerprint_digest,
    }];
    verify_reproduction_artifact_bytes_with_components(
        seed_to_u64(plan.scenario.scenario_def().seed()),
        backend_plan.resolved_backend.as_ref(),
        plan.scenario.scenario_def(),
        &canonical_log,
        &fingerprint_samples,
        &extra_payloads,
    )
}

pub(crate) fn search_extra_artifact_payloads(
    plan: &SearchDriverPlan,
    canonical_log: &mut Vec<CanonicalLogEntry>,
) -> Vec<ReproductionArtifactComponentPayload> {
    let mut payloads = Vec::new();
    if let Some(source) = &plan.schedule_named_truths {
        canonical_log.push(CanonicalLogEntry {
            sequence: canonical_log.len() as u64,
            virtual_time_ticks: canonical_log.len() as u64,
            node: String::from("search"),
            kind: String::from("search-schedule-named-truths"),
            summary: format!(
                "schema={} source={} digest={}",
                SEARCH_SCHEDULE_NAMED_TRUTHS_SCHEMA,
                source.path.display(),
                source.digest
            ),
        });
        payloads.push(ReproductionArtifactComponentPayload {
            kind: String::from("search_schedule_named_truths"),
            name: String::from("schedule-named-truths.toml"),
            media_type: String::from(SEARCH_SCHEDULE_NAMED_TRUTHS_MEDIA_TYPE),
            bytes: source.material.clone(),
        });
    }
    if let Some(source) = &plan.retained_evidence {
        canonical_log.push(CanonicalLogEntry {
            sequence: canonical_log.len() as u64,
            virtual_time_ticks: canonical_log.len() as u64,
            node: String::from("search"),
            kind: String::from("search-retained-evidence"),
            summary: format!(
                "schema={} source={} digest={}",
                SEARCH_RETAINED_EVIDENCE_SCHEMA,
                source.path.display(),
                source.digest
            ),
        });
        payloads.push(ReproductionArtifactComponentPayload {
            kind: String::from("search_retained_evidence"),
            name: String::from("retained-evidence.toml"),
            media_type: String::from(SEARCH_RETAINED_EVIDENCE_MEDIA_TYPE),
            bytes: source.material.clone(),
        });
    }
    payloads
}

pub(crate) fn canonical_log_entries_from_search_failure(
    failure: &SearchDiscoveredFailure,
) -> Vec<CanonicalLogEntry> {
    let entries = canonical_log_entries_from_engine_schedule(
        failure.reproduction_artifact.artifact.schedule(),
    );
    if !entries.is_empty() {
        return entries;
    }

    vec![CanonicalLogEntry {
        sequence: 0,
        virtual_time_ticks: 0,
        node: String::from("search"),
        kind: String::from("root-failure"),
        summary: format!(
            "configuration={} fingerprint={} discovery=state-space-search",
            format_content_hash_ref(failure.configuration),
            format_content_hash_ref(failure.fingerprint)
        ),
    }]
}

pub(crate) fn canonical_log_entries_from_engine_schedule(
    schedule: &crucible::Schedule,
) -> Vec<CanonicalLogEntry> {
    schedule
        .decisions()
        .iter()
        .enumerate()
        .map(|(index, decision)| CanonicalLogEntry {
            sequence: index as u64,
            virtual_time_ticks: index as u64 + 1,
            node: String::from("search"),
            kind: engine_decision_kind(decision).to_string(),
            summary: format!("{decision:?}"),
        })
        .collect()
}

pub(crate) fn engine_decision_kind(decision: &crucible::Decision) -> &'static str {
    match decision {
        crucible::Decision::DeliveryOrder(_) => "delivery-order",
        crucible::Decision::FaultFires(_) => "fault-fires",
        crucible::Decision::RngDraw(_) => "rng-draw",
        crucible::Decision::Override(_) => "override",
        crucible::Decision::Preemption(_) => "preemption",
        crucible::Decision::AppRandom(_) => "app-random",
        crucible::Decision::ControlFault(_) => "control-fault",
    }
}

pub(crate) fn cli_digest_from_engine_hash(hash: crucible::ContentHash) -> String {
    format!("{CONTENT_ADDRESS_PREFIX}{}", hash.to_hex())
}

pub(crate) fn apply_local_double_search_report(
    outcome: &mut BackendCommandOutcome,
    plan: &SearchDriverPlan,
    report: &LocalDoubleSearchReport,
) {
    let budget_exhausted = !report.exhausted;
    let status =
        local_double_search_status(report.failures > 0, report.exhausted, plan.on_violation);
    outcome.status = status;
    outcome.exit_code = status.exit_code();
    let (counterexample_stdout, counterexample_summary) =
        local_double_search_counterexample_fields(report.counterexample.as_ref());
    outcome.stdout.push(format!(
        "search-run\tscenario={}\troot={}\tstrategy={}\tmax_states={}\tmax_depth={}\tfailure_oracle={}\tschedule_named_truths={}\tschedule_named_truths_digest={}\tretained_evidence={}\tretained_evidence_digest={}\treplay_oracle_sampling=1/1\treplay_oracle_considered={}\treplay_oracle_sampled={}\treplay_oracle_skipped={}\ton_violation={}\texpansions={}\texplored={}\tfailures={}{}\texhausted={}\tbudget_exhausted={}\tstatus={}",
        plan.scenario.label(),
        format_content_hash_ref(report.root),
        plan.strategy_arg.label(),
        plan.max_states,
        plan.max_depth
            .map(|depth| depth.to_string())
            .unwrap_or_else(|| String::from("none")),
        report.failure_oracle,
        report.schedule_named_truths,
        report.schedule_named_truths_digest,
        report.retained_evidence,
        report.retained_evidence_digest,
        report.replay_oracle_considered,
        report.replay_oracle_sampled,
        report.replay_oracle_skipped,
        plan.on_violation.label(),
        report.expansions,
        report.explored,
        report.failures,
        counterexample_stdout,
        report.exhausted,
        budget_exhausted,
        status.label()
    ));
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: outcome.canonical_log.len() as u64,
        node: String::from("search"),
        kind: String::from("search_strategy_run"),
        summary: format!(
            "root={} strategy={} max_states={} max_depth={} failure_oracle={} schedule_named_truths={} schedule_named_truths_digest={} retained_evidence={} retained_evidence_digest={} replay_oracle_sampling=1/1 replay_oracle_considered={} replay_oracle_sampled={} replay_oracle_skipped={} on_violation={} expansions={} explored={} failures={}{} exhausted={} budget_exhausted={} status={}",
            format_content_hash_ref(report.root),
            plan.strategy_arg.label(),
            plan.max_states,
            plan.max_depth
                .map(|depth| depth.to_string())
                .unwrap_or_else(|| String::from("none")),
            report.failure_oracle,
            report.schedule_named_truths,
            report.schedule_named_truths_digest,
            report.retained_evidence,
            report.retained_evidence_digest,
            report.replay_oracle_considered,
            report.replay_oracle_sampled,
            report.replay_oracle_skipped,
            plan.on_violation.label(),
            report.expansions,
            report.explored,
            report.failures,
            counterexample_summary,
            report.exhausted,
            budget_exhausted,
            status.label()
        ),
    });
    outcome.canonical_log_digest = canonical_log_digest(&outcome.canonical_log);
}

pub(crate) fn local_double_search_counterexample_fields(
    counterexample: Option<&LocalDoubleSearchCounterexample>,
) -> (String, String) {
    let Some(counterexample) = counterexample else {
        return (String::new(), String::new());
    };
    let counterexample_configuration = format_content_hash_ref(counterexample.configuration);
    let counterexample_fingerprint = format_content_hash_ref(counterexample.fingerprint);
    let counterexample_artifact = &counterexample.artifact_digest;
    (
        format!(
            "\tcounterexample={}\tcounterexample_fingerprint={}\tcounterexample_artifact={}",
            counterexample_configuration, counterexample_fingerprint, counterexample_artifact
        ),
        format!(
            " counterexample={} counterexample_fingerprint={} counterexample_artifact={}",
            counterexample_configuration, counterexample_fingerprint, counterexample_artifact
        ),
    )
}

pub(crate) fn local_double_search_status(
    discovered_failures: bool,
    exhausted: bool,
    on_violation: SearchOnViolationArg,
) -> BackendCommandStatus {
    if discovered_failures {
        return BackendCommandStatus::Failed;
    }
    if !exhausted && on_violation == SearchOnViolationArg::Stop {
        return BackendCommandStatus::Timeout;
    }
    BackendCommandStatus::Passed
}

pub(crate) fn unsupported_search_backend_error(plan: &SearchDriverPlan) -> CliError {
    backend_error(format!(
        "search scenario {} strategy={} max-states={} on-violation={} requires the exploration-engine driver over phase-6 search policies tracked by T-CLI-13",
        plan.scenario.label(),
        plan.strategy_arg.label(),
        plan.max_states,
        plan.on_violation.label()
    ))
}
