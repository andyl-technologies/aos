//! Search/fuzz execution and machine-readable outcome rendering.

use super::*;
pub(super) fn run_builtin_fault_campaign_fuzz(
    cli: &Cli,
    plan: &FuzzDriverPlan,
) -> Result<(), CliError> {
    let report = crucible::run_fault_campaign_example(plan.config)
        .map_err(|error| backend_error(format!("built-in fault-campaign fuzz failed: {error}")))?;
    if should_emit_human_dispatch_output(cli) {
        println!(
            "crucible: fuzzed built-in {} with coverage={}",
            report.family_name,
            plan.coverage.label()
        );
        println!(
            "crucible: {} iterations, {} coverage fingerprints, discovered configuration {}",
            report.fuzz_run.iterations.len(),
            report.coverage_fingerprints.len(),
            format_content_hash_ref(report.discovered_iteration.configuration_id())
        );
        println!(
            "crucible: captured self-contained artifact {}; replay state {}",
            format_content_hash_ref(report.finding.artifact.id()),
            format_content_hash_ref(report.finding.replay.state)
        );
        println!(
            "crucible: save {}, resume {}, fork {}",
            format_content_hash_ref(report.save.checkpoint),
            format_content_hash_ref(report.resume.checkpoint),
            format_content_hash_ref(report.fork.branch.id())
        );
    }
    Ok(())
}

pub(super) fn fuzz_dispatch_route(
    backend_plan: &BackendSelectionPlan,
    plan: &FuzzDriverPlan,
) -> Option<FuzzDispatchRoute> {
    if backend_plan.target == BackendExecutionTarget::Local && is_packaged_backend(backend_plan) {
        return Some(FuzzDispatchRoute::LocalPackagedBackend);
    }
    if plan.family.is_builtin_fault_campaign() {
        return Some(FuzzDispatchRoute::BuiltInFaultCampaignProof);
    }
    if backend_plan.target == BackendExecutionTarget::Local
        && matches!(
            backend_plan.resolved_backend,
            Some(ResolvedLocalBackend::Double)
        )
    {
        return Some(FuzzDispatchRoute::LocalDouble);
    }
    None
}

pub(super) fn run_local_double_fuzz_workflow(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    plan: &FuzzDriverPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let family = load_fuzz_family(plan)?;
    run_local_double_fuzz_workflow_with_family(
        thin_plan,
        backend_plan,
        ergonomics_plan,
        plan,
        &family,
    )
}

pub(super) fn run_local_double_fuzz_workflow_with_family(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    plan: &FuzzDriverPlan,
    family: &crucible::ScenarioFamily,
) -> Result<BackendCommandOutcome, CliError> {
    let report = if let Some(corpus) = &plan.corpus {
        fs::create_dir_all(corpus).map_err(|error| {
            backend_error(format!(
                "local-double fuzz could not create corpus `{}`: {error}",
                corpus.display()
            ))
        })?;
        let store = crucible::LocalDagStore::new(corpus.clone());
        let run = family
            .fuzz_coverage_guided_corpus(
                &store,
                plan.config,
                crucible::CoverageGuidedCorpusConfig::new(plan.config.meta_seed),
                &[],
            )
            .map_err(|error| {
                backend_error(format!("local-double fuzz corpus run failed: {error}"))
            })?;
        local_double_fuzz_report_from_corpus_run(plan, corpus, &run)
    } else {
        let run = family
            .fuzz_coverage_guided(plan.config, &[])
            .map_err(|error| backend_error(format!("local-double fuzz run failed: {error}")))?;
        local_double_fuzz_report_from_run(plan, &run)
    };

    let mut outcome = backend_command_outcome(thin_plan, backend_plan, ergonomics_plan);
    apply_local_double_fuzz_report(&mut outcome, plan, &report);
    Ok(outcome)
}

pub(super) fn local_double_fuzz_report_from_run(
    plan: &FuzzDriverPlan,
    run: &crucible::CoverageGuidedFuzzRun,
) -> LocalDoubleFuzzReport {
    LocalDoubleFuzzReport {
        family: plan.family.label(),
        corpus: None,
        iterations: run.iterations.len(),
        coverage_biased_order: run.coverage_biased_order.len(),
        new_coverage: run
            .iterations
            .iter()
            .filter(|iteration| iteration.new_coverage)
            .count(),
        retained_entries: 0,
        admissions: 0,
        replay_oracle_validations: 0,
        generated_mutants: run.iterations.len() as u64,
        store_puts: 0,
    }
}

pub(super) fn local_double_fuzz_report_from_corpus_run(
    plan: &FuzzDriverPlan,
    corpus: &Path,
    run: &crucible::CoverageGuidedCorpusRun,
) -> LocalDoubleFuzzReport {
    LocalDoubleFuzzReport {
        family: plan.family.label(),
        corpus: Some(corpus.to_path_buf()),
        iterations: run.fuzz.iterations.len(),
        coverage_biased_order: run.fuzz.coverage_biased_order.len(),
        new_coverage: run
            .fuzz
            .iterations
            .iter()
            .filter(|iteration| iteration.new_coverage)
            .count(),
        retained_entries: run.corpus.len(),
        admissions: run.admissions.len(),
        replay_oracle_validations: run.throughput.replay_oracle_validations,
        generated_mutants: run.throughput.generated_mutants,
        store_puts: run.throughput.store_puts,
    }
}

pub(super) fn apply_local_double_fuzz_report(
    outcome: &mut BackendCommandOutcome,
    plan: &FuzzDriverPlan,
    report: &LocalDoubleFuzzReport,
) {
    let status = BackendCommandStatus::Passed;
    outcome.status = status;
    outcome.exit_code = status.exit_code();
    let corpus = report
        .corpus
        .as_deref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| String::from("none"));
    outcome.stdout.push(format!(
        "fuzz-run\tfamily={}\truns={}\tcoverage={}\tcorpus={}\titerations={}\tcoverage_order={}\tnew_coverage={}\tadmissions={}\tretained_entries={}\treplay_oracle_validations={}\tgenerated_mutants={}\tstore_puts={}\tstatus={}",
        report.family,
        plan.runs,
        plan.coverage.label(),
        corpus,
        report.iterations,
        report.coverage_biased_order,
        report.new_coverage,
        report.admissions,
        report.retained_entries,
        report.replay_oracle_validations,
        report.generated_mutants,
        report.store_puts,
        status.label()
    ));
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: outcome.canonical_log.len() as u64,
        node: String::from("fuzz"),
        kind: String::from("coverage_guided_fuzz_run"),
        summary: format!(
            "family={} runs={} coverage={} corpus={} iterations={} coverage_order={} new_coverage={} admissions={} retained_entries={} replay_oracle_validations={} generated_mutants={} store_puts={} status={}",
            report.family,
            plan.runs,
            plan.coverage.label(),
            corpus,
            report.iterations,
            report.coverage_biased_order,
            report.new_coverage,
            report.admissions,
            report.retained_entries,
            report.replay_oracle_validations,
            report.generated_mutants,
            report.store_puts,
            status.label()
        ),
    });
    outcome.canonical_log_digest = canonical_log_digest(&outcome.canonical_log);
}

pub(super) fn run_local_double_search_workflow(
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

pub(super) fn run_local_double_search_workflow_with_graph(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    plan: &SearchDriverPlan,
    root: &crucible::Configuration,
    graph: &mut ValidationDag,
) -> Result<BackendCommandOutcome, CliError> {
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
    run_local_double_search_workflow_with_graph_and_failure_oracle(
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

pub(super) fn merge_search_failure_oracles<I>(
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

// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::too_many_arguments)]
pub(super) fn run_local_double_search_workflow_with_graph_and_failure_oracle(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    plan: &SearchDriverPlan,
    root: &crucible::Configuration,
    graph: &mut ValidationDag,
    failure_oracle: &SearchFailureOracle,
    failure_oracle_label: &str,
) -> Result<BackendCommandOutcome, CliError> {
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
    Ok(outcome)
}

pub(super) fn search_materialization_budget(max_states: u64) -> usize {
    match usize::try_from(max_states) {
        Ok(max_states) => max_states,
        Err(_) => usize::MAX,
    }
}

pub(super) fn search_failure_reproduction_artifact_bytes(
    backend_plan: &BackendSelectionPlan,
    plan: &SearchDriverPlan,
    failure: &SearchDiscoveredFailure,
) -> Result<Vec<u8>, CliError> {
    let mut canonical_log = canonical_log_entries_from_search_failure(failure);
    let extra_payloads = search_extra_artifact_payloads(plan, &mut canonical_log);
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

pub(super) fn search_extra_artifact_payloads(
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

pub(super) fn canonical_log_entries_from_search_failure(
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

pub(super) fn canonical_log_entries_from_engine_schedule(
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

pub(super) fn engine_decision_kind(decision: &crucible::Decision) -> &'static str {
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

pub(super) fn cli_digest_from_engine_hash(hash: crucible::ContentHash) -> String {
    format!("{CONTENT_ADDRESS_PREFIX}{}", hash.to_hex())
}

pub(super) fn apply_local_double_search_report(
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

pub(super) fn local_double_search_counterexample_fields(
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

pub(super) fn local_double_search_status(
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

pub(super) fn unsupported_search_backend_error(plan: &SearchDriverPlan) -> CliError {
    backend_error(format!(
        "search scenario {} strategy={} max-states={} on-violation={} requires the exploration-engine driver over phase-6 search policies tracked by T-CLI-13",
        plan.scenario.label(),
        plan.strategy_arg.label(),
        plan.max_states,
        plan.on_violation.label()
    ))
}

pub(super) fn unsupported_fuzz_backend_error(plan: &FuzzDriverPlan) -> CliError {
    backend_error(format!(
        "fuzz family {} runs={} coverage={} requires the exploration-engine driver over phase-6 fuzzing policies tracked by T-CLI-13",
        plan.family.label(),
        plan.runs,
        plan.coverage.label()
    ))
}

pub(super) fn emit_backend_command_output(
    cli: &Cli,
    outcome: &BackendCommandOutcome,
) -> Result<(), CliError> {
    let trace_entries = backend_machine_readable_trace_entries(outcome);
    let _trace =
        emit_canonical_trace(cli.format, &trace_entries, cli.trace.as_deref(), !cli.quiet)?;
    let emit_human = !cli.quiet && should_emit_human_backend_output(cli.format);
    if emit_human {
        for line in &outcome.stdout {
            println!("{line}");
        }
    }
    if outcome.status.is_non_passing() {
        if !outcome.side_reproduction_artifacts.is_empty() {
            for (label, artifact) in &outcome.side_reproduction_artifacts {
                let slug = format!("{}-{label}", outcome.status.failure_slug());
                let report = write_failure_reproduction_artifact(cli, artifact, &slug)?;
                if emit_human {
                    println!(
                        "crucible: wrote reproduction artifact side={} {} ({}) digest={}",
                        label,
                        report.path.display(),
                        REPRODUCTION_ARTIFACT_MEDIA_TYPE,
                        report.digest
                    );
                    println!(
                        "crucible: reproduce side {} with:\n    {}",
                        label, report.footer.replay_command
                    );
                    println!(
                        "crucible: debug side {} at the failure with:\n    {}",
                        label, report.footer.debug_command
                    );
                }
            }
            return Ok(());
        }
        if outcome_skipped_reproduction_artifacts(outcome) {
            return Ok(());
        }
        let Some(artifact) = &outcome.reproduction_artifact else {
            return Err(CliError::Artifact(format!(
                "{:?} outcome did not provide a reproduction artifact",
                outcome.status
            )));
        };
        let report =
            write_failure_reproduction_artifact(cli, artifact, outcome.status.failure_slug())?;
        if emit_human {
            println!(
                "crucible: wrote reproduction artifact {} ({}) digest={}",
                report.path.display(),
                REPRODUCTION_ARTIFACT_MEDIA_TYPE,
                report.digest
            );
            println!(
                "crucible: reproduce with:\n    {}",
                report.footer.replay_command
            );
            println!(
                "crucible: debug at the failure with:\n    {}",
                report.footer.debug_command
            );
        }
    }
    Ok(())
}

pub(super) fn outcome_skipped_reproduction_artifacts(outcome: &BackendCommandOutcome) -> bool {
    outcome.stdout.iter().any(|line| {
        line == "verify-reproduction-artifacts\tskipped=producer-provenance-unavailable"
    })
}

pub(super) fn should_emit_human_backend_output(format: OutputFormat) -> bool {
    !format.is_machine_readable()
}

pub(super) fn should_emit_human_dispatch_output(cli: &Cli) -> bool {
    !cli.quiet && should_emit_human_backend_output(cli.format)
}

pub(super) fn backend_machine_readable_trace_entries(
    outcome: &BackendCommandOutcome,
) -> Vec<CanonicalLogEntry> {
    let mut entries = outcome.canonical_log.clone();
    entries.push(CanonicalLogEntry {
        sequence: entries.len() as u64,
        virtual_time_ticks: entries
            .last()
            .map(|entry| entry.virtual_time_ticks.saturating_add(1))
            .unwrap_or(0),
        node: String::from("cli"),
        kind: String::from("final_outcome"),
        summary: final_outcome_summary(outcome),
    });
    entries
}

pub(super) fn final_outcome_summary(outcome: &BackendCommandOutcome) -> String {
    format!(
        "subcommand={} status={} exit_code={} canonical_log={} artifact={}",
        outcome.subcommand.label(),
        outcome.status.label(),
        outcome.exit_code,
        outcome.canonical_log_digest,
        outcome.artifact_digest
    )
}

pub(super) fn emit_replay_report_output(
    cli: &Cli,
    report: &ReplayArtifactReport,
) -> Result<(), CliError> {
    if cli.format.is_machine_readable() {
        let status = replay_report_status(report);
        let exit_code = replay_report_exit_code(report);
        let entries = replay_machine_readable_trace_entries(report, status, exit_code);
        emit_canonical_trace(cli.format, &entries, cli.trace.as_deref(), !cli.quiet)?;
    } else if !cli.quiet {
        write_replay_report_human(&mut io::stdout(), report)?;
    }
    Ok(())
}

pub(super) fn replay_report_status(report: &ReplayArtifactReport) -> BackendCommandStatus {
    if report
        .check
        .as_ref()
        .and_then(|check| check.mismatch.as_ref())
        .is_some()
    {
        return BackendCommandStatus::Failed;
    }
    if report
        .bisect
        .as_ref()
        .and_then(|bisect| bisect.divergence.as_ref())
        .is_some()
    {
        BackendCommandStatus::Failed
    } else {
        BackendCommandStatus::Passed
    }
}

pub(super) fn replay_report_exit_code(report: &ReplayArtifactReport) -> i32 {
    replay_report_status(report).exit_code()
}

pub(super) fn replay_machine_readable_trace_entries(
    report: &ReplayArtifactReport,
    status: BackendCommandStatus,
    exit_code: i32,
) -> Vec<CanonicalLogEntry> {
    let mut entries = Vec::new();
    push_replay_trace_entry(
        &mut entries,
        "replay_artifact",
        format!(
            "path={} digest={} seed={} scenario={}",
            report.path.display(),
            report.digest,
            report.seed,
            report.scenario_digest
        ),
    );
    if let Some(check) = &report.check {
        push_replay_trace_entry(
            &mut entries,
            "replay_check",
            replay_check_machine_readable_summary(check),
        );
    }
    if let Some(target) = &report.to_savepoint {
        push_replay_trace_entry(
            &mut entries,
            "replay_to_savepoint",
            replay_to_savepoint_machine_readable_summary(target),
        );
    }
    if let Some(bisect) = &report.bisect {
        push_replay_trace_entry(
            &mut entries,
            "replay_bisect",
            replay_bisect_machine_readable_summary(bisect),
        );
    }
    let canonical_log_digest = canonical_log_digest(&entries);
    push_replay_trace_entry(
        &mut entries,
        "final_outcome",
        replay_final_outcome_summary(report, status, exit_code, &canonical_log_digest),
    );
    entries
}

pub(super) fn push_replay_trace_entry(
    entries: &mut Vec<CanonicalLogEntry>,
    kind: impl Into<String>,
    summary: impl Into<String>,
) {
    entries.push(CanonicalLogEntry {
        sequence: entries.len() as u64,
        virtual_time_ticks: entries
            .last()
            .map(|entry| entry.virtual_time_ticks.saturating_add(1))
            .unwrap_or(0),
        node: String::from("cli"),
        kind: kind.into(),
        summary: summary.into(),
    });
}

pub(super) fn replay_final_outcome_summary(
    report: &ReplayArtifactReport,
    status: BackendCommandStatus,
    exit_code: i32,
    canonical_log_digest: &str,
) -> String {
    format!(
        "subcommand=replay status={} exit_code={} canonical_log={} artifact={}",
        status.label(),
        exit_code,
        canonical_log_digest,
        report.digest
    )
}

pub(super) fn replay_check_machine_readable_summary(check: &ReplayCheckReport) -> String {
    match &check.mismatch {
        Some(mismatch) => format!(
            "path={} status=mismatch expected={} replayed={} first_diff_byte={} original_len={} replayed_len={}",
            check.path.display(),
            mismatch.original_digest,
            mismatch.replayed_digest,
            mismatch.first_diff_byte,
            mismatch.original_len,
            mismatch.replayed_len
        ),
        None => format!(
            "path={} status=byte-identical digest={}",
            check.path.display(),
            check.digest
        ),
    }
}

pub(super) fn replay_to_savepoint_machine_readable_summary(
    target: &ReplayToSavepointReport,
) -> String {
    format!(
        "target={} status=target-validated schedule_prefix=typed materialization={} unified_operation={} checkpoint={} frontier_ticks={} target_decisions={} artifact_decisions={} matched_decisions={} typed_prefix_digest={} artifact_prefix_digest={} materialized_configuration={} materialized_schedule={} materialized_checkpoint={} runtime_state={} reduced_state={} single_vm_fingerprint={} graph={} replay_fat={} replay_thin={} oracle={} store_objects={}",
        target.target_label,
        target.materialization.materialization,
        target.materialization.operation,
        format_content_hash_ref(target.checkpoint),
        target.frontier_ticks,
        target.schedule_prefix.target_decisions,
        target.schedule_prefix.artifact_decisions,
        target.schedule_prefix.matched_decisions,
        target.schedule_prefix.typed_prefix_digest,
        target.schedule_prefix.artifact_prefix_digest,
        format_content_hash_ref(target.materialization.configuration),
        format_content_hash_ref(target.materialization.schedule),
        format_content_hash_ref(target.materialization.checkpoint),
        format_content_hash_ref(target.materialization.runtime_state),
        format_content_hash_ref(target.materialization.reduced_state),
        format_content_hash_ref(target.materialization.single_vm_fingerprint),
        format_content_hash_ref(target.materialization.graph),
        format_content_hash_ref(target.materialization.replay_fat_checkpoint),
        format_content_hash_ref(target.materialization.replay_thin_checkpoint),
        target.oracle.status_label(),
        target.oracle.store_objects
    )
}

pub(super) fn replay_bisect_machine_readable_summary(bisect: &ReplayBisectionReport) -> String {
    match &bisect.divergence {
        Some(divergence) => format!(
            "path={} status=diverged mismatch={} first_decision={} first_fingerprint_sample={} first_instruction={} node={} byte={} left_state={} right_state={}",
            bisect.other_path.display(),
            divergence.mismatch.label(),
            divergence
                .first_different_decision
                .map(|decision| decision.to_string())
                .unwrap_or_else(|| String::from("unknown")),
            divergence
                .first_different_fingerprint_sample
                .map(|sample| sample.to_string())
                .unwrap_or_else(|| String::from("unknown")),
            divergence.first_different_instruction,
            divergence.node.as_deref().unwrap_or("unknown"),
            divergence.first_different_byte,
            divergence.left_state_digest,
            divergence.right_state_digest
        ),
        None => format!(
            "path={} status=byte-identical digest={}",
            bisect.other_path.display(),
            bisect.other_digest
        ),
    }
}
