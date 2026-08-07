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
    if backend_plan.target == BackendExecutionTarget::Local
        && plan.family.is_builtin_fault_campaign()
    {
        return Some(FuzzDispatchRoute::BuiltInFaultCampaignProof);
    }
    #[cfg(any(test, feature = "test-double"))]
    {
        if backend_plan.target == BackendExecutionTarget::Local
            && matches!(
                backend_plan.resolved_backend,
                Some(ResolvedLocalBackend::Double)
            )
        {
            return Some(FuzzDispatchRoute::LocalDouble);
        }
    }
    None
}

#[cfg(any(test, feature = "test-double"))]
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

#[cfg(any(test, feature = "test-double"))]
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
        property_findings: 0,
        timeout_findings: 0,
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
        property_findings: 0,
        timeout_findings: 0,
    }
}

pub(super) fn apply_local_double_fuzz_report(
    outcome: &mut BackendCommandOutcome,
    plan: &FuzzDriverPlan,
    report: &LocalDoubleFuzzReport,
) {
    let status = if report.property_findings > 0 {
        BackendCommandStatus::Failed
    } else if report.timeout_findings > 0 {
        BackendCommandStatus::Timeout
    } else {
        BackendCommandStatus::Passed
    };
    outcome.status = status;
    outcome.exit_code = status.exit_code();
    let corpus = report
        .corpus
        .as_deref()
        .map(|path| path.display().to_string())
        .unwrap_or_else(|| String::from("none"));
    outcome.stdout.push(format!(
        "fuzz-run\tfamily={}\truns={}\tcoverage={}\tcorpus={}\ton_violation={}\titerations={}\tcoverage_order={}\tnew_coverage={}\tadmissions={}\tretained_entries={}\treplay_oracle_validations={}\tgenerated_mutants={}\tstore_puts={}\tproperty_findings={}\ttimeout_findings={}\tstatus={}",
        report.family,
        plan.runs,
        plan.coverage.label(),
        corpus,
        plan.on_violation.label(),
        report.iterations,
        report.coverage_biased_order,
        report.new_coverage,
        report.admissions,
        report.retained_entries,
        report.replay_oracle_validations,
        report.generated_mutants,
        report.store_puts,
        report.property_findings,
        report.timeout_findings,
        status.label()
    ));
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: outcome.canonical_log.len() as u64,
        node: String::from("fuzz"),
        kind: String::from("coverage_guided_fuzz_run"),
        summary: format!(
            "family={} runs={} coverage={} corpus={} on_violation={} iterations={} coverage_order={} new_coverage={} admissions={} retained_entries={} replay_oracle_validations={} generated_mutants={} store_puts={} property_findings={} timeout_findings={} status={}",
            report.family,
            plan.runs,
            plan.coverage.label(),
            corpus,
            plan.on_violation.label(),
            report.iterations,
            report.coverage_biased_order,
            report.new_coverage,
            report.admissions,
            report.retained_entries,
            report.replay_oracle_validations,
            report.generated_mutants,
            report.store_puts,
            report.property_findings,
            report.timeout_findings,
            status.label()
        ),
    });
    outcome.canonical_log_digest = canonical_log_digest(&outcome.canonical_log);
}

#[path = "exploration/search.rs"]
mod search;

pub(crate) use search::*;

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
    let format = cli.output_format();
    let _trace = emit_canonical_trace(format, &trace_entries, cli.trace.as_deref(), !cli.quiet)?;
    let emit_human = !cli.quiet && should_emit_human_backend_output(format);
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
    !cli.quiet && should_emit_human_backend_output(cli.output_format())
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

#[path = "exploration/replay_output.rs"]
mod replay_output;

pub(super) use replay_output::*;
