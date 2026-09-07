//! Live local backend execution through the packaged patched emulator and plugin.

use super::*;

#[path = "finding_frames.rs"]
mod finding_frames;
use finding_frames::property_violation_from_frames;

/// Maximum scheduler quanta for one live exploration realization.
///
/// Exact local events and conservative link horizons may split a realization;
/// the bound leaves room for both VM nodes and terminal scheduler settling.
pub(crate) const LIVE_EXPLORATION_QUANTUM_LIMIT: u64 = 16;

/// Maximum scheduler quanta for one live fuzz realization.
///
/// Reaching this exact bound after producing coverage is normal campaign
/// completion. An earlier timeout remains a finding, while a realization with
/// no coverage fails closed before it can influence the corpus.
pub(crate) const LIVE_FUZZ_QUANTUM_LIMIT: u64 = 1_024;

/// Terminal instruction-count ceiling for one live fuzz realization.
///
/// Production node construction authenticates the guest at the one-million
/// instruction boot boundary. One additional million instructions exposes the
/// retained setup coverage while keeping each campaign iteration far below the
/// general 40-billion-instruction run ceiling.
pub(crate) const LIVE_FUZZ_RUN_CEILING_ICOUNT: u64 = 2_000_000;

/// Terminal instruction-count ceiling for one live exploration realization.
///
/// The certified stock-kernel network workload emits near 3.3 billion
/// instructions and resolves its link delivery below this three-window bound.
pub(crate) const LIVE_EXPLORATION_RUN_CEILING_ICOUNT: u64 = 12_000_000_000;

/// Terminal instruction-count ceiling for a production CLI lifecycle session.
pub(crate) const PRODUCTION_CLI_RUN_CEILING_ICOUNT: u64 = 40_000_000_000;

/// Scheduler-quantum ceiling for a production CLI lifecycle session.
pub(crate) const PRODUCTION_CLI_QUANTUM_BUDGET: u64 = 10_000;

/// Per-node wall-clock timeout for a production CLI lifecycle step.
const PRODUCTION_CLI_COMPLETION_TIMEOUT: Duration = Duration::from_secs(300);

#[derive(Debug)]
pub(crate) struct SelftestGateReport {
    pub(crate) name: String,
    pub(crate) status: SelftestGateStatus,
    pub(crate) corpus_entries: usize,
    pub(crate) runs_per_entry: usize,
    pub(crate) runner: SelftestGateRunner,
    pub(crate) qemu_build_id: Option<String>,
    pub(crate) live_qemu_icount: Option<u64>,
    pub(crate) live_qemu_fingerprint: Option<String>,
}

#[path = "qemu_live/probe.rs"]
mod probe;

pub(crate) use probe::*;

pub(crate) fn is_packaged_backend(backend_plan: &BackendSelectionPlan) -> bool {
    matches!(
        backend_plan.resolved_backend,
        Some(ResolvedLocalBackend::Qemu { .. })
    )
}

pub(crate) fn run_selftest(cli: &Cli, args: &SelftestArgs) -> Result<SelftestReport, CliError> {
    run_selftest_with_probe(cli, args, &mut ProductionLiveQemuProbeRunner)
}

pub(crate) fn run_selftest_with_probe(
    cli: &Cli,
    args: &SelftestArgs,
    probe: &mut impl LiveQemuProbeRunner,
) -> Result<SelftestReport, CliError> {
    let selected_gates = plan_selftest_gates(args)?;
    let qemu_backend = if selected_gates
        .iter()
        .any(|gate| selftest_gate_uses_real_backend(gate))
    {
        Some(require_selftest_qemu_backend(cli)?)
    } else {
        None
    };
    #[cfg(any(test, feature = "test-double"))]
    let verified = verify_selftest_corpus(args)?;
    #[cfg(not(any(test, feature = "test-double")))]
    let verified = Vec::new();
    let mut gates = Vec::with_capacity(selected_gates.len());
    let mut live_baseline = None;
    for gate in selected_gates {
        let runner = if selftest_gate_uses_real_backend(&gate) {
            SelftestGateRunner::RealQemu
        } else {
            #[cfg(any(test, feature = "test-double"))]
            {
                SelftestGateRunner::DoubleBackedCorpus
            }
            #[cfg(not(any(test, feature = "test-double")))]
            {
                return Err(backend_error(format!(
                    "selftest gate `{gate}` requires the `test-double` Cargo feature"
                )));
            }
        };
        let live = if runner == SelftestGateRunner::RealQemu {
            let backend = qemu_backend
                .as_ref()
                .ok_or_else(|| backend_error("real-QEMU selftest requires a resolved backend"))?;
            let evidence = probe.run_probe(backend)?;
            validate_live_qemu_probe_evidence(backend, &evidence)?;
            if live_baseline
                .as_ref()
                .is_some_and(|baseline| baseline != &evidence)
            {
                return Err(backend_error(
                    "live QEMU selftest probes diverged across identical executions",
                ));
            }
            live_baseline.get_or_insert_with(|| evidence.clone());
            Some(evidence)
        } else {
            None
        };
        gates.push(SelftestGateReport {
            name: gate,
            status: SelftestGateStatus::Passed,
            corpus_entries: verified.len(),
            runs_per_entry: DEFAULT_SELFTEST_RUNS,
            runner,
            qemu_build_id: live.as_ref().map(|evidence| evidence.qemu_build_id.clone()),
            live_qemu_icount: live.as_ref().map(|report| report.completed_icount),
            live_qemu_fingerprint: live
                .as_ref()
                .map(|report| report.execution_fingerprint.clone()),
        });
    }
    Ok(SelftestReport { gates, verified })
}

fn validate_live_qemu_probe_evidence(
    backend: &ResolvedLocalBackend,
    evidence: &LiveQemuProbeEvidence,
) -> Result<(), CliError> {
    let observed = BackendExecutionEvidence::LocalProduction {
        build_id: evidence.qemu_build_id.clone(),
        plugin_abi: evidence.plugin_abi.clone(),
    };
    let plan = BackendSelectionPlan {
        subcommand: CliSubcommand::Selftest,
        target: BackendExecutionTarget::Local,
        requested_backend: Backend::Qemu,
        resolved_backend: Some(backend.clone()),
        reason: BackendSelectionReason::ExplicitQemu,
        daemon: None,
        daemon_security: None,
        remote_uses_control_api: false,
        local_uses_simulation_backend: true,
        local_remote_equivalence_contract: true,
    };
    let expected = plan
        .expected_execution_evidence()
        .ok_or_else(|| backend_error("live QEMU probe has no selected execution identity"))?;
    if expected != observed || !observed.proves_t_cli_3(&plan) {
        return Err(backend_error(
            "live QEMU probe identity does not match the discovered backend",
        ));
    }
    Ok(())
}

#[cfg(not(test))]
pub(crate) fn require_selftest_qemu_backend(cli: &Cli) -> Result<ResolvedLocalBackend, CliError> {
    require_qemu_artifacts(
        cli,
        &ProcessQemuDiscoveryEnvironment,
        &CompileTimeAosQemuPackageSet,
    )
}

#[cfg(test)]
pub(crate) fn require_selftest_qemu_backend(cli: &Cli) -> Result<ResolvedLocalBackend, CliError> {
    require_qemu_artifacts(cli, &ProcessQemuDiscoveryEnvironment, &NoAosQemuPackageSet)
}

pub(crate) fn run_local_qemu_fuzz_workflow(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    plan: &FuzzDriverPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let backend = backend_plan
        .resolved_backend
        .as_ref()
        .ok_or_else(|| backend_error("local QEMU fuzz requires a resolved backend"))?;
    let family = load_fuzz_family(plan)?;
    let config = production_qemu_lifecycle_config(backend)?
        .with_run_ceiling_icount(LIVE_FUZZ_RUN_CEILING_ICOUNT)
        .with_coverage(production_api::ProductionPluginSwitch::On);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let warmup = family
        .fuzz_coverage_guided(plan.config, &[])
        .map_err(|error| backend_error(format!("QEMU fuzz warm-up policy failed: {error}")))?;
    let mut execution =
        execute_qemu_fuzz_iterations(&config, &runtime, &warmup, "warm-up", plan, backend_plan)?;
    let (run, mut report) = if let Some(corpus) = &plan.corpus {
        fs::create_dir_all(corpus).map_err(|error| {
            backend_error(format!(
                "QEMU fuzz could not create corpus `{}`: {error}",
                corpus.display()
            ))
        })?;
        let store = crucible::LocalDagStore::new(corpus.clone());
        let corpus_run = family
            .fuzz_coverage_guided_corpus(
                &store,
                plan.config,
                crucible::CoverageGuidedCorpusConfig::new(plan.config.meta_seed),
                &execution.feedback,
            )
            .map_err(|error| backend_error(format!("QEMU fuzz corpus policy failed: {error}")))?;
        (
            corpus_run.fuzz.clone(),
            local_double_fuzz_report_from_corpus_run(plan, corpus, &corpus_run),
        )
    } else {
        let run = family
            .fuzz_coverage_guided(plan.config, &execution.feedback)
            .map_err(|error| backend_error(format!("QEMU fuzz policy failed: {error}")))?;
        let report = local_double_fuzz_report_from_run(plan, &run);
        (run, report)
    };
    let guided_execution =
        if plan.on_violation == SearchOnViolationArg::Stop && !execution.findings.is_empty() {
            QemuFuzzExecution::default()
        } else {
            execute_qemu_fuzz_iterations(&config, &runtime, &run, "guided", plan, backend_plan)?
        };
    merge_qemu_fuzz_execution(&mut execution, guided_execution)?;
    report.property_findings = execution
        .findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.failure,
                crucible_model::FailureClusterReportFailure::Property(_)
            )
        })
        .count();
    report.timeout_findings = execution
        .findings
        .iter()
        .filter(|finding| {
            matches!(
                finding.failure,
                crucible_model::FailureClusterReportFailure::Timeout(_)
            )
        })
        .count();
    let mut outcome = backend_command_outcome(thin_plan, backend_plan, ergonomics_plan);
    apply_local_double_fuzz_report(&mut outcome, plan, &report);
    for (index, feedback) in execution.feedback.iter().enumerate() {
        outcome.canonical_log.push(CanonicalLogEntry {
            sequence: outcome.canonical_log.len() as u64,
            virtual_time_ticks: outcome.canonical_log.len() as u64,
            node: String::from("qemu"),
            kind: String::from("fuzz_coverage_feedback"),
            summary: format!(
                "iteration={index}\tblocks={}\tfingerprint={}",
                feedback.projection().len(),
                feedback.fingerprint().to_hex()
            ),
        });
    }
    attach_qemu_findings_outputs(
        &mut outcome,
        &plan.store_root,
        &plan.artifact_dir,
        plan.findings_out.as_deref(),
        execution.findings,
        execution.reproduction_artifacts,
    )?;
    append_qemu_control_plane_execution_proof(&mut outcome, backend, "fuzz-live-campaign");
    Ok(outcome)
}

#[derive(Default)]
struct QemuFuzzExecution {
    feedback: Vec<crucible::EventLogCoverageFeedback>,
    findings: Vec<TriageFindingEvidence>,
    reproduction_artifacts: Vec<Vec<u8>>,
}

fn execute_qemu_fuzz_iterations(
    config: &production_api::ProductionVmLifecycleConfig,
    runtime: &tokio::runtime::Runtime,
    run: &crucible::CoverageGuidedFuzzRun,
    phase: &str,
    plan: &FuzzDriverPlan,
    backend_plan: &BackendSelectionPlan,
) -> Result<QemuFuzzExecution, CliError> {
    let mut execution = QemuFuzzExecution {
        feedback: Vec::with_capacity(run.iterations.len()),
        ..QemuFuzzExecution::default()
    };
    for iteration in &run.iterations {
        let form = iteration.scenario.form().clone();
        let run_plan = qemu_fuzz_iteration_plan(iteration.sequence, form.clone());
        // crucible-lint: allow host-nondeterminism-state -- genesis is reconstructed from canonical scenario material, not host observations.
        let branch_base = crucible::Configuration::genesis(iteration.scenario.scenario_def());
        let iteration_config = config.clone().with_branch_prefix_overrides(
            branch_base,
            VirtualTime { ticks: 0 },
            iteration.schedule().decisions().to_vec(),
        );
        let control_plane =
            production_qemu_control_plane(iteration_config, run_plan.scenario.scenario_form());
        let client = InProcessLifecycleClient::new(control_plane);
        let report =
            runtime.block_on(run_control_client_workflow_async(&client, &run_plan, &[]))?;
        if report.status == BackendCommandStatus::Crashed {
            let last_event = report.streamed_events.last().map_or("none", String::as_str);
            return Err(backend_error(format!(
                "QEMU fuzz {phase} iteration {} crashed before producing campaign evidence: \
                 outcome={:?} final_state={} frontier_ticks={} quanta={} last_event={last_event}",
                iteration.sequence,
                report.outcome,
                report.final_state,
                report.final_frontier_ticks,
                report.final_quanta,
            )));
        }
        if report.coverage_feedback.projection().is_empty() {
            return Err(backend_error(format!(
                "QEMU fuzz {phase} iteration {} produced no basic-block coverage",
                iteration.sequence,
            )));
        }
        let recorded_overrides = report
            .terminal_configuration
            .as_ref()
            .ok_or_else(|| {
                backend_error(format!(
                    "QEMU fuzz {phase} iteration {} omitted its terminal configuration",
                    iteration.sequence,
                ))
            })?
            .schedule
            // crucible-lint: allow host-nondeterminism-state -- the terminal schedule is canonical engine output and is compared without mutation.
            .decisions()
            .iter()
            .filter_map(|decision| match decision {
                // crucible-lint: allow host-nondeterminism-state -- this projection selects only scheduler-authored override values.
                crucible::Decision::Override(override_decision) => Some(override_decision),
                _ => None,
            })
            .collect::<Vec<_>>();
        let expected_overrides = iteration
            .schedule()
            // crucible-lint: allow host-nondeterminism-state -- the authored iteration schedule is immutable canonical input.
            .decisions()
            .iter()
            .filter_map(|decision| match decision {
                // crucible-lint: allow host-nondeterminism-state -- this projection selects only authored override values.
                crucible::Decision::Override(override_decision) => Some(override_decision),
                _ => None,
            })
            .collect::<Vec<_>>();
        if recorded_overrides != expected_overrides {
            return Err(backend_error(format!(
                "QEMU fuzz {phase} iteration {} recorded {} exact overrides, expected {}",
                iteration.sequence,
                recorded_overrides.len(),
                expected_overrides.len(),
            )));
        }
        let finding = qemu_fuzz_finding_evidence(
            &form,
            &report,
            phase,
            iteration.sequence,
            iteration.schedule().len(),
            backend_plan,
        )?;
        execution.feedback.push(report.coverage_feedback);
        if let Some((evidence, reproduction)) = finding {
            let store = crucible::LocalDagStore::new(plan.store_root.clone());
            let stored = evidence
                .finding
                .store_artifact(&store)
                .map_err(CliError::Store)?;
            if stored != evidence.finding.artifact.id() {
                return Err(artifact_error(
                    "stored fuzz finding artifact did not match its content identity",
                ));
            }
            push_qemu_fuzz_finding(&mut execution, evidence, reproduction)?;
            if plan.on_violation == SearchOnViolationArg::Stop {
                break;
            }
        }
    }
    Ok(execution)
}

fn qemu_fuzz_finding_evidence(
    form: &crucible::ScenarioDefForm,
    report: &RunWorkflowReport,
    phase: &str,
    sequence: u64,
    branch_decisions: usize,
    backend_plan: &BackendSelectionPlan,
) -> Result<Option<(crate::cli_report::TriageFindingEvidence, Vec<u8>)>, CliError> {
    if report.status == BackendCommandStatus::Passed
        || qemu_fuzz_timeout_is_campaign_completion(
            report.status,
            report.budget_timed_out,
            report.outcome,
            report.final_quanta,
        )
    {
        return Ok(None);
    }
    let terminal = report.terminal_configuration.as_ref().ok_or_else(|| {
        backend_error(format!(
            "QEMU fuzz {phase} iteration {sequence} did not retain a terminal configuration"
        ))
    })?;
    let finding_fingerprint = crucible::ContentHash::from_canonical_material(
        "crucible.live-qemu-fuzz-finding.v2",
        &format!(
            "configuration={}\noutcome={}",
            terminal.id().to_hex(),
            report.status.label()
        ),
    );
    let finding = crucible::FindingReproductionArtifact::capture(
        crucible::FindingDiscoveryPath::CoverageGuidedFuzzing,
        finding_fingerprint,
        form,
        terminal,
    )
    .map_err(|error| backend_error(format!("capture QEMU fuzz finding: {error}")))?;
    let evidence = match report.status {
        BackendCommandStatus::Failed => {
            let violation = property_violation_from_frames(
                form,
                &report.streamed_event_frames,
                finding.artifact.id(),
            )?;
            crate::cli_triage_debug::triage_property_evidence_for_violation_with_recording(
                finding,
                violation,
                report.coverage_feedback.fingerprint(),
                report.streamed_event_frames.clone(),
            )
        }
        BackendCommandStatus::Timeout => {
            let timeout = crucible_model::FailureTimeoutRecord::new(
                crucible_model::FailureTimeoutBudgetKind::ExecutionQuanta,
                None,
                report.final_quanta,
                crucible::VirtualTime {
                    ticks: report.final_frontier_ticks,
                },
                None,
                None,
                finding.artifact.id(),
            );
            crate::cli_triage_debug::triage_timeout_evidence(
                finding,
                timeout,
                report.coverage_feedback.fingerprint(),
                report.streamed_event_frames.clone(),
            )
        }
        BackendCommandStatus::Crashed => {
            return Err(backend_error(format!(
                "QEMU fuzz {phase} iteration {sequence} crashed before producing campaign evidence"
            )));
        }
        BackendCommandStatus::Passed => return Ok(None),
    }
    .map_err(|error| backend_error(format!("build QEMU fuzz finding evidence: {error}")))?;
    let reproduction = live_finding_reproduction_artifact_bytes(
        backend_plan.resolved_backend.as_ref(),
        &evidence.finding,
        "fuzz",
        &qemu_fuzz_iteration_plan(sequence, form.clone()),
        report,
        LiveQemuReplayBranch::PrefixOverrides {
            base_decisions: 0,
            frontier_ticks: 0,
            decision_start: 0,
            decision_end: branch_decisions as u64,
        },
    )?;
    Ok(Some((evidence, reproduction)))
}

fn qemu_fuzz_timeout_is_campaign_completion(
    status: BackendCommandStatus,
    budget_timed_out: bool,
    outcome: Option<OutcomeKind>,
    final_quanta: u64,
) -> bool {
    status == BackendCommandStatus::Timeout
        && budget_timed_out
        && outcome == Some(OutcomeKind::Timeout)
        && final_quanta == LIVE_FUZZ_QUANTUM_LIMIT
}

fn push_qemu_fuzz_finding(
    execution: &mut QemuFuzzExecution,
    evidence: TriageFindingEvidence,
    reproduction: Vec<u8>,
) -> Result<(), CliError> {
    let artifact = evidence.finding.artifact.id();
    if let Some(index) = execution
        .findings
        .iter()
        .position(|existing| existing.finding.artifact.id() == artifact)
    {
        if execution.findings[index] != evidence
            || execution.reproduction_artifacts.get(index) != Some(&reproduction)
        {
            return Err(artifact_error(
                "repeated fuzz reproduction produced conflicting deterministic evidence",
            ));
        }
        return Ok(());
    }
    execution.findings.push(evidence);
    execution.reproduction_artifacts.push(reproduction);
    Ok(())
}

fn merge_qemu_fuzz_execution(
    target: &mut QemuFuzzExecution,
    source: QemuFuzzExecution,
) -> Result<(), CliError> {
    if source.findings.len() != source.reproduction_artifacts.len() {
        return Err(artifact_error(
            "fuzz phase produced mismatched finding and reproduction counts",
        ));
    }
    target.feedback.extend(source.feedback);
    for (evidence, reproduction) in source
        .findings
        .into_iter()
        .zip(source.reproduction_artifacts)
    {
        push_qemu_fuzz_finding(target, evidence, reproduction)?;
    }
    Ok(())
}

fn attach_qemu_findings_outputs(
    outcome: &mut BackendCommandOutcome,
    store_root: &Path,
    artifact_dir: &Path,
    findings_out: Option<&Path>,
    findings: Vec<crate::cli_report::TriageFindingEvidence>,
    reproduction_artifacts: Vec<Vec<u8>>,
) -> Result<(), CliError> {
    if findings.is_empty() && findings_out.is_none() {
        return Ok(());
    }
    let (path, digest, ledger_bytes) = crate::cli_triage_debug::write_failure_findings_ledger_v3(
        artifact_dir,
        findings_out,
        &findings,
    )?;
    let store = crucible::LocalDagStore::new(store_root.to_path_buf());
    let stored = store.put(&ledger_bytes).map_err(CliError::Store)?;
    if stored != digest {
        return Err(artifact_error(
            "stored findings ledger did not match its content identity",
        ));
    }
    outcome.stdout.push(format!(
        "findings-ledger\tpath={}\tdigest={}\tfindings={}",
        path.display(),
        format_content_hash_ref(digest),
        findings.len()
    ));
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: outcome.canonical_log.len() as u64,
        node: String::from("crucible"),
        kind: String::from("signed_findings_ledger"),
        summary: format!(
            "digest={} findings={}",
            format_content_hash_ref(digest),
            findings.len()
        ),
    });
    match reproduction_artifacts.as_slice() {
        [artifact] => outcome.reproduction_artifact = Some(artifact.clone()),
        artifacts => {
            outcome.side_reproduction_artifacts = artifacts
                .iter()
                .enumerate()
                .map(|(index, artifact)| (format!("finding-{index}"), artifact.clone()))
                .collect();
        }
    }
    outcome.canonical_log_digest = canonical_log_digest(&outcome.canonical_log);
    Ok(())
}

#[cfg(test)]
mod finding_tests {
    use super::*;

    #[test]
    fn collect_fuzz_deduplicates_identical_phase_reproductions()
    -> Result<(), Box<dyn std::error::Error>> {
        let scenario = crucible::happy_path_scenario()?.scenario;
        let configuration = crucible::Configuration::genesis(scenario.scenario_def());
        let finding = crucible::FindingReproductionArtifact::capture(
            crucible::FindingDiscoveryPath::CoverageGuidedFuzzing,
            crucible::ContentHash::from_bytes(b"repeated-fuzz-timeout"),
            &scenario,
            &configuration,
        )?;
        let timeout = crucible_model::FailureTimeoutRecord::new(
            crucible_model::FailureTimeoutBudgetKind::ExecutionQuanta,
            Some(10),
            10,
            crucible::VirtualTime { ticks: 4 },
            None,
            None,
            finding.artifact.id(),
        );
        let evidence = crate::cli_triage_debug::triage_timeout_evidence(
            finding,
            timeout,
            crucible::ContentHash::from_bytes(b"repeated-fuzz-coverage"),
            Vec::new(),
        )?;
        let mut execution = QemuFuzzExecution::default();
        push_qemu_fuzz_finding(&mut execution, evidence.clone(), vec![1, 2, 3])?;
        let mut guided = QemuFuzzExecution::default();
        push_qemu_fuzz_finding(&mut guided, evidence.clone(), vec![1, 2, 3])?;
        merge_qemu_fuzz_execution(&mut execution, guided)?;
        assert_eq!(execution.findings.len(), 1);
        assert_eq!(execution.reproduction_artifacts.len(), 1);
        assert!(push_qemu_fuzz_finding(&mut execution, evidence, vec![4, 5, 6]).is_err());
        Ok(())
    }

    #[test]
    fn cli_search_fuzz_live_qemu_iterations_bound_the_campaign()
    -> Result<(), Box<dyn std::error::Error>> {
        let scenario = crucible::happy_path_scenario()?.scenario;
        let plan = qemu_fuzz_iteration_plan(0, scenario);

        assert_eq!(plan.max_quanta, Some(LIVE_FUZZ_QUANTUM_LIMIT));
        assert_eq!(LIVE_FUZZ_RUN_CEILING_ICOUNT, 2_000_000);
        assert_eq!(plan.execution_mode, RunExecutionMode::ToCompletion);
        assert!(qemu_fuzz_timeout_is_campaign_completion(
            BackendCommandStatus::Timeout,
            true,
            Some(OutcomeKind::Timeout),
            LIVE_FUZZ_QUANTUM_LIMIT,
        ));
        assert!(!qemu_fuzz_timeout_is_campaign_completion(
            BackendCommandStatus::Timeout,
            true,
            Some(OutcomeKind::Timeout),
            LIVE_FUZZ_QUANTUM_LIMIT - 1,
        ));
        Ok(())
    }
}

fn qemu_fuzz_iteration_plan(sequence: u64, form: crucible::ScenarioDefForm) -> RunInvocationPlan {
    let scenario = form.scenario_def();
    RunInvocationPlan {
        request_seed: Some(scenario.seed()),
        save_store_root: None,
        campaign_deployment: None,
        scenario: RunScenarioRef::BuiltInExample {
            name: format!("fuzz-iteration-{sequence}"),
            form,
            scenario,
        },
        terminal_condition: RunTerminalCondition::Quiescence,
        max_virtual_time: None,
        max_virtual_time_ticks: None,
        max_quanta: Some(LIVE_FUZZ_QUANTUM_LIMIT),
        execution_mode: RunExecutionMode::ToCompletion,
        save_policy: RunSavePolicy::Never,
        watch_streams_live_status: false,
        startup_commands: vec![SessionCommandKind::Start, SessionCommandKind::Continue],
        initial_control_commands: vec![SessionCommandKind::Query],
        accepted_interactive_commands: Vec::new(),
        observer_profile: VERIFY_BASELINE_PROFILE,
        collect_execution_fingerprints: true,
        bounded_ack_quanta: RUN_INTERACTIVE_ACK_QUANTA_BOUND,
        outcome_exit_codes: vec![
            (BackendCommandStatus::Passed, 0),
            (BackendCommandStatus::Failed, 1),
            (BackendCommandStatus::Timeout, 2),
            (BackendCommandStatus::Crashed, 3),
        ],
        invalid_scenario_exit_code: 4,
    }
}

#[path = "qemu_live/search.rs"]
mod search;

pub(crate) use search::*;

#[path = "qemu_live/replay.rs"]
mod replay;
pub(crate) use replay::*;

/// Verifies every reduction through an independent packaged-QEMU session.
pub(crate) fn run_local_qemu_verify_workflow(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    verify_plan: &VerifyInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let backend = backend_plan
        .resolved_backend
        .as_ref()
        .ok_or_else(|| backend_error("local QEMU verify requires a resolved backend"))?;
    let scenario = verify_plan.scenario().ok_or_else(|| {
        backend_error("QEMU verify compare mode must use the artifact comparison path")
    })?;
    let config = production_qemu_lifecycle_config(backend)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let control_plane = production_qemu_control_plane(config, scenario.scenario_form());
    let client = InProcessLifecycleClient::new(control_plane);
    let report = runtime.block_on(run_control_client_verify_workflow_async(
        &client,
        verify_plan,
        Some(backend),
        ergonomics_plan,
    ))?;
    finish_verify_workflow_outcome(
        thin_plan,
        backend_plan,
        ergonomics_plan,
        verify_plan,
        report,
    )
}

pub(crate) fn production_qemu_control_plane(
    config: production_api::ProductionVmLifecycleConfig,
    source: &crucible::ScenarioDefForm,
) -> LifecycleControlPlane<
    production_api::ProductionVmLifecycleLoop,
    production_api::LifecycleLoopFactory<production_api::ProductionVmLifecycleLoop>,
> {
    let resume_config = config.clone();
    let white_box_policies = source
        .world()
        .vm_nodes()
        .iter()
        .map(|node| (node.id.clone(), node.white_box))
        .collect::<BTreeMap<_, _>>();
    LifecycleControlPlane::new_with_fallible_source_factory(
        "crucible-cli-qemu",
        Vec::new(),
        move |scenario, source, _seed| {
            let source = source.ok_or_else(|| production_api::LifecycleApiError::LoopFactory {
                message: String::from(
                    "production QEMU lifecycle requires an inline scenario definition",
                ),
            })?;
            production_api::build_production_vm_lifecycle_loop(scenario, source, &config)
        },
    )
    .with_fat_checkpoint_resume_factory(move |scenario, source, _seed, checkpoint| {
        production_api::build_production_vm_lifecycle_loop_from_checkpoint(
            scenario,
            source,
            &resume_config,
            checkpoint,
        )
    })
    .with_white_box_policy_provider(move |_scenario| white_box_policies.clone())
}

pub(crate) fn production_qemu_lifecycle_config(
    backend: &ResolvedLocalBackend,
) -> Result<production_api::ProductionVmLifecycleConfig, CliError> {
    let (qemu, plugin) = match backend {
        ResolvedLocalBackend::Qemu { qemu, plugin, .. } => (qemu, plugin),
        #[cfg(any(test, feature = "test-double"))]
        ResolvedLocalBackend::Double => {
            return Err(backend_error(
                "production QEMU lifecycle requires the QEMU backend",
            ));
        }
    };
    let kernel = required_live_qemu_asset(
        "CRUCIBLE_KERNEL",
        option_env!("CRUCIBLE_AOS_KERNEL"),
        "kernel",
    )?;
    let root_image = required_live_qemu_asset(
        "CRUCIBLE_ROOT_IMAGE",
        option_env!("CRUCIBLE_AOS_ROOT_IMAGE"),
        "root image",
    )?;
    let run_state_root = std::env::var_os("CRUCIBLE_RUN_STATE_ROOT")
        .map(PathBuf::from)
        .ok_or_else(|| {
            backend_error(
                "production QEMU lifecycle requires CRUCIBLE_RUN_STATE_ROOT for durable process recovery",
            )
        })?;
    let native_guest_architecture = live_qemu_native_guest_architecture()?;
    let mut config = production_api::ProductionVmLifecycleConfig::new_for_guest_architecture(
        qemu,
        plugin,
        native_guest_architecture,
        kernel,
        root_image,
        run_state_root,
    )
    .with_root_image_format(production_api::ProductionRootImageFormat::Raw)
    .with_run_ceiling_icount(PRODUCTION_CLI_RUN_CEILING_ICOUNT)
    .with_quantum_budget(PRODUCTION_CLI_QUANTUM_BUDGET)
    .with_completion_timeout(PRODUCTION_CLI_COMPLETION_TIMEOUT);
    if let Some(kernel_cmdline) = live_qemu_kernel_cmdline() {
        config = config.with_kernel_cmdline_prefix(kernel_cmdline);
    }
    if live_qemu_validate_guest_asset_references()? {
        config = config.with_guest_asset_reference_validation();
    }
    if let Some((kernel, root_image, kernel_cmdline)) = live_qemu_aarch64_assets()? {
        config = config.with_guest_assets(
            crucible::VmArchitecture::Aarch64,
            kernel,
            root_image,
            kernel_cmdline,
        );
    }
    if let Some(initrd) = optional_live_qemu_asset(
        "CRUCIBLE_INITRD",
        option_env!("CRUCIBLE_AOS_INITRD"),
        "initrd",
    )? {
        config = config.with_initrd(initrd);
    }
    if let Some(gateway) =
        optional_live_qemu_asset("CRUCIBLE_DEBUG_GATEWAY", None, "debugger gateway")?
    {
        config = config.with_debug_gateway(gateway);
    }
    Ok(config)
}

pub(crate) fn append_qemu_control_plane_execution_proof(
    outcome: &mut BackendCommandOutcome,
    backend: &ResolvedLocalBackend,
    operation: &'static str,
) {
    let (qemu_build_id, plugin_abi) = match backend {
        ResolvedLocalBackend::Qemu {
            qemu_build_id,
            plugin_abi,
            ..
        } => (qemu_build_id, plugin_abi),
        #[cfg(any(test, feature = "test-double"))]
        ResolvedLocalBackend::Double => return,
    };
    outcome.stdout.push(format!(
        "qemu-live\toperation={operation}\tqemu_build_id={qemu_build_id}\tplugin_abi={plugin_abi}"
    ));
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: outcome.canonical_log.len() as u64,
        node: String::from("qemu"),
        kind: String::from("live_backend_execution"),
        summary: format!(
            "operation={operation} qemu_build_id={qemu_build_id} plugin_abi={plugin_abi}"
        ),
    });
    outcome.canonical_log_digest = canonical_log_digest(&outcome.canonical_log);
}
