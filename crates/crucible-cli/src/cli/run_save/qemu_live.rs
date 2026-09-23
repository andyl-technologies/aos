//! Live local backend execution through the packaged patched emulator and plugin.

use super::*;

use std::sync::Arc;

use crucible_campaign::{
    ObservationCondition, ObservationStopSatisfaction, StopCondition, StopOutcome,
};
use crucible_daemon::qemu_campaign_lifecycle::{
    GuardedDefaultCampaignRun, GuardedDefaultCampaignRunRequest, run_guarded_default_campaign,
};

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

#[cfg(not(any(test, feature = "test-double")))]
pub(crate) fn run_selftest(cli: &Cli, args: &SelftestArgs) -> Result<SelftestReport, CliError> {
    #[cfg(target_os = "linux")]
    let mut probe = ProductionLiveQemuProbeRunner::new(cli.campaign_deployment.clone());
    #[cfg(not(target_os = "linux"))]
    let mut probe = ProductionLiveQemuProbeRunner;

    run_selftest_with_probe(cli, args, &mut probe)
}

#[cfg(any(test, feature = "test-double"))]
pub(crate) fn run_selftest(cli: &Cli, args: &SelftestArgs) -> Result<SelftestReport, CliError> {
    run_selftest_with_probe(cli, args, &mut TestDoubleSelftestProbeRunner)
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
    let lifecycle_artifacts =
        std::sync::Arc::new(crucible::LocalDagStore::new(plan.store_root.clone()));
    let config = crucible_daemon::with_production_qemu_coverage(
        production_qemu_lifecycle_config(backend)?,
        true,
    )
    .with_run_ceiling_icount(LIVE_FUZZ_RUN_CEILING_ICOUNT)
    .with_quantum_budget(LIVE_FUZZ_QUANTUM_LIMIT)
    .with_world_artifacts(lifecycle_artifacts.clone())
    .with_signal_artifacts(lifecycle_artifacts);
    let deployment = load_guarded_campaign_deployment(plan.campaign_deployment.as_deref())?;
    let verify_determinism_findings = deployment.verify_determinism_findings;
    if deployment.resources.maximum_execution_quanta() < LIVE_FUZZ_QUANTUM_LIMIT {
        return Err(backend_error(format!(
            "campaign deployment admits {} execution quanta, below the fuzz requirement of {}",
            deployment.resources.maximum_execution_quanta(),
            LIVE_FUZZ_QUANTUM_LIMIT,
        )));
    }
    let execution_context = QemuFuzzExecutionContext {
        config: &config,
        host: &deployment.host,
        resources: deployment.resources,
        verify_determinism_findings,
        plan,
        backend_plan,
    };
    let warmup = family
        .fuzz_coverage_guided(plan.config, &[])
        .map_err(|error| backend_error(format!("QEMU fuzz warm-up policy failed: {error}")))?;
    let mut execution = execute_qemu_fuzz_iterations(&execution_context, &warmup, "warm-up")?;
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
            fuzz_execution_report_from_corpus_run(plan, corpus, &corpus_run),
        )
    } else {
        let run = family
            .fuzz_coverage_guided(plan.config, &execution.feedback)
            .map_err(|error| backend_error(format!("QEMU fuzz policy failed: {error}")))?;
        let report = fuzz_execution_report_from_run(plan, &run);
        (run, report)
    };
    let guided_execution =
        if plan.on_violation == SearchOnViolationArg::Stop && !execution.findings.is_empty() {
            QemuFuzzExecution::default()
        } else {
            execute_qemu_fuzz_iterations(&execution_context, &run, "guided")?
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
    apply_fuzz_execution_report(&mut outcome, plan, &report);
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
    for campaign in &execution.campaigns {
        outcome.canonical_log.push(CanonicalLogEntry {
            sequence: outcome.canonical_log.len() as u64,
            virtual_time_ticks: campaign.frontier.ticks,
            node: String::from("campaign"),
            kind: String::from("fuzz_campaign_execution"),
            summary: format!(
                "phase={} iteration={} campaign={} snapshot={} observation={} configuration={} stop={} observations={} quanta={} backend=live",
                campaign.phase,
                campaign.iteration,
                campaign.campaign,
                campaign.snapshot,
                campaign.observation,
                campaign.configuration.to_hex(),
                campaign.stop,
                campaign.accepted_observations,
                campaign.quanta,
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
    campaigns: Vec<QemuFuzzCampaignRecord>,
    findings: Vec<TriageFindingEvidence>,
    reproduction_artifacts: Vec<Vec<u8>>,
}

struct QemuFuzzCampaignRecord {
    phase: String,
    iteration: u64,
    campaign: String,
    snapshot: crucible_campaign::CampaignSnapshotId,
    observation: crucible_campaign::ObservationId,
    configuration: crucible::ContentHash,
    stop: String,
    accepted_observations: usize,
    frontier: crucible::VirtualTime,
    quanta: u64,
}

fn qemu_build_id(backend_plan: &BackendSelectionPlan) -> Result<String, CliError> {
    match backend_plan.resolved_backend.as_ref() {
        Some(ResolvedLocalBackend::Qemu { qemu_build_id, .. }) => Ok(qemu_build_id.clone()),
        #[cfg(any(test, feature = "test-double"))]
        Some(ResolvedLocalBackend::Double) => Err(backend_error(
            "campaign QEMU fuzz requires a resolved production backend",
        )),
        None => Err(backend_error(
            "campaign QEMU fuzz requires a resolved backend",
        )),
    }
}

fn qemu_fuzz_campaign_status(
    campaign: &GuardedDefaultCampaignRun,
) -> Result<(BackendCommandStatus, OutcomeKind, bool), CliError> {
    match campaign.terminal().observation().stop() {
        StopOutcome::ObservationReached(proof) => {
            qemu_fuzz_observation_status(proof.condition(), proof.satisfaction())
        }
        StopOutcome::TerminalSuccess => {
            Ok((BackendCommandStatus::Passed, OutcomeKind::Passed, true))
        }
        StopOutcome::ModeledTimeout(_)
        | StopOutcome::BoundedPrimaryTimeout { .. }
        | StopOutcome::PolicyTimeout { .. } => {
            Ok((BackendCommandStatus::Timeout, OutcomeKind::Timeout, false))
        }
        StopOutcome::GuestCrash(_) => {
            Ok((BackendCommandStatus::Crashed, OutcomeKind::Crashed, false))
        }
        StopOutcome::AssertionFailure(_) | StopOutcome::ScenarioFailure(_) => {
            Ok((BackendCommandStatus::Failed, OutcomeKind::Failed, false))
        }
        StopOutcome::Reached(_) | StopOutcome::BoundedPrimaryReached { .. } => Err(backend_error(
            "campaign fuzz ended at an unexpected campaign boundary",
        )),
    }
}

fn qemu_fuzz_observation_status(
    condition: &ObservationCondition,
    satisfaction: ObservationStopSatisfaction,
) -> Result<(BackendCommandStatus, OutcomeKind, bool), CliError> {
    if condition
        != &(ObservationCondition::SchedulerQuiescentOrExecutionQuanta {
            execution_quanta: LIVE_FUZZ_QUANTUM_LIMIT,
        })
    {
        return Err(backend_error(
            "campaign fuzz reached an observation condition it did not request",
        ));
    }

    match satisfaction {
        ObservationStopSatisfaction::SchedulerQuiescent => {
            Ok((BackendCommandStatus::Passed, OutcomeKind::Passed, true))
        }
        ObservationStopSatisfaction::ExecutionQuanta => {
            Ok((BackendCommandStatus::Timeout, OutcomeKind::Timeout, true))
        }
        ObservationStopSatisfaction::AssertionViolationTransition => Err(backend_error(
            "campaign fuzz compound completion carried an assertion-transition proof",
        )),
    }
}

fn qemu_fuzz_campaign_stop_label(stop: &StopOutcome) -> String {
    match stop {
        StopOutcome::Reached(condition) => format!("reached:{condition:?}"),
        StopOutcome::BoundedPrimaryReached { stop, proof } => format!(
            "bounded-primary-reached:{:?}:frontier-ns={}:quanta={}",
            stop.primary(),
            proof.frontier_nanoseconds(),
            proof.completed_quanta()
        ),
        StopOutcome::BoundedPrimaryTimeout { stop, proof } => format!(
            "bounded-primary-timeout:{:?}:frontier-ns={}:quanta={}",
            stop.primary(),
            proof.frontier_nanoseconds(),
            proof.completed_quanta()
        ),
        StopOutcome::PolicyTimeout { stop, kind, proof } => format!(
            "policy-timeout:{kind:?}:{:?}:frontier-ns={}:quanta={}",
            stop.primary(),
            proof.frontier_nanoseconds(),
            proof.completed_quanta()
        ),
        StopOutcome::TerminalSuccess => String::from("terminal-success"),
        StopOutcome::ModeledTimeout(name) => format!("modeled-timeout:{name}"),
        StopOutcome::GuestCrash(class) => format!("guest-crash:{class}"),
        StopOutcome::AssertionFailure(property) => format!("assertion-failure:{property}"),
        StopOutcome::ScenarioFailure(reasons) => {
            format!("scenario-failure:{}", reasons.join(","))
        }
        StopOutcome::ObservationReached(proof) => format!(
            "observation-reached:{:?}:{:?}",
            proof.condition(),
            proof.satisfaction()
        ),
    }
}

struct QemuFuzzExecutionContext<'a> {
    config: &'a production_api::ProductionVmLifecycleConfig,
    host: &'a crucible_daemon::LinuxQemuAttemptHostConfig,
    resources: crucible_campaign::AttemptResourceLimits,
    verify_determinism_findings: bool,
    plan: &'a FuzzDriverPlan,
    backend_plan: &'a BackendSelectionPlan,
}

fn execute_qemu_fuzz_iterations(
    context: &QemuFuzzExecutionContext<'_>,
    run: &crucible::CoverageGuidedFuzzRun,
    phase: &str,
) -> Result<QemuFuzzExecution, CliError> {
    let mut execution = QemuFuzzExecution {
        feedback: Vec::with_capacity(run.iterations.len()),
        campaigns: Vec::with_capacity(run.iterations.len()),
        ..QemuFuzzExecution::default()
    };
    for iteration in &run.iterations {
        let form = iteration.scenario.form().clone();
        let run_plan = qemu_fuzz_iteration_plan(iteration.sequence, form.clone());
        let schedule = iteration.schedule().clone();
        let request = GuardedDefaultCampaignRunRequest::new(
            form.clone(),
            form.scenario_def().seed(),
            env!("CARGO_PKG_VERSION"),
            qemu_build_id(context.backend_plan)?,
            context.config.clone(),
            context.host.clone(),
            context.resources,
        )
        .with_initial_replay(schedule, None)
        .with_discovery_stop(StopCondition::Observation(
            ObservationCondition::SchedulerQuiescentOrExecutionQuanta {
                execution_quanta: LIVE_FUZZ_QUANTUM_LIMIT,
            },
        ));
        let request =
            apply_guarded_campaign_determinism_policy(request, context.verify_determinism_findings);
        let campaign = run_guarded_default_campaign(request).map_err(|error| {
            backend_error(format!(
                "execute QEMU fuzz {phase} iteration {} through campaign owner: {error}",
                iteration.sequence,
            ))
        })?;
        let (status, terminal_outcome, campaign_completion) = qemu_fuzz_campaign_status(&campaign)?;
        let report = crate::cli_verify_serve::campaign_run::campaign_run_report(
            &run_plan,
            &campaign,
            terminal_outcome,
            status,
        )?;
        let terminal = campaign.terminal();
        execution.campaigns.push(QemuFuzzCampaignRecord {
            phase: phase.to_owned(),
            iteration: iteration.sequence,
            campaign: campaign.campaign().as_str().to_owned(),
            snapshot: campaign.final_snapshot(),
            observation: terminal.id(),
            configuration: terminal.configuration().id(),
            stop: qemu_fuzz_campaign_stop_label(terminal.observation().stop()),
            accepted_observations: campaign.observations().len(),
            frontier: campaign.evidence().frontier(),
            quanta: campaign.evidence().quanta(),
        });
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
        let recorded_selections = report
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
                crucible::Decision::Selection(selection) => Some(selection),
                _ => None,
            })
            .collect::<Vec<_>>();
        let expected_selections = iteration
            .schedule()
            // crucible-lint: allow host-nondeterminism-state -- the authored iteration schedule is immutable canonical input.
            .decisions()
            .iter()
            .filter_map(|decision| match decision {
                crucible::Decision::Selection(selection) => Some(selection),
                _ => None,
            })
            .collect::<Vec<_>>();
        if recorded_selections != expected_selections {
            return Err(backend_error(format!(
                "QEMU fuzz {phase} iteration {} recorded {} exact selections, expected {}",
                iteration.sequence,
                recorded_selections.len(),
                expected_selections.len(),
            )));
        }
        let finding = qemu_fuzz_finding_evidence(
            &form,
            &report,
            phase,
            iteration.sequence,
            context.backend_plan,
            campaign_completion,
        )?;
        execution.feedback.push(report.coverage_feedback);
        if let Some((evidence, reproduction)) = finding {
            let store = crucible::LocalDagStore::new(context.plan.store_root.clone());
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
            if context.plan.on_violation == SearchOnViolationArg::Stop {
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
    backend_plan: &BackendSelectionPlan,
    campaign_completion: bool,
) -> Result<Option<(crate::cli_report::TriageFindingEvidence, Vec<u8>)>, CliError> {
    if campaign_completion || report.status == BackendCommandStatus::Passed {
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
        LiveQemuReplayBranch::None,
    )?;
    Ok(Some((evidence, reproduction)))
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
    target.campaigns.extend(source.campaigns);
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
    let (path, digest, ledger_bytes) = crate::cli_triage_debug::write_reproduction_findings_ledger(
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
            Some(crucible::Icount { retired: 10 }),
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
        let condition = ObservationCondition::SchedulerQuiescentOrExecutionQuanta {
            execution_quanta: LIVE_FUZZ_QUANTUM_LIMIT,
        };
        assert_eq!(
            qemu_fuzz_observation_status(
                &condition,
                ObservationStopSatisfaction::SchedulerQuiescent,
            )?,
            (BackendCommandStatus::Passed, OutcomeKind::Passed, true),
        );
        assert_eq!(
            qemu_fuzz_observation_status(&condition, ObservationStopSatisfaction::ExecutionQuanta,)?,
            (BackendCommandStatus::Timeout, OutcomeKind::Timeout, true),
        );
        assert!(
            qemu_fuzz_observation_status(
                &ObservationCondition::SchedulerQuiescent,
                ObservationStopSatisfaction::SchedulerQuiescent,
            )
            .is_err()
        );
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
        host_profile: VERIFY_BASELINE_PROFILE,
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
        .ok_or_else(|| backend_error("local QEMU verify requires a resolved production backend"))?;
    if !matches!(backend, ResolvedLocalBackend::Qemu { .. }) {
        return Err(backend_error(
            "local QEMU verify requires the packaged QEMU backend",
        ));
    }
    let scenario = verify_plan.scenario().ok_or_else(|| {
        backend_error("artifact comparison must not enter local QEMU verification")
    })?;
    let request_seed = ergonomics_plan
        .map(|plan| crucible::Seed::from_u64(plan.seed.value))
        .unwrap_or_else(|| scenario.scenario_def().seed());
    let seeded_scenario = reseed_run_scenario_ref(scenario, request_seed)?;
    let mut witnesses = Vec::with_capacity(verify_plan.reductions.len());
    for reduction in &verify_plan.reductions {
        let mut run_plan =
            verify_run_invocation_plan(seeded_scenario.clone(), request_seed, reduction.clone());
        run_plan.startup_commands = vec![SessionCommandKind::Start, SessionCommandKind::Continue];
        run_plan.initial_control_commands = vec![SessionCommandKind::Query];
        run_plan.collect_execution_fingerprints = false;
        let (lifecycle, preemption_evidence) =
            verify_qemu_lifecycle_config(backend, reduction.host_profile)?;
        let host_pressure = VerifyQemuHostPressure::start(reduction.host_profile)?;
        let report = run_local_qemu_campaign_with_hostile_deadlines(
            backend,
            &run_plan,
            lifecycle,
            reduction.host_profile,
        );
        host_pressure.finish()?;
        let report = report?;
        let mut witness = verify_witness_from_run_report(
            reduction.clone(),
            &run_plan,
            &report,
            Some(backend),
            ergonomics_plan,
            &verify_plan.store_root,
        )?;
        witness.host_scheduler_preemption = preemption_evidence
            .map(|evidence| {
                required_scheduler_preemption_snapshot(
                    &evidence,
                    &format!(
                        "verify hostile profile `{}`",
                        reduction.host_profile.label()
                    ),
                    reduction.host_profile.host_io_stall_ms,
                )
            })
            .transpose()?;
        witnesses.push(witness);
    }
    let report = VerifyWorkflowReport {
        divergence: compare_verify_witnesses(&witnesses),
        witnesses,
    };
    let mut outcome = finish_verify_workflow_outcome(
        thin_plan,
        backend_plan,
        ergonomics_plan,
        verify_plan,
        report,
    )?;
    append_qemu_control_plane_execution_proof(
        &mut outcome,
        backend,
        "verify-campaign-default-path",
    );
    Ok(outcome)
}

fn verify_qemu_lifecycle_config(
    backend: &ResolvedLocalBackend,
    profile: VerifyHostProfile,
) -> Result<
    (
        production_api::ProductionVmLifecycleConfig,
        Option<crucible_api::BoundedSchedulerPreemptionEvidence>,
    ),
    CliError,
> {
    if !profile.is_valid() {
        return Err(backend_error(format!(
            "verify hostile host profile `{}` is invalid",
            profile.label()
        )));
    }

    let mut config = production_qemu_lifecycle_config(backend)?
        .with_maximum_host_workers(profile.executor_workers);
    let preemption_evidence = profile
        .requires_scheduler_preemption()
        .then(crucible_api::BoundedSchedulerPreemptionEvidence::default);
    if let Some(evidence) = preemption_evidence.as_ref() {
        config = config.with_bounded_scheduler_preemption(evidence.clone());
    }
    Ok((config, preemption_evidence))
}

fn run_local_qemu_campaign_with_hostile_deadlines(
    backend: &ResolvedLocalBackend,
    run_plan: &RunInvocationPlan,
    lifecycle: production_api::ProductionVmLifecycleConfig,
    profile: VerifyHostProfile,
) -> Result<RunWorkflowReport, CliError> {
    let completion_timeout = lifecycle.completion_timeout();
    std::thread::scope(|scope| {
        let (started_tx, started_rx) = std::sync::mpsc::sync_channel(0);
        let (report_tx, report_rx) = std::sync::mpsc::sync_channel(1);
        scope.spawn(move || {
            if started_tx.send(()).is_err() {
                return;
            }
            let report = crate::cli_verify_serve::campaign_run::run_local_qemu_campaign_report(
                backend, run_plan, lifecycle,
            );
            let _ = report_tx.send(report);
        });
        started_rx
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| {
                backend_error("local QEMU verify worker did not enter its live lifecycle operation")
            })?;

        if profile.applies_deadline_backstep() {
            let forward_timeout_ms = profile.jittered_timeout_ms(10, 1);
            let backstep_timeout_ms =
                profile.jittered_timeout_ms(10, u64::from(profile.wall_clock_backstep_every));
            if backstep_timeout_ms >= forward_timeout_ms {
                return Err(backend_error(format!(
                    "verify hostile profile `{}` did not configure a decreasing deadline sequence",
                    profile.label()
                )));
            }
            require_live_qemu_observer_timeout(
                &report_rx,
                Duration::from_millis(forward_timeout_ms),
                profile,
                "forward",
            )?;
            require_live_qemu_observer_timeout(
                &report_rx,
                Duration::from_millis(backstep_timeout_ms),
                profile,
                "backstep",
            )?;
        }

        report_rx
            .recv_timeout(completion_timeout.saturating_add(Duration::from_secs(5)))
            .map_err(|error| match error {
                std::sync::mpsc::RecvTimeoutError::Timeout => backend_error(format!(
                    "local QEMU verify exceeded its bounded lifecycle observation deadline for profile `{}`",
                    profile.label()
                )),
                std::sync::mpsc::RecvTimeoutError::Disconnected => backend_error(format!(
                    "local QEMU verify worker exited without a report for profile `{}`",
                    profile.label()
                )),
            })?
    })
}

fn require_live_qemu_observer_timeout(
    report_rx: &std::sync::mpsc::Receiver<Result<RunWorkflowReport, CliError>>,
    timeout: Duration,
    profile: VerifyHostProfile,
    phase: &str,
) -> Result<(), CliError> {
    match report_rx.recv_timeout(timeout) {
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Ok(()),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(backend_error(format!(
            "local QEMU verify worker exited during the {phase} deadline for profile `{}`",
            profile.label()
        ))),
        Ok(_) => Err(backend_error(format!(
            "local QEMU verify completed before applying the {phase} deadline for hostile profile `{}`",
            profile.label()
        ))),
    }
}

struct VerifyQemuHostPressure {
    stop: Arc<std::sync::atomic::AtomicBool>,
    wake: Arc<(std::sync::Mutex<()>, std::sync::Condvar)>,
    workers: Vec<std::thread::JoinHandle<()>>,
}

impl VerifyQemuHostPressure {
    fn start(profile: VerifyHostProfile) -> Result<Self, CliError> {
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let wake = Arc::new((std::sync::Mutex::new(()), std::sync::Condvar::new()));
        let pressure_workers = if profile.priority_pressure_iterations == 0 {
            0
        } else {
            profile.logical_cores
        };
        let (ready_tx, ready_rx) = std::sync::mpsc::sync_channel(pressure_workers);
        let mut workers: Vec<std::thread::JoinHandle<()>> = Vec::with_capacity(pressure_workers);
        let mut worker_round = 0_u64;
        for worker_index in 0..pressure_workers {
            let worker_stop = Arc::clone(&stop);
            let worker_wake = Arc::clone(&wake);
            let name = format!("crucible-verify-host-pressure-{worker_index}");
            let initial_round = worker_round;
            worker_round = worker_round.saturating_add(1);
            let worker_ready = ready_tx.clone();
            let worker = std::thread::Builder::new().name(name).spawn(move || {
                let mut round = initial_round;
                let mut ready = Some(worker_ready);
                while !worker_stop.load(std::sync::atomic::Ordering::Acquire) {
                    let mut accumulator = profile.scheduling_seed ^ round.rotate_left(19);
                    for iteration in 0..profile.priority_pressure_iterations {
                        accumulator = accumulator.rotate_left(7)
                            ^ iteration.wrapping_mul(0x517c_c1b7_2722_0a95);
                        std::hint::spin_loop();
                        if iteration.is_multiple_of(profile.priority_yield_every) {
                            std::thread::yield_now();
                        }
                    }
                    std::hint::black_box(accumulator);
                    if profile.host_io_stall_ms > 0 {
                        let (lock, event) = &*worker_wake;
                        let guard = lock
                            .lock()
                            .unwrap_or_else(std::sync::PoisonError::into_inner);
                        drop(
                            event
                                .wait_timeout_while(
                                    guard,
                                    Duration::from_millis(profile.host_io_stall_ms),
                                    |_| !worker_stop.load(std::sync::atomic::Ordering::Acquire),
                                )
                                .unwrap_or_else(std::sync::PoisonError::into_inner),
                        );
                    }
                    if let Some(ready) = ready.take() {
                        let _ = ready.send(());
                    }
                    round = round.saturating_add(1);
                }
            });
            let worker = match worker {
                Ok(worker) => worker,
                Err(error) => {
                    stop.store(true, std::sync::atomic::Ordering::Release);
                    wake.1.notify_all();
                    for started in workers {
                        let _ = started.join();
                    }
                    return Err(backend_error(format!(
                        "start verify host pressure worker {worker_index}: {error}"
                    )));
                }
            };
            workers.push(worker);
        }
        drop(ready_tx);
        for worker_index in 0..pressure_workers {
            if ready_rx.recv_timeout(Duration::from_secs(5)).is_err() {
                stop.store(true, std::sync::atomic::Ordering::Release);
                wake.1.notify_all();
                for started in workers {
                    let _ = started.join();
                }
                return Err(backend_error(format!(
                    "verify host pressure worker {worker_index} did not complete its first perturbation"
                )));
            }
        }
        Ok(Self {
            stop,
            wake,
            workers,
        })
    }

    fn finish(self) -> Result<(), CliError> {
        self.stop.store(true, std::sync::atomic::Ordering::Release);
        self.wake.1.notify_all();
        for (worker_index, worker) in self.workers.into_iter().enumerate() {
            worker.join().map_err(|_| {
                backend_error(format!(
                    "verify host pressure worker {worker_index} panicked"
                ))
            })?;
        }
        Ok(())
    }
}

pub(crate) fn required_scheduler_preemption_snapshot(
    evidence: &crucible_api::BoundedSchedulerPreemptionEvidence,
    operation: &str,
    minimum_requested_stopped_milliseconds: u64,
) -> Result<crucible_api::BoundedSchedulerPreemptionEvidenceSnapshot, CliError> {
    let snapshot = evidence.snapshot().ok_or_else(|| {
        backend_error(format!(
            "{operation} did not publish authenticated scheduler-preemption evidence"
        ))
    })?;
    if !snapshot.applied
        || !snapshot.pending_quantum_certified
        || snapshot.perturbations == 0
        || snapshot.requested_stopped_milliseconds == 0
        || snapshot.requested_stopped_milliseconds < minimum_requested_stopped_milliseconds
    {
        return Err(backend_error(format!(
            "{operation} published incomplete scheduler-preemption evidence"
        )));
    }
    Ok(snapshot)
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
    let mut config = crucible_daemon::with_production_qemu_raw_root_image(
        production_api::ProductionVmLifecycleConfig::new_for_guest_architecture(
            qemu,
            plugin,
            native_guest_architecture,
            kernel,
            root_image,
            run_state_root,
        ),
    )
    .with_run_ceiling_icount(PRODUCTION_CLI_RUN_CEILING_ICOUNT)
    .with_quantum_budget(PRODUCTION_CLI_QUANTUM_BUDGET)
    .with_completion_timeout(PRODUCTION_CLI_COMPLETION_TIMEOUT);
    if let Some(kernel_cmdline) = live_qemu_kernel_cmdline() {
        config = config.with_kernel_cmdline_prefix(kernel_cmdline);
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
