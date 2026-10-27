//! Coverage-guided live QEMU fuzzing through the guarded campaign owner.

use super::*;

use crucible_campaign::{StopCondition, StopOutcome};
use crucible_daemon::qemu_campaign_lifecycle::{
    GuardedCampaignExploration, GuardedCampaignExplorationStrategy, GuardedCampaignRunSink,
    GuardedCampaignRunSinkError, GuardedDefaultCampaignObservation, GuardedDefaultCampaignRun,
    GuardedDefaultCampaignRunRequest, run_guarded_default_campaign_with_sink,
};

#[path = "fuzz/corpus.rs"]
mod corpus;
use corpus::{
    CorpusPayloadStore, load_qemu_fuzz_corpus, load_qemu_fuzz_entry_payload,
    persist_qemu_fuzz_corpus, store_qemu_fuzz_entry,
};

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
        std::sync::Arc::new(crucible_engine::LocalDagStore::new(plan.store_root.clone()));
    let config = crucible_daemon::with_production_qemu_coverage(
        production_qemu_lifecycle_config(backend)?,
        true,
    )
    .with_run_ceiling_ticks(LIVE_FUZZ_RUN_CEILING_TICKS)
    .with_quantum_budget(LIVE_FUZZ_QUANTUM_LIMIT)
    .with_world_artifacts(lifecycle_artifacts.clone())
    .with_signal_artifacts(lifecycle_artifacts);
    let deployment = load_guarded_campaign_deployment(plan.campaign_deployment.as_deref())?;
    let attempt_policy = deployment.attempt_policy;
    if deployment.resources.maximum_execution_quanta() < LIVE_FUZZ_QUANTUM_LIMIT {
        return Err(backend_error(format!(
            "campaign deployment admits {} execution quanta, below the fuzz requirement of {}",
            deployment.resources.maximum_execution_quanta(),
            LIVE_FUZZ_QUANTUM_LIMIT,
        )));
    }
    let (previous_corpus, payloads) = match &plan.corpus {
        Some(corpus) => (
            load_qemu_fuzz_corpus(corpus)?,
            CorpusPayloadStore::durable(corpus),
        ),
        None => (Vec::new(), CorpusPayloadStore::scratch()?),
    };
    let execution_context = QemuFuzzExecutionContext {
        config: &config,
        host: &deployment.host,
        resources: deployment.resources,
        attempt_policy,
        plan,
        backend_plan,
        payloads: &payloads,
    };
    let execution = execute_qemu_fuzz_iterations(&execution_context, &family, previous_corpus)?;
    let (retained_entries, store_puts) = match &plan.corpus {
        Some(corpus) => persist_qemu_fuzz_corpus(corpus, &execution.corpus)?,
        None => (0, 0),
    };
    let mut report = FuzzExecutionReport {
        family: plan.family.label(),
        corpus: plan.corpus.clone(),
        iterations: execution.campaigns.len(),
        coverage_biased_order: execution
            .campaigns
            .iter()
            .map(|campaign| campaign.branch_requests)
            .sum(),
        new_coverage: execution.new_coverage,
        retained_entries,
        admissions: execution.admissions,
        replay_oracle_validations: execution.replay_oracle_validations,
        generated_mutants: execution
            .campaigns
            .iter()
            .map(|campaign| campaign.override_observations as u64)
            .sum(),
        store_puts,
        property_findings: 0,
        timeout_findings: 0,
    };
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
    for (index, coverage) in execution.coverage.iter().enumerate() {
        outcome.canonical_log.push(CanonicalLogEntry {
            sequence: outcome.canonical_log.len() as u64,
            virtual_time_ticks: outcome.canonical_log.len() as u64,
            node: String::from("qemu"),
            kind: String::from("fuzz_coverage_feedback"),
            summary: format!(
                "iteration={index}\tblocks={}\tfingerprint={}",
                coverage.hits,
                coverage.fingerprint.to_hex()
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
                "iteration={} sample_index={} energy={} parent={} campaign={} snapshot={} observation={} configuration={} stop={} observations={} branch_requests={} override_observations={} quanta={} backend=live",
                campaign.iteration,
                campaign.sample_index,
                campaign.energy,
                campaign.parent.as_deref().unwrap_or("seed"),
                campaign.campaign,
                campaign.snapshot,
                campaign.observation,
                campaign.configuration.to_hex(),
                campaign.stop,
                campaign.accepted_observations,
                campaign.branch_requests,
                campaign.override_observations,
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
    coverage: Vec<QemuFuzzCoverageSummary>,
    corpus: Vec<LiveFuzzCorpusEntry>,
    admissions: usize,
    replay_oracle_validations: u64,
    new_coverage: usize,
    campaigns: Vec<QemuFuzzCampaignRecord>,
    findings: Vec<TriageFindingEvidence>,
    reproduction_artifacts: Vec<Vec<u8>>,
}

/// Coverage reported for one accepted observation in the canonical log.
struct QemuFuzzCoverageSummary {
    hits: u64,
    fingerprint: crucible_engine::ContentHash,
}

/// Resident handle of one corpus entry.
///
/// Parent selection, admission, and guidance read only these fields. The
/// entry's reproduction artifact and replay closure stay in the corpus
/// payload store until the entry is chosen as a parent.
struct LiveFuzzCorpusEntry {
    descriptor: crucible_engine::ContentHash,
    artifact_id: crucible_engine::ContentHash,
    scenario_form_id: crucible_engine::ContentHash,
    coverage_fingerprint: crucible_engine::ContentHash,
    coverage_ids: std::collections::BTreeSet<crucible_engine::ContentHash>,
    novel_coverage: usize,
    resumable_choice: bool,
    // Whether this run wrote the entry's objects, as opposed to opening them.
    stored_this_run: bool,
}

/// One accepted observation with the payloads its corpus entry would store.
///
/// Candidates live only until admission decides whether to store them.
struct LiveFuzzCorpusCandidate {
    artifact: crucible_engine::ReproductionArtifact,
    coverage: crucible_engine::EventLogCoverageSet,
    coverage_ids: std::collections::BTreeSet<crucible_engine::ContentHash>,
    parent: Option<crucible_engine::ContentHash>,
    sample_index: u64,
    energy: u64,
    replay_closure: crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignReplayClosure,
    resumable_choice: bool,
}

struct QemuFuzzCampaignRecord {
    iteration: u64,
    sample_index: u64,
    energy: u64,
    parent: Option<String>,
    campaign: String,
    snapshot: crucible_campaign::CampaignSnapshotId,
    observation: crucible_campaign::ObservationId,
    configuration: crucible_engine::ContentHash,
    stop: String,
    accepted_observations: usize,
    branch_requests: usize,
    override_observations: usize,
    frontier: crucible_engine::VirtualTime,
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
    qemu_fuzz_stop_status(campaign.terminal().observation().stop())
}

fn qemu_fuzz_stop_status(
    stop: &StopOutcome,
) -> Result<(BackendCommandStatus, OutcomeKind, bool), CliError> {
    match stop {
        StopOutcome::Reached(StopCondition::NextChoiceOrExecutionQuanta { execution_quanta })
            if *execution_quanta == LIVE_FUZZ_QUANTUM_LIMIT =>
        {
            Ok((BackendCommandStatus::Passed, OutcomeKind::Passed, true))
        }
        StopOutcome::TerminalSuccess => {
            Ok((BackendCommandStatus::Passed, OutcomeKind::Passed, true))
        }
        StopOutcome::ModeledTimeout(name) if name == "execution-quanta" => {
            Ok((BackendCommandStatus::Timeout, OutcomeKind::Timeout, true))
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
        StopOutcome::Reached(_)
        | StopOutcome::BoundedPrimaryReached { .. }
        | StopOutcome::ObservationReached(_) => Err(backend_error(
            "campaign fuzz ended at an unexpected campaign boundary",
        )),
    }
}

fn qemu_fuzz_campaign_stop_label(stop: &StopOutcome) -> String {
    match stop {
        StopOutcome::Reached(condition) => format!("reached:{condition:?}"),
        StopOutcome::BoundedPrimaryReached { stop, proof } => format!(
            "bounded-primary-reached:{:?}:frontier-ps={}:quanta={}",
            stop.primary(),
            proof.frontier_picoseconds(),
            proof.completed_quanta()
        ),
        StopOutcome::BoundedPrimaryTimeout { stop, proof } => format!(
            "bounded-primary-timeout:{:?}:frontier-ps={}:quanta={}",
            stop.primary(),
            proof.frontier_picoseconds(),
            proof.completed_quanta()
        ),
        StopOutcome::PolicyTimeout { stop, kind, proof } => format!(
            "policy-timeout:{kind:?}:{:?}:frontier-ps={}:quanta={}",
            stop.primary(),
            proof.frontier_picoseconds(),
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
    attempt_policy: GuardedCampaignAttemptPolicy,
    plan: &'a FuzzDriverPlan,
    backend_plan: &'a BackendSelectionPlan,
    payloads: &'a CorpusPayloadStore,
}

/// Folds each accepted observation of one fuzz campaign into a corpus candidate.
///
/// The campaign streams its observations, so the candidate is built while the
/// attempt's log segments are live and the observation itself is dropped.
struct QemuFuzzCandidateSink<'a> {
    form: &'a crucible_engine::ScenarioDefForm,
    parent: Option<crucible_engine::ContentHash>,
    sample_index: u64,
    energy: u64,
    override_observations: usize,
    candidates: Vec<LiveFuzzCorpusCandidate>,
    failure: Option<CliError>,
}

impl<'a> QemuFuzzCandidateSink<'a> {
    fn new(
        form: &'a crucible_engine::ScenarioDefForm,
        parent: Option<crucible_engine::ContentHash>,
        sample_index: u64,
        energy: u64,
    ) -> Self {
        Self {
            form,
            parent,
            sample_index,
            energy,
            override_observations: 0,
            candidates: Vec::new(),
            failure: None,
        }
    }
}

impl GuardedCampaignRunSink for QemuFuzzCandidateSink<'_> {
    fn on_observation(
        &mut self,
        accepted: &GuardedDefaultCampaignObservation,
    ) -> Result<(), GuardedCampaignRunSinkError> {
        match authenticate_qemu_fuzz_observation(
            self.form,
            accepted,
            self.parent,
            self.sample_index,
            self.energy,
        ) {
            Ok((overrides, candidate)) => {
                self.override_observations += usize::from(overrides);
                self.candidates.push(candidate);
                Ok(())
            }
            Err(error) => {
                let message = error.to_string();
                self.failure = Some(error);
                Err(GuardedCampaignRunSinkError::new(message))
            }
        }
    }
}

fn authenticate_qemu_fuzz_observation(
    form: &crucible_engine::ScenarioDefForm,
    accepted: &GuardedDefaultCampaignObservation,
    parent: Option<crucible_engine::ContentHash>,
    sample_index: u64,
    energy: u64,
) -> Result<(bool, LiveFuzzCorpusCandidate), CliError> {
    let configuration = accepted.configuration();
    accepted
        .replay_closure()
        .validate_for_schedule(form, &configuration.schedule)
        .map_err(|error| {
            artifact_error(format!("authenticate QEMU fuzz choice replay: {error}"))
        })?;

    let artifact = capture_qemu_fuzz_reproduction(form, configuration)?;
    let overrides = configuration
        .schedule
        .decision_history()
        .iter()
        .any(|decision| matches!(decision, crucible_engine::Decision::Override(_)));
    // One streamed pass keeps each distinct coverage observation once.
    let mut coverage = crucible_engine::EventLogCoverageSet::new();
    accepted
        .evidence()
        .try_for_each_event_log_entry(|entry| {
            coverage.observe(entry);
            Ok::<(), std::convert::Infallible>(())
        })
        .map_err(|error| artifact_error(format!("read QEMU fuzz event evidence: {error}")))?;
    Ok((
        overrides,
        LiveFuzzCorpusCandidate {
            artifact,
            coverage_ids: coverage.identities(),
            coverage,
            parent,
            sample_index,
            energy,
            replay_closure: accepted.replay_closure().clone(),
            resumable_choice: accepted.observation().stop().reached_next_choice(),
        },
    ))
}

fn capture_qemu_fuzz_reproduction(
    form: &crucible_engine::ScenarioDefForm,
    configuration: &crucible_engine::Configuration,
) -> Result<crucible_engine::ReproductionArtifact, CliError> {
    if configuration.def != form.scenario_def() {
        return Err(artifact_error(
            "QEMU fuzz accepted an observation for another pinned scenario",
        ));
    }

    let expected_state = crucible_engine::reduce(&configuration.def, &configuration.schedule)
        .map_err(|error| artifact_error(format!("reduce QEMU fuzz schedule: {error}")))?
        .id;
    let artifact = crucible_engine::ReproductionArtifact::capture(form, &configuration.schedule)
        .map_err(|error| artifact_error(format!("capture QEMU fuzz schedule: {error}")))?;
    artifact
        .verify_replay(expected_state)
        .map_err(|error| artifact_error(format!("replay QEMU fuzz schedule: {error}")))?;
    Ok(artifact)
}

fn select_qemu_fuzz_parent<'a>(
    corpus: &'a [LiveFuzzCorpusEntry],
    form: &crucible_engine::ScenarioDefForm,
    seed: crucible_engine::Seed,
    sequence: u64,
) -> Option<&'a LiveFuzzCorpusEntry> {
    corpus
        .iter()
        .filter(|entry| {
            entry.resumable_choice
                && entry.scenario_form_id == form.id()
                && !entry.coverage_ids.is_empty()
        })
        .max_by_key(|entry| {
            (
                entry.novel_coverage,
                crucible_engine::ContentHash::from_canonical_material(
                    "crucible.live-fuzz-corpus-parent.v1",
                    &format!(
                        "seed={}\nsequence={sequence}\nartifact={}\ncoverage={}",
                        seed.to_hex(),
                        entry.artifact_id.to_hex(),
                        entry.coverage_fingerprint.to_hex(),
                    ),
                ),
            )
        })
}

/// Admits candidates with novel coverage, storing each admitted one's payloads.
///
/// An admitted entry replaces every retained entry whose coverage it covers.
fn admit_qemu_fuzz_candidates(
    corpus: &mut Vec<LiveFuzzCorpusEntry>,
    observed: &mut std::collections::BTreeSet<crucible_engine::ContentHash>,
    guidance: &mut Vec<crucible_engine::ContentHash>,
    candidates: Vec<LiveFuzzCorpusCandidate>,
    payloads: &CorpusPayloadStore,
) -> Result<usize, CliError> {
    let mut admitted = 0;

    for candidate in candidates {
        let novel_coverage = admit_novel_coverage_feedback(
            observed,
            guidance,
            &candidate.coverage_ids,
            candidate.coverage.fingerprint(),
        );
        if novel_coverage == 0 {
            continue;
        }

        let entry = store_qemu_fuzz_entry(payloads, candidate, novel_coverage)?;
        corpus.retain(|retained| !retained.coverage_ids.is_subset(&entry.coverage_ids));
        corpus.push(entry);
        admitted += 1;
    }

    Ok(admitted)
}

fn admit_novel_coverage_feedback(
    observed: &mut std::collections::BTreeSet<crucible_engine::ContentHash>,
    guidance: &mut Vec<crucible_engine::ContentHash>,
    coverage_ids: &std::collections::BTreeSet<crucible_engine::ContentHash>,
    fingerprint: crucible_engine::ContentHash,
) -> usize {
    let novel = coverage_ids.difference(observed).count();
    if novel > 0 {
        observed.extend(coverage_ids.iter().copied());
        guidance.push(fingerprint);
    }
    novel
}

fn execute_qemu_fuzz_iterations(
    context: &QemuFuzzExecutionContext<'_>,
    family: &crucible_engine::ScenarioFamily,
    previous_corpus: Vec<LiveFuzzCorpusEntry>,
) -> Result<QemuFuzzExecution, CliError> {
    let mut observed_coverage = std::collections::BTreeSet::new();
    let mut guidance = Vec::with_capacity(previous_corpus.len());
    for entry in &previous_corpus {
        observed_coverage.extend(entry.coverage_ids.iter().copied());
        guidance.push(entry.coverage_fingerprint);
    }
    let mut execution = QemuFuzzExecution {
        replay_oracle_validations: previous_corpus.len() as u64,
        corpus: previous_corpus,
        ..QemuFuzzExecution::default()
    };
    for sequence in 0..context.plan.config.iterations {
        let (sample_index, pinned, energy) = family
            .sample_coverage_guided_by_fingerprint(context.plan.config, sequence, &guidance)
            .map_err(|error| backend_error(format!("sample QEMU fuzz family: {error}")))?;
        let form = pinned.into_form();
        let run_plan = qemu_fuzz_iteration_plan(sequence, form.clone());
        let parent = select_qemu_fuzz_parent(
            &execution.corpus,
            &form,
            context.plan.config.meta_seed,
            sequence,
        );
        let parent_id = parent.map(|entry| entry.artifact_id);
        // Only the chosen parent's payloads are read back from the corpus store.
        let parent_payload = parent
            .map(|entry| load_qemu_fuzz_entry_payload(context.payloads, entry))
            .transpose()?;
        let exploration = GuardedCampaignExploration::new(
            2 + (energy % 2),
            None,
            true,
            GuardedCampaignExplorationStrategy::CoverageGuided,
        )
        .and_then(|exploration| exploration.with_execution_quanta_timeout(LIVE_FUZZ_QUANTUM_LIMIT))
        .map_err(|error| backend_error(format!("build QEMU fuzz exploration: {error}")))?;
        let request = GuardedDefaultCampaignRunRequest::new(
            form.clone(),
            form.scenario_def().seed(),
            env!("CARGO_PKG_VERSION"),
            qemu_build_id(context.backend_plan)?,
            context.config.clone(),
            context.host.clone(),
            context.resources,
        );
        let request = match parent_payload {
            Some((artifact, replay_closure)) => {
                request.with_initial_replay(artifact.schedule().clone(), Some(replay_closure))
            }
            None => request,
        }
        .with_exploration(exploration);
        let request = context.attempt_policy.apply(request);
        let mut sink = QemuFuzzCandidateSink::new(&form, parent_id, sample_index, energy);
        let campaign = run_guarded_default_campaign_with_sink(request, &mut sink);
        if let Some(failure) = sink.failure.take() {
            return Err(failure);
        }
        let campaign = campaign.map_err(|error| {
            backend_error(format!(
                "execute QEMU fuzz iteration {sequence} through campaign owner: {error}",
            ))
        })?;
        let QemuFuzzCandidateSink {
            override_observations,
            candidates,
            ..
        } = sink;
        let (status, terminal_outcome, campaign_completion) = qemu_fuzz_campaign_status(&campaign)?;
        // A fuzz iteration requests no watch frames.
        let report = crate::cli_verify_serve::campaign_run::campaign_run_report(
            &run_plan,
            &campaign,
            &[],
            terminal_outcome,
            status,
        )?;
        let terminal = campaign.terminal();
        execution.campaigns.push(QemuFuzzCampaignRecord {
            iteration: sequence,
            sample_index,
            energy,
            parent: parent_id.map(|parent| parent.to_hex()),
            campaign: campaign.campaign().as_str().to_owned(),
            snapshot: campaign.final_snapshot(),
            observation: terminal.id(),
            configuration: terminal.configuration().id(),
            stop: qemu_fuzz_campaign_stop_label(terminal.observation().stop()),
            accepted_observations: campaign.observation_count(),
            branch_requests: campaign.branch_request_count(),
            override_observations,
            frontier: campaign.evidence().frontier(),
            quanta: campaign.evidence().quanta(),
        });
        if report.status == BackendCommandStatus::Crashed {
            let last_event = report.streamed_events.last().map_or("none", String::as_str);
            return Err(backend_error(format!(
                "QEMU fuzz iteration {sequence} crashed before producing campaign evidence: \
                 outcome={:?} final_state={} frontier_ticks={} quanta={} last_event={last_event}",
                report.outcome,
                report.final_state,
                report.final_frontier_ticks,
                report.final_quanta,
            )));
        }
        if report.coverage_feedback.projection().is_empty() {
            return Err(backend_error(format!(
                "QEMU fuzz iteration {sequence} produced no basic-block coverage",
            )));
        }
        let finding = qemu_fuzz_finding_evidence(
            &form,
            &report,
            terminal.observation().stop(),
            sequence,
            context.backend_plan,
            campaign_completion,
        )?;
        execution
            .coverage
            .extend(candidates.iter().map(|candidate| QemuFuzzCoverageSummary {
                hits: candidate.coverage.hits(),
                fingerprint: candidate.coverage.fingerprint(),
            }));
        execution.admissions += candidates.len();
        execution.replay_oracle_validations += candidates.len() as u64;
        let admitted = admit_qemu_fuzz_candidates(
            &mut execution.corpus,
            &mut observed_coverage,
            &mut guidance,
            candidates,
            context.payloads,
        )?;
        execution.new_coverage += usize::from(admitted > 0);
        if let Some((evidence, reproduction)) = finding {
            let store = crucible_engine::LocalDagStore::new(context.plan.store_root.clone());
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
    form: &crucible_engine::ScenarioDefForm,
    report: &RunWorkflowReport,
    stop: &StopOutcome,
    sequence: u64,
    backend_plan: &BackendSelectionPlan,
    campaign_completion: bool,
) -> Result<Option<(crate::cli_report::TriageFindingEvidence, Vec<u8>)>, CliError> {
    if campaign_completion || report.status == BackendCommandStatus::Passed {
        return Ok(None);
    }
    let terminal = report.terminal_configuration.as_ref().ok_or_else(|| {
        backend_error(format!(
            "QEMU fuzz iteration {sequence} did not retain a terminal configuration"
        ))
    })?;
    let finding_fingerprint = crucible_engine::ContentHash::from_canonical_material(
        "crucible.live-qemu-fuzz-finding.v2",
        &format!(
            "configuration={}\noutcome={}",
            terminal.id().to_hex(),
            report.status.label()
        ),
    );
    let finding = crucible_engine::FindingReproductionArtifact::capture(
        crucible_engine::FindingDiscoveryPath::CoverageGuidedFuzzing,
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
            let (budget_kind, configured_limit) = qemu_fuzz_timeout_budget(stop)?;
            let timeout = crucible_model::FailureTimeoutRecord::new(
                budget_kind,
                configured_limit,
                report.final_quanta,
                crucible_engine::VirtualTime {
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
                "QEMU fuzz iteration {sequence} crashed before producing campaign evidence"
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

fn qemu_fuzz_timeout_budget(
    stop: &StopOutcome,
) -> Result<(crucible_model::FailureTimeoutBudgetKind, Option<u64>), CliError> {
    use crucible_campaign::PolicyTimeoutKind;
    use crucible_model::FailureTimeoutBudgetKind;

    match stop {
        StopOutcome::ModeledTimeout(name) if name == "execution-quanta" => Ok((
            FailureTimeoutBudgetKind::ExecutionQuanta,
            Some(LIVE_FUZZ_QUANTUM_LIMIT),
        )),
        StopOutcome::ModeledTimeout(name) if name == "virtual-time" => {
            Ok((FailureTimeoutBudgetKind::VirtualTime, None))
        }
        StopOutcome::BoundedPrimaryTimeout { stop, .. } => match stop.primary() {
            StopCondition::NextChoiceOrExecutionQuanta { execution_quanta } => Ok((
                FailureTimeoutBudgetKind::ExecutionQuanta,
                Some(*execution_quanta),
            )),
            _ => Err(artifact_error(
                "QEMU fuzz primary timeout lacks an execution-quanta bound",
            )),
        },
        StopOutcome::PolicyTimeout { stop, kind, .. } => match (stop, kind) {
            (
                StopCondition::Bounded {
                    virtual_time_picoseconds: Some(limit),
                    ..
                },
                PolicyTimeoutKind::VirtualTime,
            ) => Ok((FailureTimeoutBudgetKind::VirtualTime, Some(*limit))),
            (
                StopCondition::Bounded {
                    execution_quanta: Some(limit),
                    ..
                },
                PolicyTimeoutKind::ExecutionQuanta,
            ) => Ok((FailureTimeoutBudgetKind::ExecutionQuanta, Some(*limit))),
            _ => Err(artifact_error(
                "QEMU fuzz policy timeout lacks its typed bound",
            )),
        },
        _ => Err(artifact_error(
            "QEMU fuzz timeout has no supported deterministic budget kind",
        )),
    }
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

fn qemu_fuzz_iteration_plan(
    sequence: u64,
    form: crucible_engine::ScenarioDefForm,
) -> RunInvocationPlan {
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

#[cfg(test)]
mod finding_tests {
    use super::*;

    #[test]
    fn qemu_fuzz_reproduction_checks_reduced_state_identity()
    -> Result<(), Box<dyn std::error::Error>> {
        let scenario = crucible_engine::happy_path_scenario()?.scenario;
        let configuration = crucible_engine::Configuration::genesis(scenario.scenario_def());
        let expected_state =
            crucible_engine::reduce(&configuration.def, &configuration.schedule)?.id;

        assert_ne!(configuration.id(), expected_state);
        let artifact = capture_qemu_fuzz_reproduction(&scenario, &configuration)?;
        assert_eq!(
            artifact.verify_replay(expected_state)?.state,
            expected_state
        );
        assert!(artifact.verify_replay(configuration.id()).is_err());

        let other_scenario = crucible_engine::partition_recovery_scenario()?.scenario;
        assert!(capture_qemu_fuzz_reproduction(&other_scenario, &configuration).is_err());
        Ok(())
    }

    #[test]
    fn duplicate_coverage_does_not_enter_future_sampling_guidance() {
        let feedback = crate::crucible_engine::ContentHash::default();
        let first = crate::crucible_engine::ContentHash::from_bytes(b"covered-block");
        let second = crate::crucible_engine::ContentHash::from_bytes(b"new-block");
        let mut observed = std::collections::BTreeSet::new();
        let mut guidance = Vec::new();

        assert_eq!(
            admit_novel_coverage_feedback(
                &mut observed,
                &mut guidance,
                &std::collections::BTreeSet::from([first]),
                feedback,
            ),
            1,
        );
        assert_eq!(
            admit_novel_coverage_feedback(
                &mut observed,
                &mut guidance,
                &std::collections::BTreeSet::from([first]),
                feedback,
            ),
            0,
        );
        assert_eq!(guidance.len(), 1);
        assert_eq!(
            admit_novel_coverage_feedback(
                &mut observed,
                &mut guidance,
                &std::collections::BTreeSet::from([first, second]),
                feedback,
            ),
            1,
        );
        assert_eq!(guidance.len(), 2);
    }

    #[test]
    fn policy_virtual_timeout_keeps_its_budget_domain() -> Result<(), Box<dyn std::error::Error>> {
        let stop = StopCondition::bounded(
            StopCondition::NextChoiceOrExecutionQuanta {
                execution_quanta: LIVE_FUZZ_QUANTUM_LIMIT,
            },
            Some(80),
            Some(300),
        )?;
        let proof = crucible_campaign::BoundedStopProof::new(80, 12);
        let virtual_timeout = StopOutcome::PolicyTimeout {
            stop: stop.clone(),
            kind: crucible_campaign::PolicyTimeoutKind::VirtualTime,
            proof,
        };
        let quantum_timeout = StopOutcome::PolicyTimeout {
            stop,
            kind: crucible_campaign::PolicyTimeoutKind::ExecutionQuanta,
            proof,
        };

        assert_eq!(
            qemu_fuzz_timeout_budget(&virtual_timeout)?,
            (
                crucible_model::FailureTimeoutBudgetKind::VirtualTime,
                Some(80)
            ),
        );
        assert_eq!(
            qemu_fuzz_timeout_budget(&quantum_timeout)?,
            (
                crucible_model::FailureTimeoutBudgetKind::ExecutionQuanta,
                Some(300)
            ),
        );
        Ok(())
    }

    #[test]
    fn collect_fuzz_deduplicates_identical_phase_reproductions()
    -> Result<(), Box<dyn std::error::Error>> {
        let scenario = crucible_engine::happy_path_scenario()?.scenario;
        let configuration = crucible_engine::Configuration::genesis(scenario.scenario_def());
        let finding = crucible_engine::FindingReproductionArtifact::capture(
            crucible_engine::FindingDiscoveryPath::CoverageGuidedFuzzing,
            crucible_engine::ContentHash::from_bytes(b"repeated-fuzz-timeout"),
            &scenario,
            &configuration,
        )?;
        let inconsistent_timeout = crucible_model::FailureTimeoutRecord::new(
            crucible_model::FailureTimeoutBudgetKind::ExecutionQuanta,
            Some(10),
            10,
            crucible_engine::VirtualTime { ticks: 4 },
            Some(crucible_engine::Icount { retired: 10 }),
            None,
            finding.artifact.id(),
        );
        assert!(
            crate::cli_triage_debug::triage_timeout_evidence(
                finding.clone(),
                inconsistent_timeout,
                crucible_engine::ContentHash::from_bytes(b"repeated-fuzz-coverage"),
                Vec::new(),
            )
            .is_err()
        );

        let timeout = crucible_model::FailureTimeoutRecord::new(
            crucible_model::FailureTimeoutBudgetKind::ExecutionQuanta,
            Some(10),
            10,
            crucible_engine::VirtualTime { ticks: 4 },
            None,
            None,
            finding.artifact.id(),
        );
        let evidence = crate::cli_triage_debug::triage_timeout_evidence(
            finding,
            timeout,
            crucible_engine::ContentHash::from_bytes(b"repeated-fuzz-coverage"),
            Vec::new(),
        )?;
        let mut execution = QemuFuzzExecution::default();
        push_qemu_fuzz_finding(&mut execution, evidence.clone(), vec![1, 2, 3])?;
        push_qemu_fuzz_finding(&mut execution, evidence.clone(), vec![1, 2, 3])?;
        assert_eq!(execution.findings.len(), 1);
        assert_eq!(execution.reproduction_artifacts.len(), 1);
        assert!(push_qemu_fuzz_finding(&mut execution, evidence, vec![4, 5, 6]).is_err());
        Ok(())
    }

    #[test]
    fn cli_search_fuzz_live_qemu_iterations_bound_the_campaign()
    -> Result<(), Box<dyn std::error::Error>> {
        let scenario = crucible_engine::happy_path_scenario()?.scenario;
        let plan = qemu_fuzz_iteration_plan(0, scenario);

        assert_eq!(plan.max_quanta, Some(LIVE_FUZZ_QUANTUM_LIMIT));
        assert_eq!(LIVE_FUZZ_RUN_CEILING_TICKS, 51_000_000);
        assert_eq!(
            LIVE_EXPLORATION_RUN_CEILING_TICKS / ::crucible_engine::SIM_TICKS_PER_NS,
            1_500_000_000,
        );
        assert_eq!(
            PRODUCTION_CLI_RUN_CEILING_TICKS / ::crucible_engine::SIM_TICKS_PER_NS,
            5_000_000_000,
        );
        assert_eq!(plan.execution_mode, RunExecutionMode::ToCompletion);
        assert_eq!(
            qemu_fuzz_stop_status(&StopOutcome::Reached(
                StopCondition::NextChoiceOrExecutionQuanta {
                    execution_quanta: LIVE_FUZZ_QUANTUM_LIMIT,
                },
            ))?,
            (BackendCommandStatus::Passed, OutcomeKind::Passed, true),
        );
        assert_eq!(
            qemu_fuzz_stop_status(&StopOutcome::ModeledTimeout(String::from(
                "execution-quanta"
            )))?,
            (BackendCommandStatus::Timeout, OutcomeKind::Timeout, true),
        );
        assert!(qemu_fuzz_stop_status(&StopOutcome::Reached(StopCondition::NextChoice)).is_err());
        Ok(())
    }
}
