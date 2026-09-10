//! Live-QEMU search through the shared authenticated campaign owner.

use super::*;

use crucible_api as campaign_output_api;
use crucible_campaign::{
    ObservationCondition, ObservationStopSatisfaction, PropertyVerdict, StopOutcome,
};
use crucible_daemon::qemu_campaign_lifecycle::{
    GuardedCampaignExploration, GuardedCampaignExplorationCompletion,
    GuardedCampaignExplorationStrategy, GuardedCampaignFindingOracle,
    GuardedCampaignFindingOracleError, GuardedCampaignFindingOracleEvaluation,
    GuardedCampaignFindingOracleSource, GuardedDefaultCampaignObservation,
    GuardedDefaultCampaignRun, GuardedDefaultCampaignRunRequest, run_guarded_default_campaign,
};

enum QemuSearchSupplementalOracleSource {
    Named(SearchScheduleNamedTruthsPlan),
    Retained(SearchRetainedEvidencePlan),
}

struct QemuSearchSupplementalOracle {
    scenario: crucible::ScenarioDefForm,
    source: QemuSearchSupplementalOracleSource,
    source_record: GuardedCampaignFindingOracleSource,
}

impl QemuSearchSupplementalOracle {
    fn from_plan(plan: &SearchDriverPlan) -> Result<Option<Self>, CliError> {
        let source = match (&plan.schedule_named_truths, &plan.retained_evidence) {
            (Some(source), None) => QemuSearchSupplementalOracleSource::Named(source.clone()),
            (None, Some(source)) => QemuSearchSupplementalOracleSource::Retained(source.clone()),
            (None, None) => return Ok(None),
            (Some(_), Some(_)) => {
                return Err(backend_error(
                    "search plan contains both supplemental evidence sources",
                ));
            }
        };
        let (media_type, material) = match &source {
            QemuSearchSupplementalOracleSource::Named(source) => (
                SEARCH_SCHEDULE_NAMED_TRUTHS_MEDIA_TYPE,
                source.material.clone(),
            ),
            QemuSearchSupplementalOracleSource::Retained(source) => {
                (SEARCH_RETAINED_EVIDENCE_MEDIA_TYPE, source.material.clone())
            }
        };
        let scenario = crucible_campaign::ScenarioDefId::from_hash(
            crucible_campaign::CampaignHash::from_bytes(plan.scenario.scenario_form().id().bytes),
        );
        let source_record = GuardedCampaignFindingOracleSource::new(scenario, media_type, material)
            .map_err(|error| {
                backend_error(format!("encode supplemental search evidence: {error}"))
            })?;
        Ok(Some(Self {
            scenario: plan.scenario.scenario_form().clone(),
            source,
            source_record,
        }))
    }

    fn assertion_finding(
        &self,
        configuration: &crucible::Configuration,
    ) -> Result<Option<crucible::SearchAssertionFinding>, crucible::EngineError> {
        match &self.source {
            QemuSearchSupplementalOracleSource::Named(source) => {
                crucible::SearchFailureOracle::evaluate_configuration_with_named_predicates(
                    &self.scenario,
                    configuration,
                    &source.truths,
                )
            }
            QemuSearchSupplementalOracleSource::Retained(source) => source
                .evidence
                .get(&configuration.id())
                .map(|evidence| {
                    crucible::SearchFailureOracle::evaluate_configuration_with_retained_log_evidence(
                        &self.scenario,
                        configuration,
                        evidence,
                    )
                })
                .transpose()
                .map(Option::flatten),
        }
    }
}

impl GuardedCampaignFindingOracle for QemuSearchSupplementalOracle {
    fn source(&self) -> &GuardedCampaignFindingOracleSource {
        &self.source_record
    }

    fn evaluate(
        &self,
        configuration: &crucible::Configuration,
    ) -> Result<Option<GuardedCampaignFindingOracleEvaluation>, GuardedCampaignFindingOracleError>
    {
        self.assertion_finding(configuration)
            .map(|finding| finding.map(GuardedCampaignFindingOracleEvaluation::new))
            .map_err(|error| GuardedCampaignFindingOracleError::new(error.to_string()))
    }
}

struct QemuSearchFinding {
    failure: crucible::SearchDiscoveredFailure,
    evidence: crate::cli_report::TriageFindingEvidence,
    outcome: OutcomeKind,
    frontier: crucible::VirtualTime,
    quanta: u64,
    event_frames: Vec<Vec<u8>>,
    fingerprints: Vec<crucible::FingerprintSample>,
    resolved_effect_trace: Option<Vec<u8>>,
    replay_closure: crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignReplayClosure,
}

fn search_finding_reproduction_artifact_bytes(
    backend_plan: &BackendSelectionPlan,
    plan: &SearchDriverPlan,
    finding: &QemuSearchFinding,
    mutation: Option<&crucible::MaterializedSearchPlan>,
) -> Result<Vec<u8>, CliError> {
    let model = &finding.evidence.finding;
    let scenario = model.artifact.scenario_form();
    let mut canonical_log = canonical_log_entries_from_engine_schedule(model.artifact.schedule());
    let fingerprints = finding
        .fingerprints
        .iter()
        .enumerate()
        .map(|(index, sample)| VerifyFingerprintSample {
            index: index as u64,
            instruction: sample.at.ticks,
            node: sample.node.name.clone(),
            digest: cli_digest_from_engine_hash(sample.fingerprint.hash),
        })
        .collect::<Vec<_>>();
    if fingerprints.is_empty() {
        return Err(artifact_error(
            "search finding capture requires terminal execution fingerprints",
        ));
    }
    let status = status_from_outcome(Some(finding.outcome))?;
    let network_choice_indices = replay_choice_indices(model.artifact.schedule());
    let live =
        LiveQemuArtifactEvidence {
            contract: LiveQemuReplayContract {
                producer: String::from("campaign-search"),
                terminal_condition: String::from("stopped"),
                terminal_status: status.label().to_string(),
                terminal_outcome: terminal_outcome_label(Some(finding.outcome)).to_string(),
                terminal_configuration: format_content_hash_ref(finding.failure.configuration),
                final_frontier_ticks: finding.frontier.ticks,
                final_quanta: finding.quanta,
                budget_timed_out: finding.outcome == OutcomeKind::Timeout,
                max_virtual_time_ticks: None,
                max_quanta: None,
                run_ceiling_icount: Some(LIVE_EXPLORATION_RUN_CEILING_ICOUNT),
                lifecycle_quantum_budget: Some(LIVE_EXPLORATION_QUANTUM_LIMIT),
                coverage: plan.engine_strategy == crucible::SearchStrategy::CoverageGuided,
                fingerprint_scope: LiveQemuFingerprintScope::TerminalAllNodes,
                branch: LiveQemuReplayBranch::None,
                network_choice_indices,
                startup_controls: Vec::new(),
                initial_controls: Vec::new(),
                controls: Vec::new(),
            },
            event_stream: canonical_verify_log_stream_bytes(&[], &finding.event_frames),
            fingerprint_stream: verify_fingerprint_stream_bytes(&fingerprints),
            fingerprint_samples: fingerprints.clone(),
            resolved_effect_trace: finding.resolved_effect_trace.clone(),
            campaign_replay_closure: Some(finding.replay_closure.to_canonical_bytes().map_err(
                |error| artifact_error(format!("encode campaign replay closure: {error}")),
            )?),
        };
    let mut payloads = search_extra_artifact_payloads(plan, &mut canonical_log);
    payloads.extend(model_reproduction_artifact_payloads(
        &model.artifact,
        model.replay.state,
    ));
    payloads.extend(live_qemu_artifact_payloads(&live));
    let store = crucible::LocalDagStore::new(plan.store_root.clone());
    payloads.extend(lifecycle_artifact_payloads(
        scenario.world(),
        scenario.plan().fault_signals(),
        &store,
        mutation,
    )?);
    let scenario_bytes = scenario.to_compact_binary();
    reproduction_artifact_bytes_with_scenario_payload(
        seed_to_u64(model.artifact.seed()),
        backend_plan.resolved_backend.as_ref(),
        ReproductionScenarioPayload {
            name: "search-scenario.crucible-scenario",
            media_type: "application/vnd.crucible.scenario.compact-binary",
            bytes: &scenario_bytes,
        },
        &canonical_log,
        &fingerprints,
        &payloads,
    )
}

pub(crate) fn run_local_qemu_search_workflow(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    plan: &SearchDriverPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let store = crucible::LocalDagStore::new(plan.store_root.clone());
    let mutation_plans = crucible::materialize_search_plans(
        plan.scenario.scenario_form().plan().fault_signals(),
        &store,
    )
    .map_err(|error| backend_error(format!("materialize fault search candidates: {error}")))?;
    if !mutation_plans.is_empty() {
        return run_local_qemu_mutation_search_workflow(
            thin_plan,
            backend_plan,
            ergonomics_plan,
            plan,
            mutation_plans,
        );
    }

    let mut execution = run_local_qemu_search_scenario(
        thin_plan,
        backend_plan,
        ergonomics_plan,
        plan,
        plan.scenario.scenario_form(),
        plan.max_states,
        None,
    )?;
    attach_qemu_findings_outputs(
        &mut execution.outcome,
        &plan.store_root,
        &plan.artifact_dir,
        plan.findings_out.as_deref(),
        execution.findings,
        execution.reproduction_artifacts,
        execution.finding_exports,
    )?;
    Ok(execution.outcome)
}

struct QemuSearchExecution {
    outcome: BackendCommandOutcome,
    materialized_states: u64,
    expansions: u64,
    findings: Vec<crate::cli_report::TriageFindingEvidence>,
    reproduction_artifacts: Vec<Vec<u8>>,
    finding_exports: Vec<GuardedCampaignFindingExport>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MutationSearchBudget {
    remaining_states: u64,
}

impl MutationSearchBudget {
    const fn new(max_states: u64) -> Self {
        Self {
            remaining_states: max_states,
        }
    }

    fn next_case_budget(self) -> Option<u64> {
        (self.remaining_states > 0).then_some(self.remaining_states)
    }

    fn charge_states(&mut self, materialized_states: u64) {
        self.remaining_states = self.remaining_states.saturating_sub(materialized_states);
    }
}

fn run_local_qemu_search_scenario(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    plan: &SearchDriverPlan,
    scenario: &crucible::ScenarioDefForm,
    maximum_states: u64,
    mutation: Option<&crucible::MaterializedSearchPlan>,
) -> Result<QemuSearchExecution, CliError> {
    let backend = backend_plan
        .resolved_backend
        .as_ref()
        .ok_or_else(|| backend_error("local QEMU search requires a resolved backend"))?;
    let qemu_build_id = match backend {
        ResolvedLocalBackend::Qemu { qemu_build_id, .. } => qemu_build_id.clone(),
        #[cfg(any(test, feature = "test-double"))]
        ResolvedLocalBackend::Double => {
            return Err(backend_error(
                "campaign QEMU search requires a resolved production backend",
            ));
        }
    };
    let coverage = if plan.engine_strategy == crucible::SearchStrategy::CoverageGuided {
        production_api::ProductionPluginSwitch::On
    } else {
        production_api::ProductionPluginSwitch::Off
    };
    let lifecycle_artifacts =
        std::sync::Arc::new(crucible::LocalDagStore::new(plan.store_root.clone()));
    let lifecycle = production_qemu_lifecycle_config(backend)?
        .with_run_ceiling_icount(LIVE_EXPLORATION_RUN_CEILING_ICOUNT)
        .with_quantum_budget(LIVE_EXPLORATION_QUANTUM_LIMIT)
        .with_coverage(coverage)
        .with_world_artifacts(lifecycle_artifacts.clone())
        .with_signal_artifacts(lifecycle_artifacts);
    let deployment = load_guarded_campaign_deployment(plan.campaign_deployment.as_deref())?;
    if deployment.resources.maximum_execution_quanta() < LIVE_EXPLORATION_QUANTUM_LIMIT {
        return Err(backend_error(format!(
            "campaign deployment admits {} execution quanta, below the search requirement of {}",
            deployment.resources.maximum_execution_quanta(),
            LIVE_EXPLORATION_QUANTUM_LIMIT,
        )));
    }
    let strategy = match plan.engine_strategy {
        crucible::SearchStrategy::BreadthFirst => GuardedCampaignExplorationStrategy::BreadthFirst,
        crucible::SearchStrategy::CoverageGuided => {
            GuardedCampaignExplorationStrategy::CoverageGuided
        }
        crucible::SearchStrategy::DepthFirst => GuardedCampaignExplorationStrategy::DepthFirst,
        crucible::SearchStrategy::Priority { seed } => {
            GuardedCampaignExplorationStrategy::Priority { seed }
        }
    };
    let exploration = GuardedCampaignExploration::new(
        maximum_states,
        plan.max_depth,
        plan.on_violation == SearchOnViolationArg::Stop,
        strategy,
    )
    .and_then(|exploration| {
        exploration.with_execution_quanta_timeout(LIVE_EXPLORATION_QUANTUM_LIMIT)
    })
    .map_err(|error| campaign_search_error("build bounded exploration contract", error))?;
    let mut request = GuardedDefaultCampaignRunRequest::new(
        scenario.clone(),
        scenario.scenario_def().seed(),
        env!("CARGO_PKG_VERSION"),
        qemu_build_id,
        lifecycle,
        deployment.host,
        deployment.resources,
    )
    .with_exploration(exploration)
    .with_watch_frames();
    if deployment.verify_determinism_findings {
        request = request.with_determinism_finding_verification();
    }
    if let Some(oracle) = QemuSearchSupplementalOracle::from_plan(plan)? {
        request = request.with_supplemental_finding_oracle(Box::new(oracle));
    }
    let campaign = run_guarded_default_campaign(request)
        .map_err(|error| campaign_search_error("execute shared campaign search", error))?;

    campaign_search_outcome(
        thin_plan,
        backend_plan,
        ergonomics_plan,
        plan,
        backend,
        &campaign,
        mutation,
    )
}

fn campaign_search_outcome(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    plan: &SearchDriverPlan,
    backend: &ResolvedLocalBackend,
    campaign: &GuardedDefaultCampaignRun,
    mutation: Option<&crucible::MaterializedSearchPlan>,
) -> Result<QemuSearchExecution, CliError> {
    let root = campaign
        .observations()
        .first()
        .ok_or_else(|| backend_error("campaign search returned no accepted observations"))?
        .configuration()
        .id();
    let mut explored = BTreeSet::new();
    let mut findings = Vec::new();
    for observation in campaign.observations() {
        explored.insert(observation.configuration().id());
        if let Some(finding) = campaign_search_finding(plan, observation)? {
            let duplicate = findings.iter().any(|existing: &QemuSearchFinding| {
                existing.failure.configuration == finding.failure.configuration
                    && existing.failure.fingerprint == finding.failure.fingerprint
            });
            if !duplicate {
                findings.push(finding);
            }
        }
    }
    let reproductions = findings
        .iter()
        .map(|finding| {
            search_finding_reproduction_artifact_bytes(backend_plan, plan, finding, mutation)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let counterexample = findings
        .first()
        .zip(reproductions.first())
        .map(|(finding, artifact)| LocalDoubleSearchCounterexample {
            configuration: finding.failure.configuration,
            fingerprint: finding.failure.fingerprint,
            artifact_digest: content_address_bytes(artifact),
        });
    let exhausted =
        campaign.exploration_completion() == Some(GuardedCampaignExplorationCompletion::Exhausted);
    let report = LocalDoubleSearchReport {
        root,
        expansions: campaign.branch_acceptances().len(),
        explored: explored.len(),
        failures: findings.len(),
        property_findings: findings
            .iter()
            .filter(|finding| finding.outcome == OutcomeKind::Failed)
            .count(),
        timeout_findings: findings
            .iter()
            .filter(|finding| finding.outcome == OutcomeKind::Timeout)
            .count(),
        exhausted,
        failure_oracle: String::from("campaign-property-verdicts"),
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
        replay_oracle_sampling: String::from("none"),
        replay_oracle_considered: 0,
        replay_oracle_sampled: 0,
        replay_oracle_skipped: 0,
    };
    let mut outcome = backend_command_outcome(thin_plan, backend_plan, ergonomics_plan);
    apply_local_double_search_report(&mut outcome, plan, &report);

    let store = crucible::LocalDagStore::new(plan.store_root.clone());
    let mut evidence = Vec::with_capacity(findings.len());
    for finding in findings {
        let stored = finding
            .evidence
            .finding
            .store_artifact(&store)
            .map_err(CliError::Store)?;
        if stored != finding.evidence.finding.artifact.id() {
            return Err(artifact_error(
                "stored search finding artifact did not match its content identity",
            ));
        }
        evidence.push(finding.evidence);
    }
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: outcome.canonical_log.len() as u64,
        node: String::from("qemu"),
        kind: String::from("search_campaign_execution"),
        summary: format!(
            "campaign={} final_snapshot={} observations={} branch_requests={} completion={:?} backend=live",
            campaign.campaign().as_str(),
            campaign.final_snapshot(),
            campaign.observations().len(),
            campaign.branch_acceptances().len(),
            campaign.exploration_completion(),
        ),
    });
    for (sequence, branch) in campaign.branch_acceptances().iter().enumerate() {
        outcome.canonical_log.push(CanonicalLogEntry {
            sequence: outcome.canonical_log.len() as u64,
            virtual_time_ticks: outcome.canonical_log.len() as u64,
            node: String::from("qemu"),
            kind: String::from("search_campaign_branch"),
            summary: format!(
                "sequence={sequence} observation={} request={} snapshot={} maximum_attempts={} backend=live",
                branch.observation(),
                branch.request(),
                branch.snapshot(),
                branch.maximum_attempts(),
            ),
        });
    }
    outcome.canonical_log_digest = canonical_log_digest(&outcome.canonical_log);
    append_qemu_control_plane_execution_proof(&mut outcome, backend, "search-campaign");
    Ok(QemuSearchExecution {
        outcome,
        materialized_states: campaign.observations().len() as u64,
        expansions: campaign.branch_acceptances().len() as u64,
        findings: evidence,
        reproduction_artifacts: reproductions,
        finding_exports: vec![campaign.finding_export().clone()],
    })
}

fn run_local_qemu_mutation_search_workflow(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    plan: &SearchDriverPlan,
    mutation_plans: Vec<crucible::MaterializedSearchPlan>,
) -> Result<BackendCommandOutcome, CliError> {
    let original = plan.scenario.scenario_form();
    let total = mutation_plans.len();
    let mut selected_outcome = None;
    let mut findings = Vec::new();
    let mut reproduction_artifacts = Vec::new();
    let mut finding_exports = Vec::new();
    let mut budget = MutationSearchBudget::new(plan.max_states);

    for (index, materialized) in mutation_plans.into_iter().enumerate() {
        let Some(case_budget) = budget.next_case_budget() else {
            break;
        };
        let materialized_plan = original
            .plan()
            .clone()
            .with_fault_signals_for_world(original.world(), materialized.plan.clone())
            .map_err(|error| {
                backend_error(format!("validate fault search candidate {index}: {error}"))
            })?;
        let form = original.with_plan(materialized_plan).map_err(|error| {
            backend_error(format!("rebuild fault search candidate {index}: {error}"))
        })?;
        let mut materialized_driver = plan.clone();
        materialized_driver.scenario = plan.scenario.with_form(form.clone());
        let execution = run_local_qemu_search_scenario(
            thin_plan,
            backend_plan,
            ergonomics_plan,
            &materialized_driver,
            &form,
            case_budget,
            Some(&materialized),
        )?;
        budget.charge_states(execution.materialized_states);
        findings.extend(execution.findings);
        reproduction_artifacts.extend(execution.reproduction_artifacts);
        finding_exports.extend(execution.finding_exports);
        let mut outcome = execution.outcome;
        outcome.canonical_log.push(CanonicalLogEntry {
            sequence: outcome.canonical_log.len() as u64,
            virtual_time_ticks: outcome.canonical_log.len() as u64,
            node: String::from("search"),
            kind: String::from("signal_fault_mutation_case"),
            summary: format!(
                "candidate={} total={} provenance={} scenario={}",
                index,
                total,
                format_content_hash_ref(materialized.provenance),
                format_content_hash_ref(form.id())
            ),
        });
        outcome.canonical_log.push(CanonicalLogEntry {
            sequence: outcome.canonical_log.len() as u64,
            virtual_time_ticks: outcome.canonical_log.len() as u64,
            node: String::from("search"),
            kind: String::from("signal_fault_mutation_budget"),
            summary: format!(
                "global_max_states={} materialized_states={} expansions={} remaining={}",
                plan.max_states,
                execution.materialized_states,
                execution.expansions,
                budget.remaining_states
            ),
        });
        outcome.canonical_log_digest = canonical_log_digest(&outcome.canonical_log);

        merge_mutation_search_outcome(&mut selected_outcome, index, outcome);
        if plan.on_violation == SearchOnViolationArg::Stop
            && selected_outcome
                .as_ref()
                .is_some_and(|outcome| outcome.status.is_non_passing())
        {
            break;
        }
    }

    let mut outcome = selected_outcome
        .ok_or_else(|| backend_error("fault mutation search produced no candidates"))?;
    attach_qemu_findings_outputs(
        &mut outcome,
        &plan.store_root,
        &plan.artifact_dir,
        plan.findings_out.as_deref(),
        findings,
        reproduction_artifacts,
        finding_exports,
    )?;
    if outcome.reproduction_artifact.is_none() && !outcome.side_reproduction_artifacts.is_empty() {
        let (_, primary) = outcome.side_reproduction_artifacts.remove(0);
        outcome.artifact_digest = content_address_bytes(&primary);
        outcome.reproduction_artifact = Some(primary);
    }
    Ok(outcome)
}

fn merge_mutation_search_outcome(
    aggregate: &mut Option<BackendCommandOutcome>,
    candidate: usize,
    mut outcome: BackendCommandOutcome,
) {
    outcome.side_reproduction_artifacts = outcome
        .side_reproduction_artifacts
        .into_iter()
        .map(|(label, artifact)| {
            let label = if label.starts_with(&format!("mutation-{candidate}-")) {
                label
            } else {
                format!("mutation-{candidate}-{label}")
            };
            (label, artifact)
        })
        .collect();
    let Some(current) = aggregate.as_mut() else {
        *aggregate = Some(outcome);
        return;
    };
    current.stdout.append(&mut outcome.stdout);
    current.stderr.append(&mut outcome.stderr);
    for mut entry in outcome.canonical_log {
        entry.sequence = current.canonical_log.len() as u64;
        current.canonical_log.push(entry);
    }
    current
        .side_reproduction_artifacts
        .append(&mut outcome.side_reproduction_artifacts);
    if mutation_outcome_rank(outcome.status) > mutation_outcome_rank(current.status) {
        current.status = outcome.status;
        current.exit_code = outcome.exit_code;
        current.artifact_digest = outcome.artifact_digest;
    }
    current.canonical_log_digest = canonical_log_digest(&current.canonical_log);
}

const fn mutation_outcome_rank(status: BackendCommandStatus) -> u8 {
    match status {
        BackendCommandStatus::Passed => 0,
        BackendCommandStatus::Timeout => 1,
        BackendCommandStatus::Failed => 2,
        BackendCommandStatus::Crashed => 3,
    }
}

fn campaign_search_finding(
    plan: &SearchDriverPlan,
    accepted: &GuardedDefaultCampaignObservation,
) -> Result<Option<QemuSearchFinding>, CliError> {
    let mut outcome = accepted_observation_outcome(accepted);
    if outcome == OutcomeKind::Crashed {
        return Err(backend_error(format!(
            "live QEMU search accepted modeled guest crash `{}`",
            accepted_stop_label(accepted.observation().stop()),
        )));
    }
    let supplemental = accepted.supplemental_finding();
    if supplemental.is_some() {
        outcome = OutcomeKind::Failed;
    }
    if !matches!(outcome, OutcomeKind::Failed | OutcomeKind::Timeout) {
        return Ok(None);
    }
    let configuration = accepted.configuration();
    let supplemental_assertion = supplemental
        .map(|accepted_finding| {
            let oracle = QemuSearchSupplementalOracle::from_plan(plan)?.ok_or_else(|| {
                backend_error("campaign observation carries an unconfigured supplemental finding")
            })?;
            if accepted_finding.source() != oracle.source().identity() {
                return Err(backend_error(
                    "campaign supplemental finding source differs from the configured evidence",
                ));
            }
            let finding = oracle.assertion_finding(configuration).map_err(|error| {
                backend_error(format!("re-evaluate supplemental search finding: {error}"))
            })?;
            let finding = finding.ok_or_else(|| {
                backend_error(
                    "campaign supplemental finding did not reproduce from its bound evidence",
                )
            })?;
            let accepted_fingerprint = crucible::ContentHash {
                bytes: accepted_finding.fingerprint().as_bytes(),
            };
            if finding.fingerprint() != accepted_fingerprint {
                return Err(backend_error(
                    "campaign supplemental finding fingerprint changed during projection",
                ));
            }
            Ok(finding)
        })
        .transpose()?;
    let fingerprint = match &supplemental_assertion {
        Some(finding) => finding.fingerprint(),
        None => {
            let failure_material = accepted_failure_material(accepted)?;
            crucible::ContentHash::from_canonical_material(
                "crucible.live-qemu-search-failure.v1",
                &format!(
                    "configuration={}\n{failure_material}",
                    configuration.id().to_hex(),
                ),
            )
        }
    };
    let reproduction_artifact = crucible::FindingReproductionArtifact::capture(
        crucible::FindingDiscoveryPath::StateSpaceSearch,
        fingerprint,
        plan.scenario.scenario_form(),
        configuration,
    )
    .map_err(|error| backend_error(format!("capture campaign search finding: {error}")))?;
    let event_frames = accepted_event_frames(accepted);
    let coverage =
        crucible::EventLogCoverageFeedback::from_event_log(accepted.evidence().event_log_entries());
    let evidence = if outcome == OutcomeKind::Timeout {
        let timeout = accepted.timeout().ok_or_else(|| {
            backend_error(format!(
                "campaign search observation `{}` has no authenticated timeout-budget record",
                accepted.id(),
            ))
        })?;
        if timeout.observation() != accepted.id() {
            return Err(backend_error(
                "campaign timeout evidence names another accepted observation",
            ));
        }
        let timeout = crucible::FailureTimeoutRecord::new(
            crucible::FailureTimeoutBudgetKind::ExecutionQuanta,
            Some(timeout.execution_quanta_limit()),
            timeout.observed_execution_quanta(),
            timeout.frontier(),
            None,
            None,
            reproduction_artifact.artifact.id(),
        );
        crate::cli_triage_debug::triage_timeout_evidence(
            reproduction_artifact.clone(),
            timeout,
            coverage.fingerprint(),
            event_frames.clone(),
        )
    } else {
        let violation = match supplemental_assertion {
            Some(finding) => {
                let mut violation = finding.into_violation();
                violation.reproduction_artifact = reproduction_artifact.artifact.id();
                violation
            }
            None => property_violation_from_frames(
                plan.scenario.scenario_form(),
                &event_frames,
                reproduction_artifact.artifact.id(),
            )?,
        };
        crate::cli_triage_debug::triage_property_evidence_for_violation_with_recording(
            reproduction_artifact.clone(),
            violation,
            coverage.fingerprint(),
            event_frames.clone(),
        )
    }
    .map_err(|error| backend_error(format!("build campaign search evidence: {error}")))?;
    let fingerprints = accepted_terminal_fingerprints(plan.scenario.scenario_form(), accepted)?;
    Ok(Some(QemuSearchFinding {
        failure: crucible::SearchDiscoveredFailure {
            configuration: configuration.id(),
            fingerprint,
            reproduction_artifact,
        },
        evidence,
        outcome,
        frontier: accepted.evidence().frontier(),
        quanta: accepted.evidence().quanta(),
        event_frames,
        fingerprints,
        resolved_effect_trace: accepted
            .evidence()
            .resolved_effect_trace()
            .map(ToOwned::to_owned),
        replay_closure: accepted.replay_closure().clone(),
    }))
}

fn accepted_terminal_fingerprints(
    scenario: &crucible::ScenarioDefForm,
    accepted: &GuardedDefaultCampaignObservation,
) -> Result<Vec<crucible::FingerprintSample>, CliError> {
    let samples = accepted.evidence().terminal_fingerprints().ok_or_else(|| {
        artifact_error(format!(
            "campaign search observation `{}` has no authenticated terminal fingerprints",
            accepted.id()
        ))
    })?;
    let mut expected_nodes = scenario
        .world()
        .vm_nodes()
        .iter()
        .map(|node| node.id.name.as_str())
        .collect::<Vec<_>>();
    expected_nodes.sort_unstable();
    let actual_nodes = samples
        .iter()
        .map(|sample| sample.node.name.as_str())
        .collect::<Vec<_>>();
    if actual_nodes != expected_nodes {
        return Err(artifact_error(format!(
            "campaign search terminal fingerprint nodes {actual_nodes:?} did not match sorted scenario VM nodes {expected_nodes:?}"
        )));
    }
    Ok(samples.to_vec())
}

fn accepted_observation_outcome(accepted: &GuardedDefaultCampaignObservation) -> OutcomeKind {
    let property_failed = accepted
        .properties()
        .properties()
        .values()
        .any(|evidence| evidence.verdict() == PropertyVerdict::Failed);
    if property_failed {
        return OutcomeKind::Failed;
    }
    match accepted.observation().stop() {
        StopOutcome::AssertionFailure(_) | StopOutcome::ScenarioFailure(_) => OutcomeKind::Failed,
        StopOutcome::ModeledTimeout(_) => OutcomeKind::Timeout,
        StopOutcome::GuestCrash(_) => OutcomeKind::Crashed,
        StopOutcome::Reached(_) | StopOutcome::TerminalSuccess => OutcomeKind::Passed,
        StopOutcome::ObservationReached(proof) => match proof.satisfaction() {
            ObservationStopSatisfaction::SchedulerQuiescent => OutcomeKind::Passed,
            ObservationStopSatisfaction::AssertionViolationTransition => OutcomeKind::Failed,
            ObservationStopSatisfaction::ExecutionQuanta => OutcomeKind::Timeout,
        },
    }
}

fn accepted_failure_material(
    accepted: &GuardedDefaultCampaignObservation,
) -> Result<String, CliError> {
    let mut violations = accepted
        .properties()
        .properties()
        .iter()
        .filter(|(_, evidence)| evidence.verdict() == PropertyVerdict::Failed)
        .map(|(name, _)| name.clone())
        .collect::<Vec<_>>();
    match accepted.observation().stop() {
        StopOutcome::AssertionFailure(property) => violations.push(property.clone()),
        StopOutcome::ScenarioFailure(reasons) => violations.extend(reasons.iter().cloned()),
        StopOutcome::ModeledTimeout(_) if violations.is_empty() => {
            return Err(backend_error(
                "campaign timeout finding lacks an authenticated timeout-budget record",
            ));
        }
        StopOutcome::ModeledTimeout(_) => {}
        StopOutcome::ObservationReached(proof)
            if proof.satisfaction()
                == ObservationStopSatisfaction::AssertionViolationTransition =>
        {
            if let Some(witness) = proof.assertion_witness() {
                violations.push(witness.assertion().to_owned());
            }
        }
        StopOutcome::ObservationReached(_) => {}
        StopOutcome::Reached(_) | StopOutcome::TerminalSuccess | StopOutcome::GuestCrash(_) => {}
    }
    violations.sort();
    violations.dedup();
    if violations.is_empty() {
        return Err(backend_error(
            "failed campaign observation retained no property or scenario failure identity",
        ));
    }
    Ok(format!(
        "kind=property\nviolations={}",
        violations.join("\n")
    ))
}

fn accepted_event_frames(accepted: &GuardedDefaultCampaignObservation) -> Vec<Vec<u8>> {
    accepted
        .evidence()
        .event_log_entries()
        .iter()
        .map(|entry| {
            canonical_streaming_event_frame_bytes(&campaign_output_api::StreamingEventFrame {
                generation: 0,
                cursor: campaign_output_api::EventLogCursor::new(entry.sequence()),
                next_cursor: campaign_output_api::EventLogCursor::new(
                    entry.sequence().saturating_add(1),
                ),
                event: campaign_output_api::open_set_event_envelope_from_entry(entry),
            })
        })
        .collect()
}

fn accepted_stop_label(stop: &StopOutcome) -> String {
    match stop {
        StopOutcome::Reached(condition) => format!("reached:{condition:?}"),
        StopOutcome::TerminalSuccess => String::from("terminal-success"),
        StopOutcome::ModeledTimeout(name) => format!("modeled-timeout:{name}"),
        StopOutcome::GuestCrash(class) => format!("guest-crash:{class}"),
        StopOutcome::AssertionFailure(property) => format!("assertion-failure:{property}"),
        StopOutcome::ScenarioFailure(reasons) => {
            format!("scenario-failure:{}", reasons.join(","))
        }
        StopOutcome::ObservationReached(proof) => match proof.condition() {
            ObservationCondition::SchedulerQuiescent => {
                String::from("observation-reached:scheduler-quiescent")
            }
            ObservationCondition::AssertionViolationTransition(assertion) => {
                format!("observation-reached:assertion-violation-transition:{assertion}")
            }
            ObservationCondition::AnyAssertionViolationTransition => {
                let assertion = proof
                    .assertion_witness()
                    .map_or("unknown", |witness| witness.assertion());
                format!("observation-reached:any-assertion-violation-transition:{assertion}")
            }
            ObservationCondition::SchedulerQuiescentOrExecutionQuanta { execution_quanta } => {
                let satisfaction = match proof.satisfaction() {
                    ObservationStopSatisfaction::SchedulerQuiescent => "scheduler-quiescent",
                    ObservationStopSatisfaction::ExecutionQuanta => "execution-quanta",
                    ObservationStopSatisfaction::AssertionViolationTransition => {
                        "invalid-assertion-transition"
                    }
                };
                format!(
                    "observation-reached:scheduler-quiescent-or-execution-quanta:{execution_quanta}:{satisfaction}"
                )
            }
        },
    }
}

fn campaign_search_error(operation: &str, error: impl std::fmt::Display) -> CliError {
    backend_error(format!("{operation}: {error}"))
}
