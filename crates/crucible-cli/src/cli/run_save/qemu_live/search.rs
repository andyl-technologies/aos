//! Live-QEMU temporal-graph search and replay-prefix realization.

use super::*;

#[path = "search/failure.rs"]
mod failure;

use failure::*;

struct QemuSearchFinding {
    failure: crucible::SearchDiscoveredFailure,
    evidence: crate::cli_report::TriageFindingEvidence,
    snapshot: crucible_session::EngineSnapshot,
    event_frames: Vec<Vec<u8>>,
    fingerprints: Vec<crucible::FingerprintSample>,
    resolved_effect_trace: Option<Vec<u8>>,
}

fn search_finding_reproduction_artifact_bytes(
    backend_plan: &BackendSelectionPlan,
    plan: &SearchDriverPlan,
    finding: &QemuSearchFinding,
    mutation: Option<&crucible::MaterializedSearchPlan>,
) -> Result<Vec<u8>, CliError> {
    let model = &finding.evidence.finding;
    let scenario = model.artifact.scenario_form();
    let canonical_log = canonical_log_entries_from_engine_schedule(model.artifact.schedule());
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
    let outcome = match &finding.snapshot.state {
        crucible_session::EngineState::Stopped { outcome } => OutcomeKind::from(outcome),
        _ => {
            return Err(artifact_error(
                "search finding capture requires a stopped engine snapshot",
            ));
        }
    };
    let status = status_from_outcome(Some(outcome))?;
    let network_choice_indices = replay_choice_indices(model.artifact.schedule());
    let live = LiveQemuArtifactEvidence {
        contract: LiveQemuReplayContract {
            producer: String::from("search"),
            terminal_condition: String::from("stopped"),
            terminal_status: status.label().to_string(),
            terminal_outcome: terminal_outcome_label(Some(outcome)).to_string(),
            terminal_configuration: format_content_hash_ref(finding.snapshot.configuration.id()),
            final_frontier_ticks: finding.snapshot.frontier.ticks,
            final_quanta: finding.snapshot.quanta,
            budget_timed_out: matches!(outcome, OutcomeKind::Timeout),
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
    };
    let mut payloads = model_reproduction_artifact_payloads(&model.artifact, model.replay.state);
    payloads.extend(live_qemu_artifact_payloads(&live));
    let store = crucible::LocalDagStore::new(plan.store_root.clone());
    payloads.extend(signal_artifact_payloads(
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
    run_local_qemu_search_scenario(
        thin_plan,
        backend_plan,
        ergonomics_plan,
        plan,
        plan.scenario.scenario_form(),
        plan.budget.max_expansions,
        None,
    )
    .map(|execution| execution.outcome)
}

struct QemuSearchExecution {
    outcome: BackendCommandOutcome,
    expansions: u64,
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

    fn begin_case(&mut self) -> Option<u64> {
        self.remaining_states = self.remaining_states.checked_sub(1)?;
        Some(self.remaining_states)
    }

    fn charge_expansions(&mut self, expansions: u64) {
        self.remaining_states = self.remaining_states.saturating_sub(expansions);
    }
}

fn run_local_qemu_search_scenario(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    plan: &SearchDriverPlan,
    scenario: &crucible::ScenarioDefForm,
    expansion_budget: u64,
    mutation: Option<&crucible::MaterializedSearchPlan>,
) -> Result<QemuSearchExecution, CliError> {
    let backend = backend_plan
        .resolved_backend
        .as_ref()
        .ok_or_else(|| backend_error("local QEMU search requires a resolved backend"))?;
    let coverage = if plan.engine_strategy == crucible::SearchStrategy::CoverageGuided {
        production_api::ProductionPluginSwitch::On
    } else {
        production_api::ProductionPluginSwitch::Off
    };
    let config = production_qemu_lifecycle_config(backend)?
        .with_run_ceiling_icount(LIVE_EXPLORATION_RUN_CEILING_ICOUNT)
        .with_quantum_budget(LIVE_EXPLORATION_QUANTUM_LIMIT)
        .with_coverage(coverage)
        .with_signal_artifacts(std::sync::Arc::new(crucible::LocalDagStore::new(
            plan.store_root.clone(),
        )));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (mut graph, root_configuration, root, mut discovered_findings) =
        runtime.block_on(qemu_search_root(&config, scenario))?;
    let mut pending = root
        .as_ref()
        .map(|frontier| vec![frontier.configuration.clone()])
        .unwrap_or_default();
    let mut live_frontiers = root
        .as_ref()
        .map(|frontier| {
            BTreeMap::from([(
                frontier.configuration.id(),
                (frontier.configuration.clone(), frontier.at),
            )])
        })
        .unwrap_or_default();
    let mut scheduled = pending
        .iter()
        // crucible-lint: allow host-nondeterminism-state -- content-addressed canonical configurations define deterministic worklist identity.
        .map(crucible::Configuration::id)
        .collect::<BTreeSet<_>>();
    let mut explored = BTreeSet::from([root_configuration.id()]);
    explored.extend(scheduled.iter().copied());
    let mut expansions = Vec::new();
    let mut live_realizations = usize::from(root.is_some());
    let mut replay_oracle_validations = 0_usize;
    'search: while (expansions.len() as u64) < expansion_budget {
        if plan.on_violation == SearchOnViolationArg::Stop && !discovered_findings.is_empty() {
            break;
        }
        let Some(index) =
            graph.select_strategy_frontier(&pending, plan.engine_strategy, plan.max_depth)
        else {
            break;
        };
        let frontier = pending.remove(index);
        let branch_frontier = live_frontiers.get(&frontier.id()).cloned();
        let materialization_budget = match usize::try_from(expansion_budget) {
            Ok(max_expansions) => max_expansions,
            Err(_) => usize::MAX,
        };
        let search = graph
            .search_frontier(
                &frontier,
                MaterializationPolicy::with_budget(materialization_budget),
                MaterializationTrigger::RepeatedForkSource,
            )
            .map_err(|error| backend_error(format!("QEMU live-frontier search failed: {error}")))?;
        for child in &search.frontier_report.explored {
            explored.insert(child.configuration.id());
            let (realized, failure) = runtime.block_on(qemu_search_realize(
                &config,
                scenario,
                &child.configuration,
                branch_frontier
                    .as_ref()
                    .map(|(configuration, at)| (configuration, *at)),
            ))?;
            replay_oracle_validations = replay_oracle_validations.saturating_add(1);
            if let Some(finding) = failure
                && discovered_findings.iter().all(|existing| {
                    existing.failure.configuration != finding.failure.configuration
                        || existing.failure.fingerprint != finding.failure.fingerprint
                })
            {
                explored.insert(finding.failure.configuration);
                discovered_findings.push(finding);
                if plan.on_violation == SearchOnViolationArg::Stop {
                    break 'search;
                }
            }
            if let Some(realized) = realized {
                live_realizations = live_realizations.saturating_add(1);
                explored.insert(realized.configuration.id());
                qemu_search_cache_frontier(&mut graph, &realized)?;
                live_frontiers.insert(
                    realized.configuration.id(),
                    (realized.configuration.clone(), realized.at),
                );
                if scheduled.insert(realized.configuration.id()) {
                    pending.push(realized.configuration);
                }
            }
        }
        expansions.push(crucible::SearchExpansion {
            sequence: expansions.len() as u64,
            frontier: frontier.id(),
            depth: frontier.schedule.len(),
            search,
        });
    }
    let exhausted = pending.is_empty();
    let run = crucible::TemporalGraphSearchRun {
        root: root_configuration.id(),
        strategy: plan.engine_strategy,
        budget: crucible::SearchBudget::new(expansion_budget),
        explored_graph: explored,
        expansions,
        discovered_failures: discovered_findings
            .iter()
            .map(|finding| finding.failure.clone())
            .collect(),
        exhausted,
    };
    let counterexample_artifact = discovered_findings
        .first()
        .map(|finding| {
            search_finding_reproduction_artifact_bytes(backend_plan, plan, finding, mutation)
        })
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
        property_findings: discovered_findings
            .iter()
            .filter(|finding| {
                matches!(
                    finding.evidence.failure,
                    crucible_model::FailureClusterReportFailure::Property(_)
                )
            })
            .count(),
        timeout_findings: discovered_findings
            .iter()
            .filter(|finding| {
                matches!(
                    finding.evidence.failure,
                    crucible_model::FailureClusterReportFailure::Timeout(_)
                )
            })
            .count(),
        exhausted: run.exhausted,
        failure_oracle: String::from("live-qemu-scheduler"),
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
        replay_oracle_considered: replay_oracle_validations,
        replay_oracle_sampled: replay_oracle_validations,
        replay_oracle_skipped: 0,
    };
    let mut outcome = backend_command_outcome(thin_plan, backend_plan, ergonomics_plan);
    if let Some(artifact) = counterexample_artifact {
        outcome.artifact_digest = content_address_bytes(&artifact);
        outcome.reproduction_artifact = Some(artifact);
    }
    apply_local_double_search_report(&mut outcome, plan, &report);
    let store = crucible::LocalDagStore::new(plan.store_root.clone());
    let mut evidence = Vec::new();
    let mut reproductions = Vec::new();
    for finding in discovered_findings {
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
        reproductions.push(search_finding_reproduction_artifact_bytes(
            backend_plan,
            plan,
            &finding,
            mutation,
        )?);
        evidence.push(finding.evidence);
    }
    attach_qemu_findings_outputs(
        &mut outcome,
        &plan.store_root,
        &plan.artifact_dir,
        plan.findings_out.as_deref(),
        evidence,
        reproductions,
    )?;
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: outcome.canonical_log.len() as u64,
        node: String::from("qemu"),
        kind: String::from("search_live_realizations"),
        summary: format!(
            "runtime_frontiers={} branch_replay_validations={} backend=live",
            live_realizations, replay_oracle_validations
        ),
    });
    for expansion in &run.expansions {
        outcome.canonical_log.push(CanonicalLogEntry {
            sequence: outcome.canonical_log.len() as u64,
            virtual_time_ticks: outcome.canonical_log.len() as u64,
            node: String::from("qemu"),
            kind: String::from("search_branch_execution"),
            summary: format!(
                "sequence={} frontier={} choices={} backend=live",
                expansion.sequence,
                expansion.frontier.to_hex(),
                expansion.search.frontier_report.explored.len()
            ),
        });
    }
    outcome.canonical_log_digest = canonical_log_digest(&outcome.canonical_log);
    append_qemu_control_plane_execution_proof(&mut outcome, backend, "search-live-branches");
    Ok(QemuSearchExecution {
        outcome,
        expansions: run.expansions.len() as u64,
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
    let mut budget = MutationSearchBudget::new(plan.max_states);
    for (index, materialized) in mutation_plans.into_iter().enumerate() {
        let Some(expansion_budget) = budget.begin_case() else {
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
            expansion_budget,
            Some(&materialized),
        )?;
        budget.charge_expansions(execution.expansions);
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
                "global_max_states={} root_and_expansions_consumed={} remaining={}",
                plan.max_states,
                execution.expansions.saturating_add(1),
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
    selected_outcome.ok_or_else(|| backend_error("fault mutation search produced no candidates"))
}

fn merge_mutation_search_outcome(
    aggregate: &mut Option<BackendCommandOutcome>,
    candidate: usize,
    mut outcome: BackendCommandOutcome,
) {
    if let Some(artifact) = outcome.reproduction_artifact.take() {
        outcome
            .side_reproduction_artifacts
            .push((format!("mutation-{candidate}-finding"), artifact));
    }
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

#[derive(Clone, Debug)]
struct QemuSearchFrontier {
    // crucible-lint: allow host-nondeterminism-state -- this configuration is returned only after scheduler replay-prefix validation.
    configuration: crucible::Configuration,
    at: crucible::VirtualTime,
    choices: crucible::SearchFrontierChoices,
    coverage: crucible::EventLogCoverageFeedback,
}

async fn qemu_search_root(
    config: &production_api::ProductionVmLifecycleConfig,
    scenario: &crucible::ScenarioDefForm,
) -> Result<
    (
        ValidationDag,
        // crucible-lint: allow host-nondeterminism-state -- the result is canonical scheduler state reconstructed through the lifecycle API.
        crucible::Configuration,
        Option<QemuSearchFrontier>,
        Vec<QemuSearchFinding>,
    ),
    CliError,
> {
    // crucible-lint: allow host-nondeterminism-state -- genesis is a pure function of canonical scenario material.
    let root = crucible::Configuration::genesis(scenario.scenario_def());
    let (frontier, failure) = qemu_search_realize(config, scenario, &root, None).await?;
    let Some(frontier) = frontier else {
        return Ok((
            save_validation_graph(&scenario.scenario_def())?,
            root,
            None,
            failure.into_iter().collect(),
        ));
    };
    let mut graph = if frontier.configuration.is_genesis() {
        let checkpoint = qemu_search_checkpoint(&frontier)?;
        // crucible-lint: allow host-nondeterminism-state -- the session validation API admits only oracle-validated checkpoint material.
        crucible_session::validation::empty_validation_dag()
            .with_baked_genesis(
                &scenario.scenario_def(),
                crucible::GenesisCheckpoint { checkpoint },
            )
            .map_err(|error| backend_error(format!("admit live QEMU search genesis: {error}")))?
    } else {
        save_validation_graph(&scenario.scenario_def())?
    };
    if !frontier.configuration.is_genesis() {
        qemu_search_cache_frontier(&mut graph, &frontier)?;
    }
    let root_configuration = frontier.configuration.clone();
    Ok((
        graph,
        root_configuration,
        Some(frontier),
        failure.into_iter().collect(),
    ))
}

async fn qemu_search_realize(
    config: &production_api::ProductionVmLifecycleConfig,
    scenario: &crucible::ScenarioDefForm,
    // crucible-lint: allow host-nondeterminism-state -- requested search state is canonical input checked against every live replay prefix.
    requested: &crucible::Configuration,
    branch: Option<(&crucible::Configuration, crucible::VirtualTime)>,
) -> Result<(Option<QemuSearchFrontier>, Option<QemuSearchFinding>), CliError> {
    let network_choices = branch_network_choice_decisions(&requested.schedule);
    let mut branch_config = config.clone().with_branch_network_choices(network_choices);
    if let Some((base, at)) = branch {
        let signal_fault_decisions = requested
            .schedule
            .decisions()
            .iter()
            .skip(base.schedule.len())
            .filter(|decision| {
                matches!(
                    decision,
                    crucible::Decision::Override(override_decision)
                        if override_decision.point.key.starts_with("signal-fault/")
                )
            })
            .cloned()
            .collect::<Vec<_>>();
        if !signal_fault_decisions.is_empty() {
            branch_config = branch_config.with_branch_prefix_overrides(
                base.clone(),
                at,
                signal_fault_decisions,
            );
        }
    }
    let control_plane = production_qemu_control_plane(branch_config, scenario);
    let client = InProcessLifecycleClient::new(control_plane);
    let seed = scenario.scenario_def().seed();
    let created = client
        .create_session(
            CreateSessionRequest::inline_form(scenario.clone(), seed).with_start_paused(true),
        )
        .await
        .map_err(control_client_error)?;
    let mut control = client
        .control_attach(
            AttachRequest::new(created.session)
                .with_expected_epoch(created.session.epoch)
                .with_client_name("crucible-cli-qemu-search"),
        )
        .await
        .map_err(control_client_error)?;
    let mut command_id = 1_u64;
    let mut coverage_events = Vec::new();
    let mut streamed_events = Vec::new();
    let mut streamed_frames = Vec::new();
    let mut event_cursor = 0_u64;
    let max_quanta = config.maximum_scheduler_quanta(scenario.world().vm_nodes().len());
    let mut captured = None;
    let mut terminal_snapshot = None;
    let mut completed_summary = None;
    let mut previous =
        wait_for_save_workflow_state(&client, created.session, LiveStateKind::Paused).await?;
    for quantum in 0..max_quanta {
        qemu_search_command(
            &control,
            &mut command_id,
            SessionCommand::step(StepMode::Quantum),
            "single-quantum step",
        )
        .await?;
        let summary = match wait_for_save_workflow_summary(
            &client,
            created.session,
            |summary| {
                summary.quanta_stepped > previous.quanta_stepped
                    && matches!(
                        summary.state,
                        LiveStateKind::Paused | LiveStateKind::Stopped
                    )
            },
            "bounded live QEMU search step",
            Duration::from_millis(RUN_INTERACTIVE_ACK_QUANTA_BOUND),
        )
        .await
        {
            Ok(summary) => summary,
            Err(error) => {
                let _ = qemu_search_stop(&control, &mut command_id).await;
                return Err(error);
            }
        };
        let snapshot = qemu_search_query_snapshot(&control, &mut command_id).await?;
        if configuration_has_prefix(&snapshot.configuration, requested)? {
            let query = qemu_search_query_frontier(&control, &mut command_id).await?;
            if query.pending_branch_choices == 0
                && let Some(frontier) = query.frontiers.into_iter().find(|frontier| {
                    configuration_has_prefix(&frontier.configuration, requested).unwrap_or(false)
                })
            {
                captured = Some(frontier);
                completed_summary = Some(summary);
                break;
            }
        }
        if summary.state == LiveStateKind::Stopped {
            terminal_snapshot = Some(snapshot);
            completed_summary = Some(summary);
            break;
        }
        previous = summary.clone();
        if quantum + 1 == max_quanta {
            completed_summary = Some(summary);
        }
    }
    let summary = completed_summary.ok_or_else(|| {
        backend_error("live QEMU search exhausted its scheduler bound without a completed step")
    })?;
    drain_terminal_event_log(
        &mut control,
        summary.event_log_len,
        VERIFY_BASELINE_PROFILE.event_timeout_ms,
        &mut streamed_events,
        &mut streamed_frames,
        &mut coverage_events,
        &mut event_cursor,
    )
    .await?;
    let coverage = coverage_feedback_from_streamed_events(coverage_events)?;
    let terminal_fingerprints = if terminal_snapshot.is_some() {
        qemu_search_query_fingerprints(&control, &mut command_id, scenario).await?
    } else {
        Vec::new()
    };
    let resolved_effect_trace = if terminal_snapshot.is_some() {
        qemu_search_query_resolved_effect_trace(&control, &mut command_id).await?
    } else {
        None
    };
    let terminal_failure = terminal_snapshot
        .as_ref()
        .map(|snapshot| {
            qemu_search_terminal_finding(
                scenario,
                snapshot,
                &streamed_frames,
                &coverage,
                max_quanta,
                &terminal_fingerprints,
                resolved_effect_trace,
            )
        })
        .transpose()?
        .flatten();
    qemu_search_stop(&control, &mut command_id).await?;
    Ok((
        captured.map(|frontier| QemuSearchFrontier {
            // crucible-lint: allow host-nondeterminism-state -- the queried configuration passed the exact requested-prefix check above.
            configuration: frontier.configuration,
            at: frontier.at,
            choices: frontier.choices,
            coverage,
        }),
        terminal_failure,
    ))
}

fn qemu_search_terminal_finding(
    scenario: &crucible::ScenarioDefForm,
    snapshot: &crucible_session::EngineSnapshot,
    streamed_frames: &[Vec<u8>],
    coverage: &crucible::EventLogCoverageFeedback,
    configured_quanta: u64,
    fingerprints: &[crucible::FingerprintSample],
    resolved_effect_trace: Option<Vec<u8>>,
) -> Result<Option<QemuSearchFinding>, CliError> {
    let Some(failure) = qemu_search_terminal_failure(scenario, snapshot)? else {
        return Ok(None);
    };
    let evidence = match &snapshot.state {
        crucible_session::EngineState::Stopped {
            outcome: crucible_session::Outcome::Failed { .. },
        } => {
            let violation = qemu_property_violation_from_frames(
                scenario,
                streamed_frames,
                failure.reproduction_artifact.artifact.id(),
            )?;
            crate::cli_triage_debug::triage_property_evidence_for_violation_with_recording(
                failure.reproduction_artifact.clone(),
                violation,
                coverage.fingerprint(),
                streamed_frames.to_vec(),
            )
        }
        crucible_session::EngineState::Stopped {
            outcome: crucible_session::Outcome::Timeout,
        } => {
            let timeout = crucible_model::FailureTimeoutRecord::new(
                crucible_model::FailureTimeoutBudgetKind::ExecutionQuanta,
                Some(configured_quanta),
                snapshot.quanta,
                snapshot.frontier,
                None,
                None,
                failure.reproduction_artifact.artifact.id(),
            );
            crate::cli_triage_debug::triage_timeout_evidence(
                failure.reproduction_artifact.clone(),
                timeout,
                coverage.fingerprint(),
                streamed_frames.to_vec(),
            )
        }
        _ => {
            return Err(backend_error(
                "live QEMU search produced failure evidence for a non-finding outcome",
            ));
        }
    }
    .map_err(|error| backend_error(format!("build live QEMU search evidence: {error}")))?;
    Ok(Some(QemuSearchFinding {
        failure,
        evidence,
        snapshot: snapshot.clone(),
        event_frames: streamed_frames.to_vec(),
        fingerprints: fingerprints.to_vec(),
        resolved_effect_trace,
    }))
}

async fn qemu_search_query_resolved_effect_trace(
    control: &crucible_api::ClientControlStream,
    command_id: &mut u64,
) -> Result<Option<Vec<u8>>, CliError> {
    let response = qemu_search_command(
        control,
        command_id,
        SessionCommand::Query {
            kind: QueryKind::ResolvedEffectTrace,
            reply: CommandReply::discard(),
        },
        "resolved-effect trace query",
    )
    .await?;
    match response.query_result {
        Some(QueryResult::ResolvedEffectTrace(trace)) => Ok(trace),
        Some(other) => Err(backend_error(format!(
            "QEMU search resolved-effect trace query returned unexpected payload: {other:?}"
        ))),
        None => Err(backend_error(
            "QEMU search resolved-effect trace query returned no payload",
        )),
    }
}

async fn qemu_search_query_fingerprints(
    control: &crucible_api::ClientControlStream,
    command_id: &mut u64,
    scenario: &crucible::ScenarioDefForm,
) -> Result<Vec<crucible::FingerprintSample>, CliError> {
    let mut nodes = scenario
        .world()
        .vm_nodes()
        .iter()
        .map(|node| node.id.clone())
        .collect::<Vec<_>>();
    nodes.sort_by(|left, right| left.name.cmp(&right.name));
    let mut samples = Vec::with_capacity(nodes.len());
    for node in nodes {
        let response = qemu_search_command(
            control,
            command_id,
            SessionCommand::Query {
                kind: QueryKind::ExecutionFingerprint { node: node.clone() },
                reply: CommandReply::discard(),
            },
            "terminal fingerprint query",
        )
        .await?;
        match response.query_result {
            Some(QueryResult::ExecutionFingerprint(sample)) => samples.push(sample),
            Some(other) => {
                return Err(backend_error(format!(
                    "QEMU search fingerprint query for node `{}` returned unexpected payload: {other:?}",
                    node.name
                )));
            }
            None => {
                return Err(backend_error(format!(
                    "QEMU search fingerprint query for node `{}` returned no payload",
                    node.name
                )));
            }
        }
    }
    Ok(samples)
}

async fn qemu_search_query_snapshot(
    // crucible-lint: allow host-nondeterminism-state -- the typed control stream returns engine-owned snapshots without host-side synthesis.
    control: &crucible_api::ClientControlStream,
    command_id: &mut u64,
    // crucible-lint: allow host-nondeterminism-state -- the result remains an engine snapshot and is validated before use.
) -> Result<crucible_session::EngineSnapshot, CliError> {
    let response = qemu_search_command(
        control,
        command_id,
        SessionCommand::query_snapshot(),
        "snapshot query",
    )
    .await?;
    match response.query_result {
        Some(QueryResult::Snapshot(snapshot)) => Ok(*snapshot),
        Some(other) => Err(backend_error(format!(
            "QEMU search snapshot query returned unexpected payload: {other:?}"
        ))),
        None => Err(backend_error(
            "QEMU search snapshot query returned no payload",
        )),
    }
}

async fn qemu_search_query_frontier(
    // crucible-lint: allow host-nondeterminism-state -- the typed control stream exposes scheduler-owned frontier evidence.
    control: &crucible_api::ClientControlStream,
    command_id: &mut u64,
) -> Result<QemuSearchFrontierQuery, CliError> {
    let response = qemu_search_command(
        control,
        command_id,
        SessionCommand::Query {
            kind: QueryKind::SearchFrontier,
            reply: CommandReply::discard(),
        },
        "frontier query",
    )
    .await?;
    match response.query_result {
        Some(QueryResult::SearchFrontier {
            frontiers,
            pending_branch_choices,
        }) => Ok(QemuSearchFrontierQuery {
            frontiers,
            pending_branch_choices,
        }),
        Some(other) => Err(backend_error(format!(
            "QEMU search frontier query returned unexpected payload: {other:?}"
        ))),
        None => Err(backend_error(
            "QEMU search frontier query returned no payload",
        )),
    }
}

struct QemuSearchFrontierQuery {
    frontiers: Vec<crucible::SearchRuntimeFrontier>,
    pending_branch_choices: usize,
}

async fn qemu_search_stop(
    // crucible-lint: allow host-nondeterminism-state -- stopping uses the session API and does not construct schedule state.
    control: &crucible_api::ClientControlStream,
    command_id: &mut u64,
) -> Result<(), CliError> {
    qemu_search_command(control, command_id, SessionCommand::Stop, "stop")
        .await
        .map(|_| ())
}

async fn qemu_search_command(
    // crucible-lint: allow host-nondeterminism-state -- commands cross the validated control API and receive typed engine replies.
    control: &crucible_api::ClientControlStream,
    command_id: &mut u64,
    command: SessionCommand,
    operation: &str,
    // crucible-lint: allow host-nondeterminism-state -- the response is transport evidence, not authoritative state synthesized by the CLI.
) -> Result<crucible_api::SendResponse, CliError> {
    let response = control
        .send_command(*command_id, command)
        .await
        .map_err(control_client_error)?;
    *command_id = command_id.saturating_add(1);
    match response.result.status {
        CommandResultStatus::Accepted => Ok(response),
        CommandResultStatus::Rejected { reason } => Err(backend_error(format!(
            "QEMU search {operation} was rejected: {reason:?}"
        ))),
    }
}

fn configuration_has_prefix(
    // crucible-lint: allow host-nondeterminism-state -- both values are canonical engine configurations compared without mutation.
    actual: &crucible::Configuration,
    // crucible-lint: allow host-nondeterminism-state -- the expected configuration originated from the temporal-graph frontier.
    expected: &crucible::Configuration,
) -> Result<bool, CliError> {
    if actual.def != expected.def || actual.schedule.len() < expected.schedule.len() {
        return Ok(false);
    }
    let prefix = actual
        .schedule
        .prefix(expected.schedule.len())
        .map_err(|error| backend_error(format!("compare QEMU search replay prefix: {error}")))?;
    Ok(prefix == expected.schedule)
}

// crucible-lint: allow host-nondeterminism-state -- this pure projection selects recorded causal decisions from a canonical schedule.
fn branch_network_choice_decisions(
    // crucible-lint: allow host-nondeterminism-state -- this pure projection reads only canonical scheduler decisions.
    schedule: &crucible::Schedule,
) -> Vec<crucible::OverrideDecision> {
    schedule
        // crucible-lint: allow host-nondeterminism-state -- the immutable decision slice is validated by the exact branch-point namespace.
        .decisions()
        .iter()
        // crucible-lint: allow host-nondeterminism-state -- filtering cannot alter or synthesize an explorer decision.
        .filter_map(|decision| match decision {
            // crucible-lint: allow host-nondeterminism-state -- only a scheduler-authored exact network override crosses into replay.
            crucible::Decision::Override(override_decision)
                if override_decision
                    .point
                    .key
                    .starts_with("live-world-network/") =>
            {
                Some(override_decision.clone())
            }
            _ => None,
        })
        .collect()
}

fn qemu_search_checkpoint(frontier: &QemuSearchFrontier) -> Result<crucible::Checkpoint, CliError> {
    // crucible-lint: allow host-nondeterminism-state -- checkpoint material is produced by the session validation oracle.
    let mut checkpoint = crucible_session::validation::recorded_checkpoint_for_configuration(
        &frontier.configuration,
        frontier.at,
    )
    .map_err(|error| backend_error(format!("materialize QEMU search frontier: {error}")))?;
    let state = checkpoint
        .state
        .as_ref()
        .ok_or_else(|| backend_error("QEMU search frontier checkpoint has no state"))?;
    let mut scheduler = state.scheduler.clone();
    scheduler.search_frontier = frontier.choices.clone();
    checkpoint.state = Some(
        crucible::MaterializedState::from_components_with_event_log_segments(
            state.vm_snapshots.clone(),
            state.device_overlays.clone(),
            scheduler,
            state.decision_rng.clone(),
            state.event_log,
            state.event_log_segments.clone(),
        ),
    );
    Ok(checkpoint.with_coverage_fingerprint(frontier.coverage.fingerprint()))
}

fn qemu_search_cache_frontier(
    graph: &mut ValidationDag,
    frontier: &QemuSearchFrontier,
) -> Result<(), CliError> {
    let checkpoint = qemu_search_checkpoint(frontier)?;
    graph
        .cache_snapshot(&frontier.configuration, checkpoint)
        .map_err(|error| backend_error(format!("cache live QEMU search frontier: {error}")))
}

#[cfg(test)]
mod mutation_search_tests {
    use super::*;

    fn outcome(status: BackendCommandStatus, artifact: &[u8]) -> BackendCommandOutcome {
        BackendCommandOutcome {
            subcommand: CliSubcommand::Search,
            status,
            exit_code: status.exit_code(),
            stdout: Vec::new(),
            stderr: Vec::new(),
            canonical_log: Vec::new(),
            canonical_log_digest: content_address_bytes(b"log"),
            artifact_digest: content_address_bytes(artifact),
            terminal_savepoint: None,
            savepoint_oracle: None,
            save_boundary_evidence: None,
            reproduction_artifact: Some(artifact.to_vec()),
            side_reproduction_artifacts: Vec::new(),
        }
    }

    #[test]
    fn mutation_search_budget_is_shared_across_roots_and_expansions() {
        let mut budget = MutationSearchBudget::new(5);
        assert_eq!(budget.begin_case(), Some(4));
        budget.charge_expansions(2);
        assert_eq!(budget.begin_case(), Some(1));
        budget.charge_expansions(1);
        assert_eq!(budget.begin_case(), None);
    }

    #[test]
    fn mutation_aggregation_retains_every_primary_artifact() {
        let mut aggregate = None;
        merge_mutation_search_outcome(
            &mut aggregate,
            0,
            outcome(BackendCommandStatus::Timeout, b"candidate-zero"),
        );
        merge_mutation_search_outcome(
            &mut aggregate,
            1,
            outcome(BackendCommandStatus::Crashed, b"candidate-one"),
        );
        let aggregate = aggregate.unwrap_or_else(|| panic!("aggregation must produce an outcome"));
        assert_eq!(aggregate.status, BackendCommandStatus::Crashed);
        assert!(aggregate.reproduction_artifact.is_none());
        assert_eq!(
            aggregate.side_reproduction_artifacts,
            vec![
                (
                    String::from("mutation-0-finding"),
                    b"candidate-zero".to_vec()
                ),
                (
                    String::from("mutation-1-finding"),
                    b"candidate-one".to_vec()
                ),
            ]
        );
    }
}
