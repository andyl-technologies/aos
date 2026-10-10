//! Packaged-QEMU artifact replay planning and branch reconstruction.

use super::*;

/// Optional authenticated resources carried by a live-QEMU replay artifact.
pub(crate) struct LiveQemuReplayResources {
    pub(crate) owner: crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignOwner,
    pub(crate) campaign_closure:
        Option<crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignReplayClosure>,
    pub(crate) effect_trace: Option<crucible::ResolvedEffectTrace>,
    pub(crate) lifecycle_artifacts: Option<std::sync::Arc<crucible::MemoryDagStore>>,
    pub(crate) bounded_scheduler_preemption:
        Option<crucible_api::BoundedSchedulerPreemptionEvidence>,
}

/// Re-executes an artifact through a fresh packaged-QEMU lifecycle session.
///
/// # Errors
///
/// Returns [`CliError`] when the contract is invalid, its branch recipe cannot
/// be reconstructed from the typed schedule, or the QEMU lifecycle fails.
pub(crate) fn run_live_qemu_artifact_replay(
    backend: &ResolvedLocalBackend,
    campaign_deployment: Option<&Path>,
    scenario: crucible::ScenarioDefForm,
    schedule: &crucible::Schedule,
    contract: &LiveQemuReplayContract,
    resources: LiveQemuReplayResources,
) -> Result<(RunInvocationPlan, RunWorkflowReport), CliError> {
    let terminal_condition = match contract.terminal_condition.as_str() {
        "quiescence" => RunTerminalCondition::Quiescence,
        "virtual-time" => RunTerminalCondition::VirtualTime,
        "property" => RunTerminalCondition::Property,
        "stopped" => RunTerminalCondition::Stopped,
        other => {
            return Err(artifact_error(format!(
                "live-QEMU replay contract has unknown terminal condition `{other}`"
            )));
        }
    };
    let scenario_def = scenario.scenario_def();
    let mut startup_commands = contract
        .startup_controls
        .iter()
        .filter_map(|control| match control.command.as_str() {
            "start" => Some(SessionCommandKind::Start),
            "continue" => Some(SessionCommandKind::Continue),
            "step-quantum" => Some(SessionCommandKind::StepQuantum),
            _ => None,
        })
        .collect::<Vec<_>>();
    if startup_commands.is_empty() {
        startup_commands = vec![SessionCommandKind::Start, SessionCommandKind::Continue];
    }
    let initial_control_commands = contract
        .initial_controls
        .iter()
        .map(|_| SessionCommandKind::Query)
        .collect();
    let run_plan = RunInvocationPlan {
        request_seed: Some(scenario_def.seed()),
        save_store_root: None,
        campaign_deployment: campaign_deployment.map(Path::to_path_buf),
        scenario: RunScenarioRef::BuiltInExample {
            name: String::from("artifact-replay"),
            form: scenario
                .try_clone_admitted()
                .map_err(|error| artifact_error(format!("admit replay scenario copy: {error}")))?,
            scenario: scenario_def.clone(),
        },
        terminal_condition,
        max_virtual_time: contract
            .max_virtual_time_ticks
            .map(|ticks| ticks.to_string()),
        max_virtual_time_ticks: contract.max_virtual_time_ticks,
        max_quanta: contract.max_quanta,
        execution_mode: contract.execution_mode,
        save_policy: RunSavePolicy::Never,
        watch_streams_live_status: false,
        startup_commands,
        initial_control_commands,
        accepted_interactive_commands: if contract.execution_mode == RunExecutionMode::Interactive {
            run_interactive_session_command_set()
        } else {
            Vec::new()
        },
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
    };
    let mut config = production_qemu_lifecycle_config(backend)?;
    if let Some(run_ceiling_ticks) = contract.run_ceiling_ticks {
        config = config.with_run_ceiling_ticks(run_ceiling_ticks);
    }
    if let Some(quantum_budget) = contract.lifecycle_quantum_budget {
        config = config.with_quantum_budget(quantum_budget);
    }
    if let Some(lifecycle_artifacts) = resources.lifecycle_artifacts {
        config = config
            .with_world_artifacts(lifecycle_artifacts.clone())
            .with_signal_artifacts(lifecycle_artifacts);
    }
    if let Some(evidence) = resources.bounded_scheduler_preemption {
        config = config.with_bounded_scheduler_preemption(evidence);
    }
    if contract.execution_mode == RunExecutionMode::Interactive {
        if resources.campaign_closure.is_some() {
            return Err(artifact_error(
                "interactive session replay cannot carry a campaign replay closure",
            ));
        }
        if !matches!(contract.branch, LiveQemuReplayBranch::None) {
            return Err(artifact_error(
                "interactive session replay cannot carry a campaign branch recipe",
            ));
        }
        if let Some(trace) = resources.effect_trace {
            config = config.with_fault_replay(trace);
        }
        let report = run_interactive_control_artifact_replay(
            backend,
            campaign_deployment,
            &scenario,
            schedule,
            contract,
            config,
            resources.owner,
        )?;
        return Ok((run_plan, report));
    }
    validate_live_qemu_campaign_owner(contract, schedule, resources.campaign_closure.is_some())?;
    match &contract.branch {
        LiveQemuReplayBranch::None => {}
        LiveQemuReplayBranch::Resume {
            base_decisions,
            frontier_ticks,
        } => {
            let base = replay_branch_base(&scenario_def, schedule, *base_decisions)?;
            validate_campaign_replay_branch_base(&base, *frontier_ticks)?;
        }
        LiveQemuReplayBranch::Reseed {
            base_decisions,
            frontier_ticks,
            seed,
        } => {
            let base = replay_branch_base(&scenario_def, schedule, *base_decisions)?;
            config = config.with_branch_reseed(
                base,
                VirtualTime {
                    ticks: *frontier_ticks,
                },
                crucible::Seed::from_u64(*seed),
            );
        }
    }
    let network_choices =
        replay_indexed_network_choices(schedule, &contract.network_choice_indices)?;
    if !network_choices.is_empty() {
        config = config.with_branch_network_choices(network_choices);
    }
    if contract.coverage {
        config = crucible_daemon::with_production_qemu_coverage(config, true);
    }
    if let Some(trace) = resources.effect_trace {
        config = config.with_fault_replay(trace);
    }
    let replay_closure =
        campaign_owner_replay_closure(&contract.producer, resources.campaign_closure)?;
    let report = crate::cli_verify_serve::run_local_qemu_campaign_replay(
        backend,
        &run_plan,
        config,
        schedule
            .try_clone_admitted()
            .map_err(|error| artifact_error(format!("admit replay schedule copy: {error}")))?,
        replay_closure,
        resources.owner,
    )?;
    Ok((run_plan, report))
}

fn run_interactive_control_artifact_replay(
    _backend: &ResolvedLocalBackend,
    campaign_deployment: Option<&Path>,
    scenario: &crucible::ScenarioDefForm,
    terminal_schedule: &crucible::Schedule,
    contract: &LiveQemuReplayContract,
    config: crucible_api::ProductionVmLifecycleConfig,
    owner: crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignOwner,
) -> Result<RunWorkflowReport, CliError> {
    let deployment = load_guarded_campaign_deployment(campaign_deployment)?;
    let resources = crate::cli_verify_serve::campaign_run::guarded_run_resources(
        deployment.resources,
        Some(contract.final_quanta),
    )?;
    let authority = owner.repository_metadata_resources().map_err(|error| {
        backend_error(format!(
            "interactive replay metadata authority is unavailable: {error}"
        ))
    })?;
    let decoding = crucible_session::engine::owned_decode::DecodeBudget::for_store(authority)
        .map_err(|error| {
            backend_error(format!(
                "interactive replay metadata admission failed: {error}"
            ))
        })?;
    let scope = decoding.enter();

    let captured_scenario =
        crucible::ScenarioDefForm::from_compact_binary(&contract.initial_scenario)
            .map_err(|error| artifact_error(format!("decode initial scenario: {error}")))?;
    if &captured_scenario != scenario {
        return Err(artifact_error(
            "interactive replay initial scenario does not match the authenticated model scenario",
        ));
    }
    let initial_schedule = crucible::Schedule::from_compact_binary(&contract.initial_schedule)
        .map_err(|error| artifact_error(format!("decode initial configuration: {error}")))?;
    if !initial_schedule.is_empty() {
        return Err(artifact_error(
            "fresh interactive replay requires a genesis initial schedule",
        ));
    }
    let initial_configuration = crucible::Configuration {
        def: captured_scenario.scenario_def(),
        schedule: initial_schedule,
    };
    if format_content_hash_ref(initial_configuration.id()) != contract.initial_configuration {
        return Err(artifact_error(
            "interactive replay initial configuration identity does not match its schedule",
        ));
    }
    let final_schedule = crucible::Schedule::from_compact_binary(&contract.final_schedule)
        .map_err(|error| artifact_error(format!("decode final configuration: {error}")))?;
    if &final_schedule != terminal_schedule {
        return Err(artifact_error(
            "interactive replay final schedule does not match the authenticated model schedule",
        ));
    }
    let final_configuration = crucible::Configuration {
        def: captured_scenario.scenario_def(),
        schedule: final_schedule,
    };
    if format_content_hash_ref(final_configuration.id()) != contract.terminal_configuration {
        return Err(artifact_error(
            "interactive replay final configuration identity does not match its schedule",
        ));
    }
    if contract.terminal_outcome != "stopped" {
        return Err(artifact_error(
            "interactive replay requires an operator-stopped final snapshot",
        ));
    }
    let terminal_savepoint = contract
        .terminal_savepoint
        .as_deref()
        .map(crucible::Checkpoint::from_compact_binary)
        .transpose()
        .map_err(|error| artifact_error(format!("decode terminal savepoint: {error}")))?;
    if let Some(checkpoint) = &terminal_savepoint
        && (checkpoint.configuration != final_configuration.id()
            || checkpoint.scenario_ref != captured_scenario.id()
            || checkpoint.virtual_time.ticks != contract.final_frontier_ticks)
    {
        return Err(artifact_error(
            "interactive replay terminal savepoint does not match the final snapshot identity",
        ));
    }
    let event_log_len = usize::try_from(contract.final_event_log_len)
        .map_err(|_| artifact_error("final event-log length cannot be represented"))?;
    let final_snapshot = crucible_session::EngineSnapshot {
        state: crucible_session::EngineState::Stopped {
            outcome: crucible_session::Outcome::Stopped,
        },
        configuration: final_configuration,
        terminal_savepoint,
        frontier: crucible::VirtualTime {
            ticks: contract.final_frontier_ticks,
        },
        event_log_len,
        quanta: contract.final_quanta,
    };
    let mut control_log = Vec::new();
    crucible_session::engine::owned_decode::reserve_vec(
        &mut control_log,
        contract.reproduction_commands.len(),
    )
    .map_err(|error| artifact_error(format!("admit replay control-log storage: {error}")))?;
    for command in &contract.reproduction_commands {
        let bytes = command
            .payload
            .command_payload
            .len()
            .checked_add(
                command
                    .payload
                    .scheduler_control
                    .as_ref()
                    .map_or(0, String::len),
            )
            .ok_or_else(|| artifact_error("replay command copy size overflow"))?;
        decoding
            .charge_bytes(
                u64::try_from(bytes)
                    .map_err(|_| artifact_error("replay command copy size overflow"))?,
            )
            .map_err(|error| artifact_error(format!("admit replay command copy: {error}")))?;
        control_log.push(
            crucible_session::SessionControlLogEntry::try_from(command.clone())
                .map_err(|error| artifact_error(error.to_string()))?,
        );
    }
    let replay_artifact = crucible_session::SessionControlReplayArtifact {
        initial_configuration: initial_configuration
            .try_clone_admitted()
            .map_err(|error| {
                artifact_error(format!("admit interactive replay configuration: {error}"))
            })?,
        final_snapshot,
        control_log,
    };

    let quantum_loop = owner
        .begin_interactive_session_with_lifecycle(
            &initial_configuration.def,
            &captured_scenario,
            crucible_daemon::ExecutionCancellation::default(),
            config,
            resources,
        )
        .map_err(|error| {
            backend_error(format!("build guarded interactive replay session: {error}"))
        })?;
    let checkpoint = crucible::Checkpoint::from_recorded_configuration(
        &initial_configuration,
        None,
        crucible::VirtualTime::default(),
        std::collections::BTreeMap::new(),
        crucible::CheckpointKind::Fat,
        std::collections::BTreeMap::new(),
    )
    .map_err(|error| artifact_error(format!("build interactive replay genesis: {error}")))?;
    let graph = crucible::TemporalGraph::empty()
        .with_baked_genesis(
            &initial_configuration.def,
            crucible::GenesisCheckpoint { checkpoint },
        )
        .map_err(|error| artifact_error(format!("build interactive replay graph: {error}")))?;
    let engine = crucible_session::Engine::new(initial_configuration, graph, quantum_loop);
    let (sender, receiver) = tokio::sync::mpsc::channel(64);
    let world_nodes = captured_scenario.world().vm_nodes();
    let mut nodes = Vec::new();
    crucible_session::engine::owned_decode::reserve_vec(&mut nodes, world_nodes.len())
        .map_err(|error| artifact_error(format!("admit replay node storage: {error}")))?;
    for node in world_nodes {
        decoding
            .charge_bytes(node.id.name.len() as u64)
            .map_err(|error| artifact_error(format!("admit replay node identity: {error}")))?;
        nodes.push(node.id.clone());
    }
    let (actor, execution_fingerprints) =
        replay_interactive_terminal_actor(engine, receiver, &replay_artifact, &nodes)?;

    let event_log = actor.event_log();
    let mut stream = event_log.subscribe(crucible_session::EventLogCursor::default());
    let mut streamed_event_frames = Vec::new();
    crucible_session::engine::owned_decode::reserve_vec(&mut streamed_event_frames, event_log_len)
        .map_err(|error| artifact_error(format!("admit replay event-frame storage: {error}")))?;
    for _ in 0..event_log_len {
        let frame = stream
            .try_recv()
            .map_err(|error| backend_error(format!("read replayed event log: {error}")))?
            .ok_or_else(|| backend_error("replayed event log ended before its final snapshot"))?;
        let frame = crucible_api::StreamingEventFrame::from_admitted(frame)
            .map_err(|error| artifact_error(format!("admit replayed event frame: {error}")))?;
        streamed_event_frames.push(
            crate::cli_verify_serve::admitted_streaming_event_frame_bytes(
                frame.value(),
                &decoding,
            )?,
        );
    }
    let reproduction_snapshot = actor
        .reproduction_log()
        .snapshot_admitted()
        .map_err(|error| artifact_error(format!("admit replay command snapshot: {error}")))?;
    let mut reproduction_commands = Vec::new();
    let mut output_custody = Vec::new();
    crucible_session::engine::owned_decode::reserve_vec(
        &mut reproduction_commands,
        reproduction_snapshot.entries().len(),
    )
    .map_err(|error| artifact_error(format!("admit replay command reports: {error}")))?;
    crucible_session::engine::owned_decode::reserve_vec(
        &mut output_custody,
        reproduction_snapshot.entries().len(),
    )
    .map_err(|error| artifact_error(format!("admit replay command custody: {error}")))?;
    for entry in reproduction_snapshot.entries() {
        let admitted = crucible_api::ReproductionCommandRecord::from_admitted(entry)
            .map_err(|error| artifact_error(format!("admit replay command record: {error}")))?;
        let (record, custody) = admitted.into_parts();
        reproduction_commands.push(record);
        output_custody.push(custody);
    }
    drop(reproduction_snapshot);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    decoding.check().map_err(|error| {
        backend_error(format!(
            "interactive replay metadata admission failed: {error}"
        ))
    })?;
    drop(scope);
    let actor_decoding = decoding.clone();

    runtime.block_on(async move {
        let actor_task = crucible_api::spawn_admitted_session_actor(actor, actor_decoding)
            .map_err(|error| backend_error(format!("admit replay actor: {error}")))?;
        let (reply, receiver) = crucible_session::CommandReply::channel();
        sender
            .send(crucible_session::SessionCommand::acknowledged(
                crucible_session::SessionCommand::Stop,
                reply,
            ))
            .await
            .map_err(|_| backend_error("replay actor closed before terminal shutdown"))?;
        receiver
            .await
            .map_err(|_| backend_error("replay shutdown reply channel closed"))?
            .map_err(|error| backend_error(format!("shutdown replay actor: {error}")))?;
        actor_task
            .await
            .map_err(|error| backend_error(format!("join replay actor: {error}")))?
            .map_err(|error| backend_error(format!("replay actor failed: {error}")))?;
        Ok::<_, CliError>(())
    })?;

    let _scope = decoding.enter();
    decoding.check().map_err(|error| {
        backend_error(format!(
            "interactive replay metadata admission failed: {error}"
        ))
    })?;
    let final_snapshot = replay_artifact.final_snapshot;
    let terminal_configuration = final_snapshot
        .configuration
        .try_clone_admitted()
        .map_err(|error| artifact_error(format!("admit replay report configuration: {error}")))?;
    let final_frontier_ticks = final_snapshot.frontier.ticks;
    let final_quanta = final_snapshot.quanta;
    decoding
        .charge_array::<String>(1)
        .and_then(|_| decoding.charge_bytes(("loaded".len() + 2 * "stopped".len()) as u64))
        .map_err(|error| artifact_error(format!("admit replay report labels: {error}")))?;
    Ok(RunWorkflowReport {
        status: BackendCommandStatus::Passed,
        execution_owner: RunExecutionOwner::Session,
        campaign_replay_closure: None,
        created_state: String::from("loaded"),
        final_state: String::from("stopped"),
        outcome: Some(OutcomeKind::Stopped),
        terminal_savepoint: final_snapshot
            .terminal_savepoint
            .as_ref()
            .map(|checkpoint| checkpoint.id),
        terminal_configuration: Some(terminal_configuration),
        final_snapshot: Some(final_snapshot),
        final_frontier_ticks,
        final_quanta,
        budget_timed_out: false,
        state_updates: vec![String::from("stopped")],
        streamed_events: Vec::new(),
        streamed_event_frames,
        coverage_feedback: crucible::EventLogCoverageFeedback::from_event_log(&[]),
        execution_fingerprints,
        resolved_effect_trace: None,
        acknowledged_commands: Vec::new(),
        reproduction_commands,
        watch_statuses: Vec::new(),
        input_custody: crucible_session::engine::owned_decode::current_custody(),
        output_custody,
    })
}

fn replay_interactive_terminal_actor<L: crucible::QuantumLoop>(
    engine: crucible_session::Engine<L>,
    receiver: tokio::sync::mpsc::Receiver<crucible_session::SessionCommand>,
    artifact: &crucible_session::SessionControlReplayArtifact,
    nodes: &[crucible::NodeId],
) -> Result<
    (
        crucible_session::SessionActor<L>,
        Vec<crucible::FingerprintSample>,
    ),
    CliError,
> {
    crucible_session::SessionActor::new(engine, receiver)
        .with_control_replay_artifact_and_terminal_fingerprints(artifact, nodes)
        .map_err(|error| backend_error(format!("replay interactive control artifact: {error}")))
}

pub(crate) fn validate_live_qemu_campaign_owner(
    contract: &LiveQemuReplayContract,
    schedule: &crucible::Schedule,
    has_campaign_closure: bool,
) -> Result<(), CliError> {
    if contract.producer == "campaign-run" || contract.producer == "campaign-search" {
        if !matches!(contract.branch, LiveQemuReplayBranch::None)
            && (!has_campaign_closure || !campaign_branch_replay_eligible(contract, schedule))
        {
            return Err(artifact_error(
                "campaign-owned branch replay contract has an unsupported execution shape",
            ));
        }
        return Ok(());
    }
    Err(artifact_error(format!(
        "live-QEMU replay contract has unsupported producer `{}`",
        contract.producer
    )))
}

fn campaign_branch_replay_eligible(
    contract: &LiveQemuReplayContract,
    // crucible-lint: allow host-nondeterminism-state -- replay routing reads authenticated artifact evidence without modifying semantic state.
    schedule: &crucible::Schedule,
) -> bool {
    let supported_schedule = schedule.decisions().iter().all(|decision| {
        matches!(
            decision,
            // crucible-lint: allow host-nondeterminism-state -- replay routing inspects authenticated scheduler evidence only to select its execution owner.
            crucible::Decision::DeliveryOrder(_)
                // crucible-lint: allow host-nondeterminism-state -- replay routing inspects authenticated scheduler evidence only to select its execution owner.
                | crucible::Decision::RngDraw(_)
                // crucible-lint: allow host-nondeterminism-state -- replay routing inspects authenticated scheduler evidence only to select its execution owner.
                | crucible::Decision::Preemption(_)
                // crucible-lint: allow host-nondeterminism-state -- replay routing inspects authenticated scheduler evidence only to select its execution owner.
                | crucible::Decision::Selection(_)
        )
    }) && schedule.decisions().iter().all(|decision| {
        // crucible-lint: allow host-nondeterminism-state -- replay routing rejects unsupported typed selection origins before execution.
        let crucible::Decision::Selection(decision) = decision else {
            return true;
        };
        decision.selection().is_ok_and(|selection| {
            !matches!(
                selection.origin(),
                crucible_campaign::SelectionOrigin::ModelSample(_)
            )
        })
    });
    let supported_terminal = matches!(
        contract.terminal_condition.as_str(),
        "quiescence" | "virtual-time" | "stopped"
    ) && (contract.terminal_condition != "virtual-time"
        || contract.max_virtual_time_ticks.is_some());

    replay_control_commands(&contract.startup_controls) == ["start", "continue"]
        && replay_control_commands(&contract.initial_controls) == ["query"]
        && contract.controls.is_empty()
        && supported_terminal
        && !contract.coverage
        && contract.fingerprint_scope == LiveQemuFingerprintScope::TerminalAllNodes
        && matches!(contract.branch, LiveQemuReplayBranch::Resume { .. })
        && supported_schedule
}

fn replay_control_commands(controls: &[LiveQemuReplayControl]) -> Vec<&str> {
    controls
        .iter()
        .map(|control| control.command.as_str())
        .collect()
}

/// Resolves the authenticated closure required by a campaign-owned artifact replay.
///
/// # Errors
///
/// Returns [`CliError`] when the producer requires a missing closure, carries a
/// closure under session-owned semantics.
pub(crate) fn campaign_owner_replay_closure(
    producer: &str,
    embedded: Option<crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignReplayClosure>,
) -> Result<crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignReplayClosure, CliError> {
    match (producer, embedded) {
        ("campaign-run" | "campaign-search", Some(closure)) => Ok(closure),
        ("campaign-run", None) => Err(artifact_error(
            "campaign-run replay requires its authenticated choice closure",
        )),
        ("campaign-search", None) => Err(artifact_error(
            "campaign-owned search replay requires its authenticated choice closure",
        )),
        (_, _) => Err(artifact_error(
            "only campaign-owned artifacts use campaign replay",
        )),
    }
}

fn validate_campaign_replay_branch_base(
    configuration: &crucible::Configuration,
    frontier_ticks: u64,
) -> Result<(), CliError> {
    let frontier = validate_resume_handle_frontier(&configuration.schedule, frontier_ticks)?;
    checkpoint_for_resume_configuration(configuration, frontier)?;
    Ok(())
}

fn replay_branch_base(
    scenario: &crucible::ScenarioDef,
    schedule: &crucible::Schedule,
    decisions: u64,
) -> Result<crucible::Configuration, CliError> {
    let decisions = usize::try_from(decisions)
        .map_err(|_| artifact_error("live-QEMU branch base length cannot be represented"))?;
    let prefix = schedule.prefix(decisions).map_err(|error| {
        artifact_error(format!("construct live-QEMU replay branch prefix: {error}"))
    })?;
    Ok(crucible::Configuration {
        def: scenario.clone(),
        schedule: prefix,
    })
}

fn replay_indexed_network_choices(
    schedule: &crucible::Schedule,
    indices: &[u64],
) -> Result<Vec<crucible::SelectionDecision>, CliError> {
    indices
        .iter()
        .map(|index| {
            let index = usize::try_from(*index)
                .map_err(|_| artifact_error("network choice index cannot be represented"))?;
            match schedule.decisions().get(index) {
                Some(crucible::Decision::Selection(decision))
                    if decision.selection().is_ok_and(|selection| {
                        decision.is_campaign_branch()
                            && crucible::is_live_world_network_selection(&selection)
                    }) =>
                {
                    decision.try_clone_admitted().map_err(|error| {
                        artifact_error(format!("admit replay network choice: {error}"))
                    })
                }
                _ => Err(artifact_error(
                    "network choice index does not identify a typed live-world network selection",
                )),
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn assert_campaign_owner(
        contract: &LiveQemuReplayContract,
        schedule: &Schedule,
        has_campaign_closure: bool,
    ) {
        validate_live_qemu_campaign_owner(contract, schedule, has_campaign_closure)
            .unwrap_or_else(|error| panic!("current replay contract should be accepted: {error}"));
    }

    fn campaign_run_contract() -> LiveQemuReplayContract {
        let scenario = crucible::happy_path_scenario()
            .unwrap_or_else(|error| panic!("build campaign replay scenario: {error}"))
            .scenario;
        LiveQemuReplayContract {
            producer: String::from("campaign-run"),
            execution_owner: RunExecutionOwner::Campaign,
            execution_mode: RunExecutionMode::ToCompletion,
            initial_configuration: String::from("blake3:initial"),
            initial_scenario: scenario.to_compact_binary(),
            initial_schedule: Schedule::empty().to_compact_binary(),
            terminal_condition: String::from("quiescence"),
            terminal_status: String::from("failed"),
            terminal_outcome: String::from("failed"),
            terminal_configuration: String::from("blake3:terminal"),
            final_frontier_ticks: 1,
            final_quanta: 1,
            final_event_log_len: 0,
            final_schedule: Schedule::empty().to_compact_binary(),
            terminal_savepoint: None,
            budget_timed_out: false,
            max_virtual_time_ticks: None,
            max_quanta: None,
            run_ceiling_ticks: Some(PRODUCTION_CLI_RUN_CEILING_TICKS),
            lifecycle_quantum_budget: Some(PRODUCTION_CLI_QUANTUM_BUDGET),
            coverage: false,
            fingerprint_scope: LiveQemuFingerprintScope::FullExecution,
            branch: LiveQemuReplayBranch::None,
            network_choice_indices: Vec::new(),
            startup_controls: vec![
                LiveQemuReplayControl {
                    sequence: 0,
                    command: String::from("start"),
                },
                LiveQemuReplayControl {
                    sequence: 1,
                    command: String::from("continue"),
                },
            ],
            initial_controls: vec![LiveQemuReplayControl {
                sequence: 0,
                command: String::from("query"),
            }],
            controls: Vec::new(),
            reproduction_commands: Vec::new(),
        }
    }

    fn campaign_resume_contract() -> LiveQemuReplayContract {
        let mut contract = campaign_run_contract();
        contract.fingerprint_scope = LiveQemuFingerprintScope::TerminalAllNodes;
        contract.branch = LiveQemuReplayBranch::Resume {
            base_decisions: 1,
            frontier_ticks: 1,
        };
        contract
    }

    #[test]
    fn campaign_artifacts_route_to_the_campaign_owner() {
        let supported = Schedule::from_decisions([crucible::Decision::DeliveryOrder(
            crucible::DeliveryOrderDecision {
                at: VirtualTime { ticks: 1 },
                order: Vec::new(),
            },
        )]);
        let campaign_run = campaign_run_contract();
        assert_campaign_owner(&campaign_run, &supported, true);
        assert_campaign_owner(&campaign_run, &supported, false);
        let mut search = campaign_run.clone();
        search.producer = String::from("campaign-search");
        assert_campaign_owner(&search, &supported, true);
        let mut unsupported = campaign_run.clone();
        unsupported.producer = String::from("unsupported-producer");
        assert!(validate_live_qemu_campaign_owner(&unsupported, &supported, false).is_err());
    }

    #[test]
    fn campaign_owned_replay_requires_its_embedded_closure() {
        for producer in ["campaign-run", "campaign-search"] {
            let error = match campaign_owner_replay_closure(producer, None) {
                Ok(_) => panic!("campaign-owned replay without its closure must fail closed"),
                Err(error) => error,
            };

            assert!(
                error
                    .to_string()
                    .contains("requires its authenticated choice closure")
            );
        }
    }

    #[test]
    fn campaign_resume_artifacts_route_by_authenticated_campaign_closure() {
        let schedule = Schedule::from_decisions([crucible::Decision::DeliveryOrder(
            crucible::DeliveryOrderDecision {
                at: VirtualTime { ticks: 1 },
                order: Vec::new(),
            },
        )]);
        let contract = campaign_resume_contract();

        assert_campaign_owner(&contract, &schedule, true);
        assert!(validate_live_qemu_campaign_owner(&contract, &schedule, false).is_err());

        let closure = match crucible_daemon::qemu_campaign_lifecycle::GuardedCampaignReplayClosure::from_canonical_bytes(b"CCRC\0\0\0\x01\0\0\0\0") {
            Ok(closure) => closure,
            Err(error) => panic!("selection-free resume closure failed: {error}"),
        };
        let accepted = match campaign_owner_replay_closure("campaign-run", Some(closure.clone())) {
            Ok(closure) => closure,
            Err(error) => panic!("campaign-owned resume closure failed: {error}"),
        };
        assert_eq!(accepted, closure);
        assert!(campaign_owner_replay_closure("campaign-run", None).is_err());

        let mut reseeded = contract.clone();
        reseeded.branch = LiveQemuReplayBranch::Reseed {
            base_decisions: 1,
            frontier_ticks: 1,
            seed: 7,
        };
        assert!(
            validate_live_qemu_campaign_owner(&reseeded, &schedule, true).is_err(),
            "campaign-owned reseeded branch must fail instead of falling back",
        );

        let mut property = contract;
        property.terminal_condition = String::from("property");
        assert!(
            validate_live_qemu_campaign_owner(&property, &schedule, true).is_err(),
            "campaign-owned property branch must fail instead of falling back",
        );
    }

    #[test]
    fn campaign_owned_contracts_do_not_fall_back_to_the_session_owner() {
        let schedule = Schedule::empty();
        let mut contract = campaign_run_contract();
        contract.terminal_condition = String::from("property");

        assert_campaign_owner(&contract, &schedule, false);
    }

    #[test]
    fn branch_replay_rejects_frontier_beyond_retained_prefix() -> Result<(), Box<dyn Error>> {
        let scenario = crucible::happy_path_scenario()?.scenario;
        let schedule = Schedule::from_decisions([crucible::Decision::DeliveryOrder(
            crucible::DeliveryOrderDecision {
                at: VirtualTime { ticks: 1 },
                order: Vec::new(),
            },
        )]);
        let base = replay_branch_base(&scenario.scenario_def(), &schedule, 1)?;
        let campaign_error = match validate_campaign_replay_branch_base(&base, 2) {
            Ok(()) => panic!("campaign branch accepted an unrecorded frontier"),
            Err(error) => error,
        };
        assert!(
            campaign_error
                .to_string()
                .contains("exceeded the latest recorded")
        );
        Ok(())
    }
}

#[cfg(test)]
#[path = "replay/terminal_tests.rs"]
mod terminal_tests;
