//! Resume and verification workflow realization.

use super::*;

#[cfg(any(test, feature = "test-double"))]
const REQUESTED_PROPERTY_VIOLATION_REASON: &str = "requested property was violated";

pub(super) fn resume_handle_evidence(
    plan: &ResumeInvocationPlan,
) -> Result<ResumeHandleEvidence, CliError> {
    savepoint_evidence("resume", &plan.savepoint, &plan.store_root)
}

pub(super) fn savepoint_evidence(
    command_name: &'static str,
    savepoint: &ResumeSavepointRef,
    _store_root: &Path,
) -> Result<ResumeHandleEvidence, CliError> {
    match savepoint {
        ResumeSavepointRef::CheckpointHash(_) => Err(artifact_error(format!(
            "{command_name} requires an authenticated .crucible-savepoint handle"
        ))),
        ResumeSavepointRef::Handle(resolved) => {
            savepoint_handle_evidence(command_name, &resolved.handle)
        }
    }
}

#[cfg(any(test, feature = "test-double"))]
pub(super) fn ensure_session_replay_evidence_supported(
    context: &str,
    evidence: &ResumeHandleEvidence,
) -> Result<(), CliError> {
    if evidence.source_observation_proof.is_some() {
        return Err(backend_error(format!(
            "{context} cannot authenticate a portable campaign observation boundary; use the campaign-owned local QEMU resume path"
        )));
    }
    if evidence
        .schedule
        .decisions()
        .iter()
        .any(|decision| matches!(decision, crucible::Decision::Selection(_)))
    {
        return Err(backend_error(format!(
            "{context} cannot consume a typed selection replay closure; use the standard local QEMU resume path"
        )));
    }
    Ok(())
}

pub(super) fn savepoint_handle_evidence(
    command_name: &'static str,
    handle: &SavepointHandle,
) -> Result<ResumeHandleEvidence, CliError> {
    if handle.materialization != "create-savepoint:reply" {
        return Err(artifact_error(format!(
            "savepoint handle materialization `{}` is not accepted for {command_name}; expected `create-savepoint:reply`",
            handle.materialization
        )));
    }
    if handle.oracle_status != "fat==thin-passed" {
        return Err(artifact_error(format!(
            "savepoint handle oracle status `{}` is not accepted for {command_name}; expected `fat==thin-passed`",
            handle.oracle_status
        )));
    }
    let scenario_form = crucible::ScenarioDefForm::from_compact_binary(&handle.scenario_payload)
        .map_err(|error| {
            artifact_error(format!("savepoint scenario payload is malformed: {error}"))
        })?;
    validate_save_selector_for_scenario(handle.selector.as_ref(), &scenario_form).map_err(
        |error| {
            artifact_error(format!(
                "savepoint selector is not admitted by its embedded scenario: {error}"
            ))
        },
    )?;
    validate_campaign_marker_event_source(handle.boundary_proof.as_ref(), &scenario_form)?;
    let scenario = scenario_form.scenario_def();
    if scenario.id().to_hex() != handle.scenario_id_hex {
        return Err(CliError::Identity(format!(
            "savepoint scenario payload id {} did not match handle scenario {}",
            scenario.id().to_hex(),
            handle.scenario_id_hex
        )));
    }
    let schedule = Schedule::from_compact_binary(&handle.schedule_payload).map_err(|error| {
        artifact_error(format!("savepoint schedule payload is malformed: {error}"))
    })?;
    let replay_closure = authenticated_replay_closure(
        &scenario_form,
        &schedule,
        handle.replay_closure_payload.as_deref(),
        "savepoint handle",
    )?;
    let configuration = crucible::Configuration {
        def: scenario.clone(),
        schedule: schedule.clone(),
    };
    if configuration.id() != handle.checkpoint {
        return Err(CliError::Identity(format!(
            "savepoint schedule reconstructs configuration {}, expected checkpoint {}",
            format_content_hash_ref(configuration.id()),
            format_content_hash_ref(handle.checkpoint)
        )));
    }
    let frontier = validate_resume_handle_frontier(&schedule, handle.frontier_ticks)?;
    let checkpoint = checkpoint_for_resume_configuration(&configuration, frontier)?;
    let (source_observation_proof, source_observation_evidence) = handle
        .boundary_proof
        .as_ref()
        .map_or((None, None), |proof| match proof {
            SavepointBoundaryProof::CampaignObservation { proof, evidence } => {
                (Some(proof.clone()), Some(evidence.clone()))
            }
            SavepointBoundaryProof::Coordinate { .. }
            | SavepointBoundaryProof::Breakpoint { .. }
            | SavepointBoundaryProof::CampaignMarkerEvent { .. } => (None, None),
        });
    if let Some(evidence) = source_observation_evidence.as_deref() {
        let campaign_scenario = crucible_campaign::ScenarioDefId::from_hash(
            crucible_campaign::CampaignHash::from_bytes(scenario.id().bytes),
        );
        let campaign_configuration = crucible_campaign::ConfigurationId::from_hash(
            crucible_campaign::CampaignHash::from_bytes(configuration.id().bytes),
        );
        evidence
            .replay(
                campaign_scenario,
                campaign_configuration,
                scenario_form.measurements(),
            )
            .map_err(|error| {
                artifact_error(format!(
                    "savepoint campaign observation evidence is invalid for the embedded scenario: {error}"
                ))
            })?;
    }
    Ok(ResumeHandleEvidence {
        scenario_form,
        scenario,
        schedule,
        configuration,
        checkpoint,
        replay_closure,
        source_observation_proof,
        source_observation_evidence,
    })
}

fn validate_campaign_marker_event_source(
    proof: Option<&SavepointBoundaryProof>,
    scenario: &crucible::ScenarioDefForm,
) -> Result<(), CliError> {
    let Some(SavepointBoundaryProof::CampaignMarkerEvent { node, .. }) = proof else {
        return Ok(());
    };
    let source = scenario
        .world()
        .nodes()
        .iter()
        .find(|candidate| candidate.id() == node)
        .ok_or_else(|| {
            artifact_error(format!(
                "campaign marker event source node `{}` is not declared by its embedded scenario",
                node.name
            ))
        })?;
    let crucible::WorldNodeDef::Vm(source) = source else {
        return Err(artifact_error(format!(
            "campaign marker event source node `{}` is not a virtual machine",
            node.name
        )));
    };
    if source.white_box != crucible::WhiteBoxPolicy::Enabled {
        return Err(artifact_error(format!(
            "campaign marker event source node `{}` is not white-box enabled",
            node.name
        )));
    }
    Ok(())
}

pub(super) fn validate_resume_handle_frontier(
    schedule: &Schedule,
    frontier_ticks: u64,
) -> Result<VirtualTime, CliError> {
    if schedule
        .recorded_virtual_time()
        .is_some_and(|latest| frontier_ticks > latest.ticks)
    {
        return Err(CliError::Identity(format!(
            "savepoint frontier {frontier_ticks} exceeded the latest recorded decision boundary"
        )));
    }
    Ok(VirtualTime {
        ticks: frontier_ticks,
    })
}

pub(super) fn checkpoint_for_resume_configuration(
    configuration: &crucible::Configuration,
    frontier: VirtualTime,
) -> Result<Checkpoint, CliError> {
    recorded_checkpoint_for_configuration(configuration, frontier)
        .map_err(|error| CliError::Identity(format!("resume checkpoint setup failed: {error}")))
}

#[cfg(any(test, feature = "test-double"))]
pub(super) fn resume_recording_loop_for_plan(
    plan: &ResumeInvocationPlan,
    evidence: &ResumeHandleEvidence,
) -> Result<ResumeRecordingLifecycleLoop, CliError> {
    if plan.terminal_condition == RunTerminalCondition::Property {
        let assertion = resume_property_fixture_assertion(&evidence.scenario_form)?;
        return Ok(ResumeRecordingLifecycleLoop::with_property_violation(
            evidence.checkpoint.virtual_time,
            assertion,
        ));
    }
    Ok(ResumeRecordingLifecycleLoop::new(
        evidence.checkpoint.virtual_time,
    ))
}

#[cfg(any(test, feature = "test-double"))]
pub(super) fn resume_property_fixture_assertion(
    scenario: &crucible::ScenarioDefForm,
) -> Result<crucible::AssertionId, CliError> {
    scenario
        .properties()
        .assertions()
        .first()
        .map(|assertion| assertion.id.clone())
        .ok_or_else(|| {
            invalid_scenario(format!(
                "resume --until property requires scenario {} to declare at least one assertion",
                scenario.id().to_hex()
            ))
        })
}

pub(super) fn resume_property_violation_predicate(
    scenario: &crucible::ScenarioDefForm,
) -> Result<crucible::Predicate, CliError> {
    let mut predicates = scenario
        .properties()
        .assertions()
        .iter()
        .map(|assertion| {
            crucible::Predicate::assertion_state(
                assertion.id.clone(),
                crucible::AssertionPhase::Violated,
            )
        })
        .collect::<Vec<_>>();
    match predicates.len() {
        0 => Err(invalid_scenario(format!(
            "resume --until property requires scenario {} to declare at least one assertion",
            scenario.id().to_hex()
        ))),
        1 => Ok(predicates.remove(0)),
        _ => Ok(crucible::Predicate::any_of(predicates)),
    }
}

pub(super) enum ResumeInteractiveCommandDriver<'a> {
    Preparsed(&'a [SessionCommandKind]),
    Stdin,
}

#[cfg(any(test, feature = "test-double"))]
pub(super) type ResumeCommandReply<T> =
    oneshot::Receiver<Result<T, crucible_session::SessionError>>;

#[cfg(any(test, feature = "test-double"))]
pub(super) async fn run_resumed_savepoint_actor_with_driver_async(
    plan: &ResumeInvocationPlan,
    evidence: ResumeHandleEvidence,
    interactive_driver: ResumeInteractiveCommandDriver<'_>,
) -> Result<ResumeWorkflowReport, CliError> {
    ensure_session_replay_evidence_supported("session-owned resume", &evidence)?;
    let resumed_loop = resume_recording_loop_for_plan(plan, &evidence)?;
    let mut graph = save_validation_graph(&evidence.scenario)?;
    if !evidence.configuration.is_genesis() {
        graph
            .cache_snapshot(&evidence.configuration, evidence.checkpoint.clone())
            .map_err(|error| {
                CliError::Identity(format!("resume checkpoint cache admission failed: {error}"))
            })?;
    }
    let genesis = crucible::Configuration::genesis(evidence.scenario.clone());
    let resumed = resume_session_from_validation_dag(
        genesis,
        graph,
        ResumeRecordingLifecycleLoop::new(evidence.checkpoint.virtual_time),
        evidence.checkpoint.id,
        resumed_loop,
    )
    .map_err(|error| backend_error(format!("resume checkpoint instantiation failed: {error}")))?;
    let source_checkpoint = resumed.checkpoint;
    let resumed_configuration = resumed.configuration.id();
    let live = resumed.session_actor.live_snapshot();
    let sender = resumed.session_sender.clone();
    let actor_task = tokio::task::spawn(async move { resumed.session_actor.run().await });
    let mut acknowledged_commands = Vec::new();
    let mut state_updates = vec![format!("{:?}", live.read().state_kind).to_ascii_lowercase()];
    let mut watch_statuses = Vec::new();
    let mut property_violation_reached = false;

    if matches!(plan.execution_mode, RunExecutionMode::Interactive) {
        drive_resumed_actor_interactive_commands(
            &sender,
            &live,
            interactive_driver,
            &mut acknowledged_commands,
            &mut watch_statuses,
            plan.watch_streams_live_status,
        )
        .await?;
        let boundary = live.read();
        state_updates.push(format!("{:?}", boundary.state_kind).to_ascii_lowercase());
        if plan.watch_streams_live_status {
            watch_statuses.push(resume_watch_status(boundary));
        }
    } else {
        match plan.terminal_condition {
            RunTerminalCondition::Quiescence => {
                send_resumed_actor_command(
                    &sender,
                    SessionCommand::step(StepMode::Quantum),
                    &mut acknowledged_commands,
                )
                .await?;
                let boundary =
                    wait_resumed_actor_boundary(&live, RUN_INTERACTIVE_ACK_QUANTA_BOUND, |view| {
                        view.quanta_stepped > 0
                    })
                    .await?;
                state_updates.push(format!("{:?}", boundary.state_kind).to_ascii_lowercase());
                if plan.watch_streams_live_status {
                    watch_statuses.push(resume_watch_status(boundary));
                }
            }
            RunTerminalCondition::VirtualTime => {
                let budget = plan.max_virtual_time_ticks.ok_or_else(|| {
                    usage_error("--until virtual-time requires --max-virtual-time")
                })?;
                let initial = live.read();
                if initial.virtual_time.ticks < budget {
                    let delta = budget.saturating_sub(initial.virtual_time.ticks);
                    send_resumed_actor_command(
                        &sender,
                        SessionCommand::step(StepMode::Duration(SimDuration { nanos: delta })),
                        &mut acknowledged_commands,
                    )
                    .await?;
                }
                let boundary = wait_resumed_actor_boundary(
                    &live,
                    resume_actor_boundary_yield_budget(initial.virtual_time.ticks, budget),
                    |view| {
                        view.virtual_time.ticks >= budget
                            && matches!(
                                view.state_kind,
                                LiveStateKind::Paused | LiveStateKind::Stopped
                            )
                    },
                )
                .await?;
                state_updates.push(format!("{:?}", boundary.state_kind).to_ascii_lowercase());
                if plan.watch_streams_live_status {
                    watch_statuses.push(resume_watch_status(boundary));
                }
            }
            RunTerminalCondition::Stopped => {}
            RunTerminalCondition::Property => {
                let predicate = resume_property_violation_predicate(&evidence.scenario_form)?;
                let breakpoint_id = set_resumed_actor_breakpoint(
                    &sender,
                    BreakpointSpec::fail_once(
                        predicate.clone(),
                        REQUESTED_PROPERTY_VIOLATION_REASON,
                    ),
                    &mut acknowledged_commands,
                )
                .await?;
                let before = live.read();
                send_resumed_actor_command(
                    &sender,
                    SessionCommand::step(StepMode::Quantum),
                    &mut acknowledged_commands,
                )
                .await?;
                let boundary =
                    wait_resumed_actor_boundary(&live, RUN_INTERACTIVE_ACK_QUANTA_BOUND, |view| {
                        view.state_kind == LiveStateKind::Paused
                            && view.quanta_stepped > before.quanta_stepped
                    })
                    .await?;
                state_updates.push(format!("{:?}", boundary.state_kind).to_ascii_lowercase());
                if plan.watch_streams_live_status {
                    watch_statuses.push(resume_watch_status(boundary));
                }
                let firings =
                    query_resumed_actor_breakpoint_firings(&sender, &mut acknowledged_commands)
                        .await?;
                validate_resume_property_firing(breakpoint_id, &predicate, boundary, &firings)?;
                property_violation_reached = true;
            }
        }
    }

    if live.read().state_kind != LiveStateKind::Stopped {
        send_resumed_actor_command(&sender, SessionCommand::Stop, &mut acknowledged_commands)
            .await?;
    }
    let actor_report = actor_task
        .await
        .map_err(|error| backend_error(format!("resume actor task failed to join: {error}")))?
        .map_err(|error| backend_error(format!("resume actor failed: {error}")))?;
    let terminal_oracle =
        validate_resume_terminal_savepoint(&evidence, &actor_report.final_snapshot)?;
    let final_view = live.read();
    state_updates.push(format!("{:?}", final_view.state_kind).to_ascii_lowercase());
    let final_state = if matches!(plan.execution_mode, RunExecutionMode::Interactive) {
        String::from("interactive")
    } else {
        match plan.terminal_condition {
            RunTerminalCondition::Quiescence => String::from("quiescent"),
            RunTerminalCondition::VirtualTime => String::from("virtual-time"),
            RunTerminalCondition::Stopped => String::from("stopped"),
            RunTerminalCondition::Property => String::from("property-failed"),
        }
    };
    if plan.watch_streams_live_status {
        watch_statuses.push(resume_watch_status(final_view));
    }

    Ok(ResumeWorkflowReport {
        run: RunWorkflowReport {
            status: if property_violation_reached {
                BackendCommandStatus::Failed
            } else {
                BackendCommandStatus::Passed
            },
            execution_owner: RunExecutionOwner::Session,
            campaign_replay_closure: None,
            created_state: String::from("paused"),
            final_state,
            outcome: Some(if property_violation_reached {
                OutcomeKind::Failed
            } else {
                OutcomeKind::Passed
            }),
            terminal_savepoint: actor_report
                .final_snapshot
                .terminal_savepoint
                .as_ref()
                .map(|checkpoint| checkpoint.id),
            terminal_configuration: Some(actor_report.final_snapshot.configuration.clone()),
            final_snapshot: Some(actor_report.final_snapshot.clone()),
            final_frontier_ticks: actor_report.final_snapshot.frontier.ticks,
            final_quanta: actor_report.quanta,
            budget_timed_out: false,
            state_updates,
            streamed_events: Vec::new(),
            streamed_event_frames: Vec::new(),
            coverage_feedback: crucible::EventLogCoverageFeedback::from_event_log(&[]),
            execution_fingerprints: Vec::new(),
            resolved_effect_trace: None,
            acknowledged_commands,
            reproduction_commands: Vec::new(),
            watch_statuses,
        },
        source_checkpoint,
        resumed_configuration,
        terminal_configuration: actor_report.final_snapshot.configuration.clone(),
        scenario_label: plan.savepoint.label(),
        terminal_oracle,
    })
}

#[cfg(any(test, feature = "test-double"))]
pub(super) async fn drive_resumed_actor_interactive_commands(
    sender: &mpsc::Sender<SessionCommand>,
    live: &Arc<LiveSnapshot>,
    interactive_driver: ResumeInteractiveCommandDriver<'_>,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
    watch_statuses: &mut Vec<String>,
    watch_streams_live_status: bool,
) -> Result<(), CliError> {
    match interactive_driver {
        ResumeInteractiveCommandDriver::Preparsed(commands) => {
            for command in commands {
                let boundary = acknowledge_resumed_actor_command_kind(
                    sender,
                    live,
                    *command,
                    acknowledged_commands,
                )
                .await?;
                if watch_streams_live_status {
                    watch_statuses.push(resume_watch_status(boundary));
                }
            }
            Ok(())
        }
        ResumeInteractiveCommandDriver::Stdin => {
            drive_resumed_actor_interactive_stdin_commands(
                sender,
                live,
                acknowledged_commands,
                watch_statuses,
                watch_streams_live_status,
            )
            .await
        }
    }
}

#[cfg(any(test, feature = "test-double"))]
pub(super) async fn drive_resumed_actor_interactive_stdin_commands(
    sender: &mpsc::Sender<SessionCommand>,
    live: &Arc<LiveSnapshot>,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
    watch_statuses: &mut Vec<String>,
    watch_streams_live_status: bool,
) -> Result<(), CliError> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    drive_resumed_actor_interactive_command_reader(
        sender,
        live,
        acknowledged_commands,
        watch_statuses,
        watch_streams_live_status,
        stdin.lock(),
        &mut stdout,
    )
    .await
}

#[cfg(any(test, feature = "test-double"))]
pub(super) async fn drive_resumed_actor_interactive_command_reader<R, W>(
    sender: &mpsc::Sender<SessionCommand>,
    live: &Arc<LiveSnapshot>,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
    watch_statuses: &mut Vec<String>,
    watch_streams_live_status: bool,
    reader: R,
    writer: &mut W,
) -> Result<(), CliError>
where
    R: BufRead,
    W: Write,
{
    for line in reader.lines() {
        let line = line?;
        let Some(command) = parse_interactive_session_command_line(&line)? else {
            continue;
        };
        cli_stream_command(command)?;
        let boundary =
            acknowledge_resumed_actor_command_kind(sender, live, command, acknowledged_commands)
                .await?;
        if watch_streams_live_status {
            watch_statuses.push(resume_watch_status(boundary));
        }
        writeln!(
            writer,
            "interactive-ack\tcommand={}\tstatus=accepted",
            session_command_name(command)
        )?;
        if command == SessionCommandKind::Query {
            write_interactive_query_state(writer, boundary.state_kind)?;
        }
        writer.flush()?;
    }
    Ok(())
}

#[cfg(any(test, feature = "test-double"))]
pub(super) async fn acknowledge_resumed_actor_command_kind(
    sender: &mpsc::Sender<SessionCommand>,
    live: &Arc<LiveSnapshot>,
    command: SessionCommandKind,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
) -> Result<LiveSnapshotView, CliError> {
    let before = live.read();
    let model_command = cli_stream_command(command)?;
    let (model_command, acknowledgement) = resume_actor_interactive_command(model_command);
    sender
        .send(model_command)
        .await
        .map_err(|error| backend_error(format!("resume actor command channel closed: {error}")))?;
    observe_resumed_actor_interactive_acceptance(command, acknowledgement).await?;
    acknowledged_commands.push(command);
    observe_resumed_actor_interactive_boundary(live, command, before).await
}

#[cfg(any(test, feature = "test-double"))]
pub(super) fn resume_actor_interactive_command(
    command: SessionCommand,
) -> (SessionCommand, ResumeCommandReply<()>) {
    let (acknowledgement, acknowledgement_receiver) = CommandReply::channel();
    (
        SessionCommand::acknowledged(command, acknowledgement),
        acknowledgement_receiver,
    )
}

#[cfg(any(test, feature = "test-double"))]
pub(super) async fn observe_resumed_actor_interactive_acceptance(
    command: SessionCommandKind,
    acknowledgement: ResumeCommandReply<()>,
) -> Result<(), CliError> {
    let context = format!("interactive command `{}`", session_command_name(command));
    receive_resumed_actor_reply(acknowledgement, &context).await
}

#[cfg(any(test, feature = "test-double"))]
pub(super) async fn observe_resumed_actor_interactive_boundary(
    live: &Arc<LiveSnapshot>,
    command: SessionCommandKind,
    before: LiveSnapshotView,
) -> Result<LiveSnapshotView, CliError> {
    match command {
        SessionCommandKind::Continue
        | SessionCommandKind::StepQuantum
        | SessionCommandKind::StepEvent
        | SessionCommandKind::StepAssertion
        | SessionCommandKind::StepTimer
        | SessionCommandKind::StepDuration => {
            wait_resumed_actor_boundary(live, RUN_INTERACTIVE_ACK_QUANTA_BOUND, |view| {
                view.quanta_stepped > before.quanta_stepped
                    || view.virtual_time.ticks > before.virtual_time.ticks
                    || view.state_kind == LiveStateKind::Stopped
            })
            .await
        }
        SessionCommandKind::Stop => {
            wait_resumed_actor_boundary(live, RUN_INTERACTIVE_ACK_QUANTA_BOUND, |view| {
                view.state_kind == LiveStateKind::Stopped
            })
            .await
        }
        _ => {
            tokio::task::yield_now().await;
            Ok(live.read())
        }
    }
}

#[cfg(any(test, feature = "test-double"))]
pub(super) async fn send_resumed_actor_command(
    sender: &mpsc::Sender<SessionCommand>,
    command: SessionCommand,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
) -> Result<(), CliError> {
    let command_kind = SessionCommandKind::from(&command);
    sender
        .send(command)
        .await
        .map_err(|error| backend_error(format!("resume actor command channel closed: {error}")))?;
    acknowledged_commands.push(command_kind);
    Ok(())
}

#[cfg(any(test, feature = "test-double"))]
pub(super) async fn set_resumed_actor_breakpoint(
    sender: &mpsc::Sender<SessionCommand>,
    spec: BreakpointSpec,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
) -> Result<BreakpointId, CliError> {
    let (reply, receiver) = CommandReply::channel();
    sender
        .send(SessionCommand::SetBreakpoint { spec, reply })
        .await
        .map_err(|error| backend_error(format!("resume actor command channel closed: {error}")))?;
    let id = receive_resumed_actor_reply(receiver, "set breakpoint").await?;
    acknowledged_commands.push(SessionCommandKind::SetBreakpoint);
    Ok(id)
}

#[cfg(any(test, feature = "test-double"))]
pub(super) async fn query_resumed_actor_breakpoint_firings(
    sender: &mpsc::Sender<SessionCommand>,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
) -> Result<Vec<crucible_session::BreakpointFiring>, CliError> {
    let (reply, receiver) = CommandReply::channel();
    sender
        .send(SessionCommand::Query {
            kind: QueryKind::BreakpointFirings,
            reply,
        })
        .await
        .map_err(|error| backend_error(format!("resume actor command channel closed: {error}")))?;
    let result = receive_resumed_actor_reply(receiver, "query breakpoint firings").await?;
    acknowledged_commands.push(SessionCommandKind::Query);
    match result {
        QueryResult::BreakpointFirings(firings) => Ok(firings),
        other => Err(backend_error(format!(
            "resume property proof query returned unexpected payload: {other:?}"
        ))),
    }
}

#[cfg(any(test, feature = "test-double"))]
pub(super) async fn receive_resumed_actor_reply<T>(
    receiver: tokio::sync::oneshot::Receiver<Result<T, crucible_session::SessionError>>,
    context: &str,
) -> Result<T, CliError> {
    receiver
        .await
        .map_err(|error| backend_error(format!("resume actor {context} reply dropped: {error}")))?
        .map_err(|error| backend_error(format!("resume actor {context} failed: {error}")))
}

#[cfg(any(test, feature = "test-double"))]
pub(super) fn validate_resume_property_firing(
    breakpoint_id: BreakpointId,
    expected: &crucible::Predicate,
    boundary: LiveSnapshotView,
    firings: &[crucible_session::BreakpointFiring],
) -> Result<(), CliError> {
    let firing = firings
        .iter()
        .find(|firing| firing.id == breakpoint_id)
        .ok_or_else(|| {
            backend_error(format!(
                "resume property breakpoint {breakpoint_id} did not fire before resume boundary; the selected checkpoint may already be terminal and have no resumable predecessor"
            ))
        })?;
    if &firing.predicate != expected {
        return Err(CliError::Identity(format!(
            "resume property breakpoint predicate {:?} did not match expected {:?}",
            firing.predicate, expected
        )));
    }
    match &firing.disposition {
        BreakpointDisposition::Action(crucible::Action::Fail { reason })
            if reason == REQUESTED_PROPERTY_VIOLATION_REASON => {}
        disposition => {
            return Err(CliError::Identity(format!(
                "resume property breakpoint used unexpected disposition {disposition:?}"
            )));
        }
    }
    if firing.frontier != boundary.virtual_time {
        return Err(CliError::Identity(format!(
            "resume property breakpoint fired at {}, but boundary is {}",
            firing.frontier.ticks, boundary.virtual_time.ticks
        )));
    }
    if firing.quanta != boundary.quanta_stepped {
        return Err(CliError::Identity(format!(
            "resume property breakpoint fired at quantum {}, but boundary is {}",
            firing.quanta, boundary.quanta_stepped
        )));
    }
    Ok(())
}

pub(super) fn validate_resume_property_suspension_summary(
    breakpoint_id: BreakpointId,
    expected: &crucible::Predicate,
    boundary: &crucible_api::SessionSummary,
    firings: &[crucible_session::BreakpointFiring],
) -> Result<(), CliError> {
    let firing = firings
        .iter()
        .find(|firing| firing.id == breakpoint_id)
        .ok_or_else(|| {
            backend_error(format!(
                "remote resume property breakpoint {breakpoint_id} did not fire before resume boundary; the selected checkpoint may already be terminal and have no resumable predecessor"
            ))
        })?;
    if &firing.predicate != expected {
        return Err(CliError::Identity(format!(
            "remote resume property breakpoint predicate {:?} did not match expected {:?}",
            firing.predicate, expected
        )));
    }
    if firing.disposition != BreakpointDisposition::Suspend {
        return Err(CliError::Identity(format!(
            "remote resume property breakpoint used unexpected disposition {:?}",
            firing.disposition
        )));
    }
    if firing.frontier != boundary.frontier {
        return Err(CliError::Identity(format!(
            "remote resume property breakpoint fired at {}, but boundary is {}",
            firing.frontier.ticks, boundary.frontier.ticks
        )));
    }
    if firing.quanta != boundary.quanta_stepped {
        return Err(CliError::Identity(format!(
            "remote resume property breakpoint fired at quantum {}, but boundary is {}",
            firing.quanta, boundary.quanta_stepped
        )));
    }
    Ok(())
}

pub(super) async fn send_resume_workflow_command<C>(
    client: &C,
    session: SessionRef,
    command_id: &mut u64,
    command: SessionCommand,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
    state_updates: &mut Vec<String>,
) -> Result<crucible_api::SendResponse, CliError>
where
    C: ControlClient + Sync,
{
    let command_kind = SessionCommandKind::from(&command);
    let request =
        SendRequest::new(session, *command_id, command).with_expected_epoch(session.epoch);
    let response = client
        .send_command(request)
        .await
        .map_err(control_client_error)?;
    *command_id = command_id.saturating_add(1);
    if let Some(update) = response.state_update {
        state_updates.push(format!("{:?}", update.state).to_ascii_lowercase());
    }
    match &response.result.status {
        CommandResultStatus::Accepted => {
            acknowledged_commands.push(command_kind);
            Ok(response)
        }
        CommandResultStatus::Rejected { reason } => Err(backend_error(format!(
            "resume workflow command `{}` was rejected: {reason:?}",
            session_command_name(command_kind)
        ))),
    }
}

pub(super) async fn wait_for_resume_workflow_state<C>(
    client: &C,
    session: SessionRef,
    expected: LiveStateKind,
) -> Result<crucible_api::SessionSummary, CliError>
where
    C: ControlClient + Sync,
{
    let description = format!("{expected:?}");
    wait_for_resume_workflow_summary(
        client,
        session,
        |summary| summary.state == expected,
        &description,
        RESUME_WORKFLOW_OBSERVER_TIMEOUT,
    )
    .await
}

pub(super) async fn wait_for_resume_workflow_summary<C>(
    client: &C,
    session: SessionRef,
    mut accepts: impl FnMut(&crucible_api::SessionSummary) -> bool,
    description: &str,
    timeout: Duration,
) -> Result<crucible_api::SessionSummary, CliError>
where
    C: ControlClient + Sync,
{
    let observation = async {
        loop {
            let sessions = client.list_sessions().await.map_err(control_client_error)?;
            let Some(summary) = sessions
                .sessions
                .iter()
                .find(|summary| summary.session == session)
            else {
                return Err(backend_error("resume workflow session disappeared"));
            };
            if accepts(summary) {
                return Ok(summary.clone());
            }
            if summary.state == LiveStateKind::Stopped {
                return Err(CliError::Outcome(status_from_outcome(summary.outcome)?));
            }
            // Local ListSessions calls complete immediately. Yield real time so
            // the actor and live backend can advance without a hot polling loop.
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    };
    tokio::time::timeout(timeout, observation)
        .await
        .map_err(|_| backend_error(format!("resume workflow did not reach {description}")))?
}

#[cfg(any(test, feature = "test-double"))]
pub(super) async fn wait_resumed_actor_boundary(
    live: &Arc<LiveSnapshot>,
    max_actor_yields: u64,
    predicate: impl Fn(LiveSnapshotView) -> bool,
) -> Result<LiveSnapshotView, CliError> {
    for _ in 0..max_actor_yields {
        let view = live.read();
        if predicate(view) {
            return Ok(view);
        }
        if view.state_kind == LiveStateKind::Stopped {
            return Ok(view);
        }
        tokio::task::yield_now().await;
    }
    let final_view = live.read();
    Err(backend_error(format!(
        "resume actor did not reach the requested deterministic boundary: state={:?} \
         frontier={} quanta={}",
        final_view.state_kind, final_view.virtual_time.ticks, final_view.quanta_stepped
    )))
}

#[cfg(any(test, feature = "test-double"))]
pub(super) fn resume_actor_boundary_yield_budget(start_ticks: u64, target_ticks: u64) -> u64 {
    RUN_INTERACTIVE_ACK_QUANTA_BOUND.saturating_add(target_ticks.saturating_sub(start_ticks))
}

#[cfg(any(test, feature = "test-double"))]
pub(super) fn resume_watch_status(view: LiveSnapshotView) -> String {
    format!(
        "state={}\tfrontier_ticks={}\tquanta={}\toutcome={}\tsavepoint={}",
        format!("{:?}", view.state_kind).to_ascii_lowercase(),
        view.virtual_time.ticks,
        view.quanta_stepped,
        terminal_outcome_label(view.outcome),
        view.terminal_savepoint
            .map(format_content_hash_ref)
            .unwrap_or_else(|| String::from("none"))
    )
}

#[path = "resume/outcome.rs"]
mod outcome;
#[path = "resume/remote.rs"]
mod remote;

pub(super) use outcome::*;
pub(super) use remote::*;
