//! Resume, fork, and verification workflow realization.

use super::*;
#[cfg(any(test, feature = "test-double"))]
pub(super) fn run_local_double_fork_workflow(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    fork_plan: &ForkInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let evidence = fork_handle_evidence(fork_plan)?;
    run_local_double_fork_workflow_with_driver(
        thin_plan,
        backend_plan,
        ergonomics_plan,
        fork_plan,
        evidence,
        default_fork_interactive_driver(fork_plan),
    )
}

pub(super) fn run_local_qemu_fork_workflow(
    _thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    _ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    _fork_plan: &ForkInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let backend = backend_plan
        .resolved_backend
        .as_ref()
        .ok_or_else(|| backend_error("local QEMU fork requires a resolved backend"))?;
    reject_unwired_qemu_workflow(backend, "fork")
}

pub(super) fn default_fork_interactive_driver(
    fork_plan: &ForkInvocationPlan,
) -> ResumeInteractiveCommandDriver<'static> {
    if matches!(fork_plan.execution_mode, RunExecutionMode::Interactive) {
        ResumeInteractiveCommandDriver::Stdin
    } else {
        ResumeInteractiveCommandDriver::Preparsed(&[])
    }
}

#[cfg(any(test, feature = "test-double"))]
pub(super) fn run_local_double_fork_workflow_with_driver(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    fork_plan: &ForkInvocationPlan,
    evidence: ResumeHandleEvidence,
    interactive_driver: ResumeInteractiveCommandDriver<'_>,
) -> Result<BackendCommandOutcome, CliError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let report = runtime.block_on(run_forked_savepoint_actor_with_driver_async(
        fork_plan,
        evidence,
        interactive_driver,
    ))?;
    finish_fork_workflow_outcome(thin_plan, backend_plan, ergonomics_plan, fork_plan, report)
}

#[cfg(test)]
pub(super) fn run_local_double_fork_workflow_with_interactive_commands(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    fork_plan: &ForkInvocationPlan,
    commands: &[SessionCommandKind],
) -> Result<BackendCommandOutcome, CliError> {
    let evidence = fork_handle_evidence(fork_plan)?;
    run_local_double_fork_workflow_with_driver(
        thin_plan,
        backend_plan,
        ergonomics_plan,
        fork_plan,
        evidence,
        ResumeInteractiveCommandDriver::Preparsed(commands),
    )
}

pub(super) fn resume_handle_evidence(
    plan: &ResumeInvocationPlan,
) -> Result<ResumeHandleEvidence, CliError> {
    savepoint_evidence("resume", &plan.savepoint, &plan.store_root)
}

pub(super) fn fork_handle_evidence(
    plan: &ForkInvocationPlan,
) -> Result<ResumeHandleEvidence, CliError> {
    savepoint_evidence("fork", &plan.source, &plan.store_root)
}

pub(super) fn savepoint_evidence(
    command_name: &'static str,
    savepoint: &ResumeSavepointRef,
    store_root: &Path,
) -> Result<ResumeHandleEvidence, CliError> {
    match savepoint {
        ResumeSavepointRef::CheckpointHash(checkpoint) => {
            savepoint_store_evidence(command_name, *checkpoint, store_root)
        }
        ResumeSavepointRef::Handle { handle, .. } => {
            savepoint_handle_evidence(command_name, handle)
        }
    }
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
    Ok(ResumeHandleEvidence {
        scenario_form,
        scenario,
        schedule,
        configuration,
        checkpoint,
    })
}

pub(super) fn savepoint_store_evidence(
    command_name: &'static str,
    checkpoint: crucible::ContentHash,
    store_root: &Path,
) -> Result<ResumeHandleEvidence, CliError> {
    let store = crucible::LocalDagStore::new(store_root.to_path_buf());
    let index = store
        .read_checkpoint_closure_index(checkpoint)
        .map_err(|error| {
            artifact_error(format!(
                "{command_name} checkpoint {} could not be loaded from DAG store {}: {error}; pass a .crucible-savepoint handle or use the same --store used when saving",
                format_content_hash_ref(checkpoint),
                store.root().display()
            ))
        })?;
    let artifact_bytes = store.get(&index.reproduction_artifact).map_err(|error| {
        artifact_error(format!(
            "{command_name} checkpoint {} index referenced missing artifact {} in DAG store {}: {error}",
            format_content_hash_ref(checkpoint),
            format_content_hash_ref(index.reproduction_artifact),
            store.root().display()
        ))
    })?;
    let artifact =
        crucible::ReproductionArtifact::from_compact_binary(&artifact_bytes).map_err(|error| {
            artifact_error(format!(
                "{command_name} checkpoint {} closure artifact {} is malformed: {error}",
                format_content_hash_ref(checkpoint),
                format_content_hash_ref(index.reproduction_artifact)
            ))
        })?;
    if artifact.id() != index.reproduction_artifact {
        return Err(artifact_error(format!(
            "{command_name} checkpoint {} closure artifact id {} did not match indexed key {}",
            format_content_hash_ref(checkpoint),
            format_content_hash_ref(artifact.id()),
            format_content_hash_ref(index.reproduction_artifact)
        )));
    }
    artifact.replay().map_err(|error| {
        artifact_error(format!(
            "{command_name} checkpoint {} closure artifact {} failed replay validation: {error}",
            format_content_hash_ref(checkpoint),
            format_content_hash_ref(index.reproduction_artifact)
        ))
    })?;
    let scenario_form = artifact.scenario_form().clone();
    let scenario = artifact.scenario_def();
    let schedule = artifact.schedule().clone();
    let configuration = crucible::Configuration {
        def: scenario.clone(),
        schedule: schedule.clone(),
    };
    if configuration.id() != checkpoint {
        return Err(artifact_error(format!(
            "{command_name} checkpoint closure reconstructed {}, expected {}",
            format_content_hash_ref(configuration.id()),
            format_content_hash_ref(checkpoint)
        )));
    }
    let frontier_ticks = u64::try_from(schedule.len()).map_err(|_| {
        artifact_error(format!(
            "{command_name} checkpoint closure schedule length {} cannot be represented as virtual time",
            schedule.len()
        ))
    })?;
    let frontier = validate_resume_handle_frontier(&schedule, frontier_ticks)?;
    let checkpoint =
        checkpoint_for_resume_configuration(&configuration, frontier).map_err(|error| {
            artifact_error(format!(
                "{command_name} checkpoint closure could not build checkpoint metadata: {error}"
            ))
        })?;
    Ok(ResumeHandleEvidence {
        scenario_form,
        scenario,
        schedule,
        configuration,
        checkpoint,
    })
}

pub(super) fn validate_resume_handle_frontier(
    schedule: &Schedule,
    frontier_ticks: u64,
) -> Result<VirtualTime, CliError> {
    let schedule_ticks = u64::try_from(schedule.len()).map_err(|_| {
        CliError::Identity(format!(
            "savepoint schedule length {} cannot be represented as virtual time",
            schedule.len()
        ))
    })?;
    if frontier_ticks != schedule_ticks {
        return Err(CliError::Identity(format!(
            "savepoint handle frontier {frontier_ticks} did not match schedule-derived frontier {schedule_ticks}"
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

pub(super) fn fork_recording_loop_for_plan(
    plan: &ForkInvocationPlan,
    evidence: &ResumeHandleEvidence,
    frontier: VirtualTime,
) -> Result<ResumeRecordingLifecycleLoop, CliError> {
    let loop_driver = if plan.terminal_condition == RunTerminalCondition::Property {
        let assertion = resume_property_fixture_assertion(&evidence.scenario_form)?;
        ResumeRecordingLifecycleLoop::with_property_violation(frontier, assertion)
    } else {
        ResumeRecordingLifecycleLoop::new(frontier)
    };
    if let Some(seed) = plan.fork_seed {
        return Ok(loop_driver.with_post_fork_seed(crucible::Seed::from_u64(seed)));
    }
    Ok(loop_driver)
}

pub(super) fn fork_override_decisions(plan: &ForkInvocationPlan) -> Vec<crucible::Decision> {
    plan.decision_overrides
        .iter()
        .map(|override_plan| {
            crucible::Decision::Override(OverrideDecision {
                point: SchedulingPoint {
                    key: override_plan.decision.clone(),
                },
                choice: ChoiceTag {
                    name: override_plan.value.clone(),
                },
            })
        })
        .collect()
}

pub(super) fn fork_branch_frontier(
    evidence: &ResumeHandleEvidence,
    appended_decisions: usize,
) -> Result<VirtualTime, CliError> {
    let branch_len = evidence
        .schedule
        .len()
        .checked_add(appended_decisions)
        .ok_or_else(|| CliError::Identity("fork branch schedule length overflowed".to_string()))?;
    let ticks = u64::try_from(branch_len).map_err(|_| {
        CliError::Identity(format!(
            "fork branch schedule length {branch_len} cannot be represented as virtual time"
        ))
    })?;
    Ok(VirtualTime { ticks })
}

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

pub(super) type ResumeCommandReply<T> =
    oneshot::Receiver<Result<T, crucible_session::SessionError>>;

pub(super) async fn run_resumed_savepoint_actor_with_driver_async(
    plan: &ResumeInvocationPlan,
    evidence: ResumeHandleEvidence,
    interactive_driver: ResumeInteractiveCommandDriver<'_>,
) -> Result<ResumeWorkflowReport, CliError> {
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
                    BreakpointSpec::suspend_once(predicate.clone()),
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
            final_frontier_ticks: actor_report.final_snapshot.frontier.ticks,
            final_quanta: actor_report.quanta,
            budget_timed_out: false,
            state_updates,
            streamed_events: Vec::new(),
            streamed_event_frames: Vec::new(),
            execution_fingerprints: Vec::new(),
            acknowledged_commands,
            watch_statuses,
        },
        source_checkpoint,
        resumed_configuration,
        terminal_configuration: actor_report.final_snapshot.configuration.clone(),
        scenario_label: plan.savepoint.label(),
        terminal_oracle,
    })
}

pub(super) async fn run_forked_savepoint_actor_with_driver_async(
    plan: &ForkInvocationPlan,
    evidence: ResumeHandleEvidence,
    interactive_driver: ResumeInteractiveCommandDriver<'_>,
) -> Result<ForkWorkflowReport, CliError> {
    let fork_decisions = fork_override_decisions(plan);
    let branch_frontier = fork_branch_frontier(&evidence, fork_decisions.len())?;
    let child_loop = fork_recording_loop_for_plan(plan, &evidence, branch_frontier)?;
    let mut graph = save_validation_graph(&evidence.scenario)?;
    if !evidence.configuration.is_genesis() {
        graph
            .cache_snapshot(&evidence.configuration, evidence.checkpoint.clone())
            .map_err(|error| {
                CliError::Identity(format!("fork checkpoint cache admission failed: {error}"))
            })?;
    }
    let genesis = crucible::Configuration::genesis(evidence.scenario.clone());
    let fork = if fork_decisions.is_empty() {
        fork_session_from_validation_checkpoint(
            genesis,
            graph,
            ResumeRecordingLifecycleLoop::new(evidence.checkpoint.virtual_time),
            CheckpointRef::Checkpoint(evidence.checkpoint.id),
            child_loop,
        )
        .map_err(|error| {
            backend_error(format!(
                "fork child checkpoint instantiation failed: {error}"
            ))
        })?
    } else {
        fork_session_from_validation_base(
            genesis,
            graph,
            ResumeRecordingLifecycleLoop::new(evidence.checkpoint.virtual_time),
            &evidence.configuration,
            fork_decisions,
            child_loop,
        )
        .map_err(|error| {
            backend_error(format!("fork child override instantiation failed: {error}"))
        })?
    };
    let source_checkpoint = fork.record.from_checkpoint;
    let branch_checkpoint = fork.record.branch_checkpoint;
    let branch_configuration = fork.branch_configuration.id();
    let live = fork.child_actor.live_snapshot();
    let sender = fork.child_sender.clone();
    let actor_task = tokio::task::spawn(async move { fork.child_actor.run().await });
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
                    BreakpointSpec::suspend_once(predicate.clone()),
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
        .map_err(|error| backend_error(format!("fork child actor task failed to join: {error}")))?
        .map_err(|error| backend_error(format!("fork child actor failed: {error}")))?;
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

    Ok(ForkWorkflowReport {
        run: RunWorkflowReport {
            status: if property_violation_reached {
                BackendCommandStatus::Failed
            } else {
                BackendCommandStatus::Passed
            },
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
            final_frontier_ticks: actor_report.final_snapshot.frontier.ticks,
            final_quanta: actor_report.quanta,
            budget_timed_out: false,
            state_updates,
            streamed_events: Vec::new(),
            streamed_event_frames: Vec::new(),
            execution_fingerprints: Vec::new(),
            acknowledged_commands,
            watch_statuses,
        },
        source_checkpoint,
        branch_checkpoint,
        branch_configuration,
        terminal_configuration: actor_report.final_snapshot.configuration,
        scenario_form: evidence.scenario_form,
        scenario_label: plan.source.label(),
        label: plan.label.clone(),
        terminal_oracle,
    })
}

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
        writer.flush()?;
    }
    Ok(())
}

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

pub(super) fn resume_actor_interactive_command(
    command: SessionCommand,
) -> (SessionCommand, ResumeCommandReply<()>) {
    let (acknowledgement, acknowledgement_receiver) = CommandReply::channel();
    (
        SessionCommand::acknowledged(command, acknowledgement),
        acknowledgement_receiver,
    )
}

pub(super) async fn observe_resumed_actor_interactive_acceptance(
    command: SessionCommandKind,
    acknowledgement: ResumeCommandReply<()>,
) -> Result<(), CliError> {
    let context = format!("interactive command `{}`", session_command_name(command));
    receive_resumed_actor_reply(acknowledgement, &context).await
}

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

pub(super) async fn receive_resumed_actor_reply<T>(
    receiver: tokio::sync::oneshot::Receiver<Result<T, crucible_session::SessionError>>,
    context: &str,
) -> Result<T, CliError> {
    receiver
        .await
        .map_err(|error| backend_error(format!("resume actor {context} reply dropped: {error}")))?
        .map_err(|error| backend_error(format!("resume actor {context} failed: {error}")))
}

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
                "resume property breakpoint {breakpoint_id} did not fire before resume boundary"
            ))
        })?;
    if &firing.predicate != expected {
        return Err(CliError::Identity(format!(
            "resume property breakpoint predicate {:?} did not match expected {:?}",
            firing.predicate, expected
        )));
    }
    if firing.disposition != BreakpointDisposition::Suspend {
        return Err(CliError::Identity(format!(
            "resume property breakpoint used {:?} disposition instead of suspend",
            firing.disposition
        )));
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

pub(super) fn validate_resume_property_firing_summary(
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
                "remote resume property breakpoint {breakpoint_id} did not fire before resume boundary"
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
            "remote resume property breakpoint used {:?} disposition instead of suspend",
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
        RUN_INTERACTIVE_ACK_QUANTA_BOUND,
    )
    .await
}

pub(super) async fn wait_for_resume_workflow_advanced_paused<C>(
    client: &C,
    session: SessionRef,
    before: &crucible_api::SessionSummary,
    description: &str,
) -> Result<crucible_api::SessionSummary, CliError>
where
    C: ControlClient + Sync,
{
    wait_for_resume_workflow_summary(
        client,
        session,
        |summary| {
            summary.state == LiveStateKind::Paused
                && summary.frontier.ticks > before.frontier.ticks
                && summary.quanta_stepped > before.quanta_stepped
        },
        description,
        RUN_INTERACTIVE_ACK_QUANTA_BOUND,
    )
    .await
}

pub(super) async fn wait_for_resume_workflow_summary<C>(
    client: &C,
    session: SessionRef,
    mut accepts: impl FnMut(&crucible_api::SessionSummary) -> bool,
    description: &str,
    max_attempts: u64,
) -> Result<crucible_api::SessionSummary, CliError>
where
    C: ControlClient + Sync,
{
    for _ in 0..max_attempts {
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
            return Err(CliError::Outcome(status_from_outcome(summary.outcome)));
        }
        tokio::task::yield_now().await;
    }
    Err(backend_error(format!(
        "resume workflow did not reach {description}"
    )))
}

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
    Err(backend_error(
        "resume actor did not reach the requested deterministic boundary",
    ))
}

pub(super) fn resume_actor_boundary_yield_budget(start_ticks: u64, target_ticks: u64) -> u64 {
    RUN_INTERACTIVE_ACK_QUANTA_BOUND.saturating_add(target_ticks.saturating_sub(start_ticks))
}

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

pub(super) fn finish_resume_workflow_outcome(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    resume_plan: &ResumeInvocationPlan,
    report: ResumeWorkflowReport,
) -> Result<BackendCommandOutcome, CliError> {
    let mut outcome = backend_command_outcome(thin_plan, backend_plan, ergonomics_plan);
    let oracle = report.terminal_oracle.clone();
    outcome.status = report.run.status;
    outcome.exit_code = report.run.status.exit_code();
    outcome.terminal_savepoint = report.run.terminal_savepoint;
    outcome.stdout.push(format!(
        "resume-session\tcheckpoint={}\tconfiguration={}\tscenario={}\tfinal={}\toutcome={}\tfrontier_ticks={}\tquanta={}\tacks={}",
        format_content_hash_ref(report.source_checkpoint),
        format_content_hash_ref(report.resumed_configuration),
        report.scenario_label,
        report.run.final_state,
        terminal_outcome_label(report.run.outcome),
        report.run.final_frontier_ticks,
        report.run.final_quanta,
        report.run.acknowledged_commands.len()
    ));
    for status in &report.run.watch_statuses {
        outcome.stdout.push(format!("run-watch\t{status}"));
    }
    outcome.stdout.push(format!(
        "resume-oracle\tstatus={}\tconfiguration={}\tfat={}\tthin={}",
        oracle.status_label(),
        format_content_hash_ref(oracle.configuration),
        format_content_hash_ref(oracle.fat_checkpoint),
        format_content_hash_ref(oracle.thin_checkpoint)
    ));
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: outcome.canonical_log.len() as u64,
        node: String::from("session"),
        kind: String::from("resume_checkpoint"),
        summary: format!(
            "checkpoint={} configuration={} until={}",
            format_content_hash_ref(report.source_checkpoint),
            format_content_hash_ref(report.resumed_configuration),
            resume_plan.terminal_condition.label()
        ),
    });
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: outcome.canonical_log.len() as u64,
        node: String::from("replay-oracle"),
        kind: String::from("resume_oracle_validation"),
        summary: format!(
            "status={} configuration={} fat={} thin={}",
            oracle.status_label(),
            format_content_hash_ref(oracle.configuration),
            format_content_hash_ref(oracle.fat_checkpoint),
            format_content_hash_ref(oracle.thin_checkpoint)
        ),
    });
    outcome.canonical_log_digest = canonical_log_digest(&outcome.canonical_log);
    outcome.savepoint_oracle = Some(oracle);
    Ok(outcome)
}

pub(super) fn finish_fork_workflow_outcome(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    fork_plan: &ForkInvocationPlan,
    report: ForkWorkflowReport,
) -> Result<BackendCommandOutcome, CliError> {
    let mut outcome = backend_command_outcome(thin_plan, backend_plan, ergonomics_plan);
    let oracle = report.terminal_oracle.clone();
    let artifact = write_fork_reproduction_artifact(
        fork_plan,
        backend_plan.resolved_backend.as_ref(),
        &report.scenario_form,
        &report.terminal_configuration,
    )?;
    outcome.status = report.run.status;
    outcome.exit_code = report.run.status.exit_code();
    outcome.terminal_savepoint = report.run.terminal_savepoint;
    outcome.stdout.push(format!(
        "fork-session\tcheckpoint={}\tbranch={}\tconfiguration={}\tscenario={}\tlabel={}\tfork_seed={}\tfinal={}\toutcome={}\tfrontier_ticks={}\tquanta={}\tacks={}",
        format_content_hash_ref(report.source_checkpoint),
        format_content_hash_ref(report.branch_checkpoint),
        format_content_hash_ref(report.branch_configuration),
        report.scenario_label,
        report.label,
        fork_seed_label(fork_plan),
        report.run.final_state,
        terminal_outcome_label(report.run.outcome),
        report.run.final_frontier_ticks,
        report.run.final_quanta,
        report.run.acknowledged_commands.len()
    ));
    outcome.stdout.push(format!(
        "fork-artifact\tpath={}\tdigest={}\tseed={}\tfork_seed={}\tmodel_artifact={}\treplay_state={}\tschedule={}\tfingerprint={}",
        artifact.path.display(),
        artifact.digest,
        format_seed(artifact.seed),
        format_optional_seed(artifact.fork_seed),
        format_content_hash_ref(artifact.model_artifact),
        format_content_hash_ref(artifact.replay_state),
        format_content_hash_ref(artifact.schedule),
        format_content_hash_ref(artifact.finding_fingerprint)
    ));
    for status in &report.run.watch_statuses {
        outcome.stdout.push(format!("run-watch\t{status}"));
    }
    outcome.stdout.push(format!(
        "fork-oracle\tstatus={}\tconfiguration={}\tfat={}\tthin={}",
        oracle.status_label(),
        format_content_hash_ref(oracle.configuration),
        format_content_hash_ref(oracle.fat_checkpoint),
        format_content_hash_ref(oracle.thin_checkpoint)
    ));
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: outcome.canonical_log.len() as u64,
        node: String::from("session"),
        kind: String::from("fork_checkpoint"),
        summary: format!(
            "checkpoint={} branch={} configuration={} label={} until={}",
            format_content_hash_ref(report.source_checkpoint),
            format_content_hash_ref(report.branch_checkpoint),
            format_content_hash_ref(report.branch_configuration),
            report.label,
            fork_plan.terminal_condition.label()
        ),
    });
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: outcome.canonical_log.len() as u64,
        node: String::from("replay-oracle"),
        kind: String::from("fork_oracle_validation"),
        summary: format!(
            "status={} configuration={} fat={} thin={}",
            oracle.status_label(),
            format_content_hash_ref(oracle.configuration),
            format_content_hash_ref(oracle.fat_checkpoint),
            format_content_hash_ref(oracle.thin_checkpoint)
        ),
    });
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: outcome.canonical_log.len() as u64,
        node: String::from("artifact"),
        kind: String::from("fork_reproduction_artifact"),
        summary: format!(
            "path={} digest={} seed={} fork_seed={} model_artifact={} replay_state={} schedule={}",
            artifact.path.display(),
            artifact.digest,
            format_seed(artifact.seed),
            format_optional_seed(artifact.fork_seed),
            format_content_hash_ref(artifact.model_artifact),
            format_content_hash_ref(artifact.replay_state),
            format_content_hash_ref(artifact.schedule)
        ),
    });
    outcome.canonical_log_digest = canonical_log_digest(&outcome.canonical_log);
    outcome.savepoint_oracle = Some(oracle);
    Ok(outcome)
}

pub(super) fn write_fork_reproduction_artifact(
    plan: &ForkInvocationPlan,
    backend: Option<&ResolvedLocalBackend>,
    scenario_form: &crucible::ScenarioDefForm,
    configuration: &crucible::Configuration,
) -> Result<ForkReproductionArtifactReport, CliError> {
    let finding_fingerprint = fork_finding_fingerprint(plan, configuration);
    let finding = FindingReproductionArtifact::capture(
        FindingDiscoveryPath::InteractiveFork,
        finding_fingerprint,
        scenario_form,
        configuration,
    )
    .map_err(|error| {
        CliError::Identity(format!(
            "fork reproduction artifact replay validation failed: {error}"
        ))
    })?;
    let canonical_log = fork_artifact_canonical_log(configuration);
    let artifact_seed = seed_to_u64(scenario_form.seed());
    let instruction = u64::try_from(configuration.schedule.len()).map_err(|_| {
        CliError::Identity(format!(
            "fork artifact schedule length {} cannot be represented as an instruction index",
            configuration.schedule.len()
        ))
    })?;
    let fingerprint = VerifyFingerprintSample {
        index: 0,
        instruction,
        node: String::from("fork"),
        digest: content_address_bytes(format_content_hash_ref(finding.replay.state).as_bytes()),
    };
    let bytes = verify_reproduction_artifact_bytes(
        artifact_seed,
        backend,
        &scenario_form.scenario_def(),
        &canonical_log,
        &[fingerprint],
    )?;
    let digest = content_address_bytes(&bytes);
    fs::create_dir_all(&plan.artifact_dir)?;
    let path = plan.artifact_dir.join(format!(
        "fork-{}-{}.crucible",
        sanitize_slug(&plan.label),
        short_digest(&digest)
    ));
    fs::write(&path, bytes)?;
    Ok(ForkReproductionArtifactReport {
        path,
        digest,
        seed: artifact_seed,
        fork_seed: plan.fork_seed,
        model_artifact: finding.artifact.id(),
        replay_state: finding.replay.state,
        schedule: finding.artifact.schedule().content_hash(),
        finding_fingerprint,
    })
}

pub(super) fn fork_seed_label(plan: &ForkInvocationPlan) -> String {
    format_optional_seed(plan.fork_seed)
}

pub(super) fn format_optional_seed(seed: Option<u64>) -> String {
    seed.map(format_seed)
        .unwrap_or_else(|| String::from("inherited"))
}

pub(super) fn fork_finding_fingerprint(
    plan: &ForkInvocationPlan,
    configuration: &crucible::Configuration,
) -> crucible::ContentHash {
    let mut material = format!(
        "source={}\nlabel={}\nconfiguration={}\n",
        format_content_hash_ref(plan.source.checkpoint()),
        plan.label,
        format_content_hash_ref(configuration.id())
    );
    if let Some(seed) = plan.fork_seed {
        material.push_str("fork_seed=");
        material.push_str(&format_seed(seed));
        material.push('\n');
    }
    for decision_override in &plan.decision_overrides {
        material.push_str("override=");
        material.push_str(&decision_override.decision);
        material.push('=');
        material.push_str(&decision_override.value);
        material.push('\n');
    }
    crucible::ContentHash::from_canonical_material("crucible.cli.fork.finding.v1", &material)
}

pub(super) fn fork_artifact_canonical_log(
    configuration: &crucible::Configuration,
) -> Vec<CanonicalLogEntry> {
    let mut entries = configuration
        .schedule
        .decisions()
        .iter()
        .enumerate()
        .map(|(sequence, decision)| CanonicalLogEntry {
            sequence: sequence as u64,
            virtual_time_ticks: sequence.saturating_add(1) as u64,
            node: String::from("schedule"),
            kind: fork_artifact_decision_kind(decision).to_string(),
            summary: format!("{decision:?}"),
        })
        .collect::<Vec<_>>();
    if entries.is_empty() {
        entries.push(CanonicalLogEntry {
            sequence: 0,
            virtual_time_ticks: 0,
            node: String::from("fork"),
            kind: String::from("empty_schedule"),
            summary: format!(
                "configuration={}",
                format_content_hash_ref(configuration.id())
            ),
        });
    }
    entries
}

pub(super) fn fork_artifact_decision_kind(decision: &crucible::Decision) -> &'static str {
    match decision {
        crucible::Decision::DeliveryOrder(_) => "delivery_order",
        crucible::Decision::FaultFires(_) => "fault_fires",
        crucible::Decision::RngDraw(_) => "rng_draw",
        crucible::Decision::Override(_) => "override",
        crucible::Decision::Preemption(_) => "preemption",
        crucible::Decision::AppRandom(_) => "app_random",
        crucible::Decision::ControlFault(_) => "control_fault",
    }
}

pub(super) fn run_remote_workflow(
    daemon: &str,
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    run_plan: &RunInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let client = RpcControlClient::new(RpcEndpoint::http2(daemon_rpc_endpoint(daemon)))
        .map_err(control_client_error)?;
    let report = if matches!(run_plan.execution_mode, RunExecutionMode::Interactive) {
        runtime.block_on(run_control_client_workflow_stdin_async(&client, run_plan))?
    } else {
        runtime.block_on(run_control_client_workflow_async(&client, run_plan, &[]))?
    };
    finish_run_workflow_outcome(thin_plan, backend_plan, ergonomics_plan, run_plan, report)
}

pub(super) fn run_remote_verify_workflow(
    daemon: &str,
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    verify_plan: &VerifyInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let report = match &verify_plan.mode {
        VerifyMode::RunScenario { .. } => {
            let client = RpcControlClient::new(RpcEndpoint::http2(daemon_rpc_endpoint(daemon)))
                .map_err(control_client_error)?;
            runtime.block_on(run_control_client_verify_workflow_async(
                &client,
                verify_plan,
                backend_plan.resolved_backend.as_ref(),
                ergonomics_plan,
            ))?
        }
        VerifyMode::CompareArtifacts { .. } => {
            verify_compare_artifacts(verify_plan, backend_plan.resolved_backend.as_ref())?
        }
    };
    finish_verify_workflow_outcome(
        thin_plan,
        backend_plan,
        ergonomics_plan,
        verify_plan,
        report,
    )
}

pub(super) fn run_remote_save_workflow(
    daemon: &str,
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    save_plan: &SaveInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let client = RpcControlClient::new(RpcEndpoint::http2(daemon_rpc_endpoint(daemon)))
        .map_err(control_client_error)?;
    let report = runtime.block_on(run_remote_control_client_save_workflow_async(
        &client, save_plan,
    ))?;
    finish_save_workflow_outcome(thin_plan, backend_plan, ergonomics_plan, save_plan, report)
}

pub(super) fn run_remote_resume_workflow(
    daemon: &str,
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    resume_plan: &ResumeInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let client = RpcControlClient::new(RpcEndpoint::http2(daemon_rpc_endpoint(daemon)))
        .map_err(control_client_error)?;
    let report = runtime.block_on(run_remote_control_client_resume_workflow_async(
        &client,
        resume_plan,
    ))?;
    finish_resume_workflow_outcome(
        thin_plan,
        backend_plan,
        ergonomics_plan,
        resume_plan,
        report,
    )
}

#[cfg(test)]
pub(super) fn run_remote_resume_workflow_with_interactive_commands(
    daemon: &str,
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    resume_plan: &ResumeInvocationPlan,
    commands: &[SessionCommandKind],
) -> Result<BackendCommandOutcome, CliError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let client = RpcControlClient::new(RpcEndpoint::http2(daemon_rpc_endpoint(daemon)))
        .map_err(control_client_error)?;
    let report = runtime.block_on(run_remote_control_client_resume_workflow_with_driver_async(
        &client,
        resume_plan,
        ResumeInteractiveCommandDriver::Preparsed(commands),
    ))?;
    finish_resume_workflow_outcome(
        thin_plan,
        backend_plan,
        ergonomics_plan,
        resume_plan,
        report,
    )
}

pub(super) fn daemon_rpc_endpoint(daemon: &str) -> String {
    if daemon.contains("://") {
        daemon.to_string()
    } else {
        format!("http://{daemon}")
    }
}

pub(super) fn finish_run_workflow_outcome(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    run_plan: &RunInvocationPlan,
    report: RunWorkflowReport,
) -> Result<BackendCommandOutcome, CliError> {
    let mut outcome = backend_command_outcome(thin_plan, backend_plan, ergonomics_plan);
    outcome.status = report.status;
    outcome.exit_code = report.status.exit_code();
    outcome.stdout.push(format!(
        "run-session\tcreated={}\tfinal={}\toutcome={}\tsavepoint={}\tfrontier_ticks={}\tquanta={}\tevents={}\tacks={}",
        report.created_state,
        report.final_state,
        terminal_outcome_label(report.outcome),
        report
            .terminal_savepoint
            .map(format_content_hash_ref)
            .unwrap_or_else(|| String::from("none")),
        report.final_frontier_ticks,
        report.final_quanta,
        report.streamed_events.len(),
        report.acknowledged_commands.len()
    ));
    for status in &report.watch_statuses {
        outcome.stdout.push(format!("run-watch\t{status}"));
    }
    append_local_double_run_entries(&mut outcome, run_plan, &report);
    if let Some(savepoint) = run_terminal_savepoint_for_policy(run_plan, &report)? {
        outcome.terminal_savepoint = Some(savepoint);
        let savepoint = format_content_hash_ref(savepoint);
        outcome.stdout.push(format!(
            "run-savepoint\tpolicy={}\tcheckpoint={}\tfinal={}\toutcome={}",
            run_save_policy_label(run_plan.save_policy),
            savepoint,
            report.final_state,
            terminal_outcome_label(report.outcome)
        ));
        outcome.canonical_log.push(CanonicalLogEntry {
            sequence: outcome.canonical_log.len() as u64,
            virtual_time_ticks: outcome.canonical_log.len() as u64,
            node: String::from("session"),
            kind: String::from("run_savepoint"),
            summary: format!(
                "policy={} checkpoint={} outcome={}",
                run_save_policy_label(run_plan.save_policy),
                savepoint,
                terminal_outcome_label(report.outcome)
            ),
        });
        outcome.canonical_log_digest = canonical_log_digest(&outcome.canonical_log);
    }
    if outcome.status.is_non_passing() && backend_plan.target == BackendExecutionTarget::Local {
        let artifact_seed = ergonomics_plan
            .map(|plan| plan.seed.value)
            .unwrap_or_else(|| {
                seed_to_u64(
                    run_plan
                        .request_seed
                        .unwrap_or_else(|| run_plan.scenario.scenario_def().seed()),
                )
            });
        let artifact = run_failure_reproduction_artifact_bytes(
            artifact_seed,
            backend_plan.resolved_backend.as_ref(),
            run_plan.scenario.scenario_form(),
            &outcome.canonical_log,
            &run_fingerprint_samples(&report),
        )?;
        outcome.artifact_digest = content_address_bytes(&artifact);
        outcome.reproduction_artifact = Some(artifact);
    }
    Ok(outcome)
}

pub(super) fn finish_save_workflow_outcome(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    save_plan: &SaveInvocationPlan,
    report: SaveWorkflowReport,
) -> Result<BackendCommandOutcome, CliError> {
    let oracle = report.oracle;
    let mut outcome = finish_run_workflow_outcome(
        thin_plan,
        backend_plan,
        ergonomics_plan,
        &save_plan.run_plan,
        report.run,
    )?;
    outcome.terminal_savepoint = Some(oracle.fat_checkpoint);
    outcome.stdout.push(format!(
        "save-oracle\tstatus={}\tconfiguration={}\tfat={}\tthin={}\tstore_objects={}",
        oracle.status_label(),
        format_content_hash_ref(oracle.configuration),
        format_content_hash_ref(oracle.fat_checkpoint),
        format_content_hash_ref(oracle.thin_checkpoint),
        oracle.store_objects
    ));
    outcome.canonical_log.push(CanonicalLogEntry {
        sequence: outcome.canonical_log.len() as u64,
        virtual_time_ticks: outcome.canonical_log.len() as u64,
        node: String::from("replay-oracle"),
        kind: String::from("save_oracle_validation"),
        summary: format!(
            "status={} configuration={} fat={} thin={}",
            oracle.status_label(),
            format_content_hash_ref(oracle.configuration),
            format_content_hash_ref(oracle.fat_checkpoint),
            format_content_hash_ref(oracle.thin_checkpoint)
        ),
    });
    outcome.canonical_log_digest = canonical_log_digest(&outcome.canonical_log);
    outcome.savepoint_oracle = Some(oracle);
    Ok(outcome)
}

pub(super) fn finish_verify_workflow_outcome(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    verify_plan: &VerifyInvocationPlan,
    report: VerifyWorkflowReport,
) -> Result<BackendCommandOutcome, CliError> {
    let mut outcome = backend_command_outcome(thin_plan, backend_plan, ergonomics_plan);
    outcome.stdout.push(format!(
        "verify-plan\tmode={}\truns={}\treductions={}\tadversarial={}\tbisect={}",
        verify_plan.mode.label(),
        verify_plan.requested_runs,
        report.witnesses.len(),
        verify_plan.applies_hostile_condition_matrix,
        verify_plan.bisection_on_divergence
    ));
    for witness in &report.witnesses {
        let canonical_log_digest = content_address_bytes(&witness.canonical_log_bytes);
        let fingerprint_digest = content_address_bytes(&witness.fingerprint_stream);
        outcome.stdout.push(format!(
            "verify-run\tindex={}\trun={}\tprofile={}\tcanonical_log={}\tfingerprint={}\tsamples={}",
            witness.reduction.index,
            witness.reduction.run_index,
            witness.reduction.host_profile.label(),
            canonical_log_digest,
            fingerprint_digest,
            witness.fingerprint_samples.len()
        ));
        outcome.canonical_log.push(CanonicalLogEntry {
            sequence: outcome.canonical_log.len() as u64,
            virtual_time_ticks: outcome.canonical_log.len() as u64,
            node: String::from("verify"),
            kind: String::from("independent_reduction"),
            summary: format!(
                "index={} run={} profile={} canonical_log={} fingerprint={} samples={}",
                witness.reduction.index,
                witness.reduction.run_index,
                witness.reduction.host_profile.label(),
                canonical_log_digest,
                fingerprint_digest,
                witness.fingerprint_samples.len()
            ),
        });
    }
    if let Some(divergence) = report.divergence {
        outcome.status = BackendCommandStatus::Failed;
        outcome.exit_code = outcome.status.exit_code();
        outcome.stdout.push(format!(
            "verify-divergence\tleft={}\tright={}\tmismatch={}\tfirst_decision={}\tfirst_fingerprint_sample={}\tfirst_instruction={}\tnode={}\tbyte={}",
            divergence.left,
            divergence.right,
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
            divergence.first_different_byte
        ));
        if verify_plan.print_bisection_state_dump {
            outcome.stdout.push(format!(
                "verify-bisect-state\tleft_state={}\tright_state={}\tleft_dump={}\tright_dump={}",
                divergence.left_state_digest,
                divergence.right_state_digest,
                divergence.left_state_dump,
                divergence.right_state_dump
            ));
        }
        outcome.canonical_log.push(CanonicalLogEntry {
            sequence: outcome.canonical_log.len() as u64,
            virtual_time_ticks: outcome.canonical_log.len() as u64,
            node: divergence
                .node
                .clone()
                .unwrap_or_else(|| String::from("verify")),
            kind: String::from("verify_divergence_bisection"),
            summary: format!(
                "left={} right={} mismatch={} first_instruction={} byte={}",
                divergence.left,
                divergence.right,
                divergence.mismatch.label(),
                divergence.first_different_instruction,
                divergence.first_different_byte
            ),
        });
        let left = report
            .witnesses
            .get(divergence.left)
            .ok_or_else(|| backend_error("verify divergence left side is out of range"))?;
        let right = report
            .witnesses
            .get(divergence.right)
            .ok_or_else(|| backend_error("verify divergence right side is out of range"))?;
        if let (Some(left_artifact), Some(right_artifact)) =
            (left.artifact.as_ref(), right.artifact.as_ref())
        {
            outcome.side_reproduction_artifacts = vec![
                (String::from("left"), left_artifact.clone()),
                (String::from("right"), right_artifact.clone()),
            ];
            let mut artifact_material = Vec::new();
            artifact_material.extend_from_slice(left_artifact);
            artifact_material.extend_from_slice(right_artifact);
            outcome.artifact_digest = content_address_bytes(&artifact_material);
        } else {
            outcome.stdout.push(String::from(
                "verify-reproduction-artifacts\tskipped=producer-provenance-unavailable",
            ));
        }
    } else {
        outcome.stdout.push(format!(
            "verify-result\tstatus=passed\treductions={}\tcanonical_log={}\tfingerprint={}",
            report.witnesses.len(),
            report
                .witnesses
                .first()
                .map(|witness| content_address_bytes(&witness.canonical_log_bytes))
                .unwrap_or_else(|| content_address_bytes(b"verify-empty-log")),
            report
                .witnesses
                .first()
                .map(|witness| content_address_bytes(&witness.fingerprint_stream))
                .unwrap_or_else(|| content_address_bytes(b"verify-empty-fingerprint"))
        ));
    }
    outcome.canonical_log_digest = canonical_log_digest(&outcome.canonical_log);
    Ok(outcome)
}
