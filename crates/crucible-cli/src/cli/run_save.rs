//! Local run/save workflows and remote resume control setup.

use super::*;
use crucible_api as production_api;

// Live QEMU quanta can spend most of the backend completion window outside the
// actor. Polling by yield count races the VM and can report a false timeout.
pub(super) const RESUME_WORKFLOW_OBSERVER_TIMEOUT: Duration = Duration::from_secs(300);

#[path = "run_save/qemu_live.rs"]
mod qemu_live;
pub(super) use qemu_live::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RunWorkflowReport {
    pub(super) status: BackendCommandStatus,
    pub(super) created_state: String,
    pub(super) final_state: String,
    pub(super) outcome: Option<OutcomeKind>,
    pub(super) terminal_savepoint: Option<crucible::ContentHash>,
    pub(super) terminal_configuration: Option<crucible::Configuration>,
    pub(super) final_frontier_ticks: u64,
    pub(super) final_quanta: u64,
    pub(super) budget_timed_out: bool,
    pub(super) state_updates: Vec<String>,
    pub(super) streamed_events: Vec<String>,
    pub(super) streamed_event_frames: Vec<Vec<u8>>,
    pub(super) coverage_feedback: crucible::EventLogCoverageFeedback,
    pub(super) execution_fingerprints: Vec<crucible::FingerprintSample>,
    pub(super) acknowledged_commands: Vec<SessionCommandKind>,
    pub(super) watch_statuses: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SaveWorkflowReport {
    pub(super) run: RunWorkflowReport,
    pub(super) oracle: SavepointOracleProof,
    pub(super) boundary_evidence: SaveBoundaryEvidence,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SaveBoundaryEvidence {
    pub(crate) at: SaveAtArg,
    pub(crate) selector: Option<SaveAtSelector>,
    pub(crate) frontier_ticks: u64,
    pub(crate) quanta: u64,
    pub(crate) breakpoint_firing: Option<crucible_session::BreakpointFiring>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct SaveWorkflowFailureTrace {
    pub(crate) selector: SaveAtSelector,
    pub(crate) frontier_ticks: u64,
    pub(crate) quanta: u64,
    pub(crate) state_updates: Vec<String>,
    pub(crate) acknowledged_commands: Vec<SessionCommandKind>,
}

impl SaveWorkflowFailureTrace {
    pub(crate) fn canonical_summary(&self, error: &CliError) -> String {
        let (at, kind, name) = match &self.selector {
            SaveAtSelector::PropertyViolation { assertion } => {
                ("property", "property-violation", assertion.as_str())
            }
            SaveAtSelector::Marker { name } => ("marker", "guest-marker", name.as_str()),
        };
        format!(
            "at={at} selector={kind}:{} frontier={} quanta={} error={:?}",
            encode_canonical_summary_value(name),
            self.frontier_ticks,
            self.quanta,
            error.to_string()
        )
    }
}

impl SaveBoundaryEvidence {
    pub(crate) fn selector_kind(&self) -> &'static str {
        match &self.selector {
            Some(SaveAtSelector::PropertyViolation { .. }) => "property-violation",
            Some(SaveAtSelector::Marker { .. }) => "guest-marker",
            None => "none",
        }
    }

    pub(crate) fn selector_name(&self) -> Option<&str> {
        match &self.selector {
            Some(SaveAtSelector::PropertyViolation { assertion }) => Some(assertion),
            Some(SaveAtSelector::Marker { name }) => Some(name),
            None => None,
        }
    }

    pub(crate) fn canonical_summary(&self) -> String {
        let selector = self
            .selector_name()
            .map(|name| {
                format!(
                    "{}:{}",
                    self.selector_kind(),
                    encode_canonical_summary_value(name)
                )
            })
            .unwrap_or_else(|| String::from("none"));
        let proof = self
            .breakpoint_firing
            .as_ref()
            .map(|firing| {
                format!(
                    "breakpoint={} disposition=suspend firing_frontier={} firing_quanta={}",
                    firing.id, firing.frontier.ticks, firing.quanta
                )
            })
            .unwrap_or_else(|| String::from("breakpoint=none"));
        format!(
            "at={} selector={} frontier={} quanta={} {}",
            self.at.label(),
            selector,
            self.frontier_ticks,
            self.quanta,
            proof
        )
    }
}

pub(super) fn encode_canonical_summary_value(value: &str) -> String {
    const HEX: &[u8; 16] = b"0123456789ABCDEF";
    let mut encoded = String::new();
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            encoded.push(char::from(byte));
        } else {
            encoded.push('%');
            encoded.push(char::from(HEX[usize::from(byte >> 4)]));
            encoded.push(char::from(HEX[usize::from(byte & 0x0f)]));
        }
    }
    encoded
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ResumeWorkflowReport {
    pub(super) run: RunWorkflowReport,
    pub(super) source_checkpoint: crucible::ContentHash,
    pub(super) resumed_configuration: crucible::ContentHash,
    pub(super) terminal_configuration: CliModelConfiguration,
    pub(super) scenario_label: String,
    pub(super) terminal_oracle: SavepointOracleProof,
}

pub(super) type CliModelConfiguration = crucible::Configuration;
#[cfg(any(test, feature = "test-double"))]
pub(super) type CliModelScenarioDef = crucible::ScenarioDef;
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ForkWorkflowReport {
    pub(super) run: RunWorkflowReport,
    pub(super) source_checkpoint: crucible::ContentHash,
    pub(super) branch_checkpoint: crucible::ContentHash,
    pub(super) branch_configuration: crucible::ContentHash,
    pub(super) terminal_configuration: crucible::Configuration,
    pub(super) scenario_form: crucible::ScenarioDefForm,
    pub(super) scenario_label: String,
    pub(super) label: String,
    pub(super) terminal_oracle: SavepointOracleProof,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ForkReproductionArtifactReport {
    pub(super) path: PathBuf,
    pub(super) digest: String,
    pub(super) seed: u64,
    pub(super) fork_seed: Option<u64>,
    pub(super) model_artifact: crucible::ContentHash,
    pub(super) replay_state: crucible::ContentHash,
    pub(super) schedule: crucible::ContentHash,
    pub(super) finding_fingerprint: crucible::ContentHash,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ResumeHandleEvidence {
    pub(super) scenario_form: crucible::ScenarioDefForm,
    pub(super) scenario: crucible::ScenarioDef,
    pub(super) schedule: Schedule,
    pub(super) configuration: crucible::Configuration,
    pub(super) checkpoint: Checkpoint,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct VerifyWorkflowReport {
    pub(super) witnesses: Vec<VerifyRunWitness>,
    pub(super) divergence: Option<VerifyDivergenceReport>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct VerifyRunWitness {
    pub(super) reduction: VerifyReductionPlan,
    pub(super) canonical_log: Vec<CanonicalLogEntry>,
    pub(super) canonical_log_bytes: Vec<u8>,
    pub(super) fingerprint_samples: Vec<VerifyFingerprintSample>,
    pub(super) fingerprint_stream: Vec<u8>,
    pub(super) state_dump: String,
    pub(super) artifact: Option<Vec<u8>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct VerifyFingerprintSample {
    pub(super) index: u64,
    pub(super) instruction: u64,
    pub(super) node: String,
    pub(super) digest: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct VerifyDivergenceReport {
    pub(super) left: usize,
    pub(super) right: usize,
    pub(super) mismatch: VerifyMismatchKind,
    pub(super) first_different_decision: Option<usize>,
    pub(super) first_different_fingerprint_sample: Option<usize>,
    pub(super) first_different_virtual_time: Option<u64>,
    pub(super) first_different_virtual_time_node: Option<String>,
    pub(super) first_different_instruction: Option<u64>,
    pub(super) first_different_instruction_node: Option<String>,
    pub(super) first_different_byte: usize,
    pub(super) left_state_digest: String,
    pub(super) right_state_digest: String,
    pub(super) left_state_dump: String,
    pub(super) right_state_dump: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum VerifyMismatchKind {
    CanonicalLog,
    FingerprintStream,
    CanonicalLogAndFingerprintStream,
}

impl VerifyMismatchKind {
    pub(super) fn label(self) -> &'static str {
        match self {
            Self::CanonicalLog => "canonical-log",
            Self::FingerprintStream => "fingerprint-stream",
            Self::CanonicalLogAndFingerprintStream => "canonical-log+fingerprint-stream",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct RunObservation {
    pub(super) final_state: String,
    pub(super) outcome: Option<OutcomeKind>,
    pub(super) terminal_savepoint: Option<crucible::ContentHash>,
    pub(super) terminal_configuration: crucible::Configuration,
    pub(super) frontier_ticks: u64,
    pub(super) quanta: u64,
    pub(super) budget_timed_out: bool,
    pub(super) watch_statuses: Vec<String>,
}

#[cfg(any(test, feature = "test-double"))]
#[path = "run_save/test_double.rs"]
mod test_double;
#[cfg(any(test, feature = "test-double"))]
pub(super) use test_double::*;

pub(super) fn run_local_qemu_save_workflow(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    save_plan: &SaveInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let backend = backend_plan
        .resolved_backend
        .as_ref()
        .ok_or_else(|| backend_error("local QEMU save requires a resolved backend"))?;
    let config = production_qemu_lifecycle_config(backend)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let control_plane =
        production_qemu_control_plane(config, save_plan.run_plan.scenario.scenario_form());
    let client = InProcessLifecycleClient::new(control_plane);
    let report = runtime.block_on(run_control_client_save_workflow_async(&client, save_plan))?;
    let mut outcome =
        finish_save_workflow_outcome(thin_plan, backend_plan, ergonomics_plan, save_plan, report)?;
    append_qemu_control_plane_execution_proof(&mut outcome, backend, "save-live-checkpoint");
    Ok(outcome)
}

#[cfg(any(test, feature = "test-double"))]
pub(super) fn run_local_save_recording_workflow(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    save_plan: &SaveInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let scenario_form = save_plan.run_plan.scenario.scenario_form();
    let sources = SaveRecordingSources::from_scenario_form(scenario_form);
    let white_box_policies = scenario_form
        .world()
        .vm_nodes()
        .iter()
        .map(|node| (node.id.clone(), node.white_box))
        .collect::<BTreeMap<_, _>>();
    let control_plane = LifecycleControlPlane::new("crucible-cli-save", Vec::new(), {
        move |_scenario: &CliModelScenarioDef, _seed| {
            SaveRecordingLifecycleLoop::new(sources.clone())
        }
    })
    .with_white_box_policy_provider(move |_scenario| white_box_policies.clone());
    let client = InProcessLifecycleClient::new(control_plane);
    let report = runtime.block_on(run_control_client_save_workflow_async(&client, save_plan))?;
    finish_save_workflow_outcome(thin_plan, backend_plan, ergonomics_plan, save_plan, report)
}

#[cfg(any(test, feature = "test-double"))]
pub(super) fn run_local_double_resume_workflow(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    resume_plan: &ResumeInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let interactive_driver = if matches!(resume_plan.execution_mode, RunExecutionMode::Interactive)
    {
        ResumeInteractiveCommandDriver::Stdin
    } else {
        ResumeInteractiveCommandDriver::Preparsed(&[])
    };
    let (_evidence, report) =
        run_local_resume_workflow_report_with_driver(resume_plan, interactive_driver)?;
    finish_resume_workflow_outcome(
        thin_plan,
        backend_plan,
        ergonomics_plan,
        resume_plan,
        report,
    )
}

pub(super) fn run_local_qemu_resume_workflow(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    resume_plan: &ResumeInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let backend = backend_plan
        .resolved_backend
        .as_ref()
        .ok_or_else(|| backend_error("local QEMU resume requires a resolved backend"))?;
    let evidence = resume_handle_evidence(resume_plan)?;
    let config = production_qemu_lifecycle_config(backend)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let control_plane = production_qemu_control_plane(config, &evidence.scenario_form);
    let client = InProcessLifecycleClient::new(control_plane);
    let report = runtime.block_on(run_remote_control_client_resume_workflow_async(
        &client,
        resume_plan,
    ))?;
    let mut outcome = finish_resume_workflow_outcome(
        thin_plan,
        backend_plan,
        ergonomics_plan,
        resume_plan,
        report,
    )?;
    append_qemu_control_plane_execution_proof(&mut outcome, backend, "resume-thin-replay");
    Ok(outcome)
}

#[cfg(any(test, feature = "test-double"))]
pub(super) fn run_local_resume_workflow_report_with_driver(
    resume_plan: &ResumeInvocationPlan,
    interactive_driver: ResumeInteractiveCommandDriver<'_>,
) -> Result<(ResumeHandleEvidence, ResumeWorkflowReport), CliError> {
    let evidence = resume_handle_evidence(resume_plan)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let report = runtime.block_on(run_resumed_savepoint_actor_with_driver_async(
        resume_plan,
        evidence.clone(),
        interactive_driver,
    ))?;
    Ok((evidence, report))
}

#[cfg(test)]
pub(super) fn run_local_double_resume_workflow_with_driver(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    resume_plan: &ResumeInvocationPlan,
    interactive_driver: ResumeInteractiveCommandDriver<'_>,
) -> Result<BackendCommandOutcome, CliError> {
    let (_evidence, report) =
        run_local_resume_workflow_report_with_driver(resume_plan, interactive_driver)?;
    finish_resume_workflow_outcome(
        thin_plan,
        backend_plan,
        ergonomics_plan,
        resume_plan,
        report,
    )
}

#[cfg(test)]
pub(super) fn run_local_double_resume_workflow_with_interactive_commands(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    resume_plan: &ResumeInvocationPlan,
    commands: &[SessionCommandKind],
) -> Result<BackendCommandOutcome, CliError> {
    run_local_double_resume_workflow_with_driver(
        thin_plan,
        backend_plan,
        ergonomics_plan,
        resume_plan,
        ResumeInteractiveCommandDriver::Preparsed(commands),
    )
}

pub(super) async fn run_remote_control_client_resume_workflow_async<C>(
    client: &C,
    resume_plan: &ResumeInvocationPlan,
) -> Result<ResumeWorkflowReport, CliError>
where
    C: ControlClient + Sync,
{
    let interactive_driver = if matches!(resume_plan.execution_mode, RunExecutionMode::Interactive)
    {
        ResumeInteractiveCommandDriver::Stdin
    } else {
        ResumeInteractiveCommandDriver::Preparsed(&[])
    };
    run_remote_control_client_resume_workflow_with_driver_async(
        client,
        resume_plan,
        interactive_driver,
    )
    .await
}

pub(super) async fn run_remote_control_client_resume_workflow_with_driver_async<C>(
    client: &C,
    resume_plan: &ResumeInvocationPlan,
    interactive_driver: ResumeInteractiveCommandDriver<'_>,
) -> Result<ResumeWorkflowReport, CliError>
where
    C: ControlClient + Sync,
{
    let evidence = resume_handle_evidence(resume_plan)?;
    run_remote_control_client_resume_from_evidence_with_driver_async(
        client,
        resume_plan,
        evidence,
        interactive_driver,
        false,
    )
    .await
}

/// Resumes through a control client from already validated checkpoint evidence.
///
/// # Errors
///
/// Returns [`CliError`] when the remote lifecycle rejects the checkpoint or a
/// command, or when the observed terminal evidence violates the resume oracle.
pub(super) async fn run_remote_control_client_resume_from_evidence_with_driver_async<C>(
    client: &C,
    resume_plan: &ResumeInvocationPlan,
    evidence: ResumeHandleEvidence,
    interactive_driver: ResumeInteractiveCommandDriver<'_>,
    reject_pending_branch_choices: bool,
) -> Result<ResumeWorkflowReport, CliError>
where
    C: ControlClient + Sync,
{
    let request = ResumeSessionRequest::new(
        evidence.scenario_form.clone(),
        evidence.schedule.clone(),
        evidence.checkpoint.clone(),
        evidence.scenario.seed(),
    );
    let resumed = client
        .resume_session(request)
        .await
        .map_err(control_client_error)?;
    if resumed.checkpoint != evidence.checkpoint.id {
        return Err(CliError::Identity(format!(
            "remote resume source checkpoint {} did not match handle checkpoint {}",
            format_content_hash_ref(resumed.checkpoint),
            format_content_hash_ref(evidence.checkpoint.id)
        )));
    }
    if resumed.configuration != evidence.configuration.id() {
        return Err(CliError::Identity(format!(
            "remote resume configuration {} did not match handle configuration {}",
            format_content_hash_ref(resumed.configuration),
            format_content_hash_ref(evidence.configuration.id())
        )));
    }

    let mut acknowledged_commands = Vec::new();
    let mut state_updates = vec![format!("{:?}", resumed.state).to_ascii_lowercase()];
    let mut watch_statuses = Vec::new();
    let mut command_id = 1;
    let mut property_violation_reached = false;
    let mut property_suspension = None;
    let mut expected_virtual_boundary = None;

    let boundary = if matches!(resume_plan.execution_mode, RunExecutionMode::Interactive) {
        drive_remote_resume_interactive_commands(
            client,
            resumed.session,
            interactive_driver,
            &mut command_id,
            &mut acknowledged_commands,
            &mut state_updates,
            &mut watch_statuses,
            resume_plan.watch_streams_live_status,
        )
        .await?;
        let boundary = current_remote_resume_summary(client, resumed.session).await?;
        state_updates.push(format!("{:?}", boundary.state).to_ascii_lowercase());
        if resume_plan.watch_streams_live_status {
            watch_statuses.push(run_watch_status(&boundary));
        }
        boundary
    } else {
        let boundary = match resume_plan.terminal_condition {
            RunTerminalCondition::Quiescence => {
                send_resume_workflow_command(
                    client,
                    resumed.session,
                    &mut command_id,
                    SessionCommand::SetBreakpoint {
                        spec: BreakpointSpec::suspend_once(crucible::Predicate::quiescent()),
                        reply: CommandReply::discard(),
                    },
                    &mut acknowledged_commands,
                    &mut state_updates,
                )
                .await?;
                wait_for_resume_workflow_state(client, resumed.session, LiveStateKind::Paused)
                    .await?;
                send_resume_workflow_command(
                    client,
                    resumed.session,
                    &mut command_id,
                    SessionCommand::Continue,
                    &mut acknowledged_commands,
                    &mut state_updates,
                )
                .await?;
                wait_for_resume_workflow_summary(
                    client,
                    resumed.session,
                    |candidate| {
                        matches!(
                            candidate.state,
                            LiveStateKind::Paused | LiveStateKind::Stopped
                        )
                    },
                    "quiescent remote resume boundary",
                    RESUME_WORKFLOW_OBSERVER_TIMEOUT,
                )
                .await?
            }
            RunTerminalCondition::VirtualTime => {
                let budget = resume_plan.max_virtual_time_ticks.ok_or_else(|| {
                    usage_error("resume --until virtual-time requires --max-virtual-time")
                })?;
                expected_virtual_boundary = Some(budget);
                let summary =
                    wait_for_resume_workflow_state(client, resumed.session, LiveStateKind::Paused)
                        .await?;
                if summary.frontier.ticks < budget {
                    send_resume_workflow_command(
                        client,
                        resumed.session,
                        &mut command_id,
                        SessionCommand::step(StepMode::Duration(SimDuration {
                            nanos: budget.saturating_sub(summary.frontier.ticks),
                        })),
                        &mut acknowledged_commands,
                        &mut state_updates,
                    )
                    .await?;
                    wait_for_resume_workflow_summary(
                        client,
                        resumed.session,
                        |candidate| {
                            matches!(
                                candidate.state,
                                LiveStateKind::Paused | LiveStateKind::Stopped
                            ) && (candidate.frontier.ticks >= budget
                                || candidate.state == LiveStateKind::Stopped)
                                && candidate.quanta_stepped > summary.quanta_stepped
                        },
                        "requested remote virtual-time resume boundary",
                        RESUME_WORKFLOW_OBSERVER_TIMEOUT,
                    )
                    .await?
                } else {
                    summary
                }
            }
            RunTerminalCondition::Stopped => {
                wait_for_resume_workflow_state(client, resumed.session, LiveStateKind::Paused)
                    .await?
            }
            RunTerminalCondition::Property => {
                let predicate = resume_property_violation_predicate(&evidence.scenario_form)?;
                let response = send_resume_workflow_command(
                    client,
                    resumed.session,
                    &mut command_id,
                    SessionCommand::SetBreakpoint {
                        spec: BreakpointSpec::suspend_once(predicate.clone()),
                        reply: CommandReply::discard(),
                    },
                    &mut acknowledged_commands,
                    &mut state_updates,
                )
                .await?;
                let breakpoint_id = response.breakpoint_id.ok_or_else(|| {
                    backend_error(
                        "remote resume property breakpoint command returned no breakpoint id",
                    )
                })?;
                wait_for_resume_workflow_state(client, resumed.session, LiveStateKind::Paused)
                    .await?;
                send_resume_workflow_command(
                    client,
                    resumed.session,
                    &mut command_id,
                    SessionCommand::Continue,
                    &mut acknowledged_commands,
                    &mut state_updates,
                )
                .await?;
                let boundary = wait_for_resume_workflow_summary(
                    client,
                    resumed.session,
                    |candidate| {
                        matches!(
                            candidate.state,
                            LiveStateKind::Paused | LiveStateKind::Stopped
                        )
                    },
                    "property remote resume boundary",
                    RESUME_WORKFLOW_OBSERVER_TIMEOUT,
                )
                .await?;
                property_suspension = Some((breakpoint_id, predicate));
                boundary
            }
        };
        if resume_plan.watch_streams_live_status {
            watch_statuses.push(run_watch_status(&boundary));
        }
        boundary
    };

    if reject_pending_branch_choices {
        let response = send_resume_workflow_command(
            client,
            resumed.session,
            &mut command_id,
            SessionCommand::Query {
                kind: QueryKind::SearchFrontier,
                reply: CommandReply::discard(),
            },
            &mut acknowledged_commands,
            &mut state_updates,
        )
        .await?;
        let pending = match response.query_result {
            Some(QueryResult::SearchFrontier {
                pending_branch_choices,
                ..
            }) => pending_branch_choices,
            Some(other) => {
                return Err(backend_error(format!(
                    "fork override validation returned unexpected query payload: {other:?}"
                )));
            }
            None => {
                return Err(backend_error(
                    "fork override validation returned no search-frontier payload",
                ));
            }
        };
        if pending != 0 {
            destroy_remote_resume_session_best_effort(client, resumed.session).await;
            return Err(artifact_error(format!(
                "fork stopped with {pending} unconsumed override choice(s); the recorded scheduling point was not reached"
            )));
        }
    }

    if let Some(expected) = expected_virtual_boundary
        && boundary.frontier.ticks != expected
    {
        return Err(CliError::Identity(format!(
            "resume remote virtual-time boundary reached {}, expected {expected}",
            boundary.frontier.ticks
        )));
    }

    if let Some((breakpoint_id, predicate)) = property_suspension {
        let firings_response = send_resume_workflow_command(
            client,
            resumed.session,
            &mut command_id,
            SessionCommand::query_breakpoint_firings(),
            &mut acknowledged_commands,
            &mut state_updates,
        )
        .await?;
        let firings = match firings_response.query_result {
            Some(QueryResult::BreakpointFirings(firings)) => firings,
            Some(other) => {
                return Err(backend_error(format!(
                    "remote resume property proof query returned unexpected payload: {other:?}"
                )));
            }
            None => {
                return Err(backend_error(
                    "remote resume property proof query returned no breakpoint firing payload",
                ));
            }
        };
        validate_resume_property_suspension_summary(
            breakpoint_id,
            &predicate,
            &boundary,
            &firings,
        )?;
        property_violation_reached = true;
    }

    let snapshot_response = send_resume_workflow_command(
        client,
        resumed.session,
        &mut command_id,
        SessionCommand::query_snapshot(),
        &mut acknowledged_commands,
        &mut state_updates,
    )
    .await?;
    let mut snapshot = match snapshot_response.query_result {
        Some(QueryResult::Snapshot(snapshot)) => *snapshot,
        Some(other) => {
            return Err(backend_error(format!(
                "remote resume boundary snapshot returned unexpected query payload: {other:?}"
            )));
        }
        None => {
            return Err(backend_error(
                "remote resume boundary snapshot returned no query payload",
            ));
        }
    };
    if !matches!(
        snapshot.state,
        crucible_session::EngineState::Stopped { .. }
    ) {
        let savepoint_response = send_resume_workflow_command(
            client,
            resumed.session,
            &mut command_id,
            SessionCommand::CreateSavepoint {
                label: String::from("resume-terminal"),
                reply: CommandReply::discard(),
            },
            &mut acknowledged_commands,
            &mut state_updates,
        )
        .await?;
        let savepoint = savepoint_response.savepoint_info.ok_or_else(|| {
            backend_error("remote resume terminal savepoint command returned no savepoint payload")
        })?;
        if savepoint.configuration != snapshot.configuration.id() {
            return Err(CliError::Identity(format!(
                "remote resume terminal savepoint configuration {} did not match snapshot {}",
                format_content_hash_ref(savepoint.configuration),
                format_content_hash_ref(snapshot.configuration.id())
            )));
        }
        snapshot.terminal_savepoint = Some(savepoint.checkpoint);
    }
    let terminal_oracle = validate_resume_terminal_savepoint(&evidence, &snapshot)?;
    let observed_outcome = remote_resume_observed_outcome(&snapshot, property_violation_reached);
    let mut execution_fingerprints = Vec::new();
    let mut nodes = evidence
        .scenario_form
        .world()
        .vm_nodes()
        .iter()
        .map(|node| node.id.clone())
        .collect::<Vec<_>>();
    nodes.sort_by(|left, right| left.name.cmp(&right.name));
    for node in nodes {
        let response = send_resume_workflow_command(
            client,
            resumed.session,
            &mut command_id,
            SessionCommand::Query {
                kind: QueryKind::ExecutionFingerprint { node: node.clone() },
                reply: CommandReply::discard(),
            },
            &mut acknowledged_commands,
            &mut state_updates,
        )
        .await?;
        match response.query_result {
            Some(QueryResult::ExecutionFingerprint(sample)) => {
                execution_fingerprints.push(sample);
            }
            Some(other) => {
                return Err(backend_error(format!(
                    "remote resume fingerprint query for node `{}` returned unexpected payload: {other:?}",
                    node.name
                )));
            }
            None => {
                return Err(backend_error(format!(
                    "remote resume fingerprint query for node `{}` returned no payload",
                    node.name
                )));
            }
        }
    }
    let mut event_control = client
        .control_attach(
            AttachRequest::new(resumed.session)
                .with_expected_epoch(resumed.session.epoch)
                .with_client_name("crucible-cli-resume-artifact"),
        )
        .await
        .map_err(control_client_error)?;
    let mut streamed_events = Vec::new();
    let mut streamed_event_frames = Vec::new();
    let mut coverage_events = Vec::new();
    let mut event_cursor = 0;
    let terminal_event_log_len = u64::try_from(snapshot.event_log_len)
        .map_err(|_| backend_error("remote resume event-log length cannot be represented"))?;
    drain_terminal_event_log(
        &mut event_control,
        terminal_event_log_len,
        VERIFY_BASELINE_PROFILE.event_timeout_ms,
        &mut streamed_events,
        &mut streamed_event_frames,
        &mut coverage_events,
        &mut event_cursor,
    )
    .await?;
    if !matches!(
        snapshot.state,
        crucible_session::EngineState::Stopped { .. }
    ) {
        send_resume_workflow_command(
            client,
            resumed.session,
            &mut command_id,
            SessionCommand::Stop,
            &mut acknowledged_commands,
            &mut state_updates,
        )
        .await?;
    } else {
        destroy_remote_resume_session_best_effort(client, resumed.session).await;
    }
    let final_state = if matches!(resume_plan.execution_mode, RunExecutionMode::Interactive) {
        String::from("interactive")
    } else {
        match resume_plan.terminal_condition {
            RunTerminalCondition::Quiescence => String::from("quiescent"),
            RunTerminalCondition::VirtualTime => String::from("virtual-time"),
            RunTerminalCondition::Stopped => String::from("stopped"),
            RunTerminalCondition::Property => String::from("property-failed"),
        }
    };
    if resume_plan.watch_streams_live_status {
        watch_statuses.push(format!(
            "state=stopped\tfrontier_ticks={}\tquanta={}\toutcome={}\tsavepoint={}",
            snapshot.frontier.ticks,
            snapshot.quanta,
            terminal_outcome_label(observed_outcome),
            format_content_hash_ref(terminal_oracle.fat_checkpoint)
        ));
    }
    if state_updates.last() != Some(&final_state) {
        state_updates.push(final_state.clone());
    }

    Ok(ResumeWorkflowReport {
        run: RunWorkflowReport {
            status: status_from_outcome(observed_outcome)?,
            created_state: format!("{:?}", resumed.state).to_ascii_lowercase(),
            final_state,
            outcome: observed_outcome,
            terminal_savepoint: Some(terminal_oracle.fat_checkpoint),
            terminal_configuration: Some(snapshot.configuration.clone()),
            final_frontier_ticks: snapshot.frontier.ticks.max(boundary.frontier.ticks),
            final_quanta: snapshot.quanta.max(boundary.quanta_stepped),
            budget_timed_out: false,
            state_updates,
            streamed_events,
            streamed_event_frames,
            coverage_feedback: coverage_feedback_from_streamed_events(coverage_events)?,
            execution_fingerprints,
            acknowledged_commands,
            watch_statuses,
        },
        source_checkpoint: evidence.checkpoint.id,
        resumed_configuration: resumed.configuration,
        terminal_configuration: snapshot.configuration.clone(),
        scenario_label: resume_plan.savepoint.label(),
        terminal_oracle,
    })
}

pub(super) async fn destroy_remote_resume_session_best_effort<C>(client: &C, session: SessionRef)
where
    C: ControlClient + Sync,
{
    let _cleanup = client
        .destroy_session(DestroySessionRequest::new(session).with_expected_epoch(session.epoch))
        .await;
}

pub(super) fn remote_resume_observed_outcome(
    snapshot: &crucible_session::EngineSnapshot,
    property_violation_reached: bool,
) -> Option<OutcomeKind> {
    match &snapshot.state {
        crucible_session::EngineState::Stopped { outcome } => Some(OutcomeKind::from(outcome)),
        _ if property_violation_reached => Some(OutcomeKind::Failed),
        _ => Some(OutcomeKind::Passed),
    }
}

// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::too_many_arguments)]
pub(super) async fn drive_remote_resume_interactive_commands<C>(
    client: &C,
    session: SessionRef,
    interactive_driver: ResumeInteractiveCommandDriver<'_>,
    command_id: &mut u64,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
    state_updates: &mut Vec<String>,
    watch_statuses: &mut Vec<String>,
    watch_streams_live_status: bool,
) -> Result<(), CliError>
where
    C: ControlClient + Sync,
{
    match interactive_driver {
        ResumeInteractiveCommandDriver::Preparsed(commands) => {
            for command in commands {
                if *command == SessionCommandKind::Stop {
                    let boundary = current_remote_resume_summary(client, session).await?;
                    if watch_streams_live_status {
                        watch_statuses.push(run_watch_status(&boundary));
                    }
                    break;
                }
                let boundary = acknowledge_remote_resume_command_kind(
                    client,
                    session,
                    command_id,
                    *command,
                    acknowledged_commands,
                    state_updates,
                )
                .await?;
                if watch_streams_live_status {
                    watch_statuses.push(run_watch_status(&boundary));
                }
            }
            Ok(())
        }
        ResumeInteractiveCommandDriver::Stdin => {
            drive_remote_resume_interactive_stdin_commands(
                client,
                session,
                command_id,
                acknowledged_commands,
                state_updates,
                watch_statuses,
                watch_streams_live_status,
            )
            .await
        }
    }
}

pub(super) async fn drive_remote_resume_interactive_stdin_commands<C>(
    client: &C,
    session: SessionRef,
    command_id: &mut u64,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
    state_updates: &mut Vec<String>,
    watch_statuses: &mut Vec<String>,
    watch_streams_live_status: bool,
) -> Result<(), CliError>
where
    C: ControlClient + Sync,
{
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    drive_remote_resume_interactive_command_reader(
        client,
        session,
        command_id,
        acknowledged_commands,
        state_updates,
        watch_statuses,
        watch_streams_live_status,
        stdin.lock(),
        &mut stdout,
    )
    .await
}

// crucible-lint: allow rust-allow -- local exception is documented at the allow site.
#[allow(clippy::too_many_arguments)]
pub(super) async fn drive_remote_resume_interactive_command_reader<R, W, C>(
    client: &C,
    session: SessionRef,
    command_id: &mut u64,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
    state_updates: &mut Vec<String>,
    watch_statuses: &mut Vec<String>,
    watch_streams_live_status: bool,
    reader: R,
    writer: &mut W,
) -> Result<(), CliError>
where
    R: BufRead,
    W: Write,
    C: ControlClient + Sync,
{
    for line in reader.lines() {
        let line = line?;
        let Some(command) = parse_interactive_session_command_line(&line)? else {
            continue;
        };
        cli_stream_command(command)?;
        if command == SessionCommandKind::Stop {
            let boundary = current_remote_resume_summary(client, session).await?;
            if watch_streams_live_status {
                watch_statuses.push(run_watch_status(&boundary));
            }
            writeln!(
                writer,
                "interactive-ack\tcommand={}\tstatus=accepted",
                session_command_name(command)
            )?;
            writer.flush()?;
            break;
        }
        let boundary = acknowledge_remote_resume_command_kind(
            client,
            session,
            command_id,
            command,
            acknowledged_commands,
            state_updates,
        )
        .await?;
        if watch_streams_live_status {
            watch_statuses.push(run_watch_status(&boundary));
        }
        writeln!(
            writer,
            "interactive-ack\tcommand={}\tstatus=accepted",
            session_command_name(command)
        )?;
        if command == SessionCommandKind::Query {
            write_interactive_query_state(writer, boundary.state)?;
        }
        writer.flush()?;
    }
    Ok(())
}

pub(super) async fn acknowledge_remote_resume_command_kind<C>(
    client: &C,
    session: SessionRef,
    command_id: &mut u64,
    command: SessionCommandKind,
    acknowledged_commands: &mut Vec<SessionCommandKind>,
    state_updates: &mut Vec<String>,
) -> Result<crucible_api::SessionSummary, CliError>
where
    C: ControlClient + Sync,
{
    let before = current_remote_resume_summary(client, session).await?;
    let model_command = cli_stream_command(command)?;
    send_resume_workflow_command(
        client,
        session,
        command_id,
        model_command,
        acknowledged_commands,
        state_updates,
    )
    .await?;
    observe_remote_resume_interactive_boundary(client, session, command, &before).await
}

pub(super) async fn observe_remote_resume_interactive_boundary<C>(
    client: &C,
    session: SessionRef,
    command: SessionCommandKind,
    before: &crucible_api::SessionSummary,
) -> Result<crucible_api::SessionSummary, CliError>
where
    C: ControlClient + Sync,
{
    match command {
        SessionCommandKind::Continue
        | SessionCommandKind::StepQuantum
        | SessionCommandKind::StepEvent
        | SessionCommandKind::StepAssertion
        | SessionCommandKind::StepTimer
        | SessionCommandKind::StepDuration => {
            wait_for_resume_workflow_summary(
                client,
                session,
                |summary| {
                    summary.quanta_stepped > before.quanta_stepped
                        || summary.frontier.ticks > before.frontier.ticks
                        || summary.state == LiveStateKind::Stopped
                },
                "remote interactive resume command boundary",
                RESUME_WORKFLOW_OBSERVER_TIMEOUT,
            )
            .await
        }
        SessionCommandKind::Stop => {
            wait_for_resume_workflow_state(client, session, LiveStateKind::Stopped).await
        }
        _ => {
            tokio::task::yield_now().await;
            current_remote_resume_summary(client, session).await
        }
    }
}

pub(super) async fn current_remote_resume_summary<C>(
    client: &C,
    session: SessionRef,
) -> Result<crucible_api::SessionSummary, CliError>
where
    C: ControlClient + Sync,
{
    let sessions = client.list_sessions().await.map_err(control_client_error)?;
    sessions
        .sessions
        .iter()
        .find(|summary| summary.session == session)
        .cloned()
        .ok_or_else(|| backend_error("resume workflow session disappeared"))
}
