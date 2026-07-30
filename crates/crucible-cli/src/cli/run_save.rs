//! Local run/save workflows and remote resume control setup.

use super::*;
use crucible_api as production_api;

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
    pub(super) first_different_instruction: u64,
    pub(super) node: Option<String>,
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
    pub(super) frontier_ticks: u64,
    pub(super) quanta: u64,
    pub(super) budget_timed_out: bool,
    pub(super) watch_statuses: Vec<String>,
}

#[cfg(any(test, feature = "test-double"))]
pub(super) fn run_local_double_workflow(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    run_plan: &RunInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let report = if matches!(run_plan.execution_mode, RunExecutionMode::Interactive) {
        runtime.block_on(run_local_double_workflow_stdin_async(
            run_plan,
            ergonomics_plan,
        ))?
    } else {
        runtime.block_on(run_local_double_workflow_async(
            run_plan,
            ergonomics_plan,
            &[],
        ))?
    };
    finish_run_workflow_outcome(thin_plan, backend_plan, ergonomics_plan, run_plan, report)
}

#[cfg(any(test, feature = "test-double"))]
pub(super) fn run_local_double_save_workflow(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    save_plan: &SaveInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    run_local_save_recording_workflow(thin_plan, backend_plan, ergonomics_plan, save_plan)
}

#[derive(Clone, Debug)]
pub(super) struct SaveRecordingSources {
    pub(super) assertion_evaluator: crucible::HostAssertionEvaluator,
    pub(super) assertion_oracle: crucible::BlackBoxHostOracle,
    pub(super) emitted_assertions: BTreeSet<crucible::AssertionId>,
    pub(super) guest_markers: Vec<SaveGuestMarkerSource>,
    pub(super) emitted_guest_markers: Vec<SaveGuestMarkerSource>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SaveGuestMarkerSource {
    pub(super) node: crucible::NodeId,
    pub(super) marker: crucible::MarkerId,
}

impl SaveRecordingSources {
    pub(super) fn from_scenario_form(scenario_form: &crucible::ScenarioDefForm) -> Self {
        Self {
            assertion_evaluator: crucible::HostAssertionEvaluator::new(scenario_form.properties())
                .with_world_white_box_policies(scenario_form.world()),
            assertion_oracle: crucible::BlackBoxHostOracle,
            emitted_assertions: BTreeSet::new(),
            guest_markers: save_guest_marker_sources(scenario_form),
            emitted_guest_markers: Vec::new(),
        }
    }
}

pub(super) fn save_guest_marker_sources(
    scenario_form: &crucible::ScenarioDefForm,
) -> Vec<SaveGuestMarkerSource> {
    scenario_form
        .world()
        .vm_nodes()
        .iter()
        .filter(|node| node.white_box == crucible::WhiteBoxPolicy::Enabled)
        .flat_map(|node| {
            node.cmdline.split_whitespace().filter_map(|token| {
                token
                    .strip_prefix(SAVE_GUEST_MARKER_CMDLINE_PREFIX)
                    .filter(|marker| !marker.is_empty())
                    .map(|marker| SaveGuestMarkerSource {
                        node: node.id.clone(),
                        marker: crucible::MarkerId::from_name(marker.to_owned()),
                    })
            })
        })
        .collect()
}

#[derive(Clone, Debug)]
pub(super) struct SaveRecordingLifecycleLoop {
    pub(super) sources: SaveRecordingSources,
    pub(super) quanta: u64,
    pub(super) event_log_events: u64,
    pub(super) retained_event_log: Vec<crucible::SchedulerEventLogEntry>,
}

impl SaveRecordingLifecycleLoop {
    pub(super) fn new(sources: SaveRecordingSources) -> Self {
        Self {
            sources,
            quanta: 0,
            event_log_events: 0,
            retained_event_log: Vec::new(),
        }
    }

    fn diagnostic_entry(
        &self,
        sequence: u64,
        frontier: crucible::VirtualTime,
    ) -> crucible::SchedulerEventLogEntry {
        let mut details = BTreeMap::new();
        details.insert(
            String::from("quantum"),
            crucible::EventAttributeValue::U64(self.quanta),
        );
        crucible::SchedulerEventLogEntry::diagnostic(
            sequence,
            frontier,
            crucible::EventDiagnosticPayload::new(
                "crucible.cli.save-lifecycle",
                crucible::EventLevel::Info,
                details,
            ),
        )
    }

    fn next_event_log_sequence(&mut self) -> u64 {
        let sequence = self.event_log_events;
        self.event_log_events = self.event_log_events.saturating_add(1);
        sequence
    }

    fn record_entry(
        &mut self,
        quantum_entries: &mut Vec<crucible::SchedulerEventLogEntry>,
        entry: crucible::SchedulerEventLogEntry,
    ) {
        self.retained_event_log.push(entry.clone());
        quantum_entries.push(entry);
    }

    fn record_scenario_guest_markers(
        &mut self,
        frontier: crucible::VirtualTime,
        quantum_entries: &mut Vec<crucible::SchedulerEventLogEntry>,
    ) {
        for source in self.sources.guest_markers.clone() {
            if self.sources.emitted_guest_markers.contains(&source) {
                continue;
            }
            self.sources.emitted_guest_markers.push(source.clone());
            let entry = crucible::SchedulerEventLogEntry::guest_marker_observation(
                self.next_event_log_sequence(),
                crucible::Icount {
                    retired: frontier.ticks,
                },
                source.node,
                source.marker,
            );
            self.record_entry(quantum_entries, entry);
        }
    }

    fn record_scenario_assertion_events(
        &mut self,
        quantum_entries: &mut Vec<crucible::SchedulerEventLogEntry>,
    ) -> Result<(), crucible::SchedulerError> {
        let prefix = crucible::ConditionEventLogPrefix::from_scheduler_event_log_entries(
            self.retained_event_log.clone(),
        )
        .map_err(|error| crucible::SchedulerError::BoundaryViolation {
            message: format!("save lifecycle could not check scenario event prefix: {error}"),
        })?;
        let outcomes = self
            .sources
            .assertion_evaluator
            .observe_prefix(&prefix, &mut self.sources.assertion_oracle);
        for outcome in outcomes {
            if outcome.kind != crucible::HostAssertionOutcomeKind::Violated
                || self.sources.emitted_assertions.contains(&outcome.assertion)
            {
                continue;
            }
            self.sources
                .emitted_assertions
                .insert(outcome.assertion.clone());
            let entry = crucible::SchedulerEventLogEntry::assertion_state_observation(
                self.next_event_log_sequence(),
                outcome.at,
                outcome.assertion,
                crucible::AssertionPhase::Violated,
            );
            self.record_entry(quantum_entries, entry);
        }
        Ok(())
    }
}

impl crucible::QuantumLoop for SaveRecordingLifecycleLoop {
    impl_quantum_drive_method!(drive_quantum, QReq, QOut, QErr, |loop_state, request| {
        let previous = request.configuration.clone();
        loop_state.quanta = loop_state.quanta.saturating_add(1);
        let frontier = crucible::VirtualTime {
            ticks: loop_state.quanta,
        };
        let mut event_log_entries = Vec::new();
        let diagnostic_sequence = loop_state.next_event_log_sequence();
        let diagnostic = loop_state.diagnostic_entry(diagnostic_sequence, frontier);
        loop_state.record_entry(&mut event_log_entries, diagnostic);
        loop_state.record_scenario_guest_markers(frontier, &mut event_log_entries);
        loop_state.record_scenario_assertion_events(&mut event_log_entries)?;
        let decision = crucible::Decision::DeliveryOrder(crucible::DeliveryOrderDecision {
            at: frontier,
            order: Vec::new(),
        });
        let configuration = crucible::try_step(&previous, decision.clone()).map_err(|error| {
            crucible::SchedulerError::BoundaryViolation {
                message: format!(
                    "save lifecycle double could not record virtual-time decision: {error}"
                ),
            }
        })?;
        Ok(crucible::QuantumOutcome {
            configuration,
            frontier,
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: vec![decision],
            event_log_entries,
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: crucible::EventLogOffset::new(
                Default::default(),
                0,
                loop_state.event_log_events,
            ),
            scheduler_quiescence: Some(crucible::SchedulerQuiescence::default()),
        })
    });

    fn sample_fingerprint(
        &mut self,
        node: crucible::NodeId,
    ) -> Result<crucible::FingerprintSample, crucible::SchedulerError> {
        let material = format!(
            "node={}\nquanta={}\nevent-log-events={}\n",
            node.name, self.quanta, self.event_log_events
        );
        Ok(crucible::FingerprintSample {
            node,
            at: crucible::VirtualTime { ticks: self.quanta },
            fingerprint: crucible::ExecutionFingerprint {
                hash: crucible::ContentHash::from_canonical_material(
                    "crucible.lifecycle.save-fingerprint.v1",
                    &material,
                ),
            },
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct ResumeRecordingLifecycleLoop {
    pub(super) frontier: u64,
    pub(super) fixture: ResumeRecordingFixture,
    pub(super) fixture_emitted: bool,
    pub(super) event_log_events: u64,
    pub(super) post_fork_seed: Option<crucible::Seed>,
    pub(super) post_fork_draws: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(super) enum ResumeRecordingFixture {
    #[default]
    None,
    PropertyViolation {
        assertion: crucible::AssertionId,
    },
}

impl ResumeRecordingLifecycleLoop {
    pub(super) fn new(frontier: VirtualTime) -> Self {
        Self {
            frontier: frontier.ticks,
            fixture: ResumeRecordingFixture::None,
            fixture_emitted: false,
            event_log_events: 0,
            post_fork_seed: None,
            post_fork_draws: 0,
        }
    }

    pub(super) fn with_property_violation(
        frontier: VirtualTime,
        assertion: crucible::AssertionId,
    ) -> Self {
        Self {
            fixture: ResumeRecordingFixture::PropertyViolation { assertion },
            ..Self::new(frontier)
        }
    }

    pub(super) fn with_post_fork_seed(mut self, seed: crucible::Seed) -> Self {
        self.post_fork_seed = Some(seed);
        self
    }

    fn selector_fixture_entry(
        &self,
        frontier: crucible::VirtualTime,
    ) -> Option<crucible::SchedulerEventLogEntry> {
        match &self.fixture {
            ResumeRecordingFixture::None => None,
            ResumeRecordingFixture::PropertyViolation { assertion } => Some(
                crucible::SchedulerEventLogEntry::assertion_state_observation(
                    self.event_log_events,
                    frontier,
                    assertion.clone(),
                    crucible::AssertionPhase::Violated,
                ),
            ),
        }
    }
}

impl crucible::QuantumLoop for ResumeRecordingLifecycleLoop {
    impl_quantum_drive_method!(drive_quantum, QReq, QOut, QErr, |loop_state, request| {
        loop_state.frontier = loop_state.frontier.saturating_add(1);
        let frontier = VirtualTime {
            ticks: loop_state.frontier,
        };
        let mut event_log_entries = Vec::new();
        if !loop_state.fixture_emitted {
            if let Some(entry) = loop_state.selector_fixture_entry(frontier) {
                event_log_entries.push(entry);
                loop_state.event_log_events = loop_state.event_log_events.saturating_add(1);
            }
            loop_state.fixture_emitted = true;
        }
        let decision = if let Some(seed) = loop_state.post_fork_seed {
            let stream = crucible::RngStreamId::new(
                "crucible.cli.fork.reseed",
                format!("post-fork-{}", loop_state.post_fork_draws),
            );
            loop_state.post_fork_draws = loop_state.post_fork_draws.saturating_add(1);
            crucible::Decision::RngDraw(crucible::RngDecision {
                value: seed.stream_seed(&stream),
                stream,
            })
        } else {
            crucible::Decision::DeliveryOrder(crucible::DeliveryOrderDecision {
                at: frontier,
                order: Vec::new(),
            })
        };
        let configuration =
            crucible::try_step(&request.configuration, decision.clone()).map_err(|error| {
                crucible::SchedulerError::BoundaryViolation {
                    message: format!(
                        "resume lifecycle double could not record post-fork decision: {error}"
                    ),
                }
            })?;
        Ok(crucible::QuantumOutcome {
            configuration,
            frontier,
            advanced_node: None,
            resolved_events: Vec::new(),
            decisions: vec![decision],
            event_log_entries,
            event_log_segment_bytes: Vec::new(),
            event_log_segment_text: String::new(),
            event_log_segment_hash: None,
            event_log_offset: crucible::EventLogOffset::new(
                Default::default(),
                0,
                loop_state.event_log_events,
            ),
            scheduler_quiescence: Some(crucible::SchedulerQuiescence::default()),
        })
    });

    fn sample_fingerprint(
        &mut self,
        node: crucible::NodeId,
    ) -> Result<crucible::FingerprintSample, crucible::SchedulerError> {
        Ok(crucible::FingerprintSample {
            node,
            at: VirtualTime {
                ticks: self.frontier,
            },
            fingerprint: crucible::ExecutionFingerprint {
                hash: crucible::ContentHash::from_canonical_material(
                    "crucible.lifecycle.resume-fingerprint.v1",
                    &format!("frontier={}\n", self.frontier),
                ),
            },
        })
    }
}

#[cfg(any(test, feature = "test-double"))]
pub(super) fn run_local_double_verify_workflow(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    verify_plan: &VerifyInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let control_plane = LifecycleControlPlane::new(
        "crucible-cli-double",
        Vec::new(),
        |_scenario: &crucible::ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
    );
    let client = InProcessLifecycleClient::new(control_plane);
    let report = runtime.block_on(run_control_client_verify_workflow_async(
        &client,
        verify_plan,
        backend_plan.resolved_backend.as_ref(),
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
                let before =
                    wait_for_resume_workflow_state(client, resumed.session, LiveStateKind::Paused)
                        .await?;
                send_resume_workflow_command(
                    client,
                    resumed.session,
                    &mut command_id,
                    SessionCommand::step(StepMode::Quantum),
                    &mut acknowledged_commands,
                    &mut state_updates,
                )
                .await?;
                wait_for_resume_workflow_advanced_paused(
                    client,
                    resumed.session,
                    &before,
                    "paused remote quiescence resume boundary",
                )
                .await?
            }
            RunTerminalCondition::VirtualTime => {
                let budget = resume_plan.max_virtual_time_ticks.ok_or_else(|| {
                    usage_error("resume --until virtual-time requires --max-virtual-time")
                })?;
                let summary =
                    wait_for_resume_workflow_state(client, resumed.session, LiveStateKind::Paused)
                        .await?;
                let boundary = if summary.frontier.ticks < budget {
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
                            candidate.state == LiveStateKind::Paused
                                && candidate.frontier.ticks >= budget
                                && candidate.quanta_stepped > summary.quanta_stepped
                        },
                        "paused requested remote virtual-time resume boundary",
                        resume_actor_boundary_yield_budget(summary.frontier.ticks, budget),
                    )
                    .await?
                } else {
                    summary
                };
                if boundary.frontier.ticks != budget {
                    return Err(CliError::Identity(format!(
                        "resume remote virtual-time boundary reached {}, expected {}",
                        boundary.frontier.ticks, budget
                    )));
                }
                boundary
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
                        spec: BreakpointSpec::fail_once(
                            predicate.clone(),
                            "requested property was violated",
                        ),
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
                let before =
                    wait_for_resume_workflow_state(client, resumed.session, LiveStateKind::Paused)
                        .await?;
                send_resume_workflow_command(
                    client,
                    resumed.session,
                    &mut command_id,
                    SessionCommand::step(StepMode::Quantum),
                    &mut acknowledged_commands,
                    &mut state_updates,
                )
                .await?;
                let boundary = wait_for_resume_workflow_advanced_paused(
                    client,
                    resumed.session,
                    &before,
                    "paused remote property resume boundary",
                )
                .await?;
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
                validate_resume_property_firing_summary(
                    breakpoint_id,
                    &predicate,
                    &boundary,
                    &firings,
                )?;
                property_violation_reached = true;
                boundary
            }
        };
        if resume_plan.watch_streams_live_status {
            watch_statuses.push(run_watch_status(&boundary));
        }
        boundary
    };

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
            final_frontier_ticks: snapshot.frontier.ticks.max(boundary.frontier.ticks),
            final_quanta: snapshot.quanta.max(boundary.quanta_stepped),
            budget_timed_out: false,
            state_updates,
            streamed_events: Vec::new(),
            streamed_event_frames: Vec::new(),
            coverage_feedback: crucible::EventLogCoverageFeedback::from_event_log(&[]),
            execution_fingerprints: Vec::new(),
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
                RUN_INTERACTIVE_ACK_QUANTA_BOUND,
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
