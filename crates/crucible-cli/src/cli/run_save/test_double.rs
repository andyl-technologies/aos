//! Test-double run, save, resume, and verification lifecycle fixtures.

use super::*;

#[cfg(any(test, feature = "test-double"))]
pub(in super::super) fn run_local_double_workflow(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    run_plan: &RunInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let decoding = crate::cli_input_resources::original_budget()?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let report = if matches!(run_plan.execution_mode, RunExecutionMode::Interactive) {
        runtime.block_on(
            crucible_api::admit_future(
                run_local_double_workflow_stdin_async(run_plan, ergonomics_plan),
                decoding.clone(),
            )
            .map_err(|source| CliError::LifecycleAdmission(Box::new(source)))?,
        )?
    } else {
        runtime.block_on(
            crucible_api::admit_future(
                run_local_double_workflow_async(run_plan, ergonomics_plan, &[]),
                decoding.clone(),
            )
            .map_err(|source| CliError::LifecycleAdmission(Box::new(source)))?,
        )?
    };
    let _scope = decoding.enter();
    finish_run_workflow_outcome(thin_plan, backend_plan, ergonomics_plan, run_plan, report)
}

#[cfg(any(test, feature = "test-double"))]
pub(in super::super) fn run_local_double_save_workflow(
    _thin_plan: &CliThinWrapperPlan,
    _backend_plan: &BackendSelectionPlan,
    _ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    _save_plan: &SaveInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    Err(backend_error(
        "savepoint export requires Campaign-owned execution with an authenticated portable replay closure",
    ))
}

#[cfg(any(test, feature = "test-double"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in super::super) struct ResumeRecordingLifecycleLoop {
    pub(in super::super) frontier: u64,
    pub(in super::super) fixture: ResumeRecordingFixture,
    pub(in super::super) fixture_emitted: bool,
    pub(in super::super) event_log_events: u64,
}

#[cfg(any(test, feature = "test-double"))]
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(in super::super) enum ResumeRecordingFixture {
    #[default]
    None,
    PropertyViolation {
        assertion: crucible::AssertionId,
    },
}

#[cfg(any(test, feature = "test-double"))]
impl ResumeRecordingLifecycleLoop {
    pub(in super::super) fn new(frontier: VirtualTime) -> Self {
        Self {
            frontier: frontier.ticks,
            fixture: ResumeRecordingFixture::None,
            fixture_emitted: false,
            event_log_events: 0,
        }
    }

    pub(in super::super) fn with_property_violation(
        frontier: VirtualTime,
        assertion: crucible::AssertionId,
    ) -> Self {
        Self {
            fixture: ResumeRecordingFixture::PropertyViolation { assertion },
            ..Self::new(frontier)
        }
    }

    fn selector_fixture_entry(
        &self,
        frontier: crucible::VirtualTime,
    ) -> Result<Option<crucible::SchedulerEventLogEntry>, crucible::EngineError> {
        Ok(match &self.fixture {
            ResumeRecordingFixture::None => None,
            ResumeRecordingFixture::PropertyViolation { assertion } => Some(
                crucible::SchedulerEventLogEntry::assertion_state_observation(
                    self.event_log_events,
                    frontier,
                    assertion.clone(),
                    crucible::AssertionPhase::Violated,
                )?,
            ),
        })
    }
}

#[cfg(any(test, feature = "test-double"))]
impl crucible::QuantumLoop for ResumeRecordingLifecycleLoop {
    impl_quantum_drive_method!(drive_quantum, QReq, QOut, QErr, |loop_state, request| {
        let output_custody =
            crucible::EventLogOutputCustody::retain_current().map_err(|source| {
                crucible::SchedulerError::Evaluation {
                    source: Arc::new(source),
                }
            })?;
        let _output_scope = output_custody.enter_decode_scope();
        loop_state.frontier = loop_state.frontier.saturating_add(1);
        let frontier = VirtualTime {
            ticks: loop_state.frontier,
        };
        let mut event_log_entries = Vec::new();
        if !loop_state.fixture_emitted {
            if let Some(entry) = loop_state
                .selector_fixture_entry(frontier)
                .map_err(|source| crucible::SchedulerError::Evaluation {
                    source: Arc::new(source),
                })?
            {
                crucible::owned_decode::reserve_vec(&mut event_log_entries, 1).map_err(
                    |source| crucible::SchedulerError::Evaluation {
                        source: Arc::new(crucible::EngineError::ArtifactDecodeAdmission { source }),
                    },
                )?;
                event_log_entries.push(entry);
                loop_state.event_log_events = loop_state.event_log_events.saturating_add(1);
            }
            loop_state.fixture_emitted = true;
        }
        let decision = crucible::Decision::DeliveryOrder(crucible::DeliveryOrderDecision {
            at: frontier,
            order: Vec::new(),
        });
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
            discovered_choices: Vec::new(),
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
            event_log_custody: output_custody,
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
pub(in super::super) fn run_local_double_verify_workflow(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    verify_plan: &VerifyInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    let decoding = crate::cli_input_resources::original_budget()?;
    let scenario = verify_plan.scenario().ok_or_else(|| {
        backend_error("verify compare mode must not enter the local-double workflow")
    })?;
    let request_seed = ergonomics_plan
        .map(|plan| crucible::Seed::from_u64(plan.seed.value))
        .unwrap_or_else(|| scenario.scenario_def().seed());
    let mut witnesses = {
        let _scope = decoding.enter();
        let mut values = Vec::new();
        crucible::owned_decode::reserve_vec(&mut values, verify_plan.reductions.len())
            .map_err(CliError::MetadataAdmission)?;
        values
    };
    for reduction in &verify_plan.reductions {
        let mut runtime_builder = if reduction.host_profile.logical_cores == 1 {
            tokio::runtime::Builder::new_current_thread()
        } else {
            let mut builder = tokio::runtime::Builder::new_multi_thread();
            builder.worker_threads(reduction.host_profile.logical_cores);
            builder
        };
        let runtime = runtime_builder.enable_all().build()?;
        let control_plane = LifecycleControlPlane::new(
            "crucible-cli-double",
            Vec::new(),
            |_scenario: &crucible::ScenarioDef, _seed| QuiescentLifecycleLoop::new(),
        )
        .with_terminal_session_retention(true)
        .with_decode_budget(decoding.clone());
        let client = InProcessLifecycleClient::new(control_plane);
        let future = {
            let _scope = decoding.enter();
            run_control_client_verify_reduction_async(
                &client,
                reseed_run_scenario_ref(scenario, request_seed)?,
                request_seed,
                reduction.clone(),
                backend_plan.resolved_backend.as_ref(),
                ergonomics_plan,
                &verify_plan.store_root,
            )
        };
        let admitted = crucible_api::admit_future(future, decoding.clone())
            .map_err(|source| CliError::LifecycleAdmission(Box::new(source)))?;
        let witness = runtime.block_on(admitted).map_err(|error| {
            backend_error(format!(
                "verify hostile profile `{}` failed: {error}",
                reduction.host_profile.label()
            ))
        })?;
        witnesses.push(witness);
    }
    let _scope = decoding.enter();
    let report = VerifyWorkflowReport {
        _input_custody: crucible_session::engine::owned_decode::current_custody(),
        divergence: compare_verify_witnesses(&witnesses),
        witnesses,
    };
    finish_verify_workflow_outcome(
        thin_plan,
        backend_plan,
        ergonomics_plan,
        verify_plan,
        report,
    )
}
