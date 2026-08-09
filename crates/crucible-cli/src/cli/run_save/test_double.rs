//! Test-double run, save, resume, and verification lifecycle fixtures.

use super::*;

#[cfg(any(test, feature = "test-double"))]
pub(in super::super) fn run_local_double_workflow(
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
pub(in super::super) fn run_local_double_save_workflow(
    thin_plan: &CliThinWrapperPlan,
    backend_plan: &BackendSelectionPlan,
    ergonomics_plan: Option<&DeterminismErgonomicsPlan>,
    save_plan: &SaveInvocationPlan,
) -> Result<BackendCommandOutcome, CliError> {
    run_local_save_recording_workflow(thin_plan, backend_plan, ergonomics_plan, save_plan)
}

#[cfg(any(test, feature = "test-double"))]
#[derive(Clone, Debug)]
pub(in super::super) struct SaveRecordingSources {
    pub(in super::super) assertion_evaluator: crucible::HostAssertionEvaluator,
    pub(in super::super) assertion_oracle: crucible::BlackBoxHostOracle,
    pub(in super::super) emitted_assertions: BTreeSet<crucible::AssertionId>,
    pub(in super::super) guest_markers: Vec<SaveGuestMarkerSource>,
    pub(in super::super) emitted_guest_markers: Vec<SaveGuestMarkerSource>,
}

#[cfg(any(test, feature = "test-double"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in super::super) struct SaveGuestMarkerSource {
    pub(in super::super) node: crucible::NodeId,
    pub(in super::super) marker: crucible::MarkerId,
}

#[cfg(any(test, feature = "test-double"))]
impl SaveRecordingSources {
    pub(in super::super) fn from_scenario_form(scenario_form: &crucible::ScenarioDefForm) -> Self {
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

#[cfg(any(test, feature = "test-double"))]
pub(in super::super) fn save_guest_marker_sources(
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

#[cfg(any(test, feature = "test-double"))]
#[derive(Clone, Debug)]
pub(in super::super) struct SaveRecordingLifecycleLoop {
    pub(in super::super) sources: SaveRecordingSources,
    pub(in super::super) quanta: u64,
    pub(in super::super) event_log_events: u64,
    pub(in super::super) retained_event_log: Vec<crucible::SchedulerEventLogEntry>,
    selector_delay_quanta: u64,
}

#[cfg(any(test, feature = "test-double"))]
impl SaveRecordingLifecycleLoop {
    pub(in super::super) fn new(sources: SaveRecordingSources) -> Self {
        Self {
            sources,
            quanta: 0,
            event_log_events: 0,
            retained_event_log: Vec::new(),
            selector_delay_quanta: 1,
        }
    }

    #[cfg(test)]
    pub(in super::super) fn with_selector_delay_quanta(mut self, quanta: u64) -> Self {
        self.selector_delay_quanta = quanta;
        self
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

#[cfg(any(test, feature = "test-double"))]
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
        if loop_state.quanta > loop_state.selector_delay_quanta {
            loop_state.record_scenario_guest_markers(frontier, &mut event_log_entries);
            loop_state.record_scenario_assertion_events(&mut event_log_entries)?;
        }
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
            scheduler_quiescence: if loop_state.quanta <= loop_state.selector_delay_quanta {
                None
            } else {
                Some(crucible::SchedulerQuiescence::default())
            },
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

#[cfg(any(test, feature = "test-double"))]
#[derive(Clone, Debug, PartialEq, Eq)]
pub(in super::super) struct ResumeRecordingLifecycleLoop {
    pub(in super::super) frontier: u64,
    pub(in super::super) fixture: ResumeRecordingFixture,
    pub(in super::super) fixture_emitted: bool,
    pub(in super::super) event_log_events: u64,
    pub(in super::super) post_fork_seed: Option<crucible::Seed>,
    pub(in super::super) post_fork_draws: u64,
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
            post_fork_seed: None,
            post_fork_draws: 0,
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

    pub(in super::super) fn with_post_fork_seed(mut self, seed: crucible::Seed) -> Self {
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

#[cfg(any(test, feature = "test-double"))]
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
pub(in super::super) fn run_local_double_verify_workflow(
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
