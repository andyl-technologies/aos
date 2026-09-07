//! QEMU campaign driver candidate, evidence, and cancellation tests.

// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
#![allow(clippy::expect_used)]

use crucible::model::{
    Aggregation, BoundarySelector, CohortPolicy, MeasurementDefinition, MeasurementDefinitions,
    MeasurementId, MetricDefinition, MetricId, MetricSource, MetricValueType, UnitId,
};
use crucible::{
    Configuration, EventLog, EventLogOffset, Icount, MarkerId, NodeId, NodeTemplate,
    ObservableEvent, Plan, Properties, QuantumOutcome, QuantumTerminalVerdict, ReadyPoint,
    ScenarioDefForm, ScenarioSelectableLimits, ScenarioSelectables, SchedulerError,
    SchedulerEventLogEntry, SchedulerQuiescence, Seed, VirtualTime, WhiteBoxPolicy, World,
    WorldNode,
};
use crucible_campaign::{
    Attempt, AttemptResourceLimits, AttemptStart, BooleanDomain, BranchPath, CampaignHash,
    CampaignLineage, ChoiceClassContext, ChoiceCoordinate, ChoiceDiscovery, ChoiceDomain,
    ChoiceOpportunity, ChoiceSource, ChoiceValue, ConfigurationId, ExecutionRetentionIntent,
    PropertyVerdict, ScenarioDefId, SelectableDeclaration, StopCondition, StopOutcome,
};
use crucible_protocol::SelectionRequest;
use crucible_protocol::selectable_catalog_plan::SelectablePlanPendingRequest;
#[cfg(target_os = "linux")]
use crucible_qemu::{QemuHotForkChildDiagnosticDrain, QemuVmRealizationError};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

use super::*;
use crate::{ExecutionCancellation, ExecutionCheckpointRequest, QemuFreshAttemptLifecycleOwner};

#[cfg(target_os = "linux")]
struct HotModeledLive<'a> {
    modeled: &'a mut dyn QemuModeledAttemptLifecycle,
    resources: AttemptResourceLimits,
    cancellation: ExecutionCancellation,
    event_log: EventLog,
}

#[cfg(target_os = "linux")]
impl crate::QemuAttemptOperationalBoundary for HotModeledLive<'_> {
    fn resource_limits(&self) -> AttemptResourceLimits {
        self.resources
    }

    fn cancellation(&self) -> &ExecutionCancellation {
        &self.cancellation
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        if self.cancellation.is_canceled() {
            Err(QemuVmRealizationError::Canceled {
                operation: "test hot-fork modeled boundary",
            })
        } else {
            Ok(())
        }
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        self.check_operational_boundary()
    }
}

#[cfg(target_os = "linux")]
impl crate::QemuHotForkLiveExecution for HotModeledLive<'_> {
    fn modeled_lifecycle(
        &mut self,
    ) -> Result<&mut dyn QemuModeledAttemptLifecycle, QemuVmRealizationError> {
        Ok(self.modeled)
    }

    fn event_log_mut(&mut self) -> &mut EventLog {
        &mut self.event_log
    }

    fn drain_diagnostics(
        &mut self,
    ) -> Result<QemuHotForkChildDiagnosticDrain, QemuVmRealizationError> {
        panic!("modeled-driver test does not use child diagnostics")
    }
}

#[cfg(target_os = "linux")]
struct RawHotLive {
    resources: AttemptResourceLimits,
    cancellation: ExecutionCancellation,
    event_log: EventLog,
}

#[cfg(target_os = "linux")]
impl crate::QemuAttemptOperationalBoundary for RawHotLive {
    fn resource_limits(&self) -> AttemptResourceLimits {
        self.resources
    }

    fn cancellation(&self) -> &ExecutionCancellation {
        &self.cancellation
    }

    fn check_operational_boundary(&mut self) -> Result<(), QemuVmRealizationError> {
        Ok(())
    }

    fn charge_execution_quantum(&mut self) -> Result<(), QemuVmRealizationError> {
        Ok(())
    }
}

#[cfg(target_os = "linux")]
impl crate::QemuHotForkLiveExecution for RawHotLive {
    fn event_log_mut(&mut self) -> &mut EventLog {
        &mut self.event_log
    }

    fn drain_diagnostics(
        &mut self,
    ) -> Result<QemuHotForkChildDiagnosticDrain, QemuVmRealizationError> {
        panic!("raw-live test does not use child diagnostics")
    }
}

struct FakeLifecycle {
    outcomes: VecDeque<Result<QuantumOutcome, SchedulerError>>,
    terminal: Option<QuantumTerminalVerdict>,
    drives: usize,
}

struct PendingSelectableLifecycle {
    outcome: Option<QuantumOutcome>,
    pending: Vec<crucible_qemu::QemuNodeSelectablePendingRequest>,
    replies: Vec<crucible_protocol::SelectionReply>,
}

impl QemuFreshAttemptLifecycleOwner for FakeLifecycle {
    fn enable_signal_fault_campaign_promotion(&mut self) {}

    fn drive_quantum(
        &mut self,
        _request: QuantumRequest,
    ) -> Result<QuantumOutcome, SchedulerError> {
        self.drives += 1;
        self.outcomes.pop_front().unwrap_or_else(|| {
            Err(SchedulerError::BoundaryViolation {
                message: String::from("fake lifecycle exhausted outcomes"),
            })
        })
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<QuantumTerminalVerdict> {
        self.terminal.clone()
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError> {
        Ok(true)
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<crucible_qemu::QemuNodeSelectablePendingRequest>, SchedulerError> {
        Ok(Vec::new())
    }

    fn enqueue_selectable_reply(
        &mut self,
        _pending: &crucible_qemu::QemuNodeSelectablePendingRequest,
        _reply: &crucible_protocol::SelectionReply,
    ) -> Result<(), SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("modeled driver fixture has no selectable transport"),
        })
    }

    fn capture_attempt_checkpoint(
        &mut self,
        _context: &crate::AttemptExecutionContext,
    ) -> Result<crate::CapturedAttemptCheckpoint, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("modeled driver fixture has no checkpoint authority"),
        })
    }

    fn fault_evidence_snapshot(
        &self,
    ) -> Result<crucible_api::ProductionFaultEvidenceSnapshot, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("fake lifecycle has no fault evidence"),
        })
    }

    fn pending_network_output_count(&self) -> usize {
        0
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        Ok(Vec::new())
    }
}

impl QemuFreshAttemptLifecycleOwner for PendingSelectableLifecycle {
    fn enable_signal_fault_campaign_promotion(&mut self) {}

    fn drive_quantum(
        &mut self,
        _request: QuantumRequest,
    ) -> Result<QuantumOutcome, SchedulerError> {
        self.outcome
            .take()
            .ok_or_else(|| SchedulerError::BoundaryViolation {
                message: String::from("selectable lifecycle exhausted its quantum"),
            })
    }

    fn terminal_verdict_for_stop(&mut self) -> Option<QuantumTerminalVerdict> {
        None
    }

    fn exact_checkpoint_ready(&mut self) -> Result<bool, SchedulerError> {
        Ok(false)
    }

    fn drain_pending_selectable_requests(
        &mut self,
    ) -> Result<Vec<crucible_qemu::QemuNodeSelectablePendingRequest>, SchedulerError> {
        Ok(std::mem::take(&mut self.pending))
    }

    fn enqueue_selectable_reply(
        &mut self,
        _pending: &crucible_qemu::QemuNodeSelectablePendingRequest,
        reply: &crucible_protocol::SelectionReply,
    ) -> Result<(), SchedulerError> {
        self.replies.push(reply.clone());
        Ok(())
    }

    fn capture_attempt_checkpoint(
        &mut self,
        _context: &crate::AttemptExecutionContext,
    ) -> Result<crate::CapturedAttemptCheckpoint, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("selectable lifecycle has no checkpoint authority"),
        })
    }

    fn fault_evidence_snapshot(
        &self,
    ) -> Result<crucible_api::ProductionFaultEvidenceSnapshot, SchedulerError> {
        Err(SchedulerError::BoundaryViolation {
            message: String::from("selectable lifecycle has no fault evidence"),
        })
    }

    fn pending_network_output_count(&self) -> usize {
        0
    }

    fn shutdown(&mut self) -> Result<Vec<SchedulerEventLogEntry>, SchedulerError> {
        Ok(Vec::new())
    }
}

fn expect_observation(
    outcome: QemuFreshDriveOutcome<QemuFreshPendingObservation>,
) -> QemuFreshPendingObservation {
    match outcome {
        QemuFreshDriveOutcome::Observation(pending) => pending,
        QemuFreshDriveOutcome::CheckpointRequested => {
            panic!("modeled observation fixture unexpectedly requested a checkpoint")
        }
    }
}

#[test]
fn sticky_checkpoint_request_stops_at_a_safe_boundary_without_driving() {
    let input = input(StopCondition::Terminal);
    let checkpoint_request = ExecutionCheckpointRequest::default();
    checkpoint_request.request_for_test();
    let context = AttemptExecutionContext::new(
        AttemptResourceLimits::new(1, 1, 0, 1).expect("checkpoint resources"),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        checkpoint_request,
    );
    let mut owner = FakeLifecycle {
        outcomes: VecDeque::new(),
        terminal: None,
        drives: 0,
    };
    let mut lifecycle = QemuFreshAttemptLifecycle::new(&mut owner);
    let mut driver = QemuFreshModeledDriver::new();

    let outcome = driver
        .drive(
            &mut lifecycle,
            &input,
            &context,
            QemuFreshStartMaterialization::genesis(),
        )
        .expect("checkpoint request should reach runner ownership");

    assert!(matches!(
        outcome,
        QemuFreshDriveOutcome::CheckpointRequested
    ));
    assert_eq!(owner.drives, 0);
}

#[test]
fn terminal_verdict_wins_over_a_coincident_checkpoint_request() {
    let input = input(StopCondition::Terminal);
    let checkpoint_request = ExecutionCheckpointRequest::default();
    checkpoint_request.request_for_test();
    let context = AttemptExecutionContext::new(
        AttemptResourceLimits::new(1, 1, 0, 1).expect("checkpoint resources"),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        checkpoint_request,
    );
    let mut owner = FakeLifecycle {
        outcomes: VecDeque::new(),
        terminal: Some(QuantumTerminalVerdict::Passed),
        drives: 0,
    };
    let mut lifecycle = QemuFreshAttemptLifecycle::new(&mut owner);
    let mut driver = QemuFreshModeledDriver::new();

    let pending = expect_observation(
        driver
            .drive(
                &mut lifecycle,
                &input,
                &context,
                QemuFreshStartMaterialization::from_test_parts(
                    Vec::new(),
                    None,
                    Some(QuantumTerminalVerdict::Passed),
                ),
            )
            .expect("terminal verdict should remain authoritative"),
    );

    assert!(matches!(pending.stop, ModeledStop::TerminalPassed));
    assert_eq!(owner.drives, 0);
}

#[test]
fn event_count_seals_final_drain_coverage_into_exact_candidate() {
    let input = input(StopCondition::EventCount(1));
    let configuration = starting_configuration(&input);
    let node = node("node-a");
    let mut log = EventLog::new();
    let prefix = log
        .append_observable_events([ObservableEvent::coverage_marker(
            Icount { retired: 0 },
            node.clone(),
            MarkerId::from_name("prefix-covered"),
        )])
        .expect("replayed prefix event-log segment");
    let first = log
        .append_observable_events([ObservableEvent::guest_marker(
            Icount { retired: 1 },
            node.clone(),
            MarkerId::from_name("first"),
        )])
        .expect("first event-log segment");
    let final_append = log
        .append_observable_events([ObservableEvent::coverage_marker(
            Icount { retired: 2 },
            node,
            MarkerId::from_name("covered"),
        )])
        .expect("final event-log segment");
    let mut owner = FakeLifecycle {
        outcomes: VecDeque::from([Ok(outcome(
            configuration.clone(),
            first.entries,
            first.offset,
            1,
        ))]),
        terminal: None,
        drives: 0,
    };
    let mut lifecycle = QemuFreshAttemptLifecycle::new(&mut owner);
    let mut driver = QemuFreshModeledDriver::new();

    let pending = expect_observation(
        driver
            .drive(
                &mut lifecycle,
                &input,
                &context(),
                QemuFreshStartMaterialization::from_test_parts(prefix.entries.clone(), None, None),
            )
            .expect("event-count stop"),
    );
    let product = driver
        .seal(pending, final_append.entries.clone())
        .expect("final coverage projection");
    let AttemptExecutionProduct::Observation(candidate) = product else {
        panic!("fresh modeled driver must return an observation")
    };

    assert_eq!(
        candidate.child().configuration(),
        configuration_id(&configuration)
    );
    assert_eq!(
        candidate.observation().stop(),
        &StopOutcome::Reached(StopCondition::EventCount(1))
    );
    let expected = prefix
        .entries
        .iter()
        .chain(&final_append.entries)
        .flat_map(|entry| {
            crucible::event_log_coverage_projection(std::slice::from_ref(entry))
                .entries()
                .to_vec()
        })
        .map(|entry| CampaignHash::from_bytes(entry.observation.content_hash().bytes))
        .collect::<BTreeSet<_>>();
    assert_eq!(candidate.coverage().identities(), &expected);
    assert_eq!(candidate.measurements().schema_version(), 2);
    assert!(candidate.measurements().evaluation().is_some());
    assert!(candidate.properties().properties().is_empty());
    assert_eq!(owner.drives, 1);
}

#[test]
#[cfg(target_os = "linux")]
fn hot_fork_driver_reuses_the_common_modeled_loop_and_seals_a_candidate() {
    let input = input(StopCondition::EventCount(1));
    let configuration = starting_configuration(&input);
    let node = node("node-a");
    let mut observed = EventLog::new();
    let append = observed
        .append_observable_events([ObservableEvent::guest_marker(
            Icount { retired: 1 },
            node,
            MarkerId::from_name("hot-fork-observation"),
        )])
        .expect("hot-fork observable event");
    let mut owner = FakeLifecycle {
        outcomes: VecDeque::from([Ok(outcome(
            configuration.clone(),
            append.entries,
            append.offset,
            1,
        ))]),
        terminal: None,
        drives: 0,
    };
    let mut modeled = QemuFreshAttemptLifecycle::new(&mut owner);
    let context = context();
    let mut live = HotModeledLive {
        modeled: &mut modeled,
        resources: context.resources(),
        cancellation: context.cancellation().clone(),
        event_log: EventLog::new(),
    };
    let mut driver = QemuHotForkModeledDriver;

    let pending = crate::QemuHotForkAttemptDriver::drive(&mut driver, &mut live, &input, &context)
        .expect("hot-fork modeled stop");
    let product =
        crate::QemuHotForkAttemptDriver::seal(&mut driver, pending, &mut live, &input, &context)
            .expect("hot-fork modeled candidate");
    let AttemptExecutionProduct::Observation(candidate) = product else {
        panic!("hot-fork modeled driver must return an observation")
    };

    assert_eq!(
        candidate.child().configuration(),
        configuration_id(&configuration)
    );
    assert_eq!(
        candidate.observation().stop(),
        &StopOutcome::Reached(StopCondition::EventCount(1))
    );
    assert_eq!(owner.drives, 1);
}

#[test]
#[cfg(target_os = "linux")]
fn hot_fork_driver_rejects_raw_channels_without_a_modeled_lifecycle() {
    let input = input(StopCondition::Terminal);
    let context = context();
    let mut live = RawHotLive {
        resources: context.resources(),
        cancellation: context.cancellation().clone(),
        event_log: EventLog::new(),
    };
    let mut driver = QemuHotForkModeledDriver;

    let error = crate::QemuHotForkAttemptDriver::drive(&mut driver, &mut live, &input, &context)
        .expect_err("raw child channels must not imply modeled execution readiness");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(QemuHotForkModeledDriverError::LifecycleUnavailable(_))
    ));
}

#[test]
#[cfg(target_os = "linux")]
fn hot_fork_driver_rejects_checkpoint_handoff_before_driving() {
    let input = input(StopCondition::Terminal);
    let checkpoint_request = ExecutionCheckpointRequest::default();
    checkpoint_request.request_for_test();
    let context = AttemptExecutionContext::new(
        AttemptResourceLimits::new(1, 1, 0, 1).expect("checkpoint resources"),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        checkpoint_request,
    );
    let mut owner = FakeLifecycle {
        outcomes: VecDeque::new(),
        terminal: None,
        drives: 0,
    };
    let mut modeled = QemuFreshAttemptLifecycle::new(&mut owner);
    let mut live = HotModeledLive {
        modeled: &mut modeled,
        resources: context.resources(),
        cancellation: context.cancellation().clone(),
        event_log: EventLog::new(),
    };
    let mut driver = QemuHotForkModeledDriver;

    let error = crate::QemuHotForkAttemptDriver::drive(&mut driver, &mut live, &input, &context)
        .expect_err("hot-child checkpoint handoff must remain owner-controlled");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(QemuHotForkModeledDriverError::CheckpointRequested)
    ));
    assert_eq!(owner.drives, 0);
}

#[test]
fn modeled_scheduler_metrics_are_derived_from_the_canonical_log() {
    let fixture = crucible::happy_path_scenario().expect("happy-path fixture");
    let scenario = measured_scenario(&fixture.scenario);
    let input = input_for_scenario(scenario, StopCondition::Terminal);
    let configuration = starting_configuration(&input);
    let mut log = EventLog::new();
    let append = log
        .append_observable_events(fixture.observations().iter().cloned())
        .expect("happy-path event log");
    let mut quantum = outcome(configuration, append.entries, append.offset, 38);
    quantum.scheduler_quiescence = Some(SchedulerQuiescence::default());
    let mut owner = FakeLifecycle {
        outcomes: VecDeque::from([Ok(quantum)]),
        terminal: Some(QuantumTerminalVerdict::Passed),
        drives: 0,
    };
    let mut lifecycle = QemuFreshAttemptLifecycle::new(&mut owner);
    let mut driver = QemuFreshModeledDriver::new();

    let pending = expect_observation(
        driver
            .drive(
                &mut lifecycle,
                &input,
                &context(),
                QemuFreshStartMaterialization::genesis(),
            )
            .expect("terminal modeled stop"),
    );
    let product = driver
        .seal(pending, Vec::new())
        .expect("model-owned measurement projection");
    let AttemptExecutionProduct::Observation(candidate) = product else {
        panic!("model-owned measurement run must return an observation")
    };
    let retained = candidate
        .measurements()
        .evaluation()
        .expect("verified evaluation payload");
    let payload = std::str::from_utf8(retained.payload()).expect("canonical measurement JSON");
    assert!(payload.contains("\"scheduler-events\""));
    assert!(payload.contains(&format!(
        "\"aggregate\":{{\"kind\":\"unsigned\",\"value\":{}}}",
        fixture.observations().len()
    )));
}

#[test]
fn guest_measurement_messages_normalize_against_the_exact_scenario_contract() {
    let fixture = crucible::happy_path_scenario().expect("happy-path fixture");
    let definitions = guest_measurement_definitions(&fixture.scenario);
    let node = fixture
        .scenario
        .world()
        .vm_nodes()
        .first()
        .expect("happy-path VM")
        .id
        .clone();
    let entries = vec![
        SchedulerEventLogEntry::guest_measurement_observation(
            0,
            Icount { retired: 1 },
            node.clone(),
            GuestMeasurementEvent::Begin {
                measurement: String::from("driver-window"),
                instance: String::from("epoch-7"),
            },
        ),
        SchedulerEventLogEntry::guest_measurement_observation(
            1,
            Icount { retired: 2 },
            node.clone(),
            GuestMeasurementEvent::Sample {
                measurement: String::from("driver-window"),
                instance: String::from("epoch-7"),
                metric: String::from("healthy-peers"),
                value: GuestMeasurementValue::Unsigned(3),
            },
        ),
        SchedulerEventLogEntry::guest_semantic_marker_observation(
            2,
            Icount { retired: 3 },
            node.clone(),
            String::from("routing-converged"),
            String::from("epoch-7"),
            Vec::new(),
        ),
        SchedulerEventLogEntry::guest_measurement_observation(
            3,
            Icount { retired: 4 },
            node,
            GuestMeasurementEvent::End {
                measurement: String::from("driver-window"),
                instance: String::from("epoch-7"),
            },
        ),
    ];

    let samples = normalize_guest_measurements(&definitions, &entries)
        .expect("declared guest measurement sequence");

    assert_eq!(samples.len(), 1);
    assert_eq!(samples[0].sequence(), 1);
    assert_eq!(samples[0].measurement().as_str(), "driver-window");
    assert_eq!(samples[0].metric().as_str(), "healthy-peers");
    assert_eq!(samples[0].value(), &MeasurementSampleValue::Unsigned(3));
}

#[test]
fn fresh_driver_retains_verified_guest_measurement_evaluation() {
    let fixture = crucible::happy_path_scenario().expect("happy-path fixture");
    let scenario = guest_measured_scenario(&fixture.scenario);
    let input = input_for_scenario(scenario, StopCondition::Terminal);
    let configuration = starting_configuration(&input);
    let node = input
        .scenario()
        .world()
        .vm_nodes()
        .first()
        .expect("happy-path VM")
        .id
        .clone();
    let mut observations = fixture.observations().to_vec();
    observations.extend([
        ObservableEvent::guest_measurement(
            Icount { retired: 40 },
            node.clone(),
            GuestMeasurementEvent::Begin {
                measurement: String::from("driver-window"),
                instance: String::from("epoch-7"),
            },
        ),
        ObservableEvent::guest_measurement(
            Icount { retired: 41 },
            node.clone(),
            GuestMeasurementEvent::Sample {
                measurement: String::from("driver-window"),
                instance: String::from("epoch-7"),
                metric: String::from("healthy-peers"),
                value: GuestMeasurementValue::Unsigned(3),
            },
        ),
        ObservableEvent::guest_semantic_marker(
            Icount { retired: 42 },
            node.clone(),
            String::from("routing-converged"),
            String::from("epoch-7"),
            Vec::new(),
        ),
        ObservableEvent::guest_measurement(
            Icount { retired: 43 },
            node,
            GuestMeasurementEvent::End {
                measurement: String::from("driver-window"),
                instance: String::from("epoch-7"),
            },
        ),
    ]);
    let mut log = EventLog::new();
    let append = log
        .append_observable_events(observations)
        .expect("guest measurement event log");
    let mut quantum = outcome(configuration, append.entries, append.offset, 43);
    quantum.scheduler_quiescence = Some(SchedulerQuiescence::default());
    let mut owner = FakeLifecycle {
        outcomes: VecDeque::from([Ok(quantum)]),
        terminal: Some(QuantumTerminalVerdict::Passed),
        drives: 0,
    };
    let mut lifecycle = QemuFreshAttemptLifecycle::new(&mut owner);
    let mut driver = QemuFreshModeledDriver::new();

    let pending = expect_observation(
        driver
            .drive(
                &mut lifecycle,
                &input,
                &context(),
                QemuFreshStartMaterialization::genesis(),
            )
            .expect("terminal guest-measured stop"),
    );
    let product = driver
        .seal(pending, Vec::new())
        .expect("verified guest measurement projection");
    let AttemptExecutionProduct::Observation(candidate) = product else {
        panic!("fresh modeled driver must return an observation")
    };
    let evaluation = candidate
        .measurements()
        .evaluation()
        .expect("verified evaluation payload");
    let payload = std::str::from_utf8(evaluation.payload()).expect("canonical evaluation JSON");

    assert!(payload.contains("\"driver-window\""));
    assert!(payload.contains("\"healthy-peers\""));
    assert!(payload.contains("\"scheduler-events\""));
    assert!(payload.contains("\"value\":3"));
}

#[test]
fn guest_measurement_messages_fail_closed_on_type_and_lifecycle_mismatch() {
    let fixture = crucible::happy_path_scenario().expect("happy-path fixture");
    let definitions = guest_measurement_definitions(&fixture.scenario);
    let node = fixture
        .scenario
        .world()
        .vm_nodes()
        .first()
        .expect("happy-path VM")
        .id
        .clone();
    let begin = SchedulerEventLogEntry::guest_measurement_observation(
        0,
        Icount { retired: 1 },
        node.clone(),
        GuestMeasurementEvent::Begin {
            measurement: String::from("driver-window"),
            instance: String::from("epoch-7"),
        },
    );
    let wrong_instance = SchedulerEventLogEntry::guest_measurement_observation(
        0,
        Icount { retired: 1 },
        node.clone(),
        GuestMeasurementEvent::Begin {
            measurement: String::from("driver-window"),
            instance: String::from("other-epoch"),
        },
    );
    let wrong_type = SchedulerEventLogEntry::guest_measurement_observation(
        1,
        Icount { retired: 2 },
        node,
        GuestMeasurementEvent::Sample {
            measurement: String::from("driver-window"),
            instance: String::from("epoch-7"),
            metric: String::from("healthy-peers"),
            value: GuestMeasurementValue::Boolean(true),
        },
    );
    let wrong_cohort_marker = SchedulerEventLogEntry::guest_semantic_marker_observation(
        0,
        Icount { retired: 1 },
        fixture.scenario.world().vm_nodes()[1].id.clone(),
        String::from("routing-converged"),
        String::from("epoch-7"),
        Vec::new(),
    );

    let error = normalize_guest_measurements(&definitions, &[begin.clone(), wrong_type])
        .expect_err("declared unsigned metric must reject a boolean");
    assert!(matches!(
        error,
        QemuFreshModeledDriverError::GuestMeasurementProtocol { sequence: 1, .. }
    ));

    let error = normalize_guest_measurements(&definitions, &[wrong_instance])
        .expect_err("a guest message must bind the declared exact instance");
    assert!(matches!(
        error,
        QemuFreshModeledDriverError::GuestMeasurementProtocol { sequence: 0, .. }
    ));

    let error = normalize_guest_measurements(&definitions, &[wrong_cohort_marker])
        .expect_err("a semantic marker must come from the declared cohort");
    assert!(matches!(
        error,
        QemuFreshModeledDriverError::GuestMeasurementProtocol { sequence: 0, .. }
    ));

    let error = normalize_guest_measurements(&definitions, &[begin])
        .expect_err("an open measurement instance must be closed");
    assert!(matches!(
        error,
        QemuFreshModeledDriverError::GuestMeasurementProtocol { sequence: 1, .. }
    ));
}

#[test]
fn named_boundary_requires_the_exact_guest_marker() {
    let input = input(StopCondition::NamedBoundary(String::from("target")));
    let configuration = starting_configuration(&input);
    let node = node("node-a");
    let mut log = EventLog::new();
    let wrong = log
        .append_observable_events([ObservableEvent::guest_marker(
            Icount { retired: 1 },
            node.clone(),
            MarkerId::from_name("other"),
        )])
        .expect("wrong marker segment");
    let target = log
        .append_observable_events([ObservableEvent::guest_marker(
            Icount { retired: 2 },
            node,
            MarkerId::from_name("target"),
        )])
        .expect("target marker segment");
    let mut owner = FakeLifecycle {
        outcomes: VecDeque::from([
            Ok(outcome(
                configuration.clone(),
                wrong.entries,
                wrong.offset,
                1,
            )),
            Ok(outcome(configuration, target.entries, target.offset, 2)),
        ]),
        terminal: None,
        drives: 0,
    };
    let mut lifecycle = QemuFreshAttemptLifecycle::new(&mut owner);

    QemuFreshModeledDriver::new()
        .drive(
            &mut lifecycle,
            &input,
            &context(),
            QemuFreshStartMaterialization::genesis(),
        )
        .expect("exact named boundary");

    assert_eq!(owner.drives, 2);
}

#[test]
fn virtual_time_boundary_stops_after_the_first_quantum_crossing_the_deadline() {
    let deadline = 2_000_000;
    let completed_frontier = deadline + 17;
    let input = input(StopCondition::VirtualTimeNanoseconds(deadline));
    let configuration = starting_configuration(&input);
    let mut owner = FakeLifecycle {
        outcomes: VecDeque::from([
            Ok(outcome(
                configuration.clone(),
                Vec::new(),
                EventLogOffset::default(),
                deadline - 1,
            )),
            Ok(outcome(
                configuration,
                Vec::new(),
                EventLogOffset::default(),
                completed_frontier,
            )),
        ]),
        terminal: None,
        drives: 0,
    };
    let mut lifecycle = QemuFreshAttemptLifecycle::new(&mut owner);

    let pending = expect_observation(
        QemuFreshModeledDriver::new()
            .drive(
                &mut lifecycle,
                &input,
                &context(),
                QemuFreshStartMaterialization::genesis(),
            )
            .expect("virtual-time boundary"),
    );

    assert_eq!(owner.drives, 2);
    assert!(matches!(
        pending.stop,
        ModeledStop::Reached(StopCondition::VirtualTimeNanoseconds(value)) if value == deadline
    ));
    assert_eq!(pending.terminal_at.ticks, completed_frontier);
}

#[test]
fn scheduler_operational_class_survives_the_concrete_driver() {
    let input = input(StopCondition::Terminal);
    let mut owner = FakeLifecycle {
        outcomes: VecDeque::from([Err(SchedulerError::OperationalBoundary {
            class: SchedulerOperationalFailureClass::Retryable,
            message: String::from("temporary host pressure"),
        })]),
        terminal: None,
        drives: 0,
    };
    let mut lifecycle = QemuFreshAttemptLifecycle::new(&mut owner);

    let error = QemuFreshModeledDriver::new()
        .drive(
            &mut lifecycle,
            &input,
            &context(),
            QemuFreshStartMaterialization::genesis(),
        )
        .expect_err("retryable scheduler boundary");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Retryable(QemuFreshModeledDriverError::Scheduler(
            SchedulerError::OperationalBoundary {
                class: SchedulerOperationalFailureClass::Retryable,
                ..
            }
        ))
    ));
}

#[test]
fn next_choice_retains_the_complete_discovery_bundle() {
    let input = input(StopCondition::NextChoice);
    let configuration = starting_configuration(&input);
    let discovery = choice_discovery(input.lineage().scenario());
    let opportunity = discovery.opportunity().id().expect("opportunity id");
    let mut quantum = outcome(configuration, Vec::new(), EventLogOffset::default(), 1);
    quantum.discovered_choices.push(discovery);
    let mut owner = FakeLifecycle {
        outcomes: VecDeque::from([Ok(quantum)]),
        terminal: None,
        drives: 0,
    };
    let mut lifecycle = QemuFreshAttemptLifecycle::new(&mut owner);
    let mut driver = QemuFreshModeledDriver::new();

    let pending = expect_observation(
        driver
            .drive(
                &mut lifecycle,
                &input,
                &context(),
                QemuFreshStartMaterialization::genesis(),
            )
            .expect("next-choice stop"),
    );
    let product = driver.seal(pending, Vec::new()).expect("choice candidate");
    let AttemptExecutionProduct::Observation(candidate) = product else {
        panic!("fresh modeled driver must return an observation")
    };

    assert_eq!(
        candidate.observation().stop(),
        &StopOutcome::Reached(StopCondition::NextChoice)
    );
    assert_eq!(
        candidate.observation().discovered_choices(),
        &BTreeSet::from([opportunity])
    );
    assert_eq!(candidate.discovered_choices().len(), 1);
}

#[test]
fn next_choice_publishes_the_live_signal_fault_frontier_at_its_exact_parent() {
    let input = input(StopCondition::NextChoice);
    let configuration = starting_configuration(&input);
    let discovery = signal_fault_choice_discovery(&configuration, 1);
    let opportunity = discovery.opportunity().id().expect("opportunity id");
    let mut quantum = outcome(
        configuration.clone(),
        Vec::new(),
        EventLogOffset::default(),
        1,
    );
    quantum.discovered_choices.push(discovery);
    let mut owner = FakeLifecycle {
        outcomes: VecDeque::from([Ok(quantum)]),
        terminal: None,
        drives: 0,
    };
    let mut lifecycle = QemuFreshAttemptLifecycle::new(&mut owner);
    let mut driver = QemuFreshModeledDriver::new();

    let pending = expect_observation(
        driver
            .drive(
                &mut lifecycle,
                &input,
                &context(),
                QemuFreshStartMaterialization::genesis(),
            )
            .expect("live signal-fault choice stop"),
    );
    let product = driver
        .seal(pending, Vec::new())
        .expect("live signal-fault candidate");
    let AttemptExecutionProduct::Observation(candidate) = product else {
        panic!("fresh modeled driver must return an observation")
    };

    assert_eq!(
        candidate.child().configuration(),
        configuration_id(&configuration)
    );
    assert_eq!(
        candidate.observation().stop(),
        &StopOutcome::Reached(StopCondition::NextChoice)
    );
    assert_eq!(
        candidate.observation().discovered_choices(),
        &BTreeSet::from([opportunity])
    );
    let [discovery] = candidate.discovered_choices() else {
        panic!("exactly one signal-fault choice must be published")
    };
    assert!(matches!(
        discovery.opportunity().source(),
        ChoiceSource::Environment { adapter, .. }
            if adapter == crucible::SIGNAL_FAULT_CAMPAIGN_ADAPTER
    ));
}

#[test]
fn signal_fault_frontier_is_not_published_after_execution_passes_it() {
    let input = input(StopCondition::NamedBoundary(String::from("target")));
    let configuration = starting_configuration(&input);
    let mut first = outcome(
        configuration.clone(),
        Vec::new(),
        EventLogOffset::default(),
        1,
    );
    first
        .discovered_choices
        .push(signal_fault_choice_discovery(&configuration, 1));
    let mut log = EventLog::new();
    let target = log
        .append_observable_events([ObservableEvent::guest_marker(
            Icount { retired: 2 },
            node("node-a"),
            MarkerId::from_name("target"),
        )])
        .expect("target marker segment");
    let second = outcome(configuration, target.entries, target.offset, 2);
    let mut owner = FakeLifecycle {
        outcomes: VecDeque::from([Ok(first), Ok(second)]),
        terminal: None,
        drives: 0,
    };
    let mut lifecycle = QemuFreshAttemptLifecycle::new(&mut owner);
    let mut driver = QemuFreshModeledDriver::new();

    let pending = expect_observation(
        driver
            .drive(
                &mut lifecycle,
                &input,
                &context(),
                QemuFreshStartMaterialization::genesis(),
            )
            .expect("later named boundary"),
    );
    let product = driver
        .seal(pending, Vec::new())
        .expect("non-retrospective candidate");
    let AttemptExecutionProduct::Observation(candidate) = product else {
        panic!("fresh modeled driver must return an observation")
    };

    assert_eq!(owner.drives, 2);
    assert!(candidate.discovered_choices().is_empty());
    assert!(candidate.observation().discovered_choices().is_empty());
}

#[test]
fn pending_guest_choice_stops_without_reply_and_retains_scenario_discovery() {
    let (input, node) = input_with_guest_selectable(StopCondition::NextChoice);
    let configuration = starting_configuration(&input);
    let mut owner = PendingSelectableLifecycle {
        outcome: Some(outcome(
            configuration.clone(),
            Vec::new(),
            EventLogOffset::default(),
            1,
        )),
        pending: vec![pending_guest_request(node, None)],
        replies: Vec::new(),
    };
    let pending = {
        let mut lifecycle = QemuFreshAttemptLifecycle::new(&mut owner);
        expect_observation(
            QemuFreshModeledDriver::new()
                .drive(
                    &mut lifecycle,
                    &input,
                    &context(),
                    QemuFreshStartMaterialization::genesis(),
                )
                .expect("guest choice discovery"),
        )
    };

    assert_eq!(pending.configuration, configuration);
    assert_eq!(pending.discoveries.len(), 1);
    assert!(owner.replies.is_empty());
}

#[test]
fn pending_guest_choice_applies_and_replies_with_exact_default() {
    let (input, node) = input_with_guest_selectable(StopCondition::EventCount(1));
    let configuration = starting_configuration(&input);
    let mut event_log = EventLog::new();
    let event = event_log
        .append_observable_events([ObservableEvent::guest_marker(
            Icount { retired: 41 },
            node.clone(),
            MarkerId::from_name("after-choice"),
        )])
        .expect("choice event");
    let mut owner = PendingSelectableLifecycle {
        outcome: Some(outcome(configuration, event.entries, event.offset, 41)),
        pending: vec![pending_guest_request(node, None)],
        replies: Vec::new(),
    };
    let pending = {
        let mut lifecycle = QemuFreshAttemptLifecycle::new(&mut owner);
        expect_observation(
            QemuFreshModeledDriver::new()
                .drive(
                    &mut lifecycle,
                    &input,
                    &context(),
                    QemuFreshStartMaterialization::genesis(),
                )
                .expect("guest default selection"),
        )
    };

    let decision = pending
        .configuration
        .schedule
        .decisions()
        .last()
        .expect("default selection decision");
    let Decision::Selection(decision) = decision else {
        panic!("guest default must append one typed selection")
    };
    let selection = decision.selection().expect("canonical guest selection");
    assert_eq!(selection.origin(), SelectionOrigin::Default);
    assert_eq!(selection.value(), &ChoiceValue::Boolean(false));
    assert_eq!(pending.discoveries.len(), 1);
    assert_eq!(owner.replies.len(), 1);
    assert_eq!(
        owner.replies[0].status(),
        crucible_protocol::SelectionReplyStatus::Selected
    );
    assert_eq!(
        owner.replies[0].selected_value(),
        Some(ChoiceValue::Boolean(false).canonical_bytes().as_slice())
    );
}

#[test]
fn terminal_run_projects_offline_property_verdicts() {
    let fixture = crucible::happy_path_scenario().expect("happy-path fixture");
    let input = input_for_scenario(fixture.scenario.clone(), StopCondition::Terminal);
    let configuration = starting_configuration(&input);
    let mut log = EventLog::new();
    let append = log
        .append_observable_events(fixture.observations().iter().cloned())
        .expect("happy-path event log");
    let mut quantum = outcome(configuration, append.entries, append.offset, 38);
    quantum.scheduler_quiescence = Some(SchedulerQuiescence::default());
    let mut owner = FakeLifecycle {
        outcomes: VecDeque::from([Ok(quantum)]),
        terminal: Some(QuantumTerminalVerdict::Passed),
        drives: 0,
    };
    let mut lifecycle = QemuFreshAttemptLifecycle::new(&mut owner);
    let mut driver = QemuFreshModeledDriver::new();

    let pending = expect_observation(
        driver
            .drive(
                &mut lifecycle,
                &input,
                &context(),
                QemuFreshStartMaterialization::genesis(),
            )
            .expect("terminal modeled stop"),
    );
    let product = driver
        .seal(pending, Vec::new())
        .expect("property projection");
    let AttemptExecutionProduct::Observation(candidate) = product else {
        panic!("fresh modeled driver must return an observation")
    };

    assert_eq!(
        candidate.observation().stop(),
        &StopOutcome::TerminalSuccess
    );
    assert_eq!(
        candidate
            .properties()
            .properties()
            .get("no-crashes")
            .expect("no-crashes verdict")
            .verdict(),
        PropertyVerdict::Passed
    );
    assert_eq!(
        candidate
            .properties()
            .properties()
            .get("all-requests-succeed")
            .expect("request verdict")
            .verdict(),
        PropertyVerdict::Passed
    );
}

#[test]
fn terminal_failure_preserves_grouped_reasons_in_scheduler_order() {
    let fixture = crucible::happy_path_scenario().expect("happy-path fixture");
    let input = input_for_scenario(fixture.scenario.clone(), StopCondition::Terminal);
    let configuration = starting_configuration(&input);
    let mut log = EventLog::new();
    let append = log
        .append_observable_events(fixture.observations().iter().cloned())
        .expect("happy-path event log");
    let mut quantum = outcome(configuration, append.entries, append.offset, 38);
    quantum.scheduler_quiescence = Some(SchedulerQuiescence::default());
    let reasons = vec![
        "later lexical reason".to_owned(),
        "earlier lexical reason".to_owned(),
        "later lexical reason".to_owned(),
    ];
    let mut owner = FakeLifecycle {
        outcomes: VecDeque::from([Ok(quantum)]),
        terminal: Some(QuantumTerminalVerdict::Failed(reasons.clone())),
        drives: 0,
    };
    let mut lifecycle = QemuFreshAttemptLifecycle::new(&mut owner);
    let mut driver = QemuFreshModeledDriver::new();

    let pending = expect_observation(
        driver
            .drive(
                &mut lifecycle,
                &input,
                &context(),
                QemuFreshStartMaterialization::genesis(),
            )
            .expect("terminal modeled failure"),
    );
    let product = driver
        .seal(pending, Vec::new())
        .expect("scenario failure projection");
    let AttemptExecutionProduct::Observation(candidate) = product else {
        panic!("fresh modeled driver must return an observation")
    };

    assert_eq!(
        candidate.observation().stop(),
        &StopOutcome::ScenarioFailure(reasons)
    );
}

#[test]
fn empty_terminal_failure_is_rejected() {
    assert!(matches!(
        modeled_terminal_stop(QuantumTerminalVerdict::Failed(Vec::new())),
        Err(QemuFreshModeledDriverError::EmptyScenarioFailure)
    ));
}

#[test]
fn non_dense_final_drain_is_rejected_before_candidate_construction() {
    let input = input(StopCondition::EventCount(1));
    let configuration = starting_configuration(&input);
    let mut log = EventLog::new();
    let first = log
        .append_observable_events([ObservableEvent::guest_marker(
            Icount { retired: 1 },
            node("node-a"),
            MarkerId::from_name("first"),
        )])
        .expect("first event-log segment");
    let mut owner = FakeLifecycle {
        outcomes: VecDeque::from([Ok(outcome(configuration, first.entries, first.offset, 1))]),
        terminal: None,
        drives: 0,
    };
    let mut lifecycle = QemuFreshAttemptLifecycle::new(&mut owner);
    let mut driver = QemuFreshModeledDriver::new();
    let pending = expect_observation(
        driver
            .drive(
                &mut lifecycle,
                &input,
                &context(),
                QemuFreshStartMaterialization::genesis(),
            )
            .expect("event-count stop"),
    );
    let invalid = SchedulerEventLogEntry::guest_marker_observation(
        7,
        Icount { retired: 2 },
        node("node-a"),
        MarkerId::from_name("late"),
    );

    let error = driver
        .seal(pending, vec![invalid])
        .expect_err("non-dense final suffix must fail closed");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(QemuFreshModeledDriverError::Assertions(_))
    ));
}

#[test]
fn retained_event_material_is_byte_bounded_before_append() {
    let entry = SchedulerEventLogEntry::guest_marker_observation(
        0,
        Icount { retired: 1 },
        node("node-a"),
        MarkerId::from_name("bounded"),
    );
    let mut event_log = Vec::new();
    let mut retained_bytes = MAX_QEMU_CAMPAIGN_EVENT_LOG_BYTES
        .checked_sub(entry.canonical_material_len())
        .expect("entry fits configured bound")
        + 1;

    let error = append_event_entries(&mut event_log, &mut retained_bytes, vec![entry])
        .expect_err("aggregate event material must be rejected before retention");

    assert!(matches!(
        error,
        QemuFreshModeledDriverError::LimitExceeded {
            limit: "fresh-campaign-event-log-bytes"
        }
    ));
    assert!(event_log.is_empty());
}

#[test]
fn retained_choices_share_contracts_and_charge_unique_records_once() {
    let scenario = ScenarioDefId::from_hash(CampaignHash::derive("fresh-driver-test", b"scenario"));
    let first = choice_discovery_named(scenario, "first");
    let second = choice_discovery_named(scenario, "second");
    let unshared_bytes = first.declaration().canonical_bytes().len()
        + first.domain().canonical_bytes().len()
        + first.opportunity().canonical_bytes().len()
        + second.declaration().canonical_bytes().len()
        + second.domain().canonical_bytes().len()
        + second.opportunity().canonical_bytes().len();
    let mut retained = RetainedChoiceDiscoveries::default();

    retained.insert(first).expect("first discovery");
    retained.insert(second).expect("second discovery");

    assert_eq!(retained.charged_records.len(), 4);
    assert!(retained.charged_bytes < unshared_bytes);
    assert_eq!(retained.representatives.len(), 1);
    assert_eq!(retained.discoveries.len(), 2);
}

fn input(stop: StopCondition) -> CrucibleAttemptExecution {
    let world = World::from_nodes_and_links(Vec::new(), Vec::new()).expect("empty world");
    let scenario = ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(7),
    )
    .expect("minimal scenario");
    input_for_scenario(scenario, stop)
}

fn input_with_guest_selectable(stop: StopCondition) -> (CrucibleAttemptExecution, NodeId) {
    let node = NodeId {
        name: String::from("router-a"),
    };
    let world = World::from_nodes(vec![WorldNode {
        id: node.clone(),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: String::from("guest-selectable-driver-test"),
        ready_point: ReadyPoint::FixedIcount {
            icount: Icount { retired: 1 },
        },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])
    .expect("guest selectable World");
    let declaration = SelectableDeclaration::new(
        "product.recovery",
        ChoiceSource::Guest {
            node: node.name.clone(),
            protocol_version: u32::from(crucible_protocol::SELECTABLE_PROTOCOL_VERSION),
        },
        ChoiceDomain::Boolean(BooleanDomain::new(1).expect("Boolean domain")),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::new()).expect("choice class"),
        BTreeSet::from([String::from("recovery")]),
        true,
    )
    .expect("guest selectable declaration");
    let selectables = ScenarioSelectables::new(
        &world,
        ScenarioSelectableLimits::new(4, 8, 16, 32).expect("selectable limits"),
        vec![declaration],
    )
    .expect("scenario selectables");
    let scenario = ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::from_u64(7),
    )
    .expect("guest selectable scenario")
    .with_selectables(selectables)
    .expect("attach guest selectables");
    (input_for_scenario(scenario, stop), node)
}

fn pending_guest_request(
    node: NodeId,
    narrowed: Option<Vec<u8>>,
) -> crucible_qemu::QemuNodeSelectablePendingRequest {
    let request = SelectionRequest::new(9, "product.recovery", "routing-epoch-7", narrowed, 256)
        .expect("guest selection request");
    crucible_qemu::QemuNodeSelectablePendingRequest::from_test_parts(
        node,
        SelectablePlanPendingRequest::new(request, 41, 0, 0x1000),
    )
}

fn input_for_scenario(scenario: ScenarioDefForm, stop: StopCondition) -> CrucibleAttemptExecution {
    let scenario_artifact =
        encode_crucible_scenario_artifact(&scenario).expect("scenario artifact");
    let scenario_id = ScenarioDefId::from_hash(CampaignHash::from_bytes(scenario.id().bytes));
    let scenario_content = scenario_artifact.id().expect("scenario artifact id");
    let configuration = Configuration::genesis(scenario.scenario_def());
    let configuration_artifact =
        encode_crucible_configuration_artifact(&scenario_artifact, &configuration.schedule)
            .expect("configuration artifact");
    let configuration_content = configuration_artifact
        .id()
        .expect("configuration artifact id");
    let path = BranchPath::new(Vec::new()).expect("genesis path");
    let attempt = Attempt::new(
        AttemptStart::Discover {
            configuration: configuration_content,
        },
        path.id().expect("path id"),
        stop,
    )
    .expect("attempt");
    let lineage = CampaignLineage::new(
        scenario_id,
        scenario_content,
        configuration_artifact.configuration(),
        configuration_content,
        "crucible-test",
        "qemu-test",
        BTreeMap::from([(String::from("control"), 1)]),
        1,
        1,
    )
    .expect("lineage");
    CrucibleAttemptExecution::from_test_parts(
        lineage,
        scenario,
        attempt,
        path,
        CrucibleResolvedAttemptStart::Discover { configuration },
    )
}

fn measured_scenario(base: &ScenarioDefForm) -> ScenarioDefForm {
    let node = base
        .world()
        .vm_nodes()
        .first()
        .expect("happy-path VM")
        .id
        .clone();
    let measurements = MeasurementDefinitions::new(
        base.world(),
        base.plan(),
        base.properties(),
        vec![MeasurementDefinition {
            id: MeasurementId::parse("driver-window").expect("measurement id"),
            begin: BoundarySelector::ScenarioGenesis,
            end: BoundarySelector::SchedulerQuiescence,
            timeout: None,
            cohort: CohortPolicy::All(vec![node]),
            metrics: vec![MetricDefinition {
                id: MetricId::parse("scheduler-events").expect("metric id"),
                value_type: MetricValueType::UnsignedInteger,
                unit: UnitId::parse("events").expect("unit id"),
                source: MetricSource::SchedulerEventCount,
                aggregation: Aggregation::Count,
            }],
        }],
    )
    .expect("measurement definitions");
    ScenarioDefForm::from_components_with_measurements_and_app_random_draw_cap(
        base.world(),
        base.plan(),
        base.properties(),
        &measurements,
        base.seed(),
        base.app_random_draw_cap(),
    )
    .expect("measured scenario")
}

fn guest_measurement_definitions(base: &ScenarioDefForm) -> MeasurementDefinitions {
    let world = white_box_world(base);
    let node = world.vm_nodes().first().expect("happy-path VM").id.clone();
    MeasurementDefinitions::new(
        &world,
        base.plan(),
        base.properties(),
        vec![MeasurementDefinition {
            id: MeasurementId::parse("driver-window").expect("measurement id"),
            begin: BoundarySelector::ScenarioGenesis,
            end: BoundarySelector::GuestMarker {
                marker: MarkerId::from_name("routing-converged"),
                instance: Some(
                    crucible::model::MeasurementInstanceKey::parse("epoch-7")
                        .expect("measurement instance"),
                ),
            },
            timeout: None,
            cohort: CohortPolicy::All(vec![node]),
            metrics: vec![
                MetricDefinition {
                    id: MetricId::parse("healthy-peers").expect("metric id"),
                    value_type: MetricValueType::UnsignedInteger,
                    unit: UnitId::parse("samples").expect("unit id"),
                    source: MetricSource::Guest,
                    aggregation: Aggregation::Sum,
                },
                MetricDefinition {
                    id: MetricId::parse("scheduler-events").expect("metric id"),
                    value_type: MetricValueType::UnsignedInteger,
                    unit: UnitId::parse("events").expect("unit id"),
                    source: MetricSource::SchedulerEventCount,
                    aggregation: Aggregation::Count,
                },
            ],
        }],
    )
    .expect("guest measurement definitions")
}

fn guest_measured_scenario(base: &ScenarioDefForm) -> ScenarioDefForm {
    let world = white_box_world(base);
    let measurements = guest_measurement_definitions(base);
    ScenarioDefForm::from_components_with_measurements_and_app_random_draw_cap(
        &world,
        base.plan(),
        base.properties(),
        &measurements,
        base.seed(),
        base.app_random_draw_cap(),
    )
    .expect("guest-measured scenario")
}

fn white_box_world(base: &ScenarioDefForm) -> World {
    let nodes = base
        .world()
        .vm_nodes()
        .iter()
        .cloned()
        .map(|mut node| {
            node.white_box = WhiteBoxPolicy::Enabled;
            node
        })
        .collect();
    World::from_nodes_and_links(nodes, base.world().links().to_vec()).expect("white-box test world")
}

fn choice_discovery(scenario: ScenarioDefId) -> ChoiceDiscovery {
    choice_discovery_named(scenario, "fresh-driver-choice")
}

fn choice_discovery_named(scenario: ScenarioDefId, instance: &str) -> ChoiceDiscovery {
    let domain = ChoiceDomain::Boolean(BooleanDomain::new(1).expect("Boolean domain"));
    let declaration = SelectableDeclaration::new(
        "product.test.fresh-driver",
        ChoiceSource::Scheduler {
            producer: String::from("fresh-driver-test"),
        },
        domain.clone(),
        ChoiceValue::Boolean(false),
        ChoiceClassContext::new(BTreeSet::new()).expect("choice class"),
        BTreeSet::new(),
        true,
    )
    .expect("choice declaration");
    let opportunity = ChoiceOpportunity::new(
        scenario,
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: CampaignHash::derive("fresh-driver-test", b"scheduler"),
            producer: CampaignHash::derive("fresh-driver-test", b"producer"),
        },
        instance,
        None,
    )
    .expect("choice opportunity");
    ChoiceDiscovery::new(declaration, domain, opportunity).expect("choice discovery")
}

fn signal_fault_choice_discovery(parent: &Configuration, ticks: u64) -> ChoiceDiscovery {
    let choice = crucible::model::BindingSearchChoice {
        id: crucible::model::SearchChoiceId::from_content_hash(crucible::ContentHash::from_bytes(
            b"fresh-driver-signal-choice",
        )),
        candidates_digest: crucible::ContentHash::from_bytes(b"fresh-driver-signal-candidates"),
        candidate_count: 2,
        selected_index: None,
        overridden: false,
    };
    let frontier = crucible::SearchRuntimeFrontier {
        configuration: parent.clone(),
        at: VirtualTime { ticks },
        choices: crucible::SearchFrontierChoices::from_decisions(
            choice
                .override_decisions(parent.id())
                .into_iter()
                .map(crucible::Decision::Override),
        ),
    };
    crucible::SignalFaultSelectable::from_frontier(&frontier)
        .and_then(|selectable| selectable.discovery())
        .expect("signal-fault discovery")
}

fn starting_configuration(input: &CrucibleAttemptExecution) -> Configuration {
    let CrucibleResolvedAttemptStart::Discover { configuration } = input.start() else {
        panic!("fresh driver fixture must be discovery")
    };
    configuration.clone()
}

fn configuration_id(configuration: &Configuration) -> ConfigurationId {
    ConfigurationId::from_hash(CampaignHash::from_bytes(configuration.id().bytes))
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn context() -> AttemptExecutionContext {
    AttemptExecutionContext::new(
        AttemptResourceLimits::new(1, 1024 * 1024, 0, 8).expect("resource limits"),
        ExecutionRetentionIntent::Discard,
        ExecutionCancellation::default(),
        ExecutionCheckpointRequest::default(),
    )
}

fn outcome(
    configuration: Configuration,
    event_log_entries: Vec<SchedulerEventLogEntry>,
    event_log_offset: EventLogOffset,
    ticks: u64,
) -> QuantumOutcome {
    QuantumOutcome {
        configuration,
        frontier: VirtualTime { ticks },
        advanced_node: None,
        resolved_events: Vec::new(),
        decisions: Vec::new(),
        discovered_choices: Vec::new(),
        event_log_entries,
        event_log_segment_bytes: Vec::new(),
        event_log_segment_text: String::new(),
        event_log_segment_hash: None,
        event_log_offset,
        scheduler_quiescence: None,
    }
}
