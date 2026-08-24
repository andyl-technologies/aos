// crucible-lint: allow panic-shortcut -- test fixtures use panic shortcuts.
#![allow(clippy::expect_used)]

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use crucible::model::{
    Aggregation, BoundarySelector, CohortPolicy, MeasurementDefinition, MeasurementDefinitions,
    MeasurementId, MetricDefinition, MetricId, MetricSource, MetricValueType, UnitId,
};
use crucible::{
    Configuration, EventLog, EventLogOffset, Icount, MarkerId, NodeId, ObservableEvent, Plan,
    Properties, QuantumOutcome, QuantumTerminalVerdict, ScenarioDefForm, SchedulerError,
    SchedulerEventLogEntry, SchedulerQuiescence, Seed, VirtualTime, World,
};
use crucible_campaign::{
    Attempt, AttemptResourceLimits, AttemptStart, BooleanDomain, BranchPath, CampaignHash,
    CampaignLineage, ChoiceClassContext, ChoiceCoordinate, ChoiceDiscovery, ChoiceDomain,
    ChoiceOpportunity, ChoiceSource, ChoiceValue, ConfigurationId, ExecutionRetentionIntent,
    PropertyVerdict, ScenarioDefId, SelectableDeclaration, StopCondition, StopOutcome,
};

use super::*;
use crate::{ExecutionCancellation, ExecutionCheckpointRequest, QemuFreshAttemptLifecycleOwner};

struct FakeLifecycle {
    outcomes: VecDeque<Result<QuantumOutcome, SchedulerError>>,
    terminal: Option<QuantumTerminalVerdict>,
    drives: usize,
}

impl QemuFreshAttemptLifecycleOwner for FakeLifecycle {
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
        Ok(false)
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

    let pending = driver
        .drive(
            &mut lifecycle,
            &input,
            &context(),
            QemuFreshStartMaterialization::from_test_parts(prefix.entries.clone(), None, None),
        )
        .expect("event-count stop");
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
fn measured_scenario_fails_closed_until_sample_producers_exist() {
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

    let pending = driver
        .drive(
            &mut lifecycle,
            &input,
            &context(),
            QemuFreshStartMaterialization::genesis(),
        )
        .expect("terminal modeled stop");
    let error = driver
        .seal(pending, Vec::new())
        .expect_err("measurement samples are not yet available");

    assert!(matches!(
        error,
        AttemptWorkerFailure::Terminal(
            QemuFreshModeledDriverError::MeasurementProducersUnavailable
        )
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

    let pending = driver
        .drive(
            &mut lifecycle,
            &input,
            &context(),
            QemuFreshStartMaterialization::genesis(),
        )
        .expect("next-choice stop");
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

    let pending = driver
        .drive(
            &mut lifecycle,
            &input,
            &context(),
            QemuFreshStartMaterialization::genesis(),
        )
        .expect("terminal modeled stop");
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
    let pending = driver
        .drive(
            &mut lifecycle,
            &input,
            &context(),
            QemuFreshStartMaterialization::genesis(),
        )
        .expect("event-count stop");
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
