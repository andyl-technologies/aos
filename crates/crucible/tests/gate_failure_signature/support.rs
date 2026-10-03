//! Shared failure-signature integration-test fixtures.

use super::*;

pub(super) fn schedule_contains_override(schedule: &Schedule, point: &str, choice: &str) -> bool {
    schedule.decisions().iter().any(|decision| {
        matches!(
            decision,
            Decision::Override(override_decision)
                if override_decision.point.key == point && override_decision.choice.name == choice
        )
    })
}

pub(super) fn recorded_event_log(decision: Decision) -> Vec<crucible::SchedulerEventLogEntry> {
    recorded_event_log_with_assertion_time(decision, 8)
}

pub(super) fn recorded_event_log_with_assertion_time(
    decision: Decision,
    assertion_ticks: u64,
) -> Vec<crucible::SchedulerEventLogEntry> {
    let observed_marker = ObservableEvent::guest_marker(
        icount(assertion_ticks),
        node("triage-node"),
        marker("forbidden"),
    );
    vec![
        crucible::test_support::condition_payload_entry_for_test(
            0,
            VirtualTime { ticks: 1 },
            crucible::SchedulerEventLogPayload::Decision(decision),
        ),
        crucible::test_support::condition_payload_entry_for_test(
            1,
            VirtualTime {
                ticks: assertion_ticks,
            },
            SchedulerEventLogPayload::Observable(observed_marker.payload().clone()),
        ),
        condition_observation_entry_for_test(
            2,
            &ObservableEvent::assertion_state_changed(
                VirtualTime {
                    ticks: assertion_ticks,
                },
                assertion_id("no-forbidden-marker"),
                AssertionPhase::Violated,
            ),
        ),
    ]
}

pub(super) fn recorded_node_divergence_event_log(
    decision: Decision,
) -> Vec<crucible::SchedulerEventLogEntry> {
    let node_state = ObservableEvent::node_state(
        VirtualTime { ticks: 8 },
        node("triage-node"),
        NodeLifecycle::Started,
    );
    vec![
        crucible::test_support::condition_payload_entry_for_test(
            0,
            VirtualTime { ticks: 1 },
            SchedulerEventLogPayload::Decision(decision),
        ),
        crucible::test_support::condition_open_payload_entry_for_test(
            1,
            VirtualTime { ticks: 8 },
            SchedulerEventLogClass::Causal,
            EventPayload::new("node_state", BTreeMap::new()),
            SchedulerEventLogPayload::Observable(node_state.payload().clone()),
        ),
    ]
}

pub(super) fn recorded_event_log_for_finding(
    finding: &FindingReproductionArtifact,
    entries: &[crucible::SchedulerEventLogEntry],
) -> Result<FailureRecordedEventLog, EngineError> {
    let event_log_artifact = finding
        .artifact
        .event_log_debug_artifact(EventLogOffset::new(ContentHash::default(), 0, 0), entries);
    FailureRecordedEventLog::from_recorded_artifact(finding, &event_log_artifact, entries)
}

pub(super) fn property_violation_record(
    reproduction_artifact: ContentHash,
) -> FailurePropertyViolationRecord {
    property_violation_record_at(reproduction_artifact, 8)
}

pub(super) fn property_violation_record_at(
    reproduction_artifact: ContentHash,
    assertion_ticks: u64,
) -> FailurePropertyViolationRecord {
    let entries = recorded_event_log_with_assertion_time(
        override_decision("fixture-decision", "fixture-choice"),
        assertion_ticks,
    );
    property_violation_record_for_entries(reproduction_artifact, &entries)
}

pub(super) fn property_violation_record_for_entries(
    reproduction_artifact: ContentHash,
    entries: &[SchedulerEventLogEntry],
) -> FailurePropertyViolationRecord {
    let scenario = scenario_form().expect("failure-signature scenario must compile");
    let report = OfflineAssertionChecker::new()
        .with_world_white_box_policies(scenario.world())
        .check_run(scenario.properties(), entries)
        .expect("failure-signature fixture must replay");
    let mut violation = report
        .violations()
        .iter()
        .find(|violation| violation.assertion == assertion_id("no-forbidden-marker"))
        .expect("failure-signature fixture must violate declared property")
        .clone();
    violation.reproduction_artifact = reproduction_artifact;
    FailurePropertyViolationRecord::new(violation)
}

pub(super) fn finding_artifact(
    scenario: &ScenarioDefForm,
    schedule: Schedule,
    discovery_path: FindingDiscoveryPath,
    fingerprint: ContentHash,
) -> Result<FindingReproductionArtifact, EngineError> {
    let configuration = Configuration {
        def: scenario.scenario_def(),
        schedule,
    };
    FindingReproductionArtifact::capture(discovery_path, fingerprint, scenario, &configuration)
}

pub(super) fn scenario_form() -> Result<ScenarioDefForm, EngineError> {
    let world = World::from_nodes(vec![WorldNode {
        id: node("triage-node"),
        arch: NodeTemplate::DEFAULT_ARCH,
        memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
        cmdline: "crucible-failure-signature".to_owned(),
        ready_point: ReadyPoint::FixedIcount { icount: icount(1) },
        white_box: WhiteBoxPolicy::Enabled,
        smp_vcpus: NodeTemplate::DEFAULT_SMP_VCPUS,
        kernel: None,
        root_image: None,
        initrd: None,
    }])?;
    let properties = Properties::from_assertions_for_world(
        &world,
        vec![AssertionDef {
            id: assertion_id("no-forbidden-marker"),
            message: String::from("forbidden marker must stay absent"),
            property: Property::Always {
                predicate: Predicate::not(Predicate::guest_marker(marker("forbidden"))),
            },
        }],
    )?;
    ScenarioDefForm::from_components(&world, &Plan::empty(), &properties, Seed::default())
}

pub(super) fn override_decision(point: &str, choice: &str) -> Decision {
    Decision::Override(OverrideDecision {
        point: SchedulingPoint {
            key: point.to_owned(),
        },
        choice: ChoiceTag {
            name: choice.to_owned(),
        },
    })
}

pub(super) fn finding_hash(label: &str) -> ContentHash {
    ContentHash::from_canonical_material("crucible.test.failure-signature", label)
}

pub(super) fn assertion_id(name: &str) -> AssertionId {
    AssertionId::from_name(name)
}

pub(super) fn marker(name: &str) -> MarkerId {
    MarkerId::from_name(name)
}

pub(super) fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

pub(super) fn icount(retired: u64) -> Icount {
    Icount { retired }
}
