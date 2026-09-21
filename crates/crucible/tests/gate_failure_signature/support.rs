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
    vec![
        crucible::test_support::condition_payload_entry_for_test(
            0,
            VirtualTime { ticks: 1 },
            crucible::SchedulerEventLogPayload::Decision(decision),
        ),
        condition_observation_entry_for_test(
            1,
            &ObservableEvent::coverage_marker(icount(7), node("triage-node"), marker("hot-path")),
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
    property_violation_record_for_node(reproduction_artifact, node("triage-node"))
}

pub(super) fn property_violation_record_for_node(
    reproduction_artifact: ContentHash,
    node: NodeId,
) -> FailurePropertyViolationRecord {
    property_violation_record_for_node_at(reproduction_artifact, node, 8)
}

pub(super) fn property_violation_record_for_node_at(
    reproduction_artifact: ContentHash,
    node: NodeId,
    assertion_ticks: u64,
) -> FailurePropertyViolationRecord {
    FailurePropertyViolationRecord::new(HostAssertionViolation {
        assertion: assertion_id("no-forbidden-marker"),
        message: "forbidden marker must stay absent".to_owned(),
        quantifier: AssertionQuantifierKind::Always,
        event_kind: "assertion_state_changed".to_owned(),
        at_icount: Some(icount(assertion_ticks)),
        at_virtual_time: VirtualTime {
            ticks: assertion_ticks,
        },
        node: Some(node),
        detail: "observed forbidden marker".to_owned(),
        reproduction_artifact,
    })
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
        icount_shift: NodeTemplate::DEFAULT_ICOUNT_SHIFT,
        kernel: None,
        root_image: None,
        initrd: None,
    }])?;
    ScenarioDefForm::from_components(
        &world,
        &Plan::empty(),
        &Properties::empty(),
        Seed::default(),
    )
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
