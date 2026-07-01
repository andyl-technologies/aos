//! Gates deterministic failure signatures computed from recorded artifacts.

#![forbid(unsafe_code)]

use std::error::Error;

use crucible::test_support::condition_observation_entry_for_test;
use crucible::{
    AssertionId, AssertionPhase, AssertionQuantifierKind, ChoiceTag, Configuration, ContentHash,
    Decision, EngineError, EventLogCausalDivergencePoint, EventLogIcountStamp, EventLogOffset,
    EventSource, FailureKind, FailurePropertyViolationRecord, FailureRecordedEventLog,
    FailureSignature, FindingDiscoveryPath, FindingReproductionArtifact, HostAssertionViolation,
    Icount, MarkerId, NodeId, NodeTemplate, ObservableEvent, OverrideDecision, Plan, Properties,
    ReadyPoint, ScenarioDefForm, Schedule, SchedulingPoint, Seed, VirtualTime, WhiteBoxPolicy,
    World, WorldNode,
};

#[test]
fn failure_signature_uses_recorded_tuple_not_discovery_campaign() -> Result<(), Box<dyn Error>> {
    let scenario = scenario_form()?;
    let schedule = Schedule::from_decisions([override_decision("triage-decision", "fail")]);
    let coverage_entries = recorded_event_log(schedule.decisions()[0].clone());
    let first = finding_artifact(
        &scenario,
        schedule.clone(),
        FindingDiscoveryPath::StateSpaceSearch,
        finding_hash("state-search"),
    )?;
    let second = finding_artifact(
        &scenario,
        schedule,
        FindingDiscoveryPath::CoverageGuidedFuzzing,
        finding_hash("coverage-fuzz"),
    )?;
    let first_log = recorded_event_log_for_finding(&first, &coverage_entries)?;
    let second_log = recorded_event_log_for_finding(&second, &coverage_entries)?;
    let first_record = property_violation_record(first.artifact.id());
    let second_record = property_violation_record(second.artifact.id());

    let first_signature =
        FailureSignature::from_recorded_property_violation(&first, &first_log, &first_record)?;
    let second_signature =
        FailureSignature::from_recorded_property_violation(&second, &second_log, &second_record)?;

    assert_ne!(first.discovery_path, second.discovery_path);
    assert_ne!(first.finding_fingerprint, second.finding_fingerprint);
    assert_eq!(first_signature, second_signature);
    assert_eq!(
        first_signature.content_hash(),
        second_signature.content_hash()
    );
    assert_eq!(first_signature.failure_kind, FailureKind::PropertyViolation);
    assert_eq!(
        first_signature
            .property
            .as_ref()
            .map(|property| &property.id),
        Some(&assertion_id("no-forbidden-marker"))
    );
    assert_eq!(
        first_signature
            .property
            .as_ref()
            .map(|property| property.quantifier),
        Some(AssertionQuantifierKind::Always)
    );
    assert_eq!(
        first_signature.first_failing_point.event_kind,
        "assertion_state_changed"
    );
    assert_eq!(
        first_signature.first_failing_point.faulting_node.as_ref(),
        Some(&node("triage-node"))
    );
    assert!(
        first_signature
            .canonical_material()
            .contains("property_quantifier=always")
    );

    let mut noisy_entries = coverage_entries.clone();
    noisy_entries.insert(
        1,
        condition_observation_entry_for_test(
            99,
            &ObservableEvent::console_output(
                VirtualTime { ticks: 2 },
                node("triage-node"),
                b"operator-visible noise".to_vec(),
            ),
        ),
    );
    let noisy_log = recorded_event_log_for_finding(&first, &noisy_entries)?;
    let noisy_signature =
        FailureSignature::from_recorded_property_violation(&first, &noisy_log, &first_record)?;
    assert_eq!(
        noisy_signature.causal_slice_hash,
        first_signature.causal_slice_hash
    );
    assert_eq!(
        noisy_signature.coverage_class,
        first_signature.coverage_class
    );
    assert_eq!(
        noisy_signature.content_hash(),
        first_signature.content_hash()
    );
    assert!(first_signature.causal_slice_hash.is_none());

    Ok(())
}

#[test]
fn failure_signature_reads_divergence_bisection_point() -> Result<(), Box<dyn Error>> {
    let scenario = scenario_form()?;
    let schedule = Schedule::from_decisions([override_decision("triage-decision", "left")]);
    let finding = finding_artifact(
        &scenario,
        schedule.clone(),
        FindingDiscoveryPath::InteractiveFork,
        finding_hash("divergence"),
    )?;
    let entries = recorded_event_log(schedule.decisions()[0].clone());
    let recorded_log = recorded_event_log_for_finding(&finding, &entries)?;
    let divergence = EventLogCausalDivergencePoint {
        raw_index: 2,
        at: EventLogIcountStamp {
            node: None,
            icount: icount(8),
        },
        source: EventSource::Engine,
        kind: "assertion_state_changed".to_owned(),
    };

    let signature =
        FailureSignature::from_recorded_divergence(&finding, &recorded_log, &divergence)?;

    assert_eq!(signature.failure_kind, FailureKind::Divergence);
    assert!(signature.property.is_none());
    assert_eq!(
        signature.first_failing_point,
        crucible::FailureFirstFailingPoint {
            event_kind: "assertion_state_changed".to_owned(),
            faulting_node: None,
        }
    );
    assert!(signature.causal_slice_hash.is_none());
    assert_eq!(signature.content_hash(), signature.content_hash());

    Ok(())
}

#[test]
fn failure_signature_rejects_static_artifact_identity_mismatch() -> Result<(), Box<dyn Error>> {
    let scenario = scenario_form()?;
    let schedule = Schedule::from_decisions([override_decision("triage-decision", "fail")]);
    let entries = recorded_event_log(schedule.decisions()[0].clone());
    let mut finding = finding_artifact(
        &scenario,
        schedule,
        FindingDiscoveryPath::StateSpaceSearch,
        finding_hash("forged"),
    )?;
    finding.replay.schedule = finding_hash("wrong-schedule");
    let valid_finding = finding_artifact(
        &scenario,
        Schedule::from_decisions([override_decision("triage-decision", "fail")]),
        FindingDiscoveryPath::StateSpaceSearch,
        finding_hash("valid"),
    )?;
    let recorded_log = recorded_event_log_for_finding(&valid_finding, &entries)?;

    let error = FailureSignature::from_recorded_property_violation(
        &finding,
        &recorded_log,
        &property_violation_record(valid_finding.artifact.id()),
    )
    .expect_err("static schedule identity mismatch must be rejected");

    assert!(matches!(error, EngineError::ReplayTargetMismatch { .. }));

    Ok(())
}

#[test]
fn failure_signature_rejects_unbound_record_inputs() -> Result<(), Box<dyn Error>> {
    let scenario = scenario_form()?;
    let schedule = Schedule::from_decisions([override_decision("triage-decision", "fail")]);
    let finding = finding_artifact(
        &scenario,
        schedule.clone(),
        FindingDiscoveryPath::StateSpaceSearch,
        finding_hash("bound"),
    )?;
    let entries = recorded_event_log(schedule.decisions()[0].clone());
    let recorded_log = recorded_event_log_for_finding(&finding, &entries)?;
    let wrong_violation = property_violation_record(finding_hash("wrong-artifact"));

    let wrong_violation_error = FailureSignature::from_recorded_property_violation(
        &finding,
        &recorded_log,
        &wrong_violation,
    )
    .expect_err("violation record must be bound to the finding artifact");
    assert!(matches!(
        wrong_violation_error,
        EngineError::ReplayTargetMismatch { .. }
    ));

    let wrong_entries = recorded_event_log(override_decision("different-decision", "left"));
    let event_log_artifact = finding
        .artifact
        .event_log_debug_artifact(EventLogOffset::new(ContentHash::default(), 0, 0), &entries);
    let wrong_log_error = FailureRecordedEventLog::from_recorded_artifact(
        &finding,
        &event_log_artifact,
        &wrong_entries,
    )
    .expect_err("event log entries must match recorded event-log metadata");
    assert!(matches!(
        wrong_log_error,
        EngineError::ReplayTargetMismatch { .. }
    ));

    let mut coverage_tampered_entries = entries.clone();
    coverage_tampered_entries.insert(
        1,
        condition_observation_entry_for_test(
            77,
            &ObservableEvent::coverage_marker(
                icount(11),
                node("triage-node"),
                marker("coverage-added-after-recording"),
            ),
        ),
    );
    let coverage_tamper_error = FailureRecordedEventLog::from_recorded_artifact(
        &finding,
        &event_log_artifact,
        &coverage_tampered_entries,
    )
    .expect_err("coverage observations must match recorded event-log metadata");
    assert!(matches!(
        coverage_tamper_error,
        EngineError::ReplayTargetMismatch { .. }
    ));

    let absent_divergence = EventLogCausalDivergencePoint {
        raw_index: 99,
        at: EventLogIcountStamp {
            node: None,
            icount: icount(99),
        },
        source: EventSource::Engine,
        kind: "assertion_state_changed".to_owned(),
    };
    let absent_divergence_error =
        FailureSignature::from_recorded_divergence(&finding, &recorded_log, &absent_divergence)
            .expect_err("divergence point must exist in the recorded causal projection");
    assert!(matches!(
        absent_divergence_error,
        EngineError::UnifiedOperationEvidenceMismatch { .. }
    ));

    Ok(())
}

fn recorded_event_log(decision: Decision) -> Vec<crucible::SchedulerEventLogEntry> {
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
                VirtualTime { ticks: 8 },
                assertion_id("no-forbidden-marker"),
                AssertionPhase::Violated,
            ),
        ),
    ]
}

fn recorded_event_log_for_finding(
    finding: &FindingReproductionArtifact,
    entries: &[crucible::SchedulerEventLogEntry],
) -> Result<FailureRecordedEventLog, EngineError> {
    let event_log_artifact = finding
        .artifact
        .event_log_debug_artifact(EventLogOffset::new(ContentHash::default(), 0, 0), entries);
    FailureRecordedEventLog::from_recorded_artifact(finding, &event_log_artifact, entries)
}

fn property_violation_record(reproduction_artifact: ContentHash) -> FailurePropertyViolationRecord {
    FailurePropertyViolationRecord::new(HostAssertionViolation {
        assertion: assertion_id("no-forbidden-marker"),
        message: "forbidden marker must stay absent".to_owned(),
        quantifier: AssertionQuantifierKind::Always,
        event_kind: "assertion_state_changed".to_owned(),
        at_icount: Some(icount(8)),
        at_virtual_time: VirtualTime { ticks: 8 },
        node: Some(node("triage-node")),
        detail: "observed forbidden marker".to_owned(),
        reproduction_artifact,
    })
}

fn finding_artifact(
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

fn scenario_form() -> Result<ScenarioDefForm, EngineError> {
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

fn override_decision(point: &str, choice: &str) -> Decision {
    Decision::Override(OverrideDecision {
        point: SchedulingPoint {
            key: point.to_owned(),
        },
        choice: ChoiceTag {
            name: choice.to_owned(),
        },
    })
}

fn finding_hash(label: &str) -> ContentHash {
    ContentHash::from_canonical_material("crucible.test.failure-signature", label)
}

fn assertion_id(name: &str) -> AssertionId {
    AssertionId::from_name(name)
}

fn marker(name: &str) -> MarkerId {
    MarkerId::from_name(name)
}

fn node(name: &str) -> NodeId {
    NodeId {
        name: name.to_owned(),
    }
}

fn icount(retired: u64) -> Icount {
    Icount { retired }
}
