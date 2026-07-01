//! Gates deterministic failure signatures computed from recorded artifacts.

#![forbid(unsafe_code)]

use std::error::Error;

use crucible::test_support::condition_observation_entry_for_test;
use crucible::{
    AssertionId, AssertionPhase, AssertionQuantifierKind, ChoiceTag, Configuration, ContentHash,
    Decision, EngineError, EventLogCausalDivergencePoint, EventLogIcountStamp, EventLogOffset,
    EventSource, FailureCausalCone, FailureKind, FailurePropertyViolationRecord,
    FailureRecordedEventLog, FailureSignature, FailureSignatureNormalization,
    FailureTriageResultIdentity, FindingDiscoveryPath, FindingReproductionArtifact,
    HostAssertionViolation, Icount, MarkerId, NodeId, NodeTemplate, ObservableEvent,
    OverrideDecision, Plan, Properties, ReadyPoint, ScenarioDefForm, Schedule,
    SchedulerEvaluationBoundaryKind, SchedulingPoint, Seed, SignaturePolicy, SignaturePolicyLevel,
    SymmetryClassId, SymmetryReductionClasses, VirtualTime, WhiteBoxPolicy, World, WorldNode,
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
    assert!(first_signature.causal_slice_hash.is_some());

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
    assert!(signature.causal_slice_hash.is_some());
    assert_eq!(signature.content_hash(), signature.content_hash());

    Ok(())
}

#[test]
fn failure_signature_applies_t_tri_2_normalizations() -> Result<(), Box<dyn Error>> {
    let scenario = scenario_form()?;
    let schedule = Schedule::from_decisions([override_decision("triage-decision", "fail")]);
    let finding = finding_artifact(
        &scenario,
        schedule.clone(),
        FindingDiscoveryPath::StateSpaceSearch,
        finding_hash("normalization"),
    )?;
    let base_entries = recorded_event_log(schedule.decisions()[0].clone());
    let base_log = recorded_event_log_for_finding(&finding, &base_entries)?;
    let replica_class = SymmetryClassId {
        name: "replicas".to_owned(),
    };
    let normalization = FailureSignatureNormalization::identity().with_symmetry_classes(
        SymmetryReductionClasses::new()
            .with_node_class(node("replica-a"), replica_class.clone())
            .with_node_class(node("replica-b"), replica_class),
    );

    let replica_a = property_violation_record_for_node(finding.artifact.id(), node("replica-a"));
    let replica_b = property_violation_record_for_node(finding.artifact.id(), node("replica-b"));
    let replica_a_signature =
        FailureSignature::from_recorded_property_violation_with_normalization(
            &finding,
            &base_log,
            &replica_a,
            &normalization,
        )?;
    let replica_b_signature =
        FailureSignature::from_recorded_property_violation_with_normalization(
            &finding,
            &base_log,
            &replica_b,
            &normalization,
        )?;

    assert_eq!(
        replica_a_signature.first_failing_point.faulting_node,
        replica_b_signature.first_failing_point.faulting_node
    );
    assert_eq!(
        replica_a_signature.first_failing_point.faulting_node,
        Some(NodeId {
            name: "symmetry-class:8:replicas".to_owned(),
        })
    );
    assert_eq!(
        replica_a_signature.content_hash(),
        replica_b_signature.content_hash()
    );

    let mut shifted_icount = replica_a_signature.clone();
    shifted_icount.at_icount_report_only = Some(icount(9000));
    assert_ne!(
        shifted_icount.at_icount_report_only,
        replica_a_signature.at_icount_report_only
    );
    assert_eq!(
        shifted_icount.content_hash(),
        replica_a_signature.content_hash()
    );
    assert!(
        !replica_a_signature
            .canonical_material()
            .contains("at_icount_report_only")
    );
    assert!(
        replica_a_signature
            .report_material()
            .contains("at_icount_report_only=8")
    );

    let shifted_entries =
        recorded_event_log_with_assertion_time(schedule.decisions()[0].clone(), 88);
    let shifted_log = recorded_event_log_for_finding(&finding, &shifted_entries)?;
    let shifted_record =
        property_violation_record_for_node_at(finding.artifact.id(), node("replica-a"), 88);
    let shifted_log_signature =
        FailureSignature::from_recorded_property_violation_with_normalization(
            &finding,
            &shifted_log,
            &shifted_record,
            &normalization,
        )?;
    assert_ne!(
        shifted_log_signature.at_icount_report_only,
        replica_a_signature.at_icount_report_only
    );
    assert_eq!(
        shifted_log_signature.causal_slice_hash,
        replica_a_signature.causal_slice_hash
    );
    assert_eq!(
        shifted_log_signature.content_hash(),
        replica_a_signature.content_hash()
    );

    let mut prefailure_out_of_cone_entries = base_entries.clone();
    prefailure_out_of_cone_entries.insert(
        2,
        crucible::test_support::condition_boundary_entry_for_test(
            77,
            VirtualTime { ticks: 5 },
            SchedulerEvaluationBoundaryKind::Quantum,
        ),
    );
    let prefailure_out_of_cone_log =
        recorded_event_log_for_finding(&finding, &prefailure_out_of_cone_entries)?;
    let prefailure_out_of_cone_signature =
        FailureSignature::from_recorded_property_violation_with_normalization(
            &finding,
            &prefailure_out_of_cone_log,
            &replica_a,
            &normalization,
        )?;
    assert_ne!(
        base_log.causal_subsequence(),
        prefailure_out_of_cone_log.causal_subsequence()
    );
    assert_eq!(
        prefailure_out_of_cone_signature.causal_slice_hash,
        replica_a_signature.causal_slice_hash
    );
    assert_eq!(
        prefailure_out_of_cone_signature.content_hash(),
        replica_a_signature.content_hash()
    );

    let mut trailing_causal_entries = base_entries.clone();
    trailing_causal_entries.push(crucible::test_support::condition_boundary_entry_for_test(
        3,
        VirtualTime { ticks: 99 },
        SchedulerEvaluationBoundaryKind::Quantum,
    ));
    let trailing_log = recorded_event_log_for_finding(&finding, &trailing_causal_entries)?;
    let trailing_signature = FailureSignature::from_recorded_property_violation_with_normalization(
        &finding,
        &trailing_log,
        &replica_a,
        &normalization,
    )?;
    assert_ne!(
        base_log.causal_subsequence(),
        trailing_log.causal_subsequence()
    );
    assert_eq!(
        trailing_signature.causal_slice_hash,
        replica_a_signature.causal_slice_hash
    );
    assert_eq!(
        trailing_signature.content_hash(),
        replica_a_signature.content_hash()
    );

    Ok(())
}

#[test]
fn failure_signature_policy_projects_versioned_keys_and_result_identity()
-> Result<(), Box<dyn Error>> {
    let scenario = scenario_form()?;
    let schedule = Schedule::from_decisions([override_decision("triage-decision", "fail")]);
    let finding = finding_artifact(
        &scenario,
        schedule.clone(),
        FindingDiscoveryPath::StateSpaceSearch,
        finding_hash("signature-policy"),
    )?;
    let entries = recorded_event_log(schedule.decisions()[0].clone());
    let recorded_log = recorded_event_log_for_finding(&finding, &entries)?;
    let record = property_violation_record(finding.artifact.id());
    let signature =
        FailureSignature::from_recorded_property_violation(&finding, &recorded_log, &record)?;

    let coarse = SignaturePolicy::coarse();
    let default = SignaturePolicy::default();
    let fine = SignaturePolicy::fine();
    let exact = SignaturePolicy::exact();
    assert_eq!(default, SignaturePolicy::default_policy());
    assert_eq!(default.level(), SignaturePolicyLevel::Default);
    assert_eq!(coarse.schema_version(), 1);
    assert_eq!(
        default.coverage_class_algorithm(),
        signature.coverage_class.algorithm
    );
    assert!(default.allows_minimize_merge());
    assert!(!exact.allows_minimize_merge());
    assert!(!default.keys_absolute_icount());
    assert!(exact.keys_absolute_icount());
    assert!(fine.keys_causal_slice_hash());

    let base_coarse = signature.signature_key(coarse)?;
    let base_default = signature.signature_key(default)?;
    let base_fine = signature.signature_key(fine)?;
    let base_exact = signature.signature_key(exact)?;
    assert_ne!(base_coarse.content_hash(), base_default.content_hash());
    assert_eq!(base_default.policy(), default);
    assert!(
        base_exact
            .canonical_material()
            .contains("exact_causal_cone_material_BEGIN")
    );
    assert!(base_exact.canonical_material().contains("at_icount_key=8"));
    assert!(
        signature
            .report_material()
            .contains("causal_cone_material_BEGIN")
    );

    let mut changed_quantifier = signature.clone();
    changed_quantifier
        .property
        .as_mut()
        .ok_or("property signature must carry a property key")?
        .quantifier = AssertionQuantifierKind::Sometimes;
    assert_eq!(
        changed_quantifier.signature_key(coarse)?.content_hash(),
        base_coarse.content_hash(),
        "coarse keys only stable property id, not quantifier"
    );
    assert_ne!(
        changed_quantifier.signature_key(default)?.content_hash(),
        base_default.content_hash(),
        "default keys property quantifier"
    );

    let mut changed_coverage = signature.clone();
    changed_coverage.coverage_class.bucket = changed_coverage.coverage_class.bucket.wrapping_add(1);
    assert_eq!(
        changed_coverage.signature_key(coarse)?.content_hash(),
        base_coarse.content_hash(),
        "coarse does not key coverage class"
    );
    assert_ne!(
        changed_coverage.signature_key(default)?.content_hash(),
        base_default.content_hash(),
        "default keys coverage class"
    );

    let mut changed_slice = signature.clone();
    changed_slice.causal_slice_hash = Some(finding_hash("changed-causal-slice"));
    assert_eq!(
        changed_slice.signature_key(default)?.content_hash(),
        base_default.content_hash(),
        "default leaves the causal slice as detail"
    );
    assert_ne!(
        changed_slice.signature_key(fine)?.content_hash(),
        base_fine.content_hash(),
        "fine keys the causal slice hash"
    );

    let mut changed_cone_signature = signature.clone();
    changed_cone_signature.causal_cone = Some(FailureCausalCone::from_canonical_material(
        "causal_cone_events=1\nentry.cone_index=0\nentry.kind=exact-only-cone-change",
    ));
    assert_eq!(
        changed_cone_signature.signature_key(fine)?.content_hash(),
        base_fine.content_hash(),
        "fine keys the causal slice hash, not the full causal cone"
    );
    let changed_cone_exact = changed_cone_signature.signature_key(exact)?;
    assert_ne!(
        changed_cone_exact.content_hash(),
        base_exact.content_hash(),
        "exact keys the full causal-cone material"
    );
    assert_ne!(
        changed_cone_signature.causal_cone, signature.causal_cone,
        "the regression must mutate only the retained full causal cone"
    );
    assert!(
        changed_cone_exact
            .canonical_material()
            .contains("exact_causal_cone_material_BEGIN")
    );
    assert!(
        changed_cone_exact
            .canonical_material()
            .contains("exact-only-cone-change")
    );

    let mut shifted_icount = signature.clone();
    shifted_icount.at_icount_report_only = Some(icount(99));
    assert_eq!(
        shifted_icount.signature_key(fine)?.content_hash(),
        base_fine.content_hash(),
        "fine keeps absolute icount report-only"
    );
    assert_ne!(
        shifted_icount.signature_key(exact)?.content_hash(),
        base_exact.content_hash(),
        "exact keys absolute icount"
    );

    let ledger = finding_hash("findings-ledger");
    let default_identity = FailureTriageResultIdentity::new(ledger, default);
    let same_default_identity = FailureTriageResultIdentity::new(ledger, default);
    let fine_identity = FailureTriageResultIdentity::new(ledger, fine);
    assert_eq!(
        default_identity.content_hash(),
        same_default_identity.content_hash()
    );
    assert_ne!(
        default_identity.content_hash(),
        fine_identity.content_hash()
    );
    assert!(
        default_identity
            .canonical_material()
            .contains("signature_policy_level=default")
    );
    assert!(
        fine_identity
            .canonical_material()
            .contains(default.coverage_class_algorithm())
    );

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
    recorded_event_log_with_assertion_time(decision, 8)
}

fn recorded_event_log_with_assertion_time(
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
    property_violation_record_for_node(reproduction_artifact, node("triage-node"))
}

fn property_violation_record_for_node(
    reproduction_artifact: ContentHash,
    node: NodeId,
) -> FailurePropertyViolationRecord {
    property_violation_record_for_node_at(reproduction_artifact, node, 8)
}

fn property_violation_record_for_node_at(
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
