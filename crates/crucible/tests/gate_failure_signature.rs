//! Gates deterministic failure signatures computed from recorded artifacts.

#![forbid(unsafe_code)]
// crucible-lint: allow panic-shortcut -- test assertions use panic shortcuts for fixture setup and failure localization.
#![allow(clippy::expect_used, clippy::unwrap_used)]

use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;

use crucible::test_support::condition_observation_entry_for_test;
use crucible::{
    AssertionId, AssertionPhase, AssertionQuantifierKind, ChoiceTag, Configuration, ContentHash,
    DagStore, Decision, EngineError, EventLogCausalDivergencePoint, EventLogIcountStamp,
    EventLogOffset, EventLogTime, EventPayload, EventSource, FailureCausalCone,
    FailureClusterFinding, FailureClusterReport, FailureClusterReportDivergence,
    FailureClusterReportFailure, FailureClusterReportFormat, FailureClusterReportSet,
    FailureClusteringResult, FailureFindingsLedger, FailureKind, FailureMinimizationDisposition,
    FailurePropertyViolationRecord, FailureRecordedEventLog, FailureSignature,
    FailureSignatureNormalization, FailureSignaturePreservingMinimizationResult,
    FailureSignaturePreservingMinimizationRun, FailureTimeoutBudgetKind, FailureTimeoutRecord,
    FailureTriageReplayEvidence, FailureTriageResult, FailureTriageResultIdentity,
    FailureTriageSignatureSelfCheck, FailureTriageSignatureSelfCheckInput, FindingDiscoveryPath,
    FindingReproductionArtifact, HostAssertionViolation, Icount, MarkerId, MemoryDagStore,
    MinimizationConfig, MinimizationRun, NodeId, NodeLifecycle, NodeTemplate, ObservableEvent,
    OverrideDecision, Plan, Properties, ReadyPoint, ScenarioDefForm, Schedule,
    SchedulerEvaluationBoundaryKind, SchedulerEventLogClass, SchedulerEventLogEntry,
    SchedulerEventLogPayload, SchedulingPoint, Seed, SignaturePolicy, SignaturePolicyLevel,
    SymmetryClassId, SymmetryReductionClasses, VirtualTime, WhiteBoxPolicy, World, WorldNode,
};

#[test]
fn failure_triage_replay_evidence_round_trips_and_enforces_bounds() -> Result<(), Box<dyn Error>> {
    let scenario = scenario_form()?;
    let schedule = Schedule::from_decisions([override_decision("triage-decision", "fail")]);
    let finding = finding_artifact(
        &scenario,
        schedule.clone(),
        FindingDiscoveryPath::StateSpaceSearch,
        finding_hash("replay-evidence"),
    )?;
    let causal_entries = recorded_event_log(schedule.clone().decisions()[0].clone());
    let coverage_fingerprint = finding_hash("replay-evidence-coverage");
    let failure =
        FailureClusterReportFailure::property(property_violation_record(finding.artifact.id()));
    let evidence = FailureTriageReplayEvidence::new(
        finding.clone(),
        failure.clone(),
        causal_entries.clone(),
        coverage_fingerprint,
        vec![b"retained transport frame".to_vec()],
    )?;
    let bytes = evidence.to_compact_binary()?;
    let historical_v1 = include_bytes!("fixtures/failure-triage-replay-evidence-v1.bin");
    assert_eq!(bytes.as_slice(), historical_v1);
    let decoded = FailureTriageReplayEvidence::from_compact_binary(finding.clone(), historical_v1)?;

    assert_eq!(decoded, evidence);
    assert_eq!(decoded.schema_version(), 1);
    assert!(FailureTriageReplayEvidence::supports_schema(1));
    assert_eq!(decoded.to_compact_binary()?, bytes);
    assert_eq!(decoded.finding(), &finding);
    assert_eq!(decoded.failure(), &failure);
    assert_eq!(decoded.causal_entries(), causal_entries);
    assert_eq!(decoded.coverage_fingerprint(), coverage_fingerprint);
    assert_eq!(
        decoded.recorded_event_frames(),
        [b"retained transport frame".to_vec()]
    );
    assert_eq!(decoded.signature(), evidence.signature());

    let wrong_finding = finding_artifact(
        &scenario,
        schedule,
        FindingDiscoveryPath::CoverageGuidedFuzzing,
        finding_hash("another-replay-evidence"),
    )?;
    assert!(
        FailureTriageReplayEvidence::from_compact_binary(wrong_finding, &bytes).is_err(),
        "the payload must bind its exact finding identity"
    );

    let mut tampered = bytes.clone();
    let last = tampered.last_mut().ok_or("evidence cannot be empty")?;
    *last ^= 1;
    assert!(
        FailureTriageReplayEvidence::from_compact_binary(finding.clone(), &tampered).is_err(),
        "signature-material tampering must be rejected"
    );

    let too_many_entries = vec![causal_entries[0].clone(); 65_537];
    assert!(
        FailureTriageReplayEvidence::new(
            finding.clone(),
            failure.clone(),
            too_many_entries,
            coverage_fingerprint,
            Vec::new(),
        )
        .is_err(),
        "causal entry count must be checked before projection"
    );
    assert!(
        FailureTriageReplayEvidence::new(
            finding.clone(),
            failure.clone(),
            causal_entries.clone(),
            coverage_fingerprint,
            vec![vec![0; 1024 * 1024 + 1]],
        )
        .is_err(),
        "a retained frame cannot exceed its individual bound"
    );

    let mut oversized_failure = property_violation_record(finding.artifact.id());
    oversized_failure.violation.detail = "x".repeat(1024 * 1024);
    assert!(
        FailureTriageReplayEvidence::new(
            finding,
            FailureClusterReportFailure::property(oversized_failure),
            causal_entries,
            coverage_fingerprint,
            Vec::new(),
        )
        .is_err(),
        "failure-source material must be bounded before signature construction"
    );

    Ok(())
}

#[test]
fn paired_divergence_evidence_retains_both_logs_and_recomputes_mismatch()
-> Result<(), Box<dyn Error>> {
    let scenario = scenario_form()?;
    let schedule = Schedule::from_decisions([override_decision("triage-divergence", "fail")]);
    let finding = finding_artifact(
        &scenario,
        schedule.clone(),
        FindingDiscoveryPath::StateSpaceSearch,
        finding_hash("paired-divergence-evidence"),
    )?;
    let expected = recorded_event_log(schedule.decisions()[0].clone());
    let mut reproduced = expected.clone();
    reproduced.pop();
    let coverage_fingerprint = finding_hash("paired-divergence-coverage");

    let evidence = FailureTriageReplayEvidence::new_paired_divergence(
        finding.clone(),
        expected.clone(),
        reproduced.clone(),
        coverage_fingerprint,
        Vec::new(),
    )?;
    let bytes = evidence.to_compact_binary()?;
    let decoded = FailureTriageReplayEvidence::from_compact_binary(finding, &bytes)?;

    assert_eq!(decoded.schema_version(), 2);
    assert!(matches!(
        decoded.failure(),
        FailureClusterReportFailure::Divergence(_)
    ));
    assert_eq!(
        decoded.paired_divergence_logs(),
        Some((expected.as_slice(), reproduced.as_slice()))
    );
    assert_eq!(decoded.to_compact_binary()?, bytes);
    let marker = b"entry.content_hash=";
    let marker_offset = bytes
        .windows(marker.len())
        .position(|window| window == marker)
        .ok_or("paired divergence summary marker")?;
    let mut tampered = bytes.clone();
    let digit = tampered
        .get_mut(marker_offset + marker.len())
        .ok_or("paired divergence summary digit")?;
    *digit = if *digit == b'0' { b'1' } else { b'0' };
    assert!(
        FailureTriageReplayEvidence::from_compact_binary(decoded.finding().clone(), &tampered)
            .is_err(),
        "decode must reject divergence detail that differs from the paired logs"
    );
    assert!(
        FailureTriageReplayEvidence::new_paired_divergence(
            decoded.finding().clone(),
            expected.clone(),
            expected,
            coverage_fingerprint,
            Vec::new(),
        )
        .is_err()
    );

    Ok(())
}

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
        FindingDiscoveryPath::CampaignFork,
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
fn timeout_signature_keys_stable_budget_domain_not_numeric_counters() -> Result<(), Box<dyn Error>>
{
    let scenario = scenario_form()?;
    let finding = finding_artifact(
        &scenario,
        Schedule::empty(),
        FindingDiscoveryPath::CoverageGuidedFuzzing,
        finding_hash("timeout"),
    )?;
    let at = VirtualTime { ticks: 41 };
    let entries = vec![SchedulerEventLogEntry::execution_budget_exhausted(
        0,
        at,
        "execution-quanta",
    )];
    let recorded_log = FailureRecordedEventLog::from_causal_entries_and_coverage(
        &finding,
        &entries,
        finding_hash("timeout-coverage"),
    )?;
    let first = FailureTimeoutRecord::new(
        FailureTimeoutBudgetKind::ExecutionQuanta,
        Some(100),
        100,
        at,
        None,
        None,
        finding.artifact.id(),
    );
    let second = FailureTimeoutRecord::new(
        FailureTimeoutBudgetKind::ExecutionQuanta,
        Some(200),
        173,
        at,
        None,
        None,
        finding.artifact.id(),
    );

    let first_signature = FailureSignature::from_recorded_timeout(&finding, &recorded_log, &first)?;
    let second_signature =
        FailureSignature::from_recorded_timeout(&finding, &recorded_log, &second)?;

    assert_eq!(first_signature.failure_kind, FailureKind::Timeout);
    assert!(first_signature.property.is_none());
    assert_eq!(first_signature, second_signature);
    assert_eq!(
        first_signature.first_failing_point.event_kind,
        "execution_budget_exhausted"
    );
    Ok(())
}

#[test]
fn timeout_signature_validates_boundary_and_normalizes_symmetric_nodes()
-> Result<(), Box<dyn Error>> {
    let scenario = scenario_form()?;
    let finding = finding_artifact(
        &scenario,
        Schedule::empty(),
        FindingDiscoveryPath::StateSpaceSearch,
        finding_hash("timeout-normalization"),
    )?;
    let at = VirtualTime { ticks: 51 };
    let replica_class = SymmetryClassId {
        name: String::from("replicas"),
    };
    let normalization = FailureSignatureNormalization::identity().with_symmetry_classes(
        SymmetryReductionClasses::new()
            .with_node_class(node("replica-a"), replica_class.clone())
            .with_node_class(node("replica-b"), replica_class),
    );
    let evidence_for = |node_id: NodeId| {
        let time = EventLogTime {
            virtual_time: at,
            icount: EventLogIcountStamp {
                node: Some(node_id.clone()),
                icount: icount(71),
            },
        };
        let entries = vec![
            SchedulerEventLogEntry::execution_budget_exhausted_with_time(
                0,
                time,
                "execution-quanta",
            ),
        ];
        let log = FailureRecordedEventLog::from_causal_entries_and_coverage(
            &finding,
            &entries,
            finding_hash("timeout-normalization-coverage"),
        )?;
        let timeout = FailureTimeoutRecord::new(
            FailureTimeoutBudgetKind::ExecutionQuanta,
            Some(100),
            100,
            at,
            Some(icount(71)),
            Some(node_id),
            finding.artifact.id(),
        );
        Ok::<_, EngineError>((log, timeout))
    };
    let (replica_a_log, replica_a) = evidence_for(node("replica-a"))?;
    let (replica_b_log, replica_b) = evidence_for(node("replica-b"))?;
    let replica_a_signature = FailureSignature::from_recorded_timeout_with_normalization(
        &finding,
        &replica_a_log,
        &replica_a,
        &normalization,
    )?;
    let replica_b_signature = FailureSignature::from_recorded_timeout_with_normalization(
        &finding,
        &replica_b_log,
        &replica_b,
        &normalization,
    )?;
    assert_eq!(
        replica_a_signature.first_failing_point.faulting_node,
        replica_b_signature.first_failing_point.faulting_node
    );

    let wrong_kind = FailureTimeoutRecord::new(
        FailureTimeoutBudgetKind::VirtualTime,
        Some(51),
        100,
        at,
        Some(icount(71)),
        Some(node("replica-a")),
        finding.artifact.id(),
    );
    assert!(
        FailureSignature::from_recorded_timeout(&finding, &replica_a_log, &wrong_kind).is_err()
    );
    let wrong_node = FailureTimeoutRecord::new(
        FailureTimeoutBudgetKind::ExecutionQuanta,
        Some(100),
        100,
        at,
        Some(icount(71)),
        Some(node("replica-b")),
        finding.artifact.id(),
    );
    assert!(
        FailureSignature::from_recorded_timeout(&finding, &replica_a_log, &wrong_node).is_err()
    );
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
fn failure_clustering_partitions_and_orders_by_signature_key() -> Result<(), Box<dyn Error>> {
    let scenario = scenario_form()?;
    let schedule = Schedule::from_decisions([override_decision("triage-decision", "fail")]);
    let finding = finding_artifact(
        &scenario,
        schedule.clone(),
        FindingDiscoveryPath::StateSpaceSearch,
        finding_hash("cluster-source"),
    )?;
    let entries = recorded_event_log(schedule.decisions()[0].clone());
    let recorded_log = recorded_event_log_for_finding(&finding, &entries)?;
    let record = property_violation_record(finding.artifact.id());
    let base_signature =
        FailureSignature::from_recorded_property_violation(&finding, &recorded_log, &record)?;

    let mut same_default_key = base_signature.clone();
    same_default_key.causal_slice_hash = Some(finding_hash("different-fine-path"));

    let mut different_default_key = base_signature.clone();
    different_default_key
        .property
        .as_mut()
        .ok_or("property signature must carry a property key")?
        .quantifier = AssertionQuantifierKind::Sometimes;

    let member_a = finding_hash("member-a");
    let member_b = finding_hash("member-b");
    let member_c = finding_hash("member-c");
    let inputs = vec![
        FailureClusterFinding::new(member_c, different_default_key.clone()),
        FailureClusterFinding::new(member_b, same_default_key.clone()),
        FailureClusterFinding::new(member_a, base_signature.clone()),
    ];
    let reversed_inputs = inputs.iter().cloned().rev().collect::<Vec<_>>();
    let policy = SignaturePolicy::default();

    let clustered = FailureClusteringResult::from_findings(policy, inputs.clone())?;
    let reclustered = FailureClusteringResult::from_findings(policy, reversed_inputs)?;
    assert_eq!(clustered, reclustered);
    assert_eq!(clustered.content_hash(), reclustered.content_hash());
    assert_eq!(clustered.cluster_count(), 2);
    assert_eq!(clustered.member_count(), 3);

    let cluster_ids = clustered
        .clusters
        .iter()
        .map(|cluster| cluster.id)
        .collect::<Vec<_>>();
    let mut sorted_cluster_ids = cluster_ids.clone();
    sorted_cluster_ids.sort();
    assert_eq!(cluster_ids, sorted_cluster_ids);

    let base_key = base_signature.signature_key(policy)?;
    let base_cluster = clustered
        .clusters
        .iter()
        .find(|cluster| cluster.id == base_key.content_hash())
        .ok_or("default cluster must exist")?;
    assert_eq!(base_cluster.id, base_cluster.signature_key.content_hash());
    assert_eq!(base_cluster.members.len(), 2);
    assert_eq!(
        base_cluster
            .representative_member()
            .map(|member| member.reproduction_artifact),
        base_cluster.member_hashes().first().copied()
    );
    let member_hashes = base_cluster.member_hashes();
    let mut sorted_member_hashes = member_hashes.clone();
    sorted_member_hashes.sort();
    assert_eq!(member_hashes, sorted_member_hashes);
    assert!(base_cluster.members.iter().all(|member| {
        member
            .signature
            .signature_key(policy)
            .map(|key| key.content_hash() == base_cluster.id)
            .unwrap_or(false)
    }));

    let coarse_clustered =
        FailureClusteringResult::from_findings(SignaturePolicy::coarse(), inputs.clone())?;
    assert_eq!(
        coarse_clustered.cluster_count(),
        1,
        "coarse clusters by failure kind and property id only"
    );

    let fine_clustered =
        FailureClusteringResult::from_findings(SignaturePolicy::fine(), inputs.clone())?;
    assert_eq!(
        fine_clustered.cluster_count(),
        3,
        "fine separates the causal slice hash"
    );
    assert!(
        clustered
            .canonical_material()
            .contains("cluster.signature_key_BEGIN")
    );
    assert!(
        clustered
            .canonical_material()
            .contains("cluster.member.reproduction_artifact")
    );

    let mut conflicting_signature = base_signature.clone();
    conflicting_signature
        .property
        .as_mut()
        .ok_or("property signature must carry a property key")?
        .id = assertion_id("different-property");
    let conflict = FailureClusteringResult::from_findings(
        policy,
        [
            FailureClusterFinding::new(member_a, base_signature),
            FailureClusterFinding::new(member_a, conflicting_signature),
        ],
    )
    .expect_err("same reproduction artifact cannot carry conflicting signatures");
    assert!(matches!(
        conflict,
        EngineError::UnifiedOperationEvidenceMismatch { .. }
    ));

    let mut report_only_conflict = same_default_key.clone();
    report_only_conflict.at_icount_report_only = Some(icount(1234));
    assert_eq!(
        same_default_key.signature_key(policy)?.content_hash(),
        report_only_conflict.signature_key(policy)?.content_hash(),
        "the duplicate report-material guard must cover same-key evidence drift"
    );
    assert_ne!(
        same_default_key.report_material(),
        report_only_conflict.report_material()
    );
    let report_only_conflict_error = FailureClusteringResult::from_findings(
        policy,
        [
            FailureClusterFinding::new(member_b, same_default_key),
            FailureClusterFinding::new(member_b, report_only_conflict),
        ],
    )
    .expect_err("same-key duplicate artifact with different report material must be rejected");
    assert!(matches!(
        report_only_conflict_error,
        EngineError::UnifiedOperationEvidenceMismatch { .. }
    ));

    Ok(())
}

#[path = "gate_failure_signature/artifacts.rs"]
mod artifacts;
#[path = "gate_failure_signature/minimization.rs"]
mod minimization;
#[path = "gate_failure_signature/support.rs"]
mod support;

use support::*;
