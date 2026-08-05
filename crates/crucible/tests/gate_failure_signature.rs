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
    FailureTriageResult, FailureTriageResultIdentity, FailureTriageSignatureSelfCheck,
    FailureTriageSignatureSelfCheckInput, FindingDiscoveryPath, FindingReproductionArtifact,
    HostAssertionViolation, Icount, MarkerId, MemoryDagStore, MinimizationConfig, MinimizationRun,
    NodeId, NodeLifecycle, NodeTemplate, ObservableEvent, OverrideDecision, Plan, Properties,
    ReadyPoint, ScenarioDefForm, Schedule, SchedulerEvaluationBoundaryKind, SchedulerEventLogClass,
    SchedulerEventLogEntry, SchedulerEventLogPayload, SchedulingPoint, Seed, SignaturePolicy,
    SignaturePolicyLevel, SymmetryClassId, SymmetryReductionClasses, VirtualTime, WhiteBoxPolicy,
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

#[test]
fn signature_preserving_minimization_extends_base_pass_per_cluster() -> Result<(), Box<dyn Error>> {
    let scenario = scenario_form()?;
    let policy = SignaturePolicy::default_policy();
    let critical = override_decision("critical-assertion", "fail");
    let schedule_a = Schedule::from_decisions([
        override_decision("noise-left", "enabled"),
        critical.clone(),
        override_decision("noise-right", "enabled"),
    ]);
    let schedule_a_peer =
        Schedule::from_decisions([override_decision("peer-noise", "enabled"), critical.clone()]);
    let schedule_b = Schedule::from_decisions([
        override_decision("other-left", "enabled"),
        critical.clone(),
        override_decision("other-right", "enabled"),
    ]);
    let schedule_b_peer = Schedule::from_decisions([
        override_decision("other-peer-noise", "enabled"),
        critical.clone(),
    ]);

    let finding_a = finding_artifact(
        &scenario,
        schedule_a,
        FindingDiscoveryPath::StateSpaceSearch,
        finding_hash("signature-minimization-a"),
    )?;
    let finding_a_peer = finding_artifact(
        &scenario,
        schedule_a_peer,
        FindingDiscoveryPath::CoverageGuidedFuzzing,
        finding_hash("signature-minimization-a-peer"),
    )?;
    let finding_b = finding_artifact(
        &scenario,
        schedule_b,
        FindingDiscoveryPath::StateSpaceSearch,
        finding_hash("signature-minimization-b"),
    )?;
    let finding_b_peer = finding_artifact(
        &scenario,
        schedule_b_peer,
        FindingDiscoveryPath::CoverageGuidedFuzzing,
        finding_hash("signature-minimization-b-peer"),
    )?;

    let base_signature = signature_for_recorded_decision(&finding_a, critical.clone())?;
    let mut other_signature = base_signature.clone();
    other_signature
        .property
        .as_mut()
        .ok_or("property signature must carry a property key")?
        .quantifier = AssertionQuantifierKind::Sometimes;

    let clustered = FailureClusteringResult::from_findings(
        policy,
        [
            FailureClusterFinding::new(finding_a.artifact.id(), base_signature.clone()),
            FailureClusterFinding::new(finding_a_peer.artifact.id(), base_signature.clone()),
            FailureClusterFinding::new(finding_b.artifact.id(), other_signature.clone()),
            FailureClusterFinding::new(finding_b_peer.artifact.id(), other_signature.clone()),
        ],
    )?;
    assert_eq!(clustered.cluster_count(), 2);
    assert_eq!(clustered.member_count(), 4);

    let artifacts = BTreeMap::from([
        (finding_a.artifact.id(), finding_a.clone()),
        (finding_a_peer.artifact.id(), finding_a_peer.clone()),
        (finding_b.artifact.id(), finding_b.clone()),
        (finding_b_peer.artifact.id(), finding_b_peer.clone()),
    ]);
    let signatures_by_fingerprint = BTreeMap::from([
        (finding_a.finding_fingerprint, base_signature.clone()),
        (finding_a_peer.finding_fingerprint, base_signature),
        (finding_b.finding_fingerprint, other_signature.clone()),
        (finding_b_peer.finding_fingerprint, other_signature),
    ]);
    let expected_representatives = clustered
        .clusters
        .iter()
        .filter_map(|cluster| {
            cluster
                .representative_member()
                .map(|member| member.reproduction_artifact)
        })
        .collect::<BTreeSet<_>>();
    let mut loaded_representatives = Vec::new();
    let mut signature_calls = 0usize;

    let minimized = clustered.minimize_representatives(
        MinimizationConfig::new(Seed::from_u64(0x5452_4935)),
        |artifact| {
            loaded_representatives.push(artifact);
            artifacts
                .get(&artifact)
                .cloned()
                .ok_or(EngineError::UnifiedOperationEvidenceMismatch {
                    operation: "signature-preserving-minimization-test",
                    reason: "missing representative artifact",
                })
        },
        |candidate| {
            signature_calls += 1;
            signature_for_minimization_candidate(&signatures_by_fingerprint, candidate)
        },
    )?;

    assert_eq!(minimized.cluster_count(), clustered.cluster_count());
    assert_eq!(minimized.minimized_count(), clustered.cluster_count());
    assert_eq!(loaded_representatives.len(), clustered.cluster_count());
    assert_eq!(
        loaded_representatives.into_iter().collect::<BTreeSet<_>>(),
        expected_representatives
    );
    assert!(
        signature_calls > minimized.minimized_count(),
        "per-candidate replay-oracle validation must drive signature checks"
    );
    assert!(minimized.runs.iter().all(|run| run.preserves_signature()));
    assert!(minimized.runs.iter().all(|run| {
        run.cluster_id == run.target_signature_key.content_hash()
            && run.cluster_id == run.minimized_signature_key.content_hash()
    }));
    assert!(minimized.runs.iter().all(|run| {
        run.representative_artifact == run.minimization.original.artifact.id()
            && run.minimization.accepted_attempts() == 1
            && run.minimization.minimized.artifact.schedule().len() == 1
    }));
    assert!(minimized.runs.iter().any(|run| {
        run.minimization.attempts.iter().any(|attempt| {
            attempt.sequence == 0
                && attempt.candidate_schedule == Schedule::from_decisions([]).content_hash()
                && !attempt.accepted
                && attempt.observed_fingerprint.is_none()
        })
    }));
    assert!(
        minimized
            .canonical_material()
            .contains("minimization.target_signature_key_BEGIN")
    );
    assert!(
        minimized
            .canonical_material()
            .contains("minimization.0.attempt.0.sequence=")
    );
    assert!(
        minimized
            .canonical_material()
            .contains("minimization.0.attempt.0.candidate_schedule=")
    );
    assert!(
        minimized
            .canonical_material()
            .contains("minimization.0.attempt.0.replayed_state=")
    );
    assert!(
        minimized
            .canonical_material()
            .contains("minimization.0.attempt.0.accepted=")
    );
    assert!(
        minimized
            .canonical_material()
            .contains("minimization.signature_preserved=true")
    );
    assert_ne!(minimized.content_hash(), ContentHash::default());

    let mut forged_attempt_evidence = minimized.clone();
    let first_attempt = forged_attempt_evidence
        .runs
        .first_mut()
        .and_then(|run| run.minimization.attempts.first_mut())
        .ok_or("signature minimization should record at least one attempt")?;
    first_attempt.replayed_state = finding_hash("forged-signature-minimization-replay");
    assert_ne!(
        forged_attempt_evidence.content_hash(),
        minimized.content_hash(),
        "canonical result hash must include per-attempt replay evidence"
    );

    Ok(())
}

#[test]
fn per_cluster_reports_render_same_content_deterministically() -> Result<(), Box<dyn Error>> {
    let scenario = scenario_form()?;
    let policy = SignaturePolicy::default_policy();
    let property_decision = override_decision("triage-decision", "fail");
    let property_finding = finding_artifact(
        &scenario,
        Schedule::from_decisions([property_decision.clone()]),
        FindingDiscoveryPath::StateSpaceSearch,
        finding_hash("cluster-report-property"),
    )?;
    let property_entries = recorded_event_log(property_decision);
    let property_log = recorded_event_log_for_finding(&property_finding, &property_entries)?;
    let property_record = property_violation_record(property_finding.artifact.id());
    let property_signature = FailureSignature::from_recorded_property_violation(
        &property_finding,
        &property_log,
        &property_record,
    )?;
    let mut stale_property_signature = property_signature.clone();
    stale_property_signature.at_icount_report_only = Some(icount(999));
    stale_property_signature.causal_cone = Some(FailureCausalCone::from_canonical_material(
        "causal_cone_events=1\nentry.cone_index=0\nentry.kind=stale-report-detail",
    ));
    assert_eq!(
        stale_property_signature
            .signature_key(policy)?
            .content_hash(),
        property_signature.signature_key(policy)?.content_hash(),
        "default policy must let the stale full-signature details share the cluster key"
    );
    assert_ne!(
        stale_property_signature.report_material(),
        property_signature.report_material()
    );
    let property_cluster = one_member_cluster(policy, &property_finding, stale_property_signature)?;
    let property_run = no_op_minimization_run(policy, &property_cluster, &property_finding)?;
    let property_report = FailureClusterReport::from_cluster(
        policy,
        &property_cluster,
        &property_run,
        FailureClusterReportFailure::property(property_record.clone()),
        &property_log,
        &FailureSignatureNormalization::identity(),
        8,
    )?;

    assert_eq!(
        property_report.signature.report_material(),
        property_signature.report_material(),
        "report construction must recompute the full minimized signature from checked evidence"
    );
    assert!(
        !property_report
            .signature
            .report_material()
            .contains("stale-report-detail")
    );
    assert_eq!(property_report.member_count, 1);
    assert_eq!(
        property_report.minimal_representative,
        property_finding.artifact.id()
    );
    assert!(
        property_report
            .replay_command
            .starts_with("crucible replay blake3:")
    );
    assert!(
        property_report
            .canonical_material()
            .contains("failure.kind=property-violation")
    );
    assert!(
        property_report
            .canonical_material()
            .contains("failure.property_message=forbidden marker must stay absent")
    );
    assert!(
        property_report
            .canonical_material()
            .contains("failure.detail=observed forbidden marker")
    );
    assert!(
        property_report
            .canonical_material()
            .contains("event_log_excerpt.")
    );
    assert!(
        property_report
            .canonical_material()
            .contains("causal_chain.")
    );
    assert!(
        !property_report
            .canonical_material()
            .contains("coverage_marker"),
        "report excerpts must use the causal projection, not observational noise"
    );

    let json = property_report.render(FailureClusterReportFormat::Json);
    let jsonl = property_report.render(FailureClusterReportFormat::JsonLines);
    let table = property_report.render(FailureClusterReportFormat::Table);
    let markdown = property_report.render(FailureClusterReportFormat::Markdown);
    assert_eq!(
        json,
        property_report.render(FailureClusterReportFormat::Json)
    );
    assert_eq!(
        jsonl,
        property_report.render(FailureClusterReportFormat::JsonLines)
    );
    assert_eq!(
        table,
        property_report.render(FailureClusterReportFormat::Table)
    );
    assert_eq!(
        markdown,
        property_report.render(FailureClusterReportFormat::Markdown)
    );
    for rendered in [&json, &jsonl, &table, &markdown] {
        assert!(rendered.contains("crucible replay blake3:"));
        assert!(rendered.to_ascii_lowercase().contains("canonical"));
        assert!(rendered.contains("causal_chain"));
    }
    assert_eq!(jsonl.lines().count(), 1);

    let mut wrong_representative_run = property_run.clone();
    wrong_representative_run.representative_artifact = finding_hash("wrong-cluster-representative");
    let wrong_representative = FailureClusterReport::from_cluster(
        policy,
        &property_cluster,
        &wrong_representative_run,
        FailureClusterReportFailure::property(property_record.clone()),
        &property_log,
        &FailureSignatureNormalization::identity(),
        8,
    )
    .expect_err("report must reject a minimization run for a different representative");
    assert!(matches!(
        wrong_representative,
        EngineError::UnifiedOperationEvidenceMismatch { .. }
    ));

    let wrong_original_finding = finding_artifact(
        &scenario,
        Schedule::from_decisions([override_decision("wrong-report-original", "noise")]),
        FindingDiscoveryPath::InteractiveFork,
        finding_hash("wrong-report-original"),
    )?;
    let mut wrong_original_run = property_run.clone();
    wrong_original_run.minimization.original = wrong_original_finding;
    let wrong_original = FailureClusterReport::from_cluster(
        policy,
        &property_cluster,
        &wrong_original_run,
        FailureClusterReportFailure::property(property_record.clone()),
        &property_log,
        &FailureSignatureNormalization::identity(),
        8,
    )
    .expect_err("report must reject a minimization run whose original is not the representative");
    assert!(matches!(
        wrong_original,
        EngineError::UnifiedOperationEvidenceMismatch { .. }
    ));

    let divergence_decision = override_decision("triage-divergence", "left");
    let divergence_finding = finding_artifact(
        &scenario,
        Schedule::from_decisions([divergence_decision.clone()]),
        FindingDiscoveryPath::InteractiveFork,
        finding_hash("cluster-report-divergence"),
    )?;
    let divergence_entries = recorded_node_divergence_event_log(divergence_decision);
    let divergence_log = recorded_event_log_for_finding(&divergence_finding, &divergence_entries)?;
    let divergence_point = EventLogCausalDivergencePoint {
        raw_index: 1,
        at: EventLogIcountStamp {
            node: Some(node("triage-node")),
            icount: icount(8),
        },
        source: EventSource::Node {
            node: node("triage-node"),
        },
        kind: "node_state".to_owned(),
    };
    let divergence_signature = FailureSignature::from_recorded_divergence(
        &divergence_finding,
        &divergence_log,
        &divergence_point,
    )?;
    let divergence_cluster =
        one_member_cluster(policy, &divergence_finding, divergence_signature.clone())?;
    let divergence_run = no_op_minimization_run(policy, &divergence_cluster, &divergence_finding)?;
    let divergence_report = FailureClusterReport::from_cluster(
        policy,
        &divergence_cluster,
        &divergence_run,
        FailureClusterReportFailure::divergence(
            FailureClusterReportDivergence::from_bisected_first_diff(
                &divergence_point,
                "expected_state=stable-before-divergence",
                "reproduced_state=changed-after-divergence",
            ),
        ),
        &divergence_log,
        &FailureSignatureNormalization::identity(),
        4,
    )?;
    assert!(
        divergence_report
            .canonical_material()
            .contains("failure.kind=divergence")
    );
    assert!(
        divergence_report
            .canonical_material()
            .contains("failure.icount_node")
    );
    assert!(
        divergence_report
            .canonical_material()
            .contains("failure.expected_state_summary=expected_state=stable-before-divergence")
    );
    assert!(
        divergence_report
            .canonical_material()
            .contains("failure.reproduced_state_summary=reproduced_state=changed-after-divergence")
    );

    let report_set = FailureClusterReportSet::from_reports(
        policy,
        [divergence_report.clone(), property_report.clone()],
    )?;
    let report_ids = report_set
        .reports
        .iter()
        .map(|report| report.cluster_id)
        .collect::<Vec<_>>();
    let mut sorted_report_ids = report_ids.clone();
    sorted_report_ids.sort();
    assert_eq!(report_ids, sorted_report_ids);
    assert_eq!(
        report_set
            .render(FailureClusterReportFormat::JsonLines)
            .lines()
            .count(),
        report_set.reports.len()
    );
    assert!(
        report_set
            .render(FailureClusterReportFormat::Json)
            .contains("\"reports\"")
    );
    assert!(
        report_set
            .render(FailureClusterReportFormat::Markdown)
            .contains("Canonical Report")
    );

    let mut forged = property_report.clone();
    forged
        .event_log_excerpt
        .first_mut()
        .ok_or("report must retain causal excerpt evidence")?
        .entry = finding_hash("forged-report-excerpt-entry");
    assert_ne!(
        forged.content_hash(),
        property_report.content_hash(),
        "report identity must include causal excerpt evidence"
    );

    Ok(())
}

#[test]
fn triage_result_artifact_dedups_diffs_and_self_checks_offline() -> Result<(), Box<dyn Error>> {
    let scenario = scenario_form()?;
    let policy = SignaturePolicy::default_policy();
    let decision = override_decision("triage-result-decision", "fail");
    let finding = finding_artifact(
        &scenario,
        Schedule::from_decisions([decision.clone()]),
        FindingDiscoveryPath::StateSpaceSearch,
        finding_hash("triage-result-finding"),
    )?;
    let entries = recorded_event_log(decision);
    let recorded_log = recorded_event_log_for_finding(&finding, &entries)?;
    let violation = property_violation_record(finding.artifact.id());
    let signature =
        FailureSignature::from_recorded_property_violation(&finding, &recorded_log, &violation)?;
    let ledger =
        FailureFindingsLedger::from_artifacts([finding.artifact.id(), finding.artifact.id()]);
    assert_eq!(ledger.artifact_count(), 1);
    assert!(ledger.canonical_material().contains("artifact_count=1"));

    let clustering = FailureClusteringResult::from_findings(
        policy,
        [FailureClusterFinding::new(
            finding.artifact.id(),
            signature.clone(),
        )],
    )?;
    let cluster = clustering
        .clusters
        .first()
        .ok_or("triage result test should produce one cluster")?
        .clone();
    let run = no_op_minimization_run(policy, &cluster, &finding)?;
    let minimization = FailureSignaturePreservingMinimizationResult {
        policy,
        runs: vec![run.clone()],
    };
    let report = FailureClusterReport::from_cluster(
        policy,
        &cluster,
        &run,
        FailureClusterReportFailure::property(violation),
        &recorded_log,
        &FailureSignatureNormalization::identity(),
        8,
    )?;
    let report_set = FailureClusterReportSet::from_reports(policy, [report.clone()])?;
    let clean_check = FailureTriageSignatureSelfCheck::from_signature_pairs([
        FailureTriageSignatureSelfCheckInput::new(
            finding.artifact.id(),
            signature.clone(),
            signature.clone(),
        ),
    ]);
    assert!(clean_check.is_clean());

    let mut stale_signature = signature.clone();
    stale_signature.at_icount_report_only = Some(icount(444));
    let mismatch_check = FailureTriageSignatureSelfCheck::from_signature_pairs([
        FailureTriageSignatureSelfCheckInput::new(
            finding.artifact.id(),
            stale_signature,
            signature.clone(),
        ),
    ]);
    assert!(!mismatch_check.is_clean());
    assert!(matches!(
        mismatch_check.assert_clean(),
        Err(EngineError::UnifiedOperationEvidenceMismatch { .. })
    ));
    let mismatch_result = FailureTriageResult::from_parts(
        ledger.content_hash(),
        clustering.clone(),
        minimization.clone(),
        report_set.clone(),
        mismatch_check,
    )
    .expect_err("--recompute-signatures mismatches must fail the triage result");
    assert!(matches!(
        mismatch_result,
        EngineError::UnifiedOperationEvidenceMismatch { .. }
    ));
    let partial_check = FailureTriageSignatureSelfCheck {
        checked_count: 2,
        checks: Vec::new(),
        mismatches: Vec::new(),
    };
    let partial_result = FailureTriageResult::from_parts(
        ledger.content_hash(),
        clustering.clone(),
        minimization.clone(),
        report_set.clone(),
        partial_check,
    )
    .expect_err("non-skipped self-checks must cover every clustered finding");
    assert!(matches!(
        partial_result,
        EngineError::UnifiedOperationEvidenceMismatch { .. }
    ));
    let mut forged_self_check = clean_check.clone();
    forged_self_check.checks[0].discovery_signature_hash =
        finding_hash("forged-self-check-discovery");
    let forged_self_check_result = FailureTriageResult::from_parts(
        ledger.content_hash(),
        clustering.clone(),
        minimization.clone(),
        report_set.clone(),
        forged_self_check,
    )
    .expect_err("self-check discovery hashes must bind to clustered finding signatures");
    assert!(matches!(
        forged_self_check_result,
        EngineError::UnifiedOperationEvidenceMismatch { .. }
    ));
    let mut forged_minimization = minimization.clone();
    forged_minimization.runs[0].representative_artifact =
        finding_hash("forged-triage-result-representative");
    let forged_minimization_result = FailureTriageResult::from_parts(
        ledger.content_hash(),
        clustering.clone(),
        forged_minimization,
        report_set.clone(),
        clean_check.clone(),
    )
    .expect_err("triage result must re-bind minimization runs to cluster representatives");
    assert!(matches!(
        forged_minimization_result,
        EngineError::UnifiedOperationEvidenceMismatch { .. }
    ));
    let mut duplicate_minimization = minimization.clone();
    duplicate_minimization
        .runs
        .push(duplicate_minimization.runs[0].clone());
    let duplicate_minimization_result = FailureTriageResult::from_parts(
        ledger.content_hash(),
        clustering.clone(),
        duplicate_minimization,
        report_set.clone(),
        clean_check.clone(),
    )
    .expect_err("triage result must reject duplicate minimization runs for a cluster");
    assert!(matches!(
        duplicate_minimization_result,
        EngineError::UnifiedOperationEvidenceMismatch { .. }
    ));
    let mut forged_report_set = report_set.clone();
    forged_report_set.reports[0].member_count = 99;
    let forged_report_result = FailureTriageResult::from_parts(
        ledger.content_hash(),
        clustering.clone(),
        minimization.clone(),
        forged_report_set,
        clean_check.clone(),
    )
    .expect_err("triage result must re-bind report membership to clusters");
    assert!(matches!(
        forged_report_result,
        EngineError::UnifiedOperationEvidenceMismatch { .. }
    ));

    let result = FailureTriageResult::from_parts(
        ledger.content_hash(),
        clustering.clone(),
        minimization.clone(),
        report_set,
        clean_check.clone(),
    )?;
    assert_eq!(
        result.identity,
        FailureTriageResultIdentity::new(ledger.content_hash(), policy)
    );
    assert!(
        result
            .canonical_material()
            .contains("triage_result_identity=")
    );
    assert!(result.canonical_material().contains("report_set="));

    let store = MemoryDagStore::new();
    let ledger_first = ledger.store(&store)?;
    let ledger_second = ledger.store(&store)?;
    assert_eq!(ledger_first.key, ledger_second.key);
    assert_eq!(ledger_first.key, ledger.content_hash());
    assert!(!ledger_first.cache_hit);
    assert!(ledger_second.cache_hit);

    let stored_first = result.store(&store)?;
    let stored_second = result.store(&store)?;
    assert_eq!(stored_first.key, stored_second.key);
    assert_eq!(stored_first.key, result.content_hash());
    assert!(!stored_first.cache_hit);
    assert!(stored_second.cache_hit);
    assert_eq!(store.object_count()?, 2);
    assert_eq!(store.get(&stored_first.key)?, result.artifact_bytes());

    let same_diff = result.compare_to(&result);
    assert!(!same_diff.has_changes());
    assert!(same_diff.content_diff().contains("unchanged\t"));

    let mut changed_report = report;
    changed_report
        .event_log_excerpt
        .first_mut()
        .ok_or("report must carry causal excerpt evidence")?
        .entry = finding_hash("triage-result-content-diff");
    let changed_report_set = FailureClusterReportSet::from_reports(policy, [changed_report])?;
    let changed_result = FailureTriageResult::from_parts(
        ledger.content_hash(),
        clustering,
        minimization,
        changed_report_set,
        clean_check,
    )?;
    let changed_diff = changed_result.compare_to(&result);
    assert!(changed_diff.has_changes());
    assert_eq!(changed_diff.changed_clusters.len(), 1);
    assert!(changed_diff.content_diff().contains("changed\t"));
    assert_ne!(changed_result.content_hash(), result.content_hash());

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

fn one_member_cluster(
    policy: SignaturePolicy,
    finding: &FindingReproductionArtifact,
    signature: FailureSignature,
) -> Result<crucible::FailureCluster, EngineError> {
    let clustered = FailureClusteringResult::from_findings(
        policy,
        [FailureClusterFinding::new(finding.artifact.id(), signature)],
    )?;
    clustered
        .clusters
        .into_iter()
        .next()
        .ok_or(EngineError::UnifiedOperationEvidenceMismatch {
            operation: "failure-report-test",
            reason: "one-member cluster was not produced",
        })
}

fn no_op_minimization_run(
    policy: SignaturePolicy,
    cluster: &crucible::FailureCluster,
    finding: &FindingReproductionArtifact,
) -> Result<FailureSignaturePreservingMinimizationRun, EngineError> {
    let representative =
        cluster
            .representative_member()
            .ok_or(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "failure-report-test",
                reason: "cluster has no representative",
            })?;
    let signature_key = representative.signature.signature_key(policy)?;
    Ok(FailureSignaturePreservingMinimizationRun {
        cluster_id: cluster.id,
        representative_artifact: finding.artifact.id(),
        target_signature_key: signature_key.clone(),
        minimized_signature_key: signature_key,
        disposition: FailureMinimizationDisposition::NotRequested,
        minimization: MinimizationRun {
            seed: Seed::from_u64(0x5452_4936),
            target_fingerprint: finding.finding_fingerprint,
            original: finding.clone(),
            minimized: finding.clone(),
            attempts: Vec::new(),
        },
    })
}

fn signature_for_recorded_decision(
    finding: &FindingReproductionArtifact,
    decision: Decision,
) -> Result<FailureSignature, EngineError> {
    let entries = recorded_event_log(decision);
    let recorded_log = recorded_event_log_for_finding(finding, &entries)?;
    let record = property_violation_record(finding.artifact.id());
    FailureSignature::from_recorded_property_violation(finding, &recorded_log, &record)
}

fn signature_for_minimization_candidate(
    signatures_by_fingerprint: &BTreeMap<ContentHash, FailureSignature>,
    candidate: &FindingReproductionArtifact,
) -> Result<Option<FailureSignature>, EngineError> {
    let template = signatures_by_fingerprint
        .get(&candidate.finding_fingerprint)
        .ok_or(EngineError::UnifiedOperationEvidenceMismatch {
            operation: "signature-preserving-minimization-test",
            reason: "missing signature template",
        })?;
    if candidate.artifact.schedule().is_empty() {
        let mut drifted = template.clone();
        drifted
            .property
            .as_mut()
            .ok_or(EngineError::UnifiedOperationEvidenceMismatch {
                operation: "signature-preserving-minimization-test",
                reason: "missing property key",
            })?
            .id = assertion_id("signature-drift");
        return Ok(Some(drifted));
    }
    if !schedule_contains_override(candidate.artifact.schedule(), "critical-assertion", "fail") {
        return Ok(None);
    }

    let mut preserved = template.clone();
    preserved.at_icount_report_only =
        Some(icount(100 + candidate.artifact.schedule().len() as u64));
    Ok(Some(preserved))
}

fn schedule_contains_override(schedule: &Schedule, point: &str, choice: &str) -> bool {
    schedule.decisions().iter().any(|decision| {
        matches!(
            decision,
            Decision::Override(override_decision)
                if override_decision.point.key == point && override_decision.choice.name == choice
        )
    })
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

fn recorded_node_divergence_event_log(decision: Decision) -> Vec<crucible::SchedulerEventLogEntry> {
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
