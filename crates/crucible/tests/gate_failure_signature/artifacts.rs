//! Triage artifact and source-binding rejection regressions.

use super::*;

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
fn triage_result_accepts_one_minimization_per_cluster_member() -> Result<(), Box<dyn Error>> {
    let scenario = scenario_form()?;
    let policy = SignaturePolicy::default_policy();
    let first_decision = override_decision("triage-member-first-decision", "fail");
    let second_decision = override_decision("triage-member-second-decision", "fail");
    let first_finding = finding_artifact(
        &scenario,
        Schedule::from_decisions([first_decision.clone()]),
        FindingDiscoveryPath::StateSpaceSearch,
        finding_hash("triage-member-first"),
    )?;
    let second_finding = finding_artifact(
        &scenario,
        Schedule::from_decisions([second_decision.clone()]),
        FindingDiscoveryPath::CoverageGuidedFuzzing,
        finding_hash("triage-member-second"),
    )?;
    let first_entries = recorded_event_log(first_decision);
    let second_entries = recorded_event_log(second_decision);
    let first_log = recorded_event_log_for_finding(&first_finding, &first_entries)?;
    let second_log = recorded_event_log_for_finding(&second_finding, &second_entries)?;
    let first_signature = FailureSignature::from_recorded_property_violation(
        &first_finding,
        &first_log,
        &property_violation_record(first_finding.artifact.id()),
    )?;
    let second_signature = FailureSignature::from_recorded_property_violation(
        &second_finding,
        &second_log,
        &property_violation_record(second_finding.artifact.id()),
    )?;
    assert_ne!(first_finding.artifact.id(), second_finding.artifact.id());
    assert_eq!(
        policy.signature_key(&first_signature)?,
        policy.signature_key(&second_signature)?
    );

    let clustering = FailureClusteringResult::from_findings(
        policy,
        [
            FailureClusterFinding::new(first_finding.artifact.id(), first_signature.clone()),
            FailureClusterFinding::new(second_finding.artifact.id(), second_signature.clone()),
        ],
    )?;
    let cluster = clustering
        .clusters
        .first()
        .ok_or("same-signature findings should produce one cluster")?
        .clone();
    let representative_artifact = cluster
        .representative_member()
        .ok_or("two-member cluster should have a representative")?
        .reproduction_artifact;
    let (representative_finding, representative_log, other_finding) =
        if representative_artifact == first_finding.artifact.id() {
            (&first_finding, &first_log, &second_finding)
        } else {
            (&second_finding, &second_log, &first_finding)
        };
    let representative_run = no_op_minimization_run(policy, &cluster, representative_finding)?;
    let other_run = no_op_minimization_run(policy, &cluster, other_finding)?;
    let report = FailureClusterReport::from_cluster(
        policy,
        &cluster,
        &representative_run,
        FailureClusterReportFailure::property(property_violation_record(
            representative_finding.artifact.id(),
        )),
        representative_log,
        &FailureSignatureNormalization::identity(),
        8,
    )?;
    let report_set = FailureClusterReportSet::from_reports(policy, [report.clone()])?;
    let self_check = FailureTriageSignatureSelfCheck::from_signature_pairs([
        FailureTriageSignatureSelfCheckInput::new(
            first_finding.artifact.id(),
            first_signature.clone(),
            first_signature.clone(),
        ),
        FailureTriageSignatureSelfCheckInput::new(
            second_finding.artifact.id(),
            second_signature.clone(),
            second_signature.clone(),
        ),
    ]);
    let ledger = FailureFindingsLedger::from_artifacts([
        first_finding.artifact.id(),
        second_finding.artifact.id(),
    ]);

    let representative_only = FailureSignaturePreservingMinimizationResult {
        policy,
        runs: vec![representative_run.clone()],
    };
    FailureTriageResult::from_parts(
        ledger.content_hash(),
        clustering.clone(),
        representative_only,
        report_set.clone(),
        self_check.clone(),
    )?;

    let all_members = FailureSignaturePreservingMinimizationResult {
        policy,
        runs: vec![representative_run.clone(), other_run.clone()],
    };
    let result = FailureTriageResult::from_parts(
        ledger.content_hash(),
        clustering.clone(),
        all_members.clone(),
        report_set.clone(),
        self_check.clone(),
    )?;
    assert_eq!(result.minimization.cluster_count(), 1);
    assert_eq!(result.minimization.minimized_count(), 2);
    assert_eq!(result.report_set.reports[0], report);
    assert_eq!(
        result.report_set.reports[0].minimal_representative,
        representative_run.minimized_artifact()
    );

    let mut duplicate_member = all_members.clone();
    duplicate_member.runs.push(other_run.clone());
    FailureTriageResult::from_parts(
        ledger.content_hash(),
        clustering.clone(),
        duplicate_member,
        report_set.clone(),
        self_check.clone(),
    )
    .expect_err("duplicate minimization runs for one cluster member must be rejected");

    let mut nonmember = all_members.clone();
    nonmember.runs[1].representative_artifact = finding_hash("triage-nonmember");
    FailureTriageResult::from_parts(
        ledger.content_hash(),
        clustering.clone(),
        nonmember,
        report_set.clone(),
        self_check.clone(),
    )
    .expect_err("minimization runs for artifacts outside the cluster must be rejected");

    let mut wrong_original = all_members.clone();
    wrong_original.runs[1].minimization.original = representative_finding.clone();
    FailureTriageResult::from_parts(
        ledger.content_hash(),
        clustering.clone(),
        wrong_original,
        report_set.clone(),
        self_check.clone(),
    )
    .expect_err("minimization originals must match their selected cluster members");

    let mut wrong_signature = all_members;
    wrong_signature.runs[1].target_signature_key =
        SignaturePolicy::fine().signature_key(&second_signature)?;
    FailureTriageResult::from_parts(
        ledger.content_hash(),
        clustering,
        wrong_signature,
        report_set,
        self_check,
    )
    .expect_err("minimization signatures must match their cluster signature");

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
        at: EventLogTickStamp {
            node: None,
            tick: crucible::SimInstant { ticks: 99 },
            retired: Some(icount(99)),
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

pub(super) fn one_member_cluster(
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

pub(super) fn no_op_minimization_run(
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
            interesting_window: None,
            target_fingerprint: finding.finding_fingerprint,
            original: finding.clone(),
            minimized: finding.clone(),
            attempts: Vec::new(),
        },
    })
}

pub(super) fn signature_for_recorded_decision(
    finding: &FindingReproductionArtifact,
    decision: Decision,
) -> Result<FailureSignature, EngineError> {
    let entries = recorded_event_log(decision);
    let recorded_log = recorded_event_log_for_finding(finding, &entries)?;
    let record = property_violation_record(finding.artifact.id());
    FailureSignature::from_recorded_property_violation(finding, &recorded_log, &record)
}

pub(super) fn signature_for_minimization_candidate(
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
