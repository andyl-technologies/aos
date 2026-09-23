//! Signature-preserving minimization and report regressions.

use super::artifacts::{
    no_op_minimization_run, one_member_cluster, signature_for_minimization_candidate,
    signature_for_recorded_decision,
};
use super::*;

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
    assert!(property_report.canonical_material().contains(&format!(
        "failure.detail={}",
        property_record.violation.detail
    )));
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
        FindingDiscoveryPath::CampaignFork,
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
        FindingDiscoveryPath::CampaignFork,
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
