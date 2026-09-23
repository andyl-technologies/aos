//! Minimized-finding and exact-retention publication regressions.

use super::*;

#[test]
fn minimized_finding_retains_trace_and_complete_observation_evidence() {
    let (repository, lineage, policy, blobs) = counted_fixture();
    let (_, admitted, observation) =
        admitted_observation_fixture(&repository, &lineage, &policy, "minimized-finding");
    let observed = repository
        .publish_observation("minimized-finding", admitted.new_snapshot, &observation)
        .expect("publish observation");
    let fingerprint = CampaignHash::derive("test-finding", b"minimized divergence");
    let original = repository
        .publish_reproduction_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            observation.child(),
            observation.child_content(),
            fingerprint,
            1,
            b"verified original reproduction".to_vec(),
        )
        .expect("publish original reproduction");
    let final_state = CampaignHash::derive("test-finding", b"minimized final state");
    let minimization = FindingMinimizationEvidence::new(
        original,
        3,
        b"seeded shortest-first; candidates=4096; bytes=134217728".to_vec(),
        vec![FindingMinimizationAttempt::new(
            0,
            CampaignHash::derive("test-finding", b"candidate artifact"),
            CampaignHash::derive("test-finding", b"candidate schedule"),
            final_state,
            Some(fingerprint),
            true,
        )],
        final_state,
    )
    .expect("minimization evidence");
    let minimized = repository
        .publish_minimized_reproduction_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            observation.child(),
            observation.child_content(),
            fingerprint,
            1,
            b"verified minimized reproduction".to_vec(),
            minimization.clone(),
        )
        .expect("publish minimized reproduction");
    let signature = FindingSignature::new(
        FindingKind::Divergence,
        fingerprint,
        None,
        "qemu.replay-divergence".to_owned(),
        Some(FindingTarget::Configuration(observation.child_content())),
        BTreeSet::from([observation.properties().content_id()]),
    )
    .expect("finding signature with property evidence closure");

    assert_eq!(
        repository
            .load_reproduction_artifact(minimized)
            .expect("load minimized reproduction")
            .minimization()
            .expect("retained minimization trace")
            .original(),
        original
    );
    let missing_original = ReproductionArtifactId::from_content_id(ContentId::for_bytes(
        ObjectKind::Finding,
        2,
        b"missing original reproduction",
    ))
    .expect("missing reproduction id");
    let invalid_trace = FindingMinimizationEvidence::new(
        missing_original,
        3,
        b"same minimization policy".to_vec(),
        Vec::new(),
        final_state,
    )
    .expect("structurally valid missing-original trace");
    let count_before = blobs.object_count().expect("object count before rejection");
    assert!(matches!(
        repository.publish_minimized_reproduction_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            observation.child(),
            observation.child_content(),
            fingerprint,
            1,
            b"unpublishable minimized reproduction".to_vec(),
            invalid_trace,
        ),
        Err(CampaignRepositoryError::Store(StoreError::NotFound { .. }))
    ));
    assert_eq!(
        blobs.object_count().expect("object count after rejection"),
        count_before
    );

    let signature_minimization = FindingSignatureMinimizationEvidence::new(
        &signature,
        &minimization,
        vec![Some(signature.clone()), Some(signature.clone())],
        vec![Some(signature.clone()), Some(signature.clone())],
    )
    .expect("signature minimization evidence");
    let minimization_original_triage = FindingTriageReplayEvidence::new(
        original,
        signature.clone(),
        1,
        b"minimization original native replay".to_vec(),
    )
    .expect("minimization original triage evidence");
    let minimization_selected_triage = FindingTriageReplayEvidence::new(
        minimized,
        signature.clone(),
        1,
        b"minimization selected native replay".to_vec(),
    )
    .expect("minimization selected triage evidence");
    let verification_original_triage = FindingTriageReplayEvidence::new(
        original,
        signature.clone(),
        1,
        b"verification original native replay".to_vec(),
    )
    .expect("verification original triage evidence");
    let verification_selected_triage = FindingTriageReplayEvidence::new(
        minimized,
        signature.clone(),
        1,
        b"verification selected native replay".to_vec(),
    )
    .expect("verification selected triage evidence");
    let triage_evidence = FindingTriageEvidenceSet::new(
        repository
            .publish_finding_triage_replay_evidence(&minimization_original_triage)
            .expect("publish minimization original triage evidence"),
        repository
            .publish_finding_triage_replay_evidence(&minimization_selected_triage)
            .expect("publish minimization selected triage evidence"),
        repository
            .publish_finding_triage_replay_evidence(&verification_original_triage)
            .expect("publish verification original triage evidence"),
        repository
            .publish_finding_triage_replay_evidence(&verification_selected_triage)
            .expect("publish verification selected triage evidence"),
    );
    let retention_basis = repository
        .attempt_retention_policy_basis_at(admitted.new_snapshot, admitted.attempt)
        .expect("finding retention policy basis");
    let exact_retention = FindingExactRetention::new(
        retention_basis.snapshot(),
        retention_basis.policy(),
        retention_basis.admission(),
        0,
        FindingExactRetentionDisposition::Incomplete(
            FindingExactRetentionIncomplete::MissingSafeBoundaryCapture,
        ),
    )
    .expect("incomplete exact retention");
    let bundle = FindingCandidateBundle::new_with_exact_retention(
        crate::FindingCandidateCore::new(
            observed.observation,
            signature.clone(),
            original,
            minimized,
            signature_minimization,
            FindingExactPins::default(),
        ),
        Some(triage_evidence),
        exact_retention,
    )
    .expect("finding candidate bundle");
    assert_eq!(bundle.schema_version(), 6);

    let mismatched_triage_bundle = FindingCandidateBundle::new_with_exact_retention(
        crate::FindingCandidateCore::new(
            observed.observation,
            signature.clone(),
            original,
            minimized,
            bundle.signature_minimization().clone(),
            FindingExactPins::default(),
        ),
        Some(FindingTriageEvidenceSet::new(
            triage_evidence.minimization_selected(),
            triage_evidence.minimization_original(),
            triage_evidence.verification_original(),
            triage_evidence.verification_selected(),
        )),
        exact_retention,
    )
    .expect("structurally valid mismatched triage bundle");
    assert!(matches!(
        repository.publish_finding_candidate_bundle(&mismatched_triage_bundle),
        Err(CampaignRepositoryError::Integrity {
            reason: "finding-triage-replay-evidence-basis-mismatch"
        })
    ));
    let bundle_id = repository
        .publish_finding_candidate_bundle(&bundle)
        .expect("publish finding candidate bundle");
    assert_eq!(
        repository
            .load_finding_candidate_bundle(bundle_id)
            .expect("load current finding candidate bundle"),
        bundle
    );
    let published = repository
        .incorporate_finding_candidate_bundle("minimized-finding", observed.new_snapshot, bundle_id)
        .expect("publish current finding with candidate occurrence");
    assert!(!published.replayed);

    let finding = repository
        .read_finding(published.finding.content_id())
        .expect("current finding");
    assert_eq!(finding.schema_version(), 4);
    assert_eq!(finding.observation(), observed.observation);
    assert_eq!(finding.reproduction(), original);
    assert_eq!(finding.minimized(), Some(minimized));
    assert_eq!(finding.first_seen_snapshot(), observed.new_snapshot);
    assert_eq!(finding.candidate_bundle(), bundle_id);
    assert_eq!(finding.candidate_occurrence_count(), 1);
    repository.evict_local_checkpoint(published.new_snapshot.content_id());
    assert_eq!(
        repository
            .head("minimized-finding")
            .expect("cold current finding history validation")
            .snapshot_id(),
        published.new_snapshot
    );
}

#[test]
fn exact_retention_rejects_source_snapshot_and_campaign_lineage_substitution() {
    let (repository, lineage, policy) = fixture();
    let (_, admitted, observation) =
        admitted_observation_fixture(&repository, &lineage, &policy, "exact-retention-source");
    let observed = repository
        .publish_observation(
            "exact-retention-source",
            admitted.new_snapshot,
            &observation,
        )
        .expect("publish source observation");

    let other_lineage = CampaignLineage::new(
        lineage.scenario(),
        lineage.scenario_content(),
        lineage.genesis(),
        lineage.genesis_content(),
        lineage.crucible_version(),
        "qemu-other-lineage",
        lineage.protocol_versions().clone(),
        lineage.scenario_schema(),
        lineage.exact_closure_schema(),
    )
    .expect("same-scenario alternate lineage");
    let (_, other_admitted, other_observation) = admitted_observation_fixture(
        &repository,
        &other_lineage,
        &policy,
        "exact-retention-other-lineage",
    );
    let other_observed = repository
        .publish_observation(
            "exact-retention-other-lineage",
            other_admitted.new_snapshot,
            &other_observation,
        )
        .expect("publish alternate-lineage observation");

    let fingerprint = CampaignHash::derive("test-finding", b"snapshot-bound retention");
    let original = repository
        .publish_reproduction_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            observation.child(),
            observation.child_content(),
            fingerprint,
            1,
            b"snapshot-bound original".to_vec(),
        )
        .expect("publish original reproduction");
    let final_state = CampaignHash::derive("test-finding", b"snapshot-bound final state");
    let minimization = FindingMinimizationEvidence::new(
        original,
        3,
        b"snapshot-bound minimization".to_vec(),
        vec![FindingMinimizationAttempt::new(
            0,
            CampaignHash::derive("test-finding", b"snapshot-bound candidate"),
            CampaignHash::derive("test-finding", b"snapshot-bound schedule"),
            final_state,
            Some(fingerprint),
            true,
        )],
        final_state,
    )
    .expect("minimization evidence");
    let minimized = repository
        .publish_minimized_reproduction_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            observation.child(),
            observation.child_content(),
            fingerprint,
            1,
            b"snapshot-bound minimized".to_vec(),
            minimization.clone(),
        )
        .expect("publish minimized reproduction");
    let signature = FindingSignature::new(
        FindingKind::Divergence,
        fingerprint,
        None,
        "qemu.snapshot-bound-divergence".to_owned(),
        Some(FindingTarget::Configuration(observation.child_content())),
        BTreeSet::new(),
    )
    .expect("finding signature");
    let signatures = FindingSignatureMinimizationEvidence::new(
        &signature,
        &minimization,
        vec![Some(signature.clone()), Some(signature.clone())],
        vec![Some(signature.clone()), Some(signature.clone())],
    )
    .expect("signature minimization evidence");
    let exact_retention = |snapshot| {
        FindingExactRetention::new(
            snapshot,
            policy.id().expect("policy ID"),
            admitted.admission,
            0,
            FindingExactRetentionDisposition::Incomplete(
                FindingExactRetentionIncomplete::MissingSafeBoundaryCapture,
            ),
        )
        .expect("exact retention evidence")
    };
    let bundle_with = |retention| {
        FindingCandidateBundle::new_with_exact_retention(
            crate::FindingCandidateCore::new(
                observed.observation,
                signature.clone(),
                original,
                minimized,
                signatures.clone(),
                FindingExactPins::default(),
            ),
            None,
            retention,
        )
        .expect("exact retention bundle")
    };

    let substituted = bundle_with(exact_retention(other_admitted.new_snapshot));
    assert!(matches!(
        repository.publish_finding_candidate_bundle(&substituted),
        Err(CampaignRepositoryError::Integrity {
            reason: "finding-exact-retention-attempt-is-not-in-source-snapshot"
        })
    ));

    let bundle = bundle_with(exact_retention(admitted.new_snapshot));
    let bundle_id = repository
        .publish_finding_candidate_bundle(&bundle)
        .expect("publish source-bound bundle");
    assert!(matches!(
        repository.incorporate_finding_candidate_bundle(
            "exact-retention-other-lineage",
            other_observed.new_snapshot,
            bundle_id,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "finding-exact-retention-source-snapshot-lineage-mismatch"
        })
    ));
}
