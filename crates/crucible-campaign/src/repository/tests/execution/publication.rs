//! Observation and finding publication tests.

use super::*;
use crate::{
    AuthenticatedFindingExactCheckpoint, CampaignExecutorStore,
    FindingExactCheckpointAuthenticationError, FindingExactCheckpointAuthenticator,
    FindingExactRetention, FindingExactRetentionCandidate, FindingExactRetentionDisposition,
    FindingExactRetentionEvidence, FindingExactRetentionIncomplete, FindingTriageEvidenceSet,
    ScenarioArtifactId,
};
use crucible_cas::content_envelope::{ContentChild, ContentEnvelope};

#[test]
fn observations_publish_exact_roots_replay_and_retain_determinism_conflicts() {
    let (repository, lineage, policy) = fixture();
    let (genesis, admitted, observation) =
        admitted_observation_fixture(&repository, &lineage, &policy, "observation");
    let observation_id = observation.id().expect("observation id");
    let accepted = repository
        .publish_observation("observation", admitted.new_snapshot, &observation)
        .expect("publish observation");
    assert_eq!(accepted.disposition, ObservationDisposition::Canonical);
    assert!(!accepted.replayed);
    assert_eq!(accepted.observation, observation_id);

    let canonical = repository
        .read_snapshot(accepted.new_snapshot.content_id())
        .expect("canonical observation snapshot");
    let roots = canonical.snapshot.roots();
    assert_eq!(
        repository
            .merkle
            .get(
                roots.observations,
                map_key_content("observations.attempt", observation.attempt().content_id()),
            )
            .expect("attempt observation lookup"),
        Some(observation_id.content_id())
    );
    assert_eq!(
        repository
            .merkle
            .get(
                roots.graph,
                map_key_hash("graph.configuration", observation.child().as_hash()),
            )
            .expect("graph child lookup"),
        Some(observation.child_content().content_id())
    );
    assert_eq!(
        repository
            .merkle
            .get(
                roots.corpus,
                map_key_hash("corpus.configuration", observation.child().as_hash()),
            )
            .expect("corpus child lookup"),
        Some(observation.child_content().content_id())
    );
    assert_eq!(
        repository
            .merkle
            .get(
                roots.coverage,
                map_key_content("coverage.projection", observation.coverage().content_id()),
            )
            .expect("coverage lookup"),
        Some(observation.coverage().content_id())
    );
    assert_eq!(
        repository
            .merkle
            .get(roots.accounting, observation_sequence_key())
            .expect("strict observation sequence"),
        Some(observation_id.content_id())
    );
    assert_eq!(
        repository
            .load_observation(observation_id)
            .expect("load observation"),
        observation
    );

    let mut forged_roots = roots;
    forged_roots.coverage = repository
        .merkle
        .insert(
            forged_roots.coverage,
            map_key_content("coverage.forged", observation.measurements().content_id()),
            observation.measurements().content_id(),
        )
        .expect("forged coverage root")
        .content_id();
    let forged = CampaignSnapshot::successor(
        admitted.new_snapshot,
        canonical.snapshot.lineage(),
        canonical.snapshot.active_policy(),
        forged_roots,
        canonical
            .snapshot
            .transition()
            .expect("observation transition"),
        crate::test_budget_ledger_id(),
    )
    .expect("forged observation successor");
    let forged_content = repository
        .put_snapshot(&forged)
        .expect("put forged observation successor");
    assert!(matches!(
        repository.validate_complete_head(forged_content),
        Err(CampaignRepositoryError::Integrity {
            reason: "observation-transition-coverage-root"
        })
    ));
    let replay = repository
        .publish_observation("observation", genesis, &observation)
        .expect("replay canonical observation");
    assert!(replay.replayed);
    assert_eq!(
        replay,
        ObservationResult {
            replayed: true,
            ..accepted.clone()
        }
    );

    let conflicting_measurements = MeasurementSet::test_evaluation(b"latency-8", BTreeSet::new())
        .expect("conflicting measurement set");
    let conflicting_measurements = repository
        .publish_measurement_set(&conflicting_measurements)
        .expect("publish conflicting measurements");
    let conflict = Observation::new(
        observation.attempt(),
        observation.child(),
        observation.child_content(),
        observation.path(),
        observation.stop().clone(),
        conflicting_measurements,
        observation.properties(),
        observation.coverage(),
        observation.discovered_choices().clone(),
    )
    .expect("conflicting observation");
    let conflict_id = conflict.id().expect("conflict id");
    let conflicted = repository
        .publish_observation("observation", accepted.new_snapshot, &conflict)
        .expect("retain observation conflict");
    assert_eq!(
        conflicted.disposition,
        ObservationDisposition::DeterminismConflict {
            canonical: observation_id
        }
    );
    let conflict_snapshot = repository
        .read_snapshot(conflicted.new_snapshot.content_id())
        .expect("conflict snapshot");
    assert_eq!(conflict_snapshot.snapshot.roots().graph, roots.graph);
    assert_eq!(conflict_snapshot.snapshot.roots().corpus, roots.corpus);
    assert_eq!(conflict_snapshot.snapshot.roots().coverage, roots.coverage);
    assert_eq!(
        conflict_snapshot.snapshot.roots().accounting,
        roots.accounting
    );
    assert_eq!(
        repository
            .merkle
            .get(
                conflict_snapshot.snapshot.roots().observations,
                observation_conflict_key(observation.attempt(), conflict_id),
            )
            .expect("conflict lookup"),
        Some(conflict_id.content_id())
    );
    let replayed_conflict = repository
        .publish_observation("observation", genesis, &conflict)
        .expect("replay observation conflict");
    assert!(replayed_conflict.replayed);
    assert_eq!(replayed_conflict.new_snapshot, conflicted.new_snapshot);
    assert_eq!(replayed_conflict.disposition, conflicted.disposition);
}

#[test]
fn executor_candidate_publication_is_immutable_and_does_not_advance_the_campaign() {
    let (repository, lineage, policy) = fixture();
    let (_, admitted, observation) =
        admitted_observation_fixture(&repository, &lineage, &policy, "observation-candidate");
    let head_before = repository
        .head("observation-candidate")
        .expect("admitted head");
    let candidate = ObservationCandidate::new(
        repository
            .load_configuration_artifact(observation.child_content())
            .expect("candidate child"),
        repository
            .load_measurement_set(observation.measurements())
            .expect("candidate measurements"),
        repository
            .load_property_verdict_set(observation.properties())
            .expect("candidate properties"),
        repository
            .load_coverage_projection(observation.coverage())
            .expect("candidate coverage"),
        observation
            .discovered_choices()
            .iter()
            .map(|id| choice_discovery_fixture(&repository, *id))
            .collect(),
        observation.clone(),
    )
    .expect("valid candidate");

    let published = repository
        .publish_observation_candidate(&candidate)
        .expect("publish immutable candidate");
    assert_eq!(published, observation.id().expect("observation id"));
    assert_eq!(
        repository
            .head("observation-candidate")
            .expect("unchanged campaign head")
            .snapshot_id(),
        head_before.snapshot_id()
    );

    let incorporated = repository
        .publish_observation(
            "observation-candidate",
            admitted.new_snapshot,
            candidate.observation(),
        )
        .expect("coordinator incorporates candidate");
    assert_eq!(incorporated.observation, published);
}

#[test]
fn campaign_report_counts_distinct_findings_from_one_observation() {
    let (repository, lineage, policy) = fixture();
    let campaign = "report-multiple-findings";
    let (_, admitted, base_observation) =
        admitted_observation_fixture(&repository, &lineage, &policy, campaign);
    let properties = PropertyVerdictSet::new(BTreeMap::from([
        (
            "no-forwarding-loop".to_owned(),
            PropertyEvidence::new(PropertyVerdict::Failed, BTreeSet::new())
                .expect("first failed property"),
        ),
        (
            "recovers-within-bound".to_owned(),
            PropertyEvidence::new(PropertyVerdict::Failed, BTreeSet::new())
                .expect("second failed property"),
        ),
    ]))
    .expect("failed property verdicts");
    let properties = repository
        .publish_property_verdict_set(&properties)
        .expect("publish failed property verdicts");
    let observation = Observation::new(
        base_observation.attempt(),
        base_observation.child(),
        base_observation.child_content(),
        base_observation.path(),
        base_observation.stop().clone(),
        base_observation.measurements(),
        properties,
        base_observation.coverage(),
        base_observation.discovered_choices().clone(),
    )
    .expect("observation with two failed properties");
    let observed = repository
        .publish_observation(campaign, admitted.new_snapshot, &observation)
        .expect("publish observation");

    let fingerprint = CampaignHash::derive("test-finding", b"two property failures");
    let reproduction = repository
        .publish_reproduction_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            observation.child(),
            observation.child_content(),
            fingerprint,
            1,
            b"verified two-property reproduction".to_vec(),
        )
        .expect("publish reproduction");
    let mut snapshot = observed.new_snapshot;
    for property in ["no-forwarding-loop", "recovers-within-bound"] {
        let signature = FindingSignature::new(
            FindingKind::PropertyViolation,
            fingerprint,
            Some(property.to_owned()),
            "guest.property-violation".to_owned(),
            Some(FindingTarget::Configuration(observation.child_content())),
            BTreeSet::from([properties.content_id()]),
        )
        .expect("property finding signature");
        snapshot = repository
            .publish_finding_with_retention(
                campaign,
                snapshot,
                signature,
                observed.observation,
                reproduction,
                None,
                FindingExactPins::default(),
            )
            .expect("publish property finding")
            .new_snapshot;
    }

    let (report, endpoints) = repository
        .project_campaign_report(campaign, snapshot)
        .expect("project campaign report");
    assert_eq!(report.outcomes().explored(), 1);
    assert_eq!(report.outcomes().failures(), 0);
    assert_eq!(report.outcomes().findings(), 2);
    assert!(endpoints.is_empty());
}

#[test]
fn finding_publication_clusters_replay_and_fails_before_invalid_writes() {
    let (repository, lineage, base_policy, blobs) = counted_fixture();
    let finding_signal = FindingKind::Divergence.guidance_signal().to_owned();
    let policy = CampaignPolicy::new(
        base_policy.scenario(),
        base_policy.campaign_seed(),
        base_policy.mode(),
        base_policy.explorer().clone(),
        base_policy.choice_policies().clone(),
        base_policy.objectives().clone(),
        BTreeMap::from([(
            finding_signal.clone(),
            GuidanceWeight::new(finding_signal, 250_000).expect("finding guidance"),
        )]),
        base_policy.stop_conditions().clone(),
        base_policy.fairness(),
        base_policy.retention(),
        base_policy.admits_scenario_defaults(),
    )
    .expect("finding-weighted policy")
    .with_intervention_learning_policy(InterventionLearningPolicy::IncludeInGuidance)
    .expect("intervention-guided finding policy");
    let (_, admitted, observation) =
        admitted_observation_fixture(&repository, &lineage, &policy, "finding-publication");
    let observed = repository
        .publish_observation("finding-publication", admitted.new_snapshot, &observation)
        .expect("publish observation");
    let attempt = repository
        .read_attempt(observation.attempt().content_id())
        .expect("finding attempt");
    let path = repository
        .read_branch_path(attempt.path().content_id())
        .expect("finding path");
    let segment = path
        .segments()
        .first()
        .copied()
        .expect("finding scoped branch segment");
    let before_finding = repository
        .project_branch_puct(observed.new_snapshot, segment.branch_point())
        .expect("PUCT before finding publication");
    assert!(before_finding.edge_finding_events().is_empty());
    assert!(before_finding.edge_finding_reward_micros().is_empty());
    assert_eq!(
        before_finding.edge_statistics()[&segment.edge()].reward_sum_micros(),
        0
    );
    let fingerprint = CampaignHash::derive("test-finding", b"replay divergence");
    let reproduction = repository
        .publish_reproduction_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            observation.child(),
            observation.child_content(),
            fingerprint,
            1,
            b"verified self-contained reproduction".to_vec(),
        )
        .expect("publish reproduction");
    let signature = FindingSignature::new(
        FindingKind::Divergence,
        fingerprint,
        None,
        "qemu.replay-divergence".to_owned(),
        Some(FindingTarget::Configuration(observation.child_content())),
        BTreeSet::from([observation.properties().content_id()]),
    )
    .expect("finding signature");

    let published = repository
        .publish_finding_with_retention(
            "finding-publication",
            observed.new_snapshot,
            signature.clone(),
            observed.observation,
            reproduction,
            None,
            FindingExactPins::default(),
        )
        .expect("publish finding");
    assert!(!published.replayed);
    let finding_puct = repository
        .project_branch_puct(published.new_snapshot, segment.branch_point())
        .expect("PUCT after finding publication");
    assert_eq!(
        finding_puct.edge_finding_events(),
        &BTreeMap::from([(
            segment.edge(),
            BTreeMap::from([(FindingKind::Divergence, 1)]),
        )])
    );
    assert_eq!(
        finding_puct.edge_finding_reward_micros(),
        &BTreeMap::from([(segment.edge(), 250_000)])
    );
    assert_eq!(
        finding_puct.edge_statistics()[&segment.edge()].reward_sum_micros(),
        250_000
    );
    assert_eq!(
        finding_puct.edge_scores()[&segment.edge()].mean_reward_micros(),
        250_000
    );
    let head = repository
        .head("finding-publication")
        .expect("finding head");
    assert_eq!(head.snapshot_id(), published.new_snapshot);
    assert_eq!(
        repository
            .merkle
            .get(
                head.snapshot().roots().findings,
                map_key_hash("findings.signature", signature.cluster_key()),
            )
            .expect("finding lookup"),
        Some(published.finding.content_id())
    );
    let stored = repository
        .read_finding(published.finding.content_id())
        .expect("read finding");
    assert_eq!(stored.first_seen_snapshot(), observed.new_snapshot);
    assert_eq!(stored.occurrence_count(), 1);
    assert_eq!(
        repository
            .merkle
            .get(
                stored.occurrences(),
                finding_occurrence_key(observed.observation),
            )
            .expect("occurrence lookup"),
        Some(observed.observation.content_id())
    );
    let finding_request = QueryCampaignFindingsRequest::new(
        CampaignPrincipal::new("operator:alice").expect("principal"),
        CampaignName::new("finding-publication").expect("campaign"),
        published.new_snapshot,
        None,
        MAX_CAMPAIGN_FINDING_QUERY_PAGE_ITEMS,
    )
    .expect("finding query request");
    let client = crate::CampaignClient::new(RepositoryCampaignService::new(
        &repository,
        AllowCampaignQueries,
    ));
    let finding_page = client
        .query_campaign_findings(&finding_request)
        .expect("authenticated finding page");
    assert_eq!(finding_page.entries(), std::slice::from_ref(&stored));
    assert_eq!(finding_page.next_after(), None);
    for (kind, expected) in [
        (
            CampaignFindingObjectKind::Observation,
            observed.observation.content_id(),
        ),
        (
            CampaignFindingObjectKind::Reproduction,
            reproduction.content_id(),
        ),
    ] {
        let request = GetCampaignFindingObjectRequest::new(
            finding_request.principal().clone(),
            finding_request.campaign().clone(),
            published.new_snapshot,
            published.finding,
            kind,
        )
        .expect("finding object request");
        let response = client
            .get_campaign_finding_object(&request)
            .expect("authenticated finding dependency");
        let actual = match response.object() {
            CampaignFindingObject::Observation(value)
            | CampaignFindingObject::LatestOccurrence(value) => {
                value.id().expect("observation ID").content_id()
            }
            CampaignFindingObject::Reproduction(value)
            | CampaignFindingObject::MinimizedReproduction(value) => {
                value.id().expect("reproduction ID").content_id()
            }
        };
        assert_eq!(actual, expected);
    }
    let attempt_request = ExplainCampaignAttemptRequest::new(
        finding_request.principal().clone(),
        finding_request.campaign().clone(),
        published.new_snapshot,
        observation.attempt(),
    )
    .expect("attempt explanation request");
    let attempt_response = client
        .explain_campaign_attempt(&attempt_request)
        .expect("authenticated attempt explanation");
    assert_eq!(
        attempt_response
            .attempt()
            .id()
            .expect("explained attempt ID"),
        observation.attempt()
    );
    assert_eq!(
        attempt_response
            .observation()
            .expect("completed attempt observation")
            .id()
            .expect("explained observation ID"),
        observed.observation
    );
    assert!(attempt_response.selection().is_some());
    assert!(attempt_response.proposal().is_some());
    repository.evict_local_checkpoint(published.new_snapshot.content_id());
    assert_eq!(
        repository
            .head("finding-publication")
            .expect("restart-style finding validation")
            .snapshot_id(),
        published.new_snapshot
    );
    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    assert_eq!(
        restarted
            .project_branch_puct(published.new_snapshot, segment.branch_point())
            .expect("restart-project finding PUCT"),
        finding_puct
    );

    let replayed = repository
        .publish_finding_with_retention(
            "finding-publication",
            published.new_snapshot,
            signature.clone(),
            observed.observation,
            reproduction,
            None,
            FindingExactPins::default(),
        )
        .expect("replay finding");
    assert!(replayed.replayed);
    assert_eq!(replayed.new_snapshot, published.new_snapshot);

    let invalid = FindingSignature::new(
        FindingKind::Divergence,
        fingerprint,
        None,
        "qemu.replay-divergence".to_owned(),
        None,
        BTreeSet::from([ContentId::for_bytes(
            ObjectKind::Trace,
            1,
            b"foreign evidence",
        )]),
    )
    .expect("structurally valid foreign evidence");
    let count_before = blobs.object_count().expect("object count");
    assert!(matches!(
        repository.publish_finding_with_retention(
            "finding-publication",
            published.new_snapshot,
            invalid,
            observed.observation,
            reproduction,
            None,
            FindingExactPins::default(),
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "finding-candidate-evidence-is-not-observation-owned"
        })
    ));
    assert_eq!(
        blobs.object_count().expect("object count after rejection"),
        count_before
    );
    assert_eq!(
        repository
            .head("finding-publication")
            .expect("unchanged head")
            .snapshot_id(),
        published.new_snapshot
    );
}

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
        1,
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

    let published = repository
        .publish_finding_with_retention(
            "minimized-finding",
            observed.new_snapshot,
            signature.clone(),
            observed.observation,
            original,
            Some(minimized),
            FindingExactPins::default(),
        )
        .expect("publish minimized finding");
    let stored = repository
        .read_finding(published.finding.content_id())
        .expect("load minimized finding");
    assert_eq!(stored.schema_version(), 2);
    assert_eq!(stored.minimized(), Some(minimized));
    assert_eq!(
        repository
            .load_reproduction_artifact(minimized)
            .expect("load minimized reproduction")
            .minimization()
            .expect("retained minimization trace")
            .original(),
        original
    );
    repository.evict_local_checkpoint(published.new_snapshot.content_id());
    assert_eq!(
        repository
            .head("minimized-finding")
            .expect("restart-style minimized finding validation")
            .snapshot_id(),
        published.new_snapshot
    );

    let missing_original = ReproductionArtifactId::from_content_id(ContentId::for_bytes(
        ObjectKind::Finding,
        1,
        b"missing original reproduction",
    ))
    .expect("missing reproduction id");
    let invalid_trace = FindingMinimizationEvidence::new(
        missing_original,
        1,
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
        observed.observation,
        signature.clone(),
        original,
        minimized,
        signature_minimization,
        FindingExactPins::default(),
        Some(triage_evidence),
        None,
        exact_retention,
    )
    .expect("finding candidate bundle");
    assert_eq!(bundle.schema_version(), 4);

    let mismatched_triage_bundle = FindingCandidateBundle::new_with_triage_evidence(
        observed.observation,
        signature.clone(),
        original,
        minimized,
        bundle.signature_minimization().clone(),
        FindingExactPins::default(),
        FindingTriageEvidenceSet::new(
            triage_evidence.minimization_selected(),
            triage_evidence.minimization_original(),
            triage_evidence.verification_original(),
            triage_evidence.verification_selected(),
        ),
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
            .expect("load schema-v2 finding candidate bundle"),
        bundle
    );
    let upgraded = repository
        .incorporate_finding_candidate_bundle(
            "minimized-finding",
            published.new_snapshot,
            bundle_id,
        )
        .expect("upgrade schema-v2 finding with candidate occurrence");
    assert!(!upgraded.replayed);

    let upgraded_finding = repository
        .read_finding(upgraded.finding.content_id())
        .expect("upgraded finding");
    assert_eq!(upgraded_finding.schema_version(), 4);
    assert_eq!(upgraded_finding.observation(), stored.observation());
    assert_eq!(upgraded_finding.reproduction(), stored.reproduction());
    assert_eq!(upgraded_finding.minimized(), stored.minimized());
    assert_eq!(
        upgraded_finding.first_seen_snapshot(),
        stored.first_seen_snapshot()
    );
    assert_eq!(upgraded_finding.candidate_bundle(), Some(bundle_id));
    assert_eq!(upgraded_finding.candidate_occurrence_count(), 1);
    repository.evict_local_checkpoint(upgraded.new_snapshot.content_id());
    assert_eq!(
        repository
            .head("minimized-finding")
            .expect("cold schema-v2-to-v4 history validation")
            .snapshot_id(),
        upgraded.new_snapshot
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
        1,
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
            observed.observation,
            signature.clone(),
            original,
            minimized,
            signatures.clone(),
            FindingExactPins::default(),
            None,
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

#[test]
fn executor_candidate_publishes_fresh_choices_with_shared_contract_records() {
    let (repository, lineage, policy) = fixture();
    let (_, admitted, basis) =
        admitted_observation_fixture(&repository, &lineage, &policy, "fresh-candidate-choice");
    let alternative = AlternativeId::from_hash(CampaignHash::derive(
        "test-fresh-candidate-alternative",
        b"new",
    ));
    let domain = ChoiceDomain::Discrete(
        DiscreteDomain::new(
            1,
            BTreeMap::from([(
                alternative,
                DiscreteAlternative::new(alternative, "new", None).expect("fresh alternative"),
            )]),
        )
        .expect("fresh domain"),
    );
    let declaration = SelectableDeclaration::new(
        "product.test.fresh-candidate-choice",
        ChoiceSource::Workload {
            producer: "fresh-candidate-producer".to_owned(),
        },
        domain.clone(),
        ChoiceValue::Discrete(alternative),
        ChoiceClassContext::new(BTreeSet::new()).expect("fresh choice class"),
        BTreeSet::new(),
        true,
    )
    .expect("fresh declaration");
    let fresh = ChoiceOpportunity::new(
        lineage.scenario(),
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: CampaignHash::derive("test-fresh-candidate-scheduler", b"new"),
            producer: CampaignHash::derive("test-fresh-candidate-producer", b"new"),
        },
        "fresh-executor-discovery",
        None,
    )
    .expect("fresh opportunity");
    let fresh_id = fresh.id().expect("fresh opportunity id");
    let second = ChoiceOpportunity::new(
        lineage.scenario(),
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: CampaignHash::derive("test-fresh-candidate-scheduler", b"second"),
            producer: CampaignHash::derive("test-fresh-candidate-producer", b"new"),
        },
        "second-fresh-executor-discovery",
        None,
    )
    .expect("second fresh opportunity");
    let second_id = second.id().expect("second fresh opportunity id");
    let declaration_id = declaration.id().expect("fresh declaration id");
    let domain_id = domain.id().expect("fresh domain id");
    assert!(matches!(
        repository.load_selectable(declaration_id),
        Err(CampaignRepositoryError::Store(StoreError::NotFound { .. }))
    ));
    assert!(matches!(
        repository.load_choice_domain(domain_id),
        Err(CampaignRepositoryError::Store(StoreError::NotFound { .. }))
    ));
    assert!(matches!(
        repository.load_choice_opportunity(fresh_id),
        Err(CampaignRepositoryError::Store(StoreError::NotFound { .. }))
    ));
    assert!(matches!(
        repository.load_choice_opportunity(second_id),
        Err(CampaignRepositoryError::Store(StoreError::NotFound { .. }))
    ));

    let observation = Observation::new(
        basis.attempt(),
        basis.child(),
        basis.child_content(),
        basis.path(),
        basis.stop().clone(),
        basis.measurements(),
        basis.properties(),
        basis.coverage(),
        BTreeSet::from([fresh_id, second_id]),
    )
    .expect("fresh-choice observation");
    let candidate = ObservationCandidate::new(
        repository
            .load_configuration_artifact(observation.child_content())
            .expect("candidate child"),
        repository
            .load_measurement_set(observation.measurements())
            .expect("candidate measurements"),
        repository
            .load_property_verdict_set(observation.properties())
            .expect("candidate properties"),
        repository
            .load_coverage_projection(observation.coverage())
            .expect("candidate coverage"),
        vec![
            ChoiceDiscovery::new(declaration.clone(), domain.clone(), fresh.clone())
                .expect("fresh choice discovery"),
            ChoiceDiscovery::new(declaration, domain, second.clone())
                .expect("second fresh choice discovery"),
        ],
        observation,
    )
    .expect("fresh candidate");
    assert!(Arc::ptr_eq(
        &candidate.discovered_choices()[0].declaration,
        &candidate.discovered_choices()[1].declaration,
    ));
    assert!(Arc::ptr_eq(
        &candidate.discovered_choices()[0].domain,
        &candidate.discovered_choices()[1].domain,
    ));
    let selection_observation = Observation::new(
        candidate.observation().attempt(),
        candidate.observation().child(),
        candidate.observation().child_content(),
        candidate.observation().path(),
        StopOutcome::Reached(StopCondition::Terminal),
        candidate.observation().measurements(),
        candidate.observation().properties(),
        candidate.observation().coverage(),
        candidate.observation().discovered_choices().clone(),
    )
    .expect("produced-selection observation");
    let selection_candidate = ObservationCandidate::new(
        candidate.child().clone(),
        candidate.measurements().clone(),
        candidate.properties().clone(),
        candidate.coverage().clone(),
        candidate.discovered_choices().to_vec(),
        selection_observation,
    )
    .expect("produced-selection candidate");
    let produced_selection = Selection::new(
        &fresh,
        candidate.discovered_choices()[0].domain(),
        ChoiceValue::Discrete(alternative),
        SelectionOrigin::Default,
    )
    .expect("produced default selection");
    let produced_candidate = selection_candidate
        .with_produced_selections(vec![produced_selection.clone()])
        .expect("candidate with produced selection");
    assert_eq!(
        produced_candidate.observation().produced_selections(),
        &BTreeSet::from([produced_selection.id().expect("produced selection id")])
    );
    assert!(matches!(
        produced_candidate.with_produced_selections(Vec::new()),
        Err(CampaignCodecError::InvalidValue {
            reason: "observation candidate already carries produced selections"
        })
    ));
    let mut mismatched_candidate = candidate.clone();
    mismatched_candidate.observation = mismatched_candidate
        .observation
        .clone()
        .with_produced_selections(BTreeSet::from([produced_selection
            .id()
            .expect("produced selection id")]))
        .expect("mismatched candidate observation");
    assert!(matches!(
        repository.validate_observation_candidate(&mismatched_candidate),
        Err(CampaignRepositoryError::Integrity {
            reason: "observation-produced-selection-bundle-mismatch"
        })
    ));

    repository
        .publish_observation_candidate(&candidate)
        .expect("publish candidate and fresh choice");
    assert_eq!(
        repository
            .load_selectable(declaration_id)
            .expect("load published declaration"),
        *candidate.discovered_choices()[0].declaration()
    );
    assert_eq!(
        repository
            .load_choice_domain(domain_id)
            .expect("load published domain"),
        *candidate.discovered_choices()[0].domain()
    );
    assert_eq!(
        repository
            .load_choice_opportunity(fresh_id)
            .expect("load published fresh choice"),
        fresh
    );
    assert_eq!(
        repository
            .load_choice_opportunity(second_id)
            .expect("load second published fresh choice"),
        second
    );
    let published = repository
        .publish_observation(
            "fresh-candidate-choice",
            admitted.new_snapshot,
            candidate.observation(),
        )
        .expect("admit candidate observation");
    let head = repository
        .head("fresh-candidate-choice")
        .expect("choice-index head");
    assert_eq!(head.snapshot_id(), published.new_snapshot);
    let (page, _, _) = repository
        .scan_choice_page(head.snapshot().roots().graph, None, 16)
        .expect("choice index page");
    for opportunity in [fresh_id, second_id] {
        assert!(page.entries().iter().any(|(key, value)| {
            *key == choice_index_order_key(opportunity) && *value == opportunity.content_id()
        }));
    }
}

#[test]
fn invalid_executor_candidate_is_rejected_before_any_bundle_write() {
    let (repository, lineage, policy, blobs) = counted_fixture();
    let (_, _, observation) = admitted_observation_fixture(
        &repository,
        &lineage,
        &policy,
        "invalid-observation-candidate",
    );
    let child = ConfigurationArtifact::new(
        lineage.scenario(),
        lineage.scenario_content(),
        ConfigurationId::from_hash(CampaignHash::derive(
            "test-invalid-candidate-child",
            b"child",
        )),
        1,
        b"unpublished-invalid-child".to_vec(),
    )
    .expect("candidate child");
    let candidate = ObservationCandidate::new(
        child,
        repository
            .load_measurement_set(observation.measurements())
            .expect("candidate measurements"),
        repository
            .load_property_verdict_set(observation.properties())
            .expect("candidate properties"),
        repository
            .load_coverage_projection(observation.coverage())
            .expect("candidate coverage"),
        observation
            .discovered_choices()
            .iter()
            .map(|id| choice_discovery_fixture(&repository, *id))
            .collect(),
        observation,
    )
    .expect("valid candidate");
    let objects_before = blobs.object_count().expect("objects before rejection");

    assert!(matches!(
        repository.publish_observation_candidate(&candidate),
        Err(CampaignRepositoryError::Integrity {
            reason: "observation-candidate-bundle-mismatch"
        })
    ));
    assert_eq!(
        blobs.object_count().expect("objects after rejection"),
        objects_before
    );
}

#[test]
fn observation_ref_conflict_leaves_the_admitted_head_authoritative() {
    let (fixture_repository, lineage, policy, blobs) = counted_fixture();
    drop(fixture_repository);
    let refs = Arc::new(ConflictAfterCreateRefBackend::new());
    let repository = CampaignRepository::new(blobs, refs.clone());
    let (_, admitted, observation) =
        admitted_observation_fixture(&repository, &lineage, &policy, "observation-cas");
    let checkpoint_count = repository
        .validated_heads
        .lock()
        .expect("validation checkpoints")
        .len();
    refs.arm();

    assert!(matches!(
        repository.publish_observation("observation-cas", admitted.new_snapshot, &observation,),
        Err(CampaignRepositoryError::RefConflict { .. })
    ));
    assert_eq!(
        repository
            .head("observation-cas")
            .expect("authoritative admitted head")
            .snapshot_id(),
        admitted.new_snapshot
    );
    assert_eq!(
        repository
            .validated_heads
            .lock()
            .expect("validation checkpoints")
            .len(),
        checkpoint_count
    );
}

struct RecordingFindingCheckpointAuthenticator {
    calls: Arc<Mutex<Vec<(ExactCheckpointId, u64)>>>,
    metadata_bytes: u64,
    scenario_override: Option<ScenarioDefId>,
    configuration_override: Option<ConfigurationId>,
    event_counts: BTreeMap<ExactCheckpointId, u64>,
    failure: Option<FindingExactCheckpointAuthenticationError>,
    object_source: Option<Arc<MemoryBlobBackend>>,
}

impl FindingExactCheckpointAuthenticator for RecordingFindingCheckpointAuthenticator {
    fn authenticate_finding_exact_checkpoint(
        &self,
        checkpoint: ExactCheckpointId,
        scenario: ScenarioDefId,
        _scenario_artifact: ScenarioArtifactId,
        configuration: ConfigurationId,
        maximum_metadata_bytes: u64,
    ) -> Result<AuthenticatedFindingExactCheckpoint, FindingExactCheckpointAuthenticationError>
    {
        self.calls
            .lock()
            .expect("record finding checkpoint authentication")
            .push((checkpoint, maximum_metadata_bytes));
        if let Some(error) = self.failure {
            return Err(error);
        }
        Ok(AuthenticatedFindingExactCheckpoint::new(
            self.scenario_override.unwrap_or(scenario),
            self.configuration_override.unwrap_or(configuration),
            *self
                .event_counts
                .get(&checkpoint)
                .expect("recorded checkpoint event count"),
            self.metadata_bytes,
        ))
    }

    fn read_finding_exact_checkpoint_object(
        &self,
        object: ContentId,
    ) -> Result<BlobHandle, FindingExactCheckpointAuthenticationError> {
        self.object_source
            .as_ref()
            .ok_or(FindingExactCheckpointAuthenticationError::AuthenticationFailed)?
            .read(object, None)
            .map_err(|_| FindingExactCheckpointAuthenticationError::AuthenticationFailed)
    }
}

fn recording_finding_checkpoint_authenticator(
    calls: Arc<Mutex<Vec<(ExactCheckpointId, u64)>>>,
    metadata_bytes: u64,
    event_counts: BTreeMap<ExactCheckpointId, u64>,
) -> RecordingFindingCheckpointAuthenticator {
    RecordingFindingCheckpointAuthenticator {
        calls,
        metadata_bytes,
        scenario_override: None,
        configuration_override: None,
        event_counts,
        failure: None,
        object_source: None,
    }
}

fn publish_test_exact_checkpoint_closure(
    repository: &CampaignRepository,
    label: &[u8],
) -> (ExactCheckpointId, ContentId, Vec<u8>) {
    let mut manifest_bytes = b"test exact manifest ".to_vec();
    manifest_bytes.extend_from_slice(label);
    let manifest = ContentId::for_bytes(ObjectKind::DeviceState, 1, &manifest_bytes);
    repository
        .blobs
        .put_if_absent(manifest, &BlobHandle::from_bytes(manifest_bytes))
        .expect("publish test exact manifest");

    let mut leaf_bytes = b"test exact leaf ".to_vec();
    leaf_bytes.extend_from_slice(label);
    let leaf = ContentId::for_bytes(ObjectKind::Trace, 1, &leaf_bytes);
    repository
        .blobs
        .put_if_absent(leaf, &BlobHandle::from_bytes(leaf_bytes.clone()))
        .expect("publish test exact leaf");

    let index = ContentEnvelope::new(
        "crucible.test.exact-checkpoint-index",
        1,
        BTreeSet::from([ContentChild::new("object.0000", leaf).expect("index child")]),
        b"test exact index".to_vec(),
    )
    .expect("test exact index");
    let index_id = index.content_id(ObjectKind::ExactManifest);
    repository
        .blobs
        .put_if_absent(index_id, &BlobHandle::from_bytes(index.canonical_bytes()))
        .expect("publish test exact index");

    let root = ContentEnvelope::new(
        "crucible.test.exact-checkpoint-root",
        4,
        BTreeSet::from([
            ContentChild::new("index.0000", index_id).expect("root index child"),
            ContentChild::new("manifest", manifest).expect("root manifest child"),
        ]),
        b"test exact root".to_vec(),
    )
    .expect("test exact root");
    let root_id = root.content_id(ObjectKind::ExactManifest);
    repository
        .blobs
        .put_if_absent(root_id, &BlobHandle::from_bytes(root.canonical_bytes()))
        .expect("publish test exact root");

    (
        ExactCheckpointId::from_content_id(root_id).expect("test exact checkpoint ID"),
        leaf,
        leaf_bytes,
    )
}

fn delete_test_blob(blobs: &MemoryBlobBackend, id: ContentId) {
    let mut inventory = blobs
        .acquire_inventory_fence()
        .expect("acquire test deletion fence");
    inventory
        .delete_candidate(id)
        .expect("delete test blob candidate");
}

#[test]
fn complete_exact_retention_requires_executor_authentication_and_cold_loads_attestation() {
    let (repository, lineage, policy, blobs) = counted_fixture();
    let (_, admitted, observation) = admitted_observation_fixture(
        &repository,
        &lineage,
        &policy,
        "authenticated-exact-retention",
    );
    let observed = repository
        .publish_observation(
            "authenticated-exact-retention",
            admitted.new_snapshot,
            &observation,
        )
        .expect("publish exact-retention observation");

    let fingerprint = CampaignHash::derive("test-finding", b"authenticated retention");
    let original = repository
        .publish_reproduction_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            observation.child(),
            observation.child_content(),
            fingerprint,
            1,
            b"authenticated original".to_vec(),
        )
        .expect("publish authenticated original");
    let final_state = CampaignHash::derive("test-finding", b"authenticated final state");
    let minimization = FindingMinimizationEvidence::new(
        original,
        1,
        b"authenticated minimization".to_vec(),
        vec![FindingMinimizationAttempt::new(
            0,
            CampaignHash::derive("test-finding", b"authenticated candidate"),
            CampaignHash::derive("test-finding", b"authenticated schedule"),
            final_state,
            Some(fingerprint),
            true,
        )],
        final_state,
    )
    .expect("authenticated minimization evidence");
    let minimized = repository
        .publish_minimized_reproduction_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            observation.child(),
            observation.child_content(),
            fingerprint,
            1,
            b"authenticated minimized".to_vec(),
            minimization.clone(),
        )
        .expect("publish authenticated minimized reproduction");
    let signature = FindingSignature::new(
        FindingKind::Divergence,
        fingerprint,
        None,
        "qemu.authenticated-retention".to_owned(),
        Some(FindingTarget::Configuration(observation.child_content())),
        BTreeSet::new(),
    )
    .expect("authenticated signature");
    let signatures = FindingSignatureMinimizationEvidence::new(
        &signature,
        &minimization,
        vec![Some(signature.clone()), Some(signature.clone())],
        vec![Some(signature.clone()), Some(signature.clone())],
    )
    .expect("authenticated signature evidence");

    let checkpoint_blobs = Arc::new(MemoryBlobBackend::new(
        "selected-exact-checkpoint-source",
        64 * 1024 * 1024,
    ));
    let checkpoint_repository =
        CampaignRepository::new(checkpoint_blobs.clone(), Arc::new(MemoryRefBackend::new()));
    let (checkpoint, selected_leaf, selected_leaf_bytes) =
        publish_test_exact_checkpoint_closure(&checkpoint_repository, b"selected");
    let (unselected_checkpoint, _, _) =
        publish_test_exact_checkpoint_closure(&checkpoint_repository, b"unselected");
    let exact_pins = FindingExactPins::new(
        BTreeSet::new(),
        BTreeSet::new(),
        BTreeSet::from([checkpoint]),
        BTreeSet::new(),
    )
    .expect("selected exact pins");
    let mut candidates = vec![
        FindingExactRetentionCandidate::new(checkpoint, 5),
        FindingExactRetentionCandidate::new(unselected_checkpoint, 6),
    ];
    candidates.sort_by_key(|candidate| candidate.checkpoint());
    let evidence =
        FindingExactRetentionEvidence::new(candidates, checkpoint, 5, None, exact_pins.clone())
            .expect("authenticated inventory evidence");
    let basis = repository
        .attempt_retention_policy_basis_at(admitted.new_snapshot, admitted.attempt)
        .expect("retention policy basis");
    let retention = FindingExactRetention::new(
        basis.snapshot(),
        basis.policy(),
        basis.admission(),
        2,
        FindingExactRetentionDisposition::Complete,
    )
    .expect("complete retention outcome");
    let single_candidate_evidence = FindingExactRetentionEvidence::new(
        vec![FindingExactRetentionCandidate::new(checkpoint, 5)],
        checkpoint,
        5,
        None,
        exact_pins.clone(),
    )
    .expect("single-candidate exact evidence");
    let single_candidate_retention = FindingExactRetention::new(
        basis.snapshot(),
        basis.policy(),
        basis.admission(),
        1,
        FindingExactRetentionDisposition::Complete,
    )
    .expect("single-candidate exact retention");
    let legacy_complete_bundle = FindingCandidateBundle::new_with_exact_retention(
        observed.observation,
        signature.clone(),
        original,
        minimized,
        signatures.clone(),
        exact_pins.clone(),
        None,
        None,
        single_candidate_retention,
    )
    .expect("legacy V4 complete finding bundle");
    let single_candidate_bundle = FindingCandidateBundle::new_with_authenticated_exact_retention(
        observed.observation,
        signature.clone(),
        original,
        minimized,
        signatures.clone(),
        exact_pins.clone(),
        None,
        None,
        single_candidate_retention,
        single_candidate_evidence,
    )
    .expect("single-candidate V5 finding bundle");
    let bundle = FindingCandidateBundle::new_with_authenticated_exact_retention(
        observed.observation,
        signature,
        original,
        minimized,
        signatures,
        exact_pins,
        None,
        None,
        retention,
        evidence,
    )
    .expect("V5 finding bundle");
    let bundle_id = bundle.id().expect("V5 finding bundle ID");
    assert!(matches!(
        repository.publish_finding_candidate_bundle(&bundle),
        Err(CampaignRepositoryError::Integrity {
            reason: "finding-exact-checkpoint-authenticator-is-missing"
        })
    ));
    assert!(
        !repository
            .blobs
            .contains(bundle_id.content_id())
            .expect("rejected bundle presence")
    );

    let repository = Arc::new(repository);
    let candidate_events = BTreeMap::from([(checkpoint, 5), (unselected_checkpoint, 6)]);

    let legacy_complete_authenticator = recording_finding_checkpoint_authenticator(
        Arc::new(Mutex::new(Vec::new())),
        17,
        BTreeMap::from([(checkpoint, 5)]),
    );
    let legacy_complete_store = CampaignExecutorStore::with_finding_exact_checkpoint_authenticator(
        Arc::clone(&repository),
        Arc::new(legacy_complete_authenticator),
    );
    assert!(matches!(
        legacy_complete_store.publish_executor_finding_candidate(&legacy_complete_bundle),
        Err(CampaignRepositoryError::Integrity {
            reason: "complete-finding-exact-retention-requires-authenticated-evidence"
        })
    ));

    let mut failed_authenticator = recording_finding_checkpoint_authenticator(
        Arc::new(Mutex::new(Vec::new())),
        17,
        candidate_events.clone(),
    );
    failed_authenticator.failure =
        Some(FindingExactCheckpointAuthenticationError::AuthenticationFailed);
    let failed_store = CampaignExecutorStore::with_finding_exact_checkpoint_authenticator(
        Arc::clone(&repository),
        Arc::new(failed_authenticator),
    );
    assert!(matches!(
        failed_store.publish_executor_finding_candidate(&bundle),
        Err(CampaignRepositoryError::Integrity {
            reason: "finding-exact-retention-candidate-authentication-failed"
        })
    ));

    let mut wrong_scenario = recording_finding_checkpoint_authenticator(
        Arc::new(Mutex::new(Vec::new())),
        17,
        candidate_events.clone(),
    );
    wrong_scenario.scenario_override = Some(ScenarioDefId::from_hash(CampaignHash::derive(
        "test.wrong-finding-scenario",
        b"wrong scenario",
    )));
    let wrong_scenario_store = CampaignExecutorStore::with_finding_exact_checkpoint_authenticator(
        Arc::clone(&repository),
        Arc::new(wrong_scenario),
    );
    assert!(
        wrong_scenario_store
            .publish_executor_finding_candidate(&bundle)
            .is_err()
    );

    let mut wrong_configuration = recording_finding_checkpoint_authenticator(
        Arc::new(Mutex::new(Vec::new())),
        17,
        candidate_events.clone(),
    );
    wrong_configuration.configuration_override = Some(ConfigurationId::from_hash(
        CampaignHash::derive("test.wrong-finding-configuration", b"wrong configuration"),
    ));
    let wrong_configuration_store =
        CampaignExecutorStore::with_finding_exact_checkpoint_authenticator(
            Arc::clone(&repository),
            Arc::new(wrong_configuration),
        );
    assert!(
        wrong_configuration_store
            .publish_executor_finding_candidate(&bundle)
            .is_err()
    );

    let wrong_events = recording_finding_checkpoint_authenticator(
        Arc::new(Mutex::new(Vec::new())),
        17,
        BTreeMap::from([(checkpoint, 4), (unselected_checkpoint, 6)]),
    );
    let wrong_events_store = CampaignExecutorStore::with_finding_exact_checkpoint_authenticator(
        Arc::clone(&repository),
        Arc::new(wrong_events),
    );
    assert!(
        wrong_events_store
            .publish_executor_finding_candidate(&bundle)
            .is_err()
    );

    let single_over_limit = recording_finding_checkpoint_authenticator(
        Arc::new(Mutex::new(Vec::new())),
        (64 * 1024 * 1024) + 1,
        BTreeMap::from([(checkpoint, 5)]),
    );
    let single_over_limit_store =
        CampaignExecutorStore::with_finding_exact_checkpoint_authenticator(
            Arc::clone(&repository),
            Arc::new(single_over_limit),
        );
    assert!(matches!(
        single_over_limit_store.publish_executor_finding_candidate(&single_candidate_bundle),
        Err(CampaignRepositoryError::Integrity {
            reason: "finding-exact-retention-metadata-byte-limit"
        })
    ));

    let mut single_at_limit = recording_finding_checkpoint_authenticator(
        Arc::new(Mutex::new(Vec::new())),
        64 * 1024 * 1024,
        BTreeMap::from([(checkpoint, 5)]),
    );
    single_at_limit.object_source = Some(Arc::clone(&checkpoint_blobs));
    let single_at_limit_store = CampaignExecutorStore::with_finding_exact_checkpoint_authenticator(
        Arc::clone(&repository),
        Arc::new(single_at_limit),
    );
    single_at_limit_store
        .publish_executor_finding_candidate(&single_candidate_bundle)
        .expect("accept exact 64 MiB checkpoint metadata limit");

    let aggregate_over_limit = recording_finding_checkpoint_authenticator(
        Arc::new(Mutex::new(Vec::new())),
        (32 * 1024 * 1024) + 1,
        candidate_events.clone(),
    );
    let aggregate_over_limit_store =
        CampaignExecutorStore::with_finding_exact_checkpoint_authenticator(
            Arc::clone(&repository),
            Arc::new(aggregate_over_limit),
        );
    assert!(matches!(
        aggregate_over_limit_store.publish_executor_finding_candidate(&bundle),
        Err(CampaignRepositoryError::Integrity {
            reason: "finding-exact-retention-metadata-byte-limit"
        })
    ));

    let calls = Arc::new(Mutex::new(Vec::new()));
    let mut authenticator = recording_finding_checkpoint_authenticator(
        Arc::clone(&calls),
        32 * 1024 * 1024,
        candidate_events.clone(),
    );
    authenticator.object_source = Some(Arc::clone(&checkpoint_blobs));
    let executor = CampaignExecutorStore::with_finding_exact_checkpoint_authenticator(
        Arc::clone(&repository),
        Arc::new(authenticator),
    );
    let publication = executor
        .publish_executor_finding_candidate(&bundle)
        .expect("publish executor-attested V5 bundle");
    assert_eq!(publication, bundle_id);
    let ordered_checkpoints = candidate_events.keys().copied().collect::<Vec<_>>();
    assert_eq!(
        calls.lock().expect("authentication calls").as_slice(),
        &[
            (ordered_checkpoints[0], 64 * 1024 * 1024),
            (ordered_checkpoints[1], 32 * 1024 * 1024),
        ]
    );
    assert!(
        blobs
            .contains(selected_leaf)
            .expect("imported selected exact leaf presence")
    );
    assert!(
        !blobs
            .contains(unselected_checkpoint.content_id())
            .expect("unselected exact root presence")
    );
    assert_eq!(
        repository
            .load_finding_candidate_bundle(bundle_id)
            .expect("cold-load V5 attestation"),
        bundle
    );
    assert!(matches!(
        repository.incorporate_finding_candidate_bundle(
            "authenticated-exact-retention",
            observed.new_snapshot,
            bundle_id,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "complete-finding-exact-retention-requires-executor-attested-incorporation"
        })
    ));
    delete_test_blob(blobs.as_ref(), selected_leaf);
    let head_before_rejection = repository
        .head("authenticated-exact-retention")
        .expect("head before missing selected descendant")
        .snapshot_id();
    assert!(
        repository
            .incorporate_checked_executor_finding_candidate_bundle(
                "authenticated-exact-retention",
                observed.new_snapshot,
                bundle_id,
                observed.observation,
                CampaignHash::derive("test.checked-executor-completion", b"missing descendant"),
            )
            .is_err()
    );
    assert_eq!(
        repository
            .head("authenticated-exact-retention")
            .expect("head after missing selected descendant")
            .snapshot_id(),
        head_before_rejection
    );
    repository
        .blobs
        .put_if_absent(selected_leaf, &BlobHandle::from_bytes(selected_leaf_bytes))
        .expect("restore selected exact descendant");
    let incorporated = repository
        .incorporate_checked_executor_finding_candidate_bundle(
            "authenticated-exact-retention",
            observed.new_snapshot,
            bundle_id,
            observed.observation,
            CampaignHash::derive("test.checked-executor-completion", b"exact completion"),
        )
        .expect("incorporate executor-attested V5 bundle");
    assert!(!incorporated.replayed);
    let cold = CampaignRepository::new(Arc::clone(&repository.blobs), Arc::clone(&repository.refs));
    assert!(
        cold.incorporate_finding_candidate_bundle(
            "authenticated-exact-retention",
            observed.new_snapshot,
            bundle_id,
        )
        .expect("cold replay of incorporated V5 bundle")
        .replayed
    );
}
