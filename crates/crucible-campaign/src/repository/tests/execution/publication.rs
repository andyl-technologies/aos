//! Observation and finding publication tests.

use super::*;
use crate::{
    AuthenticatedFindingExactCheckpoint, BoundedStopProof, CampaignAttemptTimeoutPolicy,
    CampaignExecutorStore, FindingExactCheckpointAuthenticationError,
    FindingExactCheckpointAuthenticator, FindingExactRetention, FindingExactRetentionCandidate,
    FindingExactRetentionDisposition, FindingExactRetentionEvidence,
    FindingExactRetentionIncomplete, FindingTriageEvidenceSet, ScenarioArtifactId,
};
use crucible_cas::content_envelope::{ContentChild, ContentEnvelope};

#[test]
fn bounded_intrinsic_timeout_publishes_without_opening_a_choice_continuation() {
    let (repository, lineage, base_policy) = fixture();
    let policy = base_policy
        .with_attempt_timeout_policy(
            CampaignAttemptTimeoutPolicy::new(Some(20), Some(10), None)
                .expect("modeled policy deadlines"),
        )
        .expect("timed policy");
    let stop = policy
        .bound_stop(StopCondition::NextChoiceOrExecutionQuanta {
            execution_quanta: 7,
        })
        .expect("bounded choice stop");

    let fallback = StopOutcome::BoundedPrimaryTimeout {
        stop: stop.clone(),
        proof: BoundedStopProof::new(7, 7),
    };
    let (_, admitted, observation) = admitted_observation_fixture_with_stop(
        &repository,
        &lineage,
        &policy,
        "bounded-intrinsic-timeout",
        stop.clone(),
        fallback,
        false,
    );
    assert!(observation.discovered_choices().is_empty());
    assert!(!observation.stop().reached_next_choice());
    repository
        .publish_observation(
            "bounded-intrinsic-timeout",
            admitted.new_snapshot,
            &observation,
        )
        .expect("intrinsic timeout without a discovered choice");

    let choice = StopOutcome::BoundedPrimaryReached {
        stop: stop.clone(),
        proof: BoundedStopProof::new(6, 6),
    };
    let (_, choice_admitted, choice_observation) = admitted_observation_fixture_with_stop(
        &repository,
        &lineage,
        &policy,
        "bounded-choice-before-timeout",
        stop,
        choice,
        true,
    );
    assert!(choice_observation.stop().reached_next_choice());
    repository
        .publish_observation(
            "bounded-choice-before-timeout",
            choice_admitted.new_snapshot,
            &choice_observation,
        )
        .expect("choice before intrinsic fallback");
}

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
        Observation::outcome(
            observation.child(),
            observation.child_content(),
            observation.path(),
            observation.stop().clone(),
            conflicting_measurements,
            observation.properties(),
            observation.coverage(),
        ),
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
        Observation::outcome(
            base_observation.child(),
            base_observation.child_content(),
            base_observation.path(),
            base_observation.stop().clone(),
            base_observation.measurements(),
            properties,
            base_observation.coverage(),
        ),
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
            .publish_incomplete_test_finding(
                campaign,
                snapshot,
                signature,
                observed.observation,
                reproduction,
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
        CampaignPolicy::identity(
            base_policy.scenario(),
            base_policy.campaign_seed(),
            base_policy.mode(),
            base_policy.explorer().clone(),
        ),
        CampaignPolicy::rules(
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
        ),
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
        .publish_incomplete_test_finding(
            "finding-publication",
            observed.new_snapshot,
            signature.clone(),
            observed.observation,
            reproduction,
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
        .publish_incomplete_test_finding(
            "finding-publication",
            published.new_snapshot,
            signature.clone(),
            observed.observation,
            reproduction,
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
        repository.publish_incomplete_test_finding(
            "finding-publication",
            published.new_snapshot,
            invalid,
            observed.observation,
            reproduction
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
    assert_eq!(finding.candidate_bundle(), Some(bundle_id));
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

mod candidate;
