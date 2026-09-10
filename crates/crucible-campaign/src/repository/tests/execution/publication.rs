//! Observation and finding publication tests.

use super::*;
use crate::{
    CampaignFindingOccurrenceObject, CampaignFindingOccurrenceObjectKind,
    CampaignFindingTriageReplayRole, FindingTriageEvidenceSet,
    GetCampaignFindingOccurrenceObjectRequest, GetCampaignFindingOccurrenceObjectResponse,
    GetCampaignFindingTriageReplaySegmentRequest, GetCampaignFindingTriageReplaySegmentResponse,
    MAX_CAMPAIGN_FINDING_OCCURRENCE_QUERY_PAGE_ITEMS, MAX_CAMPAIGN_SERVICE_MESSAGE_BYTES,
    MAX_FINDING_TRIAGE_REPLAY_PAYLOAD_BYTES, MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES,
    QueryCampaignFindingOccurrencesRequest, QueryCampaignFindingOccurrencesResponse,
};

/// Installs a frozen historical finding through the same snapshot transition
/// shape written by earlier repository versions.
fn install_historical_finding_successor(
    repository: &CampaignRepository,
    campaign: &str,
    parent: CampaignSnapshotId,
    finding: &Finding,
) -> CampaignSnapshotId {
    let finding_id = finding.id().expect("historical finding ID");
    assert_eq!(
        repository
            .put_finding(finding)
            .expect("store historical finding"),
        finding_id.content_id()
    );

    let loaded_parent = repository
        .read_snapshot(parent.content_id())
        .expect("historical finding parent");
    let mut roots = loaded_parent.snapshot.roots();
    roots.findings = repository
        .merkle
        .insert(
            roots.findings,
            finding_signature_key(finding.signature().cluster_key()),
            finding_id.content_id(),
        )
        .expect("historical finding root")
        .content_id();
    roots.coordination = repository
        .coordination_with_parent_result(parent.content_id(), &loaded_parent)
        .expect("historical coordination root");
    let transition = repository
        .put_fact(&CampaignFact::FindingPublished(finding_id))
        .expect("historical finding transition");
    let snapshot = repository
        .budgeted_successor(
            parent,
            loaded_parent.snapshot.lineage(),
            loaded_parent.snapshot.active_policy(),
            roots,
            CampaignFactId::from_content_id(transition).expect("historical transition identity"),
        )
        .expect("historical finding snapshot");
    let snapshot_content = repository
        .put_snapshot(&snapshot)
        .expect("store historical finding snapshot");

    let campaign_ref = campaign_ref(campaign).expect("historical campaign ref");
    match repository
        .refs
        .read_ref(&campaign_ref)
        .expect("read historical campaign ref")
    {
        None => assert!(matches!(
            repository
                .refs
                .compare_exchange(&campaign_ref, None, parent.content_id())
                .expect("install historical parent ref"),
            RefCasOutcome::Advanced { .. }
        )),
        Some(current) => assert_eq!(current, parent.content_id()),
    }
    assert!(matches!(
        repository
            .refs
            .compare_exchange(&campaign_ref, Some(parent.content_id()), snapshot_content)
            .expect("install historical finding ref"),
        RefCasOutcome::Advanced { .. }
    ));

    CampaignSnapshotId::from_content_id(snapshot_content).expect("historical snapshot ID")
}

/// Fetches and authenticates every stored envelope for one segmented replay.
fn query_segmented_triage_replay(
    client: &crate::CampaignClient<RepositoryCampaignService<'_, AllowCampaignQueries>>,
    first_request: GetCampaignFindingTriageReplaySegmentRequest,
) -> (
    FindingTriageReplayEvidence,
    crate::FindingTriageReplayStorageDescription,
) {
    let first_response = client
        .get_campaign_finding_triage_replay_segment(&first_request)
        .expect("authenticated first triage replay segment");
    let first_encoded = first_response.canonical_bytes();
    assert!(first_encoded.len() <= MAX_CAMPAIGN_SERVICE_MESSAGE_BYTES);
    let first_decoded =
        GetCampaignFindingTriageReplaySegmentResponse::from_canonical_bytes(&first_encoded)
            .expect("decode first triage replay segment");
    first_decoded
        .validate_for(&first_request)
        .expect("validate first triage replay segment");

    let description = first_decoded.description().clone();
    assert_eq!(description.evidence(), first_request.evidence());
    let mut stored_envelopes = Vec::with_capacity(description.objects().len());
    for object in description.objects() {
        let segment_count = object
            .stored_envelope_bytes()
            .div_ceil(MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES);
        let mut stored_envelope = Vec::with_capacity(
            usize::try_from(object.stored_envelope_bytes())
                .expect("triage replay stored envelope length"),
        );
        for segment_index in 0..u32::try_from(segment_count).expect("triage replay segment count") {
            let segment_request = GetCampaignFindingTriageReplaySegmentRequest::new(
                first_request.principal().clone(),
                first_request.campaign().clone(),
                first_request.snapshot(),
                first_request.finding(),
                first_request.bundle(),
                first_request.role(),
                first_request.evidence(),
                object.ordinal(),
                object.content(),
                segment_index,
            )
            .expect("triage replay segment request");
            let segment_response = if object.ordinal() == 0 && segment_index == 0 {
                first_decoded.clone()
            } else {
                client
                    .get_campaign_finding_triage_replay_segment(&segment_request)
                    .expect("authenticated triage replay segment")
            };
            let segment_encoded = segment_response.canonical_bytes();
            assert!(segment_encoded.len() <= MAX_CAMPAIGN_SERVICE_MESSAGE_BYTES);
            let segment_decoded =
                GetCampaignFindingTriageReplaySegmentResponse::from_canonical_bytes(
                    &segment_encoded,
                )
                .expect("decode triage replay segment");
            segment_decoded
                .validate_for(&segment_request)
                .expect("validate triage replay segment");
            assert_eq!(segment_decoded.description(), &description);
            assert!(
                segment_decoded.range_length() <= MAX_FINDING_TRIAGE_REPLAY_STORAGE_RANGE_BYTES
            );
            stored_envelope.extend_from_slice(segment_decoded.range_bytes());
        }
        assert_eq!(
            u64::try_from(stored_envelope.len()).expect("triage replay stored envelope length"),
            object.stored_envelope_bytes()
        );
        stored_envelopes.push(stored_envelope);
    }
    let replay =
        FindingTriageReplayEvidence::from_storage_envelopes(&description, &stored_envelopes)
            .expect("authenticate and reassemble segmented triage replay evidence");
    assert_eq!(
        replay.id().expect("reassembled triage replay ID"),
        first_request.evidence()
    );

    (replay, description)
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

    let conflicting_measurements = MeasurementSet::new(BTreeMap::from([(
        "latency".to_owned(),
        MeasurementSeries::new(
            vec![MetricValue::Unsigned(8)],
            MetricValue::Unsigned(8),
            BTreeSet::new(),
        )
        .expect("conflicting measurement series"),
    )]))
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
            .publish_finding(
                campaign,
                snapshot,
                signature,
                observed.observation,
                reproduction,
                None,
                BTreeSet::new(),
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
        .and_then(|segments| segments.first())
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
        .publish_finding(
            "finding-publication",
            observed.new_snapshot,
            signature.clone(),
            observed.observation,
            reproduction,
            None,
            BTreeSet::new(),
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
        .publish_finding(
            "finding-publication",
            published.new_snapshot,
            signature.clone(),
            observed.observation,
            reproduction,
            None,
            BTreeSet::new(),
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
        repository.publish_finding(
            "finding-publication",
            published.new_snapshot,
            invalid,
            observed.observation,
            reproduction,
            None,
            BTreeSet::new(),
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
    let bundle = FindingCandidateBundle::new_with_triage_evidence(
        observed.observation,
        signature.clone(),
        original,
        minimized,
        signature_minimization,
        FindingExactPins::default(),
        triage_evidence,
    )
    .expect("finding candidate bundle");
    assert_eq!(bundle.schema_version(), 2);

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
    let legacy_minimized = repository
        .publish_reproduction_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            observation.child(),
            observation.child_content(),
            fingerprint,
            1,
            b"legacy minimized reproduction without retained trace".to_vec(),
        )
        .expect("publish schema-v1 minimized reproduction");
    assert_ne!(legacy_minimized, original);
    assert_ne!(legacy_minimized, minimized);

    let legacy_v1_occurrences = repository
        .merkle
        .insert(
            MerkleMap::empty_content_id().expect("empty occurrence root"),
            finding_occurrence_key(observed.observation),
            observed.observation.content_id(),
        )
        .expect("schema-v1 occurrence root")
        .content_id();
    let legacy_v1 = Finding::new(
        signature.clone(),
        observed.observation,
        original,
        observed.new_snapshot,
        FindingOccurrenceSet::new(legacy_v1_occurrences, 1, observed.observation)
            .expect("schema-v1 occurrence set"),
        Some(legacy_minimized),
        BTreeSet::new(),
    )
    .expect("schema-v1 finding");
    assert_eq!(legacy_v1.schema_version(), 1);
    let legacy_v1_snapshot = install_historical_finding_successor(
        &repository,
        "minimized-finding-v1-cold",
        observed.new_snapshot,
        &legacy_v1,
    );
    let cold_v1 = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    assert_eq!(
        cold_v1
            .head("minimized-finding-v1-cold")
            .expect("cold schema-v1 history validation")
            .snapshot_id(),
        legacy_v1_snapshot
    );
    let upgraded_v1 = cold_v1
        .incorporate_finding_candidate_bundle(
            "minimized-finding-v1-cold",
            legacy_v1_snapshot,
            bundle_id,
        )
        .expect("upgrade cold schema-v1 finding");
    assert!(!upgraded_v1.replayed);
    let upgraded_v1_finding = cold_v1
        .read_finding(upgraded_v1.finding.content_id())
        .expect("upgraded schema-v1 finding");
    assert_eq!(upgraded_v1_finding.schema_version(), 4);
    assert_eq!(upgraded_v1_finding.observation(), legacy_v1.observation());
    assert_eq!(upgraded_v1_finding.reproduction(), legacy_v1.reproduction());
    assert_eq!(
        upgraded_v1_finding.first_seen_snapshot(),
        legacy_v1.first_seen_snapshot()
    );
    assert_eq!(upgraded_v1_finding.minimized(), Some(legacy_minimized));
    assert_eq!(upgraded_v1_finding.candidate_bundle(), Some(bundle_id));
    assert_eq!(upgraded_v1_finding.candidate_occurrence_count(), 1);
    cold_v1.evict_local_checkpoint(upgraded_v1.new_snapshot.content_id());
    assert_eq!(
        cold_v1
            .head("minimized-finding-v1-cold")
            .expect("cold schema-v1-to-v4 history validation")
            .snapshot_id(),
        upgraded_v1.new_snapshot
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
fn finding_candidate_bundle_incorporation_survives_gc_and_restart() {
    let (repository, lineage, policy, blobs) = fixture_with_quota(192 * 1024 * 1024);
    let campaign = CampaignName::new("finding-candidate-incorporation").expect("campaign name");
    let (_, admitted, observation) = admitted_observation_fixture(
        &repository,
        &lineage,
        &policy,
        "finding-candidate-incorporation",
    );
    let observed = repository
        .publish_observation(
            "finding-candidate-incorporation",
            admitted.new_snapshot,
            &observation,
        )
        .expect("publish observation");
    let fingerprint = CampaignHash::derive("test-finding", b"durable candidate");
    let original = repository
        .publish_reproduction_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            observation.child(),
            observation.child_content(),
            fingerprint,
            1,
            b"verified original candidate reproduction".to_vec(),
        )
        .expect("publish original reproduction");
    let final_state = CampaignHash::derive("test-finding", b"durable candidate final state");
    let minimization = FindingMinimizationEvidence::new(
        original,
        1,
        b"seeded shortest-first; candidates=4096; bytes=134217728".to_vec(),
        vec![
            FindingMinimizationAttempt::new(
                0,
                CampaignHash::derive("test-finding", b"rejected candidate artifact"),
                CampaignHash::derive("test-finding", b"rejected candidate schedule"),
                CampaignHash::derive("test-finding", b"rejected candidate state"),
                None,
                false,
            ),
            FindingMinimizationAttempt::new(
                1,
                CampaignHash::derive("test-finding", b"durable candidate artifact"),
                CampaignHash::derive("test-finding", b"durable candidate schedule"),
                final_state,
                Some(fingerprint),
                true,
            ),
        ],
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
            b"verified minimized candidate reproduction".to_vec(),
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
    .expect("finding signature");
    let different_failure_class = FindingSignature::new(
        FindingKind::Divergence,
        fingerprint,
        None,
        "qemu.different-divergence".to_owned(),
        Some(FindingTarget::Configuration(observation.child_content())),
        BTreeSet::from([observation.properties().content_id()]),
    )
    .expect("same-fingerprint different-class signature");
    let signature_minimization = FindingSignatureMinimizationEvidence::new(
        &signature,
        &minimization,
        vec![
            Some(signature.clone()),
            Some(different_failure_class.clone()),
            Some(signature.clone()),
        ],
        vec![
            Some(signature.clone()),
            Some(different_failure_class.clone()),
            Some(signature.clone()),
        ],
    )
    .expect("signature minimization evidence");
    let bundle = FindingCandidateBundle::new(
        observed.observation,
        signature.clone(),
        original,
        minimized,
        signature_minimization,
        FindingExactPins::default(),
    )
    .expect("finding candidate bundle");
    let bundle_id = repository
        .publish_finding_candidate_bundle(&bundle)
        .expect("publish finding candidate bundle");
    assert_eq!(bundle.schema_version(), 1);
    assert_eq!(
        repository
            .load_finding_candidate_bundle(bundle_id)
            .expect("load schema-v1 finding candidate bundle"),
        bundle
    );
    assert_eq!(
        repository
            .publish_finding_candidate_bundle(&bundle)
            .expect("republish finding candidate bundle"),
        bundle_id
    );

    let rejected_tail_state =
        CampaignHash::derive("test-finding", b"rejected-tail final replayed state");
    let rejected_tail_minimization = FindingMinimizationEvidence::new(
        original,
        1,
        b"rejected-tail policy".to_vec(),
        vec![FindingMinimizationAttempt::new(
            0,
            CampaignHash::derive("test-finding", b"rejected-tail artifact"),
            CampaignHash::derive("test-finding", b"rejected-tail schedule"),
            rejected_tail_state,
            None,
            false,
        )],
        rejected_tail_state,
    )
    .expect("rejected-tail minimization evidence");
    let rejected_tail_minimized = repository
        .publish_minimized_reproduction_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            observation.child(),
            observation.child_content(),
            fingerprint,
            1,
            b"verified original candidate reproduction".to_vec(),
            rejected_tail_minimization.clone(),
        )
        .expect("publish rejected-tail minimized reproduction");
    let rejected_tail_signatures = FindingSignatureMinimizationEvidence::new(
        &signature,
        &rejected_tail_minimization,
        vec![
            Some(signature.clone()),
            Some(different_failure_class.clone()),
        ],
        vec![
            Some(signature.clone()),
            Some(different_failure_class.clone()),
        ],
    )
    .expect("rejected-tail signature evidence");
    let publish_rejected_tail_triage = |reproduction, payload: &'static [u8]| {
        repository
            .publish_finding_triage_replay_evidence(
                &FindingTriageReplayEvidence::new(
                    reproduction,
                    signature.clone(),
                    1,
                    payload.to_vec(),
                )
                .expect("rejected-tail triage evidence"),
            )
            .expect("publish rejected-tail triage evidence")
    };
    let rejected_tail_bundle = FindingCandidateBundle::new_with_triage_evidence(
        observed.observation,
        signature.clone(),
        original,
        rejected_tail_minimized,
        rejected_tail_signatures,
        FindingExactPins::default(),
        FindingTriageEvidenceSet::new(
            publish_rejected_tail_triage(original, b"rejected-tail minimization original replay"),
            publish_rejected_tail_triage(
                rejected_tail_minimized,
                b"rejected-tail minimization selected replay",
            ),
            publish_rejected_tail_triage(original, b"rejected-tail verification original replay"),
            publish_rejected_tail_triage(
                rejected_tail_minimized,
                b"rejected-tail verification selected replay",
            ),
        ),
    )
    .expect("rejected-tail finding candidate bundle");
    let rejected_tail_bundle_id = repository
        .publish_finding_candidate_bundle(&rejected_tail_bundle)
        .expect("publish rejected-tail finding candidate bundle");
    assert_eq!(
        repository
            .load_finding_candidate_bundle(rejected_tail_bundle_id)
            .expect("load rejected-tail finding candidate bundle"),
        rejected_tail_bundle
    );

    let second_request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "finding-candidate-occurrence-two",
    );
    let second_requested = repository
        .submit_known_branch_request(
            "finding-candidate-incorporation",
            observed.new_snapshot,
            &second_request,
        )
        .expect("submit second occurrence request");
    let second_proposal = finite_proposal(
        &second_request,
        &policy,
        &repository
            .head("finding-candidate-incorporation")
            .expect("second occurrence request head"),
        ChoiceValue::Boolean(false),
        1,
    );
    let second_proposed = repository
        .issue_proposal(
            "finding-candidate-incorporation",
            second_requested.new_snapshot,
            &second_proposal,
        )
        .expect("issue second occurrence proposal");
    let (second_selection, second_path, second_attempt) =
        branch_attempt(&repository, &second_request, &second_proposal);
    let second_admitted = repository
        .admit_proposal(
            "finding-candidate-incorporation",
            second_proposed.new_snapshot,
            second_proposed.proposal,
            &second_selection,
            &second_path,
            &second_attempt,
        )
        .expect("admit second occurrence attempt");
    let second_observation = Observation::new(
        second_admitted.attempt,
        observation.child(),
        observation.child_content(),
        second_path.id().expect("second occurrence path ID"),
        observation.stop().clone(),
        observation.measurements(),
        observation.properties(),
        observation.coverage(),
        BTreeSet::from([second_request.opportunity()]),
    )
    .expect("second occurrence observation");
    let second_observed = repository
        .publish_observation(
            "finding-candidate-incorporation",
            second_admitted.new_snapshot,
            &second_observation,
        )
        .expect("publish second occurrence observation");
    assert_ne!(second_observation.attempt(), observation.attempt());
    assert_ne!(second_observed.observation, observed.observation);

    let second_original = repository
        .publish_reproduction_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            second_observation.child(),
            second_observation.child_content(),
            fingerprint,
            1,
            vec![b'x'; 32 * 1024 * 1024],
        )
        .expect("publish maximum-payload second original reproduction");
    let second_final_state =
        CampaignHash::derive("test-finding", b"second durable candidate final state");
    let second_minimization = FindingMinimizationEvidence::new(
        second_original,
        1,
        b"seeded shortest-first; candidates=4096; bytes=134217728".to_vec(),
        vec![FindingMinimizationAttempt::new(
            0,
            CampaignHash::derive("test-finding", b"second candidate artifact"),
            CampaignHash::derive("test-finding", b"second candidate schedule"),
            second_final_state,
            Some(fingerprint),
            true,
        )],
        second_final_state,
    )
    .expect("second minimization evidence");
    let second_minimized = repository
        .publish_minimized_reproduction_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            second_observation.child(),
            second_observation.child_content(),
            fingerprint,
            1,
            vec![b'm'; 32 * 1024 * 1024],
            second_minimization.clone(),
        )
        .expect("publish maximum-payload second minimized reproduction");
    let second_signature_minimization = FindingSignatureMinimizationEvidence::new(
        &signature,
        &second_minimization,
        vec![Some(signature.clone()), Some(signature.clone())],
        vec![Some(signature.clone()), Some(signature.clone())],
    )
    .expect("second signature minimization evidence");
    let publish_second_triage = |reproduction, payload: Vec<u8>| -> FindingTriageReplayEvidenceId {
        repository
            .publish_finding_triage_replay_evidence(
                &FindingTriageReplayEvidence::new(reproduction, signature.clone(), 1, payload)
                    .expect("second occurrence triage evidence"),
            )
            .expect("publish second occurrence triage evidence")
    };
    let second_triage_evidence = FindingTriageEvidenceSet::new(
        publish_second_triage(
            second_original,
            b"second minimization original replay".to_vec(),
        ),
        publish_second_triage(
            second_minimized,
            b"second minimization selected replay".to_vec(),
        ),
        publish_second_triage(
            second_original,
            b"second verification original replay".to_vec(),
        ),
        publish_second_triage(
            second_minimized,
            vec![b't'; MAX_FINDING_TRIAGE_REPLAY_PAYLOAD_BYTES],
        ),
    );
    let second_bundle = FindingCandidateBundle::new_with_triage_evidence(
        second_observed.observation,
        signature.clone(),
        second_original,
        second_minimized,
        second_signature_minimization,
        FindingExactPins::default(),
        second_triage_evidence,
    )
    .expect("second finding candidate bundle");
    assert_eq!(second_bundle.schema_version(), 2);
    assert_eq!(second_bundle.signature(), bundle.signature());
    let second_bundle_id = repository
        .publish_finding_candidate_bundle(&second_bundle)
        .expect("publish second finding candidate bundle");
    assert_eq!(
        repository
            .load_finding_candidate_bundle(second_bundle_id)
            .expect("load schema-v2 finding candidate bundle"),
        second_bundle
    );
    assert_ne!(second_bundle_id, bundle_id);

    let legacy_no_min_occurrences = repository
        .merkle
        .insert(
            MerkleMap::empty_content_id().expect("empty legacy occurrence root"),
            finding_occurrence_key(observed.observation),
            observed.observation.content_id(),
        )
        .expect("legacy no-min occurrence root")
        .content_id();
    let legacy_no_min_findings = [
        (
            "finding-candidate-v1-no-min",
            1,
            Finding::new(
                signature.clone(),
                observed.observation,
                original,
                second_observed.new_snapshot,
                FindingOccurrenceSet::new(legacy_no_min_occurrences, 1, observed.observation)
                    .expect("schema-v1 no-min occurrence set"),
                None,
                BTreeSet::new(),
            )
            .expect("schema-v1 no-min finding"),
        ),
        (
            "finding-candidate-v2-no-min",
            2,
            Finding::new_with_retention(
                signature.clone(),
                observed.observation,
                original,
                second_observed.new_snapshot,
                FindingOccurrenceSet::new(legacy_no_min_occurrences, 1, observed.observation)
                    .expect("schema-v2 no-min occurrence set"),
                None,
                FindingExactPins::default(),
            )
            .expect("schema-v2 no-min finding"),
        ),
    ];
    for (campaign_name, schema_version, legacy) in legacy_no_min_findings {
        assert_eq!(legacy.schema_version(), schema_version);
        let legacy_snapshot = install_historical_finding_successor(
            &repository,
            campaign_name,
            second_observed.new_snapshot,
            &legacy,
        );
        let cold = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
        assert_eq!(
            cold.head(campaign_name)
                .expect("cold legacy no-min history validation")
                .snapshot_id(),
            legacy_snapshot
        );

        let upgraded = cold
            .incorporate_finding_candidate_bundle(campaign_name, legacy_snapshot, second_bundle_id)
            .expect("upgrade no-min legacy finding with distinct candidate");
        let upgraded_finding = cold
            .read_finding(upgraded.finding.content_id())
            .expect("upgraded no-min finding");
        assert_eq!(upgraded_finding.schema_version(), 4);
        assert_eq!(upgraded_finding.observation(), observed.observation);
        assert_eq!(upgraded_finding.reproduction(), original);
        assert_eq!(upgraded_finding.minimized(), None);
        assert_eq!(upgraded_finding.occurrence_count(), 2);
        assert_eq!(upgraded_finding.candidate_occurrence_count(), 1);
        assert_eq!(upgraded_finding.candidate_bundle(), Some(second_bundle_id));
        assert_eq!(
            upgraded_finding.latest_candidate_bundle(),
            Some(second_bundle_id)
        );
        assert_ne!(second_bundle.observation(), upgraded_finding.observation());
        assert_ne!(
            second_bundle.reproduction(),
            upgraded_finding.reproduction()
        );
        cold.evict_local_checkpoint(upgraded.new_snapshot.content_id());
        assert_eq!(
            cold.head(campaign_name)
                .expect("cold no-min legacy-to-v4 history validation")
                .snapshot_id(),
            upgraded.new_snapshot
        );
    }

    let fresh_ref = campaign_ref("finding-candidate-fresh-v4").expect("fresh campaign ref");
    assert!(matches!(
        repository
            .refs
            .compare_exchange(&fresh_ref, None, second_observed.new_snapshot.content_id(),)
            .expect("install fresh candidate parent ref"),
        RefCasOutcome::Advanced { .. }
    ));
    let fresh = repository
        .incorporate_finding_candidate_bundle(
            "finding-candidate-fresh-v4",
            second_observed.new_snapshot,
            bundle_id,
        )
        .expect("incorporate fresh schema-v4 finding");
    assert!(!fresh.replayed);
    let fresh_finding = repository
        .read_finding(fresh.finding.content_id())
        .expect("fresh schema-v4 finding");
    assert_eq!(fresh_finding.schema_version(), 4);
    assert_eq!(fresh_finding.candidate_occurrence_count(), 1);
    assert_eq!(fresh_finding.candidate_bundle(), Some(bundle_id));

    let downgraded_finding = Finding::new_with_candidate_bundle(
        fresh_finding.signature().clone(),
        fresh_finding.observation(),
        fresh_finding.reproduction(),
        fresh_finding.first_seen_snapshot(),
        FindingOccurrenceSet::new(
            fresh_finding.occurrences(),
            fresh_finding.occurrence_count(),
            fresh_finding.latest_occurrence(),
        )
        .expect("downgraded occurrence set"),
        fresh_finding.minimized(),
        fresh_finding.exact_pin_retention().clone(),
        bundle_id,
    )
    .expect("schema-v3 downgrade candidate");
    let downgraded_snapshot = install_historical_finding_successor(
        &repository,
        "finding-candidate-fresh-v4",
        fresh.new_snapshot,
        &downgraded_finding,
    );
    let cold_downgrade = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    assert!(matches!(
        cold_downgrade.head("finding-candidate-fresh-v4"),
        Err(CampaignRepositoryError::Integrity {
            reason: "finding-transition-cluster-regressed-or-replaced"
        })
    ));
    assert_eq!(
        cold_downgrade
            .read_snapshot(downgraded_snapshot.content_id())
            .expect("stored downgrade snapshot")
            .snapshot
            .parent(),
        Some(fresh.new_snapshot)
    );

    // Preserve an authentic schema-v3 predecessor, validate it from cold
    // storage, then upgrade it with the independently admitted occurrence.
    let legacy_occurrences = repository
        .merkle
        .insert(
            MerkleMap::empty_content_id().expect("empty occurrence root"),
            finding_occurrence_key(observed.observation),
            observed.observation.content_id(),
        )
        .expect("legacy occurrence root")
        .content_id();
    let legacy_finding = Finding::new_with_candidate_bundle(
        signature.clone(),
        observed.observation,
        original,
        second_observed.new_snapshot,
        FindingOccurrenceSet::new(legacy_occurrences, 1, observed.observation)
            .expect("legacy occurrence set"),
        Some(minimized),
        FindingExactPins::default(),
        bundle_id,
    )
    .expect("schema-v3 finding");
    assert_eq!(legacy_finding.schema_version(), 3);
    let legacy_snapshot_id = install_historical_finding_successor(
        &repository,
        "finding-candidate-incorporation",
        second_observed.new_snapshot,
        &legacy_finding,
    );

    let cold = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    assert_eq!(
        cold.head("finding-candidate-incorporation")
            .expect("cold schema-v3 history validation")
            .snapshot_id(),
        legacy_snapshot_id
    );
    let incorporated = cold
        .incorporate_finding_candidate_bundle(
            "finding-candidate-incorporation",
            legacy_snapshot_id,
            second_bundle_id,
        )
        .expect("upgrade cold schema-v3 finding with second occurrence");
    assert!(!incorporated.replayed);
    let repeated_finding = repository
        .read_finding(incorporated.finding.content_id())
        .expect("repeated finding");
    assert_eq!(repeated_finding.schema_version(), 4);
    assert_eq!(repeated_finding.signature(), &signature);
    assert_eq!(repeated_finding.observation(), legacy_finding.observation());
    assert_eq!(
        repeated_finding.reproduction(),
        legacy_finding.reproduction()
    );
    assert_eq!(repeated_finding.minimized(), legacy_finding.minimized());
    assert_eq!(repeated_finding.occurrence_count(), 2);
    assert_eq!(repeated_finding.candidate_occurrence_count(), 2);
    assert_eq!(repeated_finding.candidate_bundle(), Some(bundle_id));
    assert_eq!(
        repeated_finding.latest_candidate_bundle(),
        Some(second_bundle_id)
    );
    for retained_bundle in [bundle_id, second_bundle_id] {
        repository
            .authenticate_current_finding_candidate_incorporation(
                &campaign,
                incorporated.finding,
                retained_bundle,
            )
            .expect("authenticate retained occurrence bundle");
    }

    let principal = CampaignPrincipal::new("operator:alice").expect("principal");
    let client = crate::CampaignClient::new(RepositoryCampaignService::new(
        &repository,
        AllowCampaignQueries,
    ));
    let mut after = None;
    let mut queried_bundle_ids = BTreeSet::new();
    let mut queried_rich_triage_objects = 0;
    loop {
        let request = QueryCampaignFindingOccurrencesRequest::new(
            principal.clone(),
            campaign.clone(),
            incorporated.new_snapshot,
            incorporated.finding,
            after,
            MAX_CAMPAIGN_FINDING_OCCURRENCE_QUERY_PAGE_ITEMS,
        )
        .expect("occurrence query request");
        let response = client
            .query_campaign_finding_occurrences(&request)
            .expect("authenticated occurrence page");
        let decoded = QueryCampaignFindingOccurrencesResponse::from_canonical_bytes(
            &response.canonical_bytes(),
        )
        .expect("decode occurrence page");
        decoded
            .validate_for(&request)
            .expect("validate decoded occurrence page");
        for occurrence in response.entries() {
            let bundle_id = occurrence.bundle().id().expect("queried bundle ID");
            queried_bundle_ids.insert(bundle_id);
            let object_kinds = [
                CampaignFindingOccurrenceObjectKind::Observation,
                CampaignFindingOccurrenceObjectKind::Reproduction,
                CampaignFindingOccurrenceObjectKind::MinimizedReproduction,
            ];
            for kind in object_kinds {
                let object_request = GetCampaignFindingOccurrenceObjectRequest::new(
                    principal.clone(),
                    campaign.clone(),
                    incorporated.new_snapshot,
                    incorporated.finding,
                    bundle_id,
                    kind,
                )
                .expect("occurrence object request");
                let object_response = client
                    .get_campaign_finding_occurrence_object(&object_request)
                    .expect("authenticated occurrence object");
                let encoded = object_response.canonical_bytes();
                assert!(encoded.len() <= MAX_CAMPAIGN_SERVICE_MESSAGE_BYTES);
                if bundle_id == second_bundle_id
                    && matches!(
                        kind,
                        CampaignFindingOccurrenceObjectKind::Reproduction
                            | CampaignFindingOccurrenceObjectKind::MinimizedReproduction
                    )
                {
                    assert!(encoded.len() > 32 * 1024 * 1024);
                }
                let decoded =
                    GetCampaignFindingOccurrenceObjectResponse::from_canonical_bytes(&encoded)
                        .expect("decode occurrence object response");
                decoded
                    .validate_for(&object_request)
                    .expect("validate decoded occurrence object response");
                match decoded.object() {
                    CampaignFindingOccurrenceObject::Observation(value) => {
                        assert_eq!(
                            value.id().expect("observation ID"),
                            occurrence.bundle().observation()
                        );
                    }
                    CampaignFindingOccurrenceObject::Reproduction(value) => {
                        assert_eq!(
                            value.id().expect("reproduction ID"),
                            occurrence.bundle().reproduction()
                        );
                    }
                    CampaignFindingOccurrenceObject::MinimizedReproduction(value) => {
                        assert_eq!(
                            value.id().expect("minimized reproduction ID"),
                            occurrence.bundle().minimized()
                        );
                    }
                    unexpected => panic!(
                        "ordinary occurrence query returned segmented triage object {unexpected:?}"
                    ),
                }
            }

            let Some(triage_evidence) = occurrence.bundle().triage_evidence() else {
                continue;
            };
            let replay_roles = [
                (
                    CampaignFindingTriageReplayRole::MinimizationOriginal,
                    triage_evidence.minimization_original(),
                ),
                (
                    CampaignFindingTriageReplayRole::MinimizationSelected,
                    triage_evidence.minimization_selected(),
                ),
                (
                    CampaignFindingTriageReplayRole::VerificationOriginal,
                    triage_evidence.verification_original(),
                ),
                (
                    CampaignFindingTriageReplayRole::VerificationSelected,
                    triage_evidence.verification_selected(),
                ),
            ];
            for (role, evidence) in replay_roles {
                let first_request = GetCampaignFindingTriageReplaySegmentRequest::new(
                    principal.clone(),
                    campaign.clone(),
                    incorporated.new_snapshot,
                    incorporated.finding,
                    bundle_id,
                    role,
                    evidence,
                    0,
                    evidence.content_id(),
                    0,
                )
                .expect("first triage replay segment request");
                let (_, description) = query_segmented_triage_replay(&client, first_request);
                if role == CampaignFindingTriageReplayRole::VerificationSelected {
                    assert_eq!(
                        description.logical_payload_bytes(),
                        MAX_FINDING_TRIAGE_REPLAY_PAYLOAD_BYTES as u64
                    );
                    assert!(description.objects().len() > 1);
                }
                queried_rich_triage_objects += 1;
            }
        }
        after = response.next_after();
        if after.is_none() {
            break;
        }
    }
    assert_eq!(
        queried_bundle_ids,
        BTreeSet::from([bundle_id, second_bundle_id])
    );
    assert_eq!(queried_rich_triage_objects, 4);
    let orphaned =
        CampaignRepository::new(repository.blobs.clone(), Arc::new(MemoryRefBackend::new()));
    assert!(
        orphaned
            .authenticate_current_finding_candidate_incorporation(
                &campaign,
                incorporated.finding,
                bundle_id,
            )
            .is_err(),
        "a well-formed but unrooted snapshot must not acknowledge the candidate",
    );
    let retained_finding = repository
        .read_finding(incorporated.finding.content_id())
        .expect("load incorporated finding");
    let unrelated_finding = Finding::new_with_retention(
        retained_finding.signature().clone(),
        retained_finding.observation(),
        retained_finding.reproduction(),
        retained_finding.first_seen_snapshot(),
        FindingOccurrenceSet::new(
            retained_finding.occurrences(),
            retained_finding.occurrence_count(),
            retained_finding.latest_occurrence(),
        )
        .expect("unrelated finding occurrences"),
        retained_finding.minimized(),
        retained_finding.exact_pin_retention().clone(),
    )
    .expect("unrelated finding");
    let unrelated_finding_id = unrelated_finding.id().expect("unrelated finding ID");
    let stored_unrelated = repository
        .put_envelope(
            ObjectEnvelope::for_record_versioned(
                CampaignRecordKind::Finding,
                unrelated_finding.schema_version(),
                crate::object::content_children(unrelated_finding.content_children())
                    .expect("unrelated finding children"),
                unrelated_finding.canonical_bytes(),
            )
            .expect("unrelated finding envelope"),
        )
        .expect("store unrelated finding");
    assert_eq!(stored_unrelated, unrelated_finding_id.content_id());
    assert!(
        repository
            .authenticate_current_finding_candidate_incorporation(
                &campaign,
                unrelated_finding_id,
                bundle_id,
            )
            .is_err(),
        "the exact bundle paired with an unrelated finding must be rejected",
    );
    let incorporation = repository
        .authenticate_current_finding_candidate_incorporation(
            &campaign,
            incorporated.finding,
            bundle_id,
        )
        .expect("authenticate finding candidate incorporation");
    assert_eq!(incorporation.campaign(), &campaign);
    assert_eq!(incorporation.bundle(), bundle_id);
    assert_eq!(incorporation.finding(), incorporated.finding);
    assert_eq!(incorporation.snapshot(), incorporated.new_snapshot);
    assert_eq!(
        repository
            .read_finding(incorporated.finding.content_id())
            .expect("load incorporated finding")
            .candidate_bundle(),
        Some(bundle_id)
    );
    let replayed = repository
        .incorporate_finding_candidate_bundle(
            "finding-candidate-incorporation",
            observed.new_snapshot,
            bundle_id,
        )
        .expect("replay finding candidate after head advancement");
    assert!(replayed.replayed);
    assert_eq!(replayed.finding, incorporated.finding);
    assert_eq!(replayed.new_snapshot, incorporated.new_snapshot);

    let orphan_bytes = b"unreachable finding candidate";
    let orphan = ContentId::for_bytes(ObjectKind::Trace, 1, orphan_bytes);
    blobs
        .put_if_absent(orphan, &BlobHandle::from_bytes(orphan_bytes))
        .expect("store GC candidate");
    let retained = repository
        .authenticated_closure_ids([incorporated.new_snapshot.content_id()])
        .expect("authenticate incorporated finding closure");
    assert!(retained.contains(&incorporated.finding.content_id()));
    assert!(retained.contains(&bundle_id.content_id()));
    let mut inventory = blobs
        .acquire_inventory_fence()
        .expect("acquire GC inventory fence");
    let mut candidates = Vec::new();
    inventory
        .visit_inventory(&mut |record| {
            if !retained.contains(&record.id()) {
                candidates.push(record.id());
            }
            Ok(())
        })
        .expect("inventory GC candidates");
    assert!(candidates.contains(&orphan));
    for candidate in candidates {
        inventory
            .delete_candidate(candidate)
            .expect("delete unreachable GC candidate");
    }
    drop(inventory);
    assert!(!blobs.contains(orphan).expect("orphan presence"));
    assert!(
        blobs
            .contains(bundle_id.content_id())
            .expect("bundle presence")
    );

    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    assert_eq!(
        restarted
            .load_finding_candidate_bundle(bundle_id)
            .expect("load finding candidate after restart"),
        bundle
    );
    let restarted_replay = restarted
        .incorporate_finding_candidate_bundle(
            "finding-candidate-incorporation",
            observed.new_snapshot,
            bundle_id,
        )
        .expect("replay finding candidate after restart");
    assert!(restarted_replay.replayed);
    assert_eq!(restarted_replay.finding, incorporated.finding);
    assert_eq!(restarted_replay.new_snapshot, incorporated.new_snapshot);
    assert_eq!(
        restarted
            .authenticate_current_finding_candidate_incorporation(
                &campaign,
                restarted_replay.finding,
                bundle_id,
            )
            .expect("authenticate incorporation after restart"),
        incorporation,
    );
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
