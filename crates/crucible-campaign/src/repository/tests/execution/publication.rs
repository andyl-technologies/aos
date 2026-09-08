//! Observation and finding publication tests.

use super::*;

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
    .expect("finding-weighted policy");
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
            minimization,
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
            signature,
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
}

#[test]
fn finding_candidate_bundle_incorporation_survives_gc_and_restart() {
    let (repository, lineage, policy, blobs) = counted_fixture();
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
            Some(different_failure_class),
            Some(signature.clone()),
        ],
    )
    .expect("signature minimization evidence");
    let bundle = FindingCandidateBundle::new(
        observed.observation,
        signature,
        original,
        minimized,
        signature_minimization,
        FindingExactPins::default(),
    )
    .expect("finding candidate bundle");
    let bundle_id = repository
        .publish_finding_candidate_bundle(&bundle)
        .expect("publish finding candidate bundle");
    assert_eq!(
        repository
            .publish_finding_candidate_bundle(&bundle)
            .expect("republish finding candidate bundle"),
        bundle_id
    );

    let incorporated = repository
        .incorporate_finding_candidate_bundle(
            "finding-candidate-incorporation",
            observed.new_snapshot,
            bundle_id,
        )
        .expect("incorporate finding candidate");
    assert!(!incorporated.replayed);
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
