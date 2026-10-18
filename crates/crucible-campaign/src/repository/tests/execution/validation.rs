//! Observation storage and ordering validation tests.

use super::*;

#[test]
fn observation_ordinal_key_preserves_the_persisted_two_layer_identity() {
    assert_eq!(
        observation_ordinal_key(AdmissionOrdinal::new(3)).to_hex(),
        "dd44cfc393c27fe74fc0f8ee6f953dcbf94880589faed965da05e4b802d06225"
    );
}

#[test]
fn coverage_frequency_upserts_count_new_identities_and_skip_saturated_ones() {
    let (repository, _, _) = fixture();
    let fresh = CampaignHash::derive("test.coverage-frequency", b"fresh");
    let repeated = CampaignHash::derive("test.coverage-frequency", b"repeated");
    let saturated = CampaignHash::derive("test.coverage-frequency", b"saturated");
    let coverage = repository
        .publish_coverage_projection(
            &CoverageProjection::new(
                BTreeSet::from([fresh, repeated, saturated]),
                BTreeSet::new(),
            )
            .expect("coverage"),
        )
        .expect("publish coverage");
    let record = |count| {
        let value = crate::CoverageIdentityFrequency::new(count).expect("frequency");
        repository
            .put_coverage_identity_frequency(value)
            .expect("publish frequency")
    };
    let mut root = repository.merkle.empty().expect("empty root").content_id();
    root = repository
        .merkle
        .insert(root, coverage_identity_frequency_key(repeated), record(3))
        .expect("index repeated identity")
        .content_id();
    root = repository
        .merkle
        .insert(
            root,
            coverage_identity_frequency_key(saturated),
            record(crate::COVERAGE_IDENTITY_FREQUENCY_SATURATION),
        )
        .expect("index saturated identity")
        .content_id();

    let mut upserts = BTreeMap::new();
    let records = repository
        .coverage_frequency_upserts(root, coverage, &mut upserts)
        .expect("frequency upserts");

    let expected = |count| {
        crate::CoverageIdentityFrequency::new(count)
            .expect("frequency")
            .content_id()
            .expect("frequency id")
    };
    assert_eq!(
        upserts,
        BTreeMap::from([
            (coverage_identity_frequency_key(fresh), expected(1)),
            (coverage_identity_frequency_key(repeated), expected(4)),
        ])
    );
    assert_eq!(
        records
            .iter()
            .map(|record| record.count())
            .collect::<Vec<_>>(),
        vec![1, 4]
    );
}

#[test]
fn observation_growth_bound_rebases_and_remains_restart_readable() {
    let (repository, lineage, policy) = fixture();
    let (_, admitted, observation) =
        admitted_observation_fixture(&repository, &lineage, &policy, "observation-growth");
    let discovered = usize::try_from(observation.discovered_choices().entry_count())
        .expect("fixture discovered-choice count");
    let growth = observation_successor_growth(discovered, 0, false, true, 0, 1)
        .expect("fixture observation growth");
    repository
        .validated_heads
        .lock()
        .expect("validation checkpoints")
        .get_mut(&admitted.new_snapshot.content_id())
        .expect("admitted checkpoint")
        .closure_objects = usize::MAX / 2;

    let accepted = repository
        .publish_observation("observation-growth", admitted.new_snapshot, &observation)
        .expect("incremental observation from a large checkpoint");
    let checkpoint_objects = repository
        .validated_heads
        .lock()
        .expect("validation checkpoints")
        .get(&accepted.new_snapshot.content_id())
        .expect("incremental observation checkpoint")
        .closure_objects;
    // The owner growth bound is charged on top of the parent count.
    assert!(checkpoint_objects - usize::MAX / 2 >= growth);

    repository
        .validated_heads
        .lock()
        .expect("validation checkpoints")
        .clear();
    assert_eq!(
        repository
            .head("observation-growth")
            .expect("restart-style full validation")
            .snapshot_id(),
        accepted.new_snapshot
    );
}

#[test]
fn observation_evidence_preflight_rejects_nested_invalid_records_without_writes() {
    let (repository, lineage, policy, blobs) = counted_fixture();
    let (_, admitted, observation) = admitted_observation_fixture(
        &repository,
        &lineage,
        &policy,
        "observation-nested-evidence",
    );
    let invalid_path = BranchPath::new(Vec::new())
        .expect("empty path")
        .id()
        .expect("empty path id");
    let nested = Observation::new(
        observation.attempt(),
        Observation::outcome(
            observation.child(),
            observation.child_content(),
            invalid_path,
            observation.stop().clone(),
            observation.measurements(),
            observation.properties(),
            observation.coverage(),
        ),
        discovered_choice_ids(&repository, &observation),
    )
    .expect("structurally valid nested observation");
    let nested_id = nested.id().expect("nested observation id");
    repository
        .put_observation(&nested)
        .expect("store incomplete nested observation fixture");
    let evidence = MeasurementSet::test_evaluation(
        b"nested-observation",
        BTreeSet::from([nested_id.content_id()]),
    )
    .expect("nested evidence set");
    let objects_before = blobs.object_count().expect("objects before rejection");

    assert!(matches!(
        repository.publish_measurement_set(&evidence),
        Err(CampaignRepositoryError::Integrity {
            reason: "observation-attempt-or-child-mismatch"
        })
    ));
    assert_eq!(
        blobs.object_count().expect("objects after rejection"),
        objects_before
    );
    assert_eq!(
        repository
            .head("observation-nested-evidence")
            .expect("unchanged admitted head")
            .snapshot_id(),
        admitted.new_snapshot
    );
}

#[test]
fn choice_validation_cache_is_compact_shared_and_checks_copied_contracts() {
    let (repository, lineage, _) = fixture();
    let alternatives = (0_u32..1_024)
        .map(|index| {
            let id = AlternativeId::from_hash(CampaignHash::derive(
                "test-cache-alternative",
                &index.to_be_bytes(),
            ));
            (
                id,
                DiscreteAlternative::new(
                    id,
                    format!("alternative-{index:04}"),
                    Some("x".repeat(512)),
                )
                .expect("cache alternative"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let default = *alternatives.keys().next().expect("first alternative");
    let domain =
        ChoiceDomain::Discrete(DiscreteDomain::new(1, alternatives).expect("large shared domain"));
    let declaration = SelectableDeclaration::new(
        "cache.shared.domain",
        ChoiceSource::Workload {
            producer: "cache-producer".to_owned(),
        },
        domain.clone(),
        ChoiceValue::Discrete(default),
        ChoiceClassContext::new(BTreeSet::new()).expect("cache class"),
        BTreeSet::new(),
        true,
    )
    .expect("cache declaration");
    repository
        .publish_choice_domain(&domain)
        .expect("publish shared domain");
    repository
        .publish_selectable(&declaration)
        .expect("publish shared declaration");

    let mut cache = ChoiceValidationCache::default();
    let mut representative = None;
    for index in 0_u32..256 {
        let opportunity = ChoiceOpportunity::new(
            lineage.scenario(),
            &declaration,
            &domain,
            ChoiceCoordinate {
                scheduler: CampaignHash::derive("test-cache-scheduler", &index.to_be_bytes()),
                producer: CampaignHash::derive("test-cache-producer", b"shared"),
            },
            format!("cache-{index:04}"),
            None,
        )
        .expect("shared-domain opportunity");
        let envelope = ObjectEnvelope::for_record(
            crate::CampaignRecordKind::ChoiceOpportunity,
            crate::object::content_children(opportunity.content_children())
                .expect("opportunity children"),
            crate::codec::encode(&opportunity),
        )
        .expect("opportunity envelope");
        repository
            .validate_opportunity_references_cached(&envelope, &mut cache)
            .expect("validate shared pair");
        representative.get_or_insert(opportunity);
    }
    assert_eq!(cache.contracts.len(), 1);

    let mut forged_bytes =
        crate::codec::encode(representative.as_ref().expect("representative opportunity"));
    let source = b"cache-producer";
    let replacement = b"forge-producer";
    let offset = forged_bytes
        .windows(source.len())
        .position(|window| window == source)
        .expect("encoded source");
    forged_bytes[offset..offset + source.len()].copy_from_slice(replacement);
    let forged = crate::codec::decode::<ChoiceOpportunity>(&forged_bytes)
        .expect("structurally valid forged opportunity");
    let forged_envelope = ObjectEnvelope::for_record(
        crate::CampaignRecordKind::ChoiceOpportunity,
        crate::object::content_children(forged.content_children())
            .expect("forged opportunity children"),
        forged_bytes,
    )
    .expect("forged opportunity envelope");
    assert!(matches!(
        repository.validate_opportunity_references_cached(&forged_envelope, &mut cache),
        Err(CampaignRepositoryError::Integrity {
            reason: "choice-opportunity-cached-reference-mismatch"
        })
    ));
}

#[test]
fn strict_observations_commit_in_global_admission_order() {
    let (repository, lineage, policy) = fixture();
    let (_, first_admitted, first_observation) =
        admitted_observation_fixture(&repository, &lineage, &policy, "observation-order");
    let second_request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "observation-order-second",
    );
    let second_requested = repository
        .submit_known_branch_request(
            "observation-order",
            first_admitted.new_snapshot,
            &second_request,
        )
        .expect("second request");
    let second_proposal = finite_proposal(
        &second_request,
        &policy,
        &repository
            .head("observation-order")
            .expect("second request head"),
        ChoiceValue::Boolean(false),
        1,
    );
    let second_proposed = repository
        .issue_proposal(
            "observation-order",
            second_requested.new_snapshot,
            &second_proposal,
        )
        .expect("second proposal");
    let (second_selection, second_path, second_attempt) =
        branch_attempt(&repository, &second_request, &second_proposal);
    let second_admitted = repository
        .admit_proposal(
            "observation-order",
            second_proposed.new_snapshot,
            second_proposed.proposal,
            &second_selection,
            &second_path,
            &second_attempt,
        )
        .expect("second admission");
    let second_observation = Observation::new(
        second_admitted.attempt,
        Observation::outcome(
            first_observation.child(),
            first_observation.child_content(),
            second_path.id().expect("second path id"),
            StopOutcome::Reached(StopCondition::NextChoice),
            first_observation.measurements(),
            first_observation.properties(),
            first_observation.coverage(),
        ),
        stored_choice_set(&repository, BTreeSet::from([second_request.opportunity()])),
    )
    .expect("second observation");

    assert!(matches!(
        repository.publish_observation(
            "observation-order",
            second_admitted.new_snapshot,
            &second_observation,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "strict-completion-order-gap"
        })
    ));
    assert_eq!(
        repository
            .head("observation-order")
            .expect("head after rejected gap")
            .snapshot_id(),
        second_admitted.new_snapshot
    );
    let first_closed = repository
        .close_attempt_non_modeled(
            "observation-order",
            second_admitted.new_snapshot,
            first_admitted.attempt,
            NonModeledAttemptDisposition::OperatorCancelled,
        )
        .expect("close first admission ordinal");
    assert_eq!(first_closed.ordinal, AdmissionOrdinal::new(1));
    let second_published = repository
        .publish_observation(
            "observation-order",
            first_closed.new_snapshot,
            &second_observation,
        )
        .expect("second observation follows closed ordinal");
    assert_eq!(
        second_published.disposition,
        ObservationDisposition::Canonical
    );
    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    assert_eq!(
        restarted
            .head("observation-order")
            .expect("restart validates mixed strict completion sequence")
            .snapshot_id(),
        second_published.new_snapshot
    );
}
