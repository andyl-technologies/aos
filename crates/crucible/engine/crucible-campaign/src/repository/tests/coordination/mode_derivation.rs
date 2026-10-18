//! Mode-derivation transactions and authenticated completion ordering.

use super::*;

#[test]
fn streaming_to_strict_derivation_accepts_an_empty_authenticated_history() {
    let (repository, lineage, strict_policy) = fixture();
    let streaming_policy = policy_with_mode(&strict_policy, CampaignMode::Streaming);
    let source = repository
        .create(
            "streaming-empty",
            &lineage,
            &streaming_policy,
            &BTreeMap::new(),
        )
        .expect("create streaming source");

    let derived = repository
        .derive_campaign(
            "streaming-empty",
            source.snapshot_id(),
            "strict-empty",
            Some(&strict_policy),
        )
        .expect("derive strict campaign");

    assert_eq!(
        derived.active_policy,
        strict_policy.id().expect("strict policy")
    );
    assert_eq!(
        repository
            .head("streaming-empty")
            .expect("source head")
            .snapshot_id(),
        source.snapshot_id()
    );
    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    assert_eq!(
        restarted
            .head("strict-empty")
            .expect("cold derived head")
            .snapshot_id(),
        derived.new_snapshot
    );
}

fn admit_later_observation(
    repository: &CampaignRepository,
    lineage: &CampaignLineage,
    policy: &CampaignPolicy,
    name: &str,
    label: &str,
    evidence: &Observation,
) -> Observation {
    let request = branch_request(
        repository,
        lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        label,
    );
    let head = repository.head(name).expect("prior admission head");
    let requested = repository
        .submit_known_branch_request(name, head.snapshot_id(), &request)
        .expect("submit distinct request");
    let proposal = finite_proposal(
        &request,
        policy,
        &repository.head(name).expect("requested head"),
        ChoiceValue::Boolean(false),
        1,
    );
    let proposed = repository
        .issue_proposal(name, requested.new_snapshot, &proposal)
        .expect("issue distinct proposal");
    let (selection, path, attempt) = branch_attempt(repository, &request, &proposal);
    let admitted = repository
        .admit_proposal(
            name,
            proposed.new_snapshot,
            proposed.proposal,
            &selection,
            &path,
            &attempt,
        )
        .expect("admit distinct attempt");

    Observation::new(
        admitted.attempt,
        Observation::outcome(
            evidence.child(),
            evidence.child_content(),
            path.id().expect("path identity"),
            evidence.stop().clone(),
            evidence.measurements(),
            evidence.properties(),
            evidence.coverage(),
        ),
        BTreeSet::from([request.opportunity()]),
    )
    .expect("later observation")
}

fn publish_current(repository: &CampaignRepository, name: &str, observation: &Observation) {
    repository
        .publish_observation(
            name,
            repository
                .head(name)
                .expect("current publication head")
                .snapshot_id(),
            observation,
        )
        .expect("publish streaming observation");
}

#[test]
fn streaming_to_strict_derivation_preserves_completions_beyond_a_real_hole() {
    let (repository, lineage, strict_policy) = fixture();
    let streaming_policy = policy_with_mode(&strict_policy, CampaignMode::Streaming);
    let (_, first, first_observation) =
        admitted_observation_fixture(&repository, &lineage, &streaming_policy, "streaming-hole");
    let second = admit_later_observation(
        &repository,
        &lineage,
        &streaming_policy,
        "streaming-hole",
        "hole-second",
        &first_observation,
    );
    let third = admit_later_observation(
        &repository,
        &lineage,
        &streaming_policy,
        "streaming-hole",
        "hole-third",
        &first_observation,
    );
    let fourth = admit_later_observation(
        &repository,
        &lineage,
        &streaming_policy,
        "streaming-hole",
        "hole-fourth",
        &first_observation,
    );
    publish_current(&repository, "streaming-hole", &third);
    let source = repository.head("streaming-hole").expect("streaming head");
    let closed = repository
        .close_attempt_non_modeled(
            "streaming-hole",
            source.snapshot_id(),
            first.attempt,
            NonModeledAttemptDisposition::OperatorCancelled,
        )
        .expect("close ordinal one after ordinal three");

    let derived = repository
        .derive_campaign(
            "streaming-hole",
            closed.new_snapshot,
            "strict-hole",
            Some(&strict_policy),
        )
        .expect("derive from mixed noncontiguous completions");
    let source_roots = repository
        .read_snapshot(closed.new_snapshot.content_id())
        .expect("source")
        .snapshot
        .roots();
    let strict_roots = repository
        .read_snapshot(derived.new_snapshot.content_id())
        .expect("strict")
        .snapshot
        .roots();
    let sequence = repository
        .merkle
        .get(strict_roots.accounting, observation_sequence_key())
        .expect("prefix anchor");
    assert_eq!(
        sequence,
        repository
            .merkle
            .get(
                source_roots.accounting,
                non_modeled_ordinal_key(AdmissionOrdinal::new(1))
            )
            .expect("closed one")
    );
    assert_eq!(
        repository
            .completion_at_ordinal(strict_roots.accounting, AdmissionOrdinal::new(3))
            .expect("retained third"),
        Some(third.id().expect("third identity").content_id())
    );
    assert_eq!(source_roots.observations, strict_roots.observations);
    assert_eq!(source_roots.graph, strict_roots.graph);

    // A cold reader must reconstruct the same prefix; no local derivation
    // cache or numeric caller cursor grants the next completion.
    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    assert!(matches!(
        restarted.publish_observation("strict-hole", derived.new_snapshot, &fourth),
        Err(CampaignRepositoryError::Integrity {
            reason: "strict-completion-order-gap"
        })
    ));
    let filled = restarted
        .publish_observation("strict-hole", derived.new_snapshot, &second)
        .expect("fill ordinal two");
    let completed = restarted
        .publish_observation("strict-hole", filled.new_snapshot, &fourth)
        .expect("skip already completed three");
    let replay = restarted
        .derive_campaign(
            "streaming-hole",
            closed.new_snapshot,
            "strict-hole",
            Some(&strict_policy),
        )
        .expect("retry exact derivation after completion");
    assert!(replay.replayed);
    assert_eq!(replay.new_snapshot, derived.new_snapshot);
    assert_eq!(
        restarted
            .head("strict-hole")
            .expect("strict final head")
            .snapshot_id(),
        completed.new_snapshot
    );
    assert_eq!(
        restarted
            .head("streaming-hole")
            .expect("source unchanged")
            .snapshot_id(),
        closed.new_snapshot
    );
}

#[test]
fn streaming_to_strict_derivation_with_a_leading_hole_keeps_the_empty_prefix() {
    let (repository, lineage, strict_policy) = fixture();
    let streaming_policy = policy_with_mode(&strict_policy, CampaignMode::Streaming);
    let (_, first, first_observation) = admitted_observation_fixture(
        &repository,
        &lineage,
        &streaming_policy,
        "streaming-leading-hole",
    );
    let second = admit_later_observation(
        &repository,
        &lineage,
        &streaming_policy,
        "streaming-leading-hole",
        "leading-second",
        &first_observation,
    );
    publish_current(&repository, "streaming-leading-hole", &second);
    let source = repository.head("streaming-leading-hole").expect("source");
    let derived = repository
        .derive_campaign(
            "streaming-leading-hole",
            source.snapshot_id(),
            "strict-leading-hole",
            Some(&strict_policy),
        )
        .expect("derive with first ordinal incomplete");
    let roots = repository
        .read_snapshot(derived.new_snapshot.content_id())
        .expect("derived")
        .snapshot
        .roots();
    assert_eq!(
        repository
            .merkle
            .get(roots.accounting, observation_sequence_key())
            .expect("no prefix"),
        None
    );
    assert_eq!(
        repository
            .next_strict_completion_ordinal(roots.accounting)
            .expect("first incomplete"),
        1
    );
    let filled = repository
        .close_attempt_non_modeled(
            "strict-leading-hole",
            derived.new_snapshot,
            first.attempt,
            NonModeledAttemptDisposition::OperatorCancelled,
        )
        .expect("close leading hole");
    let roots = repository
        .read_snapshot(filled.new_snapshot.content_id())
        .expect("filled")
        .snapshot
        .roots();
    assert_eq!(
        repository
            .next_strict_completion_ordinal(roots.accounting)
            .expect("skip retained two"),
        3
    );
}

#[test]
fn streaming_to_strict_derivation_rejects_a_forged_prefix_on_cold_import() {
    let (repository, lineage, strict_policy) = fixture();
    let streaming_policy = policy_with_mode(&strict_policy, CampaignMode::Streaming);
    let (_, _, first_observation) = admitted_observation_fixture(
        &repository,
        &lineage,
        &streaming_policy,
        "streaming-forged-prefix",
    );
    let second = admit_later_observation(
        &repository,
        &lineage,
        &streaming_policy,
        "streaming-forged-prefix",
        "forged-second",
        &first_observation,
    );
    publish_current(&repository, "streaming-forged-prefix", &second);
    let source = repository.head("streaming-forged-prefix").expect("source");
    let derived = repository
        .derive_campaign(
            "streaming-forged-prefix",
            source.snapshot_id(),
            "strict-forged-prefix",
            Some(&strict_policy),
        )
        .expect("valid leading hole derivation");
    let loaded = repository
        .read_snapshot(derived.new_snapshot.content_id())
        .expect("valid derived snapshot");
    let mut roots = loaded.snapshot.roots();
    roots.accounting = repository
        .merkle
        .insert(
            roots.accounting,
            observation_sequence_key(),
            second.id().expect("second identity").content_id(),
        )
        .expect("forge skipped hole anchor")
        .content_id();
    let forged = CampaignSnapshot::successor(
        source.snapshot_id(),
        loaded.snapshot.lineage(),
        loaded.snapshot.active_policy(),
        roots,
        loaded.snapshot.transition().expect("derivation fact"),
        loaded.snapshot.budget_ledger(),
    )
    .expect("structural forged snapshot");
    let forged_content = repository
        .put_snapshot(&forged)
        .expect("store imported forged snapshot");
    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    assert!(matches!(
        restarted.validate_complete_head(forged_content),
        Err(CampaignRepositoryError::Integrity {
            reason: "derivation-transition-changed-semantic-root"
        })
    ));
    assert_eq!(
        restarted
            .head("strict-forged-prefix")
            .expect("valid target retained")
            .snapshot_id(),
        derived.new_snapshot
    );
}

#[test]
fn streaming_to_strict_derivation_authenticates_a_complete_prefix_before_new_work() {
    let (repository, lineage, strict_policy) = fixture();
    let streaming_policy = policy_with_mode(&strict_policy, CampaignMode::Streaming);
    let (_, _, first) = admitted_observation_fixture(
        &repository,
        &lineage,
        &streaming_policy,
        "streaming-complete",
    );
    let second = admit_later_observation(
        &repository,
        &lineage,
        &streaming_policy,
        "streaming-complete",
        "complete-second",
        &first,
    );
    publish_current(&repository, "streaming-complete", &second);
    publish_current(&repository, "streaming-complete", &first);
    let source = repository
        .head("streaming-complete")
        .expect("complete source");
    let derived = repository
        .derive_campaign(
            "streaming-complete",
            source.snapshot_id(),
            "strict-complete",
            Some(&strict_policy),
        )
        .expect("derive complete prefix");
    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    let roots = restarted
        .read_snapshot(derived.new_snapshot.content_id())
        .expect("derived")
        .snapshot
        .roots();
    assert_eq!(
        restarted
            .merkle
            .get(roots.accounting, observation_sequence_key())
            .expect("prefix"),
        Some(second.id().expect("second id").content_id())
    );
    assert_eq!(
        restarted
            .next_strict_completion_ordinal(roots.accounting)
            .expect("next ordinal"),
        3
    );

    let third = admit_later_observation(
        &restarted,
        &lineage,
        &strict_policy,
        "strict-complete",
        "complete-third",
        &first,
    );
    publish_current(&restarted, "strict-complete", &third);
    let cold = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    let head = cold
        .head("strict-complete")
        .expect("new strict work validates cold");
    let roots = cold
        .read_snapshot(head.content_id())
        .expect("strict head")
        .snapshot
        .roots();
    assert_eq!(
        cold.next_strict_completion_ordinal(roots.accounting)
            .expect("strict progress"),
        4
    );
}

#[test]
fn streaming_to_strict_derivation_refuses_an_unauthenticated_source_before_publication() {
    let (repository, lineage, strict_policy, blobs) = counted_fixture();
    let streaming_policy = policy_with_mode(&strict_policy, CampaignMode::Streaming);
    let (_, _, first) = admitted_observation_fixture(
        &repository,
        &lineage,
        &streaming_policy,
        "streaming-invalid-source",
    );
    publish_current(&repository, "streaming-invalid-source", &first);
    let source = repository
        .head("streaming-invalid-source")
        .expect("valid source");
    let loaded = repository
        .read_snapshot(source.content_id())
        .expect("source snapshot");
    let mut roots = loaded.snapshot.roots();
    roots.accounting = repository
        .merkle
        .insert(
            roots.accounting,
            observation_ordinal_key(AdmissionOrdinal::new(1)),
            strict_policy.id().expect("policy id").content_id(),
        )
        .expect("wrong record under completion index")
        .content_id();
    let forged = CampaignSnapshot::successor(
        loaded.snapshot.parent().expect("source parent"),
        loaded.snapshot.lineage(),
        loaded.snapshot.active_policy(),
        roots,
        loaded.snapshot.transition().expect("source fact"),
        loaded.snapshot.budget_ledger(),
    )
    .expect("forged source");
    let forged_content = repository
        .put_snapshot(&forged)
        .expect("imported corrupt source");
    let source_ref = campaign_ref("streaming-invalid-source").expect("source ref");
    assert!(matches!(
        repository
            .refs
            .compare_exchange(&source_ref, Some(source.content_id()), forged_content)
            .expect("corrupt imported ref"),
        RefCasOutcome::Advanced { .. }
    ));
    let objects_before = blobs.object_count().expect("objects before refusal");
    let cold = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());

    assert!(
        cold.derive_campaign(
            "streaming-invalid-source",
            CampaignSnapshotId::from_content_id(forged_content).expect("forged id"),
            "strict-invalid-source",
            Some(&strict_policy)
        )
        .is_err()
    );
    assert_eq!(
        blobs
            .object_count()
            .expect("no partial policy or derivation writes"),
        objects_before
    );
    assert!(matches!(
        cold.head("strict-invalid-source"),
        Err(CampaignRepositoryError::NotFound)
    ));
    assert_eq!(
        cold.refs.read_ref(&source_ref).expect("source unchanged"),
        Some(forged_content)
    );
}
