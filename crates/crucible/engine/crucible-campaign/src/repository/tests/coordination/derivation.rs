//! Historical derivation, authorization, founding-edge replay, and concurrent publication.

use super::*;

#[test]
fn derivation_is_atomic_historical_and_replays_after_later_mutations() {
    let (repository, lineage, policy) = fixture();
    let source = repository
        .create("derive-source", &lineage, &policy, &BTreeMap::new())
        .expect("create source");
    let source_later = repository
        .apply_control(
            "derive-source",
            &command(
                "derive-source-resume",
                source.snapshot_id(),
                CampaignControlAction::Resume,
            ),
        )
        .expect("advance source");
    let derived_policy = policy_with_seed(&policy, [0x44; 32]);
    let derived_policy_id = derived_policy.id().expect("derived policy id");

    let derived = repository
        .derive_campaign(
            "derive-source",
            source.snapshot_id(),
            "derive-target",
            Some(&derived_policy),
        )
        .expect("derive historical snapshot");
    assert!(!derived.replayed);
    assert_eq!(derived.source_snapshot, source.snapshot_id());
    assert_eq!(derived.active_policy, derived_policy_id);
    assert_eq!(
        repository
            .head("derive-source")
            .expect("source head")
            .snapshot_id(),
        source_later.new_snapshot,
        "derivation changed the source ref"
    );
    let derived_head = repository.head("derive-target").expect("derived head");
    assert_eq!(derived_head.snapshot().parent(), Some(source.snapshot_id()));
    assert_eq!(derived_head.snapshot().active_policy(), derived_policy_id);

    let target_later = repository
        .apply_control(
            "derive-target",
            &command(
                "derive-target-resume",
                derived.new_snapshot,
                CampaignControlAction::Resume,
            ),
        )
        .expect("advance target");
    assert_ne!(target_later.new_snapshot, derived.new_snapshot);

    repository
        .validated_heads
        .lock()
        .expect("validation checkpoints")
        .clear();
    let replay = repository
        .derive_campaign(
            "derive-source",
            source.snapshot_id(),
            "derive-target",
            Some(&derived_policy),
        )
        .expect("replay derivation");
    assert!(replay.replayed);
    assert_eq!(replay.new_snapshot, derived.new_snapshot);

    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    let restarted_replay = restarted
        .derive_campaign(
            "derive-source",
            source.snapshot_id(),
            "derive-target",
            Some(&derived_policy),
        )
        .expect("restart replay");
    assert!(restarted_replay.replayed);
    assert_eq!(restarted_replay.new_snapshot, derived.new_snapshot);
}

#[test]
fn derivation_rejects_unsupported_campaign_mode_changes_without_publication() {
    let (repository, lineage, strict_policy) = fixture();
    let source = repository
        .create("mode-source", &lineage, &strict_policy, &BTreeMap::new())
        .expect("create strict source");
    let source_snapshot = source.snapshot_id();

    for (target, mode) in [
        ("streaming-mode-target", CampaignMode::Streaming),
        ("statistical-mode-target", CampaignMode::Statistical),
    ] {
        let policy = policy_with_mode(&strict_policy, mode);
        assert!(matches!(
            repository.derive_campaign("mode-source", source_snapshot, target, Some(&policy),),
            Err(CampaignRepositoryError::InvalidRequest {
                reason: "derived policy is incompatible with the source campaign"
            })
        ));
        assert!(matches!(
            repository.head(target),
            Err(CampaignRepositoryError::NotFound)
        ));
    }

    assert_eq!(
        repository
            .head("mode-source")
            .expect("source remains unchanged")
            .snapshot_id(),
        source_snapshot
    );
}

#[test]
fn nested_derivation_replay_is_bound_to_the_target_founding_edge() {
    let (repository, lineage, policy) = fixture();
    let source = repository
        .create("nested-derive-a", &lineage, &policy, &BTreeMap::new())
        .expect("create source");
    let first = repository
        .derive_campaign(
            "nested-derive-a",
            source.snapshot_id(),
            "nested-derive-b",
            None,
        )
        .expect("derive B");
    let second_policy = policy_with_seed(&policy, [0x63; 32]);
    let second = repository
        .derive_campaign(
            "nested-derive-b",
            first.new_snapshot,
            "nested-derive-c",
            Some(&second_policy),
        )
        .expect("derive C");
    repository
        .apply_control(
            "nested-derive-c",
            &command(
                "nested-derive-c-resume",
                second.new_snapshot,
                CampaignControlAction::Resume,
            ),
        )
        .expect("advance C");

    assert!(matches!(
        repository.derive_campaign(
            "nested-derive-a",
            source.snapshot_id(),
            "nested-derive-c",
            None,
        ),
        Err(CampaignRepositoryError::AlreadyExists)
    ));
    let replay = repository
        .derive_campaign(
            "nested-derive-b",
            first.new_snapshot,
            "nested-derive-c",
            Some(&second_policy),
        )
        .expect("replay C founding edge");
    assert!(replay.replayed);
    assert_eq!(replay.new_snapshot, second.new_snapshot);

    repository
        .validated_heads
        .lock()
        .expect("validation checkpoints")
        .clear();
    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    let restarted_replay = restarted
        .derive_campaign(
            "nested-derive-b",
            first.new_snapshot,
            "nested-derive-c",
            Some(&second_policy),
        )
        .expect("restart replay C founding edge");
    assert!(restarted_replay.replayed);
    assert_eq!(restarted_replay.new_snapshot, second.new_snapshot);
}

#[test]
fn derivation_rejects_foreign_sources_and_existing_different_basis_before_writes() {
    let (repository, lineage, policy, blobs) = counted_fixture();
    let source = repository
        .create("derive-scope-source", &lineage, &policy, &BTreeMap::new())
        .expect("create source");
    let other_policy = policy_with_seed(&policy, [0x23; 32]);
    let other = repository
        .create(
            "derive-scope-other",
            &lineage,
            &other_policy,
            &BTreeMap::new(),
        )
        .expect("create other");
    let objects_before = blobs.object_count().expect("objects before rejection");

    assert!(matches!(
        repository.derive_campaign(
            "derive-scope-source",
            other.snapshot_id(),
            "derive-invalid-target",
            None,
        ),
        Err(CampaignRepositoryError::InvalidRequest {
            reason: "campaign snapshot is not in the named history"
        })
    ));
    assert_eq!(
        blobs.object_count().expect("objects after rejection"),
        objects_before
    );
    assert!(matches!(
        repository.head("derive-invalid-target"),
        Err(CampaignRepositoryError::NotFound)
    ));

    repository
        .derive_campaign(
            "derive-scope-source",
            source.snapshot_id(),
            "derive-existing-target",
            None,
        )
        .expect("first derivation");
    let changed_policy = policy_with_seed(&policy, [0x99; 32]);
    assert!(matches!(
        repository.derive_campaign(
            "derive-scope-source",
            source.snapshot_id(),
            "derive-existing-target",
            Some(&changed_policy),
        ),
        Err(CampaignRepositoryError::AlreadyExists)
    ));
}

#[test]
fn concurrent_derivation_replays_equal_basis_and_rejects_different_basis() {
    let (source_repository, lineage, policy) = fixture();
    let source = source_repository
        .create("derive-race-source", &lineage, &policy, &BTreeMap::new())
        .expect("create derivation source");
    let source_snapshot = source.snapshot_id();
    let source_content = source.content_id();
    let blobs = source_repository.blobs.clone();
    let refs = source_repository.refs.clone();

    let same_barrier = Arc::new(std::sync::Barrier::new(2));
    let mut same_handles = Vec::new();
    for _ in 0..2 {
        let repository = Arc::new(CampaignRepository::new(blobs.clone(), refs.clone()));
        let barrier = Arc::clone(&same_barrier);
        same_handles.push(std::thread::spawn(move || {
            barrier.wait();
            let result = repository.derive_campaign(
                "derive-race-source",
                source_snapshot,
                "same-derive-race",
                None,
            );
            (repository, result)
        }));
    }
    let same_results: Vec<_> = same_handles
        .into_iter()
        .map(|handle| handle.join().expect("same-basis derivation"))
        .collect();
    assert_eq!(
        same_results
            .iter()
            .filter(|(_, result)| !result.as_ref().expect("same-basis result").replayed)
            .count(),
        1
    );
    assert_eq!(
        same_results
            .iter()
            .filter(|(_, result)| result.as_ref().expect("same-basis result").replayed)
            .count(),
        1
    );
    let same_snapshot = same_results[0]
        .1
        .as_ref()
        .expect("same-basis result")
        .new_snapshot;
    assert!(same_results.iter().all(|(_, result)| {
        result.as_ref().expect("same-basis result").new_snapshot == same_snapshot
    }));

    let policies = [
        policy_with_seed(&policy, [0x71; 32]),
        policy_with_seed(&policy, [0x72; 32]),
    ];
    let different_barrier = Arc::new(std::sync::Barrier::new(2));
    let mut different_handles = Vec::new();
    for next_policy in policies {
        let repository = Arc::new(CampaignRepository::new(blobs.clone(), refs.clone()));
        let barrier = Arc::clone(&different_barrier);
        different_handles.push(std::thread::spawn(move || {
            barrier.wait();
            let result = repository.derive_campaign(
                "derive-race-source",
                source_snapshot,
                "different-derive-race",
                Some(&next_policy),
            );
            (repository, result)
        }));
    }
    let different_results: Vec<_> = different_handles
        .into_iter()
        .map(|handle| handle.join().expect("different-basis derivation"))
        .collect();
    assert_eq!(
        different_results
            .iter()
            .filter(|(_, result)| result.is_ok())
            .count(),
        1
    );
    assert_eq!(
        different_results
            .iter()
            .filter(|(_, result)| matches!(result, Err(CampaignRepositoryError::AlreadyExists)))
            .count(),
        1
    );
    let authoritative = source_repository
        .head("different-derive-race")
        .expect("authoritative derivation")
        .content_id();
    for (repository, _) in different_results {
        let checkpoints = repository
            .validated_heads
            .lock()
            .expect("derivation validation checkpoints");
        assert_eq!(checkpoints.len(), 2);
        assert!(checkpoints.contains_key(&source_content));
        assert!(checkpoints.contains_key(&authoritative));
    }
}

#[test]
fn derivation_authorizes_both_names_before_repository_access() {
    let (repository, _, _, blobs) = counted_fixture();
    let calls = Arc::new(Mutex::new(Vec::new()));
    let request = crate::DeriveCampaignRequest::new(
        crate::CampaignPrincipal::new("operator:alice").expect("principal"),
        crate::CampaignName::new("missing-source").expect("source name"),
        CampaignSnapshotId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignSnapshot,
            3,
            b"missing-source-snapshot",
        ))
        .expect("source snapshot"),
        crate::CampaignName::new("denied-target").expect("target name"),
        None,
    )
    .expect("derive request");
    let objects_before = blobs.object_count().expect("objects before authorization");
    let client = crate::CampaignClient::new(crate::RepositoryCampaignService::new(
        &repository,
        RecordAndDenyDeriveTarget {
            calls: Arc::clone(&calls),
            denied_target: "denied-target".to_owned(),
        },
    ));

    assert!(matches!(
        client.derive_campaign(&request),
        Err(crate::CampaignClientError::Service(
            crate::CampaignServiceFailure::Unauthorized
        ))
    ));
    assert_eq!(
        *calls.lock().expect("authorization calls"),
        vec![
            (
                crate::CampaignServiceOperation::DeriveCampaign,
                "missing-source".to_owned()
            ),
            (
                crate::CampaignServiceOperation::DeriveCampaign,
                "denied-target".to_owned()
            ),
        ]
    );
    assert_eq!(
        blobs.object_count().expect("objects after authorization"),
        objects_before
    );
}

#[test]
fn derivation_source_membership_io_does_not_hold_the_mutation_lock() {
    let (source_repository, lineage, policy, blobs) = counted_fixture();
    let source = source_repository
        .create(
            "derive-unlocked-source",
            &lineage,
            &policy,
            &BTreeMap::new(),
        )
        .expect("create source");
    let blocking = Arc::new(BlockingReadBackend::new(blobs, source.content_id()));
    let repository = Arc::new(CampaignRepository::new(
        blocking.clone(),
        source_repository.refs.clone(),
    ));
    let worker_repository = Arc::clone(&repository);
    let worker = std::thread::spawn(move || {
        worker_repository.derive_campaign(
            "derive-unlocked-source",
            source.snapshot_id(),
            "derive-unlocked-target",
            None,
        )
    });

    blocking.wait_until_blocked();
    assert!(
        repository.mutation_lock.try_lock().is_ok(),
        "source authentication held the repository mutation lock"
    );
    blocking.release();
    worker
        .join()
        .expect("derive worker")
        .expect("derive after blocked source read");
}
