//! Campaign creation, imported generator admission, concurrent replay, and bounded head pages.

use super::*;

#[test]
fn campaign_service_creation_replays_the_exact_genesis_after_later_mutation() {
    let (repository, lineage, policy) = fixture();
    let principal = crate::CampaignPrincipal::new("operator:alice").expect("principal");
    let campaign = crate::CampaignName::new("service-create").expect("campaign name");
    let request = crate::CreateCampaignRequest::new(
        principal.clone(),
        campaign.clone(),
        lineage.clone(),
        policy.clone(),
    )
    .expect("create request");
    let client = crate::CampaignClient::new(crate::RepositoryCampaignService::new(
        &repository,
        PermitAlice,
    ));

    let created = client.create_campaign(&request).expect("create campaign");
    assert!(!created.replayed());
    let resumed = client
        .apply_campaign_command(
            &crate::ApplyCampaignCommandRequest::new(
                principal.clone(),
                campaign.clone(),
                command(
                    "create-replay-resume",
                    created.snapshot(),
                    CampaignControlAction::Resume,
                ),
            )
            .expect("resume request"),
        )
        .expect("resume campaign");
    assert_ne!(resumed.new_snapshot(), created.snapshot());
    let paused = client
        .apply_campaign_command(
            &crate::ApplyCampaignCommandRequest::new(
                principal,
                campaign,
                command(
                    "create-replay-pause",
                    resumed.new_snapshot(),
                    CampaignControlAction::Pause(crate::ActiveAttemptPolicy::Drain),
                ),
            )
            .expect("pause request"),
        )
        .expect("pause campaign");
    assert_ne!(paused.new_snapshot(), created.snapshot());

    repository
        .validated_heads
        .lock()
        .expect("validation checkpoints")
        .clear();

    let replayed = client.create_campaign(&request).expect("replay creation");
    assert!(replayed.replayed());
    assert_eq!(replayed.snapshot(), created.snapshot());
    assert_eq!(
        repository
            .genesis("service-create")
            .expect("genesis")
            .snapshot_id(),
        created.snapshot()
    );

    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    let restarted_client = crate::CampaignClient::new(crate::RepositoryCampaignService::new(
        &restarted,
        PermitAlice,
    ));
    let restarted_replay = restarted_client
        .create_campaign(&request)
        .expect("restart replay");
    assert!(restarted_replay.replayed());
    assert_eq!(restarted_replay.snapshot(), created.snapshot());
}

#[test]
fn campaign_service_streams_the_imported_generator_closure_before_writes() {
    let (repository, lineage, _, blobs) = counted_fixture();
    let generator = CandidateGeneratorSpec::new(
        crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::All,
    )
    .expect("generator");
    let generator_id = repository
        .publish_generator(&generator)
        .expect("import generator");
    let policy = policy_with_generator(lineage.scenario(), generator_id);
    let principal = crate::CampaignPrincipal::new("operator:alice").expect("principal");
    let service = crate::CampaignClient::new(crate::RepositoryCampaignService::new(
        &repository,
        PermitAlice,
    ));
    let request = crate::CreateCampaignRequest::new(
        principal.clone(),
        crate::CampaignName::new("stored-generator-create").expect("campaign name"),
        lineage.clone(),
        policy,
    )
    .expect("stored-generator request");
    service
        .create_campaign(&request)
        .expect("create from stored generator");

    let missing = CandidateGeneratorSpecId::from_content_id(ContentId::for_bytes(
        ObjectKind::Policy,
        1,
        b"missing-service-generator",
    ))
    .expect("missing generator id");
    let missing_request = crate::CreateCampaignRequest::new(
        principal,
        crate::CampaignName::new("missing-generator-create").expect("campaign name"),
        lineage.clone(),
        policy_with_generator(lineage.scenario(), missing),
    )
    .expect("missing-generator request");
    let objects_before = blobs.object_count().expect("objects before rejection");
    assert!(matches!(
        service.create_campaign(&missing_request),
        Err(crate::CampaignClientError::Service(
            crate::CampaignServiceFailure::Unavailable
        ))
    ));
    assert_eq!(
        blobs.object_count().expect("objects after rejection"),
        objects_before
    );
    assert!(matches!(
        repository.head("missing-generator-create"),
        Err(CampaignRepositoryError::NotFound)
    ));
}

#[test]
fn concurrent_creation_replays_equal_basis_and_rejects_different_basis() {
    let (source, lineage, policy) = fixture();
    let blobs = source.blobs.clone();
    let refs = source.refs.clone();
    let principal = crate::CampaignPrincipal::new("operator:alice").expect("principal");

    let same_request = crate::CreateCampaignRequest::new(
        principal.clone(),
        crate::CampaignName::new("same-create-race").expect("campaign name"),
        lineage.clone(),
        policy.clone(),
    )
    .expect("same request");
    let same_barrier = Arc::new(std::sync::Barrier::new(2));
    let mut same_handles = Vec::new();
    for _ in 0..2 {
        let repository = Arc::new(CampaignRepository::new(blobs.clone(), refs.clone()));
        let request = same_request.clone();
        let barrier = Arc::clone(&same_barrier);
        same_handles.push(std::thread::spawn(move || {
            barrier.wait();
            let result = crate::CampaignClient::new(crate::RepositoryCampaignService::new(
                repository.as_ref(),
                PermitAlice,
            ))
            .create_campaign(&request);
            (repository, result)
        }));
    }
    let same_results: Vec<_> = same_handles
        .into_iter()
        .map(|handle| handle.join().expect("same-basis creator"))
        .collect();
    assert_eq!(
        same_results
            .iter()
            .filter(|(_, result)| !result.as_ref().expect("same-basis result").replayed())
            .count(),
        1
    );
    assert_eq!(
        same_results
            .iter()
            .filter(|(_, result)| result.as_ref().expect("same-basis result").replayed())
            .count(),
        1
    );

    let different_policy = policy_with_seed(&policy, [0x55; 32]);
    let requests = [
        crate::CreateCampaignRequest::new(
            principal.clone(),
            crate::CampaignName::new("different-create-race").expect("campaign name"),
            lineage.clone(),
            policy,
        )
        .expect("first different-basis request"),
        crate::CreateCampaignRequest::new(
            principal,
            crate::CampaignName::new("different-create-race").expect("campaign name"),
            lineage,
            different_policy,
        )
        .expect("second different-basis request"),
    ];
    let different_barrier = Arc::new(std::sync::Barrier::new(2));
    let mut different_handles = Vec::new();
    for request in requests {
        let repository = Arc::new(CampaignRepository::new(blobs.clone(), refs.clone()));
        let barrier = Arc::clone(&different_barrier);
        different_handles.push(std::thread::spawn(move || {
            barrier.wait();
            let result = crate::CampaignClient::new(crate::RepositoryCampaignService::new(
                repository.as_ref(),
                PermitAlice,
            ))
            .create_campaign(&request);
            (repository, result)
        }));
    }
    let different_results: Vec<_> = different_handles
        .into_iter()
        .map(|handle| handle.join().expect("different-basis creator"))
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
            .filter(|(_, result)| matches!(
                result,
                Err(crate::CampaignClientError::Service(
                    crate::CampaignServiceFailure::AlreadyExists
                ))
            ))
            .count(),
        1
    );
    let authoritative = different_results[0]
        .0
        .head("different-create-race")
        .expect("authoritative raced head")
        .content_id();
    for (repository, result) in &different_results {
        if result.is_err() {
            let checkpoints = repository
                .validated_heads
                .lock()
                .expect("loser validation checkpoints");
            assert_eq!(checkpoints.len(), 1);
            assert!(checkpoints.contains_key(&authoritative));
        }
    }
}

#[test]
fn campaign_head_pages_are_bounded_ordered_and_resumable() {
    let (repository, lineage, policy) = fixture();
    for name in ["zeta", "alpha", "middle"] {
        repository
            .create(name, &lineage, &policy, &BTreeMap::new())
            .expect("create listed campaign");
    }

    let first = repository.list_heads(None, 1).expect("first head page");
    assert_eq!(first.heads().len(), 1);
    assert_eq!(first.heads()[0].name(), "alpha");
    assert_eq!(first.next_after(), Some("alpha"));
    assert_eq!(first.visited_refs(), 2);

    let alpha = first.heads()[0].snapshot_id();
    repository
        .apply_control(
            "alpha",
            &command("advance-listed-alpha", alpha, CampaignControlAction::Resume),
        )
        .expect("advance first listed campaign");

    let second = repository
        .list_heads(first.next_after(), 2)
        .expect("resumed head page");
    assert_eq!(
        second
            .heads()
            .iter()
            .map(CampaignHead::name)
            .collect::<Vec<_>>(),
        ["middle", "zeta"]
    );
    assert_eq!(second.next_after(), None);
    assert_eq!(second.visited_refs(), 3);

    assert!(repository.list_heads(None, 0).is_err());
    assert!(repository.list_heads(Some("bad:name"), 1).is_err());

    let request = crate::ListCampaignsRequest::new(
        crate::CampaignPrincipal::new("operator:alice").expect("principal"),
        Some(crate::CampaignName::new("alpha").expect("cursor")),
        2,
    )
    .expect("service list request");
    let response = crate::CampaignClient::new(crate::RepositoryCampaignService::new(
        &repository,
        PermitAlice,
    ))
    .list_campaigns(&request)
    .expect("checked service list");
    assert_eq!(
        response
            .entries()
            .iter()
            .map(|entry| entry.name().as_str())
            .collect::<Vec<_>>(),
        ["middle", "zeta"]
    );
}
