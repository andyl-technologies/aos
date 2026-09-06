//! Coordinator mutation, planner, and incremental-history repository tests.

use super::*;

struct PermitAlice;

impl crate::CampaignPrincipalAuthorizer for PermitAlice {
    fn authorize_all_campaigns(
        &self,
        principal: &crate::CampaignPrincipal,
        _operation: crate::CampaignServiceOperation,
        _request_digest: CampaignHash,
    ) -> Result<(), crate::CampaignAuthorizationError> {
        if principal.as_str() == "operator:alice" {
            Ok(())
        } else {
            Err(crate::CampaignAuthorizationError::Unauthorized)
        }
    }

    fn authorize(
        &self,
        principal: &crate::CampaignPrincipal,
        _operation: crate::CampaignServiceOperation,
        _campaign: &crate::CampaignName,
        _request_digest: CampaignHash,
    ) -> Result<(), crate::CampaignAuthorizationError> {
        if principal.as_str() == "operator:alice" {
            Ok(())
        } else {
            Err(crate::CampaignAuthorizationError::Unauthorized)
        }
    }
}

struct RecordAndDenyDeriveTarget {
    calls: Arc<Mutex<Vec<(crate::CampaignServiceOperation, String)>>>,
    denied_target: String,
}

struct BlockingReadBackend {
    inner: Arc<MemoryBlobBackend>,
    blocked_id: ContentId,
    state: Mutex<(bool, bool)>,
    changed: std::sync::Condvar,
}

impl BlockingReadBackend {
    fn new(inner: Arc<MemoryBlobBackend>, blocked_id: ContentId) -> Self {
        Self {
            inner,
            blocked_id,
            state: Mutex::new((false, false)),
            changed: std::sync::Condvar::new(),
        }
    }

    fn wait_until_blocked(&self) {
        let mut state = self.state.lock().expect("blocking read state");
        while !state.0 {
            state = self.changed.wait(state).expect("blocking read wait");
        }
    }

    fn release(&self) {
        let mut state = self.state.lock().expect("blocking read state");
        state.1 = true;
        self.changed.notify_all();
    }
}

impl crucible_cas::content_store::ImmutableBlobBackend for BlockingReadBackend {
    fn name(&self) -> &str {
        "blocking-campaign-test"
    }

    fn capabilities(&self) -> crucible_cas::content_store::BackendCapabilities {
        self.inner.capabilities()
    }

    fn contains(&self, id: ContentId) -> Result<bool, StoreError> {
        self.inner.contains(id)
    }

    fn read(
        &self,
        id: ContentId,
        range: Option<crucible_cas::content_store::ByteRange>,
    ) -> Result<crucible_cas::content_store::BlobHandle, StoreError> {
        if id == self.blocked_id {
            let mut state = self.state.lock().map_err(|_| StoreError::Poisoned {
                operation: "blocking-read-state",
            })?;
            state.0 = true;
            self.changed.notify_all();
            while !state.1 {
                state = self.changed.wait(state).map_err(|_| StoreError::Poisoned {
                    operation: "blocking-read-wait",
                })?;
            }
        }
        self.inner.read(id, range)
    }

    fn put_if_absent(
        &self,
        id: ContentId,
        source: &crucible_cas::content_store::BlobHandle,
    ) -> Result<crucible_cas::content_store::PutReceipt, StoreError> {
        self.inner.put_if_absent(id, source)
    }
}

impl crate::CampaignPrincipalAuthorizer for RecordAndDenyDeriveTarget {
    fn authorize(
        &self,
        _principal: &crate::CampaignPrincipal,
        operation: crate::CampaignServiceOperation,
        campaign: &crate::CampaignName,
        _request_digest: CampaignHash,
    ) -> Result<(), crate::CampaignAuthorizationError> {
        self.calls
            .lock()
            .expect("authorization calls")
            .push((operation, campaign.as_str().to_owned()));
        if campaign.as_str() == self.denied_target {
            Err(crate::CampaignAuthorizationError::Unauthorized)
        } else {
            Ok(())
        }
    }
}

fn policy_with_seed(policy: &CampaignPolicy, seed: [u8; 32]) -> CampaignPolicy {
    CampaignPolicy::new(
        policy.scenario(),
        CampaignSeed::from_bytes(seed),
        policy.mode(),
        policy.explorer().clone(),
        policy.choice_policies().clone(),
        policy.objectives().clone(),
        policy.guidance().clone(),
        policy.stop_conditions().clone(),
        policy.fairness(),
        policy.retention(),
        policy.admits_scenario_defaults(),
    )
    .expect("policy with changed seed")
}

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
    let generator =
        CandidateGeneratorSpec::new(1, CandidateGeneratorAlgorithm::All).expect("generator");
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
            2,
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

#[test]
fn direct_campaign_service_uses_repository_owner_and_exact_replay() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("service", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let principal = crate::CampaignPrincipal::new("operator:alice").expect("principal");
    let campaign = crate::CampaignName::new("service").expect("campaign name");
    let service = crate::RepositoryCampaignService::new(&repository, PermitAlice);
    let client = crate::CampaignClient::new(service);

    let current = client
        .get_campaign(
            &crate::GetCampaignRequest::new(principal.clone(), campaign.clone())
                .expect("get request"),
        )
        .expect("get campaign");
    assert_eq!(current.snapshot(), genesis.snapshot_id());
    assert_eq!(current.state(), CampaignState::Created);
    assert_eq!(
        current.state(),
        repository
            .state_at_snapshot(current.snapshot())
            .expect("state at returned snapshot")
    );

    let request = crate::ApplyCampaignCommandRequest::new(
        principal.clone(),
        campaign.clone(),
        command(
            "service-resume",
            genesis.snapshot_id(),
            CampaignControlAction::Resume,
        ),
    )
    .expect("apply request");
    let accepted = client
        .apply_campaign_command(&request)
        .expect("apply command");
    assert!(!accepted.replayed());
    let replayed = client
        .apply_campaign_command(&request)
        .expect("replay command");
    assert!(replayed.replayed());
    assert_eq!(replayed.prior_snapshot(), accepted.prior_snapshot());
    assert_eq!(replayed.new_snapshot(), accepted.new_snapshot());

    let pin = crate::PinCampaignRequest::new(
        principal,
        campaign,
        crate::PinRequest {
            command: crate::CampaignCommandId::from_hash(CampaignHash::derive(
                "test",
                b"service-pin",
            )),
            expected_snapshot: accepted.new_snapshot(),
            change: crate::PinChange::new(
                lineage.genesis(),
                Some(crate::PinRetention::Thin),
                "retain semantic replay",
            )
            .expect("pin change"),
        },
    )
    .expect("pin request");
    let pinned = client.pin_campaign(&pin).expect("pin campaign");
    assert!(!pinned.replayed());
    let replayed_pin = client.pin_campaign(&pin).expect("replay pin command");
    assert!(replayed_pin.replayed());
    assert_eq!(replayed_pin.prior_snapshot(), pinned.prior_snapshot());
    assert_eq!(replayed_pin.new_snapshot(), pinned.new_snapshot());
}

#[test]
fn create_and_control_form_linear_authenticated_history() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("network-recovery", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    assert_eq!(
        repository.state("network-recovery").expect("state"),
        CampaignState::Created
    );

    let resume = command(
        "resume",
        genesis.snapshot_id(),
        CampaignControlAction::Resume,
    );
    let resumed = repository
        .apply_control("network-recovery", &resume)
        .expect("resume");
    assert_eq!(resumed.prior_snapshot, genesis.snapshot_id());
    assert_eq!(
        repository.state("network-recovery").expect("state"),
        CampaignState::Running
    );

    let pause = command(
        "pause",
        resumed.new_snapshot,
        CampaignControlAction::Pause(crate::ActiveAttemptPolicy::Drain),
    );
    let paused = repository
        .apply_control("network-recovery", &pause)
        .expect("pause");
    assert_eq!(
        repository.state("network-recovery").expect("state"),
        CampaignState::Paused
    );
    let (_, lifecycle) = repository
        .head_with_lifecycle("network-recovery")
        .expect("paused lifecycle intent");
    assert_eq!(lifecycle.state(), CampaignState::Paused);
    assert_eq!(
        lifecycle.active_attempt_policy(),
        Some(crate::ActiveAttemptPolicy::Drain)
    );
    assert_ne!(paused.new_snapshot, resumed.new_snapshot);

    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    let (_, restarted_lifecycle) = restarted
        .head_with_lifecycle("network-recovery")
        .expect("restart lifecycle intent");
    assert_eq!(restarted_lifecycle, lifecycle);
}

#[test]
fn policy_activation_cannot_change_campaign_reproducibility_mode() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("policy-mode", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let streaming = CampaignPolicy::new(
        policy.scenario(),
        policy.campaign_seed(),
        CampaignMode::Streaming,
        policy.explorer().clone(),
        policy.choice_policies().clone(),
        policy.objectives().clone(),
        policy.guidance().clone(),
        policy.stop_conditions().clone(),
        policy.fairness(),
        policy.retention(),
        policy.admits_scenario_defaults(),
    )
    .expect("streaming policy");
    let streaming = CampaignPolicyId::from_content_id(
        repository
            .publish_policy(&streaming)
            .expect("publish streaming policy"),
    )
    .expect("streaming policy id");
    let activate = command(
        "policy-mode-change",
        genesis.snapshot_id(),
        CampaignControlAction::ActivatePolicy(streaming),
    );

    assert!(matches!(
        repository.apply_control("policy-mode", &activate),
        Err(CampaignRepositoryError::Integrity {
            reason: "activated-policy-mode-mismatch"
        })
    ));
    assert_eq!(
        repository
            .head("policy-mode")
            .expect("unchanged policy head")
            .snapshot_id(),
        genesis.snapshot_id()
    );

    let parent = repository
        .read_snapshot(genesis.content_id())
        .expect("policy parent");
    let control = CampaignFact::ControlRequested(activate.clone());
    let control_content = repository.put_fact(&control).expect("put forged control");
    let mut accounting = repository
        .merkle
        .insert(
            parent.snapshot.roots().accounting,
            map_key_hash("accounting.command", activate.command.as_hash()),
            control_content,
        )
        .expect("forged command accounting");
    let activation = CampaignFact::PolicyActivated(
        PolicyActivation::new(policy.id().expect("prior policy"), streaming)
            .expect("forged activation"),
    );
    let activation_content = repository
        .put_fact(&activation)
        .expect("put forged activation");
    accounting = repository
        .insert_fact(accounting, &activation, activation_content)
        .expect("forged activation accounting");
    let mut roots = parent.snapshot.roots();
    roots.accounting = accounting.content_id();
    let forged = CampaignSnapshot::successor(
        genesis.snapshot_id(),
        parent.snapshot.lineage(),
        streaming,
        roots,
        CampaignFactId::from_content_id(control_content).expect("control fact id"),
    )
    .expect("forged mode-change successor");
    let forged_content = repository
        .put_snapshot(&forged)
        .expect("put forged mode-change successor");
    assert!(matches!(
        repository.validate_complete_head(forged_content),
        Err(CampaignRepositoryError::Integrity {
            reason: "activated-policy-mode-mismatch"
        })
    ));
}

mod planning;

#[test]
fn choice_discovery_is_exact_replayable_and_required_before_branching() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("choice-discovery", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "choice-discovery",
    );
    assert!(matches!(
        repository.submit_branch_request("choice-discovery", genesis.snapshot_id(), &request),
        Err(CampaignRepositoryError::Integrity {
            reason: "branch-request-opportunity-is-not-authoritative-campaign-knowledge"
        })
    ));
    assert_eq!(
        repository
            .head("choice-discovery")
            .expect("unchanged genesis")
            .snapshot_id(),
        genesis.snapshot_id()
    );

    let discovered = repository
        .discover_choice_opportunity(
            "choice-discovery",
            genesis.snapshot_id(),
            request.parent(),
            request.opportunity(),
        )
        .expect("discover choice");
    assert!(!discovered.replayed);
    assert_eq!(discovered.prior_snapshot, genesis.snapshot_id());
    assert_eq!(discovered.parent, request.parent());
    assert_eq!(discovered.branch_point, request.branch_point());
    let discovery_snapshot = repository
        .read_snapshot(discovered.new_snapshot.content_id())
        .expect("discovery snapshot");
    assert_eq!(
        repository
            .merkle
            .get(
                discovery_snapshot.snapshot.roots().graph,
                authoritative_choice_key(request.opportunity()),
            )
            .expect("authoritative choice membership"),
        Some(request.opportunity().content_id())
    );
    let opportunity = repository
        .load_choice_opportunity(request.opportunity())
        .expect("load discovered opportunity");
    let object_request = crate::GetCampaignChoiceObjectRequest::new(
        crate::CampaignPrincipal::new("operator:alice").expect("principal"),
        crate::CampaignName::new("choice-discovery").expect("campaign"),
        discovered.new_snapshot,
        request.opportunity(),
        crate::CampaignChoiceObjectKind::Domain,
    )
    .expect("choice object request");
    let object_response = crate::CampaignClient::new(crate::RepositoryCampaignService::new(
        &repository,
        PermitAlice,
    ))
    .get_campaign_choice_object(&object_request)
    .expect("authenticated choice domain");
    assert_eq!(object_response.opportunity(), &opportunity);
    assert!(matches!(
        object_response.object(),
        crate::CampaignChoiceObject::Domain(domain) if domain.id().expect("domain id") == opportunity.domain()
    ));
    let (choice_page, index_proof, page_proof) = repository
        .scan_choice_page(discovery_snapshot.snapshot.roots().graph, None, 1)
        .expect("authenticated choice page");
    assert_eq!(
        choice_page.entries(),
        &[(
            choice_index_order_key(request.opportunity()),
            request.opportunity().content_id(),
        )]
    );
    assert!(index_proof.node_count() > 0);
    assert!(page_proof.node_count() > 0);
    let choice_index = repository
        .merkle
        .get(
            discovery_snapshot.snapshot.roots().graph,
            choice_index_anchor_key(),
        )
        .expect("choice-index anchor")
        .expect("choice-index root");
    assert_eq!(
        repository
            .merkle
            .get(choice_index, choice_index_order_key(request.opportunity()),)
            .expect("choice-index membership"),
        Some(request.opportunity().content_id())
    );
    assert_eq!(
        repository
            .merkle
            .get(
                discovery_snapshot.snapshot.roots().graph,
                branch_point_opportunity_key(request.branch_point(), request.opportunity()),
            )
            .expect("scoped choice membership"),
        Some(request.opportunity().content_id())
    );

    let accepted = repository
        .submit_branch_request("choice-discovery", discovered.new_snapshot, &request)
        .expect("submit known request");
    let historical_response = crate::CampaignClient::new(crate::RepositoryCampaignService::new(
        &repository,
        PermitAlice,
    ))
    .get_campaign_choice_object(&object_request)
    .expect("load choice domain from an exact historical snapshot");
    assert_eq!(
        historical_response
            .snapshot_body()
            .id()
            .expect("snapshot id"),
        discovered.new_snapshot
    );
    let replay = repository
        .discover_choice_opportunity(
            "choice-discovery",
            genesis.snapshot_id(),
            request.parent(),
            request.opportunity(),
        )
        .expect("replay discovery before stale check");
    assert!(replay.replayed);
    assert_eq!(replay.new_snapshot, discovered.new_snapshot);
    assert_eq!(
        repository
            .head("choice-discovery")
            .expect("branch head remains current")
            .snapshot_id(),
        accepted.new_snapshot
    );

    let mut forged_roots = discovery_snapshot.snapshot.roots();
    forged_roots.graph = repository
        .merkle
        .insert(
            forged_roots.graph,
            map_key_content("graph.forged-choice", request.opportunity().content_id()),
            request.opportunity().content_id(),
        )
        .expect("forged discovery graph")
        .content_id();
    let forged = CampaignSnapshot::successor(
        genesis.snapshot_id(),
        discovery_snapshot.snapshot.lineage(),
        discovery_snapshot.snapshot.active_policy(),
        forged_roots,
        discovery_snapshot
            .snapshot
            .transition()
            .expect("discovery transition"),
    )
    .expect("forged discovery successor");
    let forged_content = repository
        .put_snapshot(&forged)
        .expect("put forged discovery successor");
    assert!(matches!(
        repository.validate_complete_head(forged_content),
        Err(CampaignRepositoryError::Integrity {
            reason: "choice-discovery-graph-root-mismatch"
        })
    ));
}

#[test]
fn choice_authority_is_scoped_to_the_exact_parent_branch_point() {
    let (repository, lineage, policy) = fixture();
    let (genesis, admitted, observation) =
        admitted_observation_fixture(&repository, &lineage, &policy, "choice-parent-scope");
    let observed = repository
        .publish_observation("choice-parent-scope", admitted.new_snapshot, &observation)
        .expect("publish child observation");

    let request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "genesis-only-choice",
    );
    let discovered = repository
        .discover_choice_opportunity(
            "choice-parent-scope",
            observed.new_snapshot,
            request.parent(),
            request.opportunity(),
        )
        .expect("discover choice only at genesis");
    let opportunity = repository
        .load_choice_opportunity(request.opportunity())
        .expect("load opportunity");
    let cross_parent = BranchRequest::new(
        opportunity.branch_point_id(observation.child()),
        observation.child_content(),
        request.opportunity(),
        request.domain(),
        request.source().clone(),
        request.cause(),
        request.budget(),
        request.stop().clone(),
    )
    .expect("cross-parent request");
    assert!(matches!(
        repository.submit_branch_request(
            "choice-parent-scope",
            discovered.new_snapshot,
            &cross_parent,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "branch-request-opportunity-is-not-authoritative-campaign-knowledge"
        })
    ));
    assert_eq!(
        repository
            .head("choice-parent-scope")
            .expect("unchanged scoped head")
            .snapshot_id(),
        discovered.new_snapshot
    );
    assert_ne!(genesis, observed.new_snapshot);
}

#[test]
fn legacy_mutations_never_create_partial_choice_or_frontier_indexes() {
    let (repository, lineage, policy) = fixture();
    let lineage_content = repository.put_lineage(&lineage).expect("lineage");
    let policy_content = repository.put_policy(&policy).expect("policy");
    let empty = repository.merkle.empty().expect("empty root").content_id();
    let graph = repository
        .merkle
        .insert(
            empty,
            map_key_hash("graph.configuration", lineage.genesis().as_hash()),
            lineage.genesis_content().content_id(),
        )
        .expect("legacy graph");
    let corpus = repository
        .merkle
        .insert(
            empty,
            map_key_hash("corpus.configuration", lineage.genesis().as_hash()),
            lineage.genesis_content().content_id(),
        )
        .expect("legacy corpus");
    let legacy = CampaignSnapshot::genesis(
        CampaignLineageId::from_content_id(lineage_content).expect("lineage id"),
        CampaignPolicyId::from_content_id(policy_content).expect("policy id"),
        crate::CampaignRoots {
            graph: graph.content_id(),
            exploration: empty,
            observations: empty,
            corpus: corpus.content_id(),
            coverage: empty,
            findings: empty,
            pins: empty,
            accounting: empty,
            coordination: empty,
        },
    )
    .expect("legacy snapshot");
    let legacy_content = repository
        .put_snapshot(&legacy)
        .expect("legacy snapshot body");
    repository
        .refs
        .compare_exchange(
            &campaign_ref("legacy-choice-index").expect("campaign ref"),
            None,
            legacy_content,
        )
        .expect("publish legacy head");
    let legacy_id =
        CampaignSnapshotId::from_content_id(legacy_content).expect("legacy snapshot id");
    repository
        .head("legacy-choice-index")
        .expect("authenticate legacy head");

    let request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "legacy-choice",
    );
    let discovered = repository
        .discover_choice_opportunity(
            "legacy-choice-index",
            legacy_id,
            request.parent(),
            request.opportunity(),
        )
        .expect("discover on legacy head");
    let head = repository
        .head("legacy-choice-index")
        .expect("legacy successor");
    assert_eq!(head.snapshot_id(), discovered.new_snapshot);
    assert_eq!(
        repository
            .merkle
            .get(head.snapshot().roots().graph, choice_index_anchor_key())
            .expect("choice-index lookup"),
        None
    );
    assert!(matches!(
        repository.scan_choice_page(head.snapshot().roots().graph, None, 1),
        Err(CampaignRepositoryError::InvalidRequest {
            reason: "campaign-snapshot-has-no-choice-index"
        })
    ));

    let accepted = repository
        .submit_branch_request("legacy-choice-index", discovered.new_snapshot, &request)
        .expect("submit request on legacy head");
    let requested = repository
        .head("legacy-choice-index")
        .expect("legacy request successor");
    assert_eq!(requested.snapshot_id(), accepted.new_snapshot);
    assert_eq!(
        repository
            .merkle
            .get(
                requested.snapshot().roots().exploration,
                frontier_index_anchor_key(),
            )
            .expect("frontier-index lookup"),
        None
    );
    assert!(matches!(
        repository.scan_frontier_page(requested.snapshot().roots().exploration, None, 1),
        Err(CampaignRepositoryError::InvalidRequest {
            reason: "campaign-snapshot-has-no-frontier-index"
        })
    ));
    assert!(matches!(
        repository.lookup_frontier_projection(
            requested.snapshot().roots().exploration,
            request.id().expect("request id"),
        ),
        Err(CampaignRepositoryError::InvalidRequest {
            reason: "campaign-snapshot-has-no-frontier-index"
        })
    ));
}

#[test]
fn authority_adapters_bind_canonical_messages_without_prevalidation_writes() {
    let shared = [41; 32];
    assert!(matches!(
        CampaignRepository::with_component_authorities(
            Arc::new(MemoryBlobBackend::new("equal-authority", 1024)),
            Arc::new(MemoryRefBackend::new()),
            PlannerAuthorityKey::from_bytes(shared).expect("shared planner authority"),
            DebuggerAuthorityKey::from_bytes(shared).expect("shared debugger authority"),
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "component-authority-keys-must-be-distinct"
        })
    ));
    let (repository, lineage, policy, blobs, planner_key, debugger_key) = authorized_fixture();
    assert!(PlannerAuthorityKey::from_bytes([0; 32]).is_err());
    assert!(DebuggerAuthorityKey::from_bytes([0; 32]).is_err());

    let debugger_genesis = repository
        .create("debugger-authority", &lineage, &policy, &BTreeMap::new())
        .expect("create debugger campaign");
    let operator_request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "debugger-authority",
    );
    let session = DebugSessionId::from_hash(CampaignHash::derive(
        "test-debug-session",
        b"debugger-authority",
    ));
    let debugger_request = BranchRequest::new(
        operator_request.branch_point(),
        operator_request.parent(),
        operator_request.opportunity(),
        operator_request.domain(),
        operator_request.source().clone(),
        BranchRequestCause::Debugger(session),
        operator_request.budget(),
        operator_request.stop().clone(),
    )
    .expect("debugger request");
    assert!(matches!(
        repository.submit_operator_branch_request(
            "debugger-authority",
            debugger_genesis.snapshot_id(),
            &debugger_request,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "branch-request-cause-requires-authority-specific-adapter"
        })
    ));
    let discovered = repository
        .discover_choice_opportunity(
            "debugger-authority",
            debugger_genesis.snapshot_id(),
            debugger_request.parent(),
            debugger_request.opportunity(),
        )
        .expect("discover debugger choice");

    let wrong_debugger_key =
        DebuggerAuthorityKey::from_bytes([29; 32]).expect("wrong debugger key");
    let wrong_debugger = DebuggerSubmission::authorize(
        &wrong_debugger_key,
        discovered.new_snapshot,
        session,
        debugger_request.clone(),
    )
    .expect("wrong debugger submission");
    let objects_before_debugger_rejection = blobs
        .object_count()
        .expect("debugger objects before rejection");
    assert!(matches!(
        repository.submit_debugger_branch_request("debugger-authority", &wrong_debugger),
        Err(CampaignRepositoryError::Integrity {
            reason: "debugger-submission-authentication-failed"
        })
    ));
    assert_eq!(
        blobs
            .object_count()
            .expect("debugger objects after rejection"),
        objects_before_debugger_rejection
    );

    // Keep the aggregate-only ledger vector fixed while also exercising the
    // current indexed ledger. Only the expected snapshot identity differs.
    let legacy_ledger = crate::CampaignBudgetLedger::empty()
        .id()
        .expect("legacy ledger id");
    let legacy_genesis = CampaignSnapshot::genesis(
        debugger_genesis.snapshot().lineage(),
        debugger_genesis.snapshot().active_policy(),
        legacy_genesis_roots(&repository, debugger_genesis.snapshot().roots()),
    )
    .expect("legacy genesis")
    .with_budget_ledger(legacy_ledger);
    let discovered_snapshot = repository
        .head("debugger-authority")
        .expect("discovered head");
    let legacy_discovered = CampaignSnapshot::successor(
        legacy_genesis.id().expect("legacy genesis"),
        discovered_snapshot.snapshot().lineage(),
        discovered_snapshot.snapshot().active_policy(),
        legacy_genesis_roots(&repository, discovered_snapshot.snapshot().roots()),
        discovered_snapshot
            .snapshot()
            .transition()
            .expect("discovery fact"),
    )
    .expect("legacy discovery")
    .with_budget_ledger(legacy_ledger);
    let legacy_debugger = DebuggerSubmission::authorize(
        &debugger_key,
        legacy_discovered.id().expect("legacy discovery id"),
        session,
        debugger_request.clone(),
    )
    .expect("legacy debugger submission");
    assert_eq!(
        CampaignHash::derive(
            "crucible.test.debugger-submission-vector.v1",
            &legacy_debugger.canonical_bytes()
        )
        .to_hex(),
        "ff56dbf506193292e161684db60ddcf38ad7883ea8f7b21e3d23321356d4f602"
    );
    assert!(
        DebuggerSubmission::from_canonical_bytes(&legacy_debugger.canonical_bytes())
            .expect("legacy debugger round trip")
            .verify(&debugger_key)
    );

    let debugger_submission = DebuggerSubmission::authorize(
        &debugger_key,
        discovered.new_snapshot,
        session,
        debugger_request,
    )
    .expect("authorize debugger submission");
    let debugger_bytes = debugger_submission.canonical_bytes();
    assert_eq!(
        CampaignHash::derive(
            "crucible.test.debugger-submission-vector.v1",
            &debugger_bytes,
        )
        .to_hex(),
        // Version-3 snapshots now bind the version-2 indexed budget ledger.
        "59dbaca9d6bf8a2cb838a0baccd7a956f54872d997c97b9a9f03441299d1d31e",
    );
    let decoded_debugger =
        DebuggerSubmission::from_canonical_bytes(&debugger_bytes).expect("decode debugger");
    assert_eq!(decoded_debugger, debugger_submission);
    assert!(decoded_debugger.verify(&debugger_key));
    assert!(!decoded_debugger.verify(&wrong_debugger_key));
    let mut tampered_debugger_bytes = debugger_bytes;
    let last = tampered_debugger_bytes
        .last_mut()
        .expect("debugger submission has an authentication tag");
    *last ^= 1;
    let tampered_debugger = DebuggerSubmission::from_canonical_bytes(&tampered_debugger_bytes)
        .expect("tampered tag remains structurally canonical");
    assert!(!tampered_debugger.verify(&debugger_key));
    let accepted_debugger = repository
        .submit_debugger_branch_request("debugger-authority", &decoded_debugger)
        .expect("accept debugger submission");
    assert_eq!(accepted_debugger.prior_snapshot, discovered.new_snapshot);

    let planner_genesis = repository
        .create("planner-authority", &lineage, &policy, &BTreeMap::new())
        .expect("create planner campaign");
    let engine = PlannerEngine::new("closed-rust", 1, 1, BTreeSet::new()).expect("planner engine");
    let initial_state = PlannerState::new(
        engine.id().expect("engine id"),
        "closed-rust-state",
        1,
        vec![0],
    )
    .expect("initial state");
    let (engine, artifact, invocation) = planner_basis(
        &repository,
        "planner-authority",
        planner_genesis.snapshot_id(),
        initial_state.clone(),
    );
    let planner_request = PlannerRequest::new(
        planner_genesis.snapshot_id(),
        invocation.clone(),
        engine.clone(),
        artifact,
        policy.clone(),
        initial_state,
        repository
            .head("planner-authority")
            .expect("planner head")
            .snapshot()
            .planning_view(),
        CampaignPlanningBundle::new(Vec::new()).expect("empty planner bundle"),
    )
    .expect("planner request");
    let next_state = PlannerState::new(
        engine.id().expect("engine id"),
        "closed-rust-state",
        1,
        vec![1],
    )
    .expect("next state");
    let proposal = no_work_proposal(invocation.id().expect("invocation id"), next_state);
    let measured = PlanningUsage {
        branch_requests: 0,
        proposals: 0,
        input_objects: 0,
        input_bytes: 0,
        fuel: 5,
    };
    let wrong_planner_key = PlannerAuthorityKey::from_bytes([31; 32]).expect("wrong planner key");
    let wrong_planner = PlannerSubmission::authorize(
        &wrong_planner_key,
        planner_genesis.snapshot_id(),
        proposal.clone(),
        measured,
    )
    .expect("wrong planner submission");
    let wrong_response =
        PlannerResponse::authorize(&wrong_planner_key, &planner_request, wrong_planner)
            .expect("wrong planner response");
    let objects_before_planner_rejection = blobs
        .object_count()
        .expect("planner objects before rejection");
    assert!(matches!(
        repository.accept_planner_response("planner-authority", &planner_request, &wrong_response,),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-response-authentication-failed"
        })
    ));
    assert_eq!(
        blobs
            .object_count()
            .expect("planner objects after rejection"),
        objects_before_planner_rejection
    );
    assert_eq!(
        repository
            .head("planner-authority")
            .expect("unchanged planner head")
            .snapshot_id(),
        planner_genesis.snapshot_id()
    );

    let planner_submission = PlannerSubmission::authorize(
        &planner_key,
        planner_genesis.snapshot_id(),
        proposal.clone(),
        measured,
    )
    .expect("authorize planner submission");
    let legacy_invocation = PlannerInvocation::new(
        invocation.engine(),
        invocation.policy_artifact(),
        invocation.policy(),
        invocation.planner_state(),
        legacy_genesis.planning_view().id().expect("legacy view"),
        invocation.scan_page().clone(),
        invocation.budget(),
    )
    .expect("legacy invocation");
    let legacy_proposal = no_work_proposal(
        legacy_invocation.id().expect("legacy invocation id"),
        proposal.next_state().clone(),
    );
    let legacy_planner = PlannerSubmission::authorize(
        &planner_key,
        legacy_genesis.id().expect("legacy genesis id"),
        legacy_proposal,
        measured,
    )
    .expect("legacy planner submission");
    assert_eq!(
        CampaignHash::derive(
            "crucible.test.planner-submission-vector.v1",
            &legacy_planner.canonical_bytes()
        )
        .to_hex(),
        "5d2c533e0a67e19ddc66637e1f31233a4a1c8ff590921cef505e5e67716b3dd4"
    );
    assert!(
        PlannerSubmission::from_canonical_bytes(&legacy_planner.canonical_bytes())
            .expect("legacy planner round trip")
            .verify(&planner_key)
    );
    let planner_bytes = planner_submission.canonical_bytes();
    assert_eq!(
        CampaignHash::derive("crucible.test.planner-submission-vector.v1", &planner_bytes,)
            .to_hex(),
        // Version-3 snapshots bind the version-2 indexed budget ledger.
        "dd196823708be6c68bbb314183a01eec963c098061c9cf8ea2fa128c6ccf0da5",
    );
    let decoded_planner =
        PlannerSubmission::from_canonical_bytes(&planner_bytes).expect("decode planner");
    assert_eq!(decoded_planner, planner_submission);
    assert!(decoded_planner.verify(&planner_key));
    assert!(!decoded_planner.verify(&wrong_planner_key));
    let planner_response =
        PlannerResponse::authorize(&planner_key, &planner_request, decoded_planner)
            .expect("planner response");
    let different_request = PlannerRequest::new(
        CampaignSnapshotId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignSnapshot,
            2,
            b"different planner request snapshot",
        ))
        .expect("different snapshot"),
        planner_request.invocation().clone(),
        planner_request.engine().clone(),
        planner_request.policy_artifact().clone(),
        planner_request.policy().clone(),
        planner_request.planner_state().clone(),
        *planner_request.input_view(),
        planner_request.input_bundle().clone(),
    )
    .expect("different planner request");
    let objects_before_request_mismatch = blobs
        .object_count()
        .expect("objects before planner request mismatch");
    assert!(matches!(
        repository.accept_planner_response(
            "planner-authority",
            &different_request,
            &planner_response,
        ),
        Err(CampaignRepositoryError::Codec(
            CampaignCodecError::InvalidValue {
                reason: "planner response request digest mismatch"
            }
        ))
    ));
    assert_eq!(
        blobs
            .object_count()
            .expect("objects after planner request mismatch"),
        objects_before_request_mismatch
    );
    let accepted_planner = repository
        .accept_planner_response("planner-authority", &planner_request, &planner_response)
        .expect("accept planner submission");
    assert_eq!(
        accepted_planner.prior_snapshot,
        planner_genesis.snapshot_id()
    );
    let accepted_step = repository
        .load_planner_step_at(accepted_planner.new_snapshot, accepted_planner.step)
        .expect("accepted request-bound step");
    assert_eq!(
        accepted_step.request_digest(),
        planner_request.request_digest()
    );
    assert_eq!(
        repository
            .load_planner_request(accepted_step.request())
            .expect("retained planner request"),
        planner_request
    );
    assert!(matches!(
        repository.load_planner_step(accepted_planner.step),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-step-requires-snapshot-owner"
        })
    ));

    let replay_request = PlannerRequest::new(
        accepted_planner.new_snapshot,
        planner_request.invocation().clone(),
        planner_request.engine().clone(),
        planner_request.policy_artifact().clone(),
        planner_request.policy().clone(),
        planner_request.planner_state().clone(),
        *planner_request.input_view(),
        planner_request.input_bundle().clone(),
    )
    .expect("byte-distinct valid replay request");
    let replay_submission = PlannerSubmission::authorize(
        &planner_key,
        accepted_planner.new_snapshot,
        proposal,
        measured,
    )
    .expect("authorize replay submission");
    let replay_response =
        PlannerResponse::authorize(&planner_key, &replay_request, replay_submission)
            .expect("authorize replay response");
    let objects_before_replay_conflict = blobs.object_count().expect("objects before conflict");
    assert!(matches!(
        repository.accept_planner_response("planner-authority", &replay_request, &replay_response,),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-invocation-result-conflict"
        })
    ));
    assert_eq!(
        blobs.object_count().expect("objects after conflict"),
        objects_before_replay_conflict
    );
    assert_eq!(
        repository
            .head("planner-authority")
            .expect("head after replay conflict")
            .snapshot_id(),
        accepted_planner.new_snapshot
    );

    let forged_step = PlannerStep::new(
        None,
        accepted_step.invocation(),
        accepted_step.request(),
        accepted_step.request_digest(),
        accepted_step.policy(),
        accepted_step.engine(),
        accepted_step.policy_artifact(),
        accepted_step.input_view(),
        PlannerDisposition::NoWork,
        accepted_step.next_state(),
        accepted_step.usage_claim(),
        accepted_step.accounting(),
        accepted_step.evidence().clone(),
    )
    .expect("forged wrong-parent-request step");
    let forged_step_content = repository
        .put_planner_step(&forged_step)
        .expect("put forged planner step");
    let forged_fact = repository
        .put_fact(&CampaignFact::PlannerAdvanced(
            PlannerStepId::from_content_id(forged_step_content).expect("forged step id"),
        ))
        .expect("put forged planner fact");
    let accepted_snapshot = repository
        .read_snapshot(accepted_planner.new_snapshot.content_id())
        .expect("accepted snapshot");
    let forged_snapshot = CampaignSnapshot::successor(
        accepted_planner.new_snapshot,
        accepted_snapshot.snapshot.lineage(),
        accepted_snapshot.snapshot.active_policy(),
        accepted_snapshot.snapshot.roots(),
        CampaignFactId::from_content_id(forged_fact).expect("forged fact id"),
    )
    .expect("forged successor");
    let forged_content = repository
        .put_snapshot(&forged_snapshot)
        .expect("put forged successor");
    let forged_validation = repository.validate_complete_head(forged_content);
    assert!(
        matches!(
            forged_validation,
            Err(CampaignRepositoryError::Integrity {
                reason: "planner-step-transition-request-snapshot-mismatch"
            })
        ),
        "unexpected forged successor result: {forged_validation:?}"
    );
}

#[test]
fn branch_request_is_one_lazy_exact_indexed_delta_and_replays() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("lazy", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "retry-choice",
    );

    let discovered = repository
        .discover_choice_opportunity(
            "lazy",
            genesis.snapshot_id(),
            request.parent(),
            request.opportunity(),
        )
        .expect("discover request opportunity");
    let accepted = repository
        .submit_branch_request("lazy", discovered.new_snapshot, &request)
        .expect("submit request");
    assert!(!accepted.replayed);
    assert_eq!(accepted.prior_snapshot, discovered.new_snapshot);
    assert_eq!(accepted.request, request.id().expect("request id"));
    assert_eq!(
        accepted.summary.validated_cardinality(),
        BranchAcceptanceCount::Exact(2)
    );
    assert_eq!(
        accepted.summary.deduplicated_existing_edges(),
        BranchAcceptanceCount::Exact(0)
    );
    assert_eq!(
        accepted.summary.remaining_lazy_candidates(),
        BranchAcceptanceCount::Exact(2)
    );
    assert_eq!(accepted.summary.maximum_proposals(), 2);
    assert_eq!(accepted.summary.maximum_attempts(), 2);
    assert!(accepted.summary_recorded);
    assert_eq!(
        accepted.acceptance_fact,
        CampaignFact::BranchRequestAccepted {
            request: accepted.request,
            summary: accepted.summary,
        }
    );
    assert_eq!(
        accepted.snapshot.transition(),
        Some(
            CampaignFactId::from_content_id(
                accepted
                    .acceptance_fact
                    .id()
                    .expect("acceptance fact ID")
                    .content_id()
            )
            .expect("acceptance transition ID")
        )
    );

    let requested = repository.head("lazy").expect("requested head");
    let prior_roots = repository
        .read_snapshot(discovered.new_snapshot.content_id())
        .expect("discovery snapshot")
        .snapshot
        .roots();
    let next_roots = requested.snapshot().roots();
    assert_eq!(prior_roots.graph, next_roots.graph);
    assert_eq!(prior_roots.observations, next_roots.observations);
    assert_eq!(prior_roots.corpus, next_roots.corpus);
    assert_eq!(prior_roots.coverage, next_roots.coverage);
    assert_eq!(prior_roots.findings, next_roots.findings);
    assert_eq!(prior_roots.pins, next_roots.pins);
    assert_ne!(prior_roots.accounting, next_roots.accounting);
    let BranchRequestCause::Operator(command_id) = request.cause() else {
        panic!("operator request")
    };
    assert_eq!(
        repository
            .merkle
            .get(
                next_roots.accounting,
                map_key_hash("accounting.command", command_id.as_hash()),
            )
            .expect("command index"),
        requested
            .snapshot()
            .transition()
            .map(CampaignFactId::content_id)
    );
    assert_ne!(prior_roots.exploration, next_roots.exploration);
    let entries = repository
        .merkle
        .verify_closure_objects(next_roots.exploration)
        .expect("exploration closure");
    let frontier_index = repository
        .merkle
        .get(next_roots.exploration, frontier_index_anchor_key())
        .expect("frontier anchor lookup")
        .expect("frontier index");
    let branch_request_index = repository
        .merkle
        .get(next_roots.exploration, branch_request_index_anchor_key())
        .expect("branch-request anchor lookup")
        .expect("branch-request index");
    let scan_index = repository
        .merkle
        .get(next_roots.exploration, planner_scan_index_anchor_key())
        .expect("scan index lookup")
        .expect("scan index");
    assert_eq!(
        entries.values,
        BTreeSet::from([
            accepted.request.content_id(),
            frontier_index,
            branch_request_index,
            scan_index,
        ])
    );

    let resume = command(
        "resume-after-request",
        accepted.new_snapshot,
        CampaignControlAction::Resume,
    );
    repository.apply_control("lazy", &resume).expect("resume");
    let replay = repository
        .submit_known_branch_request("lazy", genesis.snapshot_id(), &request)
        .expect("replay request");
    assert!(replay.replayed);
    assert_eq!(replay.prior_snapshot, accepted.prior_snapshot);
    assert_eq!(replay.new_snapshot, accepted.new_snapshot);
    assert_eq!(replay.summary, accepted.summary);
    assert_eq!(replay.snapshot, accepted.snapshot);
    assert_eq!(replay.acceptance_fact, accepted.acceptance_fact);
    assert!(replay.summary_recorded);

    let service = crate::RepositoryCampaignService::new(&repository, PermitAlice);
    let client = crate::CampaignClient::new(service);
    let service_replay = client
        .submit_branch_request(
            &crate::SubmitCampaignBranchRequest::new(
                crate::CampaignPrincipal::new("operator:alice").expect("principal"),
                crate::CampaignName::new("lazy").expect("campaign name"),
                genesis.snapshot_id(),
                request.clone(),
            )
            .expect("service branch request"),
        )
        .expect("service replay");
    assert!(service_replay.replayed());
    assert_eq!(service_replay.prior_snapshot(), accepted.prior_snapshot);
    assert_eq!(service_replay.new_snapshot(), accepted.new_snapshot);

    let reused_command = BranchRequest::new(
        request.branch_point(),
        request.parent(),
        request.opportunity(),
        request.domain(),
        CandidateSource::finite(BTreeSet::from([ChoiceValue::Boolean(true)]))
            .expect("changed finite source"),
        request.cause(),
        BranchBudget::new(1, 1).expect("changed budget"),
        StopCondition::Terminal,
    )
    .expect("changed request");
    let current = repository.head("lazy").expect("current head");
    assert!(matches!(
        repository.submit_known_branch_request("lazy", current.snapshot_id(), &reused_command),
        Err(CampaignRepositoryError::CommandReuse)
    ));

    let BranchRequestCause::Operator(command_id) = request.cause() else {
        panic!("operator request")
    };
    let reused_control = ControlRequest {
        command: command_id,
        expected_snapshot: current.snapshot_id(),
        action: CampaignControlAction::Complete,
    };
    assert!(matches!(
        repository.apply_control("lazy", &reused_control),
        Err(CampaignRepositoryError::CommandReuse)
    ));
}

#[test]
fn legacy_branch_request_replay_uses_its_original_graph_and_transition() {
    let campaign = "legacy-branch-replay";
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create_funded(campaign, &lineage, &policy, &BTreeMap::new())
        .expect("create funded campaign");
    let request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        campaign,
    );
    let discovered = repository
        .discover_choice_opportunity(
            campaign,
            genesis.snapshot_id(),
            request.parent(),
            request.opportunity(),
        )
        .expect("discover request opportunity");
    let accepted = repository
        .submit_branch_request(campaign, discovered.new_snapshot, &request)
        .expect("accept branch request");

    let legacy_fact = CampaignFact::BranchRequestIssued(accepted.request);
    let legacy_fact_content = repository
        .put_fact(&legacy_fact)
        .expect("publish legacy acceptance fact");
    let BranchRequestCause::Operator(command) = request.cause() else {
        panic!("operator request")
    };
    let mut legacy_roots = accepted.snapshot.roots();
    legacy_roots.accounting = repository
        .merkle
        .insert(
            legacy_roots.accounting,
            map_key_hash("accounting.command", command.as_hash()),
            legacy_fact_content,
        )
        .expect("replace acceptance command index")
        .content_id();
    let legacy_snapshot = CampaignSnapshot::successor(
        accepted.prior_snapshot,
        accepted.snapshot.lineage(),
        accepted.snapshot.active_policy(),
        legacy_roots,
        CampaignFactId::from_content_id(legacy_fact_content).expect("legacy acceptance fact ID"),
    )
    .expect("build legacy acceptance snapshot")
    .with_budget_ledger(
        accepted
            .snapshot
            .budget_ledger()
            .expect("accepted snapshot budget ledger"),
    );
    let legacy_snapshot_content = repository
        .put_snapshot(&legacy_snapshot)
        .expect("publish legacy acceptance snapshot");
    let legacy_snapshot_id =
        CampaignSnapshotId::from_content_id(legacy_snapshot_content).expect("legacy snapshot ID");

    repository
        .validated_heads
        .lock()
        .expect("validated-head cache")
        .clear();
    repository
        .validate_complete_head(legacy_snapshot_content)
        .expect("validate cold legacy acceptance");
    assert!(matches!(
        repository
            .refs
            .compare_exchange(
                &campaign_ref(campaign).expect("campaign ref"),
                Some(accepted.new_snapshot.content_id()),
                legacy_snapshot_content,
            )
            .expect("install legacy acceptance head"),
        RefCasOutcome::Advanced { .. }
    ));

    let proposal = finite_proposal(
        &request,
        &policy,
        &repository.head(campaign).expect("legacy head"),
        ChoiceValue::Boolean(false),
        1,
    );
    let proposed = repository
        .issue_proposal(campaign, legacy_snapshot_id, &proposal)
        .expect("issue proposal after legacy acceptance");
    let (selection, path, attempt) = branch_attempt(&repository, &request, &proposal);
    let admitted = repository
        .admit_proposal(
            campaign,
            proposed.new_snapshot,
            proposed.proposal,
            &selection,
            &path,
            &attempt,
        )
        .expect("admit proposal after legacy acceptance");
    let child = ConfigurationId::from_hash(CampaignHash::derive(
        "test.legacy-branch-replay.child",
        campaign.as_bytes(),
    ));
    let child_content = repository
        .publish_configuration_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            child,
            1,
            b"legacy replay child".to_vec(),
        )
        .expect("publish observed child");
    let measurements = repository
        .publish_measurement_set(&MeasurementSet::new(BTreeMap::new()).expect("measurements"))
        .expect("publish measurements");
    let properties = repository
        .publish_property_verdict_set(
            &PropertyVerdictSet::new(BTreeMap::new()).expect("properties"),
        )
        .expect("publish properties");
    let coverage = repository
        .publish_coverage_projection(
            &CoverageProjection::new(BTreeSet::new(), BTreeSet::new()).expect("coverage"),
        )
        .expect("publish coverage");
    let prior_opportunity = repository
        .load_choice_opportunity(request.opportunity())
        .expect("load prior opportunity");
    let declaration = repository
        .load_selectable(prior_opportunity.declaration())
        .expect("load selectable declaration");
    let domain = repository
        .load_choice_domain(prior_opportunity.domain())
        .expect("load choice domain");
    let child_opportunity = ChoiceOpportunity::new(
        lineage.scenario(),
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: CampaignHash::derive(
                "test.legacy-branch-replay.scheduler",
                campaign.as_bytes(),
            ),
            producer: CampaignHash::derive(
                "test.legacy-branch-replay.producer",
                campaign.as_bytes(),
            ),
        },
        "legacy-replay-child-choice",
        None,
    )
    .expect("child choice opportunity");
    let child_opportunity_id = child_opportunity.id().expect("child opportunity ID");
    repository
        .publish_choice_opportunity(&child_opportunity)
        .expect("publish child choice opportunity");
    let observation = Observation::new(
        admitted.attempt,
        child,
        child_content,
        path.id().expect("path ID"),
        StopOutcome::Reached(StopCondition::NextChoice),
        measurements,
        properties,
        coverage,
        BTreeSet::from([child_opportunity_id]),
    )
    .expect("observation");
    let observed = repository
        .publish_observation(campaign, admitted.new_snapshot, &observation)
        .expect("publish observation after legacy acceptance");
    let current_summary = repository
        .branch_acceptance_summary(
            repository
                .head(campaign)
                .expect("observed head")
                .snapshot()
                .roots()
                .graph,
            &request,
        )
        .expect("summarize against later graph");
    assert_ne!(current_summary, accepted.summary);

    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    let replay = restarted
        .submit_branch_request(campaign, discovered.new_snapshot, &request)
        .expect("replay legacy acceptance after graph change");
    assert!(replay.replayed);
    assert!(!replay.summary_recorded);
    assert_eq!(replay.prior_snapshot, discovered.new_snapshot);
    assert_eq!(replay.new_snapshot, legacy_snapshot_id);
    assert_eq!(replay.snapshot, legacy_snapshot);
    assert_eq!(replay.acceptance_fact, legacy_fact);
    assert_eq!(replay.summary, accepted.summary);
    assert_eq!(
        restarted
            .head(campaign)
            .expect("current head")
            .snapshot_id(),
        observed.new_snapshot
    );
}

#[test]
fn ten_thousand_mixed_mutations_use_incremental_validation_and_replay_indexes() {
    const MUTATIONS: u64 = 10_000;

    let (repository, lineage, policy, _) = fixture_with_quota(512 * 1024 * 1024);
    let genesis = repository
        .create("branch-scale", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let template = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "branch-scale-template",
    );
    let mut snapshot = genesis.snapshot_id();
    let mut first_request = None;
    let mut first_request_result = None;
    let mut first_control = None;
    let mut first_control_result = None;
    for ordinal in 0..MUTATIONS {
        if ordinal % 2 == 0 {
            let request = BranchRequest::new(
                template.branch_point(),
                template.parent(),
                template.opportunity(),
                template.domain(),
                template.source().clone(),
                BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(
                    CampaignHash::derive("test.branch-scale", &ordinal.to_be_bytes()),
                )),
                template.budget(),
                template.stop().clone(),
            )
            .expect("scaled request");
            let result = repository
                .submit_known_branch_request("branch-scale", snapshot, &request)
                .expect("submit scaled request");
            if first_request.is_none() {
                first_request = Some(request.clone());
                first_request_result = Some(result.clone());
            }
            snapshot = result.new_snapshot;
        } else {
            let control_ordinal = ordinal / 2;
            let action = if control_ordinal % 2 == 0 {
                CampaignControlAction::Resume
            } else {
                CampaignControlAction::Pause(crate::ActiveAttemptPolicy::Drain)
            };
            let request = ControlRequest {
                command: crate::CampaignCommandId::from_hash(CampaignHash::derive(
                    "test.control-scale",
                    &ordinal.to_be_bytes(),
                )),
                expected_snapshot: snapshot,
                action,
            };
            let result = repository
                .apply_control("branch-scale", &request)
                .expect("apply scaled control");
            if first_control.is_none() {
                first_control = Some(request.clone());
                first_control_result = Some(result.clone());
            }
            snapshot = result.new_snapshot;
        }
    }

    let head = repository.head("branch-scale").expect("scaled head");
    assert_eq!(head.snapshot_id(), snapshot);
    assert_eq!(
        repository
            .merkle
            .inspect_shallow(head.snapshot().roots().exploration)
            .expect("scaled exploration root")
            .entry_count(),
        // Permanent entries anchor frontier, feedback-request, and scan indexes.
        (MUTATIONS / 2) + 3
    );
    assert_eq!(
        repository
            .merkle
            .inspect_shallow(head.snapshot().roots().accounting)
            .expect("scaled accounting root")
            .entry_count(),
        MUTATIONS
    );
    assert_eq!(
        repository
            .merkle
            .inspect_shallow(head.snapshot().roots().coordination)
            .expect("scaled coordination root")
            .entry_count(),
        MUTATIONS
    );
    assert_eq!(
        repository
            .validated_heads
            .lock()
            .expect("validation checkpoints")
            .len(),
        1
    );
    assert_eq!(
        repository.state("branch-scale").expect("scaled state"),
        CampaignState::Paused
    );

    let first_request = first_request.expect("first request");
    let expected_request = first_request_result.expect("first request result");
    let replayed_request = repository
        .submit_known_branch_request("branch-scale", genesis.snapshot_id(), &first_request)
        .expect("deep request replay");
    assert!(replayed_request.replayed);
    assert_eq!(replayed_request.new_snapshot, expected_request.new_snapshot);

    let first_control = first_control.expect("first control");
    let expected_control = first_control_result.expect("first control result");
    let replayed_control = repository
        .apply_control("branch-scale", &first_control)
        .expect("deep control replay");
    assert!(replayed_control.replayed);
    assert_eq!(replayed_control.new_snapshot, expected_control.new_snapshot);
}

#[test]
fn discarded_validation_checkpoints_rebuild_from_the_immutable_head() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("checkpoint-rebuild", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "checkpoint-rebuild",
    );
    let requested = repository
        .submit_known_branch_request("checkpoint-rebuild", genesis.snapshot_id(), &request)
        .expect("submit request");

    repository
        .validated_heads
        .lock()
        .expect("validation checkpoints")
        .clear();
    let loaded = repository.head("checkpoint-rebuild").expect("rebuild head");

    assert_eq!(loaded.snapshot_id(), requested.new_snapshot);
    {
        let checkpoints = repository
            .validated_heads
            .lock()
            .expect("rebuilt validation checkpoints");
        assert_eq!(checkpoints.len(), 1);
        assert!(checkpoints.contains_key(&requested.new_snapshot.content_id()));
    }

    // Eviction may race between an initial head validation and a later
    // lifecycle/transaction lookup. Absence is a cache miss, not an
    // integrity failure, so the immutable head is revalidated on demand.
    repository
        .validated_heads
        .lock()
        .expect("validation checkpoints")
        .clear();
    assert_eq!(
        repository
            .current_lifecycle(requested.new_snapshot.content_id())
            .expect("rebuild lifecycle after eviction")
            .visible,
        CampaignState::Created
    );
}

#[test]
fn local_successors_enforce_the_restart_ancestry_limit() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("ancestry-limit", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    repository
        .validated_heads
        .lock()
        .expect("validation checkpoints")
        .get_mut(&genesis.content_id())
        .expect("genesis checkpoint")
        .ancestry_depth = MAX_SNAPSHOT_ANCESTRY;
    let request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "ancestry-limit",
    );

    assert!(matches!(
        repository.submit_known_branch_request("ancestry-limit", genesis.snapshot_id(), &request),
        Err(CampaignRepositoryError::Integrity {
            reason: "snapshot-ancestry-limit"
        })
    ));
    assert_eq!(
        repository
            .head("ancestry-limit")
            .expect("unchanged head")
            .snapshot_id(),
        genesis.snapshot_id()
    );
}

#[test]
fn conservative_closure_limit_rebases_through_complete_validation() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("closure-rebase", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "closure-rebase",
    );
    let discovered = repository
        .discover_choice_opportunity(
            "closure-rebase",
            genesis.snapshot_id(),
            request.parent(),
            request.opportunity(),
        )
        .expect("discover closure-rebase opportunity");
    repository
        .validated_heads
        .lock()
        .expect("validation checkpoints")
        .get_mut(&discovered.new_snapshot.content_id())
        .expect("discovery checkpoint")
        .closure_objects = MAX_CAMPAIGN_CLOSURE_OBJECTS - MAX_SIMPLE_SUCCESSOR_GROWTH - 1;

    let accepted = repository
        .submit_branch_request("closure-rebase", discovered.new_snapshot, &request)
        .expect("full-validation rebase");
    let checkpoints = repository
        .validated_heads
        .lock()
        .expect("validation checkpoints");
    assert_eq!(checkpoints.len(), 1);
    let checkpoint = checkpoints
        .get(&accepted.new_snapshot.content_id())
        .expect("rebased child checkpoint");
    assert_eq!(checkpoint.ancestry_depth, 3);
    assert!(checkpoint.closure_objects < MAX_CAMPAIGN_CLOSURE_OBJECTS);
}

#[test]
fn reused_active_policy_generator_is_an_incremental_closure_anchor() {
    const GENERATOR_DEPTH: u32 = 256;

    let (repository, lineage, _) = fixture();
    let leaf =
        CandidateGeneratorSpec::new(1, CandidateGeneratorAlgorithm::All).expect("leaf generator");
    let mut generator = leaf.id().expect("leaf generator id");
    let mut generators = BTreeMap::from([(generator, leaf)]);
    for ordinal in 2..=GENERATOR_DEPTH {
        let parent = CandidateGeneratorSpec::new(
            ordinal,
            CandidateGeneratorAlgorithm::OrderedMixture {
                components: vec![
                    WeightedGenerator::new(generator, 1).expect("generator component"),
                ],
            },
        )
        .expect("parent generator");
        generator = parent.id().expect("parent generator id");
        generators.insert(generator, parent);
    }
    let policy = policy_with_generator(lineage.scenario(), generator);
    let genesis = repository
        .create("generator-anchor", &lineage, &policy, &generators)
        .expect("create generator campaign");
    let template = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "generator-anchor-template",
    );
    let request = BranchRequest::new(
        template.branch_point(),
        template.parent(),
        template.opportunity(),
        template.domain(),
        CandidateSource::generated(generator),
        BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(CampaignHash::derive(
            "test",
            b"generator-anchor",
        ))),
        template.budget(),
        template.stop().clone(),
    )
    .expect("generated request");

    let discovered = repository
        .discover_choice_opportunity(
            "generator-anchor",
            genesis.snapshot_id(),
            request.parent(),
            request.opportunity(),
        )
        .expect("discover generator request opportunity");
    repository
        .validated_heads
        .lock()
        .expect("validation checkpoints")
        .get_mut(&discovered.new_snapshot.content_id())
        .expect("discovery checkpoint")
        .closure_objects = MAX_CAMPAIGN_CLOSURE_OBJECTS - MAX_SIMPLE_SUCCESSOR_GROWTH
        // Three nested scan-index paths and its exploration anchor are new.
        - (4 * MERKLE_UPDATE_NODE_UPPER) - 32;
    let accepted = repository
        .submit_branch_request("generator-anchor", discovered.new_snapshot, &request)
        .expect("accept anchored generator request");
    let checkpoints = repository
        .validated_heads
        .lock()
        .expect("validation checkpoints");
    let checkpoint = checkpoints
        .get(&accepted.new_snapshot.content_id())
        .expect("incremental child checkpoint");

    assert!(
        checkpoint.closure_objects > MAX_CAMPAIGN_CLOSURE_OBJECTS / 2,
        "reused generator closure forced an unnecessary complete rebase"
    );
}

#[test]
fn imported_successor_must_carry_the_exact_parent_result_locator() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("result-locator", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let first_request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "result-locator-first",
    );
    let first = repository
        .submit_known_branch_request("result-locator", genesis.snapshot_id(), &first_request)
        .expect("first request");
    let second_request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "result-locator-second",
    );
    let second = repository
        .submit_known_branch_request("result-locator", first.new_snapshot, &second_request)
        .expect("second request");
    let third_request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "result-locator-third",
    );
    let third = repository
        .submit_known_branch_request("result-locator", second.new_snapshot, &third_request)
        .expect("third request");

    let parent = repository
        .read_snapshot(third.prior_snapshot.content_id())
        .expect("parent snapshot");
    let valid = repository
        .read_snapshot(third.new_snapshot.content_id())
        .expect("valid child snapshot");
    let mut roots = valid.snapshot.roots();
    roots.coordination = parent.snapshot.roots().coordination;
    let forged = CampaignSnapshot::successor(
        third.prior_snapshot,
        valid.snapshot.lineage(),
        valid.snapshot.active_policy(),
        roots,
        valid.snapshot.transition().expect("child transition"),
    )
    .expect("forged child");
    let forged_content = repository.put_snapshot(&forged).expect("put forged child");

    match repository.validate_complete_head(forged_content) {
        Err(CampaignRepositoryError::Integrity { reason }) => assert_eq!(
            reason,
            "branch-request-transition-coordination-root-mismatch"
        ),
        other => panic!("unexpected forged-result-locator validation: {other:?}"),
    }
}

#[test]
fn conflicted_successors_are_never_promoted_as_validated_heads() {
    let (fixture_repository, lineage, policy, blobs) = counted_fixture();
    drop(fixture_repository);
    let refs = Arc::new(ConflictAfterCreateRefBackend::new());
    let repository = CampaignRepository::new(blobs, refs.clone());
    let genesis = repository
        .create("checkpoint-conflict", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "checkpoint-conflict",
    );
    refs.arm();

    assert!(matches!(
        repository.submit_known_branch_request(
            "checkpoint-conflict",
            genesis.snapshot_id(),
            &request,
        ),
        Err(CampaignRepositoryError::RefConflict { .. })
    ));
    let checkpoints = repository
        .validated_heads
        .lock()
        .expect("validation checkpoints");
    assert_eq!(checkpoints.len(), 1);
    assert!(checkpoints.contains_key(&genesis.content_id()));
}

#[test]
fn finite_proposal_is_an_exact_indexed_delta_and_replays_before_staleness() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create_funded("finite-proposal", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "finite-proposal",
    );
    let requested = repository
        .submit_known_branch_request("finite-proposal", genesis.snapshot_id(), &request)
        .expect("submit request");
    let request_head = repository.head("finite-proposal").expect("request head");

    let wrong_order = finite_proposal(
        &request,
        &policy,
        &request_head,
        ChoiceValue::Boolean(true),
        1,
    );
    assert!(matches!(
        repository.issue_proposal("finite-proposal", requested.new_snapshot, &wrong_order,),
        Err(CampaignRepositoryError::Integrity {
            reason: "proposal-value-does-not-match-source-order"
        })
    ));

    let first = finite_proposal(
        &request,
        &policy,
        &request_head,
        ChoiceValue::Boolean(false),
        1,
    );
    let accepted = repository
        .issue_proposal("finite-proposal", requested.new_snapshot, &first)
        .expect("issue proposal");
    assert!(!accepted.replayed);
    assert_eq!(accepted.proposal, first.id().expect("proposal id"));
    assert_eq!(
        repository
            .load_proposal(accepted.proposal)
            .expect("load proposal"),
        first
    );

    let proposal_head = repository.head("finite-proposal").expect("proposal head");
    let prior = request_head.snapshot().roots();
    let next = proposal_head.snapshot().roots();
    assert_ne!(prior.exploration, next.exploration);
    assert_eq!(prior.graph, next.graph);
    assert_eq!(prior.observations, next.observations);
    assert_eq!(prior.corpus, next.corpus);
    assert_eq!(prior.coverage, next.coverage);
    assert_eq!(prior.findings, next.findings);
    assert_eq!(prior.pins, next.pins);
    assert_eq!(prior.accounting, next.accounting);
    assert_eq!(
        repository
            .merkle
            .inspect_shallow(next.exploration)
            .expect("exploration root")
            .entry_count(),
        7
    );

    let replay = repository
        .issue_proposal("finite-proposal", genesis.snapshot_id(), &first)
        .expect("replay proposal");
    assert!(replay.replayed);
    assert_eq!(replay.prior_snapshot, accepted.prior_snapshot);
    assert_eq!(replay.new_snapshot, accepted.new_snapshot);
}
