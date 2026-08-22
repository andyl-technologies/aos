//! Coordinator mutation, planner, and incremental-history repository tests.

use super::*;

struct PermitAlice;

impl crate::CampaignPrincipalAuthorizer for PermitAlice {
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

#[test]
fn planner_no_work_is_owned_replayable_and_state_continuous() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("planner-owner", &lineage, &policy, &BTreeMap::new())
        .expect("create");
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
        "planner-owner",
        genesis.snapshot_id(),
        initial_state,
    );
    let next_state = PlannerState::new(
        engine.id().expect("engine id"),
        "closed-rust-state",
        1,
        vec![1],
    )
    .expect("next state");
    let proposal = no_work_proposal(invocation.id().expect("invocation id"), next_state.clone());
    let measured = PlanningUsage {
        branch_requests: 0,
        proposals: 0,
        input_objects: 0,
        input_bytes: 0,
        fuel: 5,
    };
    let accepted = repository
        .accept_planner_step("planner-owner", genesis.snapshot_id(), &proposal, measured)
        .expect("accept planner step");
    assert!(!accepted.replayed);
    let step = repository
        .load_planner_step_at(accepted.new_snapshot, accepted.step)
        .expect("load accepted step");
    assert_eq!(step.parent(), None);
    assert_eq!(step.usage_claim(), proposal.usage_claim());
    assert_eq!(step.accounting().input_objects, measured.input_objects);
    assert_eq!(step.accounting().input_bytes, measured.input_bytes);
    assert_eq!(step.accounting().fuel, measured.fuel);

    let accepted_head = repository.head("planner-owner").expect("accepted head");
    assert_eq!(
        accepted_head
            .snapshot()
            .planning_view()
            .id()
            .expect("accepted planning view"),
        invocation.input_view()
    );
    assert_eq!(
        repository
            .merkle
            .inspect_shallow(accepted_head.snapshot().roots().coordination)
            .expect("planner coordination root")
            .entry_count(),
        3
    );
    let replay = repository
        .accept_planner_step("planner-owner", genesis.snapshot_id(), &proposal, measured)
        .expect("replay planner step");
    assert!(replay.replayed);
    assert_eq!(replay.step, accepted.step);
    assert_eq!(replay.new_snapshot, accepted.new_snapshot);

    let conflicting = no_work_proposal(
        invocation.id().expect("invocation id"),
        PlannerState::new(
            engine.id().expect("engine id"),
            "closed-rust-state",
            1,
            vec![9],
        )
        .expect("conflicting state"),
    );
    assert!(matches!(
        repository.accept_planner_step(
            "planner-owner",
            genesis.snapshot_id(),
            &conflicting,
            measured,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-invocation-result-conflict"
        })
    ));
    let oversized = PlanningUsage {
        input_bytes: 8193,
        ..measured
    };
    assert!(matches!(
        repository.accept_planner_step(
            "planner-owner",
            genesis.snapshot_id(),
            &proposal,
            oversized,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-step-invocation-budget-exceeded"
        })
    ));

    let request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "planner-state-continuity",
    );
    let requested = repository
        .submit_known_branch_request("planner-owner", accepted.new_snapshot, &request)
        .expect("submit intervening request");
    let wrong_input_state = PlannerState::new(
        engine.id().expect("engine id"),
        "closed-rust-state",
        1,
        vec![99],
    )
    .expect("wrong input state");
    assert!(matches!(
        repository.prepare_planner_invocation(
            "planner-owner",
            requested.new_snapshot,
            &engine,
            &artifact,
            &wrong_input_state,
            None,
            16,
            PlanningBudget::new(4, 4, 16, 8192, 100).expect("planner budget"),
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-step-parent-state-discontinuity"
        })
    ));

    let (_, _, next_invocation) = planner_basis(
        &repository,
        "planner-owner",
        requested.new_snapshot,
        next_state.clone(),
    );
    assert_eq!(
        next_invocation.policy_artifact(),
        artifact.id().expect("artifact id")
    );
    let final_state = PlannerState::new(
        engine.id().expect("engine id"),
        "closed-rust-state",
        1,
        vec![2],
    )
    .expect("final state");
    let second_proposal = no_work_proposal(
        next_invocation.id().expect("next invocation id"),
        final_state.clone(),
    );
    let second_measured = PlanningUsage {
        branch_requests: 0,
        proposals: 0,
        input_objects: next_invocation.scan_page().input_objects(),
        input_bytes: next_invocation.scan_page().input_bytes(),
        fuel: measured.fuel,
    };
    let second = repository
        .accept_planner_step(
            "planner-owner",
            requested.new_snapshot,
            &second_proposal,
            second_measured,
        )
        .expect("second planner step");
    assert_eq!(
        repository
            .load_planner_step_at(second.new_snapshot, second.step)
            .expect("second step")
            .parent(),
        Some(accepted.step)
    );

    let missing_invocation = PlannerInvocationId::from_content_id(ContentId::for_bytes(
        ObjectKind::Policy,
        2,
        b"missing parent invocation",
    ))
    .expect("missing invocation id");
    let accepted_accounting = PlanningAccounting {
        branch_requests: 0,
        proposals: 0,
        attempts: 0,
        deduplicated: 0,
        input_objects: second_measured.input_objects,
        input_bytes: second_measured.input_bytes,
        fuel: second_measured.fuel,
    };
    let incomplete_parent = PlannerStep::new(
        None,
        missing_invocation,
        RetainedPlannerRequestId::from_content_id(ContentId::for_bytes(
            ObjectKind::Policy,
            1,
            b"missing parent request",
        ))
        .expect("missing request id"),
        test_planner_request_digest(missing_invocation),
        next_invocation.policy(),
        next_invocation.engine(),
        next_invocation.policy_artifact(),
        next_invocation.input_view(),
        PlannerDisposition::NoWork,
        next_invocation.planner_state(),
        second_proposal.usage_claim(),
        accepted_accounting,
        second_proposal.explanation().clone(),
    )
    .expect("incomplete parent");
    let incomplete_parent_content = repository
        .put_planner_step(&incomplete_parent)
        .expect("put incomplete parent");
    let incomplete_parent_id =
        PlannerStepId::from_content_id(incomplete_parent_content).expect("parent id");
    let accepted_second = repository
        .load_planner_step_at(second.new_snapshot, second.step)
        .expect("accepted second step");
    let child = PlannerStep::new(
        Some(incomplete_parent_id),
        next_invocation.id().expect("next invocation id"),
        accepted_second.request(),
        accepted_second.request_digest(),
        next_invocation.policy(),
        next_invocation.engine(),
        next_invocation.policy_artifact(),
        next_invocation.input_view(),
        PlannerDisposition::NoWork,
        final_state.id().expect("final state id"),
        second_proposal.usage_claim(),
        accepted_accounting,
        second_proposal.explanation().clone(),
    )
    .expect("child step");
    let child_content = repository.put_planner_step(&child).expect("put child");
    let child_id = PlannerStepId::from_content_id(child_content).expect("child id");
    assert!(matches!(
        repository.load_planner_step(child_id),
        Err(CampaignRepositoryError::Store(StoreError::NotFound { .. }))
    ));
}

#[test]
fn planner_scan_results_are_bound_to_exact_served_pages() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("planner-pages", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let first_request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "first-planner-page-request",
    );
    let first = repository
        .submit_known_branch_request("planner-pages", genesis.snapshot_id(), &first_request)
        .expect("first request");
    let second_request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "second-planner-page-request",
    );
    let second = repository
        .submit_known_branch_request("planner-pages", first.new_snapshot, &second_request)
        .expect("second request");

    let mut expected_positions = [
        PlanningScanPosition::new(
            first_request.branch_point(),
            first_request.id().expect("first request id"),
        ),
        PlanningScanPosition::new(
            second_request.branch_point(),
            second_request.id().expect("second request id"),
        ),
    ];
    expected_positions.sort();
    let engine = PlannerEngine::new("closed-rust", 1, 1, BTreeSet::new()).expect("planner engine");
    let initial_state = PlannerState::new(
        engine.id().expect("engine id"),
        "closed-rust-state",
        1,
        vec![0],
    )
    .expect("initial state");
    let (engine, artifact, invocation) = planner_basis_with_page(
        &repository,
        "planner-pages",
        second.new_snapshot,
        initial_state.clone(),
        None,
        1,
    );
    assert_eq!(invocation.scan_page().positions(), &expected_positions[..1]);
    assert!(!invocation.scan_page().complete());
    assert!(matches!(
        repository.prepare_planner_invocation(
            "planner-pages",
            second.new_snapshot,
            &engine,
            &artifact,
            &initial_state,
            Some(expected_positions[0]),
            1,
            PlanningBudget::new(4, 4, 16, 8192, 100).expect("planner budget"),
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-invocation-scan-start-mismatch"
        })
    ));
    let measured = PlanningUsage {
        branch_requests: 0,
        proposals: 0,
        input_objects: invocation.scan_page().input_objects(),
        input_bytes: invocation.scan_page().input_bytes(),
        fuel: 1,
    };
    let next_state = PlannerState::new(
        engine.id().expect("engine id"),
        "closed-rust-state",
        1,
        vec![1],
    )
    .expect("next state");
    repository
        .put_planner_state(&next_state)
        .expect("put forged-step state");
    let false_eof_page = PlanningScanPage::new(
        None,
        invocation.scan_page().limit(),
        invocation.scan_page().positions().to_vec(),
        true,
        invocation.scan_page().input_bytes(),
    )
    .expect("false EOF page");
    let false_eof_invocation = PlannerInvocation::new(
        invocation.engine(),
        invocation.policy_artifact(),
        invocation.policy(),
        invocation.planner_state(),
        invocation.input_view(),
        false_eof_page,
        invocation.budget(),
    )
    .expect("false EOF invocation");
    repository
        .put_planner_invocation(&false_eof_invocation)
        .expect("put false EOF invocation");
    let false_eof_request = PlannerRequest::new(
        second.new_snapshot,
        false_eof_invocation.clone(),
        engine.clone(),
        artifact.clone(),
        policy.clone(),
        initial_state,
        repository
            .head("planner-pages")
            .expect("planner head")
            .snapshot()
            .planning_view(),
        CampaignPlanningBundle::new(vec![
            repository
                .read_envelope(invocation.scan_page().positions()[0].source().content_id())
                .expect("served request envelope"),
        ])
        .expect("false EOF bundle"),
    )
    .expect("false EOF request");
    repository
        .put_planner_request(&false_eof_request)
        .expect("put false EOF request");
    let false_eof_accounting = PlanningAccounting {
        branch_requests: 0,
        proposals: 0,
        attempts: 0,
        deduplicated: 0,
        input_objects: false_eof_invocation.scan_page().input_objects(),
        input_bytes: false_eof_invocation.scan_page().input_bytes(),
        fuel: 1,
    };
    let false_eof_step = PlannerStep::new(
        None,
        false_eof_invocation.id().expect("false EOF invocation id"),
        false_eof_request.id().expect("false EOF request id"),
        false_eof_request.request_digest(),
        false_eof_invocation.policy(),
        false_eof_invocation.engine(),
        false_eof_invocation.policy_artifact(),
        false_eof_invocation.input_view(),
        PlannerDisposition::NoWork,
        next_state.id().expect("next state id"),
        measured,
        false_eof_accounting,
        GuidanceEvidence::new(BTreeMap::new()).expect("false EOF evidence"),
    )
    .expect("false EOF step");
    let false_eof_step_content = repository
        .put_planner_step(&false_eof_step)
        .expect("put false EOF step");
    assert!(matches!(
        repository.load_planner_step(
            PlannerStepId::from_content_id(false_eof_step_content).expect("false EOF step id"),
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-invocation-scan-page-mismatch"
        })
    ));
    let jump = PlannerStepProposal::new(
        invocation.id().expect("invocation id"),
        next_state.clone(),
        measured,
        GuidanceEvidence::new(BTreeMap::new()).expect("jump evidence"),
        PlannerProposalDisposition::ContinueScan {
            cursor: crate::PlanningScanCursor::new(
                invocation.input_view(),
                Some(expected_positions[1]),
            ),
        },
    )
    .expect("jump proposal");
    assert!(matches!(
        repository.accept_planner_step("planner-pages", second.new_snapshot, &jump, measured,),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-step-disposition-does-not-match-served-page"
        })
    ));

    let false_eof = no_work_proposal(invocation.id().expect("invocation id"), next_state.clone());
    assert!(matches!(
        repository.accept_planner_step("planner-pages", second.new_snapshot, &false_eof, measured,),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-step-disposition-does-not-match-served-page"
        })
    ));

    let continuation = PlannerStepProposal::new(
        invocation.id().expect("invocation id"),
        next_state.clone(),
        measured,
        GuidanceEvidence::new(BTreeMap::new()).expect("continuation evidence"),
        PlannerProposalDisposition::ContinueScan {
            cursor: crate::PlanningScanCursor::new(
                invocation.input_view(),
                Some(expected_positions[0]),
            ),
        },
    )
    .expect("continuation proposal");
    let continued = repository
        .accept_planner_step(
            "planner-pages",
            second.new_snapshot,
            &continuation,
            measured,
        )
        .expect("accept continuation");
    let next_invocation = repository
        .prepare_planner_invocation(
            "planner-pages",
            continued.new_snapshot,
            &engine,
            &artifact,
            &next_state,
            Some(expected_positions[0]),
            1,
            PlanningBudget::new(4, 4, 16, 8192, 100).expect("planner budget"),
        )
        .expect("prepare final page");
    assert_eq!(
        next_invocation.scan_page().positions(),
        &expected_positions[1..]
    );
    assert!(next_invocation.scan_page().complete());
    let final_measured = PlanningUsage {
        branch_requests: 0,
        proposals: 0,
        input_objects: next_invocation.scan_page().input_objects(),
        input_bytes: next_invocation.scan_page().input_bytes(),
        fuel: 1,
    };
    let done = no_work_proposal(
        next_invocation.id().expect("next invocation id"),
        PlannerState::new(
            engine.id().expect("engine id"),
            "closed-rust-state",
            1,
            vec![2],
        )
        .expect("done state"),
    );
    let finished = repository
        .accept_planner_step(
            "planner-pages",
            continued.new_snapshot,
            &done,
            final_measured,
        )
        .expect("accept EOF");
    assert!(matches!(
        repository.prepare_planner_invocation(
            "planner-pages",
            finished.new_snapshot,
            &engine,
            &artifact,
            done.next_state(),
            None,
            1,
            PlanningBudget::new(4, 4, 16, 8192, 100).expect("planner budget"),
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-invocation-reopens-complete-view"
        })
    ));
}

#[test]
fn canonical_frontier_planner_carries_the_first_ready_offer_across_pages() {
    let (repository, lineage, policy, blobs) = counted_fixture();
    let genesis = repository
        .create("canonical-planner", &lineage, &policy, &BTreeMap::new())
        .expect("create canonical-planner campaign");
    let first_request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "canonical-planner-first",
    );
    let first = repository
        .submit_known_branch_request("canonical-planner", genesis.snapshot_id(), &first_request)
        .expect("submit first planner request");
    let second_request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "canonical-planner-second",
    );
    let second = repository
        .submit_known_branch_request("canonical-planner", first.new_snapshot, &second_request)
        .expect("submit second planner request");

    let engine = CanonicalFrontierPlanner::descriptor().expect("closed planner descriptor");
    let initial_state = CanonicalFrontierPlanner::initial_state().expect("closed planner state");
    let dependency_bytes = b"canonical planner dependency".to_vec();
    let dependency = ContentId::for_bytes(ObjectKind::Trace, 1, &dependency_bytes);
    repository
        .blobs
        .put_if_absent(dependency, &BlobHandle::from_bytes(dependency_bytes))
        .expect("planner dependency");
    let artifact = PolicyArtifact::new(
        engine.id().expect("engine id"),
        1,
        dependency,
        BTreeSet::new(),
        BTreeMap::new(),
    )
    .expect("planner artifact");
    let budget = PlanningBudget::new(1, 1, 8, 8192, 100).expect("planner budget");
    let wide_invocation = repository
        .prepare_planner_invocation(
            "canonical-planner",
            second.new_snapshot,
            &engine,
            &artifact,
            &initial_state,
            None,
            2,
            budget,
        )
        .expect("prepare complete two-source page");
    let wide_request = repository
        .build_planner_request(
            second.new_snapshot,
            wide_invocation.id().expect("wide invocation id"),
        )
        .expect("build complete two-source request");
    assert_eq!(wide_request.input_bundle().len(), 5);
    let wide_output = CanonicalFrontierPlanner
        .plan(&wide_request)
        .expect("plan complete two-source page");
    let PlannerProposalDisposition::Issue { selected, .. } = wide_output.proposal().disposition()
    else {
        panic!("complete two-source page must issue")
    };
    assert_eq!(*selected, wide_invocation.scan_page().positions()[0]);
    assert!(matches!(
        repository.prepare_planner_invocation(
            "canonical-planner",
            second.new_snapshot,
            &engine,
            &artifact,
            wide_output.proposal().next_state(),
            None,
            2,
            budget,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "builtin-planner-initial-state-mismatch"
        })
    ));

    let first_invocation = repository
        .prepare_planner_invocation(
            "canonical-planner",
            second.new_snapshot,
            &engine,
            &artifact,
            &initial_state,
            None,
            1,
            budget,
        )
        .expect("prepare first planner page");
    let first_request_message = repository
        .build_planner_request(
            second.new_snapshot,
            first_invocation.id().expect("first invocation id"),
        )
        .expect("build first planner request");
    assert_eq!(first_request_message.input_bundle().len(), 3);
    let tampered_objects = first_request_message
        .input_bundle()
        .object_ids()
        .map(|id| {
            let object = first_request_message
                .input_bundle()
                .object(id)
                .expect("decode bundle object")
                .expect("bundle object");
            if object.record_kind() != crate::CampaignRecordKind::Proposal {
                return object;
            }
            let offer = Proposal::from_canonical_bytes(object.body()).expect("candidate offer");
            let forged = Proposal::new(
                offer.branch_point(),
                offer.request(),
                offer.domain(),
                offer.value().clone(),
                offer.policy(),
                offer.planner_invocation(),
                offer.ordinal() + 1,
                offer.guidance_basis(),
            )
            .expect("forged offer");
            ObjectEnvelope::for_record(
                crate::CampaignRecordKind::Proposal,
                crate::object::content_children(forged.content_children())
                    .expect("forged offer children"),
                forged.canonical_bytes(),
            )
            .expect("forged offer envelope")
        })
        .collect::<Vec<_>>();
    let tampered = PlannerRequest::new(
        first_request_message.expected_snapshot(),
        first_request_message.invocation().clone(),
        first_request_message.engine().clone(),
        first_request_message.policy_artifact().clone(),
        first_request_message.policy().clone(),
        first_request_message.planner_state().clone(),
        *first_request_message.input_view(),
        CampaignPlanningBundle::new(tampered_objects).expect("tampered bundle"),
    )
    .expect("structurally valid tampered request");
    let before_rejection = blobs.object_count().expect("object count before rejection");
    assert!(matches!(
        repository.preflight_planner_request_inputs(&tampered),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-request-candidate-projection-mismatch"
        })
    ));
    assert_eq!(
        blobs.object_count().expect("object count after rejection"),
        before_rejection
    );
    let mut planner = CanonicalFrontierPlanner;
    let first_output = planner
        .plan(&first_request_message)
        .expect("plan first page");
    let PlannerProposalDisposition::ContinueScan { cursor } = first_output.proposal().disposition()
    else {
        panic!("first planner page must continue")
    };
    let first_position = first_invocation.scan_page().positions()[0];
    assert_eq!(cursor.after(), Some(first_position));
    let first_usage = first_output.proposal().usage_claim();
    let forged_output = PlannerStepProposal::new(
        first_output.proposal().invocation(),
        first_output.proposal().next_state().clone(),
        first_usage,
        GuidanceEvidence::new(BTreeMap::new()).expect("forged evidence"),
        first_output.proposal().disposition().clone(),
    )
    .expect("structurally valid forged planner output");
    let before_output_rejection = blobs
        .object_count()
        .expect("objects before output rejection");
    assert!(matches!(
        repository.accept_planner_step(
            "canonical-planner",
            second.new_snapshot,
            &forged_output,
            first_usage,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "builtin-planner-output-mismatch"
        })
    ));
    assert_eq!(
        blobs
            .object_count()
            .expect("objects after output rejection"),
        before_output_rejection
    );
    let continued = repository
        .accept_planner_step(
            "canonical-planner",
            second.new_snapshot,
            first_output.proposal(),
            first_usage,
        )
        .expect("accept first planner page");

    let final_invocation = repository
        .prepare_planner_invocation(
            "canonical-planner",
            continued.new_snapshot,
            &engine,
            &artifact,
            first_output.proposal().next_state(),
            cursor.after(),
            1,
            budget,
        )
        .expect("prepare final planner page");
    assert!(final_invocation.scan_page().complete());
    let final_request_message = repository
        .build_planner_request(
            continued.new_snapshot,
            final_invocation.id().expect("final invocation id"),
        )
        .expect("build final planner request");
    let final_output = planner
        .plan(&final_request_message)
        .expect("plan final page");
    let PlannerProposalDisposition::Issue {
        selected,
        branch_requests,
        proposals,
    } = final_output.proposal().disposition()
    else {
        panic!("final planner page must issue")
    };
    assert_eq!(*selected, first_position);
    assert!(branch_requests.is_empty());
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].request(), first_position.source());
    assert_eq!(proposals[0].ordinal(), 1);
    let final_usage = final_output.proposal().usage_claim();
    let issued = repository
        .accept_planner_step(
            "canonical-planner",
            continued.new_snapshot,
            final_output.proposal(),
            final_usage,
        )
        .expect("accept canonical planner issue");
    let accepted = repository
        .load_planner_step_at(issued.new_snapshot, issued.step)
        .expect("load accepted planner step");
    assert_eq!(accepted.selected_source(), Some(first_position.source()));

    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    restarted
        .validate_complete_head(issued.new_snapshot.content_id())
        .expect("restart validates canonical planner issue");
    let retained = restarted
        .load_planner_request(accepted.request())
        .expect("load retained candidate offers");
    assert_eq!(retained, final_request_message);
}

#[derive(Clone)]
struct ExactCanonicalPlannerSupervisor {
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl crate::PlannerExecutionSupervisor<CanonicalFrontierPlanner>
    for ExactCanonicalPlannerSupervisor
{
    type Error = std::convert::Infallible;

    fn execute(
        &mut self,
        engine: &mut CanonicalFrontierPlanner,
        request: &PlannerRequest,
    ) -> Result<crate::SupervisedPlannerExecution<CampaignCodecError>, Self::Error> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let measured_fuel = u64::try_from(request.invocation().scan_page().positions().len())
            .expect("page count fits u64")
            + 1;
        Ok(crate::SupervisedPlannerExecution::new(
            engine.plan(request),
            measured_fuel,
        ))
    }
}

fn canonical_planner_driver_basis(
    repository: &CampaignRepository,
) -> (PlannerEngine, PolicyArtifact, PlannerState, PlanningBudget) {
    let engine = CanonicalFrontierPlanner::descriptor().expect("canonical planner descriptor");
    let dependency_bytes = b"campaign planner driver dependency".to_vec();
    let dependency = ContentId::for_bytes(ObjectKind::Trace, 1, &dependency_bytes);
    repository
        .blobs
        .put_if_absent(dependency, &BlobHandle::from_bytes(dependency_bytes))
        .expect("planner dependency");
    let artifact = PolicyArtifact::new(
        engine.id().expect("engine id"),
        1,
        dependency,
        BTreeSet::new(),
        BTreeMap::new(),
    )
    .expect("planner artifact");
    let initial_state = CanonicalFrontierPlanner::initial_state().expect("initial planner state");
    let budget = PlanningBudget::new(1, 1, 8, 8_192, 100).expect("planner budget");
    (engine, artifact, initial_state, budget)
}

fn canonical_planner_client(
    authority: &PlannerAuthorityKey,
    calls: Arc<std::sync::atomic::AtomicUsize>,
) -> crate::PlannerClient<
    crate::AuthorizedPlannerService<CanonicalFrontierPlanner, ExactCanonicalPlannerSupervisor>,
> {
    crate::PlannerClient::new(
        crate::AuthorizedPlannerService::new(
            CanonicalFrontierPlanner,
            ExactCanonicalPlannerSupervisor { calls },
            authority.clone(),
        ),
        authority.clone(),
    )
}

struct SupervisorExecutor {
    execution: ExecutionId,
    cancellations: Arc<std::sync::atomic::AtomicUsize>,
}

impl crate::ExecutorService for SupervisorExecutor {
    type Error = &'static str;

    fn submit_attempt(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, Self::Error> {
        SubmitAttemptResponse::new(
            request,
            SubmitAttemptDisposition::Accepted {
                execution: self.execution,
            },
        )
        .map_err(|_| "response encoding")
    }
}

impl crate::ExecutorStatusService for SupervisorExecutor {
    fn get_attempt_execution(
        &mut self,
        request: &crate::GetAttemptExecutionRequest,
    ) -> Result<crate::GetAttemptExecutionResponse, Self::Error> {
        crate::GetAttemptExecutionResponse::new(
            request,
            crate::GetAttemptExecutionDisposition::Running,
        )
        .map_err(|_| "response encoding")
    }
}

impl crate::ExecutorControlService for SupervisorExecutor {
    fn checkpoint_attempt_execution(
        &mut self,
        request: &crate::CheckpointAttemptExecutionRequest,
    ) -> Result<crate::CheckpointAttemptExecutionResponse, Self::Error> {
        crate::CheckpointAttemptExecutionResponse::new(
            request,
            crate::CheckpointAttemptExecutionDisposition::Requested,
        )
        .map_err(|_| "response encoding")
    }

    fn cancel_attempt_execution(
        &mut self,
        request: &crate::CancelAttemptExecutionRequest,
    ) -> Result<crate::CancelAttemptExecutionResponse, Self::Error> {
        self.cancellations
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        crate::CancelAttemptExecutionResponse::new(
            request,
            crate::CancelAttemptExecutionDisposition::Canceled,
        )
        .map_err(|_| "response encoding")
    }
}

#[test]
fn planner_driver_rejects_invalid_static_configuration_without_repository_writes() {
    let (repository, _, _, blobs, planner_authority, _) = authorized_fixture();
    let repository = Arc::new(repository);
    let (engine, artifact, initial_state, budget) = canonical_planner_driver_basis(&repository);
    let before = blobs
        .object_count()
        .expect("object count before validation");
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let wrong_authority = PlannerAuthorityKey::from_bytes([31; 32]).expect("wrong authority");
    assert!(matches!(
        CampaignPlannerDriver::new(
            Arc::clone(&repository),
            canonical_planner_client(&wrong_authority, Arc::clone(&calls)),
            engine.clone(),
            artifact.clone(),
            initial_state.clone(),
            1,
            budget,
        ),
        Err(CampaignPlannerDriverConfigError::AuthorityMismatch)
    ));
    assert!(matches!(
        CampaignPlannerDriver::new(
            Arc::clone(&repository),
            canonical_planner_client(&planner_authority, Arc::clone(&calls)),
            engine.clone(),
            artifact.clone(),
            initial_state.clone(),
            0,
            budget,
        ),
        Err(CampaignPlannerDriverConfigError::InvalidScanLimit)
    ));
    let other_engine =
        PlannerEngine::new("other-planner", 1, 1, BTreeSet::new()).expect("other planner engine");
    let other_state = PlannerState::new(
        other_engine.id().expect("other engine id"),
        "other-state",
        1,
        Vec::new(),
    )
    .expect("other state");
    assert!(matches!(
        CampaignPlannerDriver::new(
            repository,
            canonical_planner_client(&planner_authority, calls),
            engine,
            artifact,
            other_state,
            1,
            budget,
        ),
        Err(CampaignPlannerDriverConfigError::BasisMismatch)
    ));
    assert_eq!(
        blobs.object_count().expect("object count after validation"),
        before
    );
}

#[test]
fn campaign_supervisor_applies_cancel_and_checkpoint_pause_policies_without_planning() {
    let (repository, lineage, policy, _, planner_authority, _) = authorized_fixture();
    let (_, admitted, _) =
        admitted_observation_fixture(&repository, &lineage, &policy, "campaign-supervisor-pause");
    let running = repository
        .apply_control(
            "campaign-supervisor-pause",
            &command(
                "campaign-supervisor-pause-resume",
                admitted.new_snapshot,
                CampaignControlAction::Resume,
            ),
        )
        .expect("resume campaign");
    let repository = Arc::new(repository);
    let planner_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (engine, artifact, initial_state, budget) = canonical_planner_driver_basis(&repository);
    let planner = CampaignPlannerDriver::new(
        Arc::clone(&repository),
        canonical_planner_client(&planner_authority, Arc::clone(&planner_calls)),
        engine,
        artifact,
        initial_state,
        16,
        budget,
    )
    .expect("planner driver");
    let cancellations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let execution = ExecutionId::from_bytes([0x73; 16]).expect("execution");
    let resources = AttemptResourceLimits::new(1, 256 * 1024 * 1024, 0, 10_000).expect("resources");
    let executor = CampaignExecutorDriver::new(
        Arc::clone(&repository),
        crate::ExecutorClient::new(SupervisorExecutor {
            execution,
            cancellations: Arc::clone(&cancellations),
        }),
        DaemonEpoch::from_bytes([0x74; 16]).expect("daemon epoch"),
        2,
        resources,
        ExecutionRetentionIntent::Discard,
        10_000,
    )
    .expect("executor driver");
    let mut supervisor = CampaignSupervisor::new(
        Arc::clone(&repository),
        crate::CampaignName::new("campaign-supervisor-pause").expect("campaign name"),
        planner,
        executor,
        2,
    )
    .expect("campaign supervisor");

    assert!(matches!(
        supervisor.step().expect("reserve attempt"),
        CampaignSupervisorStepOutcome::Executor {
            outcome:
                CampaignExecutorStepOutcome::Running {
                    attempt,
                    execution: accepted,
                    newly_accepted: true,
                },
            ..
        } if attempt == admitted.attempt && accepted == execution
    ));
    let drain_pause = repository
        .apply_control(
            "campaign-supervisor-pause",
            &command(
                "campaign-supervisor-drain-pause",
                running.new_snapshot,
                CampaignControlAction::Pause(crate::ActiveAttemptPolicy::Drain),
            ),
        )
        .expect("pause to drain");
    assert!(matches!(
        supervisor.step().expect("poll only held drain work"),
        CampaignSupervisorStepOutcome::Executor {
            worker_slot,
            outcome:
                CampaignExecutorStepOutcome::Running {
                    attempt,
                    execution: active,
                    newly_accepted: false,
                },
        } if worker_slot == WorkerSlotId::new(0)
            && attempt == admitted.attempt
            && active == execution
    ));
    assert_eq!(supervisor.reservation_count(), 1);
    assert_eq!(cancellations.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(planner_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    let drain_resume = repository
        .apply_control(
            "campaign-supervisor-pause",
            &command(
                "campaign-supervisor-drain-resume",
                drain_pause.new_snapshot,
                CampaignControlAction::Resume,
            ),
        )
        .expect("resume drained campaign");
    let cancel_pause = repository
        .apply_control(
            "campaign-supervisor-pause",
            &command(
                "campaign-supervisor-cancel-pause",
                drain_resume.new_snapshot,
                CampaignControlAction::Pause(crate::ActiveAttemptPolicy::CancelAndRetry),
            ),
        )
        .expect("pause with cancellation");
    assert_eq!(
        supervisor.step().expect("cancel paused execution"),
        CampaignSupervisorStepOutcome::Cancellation(CampaignExecutorCancelOutcome::Canceled {
            attempt: admitted.attempt,
            execution,
            already_canceled: false,
        })
    );
    assert_eq!(supervisor.reservation_count(), 0);
    assert_eq!(cancellations.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(planner_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(matches!(
        supervisor.step().expect("stable paused campaign"),
        CampaignSupervisorStepOutcome::Inactive {
            lifecycle,
            snapshot,
        } if lifecycle.state() == CampaignState::Paused
            && lifecycle.active_attempt_policy()
                == Some(crate::ActiveAttemptPolicy::CancelAndRetry)
            && snapshot == cancel_pause.new_snapshot
    ));

    let resumed = repository
        .apply_control(
            "campaign-supervisor-pause",
            &command(
                "campaign-supervisor-second-resume",
                cancel_pause.new_snapshot,
                CampaignControlAction::Resume,
            ),
        )
        .expect("resume canceled attempt");
    assert!(matches!(
        supervisor.step().expect("reassign canceled attempt"),
        CampaignSupervisorStepOutcome::Executor {
            outcome: CampaignExecutorStepOutcome::Running { attempt, .. },
            ..
        } if attempt == admitted.attempt
    ));
    let _checkpoint_pause = repository
        .apply_control(
            "campaign-supervisor-pause",
            &command(
                "campaign-supervisor-checkpoint-pause",
                resumed.new_snapshot,
                CampaignControlAction::Pause(crate::ActiveAttemptPolicy::ExactCheckpoint),
            ),
        )
        .expect("pause for exact checkpoint");
    assert_eq!(
        supervisor.step().expect("request exact checkpoint"),
        CampaignSupervisorStepOutcome::Checkpoint(CampaignExecutorCheckpointOutcome::Requested {
            attempt: admitted.attempt,
            execution,
            already_requested: false,
        })
    );
    assert_eq!(supervisor.reservation_count(), 1);
    assert_eq!(cancellations.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(planner_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[test]
fn campaign_supervisor_plans_only_after_executor_scan_proves_no_ready_attempt() {
    let (repository, lineage, policy, _, planner_authority, _) = authorized_fixture();
    let created = repository
        .create(
            "campaign-supervisor-planning",
            &lineage,
            &policy,
            &BTreeMap::new(),
        )
        .expect("create campaign");
    repository
        .apply_control(
            "campaign-supervisor-planning",
            &command(
                "campaign-supervisor-planning-resume",
                created.snapshot_id(),
                CampaignControlAction::Resume,
            ),
        )
        .expect("resume campaign");
    let repository = Arc::new(repository);
    let planner_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (engine, artifact, initial_state, budget) = canonical_planner_driver_basis(&repository);
    let planner = CampaignPlannerDriver::new(
        Arc::clone(&repository),
        canonical_planner_client(&planner_authority, Arc::clone(&planner_calls)),
        engine,
        artifact,
        initial_state,
        16,
        budget,
    )
    .expect("planner driver");
    let resources = AttemptResourceLimits::new(1, 4096, 0, 64).expect("resources");
    let executor = CampaignExecutorDriver::new(
        Arc::clone(&repository),
        crate::ExecutorClient::new(SupervisorExecutor {
            execution: ExecutionId::from_bytes([0x75; 16]).expect("execution"),
            cancellations: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }),
        DaemonEpoch::from_bytes([0x76; 16]).expect("daemon epoch"),
        1,
        resources,
        ExecutionRetentionIntent::Discard,
        10_000,
    )
    .expect("executor driver");
    let mut supervisor = CampaignSupervisor::new(
        repository,
        crate::CampaignName::new("campaign-supervisor-planning").expect("campaign name"),
        planner,
        executor,
        1,
    )
    .expect("campaign supervisor");

    assert!(matches!(
        supervisor.step().expect("scan executor queue"),
        CampaignSupervisorStepOutcome::Executor {
            outcome: CampaignExecutorStepOutcome::Idle { .. },
            ..
        }
    ));
    assert_eq!(planner_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(matches!(
        supervisor.step().expect("plan empty view"),
        CampaignSupervisorStepOutcome::Planner(CampaignPlannerStepOutcome::Advanced {
            disposition: PlannerDisposition::NoWork,
            ..
        })
    ));
    assert_eq!(planner_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn planner_driver_resumes_an_authenticated_page_cursor_after_restart() {
    let (repository, lineage, policy, _, planner_authority, debugger_authority) =
        authorized_fixture();
    let repository = Arc::new(repository);
    let genesis = repository
        .create(
            "planner-driver-restart",
            &lineage,
            &policy,
            &BTreeMap::new(),
        )
        .expect("create campaign");
    let first_request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "planner-driver-first",
    );
    let first = repository
        .submit_known_branch_request(
            "planner-driver-restart",
            genesis.snapshot_id(),
            &first_request,
        )
        .expect("submit first request");
    let second_request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "planner-driver-second",
    );
    let second = repository
        .submit_known_branch_request(
            "planner-driver-restart",
            first.new_snapshot,
            &second_request,
        )
        .expect("submit second request");
    let running = repository
        .apply_control(
            "planner-driver-restart",
            &command(
                "planner-driver-restart-resume",
                second.new_snapshot,
                CampaignControlAction::Resume,
            ),
        )
        .expect("resume planner campaign");
    let (engine, artifact, initial_state, budget) = canonical_planner_driver_basis(&repository);
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut driver = CampaignPlannerDriver::new(
        Arc::clone(&repository),
        canonical_planner_client(&planner_authority, Arc::clone(&calls)),
        engine.clone(),
        artifact.clone(),
        initial_state.clone(),
        1,
        budget,
    )
    .expect("planner driver");

    let first_advance = driver.step("planner-driver-restart").expect("first page");
    let (continued_snapshot, continued_step, cursor_position) = match first_advance {
        CampaignPlannerStepOutcome::Advanced {
            result,
            disposition: PlannerDisposition::ContinueScan { cursor },
        } => {
            assert_eq!(result.prior_snapshot, running.new_snapshot);
            (
                result.new_snapshot,
                result.step,
                cursor.after().expect("first page cursor"),
            )
        }
        other => panic!("first page must continue, got {other:?}"),
    };
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    drop(driver);

    let restarted = Arc::new(
        CampaignRepository::with_component_authorities(
            repository.blobs.clone(),
            repository.refs.clone(),
            planner_authority.clone(),
            debugger_authority,
        )
        .expect("restart repository"),
    );
    let persisted = restarted
        .load_planner_step_at(continued_snapshot, continued_step)
        .expect("persisted continue step");
    assert_eq!(
        persisted.disposition(),
        &PlannerDisposition::ContinueScan {
            cursor: crate::PlanningScanCursor::new(persisted.input_view(), Some(cursor_position),)
        }
    );
    let mut restarted_driver = CampaignPlannerDriver::new(
        restarted,
        canonical_planner_client(&planner_authority, Arc::clone(&calls)),
        engine,
        artifact,
        initial_state,
        1,
        budget,
    )
    .expect("restarted planner driver");
    let second_advance = restarted_driver
        .step("planner-driver-restart")
        .expect("resume final page");
    match second_advance {
        CampaignPlannerStepOutcome::Advanced {
            result,
            disposition: PlannerDisposition::Issue { selected, .. },
        } => {
            assert_eq!(result.prior_snapshot, continued_snapshot);
            assert_eq!(selected, cursor_position);
        }
        other => panic!("resumed final page must issue, got {other:?}"),
    }
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[test]
fn planner_driver_does_not_reinvoke_a_terminal_current_view() {
    let (repository, lineage, policy, _, planner_authority, _) = authorized_fixture();
    let repository = Arc::new(repository);
    let created = repository
        .create(
            "planner-driver-settled",
            &lineage,
            &policy,
            &BTreeMap::new(),
        )
        .expect("create empty campaign");
    let (engine, artifact, initial_state, budget) = canonical_planner_driver_basis(&repository);
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut driver = CampaignPlannerDriver::new(
        Arc::clone(&repository),
        canonical_planner_client(&planner_authority, Arc::clone(&calls)),
        engine,
        artifact,
        initial_state,
        16,
        budget,
    )
    .expect("planner driver");

    assert_eq!(
        driver
            .step("planner-driver-settled")
            .expect("created campaign is inactive"),
        CampaignPlannerStepOutcome::Inactive {
            snapshot: created.snapshot_id(),
            state: CampaignState::Created,
        }
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    repository
        .apply_control(
            "planner-driver-settled",
            &command(
                "planner-driver-settled-resume",
                created.snapshot_id(),
                CampaignControlAction::Resume,
            ),
        )
        .expect("resume empty campaign");

    let accepted = driver
        .step("planner-driver-settled")
        .expect("accept no-work step");
    let (settled_snapshot, settled_step) = match accepted {
        CampaignPlannerStepOutcome::Advanced {
            result,
            disposition: PlannerDisposition::NoWork,
        } => (result.new_snapshot, result.step),
        other => panic!("empty view must accept no-work, got {other:?}"),
    };
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);

    assert_eq!(
        driver
            .step("planner-driver-settled")
            .expect("reuse settled view"),
        CampaignPlannerStepOutcome::Settled {
            snapshot: settled_snapshot,
            step: settled_step,
            disposition: PlannerDisposition::NoWork,
        }
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

struct BlockingPlannerService<S> {
    started: std::sync::mpsc::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
    inner: S,
}

impl<S: crate::PlannerService> crate::PlannerService for BlockingPlannerService<S> {
    type Error = S::Error;

    fn plan(&mut self, request: &PlannerRequest) -> Result<PlannerResponse, Self::Error> {
        self.started.send(()).expect("observe planner call");
        self.release.recv().expect("release planner call");
        self.inner.plan(request)
    }
}

#[test]
fn planner_driver_releases_repository_mutation_ownership_during_component_work() {
    let (repository, lineage, policy, _, planner_authority, _) = authorized_fixture();
    let repository = Arc::new(repository);
    let genesis = repository
        .create(
            "planner-driver-concurrency",
            &lineage,
            &policy,
            &BTreeMap::new(),
        )
        .expect("create campaign");
    let running = repository
        .apply_control(
            "planner-driver-concurrency",
            &command(
                "planner-driver-concurrency-resume",
                genesis.snapshot_id(),
                CampaignControlAction::Resume,
            ),
        )
        .expect("resume planner campaign");
    let running_snapshot = running.new_snapshot;
    let (engine, artifact, initial_state, budget) = canonical_planner_driver_basis(&repository);
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let inner = crate::AuthorizedPlannerService::new(
        CanonicalFrontierPlanner,
        ExactCanonicalPlannerSupervisor { calls },
        planner_authority.clone(),
    );
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let planner = crate::PlannerClient::new(
        BlockingPlannerService {
            started: started_tx,
            release: release_rx,
            inner,
        },
        planner_authority,
    );
    let mut driver = CampaignPlannerDriver::new(
        Arc::clone(&repository),
        planner,
        engine,
        artifact,
        initial_state,
        16,
        budget,
    )
    .expect("planner driver");
    let drive = std::thread::spawn(move || driver.step("planner-driver-concurrency"));
    started_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("planner component entered");

    let (mutation_tx, mutation_rx) = std::sync::mpsc::channel();
    let mutation_repository = Arc::clone(&repository);
    let mutation = std::thread::spawn(move || {
        let result = mutation_repository.apply_control(
            "planner-driver-concurrency",
            &command(
                "planner-driver-concurrent-pause",
                running_snapshot,
                CampaignControlAction::Pause(crate::ActiveAttemptPolicy::Drain),
            ),
        );
        mutation_tx.send(result).expect("return mutation result");
    });
    let mutation_result = match mutation_rx.recv_timeout(std::time::Duration::from_secs(1)) {
        Ok(result) => result.expect("concurrent mutation"),
        Err(error) => {
            release_tx.send(()).expect("release blocked planner");
            let _ = drive.join();
            mutation.join().expect("mutation thread");
            panic!("repository mutation remained blocked by planner call: {error}");
        }
    };
    release_tx.send(()).expect("release planner");
    mutation.join().expect("mutation thread");
    let drive_result = drive.join().expect("planner driver thread");
    assert!(matches!(
        drive_result,
        Err(CampaignPlannerDriverError::Repository(
            CampaignRepositoryError::Stale { expected, current }
        )) if expected == running_snapshot && current == mutation_result.new_snapshot
    ));
    assert_eq!(
        repository
            .head("planner-driver-concurrency")
            .expect("current head")
            .snapshot_id(),
        mutation_result.new_snapshot
    );
}

#[test]
fn planner_issue_atomically_admits_attempts_and_deduplicates_replay() {
    let (repository, lineage, policy, blobs) = counted_fixture();
    let genesis = repository
        .create("planner-issue", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let source_request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "planner-issue-source",
    );
    let requested = repository
        .submit_known_branch_request("planner-issue", genesis.snapshot_id(), &source_request)
        .expect("submit source request");
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
        "planner-issue",
        requested.new_snapshot,
        initial_state,
    );
    assert!(invocation.scan_page().complete());

    let planner_request = BranchRequest::new(
        source_request.branch_point(),
        source_request.parent(),
        source_request.opportunity(),
        source_request.domain(),
        source_request.source().clone(),
        BranchRequestCause::Planner(invocation.id().expect("invocation id")),
        source_request.budget(),
        source_request.stop().clone(),
    )
    .expect("planner request");
    let first_proposal = Proposal::new(
        source_request.branch_point(),
        source_request.id().expect("source request id"),
        source_request.domain(),
        ChoiceValue::Boolean(false),
        policy.id().expect("policy id"),
        Some(invocation.id().expect("invocation id")),
        1,
        invocation.input_view(),
    )
    .expect("first proposal");
    let first_state = PlannerState::new(
        engine.id().expect("engine id"),
        "closed-rust-state",
        1,
        vec![1],
    )
    .expect("first state");
    let first_usage = PlanningUsage {
        branch_requests: 1,
        proposals: 1,
        input_objects: invocation.scan_page().input_objects(),
        input_bytes: invocation.scan_page().input_bytes(),
        fuel: 3,
    };
    let first_step = PlannerStepProposal::new(
        invocation.id().expect("invocation id"),
        first_state.clone(),
        first_usage,
        GuidanceEvidence::new(BTreeMap::from([("score".to_owned(), 7)])).expect("evidence"),
        PlannerProposalDisposition::Issue {
            selected: PlanningScanPosition::new(
                source_request.branch_point(),
                source_request.id().expect("source request id"),
            ),
            branch_requests: vec![planner_request.clone()],
            proposals: vec![first_proposal.clone()],
        },
    )
    .expect("first issue");
    let skipped_proposal = Proposal::new(
        source_request.branch_point(),
        source_request.id().expect("source request id"),
        source_request.domain(),
        ChoiceValue::Boolean(true),
        policy.id().expect("policy id"),
        Some(invocation.id().expect("invocation id")),
        3,
        invocation.input_view(),
    )
    .expect("skipped proposal");
    let invalid_usage = PlanningUsage {
        branch_requests: 1,
        proposals: 2,
        input_objects: invocation.scan_page().input_objects(),
        input_bytes: invocation.scan_page().input_bytes(),
        fuel: 4,
    };
    let invalid_step = PlannerStepProposal::new(
        invocation.id().expect("invocation id"),
        first_state.clone(),
        invalid_usage,
        GuidanceEvidence::new(BTreeMap::new()).expect("invalid evidence"),
        PlannerProposalDisposition::Issue {
            selected: PlanningScanPosition::new(
                source_request.branch_point(),
                source_request.id().expect("source request id"),
            ),
            branch_requests: vec![planner_request.clone()],
            proposals: vec![first_proposal.clone(), skipped_proposal],
        },
    )
    .expect("structurally valid late-invalid issue");
    let objects_before_rejection = blobs.object_count().expect("count before rejection");
    let rejected = repository.accept_planner_step(
        "planner-issue",
        requested.new_snapshot,
        &invalid_step,
        invalid_usage,
    );
    assert!(
        matches!(
            rejected,
            Err(CampaignRepositoryError::Codec(
                CampaignCodecError::InvalidValue {
                    reason: "proposal disagrees with its request, source, domain, or budget"
                }
            ))
        ),
        "unexpected preflight result: {rejected:?}"
    );
    assert_eq!(
        blobs.object_count().expect("count after rejection"),
        objects_before_rejection,
        "semantic preflight must reject the complete batch before publication"
    );

    let wrong_engine =
        PlannerEngine::new("wrong-engine", 1, 1, BTreeSet::new()).expect("wrong engine");
    repository
        .put_planner_engine(&wrong_engine)
        .expect("publish wrong engine");
    let wrong_state = PlannerState::new(
        wrong_engine.id().expect("wrong engine id"),
        "wrong-engine-state",
        1,
        vec![1],
    )
    .expect("wrong-engine state");
    let wrong_state_step = PlannerStepProposal::new(
        invocation.id().expect("invocation id"),
        wrong_state,
        first_usage,
        GuidanceEvidence::new(BTreeMap::new()).expect("wrong-state evidence"),
        PlannerProposalDisposition::Issue {
            selected: PlanningScanPosition::new(
                source_request.branch_point(),
                source_request.id().expect("source request id"),
            ),
            branch_requests: vec![planner_request.clone()],
            proposals: vec![first_proposal.clone()],
        },
    )
    .expect("wrong-state issue");
    let objects_before_wrong_state = blobs.object_count().expect("count before wrong state");
    assert!(matches!(
        repository.accept_planner_step(
            "planner-issue",
            requested.new_snapshot,
            &wrong_state_step,
            first_usage,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-step-next-state-engine-mismatch"
        })
    ));
    assert_eq!(
        blobs.object_count().expect("count after wrong state"),
        objects_before_wrong_state,
        "complete Issue preflight must validate next-state continuity before publication"
    );

    let first = repository
        .accept_planner_step(
            "planner-issue",
            requested.new_snapshot,
            &first_step,
            first_usage,
        )
        .expect("accept first issue");
    assert!(matches!(
        repository.load_planner_step(first.step),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-issue-requires-snapshot-owner"
        })
    ));
    let accepted_first = repository
        .load_planner_step_at(first.new_snapshot, first.step)
        .expect("load first issue");
    assert_eq!(accepted_first.accounting().branch_requests, 1);
    assert_eq!(accepted_first.accounting().proposals, 1);
    assert_eq!(accepted_first.accounting().attempts, 1);
    assert_eq!(accepted_first.accounting().deduplicated, 0);
    assert_eq!(
        accepted_first.issued_branch_requests(),
        [planner_request.id().expect("planner request id")]
    );
    assert_eq!(
        accepted_first.issued_proposals(),
        [first_proposal.id().expect("first proposal id")]
    );
    repository
        .load_proposal(first_proposal.id().expect("first proposal id"))
        .expect("load first proposal");

    let first_head = repository.head("planner-issue").expect("first issue head");
    let mut forged_roots = first_head.snapshot().roots();
    forged_roots.accounting = repository
        .merkle
        .insert(
            forged_roots.accounting,
            CampaignHash::derive("test", b"extra planner issue accounting"),
            first.step.content_id(),
        )
        .expect("forged accounting root")
        .content_id();
    let forged = CampaignSnapshot::successor(
        requested.new_snapshot,
        first_head.snapshot().lineage(),
        first_head.snapshot().active_policy(),
        forged_roots,
        first_head
            .snapshot()
            .transition()
            .expect("first issue transition"),
    )
    .expect("forged issue successor");
    let forged_content = repository
        .put_snapshot(&forged)
        .expect("put forged issue successor");
    let objects_before_validation = blobs.object_count().expect("count objects before import");
    assert!(matches!(
        repository.validate_complete_head(forged_content),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-issue-root-delta-mismatch"
        })
    ));
    assert_eq!(
        blobs.object_count().expect("count objects after import"),
        objects_before_validation,
        "invalid imported projection validation must be read-only"
    );

    let (_, _, second_invocation) = planner_basis(
        &repository,
        "planner-issue",
        first.new_snapshot,
        first_state.clone(),
    );
    let ancestry_usage = PlanningUsage {
        branch_requests: 0,
        proposals: 0,
        input_objects: second_invocation.scan_page().input_objects(),
        input_bytes: second_invocation.scan_page().input_bytes(),
        fuel: 1,
    };
    let ancestry_request = repository
        .build_planner_request(first.new_snapshot, second_invocation.id().expect("id"))
        .expect("ancestry request");
    repository
        .put_planner_request(&ancestry_request)
        .expect("put ancestry request");
    let ancestry_child = PlannerStep::new(
        Some(first.step),
        second_invocation.id().expect("second invocation id"),
        ancestry_request.id().expect("ancestry request id"),
        ancestry_request.request_digest(),
        second_invocation.policy(),
        second_invocation.engine(),
        second_invocation.policy_artifact(),
        second_invocation.input_view(),
        PlannerDisposition::NoWork,
        first_state.id().expect("first state id"),
        ancestry_usage,
        PlanningAccounting {
            branch_requests: 0,
            proposals: 0,
            attempts: 0,
            deduplicated: 0,
            input_objects: ancestry_usage.input_objects,
            input_bytes: ancestry_usage.input_bytes,
            fuel: ancestry_usage.fuel,
        },
        GuidanceEvidence::new(BTreeMap::new()).expect("ancestry evidence"),
    )
    .expect("non-issue ancestry child");
    let ancestry_child_content = repository
        .put_planner_step(&ancestry_child)
        .expect("put non-issue ancestry child");
    assert!(matches!(
        repository.load_planner_step(
            PlannerStepId::from_content_id(ancestry_child_content).expect("ancestry child id")
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-issue-requires-snapshot-owner"
        })
    ));

    let second_proposal = Proposal::new(
        planner_request.branch_point(),
        planner_request.id().expect("planner request id"),
        planner_request.domain(),
        ChoiceValue::Boolean(false),
        policy.id().expect("policy id"),
        Some(second_invocation.id().expect("second invocation id")),
        1,
        second_invocation.input_view(),
    )
    .expect("second proposal");
    let second_usage = PlanningUsage {
        branch_requests: 0,
        proposals: 1,
        input_objects: second_invocation.scan_page().input_objects(),
        input_bytes: second_invocation.scan_page().input_bytes(),
        fuel: 3,
    };
    let second_step = PlannerStepProposal::new(
        second_invocation.id().expect("second invocation id"),
        PlannerState::new(
            engine.id().expect("engine id"),
            "closed-rust-state",
            1,
            vec![2],
        )
        .expect("second state"),
        second_usage,
        GuidanceEvidence::new(BTreeMap::from([("score".to_owned(), 7)])).expect("evidence"),
        PlannerProposalDisposition::Issue {
            selected: PlanningScanPosition::new(
                planner_request.branch_point(),
                planner_request.id().expect("planner request id"),
            ),
            branch_requests: Vec::new(),
            proposals: vec![second_proposal],
        },
    )
    .expect("second issue");
    let second = repository
        .accept_planner_step(
            "planner-issue",
            first.new_snapshot,
            &second_step,
            second_usage,
        )
        .expect("accept deduplicated issue");
    let accepted_second = repository
        .load_planner_step_at(second.new_snapshot, second.step)
        .expect("load second issue");
    assert_eq!(accepted_second.accounting().attempts, 0);
    assert_eq!(accepted_second.accounting().deduplicated, 1);

    let replay = repository
        .accept_planner_step(
            "planner-issue",
            requested.new_snapshot,
            &first_step,
            first_usage,
        )
        .expect("replay first issue");
    assert!(replay.replayed);
    assert_eq!(replay.step, first.step);
    assert_eq!(replay.new_snapshot, first.new_snapshot);
    assert_eq!(artifact.engine(), engine.id().expect("engine id"));
}

#[test]
fn planner_issue_uses_the_canonical_authenticated_path_after_convergence() {
    let (repository, lineage, policy) = fixture();
    let (_, first_admitted, first_observation) =
        admitted_observation_fixture(&repository, &lineage, &policy, "planner-nested-path");
    let first_observed = repository
        .publish_observation(
            "planner-nested-path",
            first_admitted.new_snapshot,
            &first_observation,
        )
        .expect("publish first convergent observation");

    let first_proposal = repository
        .read_proposal(first_admitted.proposal.content_id())
        .expect("first proposal");
    let source_request = repository
        .read_branch_request(first_proposal.request().content_id())
        .expect("source request");
    let first_path = repository
        .read_branch_path(first_observation.path().content_id())
        .expect("first path");
    let second_proposal = finite_proposal(
        &source_request,
        &policy,
        &repository
            .head("planner-nested-path")
            .expect("first observation head"),
        ChoiceValue::Boolean(true),
        2,
    );
    let second_proposed = repository
        .issue_proposal(
            "planner-nested-path",
            first_observed.new_snapshot,
            &second_proposal,
        )
        .expect("issue second convergent proposal");
    let (second_selection, second_path, second_attempt) =
        branch_attempt(&repository, &source_request, &second_proposal);
    let second_admitted = repository
        .admit_proposal(
            "planner-nested-path",
            second_proposed.new_snapshot,
            second_proposed.proposal,
            &second_selection,
            &second_path,
            &second_attempt,
        )
        .expect("admit second convergent attempt");
    let second_observation = Observation::new(
        second_admitted.attempt,
        first_observation.child(),
        first_observation.child_content(),
        second_path.id().expect("second path id"),
        first_observation.stop().clone(),
        first_observation.measurements(),
        first_observation.properties(),
        first_observation.coverage(),
        first_observation.discovered_choices().clone(),
    )
    .expect("second convergent observation");
    let second_observed = repository
        .publish_observation(
            "planner-nested-path",
            second_admitted.new_snapshot,
            &second_observation,
        )
        .expect("publish second convergent observation");

    let opportunity_id = *first_observation
        .discovered_choices()
        .first()
        .expect("nested opportunity id");
    let opportunity = repository
        .load_choice_opportunity(opportunity_id)
        .expect("nested opportunity");
    let domain = repository
        .load_choice_domain(opportunity.domain())
        .expect("nested domain");
    let branch_point = opportunity.branch_point_id(first_observation.child());
    let nested_request = BranchRequest::new(
        branch_point,
        first_observation.child_content(),
        opportunity_id,
        opportunity.domain(),
        CandidateSource::finite(BTreeSet::from([
            ChoiceValue::Boolean(false),
            ChoiceValue::Boolean(true),
        ]))
        .expect("nested finite source"),
        BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(CampaignHash::derive(
            "test.planner-nested-path",
            b"nested request",
        ))),
        BranchBudget::new(2, 2).expect("nested branch budget"),
        StopCondition::NextChoice,
    )
    .expect("nested request");
    let nested_requested = repository
        .submit_known_branch_request(
            "planner-nested-path",
            second_observed.new_snapshot,
            &nested_request,
        )
        .expect("submit nested request");

    let engine = PlannerEngine::new("closed-rust", 1, 1, BTreeSet::new()).expect("planner engine");
    let initial_state = PlannerState::new(
        engine.id().expect("engine id"),
        "closed-rust-state",
        1,
        vec![0],
    )
    .expect("planner state");
    let (_, _, invocation) = planner_basis(
        &repository,
        "planner-nested-path",
        nested_requested.new_snapshot,
        initial_state,
    );
    let proposal = Proposal::new(
        branch_point,
        nested_request.id().expect("nested request id"),
        nested_request.domain(),
        ChoiceValue::Boolean(false),
        policy.id().expect("policy id"),
        Some(invocation.id().expect("invocation id")),
        1,
        invocation.input_view(),
    )
    .expect("nested proposal");
    let usage = PlanningUsage {
        branch_requests: 0,
        proposals: 1,
        input_objects: invocation.scan_page().input_objects(),
        input_bytes: invocation.scan_page().input_bytes(),
        fuel: 3,
    };
    let step = PlannerStepProposal::new(
        invocation.id().expect("invocation id"),
        PlannerState::new(
            engine.id().expect("engine id"),
            "closed-rust-state",
            1,
            vec![1],
        )
        .expect("next planner state"),
        usage,
        GuidanceEvidence::new(BTreeMap::new()).expect("guidance evidence"),
        PlannerProposalDisposition::Issue {
            selected: PlanningScanPosition::new(
                branch_point,
                nested_request.id().expect("nested request id"),
            ),
            branch_requests: Vec::new(),
            proposals: vec![proposal.clone()],
        },
    )
    .expect("nested planner issue");
    let accepted = repository
        .accept_planner_step(
            "planner-nested-path",
            nested_requested.new_snapshot,
            &step,
            usage,
        )
        .expect("accept nested planner issue");

    let accepted_snapshot = repository
        .read_snapshot(accepted.new_snapshot.content_id())
        .expect("accepted nested snapshot");
    let admission_content = repository
        .merkle
        .get(
            accepted_snapshot.snapshot.roots().accounting,
            map_key_content(
                "accounting.proposal-admission",
                proposal.id().expect("proposal id").content_id(),
            ),
        )
        .expect("proposal admission lookup")
        .expect("proposal admission");
    let admission = repository
        .read_attempt_admission(admission_content)
        .expect("nested attempt admission");
    let attempt = repository
        .read_attempt(admission.attempt().content_id())
        .expect("nested attempt");
    let path = repository
        .read_branch_path(attempt.path().content_id())
        .expect("nested cumulative path");
    let canonical_parent = [first_path, second_path]
        .into_iter()
        .min_by_key(|path| path_index_order_key(path.id().expect("candidate path id")))
        .expect("canonical parent path");
    let selection = Selection::new_campaign_branch(
        &opportunity,
        &domain,
        proposal.value().clone(),
        branch_point,
    )
    .expect("nested selection");
    let crate::SelectionOrigin::CampaignBranch { edge, .. } = selection.origin() else {
        panic!("nested campaign selection")
    };
    let mut expected_segments = canonical_parent
        .segments()
        .expect("scoped canonical parent")
        .to_vec();
    expected_segments.push(crate::BranchPathSegment::new(branch_point, edge));
    assert_eq!(path.segments(), Some(expected_segments.as_slice()));

    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    restarted
        .validate_complete_head(accepted.new_snapshot.content_id())
        .expect("restart-valid nested planner issue");
    let replay = restarted
        .accept_planner_step(
            "planner-nested-path",
            nested_requested.new_snapshot,
            &step,
            usage,
        )
        .expect("replay nested planner issue");
    assert!(replay.replayed);
    assert_eq!(replay.new_snapshot, accepted.new_snapshot);
}

#[test]
fn planner_issue_rejects_a_legacy_parent_path_before_publication() {
    let (repository, lineage, policy, blobs) = counted_fixture();
    let genesis = repository
        .create("planner-legacy-path", &lineage, &policy, &BTreeMap::new())
        .expect("create legacy-path campaign");
    let source_request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "planner-legacy-path-source",
    );
    let requested = repository
        .submit_known_branch_request(
            "planner-legacy-path",
            genesis.snapshot_id(),
            &source_request,
        )
        .expect("submit legacy-path source");
    let source_proposal = finite_proposal(
        &source_request,
        &policy,
        &repository
            .head("planner-legacy-path")
            .expect("source request head"),
        ChoiceValue::Boolean(false),
        1,
    );
    let proposed = repository
        .issue_proposal(
            "planner-legacy-path",
            requested.new_snapshot,
            &source_proposal,
        )
        .expect("issue legacy-path proposal");
    let (selection, _, _) = branch_attempt(&repository, &source_request, &source_proposal);
    let crate::SelectionOrigin::CampaignBranch { edge, .. } = selection.origin() else {
        panic!("campaign branch selection")
    };
    let mut legacy_encoder = crate::codec::Encoder::new();
    crate::codec::Canonical::encode(&1_u32, &mut legacy_encoder);
    crate::codec::Canonical::encode(&vec![edge], &mut legacy_encoder);
    let legacy_path =
        BranchPath::from_canonical_bytes(&legacy_encoder.finish()).expect("legacy branch path");
    assert!(legacy_path.segments().is_none());
    let legacy_attempt = Attempt::new(
        AttemptStart::Branch {
            edge,
            parent: source_request.parent(),
            selection: selection.id().expect("selection id"),
        },
        legacy_path.id().expect("legacy path id"),
        source_request.stop().clone(),
    )
    .expect("legacy-path attempt");
    let admitted = repository
        .admit_proposal(
            "planner-legacy-path",
            proposed.new_snapshot,
            proposed.proposal,
            &selection,
            &legacy_path,
            &legacy_attempt,
        )
        .expect("admit legacy genesis path");

    let child =
        ConfigurationId::from_hash(CampaignHash::derive("test.planner-legacy-path", b"child"));
    let child_content = repository
        .publish_configuration_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            child,
            1,
            b"planner legacy path child".to_vec(),
        )
        .expect("publish child");
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
    let observation = Observation::new(
        admitted.attempt,
        child,
        child_content,
        legacy_path.id().expect("legacy path id"),
        StopOutcome::Reached(StopCondition::NextChoice),
        measurements,
        properties,
        coverage,
        BTreeSet::from([source_request.opportunity()]),
    )
    .expect("legacy-path observation");
    let observed = repository
        .publish_observation("planner-legacy-path", admitted.new_snapshot, &observation)
        .expect("publish legacy-path observation");

    let opportunity = repository
        .load_choice_opportunity(source_request.opportunity())
        .expect("nested opportunity");
    let branch_point = opportunity.branch_point_id(child);
    let nested_request = BranchRequest::new(
        branch_point,
        child_content,
        source_request.opportunity(),
        source_request.domain(),
        source_request.source().clone(),
        BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(CampaignHash::derive(
            "test.planner-legacy-path",
            b"nested request",
        ))),
        source_request.budget(),
        source_request.stop().clone(),
    )
    .expect("nested request");
    let nested_requested = repository
        .submit_known_branch_request(
            "planner-legacy-path",
            observed.new_snapshot,
            &nested_request,
        )
        .expect("submit nested request");
    let engine = PlannerEngine::new("closed-rust", 1, 1, BTreeSet::new()).expect("planner engine");
    let (_, _, invocation) = planner_basis(
        &repository,
        "planner-legacy-path",
        nested_requested.new_snapshot,
        PlannerState::new(
            engine.id().expect("engine id"),
            "closed-rust-state",
            1,
            vec![0],
        )
        .expect("planner state"),
    );
    let nested_proposal = Proposal::new(
        branch_point,
        nested_request.id().expect("nested request id"),
        nested_request.domain(),
        ChoiceValue::Boolean(false),
        policy.id().expect("policy id"),
        Some(invocation.id().expect("invocation id")),
        1,
        invocation.input_view(),
    )
    .expect("nested proposal");
    let usage = PlanningUsage {
        branch_requests: 0,
        proposals: 1,
        input_objects: invocation.scan_page().input_objects(),
        input_bytes: invocation.scan_page().input_bytes(),
        fuel: 3,
    };
    let step = PlannerStepProposal::new(
        invocation.id().expect("invocation id"),
        PlannerState::new(
            engine.id().expect("engine id"),
            "closed-rust-state",
            1,
            vec![1],
        )
        .expect("next planner state"),
        usage,
        GuidanceEvidence::new(BTreeMap::new()).expect("guidance evidence"),
        PlannerProposalDisposition::Issue {
            selected: PlanningScanPosition::new(
                branch_point,
                nested_request.id().expect("nested request id"),
            ),
            branch_requests: Vec::new(),
            proposals: vec![nested_proposal],
        },
    )
    .expect("legacy-parent planner issue");
    let before = blobs.object_count().expect("object count before rejection");
    assert!(matches!(
        repository.accept_planner_step(
            "planner-legacy-path",
            nested_requested.new_snapshot,
            &step,
            usage,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-issue-parent-path-is-legacy"
        })
    ));
    assert_eq!(
        blobs.object_count().expect("object count after rejection"),
        before
    );
    assert_eq!(
        repository
            .head("planner-legacy-path")
            .expect("head after rejection")
            .snapshot_id(),
        nested_requested.new_snapshot
    );
}

#[test]
fn planner_cursor_and_imported_root_fail_closed() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("planner-forgery", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let engine = PlannerEngine::new("closed-rust", 1, 1, BTreeSet::new()).expect("planner engine");
    let initial_state = PlannerState::new(
        engine.id().expect("engine id"),
        "closed-rust-state",
        1,
        vec![0],
    )
    .expect("initial state");
    let (engine, _, invocation) = planner_basis(
        &repository,
        "planner-forgery",
        genesis.snapshot_id(),
        initial_state,
    );
    let fabricated_source = BranchRequestId::from_content_id(ContentId::for_bytes(
        ObjectKind::CampaignFact,
        1,
        b"fabricated planner cursor",
    ))
    .expect("fabricated source");
    let cursor_proposal = PlannerStepProposal::new(
        invocation.id().expect("invocation id"),
        PlannerState::new(
            engine.id().expect("engine id"),
            "closed-rust-state",
            1,
            vec![1],
        )
        .expect("next state"),
        PlanningUsage {
            branch_requests: 0,
            proposals: 0,
            input_objects: 1,
            input_bytes: 1,
            fuel: 1,
        },
        GuidanceEvidence::new(BTreeMap::new()).expect("cursor evidence"),
        PlannerProposalDisposition::ContinueScan {
            cursor: crate::PlanningScanCursor::new(
                invocation.input_view(),
                Some(crate::PlanningScanPosition::new(
                    crate::BranchPointId::from_hash(CampaignHash::derive(
                        "test",
                        b"fabricated branch point",
                    )),
                    fabricated_source,
                )),
            ),
        },
    )
    .expect("cursor proposal");
    let measured = PlanningUsage {
        branch_requests: 0,
        proposals: 0,
        input_objects: 0,
        input_bytes: 0,
        fuel: 1,
    };
    assert!(matches!(
        repository.accept_planner_step(
            "planner-forgery",
            genesis.snapshot_id(),
            &cursor_proposal,
            measured,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-step-scan-cursor-is-not-authoritative"
        })
    ));

    let accepted_proposal = no_work_proposal(
        invocation.id().expect("invocation id"),
        cursor_proposal.next_state().clone(),
    );
    let accepted = repository
        .accept_planner_step(
            "planner-forgery",
            genesis.snapshot_id(),
            &accepted_proposal,
            measured,
        )
        .expect("accept no-work step");
    let accepted_head = repository.head("planner-forgery").expect("accepted head");
    let extra_key = CampaignHash::derive("test", b"forged planner index");
    let forged_coordination = repository
        .merkle
        .insert(
            accepted_head.snapshot().roots().coordination,
            extra_key,
            accepted.step.content_id(),
        )
        .expect("forged root")
        .content_id();
    let mut forged_roots = accepted_head.snapshot().roots();
    forged_roots.coordination = forged_coordination;
    let transition = repository
        .put_fact(&CampaignFact::PlannerAdvanced(accepted.step))
        .expect("planner fact");
    let forged = CampaignSnapshot::successor(
        genesis.snapshot_id(),
        genesis.snapshot().lineage(),
        genesis.snapshot().active_policy(),
        forged_roots,
        CampaignFactId::from_content_id(transition).expect("fact id"),
    )
    .expect("forged snapshot");
    let forged_content = repository
        .put_snapshot(&forged)
        .expect("put forged snapshot");
    assert!(matches!(
        repository.validate_complete_head(forged_content),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-step-transition-coordination-root-mismatch"
        })
    ));
}

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
        "79a28994f5be3954adab2a1d8092ff036717e840f70a067a26e506167b446630",
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
    let planner_bytes = planner_submission.canonical_bytes();
    assert_eq!(
        CampaignHash::derive("crucible.test.planner-submission-vector.v1", &planner_bytes,)
            .to_hex(),
        "7ef3e193d9b56bc42612cabb9a788900349830e49e2cca58b25602ea9539d7a5",
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
    assert_eq!(
        entries.values,
        BTreeSet::from([
            accepted.request.content_id(),
            frontier_index,
            branch_request_index,
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
        // Two permanent entries anchor the frontier and branch-request indexes.
        (MUTATIONS / 2) + 2
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
        .closure_objects = MAX_CAMPAIGN_CLOSURE_OBJECTS - MAX_SIMPLE_SUCCESSOR_GROWTH - 32;
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
        .create("finite-proposal", &lineage, &policy, &BTreeMap::new())
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
        6
    );

    let replay = repository
        .issue_proposal("finite-proposal", genesis.snapshot_id(), &first)
        .expect("replay proposal");
    assert!(replay.replayed);
    assert_eq!(replay.prior_snapshot, accepted.prior_snapshot);
    assert_eq!(replay.new_snapshot, accepted.new_snapshot);
}
