//! Incremental histories, cold validation bounds, exact locators, and cache failure atomicity.

use super::*;

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
                BranchRequest::identity(
                    template.branch_point(),
                    template.parent(),
                    template.opportunity(),
                    template.domain(),
                ),
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
fn cold_ancestry_validation_rejects_a_head_beyond_its_bounded_depth() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("cold-ancestry-limit", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "cold-ancestry-limit",
    );
    let child = repository
        .submit_known_branch_request("cold-ancestry-limit", genesis.snapshot_id(), &request)
        .expect("publish one successor");
    let content = child.new_snapshot.content_id();

    assert!(matches!(
        repository.validate_snapshot_ancestry(content, &mut ChoiceValidationCache::default(), 2),
        Err(CampaignRepositoryError::Integrity {
            reason: "snapshot-ancestry-limit"
        })
    ));
    let (depth, _, _, _) = repository
        .validate_snapshot_ancestry(content, &mut ChoiceValidationCache::default(), 3)
        .expect("three-snapshot cold ancestry");
    assert_eq!(depth, 3);
    assert_eq!(MAX_SNAPSHOT_ANCESTRY, 1_250_001);
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
    const GENERATOR_DEPTH: u32 = crate::ORDERED_MIXTURE_GENERATOR_MAX_DEPTH as u32;

    let (repository, lineage, _) = fixture();
    let leaf = CandidateGeneratorSpec::new(
        crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::All,
    )
    .expect("leaf generator");
    let mut generator = leaf.id().expect("leaf generator id");
    let mut generators = BTreeMap::from([(generator, leaf)]);
    for _ in 2..=GENERATOR_DEPTH {
        let parent = CandidateGeneratorSpec::new(
            crate::ORDERED_MIXTURE_GENERATOR_IMPLEMENTATION_VERSION,
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
        BranchRequest::identity(
            template.branch_point(),
            template.parent(),
            template.opportunity(),
            template.domain(),
        ),
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
        crate::test_budget_ledger_id(),
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
