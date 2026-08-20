//! Imported-history, closure, identity, and owner-validation repository tests.

use super::*;

#[test]
fn branch_request_staleness_and_campaign_scope_fail_before_ref_advance() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("scope", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "stale-request",
    );
    let stale = CampaignSnapshotId::from_content_id(ContentId::for_bytes(
        ObjectKind::CampaignSnapshot,
        2,
        b"stale-request",
    ))
    .expect("stale id");
    assert!(matches!(
        repository.submit_known_branch_request("scope", stale, &request),
        Err(CampaignRepositoryError::Stale { .. })
    ));
    assert_eq!(
        repository.head("scope").expect("head").snapshot_id(),
        genesis.snapshot_id()
    );

    let outside_configuration =
        ConfigurationId::from_hash(CampaignHash::derive("test", b"outside-configuration"));
    let outside = repository
        .publish_configuration_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            outside_configuration,
            1,
            b"outside".to_vec(),
        )
        .expect("outside configuration");
    let outside_request = branch_request(
        &repository,
        &lineage,
        outside,
        outside_configuration,
        "outside-request",
    );
    assert!(matches!(
        repository.discover_choice_opportunity(
            "scope",
            genesis.snapshot_id(),
            outside_request.parent(),
            outside_request.opportunity(),
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "choice-discovery-parent-is-not-in-campaign-graph"
        })
    ));
    assert_eq!(
        repository.head("scope").expect("head").snapshot_id(),
        genesis.snapshot_id()
    );
}

#[test]
fn generated_branch_requests_validate_the_complete_domain_compatible_spec() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("generators", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let finite = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "generator-opportunity",
    );
    let integer = CandidateGeneratorSpec::new(
        1,
        CandidateGeneratorAlgorithm::ProgressiveInteger {
            initial_strata: 2,
            feedback_interval: 1,
        },
    )
    .expect("integer generator");
    let integer_id = repository
        .publish_generator(&integer)
        .expect("publish integer generator");
    let incompatible = BranchRequest::new(
        finite.branch_point(),
        finite.parent(),
        finite.opportunity(),
        finite.domain(),
        CandidateSource::generated(integer_id),
        BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(CampaignHash::derive(
            "test",
            b"incompatible-generator",
        ))),
        BranchBudget::new(2, 2).expect("budget"),
        StopCondition::NextChoice,
    )
    .expect("incompatible request");
    assert!(matches!(
        repository.submit_known_branch_request("generators", genesis.snapshot_id(), &incompatible,),
        Err(CampaignRepositoryError::Integrity {
            reason: "candidate-generator-domain-family-mismatch"
        })
    ));

    let mixture = CandidateGeneratorSpec::new(
        1,
        CandidateGeneratorAlgorithm::OrderedMixture {
            components: vec![WeightedGenerator::new(integer_id, 1).expect("component")],
        },
    )
    .expect("mixture");
    let mixture_id = repository
        .publish_generator(&mixture)
        .expect("publish mixture");
    let incompatible_mixture = BranchRequest::new(
        finite.branch_point(),
        finite.parent(),
        finite.opportunity(),
        finite.domain(),
        CandidateSource::generated(mixture_id),
        BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(CampaignHash::derive(
            "test",
            b"incompatible-mixture",
        ))),
        BranchBudget::new(2, 2).expect("budget"),
        StopCondition::NextChoice,
    )
    .expect("mixture request");
    assert!(matches!(
        repository.submit_known_branch_request(
            "generators",
            genesis.snapshot_id(),
            &incompatible_mixture,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "candidate-generator-domain-family-mismatch"
        })
    ));

    let all =
        CandidateGeneratorSpec::new(1, CandidateGeneratorAlgorithm::All).expect("all generator");
    let all_id = repository
        .publish_generator(&all)
        .expect("publish all generator");
    let first_domain = repository
        .load_choice_domain(finite.domain())
        .expect("first compatible domain");
    let second_domain =
        ChoiceDomain::Boolean(BooleanDomain::new(2).expect("second compatible boolean domain"));
    let mut aggregate_work = 1;
    repository
        .validate_generator_for_domain_with_budget(all_id, &first_domain, &mut aggregate_work)
        .expect("first aggregate validation");
    assert_eq!(aggregate_work, 0);
    assert!(matches!(
        repository.validate_generator_for_domain_with_budget(
            all_id,
            &second_domain,
            &mut aggregate_work,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "candidate-generator-validation-limit"
        })
    ));
    let valid = BranchRequest::new(
        finite.branch_point(),
        finite.parent(),
        finite.opportunity(),
        finite.domain(),
        CandidateSource::generated(all_id),
        BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(CampaignHash::derive(
            "test",
            b"valid-generator",
        ))),
        BranchBudget::new(2, 2).expect("budget"),
        StopCondition::NextChoice,
    )
    .expect("valid generated request");
    let generated = repository
        .submit_known_branch_request("generators", genesis.snapshot_id(), &valid)
        .expect("accept compatible generator");
    assert!(matches!(
        repository
            .project_finite_expansion(generated.new_snapshot, valid.branch_point(), None, 10,),
        Err(CampaignRepositoryError::Integrity {
            reason: "generated-expansion-projector-is-not-implemented"
        })
    ));
}

#[test]
fn ancestry_rejects_branch_request_with_an_unrelated_root_change() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("forged-request", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "forged-request",
    );
    let discovered = repository
        .discover_choice_opportunity(
            "forged-request",
            genesis.snapshot_id(),
            request.parent(),
            request.opportunity(),
        )
        .expect("discover forged-request opportunity");
    let parent = repository
        .read_snapshot(discovered.new_snapshot.content_id())
        .expect("discovery parent");
    let request_content = repository
        .put_branch_request(&request)
        .expect("put request");
    let request_id = BranchRequestId::from_content_id(request_content).expect("request id");
    let transition_content = repository
        .put_fact(&CampaignFact::BranchRequestIssued(request_id))
        .expect("put transition");
    let mut roots = parent.snapshot.roots();
    roots.exploration = repository
        .merkle
        .insert(
            roots.exploration,
            map_key_content("exploration.branch-request", request_content),
            request_content,
        )
        .expect("request root")
        .content_id();
    let next_frontier = repository
        .frontier_index_after(
            parent.snapshot.roots().exploration,
            &[(
                request_id,
                request.branch_point(),
                CampaignRepository::initial_continuation_state(&request),
            )],
            true,
        )
        .expect("frontier projection")
        .expect("frontier index");
    roots.exploration = repository
        .merkle
        .insert(
            roots.exploration,
            frontier_index_anchor_key(),
            next_frontier,
        )
        .expect("frontier root")
        .content_id();
    roots.accounting = repository
        .merkle
        .insert(
            roots.accounting,
            map_key_content("accounting.forged", request_content),
            request_content,
        )
        .expect("forged accounting root")
        .content_id();
    let forged = CampaignSnapshot::successor(
        discovered.new_snapshot,
        parent.snapshot.lineage(),
        parent.snapshot.active_policy(),
        roots,
        CampaignFactId::from_content_id(transition_content).expect("transition id"),
    )
    .expect("forged snapshot");
    let forged_content = repository
        .put_snapshot(&forged)
        .expect("put forged snapshot");

    assert!(matches!(
        repository.validate_complete_head(forged_content),
        Err(CampaignRepositoryError::Integrity {
            reason: "branch-request-transition-accounting-root-mismatch"
        })
    ));
}

#[test]
fn ancestry_rejects_a_forged_initial_frontier_projection() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("forged-frontier", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "forged-frontier",
    );
    let discovered = repository
        .discover_choice_opportunity(
            "forged-frontier",
            genesis.snapshot_id(),
            request.parent(),
            request.opportunity(),
        )
        .expect("discover forged-frontier opportunity");
    let parent = repository
        .read_snapshot(discovered.new_snapshot.content_id())
        .expect("discovery parent");
    let request_content = repository
        .put_branch_request(&request)
        .expect("put request");
    let request_id = BranchRequestId::from_content_id(request_content).expect("request id");
    let transition_content = repository
        .put_fact(&CampaignFact::BranchRequestIssued(request_id))
        .expect("put transition");

    let mut roots = parent.snapshot.roots();
    roots.exploration = repository
        .merkle
        .insert(
            roots.exploration,
            map_key_content("exploration.branch-request", request_content),
            request_content,
        )
        .expect("request root")
        .content_id();
    let forged_frontier = repository
        .frontier_index_after(
            parent.snapshot.roots().exploration,
            &[(
                request_id,
                request.branch_point(),
                ContinuationState::Closed,
            )],
            true,
        )
        .expect("forged frontier projection")
        .expect("frontier index");
    roots.exploration = repository
        .merkle
        .insert(
            roots.exploration,
            frontier_index_anchor_key(),
            forged_frontier,
        )
        .expect("frontier root")
        .content_id();
    let BranchRequestCause::Operator(command) = request.cause() else {
        panic!("operator request")
    };
    roots.accounting = repository
        .merkle
        .insert(
            roots.accounting,
            map_key_hash("accounting.command", command.as_hash()),
            transition_content,
        )
        .expect("command root")
        .content_id();
    roots.coordination = repository
        .coordination_with_parent_result(discovered.new_snapshot.content_id(), &parent)
        .expect("coordination root");
    let forged = CampaignSnapshot::successor(
        discovered.new_snapshot,
        parent.snapshot.lineage(),
        parent.snapshot.active_policy(),
        roots,
        CampaignFactId::from_content_id(transition_content).expect("transition id"),
    )
    .expect("forged snapshot");
    let forged_content = repository
        .put_snapshot(&forged)
        .expect("put forged snapshot");

    let validation = repository.validate_complete_head(forged_content);
    assert!(
        matches!(
            validation,
            Err(CampaignRepositoryError::Integrity {
                reason: "branch-request-transition-exploration-root-mismatch"
            })
        ),
        "unexpected forged frontier validation result: {validation:?}"
    );
}

#[test]
fn imported_ancestry_rejects_cross_type_mutation_command_reuse() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("duplicate-command", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "shared-command",
    );
    let accepted = repository
        .submit_known_branch_request("duplicate-command", genesis.snapshot_id(), &request)
        .expect("accept request");
    let head = repository.head("duplicate-command").expect("head");
    let BranchRequestCause::Operator(command_id) = request.cause() else {
        panic!("operator request")
    };
    let control = ControlRequest {
        command: command_id,
        expected_snapshot: accepted.new_snapshot,
        action: CampaignControlAction::Resume,
    };
    let transition_content = repository
        .put_fact(&CampaignFact::ControlRequested(control.clone()))
        .expect("put control");
    let mut roots = head.snapshot().roots();
    roots.accounting = repository
        .merkle
        .insert(
            roots.accounting,
            map_key_hash("accounting.command", command_id.as_hash()),
            transition_content,
        )
        .expect("accounting root")
        .content_id();
    let forged = CampaignSnapshot::successor(
        accepted.new_snapshot,
        head.snapshot().lineage(),
        head.snapshot().active_policy(),
        roots,
        CampaignFactId::from_content_id(transition_content).expect("transition id"),
    )
    .expect("forged snapshot");
    let forged_content = repository
        .put_snapshot(&forged)
        .expect("put forged snapshot");
    let campaign_ref = campaign_ref("duplicate-command").expect("campaign ref");
    repository
        .refs
        .compare_exchange(&campaign_ref, Some(head.content_id()), forged_content)
        .expect("forge ref");

    assert!(matches!(
        repository.head("duplicate-command"),
        Err(CampaignRepositoryError::Integrity {
            reason: "control-transition-reused-command"
        })
    ));
}

#[test]
fn command_replay_precedes_stale_check_and_preserves_response() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("test", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let resume = command(
        "resume",
        genesis.snapshot_id(),
        CampaignControlAction::Resume,
    );
    let first = repository.apply_control("test", &resume).expect("resume");
    let pause = command(
        "pause",
        first.new_snapshot,
        CampaignControlAction::Pause(crate::ActiveAttemptPolicy::Drain),
    );
    repository.apply_control("test", &pause).expect("pause");

    let replay = repository.apply_control("test", &resume).expect("replay");
    assert!(replay.replayed);
    assert_eq!(replay.prior_snapshot, first.prior_snapshot);
    assert_eq!(replay.new_snapshot, first.new_snapshot);

    let reused = ControlRequest {
        command: resume.command,
        expected_snapshot: resume.expected_snapshot,
        action: CampaignControlAction::Complete,
    };
    assert!(matches!(
        repository.apply_control("test", &reused),
        Err(CampaignRepositoryError::CommandReuse)
    ));
}

#[test]
fn stale_and_invalid_transitions_do_not_advance_head() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("test", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let stale = command(
        "stale",
        CampaignSnapshotId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignSnapshot,
            2,
            b"stale",
        ))
        .expect("stale snapshot id"),
        CampaignControlAction::Resume,
    );
    assert!(matches!(
        repository.apply_control("test", &stale),
        Err(CampaignRepositoryError::Stale { .. })
    ));
    assert_eq!(
        repository.head("test").expect("head").snapshot_id(),
        genesis.snapshot_id()
    );

    let invalid = command(
        "invalid",
        genesis.snapshot_id(),
        CampaignControlAction::Pause(crate::ActiveAttemptPolicy::Drain),
    );
    assert!(matches!(
        repository.apply_control("test", &invalid),
        Err(CampaignRepositoryError::InvalidTransition {
            state: CampaignState::Created
        })
    ));
    assert_eq!(
        repository.head("test").expect("head").snapshot_id(),
        genesis.snapshot_id()
    );
}

#[test]
fn nonempty_policy_round_trips_and_missing_generator_fails_before_ref_publication() {
    let (repository, lineage, _) = fixture();
    let generator =
        CandidateGeneratorSpec::new(1, CandidateGeneratorAlgorithm::All).expect("generator");
    let generator_id = generator.id().expect("generator id");
    let policy = policy_with_generator(lineage.scenario(), generator_id);
    let generators = BTreeMap::from([(generator_id, generator)]);

    let created = repository
        .create("with-generator", &lineage, &policy, &generators)
        .expect("create with generator");
    assert_eq!(
        repository
            .head("with-generator")
            .expect("authenticated head")
            .snapshot_id(),
        created.snapshot_id()
    );

    let missing = CandidateGeneratorSpecId::from_content_id(ContentId::for_bytes(
        ObjectKind::Policy,
        1,
        b"missing-generator",
    ))
    .expect("missing generator id");
    let missing_policy = policy_with_generator(lineage.scenario(), missing);
    assert!(matches!(
        repository.create(
            "missing-generator",
            &lineage,
            &missing_policy,
            &BTreeMap::new(),
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "campaign-policy-generator-was-not-supplied"
        })
    ));
    assert!(matches!(
        repository.head("missing-generator"),
        Err(CampaignRepositoryError::NotFound)
    ));
}

#[test]
fn closure_walker_rejects_missing_generator_grandchildren() {
    let (repository, lineage, _, blobs) = counted_fixture();
    let missing = CandidateGeneratorSpecId::from_content_id(ContentId::for_bytes(
        ObjectKind::Policy,
        1,
        b"missing-mixture-child",
    ))
    .expect("missing child");
    let mixture = CandidateGeneratorSpec::new(
        1,
        CandidateGeneratorAlgorithm::OrderedMixture {
            components: vec![WeightedGenerator::new(missing, 1).expect("weighted child")],
        },
    )
    .expect("mixture");
    let mixture_id = mixture.id().expect("mixture id");
    let policy = policy_with_generator(lineage.scenario(), mixture_id);
    let objects_before = blobs.object_count().expect("objects before rejection");

    assert!(matches!(
        repository.create(
            "incomplete-closure",
            &lineage,
            &policy,
            &BTreeMap::from([(mixture_id, mixture)]),
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "campaign-policy-generator-was-not-supplied"
        })
    ));
    assert_eq!(
        blobs.object_count().expect("objects after rejection"),
        objects_before,
        "an incomplete generator closure wrote immutable objects"
    );
    assert!(matches!(
        repository.head("incomplete-closure"),
        Err(CampaignRepositoryError::NotFound)
    ));
}

#[test]
fn generator_publication_rejects_missing_children_before_writing() {
    let (repository, _, _, blobs) = counted_fixture();
    let missing = CandidateGeneratorSpecId::from_content_id(ContentId::for_bytes(
        ObjectKind::Policy,
        1,
        b"missing-published-generator-child",
    ))
    .expect("missing child");
    let generator = CandidateGeneratorSpec::new(
        1,
        CandidateGeneratorAlgorithm::OrderedMixture {
            components: vec![WeightedGenerator::new(missing, 1).expect("weighted child")],
        },
    )
    .expect("generator");
    let objects_before = blobs.object_count().expect("objects before rejection");

    assert!(matches!(
        repository.publish_generator(&generator),
        Err(CampaignRepositoryError::Store(StoreError::NotFound { .. }))
    ));
    assert_eq!(
        blobs.object_count().expect("objects after rejection"),
        objects_before,
        "a generator with a missing child wrote its immutable parent"
    );
}

#[test]
fn creation_rejects_unrelated_generators_before_publication() {
    let (repository, lineage, policy, blobs) = counted_fixture();
    let unrelated =
        CandidateGeneratorSpec::new(1, CandidateGeneratorAlgorithm::All).expect("generator");
    let unrelated_id = unrelated.id().expect("generator id");
    let objects_before = blobs.object_count().expect("objects before rejection");

    assert!(matches!(
        repository.create(
            "unrelated-generator",
            &lineage,
            &policy,
            &BTreeMap::from([(unrelated_id, unrelated)]),
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "campaign-generator-map-has-unreachable-record"
        })
    ));
    assert_eq!(
        blobs.object_count().expect("objects after rejection"),
        objects_before,
        "an unrelated generator wrote immutable objects"
    );
    assert!(matches!(
        repository.head("unrelated-generator"),
        Err(CampaignRepositoryError::NotFound)
    ));
}

#[test]
fn creation_generator_byte_budget_is_checked_at_the_boundary() {
    let mut bytes = crate::MAX_CREATE_CAMPAIGN_GENERATOR_BYTES - 1;
    super::super::transactions::charge_creation_generator_bytes(&mut bytes, 1)
        .expect("exact generator byte boundary");
    assert_eq!(bytes, crate::MAX_CREATE_CAMPAIGN_GENERATOR_BYTES);
    assert!(matches!(
        super::super::transactions::charge_creation_generator_bytes(&mut bytes, 1),
        Err(CampaignRepositoryError::Integrity {
            reason: "campaign-generator-byte-limit"
        })
    ));
    assert_eq!(bytes, crate::MAX_CREATE_CAMPAIGN_GENERATOR_BYTES);
}

#[test]
fn head_rejects_a_snapshot_with_missing_parent_and_transition() {
    let (repository, lineage, policy) = fixture();
    let created = repository
        .create("damaged", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let missing_parent = CampaignSnapshotId::from_content_id(ContentId::for_bytes(
        ObjectKind::CampaignSnapshot,
        2,
        b"missing-parent",
    ))
    .expect("parent id");
    let missing_transition = crate::CampaignFactId::from_content_id(ContentId::for_bytes(
        ObjectKind::CampaignFact,
        2,
        b"missing-transition",
    ))
    .expect("transition id");
    let damaged = CampaignSnapshot::successor(
        missing_parent,
        created.snapshot().lineage(),
        created.snapshot().active_policy(),
        created.snapshot().roots(),
        missing_transition,
    )
    .expect("damaged snapshot");
    let damaged_content = repository.put_snapshot(&damaged).expect("put damaged");
    let campaign_ref = campaign_ref("damaged").expect("campaign ref");
    assert!(matches!(
        repository
            .refs
            .compare_exchange(&campaign_ref, Some(created.content_id()), damaged_content)
            .expect("advance ref"),
        RefCasOutcome::Advanced { .. }
    ));

    assert!(matches!(
        repository.head("damaged"),
        Err(CampaignRepositoryError::Store(StoreError::NotFound { .. }))
    ));
}

#[test]
fn head_rejects_forged_control_successors_and_noncontrol_transitions() {
    let (repository, lineage, policy) = fixture();
    let created = repository
        .create("forged", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let request = command(
        "forged-resume",
        created.snapshot_id(),
        CampaignControlAction::Resume,
    );
    let transition = CampaignFact::ControlRequested(request.clone());
    let transition_content = repository.put_fact(&transition).expect("put transition");
    let accounting = repository
        .merkle
        .insert(
            created.snapshot().roots().accounting,
            map_key_hash("accounting.command", request.command.as_hash()),
            transition_content,
        )
        .expect("accounting root");
    let mut changed_roots = created.snapshot().roots();
    changed_roots.accounting = accounting.content_id();
    changed_roots.coverage = changed_roots.graph;
    let forged = CampaignSnapshot::successor(
        created.snapshot_id(),
        created.snapshot().lineage(),
        created.snapshot().active_policy(),
        changed_roots,
        CampaignFactId::from_content_id(transition_content).expect("transition id"),
    )
    .expect("forged snapshot");
    let forged_content = repository
        .put_snapshot(&forged)
        .expect("put forged snapshot");
    let forged_ref = campaign_ref("forged").expect("campaign ref");
    repository
        .refs
        .compare_exchange(&forged_ref, Some(created.content_id()), forged_content)
        .expect("advance ref");
    assert!(matches!(
        repository.head("forged"),
        Err(CampaignRepositoryError::Integrity {
            reason: "control-transition-changed-nonaccounting-root"
        })
    ));

    let (repository, lineage, policy) = fixture();
    let created = repository
        .create("noncontrol", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let noncontrol = CampaignFact::BudgetGranted(BudgetGrant::new(1, 0).expect("grant"));
    let transition_content = repository.put_fact(&noncontrol).expect("put fact");
    let forged = CampaignSnapshot::successor(
        created.snapshot_id(),
        created.snapshot().lineage(),
        created.snapshot().active_policy(),
        created.snapshot().roots(),
        CampaignFactId::from_content_id(transition_content).expect("transition id"),
    )
    .expect("forged snapshot");
    let forged_content = repository
        .put_snapshot(&forged)
        .expect("put forged snapshot");
    let noncontrol_ref = campaign_ref("noncontrol").expect("campaign ref");
    repository
        .refs
        .compare_exchange(&noncontrol_ref, Some(created.content_id()), forged_content)
        .expect("advance ref");
    assert!(matches!(
        repository.head("noncontrol"),
        Err(CampaignRepositoryError::Integrity {
            reason: "snapshot-transition-type-is-not-implemented"
        })
    ));
}

#[test]
fn imported_derivation_rejects_changed_semantic_roots() {
    let (repository, lineage, policy) = fixture();
    let source = repository
        .create("forged-derive-source", &lineage, &policy, &BTreeMap::new())
        .expect("create source");
    let loaded_source = repository
        .read_snapshot(source.content_id())
        .expect("load source");
    let transition_content = repository
        .put_fact(&CampaignFact::CampaignDerived(CampaignDerivation::new(
            source.snapshot_id(),
            source.snapshot().active_policy(),
        )))
        .expect("put derivation fact");
    let mut roots = source.snapshot().roots();
    roots.coordination = repository
        .coordination_with_parent_result(source.content_id(), &loaded_source)
        .expect("coordination root");
    roots.coverage = roots.graph;
    let forged = CampaignSnapshot::successor(
        source.snapshot_id(),
        source.snapshot().lineage(),
        source.snapshot().active_policy(),
        roots,
        CampaignFactId::from_content_id(transition_content).expect("transition id"),
    )
    .expect("forged derivation");
    let forged_content = repository
        .put_snapshot(&forged)
        .expect("put forged derivation");
    repository
        .refs
        .compare_exchange(
            &campaign_ref("forged-derive-target").expect("target ref"),
            None,
            forged_content,
        )
        .expect("install forged target");

    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    assert!(matches!(
        restarted.head("forged-derive-target"),
        Err(CampaignRepositoryError::Integrity {
            reason: "derivation-transition-changed-semantic-root"
        })
    ));
}

#[test]
fn imported_derivation_enforces_the_bounded_generator_closure() {
    let (repository, lineage, policy, blobs) = counted_fixture();
    let source = repository
        .create("bounded-derive-source", &lineage, &policy, &BTreeMap::new())
        .expect("create source");
    let mut generator =
        CandidateGeneratorSpec::new(1, CandidateGeneratorAlgorithm::All).expect("base generator");
    let mut generator_id = CandidateGeneratorSpecId::from_content_id(
        repository
            .put_generator(&generator)
            .expect("put base generator"),
    )
    .expect("base generator id");
    for _ in 0..crate::MAX_CREATE_CAMPAIGN_GENERATORS {
        generator = CandidateGeneratorSpec::new(
            1,
            CandidateGeneratorAlgorithm::OrderedMixture {
                components: vec![
                    WeightedGenerator::new(generator_id, 1).expect("weighted generator"),
                ],
            },
        )
        .expect("linked generator");
        generator_id = CandidateGeneratorSpecId::from_content_id(
            repository
                .put_generator(&generator)
                .expect("put linked generator"),
        )
        .expect("linked generator id");
    }
    let oversized_policy = policy_with_generator(lineage.scenario(), generator_id);
    let oversized_policy_id = CampaignPolicyId::from_content_id(
        repository
            .put_policy(&oversized_policy)
            .expect("put oversized policy"),
    )
    .expect("oversized policy id");
    let loaded_source = repository
        .read_snapshot(source.content_id())
        .expect("load source");
    let transition_content = repository
        .put_fact(&CampaignFact::CampaignDerived(CampaignDerivation::new(
            source.snapshot_id(),
            oversized_policy_id,
        )))
        .expect("put derivation fact");
    let mut roots = source.snapshot().roots();
    roots.coordination = repository
        .coordination_with_parent_result(source.content_id(), &loaded_source)
        .expect("coordination root");
    let forged = CampaignSnapshot::successor(
        source.snapshot_id(),
        source.snapshot().lineage(),
        oversized_policy_id,
        roots,
        CampaignFactId::from_content_id(transition_content).expect("transition id"),
    )
    .expect("forged derivation");
    let forged_content = repository
        .put_snapshot(&forged)
        .expect("put forged derivation");
    repository
        .refs
        .compare_exchange(
            &campaign_ref("bounded-derive-target").expect("target ref"),
            None,
            forged_content,
        )
        .expect("install forged target");
    let objects_before = blobs.object_count().expect("objects before validation");

    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    assert!(matches!(
        restarted.head("bounded-derive-target"),
        Err(CampaignRepositoryError::Integrity {
            reason: "campaign-generator-count-limit"
        })
    ));
    assert_eq!(
        blobs.object_count().expect("objects after validation"),
        objects_before,
        "import validation wrote while rejecting an oversized generator closure"
    );
}

#[test]
fn head_rejects_genesis_without_canonical_configuration_membership() {
    let (repository, lineage, policy) = fixture();
    let lineage_content = repository.put_lineage(&lineage).expect("lineage");
    let policy_content = repository.put_policy(&policy).expect("policy");
    let empty = repository.merkle.empty().expect("empty root").content_id();
    let malformed = CampaignSnapshot::genesis(
        CampaignLineageId::from_content_id(lineage_content).expect("lineage id"),
        CampaignPolicyId::from_content_id(policy_content).expect("policy id"),
        crate::CampaignRoots {
            graph: empty,
            exploration: empty,
            observations: empty,
            corpus: empty,
            coverage: empty,
            findings: empty,
            pins: empty,
            accounting: empty,
            coordination: empty,
        },
    )
    .expect("malformed genesis");
    let content = repository.put_snapshot(&malformed).expect("snapshot");
    let campaign_ref = campaign_ref("missing-genesis").expect("campaign ref");
    repository
        .refs
        .compare_exchange(&campaign_ref, None, content)
        .expect("publish malformed head");
    assert!(matches!(
        repository.head("missing-genesis"),
        Err(CampaignRepositoryError::Integrity {
            reason: "genesis-configuration-root-mismatch"
        })
    ));
}

#[test]
fn imported_lineages_revalidate_scenario_and_configuration_bindings() {
    let (repository, lineage, _) = fixture();
    let other_scenario = ScenarioDefId::from_hash(CampaignHash::derive("test", b"other"));
    let mismatched_lineage = CampaignLineage::new(
        other_scenario,
        lineage.scenario_content(),
        lineage.genesis(),
        lineage.genesis_content(),
        lineage.crucible_version(),
        lineage.qemu_build(),
        lineage.protocol_versions().clone(),
        lineage.scenario_schema(),
        lineage.exact_closure_schema(),
    )
    .expect("structurally valid lineage");
    let content = repository
        .put_lineage(&mismatched_lineage)
        .expect("put mismatched lineage");
    assert!(matches!(
        repository.read_lineage(content),
        Err(CampaignRepositoryError::Integrity {
            reason: "lineage-execution-model-artifact-mismatch"
        })
    ));

    let mismatched_configuration = ConfigurationArtifact::new(
        other_scenario,
        lineage.scenario_content(),
        lineage.genesis(),
        1,
        b"mismatched configuration".to_vec(),
    )
    .expect("configuration");
    let content = repository
        .put_configuration_artifact(&mismatched_configuration)
        .expect("put configuration");
    assert!(matches!(
        repository.read_configuration_artifact(content),
        Err(CampaignRepositoryError::Integrity {
            reason: "configuration-scenario-artifact-mismatch"
        })
    ));
}

#[test]
fn every_reachable_merkle_root_uses_the_owner_validator() {
    let (repository, _, _) = fixture();
    let malformed = ObjectEnvelope::for_record(
        crate::CampaignRecordKind::MerkleNode,
        BTreeSet::new(),
        vec![0],
    )
    .expect("structural malformed node");
    let malformed_content = repository
        .put_envelope(malformed)
        .expect("put malformed node");
    let empty = repository.merkle.empty().expect("empty root").content_id();
    let view =
        CampaignPlanningView::new(malformed_content, empty, empty, empty, empty, empty, empty)
            .expect("planning view");
    let view_envelope = ObjectEnvelope::for_record(
        crate::CampaignRecordKind::PlanningView,
        crate::object::content_children(view.content_children()).expect("children"),
        view.canonical_bytes(),
    )
    .expect("view envelope");
    let view_content = repository.put_envelope(view_envelope).expect("put view");
    assert!(matches!(
        repository.verify_campaign_closure(view_content),
        Err(CampaignRepositoryError::Merkle(_))
    ));
}

#[test]
fn planner_invocations_bind_artifact_and_state_to_one_engine() {
    let (repository, _, policy) = fixture();
    let engine_a = PlannerEngine::new("engine-a", 1, 1, BTreeSet::new()).expect("engine A");
    let engine_b = PlannerEngine::new("engine-b", 1, 1, BTreeSet::new()).expect("engine B");
    for engine in [&engine_a, &engine_b] {
        repository
            .put_envelope(
                ObjectEnvelope::for_record(
                    crate::CampaignRecordKind::PlannerEngine,
                    BTreeSet::new(),
                    crate::codec::encode(engine),
                )
                .expect("engine envelope"),
            )
            .expect("put engine");
    }

    let dependency_bytes = b"planner dependency".to_vec();
    let dependency = ContentId::for_bytes(ObjectKind::Trace, 1, &dependency_bytes);
    repository
        .blobs
        .put_if_absent(dependency, &BlobHandle::from_bytes(dependency_bytes))
        .expect("put dependency");
    let artifact = PolicyArtifact::new(
        engine_a.id().expect("engine A id"),
        1,
        dependency,
        BTreeSet::new(),
        BTreeMap::new(),
    )
    .expect("artifact");
    repository
        .put_envelope(
            ObjectEnvelope::for_record(
                crate::CampaignRecordKind::PolicyArtifact,
                crate::object::content_children(artifact.content_children())
                    .expect("artifact children"),
                crate::codec::encode(&artifact),
            )
            .expect("artifact envelope"),
        )
        .expect("put artifact");
    let state = PlannerState::new(
        engine_b.id().expect("engine B id"),
        "test-state",
        1,
        Vec::new(),
    )
    .expect("state");
    repository
        .put_envelope(
            ObjectEnvelope::for_record(
                crate::CampaignRecordKind::PlannerState,
                crate::object::content_children([("engine", state.engine().content_id())])
                    .expect("state children"),
                crate::codec::encode(&state),
            )
            .expect("state envelope"),
        )
        .expect("put state");
    repository.put_policy(&policy).expect("put policy");

    let empty = repository.merkle.empty().expect("empty root").content_id();
    let view =
        CampaignPlanningView::new(empty, empty, empty, empty, empty, empty, empty).expect("view");
    repository
        .put_envelope(
            ObjectEnvelope::for_record(
                crate::CampaignRecordKind::PlanningView,
                crate::object::content_children(view.content_children()).expect("view children"),
                view.canonical_bytes(),
            )
            .expect("view envelope"),
        )
        .expect("put view");
    let invocation = PlannerInvocation::new(
        engine_a.id().expect("engine A id"),
        artifact.id().expect("artifact id"),
        policy.id().expect("policy id"),
        state.id().expect("state id"),
        view.id().expect("view id"),
        PlanningScanPage::new(None, 1, Vec::new(), true, 0).expect("scan page"),
        PlanningBudget::new(1, 1, 1, 1, 1).expect("budget"),
    )
    .expect("invocation");
    let invocation_content = repository
        .put_envelope(
            ObjectEnvelope::for_record(
                crate::CampaignRecordKind::PlannerInvocation,
                crate::object::content_children(invocation.content_children())
                    .expect("invocation children"),
                crate::codec::encode(&invocation),
            )
            .expect("invocation envelope"),
        )
        .expect("put invocation");
    assert!(matches!(
        repository.verify_campaign_closure(invocation_content),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-invocation-engine-mismatch"
        })
    ));
}

#[test]
fn unowned_fact_reference_families_fail_closed() {
    let (repository, lineage, _) = fixture();
    let lineage_content = repository.put_lineage(&lineage).expect("lineage");
    let asserted_branch_request = crate::BranchRequestId::from_content_id(lineage_content)
        .expect("same broad-kind asserted ID");
    let fact = CampaignFact::BranchRequestIssued(asserted_branch_request);
    let fact_content = repository.put_fact(&fact).expect("put fact");
    assert!(matches!(
        repository.verify_campaign_closure(fact_content),
        Err(CampaignRepositoryError::Integrity {
            reason: "campaign-child-record-kind-mismatch"
        })
    ));
}
