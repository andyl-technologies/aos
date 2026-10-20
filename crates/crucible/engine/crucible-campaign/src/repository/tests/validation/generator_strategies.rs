//! Corpus and static integer generator strategy regressions.

use super::*;

#[test]
fn corpus_mutation_generator_tracks_retained_values_by_portable_proposal_set() {
    let (repository, lineage, base_policy, blobs) = counted_fixture();
    let policy = CampaignPolicy::new(
        CampaignPolicy::identity(
            base_policy.scenario(),
            base_policy.campaign_seed(),
            CampaignMode::Streaming,
            base_policy.explorer().clone(),
        ),
        CampaignPolicy::rules(
            base_policy.choice_policies().clone(),
            base_policy.objectives().clone(),
            base_policy.guidance().clone(),
            base_policy.stop_conditions().clone(),
            base_policy.fairness(),
            base_policy.retention(),
            base_policy.admits_scenario_defaults(),
        ),
    )
    .expect("fast corpus-mutation policy");
    repository
        .publish_policy(&policy)
        .expect("publish fast corpus-mutation policy");
    let genesis = repository
        .create_funded(
            "generated-corpus-mutation",
            &lineage,
            &policy,
            &BTreeMap::new(),
        )
        .expect("create corpus-mutation campaign");
    let domain = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(10),
            1,
            None,
            ExactRational::new(1, 1).expect("scale"),
            Vec::new(),
        )
        .expect("corpus-mutation domain"),
    );
    let generator = CandidateGeneratorSpec::new(
        crate::CORPUS_MUTATION_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::MutateNearCorpus {
            maximum_distance: 2,
        },
    )
    .expect("corpus-mutation generator");
    let generator_id = repository
        .publish_generator(&generator)
        .expect("publish corpus-mutation generator");
    let (_, mutation_request) = generated_integer_request(
        &repository,
        &lineage,
        domain.clone(),
        IntegerValue::Unsigned(8),
        generator_id,
        "corpus-mutation",
        8,
    );
    let mutation_summary = repository
        .branch_acceptance_summary(
            repository
                .head("generated-corpus-mutation")
                .expect("corpus-mutation campaign head")
                .snapshot()
                .roots()
                .graph,
            &mutation_request,
        )
        .expect("history-sensitive acceptance summary");
    assert_eq!(
        mutation_summary.validated_cardinality(),
        BranchAcceptanceCount::between(0, 11).expect("source cardinality bounds")
    );
    assert_eq!(
        mutation_summary.remaining_lazy_candidates(),
        BranchAcceptanceCount::between(0, 8).expect("proposal-window bounds")
    );
    let seed_request = BranchRequest::new(
        BranchRequest::identity(
            mutation_request.branch_point(),
            mutation_request.parent(),
            mutation_request.opportunity(),
            mutation_request.domain(),
        ),
        CandidateSource::finite(BTreeSet::from([ChoiceValue::Integer(
            IntegerValue::Unsigned(8),
        )]))
        .expect("seed source"),
        BranchRequestCause::Operator(CampaignCommandId::from_hash(CampaignHash::derive(
            "test",
            b"corpus-mutation-seed-request",
        ))),
        BranchBudget::new(1, 1).expect("seed budget"),
        StopCondition::NextChoice,
    )
    .expect("seed request");
    let seeded = repository
        .submit_known_branch_request(
            "generated-corpus-mutation",
            genesis.snapshot_id(),
            &seed_request,
        )
        .expect("submit seed request");

    let seed_eight = finite_proposal(
        &seed_request,
        &policy,
        &repository
            .head("generated-corpus-mutation")
            .expect("seed request head"),
        ChoiceValue::Integer(IntegerValue::Unsigned(8)),
        1,
    );
    let proposed = repository
        .issue_proposal(
            "generated-corpus-mutation",
            seeded.new_snapshot,
            &seed_eight,
        )
        .expect("issue first seed");
    let (selection, path, attempt) = branch_attempt(&repository, &seed_request, &seed_eight);
    let admitted = repository
        .admit_proposal(
            "generated-corpus-mutation",
            proposed.new_snapshot,
            proposed.proposal,
            &selection,
            &path,
            &attempt,
        )
        .expect("admit first seed");
    let first_observation = generated_observation(
        &repository,
        &lineage,
        &admitted,
        &path,
        seed_request.opportunity(),
        "corpus-mutation-eight",
    );
    let observed = repository
        .publish_observation(
            "generated-corpus-mutation",
            admitted.new_snapshot,
            &first_observation,
        )
        .expect("retain first corpus value");
    let requested = repository
        .submit_branch_request(
            "generated-corpus-mutation",
            observed.new_snapshot,
            &mutation_request,
        )
        .expect("submit corpus-mutation request");
    let mutation_id = mutation_request.id().expect("mutation request id");
    let ready = repository
        .read_continuation_projection(
            repository
                .lookup_frontier_projection(
                    repository
                        .read_snapshot(requested.new_snapshot.content_id())
                        .expect("mutation request snapshot")
                        .snapshot
                        .roots()
                        .exploration,
                    mutation_id,
                )
                .expect("mutation frontier lookup")
                .0,
        )
        .expect("mutation frontier projection");
    assert_eq!(ready.state(), ContinuationState::Ready);

    let mut current = requested.new_snapshot;
    for (ordinal, value) in [(1, 7), (2, 9)] {
        let proposal = finite_proposal(
            &mutation_request,
            &policy,
            &repository
                .head("generated-corpus-mutation")
                .expect("mutation proposal head"),
            ChoiceValue::Integer(IntegerValue::Unsigned(value)),
            ordinal,
        );
        let proposed = repository
            .issue_proposal("generated-corpus-mutation", current, &proposal)
            .expect("issue corpus mutation");
        let (selection, path, attempt) = branch_attempt(&repository, &mutation_request, &proposal);
        current = repository
            .admit_proposal(
                "generated-corpus-mutation",
                proposed.new_snapshot,
                proposed.proposal,
                &selection,
                &path,
                &attempt,
            )
            .expect("admit corpus mutation")
            .new_snapshot;
    }

    let second_seed_request = BranchRequest::new(
        BranchRequest::identity(
            mutation_request.branch_point(),
            mutation_request.parent(),
            mutation_request.opportunity(),
            mutation_request.domain(),
        ),
        CandidateSource::finite(BTreeSet::from([ChoiceValue::Integer(
            IntegerValue::Unsigned(2),
        )]))
        .expect("second seed source"),
        BranchRequestCause::Operator(CampaignCommandId::from_hash(CampaignHash::derive(
            "test",
            b"corpus-mutation-second-seed-request",
        ))),
        BranchBudget::new(1, 1).expect("second seed budget"),
        StopCondition::NextChoice,
    )
    .expect("second seed request");
    current = repository
        .submit_branch_request("generated-corpus-mutation", current, &second_seed_request)
        .expect("submit second seed request")
        .new_snapshot;
    let seed_two = finite_proposal(
        &second_seed_request,
        &policy,
        &repository
            .head("generated-corpus-mutation")
            .expect("second seed head"),
        ChoiceValue::Integer(IntegerValue::Unsigned(2)),
        1,
    );
    let proposed = repository
        .issue_proposal("generated-corpus-mutation", current, &seed_two)
        .expect("issue second seed");
    let (selection, path, attempt) = branch_attempt(&repository, &second_seed_request, &seed_two);
    let admitted = repository
        .admit_proposal(
            "generated-corpus-mutation",
            proposed.new_snapshot,
            proposed.proposal,
            &selection,
            &path,
            &attempt,
        )
        .expect("admit second seed");
    let second_observation = generated_observation(
        &repository,
        &lineage,
        &admitted,
        &path,
        second_seed_request.opportunity(),
        "corpus-mutation-two",
    );
    current = repository
        .publish_observation(
            "generated-corpus-mutation",
            admitted.new_snapshot,
            &second_observation,
        )
        .expect("retain second corpus value")
        .new_snapshot;

    let wrong = finite_proposal(
        &mutation_request,
        &policy,
        &repository
            .head("generated-corpus-mutation")
            .expect("wrong mutation head"),
        ChoiceValue::Integer(IntegerValue::Unsigned(6)),
        3,
    );
    let before = blobs.object_count().expect("objects before wrong mutation");
    assert!(matches!(
        repository.issue_proposal("generated-corpus-mutation", current, &wrong),
        Err(CampaignRepositoryError::Integrity {
            reason: "proposal-value-does-not-match-source-order"
        })
    ));
    assert_eq!(
        blobs.object_count().expect("objects after wrong mutation"),
        before
    );

    let next = finite_proposal(
        &mutation_request,
        &policy,
        &repository
            .head("generated-corpus-mutation")
            .expect("next mutation head"),
        ChoiceValue::Integer(IntegerValue::Unsigned(1)),
        3,
    );
    current = repository
        .issue_proposal("generated-corpus-mutation", current, &next)
        .expect("issue mutation from newly retained anchor")
        .new_snapshot;

    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    restarted
        .validate_complete_head(current.content_id())
        .expect("restart validates corpus-mutation history");
    let rebuilt = restarted
        .project_finite_expansion(current, mutation_request.branch_point(), None, 10)
        .expect("rebuild corpus-mutation expansion");
    assert_eq!(
        restarted
            .load_expansion_state(rebuilt)
            .expect("load rebuilt corpus-mutation expansion")
            .continuations()
            .get(&mutation_id),
        Some(&ContinuationState::Open)
    );
}

#[test]
fn corpus_mutation_generator_enforces_exact_owner_bounds_before_writes() {
    let (repository, lineage, policy, blobs) = counted_fixture();
    let genesis = repository
        .create_funded(
            "corpus-mutation-bounds",
            &lineage,
            &policy,
            &BTreeMap::new(),
        )
        .expect("create corpus-mutation bounds campaign");
    let domain = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(10_000),
            1,
            None,
            ExactRational::new(1, 1).expect("scale"),
            Vec::new(),
        )
        .expect("bounded corpus-mutation domain"),
    );

    let oversized_distance = CandidateGeneratorSpec::new(
        crate::CORPUS_MUTATION_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::MutateNearCorpus {
            maximum_distance: crate::CORPUS_MUTATION_GENERATOR_MAX_DISTANCE + 1,
        },
    )
    .expect("oversized-distance generator");
    let oversized_distance_id = repository
        .publish_generator(&oversized_distance)
        .expect("publish oversized-distance generator");
    let (_, oversized_distance_request) = generated_integer_request(
        &repository,
        &lineage,
        domain.clone(),
        IntegerValue::Unsigned(5_000),
        oversized_distance_id,
        "corpus-mutation-oversized-distance",
        1,
    );
    let oversized_distance_discovery = repository
        .discover_choice_opportunity(
            "corpus-mutation-bounds",
            genesis.snapshot_id(),
            oversized_distance_request.parent(),
            oversized_distance_request.opportunity(),
        )
        .expect("discover oversized-distance opportunity");
    let before_distance = blobs
        .object_count()
        .expect("objects before distance rejection");
    assert!(matches!(
        repository.submit_branch_request(
            "corpus-mutation-bounds",
            oversized_distance_discovery.new_snapshot,
            &oversized_distance_request,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "corpus-mutation-generator-distance-limit"
        })
    ));
    assert_eq!(
        blobs
            .object_count()
            .expect("objects after distance rejection"),
        before_distance
    );

    let bounded = CandidateGeneratorSpec::new(
        crate::CORPUS_MUTATION_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::MutateNearCorpus {
            maximum_distance: 1,
        },
    )
    .expect("bounded corpus-mutation generator");
    let bounded_id = repository
        .publish_generator(&bounded)
        .expect("publish bounded corpus-mutation generator");
    let (_, oversized_budget_request) = generated_integer_request(
        &repository,
        &lineage,
        domain.clone(),
        IntegerValue::Unsigned(5_000),
        bounded_id,
        "corpus-mutation-oversized-budget",
        crate::CORPUS_MUTATION_GENERATOR_MAX_PROPOSALS + 1,
    );
    let oversized_budget_discovery = repository
        .discover_choice_opportunity(
            "corpus-mutation-bounds",
            oversized_distance_discovery.new_snapshot,
            oversized_budget_request.parent(),
            oversized_budget_request.opportunity(),
        )
        .expect("discover oversized-budget opportunity");
    let before_budget = blobs
        .object_count()
        .expect("objects before budget rejection");
    assert!(matches!(
        repository.submit_branch_request(
            "corpus-mutation-bounds",
            oversized_budget_discovery.new_snapshot,
            &oversized_budget_request,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "corpus-mutation-generator-proposal-limit"
        })
    ));
    assert_eq!(
        blobs
            .object_count()
            .expect("objects after budget rejection"),
        before_budget
    );

    let alternative = AlternativeId::from_hash(CampaignHash::derive(
        "test-alternative",
        b"corpus-mutation-domain-mismatch",
    ));
    let discrete = ChoiceDomain::Discrete(
        DiscreteDomain::new(
            1,
            BTreeMap::from([(
                alternative,
                DiscreteAlternative::new(alternative, "alternative", None).expect("alternative"),
            )]),
        )
        .expect("discrete domain"),
    );
    let (_, incompatible_request) = generated_discrete_request(
        &repository,
        &lineage,
        discrete,
        alternative,
        bounded_id,
        "corpus-mutation-incompatible-domain",
        1,
    );
    let incompatible_discovery = repository
        .discover_choice_opportunity(
            "corpus-mutation-bounds",
            oversized_budget_discovery.new_snapshot,
            incompatible_request.parent(),
            incompatible_request.opportunity(),
        )
        .expect("discover incompatible-domain opportunity");
    let before_incompatible = blobs
        .object_count()
        .expect("objects before incompatible-domain rejection");
    assert!(matches!(
        repository.submit_branch_request(
            "corpus-mutation-bounds",
            incompatible_discovery.new_snapshot,
            &incompatible_request,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "candidate-generator-domain-family-mismatch"
        })
    ));
    assert_eq!(
        blobs
            .object_count()
            .expect("objects after incompatible-domain rejection"),
        before_incompatible
    );

    let (_, empty_corpus_request) = generated_integer_request(
        &repository,
        &lineage,
        domain.clone(),
        IntegerValue::Unsigned(5_000),
        bounded_id,
        "corpus-mutation-empty-corpus",
        1,
    );
    let empty_corpus_discovery = repository
        .discover_choice_opportunity(
            "corpus-mutation-bounds",
            incompatible_discovery.new_snapshot,
            empty_corpus_request.parent(),
            empty_corpus_request.opportunity(),
        )
        .expect("discover empty-corpus opportunity");
    let empty_corpus = repository
        .submit_branch_request(
            "corpus-mutation-bounds",
            empty_corpus_discovery.new_snapshot,
            &empty_corpus_request,
        )
        .expect("retain empty-corpus mutation request");
    assert_eq!(
        repository
            .read_continuation_projection(
                repository
                    .lookup_frontier_projection(
                        repository
                            .read_snapshot(empty_corpus.new_snapshot.content_id())
                            .expect("empty-corpus snapshot")
                            .snapshot
                            .roots()
                            .exploration,
                        empty_corpus_request.id().expect("empty-corpus request id"),
                    )
                    .expect("empty-corpus frontier lookup")
                    .0,
            )
            .expect("empty-corpus frontier projection")
            .state(),
        ContinuationState::WaitingForFeedback(
            FeedbackWait::new(0, 1).expect("empty-corpus feedback wait")
        )
    );

    assert!(matches!(
        CandidateGeneratorSpec::new(
            u32::MAX,
            CandidateGeneratorAlgorithm::MutateNearCorpus {
                maximum_distance: 1,
            },
        ),
        Err(CampaignCodecError::InvalidValue {
            reason: "candidate-generator implementation version does not match its algorithm"
        })
    ));
}

#[test]
fn boundary_integer_generator_uses_exact_static_order() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create_funded("generated-boundary", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let domain = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(20),
            2,
            None,
            ExactRational::new(1, 1).expect("scale"),
            vec![IntegerValue::Unsigned(6), IntegerValue::Unsigned(14)],
        )
        .expect("integer domain"),
    );
    let declaration = SelectableDeclaration::new(
        "generated.boundary",
        ChoiceSource::Workload {
            producer: "generated-boundary".to_owned(),
        },
        domain.clone(),
        ChoiceValue::Integer(IntegerValue::Unsigned(10)),
        ChoiceClassContext::new(BTreeSet::new()).expect("choice class"),
        BTreeSet::new(),
        true,
    )
    .expect("declaration");
    repository
        .publish_choice_domain(&domain)
        .expect("publish domain");
    repository
        .publish_selectable(&declaration)
        .expect("publish declaration");
    let opportunity = ChoiceOpportunity::new(
        lineage.scenario(),
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: CampaignHash::derive("test", b"generated-boundary"),
            producer: CampaignHash::derive("test", b"generated-boundary-producer"),
        },
        "generated-boundary",
        None,
    )
    .expect("opportunity");
    repository
        .publish_choice_opportunity(&opportunity)
        .expect("publish opportunity");
    let generator = CandidateGeneratorSpec::new(
        crate::BOUNDARY_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::BoundaryInteger,
    )
    .expect("boundary generator");
    let generator_id = repository
        .publish_generator(&generator)
        .expect("publish generator");
    let oversized_domain = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(128),
            1,
            None,
            ExactRational::new(1, 1).expect("oversized scale"),
            (0..=crate::BOUNDARY_INTEGER_GENERATOR_MAX_LANDMARKS as u64)
                .map(IntegerValue::Unsigned)
                .collect(),
        )
        .expect("oversized-landmark domain"),
    );
    assert!(matches!(
        repository.validate_generator_for_domain(generator_id, &oversized_domain),
        Err(CampaignRepositoryError::Integrity {
            reason: "boundary-generator-landmark-limit"
        })
    ));
    let request = BranchRequest::new(
        BranchRequest::identity(
            opportunity.branch_point_id(lineage.genesis()),
            lineage.genesis_content(),
            opportunity.id().expect("opportunity id"),
            domain.id().expect("domain id"),
        ),
        CandidateSource::generated(generator_id),
        BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(CampaignHash::derive(
            "test",
            b"generated-boundary-request",
        ))),
        BranchBudget::new(11, 11).expect("budget"),
        StopCondition::NextChoice,
    )
    .expect("request");
    assert!(matches!(
        CandidateGeneratorSpec::new(
            crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
            CandidateGeneratorAlgorithm::BoundaryInteger,
        ),
        Err(CampaignCodecError::InvalidValue {
            reason: "candidate-generator implementation version does not match its algorithm"
        })
    ));
    let expected = [0, 20, 10, 6, 14, 2, 18, 8, 12, 4, 16]
        .map(|value| ChoiceValue::Integer(IntegerValue::Unsigned(value)));
    assert_eq!(
        repository
            .static_candidate_count(&request, &domain)
            .expect("candidate count"),
        Some(expected.len() as u64)
    );
    for (index, expected) in expected.iter().enumerate() {
        assert_eq!(
            repository
                .static_candidate_at(&request, &domain, index as u64 + 1)
                .expect("candidate ordinal"),
            Some(expected.clone())
        );
    }

    let issued = repository
        .submit_known_branch_request("generated-boundary", genesis.snapshot_id(), &request)
        .expect("issue request");
    let projection_id = repository
        .project_finite_expansion(issued.new_snapshot, request.branch_point(), None, 10)
        .expect("project boundary source");
    assert_eq!(
        repository
            .load_expansion_state(projection_id)
            .expect("load projection")
            .continuations()
            .get(&request.id().expect("request id")),
        Some(&ContinuationState::Ready)
    );
    let head = repository.head("generated-boundary").expect("request head");
    let wrong = finite_proposal(
        &request,
        &policy,
        &head,
        ChoiceValue::Integer(IntegerValue::Unsigned(20)),
        1,
    );
    assert!(matches!(
        repository.issue_proposal("generated-boundary", issued.new_snapshot, &wrong),
        Err(CampaignRepositoryError::Integrity {
            reason: "proposal-value-does-not-match-source-order"
        })
    ));
    let first = finite_proposal(
        &request,
        &policy,
        &head,
        ChoiceValue::Integer(IntegerValue::Unsigned(0)),
        1,
    );
    let first_issued = repository
        .issue_proposal("generated-boundary", issued.new_snapshot, &first)
        .expect("issue first boundary proposal");

    let signed_domain = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Signed64,
            IntegerValue::Signed(-8),
            IntegerValue::Signed(8),
            1,
            None,
            ExactRational::new(1, 1).expect("signed scale"),
            vec![IntegerValue::Signed(0)],
        )
        .expect("signed domain"),
    );
    let signed_declaration = SelectableDeclaration::new(
        "generated.boundary.signed",
        ChoiceSource::Workload {
            producer: "generated-boundary".to_owned(),
        },
        signed_domain.clone(),
        ChoiceValue::Integer(IntegerValue::Signed(0)),
        ChoiceClassContext::new(BTreeSet::new()).expect("signed choice class"),
        BTreeSet::new(),
        true,
    )
    .expect("signed declaration");
    repository
        .publish_choice_domain(&signed_domain)
        .expect("publish signed domain");
    repository
        .publish_selectable(&signed_declaration)
        .expect("publish signed declaration");
    let signed_opportunity = ChoiceOpportunity::new(
        lineage.scenario(),
        &signed_declaration,
        &signed_domain,
        ChoiceCoordinate {
            scheduler: CampaignHash::derive("test", b"generated-boundary-signed"),
            producer: CampaignHash::derive("test", b"generated-boundary-producer"),
        },
        "generated-boundary-signed",
        None,
    )
    .expect("signed opportunity");
    repository
        .publish_choice_opportunity(&signed_opportunity)
        .expect("publish signed opportunity");
    let signed_request = BranchRequest::new(
        BranchRequest::identity(
            signed_opportunity.branch_point_id(lineage.genesis()),
            lineage.genesis_content(),
            signed_opportunity.id().expect("signed opportunity id"),
            signed_domain.id().expect("signed domain id"),
        ),
        CandidateSource::generated(generator_id),
        BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(CampaignHash::derive(
            "test",
            b"generated-boundary-signed-request",
        ))),
        BranchBudget::new(11, 11).expect("signed budget"),
        StopCondition::NextChoice,
    )
    .expect("signed request");
    let signed_expected = [-8, 8, 0, -7, 7, -1, 1, 2, -2, 4, -4]
        .map(|value| ChoiceValue::Integer(IntegerValue::Signed(value)));
    for (index, expected) in signed_expected.iter().enumerate() {
        assert_eq!(
            repository
                .static_candidate_at(&signed_request, &signed_domain, index as u64 + 1)
                .expect("signed candidate ordinal"),
            Some(expected.clone())
        );
    }
    repository
        .validated_heads
        .lock()
        .expect("validation cache")
        .clear();
    assert_eq!(
        repository
            .head("generated-boundary")
            .expect("rebuild boundary history")
            .snapshot_id(),
        first_issued.new_snapshot
    );
}

#[test]
fn stratified_integer_generator_uses_exact_static_offsets() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create_funded("generated-stratified", &lineage, &policy, &BTreeMap::new())
        .expect("create");

    let generator = CandidateGeneratorSpec::new(
        crate::STRATIFIED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::StratifiedInteger { strata: 4 },
    )
    .expect("stratified generator");
    let generator_id = repository
        .publish_generator(&generator)
        .expect("publish stratified generator");
    let unsigned = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(20),
            2,
            None,
            ExactRational::new(1, 1).expect("scale"),
            Vec::new(),
        )
        .expect("unsigned domain"),
    );
    let (unsigned, request) = generated_integer_request(
        &repository,
        &lineage,
        unsigned,
        IntegerValue::Unsigned(10),
        generator_id,
        "unsigned",
        4,
    );
    let expected = [0, 6, 12, 20].map(|value| ChoiceValue::Integer(IntegerValue::Unsigned(value)));
    assert_eq!(
        repository
            .static_candidate_count(&request, &unsigned)
            .expect("candidate count"),
        Some(expected.len() as u64)
    );
    for (index, expected) in expected.iter().enumerate() {
        assert_eq!(
            repository
                .static_candidate_at(&request, &unsigned, index as u64 + 1)
                .expect("candidate ordinal"),
            Some(expected.clone())
        );
    }
    assert!(matches!(
        repository.static_candidate_at(&request, &unsigned, 5),
        Err(CampaignRepositoryError::Integrity {
            reason: "proposal-ordinal-exceeds-source-cardinality"
        })
    ));

    let singleton = CandidateGeneratorSpec::new(
        crate::STRATIFIED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::StratifiedInteger { strata: 1 },
    )
    .expect("singleton generator");
    let singleton_id = repository
        .publish_generator(&singleton)
        .expect("publish singleton generator");
    let (_, singleton_request) = generated_integer_request(
        &repository,
        &lineage,
        unsigned.clone(),
        IntegerValue::Unsigned(10),
        singleton_id,
        "singleton",
        1,
    );
    assert_eq!(
        repository
            .static_candidate_at(&singleton_request, &unsigned, 1)
            .expect("singleton candidate"),
        Some(ChoiceValue::Integer(IntegerValue::Unsigned(10)))
    );

    let dense = CandidateGeneratorSpec::new(
        crate::STRATIFIED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::StratifiedInteger { strata: 32 },
    )
    .expect("dense generator");
    let dense_id = repository
        .publish_generator(&dense)
        .expect("publish dense generator");
    let (_, dense_request) = generated_integer_request(
        &repository,
        &lineage,
        unsigned.clone(),
        IntegerValue::Unsigned(10),
        dense_id,
        "dense",
        11,
    );
    assert_eq!(
        repository
            .static_candidate_count(&dense_request, &unsigned)
            .expect("dense candidate count"),
        Some(11)
    );
    for ordinal in 1..=11 {
        assert_eq!(
            repository
                .static_candidate_at(&dense_request, &unsigned, ordinal)
                .expect("dense candidate"),
            Some(ChoiceValue::Integer(IntegerValue::Unsigned(
                (ordinal - 1) * 2,
            )))
        );
    }

    let signed = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Signed64,
            IntegerValue::Signed(-10),
            IntegerValue::Signed(10),
            2,
            None,
            ExactRational::new(1, 1).expect("signed scale"),
            Vec::new(),
        )
        .expect("signed domain"),
    );
    let (signed, signed_request) = generated_integer_request(
        &repository,
        &lineage,
        signed,
        IntegerValue::Signed(0),
        generator_id,
        "signed",
        4,
    );
    let signed_expected =
        [-10, -4, 2, 10].map(|value| ChoiceValue::Integer(IntegerValue::Signed(value)));
    for (index, expected) in signed_expected.iter().enumerate() {
        assert_eq!(
            repository
                .static_candidate_at(&signed_request, &signed, index as u64 + 1)
                .expect("signed candidate"),
            Some(expected.clone())
        );
    }

    let full_signed = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Signed64,
            IntegerValue::Signed(i64::MIN),
            IntegerValue::Signed(i64::MAX),
            1,
            None,
            ExactRational::new(1, 1).expect("full signed scale"),
            Vec::new(),
        )
        .expect("full signed domain"),
    );
    let (full_signed, full_signed_request) = generated_integer_request(
        &repository,
        &lineage,
        full_signed,
        IntegerValue::Signed(0),
        generator_id,
        "full-signed",
        4,
    );
    let full_signed_expected = [
        i64::MIN,
        -3_074_457_345_618_258_603,
        3_074_457_345_618_258_602,
        i64::MAX,
    ]
    .map(|value| ChoiceValue::Integer(IntegerValue::Signed(value)));
    for (index, expected) in full_signed_expected.iter().enumerate() {
        assert_eq!(
            repository
                .static_candidate_at(&full_signed_request, &full_signed, index as u64 + 1)
                .expect("full signed candidate"),
            Some(expected.clone())
        );
    }

    let oversized = CandidateGeneratorSpec::new(
        crate::STRATIFIED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::StratifiedInteger {
            strata: crate::STRATIFIED_INTEGER_GENERATOR_MAX_STRATA + 1,
        },
    )
    .expect("oversized generator");
    let oversized_id = repository
        .publish_generator(&oversized)
        .expect("publish oversized generator");
    assert!(matches!(
        repository.validate_generator_for_domain(oversized_id, &unsigned),
        Err(CampaignRepositoryError::Integrity {
            reason: "stratified-generator-strata-limit"
        })
    ));

    assert!(matches!(
        CandidateGeneratorSpec::new(
            crate::BOUNDARY_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
            CandidateGeneratorAlgorithm::StratifiedInteger { strata: 4 },
        ),
        Err(CampaignCodecError::InvalidValue {
            reason: "candidate-generator implementation version does not match its algorithm"
        })
    ));

    let issued = repository
        .submit_known_branch_request("generated-stratified", genesis.snapshot_id(), &request)
        .expect("issue request");
    let projection_id = repository
        .project_finite_expansion(issued.new_snapshot, request.branch_point(), None, 10)
        .expect("project stratified source");
    assert_eq!(
        repository
            .load_expansion_state(projection_id)
            .expect("load projection")
            .continuations()
            .get(&request.id().expect("request id")),
        Some(&ContinuationState::Ready)
    );
    let head = repository
        .head("generated-stratified")
        .expect("request head");
    let wrong = finite_proposal(
        &request,
        &policy,
        &head,
        ChoiceValue::Integer(IntegerValue::Unsigned(20)),
        1,
    );
    assert!(matches!(
        repository.issue_proposal("generated-stratified", issued.new_snapshot, &wrong),
        Err(CampaignRepositoryError::Integrity {
            reason: "proposal-value-does-not-match-source-order"
        })
    ));
    assert_eq!(
        repository
            .head("generated-stratified")
            .expect("unchanged head")
            .snapshot_id(),
        issued.new_snapshot
    );
    let first = finite_proposal(
        &request,
        &policy,
        &head,
        ChoiceValue::Integer(IntegerValue::Unsigned(0)),
        1,
    );
    let first_issued = repository
        .issue_proposal("generated-stratified", issued.new_snapshot, &first)
        .expect("issue first stratified proposal");

    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    assert_eq!(
        restarted
            .head("generated-stratified")
            .expect("rebuild stratified history")
            .snapshot_id(),
        first_issued.new_snapshot
    );
}

#[test]
fn log_integer_generator_uses_exact_rounded_powers() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create_funded("generated-log", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let generator = CandidateGeneratorSpec::new(
        crate::LOG_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::LogInteger { base: 10 },
    )
    .expect("log generator");
    let generator_id = repository
        .publish_generator(&generator)
        .expect("publish log generator");
    let unsigned = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(3),
            IntegerValue::Unsigned(249),
            2,
            None,
            ExactRational::new(1, 1).expect("scale"),
            Vec::new(),
        )
        .expect("unsigned domain"),
    );
    let (unsigned, request) = generated_integer_request(
        &repository,
        &lineage,
        unsigned,
        IntegerValue::Unsigned(3),
        generator_id,
        "log-unsigned",
        4,
    );
    let expected =
        [3, 11, 101, 249].map(|value| ChoiceValue::Integer(IntegerValue::Unsigned(value)));
    assert_eq!(
        repository
            .static_candidate_count(&request, &unsigned)
            .expect("candidate count"),
        Some(expected.len() as u64)
    );
    for (index, expected) in expected.iter().enumerate() {
        assert_eq!(
            repository
                .static_candidate_at(&request, &unsigned, index as u64 + 1)
                .expect("candidate ordinal"),
            Some(expected.clone())
        );
    }
    assert!(matches!(
        repository.static_candidate_at(&request, &unsigned, 5),
        Err(CampaignRepositoryError::Integrity {
            reason: "proposal-ordinal-exceeds-source-cardinality"
        })
    ));

    let signed = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Signed64,
            IntegerValue::Signed(1),
            IntegerValue::Signed(1_000),
            3,
            None,
            ExactRational::new(1, 1).expect("signed scale"),
            Vec::new(),
        )
        .expect("signed domain"),
    );
    let (signed, signed_request) = generated_integer_request(
        &repository,
        &lineage,
        signed,
        IntegerValue::Signed(1),
        generator_id,
        "log-signed",
        4,
    );
    let signed_expected =
        [1, 10, 100, 1_000].map(|value| ChoiceValue::Integer(IntegerValue::Signed(value)));
    for (index, expected) in signed_expected.iter().enumerate() {
        assert_eq!(
            repository
                .static_candidate_at(&signed_request, &signed, index as u64 + 1)
                .expect("signed candidate"),
            Some(expected.clone())
        );
    }

    let base_two = CandidateGeneratorSpec::new(
        crate::LOG_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::LogInteger { base: 2 },
    )
    .expect("base-two generator");
    let base_two_id = repository
        .publish_generator(&base_two)
        .expect("publish base-two generator");
    let full_unsigned = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(1),
            IntegerValue::Unsigned(u64::MAX),
            1,
            None,
            ExactRational::new(1, 1).expect("full scale"),
            Vec::new(),
        )
        .expect("full unsigned domain"),
    );
    let (full_unsigned, full_request) = generated_integer_request(
        &repository,
        &lineage,
        full_unsigned,
        IntegerValue::Unsigned(1),
        base_two_id,
        "log-full-unsigned",
        crate::LOG_INTEGER_GENERATOR_MAX_CANDIDATES as u64,
    );
    assert_eq!(
        repository
            .static_candidate_count(&full_request, &full_unsigned)
            .expect("full candidate count"),
        Some(crate::LOG_INTEGER_GENERATOR_MAX_CANDIDATES as u64)
    );
    assert_eq!(
        repository
            .static_candidate_at(&full_request, &full_unsigned, 64)
            .expect("last power"),
        Some(ChoiceValue::Integer(IntegerValue::Unsigned(1_u64 << 63)))
    );
    assert_eq!(
        repository
            .static_candidate_at(&full_request, &full_unsigned, 65)
            .expect("inclusive maximum"),
        Some(ChoiceValue::Integer(IntegerValue::Unsigned(u64::MAX)))
    );

    let nonpositive = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Signed64,
            IntegerValue::Signed(-10),
            IntegerValue::Signed(10),
            1,
            None,
            ExactRational::new(1, 1).expect("nonpositive scale"),
            Vec::new(),
        )
        .expect("nonpositive domain"),
    );
    assert!(matches!(
        repository.validate_generator_for_domain(generator_id, &nonpositive),
        Err(CampaignRepositoryError::Integrity {
            reason: "log-generator-domain-is-not-positive"
        })
    ));
    let zero_unsigned = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(10),
            1,
            None,
            ExactRational::new(1, 1).expect("zero scale"),
            Vec::new(),
        )
        .expect("zero domain"),
    );
    assert!(matches!(
        repository.validate_generator_for_domain(generator_id, &zero_unsigned),
        Err(CampaignRepositoryError::Integrity {
            reason: "log-generator-domain-is-not-positive"
        })
    ));

    assert!(matches!(
        CandidateGeneratorSpec::new(
            crate::STRATIFIED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
            CandidateGeneratorAlgorithm::LogInteger { base: 10 },
        ),
        Err(CampaignCodecError::InvalidValue {
            reason: "candidate-generator implementation version does not match its algorithm"
        })
    ));

    let issued = repository
        .submit_known_branch_request("generated-log", genesis.snapshot_id(), &request)
        .expect("issue request");
    let projection_id = repository
        .project_finite_expansion(issued.new_snapshot, request.branch_point(), None, 10)
        .expect("project log source");
    assert_eq!(
        repository
            .load_expansion_state(projection_id)
            .expect("load projection")
            .continuations()
            .get(&request.id().expect("request id")),
        Some(&ContinuationState::Ready)
    );
    let head = repository.head("generated-log").expect("request head");
    let wrong = finite_proposal(
        &request,
        &policy,
        &head,
        ChoiceValue::Integer(IntegerValue::Unsigned(249)),
        1,
    );
    assert!(matches!(
        repository.issue_proposal("generated-log", issued.new_snapshot, &wrong),
        Err(CampaignRepositoryError::Integrity {
            reason: "proposal-value-does-not-match-source-order"
        })
    ));
    assert_eq!(
        repository
            .head("generated-log")
            .expect("unchanged head")
            .snapshot_id(),
        issued.new_snapshot
    );
    let first = finite_proposal(
        &request,
        &policy,
        &head,
        ChoiceValue::Integer(IntegerValue::Unsigned(3)),
        1,
    );
    let first_issued = repository
        .issue_proposal("generated-log", issued.new_snapshot, &first)
        .expect("issue first log proposal");

    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    assert_eq!(
        restarted
            .head("generated-log")
            .expect("rebuild log history")
            .snapshot_id(),
        first_issued.new_snapshot
    );
}

#[test]
fn modeled_uniform_integer_generator_bounds_full_width_and_restarts() {
    let (repository, lineage, policy, blobs) = counted_fixture();
    let genesis = repository
        .create_funded("modeled-uniform", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let domain = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(u64::MAX),
            1,
            None,
            ExactRational::new(1, 1).expect("scale"),
            Vec::new(),
        )
        .expect("full-width domain"),
    );
    let declaration = SelectableDeclaration::new(
        "modeled.uniform.full-width",
        ChoiceSource::Workload {
            producer: "modeled-uniform".to_owned(),
        },
        domain.clone(),
        ChoiceValue::Integer(IntegerValue::Unsigned(0)),
        ChoiceClassContext::new(BTreeSet::new()).expect("choice class"),
        BTreeSet::new(),
        true,
    )
    .expect("declaration");
    let model = ProbabilityModelId::from_hash(CampaignHash::derive(
        "test.modeled-uniform.v1",
        b"full-width",
    ));
    let opportunity = ChoiceOpportunity::new(
        lineage.scenario(),
        &declaration,
        &domain,
        ChoiceCoordinate {
            scheduler: CampaignHash::derive("test", b"modeled-uniform"),
            producer: CampaignHash::derive("test", b"modeled-uniform-producer"),
        },
        "modeled-uniform",
        Some(model),
    )
    .expect("opportunity");
    repository
        .publish_choice_domain(&domain)
        .expect("publish domain");
    repository
        .publish_selectable(&declaration)
        .expect("publish declaration");
    repository
        .publish_choice_opportunity(&opportunity)
        .expect("publish opportunity");
    let generator = CandidateGeneratorSpec::new(
        crate::PERMUTED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::PermutedInteger,
    )
    .expect("modeled uniform generator");
    let generator_id = repository
        .publish_generator(&generator)
        .expect("publish generator");
    let request = BranchRequest::new(
        BranchRequest::identity(
            opportunity.branch_point_id(lineage.genesis()),
            lineage.genesis_content(),
            opportunity.id().expect("opportunity id"),
            domain.id().expect("domain id"),
        ),
        CandidateSource::modeled_generated(model, generator_id),
        BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(CampaignHash::derive(
            "test",
            b"modeled-uniform-request",
        ))),
        BranchBudget::new(4, 4).expect("budget"),
        StopCondition::NextChoice,
    )
    .expect("request");
    let discovered = repository
        .discover_choice_opportunity(
            "modeled-uniform",
            genesis.snapshot_id(),
            request.parent(),
            request.opportunity(),
        )
        .expect("discover modeled opportunity");

    let candidates = (1..=4)
        .map(|ordinal| {
            repository
                .static_candidate_at(&request, &domain, ordinal)
                .expect("modeled candidate")
                .expect("implemented source")
        })
        .collect::<Vec<_>>();
    assert_eq!(candidates.iter().cloned().collect::<BTreeSet<_>>().len(), 4);
    assert!(candidates.iter().all(|value| domain.contains(value)));
    assert_eq!(
        repository
            .static_candidate_count(&request, &domain)
            .expect("bounded candidate count"),
        Some(4)
    );
    assert!(matches!(
        repository.static_candidate_at(&request, &domain, 5),
        Err(CampaignRepositoryError::Integrity {
            reason: "proposal-ordinal-exceeds-source-cardinality"
        })
    ));

    let wrong_model = BranchRequest::new(
        BranchRequest::identity(
            request.branch_point(),
            request.parent(),
            request.opportunity(),
            request.domain(),
        ),
        CandidateSource::modeled_generated(
            ProbabilityModelId::from_hash(CampaignHash::derive(
                "test.modeled-uniform.v1",
                b"wrong",
            )),
            generator_id,
        ),
        request.cause(),
        request.budget(),
        request.stop().clone(),
    )
    .expect("wrong-model request");
    let before_wrong_model = blobs.object_count().expect("object count");
    assert!(matches!(
        repository.submit_branch_request("modeled-uniform", discovered.new_snapshot, &wrong_model,),
        Err(CampaignRepositoryError::Codec(
            CampaignCodecError::InvalidValue {
                reason: "branch request modeled prior disagrees with its opportunity"
            }
        ))
    ));
    assert_eq!(
        blobs.object_count().expect("unchanged object count"),
        before_wrong_model
    );

    let requested = repository
        .submit_branch_request("modeled-uniform", discovered.new_snapshot, &request)
        .expect("submit modeled request");
    let projection = repository
        .project_finite_expansion(requested.new_snapshot, request.branch_point(), None, 10)
        .expect("project modeled source");
    assert_eq!(
        repository
            .load_expansion_state(projection)
            .expect("load projection")
            .continuations()
            .get(&request.id().expect("request id")),
        Some(&ContinuationState::Ready)
    );
    let mut current = requested.new_snapshot;
    for (index, candidate) in candidates.iter().enumerate() {
        let proposal = finite_proposal(
            &request,
            &policy,
            &repository.head("modeled-uniform").expect("proposal head"),
            candidate.clone(),
            index as u64 + 1,
        );
        let proposed = repository
            .issue_proposal("modeled-uniform", current, &proposal)
            .expect("issue modeled proposal");
        let (selection, path, attempt) = branch_attempt(&repository, &request, &proposal);
        current = repository
            .admit_proposal(
                "modeled-uniform",
                proposed.new_snapshot,
                proposed.proposal,
                &selection,
                &path,
                &attempt,
            )
            .expect("admit modeled proposal")
            .new_snapshot;
    }
    let closed_projection = repository
        .project_finite_expansion(current, request.branch_point(), None, 10)
        .expect("project bounded modeled source");
    assert_eq!(
        repository
            .load_expansion_state(closed_projection)
            .expect("load closed projection")
            .continuations()
            .get(&request.id().expect("request id")),
        Some(&ContinuationState::Closed)
    );

    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    assert_eq!(
        restarted
            .head("modeled-uniform")
            .expect("rebuild modeled history")
            .snapshot_id(),
        current
    );
    assert_eq!(
        restarted
            .static_candidate_at(&request, &domain, 1)
            .expect("recompute candidate after restart"),
        Some(candidates[0].clone())
    );
}
