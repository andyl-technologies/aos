//! Generator expansion, feedback, and owner-bound validation regressions.

use super::*;

#[test]
fn branch_request_staleness_and_campaign_scope_fail_before_ref_advance() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create_funded("scope", &lineage, &policy, &BTreeMap::new())
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
        .create_funded("generators", &lineage, &policy, &BTreeMap::new())
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

    let all = CandidateGeneratorSpec::new(
        crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::All,
    )
    .expect("all generator");
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
    let ready_id = repository
        .project_finite_expansion(generated.new_snapshot, valid.branch_point(), None, 10)
        .expect("project generated all source");
    let ready = repository
        .load_expansion_state(ready_id)
        .expect("load generated projection");
    assert_eq!(
        ready.continuations().get(&valid.id().expect("request id")),
        Some(&ContinuationState::Ready)
    );

    let generated_head = repository.head("generators").expect("generated head");
    let wrong_first = finite_proposal(
        &valid,
        &policy,
        &generated_head,
        ChoiceValue::Boolean(true),
        1,
    );
    assert!(matches!(
        repository.issue_proposal("generators", generated_head.snapshot_id(), &wrong_first,),
        Err(CampaignRepositoryError::Integrity {
            reason: "proposal-value-does-not-match-source-order"
        })
    ));
    assert_eq!(
        repository
            .head("generators")
            .expect("unchanged head")
            .snapshot_id(),
        generated_head.snapshot_id()
    );

    let engine = PlannerEngine::new("closed-rust", 1, 1, BTreeSet::new()).expect("planner engine");
    let initial_state = PlannerState::new(
        engine.id().expect("engine id"),
        "closed-rust-state",
        1,
        vec![0],
    )
    .expect("planner state");
    let (engine, _artifact, invocation) = planner_basis(
        &repository,
        "generators",
        generated_head.snapshot_id(),
        initial_state,
    );
    let first = Proposal::new(
        valid.branch_point(),
        valid.id().expect("request id"),
        valid.domain(),
        ChoiceValue::Boolean(false),
        policy.id().expect("policy id"),
        Some(invocation.id().expect("invocation id")),
        1,
        invocation.input_view(),
    )
    .expect("first generated proposal");
    let usage = PlanningUsage {
        branch_requests: 0,
        proposals: 1,
        input_objects: invocation.scan_page().input_objects(),
        input_bytes: invocation.scan_page().input_bytes(),
        fuel: 1,
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
        GuidanceEvidence::new(BTreeMap::new()).expect("guidance"),
        PlannerProposalDisposition::Issue {
            selected: PlanningScanPosition::new(
                valid.branch_point(),
                valid.id().expect("request id"),
            ),
            branch_requests: Vec::new(),
            proposals: vec![first],
        },
    )
    .expect("generated planner issue");
    let first_admitted = repository
        .accept_planner_step("generators", generated_head.snapshot_id(), &step, usage)
        .expect("atomically issue and admit first generated proposal");
    let after_first_id = repository
        .project_finite_expansion(first_admitted.new_snapshot, valid.branch_point(), None, 10)
        .expect("project after first generated proposal");
    let after_first = repository
        .load_expansion_state(after_first_id)
        .expect("load first generated continuation");
    assert_eq!(
        after_first
            .continuations()
            .get(&valid.id().expect("request id")),
        Some(&ContinuationState::Ready)
    );

    let first_head = repository.head("generators").expect("first generated head");
    let second = finite_proposal(&valid, &policy, &first_head, ChoiceValue::Boolean(true), 2);
    let second_proposed = repository
        .issue_proposal("generators", first_head.snapshot_id(), &second)
        .expect("issue second generated proposal");
    let (selection, path, attempt) = branch_attempt(&repository, &valid, &second);
    let second_admitted = repository
        .admit_proposal(
            "generators",
            second_proposed.new_snapshot,
            second_proposed.proposal,
            &selection,
            &path,
            &attempt,
        )
        .expect("admit second generated proposal");
    let exhausted_id = repository
        .project_finite_expansion(second_admitted.new_snapshot, valid.branch_point(), None, 10)
        .expect("project exhausted generated source");
    let exhausted = repository
        .load_expansion_state(exhausted_id)
        .expect("load exhausted generated continuation");
    assert_eq!(
        exhausted
            .continuations()
            .get(&valid.id().expect("request id")),
        Some(&ContinuationState::Exhausted)
    );

    let legacy_all = CandidateGeneratorSpec::new(1, CandidateGeneratorAlgorithm::All)
        .expect("legacy all generator");
    let legacy_all_id = repository
        .publish_generator(&legacy_all)
        .expect("publish legacy all generator");
    let legacy_request = BranchRequest::new(
        valid.branch_point(),
        valid.parent(),
        valid.opportunity(),
        valid.domain(),
        CandidateSource::generated(legacy_all_id),
        BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(CampaignHash::derive(
            "test",
            b"legacy-generator",
        ))),
        BranchBudget::new(2, 2).expect("budget"),
        StopCondition::NextChoice,
    )
    .expect("legacy generated request");
    let legacy_issued = repository
        .submit_known_branch_request("generators", second_admitted.new_snapshot, &legacy_request)
        .expect("accept legacy generated request as suspended work");
    assert_eq!(
        repository
            .initial_continuation_state(&legacy_request)
            .expect("legacy continuation"),
        ContinuationState::Open
    );
    assert!(matches!(
        repository.project_finite_expansion(
            legacy_issued.new_snapshot,
            legacy_request.branch_point(),
            None,
            10,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "generated-expansion-projector-is-not-implemented"
        })
    ));
    repository
        .validated_heads
        .lock()
        .expect("validation cache")
        .clear();
    assert_eq!(
        repository
            .head("generators")
            .expect("rebuild generated history")
            .snapshot_id(),
        legacy_issued.new_snapshot
    );
}

#[test]
fn exhaustive_all_requests_bind_policy_cardinality_and_replay_exactly() {
    let (repository, lineage, _, blobs) = fixture_with_quota(64 * 1024 * 1024);
    let all = CandidateGeneratorSpec::new(
        crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::All,
    )
    .expect("all generator");
    let all_id = all.id().expect("all generator id");
    let policy =
        exhaustive_policy_with_generator(lineage.scenario(), all_id, "product.network.retry", 2);
    let genesis = repository
        .create_funded(
            "exhaustive-all",
            &lineage,
            &policy,
            &BTreeMap::from([(all_id, all.clone())]),
        )
        .expect("create exhaustive campaign");
    let finite = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "exhaustive-all",
    );
    let discovered = repository
        .discover_choice_opportunity(
            "exhaustive-all",
            genesis.snapshot_id(),
            finite.parent(),
            finite.opportunity(),
        )
        .expect("discover exhaustive choice");
    let exhaustive = BranchRequest::new(
        finite.branch_point(),
        finite.parent(),
        finite.opportunity(),
        finite.domain(),
        CandidateSource::generated(all_id),
        BranchRequestCause::ExhaustivePolicy(policy.id().expect("policy id")),
        BranchBudget::new(2, 2).expect("exact exhaustive budget"),
        finite.stop().clone(),
    )
    .expect("exhaustive request");
    let partial = BranchRequest::new(
        finite.branch_point(),
        finite.parent(),
        finite.opportunity(),
        finite.domain(),
        CandidateSource::generated(all_id),
        BranchRequestCause::ExhaustivePolicy(policy.id().expect("policy id")),
        BranchBudget::new(1, 1).expect("partial budget"),
        finite.stop().clone(),
    )
    .expect("partial exhaustive request");
    let objects_before_partial = blobs
        .object_count()
        .expect("objects before partial rejection");
    assert!(matches!(
        repository.submit_branch_request("exhaustive-all", discovered.new_snapshot, &partial),
        Err(CampaignRepositoryError::Integrity {
            reason: "exhaustive-branch-request-budget-is-not-domain-cardinality"
        })
    ));
    assert_eq!(
        blobs
            .object_count()
            .expect("objects after partial rejection"),
        objects_before_partial
    );
    assert_eq!(
        repository
            .head("exhaustive-all")
            .expect("head after partial rejection")
            .snapshot_id(),
        discovered.new_snapshot
    );
    let accepted = repository
        .submit_branch_request("exhaustive-all", discovered.new_snapshot, &exhaustive)
        .expect("accept exhaustive request");
    let advanced = repository
        .submit_branch_request("exhaustive-all", accepted.new_snapshot, &finite)
        .expect("advance after exhaustive request");
    let replay = repository
        .submit_branch_request("exhaustive-all", discovered.new_snapshot, &exhaustive)
        .expect("replay exhaustive request before stale check");
    assert!(replay.replayed);
    assert_eq!(replay.prior_snapshot, discovered.new_snapshot);
    assert_eq!(replay.new_snapshot, accepted.new_snapshot);
    let service_replay = crate::CampaignClient::new(crate::RepositoryCampaignService::new(
        &repository,
        PermitExhaustive,
    ))
    .submit_branch_request(
        &crate::SubmitCampaignBranchRequest::new(
            crate::CampaignPrincipal::new("operator").expect("principal"),
            crate::CampaignName::new("exhaustive-all").expect("campaign name"),
            discovered.new_snapshot,
            exhaustive.clone(),
        )
        .expect("service exhaustive request"),
    )
    .expect("service accepts exhaustive policy request");
    assert!(service_replay.replayed());
    assert_eq!(service_replay.prior_snapshot(), discovered.new_snapshot);
    assert_eq!(service_replay.new_snapshot(), accepted.new_snapshot);
    assert_eq!(
        repository
            .head("exhaustive-all")
            .expect("current exhaustive head")
            .snapshot_id(),
        advanced.new_snapshot
    );
    repository
        .validated_heads
        .lock()
        .expect("validation cache")
        .clear();
    assert_eq!(
        repository
            .head("exhaustive-all")
            .expect("rebuild exhaustive history")
            .snapshot_id(),
        advanced.new_snapshot
    );

    let narrow_policy =
        exhaustive_policy_with_generator(lineage.scenario(), all_id, "product.network.retry", 1);
    let narrow_genesis = repository
        .create_funded(
            "exhaustive-too-wide",
            &lineage,
            &narrow_policy,
            &BTreeMap::from([(all_id, all)]),
        )
        .expect("create narrow exhaustive campaign");
    let narrow_finite = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "exhaustive-too-wide",
    );
    let narrow_discovery = repository
        .discover_choice_opportunity(
            "exhaustive-too-wide",
            narrow_genesis.snapshot_id(),
            narrow_finite.parent(),
            narrow_finite.opportunity(),
        )
        .expect("discover too-wide choice");
    let too_wide = BranchRequest::new(
        narrow_finite.branch_point(),
        narrow_finite.parent(),
        narrow_finite.opportunity(),
        narrow_finite.domain(),
        CandidateSource::generated(all_id),
        BranchRequestCause::ExhaustivePolicy(narrow_policy.id().expect("narrow policy id")),
        BranchBudget::new(2, 2).expect("complete domain budget"),
        narrow_finite.stop().clone(),
    )
    .expect("too-wide exhaustive request");
    let objects_before = blobs.object_count().expect("objects before rejection");
    assert!(matches!(
        repository.submit_branch_request(
            "exhaustive-too-wide",
            narrow_discovery.new_snapshot,
            &too_wide,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "exhaustive-branch-request-domain-exceeds-policy"
        })
    ));
    assert_eq!(
        blobs.object_count().expect("objects after rejection"),
        objects_before
    );
    assert_eq!(
        repository
            .head("exhaustive-too-wide")
            .expect("unchanged narrow head")
            .snapshot_id(),
        narrow_discovery.new_snapshot
    );
}

#[test]
fn generated_all_discrete_uses_stable_alternative_order() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create_funded("generated-discrete", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let alternative_ids = ["third", "first", "second"].map(|name| {
        AlternativeId::from_hash(CampaignHash::derive("test-alternative", name.as_bytes()))
    });
    let alternatives = alternative_ids
        .into_iter()
        .map(|id| {
            (
                id,
                DiscreteAlternative::new(id, "alternative", None).expect("alternative"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let expected = alternatives.keys().copied().collect::<Vec<_>>();
    let domain =
        ChoiceDomain::Discrete(DiscreteDomain::new(1, alternatives).expect("discrete domain"));
    let declaration = SelectableDeclaration::new(
        "generated.discrete",
        ChoiceSource::Workload {
            producer: "generated-discrete".to_owned(),
        },
        domain.clone(),
        ChoiceValue::Discrete(expected[0]),
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
            scheduler: CampaignHash::derive("test", b"generated-discrete"),
            producer: CampaignHash::derive("test", b"generated-discrete-producer"),
        },
        "generated-discrete",
        None,
    )
    .expect("opportunity");
    repository
        .publish_choice_opportunity(&opportunity)
        .expect("publish opportunity");
    let generator = CandidateGeneratorSpec::new(
        crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::All,
    )
    .expect("all generator");
    let generator_id = repository
        .publish_generator(&generator)
        .expect("publish generator");
    let request = BranchRequest::new(
        opportunity.branch_point_id(lineage.genesis()),
        lineage.genesis_content(),
        opportunity.id().expect("opportunity id"),
        domain.id().expect("domain id"),
        CandidateSource::generated(generator_id),
        BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(CampaignHash::derive(
            "test",
            b"generated-discrete-request",
        ))),
        BranchBudget::new(3, 3).expect("budget"),
        StopCondition::NextChoice,
    )
    .expect("request");
    let issued = repository
        .submit_known_branch_request("generated-discrete", genesis.snapshot_id(), &request)
        .expect("issue request");
    let head = repository.head("generated-discrete").expect("request head");
    let first = finite_proposal(
        &request,
        &policy,
        &head,
        ChoiceValue::Discrete(expected[0]),
        1,
    );
    let first_issued = repository
        .issue_proposal("generated-discrete", issued.new_snapshot, &first)
        .expect("issue first stable alternative");
    let wrong_second = finite_proposal(
        &request,
        &policy,
        &repository
            .head("generated-discrete")
            .expect("proposal head"),
        ChoiceValue::Discrete(expected[2]),
        2,
    );
    assert!(matches!(
        repository.issue_proposal(
            "generated-discrete",
            first_issued.new_snapshot,
            &wrong_second,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "proposal-value-does-not-match-source-order"
        })
    ));
}

#[test]
fn weighted_categorical_generator_is_exact_keyed_and_restart_stable() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create_funded("generated-weighted", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let ids = ["alpha", "beta", "gamma", "delta"]
        .into_iter()
        .map(|label| {
            (
                label,
                AlternativeId::from_hash(CampaignHash::derive(
                    "test-weighted-alternative",
                    label.as_bytes(),
                )),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let labels = ids
        .iter()
        .map(|(label, id)| (*id, *label))
        .collect::<BTreeMap<_, _>>();
    let alternatives = ids
        .values()
        .copied()
        .map(|id| {
            (
                id,
                DiscreteAlternative::new(id, "weighted alternative", None).expect("alternative"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let domain =
        ChoiceDomain::Discrete(DiscreteDomain::new(1, alternatives).expect("discrete domain"));
    let weights = [("alpha", 1_u64), ("beta", 9), ("gamma", 3), ("delta", 20)]
        .into_iter()
        .map(|(label, weight)| (ids[label], weight))
        .collect::<BTreeMap<_, _>>();
    let generator = CandidateGeneratorSpec::new(
        crate::WEIGHTED_CATEGORICAL_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::WeightedCategorical { weights },
    )
    .expect("weighted generator");
    let generator_id = repository
        .publish_generator(&generator)
        .expect("publish weighted generator");
    let (domain, request) = generated_discrete_request(
        &repository,
        &lineage,
        domain,
        ids["alpha"],
        generator_id,
        "weighted-main",
        4,
    );

    let candidates = (1..=4)
        .map(|ordinal| {
            let Some(ChoiceValue::Discrete(alternative)) = repository
                .static_candidate_at(&request, &domain, ordinal)
                .expect("weighted candidate")
            else {
                panic!("weighted generator returned a non-discrete candidate");
            };
            alternative
        })
        .collect::<Vec<_>>();
    assert_eq!(
        candidates
            .iter()
            .map(|alternative| labels[alternative])
            .collect::<Vec<_>>(),
        vec!["beta", "delta", "gamma", "alpha"]
    );
    assert_eq!(candidates.iter().copied().collect::<BTreeSet<_>>().len(), 4);
    assert_eq!(
        repository
            .static_candidate_count(&request, &domain)
            .expect("weighted candidate count"),
        Some(4)
    );
    assert!(matches!(
        repository.static_candidate_at(&request, &domain, 5),
        Err(CampaignRepositoryError::Integrity {
            reason: "proposal-ordinal-exceeds-source-cardinality"
        })
    ));

    let issued = repository
        .submit_known_branch_request("generated-weighted", genesis.snapshot_id(), &request)
        .expect("issue weighted request");
    let projection_id = repository
        .project_finite_expansion(issued.new_snapshot, request.branch_point(), None, 10)
        .expect("project weighted request");
    assert_eq!(
        repository
            .load_expansion_state(projection_id)
            .expect("load weighted projection")
            .continuations()
            .get(&request.id().expect("request id")),
        Some(&ContinuationState::Ready)
    );
    let head = repository.head("generated-weighted").expect("request head");
    let wrong = finite_proposal(
        &request,
        &policy,
        &head,
        ChoiceValue::Discrete(candidates[1]),
        1,
    );
    assert!(matches!(
        repository.issue_proposal("generated-weighted", issued.new_snapshot, &wrong),
        Err(CampaignRepositoryError::Integrity {
            reason: "proposal-value-does-not-match-source-order"
        })
    ));
    let first = finite_proposal(
        &request,
        &policy,
        &head,
        ChoiceValue::Discrete(candidates[0]),
        1,
    );
    let first_issued = repository
        .issue_proposal("generated-weighted", issued.new_snapshot, &first)
        .expect("issue first weighted proposal");
    let open_projection_id = repository
        .project_finite_expansion(first_issued.new_snapshot, request.branch_point(), None, 10)
        .expect("project pending weighted proposal");
    assert_eq!(
        repository
            .load_expansion_state(open_projection_id)
            .expect("load pending weighted projection")
            .continuations()
            .get(&request.id().expect("request id")),
        Some(&ContinuationState::Open)
    );

    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    assert_eq!(
        restarted
            .head("generated-weighted")
            .expect("rebuild weighted history")
            .snapshot_id(),
        first_issued.new_snapshot
    );
    assert_eq!(
        restarted
            .load_expansion_state(open_projection_id)
            .expect("rebuild pending weighted projection")
            .continuations()
            .get(&request.id().expect("request id")),
        Some(&ContinuationState::Open)
    );

    let expected_candidates = candidates
        .iter()
        .copied()
        .map(ChoiceValue::Discrete)
        .map(Some)
        .collect::<Vec<_>>();
    let (_, other_request) = generated_discrete_request(
        &repository,
        &lineage,
        domain.clone(),
        ids["alpha"],
        generator_id,
        "weighted-other-0",
        4,
    );
    let other_candidates = (1..=4)
        .map(|ordinal| {
            repository
                .static_candidate_at(&other_request, &domain, ordinal)
                .expect("other weighted candidate")
        })
        .collect::<Vec<_>>();
    assert_ne!(
        other_request.id().expect("other weighted request ID"),
        request.id().expect("weighted request ID")
    );
    assert_eq!(
        other_candidates
            .into_iter()
            .flatten()
            .collect::<BTreeSet<_>>(),
        expected_candidates
            .into_iter()
            .flatten()
            .collect::<BTreeSet<_>>()
    );
}

#[test]
fn weighted_categorical_generator_bounds_and_versions_fail_closed() {
    let (repository, lineage, _) = fixture();
    let alternatives = (0..=crate::WEIGHTED_CATEGORICAL_GENERATOR_MAX_ALTERNATIVES)
        .map(|index| {
            let id = AlternativeId::from_hash(CampaignHash::derive(
                "test-weighted-bound-alternative",
                &index.to_be_bytes(),
            ));
            (
                id,
                DiscreteAlternative::new(id, "bounded alternative", None).expect("alternative"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let weights = alternatives
        .keys()
        .copied()
        .map(|alternative| (alternative, 1_u64))
        .collect::<BTreeMap<_, _>>();
    let domain =
        ChoiceDomain::Discrete(DiscreteDomain::new(1, alternatives).expect("discrete domain"));
    let oversized = CandidateGeneratorSpec::new(
        crate::WEIGHTED_CATEGORICAL_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::WeightedCategorical { weights },
    )
    .expect("oversized weighted generator");
    let oversized_id = repository
        .publish_generator(&oversized)
        .expect("publish oversized weighted generator");
    assert!(matches!(
        repository.validate_generator_for_domain(oversized_id, &domain),
        Err(CampaignRepositoryError::Integrity {
            reason: "weighted-generator-alternative-limit"
        })
    ));

    let ChoiceDomain::Discrete(discrete) = &domain else {
        panic!("expected discrete domain");
    };
    let alternative = *discrete
        .alternatives()
        .first_key_value()
        .expect("alternative")
        .0;
    let bounded = CandidateGeneratorSpec::new(
        crate::WEIGHTED_CATEGORICAL_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::WeightedCategorical {
            weights: discrete
                .alternatives()
                .keys()
                .take(crate::WEIGHTED_CATEGORICAL_GENERATOR_MAX_ALTERNATIVES)
                .copied()
                .map(|alternative| (alternative, u64::MAX))
                .collect(),
        },
    )
    .expect("bounded weighted generator");
    let bounded_id = repository
        .publish_generator(&bounded)
        .expect("publish bounded weighted generator");
    repository
        .validate_generator_for_domain(bounded_id, &domain)
        .expect("validate exact weighted bound");
    let (_, bounded_request) = generated_discrete_request(
        &repository,
        &lineage,
        domain.clone(),
        alternative,
        bounded_id,
        "weighted-boundary",
        crate::WEIGHTED_CATEGORICAL_GENERATOR_MAX_ALTERNATIVES as u64,
    );
    assert_eq!(
        repository
            .static_candidate_count(&bounded_request, &domain)
            .expect("bounded candidate count"),
        Some(crate::WEIGHTED_CATEGORICAL_GENERATOR_MAX_ALTERNATIVES as u64)
    );

    let foreign_alternative = AlternativeId::from_hash(CampaignHash::derive(
        "test-weighted-bound-alternative",
        b"foreign",
    ));
    let foreign = CandidateGeneratorSpec::new(
        crate::WEIGHTED_CATEGORICAL_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::WeightedCategorical {
            weights: BTreeMap::from([(foreign_alternative, 1)]),
        },
    )
    .expect("foreign weighted generator");
    let foreign_id = repository
        .publish_generator(&foreign)
        .expect("publish foreign weighted generator");
    assert!(matches!(
        repository.validate_generator_for_domain(foreign_id, &domain),
        Err(CampaignRepositoryError::Integrity {
            reason: "candidate-generator-discrete-alternative-mismatch"
        })
    ));

    let legacy = CandidateGeneratorSpec::new(
        crate::PERMUTED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::WeightedCategorical {
            weights: BTreeMap::from([(alternative, 1)]),
        },
    )
    .expect("legacy weighted generator");
    let legacy_id = repository
        .publish_generator(&legacy)
        .expect("publish legacy weighted generator");
    let (_, request) = generated_discrete_request(
        &repository,
        &lineage,
        domain.clone(),
        alternative,
        legacy_id,
        "weighted-legacy",
        1,
    );
    assert_eq!(
        repository
            .static_candidate_count(&request, &domain)
            .expect("legacy candidate count"),
        None
    );
    assert_eq!(
        repository
            .initial_continuation_state(&request)
            .expect("legacy continuation"),
        ContinuationState::Open
    );
}

#[test]
fn ordered_mixture_generator_schedules_deduplicates_and_restarts_exactly() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create_funded("generated-mixture", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let ids = ["alpha", "beta", "gamma", "delta"]
        .into_iter()
        .map(|label| {
            (
                label,
                AlternativeId::from_hash(CampaignHash::derive(
                    "test-mixture-alternative",
                    label.as_bytes(),
                )),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let labels = ids
        .iter()
        .map(|(label, id)| (*id, *label))
        .collect::<BTreeMap<_, _>>();
    let alternatives = ids
        .values()
        .copied()
        .map(|id| {
            (
                id,
                DiscreteAlternative::new(id, "mixture alternative", None).expect("alternative"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let domain =
        ChoiceDomain::Discrete(DiscreteDomain::new(1, alternatives).expect("discrete domain"));
    let first = CandidateGeneratorSpec::new(
        crate::WEIGHTED_CATEGORICAL_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::WeightedCategorical {
            weights: BTreeMap::from([(ids["alpha"], 5), (ids["beta"], 1)]),
        },
    )
    .expect("first child");
    let first_id = repository
        .publish_generator(&first)
        .expect("publish first child");
    let second = CandidateGeneratorSpec::new(
        crate::WEIGHTED_CATEGORICAL_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::WeightedCategorical {
            weights: BTreeMap::from([(ids["beta"], 1), (ids["gamma"], 3), (ids["delta"], 1)]),
        },
    )
    .expect("second child");
    let second_id = repository
        .publish_generator(&second)
        .expect("publish second child");
    let mixture = CandidateGeneratorSpec::new(
        crate::ORDERED_MIXTURE_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::OrderedMixture {
            components: vec![
                WeightedGenerator::new(first_id, 2).expect("first component"),
                WeightedGenerator::new(second_id, 1).expect("second component"),
            ],
        },
    )
    .expect("mixture");
    let mixture_id = repository
        .publish_generator(&mixture)
        .expect("publish mixture");
    let (domain, request) = generated_discrete_request(
        &repository,
        &lineage,
        domain,
        ids["alpha"],
        mixture_id,
        "mixture-main",
        4,
    );

    let candidates = (1..=4)
        .map(|ordinal| {
            let Some(ChoiceValue::Discrete(alternative)) = repository
                .static_candidate_at(&request, &domain, ordinal)
                .expect("mixture candidate")
            else {
                panic!("ordered mixture returned a non-discrete candidate");
            };
            alternative
        })
        .collect::<Vec<_>>();
    assert_eq!(
        candidates
            .iter()
            .map(|alternative| labels[alternative])
            .collect::<Vec<_>>(),
        vec!["beta", "alpha", "gamma", "delta"]
    );
    assert_eq!(candidates.iter().copied().collect::<BTreeSet<_>>().len(), 4);
    assert_eq!(
        repository
            .static_candidate_count(&request, &domain)
            .expect("mixture candidate count"),
        Some(4),
        "the repeated beta value was not deduplicated"
    );

    let issued = repository
        .submit_known_branch_request("generated-mixture", genesis.snapshot_id(), &request)
        .expect("issue mixture request");
    let ready = repository
        .project_finite_expansion(issued.new_snapshot, request.branch_point(), None, 10)
        .expect("project ready mixture");
    assert_eq!(
        repository
            .load_expansion_state(ready)
            .expect("load ready mixture")
            .continuations()
            .get(&request.id().expect("request id")),
        Some(&ContinuationState::Ready)
    );
    let head = repository.head("generated-mixture").expect("request head");
    let wrong = finite_proposal(
        &request,
        &policy,
        &head,
        ChoiceValue::Discrete(candidates[1]),
        1,
    );
    assert!(matches!(
        repository.issue_proposal("generated-mixture", issued.new_snapshot, &wrong),
        Err(CampaignRepositoryError::Integrity {
            reason: "proposal-value-does-not-match-source-order"
        })
    ));
    let first_proposal = finite_proposal(
        &request,
        &policy,
        &head,
        ChoiceValue::Discrete(candidates[0]),
        1,
    );
    let first_issued = repository
        .issue_proposal("generated-mixture", issued.new_snapshot, &first_proposal)
        .expect("issue first mixture proposal");
    let open = repository
        .project_finite_expansion(first_issued.new_snapshot, request.branch_point(), None, 10)
        .expect("project open mixture");

    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    assert_eq!(
        restarted
            .head("generated-mixture")
            .expect("rebuild mixture history")
            .snapshot_id(),
        first_issued.new_snapshot
    );
    assert_eq!(
        restarted
            .load_expansion_state(open)
            .expect("rebuild open mixture")
            .continuations()
            .get(&request.id().expect("request id")),
        Some(&ContinuationState::Open)
    );

    let nested = CandidateGeneratorSpec::new(
        crate::ORDERED_MIXTURE_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::OrderedMixture {
            components: vec![WeightedGenerator::new(mixture_id, 1).expect("nested component")],
        },
    )
    .expect("nested mixture");
    let nested_id = repository
        .publish_generator(&nested)
        .expect("publish nested mixture");
    let (_, nested_request) = generated_discrete_request(
        &repository,
        &lineage,
        domain.clone(),
        ids["alpha"],
        nested_id,
        "mixture-nested",
        4,
    );
    assert_eq!(
        repository
            .static_candidate_count(&nested_request, &domain)
            .expect("nested candidate count"),
        Some(4)
    );

    let legacy = CandidateGeneratorSpec::new(
        crate::WEIGHTED_CATEGORICAL_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::OrderedMixture {
            components: vec![WeightedGenerator::new(first_id, 1).expect("legacy component")],
        },
    )
    .expect("legacy mixture");
    let legacy_id = repository
        .publish_generator(&legacy)
        .expect("publish legacy mixture");
    let (_, legacy_request) = generated_discrete_request(
        &repository,
        &lineage,
        domain.clone(),
        ids["alpha"],
        legacy_id,
        "mixture-legacy",
        2,
    );
    assert_eq!(
        repository
            .static_candidate_count(&legacy_request, &domain)
            .expect("legacy candidate count"),
        None
    );
    assert_eq!(
        repository
            .initial_continuation_state(&legacy_request)
            .expect("legacy continuation"),
        ContinuationState::Open
    );
}

#[test]
fn ordered_mixture_generator_enforces_output_work_and_depth_bounds() {
    let (repository, lineage, policy, blobs) = counted_fixture();
    let genesis = repository
        .create_funded("mixture-bounds", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let alternatives = (0_u32..=crate::ORDERED_MIXTURE_GENERATOR_MAX_CANDIDATES as u32)
        .map(|index| {
            let id = AlternativeId::from_hash(CampaignHash::derive(
                "test-mixture-bound-alternative",
                &index.to_be_bytes(),
            ));
            (
                id,
                DiscreteAlternative::new(id, "mixture bound alternative", None)
                    .expect("alternative"),
            )
        })
        .collect::<BTreeMap<_, _>>();
    let domain =
        ChoiceDomain::Discrete(DiscreteDomain::new(1, alternatives).expect("discrete domain"));
    let ChoiceDomain::Discrete(discrete) = &domain else {
        panic!("expected discrete domain");
    };
    let default = *discrete
        .alternatives()
        .first_key_value()
        .expect("default alternative")
        .0;
    let chunks = discrete
        .alternatives()
        .keys()
        .copied()
        .collect::<Vec<_>>()
        .chunks(crate::WEIGHTED_CATEGORICAL_GENERATOR_MAX_ALTERNATIVES)
        .map(|chunk| {
            let child = CandidateGeneratorSpec::new(
                crate::WEIGHTED_CATEGORICAL_GENERATOR_IMPLEMENTATION_VERSION,
                CandidateGeneratorAlgorithm::WeightedCategorical {
                    weights: chunk
                        .iter()
                        .copied()
                        .map(|alternative| (alternative, 1_u64))
                        .collect(),
                },
            )
            .expect("bounded child");
            repository
                .publish_generator(&child)
                .expect("publish bounded child")
        })
        .collect::<Vec<_>>();
    assert_eq!(chunks.len(), 3);

    let exact = CandidateGeneratorSpec::new(
        crate::ORDERED_MIXTURE_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::OrderedMixture {
            components: chunks[..2]
                .iter()
                .copied()
                .map(|child| WeightedGenerator::new(child, 1).expect("exact component"))
                .collect(),
        },
    )
    .expect("exact-bound mixture");
    let exact_id = repository
        .publish_generator(&exact)
        .expect("publish exact-bound mixture");
    let (_, exact_request) = generated_discrete_request(
        &repository,
        &lineage,
        domain.clone(),
        default,
        exact_id,
        "mixture-exact-bound",
        crate::ORDERED_MIXTURE_GENERATOR_MAX_CANDIDATES as u64,
    );
    assert_eq!(
        repository
            .static_candidate_count(&exact_request, &domain)
            .expect("exact-bound candidate count"),
        Some(crate::ORDERED_MIXTURE_GENERATOR_MAX_CANDIDATES as u64)
    );

    let oversized = CandidateGeneratorSpec::new(
        crate::ORDERED_MIXTURE_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::OrderedMixture {
            components: chunks
                .iter()
                .copied()
                .map(|child| WeightedGenerator::new(child, 1).expect("oversized component"))
                .collect(),
        },
    )
    .expect("oversized mixture");
    let oversized_id = repository
        .publish_generator(&oversized)
        .expect("publish oversized mixture");
    let (_, oversized_request) = generated_discrete_request(
        &repository,
        &lineage,
        domain.clone(),
        default,
        oversized_id,
        "mixture-oversized",
        crate::ORDERED_MIXTURE_GENERATOR_MAX_CANDIDATES as u64 + 1,
    );
    assert!(matches!(
        repository.static_candidate_count(&oversized_request, &domain),
        Err(CampaignRepositoryError::Integrity {
            reason: "ordered-mixture-generator-candidate-limit"
        })
    ));
    let discovered = repository
        .discover_choice_opportunity(
            "mixture-bounds",
            genesis.snapshot_id(),
            oversized_request.parent(),
            oversized_request.opportunity(),
        )
        .expect("discover oversized opportunity");
    let objects_before = blobs.object_count().expect("objects before rejection");
    assert!(matches!(
        repository.submit_branch_request(
            "mixture-bounds",
            discovered.new_snapshot,
            &oversized_request,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "ordered-mixture-generator-candidate-limit"
        })
    ));
    assert_eq!(
        blobs.object_count().expect("objects after rejection"),
        objects_before
    );
    assert_eq!(
        repository
            .head("mixture-bounds")
            .expect("unchanged bounds head")
            .snapshot_id(),
        discovered.new_snapshot
    );

    let work_components = (0..129)
        .map(|_| WeightedGenerator::new(chunks[0], 1).expect("work component"))
        .collect();
    let excessive_work = CandidateGeneratorSpec::new(
        crate::ORDERED_MIXTURE_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::OrderedMixture {
            components: work_components,
        },
    )
    .expect("work-bounded mixture");
    let excessive_work_id = repository
        .publish_generator(&excessive_work)
        .expect("publish work-bounded mixture");
    let (_, excessive_work_request) = generated_discrete_request(
        &repository,
        &lineage,
        domain.clone(),
        default,
        excessive_work_id,
        "mixture-work-limit",
        1,
    );
    assert!(matches!(
        repository.static_candidate_count(&excessive_work_request, &domain),
        Err(CampaignRepositoryError::Integrity {
            reason: "ordered-mixture-generator-work-limit"
        })
    ));

    let one = CandidateGeneratorSpec::new(
        crate::WEIGHTED_CATEGORICAL_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::WeightedCategorical {
            weights: BTreeMap::from([(default, 1)]),
        },
    )
    .expect("one-value child");
    let mut nested_id = repository
        .publish_generator(&one)
        .expect("publish one-value child");
    for _ in 0..=crate::ORDERED_MIXTURE_GENERATOR_MAX_DEPTH {
        let nested = CandidateGeneratorSpec::new(
            crate::ORDERED_MIXTURE_GENERATOR_IMPLEMENTATION_VERSION,
            CandidateGeneratorAlgorithm::OrderedMixture {
                components: vec![WeightedGenerator::new(nested_id, 1).expect("nested component")],
            },
        )
        .expect("nested mixture");
        nested_id = repository
            .publish_generator(&nested)
            .expect("publish nested mixture");
    }
    let (_, nested_request) = generated_discrete_request(
        &repository,
        &lineage,
        domain.clone(),
        default,
        nested_id,
        "mixture-depth-limit",
        1,
    );
    assert!(matches!(
        repository.static_candidate_count(&nested_request, &domain),
        Err(CampaignRepositoryError::Integrity {
            reason: "ordered-mixture-generator-depth-limit"
        })
    ));

    let suspended_child =
        CandidateGeneratorSpec::new(1, CandidateGeneratorAlgorithm::All).expect("suspended child");
    let suspended_child_id = repository
        .publish_generator(&suspended_child)
        .expect("publish suspended child");
    let suspended = CandidateGeneratorSpec::new(
        crate::ORDERED_MIXTURE_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::OrderedMixture {
            components: vec![
                WeightedGenerator::new(suspended_child_id, 1).expect("suspended component"),
            ],
        },
    )
    .expect("suspended mixture");
    let suspended_id = repository
        .publish_generator(&suspended)
        .expect("publish suspended mixture");
    let (_, suspended_request) = generated_discrete_request(
        &repository,
        &lineage,
        domain.clone(),
        default,
        suspended_id,
        "mixture-suspended-child",
        1,
    );
    assert_eq!(
        repository
            .static_candidate_count(&suspended_request, &domain)
            .expect("suspended candidate count"),
        None
    );
    assert_eq!(
        repository
            .initial_continuation_state(&suspended_request)
            .expect("suspended continuation"),
        ContinuationState::Open
    );
}

#[test]
fn progressive_integer_generator_refines_only_after_exact_feedback() {
    let (repository, lineage, policy, blobs) = counted_fixture();
    let genesis = repository
        .create_funded("generated-progressive", &lineage, &policy, &BTreeMap::new())
        .expect("create progressive campaign");
    let domain = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(16),
            1,
            None,
            ExactRational::new(1, 1).expect("scale"),
            Vec::new(),
        )
        .expect("progressive domain"),
    );
    let generator = CandidateGeneratorSpec::new(
        crate::PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::ProgressiveInteger {
            initial_strata: 3,
            feedback_interval: 2,
        },
    )
    .expect("progressive generator");
    let generator_id = repository
        .publish_generator(&generator)
        .expect("publish progressive generator");
    let (_, request) = generated_integer_request(
        &repository,
        &lineage,
        domain.clone(),
        IntegerValue::Unsigned(8),
        generator_id,
        "progressive",
        9,
    );
    let expected = [0, 8, 16, 4, 12, 2, 6, 10, 14]
        .map(|value| ChoiceValue::Integer(IntegerValue::Unsigned(value)));
    assert_eq!(
        repository
            .static_candidate_count(&request, &domain)
            .expect("history-independent count"),
        None
    );
    for (index, expected) in expected.iter().enumerate() {
        let visits = if index < 3 {
            0
        } else {
            ((index - 2) * 2) as u64
        };
        assert_eq!(
            repository
                .candidate_at_with_feedback(&request, &domain, index as u64 + 1, visits)
                .expect("progressive candidate"),
            Some(expected.clone())
        );
    }

    let requested = repository
        .submit_known_branch_request("generated-progressive", genesis.snapshot_id(), &request)
        .expect("submit progressive request");
    let mut current = requested.new_snapshot;
    let mut observations = Vec::new();
    for (index, value) in expected.iter().take(3).enumerate() {
        let head = repository
            .head("generated-progressive")
            .expect("proposal head");
        let proposal = finite_proposal(&request, &policy, &head, value.clone(), index as u64 + 1);
        let proposed = repository
            .issue_proposal("generated-progressive", current, &proposal)
            .expect("issue initial progressive proposal");
        let (selection, path, attempt) = branch_attempt(&repository, &request, &proposal);
        let admitted = repository
            .admit_proposal(
                "generated-progressive",
                proposed.new_snapshot,
                proposed.proposal,
                &selection,
                &path,
                &attempt,
            )
            .expect("admit initial progressive proposal");
        current = admitted.new_snapshot;
        observations.push(generated_observation(
            &repository,
            &lineage,
            &admitted,
            &path,
            request.opportunity(),
            &format!("initial-{index}"),
        ));
    }

    let planner_state = CanonicalFrontierPlanner::initial_state().expect("planner state");
    let (_, _, waiting_invocation) = canonical_planner_basis_with_page(
        &repository,
        "generated-progressive",
        current,
        &planner_state,
        None,
        16,
    );
    let waiting_request = repository
        .build_planner_request(
            current,
            waiting_invocation.id().expect("waiting invocation id"),
        )
        .expect("build waiting planner request");
    assert_eq!(waiting_request.input_bundle().len(), 2);
    let waiting_output = CanonicalFrontierPlanner
        .plan(&waiting_request)
        .expect("plan waiting frontier");
    assert!(matches!(
        waiting_output.proposal().disposition(),
        PlannerProposalDisposition::NoWork
    ));

    let request_id = request.id().expect("request id");
    let second_request = BranchRequest::new(
        request.branch_point(),
        request.parent(),
        request.opportunity(),
        request.domain(),
        CandidateSource::generated(generator_id),
        BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(CampaignHash::derive(
            "test",
            b"progressive-second-request",
        ))),
        BranchBudget::new(9, 9).expect("second request budget"),
        StopCondition::NextChoice,
    )
    .expect("second progressive request");
    let second_requested = repository
        .submit_branch_request("generated-progressive", current, &second_request)
        .expect("submit second progressive request");
    current = second_requested.new_snapshot;
    for (index, value) in expected.iter().take(3).enumerate() {
        let head = repository
            .head("generated-progressive")
            .expect("second proposal head");
        let proposal = finite_proposal(
            &second_request,
            &policy,
            &head,
            value.clone(),
            index as u64 + 1,
        );
        let proposed = repository
            .issue_proposal("generated-progressive", current, &proposal)
            .expect("issue second progressive proposal");
        let (selection, path, attempt) = branch_attempt(&repository, &second_request, &proposal);
        let admitted = repository
            .admit_proposal(
                "generated-progressive",
                proposed.new_snapshot,
                proposed.proposal,
                &selection,
                &path,
                &attempt,
            )
            .expect("admit second progressive proposal");
        current = admitted.new_snapshot;
    }
    let second_request_id = second_request.id().expect("second request id");
    let waiting_content = repository
        .lookup_frontier_projection(
            repository
                .read_snapshot(current.content_id())
                .expect("waiting snapshot")
                .snapshot
                .roots()
                .exploration,
            request_id,
        )
        .expect("waiting frontier lookup")
        .0;
    let waiting = repository
        .read_continuation_projection(waiting_content)
        .expect("waiting frontier projection");
    assert_eq!(
        waiting.state(),
        ContinuationState::WaitingForFeedback(
            FeedbackWait::new(0, 2).expect("initial feedback wait")
        )
    );

    let head_before_early = repository
        .head("generated-progressive")
        .expect("early head");
    let early = finite_proposal(
        &request,
        &policy,
        &head_before_early,
        expected[3].clone(),
        4,
    );
    let object_count = blobs.object_count().expect("objects before early proposal");
    assert!(matches!(
        repository.issue_proposal("generated-progressive", current, &early),
        Err(CampaignRepositoryError::Integrity {
            reason: "progressive-generator-feedback-is-insufficient"
        })
    ));
    assert_eq!(
        blobs.object_count().expect("objects after early proposal"),
        object_count
    );

    let first_observed = repository
        .publish_observation("generated-progressive", current, &observations[0])
        .expect("publish first feedback observation");
    current = first_observed.new_snapshot;
    let after_one_content = repository
        .lookup_frontier_projection(
            repository
                .read_snapshot(current.content_id())
                .expect("one-visit snapshot")
                .snapshot
                .roots()
                .exploration,
            request_id,
        )
        .expect("one-visit frontier lookup")
        .0;
    let after_one = repository
        .read_continuation_projection(after_one_content)
        .expect("one-visit frontier projection");
    assert_eq!(
        after_one.state(),
        ContinuationState::WaitingForFeedback(
            FeedbackWait::new(1, 2).expect("one-visit feedback wait")
        )
    );
    let second_after_one = repository
        .read_continuation_projection(
            repository
                .lookup_frontier_projection(
                    repository
                        .read_snapshot(current.content_id())
                        .expect("one-visit second-request snapshot")
                        .snapshot
                        .roots()
                        .exploration,
                    second_request_id,
                )
                .expect("one-visit second frontier lookup")
                .0,
        )
        .expect("one-visit second frontier projection");
    assert_eq!(
        second_after_one.state(),
        ContinuationState::WaitingForFeedback(
            FeedbackWait::new(1, 2).expect("one-visit second feedback wait")
        )
    );

    let second_observed = repository
        .publish_observation("generated-progressive", current, &observations[1])
        .expect("publish second feedback observation");
    current = second_observed.new_snapshot;
    let after_two_content = repository
        .lookup_frontier_projection(
            repository
                .read_snapshot(current.content_id())
                .expect("two-visit snapshot")
                .snapshot
                .roots()
                .exploration,
            request_id,
        )
        .expect("two-visit frontier lookup")
        .0;
    let after_two = repository
        .read_continuation_projection(after_two_content)
        .expect("two-visit frontier projection");
    assert_eq!(after_two.state(), ContinuationState::Ready);
    let second_after_two = repository
        .read_continuation_projection(
            repository
                .lookup_frontier_projection(
                    repository
                        .read_snapshot(current.content_id())
                        .expect("two-visit second-request snapshot")
                        .snapshot
                        .roots()
                        .exploration,
                    second_request_id,
                )
                .expect("two-visit second frontier lookup")
                .0,
        )
        .expect("two-visit second frontier projection");
    assert_eq!(second_after_two.state(), ContinuationState::Ready);

    let ready_head = repository
        .head("generated-progressive")
        .expect("ready head");
    let fourth = finite_proposal(&request, &policy, &ready_head, expected[3].clone(), 4);
    let proposed = repository
        .issue_proposal("generated-progressive", current, &fourth)
        .expect("issue first refinement");
    let (selection, path, attempt) = branch_attempt(&repository, &request, &fourth);
    let admitted = repository
        .admit_proposal(
            "generated-progressive",
            proposed.new_snapshot,
            proposed.proposal,
            &selection,
            &path,
            &attempt,
        )
        .expect("admit first refinement");
    current = admitted.new_snapshot;
    let after_refinement_content = repository
        .lookup_frontier_projection(
            repository
                .read_snapshot(current.content_id())
                .expect("refinement snapshot")
                .snapshot
                .roots()
                .exploration,
            request_id,
        )
        .expect("refinement frontier lookup")
        .0;
    let after_refinement = repository
        .read_continuation_projection(after_refinement_content)
        .expect("refinement frontier projection");
    assert_eq!(
        after_refinement.state(),
        ContinuationState::WaitingForFeedback(
            FeedbackWait::new(2, 4).expect("second feedback wait")
        )
    );

    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    restarted
        .validate_complete_head(current.content_id())
        .expect("restart validates progressive feedback transition");
    let rebuilt = restarted
        .project_finite_expansion(current, request.branch_point(), None, 10)
        .expect("rebuild progressive expansion");
    assert_eq!(
        restarted
            .load_expansion_state(rebuilt)
            .expect("load rebuilt progressive expansion")
            .continuations()
            .get(&request_id),
        Some(&ContinuationState::WaitingForFeedback(
            FeedbackWait::new(2, 4).expect("rebuilt feedback wait")
        ))
    );
    assert_eq!(
        restarted
            .load_expansion_state(rebuilt)
            .expect("reload rebuilt progressive expansion")
            .continuations()
            .get(&second_request_id),
        Some(&ContinuationState::Ready)
    );
}

#[test]
fn feedback_progressive_integer_refines_the_highest_owner_scored_interval() {
    let (repository, lineage, policy, blobs) = counted_fixture();
    let genesis = repository
        .create_funded(
            "generated-feedback-progressive",
            &lineage,
            &policy,
            &BTreeMap::new(),
        )
        .expect("create feedback-progressive campaign");
    let domain = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(16),
            1,
            None,
            ExactRational::new(1, 1).expect("scale"),
            vec![IntegerValue::Unsigned(2), IntegerValue::Unsigned(6)],
        )
        .expect("feedback-progressive domain"),
    );
    let generator = CandidateGeneratorSpec::new(
        crate::FEEDBACK_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::ProgressiveInteger {
            initial_strata: 3,
            feedback_interval: 2,
        },
    )
    .expect("feedback-progressive generator");
    let generator_id = repository
        .publish_generator(&generator)
        .expect("publish feedback-progressive generator");
    let (_, request) = generated_integer_request(
        &repository,
        &lineage,
        domain,
        IntegerValue::Unsigned(8),
        generator_id,
        "feedback-progressive",
        9,
    );
    let requested = repository
        .submit_known_branch_request(
            "generated-feedback-progressive",
            genesis.snapshot_id(),
            &request,
        )
        .expect("submit feedback-progressive request");

    let initial = [0_u64, 8, 16];
    let mut current = requested.new_snapshot;
    let mut observations = Vec::new();
    for (index, value) in initial.into_iter().enumerate() {
        let head = repository
            .head("generated-feedback-progressive")
            .expect("feedback-progressive proposal head");
        let proposal = finite_proposal(
            &request,
            &policy,
            &head,
            ChoiceValue::Integer(IntegerValue::Unsigned(value)),
            index as u64 + 1,
        );
        let proposed = repository
            .issue_proposal("generated-feedback-progressive", current, &proposal)
            .expect("issue feedback-progressive initial proposal");
        let (selection, path, attempt) = branch_attempt(&repository, &request, &proposal);
        let admitted = repository
            .admit_proposal(
                "generated-feedback-progressive",
                proposed.new_snapshot,
                proposed.proposal,
                &selection,
                &path,
                &attempt,
            )
            .expect("admit feedback-progressive initial proposal");
        current = admitted.new_snapshot;
        observations.push(generated_observation(
            &repository,
            &lineage,
            &admitted,
            &path,
            request.opportunity(),
            &format!("feedback-progressive-{index}"),
        ));
    }

    for (index, observation) in observations.iter().take(2).enumerate() {
        current = repository
            .publish_observation("generated-feedback-progressive", current, observation)
            .expect("publish feedback-progressive observation")
            .new_snapshot;
        if index == 0 {
            let early_head = repository
                .head("generated-feedback-progressive")
                .expect("early feedback-progressive head");
            let early = finite_proposal(
                &request,
                &policy,
                &early_head,
                ChoiceValue::Integer(IntegerValue::Unsigned(12)),
                4,
            );
            let before_early = blobs
                .object_count()
                .expect("objects before early feedback refinement");
            assert!(matches!(
                repository.issue_proposal("generated-feedback-progressive", current, &early),
                Err(CampaignRepositoryError::Integrity {
                    reason: "progressive-generator-feedback-is-insufficient"
                })
            ));
            assert_eq!(
                blobs
                    .object_count()
                    .expect("objects after early feedback refinement"),
                before_early
            );
        }
    }
    let ready = repository
        .head("generated-feedback-progressive")
        .expect("feedback-progressive ready head");
    let planner_state = CanonicalFrontierPlanner::initial_state().expect("planner state");
    let (_, _, invocation) = canonical_planner_basis_with_page(
        &repository,
        "generated-feedback-progressive",
        current,
        &planner_state,
        None,
        16,
    );
    let planner_request = repository
        .build_planner_request(current, invocation.id().expect("planner invocation id"))
        .expect("build feedback-progressive planner request");
    let planner_output = CanonicalFrontierPlanner
        .plan(&planner_request)
        .expect("plan feedback-progressive frontier");
    let PlannerProposalDisposition::Issue { proposals, .. } =
        planner_output.proposal().disposition()
    else {
        panic!("ready feedback-progressive request did not issue");
    };
    assert_eq!(
        proposals.first().map(Proposal::value),
        Some(&ChoiceValue::Integer(IntegerValue::Unsigned(12)))
    );
    let old_largest_gap = finite_proposal(
        &request,
        &policy,
        &ready,
        ChoiceValue::Integer(IntegerValue::Unsigned(4)),
        4,
    );
    let before_rejection = blobs
        .object_count()
        .expect("objects before wrong feedback refinement");
    assert!(matches!(
        repository.issue_proposal("generated-feedback-progressive", current, &old_largest_gap,),
        Err(CampaignRepositoryError::Integrity {
            reason: "proposal-value-does-not-match-source-order"
        })
    ));
    assert_eq!(
        blobs
            .object_count()
            .expect("objects after wrong feedback refinement"),
        before_rejection
    );

    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    restarted
        .validate_complete_head(current.content_id())
        .expect("restart validates feedback-progressive head");
    let restarted_head = restarted
        .head("generated-feedback-progressive")
        .expect("restarted feedback-progressive head");
    let scored_refinement = finite_proposal(
        &request,
        &policy,
        &restarted_head,
        ChoiceValue::Integer(IntegerValue::Unsigned(12)),
        4,
    );
    let refined = restarted
        .issue_proposal(
            "generated-feedback-progressive",
            current,
            &scored_refinement,
        )
        .expect("issue owner-scored feedback refinement");
    CampaignRepository::new(repository.blobs.clone(), repository.refs.clone())
        .validate_complete_head(refined.new_snapshot.content_id())
        .expect("restart validates owner-scored feedback refinement");
}

#[test]
fn landmark_progressive_integer_prioritizes_an_authenticated_producer_landmark() {
    let (repository, lineage, policy, blobs) = counted_fixture();
    let genesis = repository
        .create_funded(
            "generated-landmark-progressive",
            &lineage,
            &policy,
            &BTreeMap::new(),
        )
        .expect("create landmark-progressive campaign");
    let domain = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(16),
            1,
            None,
            ExactRational::new(1, 1).expect("scale"),
            vec![IntegerValue::Unsigned(2), IntegerValue::Unsigned(6)],
        )
        .expect("landmark-progressive domain"),
    );
    let generator = CandidateGeneratorSpec::new(
        crate::LANDMARK_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::ProgressiveInteger {
            initial_strata: 3,
            feedback_interval: 2,
        },
    )
    .expect("landmark-progressive generator");
    let generator_id = repository
        .publish_generator(&generator)
        .expect("publish landmark-progressive generator");
    let (_, request) = generated_integer_request(
        &repository,
        &lineage,
        domain,
        IntegerValue::Unsigned(8),
        generator_id,
        "landmark-progressive",
        9,
    );
    let requested = repository
        .submit_known_branch_request(
            "generated-landmark-progressive",
            genesis.snapshot_id(),
            &request,
        )
        .expect("submit landmark-progressive request");

    let mut current = requested.new_snapshot;
    let mut observations = Vec::new();
    for (index, value) in [0_u64, 8, 16].into_iter().enumerate() {
        let head = repository
            .head("generated-landmark-progressive")
            .expect("landmark-progressive proposal head");
        let proposal = finite_proposal(
            &request,
            &policy,
            &head,
            ChoiceValue::Integer(IntegerValue::Unsigned(value)),
            index as u64 + 1,
        );
        let proposed = repository
            .issue_proposal("generated-landmark-progressive", current, &proposal)
            .expect("issue landmark-progressive initial proposal");
        let (selection, path, attempt) = branch_attempt(&repository, &request, &proposal);
        let admitted = repository
            .admit_proposal(
                "generated-landmark-progressive",
                proposed.new_snapshot,
                proposed.proposal,
                &selection,
                &path,
                &attempt,
            )
            .expect("admit landmark-progressive initial proposal");
        current = admitted.new_snapshot;
        observations.push(generated_observation(
            &repository,
            &lineage,
            &admitted,
            &path,
            request.opportunity(),
            &format!("landmark-progressive-{index}"),
        ));
    }
    for observation in observations.iter().take(2) {
        current = repository
            .publish_observation("generated-landmark-progressive", current, observation)
            .expect("publish landmark-progressive observation")
            .new_snapshot;
    }

    let ready = repository
        .head("generated-landmark-progressive")
        .expect("landmark-progressive ready head");
    let planner_state = CanonicalFrontierPlanner::initial_state().expect("planner state");
    let (_, _, invocation) = canonical_planner_basis_with_page(
        &repository,
        "generated-landmark-progressive",
        current,
        &planner_state,
        None,
        16,
    );
    let planner_request = repository
        .build_planner_request(current, invocation.id().expect("planner invocation id"))
        .expect("build landmark-progressive planner request");
    let planner_output = CanonicalFrontierPlanner
        .plan(&planner_request)
        .expect("plan landmark-progressive frontier");
    let PlannerProposalDisposition::Issue { proposals, .. } =
        planner_output.proposal().disposition()
    else {
        panic!("ready landmark-progressive request did not issue");
    };
    assert_eq!(
        proposals.first().map(Proposal::value),
        Some(&ChoiceValue::Integer(IntegerValue::Unsigned(2)))
    );

    let puct_only_candidate = finite_proposal(
        &request,
        &policy,
        &ready,
        ChoiceValue::Integer(IntegerValue::Unsigned(12)),
        4,
    );
    let before_rejection = blobs
        .object_count()
        .expect("objects before non-landmark refinement");
    assert!(matches!(
        repository.issue_proposal(
            "generated-landmark-progressive",
            current,
            &puct_only_candidate,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "proposal-value-does-not-match-source-order"
        })
    ));
    assert_eq!(
        blobs
            .object_count()
            .expect("objects after non-landmark refinement"),
        before_rejection
    );

    let landmark = finite_proposal(
        &request,
        &policy,
        &ready,
        ChoiceValue::Integer(IntegerValue::Unsigned(2)),
        4,
    );
    let refined = repository
        .issue_proposal("generated-landmark-progressive", current, &landmark)
        .expect("issue landmark-progressive refinement");
    CampaignRepository::new(repository.blobs.clone(), repository.refs.clone())
        .validate_complete_head(refined.new_snapshot.content_id())
        .expect("restart validates landmark-progressive refinement");
}

#[test]
fn measurement_progressive_integer_prioritizes_verified_objective_discontinuity() {
    let (repository, lineage, base_policy, blobs) = counted_fixture();
    let objective_name = "latency";
    let policy = CampaignPolicy::new(
        base_policy.scenario(),
        base_policy.campaign_seed(),
        base_policy.mode(),
        base_policy.explorer().clone(),
        base_policy.choice_policies().clone(),
        BTreeMap::from([(
            objective_name.to_owned(),
            Objective::new(objective_name, ObjectiveGoal::Minimize, 1_000_000)
                .expect("measurement-progressive objective"),
        )]),
        base_policy.guidance().clone(),
        base_policy.stop_conditions().clone(),
        base_policy.fairness(),
        base_policy.retention(),
        base_policy.admits_scenario_defaults(),
    )
    .expect("measurement-progressive policy");
    let campaign = "generated-measurement-progressive";
    let genesis = repository
        .create_funded(campaign, &lineage, &policy, &BTreeMap::new())
        .expect("create measurement-progressive campaign");
    let domain = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(16),
            1,
            None,
            ExactRational::new(1, 1).expect("scale"),
            vec![IntegerValue::Unsigned(2), IntegerValue::Unsigned(6)],
        )
        .expect("measurement-progressive domain"),
    );
    let generator = CandidateGeneratorSpec::new(
        crate::MEASUREMENT_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::ProgressiveInteger {
            initial_strata: 3,
            feedback_interval: 2,
        },
    )
    .expect("measurement-progressive generator");
    let generator_id = repository
        .publish_generator(&generator)
        .expect("publish measurement-progressive generator");
    let (_, request) = generated_integer_request(
        &repository,
        &lineage,
        domain,
        IntegerValue::Unsigned(8),
        generator_id,
        "measurement-progressive",
        9,
    );
    let requested = repository
        .submit_known_branch_request(campaign, genesis.snapshot_id(), &request)
        .expect("submit measurement-progressive request");

    let mut current = requested.new_snapshot;
    let mut observations = Vec::new();
    for (index, value) in [0_u64, 8, 16].into_iter().enumerate() {
        let head = repository
            .head(campaign)
            .expect("measurement-progressive proposal head");
        let proposal = finite_proposal(
            &request,
            &policy,
            &head,
            ChoiceValue::Integer(IntegerValue::Unsigned(value)),
            index as u64 + 1,
        );
        let proposed = repository
            .issue_proposal(campaign, current, &proposal)
            .expect("issue measurement-progressive initial proposal");
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
            .expect("admit measurement-progressive initial proposal");
        current = admitted.new_snapshot;
        observations.push(generated_observation(
            &repository,
            &lineage,
            &admitted,
            &path,
            request.opportunity(),
            &format!("measurement-progressive-{index}"),
        ));
    }
    for observation in observations.iter().take(2) {
        current = repository
            .publish_observation(campaign, current, observation)
            .expect("publish measurement-progressive observation")
            .new_snapshot;
        let properties = repository
            .load_property_verdict_set(observation.properties())
            .expect("measurement-progressive properties");
        let evaluation = evaluate_objectives(
            &policy,
            observation,
            &properties,
            BTreeMap::from([(objective_name.to_owned(), ObjectiveValue::Unsigned(7))]),
        )
        .expect("measurement-progressive evaluation");
        current = repository
            .publish_objective_evaluation(campaign, current, &evaluation)
            .expect("publish measurement-progressive evaluation")
            .new_snapshot;
    }

    let ready = repository
        .head(campaign)
        .expect("measurement-progressive ready head");
    let planner_state = CanonicalFrontierPlanner::initial_state().expect("planner state");
    let (_, _, invocation) =
        canonical_planner_basis_with_page(&repository, campaign, current, &planner_state, None, 16);
    let planner_request = repository
        .build_planner_request(current, invocation.id().expect("planner invocation id"))
        .expect("build measurement-progressive planner request");
    let planner_output = CanonicalFrontierPlanner
        .plan(&planner_request)
        .expect("plan measurement-progressive frontier");
    let PlannerProposalDisposition::Issue { proposals, .. } =
        planner_output.proposal().disposition()
    else {
        panic!("ready measurement-progressive request did not issue");
    };
    assert_eq!(
        proposals.first().map(Proposal::value),
        Some(&ChoiceValue::Integer(IntegerValue::Unsigned(12)))
    );

    let landmark_only_candidate = finite_proposal(
        &request,
        &policy,
        &ready,
        ChoiceValue::Integer(IntegerValue::Unsigned(2)),
        4,
    );
    let before_rejection = blobs
        .object_count()
        .expect("objects before measurement-discontinuity substitution");
    assert!(matches!(
        repository.issue_proposal(campaign, current, &landmark_only_candidate),
        Err(CampaignRepositoryError::Integrity {
            reason: "proposal-value-does-not-match-source-order"
        })
    ));
    assert_eq!(
        blobs
            .object_count()
            .expect("objects after measurement-discontinuity substitution"),
        before_rejection
    );

    let discontinuity = finite_proposal(
        &request,
        &policy,
        &ready,
        ChoiceValue::Integer(IntegerValue::Unsigned(12)),
        4,
    );
    let refined = repository
        .issue_proposal(campaign, current, &discontinuity)
        .expect("issue measurement-progressive refinement");
    CampaignRepository::new(repository.blobs.clone(), repository.refs.clone())
        .validate_complete_head(refined.new_snapshot.content_id())
        .expect("restart validates measurement-progressive refinement");
}

#[test]
fn coverage_progressive_integer_prioritizes_verified_novelty_discontinuity() {
    let (repository, lineage, base_policy, blobs) = counted_fixture();
    let objective_name = "latency";
    let policy = CampaignPolicy::new(
        base_policy.scenario(),
        base_policy.campaign_seed(),
        base_policy.mode(),
        base_policy.explorer().clone(),
        base_policy.choice_policies().clone(),
        BTreeMap::from([(
            objective_name.to_owned(),
            Objective::new(objective_name, ObjectiveGoal::Minimize, 1_000_000)
                .expect("coverage-progressive objective"),
        )]),
        base_policy.guidance().clone(),
        base_policy.stop_conditions().clone(),
        base_policy.fairness(),
        base_policy.retention(),
        base_policy.admits_scenario_defaults(),
    )
    .expect("coverage-progressive policy");
    let campaign = "generated-coverage-progressive";
    let genesis = repository
        .create_funded(campaign, &lineage, &policy, &BTreeMap::new())
        .expect("create coverage-progressive campaign");
    let domain = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(16),
            1,
            None,
            ExactRational::new(1, 1).expect("scale"),
            vec![IntegerValue::Unsigned(2), IntegerValue::Unsigned(6)],
        )
        .expect("coverage-progressive domain"),
    );
    let generator = CandidateGeneratorSpec::new(
        crate::COVERAGE_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::ProgressiveInteger {
            initial_strata: 3,
            feedback_interval: 2,
        },
    )
    .expect("coverage-progressive generator");
    let generator_id = repository
        .publish_generator(&generator)
        .expect("publish coverage-progressive generator");
    let (_, request) = generated_integer_request(
        &repository,
        &lineage,
        domain,
        IntegerValue::Unsigned(8),
        generator_id,
        "coverage-progressive",
        9,
    );
    let requested = repository
        .submit_known_branch_request(campaign, genesis.snapshot_id(), &request)
        .expect("submit coverage-progressive request");

    let mut current = requested.new_snapshot;
    let mut observations = Vec::new();
    for (index, value) in [0_u64, 8, 16].into_iter().enumerate() {
        let head = repository
            .head(campaign)
            .expect("coverage-progressive proposal head");
        let proposal = finite_proposal(
            &request,
            &policy,
            &head,
            ChoiceValue::Integer(IntegerValue::Unsigned(value)),
            index as u64 + 1,
        );
        let proposed = repository
            .issue_proposal(campaign, current, &proposal)
            .expect("issue coverage-progressive initial proposal");
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
            .expect("admit coverage-progressive initial proposal");
        current = admitted.new_snapshot;
        let coverage = if index == 0 {
            BTreeSet::from([
                CampaignHash::derive("test.coverage-progressive", b"block-a"),
                CampaignHash::derive("test.coverage-progressive", b"block-b"),
                CampaignHash::derive("test.coverage-progressive", b"block-c"),
            ])
        } else {
            BTreeSet::new()
        };
        observations.push(generated_observation_with_coverage(
            &repository,
            &lineage,
            &admitted,
            &path,
            request.opportunity(),
            &format!("coverage-progressive-{index}"),
            coverage,
        ));
    }
    for observation in observations.iter().take(2) {
        current = repository
            .publish_observation(campaign, current, observation)
            .expect("publish coverage-progressive observation")
            .new_snapshot;
        let properties = repository
            .load_property_verdict_set(observation.properties())
            .expect("coverage-progressive properties");
        let evaluation = evaluate_objectives(
            &policy,
            observation,
            &properties,
            BTreeMap::from([(objective_name.to_owned(), ObjectiveValue::Unsigned(7))]),
        )
        .expect("coverage-progressive evaluation");
        current = repository
            .publish_objective_evaluation(campaign, current, &evaluation)
            .expect("publish coverage-progressive evaluation")
            .new_snapshot;
    }

    let ready = repository
        .head(campaign)
        .expect("coverage-progressive ready head");
    let planner_state = CanonicalFrontierPlanner::initial_state().expect("planner state");
    let (_, _, invocation) =
        canonical_planner_basis_with_page(&repository, campaign, current, &planner_state, None, 16);
    let planner_request = repository
        .build_planner_request(current, invocation.id().expect("planner invocation id"))
        .expect("build coverage-progressive planner request");
    let planner_output = CanonicalFrontierPlanner
        .plan(&planner_request)
        .expect("plan coverage-progressive frontier");
    let PlannerProposalDisposition::Issue { proposals, .. } =
        planner_output.proposal().disposition()
    else {
        panic!("ready coverage-progressive request did not issue");
    };
    assert_eq!(
        proposals.first().map(Proposal::value),
        Some(&ChoiceValue::Integer(IntegerValue::Unsigned(2)))
    );

    let objective_only_candidate = finite_proposal(
        &request,
        &policy,
        &ready,
        ChoiceValue::Integer(IntegerValue::Unsigned(12)),
        4,
    );
    let before_rejection = blobs
        .object_count()
        .expect("objects before novelty-discontinuity substitution");
    assert!(matches!(
        repository.issue_proposal(campaign, current, &objective_only_candidate),
        Err(CampaignRepositoryError::Integrity {
            reason: "proposal-value-does-not-match-source-order"
        })
    ));
    assert_eq!(
        blobs
            .object_count()
            .expect("objects after novelty-discontinuity substitution"),
        before_rejection
    );

    let discontinuity = finite_proposal(
        &request,
        &policy,
        &ready,
        ChoiceValue::Integer(IntegerValue::Unsigned(2)),
        4,
    );
    let refined = repository
        .issue_proposal(campaign, current, &discontinuity)
        .expect("issue coverage-progressive refinement");
    CampaignRepository::new(repository.blobs.clone(), repository.refs.clone())
        .validate_complete_head(refined.new_snapshot.content_id())
        .expect("restart validates coverage-progressive refinement");
}

#[test]
fn finding_progressive_integer_prioritizes_verified_reward_discontinuity() {
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
            GuidanceWeight::new(finding_signal, 1_000_000).expect("finding-progressive guidance"),
        )]),
        base_policy.stop_conditions().clone(),
        base_policy.fairness(),
        base_policy.retention(),
        base_policy.admits_scenario_defaults(),
    )
    .expect("finding-progressive policy");
    let campaign = "generated-finding-progressive";
    let genesis = repository
        .create_funded(campaign, &lineage, &policy, &BTreeMap::new())
        .expect("create finding-progressive campaign");
    let domain = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(16),
            1,
            None,
            ExactRational::new(1, 1).expect("scale"),
            vec![IntegerValue::Unsigned(2), IntegerValue::Unsigned(6)],
        )
        .expect("finding-progressive domain"),
    );
    let generator = CandidateGeneratorSpec::new(
        crate::FINDING_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::ProgressiveInteger {
            initial_strata: 3,
            feedback_interval: 2,
        },
    )
    .expect("finding-progressive generator");
    let generator_id = repository
        .publish_generator(&generator)
        .expect("publish finding-progressive generator");
    let (_, request) = generated_integer_request(
        &repository,
        &lineage,
        domain,
        IntegerValue::Unsigned(8),
        generator_id,
        "finding-progressive",
        9,
    );
    let requested = repository
        .submit_known_branch_request(campaign, genesis.snapshot_id(), &request)
        .expect("submit finding-progressive request");

    let mut current = requested.new_snapshot;
    let mut observations = Vec::new();
    for (index, value) in [0_u64, 8, 16].into_iter().enumerate() {
        let head = repository
            .head(campaign)
            .expect("finding-progressive proposal head");
        let proposal = finite_proposal(
            &request,
            &policy,
            &head,
            ChoiceValue::Integer(IntegerValue::Unsigned(value)),
            index as u64 + 1,
        );
        let proposed = repository
            .issue_proposal(campaign, current, &proposal)
            .expect("issue finding-progressive initial proposal");
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
            .expect("admit finding-progressive initial proposal");
        current = admitted.new_snapshot;
        let coverage = if index == 0 {
            BTreeSet::from([
                CampaignHash::derive("test.finding-progressive", b"block-a"),
                CampaignHash::derive("test.finding-progressive", b"block-b"),
                CampaignHash::derive("test.finding-progressive", b"block-c"),
            ])
        } else {
            BTreeSet::new()
        };
        observations.push(generated_observation_with_coverage(
            &repository,
            &lineage,
            &admitted,
            &path,
            request.opportunity(),
            &format!("finding-progressive-{index}"),
            coverage,
        ));
    }
    for (index, observation) in observations.iter().take(2).enumerate() {
        let observed = repository
            .publish_observation(campaign, current, observation)
            .expect("publish finding-progressive observation");
        current = observed.new_snapshot;
        let fingerprint = CampaignHash::derive(
            "test.finding-progressive",
            if index == 0 {
                b"endpoint-zero-replay-divergence"
            } else {
                b"endpoint-eight-replay-divergence"
            },
        );
        let reproduction = repository
            .publish_reproduction_artifact(
                lineage.scenario(),
                lineage.scenario_content(),
                observation.child(),
                observation.child_content(),
                fingerprint,
                1,
                format!("finding-progressive reproduction {index}").into_bytes(),
            )
            .expect("publish finding-progressive reproduction");
        let signature = FindingSignature::new(
            FindingKind::Divergence,
            fingerprint,
            None,
            "qemu.replay-divergence".to_owned(),
            Some(FindingTarget::Configuration(observation.child_content())),
            BTreeSet::from([observation.properties().content_id()]),
        )
        .expect("finding-progressive signature");
        current = repository
            .publish_finding(
                campaign,
                current,
                signature,
                observed.observation,
                reproduction,
                None,
                BTreeSet::new(),
            )
            .expect("publish finding-progressive finding")
            .new_snapshot;
    }

    let ready = repository
        .head(campaign)
        .expect("finding-progressive ready head");
    let planner_state = CanonicalFrontierPlanner::initial_state().expect("planner state");
    let (_, _, invocation) =
        canonical_planner_basis_with_page(&repository, campaign, current, &planner_state, None, 16);
    let planner_request = repository
        .build_planner_request(current, invocation.id().expect("planner invocation id"))
        .expect("build finding-progressive planner request");
    let planner_output = CanonicalFrontierPlanner
        .plan(&planner_request)
        .expect("plan finding-progressive frontier");
    let PlannerProposalDisposition::Issue { proposals, .. } =
        planner_output.proposal().disposition()
    else {
        panic!("ready finding-progressive request did not issue");
    };
    assert_eq!(
        proposals.first().map(Proposal::value),
        Some(&ChoiceValue::Integer(IntegerValue::Unsigned(12)))
    );

    let coverage_only_candidate = finite_proposal(
        &request,
        &policy,
        &ready,
        ChoiceValue::Integer(IntegerValue::Unsigned(2)),
        4,
    );
    let before_rejection = blobs
        .object_count()
        .expect("objects before finding-discontinuity substitution");
    assert!(matches!(
        repository.issue_proposal(campaign, current, &coverage_only_candidate),
        Err(CampaignRepositoryError::Integrity {
            reason: "proposal-value-does-not-match-source-order"
        })
    ));
    assert_eq!(
        blobs
            .object_count()
            .expect("objects after finding-discontinuity substitution"),
        before_rejection
    );

    let discontinuity = finite_proposal(
        &request,
        &policy,
        &ready,
        ChoiceValue::Integer(IntegerValue::Unsigned(12)),
        4,
    );
    let refined = repository
        .issue_proposal(campaign, current, &discontinuity)
        .expect("issue finding-progressive refinement");
    CampaignRepository::new(repository.blobs.clone(), repository.refs.clone())
        .validate_complete_head(refined.new_snapshot.content_id())
        .expect("restart validates finding-progressive refinement");
}

#[test]
fn rarity_progressive_integer_prioritizes_inverse_frequency_discontinuity() {
    let (repository, lineage, policy, blobs) = counted_fixture();
    let campaign = "generated-rarity-progressive";
    let genesis = repository
        .create_funded(campaign, &lineage, &policy, &BTreeMap::new())
        .expect("create rarity-progressive campaign");
    let domain = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(16),
            1,
            None,
            ExactRational::new(1, 1).expect("scale"),
            vec![IntegerValue::Unsigned(2), IntegerValue::Unsigned(6)],
        )
        .expect("rarity-progressive domain"),
    );
    let generator = CandidateGeneratorSpec::new(
        crate::RARITY_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::ProgressiveInteger {
            initial_strata: 3,
            feedback_interval: 2,
        },
    )
    .expect("rarity-progressive generator");
    let generator_id = repository
        .publish_generator(&generator)
        .expect("publish rarity-progressive generator");
    let (_, request) = generated_integer_request(
        &repository,
        &lineage,
        domain,
        IntegerValue::Unsigned(8),
        generator_id,
        "rarity-progressive",
        9,
    );
    let requested = repository
        .submit_known_branch_request(campaign, genesis.snapshot_id(), &request)
        .expect("submit rarity-progressive request");

    let shared = [b"shared-a".as_slice(), b"shared-b", b"shared-c"]
        .into_iter()
        .map(|label| CampaignHash::derive("test.rarity-progressive", label))
        .collect::<BTreeSet<_>>();
    let unique = CampaignHash::derive("test.rarity-progressive", b"unique");
    let mut current = requested.new_snapshot;
    let mut observations = Vec::new();
    for (index, value) in [0_u64, 8, 16].into_iter().enumerate() {
        let head = repository
            .head(campaign)
            .expect("rarity-progressive proposal head");
        let proposal = finite_proposal(
            &request,
            &policy,
            &head,
            ChoiceValue::Integer(IntegerValue::Unsigned(value)),
            index as u64 + 1,
        );
        let proposed = repository
            .issue_proposal(campaign, current, &proposal)
            .expect("issue rarity-progressive initial proposal");
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
            .expect("admit rarity-progressive initial proposal");
        current = admitted.new_snapshot;
        let mut coverage = if index < 2 {
            shared.clone()
        } else {
            BTreeSet::new()
        };
        if index == 0 {
            coverage.insert(unique);
        }
        observations.push(generated_observation_with_coverage(
            &repository,
            &lineage,
            &admitted,
            &path,
            request.opportunity(),
            &format!("rarity-progressive-{index}"),
            coverage,
        ));
    }
    for observation in observations.iter().take(2) {
        current = repository
            .publish_observation(campaign, current, observation)
            .expect("publish rarity-progressive observation")
            .new_snapshot;
    }

    let projection = repository
        .project_branch_puct(current, request.branch_point())
        .expect("project rarity-progressive guidance");
    let mut rarity = projection
        .edge_rarity_weights()
        .values()
        .copied()
        .collect::<Vec<_>>();
    rarity.sort_unstable();
    assert_eq!(rarity, vec![98_304, 163_840]);
    assert_eq!(
        projection
            .edge_novelty_events()
            .values()
            .copied()
            .sum::<u64>(),
        1
    );

    let ready = repository
        .head(campaign)
        .expect("rarity-progressive ready head");
    let planner_state = CanonicalFrontierPlanner::initial_state().expect("planner state");
    let (_, _, invocation) =
        canonical_planner_basis_with_page(&repository, campaign, current, &planner_state, None, 16);
    let planner_request = repository
        .build_planner_request(current, invocation.id().expect("planner invocation id"))
        .expect("build rarity-progressive planner request");
    let planner_output = CanonicalFrontierPlanner
        .plan(&planner_request)
        .expect("plan rarity-progressive frontier");
    let PlannerProposalDisposition::Issue { proposals, .. } =
        planner_output.proposal().disposition()
    else {
        panic!("ready rarity-progressive request did not issue");
    };
    assert_eq!(
        proposals.first().map(Proposal::value),
        Some(&ChoiceValue::Integer(IntegerValue::Unsigned(12)))
    );

    let unique_only_candidate = finite_proposal(
        &request,
        &policy,
        &ready,
        ChoiceValue::Integer(IntegerValue::Unsigned(2)),
        4,
    );
    let before_rejection = blobs
        .object_count()
        .expect("objects before rarity-discontinuity substitution");
    assert!(matches!(
        repository.issue_proposal(campaign, current, &unique_only_candidate),
        Err(CampaignRepositoryError::Integrity {
            reason: "proposal-value-does-not-match-source-order"
        })
    ));
    assert_eq!(
        blobs
            .object_count()
            .expect("objects after rarity-discontinuity substitution"),
        before_rejection
    );

    let discontinuity = finite_proposal(
        &request,
        &policy,
        &ready,
        ChoiceValue::Integer(IntegerValue::Unsigned(12)),
        4,
    );
    let refined = repository
        .issue_proposal(campaign, current, &discontinuity)
        .expect("issue rarity-progressive refinement");
    CampaignRepository::new(repository.blobs.clone(), repository.refs.clone())
        .validate_complete_head(refined.new_snapshot.content_id())
        .expect("restart validates rarity-progressive refinement");
}
