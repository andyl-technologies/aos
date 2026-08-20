//! Imported-history, closure, identity, and owner-validation repository tests.

use super::*;
use crate::{ExactRational, FeedbackWait, IntegerDomain, IntegerRepresentation, IntegerValue};

fn generated_integer_request(
    repository: &CampaignRepository,
    lineage: &CampaignLineage,
    domain: ChoiceDomain,
    default: IntegerValue,
    generator: CandidateGeneratorSpecId,
    label: &str,
    budget: u64,
) -> (ChoiceDomain, BranchRequest) {
    let declaration = SelectableDeclaration::new(
        format!("generated.integer.{label}"),
        ChoiceSource::Workload {
            producer: "generated-integer".to_owned(),
        },
        domain.clone(),
        ChoiceValue::Integer(default),
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
            scheduler: CampaignHash::derive("test", label.as_bytes()),
            producer: CampaignHash::derive("test", b"generated-integer-producer"),
        },
        label,
        None,
    )
    .expect("opportunity");
    repository
        .publish_choice_opportunity(&opportunity)
        .expect("publish opportunity");
    let request = BranchRequest::new(
        opportunity.branch_point_id(lineage.genesis()),
        lineage.genesis_content(),
        opportunity.id().expect("opportunity id"),
        domain.id().expect("domain id"),
        CandidateSource::generated(generator),
        BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(CampaignHash::derive(
            "test",
            format!("{label}-request").as_bytes(),
        ))),
        BranchBudget::new(budget, budget).expect("budget"),
        StopCondition::NextChoice,
    )
    .expect("request");
    (domain, request)
}

fn generated_discrete_request(
    repository: &CampaignRepository,
    lineage: &CampaignLineage,
    domain: ChoiceDomain,
    default: AlternativeId,
    generator: CandidateGeneratorSpecId,
    label: &str,
    budget: u64,
) -> (ChoiceDomain, BranchRequest) {
    let declaration = SelectableDeclaration::new(
        format!("generated.discrete.{label}"),
        ChoiceSource::Workload {
            producer: "generated-discrete".to_owned(),
        },
        domain.clone(),
        ChoiceValue::Discrete(default),
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
            scheduler: CampaignHash::derive("test", label.as_bytes()),
            producer: CampaignHash::derive("test", b"generated-discrete-producer"),
        },
        label,
        None,
    )
    .expect("opportunity");
    repository
        .publish_choice_opportunity(&opportunity)
        .expect("publish opportunity");
    let request = BranchRequest::new(
        opportunity.branch_point_id(lineage.genesis()),
        lineage.genesis_content(),
        opportunity.id().expect("opportunity id"),
        domain.id().expect("domain id"),
        CandidateSource::generated(generator),
        BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(CampaignHash::derive(
            "test",
            format!("{label}-request").as_bytes(),
        ))),
        BranchBudget::new(budget, budget).expect("budget"),
        StopCondition::NextChoice,
    )
    .expect("request");
    (domain, request)
}

fn generated_observation(
    repository: &CampaignRepository,
    lineage: &CampaignLineage,
    admission: &AttemptAdmissionResult,
    path: &BranchPath,
    opportunity: ChoiceOpportunityId,
    label: &str,
) -> Observation {
    let child = ConfigurationId::from_hash(CampaignHash::derive(
        "test-progressive-child",
        label.as_bytes(),
    ));
    let child_content = repository
        .publish_configuration_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            child,
            1,
            format!("progressive child:{label}").into_bytes(),
        )
        .expect("publish progressive child");
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
    Observation::new(
        admission.attempt,
        child,
        child_content,
        path.id().expect("path id"),
        StopOutcome::Reached(StopCondition::NextChoice),
        measurements,
        properties,
        coverage,
        BTreeSet::from([opportunity]),
    )
    .expect("progressive observation")
}

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
fn generated_all_discrete_uses_stable_alternative_order() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("generated-discrete", &lineage, &policy, &BTreeMap::new())
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
        .create("generated-weighted", &lineage, &policy, &BTreeMap::new())
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
        vec!["beta", "delta", "alpha", "gamma"]
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
    assert_ne!(other_candidates, expected_candidates);
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
        .create("generated-mixture", &lineage, &policy, &BTreeMap::new())
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
        vec!["alpha", "beta", "delta", "gamma"]
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
        .create("mixture-bounds", &lineage, &policy, &BTreeMap::new())
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
        .create("generated-progressive", &lineage, &policy, &BTreeMap::new())
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
fn progressive_integer_generator_enforces_exact_owner_bounds_before_writes() {
    let (repository, lineage, policy, blobs) = counted_fixture();
    let genesis = repository
        .create("progressive-bounds", &lineage, &policy, &BTreeMap::new())
        .expect("create progressive bounds campaign");
    let domain = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(5_000),
            1,
            None,
            ExactRational::new(1, 1).expect("scale"),
            Vec::new(),
        )
        .expect("bounded progressive domain"),
    );

    let oversized_strata = CandidateGeneratorSpec::new(
        crate::PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::ProgressiveInteger {
            initial_strata: crate::PROGRESSIVE_INTEGER_GENERATOR_MAX_INITIAL_STRATA + 1,
            feedback_interval: 1,
        },
    )
    .expect("oversized-strata generator");
    let oversized_strata_id = repository
        .publish_generator(&oversized_strata)
        .expect("publish oversized-strata generator");
    let (_, oversized_strata_request) = generated_integer_request(
        &repository,
        &lineage,
        domain.clone(),
        IntegerValue::Unsigned(2_500),
        oversized_strata_id,
        "progressive-oversized-strata",
        1,
    );
    let oversized_strata_discovery = repository
        .discover_choice_opportunity(
            "progressive-bounds",
            genesis.snapshot_id(),
            oversized_strata_request.parent(),
            oversized_strata_request.opportunity(),
        )
        .expect("discover oversized-strata opportunity");
    let before_strata = blobs
        .object_count()
        .expect("objects before strata rejection");
    assert!(matches!(
        repository.submit_branch_request(
            "progressive-bounds",
            oversized_strata_discovery.new_snapshot,
            &oversized_strata_request,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "progressive-generator-initial-strata-limit"
        })
    ));
    assert_eq!(
        blobs
            .object_count()
            .expect("objects after strata rejection"),
        before_strata
    );

    let bounded = CandidateGeneratorSpec::new(
        crate::PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::ProgressiveInteger {
            initial_strata: 1,
            feedback_interval: 1,
        },
    )
    .expect("bounded progressive generator");
    let bounded_id = repository
        .publish_generator(&bounded)
        .expect("publish bounded progressive generator");
    let (_, oversized_budget_request) = generated_integer_request(
        &repository,
        &lineage,
        domain.clone(),
        IntegerValue::Unsigned(2_500),
        bounded_id,
        "progressive-oversized-budget",
        crate::PROGRESSIVE_INTEGER_GENERATOR_MAX_PROPOSALS + 1,
    );
    let oversized_budget_discovery = repository
        .discover_choice_opportunity(
            "progressive-bounds",
            oversized_strata_discovery.new_snapshot,
            oversized_budget_request.parent(),
            oversized_budget_request.opportunity(),
        )
        .expect("discover oversized-budget opportunity");
    let before_budget = blobs
        .object_count()
        .expect("objects before budget rejection");
    assert!(matches!(
        repository.submit_branch_request(
            "progressive-bounds",
            oversized_budget_discovery.new_snapshot,
            &oversized_budget_request,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "progressive-generator-proposal-limit"
        })
    ));
    assert_eq!(
        blobs
            .object_count()
            .expect("objects after budget rejection"),
        before_budget
    );

    let overflow = CandidateGeneratorSpec::new(
        crate::PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::ProgressiveInteger {
            initial_strata: 1,
            feedback_interval: u64::MAX,
        },
    )
    .expect("overflow-threshold generator");
    let overflow_id = repository
        .publish_generator(&overflow)
        .expect("publish overflow-threshold generator");
    let overflow_domain = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(2),
            1,
            None,
            ExactRational::new(1, 1).expect("overflow scale"),
            Vec::new(),
        )
        .expect("overflow domain"),
    );
    let (_, overflow_request) = generated_integer_request(
        &repository,
        &lineage,
        overflow_domain,
        IntegerValue::Unsigned(1),
        overflow_id,
        "progressive-overflow",
        3,
    );
    let overflow_discovery = repository
        .discover_choice_opportunity(
            "progressive-bounds",
            oversized_budget_discovery.new_snapshot,
            overflow_request.parent(),
            overflow_request.opportunity(),
        )
        .expect("discover overflow-threshold opportunity");
    let before_overflow = blobs
        .object_count()
        .expect("objects before overflow rejection");
    assert!(matches!(
        repository.submit_branch_request(
            "progressive-bounds",
            overflow_discovery.new_snapshot,
            &overflow_request,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "progressive-generator-feedback-threshold-overflow"
        })
    ));
    assert_eq!(
        blobs
            .object_count()
            .expect("objects after overflow rejection"),
        before_overflow
    );

    let legacy = CandidateGeneratorSpec::new(
        crate::ORDERED_MIXTURE_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::ProgressiveInteger {
            initial_strata: 3,
            feedback_interval: 2,
        },
    )
    .expect("legacy progressive generator");
    let legacy_id = repository
        .publish_generator(&legacy)
        .expect("publish legacy progressive generator");
    let (_, legacy_request) = generated_integer_request(
        &repository,
        &lineage,
        domain.clone(),
        IntegerValue::Unsigned(2_500),
        legacy_id,
        "progressive-legacy",
        9,
    );
    assert_eq!(
        repository
            .initial_continuation_state(&legacy_request)
            .expect("legacy progressive continuation"),
        ContinuationState::Open
    );

    let exact_domain = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(4_095),
            1,
            None,
            ExactRational::new(1, 1).expect("exact scale"),
            Vec::new(),
        )
        .expect("exact maximum domain"),
    );
    let exact = CandidateGeneratorSpec::new(
        crate::PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::ProgressiveInteger {
            initial_strata: crate::PROGRESSIVE_INTEGER_GENERATOR_MAX_INITIAL_STRATA,
            feedback_interval: 1,
        },
    )
    .expect("exact maximum progressive generator");
    let exact_id = repository
        .publish_generator(&exact)
        .expect("publish exact maximum generator");
    let (_, exact_request) = generated_integer_request(
        &repository,
        &lineage,
        exact_domain.clone(),
        IntegerValue::Unsigned(2_047),
        exact_id,
        "progressive-exact-maximum",
        crate::PROGRESSIVE_INTEGER_GENERATOR_MAX_PROPOSALS,
    );
    assert_eq!(
        repository
            .candidate_at_with_feedback(&exact_request, &exact_domain, 4_096, 0)
            .expect("maximum initial candidate"),
        Some(ChoiceValue::Integer(IntegerValue::Unsigned(4_095)))
    );
}

#[test]
fn boundary_integer_generator_uses_exact_static_order() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("generated-boundary", &lineage, &policy, &BTreeMap::new())
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
        opportunity.branch_point_id(lineage.genesis()),
        lineage.genesis_content(),
        opportunity.id().expect("opportunity id"),
        domain.id().expect("domain id"),
        CandidateSource::generated(generator_id),
        BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(CampaignHash::derive(
            "test",
            b"generated-boundary-request",
        ))),
        BranchBudget::new(11, 11).expect("budget"),
        StopCondition::NextChoice,
    )
    .expect("request");
    let legacy_generator = CandidateGeneratorSpec::new(
        crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::BoundaryInteger,
    )
    .expect("legacy boundary generator");
    let legacy_generator_id = repository
        .publish_generator(&legacy_generator)
        .expect("publish legacy boundary generator");
    let legacy_request = BranchRequest::new(
        request.branch_point(),
        request.parent(),
        request.opportunity(),
        request.domain(),
        CandidateSource::generated(legacy_generator_id),
        BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(CampaignHash::derive(
            "test",
            b"generated-boundary-legacy-request",
        ))),
        request.budget(),
        request.stop().clone(),
    )
    .expect("legacy boundary request");
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
        signed_opportunity.branch_point_id(lineage.genesis()),
        lineage.genesis_content(),
        signed_opportunity.id().expect("signed opportunity id"),
        signed_domain.id().expect("signed domain id"),
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
        .create("generated-stratified", &lineage, &policy, &BTreeMap::new())
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

    let legacy = CandidateGeneratorSpec::new(
        crate::BOUNDARY_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::StratifiedInteger { strata: 4 },
    )
    .expect("legacy generator");
    let legacy_id = repository
        .publish_generator(&legacy)
        .expect("publish legacy generator");
    let (_, legacy_request) = generated_integer_request(
        &repository,
        &lineage,
        unsigned.clone(),
        IntegerValue::Unsigned(10),
        legacy_id,
        "legacy",
        4,
    );
    assert_eq!(
        repository
            .static_candidate_count(&legacy_request, &unsigned)
            .expect("legacy candidate count"),
        None
    );
    assert_eq!(
        repository
            .initial_continuation_state(&legacy_request)
            .expect("legacy continuation"),
        ContinuationState::Open
    );

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
        .create("generated-log", &lineage, &policy, &BTreeMap::new())
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

    let legacy = CandidateGeneratorSpec::new(
        crate::STRATIFIED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::LogInteger { base: 10 },
    )
    .expect("legacy generator");
    let legacy_id = repository
        .publish_generator(&legacy)
        .expect("publish legacy generator");
    let (_, legacy_request) = generated_integer_request(
        &repository,
        &lineage,
        unsigned.clone(),
        IntegerValue::Unsigned(3),
        legacy_id,
        "log-legacy",
        4,
    );
    assert_eq!(
        repository
            .static_candidate_count(&legacy_request, &unsigned)
            .expect("legacy candidate count"),
        None
    );
    assert_eq!(
        repository
            .initial_continuation_state(&legacy_request)
            .expect("legacy continuation"),
        ContinuationState::Open
    );

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
fn permuted_integer_generator_is_keyed_bijective_and_restart_stable() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("generated-permuted", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let generator = CandidateGeneratorSpec::new(
        crate::PERMUTED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::PermutedInteger,
    )
    .expect("permuted generator");
    let generator_id = repository
        .publish_generator(&generator)
        .expect("publish permuted generator");
    let unsigned = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(10),
            IntegerValue::Unsigned(28),
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
        "permuted-main",
        10,
    );
    assert_eq!(
        repository
            .static_candidate_count(&request, &unsigned)
            .expect("candidate count"),
        Some(10)
    );
    let sequence = (1..=10)
        .map(|ordinal| {
            repository
                .static_candidate_at(&request, &unsigned, ordinal)
                .expect("candidate ordinal")
                .expect("implemented source")
        })
        .collect::<Vec<_>>();
    assert_eq!(
        sequence,
        [24, 26, 14, 28, 12, 10, 20, 22, 18, 16]
            .map(|value| ChoiceValue::Integer(IntegerValue::Unsigned(value)))
    );
    assert_eq!(
        sequence.iter().cloned().collect::<BTreeSet<_>>(),
        (10..=28)
            .step_by(2)
            .map(|value| ChoiceValue::Integer(IntegerValue::Unsigned(value)))
            .collect()
    );
    assert!(matches!(
        repository.static_candidate_at(&request, &unsigned, 11),
        Err(CampaignRepositoryError::Integrity {
            reason: "proposal-ordinal-exceeds-source-cardinality"
        })
    ));

    let (_, other_request) = generated_integer_request(
        &repository,
        &lineage,
        unsigned.clone(),
        IntegerValue::Unsigned(10),
        generator_id,
        "permuted-other",
        10,
    );
    let other_sequence = (1..=10)
        .map(|ordinal| {
            repository
                .static_candidate_at(&other_request, &unsigned, ordinal)
                .expect("other candidate ordinal")
                .expect("implemented source")
        })
        .collect::<Vec<_>>();
    assert_ne!(sequence, other_sequence);
    assert_eq!(
        other_sequence.iter().cloned().collect::<BTreeSet<_>>(),
        sequence.iter().cloned().collect()
    );

    let singleton = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Signed64,
            IntegerValue::Signed(42),
            IntegerValue::Signed(42),
            1,
            None,
            ExactRational::new(1, 1).expect("singleton scale"),
            Vec::new(),
        )
        .expect("singleton domain"),
    );
    let (singleton, singleton_request) = generated_integer_request(
        &repository,
        &lineage,
        singleton,
        IntegerValue::Signed(42),
        generator_id,
        "permuted-singleton",
        1,
    );
    assert_eq!(
        repository
            .static_candidate_at(&singleton_request, &singleton, 1)
            .expect("singleton candidate"),
        Some(ChoiceValue::Integer(IntegerValue::Signed(42)))
    );

    let signed = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Signed64,
            IntegerValue::Signed(-5),
            IntegerValue::Signed(5),
            1,
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
        "permuted-signed",
        11,
    );
    let signed_values = (1..=11)
        .map(|ordinal| {
            repository
                .static_candidate_at(&signed_request, &signed, ordinal)
                .expect("signed candidate")
                .expect("implemented source")
        })
        .collect::<BTreeSet<_>>();
    assert_eq!(
        signed_values,
        (-5..=5)
            .map(|value| ChoiceValue::Integer(IntegerValue::Signed(value)))
            .collect()
    );

    let full_unsigned = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(0),
            IntegerValue::Unsigned(u64::MAX),
            1,
            None,
            ExactRational::new(1, 1).expect("full scale"),
            Vec::new(),
        )
        .expect("full unsigned domain"),
    );
    assert!(matches!(
        repository.validate_generator_for_domain(generator_id, &full_unsigned),
        Err(CampaignRepositoryError::Integrity {
            reason: "permuted-generator-cardinality-limit"
        })
    ));

    let maximum = ChoiceDomain::Integer(
        IntegerDomain::new(
            1,
            IntegerRepresentation::Unsigned64,
            IntegerValue::Unsigned(1),
            IntegerValue::Unsigned(u64::MAX),
            1,
            None,
            ExactRational::new(1, 1).expect("maximum scale"),
            Vec::new(),
        )
        .expect("maximum domain"),
    );
    let (maximum, maximum_request) = generated_integer_request(
        &repository,
        &lineage,
        maximum,
        IntegerValue::Unsigned(1),
        generator_id,
        "permuted-maximum",
        1,
    );
    assert_eq!(
        repository
            .static_candidate_count(&maximum_request, &maximum)
            .expect("maximum candidate count"),
        Some(u64::MAX)
    );
    assert!(matches!(
        repository
            .static_candidate_at(&maximum_request, &maximum, u64::MAX)
            .expect("maximum ordinal"),
        Some(ChoiceValue::Integer(IntegerValue::Unsigned(_)))
    ));

    let legacy = CandidateGeneratorSpec::new(
        crate::LOG_INTEGER_GENERATOR_IMPLEMENTATION_VERSION,
        CandidateGeneratorAlgorithm::PermutedInteger,
    )
    .expect("legacy generator");
    let legacy_id = repository
        .publish_generator(&legacy)
        .expect("publish legacy generator");
    let (_, legacy_request) = generated_integer_request(
        &repository,
        &lineage,
        unsigned.clone(),
        IntegerValue::Unsigned(10),
        legacy_id,
        "permuted-legacy",
        10,
    );
    assert_eq!(
        repository
            .static_candidate_count(&legacy_request, &unsigned)
            .expect("legacy candidate count"),
        None
    );
    assert_eq!(
        repository
            .initial_continuation_state(&legacy_request)
            .expect("legacy continuation"),
        ContinuationState::Open
    );

    let issued = repository
        .submit_known_branch_request("generated-permuted", genesis.snapshot_id(), &request)
        .expect("issue request");
    let projection_id = repository
        .project_finite_expansion(issued.new_snapshot, request.branch_point(), None, 10)
        .expect("project permuted source");
    assert_eq!(
        repository
            .load_expansion_state(projection_id)
            .expect("load projection")
            .continuations()
            .get(&request.id().expect("request id")),
        Some(&ContinuationState::Ready)
    );
    let head = repository.head("generated-permuted").expect("request head");
    let wrong = finite_proposal(&request, &policy, &head, sequence[1].clone(), 1);
    assert!(matches!(
        repository.issue_proposal("generated-permuted", issued.new_snapshot, &wrong),
        Err(CampaignRepositoryError::Integrity {
            reason: "proposal-value-does-not-match-source-order"
        })
    ));
    assert_eq!(
        repository
            .head("generated-permuted")
            .expect("unchanged head")
            .snapshot_id(),
        issued.new_snapshot
    );
    let first = finite_proposal(&request, &policy, &head, sequence[0].clone(), 1);
    let first_issued = repository
        .issue_proposal("generated-permuted", issued.new_snapshot, &first)
        .expect("issue first permuted proposal");

    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    assert_eq!(
        restarted
            .head("generated-permuted")
            .expect("rebuild permuted history")
            .snapshot_id(),
        first_issued.new_snapshot
    );
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
                repository
                    .initial_continuation_state(&request)
                    .expect("initial continuation"),
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

    let result = repository.validate_complete_head(forged_content);
    assert!(
        matches!(
            result,
            Err(CampaignRepositoryError::Integrity {
                reason: "branch-request-transition-accounting-root-mismatch"
            })
        ),
        "unexpected forged branch-request result: {result:?}"
    );
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
