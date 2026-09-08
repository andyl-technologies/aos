//! Imported-history, closure, identity, and owner-validation repository tests.

use super::*;
use crate::{
    CampaignCommandId, ExactRational, FeedbackWait, FindingKind, FindingSignature, FindingTarget,
    IntegerDomain, IntegerRepresentation, IntegerValue, Objective, ObjectiveGoal, ObjectiveValue,
    PinChange, PinRetention, RankingCandidate, RankingMethod, SurvivorRule, evaluate_objectives,
    rank_survivors,
};

struct PermitExhaustive;

impl crate::CampaignPrincipalAuthorizer for PermitExhaustive {
    fn authorize(
        &self,
        _principal: &crate::CampaignPrincipal,
        _operation: crate::CampaignServiceOperation,
        _campaign: &crate::CampaignName,
        _request_digest: CampaignHash,
    ) -> Result<(), crate::CampaignAuthorizationError> {
        Ok(())
    }
}

#[test]
fn survivor_decision_publication_is_failure_atomic_and_replayable() {
    let (repository, lineage, base, blobs) = counted_fixture();
    let objective_name = "latency";
    let policy = CampaignPolicy::new(
        base.scenario(),
        base.campaign_seed(),
        base.mode(),
        base.explorer().clone(),
        base.choice_policies().clone(),
        BTreeMap::from([(
            objective_name.to_owned(),
            Objective::new(objective_name, ObjectiveGoal::Minimize, 1_000_000).expect("objective"),
        )]),
        base.guidance().clone(),
        base.stop_conditions().clone(),
        base.fairness(),
        base.retention(),
        base.admits_scenario_defaults(),
    )
    .expect("objective policy");
    repository.publish_policy(&policy).expect("publish policy");
    let campaign_observations = (0_u64..16)
        .map(|ordinal| {
            let name = format!("objective-publication-{ordinal}");
            let (_created, _admitted, observation) =
                admitted_observation_fixture(&repository, &lineage, &policy, &name);
            (name, observation)
        })
        .collect::<Vec<_>>();
    let candidates = campaign_observations
        .iter()
        .map(|(_name, observation)| {
            let properties = repository
                .load_property_verdict_set(observation.properties())
                .expect("properties");
            let evaluation = evaluate_objectives(
                &policy,
                observation,
                &properties,
                BTreeMap::from([(objective_name.to_owned(), ObjectiveValue::Unsigned(7))]),
            )
            .expect("evaluation");
            RankingCandidate::new(evaluation, 3, 0)
        })
        .collect();
    let bundle = rank_survivors(
        &policy,
        SurvivorRule::new(RankingMethod::WeightedTopK, 8, 2, 2).expect("rule"),
        candidates,
    )
    .expect("ranking");

    let before = blobs
        .object_count()
        .expect("objects before rejected publication");
    assert!(matches!(
        repository.publish_survivor_selection(&bundle),
        Err(CampaignRepositoryError::Store(StoreError::NotFound { .. }))
    ));
    assert_eq!(
        blobs
            .object_count()
            .expect("objects after rejected publication"),
        before
    );

    for (name, observation) in &campaign_observations {
        let current = repository
            .head(name)
            .expect("current campaign")
            .snapshot_id();
        repository
            .publish_observation(name, current, observation)
            .expect("publish observation");
    }
    let selection = repository
        .publish_survivor_selection(&bundle)
        .expect("publish survivor selection");
    assert_eq!(
        repository
            .load_survivor_selection(selection)
            .expect("load and replay survivor selection"),
        bundle
    );
    let mut cache = ChoiceValidationCache::default();
    assert_eq!(
        repository
            .read_survivor_selection_bundle_cached(selection.content_id(), &mut cache)
            .expect("load shared-policy survivor selection"),
        bundle
    );
    assert_eq!(cache.objective_contracts.len(), 1);
    let after = blobs.object_count().expect("objects after publication");
    assert_eq!(
        repository
            .publish_survivor_selection(&bundle)
            .expect("idempotent publication"),
        selection
    );
    assert_eq!(blobs.object_count().expect("objects after replay"), after);
}

#[test]
fn objective_evaluation_publication_is_snapshot_owned_replayable_and_failure_atomic() {
    let (repository, lineage, base, blobs) = counted_fixture();
    let objective_name = "latency";
    let policy = CampaignPolicy::new(
        base.scenario(),
        base.campaign_seed(),
        base.mode(),
        base.explorer().clone(),
        base.choice_policies().clone(),
        BTreeMap::from([(
            objective_name.to_owned(),
            Objective::new(objective_name, ObjectiveGoal::Minimize, 1_000_000).expect("objective"),
        )]),
        base.guidance().clone(),
        base.stop_conditions().clone(),
        base.fairness(),
        base.retention(),
        base.admits_scenario_defaults(),
    )
    .expect("objective policy");
    repository.publish_policy(&policy).expect("publish policy");
    let name = "objective-evaluation-owner";
    let (_genesis, admitted, observation) =
        admitted_observation_fixture(&repository, &lineage, &policy, name);
    let properties = repository
        .load_property_verdict_set(observation.properties())
        .expect("properties");
    let evaluation = evaluate_objectives(
        &policy,
        &observation,
        &properties,
        BTreeMap::from([(objective_name.to_owned(), ObjectiveValue::Unsigned(7))]),
    )
    .expect("evaluation");

    let before = blobs.object_count().expect("objects before rejection");
    let rejected =
        repository.publish_objective_evaluation(name, admitted.new_snapshot, &evaluation);
    assert!(
        matches!(
            rejected,
            Err(CampaignRepositoryError::Store(StoreError::NotFound { .. }))
        ),
        "{rejected:?}"
    );
    assert_eq!(
        blobs.object_count().expect("objects after rejection"),
        before
    );

    let observed = repository
        .publish_observation(name, admitted.new_snapshot, &observation)
        .expect("publish observation");
    let published = repository
        .publish_objective_evaluation(name, observed.new_snapshot, &evaluation)
        .expect("publish objective evaluation");
    assert_eq!(published.prior_snapshot, observed.new_snapshot);
    assert_eq!(
        published.evaluation,
        evaluation.id().expect("evaluation ID")
    );
    assert!(!published.replayed);
    let published_snapshot = repository
        .read_snapshot(published.new_snapshot.content_id())
        .expect("objective publication snapshot");
    let transition = published_snapshot
        .snapshot
        .transition()
        .expect("objective publication transition");
    assert_eq!(transition.content_id().schema_version(), 6);
    assert_eq!(
        repository
            .read_fact(transition.content_id())
            .expect("objective publication fact"),
        CampaignFact::ObjectiveEvaluationPublished(published.evaluation)
    );
    let observed_snapshot = repository
        .read_snapshot(observed.new_snapshot.content_id())
        .expect("objective parent snapshot");
    let mut forged_roots = published_snapshot.snapshot.roots();
    forged_roots.observations = repository
        .merkle
        .insert(
            observed_snapshot.snapshot.roots().observations,
            CampaignHash::derive("test-objective-evaluation-wrong-key", b"wrong"),
            published.evaluation.content_id(),
        )
        .expect("forge wrong objective index key")
        .content_id();
    let forged_snapshot = CampaignSnapshot::successor(
        observed.new_snapshot,
        published_snapshot.snapshot.lineage(),
        published_snapshot.snapshot.active_policy(),
        forged_roots,
        transition,
    )
    .expect("forged objective successor");
    let forged_content = repository
        .put_snapshot(&forged_snapshot)
        .expect("put forged objective successor");
    assert!(matches!(
        repository.validate_complete_head(forged_content),
        Err(CampaignRepositoryError::Integrity {
            reason: "objective-evaluation-transition-observation-root"
        })
    ));

    let conflicting = evaluate_objectives(
        &policy,
        &observation,
        &properties,
        BTreeMap::from([(objective_name.to_owned(), ObjectiveValue::Unsigned(8))]),
    )
    .expect("conflicting evaluation");
    let before_conflict = blobs.object_count().expect("objects before conflict");
    assert!(matches!(
        repository.publish_objective_evaluation(name, published.new_snapshot, &conflicting),
        Err(CampaignRepositoryError::AlreadyExists)
    ));
    assert_eq!(
        blobs.object_count().expect("objects after conflict"),
        before_conflict
    );

    let advanced = repository
        .apply_control(
            name,
            &ControlRequest {
                command: CampaignCommandId::from_hash(CampaignHash::derive(
                    "test-objective-evaluation-control",
                    b"resume",
                )),
                expected_snapshot: published.new_snapshot,
                action: CampaignControlAction::Resume,
            },
        )
        .expect("advance after objective evaluation");
    repository
        .validated_heads
        .lock()
        .expect("validated-head cache")
        .clear();
    assert_eq!(
        repository
            .head(name)
            .expect("restart-validate objective head")
            .snapshot_id(),
        advanced.new_snapshot
    );
    assert_eq!(
        repository
            .publish_objective_evaluation(name, observed.new_snapshot, &evaluation)
            .expect("replay objective evaluation after later mutation"),
        ObjectiveEvaluationPublicationResult {
            replayed: true,
            ..published
        }
    );
}

#[test]
fn canonical_frontier_planner_basis_is_complete_and_idempotent() {
    let (repository, _lineage, _policy, blobs) = counted_fixture();
    let before = blobs.object_count().expect("objects before planner basis");

    let basis = repository
        .publish_canonical_frontier_planner_basis()
        .expect("publish canonical planner basis");
    let after = blobs.object_count().expect("objects after planner basis");
    assert_eq!(after, before + 4);
    assert_eq!(
        basis,
        CanonicalFrontierPlanner::basis().expect("closed basis")
    );

    let objects = repository
        .authenticated_closure_ids([
            basis.artifact().id().expect("artifact id").content_id(),
            basis.initial_state().id().expect("state id").content_id(),
        ])
        .expect("authenticate planner basis");
    assert!(objects.contains(&CanonicalFrontierPlanner::dependency_lock_id()));
    assert!(objects.contains(&basis.engine().id().expect("engine id").content_id()));

    assert_eq!(
        repository
            .publish_canonical_frontier_planner_basis()
            .expect("replay canonical planner basis"),
        basis
    );
    assert_eq!(
        blobs.object_count().expect("objects after basis replay"),
        after
    );
}

#[test]
fn authenticated_closure_inventory_includes_campaign_records_and_merkle_nodes() {
    let (repository, lineage, policy) = fixture();
    let created = repository
        .create("closure-inventory", &lineage, &policy, &BTreeMap::new())
        .expect("create campaign");
    let head = repository.head("closure-inventory").expect("load head");

    let objects = repository
        .authenticated_closure_ids([created.snapshot_id().content_id()])
        .expect("authenticate complete closure");

    assert!(objects.contains(&created.snapshot_id().content_id()));
    assert!(objects.contains(&lineage.id().expect("lineage id").content_id()));
    assert!(objects.contains(&policy.id().expect("policy id").content_id()));
    for root in snapshot_roots(head.snapshot()) {
        assert!(objects.contains(&root), "missing Merkle root {root}");
    }
}

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
    generated_observation_with_coverage(
        repository,
        lineage,
        admission,
        path,
        opportunity,
        label,
        BTreeSet::new(),
    )
}

fn generated_observation_with_coverage(
    repository: &CampaignRepository,
    lineage: &CampaignLineage,
    admission: &AttemptAdmissionResult,
    path: &BranchPath,
    opportunity: ChoiceOpportunityId,
    label: &str,
    coverage_identities: BTreeSet<CampaignHash>,
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
            &CoverageProjection::new(coverage_identities, BTreeSet::new()).expect("coverage"),
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

mod generator_expansion;

mod generator_strategies;

#[test]
fn cold_ancestry_rejects_a_forged_branch_acceptance_summary() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create(
            "forged-acceptance-summary",
            &lineage,
            &policy,
            &BTreeMap::new(),
        )
        .expect("create");
    let request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "forged-acceptance-summary",
    );
    let discovered = repository
        .discover_choice_opportunity(
            "forged-acceptance-summary",
            genesis.snapshot_id(),
            request.parent(),
            request.opportunity(),
        )
        .expect("discover request opportunity");
    let accepted = repository
        .submit_branch_request(
            "forged-acceptance-summary",
            discovered.new_snapshot,
            &request,
        )
        .expect("accept branch request");
    let accepted_snapshot = repository
        .read_snapshot(accepted.new_snapshot.content_id())
        .expect("accepted snapshot");
    let forged_summary = BranchAcceptanceSummary::new(
        BranchAcceptanceCount::Exact(2),
        BranchAcceptanceCount::Exact(1),
        BranchAcceptanceCount::Exact(1),
        2,
        2,
    )
    .expect("internally consistent forged summary");
    assert_ne!(forged_summary, accepted.summary);
    let forged_fact = repository
        .put_fact(&CampaignFact::BranchRequestAccepted {
            request: accepted.request,
            summary: forged_summary,
        })
        .expect("put forged acceptance fact");
    let forged_snapshot = CampaignSnapshot::successor(
        discovered.new_snapshot,
        accepted_snapshot.snapshot.lineage(),
        accepted_snapshot.snapshot.active_policy(),
        accepted_snapshot.snapshot.roots(),
        CampaignFactId::from_content_id(forged_fact).expect("forged fact ID"),
    )
    .expect("forge acceptance successor");
    let forged_content = repository
        .put_snapshot(&forged_snapshot)
        .expect("put forged acceptance snapshot");

    repository
        .validated_heads
        .lock()
        .expect("validated-head cache")
        .clear();
    let result = repository.validate_complete_head(forged_content);
    assert!(
        matches!(
            result,
            Err(CampaignRepositoryError::Integrity {
                reason: "branch-request-acceptance-summary-mismatch"
            })
        ),
        "unexpected forged acceptance result: {result:?}"
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
    let scan_index = repository
        .planner_scan_index_after(
            parent.snapshot.roots().exploration,
            &[(request_id, request.branch_point())],
            true,
        )
        .expect("scan update")
        .expect("scan index");
    roots.exploration = repository
        .merkle
        .insert(
            roots.exploration,
            planner_scan_index_anchor_key(),
            scan_index,
        )
        .expect("scan root")
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
fn pin_command_projects_retention_and_replays_exactly_after_later_mutation() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("pin-replay", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let request = PinRequest {
        command: CampaignCommandId::from_hash(CampaignHash::derive("test", b"pin-command")),
        expected_snapshot: genesis.snapshot_id(),
        change: PinChange::new(lineage.genesis(), Some(PinRetention::Thin), "triage")
            .expect("pin change"),
    };

    let accepted = repository
        .apply_pin("pin-replay", &request)
        .expect("accept pin");
    repository.evict_local_checkpoint(accepted.new_snapshot.content_id());
    let accepted_head = repository.head("pin-replay").expect("accepted head");
    let pin_content = repository
        .merkle
        .get(
            accepted_head.snapshot().roots().pins,
            pin_configuration_key(lineage.genesis()),
        )
        .expect("read pin projection")
        .expect("pin projection value");
    assert_eq!(
        repository.read_fact(pin_content).expect("pin fact"),
        CampaignFact::PinCommandAccepted(request.clone())
    );

    let resume = command(
        "pin-replay-resume",
        accepted.new_snapshot,
        CampaignControlAction::Resume,
    );
    repository
        .apply_control("pin-replay", &resume)
        .expect("later mutation");

    let replay = repository
        .apply_pin("pin-replay", &request)
        .expect("replay pin");
    assert!(replay.replayed);
    assert_eq!(replay.prior_snapshot, accepted.prior_snapshot);
    assert_eq!(replay.new_snapshot, accepted.new_snapshot);

    let reused = PinRequest {
        command: request.command,
        expected_snapshot: request.expected_snapshot,
        change: PinChange::new(lineage.genesis(), Some(PinRetention::Exact), "retain")
            .expect("changed pin"),
    };
    assert!(matches!(
        repository.apply_pin("pin-replay", &reused),
        Err(CampaignRepositoryError::CommandReuse)
    ));

    let reused_as_control = ControlRequest {
        command: request.command,
        expected_snapshot: repository
            .head("pin-replay")
            .expect("current head")
            .snapshot_id(),
        action: CampaignControlAction::Complete,
    };
    assert!(matches!(
        repository.apply_control("pin-replay", &reused_as_control),
        Err(CampaignRepositoryError::CommandReuse)
    ));

    let current = repository.head("pin-replay").expect("head before unpin");
    let unpin = PinRequest {
        command: CampaignCommandId::from_hash(CampaignHash::derive("test", b"unpin-command")),
        expected_snapshot: current.snapshot_id(),
        change: PinChange::new(lineage.genesis(), None, "resolved").expect("unpin change"),
    };
    repository
        .apply_pin("pin-replay", &unpin)
        .expect("accept unpin");
    let unpinned = repository.head("pin-replay").expect("unpinned head");
    let tombstone = repository
        .merkle
        .get(
            unpinned.snapshot().roots().pins,
            pin_configuration_key(lineage.genesis()),
        )
        .expect("read unpin projection")
        .expect("unpin tombstone");
    assert_eq!(
        repository.read_fact(tombstone).expect("unpin fact"),
        CampaignFact::PinCommandAccepted(unpin)
    );
}

#[test]
fn pin_retention_inventory_is_snapshot_bound_and_reconstructs_after_cache_eviction() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("pin-retention", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let thin = PinRequest {
        command: CampaignCommandId::from_hash(CampaignHash::derive("test", b"pin-retention-thin")),
        expected_snapshot: genesis.snapshot_id(),
        change: PinChange::new(
            lineage.genesis(),
            Some(PinRetention::Thin),
            "retain semantic replay inputs",
        )
        .expect("thin pin"),
    };
    let accepted = repository
        .apply_pin("pin-retention", &thin)
        .expect("accept thin pin");
    repository.evict_local_checkpoint(accepted.new_snapshot.content_id());

    let mut roots = Vec::new();
    let summary = repository
        .visit_pin_retention_roots("pin-retention", &mut |record| roots.push(record))
        .expect("visit thin retention roots after cache eviction");
    assert_eq!(summary.snapshot(), accepted.new_snapshot);
    assert_eq!(summary.entries(), 1);
    assert_eq!(summary.thin_pins(), 1);
    assert_eq!(summary.exact_pins(), 0);
    assert_eq!(summary.tombstones(), 0);
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0].request(), &thin);
    assert_eq!(roots[0].retention(), PinRetention::Thin);
    assert_eq!(roots[0].configuration_artifact(), lineage.genesis_content());
    assert_eq!(roots[0].scenario_artifact(), lineage.scenario_content());

    let exact = PinRequest {
        command: CampaignCommandId::from_hash(CampaignHash::derive("test", b"pin-retention-exact")),
        expected_snapshot: accepted.new_snapshot,
        change: PinChange::new(
            lineage.genesis(),
            Some(PinRetention::Exact),
            "retain a portable exact closure",
        )
        .expect("exact pin"),
    };
    let exact_accepted = repository
        .apply_pin("pin-retention", &exact)
        .expect("upgrade pin to exact");
    roots.clear();
    let exact_summary = repository
        .visit_pin_retention_roots("pin-retention", &mut |record| roots.push(record))
        .expect("visit exact retention roots");
    assert_eq!(exact_summary.snapshot(), exact_accepted.new_snapshot);
    assert_eq!(exact_summary.entries(), 1);
    assert_eq!(exact_summary.thin_pins(), 0);
    assert_eq!(exact_summary.exact_pins(), 1);
    assert_eq!(exact_summary.tombstones(), 0);
    assert_eq!(roots.len(), 1);
    assert_eq!(roots[0].request(), &exact);
    assert_eq!(roots[0].retention(), PinRetention::Exact);

    let unpin = PinRequest {
        command: CampaignCommandId::from_hash(CampaignHash::derive("test", b"pin-retention-unpin")),
        expected_snapshot: exact_accepted.new_snapshot,
        change: PinChange::new(lineage.genesis(), None, "retention no longer required")
            .expect("unpin"),
    };
    let unpinned = repository
        .apply_pin("pin-retention", &unpin)
        .expect("accept unpin");
    roots.clear();
    let unpinned_summary = repository
        .visit_pin_retention_roots("pin-retention", &mut |record| roots.push(record))
        .expect("visit unpinned projection");
    assert_eq!(unpinned_summary.snapshot(), unpinned.new_snapshot);
    assert_eq!(unpinned_summary.entries(), 1);
    assert_eq!(unpinned_summary.thin_pins(), 0);
    assert_eq!(unpinned_summary.exact_pins(), 0);
    assert_eq!(unpinned_summary.tombstones(), 1);
    assert!(roots.is_empty());
}

#[test]
fn pin_rejects_stale_or_nonauthoritative_configuration_before_writes() {
    let (repository, lineage, policy, blobs) = counted_fixture();
    let genesis = repository
        .create("pin-invalid", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let missing = ConfigurationId::from_hash(CampaignHash::derive("test", b"missing-config"));
    let request = PinRequest {
        command: CampaignCommandId::from_hash(CampaignHash::derive("test", b"missing-pin")),
        expected_snapshot: genesis.snapshot_id(),
        change: PinChange::new(missing, Some(PinRetention::Thin), "missing").expect("pin change"),
    };
    let before = blobs.object_count().expect("objects before rejection");

    assert!(matches!(
        repository.apply_pin("pin-invalid", &request),
        Err(CampaignRepositoryError::Integrity {
            reason: "pin-configuration-is-not-in-campaign-graph"
        })
    ));
    assert_eq!(
        blobs.object_count().expect("objects after rejection"),
        before
    );
    assert_eq!(
        repository.head("pin-invalid").expect("head").snapshot_id(),
        genesis.snapshot_id()
    );

    let stale = PinRequest {
        command: CampaignCommandId::from_hash(CampaignHash::derive("test", b"stale-pin")),
        expected_snapshot: CampaignSnapshotId::from_content_id(ContentId::for_bytes(
            ObjectKind::CampaignSnapshot,
            2,
            b"stale-pin-snapshot",
        ))
        .expect("stale snapshot id"),
        change: PinChange::new(lineage.genesis(), None, "stale").expect("unpin change"),
    };
    assert!(matches!(
        repository.apply_pin("pin-invalid", &stale),
        Err(CampaignRepositoryError::Stale { .. })
    ));
    assert_eq!(
        blobs.object_count().expect("objects after stale request"),
        before
    );
}

#[test]
fn imported_pin_transition_requires_the_exact_pin_projection() {
    let (repository, lineage, policy) = fixture();
    let source = repository
        .create("pin-source", &lineage, &policy, &BTreeMap::new())
        .expect("create source");
    repository
        .create("pin-forged", &lineage, &policy, &BTreeMap::new())
        .expect("create target");
    let request = PinRequest {
        command: CampaignCommandId::from_hash(CampaignHash::derive("test", b"imported-pin")),
        expected_snapshot: source.snapshot_id(),
        change: PinChange::new(lineage.genesis(), Some(PinRetention::Exact), "reproduce")
            .expect("pin change"),
    };
    let accepted = repository
        .apply_pin("pin-source", &request)
        .expect("accept source pin");
    let accepted_head = repository.head("pin-source").expect("accepted head");
    let transition = accepted_head
        .snapshot()
        .transition()
        .expect("pin transition");
    let mut roots = accepted_head.snapshot().roots();
    roots.pins = source.snapshot().roots().pins;
    let forged = CampaignSnapshot::successor(
        source.snapshot_id(),
        source.snapshot().lineage(),
        source.snapshot().active_policy(),
        roots,
        transition,
    )
    .expect("forged snapshot");
    let forged_content = repository
        .put_snapshot(&forged)
        .expect("put forged snapshot");
    let target_ref = campaign_ref("pin-forged").expect("target ref");
    repository
        .refs
        .compare_exchange(&target_ref, Some(source.content_id()), forged_content)
        .expect("advance forged ref");
    repository.evict_local_checkpoint(forged_content);

    assert!(matches!(
        repository.head("pin-forged"),
        Err(CampaignRepositoryError::Integrity {
            reason: "pin-transition-pins-root-mismatch"
        })
    ));
    assert_eq!(accepted.prior_snapshot, source.snapshot_id());
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
fn genesis_payload_and_exact_checkpoint_closure_versions_are_independent() {
    let (repository, original, policy) = fixture();
    let genesis = repository
        .publish_configuration_artifact(
            original.scenario(),
            original.scenario_content(),
            original.genesis(),
            2,
            b"configuration payload version two".to_vec(),
        )
        .expect("version-two genesis payload");
    let lineage = CampaignLineage::new(
        original.scenario(),
        original.scenario_content(),
        original.genesis(),
        genesis,
        original.crucible_version(),
        original.qemu_build(),
        original.protocol_versions().clone(),
        original.scenario_schema(),
        4,
    )
    .expect("version-four exact closure lineage");

    let created = repository
        .create("independent-versions", &lineage, &policy, &BTreeMap::new())
        .expect("configuration payload is not an exact checkpoint closure");
    let reopened = repository
        .head("independent-versions")
        .expect("revalidate head");
    assert_eq!(created, reopened);
    let content = repository.put_lineage(&lineage).expect("store lineage");
    assert_eq!(
        repository
            .read_lineage(content)
            .expect("revalidate lineage"),
        lineage
    );
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
