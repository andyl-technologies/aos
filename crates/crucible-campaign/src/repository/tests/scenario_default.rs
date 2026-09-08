//! Scenario-default request admission and cold-history validation.

use super::*;

fn policy_with_default_admission(base: &CampaignPolicy, admitted: bool) -> CampaignPolicy {
    CampaignPolicy::new(
        base.scenario(),
        base.campaign_seed(),
        base.mode(),
        base.explorer().clone(),
        base.choice_policies().clone(),
        base.objectives().clone(),
        base.guidance().clone(),
        base.stop_conditions().clone(),
        base.fairness(),
        base.retention(),
        admitted,
    )
    .expect("scenario-default policy")
}

fn request_with_source(
    basis: &BranchRequest,
    policy: CampaignPolicyId,
    source: CandidateSource,
) -> BranchRequest {
    BranchRequest::new(
        basis.branch_point(),
        basis.parent(),
        basis.opportunity(),
        basis.domain(),
        source,
        BranchRequestCause::ScenarioDefault(policy),
        BranchBudget::new(1, 1).expect("single default budget"),
        StopCondition::NextChoice,
    )
    .expect("scenario-default request")
}

fn exact_default_request(
    repository: &CampaignRepository,
    basis: &BranchRequest,
    policy: CampaignPolicyId,
) -> BranchRequest {
    let opportunity = repository
        .load_choice_opportunity(basis.opportunity())
        .expect("default opportunity");
    request_with_source(
        basis,
        policy,
        CandidateSource::finite(BTreeSet::from([opportunity.default().clone()]))
            .expect("one default value"),
    )
}

fn discover_request_basis(
    repository: &CampaignRepository,
    lineage: &CampaignLineage,
    policy: &CampaignPolicy,
    campaign: &str,
) -> (CampaignSnapshotId, BranchRequest) {
    let genesis = repository
        .create(campaign, lineage, policy, &BTreeMap::new())
        .expect("create scenario-default campaign");
    let basis = branch_request(
        repository,
        lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        campaign,
    );
    let discovered = repository
        .discover_choice_opportunity(
            campaign,
            genesis.snapshot_id(),
            basis.parent(),
            basis.opportunity(),
        )
        .expect("discover scenario-default opportunity");
    (discovered.new_snapshot, basis)
}

fn forge_branch_request_successor(
    repository: &CampaignRepository,
    parent_id: CampaignSnapshotId,
    request: &BranchRequest,
) -> ContentId {
    let parent = repository
        .read_snapshot(parent_id.content_id())
        .expect("branch-request parent");
    let request_content = repository
        .put_branch_request(request)
        .expect("put forged branch request");
    let request_id = BranchRequestId::from_content_id(request_content).expect("request id");
    let transition_content = repository
        .put_fact(&CampaignFact::BranchRequestIssued(request_id))
        .expect("put forged request fact");

    let mut roots = parent.snapshot.roots();
    roots.exploration = repository
        .merkle
        .insert(
            roots.exploration,
            map_key_content("exploration.branch-request", request_content),
            request_content,
        )
        .expect("insert forged request")
        .content_id();
    let frontier = repository
        .frontier_index_after(
            parent.snapshot.roots().exploration,
            &[(
                request_id,
                request.branch_point(),
                repository
                    .initial_continuation_state(request)
                    .expect("initial continuation"),
            )],
            true,
        )
        .expect("project forged frontier")
        .expect("frontier index");
    roots.exploration = repository
        .merkle
        .insert(roots.exploration, frontier_index_anchor_key(), frontier)
        .expect("install forged frontier")
        .content_id();
    let scan = repository
        .planner_scan_index_after(
            parent.snapshot.roots().exploration,
            &[(request_id, request.branch_point())],
            true,
        )
        .expect("project forged scan index")
        .expect("planner scan index");
    roots.exploration = repository
        .merkle
        .insert(roots.exploration, planner_scan_index_anchor_key(), scan)
        .expect("install forged scan index")
        .content_id();
    roots.coordination = repository
        .coordination_with_parent_result(parent_id.content_id(), &parent)
        .expect("coordination root");

    let forged = CampaignSnapshot::successor(
        parent_id,
        parent.snapshot.lineage(),
        parent.snapshot.active_policy(),
        roots,
        CampaignFactId::from_content_id(transition_content).expect("transition id"),
    )
    .expect("forged branch-request successor");
    repository
        .put_snapshot(&forged)
        .expect("put forged branch-request snapshot")
}

fn assert_cold_rejects(
    repository: &CampaignRepository,
    parent: CampaignSnapshotId,
    request: &BranchRequest,
    expected_reason: &'static str,
) {
    let forged = forge_branch_request_successor(repository, parent, request);
    let cold = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    let result = cold.validate_complete_head(forged);
    assert!(
        matches!(
            result,
            Err(CampaignRepositoryError::Integrity { reason }) if reason == expected_reason
        ),
        "unexpected cold validation result: {result:?}"
    );
}

#[test]
fn scenario_default_request_uses_the_ordinary_snapshot_bound_service_path() {
    let (repository, lineage, policy) = fixture();
    let (discovered, basis) =
        discover_request_basis(&repository, &lineage, &policy, "scenario-default-service");
    let request =
        exact_default_request(&repository, &basis, policy.id().expect("active policy id"));
    let service = RepositoryCampaignService::new(&repository, AllowCampaignQueries);
    let client = crate::CampaignClient::new(service);
    let principal = CampaignPrincipal::new("operator:default-run").expect("principal");
    let campaign = CampaignName::new("scenario-default-service").expect("campaign");

    let stale = crate::SubmitCampaignBranchRequest::new(
        principal.clone(),
        campaign.clone(),
        repository
            .genesis(campaign.as_str())
            .expect("genesis")
            .snapshot_id(),
        request.clone(),
    )
    .expect("stale submission");
    assert!(matches!(
        client.submit_branch_request(&stale),
        Err(crate::CampaignClientError::Service(
            crate::CampaignServiceFailure::Stale { .. }
        ))
    ));

    let submission = crate::SubmitCampaignBranchRequest::new(
        principal,
        campaign.clone(),
        discovered,
        request.clone(),
    )
    .expect("scenario-default submission");
    let accepted = client
        .submit_branch_request(&submission)
        .expect("accept scenario default");
    assert_eq!(accepted.request(), request.id().expect("request id"));

    let funded = repository
        .apply_control(
            campaign.as_str(),
            &command(
                "scenario-default-budget",
                accepted.new_snapshot(),
                CampaignControlAction::GrantBudget(
                    BudgetGrant::new(1, 1).expect("one default-path allowance"),
                ),
            ),
        )
        .expect("fund default path");
    let funded_head = repository
        .head(campaign.as_str())
        .expect("funded scenario-default head");
    let opportunity = repository
        .load_choice_opportunity(request.opportunity())
        .expect("default opportunity");
    let proposal = finite_proposal(
        &request,
        &policy,
        &funded_head,
        opportunity.default().clone(),
        1,
    );
    let proposed = repository
        .issue_proposal(campaign.as_str(), funded.new_snapshot, &proposal)
        .expect("issue exact default proposal");
    let (selection, path, attempt) = branch_attempt(&repository, &request, &proposal);
    let admitted = repository
        .admit_proposal(
            campaign.as_str(),
            proposed.new_snapshot,
            proposed.proposal,
            &selection,
            &path,
            &attempt,
        )
        .expect("admit exact default attempt");
    let admission = repository
        .load_attempt_admission(admitted.admission)
        .expect("load exact default admission");
    assert_eq!(admission.schema_version(), 2);
    assert_eq!(admitted.admission.content_id().schema_version(), 2);
    assert_eq!(
        admission.role(),
        AttemptAdmissionRole::ExecutionBasis {
            proposal: Some(proposed.proposal),
            cause: BranchRequestCause::ScenarioDefault(policy.id().expect("active policy id")),
            admission_ordinal: AdmissionOrdinal::new(1),
        }
    );

    let cold = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    cold.validate_complete_head(admitted.new_snapshot.content_id())
        .expect("cold validation accepts admitted exact default");
}

#[test]
fn cold_repository_rejects_invalid_scenario_default_provenance() {
    let (repository, lineage, base) = fixture();

    let disabled = policy_with_default_admission(&base, false);
    let (disabled_parent, disabled_basis) = discover_request_basis(
        &repository,
        &lineage,
        &disabled,
        "scenario-default-disabled",
    );
    let disabled_request = exact_default_request(
        &repository,
        &disabled_basis,
        disabled.id().expect("disabled policy id"),
    );
    assert_cold_rejects(
        &repository,
        disabled_parent,
        &disabled_request,
        "scenario-default-branch-request-is-disabled-by-policy",
    );

    let (wrong_parent, wrong_basis) = discover_request_basis(
        &repository,
        &lineage,
        &base,
        "scenario-default-wrong-policy",
    );
    let other_policy = CampaignPolicy::new(
        base.scenario(),
        CampaignSeed::from_bytes([0x55; 32]),
        base.mode(),
        base.explorer().clone(),
        base.choice_policies().clone(),
        base.objectives().clone(),
        base.guidance().clone(),
        base.stop_conditions().clone(),
        base.fairness(),
        base.retention(),
        true,
    )
    .expect("other policy");
    repository
        .publish_policy(&other_policy)
        .expect("publish other policy");
    let wrong_policy_request = exact_default_request(
        &repository,
        &wrong_basis,
        other_policy.id().expect("other policy id"),
    );
    assert_cold_rejects(
        &repository,
        wrong_parent,
        &wrong_policy_request,
        "branch-request-policy-is-not-active",
    );

    let (value_parent, value_basis) =
        discover_request_basis(&repository, &lineage, &base, "scenario-default-wrong-value");
    let wrong_value = request_with_source(
        &value_basis,
        base.id().expect("active policy id"),
        CandidateSource::finite(BTreeSet::from([ChoiceValue::Boolean(true)]))
            .expect("wrong value source"),
    );
    assert_cold_rejects(
        &repository,
        value_parent,
        &wrong_value,
        "scenario-default-branch-request-source-is-not-exact-default",
    );

    let multiple_values = request_with_source(
        &value_basis,
        base.id().expect("active policy id"),
        CandidateSource::finite(BTreeSet::from([
            ChoiceValue::Boolean(false),
            ChoiceValue::Boolean(true),
        ]))
        .expect("multiple value source"),
    );
    assert_cold_rejects(
        &repository,
        value_parent,
        &multiple_values,
        "scenario-default-branch-request-source-is-not-exact-default",
    );

    let generator =
        CandidateGeneratorSpec::new(1, CandidateGeneratorAlgorithm::All).expect("static generator");
    let generator_id = repository
        .publish_generator(&generator)
        .expect("publish static generator");
    let generated = request_with_source(
        &value_basis,
        base.id().expect("active policy id"),
        CandidateSource::generated(generator_id),
    );
    assert_cold_rejects(
        &repository,
        value_parent,
        &generated,
        "scenario-default-branch-request-source-is-not-finite",
    );
}
