//! Request-local attempt caps, convergent causes, and paginated selection.

use super::*;

const CAMPAIGN: &str = "local-attempt-cap";

fn position(request: &BranchRequest) -> PlanningScanPosition {
    PlanningScanPosition::new(request.branch_point(), request.id().expect("request id"))
}

fn edge(
    repository: &CampaignRepository,
    policy: &CampaignPolicy,
    request: &BranchRequest,
    value: bool,
) -> crate::BranchEdgeId {
    let head = repository.head(CAMPAIGN).expect("head");
    let proposal = finite_proposal(request, policy, &head, ChoiceValue::Boolean(value), 1);
    let (selection, _, _) = branch_attempt(repository, request, &proposal);
    let crate::SelectionOrigin::CampaignBranch { edge, .. } = selection.origin() else {
        panic!("campaign edge")
    };
    edge
}

fn capped_request(request: &BranchRequest, values: BTreeSet<ChoiceValue>) -> BranchRequest {
    BranchRequest::new(
        request.branch_point(),
        request.parent(),
        request.opportunity(),
        request.domain(),
        CandidateSource::finite(values).expect("source"),
        request.cause(),
        BranchBudget::new(2, 1).expect("one new attempt"),
        request.stop().clone(),
    )
    .expect("capped request")
}

fn admit_value(
    repository: &CampaignRepository,
    policy: &CampaignPolicy,
    request: &BranchRequest,
    value: bool,
) {
    let head = repository.head(CAMPAIGN).expect("head");
    let proposal = finite_proposal(request, policy, &head, ChoiceValue::Boolean(value), 1);
    let issued = repository
        .issue_proposal(CAMPAIGN, head.snapshot_id(), &proposal)
        .expect("issue seed proposal");
    let (selection, path, attempt) = branch_attempt(repository, request, &proposal);
    repository
        .admit_proposal(
            CAMPAIGN,
            issued.new_snapshot,
            issued.proposal,
            &selection,
            &path,
            &attempt,
        )
        .expect("admit seed attempt");
}

fn complete_scan(
    repository: &mut CampaignRepository,
    engine: &PlannerEngine,
    artifact: &PolicyArtifact,
    state: &mut PlannerState,
    puct: bool,
    limit: u32,
) -> (PlannerRequest, crate::PlannerEngineOutput) {
    let mut after = None;
    for _ in 0..4 {
        let head = repository.head(CAMPAIGN).expect("scan head");
        let invocation = repository
            .prepare_planner_invocation(
                CAMPAIGN,
                head.snapshot_id(),
                engine,
                artifact,
                state,
                after,
                limit,
                PlanningBudget::new(1, 1, 32, 32_768, 100).expect("planning budget"),
            )
            .expect("invocation");
        let request = repository
            .build_planner_request(head.snapshot_id(), invocation.id().expect("invocation id"))
            .expect("request");
        let output = if puct {
            crate::CanonicalPuctPlanner
                .plan(&request)
                .expect("PUCT plan")
        } else {
            CanonicalFrontierPlanner
                .plan(&request)
                .expect("canonical plan")
        };
        let PlannerProposalDisposition::ContinueScan { cursor } = output.proposal().disposition()
        else {
            return (request, output);
        };
        after = cursor.after();
        accept(repository, &request, &output);
        *state = output.proposal().next_state().clone();
    }
    panic!("bounded fixture scan did not reach EOF")
}

fn accept(
    repository: &mut CampaignRepository,
    request: &PlannerRequest,
    output: &crate::PlannerEngineOutput,
) -> PlannerStepResult {
    let result = repository
        .accept_planner_step(
            CAMPAIGN,
            request.expected_snapshot(),
            output.proposal(),
            output.proposal().usage_claim(),
        )
        .expect("accept page");
    *repository = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    repository
        .validate_complete_head(result.new_snapshot.content_id())
        .expect("cold validation");
    result
}

fn assert_local_projection(
    repository: &CampaignRepository,
    request: &PlannerRequest,
    capped: &BranchRequest,
    blobs: &MemoryBlobBackend,
) {
    let inputs = request
        .input_bundle()
        .candidate_inputs(request)
        .expect("inputs");
    let input = &inputs[&position(capped)];
    let budget = input.budget.as_ref().expect("request budget");
    assert_eq!(budget.remaining_request_attempts(), Some(0));
    assert!(!budget.request_can_issue());
    let snapshot = repository
        .read_snapshot(request.expected_snapshot().content_id())
        .expect("snapshot");
    let mut work = 0;
    assert_eq!(
        repository
            .remaining_request_attempts_before(
                &snapshot,
                capped.id().expect("request id"),
                2,
                1,
                &mut work
            )
            .expect("indexed request allowance"),
        0
    );
    let ledger = repository.parent_budget_ledger(&snapshot).expect("ledger");
    let legacy = crate::CampaignBudgetLedger::from_accounted_totals(
        ledger.granted_proposals(),
        ledger.granted_attempts(),
        ledger.spent_proposals(),
        ledger.spent_attempts(),
    );
    let legacy_snapshot = snapshot
        .snapshot
        .clone()
        .with_budget_ledger(repository.put_budget_ledger(legacy).expect("legacy ledger"));
    let snapshot = LoadedSnapshot {
        envelope: ObjectEnvelope::for_snapshot(&legacy_snapshot)
            .expect("legacy projection envelope"),
        snapshot: legacy_snapshot,
    };
    let mut work = 1;
    assert_eq!(
        repository
            .remaining_request_attempts_before(
                &snapshot,
                capped.id().expect("request id"),
                2,
                1,
                &mut work
            )
            .expect("one prior proposal"),
        0
    );
    assert_eq!(work, 0);
    assert!(matches!(
        repository.remaining_request_attempts_before(
            &snapshot,
            capped.id().expect("request id"),
            2,
            1,
            &mut work
        ),
        Err(CampaignRepositoryError::Codec(
            CampaignCodecError::LimitExceeded {
                limit: "planner-request-budget-prior-proposals"
            }
        ))
    ));

    let before = blobs.object_count().expect("before");
    let forged = budget.clone().with_request_attempts(1);
    let objects = request
        .input_bundle()
        .object_ids()
        .map(|id| {
            if id == budget.id().expect("id").content_id() {
                ObjectEnvelope::for_candidate_budget(&forged).expect("forged envelope")
            } else {
                request
                    .input_bundle()
                    .object(id)
                    .expect("decode")
                    .expect("object")
            }
        })
        .collect();
    let forged = PlannerRequest::new(
        request.expected_snapshot(),
        request.invocation().clone(),
        request.engine().clone(),
        request.policy_artifact().clone(),
        request.policy().clone(),
        request.planner_state().clone(),
        *request.input_view(),
        CampaignPlanningBundle::new(objects).expect("bundle"),
    )
    .expect("structural forgery");
    assert!(matches!(
        repository.preflight_planner_request_inputs(&forged),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-request-candidate-budget-mismatch"
        })
    ));
    assert_eq!(blobs.object_count().expect("after"), before);
    assert_eq!(
        repository.head(CAMPAIGN).expect("head").snapshot_id(),
        request.expected_snapshot()
    );
}

#[test]
fn request_attempt_caps_do_not_block_other_frontiers_or_later_convergence() {
    for puct in [false, true] {
        for limit in [1, 8] {
            let (mut repository, lineage, policy, blobs) = counted_fixture();
            let head = repository
                .create(CAMPAIGN, &lineage, &policy, &BTreeMap::new())
                .expect("create");
            repository
                .apply_control(
                    CAMPAIGN,
                    &command(
                        "fund-local-cap",
                        head.snapshot_id(),
                        CampaignControlAction::GrantBudget(BudgetGrant::new(8, 4).expect("grant")),
                    ),
                )
                .expect("fund");
            let mut requests = ["budget-left", "budget-right"].map(|name| {
                branch_request(
                    &repository,
                    &lineage,
                    lineage.genesis_content(),
                    lineage.genesis(),
                    name,
                )
            });
            if puct {
                if edge(&repository, &policy, &requests[0], true)
                    >= edge(&repository, &policy, &requests[1], false)
                {
                    requests.swap(0, 1);
                }
                assert!(
                    edge(&repository, &policy, &requests[0], true)
                        < edge(&repository, &policy, &requests[1], false)
                );
            } else {
                requests.sort_by_key(position);
            }
            let capped = capped_request(
                &requests[0],
                BTreeSet::from([ChoiceValue::Boolean(false), ChoiceValue::Boolean(true)]),
            );
            let other = capped_request(&requests[1], BTreeSet::from([ChoiceValue::Boolean(false)]));
            for request in [&capped, &other] {
                let head = repository.head(CAMPAIGN).expect("head");
                repository
                    .submit_known_branch_request(CAMPAIGN, head.snapshot_id(), request)
                    .expect("submit");
            }
            admit_value(&repository, &policy, &capped, false);
            let (engine, artifact, mut state) = if puct {
                crate::CanonicalPuctPlanner::basis()
                    .expect("PUCT basis")
                    .into_parts()
            } else {
                CanonicalFrontierPlanner::basis()
                    .expect("canonical basis")
                    .into_parts()
            };
            let dependency = if puct {
                crate::CanonicalPuctPlanner::dependency_lock_bytes()
            } else {
                CanonicalFrontierPlanner::dependency_lock_bytes()
            };
            repository
                .blobs
                .put_if_absent(
                    artifact.dependency_lock(),
                    &BlobHandle::from_bytes(dependency.to_vec()),
                )
                .expect("dependency");

            if limit == 8 {
                let mut capabilities = engine.capabilities().clone();
                capabilities.remove(crate::CANONICAL_FRONTIER_REQUEST_BUDGET_CAPABILITY);
                let legacy_engine = PlannerEngine::new(
                    "crucible-canonical-frontier",
                    if puct { 4 } else { 3 },
                    1,
                    capabilities,
                )
                .expect("aggregate-only engine");
                let legacy_artifact = PolicyArtifact::new(
                    legacy_engine.id().expect("engine id"),
                    1,
                    artifact.dependency_lock(),
                    BTreeSet::new(),
                    BTreeMap::new(),
                )
                .expect("legacy artifact");
                let mut legacy_state = if puct {
                    crate::CanonicalPuctPlanner::initial_state_for_engine(&legacy_engine)
                        .expect("state")
                } else {
                    CanonicalFrontierPlanner::initial_state_for_engine(&legacy_engine)
                        .expect("state")
                };
                let (legacy_request, legacy_output) = complete_scan(
                    &mut repository,
                    &legacy_engine,
                    &legacy_artifact,
                    &mut legacy_state,
                    puct,
                    limit,
                );
                assert!(
                    matches!(legacy_output.proposal().disposition(), PlannerProposalDisposition::Issue { selected, .. } if *selected == position(&capped))
                );
                let before = blobs.object_count().expect("before legacy rejection");
                assert!(matches!(
                    repository.accept_planner_step(
                        CAMPAIGN,
                        legacy_request.expected_snapshot(),
                        legacy_output.proposal(),
                        legacy_output.proposal().usage_claim()
                    ),
                    Err(CampaignRepositoryError::Integrity {
                        reason: "branch-request-attempt-budget-exhausted"
                    })
                ));
                assert_eq!(
                    blobs.object_count().expect("after legacy rejection"),
                    before
                );
            }

            let (request, output) =
                complete_scan(&mut repository, &engine, &artifact, &mut state, puct, limit);
            if limit == 8 {
                assert_local_projection(&repository, &request, &capped, &blobs);
            }
            assert!(
                matches!(output.proposal().disposition(), PlannerProposalDisposition::Issue { selected, .. } if *selected == position(&other)),
                "puct={puct}, limit={limit}, capped candidate won: {:?}",
                output.proposal().disposition()
            );
            accept(&mut repository, &request, &output);
            state = output.proposal().next_state().clone();

            let (request, output) =
                complete_scan(&mut repository, &engine, &artifact, &mut state, puct, limit);
            assert!(matches!(
                output.proposal().disposition(),
                PlannerProposalDisposition::NoWork
            ));
            assert_eq!(
                output
                    .proposal()
                    .explanation()
                    .terms_micros()
                    .get("budget-blocked"),
                Some(&0)
            );
            accept(&mut repository, &request, &output);
            state = output.proposal().next_state().clone();

            let head = repository.head(CAMPAIGN).expect("head");
            repository
                .apply_control(
                    CAMPAIGN,
                    &command(
                        "aggregate-grant-cannot-reset-request-cap",
                        head.snapshot_id(),
                        CampaignControlAction::GrantBudget(BudgetGrant::new(1, 1).expect("grant")),
                    ),
                )
                .expect("aggregate grant");
            let (request, output) =
                complete_scan(&mut repository, &engine, &artifact, &mut state, puct, limit);
            assert!(matches!(
                output.proposal().disposition(),
                PlannerProposalDisposition::NoWork
            ));
            assert_eq!(
                output
                    .proposal()
                    .explanation()
                    .terms_micros()
                    .get("budget-blocked"),
                Some(&0)
            );
            accept(&mut repository, &request, &output);
            state = output.proposal().next_state().clone();

            // A new cause can establish the next candidate's execution basis.
            // Reusing it must remain legal even though this request spent its cap.
            let convergent = BranchRequest::new(
                capped.branch_point(),
                capped.parent(),
                capped.opportunity(),
                capped.domain(),
                CandidateSource::finite(BTreeSet::from([ChoiceValue::Boolean(true)]))
                    .expect("convergent source"),
                BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(
                    CampaignHash::derive("test.local-cap", b"new-cause"),
                )),
                BranchBudget::new(1, 1).expect("convergent budget"),
                capped.stop().clone(),
            )
            .expect("convergent request");
            let head = repository.head(CAMPAIGN).expect("head");
            repository
                .submit_known_branch_request(CAMPAIGN, head.snapshot_id(), &convergent)
                .expect("submit convergent cause");
            admit_value(&repository, &policy, &convergent, true);
            let (request, output) =
                complete_scan(&mut repository, &engine, &artifact, &mut state, puct, limit);
            assert!(
                matches!(output.proposal().disposition(), PlannerProposalDisposition::Issue { selected, .. } if *selected == position(&capped))
            );
            let result = accept(&mut repository, &request, &output);
            let step = repository
                .load_planner_step_at(result.new_snapshot, result.step)
                .expect("deduplicated step");
            assert_eq!(
                (step.accounting().attempts, step.accounting().deduplicated),
                (0, 1)
            );
            let budget = repository.budget_projection(CAMPAIGN).expect("ledger");
            assert_eq!((budget.spent_proposals, budget.spent_attempts), (4, 3));
        }
    }
}
