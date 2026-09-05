//! Budget-aware offer selection, hostile input, and legacy replay regressions.

use super::*;
use crate::PlannerEngineOutput;

const CAMPAIGN: &str = "candidate-budget";

struct MixedBudgetFixture {
    repository: CampaignRepository,
    blobs: Arc<MemoryBlobBackend>,
    blocked: BranchRequest,
    convergent: BranchRequest,
    engine: PlannerEngine,
    artifact: PolicyArtifact,
    state: PlannerState,
}

fn mixed_budget_fixture(puct: bool) -> MixedBudgetFixture {
    let (repository, lineage, policy, blobs) = counted_fixture();
    repository
        .create(CAMPAIGN, &lineage, &policy, &BTreeMap::new())
        .expect("create");
    grant(&repository, "initial-grant", 3, 1);
    let mut requests = ["budget-left", "budget-right"].map(|name| {
        let request = branch_request(
            &repository,
            &lineage,
            lineage.genesis_content(),
            lineage.genesis(),
            name,
        );
        BranchRequest::new(
            request.branch_point(),
            request.parent(),
            request.opportunity(),
            request.domain(),
            CandidateSource::finite(BTreeSet::from([ChoiceValue::Boolean(false)]))
                .expect("single candidate"),
            request.cause(),
            request.budget(),
            request.stop().clone(),
        )
        .expect("single-candidate request")
    });
    if puct {
        requests.sort_by_key(|request| {
            let proposal = finite_proposal(
                request,
                &policy,
                &repository.head(CAMPAIGN).expect("head"),
                ChoiceValue::Boolean(false),
                1,
            );
            let (selection, _, _) = branch_attempt(&repository, request, &proposal);
            let crate::SelectionOrigin::CampaignBranch { edge, .. } = selection.origin() else {
                panic!("campaign edge")
            };
            edge
        });
    } else {
        requests.sort_by_key(|request| {
            PlanningScanPosition::new(request.branch_point(), request.id().expect("request id"))
        });
    }
    let [blocked, seeded] = requests;
    for request in [&blocked, &seeded] {
        let head = repository.head(CAMPAIGN).expect("head");
        repository
            .submit_known_branch_request(CAMPAIGN, head.snapshot_id(), request)
            .expect("request");
    }
    let head = repository.head(CAMPAIGN).expect("head");
    let proposal = finite_proposal(&seeded, &policy, &head, ChoiceValue::Boolean(false), 1);
    let issued = repository
        .issue_proposal(CAMPAIGN, head.snapshot_id(), &proposal)
        .expect("seed proposal");
    let (selection, path, attempt) = branch_attempt(&repository, &seeded, &proposal);
    repository
        .admit_proposal(
            CAMPAIGN,
            issued.new_snapshot,
            issued.proposal,
            &selection,
            &path,
            &attempt,
        )
        .expect("seed attempt");
    let convergent = BranchRequest::new(
        seeded.branch_point(),
        seeded.parent(),
        seeded.opportunity(),
        seeded.domain(),
        CandidateSource::finite(BTreeSet::from([ChoiceValue::Boolean(false)]))
            .expect("single convergent cause"),
        BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(CampaignHash::derive(
            "test.candidate-budget",
            b"convergent-cause",
        ))),
        seeded.budget(),
        seeded.stop().clone(),
    )
    .expect("convergent request");
    let head = repository.head(CAMPAIGN).expect("head");
    repository
        .submit_known_branch_request(CAMPAIGN, head.snapshot_id(), &convergent)
        .expect("convergent request");
    let budget = repository.budget_projection(CAMPAIGN).expect("budget");
    assert_eq!(
        (budget.remaining_proposals(), budget.remaining_attempts()),
        (2, 0)
    );
    let (engine, artifact, state) = if puct {
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
        .expect("dependency lock");
    MixedBudgetFixture {
        repository,
        blobs,
        blocked,
        convergent,
        engine,
        artifact,
        state,
    }
}

fn grant(repository: &CampaignRepository, name: &str, proposals: u64, attempts: u64) {
    let head = repository.head(CAMPAIGN).expect("head");
    repository
        .apply_control(
            CAMPAIGN,
            &command(
                name,
                head.snapshot_id(),
                CampaignControlAction::GrantBudget(
                    BudgetGrant::new(proposals, attempts).expect("grant"),
                ),
            ),
        )
        .expect("grant funding");
}

fn request_for(
    fixture: &MixedBudgetFixture,
    state: &PlannerState,
    after: Option<PlanningScanPosition>,
    limit: u32,
) -> PlannerRequest {
    let head = fixture.repository.head(CAMPAIGN).expect("head");
    let invocation = fixture
        .repository
        .prepare_planner_invocation(
            CAMPAIGN,
            head.snapshot_id(),
            &fixture.engine,
            &fixture.artifact,
            state,
            after,
            limit,
            PlanningBudget::new(1, 1, 32, 32_768, 100).expect("planning budget"),
        )
        .expect("invocation");
    fixture
        .repository
        .build_planner_request(head.snapshot_id(), invocation.id().expect("invocation id"))
        .expect("request")
}

fn plan(request: &PlannerRequest, puct: bool) -> PlannerEngineOutput {
    if puct {
        crate::CanonicalPuctPlanner
            .plan(request)
            .expect("PUCT plan")
    } else {
        CanonicalFrontierPlanner
            .plan(request)
            .expect("canonical plan")
    }
}

#[test]
fn both_planners_pass_unaffordable_frontiers_to_reuse_an_attempt_across_pages() {
    for puct in [false, true] {
        let mut fixture = mixed_budget_fixture(puct);
        let wide = request_for(&fixture, &fixture.state, None, 8);
        let inputs = wide.input_bundle().candidate_inputs(&wide).expect("inputs");
        let blocked_position = PlanningScanPosition::new(
            fixture.blocked.branch_point(),
            fixture.blocked.id().expect("blocked id"),
        );
        let convergent_position = PlanningScanPosition::new(
            fixture.convergent.branch_point(),
            fixture.convergent.id().expect("convergent id"),
        );
        assert!(
            !inputs[&blocked_position]
                .budget
                .as_ref()
                .expect("blocked budget")
                .can_issue()
        );
        assert!(
            inputs[&convergent_position]
                .budget
                .as_ref()
                .expect("convergent budget")
                .can_issue()
        );
        if puct {
            let blocked = inputs[&blocked_position]
                .guidance
                .as_ref()
                .expect("blocked guidance");
            let convergent = inputs[&convergent_position]
                .guidance
                .as_ref()
                .expect("convergent guidance");
            assert!(blocked.edge() < convergent.edge());
            assert_eq!(
                blocked
                    .score_for_policy(wide.policy(), wide.invocation().input_view())
                    .expect("score")
                    .total_micros(),
                convergent
                    .score_for_policy(wide.policy(), wide.invocation().input_view())
                    .expect("score")
                    .total_micros()
            );
            assert_eq!(
                wide.ranked_candidates().expect("eligible rankings").len(),
                1
            );
        } else {
            assert!(blocked_position < convergent_position);
        }
        let wide_output = plan(&wide, puct);
        assert!(
            matches!(wide_output.proposal().disposition(), PlannerProposalDisposition::Issue { selected, .. } if *selected == convergent_position)
        );
        let mut state = fixture.state.clone();
        let mut after = None;
        let mut issued = false;
        for _ in 0..4 {
            let request = request_for(&fixture, &state, after, 1);
            let output = plan(&request, puct);
            let result = fixture
                .repository
                .accept_planner_step(
                    CAMPAIGN,
                    request.expected_snapshot(),
                    output.proposal(),
                    output.proposal().usage_claim(),
                )
                .expect("accept page");
            let cold = CampaignRepository::new(
                fixture.repository.blobs.clone(),
                fixture.repository.refs.clone(),
            );
            cold.validate_complete_head(result.new_snapshot.content_id())
                .expect("cold owner validation");
            fixture.repository = cold;
            state = output.proposal().next_state().clone();
            match output.proposal().disposition() {
                PlannerProposalDisposition::ContinueScan { cursor } => after = cursor.after(),
                PlannerProposalDisposition::Issue { selected, .. } => {
                    assert_eq!(*selected, convergent_position);
                    let step = fixture
                        .repository
                        .load_planner_step_at(result.new_snapshot, result.step)
                        .expect("step");
                    assert_eq!(
                        (step.accounting().attempts, step.accounting().deduplicated),
                        (0, 1)
                    );
                    issued = true;
                    break;
                }
                _ => panic!("eligible convergent candidate disappeared"),
            }
        }
        assert!(issued);
        let budget = fixture
            .repository
            .budget_projection(CAMPAIGN)
            .expect("budget");
        assert_eq!((budget.spent_proposals, budget.spent_attempts), (2, 1));
        let mut after = None;
        let mut blocked_at_eof = false;
        for _ in 0..4 {
            let request = request_for(&fixture, &state, after, 1);
            let output = plan(&request, puct);
            let result = fixture
                .repository
                .accept_planner_step(
                    CAMPAIGN,
                    request.expected_snapshot(),
                    output.proposal(),
                    output.proposal().usage_claim(),
                )
                .expect("retain blocked scan page");
            fixture.repository = CampaignRepository::new(
                fixture.repository.blobs.clone(),
                fixture.repository.refs.clone(),
            );
            fixture
                .repository
                .validate_complete_head(result.new_snapshot.content_id())
                .expect("cold blocked scan");
            let retained = fixture
                .repository
                .require_record_kind(
                    output
                        .proposal()
                        .next_state()
                        .id()
                        .expect("state id")
                        .content_id(),
                    crate::CampaignRecordKind::PlannerState,
                )
                .expect("retained state");
            state = crate::codec::decode(retained.body()).expect("restore portable state");
            match output.proposal().disposition() {
                PlannerProposalDisposition::ContinueScan { cursor } => after = cursor.after(),
                PlannerProposalDisposition::NoWork => {
                    assert_eq!(
                        output
                            .proposal()
                            .explanation()
                            .terms_micros()
                            .get("budget-blocked"),
                        Some(&1)
                    );
                    blocked_at_eof = true;
                    break;
                }
                _ => panic!("exhausted attempt allowance admitted another attempt"),
            }
        }
        assert!(blocked_at_eof);
        grant(&fixture.repository, "new-attempt-grant", 0, 1);
        let request = request_for(&fixture, &state, None, 8);
        let output = plan(&request, puct);
        assert!(
            matches!(output.proposal().disposition(), PlannerProposalDisposition::Issue { selected, .. } if *selected == blocked_position),
            "puct={puct}, expected={blocked_position:?}, disposition={:?}",
            output.proposal().disposition()
        );
        fixture
            .repository
            .accept_planner_step(
                CAMPAIGN,
                request.expected_snapshot(),
                output.proposal(),
                output.proposal().usage_claim(),
            )
            .expect("grant re-enables new attempt");
        let budget = fixture
            .repository
            .budget_projection(CAMPAIGN)
            .expect("spent budget");
        assert_eq!((budget.spent_proposals, budget.spent_attempts), (3, 2));
    }
}

#[test]
fn candidate_budget_forgery_is_rejected_before_publication() {
    let fixture = mixed_budget_fixture(true);
    let request = request_for(&fixture, &fixture.state, None, 8);
    let inputs = request
        .input_bundle()
        .candidate_inputs(&request)
        .expect("inputs");
    let position = PlanningScanPosition::new(
        fixture.blocked.branch_point(),
        fixture.blocked.id().expect("id"),
    );
    let input = &inputs[&position];
    let offer = input.offer.as_ref().expect("offer");
    let original = input.budget.as_ref().expect("budget");
    assert_eq!(
        crate::PlannerCandidateBudget::from_canonical_bytes(&original.canonical_bytes())
            .expect("round trip"),
        *original
    );
    let bytes = original.canonical_bytes();
    assert!(
        crate::PlannerCandidateBudget::from_canonical_bytes(&bytes[..bytes.len() - 1]).is_err()
    );
    for malformed in [
        [bytes.as_slice(), &[0]].concat(),
        [&2_u32.to_be_bytes()[..], &bytes[4..]].concat(),
        [&bytes[..bytes.len() - 1], &[2]].concat(),
    ] {
        assert!(crate::PlannerCandidateBudget::from_canonical_bytes(&malformed).is_err());
    }
    let missing_children = ObjectEnvelope::for_record(
        crate::CampaignRecordKind::PlannerCandidateBudget,
        BTreeSet::new(),
        bytes,
    )
    .expect("unchecked envelope construction");
    assert!(ObjectEnvelope::from_canonical_bytes(&missing_children.canonical_bytes()).is_err());
    for forged in [
        crate::PlannerCandidateBudget::new(offer, original.remaining_proposals() + 1, 0, true)
            .expect("inflated proposals"),
        crate::PlannerCandidateBudget::new(offer, original.remaining_proposals(), 1, true)
            .expect("inflated attempts"),
        crate::PlannerCandidateBudget::new(offer, original.remaining_proposals(), 0, false)
            .expect("forged dedup"),
    ] {
        let objects = request
            .input_bundle()
            .object_ids()
            .map(|id| {
                if id == original.id().expect("budget id").content_id() {
                    ObjectEnvelope::for_record(
                        crate::CampaignRecordKind::PlannerCandidateBudget,
                        crate::object::content_children(forged.content_children())
                            .expect("children"),
                        forged.canonical_bytes(),
                    )
                    .expect("forged envelope")
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
        .expect("structural request");
        let before = fixture.blobs.object_count().expect("before");
        assert!(matches!(
            fixture.repository.preflight_planner_request_inputs(&forged),
            Err(CampaignRepositoryError::Integrity {
                reason: "planner-request-candidate-budget-mismatch"
            })
        ));
        assert_eq!(fixture.blobs.object_count().expect("after"), before);
        assert_eq!(
            fixture
                .repository
                .head(CAMPAIGN)
                .expect("head")
                .snapshot_id(),
            request.expected_snapshot()
        );
    }
    let missing = request
        .input_bundle()
        .object_ids()
        .filter(|id| *id != original.id().expect("budget id").content_id())
        .map(|id| {
            request
                .input_bundle()
                .object(id)
                .expect("decode")
                .expect("object")
        })
        .collect();
    assert!(
        PlannerRequest::new(
            request.expected_snapshot(),
            request.invocation().clone(),
            request.engine().clone(),
            request.policy_artifact().clone(),
            request.policy().clone(),
            request.planner_state().clone(),
            *request.input_view(),
            CampaignPlanningBundle::new(missing).expect("bundle")
        )
        .is_err()
    );
}

#[test]
fn restarted_driver_retains_cross_page_blockers_without_settling_the_frontier() {
    let fixture = mixed_budget_fixture(false);
    let authority = PlannerAuthorityKey::from_bytes([17; 32]).expect("planner authority");
    let debugger = DebuggerAuthorityKey::from_bytes([23; 32]).expect("debugger authority");
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let restart = || {
        let repository = Arc::new(
            CampaignRepository::with_component_authorities(
                fixture.repository.blobs.clone(),
                fixture.repository.refs.clone(),
                authority.clone(),
                debugger.clone(),
            )
            .expect("cold authorized repository"),
        );
        let driver = CampaignPlannerDriver::new(
            Arc::clone(&repository),
            canonical_planner_client(&authority, Arc::clone(&calls)),
            fixture.engine.clone(),
            fixture.artifact.clone(),
            fixture.state.clone(),
            1,
            PlanningBudget::new(1, 1, 32, 32_768, 100).expect("budget"),
        )
        .expect("driver");
        (repository, driver)
    };
    let (mut repository, mut driver) = restart();
    let head = repository.head(CAMPAIGN).expect("head");
    repository
        .apply_control(
            CAMPAIGN,
            &command(
                "resume-driver",
                head.snapshot_id(),
                CampaignControlAction::Resume,
            ),
        )
        .expect("resume");
    let mut converged = false;
    let mut blocked = None;
    for _ in 0..8 {
        match driver.step(CAMPAIGN).expect("drive one page") {
            CampaignPlannerStepOutcome::Advanced {
                disposition: PlannerDisposition::ContinueScan { .. },
                ..
            } => {}
            CampaignPlannerStepOutcome::Advanced {
                disposition: PlannerDisposition::Issue { .. },
                ..
            } => {
                assert!(!converged, "only the existing attempt is affordable");
                converged = true;
            }
            outcome @ CampaignPlannerStepOutcome::BudgetBlocked { .. } => {
                blocked = Some(outcome);
                break;
            }
            other => panic!("blocked frontier must remain waitable: {other:?}"),
        }
        // Every committed page must contain enough state for a new owner and
        // planner client to continue, including an empty final scan page.
        (repository, driver) = restart();
    }
    assert!(converged);
    let blocked = blocked.expect("cross-page budget blocker");
    let count = calls.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(driver.step(CAMPAIGN).expect("unchanged wait"), blocked);
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), count);
    let budget = repository
        .budget_projection(CAMPAIGN)
        .expect("blocked ledger");
    assert_eq!((budget.spent_proposals, budget.spent_attempts), (2, 1));

    grant(&repository, "restart-driver-grant", 0, 1);
    (repository, driver) = restart();
    let mut issued = false;
    for _ in 0..4 {
        match driver.step(CAMPAIGN).expect("funded page") {
            CampaignPlannerStepOutcome::Advanced {
                disposition: PlannerDisposition::ContinueScan { .. },
                ..
            } => (repository, driver) = restart(),
            CampaignPlannerStepOutcome::Advanced {
                disposition: PlannerDisposition::Issue { .. },
                ..
            } => {
                issued = true;
                break;
            }
            other => panic!("grant must restart selection: {other:?}"),
        }
    }
    assert!(issued);
    let budget = repository
        .budget_projection(CAMPAIGN)
        .expect("funded ledger");
    assert_eq!((budget.spent_proposals, budget.spent_attempts), (3, 2));
}

#[test]
fn legacy_builtin_descriptors_keep_their_original_unfiltered_semantics() {
    for puct in [false, true] {
        let mut fixture = mixed_budget_fixture(puct);
        let mut capabilities =
            BTreeSet::from([crate::CANONICAL_FRONTIER_OFFERS_CAPABILITY.to_owned()]);
        if puct {
            capabilities.insert(crate::CANONICAL_FRONTIER_PUCT_CAPABILITY.to_owned());
        }
        fixture.engine = PlannerEngine::new(
            "crucible-canonical-frontier",
            if puct { 2 } else { 1 },
            1,
            capabilities,
        )
        .expect("legacy engine");
        fixture.state = if puct {
            crate::CanonicalPuctPlanner::initial_state_for_engine(&fixture.engine)
                .expect("legacy PUCT state")
        } else {
            CanonicalFrontierPlanner::initial_state_for_engine(&fixture.engine)
                .expect("legacy canonical state")
        };
        fixture.artifact = PolicyArtifact::new(
            fixture.engine.id().expect("engine id"),
            1,
            fixture.artifact.dependency_lock(),
            BTreeSet::new(),
            BTreeMap::new(),
        )
        .expect("legacy artifact");
        let request = request_for(&fixture, &fixture.state, None, 8);
        assert!(
            request
                .input_bundle()
                .candidate_inputs(&request)
                .expect("legacy inputs")
                .values()
                .all(|input| input.budget.is_none())
        );
        let output = plan(&request, puct);
        let blocked = PlanningScanPosition::new(
            fixture.blocked.branch_point(),
            fixture.blocked.id().expect("id"),
        );
        assert!(
            matches!(output.proposal().disposition(), PlannerProposalDisposition::Issue { selected, .. } if *selected == blocked),
            "puct={puct}, expected={blocked:?}, disposition={:?}",
            output.proposal().disposition()
        );
        assert!(
            !output
                .proposal()
                .explanation()
                .terms_micros()
                .contains_key("budget-blocked")
        );
        assert_eq!(
            &output.proposal().next_state().bytes()[..4],
            &1_u32.to_be_bytes()
        );
        assert!(matches!(
            fixture.repository.accept_planner_step(
                CAMPAIGN,
                request.expected_snapshot(),
                output.proposal(),
                output.proposal().usage_claim()
            ),
            Err(CampaignRepositoryError::Budget(
                crate::CampaignBudgetError::AttemptAllowanceExhausted
            ))
        ));
        grant(&fixture.repository, "fund-legacy", 0, 1);
        let request = request_for(&fixture, &fixture.state, None, 8);
        let output = plan(&request, puct);
        let result = fixture
            .repository
            .accept_planner_step(
                CAMPAIGN,
                request.expected_snapshot(),
                output.proposal(),
                output.proposal().usage_claim(),
            )
            .expect("accept legacy output");
        CampaignRepository::new(
            fixture.repository.blobs.clone(),
            fixture.repository.refs.clone(),
        )
        .validate_complete_head(result.new_snapshot.content_id())
        .expect("cold legacy replay");
    }
}
