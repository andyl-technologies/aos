//! Attempt admission and budget accounting tests.

use super::*;

#[test]
fn attempt_admission_assigns_one_basis_and_deduplicates_later_causes() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("admission", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    repository
        .apply_control(
            "admission",
            &command(
                "exact-allowance",
                genesis.snapshot_id(),
                CampaignControlAction::GrantBudget(BudgetGrant::new(3, 2).expect("allowance")),
            ),
        )
        .expect("fund three causes and two attempts");
    let genesis = repository.head("admission").expect("funded head");
    let request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "admission-first",
    );
    let requested = repository
        .submit_known_branch_request("admission", genesis.snapshot_id(), &request)
        .expect("request");
    let request_head = repository.head("admission").expect("request head");
    let proposal = finite_proposal(
        &request,
        &policy,
        &request_head,
        ChoiceValue::Boolean(false),
        1,
    );
    let proposed = repository
        .issue_proposal("admission", requested.new_snapshot, &proposal)
        .expect("proposal");
    let (selection, path, attempt) = branch_attempt(&repository, &request, &proposal);
    let admitted = repository
        .admit_proposal(
            "admission",
            proposed.new_snapshot,
            proposed.proposal,
            &selection,
            &path,
            &attempt,
        )
        .expect("admission");
    assert!(!admitted.replayed);
    let basis = repository
        .load_attempt_admission(admitted.admission)
        .expect("basis");
    assert_eq!(
        basis.role(),
        AttemptAdmissionRole::ExecutionBasis {
            proposal: Some(proposed.proposal),
            cause: request.cause(),
            admission_ordinal: AdmissionOrdinal::new(1),
        }
    );
    assert_eq!(basis.retention_policy(), policy.id().ok());
    let basis_head = repository.head("admission").expect("basis head");
    assert_eq!(
        repository
            .merkle
            .inspect_shallow(basis_head.snapshot().roots().accounting)
            .expect("accounting root")
            .entry_count(),
        7 + repository
            .merkle
            .inspect_shallow(genesis.snapshot().roots().accounting)
            .expect("funded accounting root")
            .entry_count()
    );

    let valid_admission_snapshot = repository
        .read_snapshot(admitted.new_snapshot.content_id())
        .expect("valid admission snapshot");
    let mut forged_roots = valid_admission_snapshot.snapshot.roots();
    forged_roots.accounting = repository
        .merkle
        .insert(
            forged_roots.accounting,
            map_key_content("accounting.forged", admitted.admission.content_id()),
            admitted.admission.content_id(),
        )
        .expect("forged accounting root")
        .content_id();
    let forged = CampaignSnapshot::successor(
        valid_admission_snapshot
            .snapshot
            .parent()
            .expect("admission parent"),
        valid_admission_snapshot.snapshot.lineage(),
        valid_admission_snapshot.snapshot.active_policy(),
        forged_roots,
        valid_admission_snapshot
            .snapshot
            .transition()
            .expect("admission transition"),
    )
    .expect("forged admission successor");
    let forged_content = repository
        .put_snapshot(&forged)
        .expect("put forged admission successor");
    assert!(matches!(
        repository.validate_complete_head(forged_content),
        Err(CampaignRepositoryError::Integrity {
            reason: "attempt-admission-transition-accounting-root-mismatch"
        })
    ));

    let replay = repository
        .admit_proposal(
            "admission",
            genesis.snapshot_id(),
            proposed.proposal,
            &selection,
            &path,
            &attempt,
        )
        .expect("replay admission");
    assert!(replay.replayed);
    assert_eq!(replay.new_snapshot, admitted.new_snapshot);
    let wrong_path = BranchPath::new(Vec::new()).expect("wrong path");
    assert!(matches!(
        repository.admit_proposal(
            "admission",
            genesis.snapshot_id(),
            proposed.proposal,
            &selection,
            &wrong_path,
            &attempt,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "proposal-admission-input-closure-mismatch"
        })
    ));

    let AttemptStart::Branch {
        edge,
        parent,
        selection: selection_id,
    } = attempt.start()
    else {
        panic!("branch attempt")
    };
    let wrong_scope = BranchPath::new(vec![crate::BranchPathSegment::new(
        crate::BranchPointId::from_hash(CampaignHash::derive("test", b"wrong-path-branch-point")),
        edge,
    )])
    .expect("wrong-scope path");
    repository
        .put_branch_path(&wrong_scope)
        .expect("publish wrong-scope path");
    let wrong_scope_attempt = Attempt::new(
        AttemptStart::Branch {
            edge,
            parent,
            selection: selection_id,
        },
        wrong_scope.id().expect("wrong-scope path id"),
        attempt.stop().clone(),
    )
    .expect("wrong-scope attempt");
    let wrong_scope_attempt_id = repository
        .put_attempt(&wrong_scope_attempt)
        .expect("publish wrong-scope attempt");
    assert!(matches!(
        repository.load_attempt(
            AttemptId::from_content_id(wrong_scope_attempt_id).expect("wrong-scope attempt id")
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "attempt-branch-path-terminal-scope-mismatch"
        })
    ));

    let second_proposal = finite_proposal(
        &request,
        &policy,
        &basis_head,
        ChoiceValue::Boolean(true),
        2,
    );
    let second_proposed = repository
        .issue_proposal("admission", basis_head.snapshot_id(), &second_proposal)
        .expect("second proposal");
    let (second_selection, second_path, second_attempt) =
        branch_attempt(&repository, &request, &second_proposal);
    let second_admitted = repository
        .admit_proposal(
            "admission",
            second_proposed.new_snapshot,
            second_proposed.proposal,
            &second_selection,
            &second_path,
            &second_attempt,
        )
        .expect("second admission");
    assert_eq!(
        repository
            .load_attempt_admission(second_admitted.admission)
            .expect("second basis")
            .role(),
        AttemptAdmissionRole::ExecutionBasis {
            proposal: Some(second_proposed.proposal),
            cause: request.cause(),
            admission_ordinal: AdmissionOrdinal::new(2),
        }
    );
    let second_head = repository.head("admission").expect("second head");
    assert_eq!(
        repository
            .budget_projection("admission")
            .expect("exhausted attempts")
            .remaining_attempts(),
        0
    );
    assert_eq!(
        repository
            .merkle
            .inspect_shallow(second_head.snapshot().roots().accounting)
            .expect("second accounting root")
            .entry_count(),
        12 + repository
            .merkle
            .inspect_shallow(genesis.snapshot().roots().accounting)
            .expect("funded accounting root")
            .entry_count()
    );

    let duplicate_request = BranchRequest::new(
        request.branch_point(),
        request.parent(),
        request.opportunity(),
        request.domain(),
        request.source().clone(),
        BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(CampaignHash::derive(
            "test",
            b"admission-duplicate",
        ))),
        request.budget(),
        request.stop().clone(),
    )
    .expect("duplicate request");
    let duplicate_requested = repository
        .submit_known_branch_request("admission", second_head.snapshot_id(), &duplicate_request)
        .expect("duplicate request transition");
    let duplicate_request_head = repository
        .head("admission")
        .expect("duplicate request head");
    let duplicate_proposal = finite_proposal(
        &duplicate_request,
        &policy,
        &duplicate_request_head,
        ChoiceValue::Boolean(false),
        1,
    );
    let duplicate_proposed = repository
        .issue_proposal(
            "admission",
            duplicate_requested.new_snapshot,
            &duplicate_proposal,
        )
        .expect("duplicate proposal");
    let (duplicate_selection, duplicate_path, duplicate_attempt) =
        branch_attempt(&repository, &duplicate_request, &duplicate_proposal);
    assert_eq!(
        duplicate_attempt.id().expect("duplicate attempt id"),
        admitted.attempt
    );
    let deduplicated = repository
        .admit_proposal(
            "admission",
            duplicate_proposed.new_snapshot,
            duplicate_proposed.proposal,
            &duplicate_selection,
            &duplicate_path,
            &duplicate_attempt,
        )
        .expect("deduplicated admission");
    let additional = repository
        .load_attempt_admission(deduplicated.admission)
        .expect("additional cause");
    assert_eq!(
        additional.role(),
        AttemptAdmissionRole::AdditionalCause {
            proposal: duplicate_proposed.proposal,
        }
    );
    assert_eq!(additional.retention_policy(), policy.id().ok());
    let deduplicated_head = repository.head("admission").expect("deduplicated head");
    assert_eq!(
        repository
            .merkle
            .inspect_shallow(deduplicated_head.snapshot().roots().accounting)
            .expect("deduplicated accounting root")
            .entry_count(),
        15 + repository
            .merkle
            .inspect_shallow(genesis.snapshot().roots().accounting)
            .expect("funded accounting root")
            .entry_count()
    );
    let budget = repository
        .budget_projection("admission")
        .expect("deduplicated budget");
    assert_eq!((budget.spent_proposals, budget.spent_attempts), (3, 2));
    assert_eq!(
        (budget.remaining_proposals(), budget.remaining_attempts()),
        (0, 0)
    );
    assert_eq!(
        repository
            .merkle
            .get(
                deduplicated_head.snapshot().roots().accounting,
                admission_sequence_key(),
            )
            .expect("sequence lookup"),
        Some(second_admitted.admission.content_id())
    );
}

#[test]
fn attempt_admission_enforces_request_budget_without_materializing_accounting() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create_funded("admission-budget", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let base = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "admission-budget",
    );
    let request = BranchRequest::new(
        base.branch_point(),
        base.parent(),
        base.opportunity(),
        base.domain(),
        base.source().clone(),
        base.cause(),
        BranchBudget::new(2, 1).expect("limited budget"),
        base.stop().clone(),
    )
    .expect("limited request");
    let requested = repository
        .submit_known_branch_request("admission-budget", genesis.snapshot_id(), &request)
        .expect("request");
    let request_head = repository.head("admission-budget").expect("request head");
    let first = finite_proposal(
        &request,
        &policy,
        &request_head,
        ChoiceValue::Boolean(false),
        1,
    );
    let first_proposed = repository
        .issue_proposal("admission-budget", requested.new_snapshot, &first)
        .expect("first proposal");
    let (first_selection, first_path, first_attempt) =
        branch_attempt(&repository, &request, &first);
    repository
        .admit_proposal(
            "admission-budget",
            first_proposed.new_snapshot,
            first_proposed.proposal,
            &first_selection,
            &first_path,
            &first_attempt,
        )
        .expect("first admission");

    let first_head = repository.head("admission-budget").expect("first head");
    let second = finite_proposal(
        &request,
        &policy,
        &first_head,
        ChoiceValue::Boolean(true),
        2,
    );
    let second_proposed = repository
        .issue_proposal("admission-budget", first_head.snapshot_id(), &second)
        .expect("second proposal");
    let (second_selection, second_path, second_attempt) =
        branch_attempt(&repository, &request, &second);
    assert!(matches!(
        repository.admit_proposal(
            "admission-budget",
            second_proposed.new_snapshot,
            second_proposed.proposal,
            &second_selection,
            &second_path,
            &second_attempt,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "branch-request-attempt-budget-exhausted"
        })
    ));
    assert_eq!(
        repository
            .head("admission-budget")
            .expect("unchanged head")
            .snapshot_id(),
        second_proposed.new_snapshot
    );
}

#[test]
fn policy_bound_admission_validates_every_request_cause() {
    let (repository, lineage, policy) = fixture();
    let head = repository
        .create_funded("admission-all-causes", &lineage, &policy, &BTreeMap::new())
        .expect("create funded campaign");
    let base = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "admission-all-causes",
    );
    let policy_id = policy.id().expect("policy ID");
    let causes = [
        BranchRequestCause::Planner(
            PlannerInvocationId::from_content_id(ContentId::for_bytes(
                ObjectKind::Policy,
                2,
                b"admission-all-causes-planner",
            ))
            .expect("planner invocation ID"),
        ),
        BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(CampaignHash::derive(
            "test",
            b"admission-all-causes-operator",
        ))),
        BranchRequestCause::Debugger(DebugSessionId::from_hash(CampaignHash::derive(
            "test",
            b"admission-all-causes-debugger",
        ))),
        BranchRequestCause::ExhaustivePolicy(policy_id),
        BranchRequestCause::ScenarioDefault(policy_id),
    ];

    for (index, cause) in causes.into_iter().enumerate() {
        let request = BranchRequest::new(
            base.branch_point(),
            base.parent(),
            base.opportunity(),
            base.domain(),
            base.source().clone(),
            cause,
            base.budget(),
            base.stop().clone(),
        )
        .expect("request cause");
        repository
            .put_branch_request(&request)
            .expect("publish request cause");
        let proposal = finite_proposal(
            &request,
            &policy,
            &head,
            if index % 2 == 0 {
                ChoiceValue::Boolean(false)
            } else {
                ChoiceValue::Boolean(true)
            },
            1,
        );
        repository
            .put_proposal(&proposal)
            .expect("publish proposal cause");
        let (selection, path, attempt) = branch_attempt(&repository, &request, &proposal);
        repository
            .put_selection(&selection)
            .expect("publish cause selection");
        repository
            .put_branch_path(&path)
            .expect("publish cause path");
        repository
            .put_attempt(&attempt)
            .expect("publish cause attempt");
        let admission = AttemptAdmission::new_policy_bound(
            attempt.id().expect("attempt ID"),
            AttemptAdmissionRole::ExecutionBasis {
                proposal: Some(proposal.id().expect("proposal ID")),
                cause,
                admission_ordinal: AdmissionOrdinal::new(
                    u64::try_from(index).expect("cause index") + 1,
                ),
            },
            policy_id,
        );
        let decoded = AttemptAdmission::from_canonical_bytes(&admission.canonical_bytes())
            .expect("round-trip policy-bound admission");
        assert_eq!(decoded.retention_policy(), Some(policy_id));
        assert_eq!(
            admission
                .id()
                .expect("policy-bound admission ID")
                .content_id()
                .schema_version(),
            3
        );
    }
}

#[test]
fn admission_policy_binding_rejects_forgery_and_survives_policy_activation() {
    let (repository, lineage, policy) = fixture();
    let (_, admitted, observation) =
        admitted_observation_fixture(&repository, &lineage, &policy, "admission-policy");
    let basis = repository
        .load_attempt_admission(admitted.admission)
        .expect("policy-bound admission");
    let policy_id = policy.id().expect("original policy ID");
    assert_eq!(basis.retention_policy(), Some(policy_id));

    let (revision, revision_id) = retention_policy_revision(&repository, &policy);
    let forged = AttemptAdmission::new_policy_bound(basis.attempt(), basis.role(), revision_id);
    let forged_content = repository
        .put_attempt_admission(&forged)
        .expect("publish forged admission");
    assert!(matches!(
        repository.load_attempt_admission(
            AttemptAdmissionId::from_content_id(forged_content).expect("forged admission ID")
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "attempt-admission-retention-policy-mismatch"
        })
    ));
    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    assert!(matches!(
        restarted.verify_campaign_closure(forged_content),
        Err(CampaignRepositoryError::Integrity {
            reason: "attempt-admission-retention-policy-mismatch"
        })
    ));
    let valid_successor = repository
        .read_snapshot(admitted.new_snapshot.content_id())
        .expect("valid admission successor");
    let parent_content = valid_successor
        .snapshot
        .parent()
        .expect("admission parent")
        .content_id();
    let parent = repository
        .read_snapshot(parent_content)
        .expect("admission parent snapshot");
    let mut forged_roots = valid_successor.snapshot.roots();
    forged_roots.accounting = parent.snapshot.roots().accounting;
    for (key, value) in
        attempt_admission_upserts(forged_content, forged).expect("forged admission upserts")
    {
        forged_roots.accounting = repository
            .merkle
            .insert(forged_roots.accounting, key, value)
            .expect("forged accounting entry")
            .content_id();
    }
    let forged_transition = repository
        .put_fact(&CampaignFact::AttemptAdmitted(
            forged.id().expect("forged admission ID"),
        ))
        .expect("forged transition");
    assert!(matches!(
        repository.budgeted_successor(
            parent.snapshot.id().expect("parent snapshot ID"),
            parent.snapshot.lineage(),
            parent.snapshot.active_policy(),
            forged_roots,
            CampaignFactId::from_content_id(forged_transition).expect("forged transition ID"),
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "attempt-admission-retention-policy-mismatch"
        })
    ));

    let request = SubmitAttemptRequest::new(
        AssignmentId::from_bytes([0x31; 16]).expect("assignment"),
        DaemonEpoch::from_bytes([0x32; 16]).expect("daemon epoch"),
        lineage.id().expect("lineage ID"),
        admitted.attempt,
        AttemptResourceLimits::new(1, 512 * 1024 * 1024, 0, 10_000).expect("resource limits"),
        ExecutionRetentionIntent::RetainOnFailure,
    )
    .expect("submit request");
    let observation = ObservationId::from_content_id(
        repository
            .put_observation(&observation)
            .expect("publish observation"),
    )
    .expect("observation ID");
    let head = repository.head("admission-policy").expect("admission head");
    repository
        .apply_control(
            "admission-policy",
            &command(
                "activate-retention-revision",
                head.snapshot_id(),
                CampaignControlAction::ActivatePolicy(revision_id),
            ),
        )
        .expect("activate revised policy");

    repository
        .validate_executor_completion(&request, observation)
        .expect("in-flight completion under original admission policy");
    assert_eq!(
        repository
            .load_attempt_admission(admitted.admission)
            .expect("original basis after activation")
            .retention_policy(),
        Some(policy_id)
    );
    assert_eq!(revision.id().expect("revision ID"), revision_id);
}

#[test]
fn post_activation_additional_cause_keeps_each_admission_policy() {
    let (repository, lineage, policy) = fixture();
    let campaign = "cross-policy-dedup";
    let genesis = repository
        .create_funded(campaign, &lineage, &policy, &BTreeMap::new())
        .expect("create funded campaign");
    let request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "cross-policy-first",
    );
    let requested = repository
        .submit_known_branch_request(campaign, genesis.snapshot_id(), &request)
        .expect("submit first request");
    let proposal = finite_proposal(
        &request,
        &policy,
        &repository.head(campaign).expect("first request head"),
        ChoiceValue::Boolean(false),
        1,
    );
    let proposed = repository
        .issue_proposal(campaign, requested.new_snapshot, &proposal)
        .expect("issue first proposal");
    let (selection, path, attempt) = branch_attempt(&repository, &request, &proposal);
    let basis_result = repository
        .admit_proposal(
            campaign,
            proposed.new_snapshot,
            proposed.proposal,
            &selection,
            &path,
            &attempt,
        )
        .expect("admit first cause");

    let (revision, revision_id) = retention_policy_revision(&repository, &policy);
    repository
        .apply_control(
            campaign,
            &command(
                "activate-cross-policy-revision",
                basis_result.new_snapshot,
                CampaignControlAction::ActivatePolicy(revision_id),
            ),
        )
        .expect("activate revised policy");
    let duplicate_request = BranchRequest::new(
        request.branch_point(),
        request.parent(),
        request.opportunity(),
        request.domain(),
        request.source().clone(),
        BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(CampaignHash::derive(
            "test",
            b"cross-policy-second",
        ))),
        request.budget(),
        request.stop().clone(),
    )
    .expect("duplicate request");
    let duplicate_requested = repository
        .submit_known_branch_request(
            campaign,
            repository
                .head(campaign)
                .expect("activated head")
                .snapshot_id(),
            &duplicate_request,
        )
        .expect("submit duplicate request");
    let duplicate_proposal = finite_proposal(
        &duplicate_request,
        &revision,
        &repository.head(campaign).expect("duplicate request head"),
        ChoiceValue::Boolean(false),
        1,
    );
    let duplicate_proposed = repository
        .issue_proposal(
            campaign,
            duplicate_requested.new_snapshot,
            &duplicate_proposal,
        )
        .expect("issue duplicate proposal");
    let (duplicate_selection, duplicate_path, duplicate_attempt) =
        branch_attempt(&repository, &duplicate_request, &duplicate_proposal);
    assert_eq!(
        duplicate_attempt.id().expect("duplicate attempt ID"),
        basis_result.attempt
    );
    let additional_result = repository
        .admit_proposal(
            campaign,
            duplicate_proposed.new_snapshot,
            duplicate_proposed.proposal,
            &duplicate_selection,
            &duplicate_path,
            &duplicate_attempt,
        )
        .expect("admit post-activation cause");

    let basis = repository
        .load_attempt_admission(basis_result.admission)
        .expect("original execution basis");
    let additional = repository
        .load_attempt_admission(additional_result.admission)
        .expect("post-activation additional cause");
    assert!(matches!(
        additional.role(),
        AttemptAdmissionRole::AdditionalCause { .. }
    ));
    assert_eq!(basis.retention_policy(), policy.id().ok());
    assert_eq!(additional.retention_policy(), Some(revision_id));
}

fn retention_policy_revision(
    repository: &CampaignRepository,
    policy: &CampaignPolicy,
) -> (CampaignPolicy, CampaignPolicyId) {
    let revision = CampaignPolicy::new(
        policy.scenario(),
        policy.campaign_seed(),
        policy.mode(),
        policy.explorer().clone(),
        policy.choice_policies().clone(),
        policy.objectives().clone(),
        policy.guidance().clone(),
        policy.stop_conditions().clone(),
        policy.fairness(),
        RetentionPolicy::new(true, 2, true, true),
        policy.admits_scenario_defaults(),
    )
    .expect("retention policy revision");
    let revision_id = CampaignPolicyId::from_content_id(
        repository
            .publish_policy(&revision)
            .expect("publish retention policy revision"),
    )
    .expect("retention policy revision ID");
    (revision, revision_id)
}
