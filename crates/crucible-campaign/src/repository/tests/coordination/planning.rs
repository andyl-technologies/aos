//! Planner driving, issue admission, restart, and cursor coordination regressions.

use super::*;

mod budget;
mod budget_scale;

#[test]
fn planner_no_work_is_owned_replayable_and_state_continuous() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create("planner-owner", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let engine = PlannerEngine::new("closed-rust", 1, 1, BTreeSet::new()).expect("planner engine");
    let initial_state = PlannerState::new(
        engine.id().expect("engine id"),
        "closed-rust-state",
        1,
        vec![0],
    )
    .expect("initial state");
    let (engine, artifact, invocation) = planner_basis(
        &repository,
        "planner-owner",
        genesis.snapshot_id(),
        initial_state,
    );
    let next_state = PlannerState::new(
        engine.id().expect("engine id"),
        "closed-rust-state",
        1,
        vec![1],
    )
    .expect("next state");
    let proposal = no_work_proposal(invocation.id().expect("invocation id"), next_state.clone());
    let measured = PlanningUsage {
        branch_requests: 0,
        proposals: 0,
        input_objects: 0,
        input_bytes: 0,
        fuel: 5,
    };
    let accepted = repository
        .accept_planner_step("planner-owner", genesis.snapshot_id(), &proposal, measured)
        .expect("accept planner step");
    assert!(!accepted.replayed);
    let step = repository
        .load_planner_step_at(accepted.new_snapshot, accepted.step)
        .expect("load accepted step");
    assert_eq!(step.parent(), None);
    assert_eq!(step.usage_claim(), proposal.usage_claim());
    assert_eq!(step.accounting().input_objects, measured.input_objects);
    assert_eq!(step.accounting().input_bytes, measured.input_bytes);
    assert_eq!(step.accounting().fuel, measured.fuel);

    let accepted_head = repository.head("planner-owner").expect("accepted head");
    assert_eq!(
        accepted_head
            .snapshot()
            .planning_view()
            .id()
            .expect("accepted planning view"),
        invocation.input_view()
    );
    assert_eq!(
        repository
            .merkle
            .inspect_shallow(accepted_head.snapshot().roots().coordination)
            .expect("planner coordination root")
            .entry_count(),
        3
    );
    let replay = repository
        .accept_planner_step("planner-owner", genesis.snapshot_id(), &proposal, measured)
        .expect("replay planner step");
    assert!(replay.replayed);
    assert_eq!(replay.step, accepted.step);
    assert_eq!(replay.new_snapshot, accepted.new_snapshot);

    let conflicting = no_work_proposal(
        invocation.id().expect("invocation id"),
        PlannerState::new(
            engine.id().expect("engine id"),
            "closed-rust-state",
            1,
            vec![9],
        )
        .expect("conflicting state"),
    );
    assert!(matches!(
        repository.accept_planner_step(
            "planner-owner",
            genesis.snapshot_id(),
            &conflicting,
            measured,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-invocation-result-conflict"
        })
    ));
    let oversized = PlanningUsage {
        input_bytes: 8193,
        ..measured
    };
    assert!(matches!(
        repository.accept_planner_step(
            "planner-owner",
            genesis.snapshot_id(),
            &proposal,
            oversized,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-step-invocation-budget-exceeded"
        })
    ));

    let request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "planner-state-continuity",
    );
    let requested = repository
        .submit_known_branch_request("planner-owner", accepted.new_snapshot, &request)
        .expect("submit intervening request");
    let wrong_input_state = PlannerState::new(
        engine.id().expect("engine id"),
        "closed-rust-state",
        1,
        vec![99],
    )
    .expect("wrong input state");
    assert!(matches!(
        repository.prepare_planner_invocation(
            "planner-owner",
            requested.new_snapshot,
            &engine,
            &artifact,
            &wrong_input_state,
            None,
            16,
            PlanningBudget::new(4, 4, 16, 8192, 100).expect("planner budget"),
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-step-parent-state-discontinuity"
        })
    ));

    let (_, _, next_invocation) = planner_basis(
        &repository,
        "planner-owner",
        requested.new_snapshot,
        next_state.clone(),
    );
    assert_eq!(
        next_invocation.policy_artifact(),
        artifact.id().expect("artifact id")
    );
    let final_state = PlannerState::new(
        engine.id().expect("engine id"),
        "closed-rust-state",
        1,
        vec![2],
    )
    .expect("final state");
    let second_proposal = no_work_proposal(
        next_invocation.id().expect("next invocation id"),
        final_state.clone(),
    );
    let second_measured = PlanningUsage {
        branch_requests: 0,
        proposals: 0,
        input_objects: next_invocation.scan_page().input_objects(),
        input_bytes: next_invocation.scan_page().input_bytes(),
        fuel: measured.fuel,
    };
    let second = repository
        .accept_planner_step(
            "planner-owner",
            requested.new_snapshot,
            &second_proposal,
            second_measured,
        )
        .expect("second planner step");
    assert_eq!(
        repository
            .load_planner_step_at(second.new_snapshot, second.step)
            .expect("second step")
            .parent(),
        Some(accepted.step)
    );

    let missing_invocation = PlannerInvocationId::from_content_id(ContentId::for_bytes(
        ObjectKind::Policy,
        2,
        b"missing parent invocation",
    ))
    .expect("missing invocation id");
    let accepted_accounting = PlanningAccounting {
        branch_requests: 0,
        proposals: 0,
        attempts: 0,
        deduplicated: 0,
        input_objects: second_measured.input_objects,
        input_bytes: second_measured.input_bytes,
        fuel: second_measured.fuel,
    };
    let incomplete_parent = PlannerStep::new(
        None,
        missing_invocation,
        RetainedPlannerRequestId::from_content_id(ContentId::for_bytes(
            ObjectKind::Policy,
            1,
            b"missing parent request",
        ))
        .expect("missing request id"),
        test_planner_request_digest(missing_invocation),
        next_invocation.policy(),
        next_invocation.engine(),
        next_invocation.policy_artifact(),
        next_invocation.input_view(),
        PlannerDisposition::NoWork,
        next_invocation.planner_state(),
        second_proposal.usage_claim(),
        accepted_accounting,
        second_proposal.explanation().clone(),
    )
    .expect("incomplete parent");
    let incomplete_parent_content = repository
        .put_planner_step(&incomplete_parent)
        .expect("put incomplete parent");
    let incomplete_parent_id =
        PlannerStepId::from_content_id(incomplete_parent_content).expect("parent id");
    let accepted_second = repository
        .load_planner_step_at(second.new_snapshot, second.step)
        .expect("accepted second step");
    let child = PlannerStep::new(
        Some(incomplete_parent_id),
        next_invocation.id().expect("next invocation id"),
        accepted_second.request(),
        accepted_second.request_digest(),
        next_invocation.policy(),
        next_invocation.engine(),
        next_invocation.policy_artifact(),
        next_invocation.input_view(),
        PlannerDisposition::NoWork,
        final_state.id().expect("final state id"),
        second_proposal.usage_claim(),
        accepted_accounting,
        second_proposal.explanation().clone(),
    )
    .expect("child step");
    let child_content = repository.put_planner_step(&child).expect("put child");
    let child_id = PlannerStepId::from_content_id(child_content).expect("child id");
    assert!(matches!(
        repository.load_planner_step(child_id),
        Err(CampaignRepositoryError::Store(StoreError::NotFound { .. }))
    ));
}

#[test]
fn planner_scan_results_are_bound_to_exact_served_pages() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create_funded("planner-pages", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let first_request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "first-planner-page-request",
    );
    let first = repository
        .submit_known_branch_request("planner-pages", genesis.snapshot_id(), &first_request)
        .expect("first request");
    let second_request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "second-planner-page-request",
    );
    let second = repository
        .submit_known_branch_request("planner-pages", first.new_snapshot, &second_request)
        .expect("second request");

    let mut expected_positions = [
        PlanningScanPosition::new(
            first_request.branch_point(),
            first_request.id().expect("first request id"),
        ),
        PlanningScanPosition::new(
            second_request.branch_point(),
            second_request.id().expect("second request id"),
        ),
    ];
    expected_positions.sort();
    let engine = PlannerEngine::new("closed-rust", 1, 1, BTreeSet::new()).expect("planner engine");
    let initial_state = PlannerState::new(
        engine.id().expect("engine id"),
        "closed-rust-state",
        1,
        vec![0],
    )
    .expect("initial state");
    let (engine, artifact, invocation) = planner_basis_with_page(
        &repository,
        "planner-pages",
        second.new_snapshot,
        initial_state.clone(),
        None,
        1,
    );
    assert_eq!(invocation.scan_page().positions(), &expected_positions[..1]);
    assert!(!invocation.scan_page().complete());
    assert!(matches!(
        repository.prepare_planner_invocation(
            "planner-pages",
            second.new_snapshot,
            &engine,
            &artifact,
            &initial_state,
            Some(expected_positions[0]),
            1,
            PlanningBudget::new(4, 4, 16, 8192, 100).expect("planner budget"),
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-invocation-scan-start-mismatch"
        })
    ));
    let measured = PlanningUsage {
        branch_requests: 0,
        proposals: 0,
        input_objects: invocation.scan_page().input_objects(),
        input_bytes: invocation.scan_page().input_bytes(),
        fuel: 1,
    };
    let next_state = PlannerState::new(
        engine.id().expect("engine id"),
        "closed-rust-state",
        1,
        vec![1],
    )
    .expect("next state");
    repository
        .put_planner_state(&next_state)
        .expect("put forged-step state");
    let false_eof_page = PlanningScanPage::new(
        None,
        invocation.scan_page().limit(),
        invocation.scan_page().positions().to_vec(),
        true,
        invocation.scan_page().input_bytes(),
    )
    .expect("false EOF page");
    let false_eof_invocation = PlannerInvocation::new(
        invocation.engine(),
        invocation.policy_artifact(),
        invocation.policy(),
        invocation.planner_state(),
        invocation.input_view(),
        false_eof_page,
        invocation.budget(),
    )
    .expect("false EOF invocation");
    repository
        .put_planner_invocation(&false_eof_invocation)
        .expect("put false EOF invocation");
    let false_eof_request = PlannerRequest::new(
        second.new_snapshot,
        false_eof_invocation.clone(),
        engine.clone(),
        artifact.clone(),
        policy.clone(),
        initial_state,
        repository
            .head("planner-pages")
            .expect("planner head")
            .snapshot()
            .planning_view(),
        CampaignPlanningBundle::new(vec![
            repository
                .read_envelope(invocation.scan_page().positions()[0].source().content_id())
                .expect("served request envelope"),
        ])
        .expect("false EOF bundle"),
    )
    .expect("false EOF request");
    repository
        .put_planner_request(&false_eof_request)
        .expect("put false EOF request");
    let false_eof_accounting = PlanningAccounting {
        branch_requests: 0,
        proposals: 0,
        attempts: 0,
        deduplicated: 0,
        input_objects: false_eof_invocation.scan_page().input_objects(),
        input_bytes: false_eof_invocation.scan_page().input_bytes(),
        fuel: 1,
    };
    let false_eof_step = PlannerStep::new(
        None,
        false_eof_invocation.id().expect("false EOF invocation id"),
        false_eof_request.id().expect("false EOF request id"),
        false_eof_request.request_digest(),
        false_eof_invocation.policy(),
        false_eof_invocation.engine(),
        false_eof_invocation.policy_artifact(),
        false_eof_invocation.input_view(),
        PlannerDisposition::NoWork,
        next_state.id().expect("next state id"),
        measured,
        false_eof_accounting,
        GuidanceEvidence::new(BTreeMap::new()).expect("false EOF evidence"),
    )
    .expect("false EOF step");
    let false_eof_step_content = repository
        .put_planner_step(&false_eof_step)
        .expect("put false EOF step");
    assert!(matches!(
        repository.load_planner_step(
            PlannerStepId::from_content_id(false_eof_step_content).expect("false EOF step id"),
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-invocation-scan-page-mismatch"
        })
    ));
    let jump = PlannerStepProposal::new(
        invocation.id().expect("invocation id"),
        next_state.clone(),
        measured,
        GuidanceEvidence::new(BTreeMap::new()).expect("jump evidence"),
        PlannerProposalDisposition::ContinueScan {
            cursor: crate::PlanningScanCursor::new(
                invocation.input_view(),
                Some(expected_positions[1]),
            ),
        },
    )
    .expect("jump proposal");
    assert!(matches!(
        repository.accept_planner_step("planner-pages", second.new_snapshot, &jump, measured,),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-step-disposition-does-not-match-served-page"
        })
    ));

    let false_eof = no_work_proposal(invocation.id().expect("invocation id"), next_state.clone());
    assert!(matches!(
        repository.accept_planner_step("planner-pages", second.new_snapshot, &false_eof, measured,),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-step-disposition-does-not-match-served-page"
        })
    ));

    let continuation = PlannerStepProposal::new(
        invocation.id().expect("invocation id"),
        next_state.clone(),
        measured,
        GuidanceEvidence::new(BTreeMap::new()).expect("continuation evidence"),
        PlannerProposalDisposition::ContinueScan {
            cursor: crate::PlanningScanCursor::new(
                invocation.input_view(),
                Some(expected_positions[0]),
            ),
        },
    )
    .expect("continuation proposal");
    let continued = repository
        .accept_planner_step(
            "planner-pages",
            second.new_snapshot,
            &continuation,
            measured,
        )
        .expect("accept continuation");
    let next_invocation = repository
        .prepare_planner_invocation(
            "planner-pages",
            continued.new_snapshot,
            &engine,
            &artifact,
            &next_state,
            Some(expected_positions[0]),
            1,
            PlanningBudget::new(4, 4, 16, 8192, 100).expect("planner budget"),
        )
        .expect("prepare final page");
    assert_eq!(
        next_invocation.scan_page().positions(),
        &expected_positions[1..]
    );
    assert!(next_invocation.scan_page().complete());
    let final_measured = PlanningUsage {
        branch_requests: 0,
        proposals: 0,
        input_objects: next_invocation.scan_page().input_objects(),
        input_bytes: next_invocation.scan_page().input_bytes(),
        fuel: 1,
    };
    let done = no_work_proposal(
        next_invocation.id().expect("next invocation id"),
        PlannerState::new(
            engine.id().expect("engine id"),
            "closed-rust-state",
            1,
            vec![2],
        )
        .expect("done state"),
    );
    let finished = repository
        .accept_planner_step(
            "planner-pages",
            continued.new_snapshot,
            &done,
            final_measured,
        )
        .expect("accept EOF");
    assert!(matches!(
        repository.prepare_planner_invocation(
            "planner-pages",
            finished.new_snapshot,
            &engine,
            &artifact,
            done.next_state(),
            None,
            1,
            PlanningBudget::new(4, 4, 16, 8192, 100).expect("planner budget"),
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-invocation-reopens-complete-view"
        })
    ));
}

#[test]
fn canonical_frontier_planner_carries_the_first_ready_offer_across_pages() {
    let (repository, lineage, policy, blobs) = counted_fixture();
    let genesis = repository
        .create_funded("canonical-planner", &lineage, &policy, &BTreeMap::new())
        .expect("create canonical-planner campaign");
    let first_request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "canonical-planner-first",
    );
    let first = repository
        .submit_known_branch_request("canonical-planner", genesis.snapshot_id(), &first_request)
        .expect("submit first planner request");
    let second_request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "canonical-planner-second",
    );
    let second = repository
        .submit_known_branch_request("canonical-planner", first.new_snapshot, &second_request)
        .expect("submit second planner request");

    let engine = CanonicalFrontierPlanner::descriptor().expect("closed planner descriptor");
    let initial_state = CanonicalFrontierPlanner::initial_state().expect("closed planner state");
    let dependency_bytes = b"canonical planner dependency".to_vec();
    let dependency = ContentId::for_bytes(ObjectKind::Trace, 1, &dependency_bytes);
    repository
        .blobs
        .put_if_absent(dependency, &BlobHandle::from_bytes(dependency_bytes))
        .expect("planner dependency");
    let artifact = PolicyArtifact::new(
        engine.id().expect("engine id"),
        1,
        dependency,
        BTreeSet::new(),
        BTreeMap::new(),
    )
    .expect("planner artifact");
    let budget = PlanningBudget::new(1, 1, 8, 8192, 100).expect("planner budget");
    let wide_invocation = repository
        .prepare_planner_invocation(
            "canonical-planner",
            second.new_snapshot,
            &engine,
            &artifact,
            &initial_state,
            None,
            2,
            budget,
        )
        .expect("prepare complete two-source page");
    let wide_request = repository
        .build_planner_request(
            second.new_snapshot,
            wide_invocation.id().expect("wide invocation id"),
        )
        .expect("build complete two-source request");
    assert_eq!(wide_request.input_bundle().len(), 8);
    let wide_output = CanonicalFrontierPlanner
        .plan(&wide_request)
        .expect("plan complete two-source page");
    let PlannerProposalDisposition::Issue { selected, .. } = wide_output.proposal().disposition()
    else {
        panic!("complete two-source page must issue")
    };
    assert_eq!(*selected, wide_invocation.scan_page().positions()[0]);
    assert!(matches!(
        repository.prepare_planner_invocation(
            "canonical-planner",
            second.new_snapshot,
            &engine,
            &artifact,
            wide_output.proposal().next_state(),
            None,
            2,
            budget,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "builtin-planner-initial-state-mismatch"
        })
    ));

    let first_invocation = repository
        .prepare_planner_invocation(
            "canonical-planner",
            second.new_snapshot,
            &engine,
            &artifact,
            &initial_state,
            None,
            1,
            budget,
        )
        .expect("prepare first planner page");
    let first_request_message = repository
        .build_planner_request(
            second.new_snapshot,
            first_invocation.id().expect("first invocation id"),
        )
        .expect("build first planner request");
    assert_eq!(first_request_message.input_bundle().len(), 4);
    let original = first_request_message
        .input_bundle()
        .candidate_inputs(&first_request_message)
        .expect("candidate inputs")
        .into_values()
        .next()
        .expect("first candidate")
        .offer
        .expect("offer");
    let forged = Proposal::new(
        original.branch_point(),
        original.request(),
        original.domain(),
        original.value().clone(),
        original.policy(),
        original.planner_invocation(),
        original.ordinal() + 1,
        original.guidance_basis(),
    )
    .expect("forged offer");
    let tampered_objects = first_request_message
        .input_bundle()
        .object_ids()
        .map(|id| {
            let object = first_request_message
                .input_bundle()
                .object(id)
                .expect("decode bundle object")
                .expect("bundle object");
            match object.record_kind() {
                crate::CampaignRecordKind::Proposal => ObjectEnvelope::for_record(
                    crate::CampaignRecordKind::Proposal,
                    crate::object::content_children(forged.content_children())
                        .expect("offer children"),
                    forged.canonical_bytes(),
                )
                .expect("forged offer envelope"),
                crate::CampaignRecordKind::PlannerCandidateBudget => {
                    let original =
                        crate::PlannerCandidateBudget::from_canonical_bytes(object.body())
                            .expect("budget");
                    let budget = crate::PlannerCandidateBudget::new(
                        &forged,
                        original.remaining_proposals(),
                        original.remaining_attempts(),
                        original.requires_new_attempt(),
                    )
                    .expect("rebind budget");
                    ObjectEnvelope::for_record(
                        crate::CampaignRecordKind::PlannerCandidateBudget,
                        crate::object::content_children(budget.content_children())
                            .expect("budget children"),
                        budget.canonical_bytes(),
                    )
                    .expect("forged budget envelope")
                }
                _ => object,
            }
        })
        .collect::<Vec<_>>();
    let tampered = PlannerRequest::new(
        first_request_message.expected_snapshot(),
        first_request_message.invocation().clone(),
        first_request_message.engine().clone(),
        first_request_message.policy_artifact().clone(),
        first_request_message.policy().clone(),
        first_request_message.planner_state().clone(),
        *first_request_message.input_view(),
        CampaignPlanningBundle::new(tampered_objects).expect("tampered bundle"),
    )
    .expect("structurally valid tampered request");
    let before_rejection = blobs.object_count().expect("object count before rejection");
    assert!(matches!(
        repository.preflight_planner_request_inputs(&tampered),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-request-candidate-projection-mismatch"
        })
    ));
    assert_eq!(
        blobs.object_count().expect("object count after rejection"),
        before_rejection
    );
    let mut planner = CanonicalFrontierPlanner;
    let first_output = planner
        .plan(&first_request_message)
        .expect("plan first page");
    let PlannerProposalDisposition::ContinueScan { cursor } = first_output.proposal().disposition()
    else {
        panic!("first planner page must continue")
    };
    let first_position = first_invocation.scan_page().positions()[0];
    assert_eq!(cursor.after(), Some(first_position));
    let first_usage = first_output.proposal().usage_claim();
    let forged_output = PlannerStepProposal::new(
        first_output.proposal().invocation(),
        first_output.proposal().next_state().clone(),
        first_usage,
        GuidanceEvidence::new(BTreeMap::new()).expect("forged evidence"),
        first_output.proposal().disposition().clone(),
    )
    .expect("structurally valid forged planner output");
    let before_output_rejection = blobs
        .object_count()
        .expect("objects before output rejection");
    assert!(matches!(
        repository.accept_planner_step(
            "canonical-planner",
            second.new_snapshot,
            &forged_output,
            first_usage,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "builtin-planner-output-mismatch"
        })
    ));
    assert_eq!(
        blobs
            .object_count()
            .expect("objects after output rejection"),
        before_output_rejection
    );
    let continued = repository
        .accept_planner_step(
            "canonical-planner",
            second.new_snapshot,
            first_output.proposal(),
            first_usage,
        )
        .expect("accept first planner page");

    let final_invocation = repository
        .prepare_planner_invocation(
            "canonical-planner",
            continued.new_snapshot,
            &engine,
            &artifact,
            first_output.proposal().next_state(),
            cursor.after(),
            1,
            budget,
        )
        .expect("prepare final planner page");
    assert!(final_invocation.scan_page().complete());
    let final_request_message = repository
        .build_planner_request(
            continued.new_snapshot,
            final_invocation.id().expect("final invocation id"),
        )
        .expect("build final planner request");
    let final_output = planner
        .plan(&final_request_message)
        .expect("plan final page");
    let PlannerProposalDisposition::Issue {
        selected,
        branch_requests,
        proposals,
    } = final_output.proposal().disposition()
    else {
        panic!("final planner page must issue")
    };
    assert_eq!(*selected, first_position);
    assert!(branch_requests.is_empty());
    assert_eq!(proposals.len(), 1);
    assert_eq!(proposals[0].request(), first_position.source());
    assert_eq!(proposals[0].ordinal(), 1);
    let final_usage = final_output.proposal().usage_claim();
    let issued = repository
        .accept_planner_step(
            "canonical-planner",
            continued.new_snapshot,
            final_output.proposal(),
            final_usage,
        )
        .expect("accept canonical planner issue");
    let accepted = repository
        .load_planner_step_at(issued.new_snapshot, issued.step)
        .expect("load accepted planner step");
    assert_eq!(accepted.selected_source(), Some(first_position.source()));

    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    restarted
        .validate_complete_head(issued.new_snapshot.content_id())
        .expect("restart validates canonical planner issue");
    let retained = restarted
        .load_planner_request(accepted.request())
        .expect("load retained candidate offers");
    assert_eq!(retained, final_request_message);
}

#[test]
fn canonical_puct_planner_ranks_every_ready_offer_and_replays_owner_guidance() {
    let (repository, lineage, policy, blobs) = counted_fixture();
    let genesis = repository
        .create_funded("canonical-puct", &lineage, &policy, &BTreeMap::new())
        .expect("create canonical PUCT campaign");
    let request_a = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "canonical-puct-a",
    );
    let first = repository
        .submit_known_branch_request("canonical-puct", genesis.snapshot_id(), &request_a)
        .expect("submit first PUCT request");
    let request_b = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "canonical-puct-b",
    );
    let second = repository
        .submit_known_branch_request("canonical-puct", first.new_snapshot, &request_b)
        .expect("submit second PUCT request");
    let mut requests = [request_a, request_b];
    requests.sort_by_key(|request| {
        PlanningScanPosition::new(request.branch_point(), request.id().expect("request id"))
    });
    let guided = requests[1].clone();
    let guided_position = PlanningScanPosition::new(
        guided.branch_point(),
        guided.id().expect("guided request id"),
    );

    let completed_proposal = finite_proposal(
        &guided,
        &policy,
        &repository.head("canonical-puct").expect("request head"),
        ChoiceValue::Boolean(false),
        1,
    );
    let proposed = repository
        .issue_proposal("canonical-puct", second.new_snapshot, &completed_proposal)
        .expect("issue completed-edge proposal");
    let (selection, path, attempt) = branch_attempt(&repository, &guided, &completed_proposal);
    let admitted = repository
        .admit_proposal(
            "canonical-puct",
            proposed.new_snapshot,
            proposed.proposal,
            &selection,
            &path,
            &attempt,
        )
        .expect("admit completed-edge attempt");
    let child = ConfigurationId::from_hash(CampaignHash::derive(
        "test.canonical-puct",
        b"completed-child",
    ));
    let child_content = repository
        .publish_configuration_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            child,
            1,
            b"canonical PUCT completed child".to_vec(),
        )
        .expect("publish completed child");
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
    let observation = Observation::new(
        admitted.attempt,
        child,
        child_content,
        path.id().expect("path id"),
        StopOutcome::Reached(StopCondition::NextChoice),
        measurements,
        properties,
        coverage,
        BTreeSet::from([guided.opportunity()]),
    )
    .expect("completed observation");
    let observed = repository
        .publish_observation("canonical-puct", admitted.new_snapshot, &observation)
        .expect("publish completed observation");

    let basis = repository
        .publish_canonical_puct_planner_basis()
        .expect("publish PUCT planner basis");
    let budget = PlanningBudget::new(1, 1, 32, 1024 * 1024, 100).expect("planner budget");
    let invocation = repository
        .prepare_planner_invocation(
            "canonical-puct",
            observed.new_snapshot,
            basis.engine(),
            basis.artifact(),
            basis.initial_state(),
            None,
            2,
            budget,
        )
        .expect("prepare PUCT invocation");
    let request = repository
        .build_planner_request(
            observed.new_snapshot,
            invocation.id().expect("invocation id"),
        )
        .expect("build PUCT request");
    let kinds = request
        .input_bundle()
        .object_ids()
        .map(|id| {
            request
                .input_bundle()
                .object(id)
                .expect("decode bundle object")
                .expect("bundle object")
                .record_kind()
        })
        .collect::<Vec<_>>();
    assert_eq!(
        kinds
            .iter()
            .filter(|kind| **kind == crate::CampaignRecordKind::Proposal)
            .count(),
        2
    );
    assert_eq!(
        kinds
            .iter()
            .filter(|kind| **kind == crate::CampaignRecordKind::PlannerCandidateGuidance)
            .count(),
        2
    );
    let rankings = request
        .ranked_candidates()
        .expect("rank authenticated PUCT candidates");
    assert_eq!(rankings.len(), 2);
    assert_eq!(rankings[0].guidance().position(), guided_position);
    assert!(rankings[0].score().total_micros() > rankings[1].score().total_micros());
    assert_eq!(
        rankings[0].proposal().branch_point(),
        rankings[0].guidance().position().branch_point()
    );
    assert_eq!(
        rankings[0].proposal().request(),
        rankings[0].guidance().position().source()
    );

    let output = CanonicalPuctPlanner
        .plan(&request)
        .expect("rank PUCT request");
    let PlannerProposalDisposition::Issue { selected, .. } = output.proposal().disposition() else {
        panic!("complete PUCT page must issue")
    };
    assert_eq!(*selected, guided_position);
    assert_eq!(*selected, rankings[0].guidance().position());
    assert_eq!(
        output.proposal().explanation().terms_micros()["selected-parent-visits"],
        1
    );
    assert!(output.proposal().explanation().terms_micros()["selected-total-micros"] > 0);

    let before_tamper = blobs.object_count().expect("objects before tamper");
    let tampered_objects = request
        .input_bundle()
        .object_ids()
        .map(|id| {
            let object = request
                .input_bundle()
                .object(id)
                .expect("decode bundle object")
                .expect("bundle object");
            if object.record_kind() != crate::CampaignRecordKind::PlannerCandidateGuidance {
                return object;
            }
            let guidance = crate::PlannerCandidateGuidance::from_canonical_bytes(object.body())
                .expect("candidate guidance");
            if guidance.position() != guided_position {
                return object;
            }
            let statistics = guidance.statistics();
            let forged_statistics = crate::PuctEdgeStatistics::new(
                statistics.parent_visits(),
                statistics.edge_visits(),
                statistics.reward_sum_micros(),
                statistics.prior_micros().saturating_sub(1),
                statistics.is_novel(),
                statistics.is_fairness_reserved(),
            )
            .expect("forged statistics");
            let forged = crate::PlannerCandidateGuidance::new(
                guidance.input_view(),
                guidance.policy(),
                guidance.position(),
                guidance.domain(),
                guidance.domain_semantics(),
                guidance.value().clone(),
                guidance.ordinal(),
                guidance.edge(),
                forged_statistics,
                guidance.novelty_events(),
                guidance.objective_reward_micros(),
                guidance.finding_events().clone(),
            )
            .expect("forged guidance");
            ObjectEnvelope::for_record(
                crate::CampaignRecordKind::PlannerCandidateGuidance,
                crate::object::content_children(forged.content_children())
                    .expect("forged guidance children"),
                forged.canonical_bytes(),
            )
            .expect("forged guidance envelope")
        })
        .collect::<Vec<_>>();
    let tampered = PlannerRequest::new(
        request.expected_snapshot(),
        request.invocation().clone(),
        request.engine().clone(),
        request.policy_artifact().clone(),
        request.policy().clone(),
        request.planner_state().clone(),
        *request.input_view(),
        CampaignPlanningBundle::new(tampered_objects).expect("tampered PUCT bundle"),
    )
    .expect("structurally valid owner-guidance forgery");
    assert!(matches!(
        repository.preflight_planner_request_inputs(&tampered),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-request-candidate-guidance-mismatch"
        })
    ));
    assert_eq!(
        blobs.object_count().expect("objects after tamper"),
        before_tamper
    );

    let accepted = repository
        .accept_planner_step(
            "canonical-puct",
            observed.new_snapshot,
            output.proposal(),
            output.proposal().usage_claim(),
        )
        .expect("accept PUCT output");
    repository
        .validated_heads
        .lock()
        .expect("validation cache")
        .clear();
    let replayed = repository
        .load_planner_step_at(accepted.new_snapshot, accepted.step)
        .expect("replay PUCT step after cache clear");
    assert_eq!(replayed.disposition().selected(), Some(guided_position));

    let ranking_request = crate::GetCampaignPlannerRankingsRequest::new(
        crate::CampaignPrincipal::new("operator:alice").expect("principal"),
        crate::CampaignName::new("canonical-puct").expect("campaign"),
        accepted.new_snapshot,
        accepted.step,
    )
    .expect("ranking request");
    let ranking_response = crate::CampaignClient::new(crate::RepositoryCampaignService::new(
        &repository,
        PermitAlice,
    ))
    .get_campaign_planner_rankings(&ranking_request)
    .expect("proof-bearing planner rankings");
    assert_eq!(
        ranking_response.step().id().expect("response step ID"),
        accepted.step
    );
    assert_eq!(ranking_response.parent(), replayed.parent());
    let served_rankings = ranking_response
        .ranked_candidates()
        .expect("served authenticated rankings");
    assert_eq!(served_rankings.len(), 2);
    assert_eq!(served_rankings[0].guidance().position(), guided_position);
    let decoded = crate::GetCampaignPlannerRankingsResponse::from_canonical_bytes(
        &ranking_response.canonical_bytes(),
    )
    .expect("decode ranking response");
    decoded
        .validate_for(&ranking_request)
        .expect("validate decoded ranking response");
}

#[derive(Clone)]
struct ExactCanonicalPlannerSupervisor {
    calls: Arc<std::sync::atomic::AtomicUsize>,
}

impl crate::PlannerExecutionSupervisor<CanonicalFrontierPlanner>
    for ExactCanonicalPlannerSupervisor
{
    type Error = std::convert::Infallible;

    fn execute(
        &mut self,
        engine: &mut CanonicalFrontierPlanner,
        request: &PlannerRequest,
    ) -> Result<crate::SupervisedPlannerExecution<CampaignCodecError>, Self::Error> {
        self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let measured_fuel = u64::try_from(request.invocation().scan_page().positions().len())
            .expect("page count fits u64")
            + 1;
        Ok(crate::SupervisedPlannerExecution::new(
            engine.plan(request),
            measured_fuel,
        ))
    }
}

fn canonical_planner_driver_basis(
    repository: &CampaignRepository,
) -> (PlannerEngine, PolicyArtifact, PlannerState, PlanningBudget) {
    let engine = CanonicalFrontierPlanner::descriptor().expect("canonical planner descriptor");
    let dependency_bytes = b"campaign planner driver dependency".to_vec();
    let dependency = ContentId::for_bytes(ObjectKind::Trace, 1, &dependency_bytes);
    repository
        .blobs
        .put_if_absent(dependency, &BlobHandle::from_bytes(dependency_bytes))
        .expect("planner dependency");
    let artifact = PolicyArtifact::new(
        engine.id().expect("engine id"),
        1,
        dependency,
        BTreeSet::new(),
        BTreeMap::new(),
    )
    .expect("planner artifact");
    let initial_state = CanonicalFrontierPlanner::initial_state().expect("initial planner state");
    let budget = PlanningBudget::new(1, 1, 8, 8_192, 100).expect("planner budget");
    (engine, artifact, initial_state, budget)
}

fn canonical_planner_client(
    authority: &PlannerAuthorityKey,
    calls: Arc<std::sync::atomic::AtomicUsize>,
) -> crate::PlannerClient<
    crate::AuthorizedPlannerService<CanonicalFrontierPlanner, ExactCanonicalPlannerSupervisor>,
> {
    crate::PlannerClient::new(
        crate::AuthorizedPlannerService::new(
            CanonicalFrontierPlanner,
            ExactCanonicalPlannerSupervisor { calls },
            authority.clone(),
        ),
        authority.clone(),
    )
}

struct SupervisorExecutor {
    execution: ExecutionId,
    cancellations: Arc<std::sync::atomic::AtomicUsize>,
}

impl crate::ExecutorService for SupervisorExecutor {
    type Error = &'static str;

    fn submit_attempt(
        &mut self,
        request: &SubmitAttemptRequest,
    ) -> Result<SubmitAttemptResponse, Self::Error> {
        SubmitAttemptResponse::new(
            request,
            SubmitAttemptDisposition::Accepted {
                execution: self.execution,
            },
        )
        .map_err(|_| "response encoding")
    }
}

impl crate::ExecutorStatusService for SupervisorExecutor {
    fn get_attempt_execution(
        &mut self,
        request: &crate::GetAttemptExecutionRequest,
    ) -> Result<crate::GetAttemptExecutionResponse, Self::Error> {
        crate::GetAttemptExecutionResponse::new(
            request,
            crate::GetAttemptExecutionDisposition::Running,
        )
        .map_err(|_| "response encoding")
    }
}

impl crate::ExecutorControlService for SupervisorExecutor {
    fn checkpoint_attempt_execution(
        &mut self,
        request: &crate::CheckpointAttemptExecutionRequest,
    ) -> Result<crate::CheckpointAttemptExecutionResponse, Self::Error> {
        crate::CheckpointAttemptExecutionResponse::new(
            request,
            crate::CheckpointAttemptExecutionDisposition::Requested,
        )
        .map_err(|_| "response encoding")
    }

    fn cancel_attempt_execution(
        &mut self,
        request: &crate::CancelAttemptExecutionRequest,
    ) -> Result<crate::CancelAttemptExecutionResponse, Self::Error> {
        self.cancellations
            .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        crate::CancelAttemptExecutionResponse::new(
            request,
            crate::CancelAttemptExecutionDisposition::Canceled,
        )
        .map_err(|_| "response encoding")
    }
}

impl crate::ExecutorResumeService for SupervisorExecutor {
    fn resume_attempt_execution(
        &mut self,
        request: &crate::ResumeAttemptExecutionRequest,
    ) -> Result<crate::ResumeAttemptExecutionResponse, Self::Error> {
        crate::ResumeAttemptExecutionResponse::new(
            request,
            crate::ResumeAttemptExecutionDisposition::NotCurrent,
        )
        .map_err(|_| "response encoding")
    }
}

#[test]
fn planner_driver_rejects_invalid_static_configuration_without_repository_writes() {
    let (repository, _, _, blobs, planner_authority, _) = authorized_fixture();
    let repository = Arc::new(repository);
    let (engine, artifact, initial_state, budget) = canonical_planner_driver_basis(&repository);
    let before = blobs
        .object_count()
        .expect("object count before validation");
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let wrong_authority = PlannerAuthorityKey::from_bytes([31; 32]).expect("wrong authority");
    assert!(matches!(
        CampaignPlannerDriver::new(
            Arc::clone(&repository),
            canonical_planner_client(&wrong_authority, Arc::clone(&calls)),
            engine.clone(),
            artifact.clone(),
            initial_state.clone(),
            1,
            budget,
        ),
        Err(CampaignPlannerDriverConfigError::AuthorityMismatch)
    ));
    assert!(matches!(
        CampaignPlannerDriver::new(
            Arc::clone(&repository),
            canonical_planner_client(&planner_authority, Arc::clone(&calls)),
            engine.clone(),
            artifact.clone(),
            initial_state.clone(),
            0,
            budget,
        ),
        Err(CampaignPlannerDriverConfigError::InvalidScanLimit)
    ));
    let other_engine =
        PlannerEngine::new("other-planner", 1, 1, BTreeSet::new()).expect("other planner engine");
    let other_state = PlannerState::new(
        other_engine.id().expect("other engine id"),
        "other-state",
        1,
        Vec::new(),
    )
    .expect("other state");
    assert!(matches!(
        CampaignPlannerDriver::new(
            repository,
            canonical_planner_client(&planner_authority, calls),
            engine,
            artifact,
            other_state,
            1,
            budget,
        ),
        Err(CampaignPlannerDriverConfigError::BasisMismatch)
    ));
    assert_eq!(
        blobs.object_count().expect("object count after validation"),
        before
    );
}

#[test]
fn campaign_supervisor_applies_cancel_and_checkpoint_pause_policies_without_planning() {
    let (repository, lineage, policy, _, planner_authority, _) = authorized_fixture();
    let (_, admitted, _) =
        admitted_observation_fixture(&repository, &lineage, &policy, "campaign-supervisor-pause");
    let running = repository
        .apply_control(
            "campaign-supervisor-pause",
            &command(
                "campaign-supervisor-pause-resume",
                admitted.new_snapshot,
                CampaignControlAction::Resume,
            ),
        )
        .expect("resume campaign");
    let repository = Arc::new(repository);
    let planner_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (engine, artifact, initial_state, budget) = canonical_planner_driver_basis(&repository);
    let planner = CampaignPlannerDriver::new(
        Arc::clone(&repository),
        canonical_planner_client(&planner_authority, Arc::clone(&planner_calls)),
        engine,
        artifact,
        initial_state,
        16,
        budget,
    )
    .expect("planner driver");
    let cancellations = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let execution = ExecutionId::from_bytes([0x73; 16]).expect("execution");
    let resources = AttemptResourceLimits::new(1, 256 * 1024 * 1024, 0, 10_000).expect("resources");
    let executor = CampaignExecutorDriver::new(
        Arc::clone(&repository),
        crate::ExecutorClient::new(SupervisorExecutor {
            execution,
            cancellations: Arc::clone(&cancellations),
        }),
        DaemonEpoch::from_bytes([0x74; 16]).expect("daemon epoch"),
        2,
        resources,
        ExecutionRetentionIntent::Discard,
        10_000,
    )
    .expect("executor driver");
    let mut supervisor = CampaignSupervisor::new(
        Arc::clone(&repository),
        crate::CampaignName::new("campaign-supervisor-pause").expect("campaign name"),
        planner,
        executor,
        2,
    )
    .expect("campaign supervisor");

    assert!(matches!(
        supervisor.step().expect("reserve attempt"),
        CampaignSupervisorStepOutcome::Executor {
            outcome:
                CampaignExecutorStepOutcome::Running {
                    attempt,
                    execution: accepted,
                    newly_accepted: true,
                },
            ..
        } if attempt == admitted.attempt && accepted == execution
    ));
    let drain_pause = repository
        .apply_control(
            "campaign-supervisor-pause",
            &command(
                "campaign-supervisor-drain-pause",
                running.new_snapshot,
                CampaignControlAction::Pause(crate::ActiveAttemptPolicy::Drain),
            ),
        )
        .expect("pause to drain");
    assert!(matches!(
        supervisor.step().expect("poll only held drain work"),
        CampaignSupervisorStepOutcome::Executor {
            worker_slot,
            outcome:
                CampaignExecutorStepOutcome::Running {
                    attempt,
                    execution: active,
                    newly_accepted: false,
                },
        } if worker_slot == WorkerSlotId::new(0)
            && attempt == admitted.attempt
            && active == execution
    ));
    assert_eq!(supervisor.reservation_count(), 1);
    assert_eq!(cancellations.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert_eq!(planner_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    let drain_resume = repository
        .apply_control(
            "campaign-supervisor-pause",
            &command(
                "campaign-supervisor-drain-resume",
                drain_pause.new_snapshot,
                CampaignControlAction::Resume,
            ),
        )
        .expect("resume drained campaign");
    let cancel_pause = repository
        .apply_control(
            "campaign-supervisor-pause",
            &command(
                "campaign-supervisor-cancel-pause",
                drain_resume.new_snapshot,
                CampaignControlAction::Pause(crate::ActiveAttemptPolicy::CancelAndRetry),
            ),
        )
        .expect("pause with cancellation");
    assert_eq!(
        supervisor.step().expect("cancel paused execution"),
        CampaignSupervisorStepOutcome::Cancellation(CampaignExecutorCancelOutcome::Canceled {
            attempt: admitted.attempt,
            execution,
            already_canceled: false,
        })
    );
    assert_eq!(supervisor.reservation_count(), 0);
    assert_eq!(cancellations.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(planner_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(matches!(
        supervisor.step().expect("stable paused campaign"),
        CampaignSupervisorStepOutcome::Inactive {
            lifecycle,
            snapshot,
        } if lifecycle.state() == CampaignState::Paused
            && lifecycle.active_attempt_policy()
                == Some(crate::ActiveAttemptPolicy::CancelAndRetry)
            && snapshot == cancel_pause.new_snapshot
    ));

    let resumed = repository
        .apply_control(
            "campaign-supervisor-pause",
            &command(
                "campaign-supervisor-second-resume",
                cancel_pause.new_snapshot,
                CampaignControlAction::Resume,
            ),
        )
        .expect("resume canceled attempt");
    assert!(matches!(
        supervisor.step().expect("reassign canceled attempt"),
        CampaignSupervisorStepOutcome::Executor {
            outcome: CampaignExecutorStepOutcome::Running { attempt, .. },
            ..
        } if attempt == admitted.attempt
    ));
    let _checkpoint_pause = repository
        .apply_control(
            "campaign-supervisor-pause",
            &command(
                "campaign-supervisor-checkpoint-pause",
                resumed.new_snapshot,
                CampaignControlAction::Pause(crate::ActiveAttemptPolicy::ExactCheckpoint),
            ),
        )
        .expect("pause for exact checkpoint");
    assert_eq!(
        supervisor.step().expect("request exact checkpoint"),
        CampaignSupervisorStepOutcome::Checkpoint(CampaignExecutorCheckpointOutcome::Requested {
            attempt: admitted.attempt,
            execution,
            already_requested: false,
        })
    );
    assert_eq!(supervisor.reservation_count(), 1);
    assert_eq!(cancellations.load(std::sync::atomic::Ordering::SeqCst), 1);
    assert_eq!(planner_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
}

#[test]
fn campaign_supervisor_plans_only_after_executor_scan_proves_no_ready_attempt() {
    let (repository, lineage, policy, _, planner_authority, _) = authorized_fixture();
    let created = repository
        .create(
            "campaign-supervisor-planning",
            &lineage,
            &policy,
            &BTreeMap::new(),
        )
        .expect("create campaign");
    repository
        .apply_control(
            "campaign-supervisor-planning",
            &command(
                "campaign-supervisor-planning-resume",
                created.snapshot_id(),
                CampaignControlAction::Resume,
            ),
        )
        .expect("resume campaign");
    let repository = Arc::new(repository);
    let planner_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let (engine, artifact, initial_state, budget) = canonical_planner_driver_basis(&repository);
    let planner = CampaignPlannerDriver::new(
        Arc::clone(&repository),
        canonical_planner_client(&planner_authority, Arc::clone(&planner_calls)),
        engine,
        artifact,
        initial_state,
        16,
        budget,
    )
    .expect("planner driver");
    let resources = AttemptResourceLimits::new(1, 4096, 0, 64).expect("resources");
    let executor = CampaignExecutorDriver::new(
        Arc::clone(&repository),
        crate::ExecutorClient::new(SupervisorExecutor {
            execution: ExecutionId::from_bytes([0x75; 16]).expect("execution"),
            cancellations: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        }),
        DaemonEpoch::from_bytes([0x76; 16]).expect("daemon epoch"),
        1,
        resources,
        ExecutionRetentionIntent::Discard,
        10_000,
    )
    .expect("executor driver");
    let mut supervisor = CampaignSupervisor::new(
        repository,
        crate::CampaignName::new("campaign-supervisor-planning").expect("campaign name"),
        planner,
        executor,
        1,
    )
    .expect("campaign supervisor");

    assert!(matches!(
        supervisor.step().expect("scan executor queue"),
        CampaignSupervisorStepOutcome::Executor {
            outcome: CampaignExecutorStepOutcome::Idle { .. },
            ..
        }
    ));
    assert_eq!(planner_calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    assert!(matches!(
        supervisor.step().expect("plan empty view"),
        CampaignSupervisorStepOutcome::Planner(CampaignPlannerStepOutcome::Advanced {
            disposition: PlannerDisposition::NoWork,
            ..
        })
    ));
    assert_eq!(planner_calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn planner_driver_resumes_an_authenticated_page_cursor_after_restart() {
    let (repository, lineage, policy, _, planner_authority, debugger_authority) =
        authorized_fixture();
    let repository = Arc::new(repository);
    let genesis = repository
        .create_funded(
            "planner-driver-restart",
            &lineage,
            &policy,
            &BTreeMap::new(),
        )
        .expect("create campaign");
    let first_request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "planner-driver-first",
    );
    let first = repository
        .submit_known_branch_request(
            "planner-driver-restart",
            genesis.snapshot_id(),
            &first_request,
        )
        .expect("submit first request");
    let second_request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "planner-driver-second",
    );
    let second = repository
        .submit_known_branch_request(
            "planner-driver-restart",
            first.new_snapshot,
            &second_request,
        )
        .expect("submit second request");
    let running = repository
        .apply_control(
            "planner-driver-restart",
            &command(
                "planner-driver-restart-resume",
                second.new_snapshot,
                CampaignControlAction::Resume,
            ),
        )
        .expect("resume planner campaign");
    let (engine, artifact, initial_state, budget) = canonical_planner_driver_basis(&repository);
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut driver = CampaignPlannerDriver::new(
        Arc::clone(&repository),
        canonical_planner_client(&planner_authority, Arc::clone(&calls)),
        engine.clone(),
        artifact.clone(),
        initial_state.clone(),
        1,
        budget,
    )
    .expect("planner driver");

    let first_advance = driver.step("planner-driver-restart").expect("first page");
    let (continued_snapshot, continued_step, cursor_position) = match first_advance {
        CampaignPlannerStepOutcome::Advanced {
            result,
            disposition: PlannerDisposition::ContinueScan { cursor },
        } => {
            assert_eq!(result.prior_snapshot, running.new_snapshot);
            (
                result.new_snapshot,
                result.step,
                cursor.after().expect("first page cursor"),
            )
        }
        other => panic!("first page must continue, got {other:?}"),
    };
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    drop(driver);

    let restarted = Arc::new(
        CampaignRepository::with_component_authorities(
            repository.blobs.clone(),
            repository.refs.clone(),
            planner_authority.clone(),
            debugger_authority,
        )
        .expect("restart repository"),
    );
    let persisted = restarted
        .load_planner_step_at(continued_snapshot, continued_step)
        .expect("persisted continue step");
    assert_eq!(
        persisted.disposition(),
        &PlannerDisposition::ContinueScan {
            cursor: crate::PlanningScanCursor::new(persisted.input_view(), Some(cursor_position),)
        }
    );
    let mut restarted_driver = CampaignPlannerDriver::new(
        restarted,
        canonical_planner_client(&planner_authority, Arc::clone(&calls)),
        engine,
        artifact,
        initial_state,
        1,
        budget,
    )
    .expect("restarted planner driver");
    let second_advance = restarted_driver
        .step("planner-driver-restart")
        .expect("resume final page");
    match second_advance {
        CampaignPlannerStepOutcome::Advanced {
            result,
            disposition: PlannerDisposition::Issue { selected, .. },
        } => {
            assert_eq!(result.prior_snapshot, continued_snapshot);
            assert_eq!(selected, cursor_position);
        }
        other => panic!("resumed final page must issue, got {other:?}"),
    }
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 2);
}

#[test]
fn planner_driver_does_not_reinvoke_a_terminal_current_view() {
    let (repository, lineage, policy, _, planner_authority, _) = authorized_fixture();
    let repository = Arc::new(repository);
    let created = repository
        .create_funded(
            "planner-driver-settled",
            &lineage,
            &policy,
            &BTreeMap::new(),
        )
        .expect("create empty campaign");
    let (engine, artifact, initial_state, budget) = canonical_planner_driver_basis(&repository);
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut driver = CampaignPlannerDriver::new(
        Arc::clone(&repository),
        canonical_planner_client(&planner_authority, Arc::clone(&calls)),
        engine,
        artifact,
        initial_state,
        16,
        budget,
    )
    .expect("planner driver");

    assert_eq!(
        driver
            .step("planner-driver-settled")
            .expect("created campaign is inactive"),
        CampaignPlannerStepOutcome::Inactive {
            snapshot: created.snapshot_id(),
            state: CampaignState::Created,
        }
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    repository
        .apply_control(
            "planner-driver-settled",
            &command(
                "planner-driver-settled-resume",
                created.snapshot_id(),
                CampaignControlAction::Resume,
            ),
        )
        .expect("resume empty campaign");

    let accepted = driver
        .step("planner-driver-settled")
        .expect("accept no-work step");
    let (settled_snapshot, settled_step) = match accepted {
        CampaignPlannerStepOutcome::Advanced {
            result,
            disposition: PlannerDisposition::NoWork,
        } => (result.new_snapshot, result.step),
        other => panic!("empty view must accept no-work, got {other:?}"),
    };
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);

    assert_eq!(
        driver
            .step("planner-driver-settled")
            .expect("reuse settled view"),
        CampaignPlannerStepOutcome::Settled {
            snapshot: settled_snapshot,
            step: settled_step,
            disposition: PlannerDisposition::NoWork,
        }
    );
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
}

#[test]
fn planner_driver_waits_for_each_allowance_and_resumes_after_a_grant() {
    use crate::CampaignBudgetError;

    let (repository, lineage, policy, _, authority, _) = authorized_fixture();
    let repository = Arc::new(repository);
    let created = repository
        .create("planner-budget", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "budget-branch",
    );
    let requested = repository
        .submit_known_branch_request("planner-budget", created.snapshot_id(), &request)
        .expect("request");
    repository
        .apply_control(
            "planner-budget",
            &command(
                "resume",
                requested.new_snapshot,
                CampaignControlAction::Resume,
            ),
        )
        .expect("resume");
    let (engine, artifact, state, budget) = canonical_planner_driver_basis(&repository);
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let mut driver = CampaignPlannerDriver::new(
        Arc::clone(&repository),
        canonical_planner_client(&authority, Arc::clone(&calls)),
        engine,
        artifact,
        state,
        16,
        budget,
    )
    .expect("driver");

    for (reason, proposals, attempts, command_name) in [
        (
            CampaignBudgetError::ProposalAllowanceExhausted,
            1,
            0,
            "fund-proposals",
        ),
        (
            CampaignBudgetError::AttemptAllowanceExhausted,
            0,
            1,
            "fund-attempts",
        ),
    ] {
        let head = repository.head("planner-budget").expect("head");
        let before = repository
            .budget_projection("planner-budget")
            .expect("budget");
        let expected = CampaignPlannerStepOutcome::BudgetBlocked {
            snapshot: head.snapshot_id(),
            reason,
        };
        assert_eq!(
            driver.step("planner-budget").expect("wait for budget"),
            expected
        );
        let after_call = calls.load(std::sync::atomic::Ordering::SeqCst);
        assert_eq!(
            driver
                .step("planner-budget")
                .expect("wait without invoking"),
            expected
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), after_call);
        assert_eq!(
            repository
                .budget_projection("planner-budget")
                .expect("unchanged budget"),
            before
        );
        repository
            .apply_control(
                "planner-budget",
                &command(
                    command_name,
                    head.snapshot_id(),
                    CampaignControlAction::GrantBudget(
                        BudgetGrant::new(proposals, attempts).expect("grant"),
                    ),
                ),
            )
            .expect("fund campaign");
    }

    assert!(matches!(
        driver.step("planner-budget").expect("funded work resumes"),
        CampaignPlannerStepOutcome::Advanced {
            disposition: PlannerDisposition::Issue { .. },
            ..
        }
    ));
    let budget = repository
        .budget_projection("planner-budget")
        .expect("spent budget");
    assert_eq!((budget.granted_proposals, budget.granted_attempts), (1, 1));
    assert_eq!((budget.spent_proposals, budget.spent_attempts), (1, 1));
    assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 3);
}

struct BlockingPlannerService<S> {
    started: std::sync::mpsc::Sender<()>,
    release: std::sync::mpsc::Receiver<()>,
    inner: S,
}

impl<S: crate::PlannerService> crate::PlannerService for BlockingPlannerService<S> {
    type Error = S::Error;

    fn plan(&mut self, request: &PlannerRequest) -> Result<PlannerResponse, Self::Error> {
        self.started.send(()).expect("observe planner call");
        self.release.recv().expect("release planner call");
        self.inner.plan(request)
    }
}

#[test]
fn planner_driver_releases_repository_mutation_ownership_during_component_work() {
    let (repository, lineage, policy, _, planner_authority, _) = authorized_fixture();
    let repository = Arc::new(repository);
    let genesis = repository
        .create_funded(
            "planner-driver-concurrency",
            &lineage,
            &policy,
            &BTreeMap::new(),
        )
        .expect("create campaign");
    let running = repository
        .apply_control(
            "planner-driver-concurrency",
            &command(
                "planner-driver-concurrency-resume",
                genesis.snapshot_id(),
                CampaignControlAction::Resume,
            ),
        )
        .expect("resume planner campaign");
    let running_snapshot = running.new_snapshot;
    let (engine, artifact, initial_state, budget) = canonical_planner_driver_basis(&repository);
    let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let inner = crate::AuthorizedPlannerService::new(
        CanonicalFrontierPlanner,
        ExactCanonicalPlannerSupervisor { calls },
        planner_authority.clone(),
    );
    let (started_tx, started_rx) = std::sync::mpsc::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let planner = crate::PlannerClient::new(
        BlockingPlannerService {
            started: started_tx,
            release: release_rx,
            inner,
        },
        planner_authority,
    );
    let mut driver = CampaignPlannerDriver::new(
        Arc::clone(&repository),
        planner,
        engine,
        artifact,
        initial_state,
        16,
        budget,
    )
    .expect("planner driver");
    let drive = std::thread::spawn(move || driver.step("planner-driver-concurrency"));
    started_rx
        .recv_timeout(std::time::Duration::from_secs(1))
        .expect("planner component entered");

    let (mutation_tx, mutation_rx) = std::sync::mpsc::channel();
    let mutation_repository = Arc::clone(&repository);
    let mutation = std::thread::spawn(move || {
        let result = mutation_repository.apply_control(
            "planner-driver-concurrency",
            &command(
                "planner-driver-concurrent-pause",
                running_snapshot,
                CampaignControlAction::Pause(crate::ActiveAttemptPolicy::Drain),
            ),
        );
        mutation_tx.send(result).expect("return mutation result");
    });
    let mutation_result = match mutation_rx.recv_timeout(std::time::Duration::from_secs(1)) {
        Ok(result) => result.expect("concurrent mutation"),
        Err(error) => {
            release_tx.send(()).expect("release blocked planner");
            let _ = drive.join();
            mutation.join().expect("mutation thread");
            panic!("repository mutation remained blocked by planner call: {error}");
        }
    };
    release_tx.send(()).expect("release planner");
    mutation.join().expect("mutation thread");
    let drive_result = drive.join().expect("planner driver thread");
    assert!(matches!(
        drive_result,
        Err(CampaignPlannerDriverError::Repository(
            CampaignRepositoryError::Stale { expected, current }
        )) if expected == running_snapshot && current == mutation_result.new_snapshot
    ));
    assert_eq!(
        repository
            .head("planner-driver-concurrency")
            .expect("current head")
            .snapshot_id(),
        mutation_result.new_snapshot
    );
}

#[test]
fn planner_issue_atomically_admits_attempts_and_deduplicates_replay() {
    let (repository, lineage, policy, blobs) = counted_fixture();
    let genesis = repository
        .create_funded("planner-issue", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let source_request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "planner-issue-source",
    );
    let requested = repository
        .submit_known_branch_request("planner-issue", genesis.snapshot_id(), &source_request)
        .expect("submit source request");
    let engine = PlannerEngine::new("closed-rust", 1, 1, BTreeSet::new()).expect("planner engine");
    let initial_state = PlannerState::new(
        engine.id().expect("engine id"),
        "closed-rust-state",
        1,
        vec![0],
    )
    .expect("initial state");
    let (engine, artifact, invocation) = planner_basis(
        &repository,
        "planner-issue",
        requested.new_snapshot,
        initial_state,
    );
    assert!(invocation.scan_page().complete());

    let planner_request = BranchRequest::new(
        source_request.branch_point(),
        source_request.parent(),
        source_request.opportunity(),
        source_request.domain(),
        source_request.source().clone(),
        BranchRequestCause::Planner(invocation.id().expect("invocation id")),
        source_request.budget(),
        source_request.stop().clone(),
    )
    .expect("planner request");
    let first_proposal = Proposal::new(
        source_request.branch_point(),
        source_request.id().expect("source request id"),
        source_request.domain(),
        ChoiceValue::Boolean(false),
        policy.id().expect("policy id"),
        Some(invocation.id().expect("invocation id")),
        1,
        invocation.input_view(),
    )
    .expect("first proposal");
    let first_state = PlannerState::new(
        engine.id().expect("engine id"),
        "closed-rust-state",
        1,
        vec![1],
    )
    .expect("first state");
    let first_usage = PlanningUsage {
        branch_requests: 1,
        proposals: 1,
        input_objects: invocation.scan_page().input_objects(),
        input_bytes: invocation.scan_page().input_bytes(),
        fuel: 3,
    };
    let first_step = PlannerStepProposal::new(
        invocation.id().expect("invocation id"),
        first_state.clone(),
        first_usage,
        GuidanceEvidence::new(BTreeMap::from([("score".to_owned(), 7)])).expect("evidence"),
        PlannerProposalDisposition::Issue {
            selected: PlanningScanPosition::new(
                source_request.branch_point(),
                source_request.id().expect("source request id"),
            ),
            branch_requests: vec![planner_request.clone()],
            proposals: vec![first_proposal.clone()],
        },
    )
    .expect("first issue");
    let skipped_proposal = Proposal::new(
        source_request.branch_point(),
        source_request.id().expect("source request id"),
        source_request.domain(),
        ChoiceValue::Boolean(true),
        policy.id().expect("policy id"),
        Some(invocation.id().expect("invocation id")),
        3,
        invocation.input_view(),
    )
    .expect("skipped proposal");
    let invalid_usage = PlanningUsage {
        branch_requests: 1,
        proposals: 2,
        input_objects: invocation.scan_page().input_objects(),
        input_bytes: invocation.scan_page().input_bytes(),
        fuel: 4,
    };
    let invalid_step = PlannerStepProposal::new(
        invocation.id().expect("invocation id"),
        first_state.clone(),
        invalid_usage,
        GuidanceEvidence::new(BTreeMap::new()).expect("invalid evidence"),
        PlannerProposalDisposition::Issue {
            selected: PlanningScanPosition::new(
                source_request.branch_point(),
                source_request.id().expect("source request id"),
            ),
            branch_requests: vec![planner_request.clone()],
            proposals: vec![first_proposal.clone(), skipped_proposal],
        },
    )
    .expect("structurally valid late-invalid issue");
    let objects_before_rejection = blobs.object_count().expect("count before rejection");
    let rejected = repository.accept_planner_step(
        "planner-issue",
        requested.new_snapshot,
        &invalid_step,
        invalid_usage,
    );
    assert!(
        matches!(
            rejected,
            Err(CampaignRepositoryError::Codec(
                CampaignCodecError::InvalidValue {
                    reason: "proposal disagrees with its request, source, domain, or budget"
                }
            ))
        ),
        "unexpected preflight result: {rejected:?}"
    );
    assert_eq!(
        blobs.object_count().expect("count after rejection"),
        objects_before_rejection,
        "semantic preflight must reject the complete batch before publication"
    );

    let wrong_engine =
        PlannerEngine::new("wrong-engine", 1, 1, BTreeSet::new()).expect("wrong engine");
    repository
        .put_planner_engine(&wrong_engine)
        .expect("publish wrong engine");
    let wrong_state = PlannerState::new(
        wrong_engine.id().expect("wrong engine id"),
        "wrong-engine-state",
        1,
        vec![1],
    )
    .expect("wrong-engine state");
    let wrong_state_step = PlannerStepProposal::new(
        invocation.id().expect("invocation id"),
        wrong_state,
        first_usage,
        GuidanceEvidence::new(BTreeMap::new()).expect("wrong-state evidence"),
        PlannerProposalDisposition::Issue {
            selected: PlanningScanPosition::new(
                source_request.branch_point(),
                source_request.id().expect("source request id"),
            ),
            branch_requests: vec![planner_request.clone()],
            proposals: vec![first_proposal.clone()],
        },
    )
    .expect("wrong-state issue");
    let objects_before_wrong_state = blobs.object_count().expect("count before wrong state");
    assert!(matches!(
        repository.accept_planner_step(
            "planner-issue",
            requested.new_snapshot,
            &wrong_state_step,
            first_usage,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-step-next-state-engine-mismatch"
        })
    ));
    assert_eq!(
        blobs.object_count().expect("count after wrong state"),
        objects_before_wrong_state,
        "complete Issue preflight must validate next-state continuity before publication"
    );

    let first = repository
        .accept_planner_step(
            "planner-issue",
            requested.new_snapshot,
            &first_step,
            first_usage,
        )
        .expect("accept first issue");
    assert!(matches!(
        repository.load_planner_step(first.step),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-issue-requires-snapshot-owner"
        })
    ));
    let accepted_first = repository
        .load_planner_step_at(first.new_snapshot, first.step)
        .expect("load first issue");
    assert_eq!(accepted_first.accounting().branch_requests, 1);
    assert_eq!(accepted_first.accounting().proposals, 1);
    assert_eq!(accepted_first.accounting().attempts, 1);
    assert_eq!(accepted_first.accounting().deduplicated, 0);
    assert_eq!(
        accepted_first.issued_branch_requests(),
        [planner_request.id().expect("planner request id")]
    );
    assert_eq!(
        accepted_first.issued_proposals(),
        [first_proposal.id().expect("first proposal id")]
    );
    repository
        .load_proposal(first_proposal.id().expect("first proposal id"))
        .expect("load first proposal");

    let first_head = repository.head("planner-issue").expect("first issue head");
    let mut forged_roots = first_head.snapshot().roots();
    forged_roots.accounting = repository
        .merkle
        .insert(
            forged_roots.accounting,
            CampaignHash::derive("test", b"extra planner issue accounting"),
            first.step.content_id(),
        )
        .expect("forged accounting root")
        .content_id();
    let forged = CampaignSnapshot::successor(
        requested.new_snapshot,
        first_head.snapshot().lineage(),
        first_head.snapshot().active_policy(),
        forged_roots,
        first_head
            .snapshot()
            .transition()
            .expect("first issue transition"),
    )
    .expect("forged issue successor");
    let forged_content = repository
        .put_snapshot(&forged)
        .expect("put forged issue successor");
    let objects_before_validation = blobs.object_count().expect("count objects before import");
    assert!(matches!(
        repository.validate_complete_head(forged_content),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-issue-root-delta-mismatch"
        })
    ));
    assert_eq!(
        blobs.object_count().expect("count objects after import"),
        objects_before_validation,
        "invalid imported projection validation must be read-only"
    );

    let (_, _, second_invocation) = planner_basis(
        &repository,
        "planner-issue",
        first.new_snapshot,
        first_state.clone(),
    );
    let ancestry_usage = PlanningUsage {
        branch_requests: 0,
        proposals: 0,
        input_objects: second_invocation.scan_page().input_objects(),
        input_bytes: second_invocation.scan_page().input_bytes(),
        fuel: 1,
    };
    let ancestry_request = repository
        .build_planner_request(first.new_snapshot, second_invocation.id().expect("id"))
        .expect("ancestry request");
    repository
        .put_planner_request(&ancestry_request)
        .expect("put ancestry request");
    let ancestry_child = PlannerStep::new(
        Some(first.step),
        second_invocation.id().expect("second invocation id"),
        ancestry_request.id().expect("ancestry request id"),
        ancestry_request.request_digest(),
        second_invocation.policy(),
        second_invocation.engine(),
        second_invocation.policy_artifact(),
        second_invocation.input_view(),
        PlannerDisposition::NoWork,
        first_state.id().expect("first state id"),
        ancestry_usage,
        PlanningAccounting {
            branch_requests: 0,
            proposals: 0,
            attempts: 0,
            deduplicated: 0,
            input_objects: ancestry_usage.input_objects,
            input_bytes: ancestry_usage.input_bytes,
            fuel: ancestry_usage.fuel,
        },
        GuidanceEvidence::new(BTreeMap::new()).expect("ancestry evidence"),
    )
    .expect("non-issue ancestry child");
    let ancestry_child_content = repository
        .put_planner_step(&ancestry_child)
        .expect("put non-issue ancestry child");
    assert!(matches!(
        repository.load_planner_step(
            PlannerStepId::from_content_id(ancestry_child_content).expect("ancestry child id")
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-issue-requires-snapshot-owner"
        })
    ));

    let second_proposal = Proposal::new(
        planner_request.branch_point(),
        planner_request.id().expect("planner request id"),
        planner_request.domain(),
        ChoiceValue::Boolean(false),
        policy.id().expect("policy id"),
        Some(second_invocation.id().expect("second invocation id")),
        1,
        second_invocation.input_view(),
    )
    .expect("second proposal");
    let second_usage = PlanningUsage {
        branch_requests: 0,
        proposals: 1,
        input_objects: second_invocation.scan_page().input_objects(),
        input_bytes: second_invocation.scan_page().input_bytes(),
        fuel: 3,
    };
    let second_step = PlannerStepProposal::new(
        second_invocation.id().expect("second invocation id"),
        PlannerState::new(
            engine.id().expect("engine id"),
            "closed-rust-state",
            1,
            vec![2],
        )
        .expect("second state"),
        second_usage,
        GuidanceEvidence::new(BTreeMap::from([("score".to_owned(), 7)])).expect("evidence"),
        PlannerProposalDisposition::Issue {
            selected: PlanningScanPosition::new(
                planner_request.branch_point(),
                planner_request.id().expect("planner request id"),
            ),
            branch_requests: Vec::new(),
            proposals: vec![second_proposal],
        },
    )
    .expect("second issue");
    let second = repository
        .accept_planner_step(
            "planner-issue",
            first.new_snapshot,
            &second_step,
            second_usage,
        )
        .expect("accept deduplicated issue");
    let accepted_second = repository
        .load_planner_step_at(second.new_snapshot, second.step)
        .expect("load second issue");
    assert_eq!(accepted_second.accounting().attempts, 0);
    assert_eq!(accepted_second.accounting().deduplicated, 1);

    let replay = repository
        .accept_planner_step(
            "planner-issue",
            requested.new_snapshot,
            &first_step,
            first_usage,
        )
        .expect("replay first issue");
    assert!(replay.replayed);
    assert_eq!(replay.step, first.step);
    assert_eq!(replay.new_snapshot, first.new_snapshot);
    assert_eq!(artifact.engine(), engine.id().expect("engine id"));
}

#[test]
fn planner_issue_uses_the_canonical_authenticated_path_after_convergence() {
    let (repository, lineage, policy) = fixture();
    let (_, first_admitted, first_observation) =
        admitted_observation_fixture(&repository, &lineage, &policy, "planner-nested-path");
    let first_observed = repository
        .publish_observation(
            "planner-nested-path",
            first_admitted.new_snapshot,
            &first_observation,
        )
        .expect("publish first convergent observation");

    let first_proposal = repository
        .read_proposal(first_admitted.proposal.content_id())
        .expect("first proposal");
    let source_request = repository
        .read_branch_request(first_proposal.request().content_id())
        .expect("source request");
    let first_path = repository
        .read_branch_path(first_observation.path().content_id())
        .expect("first path");
    let second_proposal = finite_proposal(
        &source_request,
        &policy,
        &repository
            .head("planner-nested-path")
            .expect("first observation head"),
        ChoiceValue::Boolean(true),
        2,
    );
    let second_proposed = repository
        .issue_proposal(
            "planner-nested-path",
            first_observed.new_snapshot,
            &second_proposal,
        )
        .expect("issue second convergent proposal");
    let (second_selection, second_path, second_attempt) =
        branch_attempt(&repository, &source_request, &second_proposal);
    let second_admitted = repository
        .admit_proposal(
            "planner-nested-path",
            second_proposed.new_snapshot,
            second_proposed.proposal,
            &second_selection,
            &second_path,
            &second_attempt,
        )
        .expect("admit second convergent attempt");
    let second_observation = Observation::new(
        second_admitted.attempt,
        first_observation.child(),
        first_observation.child_content(),
        second_path.id().expect("second path id"),
        first_observation.stop().clone(),
        first_observation.measurements(),
        first_observation.properties(),
        first_observation.coverage(),
        first_observation.discovered_choices().clone(),
    )
    .expect("second convergent observation");
    let second_observed = repository
        .publish_observation(
            "planner-nested-path",
            second_admitted.new_snapshot,
            &second_observation,
        )
        .expect("publish second convergent observation");

    let opportunity_id = *first_observation
        .discovered_choices()
        .first()
        .expect("nested opportunity id");
    let opportunity = repository
        .load_choice_opportunity(opportunity_id)
        .expect("nested opportunity");
    let domain = repository
        .load_choice_domain(opportunity.domain())
        .expect("nested domain");
    let branch_point = opportunity.branch_point_id(first_observation.child());
    let nested_request = BranchRequest::new(
        branch_point,
        first_observation.child_content(),
        opportunity_id,
        opportunity.domain(),
        CandidateSource::finite(BTreeSet::from([
            ChoiceValue::Boolean(false),
            ChoiceValue::Boolean(true),
        ]))
        .expect("nested finite source"),
        BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(CampaignHash::derive(
            "test.planner-nested-path",
            b"nested request",
        ))),
        BranchBudget::new(2, 2).expect("nested branch budget"),
        StopCondition::NextChoice,
    )
    .expect("nested request");
    let nested_requested = repository
        .submit_known_branch_request(
            "planner-nested-path",
            second_observed.new_snapshot,
            &nested_request,
        )
        .expect("submit nested request");

    let engine = PlannerEngine::new("closed-rust", 1, 1, BTreeSet::new()).expect("planner engine");
    let initial_state = PlannerState::new(
        engine.id().expect("engine id"),
        "closed-rust-state",
        1,
        vec![0],
    )
    .expect("planner state");
    let (_, _, invocation) = planner_basis(
        &repository,
        "planner-nested-path",
        nested_requested.new_snapshot,
        initial_state,
    );
    let proposal = Proposal::new(
        branch_point,
        nested_request.id().expect("nested request id"),
        nested_request.domain(),
        ChoiceValue::Boolean(false),
        policy.id().expect("policy id"),
        Some(invocation.id().expect("invocation id")),
        1,
        invocation.input_view(),
    )
    .expect("nested proposal");
    let usage = PlanningUsage {
        branch_requests: 0,
        proposals: 1,
        input_objects: invocation.scan_page().input_objects(),
        input_bytes: invocation.scan_page().input_bytes(),
        fuel: 3,
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
        GuidanceEvidence::new(BTreeMap::new()).expect("guidance evidence"),
        PlannerProposalDisposition::Issue {
            selected: PlanningScanPosition::new(
                branch_point,
                nested_request.id().expect("nested request id"),
            ),
            branch_requests: Vec::new(),
            proposals: vec![proposal.clone()],
        },
    )
    .expect("nested planner issue");
    let accepted = repository
        .accept_planner_step(
            "planner-nested-path",
            nested_requested.new_snapshot,
            &step,
            usage,
        )
        .expect("accept nested planner issue");

    let accepted_snapshot = repository
        .read_snapshot(accepted.new_snapshot.content_id())
        .expect("accepted nested snapshot");
    let admission_content = repository
        .merkle
        .get(
            accepted_snapshot.snapshot.roots().accounting,
            map_key_content(
                "accounting.proposal-admission",
                proposal.id().expect("proposal id").content_id(),
            ),
        )
        .expect("proposal admission lookup")
        .expect("proposal admission");
    let admission = repository
        .read_attempt_admission(admission_content)
        .expect("nested attempt admission");
    let attempt = repository
        .read_attempt(admission.attempt().content_id())
        .expect("nested attempt");
    let path = repository
        .read_branch_path(attempt.path().content_id())
        .expect("nested cumulative path");
    let canonical_parent = [first_path, second_path]
        .into_iter()
        .min_by_key(|path| path_index_order_key(path.id().expect("candidate path id")))
        .expect("canonical parent path");
    let selection = Selection::new_campaign_branch(
        &opportunity,
        &domain,
        proposal.value().clone(),
        branch_point,
    )
    .expect("nested selection");
    let crate::SelectionOrigin::CampaignBranch { edge, .. } = selection.origin() else {
        panic!("nested campaign selection")
    };
    let mut expected_segments = canonical_parent
        .segments()
        .expect("scoped canonical parent")
        .to_vec();
    expected_segments.push(crate::BranchPathSegment::new(branch_point, edge));
    assert_eq!(path.segments(), Some(expected_segments.as_slice()));

    let restarted = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    restarted
        .validate_complete_head(accepted.new_snapshot.content_id())
        .expect("restart-valid nested planner issue");
    let replay = restarted
        .accept_planner_step(
            "planner-nested-path",
            nested_requested.new_snapshot,
            &step,
            usage,
        )
        .expect("replay nested planner issue");
    assert!(replay.replayed);
    assert_eq!(replay.new_snapshot, accepted.new_snapshot);
}

#[test]
fn planner_issue_rejects_a_legacy_parent_path_before_publication() {
    let (repository, lineage, policy, blobs) = counted_fixture();
    let genesis = repository
        .create_funded("planner-legacy-path", &lineage, &policy, &BTreeMap::new())
        .expect("create legacy-path campaign");
    let source_request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "planner-legacy-path-source",
    );
    let requested = repository
        .submit_known_branch_request(
            "planner-legacy-path",
            genesis.snapshot_id(),
            &source_request,
        )
        .expect("submit legacy-path source");
    let source_proposal = finite_proposal(
        &source_request,
        &policy,
        &repository
            .head("planner-legacy-path")
            .expect("source request head"),
        ChoiceValue::Boolean(false),
        1,
    );
    let proposed = repository
        .issue_proposal(
            "planner-legacy-path",
            requested.new_snapshot,
            &source_proposal,
        )
        .expect("issue legacy-path proposal");
    let (selection, _, _) = branch_attempt(&repository, &source_request, &source_proposal);
    let crate::SelectionOrigin::CampaignBranch { edge, .. } = selection.origin() else {
        panic!("campaign branch selection")
    };
    let mut legacy_encoder = crate::codec::Encoder::new();
    crate::codec::Canonical::encode(&1_u32, &mut legacy_encoder);
    crate::codec::Canonical::encode(&vec![edge], &mut legacy_encoder);
    let legacy_path =
        BranchPath::from_canonical_bytes(&legacy_encoder.finish()).expect("legacy branch path");
    assert!(legacy_path.segments().is_none());
    let legacy_attempt = Attempt::new(
        AttemptStart::Branch {
            edge,
            parent: source_request.parent(),
            selection: selection.id().expect("selection id"),
        },
        legacy_path.id().expect("legacy path id"),
        source_request.stop().clone(),
    )
    .expect("legacy-path attempt");
    let admitted = repository
        .admit_proposal(
            "planner-legacy-path",
            proposed.new_snapshot,
            proposed.proposal,
            &selection,
            &legacy_path,
            &legacy_attempt,
        )
        .expect("admit legacy genesis path");

    let child =
        ConfigurationId::from_hash(CampaignHash::derive("test.planner-legacy-path", b"child"));
    let child_content = repository
        .publish_configuration_artifact(
            lineage.scenario(),
            lineage.scenario_content(),
            child,
            1,
            b"planner legacy path child".to_vec(),
        )
        .expect("publish child");
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
    let observation = Observation::new(
        admitted.attempt,
        child,
        child_content,
        legacy_path.id().expect("legacy path id"),
        StopOutcome::Reached(StopCondition::NextChoice),
        measurements,
        properties,
        coverage,
        BTreeSet::from([source_request.opportunity()]),
    )
    .expect("legacy-path observation");
    let observed = repository
        .publish_observation("planner-legacy-path", admitted.new_snapshot, &observation)
        .expect("publish legacy-path observation");

    let opportunity = repository
        .load_choice_opportunity(source_request.opportunity())
        .expect("nested opportunity");
    let branch_point = opportunity.branch_point_id(child);
    let nested_request = BranchRequest::new(
        branch_point,
        child_content,
        source_request.opportunity(),
        source_request.domain(),
        source_request.source().clone(),
        BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(CampaignHash::derive(
            "test.planner-legacy-path",
            b"nested request",
        ))),
        source_request.budget(),
        source_request.stop().clone(),
    )
    .expect("nested request");
    let nested_requested = repository
        .submit_known_branch_request(
            "planner-legacy-path",
            observed.new_snapshot,
            &nested_request,
        )
        .expect("submit nested request");
    let engine = PlannerEngine::new("closed-rust", 1, 1, BTreeSet::new()).expect("planner engine");
    let (_, _, invocation) = planner_basis(
        &repository,
        "planner-legacy-path",
        nested_requested.new_snapshot,
        PlannerState::new(
            engine.id().expect("engine id"),
            "closed-rust-state",
            1,
            vec![0],
        )
        .expect("planner state"),
    );
    let nested_proposal = Proposal::new(
        branch_point,
        nested_request.id().expect("nested request id"),
        nested_request.domain(),
        ChoiceValue::Boolean(false),
        policy.id().expect("policy id"),
        Some(invocation.id().expect("invocation id")),
        1,
        invocation.input_view(),
    )
    .expect("nested proposal");
    let usage = PlanningUsage {
        branch_requests: 0,
        proposals: 1,
        input_objects: invocation.scan_page().input_objects(),
        input_bytes: invocation.scan_page().input_bytes(),
        fuel: 3,
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
        GuidanceEvidence::new(BTreeMap::new()).expect("guidance evidence"),
        PlannerProposalDisposition::Issue {
            selected: PlanningScanPosition::new(
                branch_point,
                nested_request.id().expect("nested request id"),
            ),
            branch_requests: Vec::new(),
            proposals: vec![nested_proposal],
        },
    )
    .expect("legacy-parent planner issue");
    let before = blobs.object_count().expect("object count before rejection");
    assert!(matches!(
        repository.accept_planner_step(
            "planner-legacy-path",
            nested_requested.new_snapshot,
            &step,
            usage,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-issue-parent-path-is-legacy"
        })
    ));
    assert_eq!(
        blobs.object_count().expect("object count after rejection"),
        before
    );
    assert_eq!(
        repository
            .head("planner-legacy-path")
            .expect("head after rejection")
            .snapshot_id(),
        nested_requested.new_snapshot
    );
}

#[test]
fn planner_cursor_and_imported_root_fail_closed() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create_funded("planner-forgery", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let engine = PlannerEngine::new("closed-rust", 1, 1, BTreeSet::new()).expect("planner engine");
    let initial_state = PlannerState::new(
        engine.id().expect("engine id"),
        "closed-rust-state",
        1,
        vec![0],
    )
    .expect("initial state");
    let (engine, _, invocation) = planner_basis(
        &repository,
        "planner-forgery",
        genesis.snapshot_id(),
        initial_state,
    );
    let fabricated_source = BranchRequestId::from_content_id(ContentId::for_bytes(
        ObjectKind::CampaignFact,
        1,
        b"fabricated planner cursor",
    ))
    .expect("fabricated source");
    let cursor_proposal = PlannerStepProposal::new(
        invocation.id().expect("invocation id"),
        PlannerState::new(
            engine.id().expect("engine id"),
            "closed-rust-state",
            1,
            vec![1],
        )
        .expect("next state"),
        PlanningUsage {
            branch_requests: 0,
            proposals: 0,
            input_objects: 1,
            input_bytes: 1,
            fuel: 1,
        },
        GuidanceEvidence::new(BTreeMap::new()).expect("cursor evidence"),
        PlannerProposalDisposition::ContinueScan {
            cursor: crate::PlanningScanCursor::new(
                invocation.input_view(),
                Some(crate::PlanningScanPosition::new(
                    crate::BranchPointId::from_hash(CampaignHash::derive(
                        "test",
                        b"fabricated branch point",
                    )),
                    fabricated_source,
                )),
            ),
        },
    )
    .expect("cursor proposal");
    let measured = PlanningUsage {
        branch_requests: 0,
        proposals: 0,
        input_objects: 0,
        input_bytes: 0,
        fuel: 1,
    };
    assert!(matches!(
        repository.accept_planner_step(
            "planner-forgery",
            genesis.snapshot_id(),
            &cursor_proposal,
            measured,
        ),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-step-scan-cursor-is-not-authoritative"
        })
    ));

    let accepted_proposal = no_work_proposal(
        invocation.id().expect("invocation id"),
        cursor_proposal.next_state().clone(),
    );
    let accepted = repository
        .accept_planner_step(
            "planner-forgery",
            genesis.snapshot_id(),
            &accepted_proposal,
            measured,
        )
        .expect("accept no-work step");
    let accepted_head = repository.head("planner-forgery").expect("accepted head");
    let extra_key = CampaignHash::derive("test", b"forged planner index");
    let forged_coordination = repository
        .merkle
        .insert(
            accepted_head.snapshot().roots().coordination,
            extra_key,
            accepted.step.content_id(),
        )
        .expect("forged root")
        .content_id();
    let mut forged_roots = accepted_head.snapshot().roots();
    forged_roots.coordination = forged_coordination;
    let transition = repository
        .put_fact(&CampaignFact::PlannerAdvanced(accepted.step))
        .expect("planner fact");
    let forged = CampaignSnapshot::successor(
        genesis.snapshot_id(),
        genesis.snapshot().lineage(),
        genesis.snapshot().active_policy(),
        forged_roots,
        CampaignFactId::from_content_id(transition).expect("fact id"),
    )
    .expect("forged snapshot");
    let forged_content = repository
        .put_snapshot(&forged)
        .expect("put forged snapshot");
    assert!(matches!(
        repository.validate_complete_head(forged_content),
        Err(CampaignRepositoryError::Integrity {
            reason: "planner-step-transition-coordination-root-mismatch"
        })
    ));
}
