//! Canonical grant counting, paging, exact arithmetic, and restart regressions.

use super::*;

#[test]
fn budget_projection_counts_distinct_commands_not_auxiliary_facts_or_retries() {
    let (repository, lineage, policy) = fixture();
    repository
        .create("budget", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    for index in 0..140 {
        let head = repository.head("budget").expect("head");
        let request = command(
            &format!("grant-{index}"),
            head.snapshot_id(),
            CampaignControlAction::GrantBudget(BudgetGrant::new(3, 2).expect("grant")),
        );
        repository.apply_control("budget", &request).expect("grant");
        repository
            .apply_control("budget", &request)
            .expect("idempotent retry");
    }
    let head = repository.head("budget").expect("head");
    let projection = repository.budget_projection("budget").expect("projection");
    assert_eq!(projection.snapshot, head.snapshot_id());
    assert_eq!(projection.granted_proposals, 420);
    assert_eq!(projection.granted_attempts, 280);
    assert_eq!(projection.spent_proposals, 0);
    assert_eq!(projection.spent_attempts, 0);
    assert_eq!(projection.remaining_proposals(), 420);
    assert_eq!(projection.remaining_attempts(), 280);
    assert_eq!(
        repository.head("budget").expect("unchanged").snapshot_id(),
        head.snapshot_id()
    );

    let cold = CampaignRepository::new(Arc::clone(&repository.blobs), Arc::clone(&repository.refs));
    assert_eq!(
        cold.budget_projection("budget").expect("cold projection"),
        projection
    );
}

#[test]
fn budget_projection_adds_u64_grants_without_wrapping_or_saturating() {
    let (repository, lineage, policy) = fixture();
    repository
        .create("budget", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    for name in ["first", "second"] {
        let head = repository.head("budget").expect("head");
        repository
            .apply_control(
                "budget",
                &command(
                    name,
                    head.snapshot_id(),
                    CampaignControlAction::GrantBudget(
                        BudgetGrant::new(u64::MAX, u64::MAX).expect("grant"),
                    ),
                ),
            )
            .expect("grant");
    }
    let projection = repository.budget_projection("budget").expect("projection");
    assert_eq!(projection.granted_attempts, u128::from(u64::MAX) * 2);
    assert_eq!(projection.granted_proposals, u128::from(u64::MAX) * 2);
}

#[test]
fn budget_projection_counts_accepted_work_once_across_auxiliary_indexes() {
    let (repository, lineage, policy) = fixture();
    admitted_observation_fixture(&repository, &lineage, &policy, "budget");
    let projection = repository.budget_projection("budget").expect("projection");
    assert_eq!(projection.granted_attempts, 1_000_000);
    assert_eq!(projection.granted_proposals, 1_000_000);
    assert_eq!(projection.spent_attempts, 1);
    assert_eq!(projection.spent_proposals, 1);
    assert_eq!(projection.remaining_attempts(), 999_999);
    assert_eq!(projection.remaining_proposals(), 999_999);
}

#[test]
fn request_attempt_page_authenticates_cursor_and_empty_tail() {
    let (repository, lineage, policy) = fixture();
    let (_, admitted, _) =
        admitted_observation_fixture(&repository, &lineage, &policy, "attempt-page");
    let request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "attempt-page",
    );
    let request_id = request.id().expect("request ID");
    let head = repository
        .head("attempt-page")
        .expect("head before second proposal");
    let second_proposal = finite_proposal(&request, &policy, &head, ChoiceValue::Boolean(true), 2);
    let issued = repository
        .issue_proposal("attempt-page", head.snapshot_id(), &second_proposal)
        .expect("issue second proposal");
    let (selection, path, attempt) = branch_attempt(&repository, &request, &second_proposal);
    let second = repository
        .admit_proposal(
            "attempt-page",
            issued.new_snapshot,
            issued.proposal,
            &selection,
            &path,
            &attempt,
        )
        .expect("admit second attempt");
    let head = repository.head("attempt-page").expect("head");
    let snapshot = head.snapshot_id();
    let ledger = repository
        .read_budget_ledger(head.snapshot().budget_ledger())
        .expect("budget ledger");
    let principal = crate::CampaignPrincipal::new("operator:alice").expect("principal");
    let campaign = crate::CampaignName::new("attempt-page").expect("campaign");
    let query = crate::QueryCampaignRequestAttemptsRequest::new(
        principal.clone(),
        campaign.clone(),
        snapshot,
        request_id,
        None,
        1,
    )
    .expect("query");
    let (entries, next, index_proof, page_proof) = repository
        .scan_request_attempt_page(ledger, request_id, None, 1)
        .expect("indexed page");
    assert_eq!(entries.len(), 1);
    let first_proposal = entries[0].0.id().expect("first proposal ID");
    assert!(next.is_some());
    let response = crate::QueryCampaignRequestAttemptsResponse::new(
        &query,
        head.snapshot().clone(),
        ledger,
        entries,
        next,
        index_proof,
        page_proof,
    )
    .expect("proved page");
    let decoded = crate::QueryCampaignRequestAttemptsResponse::from_canonical_bytes(
        &response.canonical_bytes(),
    )
    .expect("canonical response");
    decoded.validate_for(&query).expect("authenticated page");

    let second_query = crate::QueryCampaignRequestAttemptsRequest::new(
        principal.clone(),
        campaign.clone(),
        snapshot,
        request_id,
        next,
        1,
    )
    .expect("second page query");
    assert!(decoded.validate_for(&second_query).is_err());
    let (entries, next, index_proof, page_proof) = repository
        .scan_request_attempt_page(ledger, request_id, Some(first_proposal), 1)
        .expect("second page");
    assert_eq!(entries.len(), 1);
    let last_proposal = entries[0].0.id().expect("last proposal ID");
    assert_eq!(
        BTreeSet::from([first_proposal, last_proposal]),
        BTreeSet::from([admitted.proposal, second.proposal])
    );
    assert!(next.is_none());
    crate::QueryCampaignRequestAttemptsResponse::new(
        &second_query,
        head.snapshot().clone(),
        ledger,
        entries,
        next,
        index_proof,
        page_proof,
    )
    .expect("proved second page");

    let tail = crate::QueryCampaignRequestAttemptsRequest::new(
        principal,
        campaign,
        snapshot,
        request_id,
        Some(last_proposal),
        1,
    )
    .expect("tail query");
    let (entries, next, index_proof, page_proof) = repository
        .scan_request_attempt_page(ledger, request_id, Some(last_proposal), 1)
        .expect("empty tail");
    assert!(entries.is_empty());
    assert!(next.is_none());
    crate::QueryCampaignRequestAttemptsResponse::new(
        &tail,
        head.snapshot().clone(),
        ledger,
        entries,
        next,
        index_proof,
        page_proof,
    )
    .expect("proved empty tail");
}

#[test]
fn request_admission_pages_include_convergent_causes_and_reject_wrong_proofs() {
    let (repository, lineage, policy) = fixture();
    let campaign = "request-causes";
    let genesis = repository
        .create_funded(campaign, &lineage, &policy, &BTreeMap::new())
        .expect("create funded campaign");
    let basis_request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        campaign,
    );
    repository
        .submit_known_branch_request(campaign, genesis.snapshot_id(), &basis_request)
        .expect("submit basis request");

    let mut basis_admissions = Vec::new();
    for (ordinal, value) in [(1, false), (2, true)] {
        let head = repository.head(campaign).expect("head");
        let proposal = finite_proposal(
            &basis_request,
            &policy,
            &head,
            ChoiceValue::Boolean(value),
            ordinal,
        );
        let issued = repository
            .issue_proposal(campaign, head.snapshot_id(), &proposal)
            .expect("issue basis proposal");
        let (selection, path, attempt) = branch_attempt(&repository, &basis_request, &proposal);
        let admitted = repository
            .admit_proposal(
                campaign,
                issued.new_snapshot,
                issued.proposal,
                &selection,
                &path,
                &attempt,
            )
            .expect("admit basis proposal");
        basis_admissions.push(admitted);
    }
    let basis_id = basis_request.id().expect("basis request ID");
    let prior_head = repository.head(campaign).expect("basis head");
    let prior_ledger = repository
        .read_budget_ledger(prior_head.snapshot().budget_ledger())
        .expect("basis ledger");
    let (_, _, stale_index_proof, _) = repository
        .scan_request_attempt_page(prior_ledger, basis_id, None, 1)
        .expect("basis proof before convergence");

    let convergent_request = BranchRequest::new(
        BranchRequest::identity(
            basis_request.branch_point(),
            basis_request.parent(),
            basis_request.opportunity(),
            basis_request.domain(),
        ),
        CandidateSource::finite(BTreeSet::from([ChoiceValue::Boolean(false)]))
            .expect("convergent source"),
        BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(CampaignHash::derive(
            "test.request-causes",
            b"additional-cause",
        ))),
        BranchBudget::new(1, 1).expect("convergent budget"),
        basis_request.stop().clone(),
    )
    .expect("convergent request");
    let head = repository.head(campaign).expect("head");
    repository
        .submit_known_branch_request(campaign, head.snapshot_id(), &convergent_request)
        .expect("submit convergent request");
    let head = repository.head(campaign).expect("head");
    let proposal = finite_proposal(
        &convergent_request,
        &policy,
        &head,
        ChoiceValue::Boolean(false),
        1,
    );
    let issued = repository
        .issue_proposal(campaign, head.snapshot_id(), &proposal)
        .expect("issue convergent proposal");
    let (selection, path, attempt) = branch_attempt(&repository, &convergent_request, &proposal);
    let additional = repository
        .admit_proposal(
            campaign,
            issued.new_snapshot,
            issued.proposal,
            &selection,
            &path,
            &attempt,
        )
        .expect("admit additional cause");
    assert_eq!(additional.attempt, basis_admissions[0].attempt);
    let replay = repository
        .admit_proposal(
            campaign,
            issued.new_snapshot,
            issued.proposal,
            &selection,
            &path,
            &attempt,
        )
        .expect("replay convergent admission");
    assert!(replay.replayed);
    assert_eq!(replay.admission, additional.admission);

    let head = repository.head(campaign).expect("final head");
    let snapshot = head.snapshot_id();
    let ledger = repository
        .read_budget_ledger(head.snapshot().budget_ledger())
        .expect("ledger");
    let principal = crate::CampaignPrincipal::new("operator:alice").expect("principal");
    let name = crate::CampaignName::new(campaign).expect("campaign name");
    let basis_request_id = basis_id;
    let query = crate::QueryCampaignRequestAttemptsRequest::new(
        principal.clone(),
        name.clone(),
        snapshot,
        basis_request_id,
        None,
        1,
    )
    .expect("first page request");
    let (first_entries, first_next, first_index, first_proof) = repository
        .scan_request_attempt_page(ledger, basis_request_id, None, 1)
        .expect("first page");
    assert_eq!(first_entries.len(), 1);
    assert!(first_next.is_some());
    let first_response = crate::QueryCampaignRequestAttemptsResponse::new(
        &query,
        head.snapshot().clone(),
        ledger,
        first_entries,
        first_next,
        first_index,
        first_proof.clone(),
    )
    .expect("authenticated first page");
    first_response
        .validate_for(&query)
        .expect("first page proof");

    let cursor = first_response.next_after().expect("next proposal cursor");
    let second_query = crate::QueryCampaignRequestAttemptsRequest::new(
        principal.clone(),
        name.clone(),
        snapshot,
        basis_request_id,
        Some(cursor),
        1,
    )
    .expect("second page request");
    let (second_entries, second_next, second_index, second_proof) = repository
        .scan_request_attempt_page(ledger, basis_request_id, Some(cursor), 1)
        .expect("second page");
    assert_eq!(second_entries.len(), 1);
    assert!(second_next.is_none());
    crate::QueryCampaignRequestAttemptsResponse::new(
        &second_query,
        head.snapshot().clone(),
        ledger,
        second_entries,
        second_next,
        second_index,
        second_proof,
    )
    .expect("authenticated second page");

    let convergent_id = convergent_request.id().expect("convergent request ID");
    assert_eq!(ledger.spent_attempts(), 2);
    assert_eq!(
        repository
            .indexed_request_execution_bases(ledger, convergent_id)
            .expect("convergent request spending"),
        0
    );
    let convergent_query = crate::QueryCampaignRequestAttemptsRequest::new(
        principal,
        name,
        snapshot,
        convergent_id,
        None,
        1,
    )
    .expect("convergent page request");
    let (entries, next, index_proof, page_proof) = repository
        .scan_request_attempt_page(ledger, convergent_id, None, 1)
        .expect("convergent page");
    assert_eq!(entries.len(), 1);
    assert!(next.is_none());
    assert_eq!(entries[0].1.attempt(), additional.attempt);
    assert!(matches!(
        entries[0].1.role(),
        AttemptAdmissionRole::AdditionalCause { .. }
    ));
    let response = crate::QueryCampaignRequestAttemptsResponse::new(
        &convergent_query,
        head.snapshot().clone(),
        ledger,
        entries.clone(),
        next,
        index_proof.clone(),
        page_proof.clone(),
    )
    .expect("authenticated additional cause");
    response
        .validate_for(&convergent_query)
        .expect("additional cause proof");
    assert!(
        crate::QueryCampaignRequestAttemptsResponse::new(
            &convergent_query,
            head.snapshot().clone(),
            ledger,
            entries.clone(),
            next,
            stale_index_proof,
            page_proof.clone(),
        )
        .is_err()
    );
    assert!(
        crate::QueryCampaignRequestAttemptsResponse::new(
            &convergent_query,
            head.snapshot().clone(),
            ledger,
            entries,
            next,
            index_proof,
            first_proof,
        )
        .is_err()
    );
    assert!(
        crate::QueryCampaignRequestAttemptsResponse::from_canonical_bytes(
            &response.canonical_bytes()[..response.canonical_bytes().len() - 1],
        )
        .is_err()
    );
}
