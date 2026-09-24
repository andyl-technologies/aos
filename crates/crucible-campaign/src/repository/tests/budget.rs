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
    let first_attempt = entries[0].attempt();
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
        .scan_request_attempt_page(ledger, request_id, Some(first_attempt), 1)
        .expect("second page");
    assert_eq!(entries.len(), 1);
    let last_attempt = entries[0].attempt();
    assert_eq!(
        BTreeSet::from([first_attempt, last_attempt]),
        BTreeSet::from([admitted.attempt, second.attempt])
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
        Some(last_attempt),
        1,
    )
    .expect("tail query");
    let (entries, next, index_proof, page_proof) = repository
        .scan_request_attempt_page(ledger, request_id, Some(last_attempt), 1)
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
