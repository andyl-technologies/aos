//! Negative request-local proposal-head projection cases.

use super::*;
use crate::repository::projection::CandidateViewRoots;

#[test]
fn indexed_progress_rejects_missing_and_stale_heads() {
    let (repository, lineage, policy, _) = counted_fixture();
    let campaign = "proposal-head-guard";
    let created = repository
        .create_funded(campaign, &lineage, &policy, &BTreeMap::new())
        .expect("fund campaign");
    let request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        campaign,
    );
    let requested = repository
        .submit_known_branch_request(campaign, created.snapshot_id(), &request)
        .expect("submit request");
    let requested_head = repository.head(campaign).expect("request head");
    let request_id = request.id().expect("request identity");
    let domain = repository
        .read_choice_domain(request.domain().content_id())
        .expect("request domain");
    let first = finite_proposal(
        &request,
        &policy,
        &requested_head,
        ChoiceValue::Boolean(false),
        1,
    );
    let first_content = repository.put_proposal(&first).expect("first proposal");
    let missing_head_root = repository
        .merkle
        .insert(
            requested_head.snapshot().roots().exploration,
            proposal_ordinal_key(request_id, 1),
            first_content,
        )
        .expect("synthetic missing-head root")
        .content_id();
    let requested_ledger = repository
        .read_budget_ledger(requested_head.snapshot().budget_ledger())
        .expect("request ledger");
    let requested_roots = requested_head.snapshot().roots();
    let missing_head_view = CandidateViewRoots::new(
        missing_head_root,
        requested_roots.observations,
        requested_roots.corpus,
        requested_roots.accounting,
    )
    .with_request_admissions(requested_ledger.request_admissions());
    assert!(matches!(
        repository.continuation_progress(missing_head_view, request_id, &request, &domain),
        Err(CampaignRepositoryError::Integrity {
            reason: "finite-expansion-proposal-head-is-missing"
        })
    ));

    let issued = repository
        .issue_proposal(campaign, requested.new_snapshot, &first)
        .expect("issue first proposal");
    let issued_head = repository.head(campaign).expect("issued head");
    let second = finite_proposal(
        &request,
        &policy,
        &issued_head,
        ChoiceValue::Boolean(true),
        2,
    );
    let second_content = repository.put_proposal(&second).expect("second proposal");
    let stale_head_root = repository
        .merkle
        .insert(
            issued_head.snapshot().roots().exploration,
            proposal_ordinal_key(request_id, 2),
            second_content,
        )
        .expect("synthetic stale-head root")
        .content_id();
    let issued_ledger = repository
        .read_budget_ledger(issued_head.snapshot().budget_ledger())
        .expect("issued ledger");
    let issued_roots = issued_head.snapshot().roots();
    let stale_head_view = CandidateViewRoots::new(
        stale_head_root,
        issued_roots.observations,
        issued_roots.corpus,
        issued_roots.accounting,
    )
    .with_request_admissions(issued_ledger.request_admissions());
    assert!(matches!(
        repository.continuation_progress(stale_head_view, request_id, &request, &domain),
        Err(CampaignRepositoryError::Integrity {
            reason: "finite-expansion-proposal-head-is-stale"
        })
    ));
    assert_eq!(
        repository
            .head(campaign)
            .expect("unchanged head")
            .snapshot_id(),
        issued.new_snapshot
    );
}
