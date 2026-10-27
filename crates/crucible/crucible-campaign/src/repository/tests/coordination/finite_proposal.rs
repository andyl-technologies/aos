//! Finite proposal replay and staleness regression.

use super::*;

#[test]
fn finite_proposal_is_an_exact_indexed_delta_and_replays_before_staleness() {
    let (repository, lineage, policy) = fixture();
    let genesis = repository
        .create_funded("finite-proposal", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "finite-proposal",
    );
    let requested = repository
        .submit_known_branch_request("finite-proposal", genesis.snapshot_id(), &request)
        .expect("submit request");
    let request_head = repository.head("finite-proposal").expect("request head");

    let wrong_order = finite_proposal(
        &request,
        &policy,
        &request_head,
        ChoiceValue::Boolean(true),
        1,
    );
    assert!(matches!(
        repository.issue_proposal("finite-proposal", requested.new_snapshot, &wrong_order,),
        Err(CampaignRepositoryError::Integrity {
            reason: "proposal-value-does-not-match-source-order"
        })
    ));

    let first = finite_proposal(
        &request,
        &policy,
        &request_head,
        ChoiceValue::Boolean(false),
        1,
    );
    let accepted = repository
        .issue_proposal("finite-proposal", requested.new_snapshot, &first)
        .expect("issue proposal");
    assert!(!accepted.replayed);
    assert_eq!(accepted.proposal, first.id().expect("proposal id"));
    assert_eq!(
        repository
            .load_proposal(accepted.proposal)
            .expect("load proposal"),
        first
    );

    let proposal_head = repository.head("finite-proposal").expect("proposal head");
    let prior = request_head.snapshot().roots();
    let next = proposal_head.snapshot().roots();
    assert_ne!(prior.exploration, next.exploration);
    assert_eq!(prior.graph, next.graph);
    assert_eq!(prior.observations, next.observations);
    assert_eq!(prior.corpus, next.corpus);
    assert_eq!(prior.coverage, next.coverage);
    assert_eq!(prior.findings, next.findings);
    assert_eq!(prior.pins, next.pins);
    assert_eq!(prior.accounting, next.accounting);
    assert_eq!(
        repository
            .merkle
            .get(
                next.exploration,
                proposal_head_key(request.id().expect("request id"))
            )
            .expect("proposal head lookup"),
        Some(accepted.proposal.content_id())
    );
    assert_eq!(
        repository
            .merkle
            .inspect_shallow(next.exploration)
            .expect("exploration root")
            .entry_count(),
        8
    );

    let replay = repository
        .issue_proposal("finite-proposal", genesis.snapshot_id(), &first)
        .expect("replay proposal");
    assert!(replay.replayed);
    assert_eq!(replay.prior_snapshot, accepted.prior_snapshot);
    assert_eq!(replay.new_snapshot, accepted.new_snapshot);
}
