//! Mutation-scale accounting, cold validation, and exact replay of campaign budgets.

use super::*;

const CAMPAIGN: &str = "budget-scale";

#[test]
fn ten_thousand_budget_transitions_preserve_exact_spending_and_cold_replay() {
    const CAUSES: u64 = 2_500;

    let (repository, lineage, policy, blobs) = fixture_with_quota(512 * 1024 * 1024);
    repository
        .create(CAMPAIGN, &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let template = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "budget-scale-template",
    );
    let mut first = None;
    for ordinal in 0..CAUSES {
        // Each iteration adds four real owner transitions. All causes resolve
        // to one execution basis, but each must fund its own proposal.
        let head = repository.head(CAMPAIGN).expect("head");
        let control = command(
            &format!("budget-scale-grant-{ordinal}"),
            head.snapshot_id(),
            CampaignControlAction::GrantBudget(
                BudgetGrant::new(1, u64::from(ordinal == 0)).expect("grant"),
            ),
        );
        let granted = repository.apply_control(CAMPAIGN, &control).expect("grant");
        let request = BranchRequest::new(
            template.branch_point(),
            template.parent(),
            template.opportunity(),
            template.domain(),
            template.source().clone(),
            BranchRequestCause::Operator(crate::CampaignCommandId::from_hash(
                CampaignHash::derive("test.budget-scale", &ordinal.to_be_bytes()),
            )),
            template.budget(),
            template.stop().clone(),
        )
        .expect("scaled request");
        repository
            .submit_known_branch_request(CAMPAIGN, granted.new_snapshot, &request)
            .expect("submit request");
        let head = repository.head(CAMPAIGN).expect("proposal head");
        let proposal = finite_proposal(&request, &policy, &head, ChoiceValue::Boolean(false), 1);
        let issued = repository
            .issue_proposal(CAMPAIGN, head.snapshot_id(), &proposal)
            .expect("issue proposal");
        let (selection, path, attempt) = branch_attempt(&repository, &request, &proposal);
        let admitted = repository
            .admit_proposal(
                CAMPAIGN,
                issued.new_snapshot,
                issued.proposal,
                &selection,
                &path,
                &attempt,
            )
            .expect("admit convergent attempt");
        let budget = repository
            .budget_projection(CAMPAIGN)
            .expect("indexed ledger");
        assert_eq!(budget.granted_proposals, u128::from(ordinal + 1));
        assert_eq!(budget.spent_proposals, ordinal + 1);
        assert_eq!((budget.granted_attempts, budget.spent_attempts), (1, 1));
        assert_eq!(
            (budget.remaining_proposals(), budget.remaining_attempts()),
            (0, 0)
        );
        if ordinal == 0 {
            first = Some((
                control, granted, proposal, issued, selection, path, attempt, admitted,
            ));
        }
    }

    let before_restart = repository
        .budget_projection(CAMPAIGN)
        .expect("final ledger");
    let cold = CampaignRepository::new(repository.blobs.clone(), repository.refs.clone());
    assert_eq!(
        cold.budget_projection(CAMPAIGN).expect("cold ledger"),
        before_restart
    );
    let (control, granted, proposal, issued, selection, path, attempt, admitted) =
        first.expect("first transition set");
    let object_count = blobs.object_count().expect("before retries");
    let replay = cold
        .apply_control(CAMPAIGN, &control)
        .expect("deep grant replay");
    assert!(replay.replayed);
    assert_eq!(replay.new_snapshot, granted.new_snapshot);
    let replay = cold
        .issue_proposal(CAMPAIGN, issued.prior_snapshot, &proposal)
        .expect("deep proposal replay");
    assert!(replay.replayed);
    assert_eq!(replay.new_snapshot, issued.new_snapshot);
    let replay = cold
        .admit_proposal(
            CAMPAIGN,
            admitted.prior_snapshot,
            issued.proposal,
            &selection,
            &path,
            &attempt,
        )
        .expect("deep admission replay");
    assert!(replay.replayed);
    assert_eq!(replay.new_snapshot, admitted.new_snapshot);
    assert_eq!(blobs.object_count().expect("after retries"), object_count);
    assert_eq!(
        cold.budget_projection(CAMPAIGN).expect("replayed ledger"),
        before_restart
    );

    // A different proposal under the first request must still fail before
    // publication, even after all process-local validation caches were lost.
    let head = cold.head(CAMPAIGN).expect("cold head");
    let request = cold
        .read_branch_request(proposal.request().content_id())
        .expect("first request");
    let unfunded = finite_proposal(&request, &policy, &head, ChoiceValue::Boolean(true), 2);
    assert!(matches!(
        cold.issue_proposal(CAMPAIGN, head.snapshot_id(), &unfunded),
        Err(CampaignRepositoryError::Budget(
            crate::CampaignBudgetError::ProposalAllowanceExhausted
        ))
    ));
    assert_eq!(blobs.object_count().expect("after rejection"), object_count);
    assert_eq!(
        cold.budget_projection(CAMPAIGN).expect("unchanged ledger"),
        before_restart
    );
}
