//! Versioned campaign budget enforcement and hostile-import regressions.

use super::*;
use crate::{CampaignBudgetError, CampaignBudgetLedger};

fn grant(
    repository: &CampaignRepository,
    name: &str,
    command_name: &str,
    proposals: u64,
    attempts: u64,
) -> CampaignHead {
    let head = repository.head(name).expect("head");
    repository
        .apply_control(
            name,
            &command(
                command_name,
                head.snapshot_id(),
                CampaignControlAction::GrantBudget(
                    BudgetGrant::new(proposals, attempts).expect("grant"),
                ),
            ),
        )
        .expect("apply grant");
    repository.head(name).expect("funded head")
}

#[test]
fn campaign_allowances_gate_new_work_but_never_charge_replay() {
    let (repository, lineage, policy, blobs) = counted_fixture();
    let created = repository
        .create("budget", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    repository
        .read_budget_ledger(created.snapshot().budget_ledger())
        .expect("genesis ledger");
    let request = branch_request(
        &repository,
        &lineage,
        lineage.genesis_content(),
        lineage.genesis(),
        "budget-request",
    );
    repository
        .submit_known_branch_request("budget", created.snapshot_id(), &request)
        .expect("request");
    let head = repository.head("budget").expect("head");
    let unfunded = finite_proposal(&request, &policy, &head, ChoiceValue::Boolean(false), 1);
    let before = blobs.object_count().expect("object count");
    assert!(matches!(
        repository.issue_proposal("budget", head.snapshot_id(), &unfunded),
        Err(CampaignRepositoryError::Budget(
            CampaignBudgetError::ProposalAllowanceExhausted
        ))
    ));
    assert_eq!(
        blobs
            .object_count()
            .expect("rejected proposal writes nothing"),
        before
    );
    assert_eq!(
        repository.head("budget").expect("unchanged").snapshot_id(),
        head.snapshot_id()
    );

    let funded = grant(&repository, "budget", "proposal-allowance", 1, 0);
    let proposal = finite_proposal(&request, &policy, &funded, ChoiceValue::Boolean(false), 1);
    let issued = repository
        .issue_proposal("budget", funded.snapshot_id(), &proposal)
        .expect("issue");
    let (selection, path, attempt) = branch_attempt(&repository, &request, &proposal);
    let before = blobs.object_count().expect("object count");
    assert!(matches!(
        repository.admit_proposal(
            "budget",
            issued.new_snapshot,
            issued.proposal,
            &selection,
            &path,
            &attempt
        ),
        Err(CampaignRepositoryError::Budget(
            CampaignBudgetError::AttemptAllowanceExhausted
        ))
    ));
    assert_eq!(
        blobs
            .object_count()
            .expect("rejected admission writes nothing"),
        before
    );
    assert_eq!(
        repository.head("budget").expect("unadmitted").snapshot_id(),
        issued.new_snapshot
    );

    let funded = grant(&repository, "budget", "attempt-allowance", 0, 1);
    let admitted = repository
        .admit_proposal(
            "budget",
            funded.snapshot_id(),
            issued.proposal,
            &selection,
            &path,
            &attempt,
        )
        .expect("admit");
    let budget = repository.budget_projection("budget").expect("budget");
    assert_eq!((budget.spent_proposals, budget.spent_attempts), (1, 1));
    assert_eq!(
        (budget.remaining_proposals(), budget.remaining_attempts()),
        (0, 0)
    );
    assert!(
        repository
            .issue_proposal("budget", created.snapshot_id(), &proposal)
            .expect("proposal replay")
            .replayed
    );
    assert!(
        repository
            .admit_proposal(
                "budget",
                created.snapshot_id(),
                issued.proposal,
                &selection,
                &path,
                &attempt
            )
            .expect("admission replay")
            .replayed
    );
    assert_eq!(
        repository
            .budget_projection("budget")
            .expect("unchanged spending"),
        budget
    );
    assert_eq!(
        repository.head("budget").expect("same head").snapshot_id(),
        admitted.new_snapshot
    );

    let cold = CampaignRepository::new(Arc::clone(&repository.blobs), Arc::clone(&repository.refs));
    assert_eq!(
        cold.budget_projection("budget").expect("cold budget"),
        budget
    );
}

#[test]
fn imported_successors_cannot_inflate_or_drop_the_budget_contract() {
    let (repository, lineage, policy) = fixture();
    repository
        .create("budget", &lineage, &policy, &BTreeMap::new())
        .expect("create");
    let funded = grant(&repository, "budget", "grant", 1, 1);
    let snapshot = funded.snapshot();
    let inflated = CampaignBudgetLedger::empty(MerkleMap::empty_content_id().expect("empty index"))
        .expect("empty ledger")
        .with_grant(BudgetGrant::new(2, 2).expect("grant"))
        .expect("inflated");
    let inflated_id = repository.put_budget_ledger(inflated).expect("ledger");
    let forged = CampaignSnapshot::successor(
        snapshot.parent().expect("parent"),
        snapshot.lineage(),
        snapshot.active_policy(),
        snapshot.roots(),
        snapshot.transition().expect("transition"),
        inflated_id,
    )
    .expect("forged successor");
    let content = repository.put_snapshot(&forged).expect("forged snapshot");
    let cold = CampaignRepository::new(Arc::clone(&repository.blobs), Arc::clone(&repository.refs));
    assert!(matches!(
        cold.validate_complete_head(content),
        Err(CampaignRepositoryError::Integrity {
            reason: "campaign-budget-successor-mismatch"
        })
    ));
    assert_eq!(
        repository.head("budget").expect("unchanged").snapshot_id(),
        funded.snapshot_id()
    );
}
