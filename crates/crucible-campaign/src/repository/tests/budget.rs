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
