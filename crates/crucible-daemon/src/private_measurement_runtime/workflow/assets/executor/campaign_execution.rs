//! Validates required coordinator inputs with the actual campaign contracts.
//!
//! Validation is allocation-free and runs in executor preflight before import
//! or head publication. These values do not authorize a semantic command; the
//! consuming prepared service must still use its real policy and principal.

use crucible::owned_decode::json_profiles::workflow::CampaignExecution;
use crucible_campaign::{
    BudgetGrant, MAX_ATTEMPT_QUEUE_SCAN_PAGE_ITEMS, MAX_PLANNER_SCAN_PAGE_ITEMS, PlanningBudget,
};

use super::ArtifactCause;

/// Checks the actual planning, grant and scan constructors before service work.
///
/// # Errors
/// Refuses zero planning dimensions, an empty semantic grant, or either scan
/// outside the existing campaign driver's finite page bound.
pub(super) fn validate(input: &CampaignExecution) -> Result<(), ArtifactCause> {
    let budget = &input.planning_budget;
    PlanningBudget::new(
        budget.branch_requests,
        budget.proposals,
        budget.input_objects,
        budget.input_bytes,
        budget.fuel,
    )?;
    BudgetGrant::new(input.grant.proposals, input.grant.attempts)?;
    if input.planner_scan_limit == 0
        || input.planner_scan_limit > MAX_PLANNER_SCAN_PAGE_ITEMS
        || input.executor_scan_limit == 0
        || input.executor_scan_limit > MAX_ATTEMPT_QUEUE_SCAN_PAGE_ITEMS
    {
        return Err(ArtifactCause::Identity);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> Result<CampaignExecution, serde_json::Error> {
        serde_json::from_str(
            r#"{
            "planner":{"exhaustive":{"search":"breadthFirst"}},
            "planningBudget":{"branchRequests":1,"proposals":1,"inputObjects":1,"inputBytes":1,"fuel":1},
            "plannerScanLimit":1,"executorScanLimit":1,"retention":"discard",
            "grant":{"proposals":0,"attempts":1}
        }"#,
        )
    }

    #[test]
    fn required_contract_preserves_independent_grant_and_planning_budget()
    -> Result<(), Box<dyn std::error::Error>> {
        validate(&input()?)?;
        Ok(())
    }

    #[test]
    fn constructor_refusals_precede_service_effects() -> Result<(), Box<dyn std::error::Error>> {
        let mut input = input()?;
        input.planning_budget.fuel = 0;
        assert!(validate(&input).is_err());
        input.planning_budget.fuel = 1;
        input.grant.attempts = 0;
        assert!(validate(&input).is_err());
        input.grant.attempts = 1;
        input.executor_scan_limit = MAX_ATTEMPT_QUEUE_SCAN_PAGE_ITEMS + 1;
        assert!(validate(&input).is_err());
        Ok(())
    }
}
