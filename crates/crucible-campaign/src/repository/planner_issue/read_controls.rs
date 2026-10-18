//! Uncached scalar controls of the production Issue projection for unit tests.

#![cfg(test)]

use super::*;

impl CampaignRepository {
    /// Runs the same preflight projection with original independent node reads.
    ///
    /// # Errors
    ///
    /// Returns the original projection's store, codec, or owner-validation error.
    pub(in crate::repository) fn uncached_issue_preflight_for_test(
        &self,
        basis: &PlannerIssueBasis<'_>,
    ) -> Result<PlannerIssueProjection, CampaignRepositoryError> {
        self.project_planner_issue_with_validation_reads(
            basis,
            IssueProjectionMode::Preflight,
            None,
        )
    }

    /// Runs the same publication projection with original independent node reads.
    ///
    /// # Errors
    ///
    /// Returns the original projection's validation or durable-publication error.
    pub(in crate::repository) fn uncached_issue_publication_for_test(
        &self,
        basis: &PlannerIssueBasis<'_>,
    ) -> Result<PlannerIssueProjection, CampaignRepositoryError> {
        self.project_planner_issue_with_validation_reads(basis, IssueProjectionMode::Publish, None)
    }
}
