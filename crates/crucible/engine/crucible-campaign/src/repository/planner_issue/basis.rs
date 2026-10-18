//! Immutable authenticated inputs shared within one planner Issue operation.

use super::super::projection::CandidateSourceProfile;
use super::*;

/// Holds one guarded operation's basis, never a repository or cross-operation cache.
///
/// Acceptance constructs it under mutation ownership; cold validation resolves
/// a fresh basis for its supplied immutable snapshot. Neither retains this value
/// after the operation returns.
pub(in crate::repository) struct PlannerIssueBasis<'a> {
    pub(super) snapshot: &'a LoadedSnapshot,
    pub(super) invocation_id: PlannerInvocationId,
    pub(super) invocation: &'a PlannerInvocation,
    pub(super) selected: PlanningScanPosition,
    pub(super) branch_requests: &'a [BranchRequest],
    pub(super) proposals: &'a [Proposal],
    pub(super) selected_request: BranchRequest,
    pub(super) selected_opportunity: ChoiceOpportunity,
    pub(super) selected_domain: ChoiceDomain,
    pub(super) selected_profile: Option<CandidateSourceProfile>,
    pub(super) feedback_projection: Option<crate::BranchPuctProjection>,
    pub(super) lineage: CampaignLineage,
    pub(super) parent_path: BranchPath,
    pub(super) completed_visits: u64,
}

impl CampaignRepository {
    /// Resolves immutable inputs after the caller authenticates the invocation.
    /// Both owner projections still independently derive all output and index changes.
    ///
    /// # Errors
    ///
    /// Returns a store, codec, or integrity error for missing or corrupt selected
    /// records, a mismatched invocation view or policy, or an invalid selection.
    pub(in crate::repository) fn planner_issue_basis<'a>(
        &self,
        snapshot: &'a LoadedSnapshot,
        invocation: &'a PlannerInvocation,
        selected: PlanningScanPosition,
        branch_requests: &'a [BranchRequest],
        proposals: &'a [Proposal],
    ) -> Result<PlannerIssueBasis<'a>, CampaignRepositoryError> {
        let invocation_id = invocation.id()?;
        if invocation.policy() != snapshot.snapshot.active_policy()
            || invocation.input_view() != snapshot.snapshot.planning_view().id()?
        {
            return Err(integrity("planner-issue-invocation-is-not-current"));
        }
        let selected_request = branch_requests
            .iter()
            .find_map(|request| {
                request
                    .id()
                    .ok()
                    .filter(|request_id| *request_id == selected.source())
                    .map(|_| request.clone())
            })
            .map(Ok)
            .unwrap_or_else(|| self.read_branch_request(selected.source().content_id()))?;
        let selected_is_new = branch_requests
            .iter()
            .map(BranchRequest::id)
            .collect::<Result<BTreeSet<_>, _>>()?
            .contains(&selected.source());
        if selected_is_new
            && (!proposals.is_empty()
                || !matches!(
                    selected_request.source(),
                    CandidateSource::StatisticalFinite(_) | CandidateSource::StatisticalSmc(_)
                ))
        {
            return Err(integrity(
                "planner-new-selected-request-is-not-statistical-request-only",
            ));
        }
        if selected_request.branch_point() != selected.branch_point() {
            return Err(integrity("planner-issue-selected-request-mismatch"));
        }
        let selected_opportunity =
            self.read_opportunity(selected_request.opportunity().content_id())?;
        let selected_domain = self.read_choice_domain(selected_request.domain().content_id())?;
        let selected_profile =
            self.candidate_source_profile(&selected_request, &selected_domain)?;
        let feedback_projection = if selected_profile.is_some_and(|profile| {
            proposals
                .iter()
                .any(|proposal| profile.scores_interval_at(proposal.ordinal()))
        }) {
            Some(self.project_branch_puct_loaded(snapshot, selected.branch_point())?)
        } else {
            None
        };
        let lineage = self.read_lineage(required_child(&snapshot.envelope, "lineage")?)?;
        let parent_path = self.planner_issue_parent_path(snapshot, &lineage, &selected_request)?;

        let completed_visits = if proposals.is_empty() {
            0
        } else {
            self.branch_completed_visits(
                snapshot.snapshot.roots().observations,
                selected_request.branch_point(),
            )?
        };

        Ok(PlannerIssueBasis {
            snapshot,
            invocation_id,
            invocation,
            selected,
            branch_requests,
            proposals,
            selected_request,
            selected_opportunity,
            selected_domain,
            selected_profile,
            feedback_projection,
            lineage,
            parent_path,
            completed_visits,
        })
    }
}
