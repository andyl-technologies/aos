//! Checked reconstruction of retained planner candidate inputs.

use super::*;
use crate::repository::projection::{
    CandidateEnumerationBasis, CandidateFeedbackProjection, CandidateViewRoots,
    continuation_state_after_progress,
};

impl ClosureSemanticRead<'_, '_> {
    pub(super) fn planner_continuation_projection(
        &mut self,
        snapshot: &LoadedSnapshot,
        position: crate::PlanningScanPosition,
    ) -> Result<ContinuationProjection, CampaignRepositoryError> {
        let frontier = self
            .merkle_get(
                snapshot.snapshot.roots().exploration,
                frontier_index_anchor_key(),
            )?
            .ok_or_else(|| integrity("planner-candidate-frontier-index-is-missing"))?;
        let projection_content = self
            .merkle_get(frontier, frontier_index_order_key(position.source()))?
            .ok_or_else(|| integrity("planner-candidate-projection-is-missing"))?;
        let projection = self.read_continuation_projection(projection_content)?;
        if projection.request() != position.source()
            || projection.branch_point() != position.branch_point()
        {
            return Err(integrity("planner-candidate-position-mismatch"));
        }
        Ok(projection)
    }

    pub(super) fn planner_candidate_input(
        &mut self,
        snapshot: &LoadedSnapshot,
        invocation_id: crate::PlannerInvocationId,
        position: crate::PlanningScanPosition,
        feedback_projection: Option<&crate::BranchPuctProjection>,
    ) -> Result<(ContinuationProjection, Option<Proposal>), CampaignRepositoryError> {
        let roots = snapshot.snapshot.roots();
        let request_admissions = self.parent_budget_ledger(snapshot)?.request_admissions();
        let candidate_view =
            CandidateViewRoots::from_roots(roots).with_request_admissions(request_admissions);
        let projection = self.planner_continuation_projection(snapshot, position)?;
        let request = self.read_branch_request(position.source())?;
        let domain = self.read_choice_domain(request.domain().content_id())?;
        if self.candidate_source_profile(&request, &domain)?.is_none() {
            let expected = ContinuationProjection::new(
                position.source(),
                position.branch_point(),
                crate::ContinuationState::Open,
            );
            if projection != expected {
                return Err(integrity("planner-candidate-frontier-projection-mismatch"));
            }
            return Ok((projection, None));
        }

        let (profile, proposed, pending, next_candidate, completed_visits) =
            self.planner_candidate_progress(roots, request_admissions, &request)?;
        let state = continuation_state_after_progress(
            profile,
            proposed,
            pending,
            next_candidate.is_some(),
            request.budget().maximum_proposals(),
            completed_visits,
        )?;
        if projection
            != ContinuationProjection::new(position.source(), position.branch_point(), state)
        {
            return Err(integrity("planner-candidate-frontier-projection-mismatch"));
        }

        let offer = if state == crate::ContinuationState::Ready {
            let ordinal = proposed
                .checked_add(1)
                .ok_or_else(|| integrity("planner-candidate-ordinal-overflow"))?;
            let value = match next_candidate {
                Some(value) => value,
                None => self
                    .expected_candidate_at_view(
                        &request,
                        &domain,
                        ordinal,
                        CandidateEnumerationBasis::new(candidate_view, completed_visits)
                            .with_feedback(feedback_projection.map(|projection| {
                                CandidateFeedbackProjection::new(
                                    snapshot.snapshot.active_policy(),
                                    projection,
                                )
                            })),
                    )?
                    .ok_or_else(|| integrity("planner-candidate-enumerator-is-not-implemented"))?,
            };
            Some(Proposal::new_for_request(
                position.branch_point(),
                position.source(),
                request.domain(),
                value,
                snapshot.snapshot.active_policy(),
                Some(invocation_id),
                ordinal,
                snapshot.snapshot.planning_view().id()?,
                &request,
            )?)
        } else {
            None
        };
        Ok((projection, offer))
    }
}
