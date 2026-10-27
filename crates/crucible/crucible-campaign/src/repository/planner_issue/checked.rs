//! Checked semantic reconstruction for planner-issued campaign work.

use super::*;

mod projection;

impl ClosureSemanticRead<'_, '_> {
    pub(in crate::repository) fn planner_search_candidate(
        &mut self,
        snapshot: &LoadedSnapshot,
        offer: &Proposal,
    ) -> Result<(crate::PlannerSearchCandidate, BranchPath, BranchPath), CampaignRepositoryError>
    {
        let _operation = self.enter_operation();
        let request = self.read_branch_request(offer.request())?;
        let domain = self.read_choice_domain(offer.domain().content_id())?;
        let lineage = self.read_lineage(snapshot.snapshot.lineage().content_id())?;
        let parent_path = self.planner_issue_parent_path(snapshot, &lineage, &request)?;
        let edge =
            Selection::campaign_edge_id(offer.branch_point(), domain.semantic_id(), offer.value());
        let mut segments = Vec::new();
        for segment in parent_path.segments() {
            self.push(&mut segments, *segment)?;
        }
        self.push(
            &mut segments,
            crate::BranchPathSegment::new(offer.branch_point(), edge),
        )?;
        let path = BranchPath::new(segments)?;
        let depth = u64::try_from(path.edges().len()).map_err(|_| {
            CampaignRepositoryError::Codec(CampaignCodecError::LimitExceeded {
                limit: "planner-search-candidate-depth",
            })
        })?;
        let candidate = crate::PlannerSearchCandidate::new(
            snapshot.snapshot.planning_view().id()?,
            snapshot.snapshot.active_policy(),
            PlanningScanPosition::new(offer.branch_point(), offer.request()),
            offer.domain(),
            domain.semantic_id(),
            offer.value().clone_admitted()?,
            offer.ordinal(),
            edge,
            parent_path.id()?,
            path.id()?,
            depth,
        )?;

        Ok((candidate, parent_path, path))
    }

    pub(in crate::repository) fn planner_candidate_budget(
        &mut self,
        snapshot: &LoadedSnapshot,
        offer: &Proposal,
        ledger: crate::CampaignBudgetLedger,
        request_budget_work: Option<&mut usize>,
    ) -> Result<crate::PlannerCandidateBudget, CampaignRepositoryError> {
        let _operation = self.enter_operation();
        let request = self.read_branch_request(offer.request())?;
        let opportunity = self.read_opportunity(request.opportunity().content_id())?;
        let domain = self.read_choice_domain(request.domain().content_id())?;
        let lineage = self.read_lineage(required_child(&snapshot.envelope, "lineage")?)?;
        let parent_path = self.planner_issue_parent_path(snapshot, &lineage, &request)?;
        let attempt = self.derive_planner_issue_attempt(
            &PlannerIssueAttemptBasis {
                snapshot,
                lineage: &lineage,
                request: &request,
                opportunity: &opportunity,
                domain: &domain,
                parent_path: &parent_path,
            },
            offer,
            false,
        )?;
        let attempt = attempt.id()?;
        let accounting = snapshot.snapshot.roots().accounting;
        let indexed_attempt = self.merkle_get(
            accounting,
            map_key_content("accounting.attempt", attempt.content_id()),
        )?;
        let indexed_basis = self.merkle_get(
            accounting,
            map_key_content("accounting.attempt-execution-basis", attempt.content_id()),
        )?;
        let new_attempt = match (indexed_attempt, indexed_basis) {
            (None, None) => true,
            (Some(indexed), Some(basis)) if indexed == attempt.content_id() => {
                let admission = self.decode_attempt_admission(basis)?;
                if admission.attempt() != attempt
                    || !matches!(
                        admission.role(),
                        AttemptAdmissionRole::ExecutionBasis { .. }
                    )
                {
                    return Err(integrity("planner-budget-attempt-basis-mismatch"));
                }
                false
            }
            _ => return Err(integrity("planner-budget-attempt-index-mismatch")),
        };
        let _work = request_budget_work
            .ok_or_else(|| integrity("planner-candidate-request-budget-is-missing"))?;
        let count = self.request_execution_bases_at(snapshot, offer.request())?;
        let remaining = request.budget().maximum_attempts().saturating_sub(count);
        Ok(crate::PlannerCandidateBudget::new(
            offer,
            ledger.remaining_proposals(),
            ledger.remaining_attempts(),
            new_attempt,
            remaining,
        )?)
    }

    pub(in crate::repository) fn planner_issue_parent_path(
        &mut self,
        snapshot: &LoadedSnapshot,
        lineage: &CampaignLineage,
        request: &BranchRequest,
    ) -> Result<BranchPath, CampaignRepositoryError> {
        if request.parent() == lineage.genesis_content() {
            return BranchPath::new(Vec::new()).map_err(Into::into);
        }

        let path_index = self
            .merkle_get(
                snapshot.snapshot.roots().observations,
                configuration_path_index_key(request.parent()),
            )?
            .ok_or_else(|| integrity("planner-issue-parent-path-index-is-missing"))?;
        let page = self.merkle_scan(path_index, None, 1)?;
        let [(key, content)] = page.entries() else {
            return Err(integrity("planner-issue-parent-path-index-is-empty"));
        };
        let path_id = BranchPathId::from_content_id(*content)?;
        if *key != path_index_order_key(path_id) {
            return Err(integrity("planner-issue-parent-path-index-key-mismatch"));
        }
        self.read_branch_path(*content)
    }

    fn derive_planner_issue_attempt(
        &mut self,
        basis: &PlannerIssueAttemptBasis<'_>,
        proposal: &Proposal,
        validates_import: bool,
    ) -> Result<Attempt, CampaignRepositoryError> {
        let selection = Selection::new_campaign_branch(
            basis.opportunity,
            basis.domain,
            proposal.value().clone_admitted()?,
            proposal.branch_point(),
        )?;
        let crate::SelectionOrigin::CampaignBranch { edge, .. } = selection.origin() else {
            return Err(integrity("planner-issue-selection-is-not-campaign-branch"));
        };
        let mut segments = Vec::new();
        for segment in basis.parent_path.segments() {
            self.push(&mut segments, *segment)?;
        }
        self.push(
            &mut segments,
            crate::BranchPathSegment::new(proposal.branch_point(), edge),
        )?;
        let path = BranchPath::new(segments)?;
        self.validate_attempt_path_owner(
            basis.snapshot,
            basis.lineage,
            basis.request,
            &path,
            edge,
        )?;
        let attempt = Attempt::new(
            AttemptStart::Branch {
                edge,
                parent: basis.request.parent(),
                selection: selection.id()?,
            },
            path.id()?,
            basis.request.stop().clone_admitted()?,
        )?;

        if validates_import {
            let (stored_selection, _, _) = self
                .read_resolved_selection(selection.id()?, &mut ChoiceValidationCache::default())?;
            let stored_path = self.read_branch_path(path.id()?.content_id())?;
            let stored_attempt = self.read_attempt_cached(
                attempt.id()?.content_id(),
                &mut ChoiceValidationCache::default(),
            )?;
            if stored_selection != selection || stored_path != path || stored_attempt != attempt {
                return Err(integrity("planner-issue-derived-attempt-mismatch"));
            }
        }
        Ok(attempt)
    }
}
