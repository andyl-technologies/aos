//! Atomic owner projection for planner-issued requests, proposals, and admissions.

use super::*;
use crate::ProbabilityModelId;

#[derive(Clone, Debug)]
pub(super) struct PlannerIssueProjection {
    pub exploration: ContentId,
    pub accounting: ContentId,
    pub branch_requests: Vec<BranchRequestId>,
    pub proposals: Vec<ProposalId>,
    pub attempts: u64,
    pub deduplicated: u64,
}

#[derive(Clone, Copy)]
enum IssueProjectionMode {
    Preflight,
    Publish,
    Validate {
        target_exploration: ContentId,
        target_accounting: ContentId,
    },
}

impl IssueProjectionMode {
    const fn publishes(self) -> bool {
        matches!(self, Self::Publish)
    }

    const fn validates_import(self) -> bool {
        matches!(self, Self::Validate { .. })
    }
}

struct IssueGeneratorValidation {
    validated: BTreeSet<(
        CandidateGeneratorSpecId,
        ChoiceDomainId,
        Option<ProbabilityModelId>,
    )>,
    remaining: usize,
}

struct PlannerIssueAttemptBasis<'a> {
    snapshot: &'a LoadedSnapshot,
    lineage: &'a CampaignLineage,
    request: &'a BranchRequest,
    opportunity: &'a ChoiceOpportunity,
    domain: &'a ChoiceDomain,
    parent_path: &'a BranchPath,
}

#[derive(Clone, Copy)]
struct PlannerIssueProposalBasis<'a> {
    request: &'a BranchRequest,
    domain: &'a ChoiceDomain,
    feedback_projection: Option<&'a crate::BranchPuctProjection>,
}

impl IssueGeneratorValidation {
    fn new() -> Self {
        Self {
            validated: BTreeSet::new(),
            remaining: MAX_ISSUE_GENERATOR_VALIDATION_OBJECTS,
        }
    }
}

impl CampaignRepository {
    pub(super) fn preflight_planner_issue(
        &self,
        snapshot: &LoadedSnapshot,
        invocation: PlannerInvocationId,
        selected: PlanningScanPosition,
        branch_requests: &[BranchRequest],
        proposals: &[Proposal],
    ) -> Result<PlannerIssueProjection, CampaignRepositoryError> {
        self.project_planner_issue(
            snapshot,
            invocation,
            selected,
            branch_requests,
            proposals,
            IssueProjectionMode::Preflight,
        )
    }

    pub(super) fn publish_planner_issue(
        &self,
        snapshot: &LoadedSnapshot,
        invocation: PlannerInvocationId,
        selected: PlanningScanPosition,
        branch_requests: &[BranchRequest],
        proposals: &[Proposal],
        prepared: &PlannerIssueProjection,
    ) -> Result<PlannerIssueProjection, CampaignRepositoryError> {
        let published = self.project_planner_issue(
            snapshot,
            invocation,
            selected,
            branch_requests,
            proposals,
            IssueProjectionMode::Publish,
        )?;
        if prepared.branch_requests != published.branch_requests
            || prepared.proposals != published.proposals
            || prepared.attempts != published.attempts
            || prepared.deduplicated != published.deduplicated
        {
            return Err(integrity("planner-issue-preflight-publication-mismatch"));
        }
        Ok(published)
    }

    pub(super) fn validate_planner_issue_projection(
        &self,
        parent: &LoadedSnapshot,
        child: &LoadedSnapshot,
        step: &PlannerStep,
    ) -> Result<(), CampaignRepositoryError> {
        let PlannerDisposition::Issue {
            selected,
            issued_branch_requests,
            issued_proposals,
            ..
        } = step.disposition()
        else {
            return Err(integrity("planner-step-is-not-issue"));
        };
        let branch_requests = issued_branch_requests
            .iter()
            .map(|id| self.decode_branch_request(id.content_id()))
            .collect::<Result<Vec<_>, _>>()?;
        let proposals = issued_proposals
            .iter()
            .map(|id| self.decode_proposal(id.content_id()))
            .collect::<Result<Vec<_>, _>>()?;
        let projected = self.project_planner_issue(
            parent,
            step.invocation(),
            *selected,
            &branch_requests,
            &proposals,
            IssueProjectionMode::Validate {
                target_exploration: child.snapshot.roots().exploration,
                target_accounting: child.snapshot.roots().accounting,
            },
        )?;
        if projected.branch_requests != *issued_branch_requests
            || projected.proposals != *issued_proposals
            || projected.exploration != child.snapshot.roots().exploration
            || projected.accounting != child.snapshot.roots().accounting
            || projected.attempts != step.accounting().attempts
            || projected.deduplicated != step.accounting().deduplicated
        {
            return Err(integrity("planner-issue-owner-recomputation-mismatch"));
        }
        Ok(())
    }

    fn project_planner_issue(
        &self,
        snapshot: &LoadedSnapshot,
        invocation_id: PlannerInvocationId,
        selected: PlanningScanPosition,
        branch_requests: &[BranchRequest],
        proposals: &[Proposal],
        mode: IssueProjectionMode,
    ) -> Result<PlannerIssueProjection, CampaignRepositoryError> {
        let invocation = self.load_planner_invocation(invocation_id)?;
        if invocation.policy() != snapshot.snapshot.active_policy()
            || invocation.input_view() != snapshot.snapshot.planning_view().id()?
        {
            return Err(integrity("planner-issue-invocation-is-not-current"));
        }
        let selected_request = self.read_branch_request(selected.source().content_id())?;
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

        let prior_exploration = snapshot.snapshot.roots().exploration;
        let prior_accounting = snapshot.snapshot.roots().accounting;
        let frontier_index = self
            .merkle
            .get(prior_exploration, frontier_index_anchor_key())?;
        let mut exploration_upserts = BTreeMap::new();
        let mut generator_validation = IssueGeneratorValidation::new();
        let mut branch_request_ids = Vec::with_capacity(branch_requests.len());
        let mut indexed_requests = Vec::new();
        for request in branch_requests {
            self.validate_planner_issue_request(
                snapshot,
                &lineage,
                invocation_id,
                &invocation,
                request,
                &mut generator_validation,
            )?;
            let request_id = request.id()?;
            let request_content = if mode.publishes() {
                self.put_branch_request(request)?
            } else {
                request_id.content_id()
            };
            if request_content != request_id.content_id() {
                return Err(integrity("planner-issue-request-publication-id-mismatch"));
            }
            self.insert_overlay_unique(
                prior_exploration,
                &mut exploration_upserts,
                map_key_content("exploration.branch-request", request_content),
                request_content,
                "planner-issue-reused-branch-request-slot",
            )?;
            if let Some(frontier_index) = frontier_index
                && self
                    .merkle
                    .get(frontier_index, frontier_index_order_key(request_id))?
                    .is_some()
            {
                return Err(integrity("planner-issue-reused-frontier-slot"));
            }
            let domain = self.read_choice_domain(request.domain().content_id())?;
            if self
                .candidate_source_profile(request, &domain)?
                .is_some_and(super::projection::CandidateSourceProfile::requires_feedback_index)
            {
                if frontier_index.is_none() {
                    return Err(integrity("progressive-generator-requires-frontier-index"));
                }
                indexed_requests.push((request_id, request.branch_point()));
            }
            branch_request_ids.push(request_id);
        }
        if !indexed_requests.is_empty()
            && let Some(next_index) = self.branch_request_index_after(
                prior_exploration,
                &indexed_requests,
                mode.publishes(),
            )?
        {
            exploration_upserts.insert(branch_request_index_anchor_key(), next_index);
        }

        let selected_key = map_key_content(
            "exploration.branch-request",
            selected_request.id()?.content_id(),
        );
        if self.overlay_get(prior_exploration, &exploration_upserts, selected_key)?
            != Some(selected.source().content_id())
        {
            return Err(integrity(
                "planner-issue-selected-request-is-not-authoritative",
            ));
        }

        let mut proposal_ids = Vec::with_capacity(proposals.len());
        let proposal_basis = PlannerIssueProposalBasis {
            request: &selected_request,
            domain: &selected_domain,
            feedback_projection: feedback_projection.as_ref(),
        };
        for (proposal_index, proposal) in proposals.iter().enumerate() {
            self.validate_planner_issue_proposal(
                snapshot,
                invocation_id,
                &proposal_basis,
                proposal,
                &proposals[..proposal_index],
            )?;
            let proposal_id = proposal.id()?;
            let proposal_content = if mode.publishes() {
                self.put_proposal(proposal)?
            } else {
                proposal_id.content_id()
            };
            if proposal_content != proposal_id.content_id() {
                return Err(integrity("planner-issue-proposal-publication-id-mismatch"));
            }
            self.insert_planner_issue_proposal_overlay(
                prior_exploration,
                &mut exploration_upserts,
                proposal,
                proposal_content,
            )?;
            proposal_ids.push(proposal_id);
        }

        let mut accounting_upserts = BTreeMap::new();
        let mut prepared_admissions = BTreeMap::new();
        let mut attempts = 0_u64;
        let mut deduplicated = 0_u64;
        let mut request_attempts = if proposals.is_empty() {
            0
        } else {
            self.count_request_execution_bases(prior_accounting, selected.source())?
        };
        let mut next_ordinal = if proposals.is_empty() {
            None
        } else {
            self.next_planner_issue_admission_ordinal(prior_accounting)?
        };
        let attempt_basis = PlannerIssueAttemptBasis {
            snapshot,
            lineage: &lineage,
            request: &selected_request,
            opportunity: &selected_opportunity,
            domain: &selected_domain,
            parent_path: &parent_path,
        };
        for (proposal, proposal_id) in proposals.iter().zip(proposal_ids.iter().copied()) {
            let attempt = self.derive_planner_issue_attempt(&attempt_basis, proposal, mode)?;
            let attempt_id = attempt.id()?;
            let expected = self.expected_planner_issue_admission(
                prior_accounting,
                &accounting_upserts,
                &prepared_admissions,
                &selected_request,
                proposal_id,
                attempt_id,
                request_attempts,
                next_ordinal,
            )?;
            let admission_content = match mode {
                IssueProjectionMode::Publish => {
                    let content = self.put_attempt_admission(&expected)?;
                    if content != expected.id()?.content_id() {
                        return Err(integrity("planner-issue-admission-publication-mismatch"));
                    }
                    content
                }
                IssueProjectionMode::Preflight => expected.id()?.content_id(),
                IssueProjectionMode::Validate {
                    target_accounting, ..
                } => {
                    let content = self
                        .merkle
                        .get(
                            target_accounting,
                            map_key_content(
                                "accounting.proposal-admission",
                                proposal_id.content_id(),
                            ),
                        )?
                        .ok_or_else(|| integrity("planner-issue-admission-is-missing"))?;
                    if self.decode_attempt_admission(content)? != expected {
                        return Err(integrity("planner-issue-admission-owner-mismatch"));
                    }
                    content
                }
            };
            prepared_admissions.insert(admission_content, expected);
            match expected.role() {
                AttemptAdmissionRole::ExecutionBasis {
                    admission_ordinal, ..
                } => {
                    attempts = attempts
                        .checked_add(1)
                        .ok_or_else(|| integrity("planner-issue-attempt-count-overflow"))?;
                    request_attempts = request_attempts
                        .checked_add(1)
                        .ok_or_else(|| integrity("planner-issue-attempt-count-overflow"))?;
                    next_ordinal = admission_ordinal.checked_next();
                }
                AttemptAdmissionRole::AdditionalCause { .. } => {
                    deduplicated = deduplicated
                        .checked_add(1)
                        .ok_or_else(|| integrity("planner-issue-dedup-count-overflow"))?;
                }
            }
            for (key, value) in attempt_admission_upserts(admission_content, expected)? {
                if key == admission_sequence_key() {
                    accounting_upserts.insert(key, value);
                    continue;
                }
                self.insert_overlay_unique(
                    prior_accounting,
                    &mut accounting_upserts,
                    key,
                    value,
                    "planner-issue-reused-admission-slot",
                )?;
            }
        }

        if let Some(frontier_index) = frontier_index {
            let mut frontier_states = BTreeMap::new();
            for (request, request_id) in branch_requests.iter().zip(branch_request_ids.iter()) {
                frontier_states.insert(
                    *request_id,
                    (
                        request.branch_point(),
                        self.initial_continuation_state_at(
                            request,
                            super::projection::CandidateViewRoots::from_roots(
                                snapshot.snapshot.roots(),
                            ),
                        )?,
                    ),
                );
            }
            if let Some(last_proposal) = proposals.last() {
                if !frontier_states.contains_key(&selected.source()) {
                    let prior_state = self.continuation_state(
                        super::projection::CandidateViewRoots::new(
                            prior_exploration,
                            snapshot.snapshot.roots().observations,
                            snapshot.snapshot.roots().corpus,
                            prior_accounting,
                        ),
                        selected.source(),
                        &selected_request,
                    )?;
                    self.validate_frontier_projection(
                        frontier_index,
                        selected.source(),
                        selected.branch_point(),
                        prior_state,
                    )?;
                }
                let proposed = last_proposal.ordinal();
                let profile = self
                    .candidate_source_profile(&selected_request, &selected_domain)?
                    .ok_or_else(|| integrity("generated-proposal-enumerator-is-not-implemented"))?;
                let completed_visits = self.branch_completed_visits(
                    snapshot.snapshot.roots().observations,
                    selected_request.branch_point(),
                )?;
                let has_next_candidate = if profile
                    == super::projection::CandidateSourceProfile::CorpusMutation
                    && proposed < selected_request.budget().maximum_proposals()
                {
                    self.expected_candidate_at_view(
                        &selected_request,
                        &selected_domain,
                        proposed
                            .checked_add(1)
                            .ok_or_else(|| integrity("planner-candidate-ordinal-overflow"))?,
                        super::projection::CandidateEnumerationBasis::new(
                            super::projection::CandidateViewRoots::new(
                                prior_exploration,
                                snapshot.snapshot.roots().observations,
                                snapshot.snapshot.roots().corpus,
                                prior_accounting,
                            ),
                            completed_visits,
                        )
                        .with_additional_previous(proposals)
                        .with_feedback(feedback_projection.as_ref().map(|projection| {
                            super::projection::CandidateFeedbackProjection::new(
                                snapshot.snapshot.active_policy(),
                                projection,
                            )
                        })),
                    )?
                    .is_some()
                } else {
                    false
                };
                let state = super::projection::continuation_state_after_progress(
                    profile,
                    proposed,
                    false,
                    has_next_candidate,
                    selected_request.budget().maximum_proposals(),
                    completed_visits,
                )?;
                frontier_states.insert(selected.source(), (selected.branch_point(), state));
            }
            let projections = frontier_states
                .into_iter()
                .map(|(request, (branch_point, state))| (request, branch_point, state))
                .collect::<Vec<_>>();
            let next_frontier = self
                .frontier_index_after(prior_exploration, &projections, mode.publishes())?
                .ok_or_else(|| integrity("planner-issue-frontier-index-disappeared"))?;
            exploration_upserts.insert(frontier_index_anchor_key(), next_frontier);
        }

        let exploration =
            self.finish_issue_root(prior_exploration, &exploration_upserts, mode, true)?;
        let accounting =
            self.finish_issue_root(prior_accounting, &accounting_upserts, mode, false)?;

        Ok(PlannerIssueProjection {
            exploration,
            accounting,
            branch_requests: branch_request_ids,
            proposals: proposal_ids,
            attempts,
            deduplicated,
        })
    }

    fn validate_planner_issue_request(
        &self,
        snapshot: &LoadedSnapshot,
        lineage: &CampaignLineage,
        invocation_id: PlannerInvocationId,
        invocation: &PlannerInvocation,
        request: &BranchRequest,
        generator_validation: &mut IssueGeneratorValidation,
    ) -> Result<(), CampaignRepositoryError> {
        if request.cause() != BranchRequestCause::Planner(invocation_id) {
            return Err(integrity("planner-issue-request-invocation-mismatch"));
        }
        self.validate_branch_request_references_shallow(request)?;
        if let Some(generator) = request.source().generator()
            && generator_validation.validated.insert((
                generator,
                request.domain(),
                request.source().model_prior(),
            ))
        {
            let domain = self.read_choice_domain(request.domain().content_id())?;
            self.validate_candidate_source_generator_with_budget(
                request.source(),
                &domain,
                &mut generator_validation.remaining,
            )?;
        }
        let parent = self.read_configuration_artifact(request.parent().content_id())?;
        if parent.scenario() != lineage.scenario() {
            return Err(integrity("branch-request-parent-scenario-mismatch"));
        }
        if self.merkle.get(
            snapshot.snapshot.roots().graph,
            map_key_hash("graph.configuration", parent.configuration().as_hash()),
        )? != Some(request.parent().content_id())
        {
            return Err(integrity("branch-request-parent-is-not-in-campaign-graph"));
        }
        if invocation.policy() != snapshot.snapshot.active_policy()
            || invocation.input_view() != snapshot.snapshot.planning_view().id()?
        {
            return Err(integrity("planner-issue-request-invocation-basis-mismatch"));
        }
        if let CandidateSource::Generated(generator) = request.source() {
            let opportunity = self.read_opportunity(request.opportunity().content_id())?;
            let declaration = self.read_selectable(opportunity.declaration().content_id())?;
            let policy = self.read_policy(snapshot.snapshot.active_policy().content_id())?;
            if policy
                .choice_policies()
                .get(declaration.name())
                .map(crate::ChoicePolicy::generator)
                != Some(*generator)
            {
                return Err(integrity(
                    "branch-request-generator-is-not-selected-by-active-policy",
                ));
            }
        }
        Ok(())
    }

    fn validate_planner_issue_proposal(
        &self,
        snapshot: &LoadedSnapshot,
        invocation: PlannerInvocationId,
        basis: &PlannerIssueProposalBasis<'_>,
        proposal: &Proposal,
        additional_previous: &[Proposal],
    ) -> Result<(), CampaignRepositoryError> {
        let PlannerIssueProposalBasis {
            request,
            domain,
            feedback_projection,
        } = *basis;
        if proposal.planner_invocation() != Some(invocation)
            || proposal.request() != request.id()?
            || proposal.branch_point() != request.branch_point()
        {
            return Err(integrity("planner-issue-proposal-selection-mismatch"));
        }
        proposal.validate_resolved(request, domain)?;
        if proposal.policy() != snapshot.snapshot.active_policy()
            || proposal.guidance_basis() != snapshot.snapshot.planning_view().id()?
        {
            return Err(integrity("proposal-campaign-basis-mismatch"));
        }
        let completed_visits = self.branch_completed_visits(
            snapshot.snapshot.roots().observations,
            request.branch_point(),
        )?;
        let expected = self
            .expected_candidate_at_view(
                request,
                domain,
                proposal.ordinal(),
                super::projection::CandidateEnumerationBasis::new(
                    super::projection::CandidateViewRoots::from_roots(snapshot.snapshot.roots()),
                    completed_visits,
                )
                .with_additional_previous(additional_previous)
                .with_feedback(feedback_projection.map(|projection| {
                    super::projection::CandidateFeedbackProjection::new(
                        snapshot.snapshot.active_policy(),
                        projection,
                    )
                })),
            )?
            .ok_or_else(|| integrity("generated-proposal-enumerator-is-not-implemented"))?;
        if &expected != proposal.value() {
            return Err(integrity("proposal-value-does-not-match-source-order"));
        }
        Ok(())
    }

    fn insert_planner_issue_proposal_overlay(
        &self,
        prior: ContentId,
        upserts: &mut BTreeMap<CampaignHash, ContentId>,
        proposal: &Proposal,
        proposal_content: ContentId,
    ) -> Result<(), CampaignRepositoryError> {
        let proposal_key = map_key_content("exploration.proposal", proposal_content);
        let ordinal_key = proposal_ordinal_key(proposal.request(), proposal.ordinal());
        let value_key = proposal_value_key(proposal.request(), proposal.value());
        for key in [proposal_key, ordinal_key, value_key] {
            self.insert_overlay_unique(
                prior,
                upserts,
                key,
                proposal_content,
                "planner-issue-reused-proposal-slot",
            )?;
        }
        if proposal.ordinal() > 1 {
            let prior_key = proposal_ordinal_key(proposal.request(), proposal.ordinal() - 1);
            let prior_content = self
                .overlay_get(prior, upserts, prior_key)?
                .ok_or_else(|| integrity("planner-issue-skipped-proposal-ordinal"))?;
            let prior_proposal = self.decode_proposal(prior_content)?;
            if prior_proposal.request() != proposal.request()
                || prior_proposal.ordinal().checked_add(1) != Some(proposal.ordinal())
            {
                return Err(integrity("planner-issue-proposal-predecessor-mismatch"));
            }
        }
        Ok(())
    }

    // crucible-lint: allow rust-allow -- this narrowly scoped exception preserves the surrounding typed boundary.
    #[allow(clippy::too_many_arguments)]
    fn expected_planner_issue_admission(
        &self,
        prior: ContentId,
        upserts: &BTreeMap<CampaignHash, ContentId>,
        prepared_admissions: &BTreeMap<ContentId, AttemptAdmission>,
        request: &BranchRequest,
        proposal: ProposalId,
        attempt: AttemptId,
        request_attempts: u64,
        next_ordinal: Option<AdmissionOrdinal>,
    ) -> Result<AttemptAdmission, CampaignRepositoryError> {
        if self
            .overlay_get(
                prior,
                upserts,
                map_key_content("accounting.proposal-admission", proposal.content_id()),
            )?
            .is_some()
        {
            return Err(integrity("proposal-already-has-admission"));
        }
        let attempt_key = map_key_content("accounting.attempt", attempt.content_id());
        let basis_key = map_key_content("accounting.attempt-execution-basis", attempt.content_id());
        let indexed_attempt = self.overlay_get(prior, upserts, attempt_key)?;
        let indexed_basis = self.overlay_get(prior, upserts, basis_key)?;
        match (indexed_attempt, indexed_basis) {
            (None, None) => {
                if request_attempts >= request.budget().maximum_attempts() {
                    return Err(integrity("branch-request-attempt-budget-exhausted"));
                }
                let admission_ordinal =
                    next_ordinal.ok_or_else(|| integrity("admission-ordinal-overflow"))?;
                Ok(AttemptAdmission::new(
                    attempt,
                    AttemptAdmissionRole::ExecutionBasis {
                        proposal: Some(proposal),
                        cause: request.cause(),
                        admission_ordinal,
                    },
                ))
            }
            (Some(indexed_attempt), Some(indexed_basis))
                if indexed_attempt == attempt.content_id() =>
            {
                let basis = match prepared_admissions.get(&indexed_basis) {
                    Some(admission) => *admission,
                    None => self.decode_attempt_admission(indexed_basis)?,
                };
                if basis.attempt() != attempt
                    || !matches!(basis.role(), AttemptAdmissionRole::ExecutionBasis { .. })
                {
                    return Err(integrity("attempt-execution-basis-index-mismatch"));
                }
                Ok(AttemptAdmission::new(
                    attempt,
                    AttemptAdmissionRole::AdditionalCause { proposal },
                ))
            }
            _ => Err(integrity("attempt-admission-index-shape")),
        }
    }

    fn derive_planner_issue_attempt(
        &self,
        basis: &PlannerIssueAttemptBasis<'_>,
        proposal: &Proposal,
        mode: IssueProjectionMode,
    ) -> Result<Attempt, CampaignRepositoryError> {
        let selection = Selection::new_campaign_branch(
            basis.opportunity,
            basis.domain,
            proposal.value().clone(),
            proposal.branch_point(),
        )?;
        let crate::SelectionOrigin::CampaignBranch { edge, .. } = selection.origin() else {
            return Err(integrity("planner-issue-selection-is-not-campaign-branch"));
        };
        let mut segments = basis
            .parent_path
            .segments()
            .ok_or_else(|| integrity("planner-issue-parent-path-is-legacy"))?
            .to_vec();
        segments.push(crate::BranchPathSegment::new(proposal.branch_point(), edge));
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
            basis.request.stop().clone(),
        )?;

        if mode.publishes() {
            if self.put_selection(&selection)? != selection.id()?.content_id()
                || self.put_branch_path(&path)? != path.id()?.content_id()
                || self.put_attempt(&attempt)? != attempt.id()?.content_id()
            {
                return Err(integrity("planner-issue-attempt-publication-id-mismatch"));
            }
        } else if mode.validates_import()
            && (self.resolve_selection(selection.id()?)?.selection() != &selection
                || self.read_branch_path(path.id()?.content_id())? != path
                || self.read_attempt(attempt.id()?.content_id())? != attempt)
        {
            return Err(integrity("planner-issue-derived-attempt-mismatch"));
        }
        Ok(attempt)
    }

    fn planner_issue_parent_path(
        &self,
        snapshot: &LoadedSnapshot,
        lineage: &CampaignLineage,
        request: &BranchRequest,
    ) -> Result<BranchPath, CampaignRepositoryError> {
        if request.parent() == lineage.genesis_content() {
            return BranchPath::new(Vec::new()).map_err(Into::into);
        }

        let path_index = self
            .merkle
            .get(
                snapshot.snapshot.roots().observations,
                configuration_path_index_key(request.parent()),
            )?
            .ok_or_else(|| integrity("planner-issue-parent-path-index-is-missing"))?;
        let page = self.merkle.scan(path_index, None, 1)?;
        let [(key, content)] = page.entries() else {
            return Err(integrity("planner-issue-parent-path-index-is-empty"));
        };
        let path_id = BranchPathId::from_content_id(*content)?;
        if *key != path_index_order_key(path_id) {
            return Err(integrity("planner-issue-parent-path-index-key-mismatch"));
        }
        let path = self.read_branch_path(*content)?;
        if path.segments().is_none() {
            return Err(integrity("planner-issue-parent-path-is-legacy"));
        }
        Ok(path)
    }

    fn overlay_get(
        &self,
        prior: ContentId,
        upserts: &BTreeMap<CampaignHash, ContentId>,
        key: CampaignHash,
    ) -> Result<Option<ContentId>, CampaignRepositoryError> {
        match upserts.get(&key).copied() {
            Some(value) => Ok(Some(value)),
            None => Ok(self.merkle.get(prior, key)?),
        }
    }

    fn next_planner_issue_admission_ordinal(
        &self,
        accounting: ContentId,
    ) -> Result<Option<AdmissionOrdinal>, CampaignRepositoryError> {
        let Some(latest) = self.merkle.get(accounting, admission_sequence_key())? else {
            return Ok(Some(AdmissionOrdinal::new(1)));
        };
        let admission = self.decode_attempt_admission(latest)?;
        let AttemptAdmissionRole::ExecutionBasis {
            admission_ordinal, ..
        } = admission.role()
        else {
            return Err(integrity(
                "admission-sequence-does-not-name-execution-basis",
            ));
        };
        Ok(admission_ordinal.checked_next())
    }

    fn insert_overlay_unique(
        &self,
        prior: ContentId,
        upserts: &mut BTreeMap<CampaignHash, ContentId>,
        key: CampaignHash,
        value: ContentId,
        error: &'static str,
    ) -> Result<(), CampaignRepositoryError> {
        if upserts.contains_key(&key) || self.merkle.get(prior, key)?.is_some() {
            return Err(integrity(error));
        }
        upserts.insert(key, value);
        Ok(())
    }

    fn finish_issue_root(
        &self,
        prior: ContentId,
        upserts: &BTreeMap<CampaignHash, ContentId>,
        mode: IssueProjectionMode,
        exploration: bool,
    ) -> Result<ContentId, CampaignRepositoryError> {
        match mode {
            IssueProjectionMode::Preflight => Ok(prior),
            IssueProjectionMode::Publish => {
                let mut root = prior;
                for (key, value) in upserts {
                    root = self.merkle.insert(root, *key, *value)?.content_id();
                }
                Ok(root)
            }
            IssueProjectionMode::Validate {
                target_exploration,
                target_accounting,
            } => {
                let target = if exploration {
                    target_exploration
                } else {
                    target_accounting
                };
                if !self.merkle.equals_after_upserts(prior, target, upserts)? {
                    return Err(integrity("planner-issue-root-delta-mismatch"));
                }
                Ok(target)
            }
        }
    }
}
