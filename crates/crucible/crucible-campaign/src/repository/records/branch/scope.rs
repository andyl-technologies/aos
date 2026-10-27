//! Checked campaign-scope validation for immutable requests and proposals.

use super::*;
use crate::BranchBudget;
use crate::repository::closure::read::ClosureSemanticRead;
use crate::repository::projection::{
    CandidateEnumerationBasis, CandidateFeedbackProjection, CandidateViewRoots,
};

impl ClosureSemanticRead<'_, '_> {
    pub(in crate::repository) fn validate_proposal_campaign_scope(
        &mut self,
        snapshot: &LoadedSnapshot,
        proposal: &Proposal,
    ) -> Result<BranchRequest, CampaignRepositoryError> {
        let request = self.read_branch_request(proposal.request())?;
        let request_content = proposal.request().content_id();
        let request_key = map_key_content("exploration.branch-request", request_content);
        if self.merkle_get(snapshot.snapshot.roots().exploration, request_key)?
            != Some(request_content)
        {
            return Err(integrity("proposal-request-is-not-authoritative"));
        }

        let domain = self.read_choice_domain(proposal.domain().content_id())?;
        proposal.validate_resolved(&request, &domain)?;
        if proposal.policy() != snapshot.snapshot.active_policy()
            || proposal.guidance_basis() != snapshot.snapshot.planning_view().id()?
        {
            return Err(integrity("proposal-campaign-basis-mismatch"));
        }
        if let Some(invocation) = proposal.planner_invocation() {
            let invocation = self.read_planner_invocation(invocation)?;
            if invocation.policy() != proposal.policy()
                || invocation.input_view() != proposal.guidance_basis()
            {
                return Err(integrity("proposal-planner-invocation-mismatch"));
            }
        }

        let roots = snapshot.snapshot.roots();
        let completed_visits =
            self.branch_completed_visits(roots.observations, request.branch_point())?;
        let feedback_projection = if self
            .candidate_source_profile(&request, &domain)?
            .is_some_and(|profile| profile.scores_interval_at(proposal.ordinal()))
        {
            Some(self.project_branch_puct_loaded(snapshot, request.branch_point())?)
        } else {
            None
        };
        let expected = self
            .expected_candidate_at_view(
                &request,
                &domain,
                proposal.ordinal(),
                CandidateEnumerationBasis::new(
                    CandidateViewRoots::from_roots(roots),
                    completed_visits,
                )
                .with_feedback(feedback_projection.as_ref().map(|projection| {
                    CandidateFeedbackProjection::new(snapshot.snapshot.active_policy(), projection)
                })),
            )?
            .ok_or_else(|| integrity("generated-proposal-enumerator-is-not-implemented"))?;
        if &expected != proposal.value() {
            return Err(integrity("proposal-value-does-not-match-source-order"));
        }
        Ok(request)
    }

    pub(in crate::repository) fn validate_branch_request_campaign_scope(
        &mut self,
        snapshot: &LoadedSnapshot,
        request: &BranchRequest,
        parent: &ConfigurationArtifact,
    ) -> Result<(), CampaignRepositoryError> {
        let _operation = self.enter_operation();
        let lineage = self.read_lineage(required_child(&snapshot.envelope, "lineage")?)?;
        let active_policy = self.read_policy(snapshot.snapshot.active_policy().content_id())?;
        if request.stop()
            != &active_policy.bound_stop(request.stop().primary().clone_admitted()?)?
        {
            return Err(integrity(
                "branch-request-stop-disagrees-with-active-policy-timeout",
            ));
        }
        self.validate_statistical_request_policy(snapshot, &lineage, &active_policy, request)?;
        if parent.scenario() != lineage.scenario() {
            return Err(integrity("branch-request-parent-scenario-mismatch"));
        }
        if self.merkle_get(
            snapshot.snapshot.roots().graph,
            map_key_hash("graph.configuration", parent.configuration().as_hash()),
        )? != Some(request.parent().content_id())
        {
            return Err(integrity("branch-request-parent-is-not-in-campaign-graph"));
        }
        if self.merkle_get(
            snapshot.snapshot.roots().graph,
            branch_point_opportunity_key(request.branch_point(), request.opportunity()),
        )? != Some(request.opportunity().content_id())
        {
            return Err(integrity(
                "branch-request-opportunity-is-not-authoritative-campaign-knowledge",
            ));
        }

        match request.cause() {
            BranchRequestCause::Planner(invocation) => {
                let invocation = self.read_planner_invocation(invocation)?;
                if invocation.policy() != snapshot.snapshot.active_policy() {
                    return Err(integrity("branch-request-planner-policy-is-not-active"));
                }
                if invocation.input_view() != snapshot.snapshot.planning_view().id()? {
                    return Err(integrity("branch-request-planner-view-is-not-current"));
                }
            }
            BranchRequestCause::ExhaustivePolicy(policy)
            | BranchRequestCause::ScenarioDefault(policy)
                if policy != snapshot.snapshot.active_policy() =>
            {
                return Err(integrity("branch-request-policy-is-not-active"));
            }
            BranchRequestCause::ExhaustivePolicy(_)
            | BranchRequestCause::ScenarioDefault(_)
            | BranchRequestCause::Operator(_)
            | BranchRequestCause::Debugger(_) => {}
        }

        if let BranchRequestCause::ExhaustivePolicy(policy_id) = request.cause() {
            let policy = self.read_policy(policy_id.content_id())?;
            let crate::ExplorerPolicy::Exhaustive {
                maximum_cardinality,
            } = policy.explorer()
            else {
                return Err(integrity(
                    "exhaustive-branch-request-policy-is-not-exhaustive",
                ));
            };
            let CandidateSource::Generated(generator_id) = request.source() else {
                return Err(integrity(
                    "exhaustive-branch-request-source-is-not-generated",
                ));
            };
            let generator = self.read_generator(generator_id.content_id())?;
            if generator.implementation_version()
                != crate::STATIC_ALL_GENERATOR_IMPLEMENTATION_VERSION
                || generator.algorithm() != &CandidateGeneratorAlgorithm::All
            {
                return Err(integrity("exhaustive-branch-request-generator-is-not-all"));
            }
            let domain = self.read_choice_domain(request.domain().content_id())?;
            let cardinality = domain.cardinality();
            if cardinality > u128::from(*maximum_cardinality) {
                return Err(integrity("exhaustive-branch-request-domain-exceeds-policy"));
            }
            if u128::from(request.budget().maximum_proposals()) != cardinality {
                return Err(integrity(
                    "exhaustive-branch-request-budget-is-not-domain-cardinality",
                ));
            }
        }

        if let BranchRequestCause::ScenarioDefault(policy_id) = request.cause() {
            let policy = self.read_policy(policy_id.content_id())?;
            if !policy.admits_scenario_defaults() {
                return Err(integrity(
                    "scenario-default-branch-request-is-disabled-by-policy",
                ));
            }
            let CandidateSource::Finite(source) = request.source() else {
                return Err(integrity(
                    "scenario-default-branch-request-source-is-not-finite",
                ));
            };
            let opportunity = self.read_opportunity(request.opportunity().content_id())?;
            if source.prior_weights().is_some()
                || source.values().len() != 1
                || !source.values().contains(opportunity.default())
            {
                return Err(integrity(
                    "scenario-default-branch-request-source-is-not-exact-default",
                ));
            }
            if request.budget().maximum_proposals() != 1 || request.budget().maximum_attempts() != 1
            {
                return Err(integrity(
                    "scenario-default-branch-request-budget-is-not-one",
                ));
            }
        }

        if let CandidateSource::Generated(generator) = request.source()
            && matches!(
                request.cause(),
                BranchRequestCause::Planner(_) | BranchRequestCause::ExhaustivePolicy(_)
            )
        {
            let opportunity = self.read_opportunity(request.opportunity().content_id())?;
            let declaration = self.read_selectable(opportunity.declaration().content_id())?;
            let selected = active_policy.choice_policies().get(declaration.name());
            if selected.map(crate::ChoicePolicy::generator) != Some(*generator) {
                return Err(integrity(
                    "branch-request-generator-is-not-selected-by-active-policy",
                ));
            }
        }
        Ok(())
    }

    pub(in crate::repository) fn validate_statistical_request_policy(
        &mut self,
        snapshot: &LoadedSnapshot,
        lineage: &CampaignLineage,
        policy: &CampaignPolicy,
        request: &BranchRequest,
    ) -> Result<(), CampaignRepositoryError> {
        let _operation = self.enter_operation();
        let source = match request.source() {
            CandidateSource::StatisticalFinite(source) => source,
            CandidateSource::StatisticalSmc(_)
                if policy.mode() == CampaignMode::Statistical
                    && policy.sequential_monte_carlo_design().is_some() =>
            {
                return Ok(());
            }
            CandidateSource::StatisticalSmc(_) => {
                return if policy.mode() == CampaignMode::Statistical {
                    Err(integrity("statistical-policy-requires-statistical-request"))
                } else {
                    Ok(())
                };
            }
            CandidateSource::Finite(_)
            | CandidateSource::ModeledFinite(_)
            | CandidateSource::ModeledGenerated(_)
            | CandidateSource::Generated(_) => return Ok(()),
        };
        if policy.mode() != CampaignMode::Statistical {
            return Err(integrity("statistical-request-requires-statistical-policy"));
        }
        let design = policy
            .statistical_sampling_design()
            .ok_or_else(|| integrity("statistical-policy-lacks-sampling-design"))?;
        let draw = design
            .draw(source.coordinate())
            .ok_or_else(|| integrity("statistical-request-coordinate-is-not-planned"))?;
        let distribution = design
            .distributions()
            .get(&draw.model())
            .ok_or_else(|| integrity("statistical-request-model-is-not-planned"))?;
        let opportunity = self.read_opportunity(draw.opportunity().content_id())?;
        let parent = self.read_configuration_artifact(request.parent().content_id())?;
        let expected_branch_point = crate::ChoiceOpportunity::branch_point_id_for_semantics(
            parent.configuration(),
            draw.opportunity_semantics(),
        );
        if !matches!(request.cause(), BranchRequestCause::Planner(_))
            || request.opportunity() != draw.opportunity()
            || request.domain() != draw.domain()
            || request.stop() != &policy.bound_stop(draw.stop().clone_admitted()?)?
            || request.budget() != BranchBudget::new(1, 1)?
            || request.branch_point() != expected_branch_point
            || opportunity.id()? != draw.opportunity()
            || opportunity.semantic_id() != draw.opportunity_semantics()
            || opportunity.domain() != draw.domain()
            || opportunity.model_prior() != Some(draw.model())
            || self.merkle_get(
                snapshot.snapshot.roots().graph,
                branch_point_opportunity_key(expected_branch_point, draw.opportunity()),
            )? != Some(draw.opportunity().content_id())
            || source.model() != draw.model()
            || source.target_masses() != distribution.target_masses()
            || source.proposal_masses() != distribution.proposal_masses()
        {
            return Err(integrity("statistical-request-disagrees-with-pinned-draw"));
        }

        let Some(parent_coordinate) = draw.parent() else {
            if request.parent() != lineage.genesis_content()
                || parent.configuration() != lineage.genesis()
            {
                return Err(integrity("statistical-root-draw-parent-is-not-genesis"));
            }
            return Ok(());
        };
        let parent_proposal_content = self
            .merkle_get(
                snapshot.snapshot.roots().accounting,
                statistical_draw_proposal_key(parent_coordinate),
            )?
            .ok_or_else(|| integrity("statistical-parent-draw-is-not-admitted"))?;
        let parent_proposal = self.read_proposal(parent_proposal_content)?;
        let parent_request = self.read_branch_request(parent_proposal.request())?;
        let CandidateSource::StatisticalFinite(parent_source) = parent_request.source() else {
            return Err(integrity("statistical-parent-draw-source-mismatch"));
        };
        if parent_source.coordinate() != parent_coordinate {
            return Err(integrity("statistical-parent-draw-coordinate-mismatch"));
        }
        let admission_content = self
            .merkle_get(
                snapshot.snapshot.roots().accounting,
                map_key_content("accounting.proposal-admission", parent_proposal_content),
            )?
            .ok_or_else(|| integrity("statistical-parent-draw-admission-is-missing"))?;
        let admission = self.read_attempt_admission(admission_content)?;
        let observation_content = self
            .merkle_get(
                snapshot.snapshot.roots().observations,
                map_key_content("observations.attempt", admission.attempt().content_id()),
            )?
            .ok_or_else(|| integrity("statistical-parent-draw-observation-is-missing"))?;
        let observation = self.decode_observation(observation_content)?;
        self.validate_observation_references_cached(
            &observation,
            &mut ChoiceValidationCache::default(),
        )?;
        if observation.attempt() != admission.attempt()
            || observation.child_content() != request.parent()
            || observation.child() != parent.configuration()
        {
            return Err(integrity("statistical-parent-draw-endpoint-mismatch"));
        }
        self.validate_statistical_attempt_basis(snapshot, admission.attempt())
    }

    fn validate_statistical_attempt_basis(
        &mut self,
        snapshot: &LoadedSnapshot,
        attempt: AttemptId,
    ) -> Result<(), CampaignRepositoryError> {
        let basis_content = self
            .merkle_get(
                snapshot.snapshot.roots().accounting,
                map_key_content("accounting.attempt-execution-basis", attempt.content_id()),
            )?
            .ok_or_else(|| integrity("statistical-attempt-execution-basis-is-missing"))?;
        let basis = self.read_attempt_admission(basis_content)?;
        let AttemptAdmissionRole::ExecutionBasis {
            proposal: Some(proposal),
            cause: BranchRequestCause::Planner(_),
            ..
        } = basis.role()
        else {
            return Err(integrity(
                "statistical-attempt-execution-basis-is-intervention",
            ));
        };
        if basis.attempt() != attempt {
            return Err(integrity("statistical-attempt-execution-basis-mismatch"));
        }
        let proposal = self.read_proposal(proposal.content_id())?;
        let request = self.read_branch_request(proposal.request())?;
        if !matches!(
            request.source(),
            CandidateSource::StatisticalFinite(_) | CandidateSource::StatisticalSmc(_)
        ) {
            return Err(integrity(
                "statistical-attempt-execution-basis-is-not-a-draw",
            ));
        }
        Ok(())
    }
}
