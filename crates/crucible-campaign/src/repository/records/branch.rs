//! Branch requests, generators, proposals, and their campaign scope.

use super::*;
use crate::BranchBudget;

impl CampaignRepository {
    pub(crate) fn read_branch_request(
        &self,
        id: ContentId,
    ) -> Result<BranchRequest, CampaignRepositoryError> {
        let request = self.decode_branch_request(id)?;
        self.validate_branch_request_references(&request)?;
        Ok(request)
    }

    pub(in crate::repository) fn decode_branch_request(
        &self,
        id: ContentId,
    ) -> Result<BranchRequest, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::BranchRequest)?;
        let request = BranchRequest::from_canonical_bytes(envelope.body())?;
        if request.id()?.content_id() != id {
            return Err(integrity("branch-request-envelope-shape"));
        }
        Ok(request)
    }

    pub(in crate::repository) fn validate_branch_request_references(
        &self,
        request: &BranchRequest,
    ) -> Result<ConfigurationArtifact, CampaignRepositoryError> {
        let parent = self.read_configuration_artifact(request.parent().content_id())?;
        let opportunity = self.read_opportunity(request.opportunity().content_id())?;
        let domain = self.read_choice_domain(request.domain().content_id())?;
        request.validate_resolved(&parent, &opportunity, &domain)?;
        let mut remaining = MAX_CAMPAIGN_CLOSURE_OBJECTS;
        self.validate_candidate_source_generator_with_budget(
            request.source(),
            &domain,
            &mut remaining,
        )?;
        match request.cause() {
            BranchRequestCause::Planner(invocation) => {
                self.load_planner_invocation(invocation)?;
            }
            BranchRequestCause::ExhaustivePolicy(policy) => {
                self.read_policy(policy.content_id())?;
            }
            BranchRequestCause::ScenarioDefault(policy) => {
                self.read_policy(policy.content_id())?;
            }
            BranchRequestCause::Operator(_) | BranchRequestCause::Debugger(_) => {}
        }
        Ok(parent)
    }

    pub(in crate::repository) fn validate_branch_request_references_shallow(
        &self,
        request: &BranchRequest,
    ) -> Result<(), CampaignRepositoryError> {
        let parent = self.read_configuration_artifact(request.parent().content_id())?;
        let opportunity = self.read_opportunity(request.opportunity().content_id())?;
        let domain = self.read_choice_domain(request.domain().content_id())?;
        request.validate_resolved(&parent, &opportunity, &domain)?;
        if let Some(generator) = request.source().generator() {
            self.require_record_kind(
                generator.content_id(),
                crate::CampaignRecordKind::CandidateGeneratorSpec,
            )?;
        }
        match request.cause() {
            BranchRequestCause::Planner(invocation) => {
                self.require_record_kind(
                    invocation.content_id(),
                    crate::CampaignRecordKind::PlannerInvocation,
                )?;
            }
            BranchRequestCause::ExhaustivePolicy(policy) => {
                self.read_policy(policy.content_id())?;
            }
            BranchRequestCause::ScenarioDefault(policy) => {
                self.read_policy(policy.content_id())?;
            }
            BranchRequestCause::Operator(_) | BranchRequestCause::Debugger(_) => {}
        }
        Ok(())
    }

    #[cfg(test)]
    pub(in crate::repository) fn validate_generator_for_domain(
        &self,
        root: CandidateGeneratorSpecId,
        domain: &ChoiceDomain,
    ) -> Result<(), CampaignRepositoryError> {
        let mut remaining = MAX_CAMPAIGN_CLOSURE_OBJECTS;
        self.validate_generator_for_domain_with_budget(root, domain, &mut remaining)
    }

    pub(in crate::repository) fn validate_candidate_source_generator_with_budget(
        &self,
        source: &CandidateSource,
        domain: &ChoiceDomain,
        remaining: &mut usize,
    ) -> Result<(), CampaignRepositoryError> {
        let Some(generator_id) = source.generator() else {
            return Ok(());
        };
        if let CandidateSource::ModeledGenerated(_) = source {
            let generator = self.read_generator(generator_id.content_id())?;
            let ChoiceDomain::Integer(integer) = domain else {
                return Err(integrity("modeled-uniform-integer-domain-family-mismatch"));
            };
            let cardinality = integer.cardinality();
            if generator.algorithm() != &CandidateGeneratorAlgorithm::PermutedInteger
                || generator.implementation_version()
                    != crate::MODELED_UNIFORM_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                || cardinality == 0
                || !cardinality.is_power_of_two()
                || cardinality > u128::from(u64::MAX) + 1
            {
                return Err(integrity("modeled-generated-source-contract-mismatch"));
            }
        }
        self.validate_generator_for_domain_with_budget(generator_id, domain, remaining)
    }

    pub(in crate::repository) fn validate_generator_for_domain_with_budget(
        &self,
        root: CandidateGeneratorSpecId,
        domain: &ChoiceDomain,
        remaining: &mut usize,
    ) -> Result<(), CampaignRepositoryError> {
        let mut stack = vec![(root, 0_usize)];
        let mut visited = BTreeSet::new();
        while let Some((id, depth)) = stack.pop() {
            if depth > 1024 {
                return Err(integrity("candidate-generator-validation-limit"));
            }
            if !visited.insert(id) {
                continue;
            }
            if *remaining == 0 {
                return Err(integrity("candidate-generator-validation-limit"));
            }
            *remaining -= 1;
            let generator = self.read_generator(id.content_id())?;
            match generator.algorithm() {
                CandidateGeneratorAlgorithm::All
                    if matches!(domain, ChoiceDomain::Boolean(_) | ChoiceDomain::Discrete(_)) => {}
                CandidateGeneratorAlgorithm::WeightedCategorical { weights } => {
                    let ChoiceDomain::Discrete(discrete) = domain else {
                        return Err(integrity("candidate-generator-domain-family-mismatch"));
                    };
                    if weights
                        .keys()
                        .any(|alternative| !discrete.alternatives().contains_key(alternative))
                    {
                        return Err(integrity(
                            "candidate-generator-discrete-alternative-mismatch",
                        ));
                    }
                    if generator.implementation_version()
                        == crate::WEIGHTED_CATEGORICAL_GENERATOR_IMPLEMENTATION_VERSION
                        && weights.len() > crate::WEIGHTED_CATEGORICAL_GENERATOR_MAX_ALTERNATIVES
                    {
                        return Err(integrity("weighted-generator-alternative-limit"));
                    }
                }
                CandidateGeneratorAlgorithm::BoundaryInteger => {
                    let ChoiceDomain::Integer(integer) = domain else {
                        return Err(integrity("candidate-generator-domain-family-mismatch"));
                    };
                    if generator.implementation_version()
                        == crate::BOUNDARY_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                        && integer.landmarks().len()
                            > crate::BOUNDARY_INTEGER_GENERATOR_MAX_LANDMARKS
                    {
                        return Err(integrity("boundary-generator-landmark-limit"));
                    }
                }
                CandidateGeneratorAlgorithm::StratifiedInteger { strata } => {
                    if !matches!(domain, ChoiceDomain::Integer(_)) {
                        return Err(integrity("candidate-generator-domain-family-mismatch"));
                    }
                    if generator.implementation_version()
                        == crate::STRATIFIED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                        && *strata > crate::STRATIFIED_INTEGER_GENERATOR_MAX_STRATA
                    {
                        return Err(integrity("stratified-generator-strata-limit"));
                    }
                }
                CandidateGeneratorAlgorithm::LogInteger { .. } => {
                    let ChoiceDomain::Integer(integer) = domain else {
                        return Err(integrity("candidate-generator-domain-family-mismatch"));
                    };
                    let minimum_is_positive = match integer.minimum() {
                        IntegerValue::Signed(value) => value > 0,
                        IntegerValue::Unsigned(value) => value > 0,
                    };
                    if generator.implementation_version()
                        == crate::LOG_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                        && !minimum_is_positive
                    {
                        return Err(integrity("log-generator-domain-is-not-positive"));
                    }
                }
                CandidateGeneratorAlgorithm::PermutedInteger => {
                    let ChoiceDomain::Integer(integer) = domain else {
                        return Err(integrity("candidate-generator-domain-family-mismatch"));
                    };
                    if generator.implementation_version()
                        == crate::PERMUTED_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                        && integer.cardinality() > crate::PERMUTED_INTEGER_GENERATOR_MAX_CARDINALITY
                    {
                        return Err(integrity("permuted-generator-cardinality-limit"));
                    }
                    if generator.implementation_version()
                        == crate::MODELED_UNIFORM_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                        && (integer.cardinality() == 0
                            || !integer.cardinality().is_power_of_two()
                            || integer.cardinality() > u128::from(u64::MAX) + 1)
                    {
                        return Err(integrity("modeled-uniform-integer-cardinality-limit"));
                    }
                }
                CandidateGeneratorAlgorithm::ProgressiveInteger { initial_strata, .. }
                    if matches!(domain, ChoiceDomain::Integer(_)) =>
                {
                    if matches!(
                        generator.implementation_version(),
                        crate::PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                            | crate::FEEDBACK_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                            | crate::LANDMARK_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                            | crate::MEASUREMENT_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                            | crate::COVERAGE_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                            | crate::FINDING_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                            | crate::RARITY_PROGRESSIVE_INTEGER_GENERATOR_IMPLEMENTATION_VERSION
                    ) && *initial_strata
                        > crate::PROGRESSIVE_INTEGER_GENERATOR_MAX_INITIAL_STRATA
                    {
                        return Err(integrity("progressive-generator-initial-strata-limit"));
                    }
                }
                CandidateGeneratorAlgorithm::MutateNearCorpus { maximum_distance }
                    if matches!(domain, ChoiceDomain::Integer(_)) =>
                {
                    if generator.implementation_version()
                        == crate::CORPUS_MUTATION_GENERATOR_IMPLEMENTATION_VERSION
                        && *maximum_distance > crate::CORPUS_MUTATION_GENERATOR_MAX_DISTANCE
                    {
                        return Err(integrity("corpus-mutation-generator-distance-limit"));
                    }
                }
                CandidateGeneratorAlgorithm::OrderedMixture { components } => {
                    stack.extend(
                        components
                            .iter()
                            .rev()
                            .map(|component| (component.generator(), depth + 1)),
                    );
                }
                _ => return Err(integrity("candidate-generator-domain-family-mismatch")),
            }
        }
        Ok(())
    }

    pub(in crate::repository) fn validate_branch_request_campaign_scope(
        &self,
        snapshot: &LoadedSnapshot,
        request: &BranchRequest,
        parent: &ConfigurationArtifact,
    ) -> Result<(), CampaignRepositoryError> {
        let lineage = self.read_lineage(required_child(&snapshot.envelope, "lineage")?)?;
        let active_policy = self.read_policy(snapshot.snapshot.active_policy().content_id())?;
        self.validate_statistical_request_policy(snapshot, &lineage, &active_policy, request)?;
        if parent.scenario() != lineage.scenario() {
            return Err(integrity("branch-request-parent-scenario-mismatch"));
        }
        let expected_parent = self.merkle.get(
            snapshot.snapshot.roots().graph,
            map_key_hash("graph.configuration", parent.configuration().as_hash()),
        )?;
        if expected_parent != Some(request.parent().content_id()) {
            return Err(integrity("branch-request-parent-is-not-in-campaign-graph"));
        }
        if self.merkle.get(
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
                let invocation = self.load_planner_invocation(invocation)?;
                if invocation.policy() != snapshot.snapshot.active_policy() {
                    return Err(integrity("branch-request-planner-policy-is-not-active"));
                }
                if invocation.input_view() != snapshot.snapshot.planning_view().id()? {
                    return Err(integrity("branch-request-planner-view-is-not-current"));
                }
            }
            BranchRequestCause::ExhaustivePolicy(policy)
                if policy != snapshot.snapshot.active_policy() =>
            {
                return Err(integrity("branch-request-policy-is-not-active"));
            }
            BranchRequestCause::ScenarioDefault(policy)
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
        &self,
        snapshot: &LoadedSnapshot,
        lineage: &CampaignLineage,
        policy: &CampaignPolicy,
        request: &BranchRequest,
    ) -> Result<(), CampaignRepositoryError> {
        let source = match request.source() {
            CandidateSource::StatisticalFinite(source) => source,
            CandidateSource::StatisticalSmc(_)
                if policy.mode() == CampaignMode::Statistical
                    && policy.sequential_monte_carlo_design().is_some() =>
            {
                return Ok(());
            }
            _ if policy.mode() == CampaignMode::Statistical => {
                return Err(integrity("statistical-policy-requires-statistical-request"));
            }
            _ => return Ok(()),
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
            || request.stop() != draw.stop()
            || request.budget() != BranchBudget::new(1, 1)?
            || request.branch_point() != expected_branch_point
            || opportunity.id()? != draw.opportunity()
            || opportunity.semantic_id() != draw.opportunity_semantics()
            || opportunity.domain() != draw.domain()
            || opportunity.model_prior() != Some(draw.model())
            || self.merkle.get(
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
            .merkle
            .get(
                snapshot.snapshot.roots().accounting,
                statistical_draw_proposal_key(parent_coordinate),
            )?
            .ok_or_else(|| integrity("statistical-parent-draw-is-not-admitted"))?;
        let parent_proposal = self.read_proposal(parent_proposal_content)?;
        let CandidateSource::StatisticalFinite(parent_source) = self
            .read_branch_request(parent_proposal.request().content_id())?
            .source()
            .clone()
        else {
            return Err(integrity("statistical-parent-draw-source-mismatch"));
        };
        if parent_source.coordinate() != parent_coordinate {
            return Err(integrity("statistical-parent-draw-coordinate-mismatch"));
        }
        let admission_content = self
            .merkle
            .get(
                snapshot.snapshot.roots().accounting,
                map_key_content("accounting.proposal-admission", parent_proposal_content),
            )?
            .ok_or_else(|| integrity("statistical-parent-draw-admission-is-missing"))?;
        let admission = self.read_attempt_admission(admission_content)?;
        let observation_content = self
            .merkle
            .get(
                snapshot.snapshot.roots().observations,
                map_key_content("observations.attempt", admission.attempt().content_id()),
            )?
            .ok_or_else(|| integrity("statistical-parent-draw-observation-is-missing"))?;
        let observation = self.read_observation(observation_content)?;
        if observation.attempt() != admission.attempt()
            || observation.child_content() != request.parent()
            || observation.child() != parent.configuration()
        {
            return Err(integrity("statistical-parent-draw-endpoint-mismatch"));
        }
        self.validate_statistical_attempt_basis(snapshot, admission.attempt())
    }

    pub(in crate::repository) fn validate_smc_request_policy(
        &self,
        snapshot: &LoadedSnapshot,
        policy: &CampaignPolicy,
        generation: &crate::StatisticalGeneration,
        particle: &crate::StatisticalParticleSlot,
        request: &BranchRequest,
    ) -> Result<(), CampaignRepositoryError> {
        let CandidateSource::StatisticalSmc(source) = request.source() else {
            return Err(integrity("SMC policy requires an SMC transition request"));
        };
        if policy.mode() != CampaignMode::Statistical
            || generation.policy() != snapshot.snapshot.active_policy()
            || source.generation() != generation.id()
            || source.input_particle() != particle.id()
            || source.stage() != generation.next_stage()
            || source.slot() != particle.slot()
        {
            return Err(integrity("SMC request generation basis mismatch"));
        }
        let design = policy
            .sequential_monte_carlo_design()
            .ok_or_else(|| integrity("SMC request requires an SMC design"))?;
        let stage = design
            .stage(source.stage())
            .ok_or_else(|| integrity("SMC request stage is not planned"))?;
        let distribution = design
            .distributions()
            .get(&stage.selector().model())
            .ok_or_else(|| integrity("SMC request model is not planned"))?;
        let basis = self.resolve_smc_request_basis(snapshot, policy, generation, particle)?;
        let BranchRequestCause::Planner(invocation) = request.cause() else {
            return Err(integrity("SMC request cause is not a planner"));
        };
        let expected = BranchRequest::new(
            basis.opportunity().branch_point_id(basis.configuration()),
            basis.parent(),
            basis.opportunity().id()?,
            basis.domain().id()?,
            CandidateSource::statistical_smc(
                generation.id(),
                particle.id(),
                source.stage(),
                source.slot(),
                stage.selector().model(),
                distribution.target_masses().clone(),
                distribution.proposal_masses().clone(),
            )?,
            BranchRequestCause::Planner(invocation),
            BranchBudget::new(1, 1)?,
            stage.selector().stop().clone(),
        )?;
        if &expected != request {
            return Err(integrity("SMC request disagrees with owner replay"));
        }
        Ok(())
    }

    pub(in crate::repository) fn validate_statistical_attempt_basis(
        &self,
        snapshot: &LoadedSnapshot,
        attempt: AttemptId,
    ) -> Result<(), CampaignRepositoryError> {
        let basis_content = self
            .merkle
            .get(
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
        let request = self.read_branch_request(proposal.request().content_id())?;
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

    pub(in crate::repository) fn validate_proposal_campaign_scope(
        &self,
        snapshot: &LoadedSnapshot,
        proposal: &Proposal,
    ) -> Result<BranchRequest, CampaignRepositoryError> {
        let request = self.read_branch_request(proposal.request().content_id())?;
        let request_key = map_key_content(
            "exploration.branch-request",
            proposal.request().content_id(),
        );
        if self
            .merkle
            .get(snapshot.snapshot.roots().exploration, request_key)?
            != Some(proposal.request().content_id())
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
            let invocation = self.load_planner_invocation(invocation)?;
            if invocation.policy() != proposal.policy()
                || invocation.input_view() != proposal.guidance_basis()
            {
                return Err(integrity("proposal-planner-invocation-mismatch"));
            }
        }

        let completed_visits = self.branch_completed_visits(
            snapshot.snapshot.roots().observations,
            request.branch_point(),
        )?;
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
                super::projection::CandidateEnumerationBasis::new(
                    super::projection::CandidateViewRoots::from_roots(snapshot.snapshot.roots()),
                    completed_visits,
                )
                .with_feedback(feedback_projection.as_ref().map(|projection| {
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
        Ok(request)
    }

    pub(in crate::repository) fn validate_proposal_references_shallow(
        &self,
        proposal: &Proposal,
    ) -> Result<(), CampaignRepositoryError> {
        let request = self.decode_branch_request(proposal.request().content_id())?;
        let domain = self.read_choice_domain(proposal.domain().content_id())?;
        proposal.validate_resolved(&request, &domain)?;
        self.read_policy(proposal.policy().content_id())?;
        self.require_record_kind(
            proposal.guidance_basis().content_id(),
            crate::CampaignRecordKind::PlanningView,
        )?;
        if let Some(invocation_id) = proposal.planner_invocation() {
            let (_, invocation) = self.decode_planner_invocation(invocation_id.content_id())?;
            if invocation.policy() != proposal.policy()
                || invocation.input_view() != proposal.guidance_basis()
            {
                return Err(integrity("proposal-planner-invocation-mismatch"));
            }
        }
        Ok(())
    }

    pub(in crate::repository) fn read_proposal(
        &self,
        id: ContentId,
    ) -> Result<Proposal, CampaignRepositoryError> {
        let proposal = self.decode_proposal(id)?;
        let request = self.read_branch_request(proposal.request().content_id())?;
        let domain = self.read_choice_domain(proposal.domain().content_id())?;
        proposal.validate_resolved(&request, &domain)?;
        self.read_policy(proposal.policy().content_id())?;
        self.require_record_kind(
            proposal.guidance_basis().content_id(),
            crate::CampaignRecordKind::PlanningView,
        )?;
        if let Some(invocation) = proposal.planner_invocation() {
            let invocation = self.load_planner_invocation(invocation)?;
            if invocation.policy() != proposal.policy()
                || invocation.input_view() != proposal.guidance_basis()
            {
                return Err(integrity("proposal-planner-invocation-mismatch"));
            }
        }
        Ok(proposal)
    }

    pub(in crate::repository) fn decode_proposal(
        &self,
        id: ContentId,
    ) -> Result<Proposal, CampaignRepositoryError> {
        let envelope = self.require_record_kind(id, crate::CampaignRecordKind::Proposal)?;
        let proposal = Proposal::from_canonical_bytes(envelope.body())?;
        if proposal.id()?.content_id() != id {
            return Err(integrity("proposal-envelope-shape"));
        }
        Ok(proposal)
    }
}
