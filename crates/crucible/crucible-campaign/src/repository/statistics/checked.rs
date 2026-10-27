//! Checked semantic replay for planner statistical request bases.

use super::*;
use crate::BranchBudget;
use crate::repository::closure::read::ClosureSemanticRead;

impl ClosureSemanticRead<'_, '_> {
    pub(in crate::repository) fn statistical_request_basis(
        &mut self,
        snapshot: &LoadedSnapshot,
        policy: &CampaignPolicy,
    ) -> Result<Option<crate::StatisticalRequestBasis>, CampaignRepositoryError> {
        let _operation = self.enter_operation();
        let Some(design) = policy.statistical_sampling_design() else {
            return Ok(None);
        };
        let mut coordinate = None;
        for candidate in design.draws().keys().copied() {
            if self
                .merkle_get(
                    snapshot.snapshot.roots().exploration,
                    statistical_draw_request_key(candidate),
                )?
                .is_none()
            {
                coordinate = Some(candidate);
                break;
            }
        }
        let Some(coordinate) = coordinate else {
            return Ok(None);
        };
        for prior_coordinate in 0..coordinate {
            if self
                .merkle_get(
                    snapshot.snapshot.roots().accounting,
                    statistical_draw_proposal_key(prior_coordinate),
                )?
                .is_none()
            {
                return Ok(None);
            }
        }
        let draw = design
            .draw(coordinate)
            .ok_or_else(|| integrity("statistical-request-coordinate-is-not-planned"))?;
        let lineage = self.read_lineage(required_child(&snapshot.envelope, "lineage")?)?;
        let (parent, configuration) = match draw.parent() {
            None => (lineage.genesis_content(), lineage.genesis()),
            Some(parent_coordinate) => {
                let Some(proposal_content) = self.merkle_get(
                    snapshot.snapshot.roots().accounting,
                    statistical_draw_proposal_key(parent_coordinate),
                )?
                else {
                    return Ok(None);
                };
                let proposal = self.read_proposal(proposal_content)?;
                let parent_request = self.read_branch_request(proposal.request())?;
                let CandidateSource::StatisticalFinite(parent_source) = parent_request.source()
                else {
                    return Err(integrity("statistical-parent-draw-source-mismatch"));
                };
                if parent_source.coordinate() != parent_coordinate {
                    return Err(integrity("statistical-parent-draw-coordinate-mismatch"));
                }
                let admission_content = self
                    .merkle_get(
                        snapshot.snapshot.roots().accounting,
                        map_key_content("accounting.proposal-admission", proposal_content),
                    )?
                    .ok_or_else(|| integrity("statistical-parent-draw-admission-is-missing"))?;
                let admission = self.read_attempt_admission(admission_content)?;
                self.validate_statistical_attempt_basis_checked(snapshot, admission.attempt())?;
                let Some(observation_content) = self.merkle_get(
                    snapshot.snapshot.roots().observations,
                    map_key_content("observations.attempt", admission.attempt().content_id()),
                )?
                else {
                    return Ok(None);
                };
                let observation = self.read_observation_checked(observation_content)?;
                if observation.attempt() != admission.attempt()
                    || !observation.stop().reaches(parent_request.stop())
                {
                    return Err(integrity("statistical-parent-draw-cannot-continue"));
                }
                (observation.child_content(), observation.child())
            }
        };
        let parent_artifact = self.read_configuration_artifact(parent.content_id())?;
        if parent_artifact.configuration() != configuration
            || self.merkle_get(
                snapshot.snapshot.roots().graph,
                map_key_hash("graph.configuration", configuration.as_hash()),
            )? != Some(parent.content_id())
        {
            return Err(integrity("statistical-request-parent-is-not-authoritative"));
        }
        let opportunity = self.read_opportunity(draw.opportunity().content_id())?;
        if opportunity.id()? != draw.opportunity()
            || opportunity.semantic_id() != draw.opportunity_semantics()
            || opportunity.domain() != draw.domain()
            || opportunity.model_prior() != Some(draw.model())
        {
            return Err(integrity("statistical-design-opportunity-basis-mismatch"));
        }
        let branch_point = opportunity.branch_point_id(configuration);
        if self.merkle_get(
            snapshot.snapshot.roots().graph,
            branch_point_opportunity_key(branch_point, draw.opportunity()),
        )? != Some(draw.opportunity().content_id())
        {
            return Err(integrity(
                "statistical-draw-opportunity-is-not-authoritative",
            ));
        }
        Ok(Some(crate::StatisticalRequestBasis::new(
            coordinate,
            parent,
            configuration,
        )))
    }

    pub(in crate::repository) fn smc_request_basis(
        &mut self,
        snapshot: &LoadedSnapshot,
        policy: &CampaignPolicy,
    ) -> Result<Option<crate::SmcRequestBasis>, CampaignRepositoryError> {
        let _operation = self.enter_operation();
        let Some(design) = policy.sequential_monte_carlo_design() else {
            return Ok(None);
        };
        if !self.initial_statistical_stage_is_complete(snapshot, policy)? {
            return Ok(None);
        }
        let mut generation = self.initial_smc_generation_from_loaded(snapshot, policy)?;
        for stage in design.stages().keys().copied() {
            if generation.next_stage() != stage {
                return Err(integrity("SMC replay generation stage is not canonical"));
            }
            for particle in generation.slots() {
                let request = self.merkle_get(
                    snapshot.snapshot.roots().exploration,
                    smc_transition_request_key(stage, particle.slot()),
                )?;
                if request.is_none() {
                    return self
                        .resolve_smc_request_basis(snapshot, policy, &generation, particle)
                        .map(Some);
                }
                if self
                    .merkle_get(
                        snapshot.snapshot.roots().accounting,
                        smc_transition_proposal_key(stage, particle.slot()),
                    )?
                    .is_none()
                {
                    return Ok(None);
                }
            }

            let Some(outcomes) = self.completed_smc_stage(snapshot, policy, &generation)? else {
                return Ok(None);
            };
            if design.stage(stage.saturating_add(1)).is_none() {
                return Ok(None);
            }
            self.poll()?;
            generation = StatisticalGeneration::from_completed_stage(
                snapshot.snapshot.active_policy(),
                policy.campaign_seed(),
                design,
                stage,
                &outcomes,
            )?;
        }
        Ok(None)
    }

    fn initial_statistical_stage_is_complete(
        &mut self,
        snapshot: &LoadedSnapshot,
        policy: &CampaignPolicy,
    ) -> Result<bool, CampaignRepositoryError> {
        let design = policy
            .statistical_sampling_design()
            .ok_or_else(|| integrity("SMC policy lacks an initial sampling design"))?;
        for coordinate in design.draws().keys().copied() {
            let Some(proposal) = self.merkle_get(
                snapshot.snapshot.roots().accounting,
                statistical_draw_proposal_key(coordinate),
            )?
            else {
                return Ok(false);
            };
            let Some(admission) = self.merkle_get(
                snapshot.snapshot.roots().accounting,
                map_key_content("accounting.proposal-admission", proposal),
            )?
            else {
                return Ok(false);
            };
            let admission = self.read_attempt_admission(admission)?;
            if self
                .merkle_get(
                    snapshot.snapshot.roots().observations,
                    map_key_content("observations.attempt", admission.attempt().content_id()),
                )?
                .is_none()
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn initial_smc_generation_from_loaded(
        &mut self,
        snapshot: &LoadedSnapshot,
        policy: &CampaignPolicy,
    ) -> Result<StatisticalGeneration, CampaignRepositoryError> {
        self.validate_initial_smc_transition_sources(snapshot, policy)?;
        let evidence = self.collect_finite_statistical_evidence(snapshot, policy, true)?;
        self.poll()?;
        let initial = verify_initial_smc_statistical_evidence(&evidence)?;
        let design = policy
            .sequential_monte_carlo_design()
            .ok_or_else(|| integrity("SMC generation requires an SMC policy"))?;
        StatisticalGeneration::from_initial_report(
            initial.policy(),
            policy.campaign_seed(),
            design,
            &initial,
        )
        .map_err(Into::into)
    }

    fn validate_initial_smc_transition_sources(
        &mut self,
        snapshot: &LoadedSnapshot,
        policy: &CampaignPolicy,
    ) -> Result<(), CampaignRepositoryError> {
        let initial = policy
            .statistical_sampling_design()
            .ok_or_else(|| integrity("SMC policy lacks an initial sampling design"))?;
        for coordinate in initial.draws().keys().copied() {
            let request_content = self
                .merkle_get(
                    snapshot.snapshot.roots().exploration,
                    statistical_draw_request_key(coordinate),
                )?
                .ok_or_else(|| integrity("SMC initial transition request is missing"))?;
            let request =
                self.read_branch_request(BranchRequestId::from_content_id(request_content)?)?;
            let proposal_content = self
                .merkle_get(
                    snapshot.snapshot.roots().accounting,
                    statistical_draw_proposal_key(coordinate),
                )?
                .ok_or_else(|| integrity("SMC initial transition proposal is missing"))?;
            let admission_content = self
                .merkle_get(
                    snapshot.snapshot.roots().accounting,
                    map_key_content("accounting.proposal-admission", proposal_content),
                )?
                .ok_or_else(|| integrity("SMC initial transition admission is missing"))?;
            let admission = self.read_attempt_admission(admission_content)?;
            let observation_content = self
                .merkle_get(
                    snapshot.snapshot.roots().observations,
                    map_key_content("observations.attempt", admission.attempt().content_id()),
                )?
                .ok_or_else(|| integrity("SMC initial transition observation is missing"))?;
            let observation = self.read_observation_checked(observation_content)?;
            if !observation.stop().reaches(request.stop()) {
                return Err(integrity(
                    "SMC initial transition did not reach its declared stop",
                ));
            }
        }
        Ok(())
    }

    fn resolve_smc_request_basis(
        &mut self,
        snapshot: &LoadedSnapshot,
        policy: &CampaignPolicy,
        generation: &StatisticalGeneration,
        particle: &crate::StatisticalParticleSlot,
    ) -> Result<crate::SmcRequestBasis, CampaignRepositoryError> {
        if generation.policy() != snapshot.snapshot.active_policy()
            || particle.generation() != generation.next_stage()
        {
            return Err(integrity(
                "SMC request basis generation is not authoritative",
            ));
        }
        let observation = self.read_observation_checked(particle.observation().content_id())?;
        let source_proposal = self.read_proposal(particle.proposal().content_id())?;
        let source_request = self.read_branch_request(source_proposal.request())?;
        if observation.id()? != particle.observation()
            || observation.path() != particle.path()
            || !observation.stop().reaches(source_request.stop())
        {
            return Err(integrity(
                "SMC particle source observation identity mismatch",
            ));
        }
        let parent = self.read_configuration_artifact(observation.child_content().content_id())?;
        if parent.id()? != observation.child_content()
            || parent.configuration() != observation.child()
            || self.merkle_get(
                snapshot.snapshot.roots().graph,
                map_key_hash("graph.configuration", observation.child().as_hash()),
            )? != Some(observation.child_content().content_id())
        {
            return Err(integrity("SMC request parent is not authoritative"));
        }
        let selector = generation.selector();
        let mut selected = None;
        for opportunity_id in observation.discovered_choices().iter().copied() {
            let opportunity = self.read_opportunity(opportunity_id.content_id())?;
            if opportunity.declaration_semantics() == selector.declaration()
                && opportunity.domain_semantics() == selector.domain()
                && opportunity.instance() == selector.instance()
                && opportunity.model_prior() == Some(selector.model())
                && selected.replace(opportunity).is_some()
            {
                return Err(integrity("SMC selector matches multiple opportunities"));
            }
        }
        let opportunity = selected.ok_or_else(|| {
            if matches!(
                observation.stop(),
                StopOutcome::TerminalSuccess
                    | StopOutcome::ModeledTimeout(_)
                    | StopOutcome::BoundedPrimaryTimeout { .. }
                    | StopOutcome::PolicyTimeout { .. }
                    | StopOutcome::GuestCrash(_)
                    | StopOutcome::AssertionFailure(_)
                    | StopOutcome::ScenarioFailure(_)
            ) {
                integrity("SMC selector cannot continue from a terminal particle")
            } else {
                integrity("SMC selector has no matching discovered opportunity")
            }
        })?;
        let branch_point = opportunity.branch_point_id(observation.child());
        if self.merkle_get(
            snapshot.snapshot.roots().graph,
            branch_point_opportunity_key(branch_point, opportunity.id()?),
        )? != Some(opportunity.id()?.content_id())
        {
            return Err(integrity("SMC selected opportunity is not authoritative"));
        }
        let domain = self.read_choice_domain(opportunity.domain().content_id())?;
        let design = policy
            .sequential_monte_carlo_design()
            .ok_or_else(|| integrity("SMC request basis requires an SMC policy"))?;
        let distribution = design
            .distributions()
            .get(&selector.model())
            .ok_or_else(|| integrity("SMC selector model is not planned"))?;
        if domain.id()? != opportunity.domain()
            || domain.cardinality() != distribution.target_masses().len() as u128
            || distribution
                .target_masses()
                .keys()
                .any(|value| !domain.contains(value))
        {
            return Err(integrity("SMC selected opportunity support drifted"));
        }
        crate::SmcRequestBasis::new(
            generation.id(),
            crate::codec::admitted_clone(particle)?,
            observation.child_content(),
            observation.child(),
            opportunity,
            domain,
        )
        .map_err(Into::into)
    }

    fn completed_smc_stage(
        &mut self,
        snapshot: &LoadedSnapshot,
        policy: &CampaignPolicy,
        generation: &StatisticalGeneration,
    ) -> Result<Option<Vec<StatisticalParticleOutcome>>, CampaignRepositoryError> {
        let mut outcomes = Vec::new();
        for particle in generation.slots() {
            let request_content = self
                .merkle_get(
                    snapshot.snapshot.roots().exploration,
                    smc_transition_request_key(generation.next_stage(), particle.slot()),
                )?
                .ok_or_else(|| integrity("SMC transition request is missing"))?;
            let request =
                self.read_branch_request(BranchRequestId::from_content_id(request_content)?)?;
            self.validate_smc_request_policy(snapshot, policy, generation, particle, &request)?;

            let Some(proposal_content) = self.merkle_get(
                snapshot.snapshot.roots().accounting,
                smc_transition_proposal_key(generation.next_stage(), particle.slot()),
            )?
            else {
                return Ok(None);
            };
            let proposal_id = ProposalId::from_content_id(proposal_content)?;
            let proposal = self.read_proposal(proposal_content)?;
            let domain = self.read_choice_domain(request.domain().content_id())?;
            proposal.validate_resolved(&request, &domain)?;
            if proposal.request().content_id() != request_content
                || proposal.statistical_evidence().is_none()
            {
                return Err(integrity("SMC transition proposal mismatch"));
            }
            let admission_content = self
                .merkle_get(
                    snapshot.snapshot.roots().accounting,
                    map_key_content("accounting.proposal-admission", proposal_content),
                )?
                .ok_or_else(|| integrity("SMC transition admission is missing"))?;
            let admission = self.read_attempt_admission(admission_content)?;
            let admitted_proposal = match admission.role() {
                AttemptAdmissionRole::ExecutionBasis {
                    proposal: Some(proposal),
                    ..
                }
                | AttemptAdmissionRole::AdditionalCause { proposal } => proposal,
                AttemptAdmissionRole::ExecutionBasis { proposal: None, .. } => {
                    return Err(integrity("SMC transition admission has no proposal"));
                }
            };
            if admitted_proposal != proposal_id {
                return Err(integrity("SMC transition admission mismatch"));
            }
            self.validate_statistical_attempt_basis_checked(snapshot, admission.attempt())?;

            let Some(observation_content) = self.merkle_get(
                snapshot.snapshot.roots().observations,
                map_key_content("observations.attempt", admission.attempt().content_id()),
            )?
            else {
                return Ok(None);
            };
            let observation_id = ObservationId::from_content_id(observation_content)?;
            let observation = self.read_observation_checked(observation_content)?;
            let attempt = self.read_attempt_cached(
                admission.attempt().content_id(),
                &mut ChoiceValidationCache::default(),
            )?;
            if observation.attempt() != admission.attempt() || observation.path() != attempt.path()
            {
                return Err(integrity("SMC transition observation mismatch"));
            }
            let design = policy
                .sequential_monte_carlo_design()
                .ok_or_else(|| integrity("SMC transition requires an SMC design"))?;
            if design
                .stage(generation.next_stage().saturating_add(1))
                .is_some()
                && !observation.stop().reaches(request.stop())
            {
                return Err(integrity(
                    "nonfinal SMC transition did not reach its declared stop",
                ));
            }
            let AttemptStart::Branch {
                edge,
                parent,
                selection,
            } = attempt.start()
            else {
                return Err(integrity("SMC transition attempt is not a branch"));
            };
            if parent != request.parent() {
                return Err(integrity("SMC transition attempt parent mismatch"));
            }
            let (selection, _, _, _) = self.resolve_selection_for_statistics(selection)?;
            let crate::SelectionOrigin::CampaignBranch {
                branch_point,
                edge: selected_edge,
            } = selection.origin()
            else {
                return Err(integrity("SMC transition selection origin mismatch"));
            };
            if branch_point != proposal.branch_point()
                || edge != selected_edge
                || selection.value() != proposal.value()
            {
                return Err(integrity("SMC transition selection mismatch"));
            }
            let path = self.read_branch_path(attempt.path().content_id())?;
            let segments = path.segments();
            let source_path = self.read_branch_path(particle.path().content_id())?;
            let source_segments = source_path.segments();
            let Some(terminal) = segments.last().copied() else {
                return Err(integrity("SMC transition path is empty"));
            };
            if terminal.branch_point() != proposal.branch_point()
                || terminal.edge() != edge
                || segments.len() != source_segments.len().saturating_add(1)
                || !segments.starts_with(source_segments)
            {
                return Err(integrity("SMC transition path ancestry mismatch"));
            }
            let evidence = proposal
                .statistical_evidence()
                .ok_or_else(|| integrity("SMC transition evidence is missing"))?;
            let target_probability = particle
                .cumulative_target_probability()
                .checked_multiply(statistical_target_probability(evidence)?)?;
            let proposal_probability = particle
                .cumulative_proposal_probability()
                .checked_multiply(statistical_proposal_probability(evidence)?)?;
            let branch_weight = statistical_target_probability(evidence)?
                .checked_divide(statistical_proposal_probability(evidence)?)?;
            let estimator_weight = particle
                .estimator_weight()
                .checked_multiply(branch_weight)?;
            let outcome = StatisticalParticleOutcome::new(
                generation.next_stage(),
                particle.slot(),
                particle.id(),
                particle.source_coordinate(),
                proposal_id,
                admission.attempt(),
                observation_id,
                attempt.path(),
                target_probability,
                proposal_probability,
                estimator_weight,
            )?;
            self.push(&mut outcomes, outcome)?;
        }
        Ok(Some(outcomes))
    }

    fn validate_smc_request_policy(
        &mut self,
        snapshot: &LoadedSnapshot,
        policy: &CampaignPolicy,
        generation: &StatisticalGeneration,
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
            BranchRequest::identity(
                basis.opportunity().branch_point_id(basis.configuration()),
                basis.parent(),
                basis.opportunity().id()?,
                basis.domain().id()?,
            ),
            CandidateSource::statistical_smc(
                generation.id(),
                particle.id(),
                source.stage(),
                source.slot(),
                stage.selector().model(),
                crate::codec::admitted_clone(distribution.target_masses())?,
                crate::codec::admitted_clone(distribution.proposal_masses())?,
            )?,
            BranchRequestCause::Planner(invocation),
            BranchBudget::new(1, 1)?,
            policy.bound_stop(crate::codec::admitted_clone(stage.selector().stop())?)?,
        )?;
        if &expected != request {
            return Err(integrity("SMC request disagrees with owner replay"));
        }
        Ok(())
    }

    fn validate_statistical_attempt_basis_checked(
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

    fn collect_finite_statistical_evidence(
        &mut self,
        snapshot: &LoadedSnapshot,
        policy: &CampaignPolicy,
        allow_smc: bool,
    ) -> Result<FiniteStatisticalEvidence, CampaignRepositoryError> {
        if policy.mode() != CampaignMode::Statistical {
            return Err(integrity("statistical-report-requires-statistical-policy"));
        }
        if policy.sequential_monte_carlo_design().is_some() != allow_smc {
            return Err(if allow_smc {
                integrity("SMC generation requires an SMC policy")
            } else {
                integrity("statistical report refuses incomplete SMC policy")
            });
        }
        let design = policy
            .statistical_sampling_design()
            .ok_or_else(|| integrity("statistical-report-policy-lacks-design"))?;
        let lineage = self.read_lineage(required_child(&snapshot.envelope, "lineage")?)?;
        let snapshot_bytes = crate::codec::encoded_length(&snapshot.snapshot)?;
        let planning_view_bytes = crate::codec::encoded_length(&snapshot.snapshot.planning_view())?;
        let policy_bytes = crate::codec::encoded_length(policy)?;
        let lineage_bytes = crate::codec::encoded_length(&lineage)?;
        let mut charged_bytes = snapshot_bytes
            .checked_add(planning_view_bytes)
            .and_then(|bytes| bytes.checked_add(policy_bytes))
            .and_then(|bytes| bytes.checked_add(lineage_bytes))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<u64>()))
            .ok_or_else(|| integrity("finite evidence byte accounting overflows"))?;
        charge_statistical_evidence(&mut charged_bytes, 0)?;
        let mut draws = Vec::new();

        for coordinate in design.draws().keys().copied() {
            let request_content = self
                .merkle_get(
                    snapshot.snapshot.roots().exploration,
                    statistical_draw_request_key(coordinate),
                )?
                .ok_or_else(|| integrity("statistical-report-draw-request-is-missing"))?;
            let proposal_content = self
                .merkle_get(
                    snapshot.snapshot.roots().accounting,
                    statistical_draw_proposal_key(coordinate),
                )?
                .ok_or_else(|| integrity("statistical-report-draw-proposal-is-missing"))?;
            let remaining_bytes =
                remaining_statistical_evidence_bytes(charged_bytes, std::mem::size_of::<u64>())?;
            let execution = self.collect_statistical_execution_evidence(
                snapshot,
                request_content,
                proposal_content,
                remaining_bytes,
            )?;
            let draw = StatisticalDrawEvidence::new(coordinate, execution);
            charge_statistical_evidence(&mut charged_bytes, crate::codec::encoded_length(&draw)?)?;
            self.push(&mut draws, draw)?;
        }

        Ok(FiniteStatisticalEvidence::new(
            crate::codec::admitted_clone(&snapshot.snapshot)?,
            snapshot.snapshot.planning_view(),
            crate::codec::admitted_clone(policy)?,
            lineage,
            draws,
        ))
    }

    fn collect_statistical_execution_evidence(
        &mut self,
        snapshot: &LoadedSnapshot,
        request_content: ContentId,
        proposal_content: ContentId,
        maximum_bytes: usize,
    ) -> Result<StatisticalExecutionEvidence, CampaignRepositoryError> {
        let mut charged_bytes = std::mem::size_of::<u64>();
        let request =
            self.read_branch_request(BranchRequestId::from_content_id(request_content)?)?;
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encoded_length(&request)?,
            maximum_bytes,
        )?;
        let parent = self.read_configuration_artifact(request.parent().content_id())?;
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encoded_length(&parent)?,
            maximum_bytes,
        )?;
        let request_opportunity =
            self.collect_statistical_opportunity_evidence(request.opportunity())?;
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encoded_length(&request_opportunity)?,
            maximum_bytes,
        )?;
        let proposal = self.read_proposal(proposal_content)?;
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encoded_length(&proposal)?,
            maximum_bytes,
        )?;

        let proposal_admission_content = self
            .merkle_get(
                snapshot.snapshot.roots().accounting,
                map_key_content("accounting.proposal-admission", proposal_content),
            )?
            .ok_or_else(|| integrity("statistical evidence proposal admission is missing"))?;
        let proposal_admission = self.read_attempt_admission(proposal_admission_content)?;
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encoded_length(&proposal_admission)?,
            maximum_bytes,
        )?;
        let attempt_id = proposal_admission.attempt();
        let attempt = self.read_attempt_cached(
            attempt_id.content_id(),
            &mut ChoiceValidationCache::default(),
        )?;
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encoded_length(&attempt)?,
            maximum_bytes,
        )?;
        let AttemptStart::Branch { selection, .. } = attempt.start() else {
            return Err(integrity("statistical evidence attempt is not a branch"));
        };
        let (selection, opportunity, declaration, domain) =
            self.resolve_selection_for_statistics(selection)?;
        let choice = StatisticalChoiceEvidence::new(
            selection,
            StatisticalOpportunityEvidence::new(opportunity, declaration, domain),
        );
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encoded_length(&choice)?,
            maximum_bytes,
        )?;

        let path = self.read_branch_path(attempt.path().content_id())?;
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encoded_length(&path)?,
            maximum_bytes,
        )?;

        let observation_content = self
            .merkle_get(
                snapshot.snapshot.roots().observations,
                map_key_content("observations.attempt", attempt_id.content_id()),
            )?
            .ok_or_else(|| integrity("statistical-report-draw-observation-is-missing"))?;
        let observation = self.read_observation_checked(observation_content)?;
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encoded_length(&observation)?,
            maximum_bytes,
        )?;
        let child = self.read_configuration_artifact(observation.child_content().content_id())?;
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encoded_length(&child)?,
            maximum_bytes,
        )?;
        let mut discovered_opportunities = Vec::new();
        for opportunity in observation.discovered_choices().iter().copied() {
            let opportunity = self.collect_statistical_opportunity_evidence(opportunity)?;
            charge_statistical_execution_evidence(
                &mut charged_bytes,
                crate::codec::encoded_length(&opportunity)?,
                maximum_bytes,
            )?;
            self.push(&mut discovered_opportunities, opportunity)?;
        }

        let basis_content = self
            .merkle_get(
                snapshot.snapshot.roots().accounting,
                map_key_content(
                    "accounting.attempt-execution-basis",
                    attempt_id.content_id(),
                ),
            )?
            .ok_or_else(|| integrity("statistical evidence execution basis is missing"))?;
        let basis_admission = self.read_attempt_admission(basis_content)?;
        let AttemptAdmissionRole::ExecutionBasis {
            proposal: Some(basis_proposal),
            ..
        } = basis_admission.role()
        else {
            return Err(integrity(
                "statistical evidence execution basis has no proposal",
            ));
        };
        let basis_proposal = self.read_proposal(basis_proposal.content_id())?;
        let basis_request = self.read_branch_request(basis_proposal.request())?;
        let execution_basis =
            StatisticalExecutionBasisEvidence::new(basis_admission, basis_proposal, basis_request);
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encoded_length(&execution_basis)?,
            maximum_bytes,
        )?;

        let evidence = StatisticalExecutionEvidence::new(
            request,
            parent,
            request_opportunity,
            proposal,
            proposal_admission,
            execution_basis,
            attempt,
            choice,
            path,
            observation,
            child,
            discovered_opportunities,
        );
        debug_assert_eq!(charged_bytes, crate::codec::encoded_length(&evidence)?);
        Ok(evidence)
    }

    fn collect_statistical_opportunity_evidence(
        &mut self,
        id: ChoiceOpportunityId,
    ) -> Result<StatisticalOpportunityEvidence, CampaignRepositoryError> {
        let envelope = self.read_envelope(id.content_id())?;
        if envelope.record_kind() != crate::CampaignRecordKind::ChoiceOpportunity {
            return Err(integrity("choice-opportunity-envelope-shape"));
        }
        let opportunity = crate::codec::decode::<ChoiceOpportunity>(envelope.body())?;
        if opportunity.id()? != id {
            return Err(integrity("choice-opportunity-envelope-shape"));
        }
        let declaration = self.read_selectable(opportunity.declaration().content_id())?;
        let domain = self.read_choice_domain(opportunity.domain().content_id())?;
        opportunity.validate_references(&declaration, &domain)?;
        Ok(StatisticalOpportunityEvidence::new(
            opportunity,
            declaration,
            domain,
        ))
    }

    fn read_observation_checked(
        &mut self,
        id: ContentId,
    ) -> Result<Observation, CampaignRepositoryError> {
        let observation = self.decode_observation(id)?;
        self.validate_observation_references_cached(
            &observation,
            &mut ChoiceValidationCache::default(),
        )?;
        Ok(observation)
    }

    fn resolve_selection_for_statistics(
        &mut self,
        id: SelectionId,
    ) -> Result<
        (
            Selection,
            ChoiceOpportunity,
            SelectableDeclaration,
            ChoiceDomain,
        ),
        CampaignRepositoryError,
    > {
        let mut charged_bytes = 0_usize;
        let selection_envelope =
            self.require_record_kind(id.content_id(), crate::CampaignRecordKind::Selection)?;
        charge_selection_resolution_record(&selection_envelope, &mut charged_bytes)?;
        let selection = Selection::from_canonical_bytes(selection_envelope.body())?;
        if selection.id()? != id {
            return Err(integrity("selection-envelope-shape"));
        }

        let opportunity_id = required_child(&selection_envelope, "opportunity")?;
        let selection_domain_id = required_child(&selection_envelope, "domain")?;
        let opportunity_envelope =
            self.require_record_kind(opportunity_id, crate::CampaignRecordKind::ChoiceOpportunity)?;
        charge_selection_resolution_record(&opportunity_envelope, &mut charged_bytes)?;
        let opportunity = crate::codec::decode::<ChoiceOpportunity>(opportunity_envelope.body())?;
        if opportunity.id()?.content_id() != opportunity_id {
            return Err(integrity("choice-opportunity-envelope-shape"));
        }

        let declaration_id = opportunity.declaration().content_id();
        let declaration_envelope = self.require_record_kind(
            declaration_id,
            crate::CampaignRecordKind::SelectableDeclaration,
        )?;
        charge_selection_resolution_record(&declaration_envelope, &mut charged_bytes)?;
        let declaration = SelectableDeclaration::from_canonical_bytes(declaration_envelope.body())?;
        if declaration.id()?.content_id() != declaration_id {
            return Err(integrity("selectable-envelope-shape"));
        }

        let domain_id = opportunity.domain().content_id();
        if domain_id != selection_domain_id {
            return Err(integrity("selection-envelope-domain-mismatch"));
        }
        let domain_envelope =
            self.require_record_kind(domain_id, crate::CampaignRecordKind::ChoiceDomain)?;
        charge_selection_resolution_record(&domain_envelope, &mut charged_bytes)?;
        let domain = ChoiceDomain::from_canonical_bytes(domain_envelope.body())?;
        if domain.id()?.content_id() != domain_id {
            return Err(integrity("choice-domain-envelope-shape"));
        }

        opportunity.validate_references(&declaration, &domain)?;
        selection.validate_resolved_references(&opportunity, &domain)?;
        Ok((selection, opportunity, declaration, domain))
    }
}

fn charge_selection_resolution_record(
    envelope: &ObjectEnvelope,
    charged_bytes: &mut usize,
) -> Result<(), CampaignRepositoryError> {
    let limit_error = || CampaignCodecError::InvalidValue {
        reason: "selection resolution exceeds canonical record byte limit",
    };
    *charged_bytes = charged_bytes
        .checked_add(envelope.canonical_bytes().len())
        .ok_or_else(limit_error)?;
    if *charged_bytes > MAX_SELECTION_RESOLUTION_BYTES {
        return Err(limit_error().into());
    }
    Ok(())
}
