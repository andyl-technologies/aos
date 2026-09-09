//! Authenticated projection of complete statistical sampling flights.
//!
//! SMC generation state is derived from authenticated campaign records rather
//! than persisted as an independent authority. Transition lookup currently
//! replays the initial flight and every completed prior stage, so its work grows
//! with the completed transition prefix even though policy bounds cap the total
//! population. Callers should not treat the current projection path as a
//! constant-time scheduler operation.

use super::*;
use crate::statistics::verify_initial_smc_statistical_evidence;
use crate::{
    FiniteStatisticalEvidence, MAX_STATISTICAL_EVIDENCE_BYTES, MAX_STATISTICAL_EVIDENCE_ITEMS,
    SequentialMonteCarloEstimateReport, SequentialMonteCarloEvidence, SmcTransitionEvidence,
    StatisticalChoiceEvidence, StatisticalDrawEvidence, StatisticalEstimateReport,
    StatisticalExecutionBasisEvidence, StatisticalExecutionEvidence, StatisticalGeneration,
    StatisticalOpportunityEvidence, StatisticalParticleOutcome, StatisticalProposalEvidence,
    StatisticalRational, verify_finite_statistical_evidence,
    verify_sequential_monte_carlo_evidence,
};

impl CampaignRepository {
    pub(super) fn statistical_request_basis(
        &self,
        snapshot: &LoadedSnapshot,
        policy: &CampaignPolicy,
    ) -> Result<Option<crate::StatisticalRequestBasis>, CampaignRepositoryError> {
        let Some(design) = policy.statistical_sampling_design() else {
            return Ok(None);
        };
        let mut coordinate = None;
        for candidate in design.draws().keys().copied() {
            if self
                .merkle
                .get(
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
                .merkle
                .get(
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
                let Some(proposal_content) = self.merkle.get(
                    snapshot.snapshot.roots().accounting,
                    statistical_draw_proposal_key(parent_coordinate),
                )?
                else {
                    return Ok(None);
                };
                let proposal = self.read_proposal(proposal_content)?;
                let parent_request = self.read_branch_request(proposal.request().content_id())?;
                let CandidateSource::StatisticalFinite(parent_source) = parent_request.source()
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
                        map_key_content("accounting.proposal-admission", proposal_content),
                    )?
                    .ok_or_else(|| integrity("statistical-parent-draw-admission-is-missing"))?;
                let admission = self.read_attempt_admission(admission_content)?;
                self.validate_statistical_attempt_basis(snapshot, admission.attempt())?;
                let Some(observation_content) = self.merkle.get(
                    snapshot.snapshot.roots().observations,
                    map_key_content("observations.attempt", admission.attempt().content_id()),
                )?
                else {
                    return Ok(None);
                };
                let observation = self.read_observation(observation_content)?;
                if observation.attempt() != admission.attempt()
                    || observation.stop() != &StopOutcome::Reached(parent_request.stop().clone())
                {
                    return Err(integrity("statistical-parent-draw-cannot-continue"));
                }
                (observation.child_content(), observation.child())
            }
        };
        let parent_artifact = self.read_configuration_artifact(parent.content_id())?;
        if parent_artifact.configuration() != configuration
            || self.merkle.get(
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
        if self.merkle.get(
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

    pub(super) fn smc_request_basis(
        &self,
        snapshot: &LoadedSnapshot,
        policy: &CampaignPolicy,
    ) -> Result<Option<crate::SmcRequestBasis>, CampaignRepositoryError> {
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
                let request = self.merkle.get(
                    snapshot.snapshot.roots().exploration,
                    smc_transition_request_key(stage, particle.slot()),
                )?;
                if request.is_none() {
                    return self
                        .resolve_smc_request_basis(snapshot, policy, &generation, particle)
                        .map(Some);
                }
                if self
                    .merkle
                    .get(
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
        &self,
        snapshot: &LoadedSnapshot,
        policy: &CampaignPolicy,
    ) -> Result<bool, CampaignRepositoryError> {
        let design = policy
            .statistical_sampling_design()
            .ok_or_else(|| integrity("SMC policy lacks an initial sampling design"))?;
        for coordinate in design.draws().keys().copied() {
            let Some(proposal) = self.merkle.get(
                snapshot.snapshot.roots().accounting,
                statistical_draw_proposal_key(coordinate),
            )?
            else {
                return Ok(false);
            };
            let Some(admission) = self.merkle.get(
                snapshot.snapshot.roots().accounting,
                map_key_content("accounting.proposal-admission", proposal),
            )?
            else {
                return Ok(false);
            };
            let admission = self.read_attempt_admission(admission)?;
            if self
                .merkle
                .get(
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
        &self,
        snapshot: &LoadedSnapshot,
        policy: &CampaignPolicy,
    ) -> Result<StatisticalGeneration, CampaignRepositoryError> {
        self.validate_initial_smc_transition_sources(snapshot, policy)?;
        let initial =
            self.project_finite_statistical_estimate_from_loaded(snapshot, policy, true)?;
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
        &self,
        snapshot: &LoadedSnapshot,
        policy: &CampaignPolicy,
    ) -> Result<(), CampaignRepositoryError> {
        let initial = policy
            .statistical_sampling_design()
            .ok_or_else(|| integrity("SMC policy lacks an initial sampling design"))?;
        for coordinate in initial.draws().keys().copied() {
            let request_content = self
                .merkle
                .get(
                    snapshot.snapshot.roots().exploration,
                    statistical_draw_request_key(coordinate),
                )?
                .ok_or_else(|| integrity("SMC initial transition request is missing"))?;
            let request = self.read_branch_request(request_content)?;
            let proposal_content = self
                .merkle
                .get(
                    snapshot.snapshot.roots().accounting,
                    statistical_draw_proposal_key(coordinate),
                )?
                .ok_or_else(|| integrity("SMC initial transition proposal is missing"))?;
            let admission_content = self
                .merkle
                .get(
                    snapshot.snapshot.roots().accounting,
                    map_key_content("accounting.proposal-admission", proposal_content),
                )?
                .ok_or_else(|| integrity("SMC initial transition admission is missing"))?;
            let admission = self.read_attempt_admission(admission_content)?;
            let observation_content = self
                .merkle
                .get(
                    snapshot.snapshot.roots().observations,
                    map_key_content("observations.attempt", admission.attempt().content_id()),
                )?
                .ok_or_else(|| integrity("SMC initial transition observation is missing"))?;
            let observation = self.read_observation(observation_content)?;
            if observation.stop() != &StopOutcome::Reached(request.stop().clone()) {
                return Err(integrity(
                    "SMC initial transition did not reach its declared stop",
                ));
            }
        }
        Ok(())
    }

    pub(in crate::repository) fn resolve_smc_request_basis(
        &self,
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
        let observation = self.read_observation(particle.observation().content_id())?;
        let source_proposal = self.read_proposal(particle.proposal().content_id())?;
        let source_request = self.read_branch_request(source_proposal.request().content_id())?;
        if observation.id()? != particle.observation()
            || observation.path() != particle.path()
            || observation.stop() != &StopOutcome::Reached(source_request.stop().clone())
        {
            return Err(integrity(
                "SMC particle source observation identity mismatch",
            ));
        }
        let parent = self.read_configuration_artifact(observation.child_content().content_id())?;
        if parent.id()? != observation.child_content()
            || parent.configuration() != observation.child()
            || self.merkle.get(
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
        if self.merkle.get(
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
            particle.clone(),
            observation.child_content(),
            observation.child(),
            opportunity,
            domain,
        )
        .map_err(Into::into)
    }

    fn completed_smc_stage(
        &self,
        snapshot: &LoadedSnapshot,
        policy: &CampaignPolicy,
        generation: &StatisticalGeneration,
    ) -> Result<Option<Vec<StatisticalParticleOutcome>>, CampaignRepositoryError> {
        let mut outcomes = Vec::with_capacity(generation.slots().len());
        for particle in generation.slots() {
            let request_content = self
                .merkle
                .get(
                    snapshot.snapshot.roots().exploration,
                    smc_transition_request_key(generation.next_stage(), particle.slot()),
                )?
                .ok_or_else(|| integrity("SMC transition request is missing"))?;
            let request = self.read_branch_request(request_content)?;
            self.validate_smc_request_policy(snapshot, policy, generation, particle, &request)?;

            let Some(proposal_content) = self.merkle.get(
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
                .merkle
                .get(
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
            self.validate_statistical_attempt_basis(snapshot, admission.attempt())?;

            let Some(observation_content) = self.merkle.get(
                snapshot.snapshot.roots().observations,
                map_key_content("observations.attempt", admission.attempt().content_id()),
            )?
            else {
                return Ok(None);
            };
            let observation_id = ObservationId::from_content_id(observation_content)?;
            let observation = self.read_observation(observation_content)?;
            let attempt = self.read_attempt(admission.attempt().content_id())?;
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
                && observation.stop() != &StopOutcome::Reached(request.stop().clone())
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
            let selection = self.resolve_selection(selection)?;
            let crate::SelectionOrigin::CampaignBranch {
                branch_point,
                edge: selected_edge,
            } = selection.selection().origin()
            else {
                return Err(integrity("SMC transition selection origin mismatch"));
            };
            if branch_point != proposal.branch_point()
                || edge != selected_edge
                || selection.selection().value() != proposal.value()
            {
                return Err(integrity("SMC transition selection mismatch"));
            }
            let path = self.read_branch_path(attempt.path().content_id())?;
            let segments = path
                .segments()
                .ok_or_else(|| integrity("SMC transition path is legacy"))?;
            let source_path = self.read_branch_path(particle.path().content_id())?;
            let source_segments = source_path
                .segments()
                .ok_or_else(|| integrity("SMC source path is legacy"))?;
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
            outcomes.push(StatisticalParticleOutcome::new(
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
            )?);
        }
        Ok(Some(outcomes))
    }

    /// Collects complete owner-authenticated evidence for a finite estimate.
    ///
    /// Collection reads every policy-declared coordinate from the pinned roots,
    /// resolves each immutable record closure, and applies the same pure
    /// semantic verifier used by checked clients before returning.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale or incomplete snapshot, invalid root
    /// membership, malformed record closure, semantic replay failure, or an
    /// aggregate evidence body larger than the public transport bound.
    pub fn collect_finite_statistical_evidence(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
    ) -> Result<FiniteStatisticalEvidence, CampaignRepositoryError> {
        let snapshot = self.load_statistical_snapshot(name, expected_snapshot)?;
        let policy = self.read_policy(snapshot.snapshot.active_policy().content_id())?;
        let evidence =
            self.collect_finite_statistical_evidence_from_loaded(&snapshot, &policy, false)?;
        verify_finite_statistical_evidence(&evidence)?;
        Ok(evidence)
    }

    /// Collects complete owner-authenticated evidence for a finished SMC run.
    ///
    /// Every stage and slot is read in policy order. Missing transitions fail
    /// closed, and the common pure verifier checks all stage barriers,
    /// selectors, support, genealogy, and exact weights before return.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale or incomplete snapshot, invalid root
    /// membership, malformed record closure, semantic replay failure, or an
    /// aggregate evidence body larger than the public transport bound.
    pub fn collect_sequential_monte_carlo_evidence(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
    ) -> Result<SequentialMonteCarloEvidence, CampaignRepositoryError> {
        let snapshot = self.load_statistical_snapshot(name, expected_snapshot)?;
        let policy = self.read_policy(snapshot.snapshot.active_policy().content_id())?;
        let initial =
            self.collect_finite_statistical_evidence_from_loaded(&snapshot, &policy, true)?;
        let design = policy
            .sequential_monte_carlo_design()
            .ok_or_else(|| integrity("SMC evidence requires an SMC policy"))?;

        let mut charged_bytes = initial
            .canonical_bytes()
            .len()
            .checked_add(std::mem::size_of::<u64>())
            .ok_or_else(|| integrity("SMC evidence byte accounting overflows"))?;
        charge_statistical_evidence(&mut charged_bytes, 0)?;
        let transition_count =
            checked_smc_evidence_transition_count(design.stages().len(), design.particle_count())?;
        let minimum_transition_bytes = transition_count
            .checked_mul(std::mem::size_of::<u32>() * 2)
            .ok_or_else(|| integrity("SMC evidence minimum byte count overflows"))?;
        if charged_bytes
            .checked_add(minimum_transition_bytes)
            .is_none_or(|bytes| bytes > MAX_STATISTICAL_EVIDENCE_BYTES)
        {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "statistical-evidence-bytes",
            }
            .into());
        }
        let mut transitions = Vec::with_capacity(transition_count);
        for stage in design.stages().keys().copied() {
            for slot in 0..design.particle_count() {
                let request_content = self
                    .merkle
                    .get(
                        snapshot.snapshot.roots().exploration,
                        smc_transition_request_key(stage, slot),
                    )?
                    .ok_or_else(|| integrity("SMC evidence transition request is missing"))?;
                let proposal_content = self
                    .merkle
                    .get(
                        snapshot.snapshot.roots().accounting,
                        smc_transition_proposal_key(stage, slot),
                    )?
                    .ok_or_else(|| integrity("SMC evidence transition proposal is missing"))?;
                let remaining_bytes = remaining_statistical_evidence_bytes(
                    charged_bytes,
                    std::mem::size_of::<u32>() * 2,
                )?;
                let execution = self.collect_statistical_execution_evidence(
                    &snapshot,
                    request_content,
                    proposal_content,
                    remaining_bytes,
                )?;
                let transition = SmcTransitionEvidence::new(stage, slot, execution);
                charge_statistical_evidence(
                    &mut charged_bytes,
                    crate::codec::encode(&transition).len(),
                )?;
                transitions.push(transition);
            }
        }

        let evidence = SequentialMonteCarloEvidence::new(initial, transitions);
        verify_sequential_monte_carlo_evidence(&evidence)?;
        Ok(evidence)
    }

    fn load_statistical_snapshot(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
    ) -> Result<LoadedSnapshot, CampaignRepositoryError> {
        let head = self.head(name)?;
        if head.snapshot_id() != expected_snapshot {
            return Err(CampaignRepositoryError::Stale {
                expected: expected_snapshot,
                current: head.snapshot_id(),
            });
        }
        let snapshot = self.read_snapshot(expected_snapshot.content_id())?;
        self.validate_complete_head(expected_snapshot.content_id())?;
        Ok(snapshot)
    }

    fn collect_finite_statistical_evidence_from_loaded(
        &self,
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
        let mut charged_bytes = crate::codec::encode(&snapshot.snapshot)
            .len()
            .checked_add(crate::codec::encode(&snapshot.snapshot.planning_view()).len())
            .and_then(|bytes| bytes.checked_add(crate::codec::encode(policy).len()))
            .and_then(|bytes| bytes.checked_add(crate::codec::encode(&lineage).len()))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<u64>()))
            .ok_or_else(|| integrity("finite evidence byte accounting overflows"))?;
        charge_statistical_evidence(&mut charged_bytes, 0)?;
        let mut draws = Vec::with_capacity(design.draws().len());

        for coordinate in design.draws().keys().copied() {
            let request_content = self
                .merkle
                .get(
                    snapshot.snapshot.roots().exploration,
                    statistical_draw_request_key(coordinate),
                )?
                .ok_or_else(|| integrity("statistical-report-draw-request-is-missing"))?;
            let proposal_content = self
                .merkle
                .get(
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
            charge_statistical_evidence(&mut charged_bytes, crate::codec::encode(&draw).len())?;
            draws.push(draw);
        }

        Ok(FiniteStatisticalEvidence::new(
            snapshot.snapshot.clone(),
            snapshot.snapshot.planning_view(),
            policy.clone(),
            lineage,
            draws,
        ))
    }

    fn collect_statistical_execution_evidence(
        &self,
        snapshot: &LoadedSnapshot,
        request_content: ContentId,
        proposal_content: ContentId,
        maximum_bytes: usize,
    ) -> Result<StatisticalExecutionEvidence, CampaignRepositoryError> {
        let mut charged_bytes = std::mem::size_of::<u64>();
        let request = self.read_branch_request(request_content)?;
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encode(&request).len(),
            maximum_bytes,
        )?;
        let parent = self.read_configuration_artifact(request.parent().content_id())?;
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encode(&parent).len(),
            maximum_bytes,
        )?;
        let request_opportunity =
            self.collect_statistical_opportunity_evidence(request.opportunity())?;
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encode(&request_opportunity).len(),
            maximum_bytes,
        )?;
        let proposal = self.read_proposal(proposal_content)?;
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encode(&proposal).len(),
            maximum_bytes,
        )?;

        let proposal_admission_content = self
            .merkle
            .get(
                snapshot.snapshot.roots().accounting,
                map_key_content("accounting.proposal-admission", proposal_content),
            )?
            .ok_or_else(|| integrity("statistical evidence proposal admission is missing"))?;
        let proposal_admission = self.read_attempt_admission(proposal_admission_content)?;
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encode(&proposal_admission).len(),
            maximum_bytes,
        )?;
        let attempt_id = proposal_admission.attempt();
        let attempt = self.read_attempt(attempt_id.content_id())?;
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encode(&attempt).len(),
            maximum_bytes,
        )?;
        let AttemptStart::Branch { selection, .. } = attempt.start() else {
            return Err(integrity("statistical evidence attempt is not a branch"));
        };
        let selection = self.resolve_selection(selection)?;
        let choice = StatisticalChoiceEvidence::new(
            selection.selection().clone(),
            StatisticalOpportunityEvidence::new(
                selection.opportunity().clone(),
                selection.declaration().clone(),
                selection.domain().clone(),
            ),
        );
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encode(&choice).len(),
            maximum_bytes,
        )?;
        let path = self.read_branch_path(attempt.path().content_id())?;
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encode(&path).len(),
            maximum_bytes,
        )?;

        let observation_content = self
            .merkle
            .get(
                snapshot.snapshot.roots().observations,
                map_key_content("observations.attempt", attempt_id.content_id()),
            )?
            .ok_or_else(|| integrity("statistical-report-draw-observation-is-missing"))?;
        let observation = self.read_observation(observation_content)?;
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encode(&observation).len(),
            maximum_bytes,
        )?;
        let child = self.read_configuration_artifact(observation.child_content().content_id())?;
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encode(&child).len(),
            maximum_bytes,
        )?;
        let mut discovered_opportunities = Vec::new();
        for opportunity in observation.discovered_choices().iter().copied() {
            let opportunity = self.collect_statistical_opportunity_evidence(opportunity)?;
            charge_statistical_execution_evidence(
                &mut charged_bytes,
                crate::codec::encode(&opportunity).len(),
                maximum_bytes,
            )?;
            discovered_opportunities.push(opportunity);
        }

        let basis_content = self
            .merkle
            .get(
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
        let basis_request = self.read_branch_request(basis_proposal.request().content_id())?;
        let execution_basis =
            StatisticalExecutionBasisEvidence::new(basis_admission, basis_proposal, basis_request);
        charge_statistical_execution_evidence(
            &mut charged_bytes,
            crate::codec::encode(&execution_basis).len(),
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
        debug_assert_eq!(charged_bytes, crate::codec::encode(&evidence).len());
        Ok(evidence)
    }

    fn collect_statistical_opportunity_evidence(
        &self,
        opportunity: ChoiceOpportunityId,
    ) -> Result<StatisticalOpportunityEvidence, CampaignRepositoryError> {
        let (opportunity, declaration, domain) =
            self.load_choice_opportunity_dependencies(opportunity)?;
        Ok(StatisticalOpportunityEvidence::new(
            opportunity,
            declaration,
            domain,
        ))
    }

    /// Projects exact importance weights for a complete pinned sampling design.
    ///
    /// The endpoint population is the equal-weight mixture declared by the
    /// policy's terminal coordinates. Every planned coordinate, including
    /// shared prefixes, must have one admitted proposal and a canonical
    /// observation. Shared ancestry is retained, so diagnostics describe
    /// weights without claiming independent samples.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale snapshot, a non-statistical or legacy
    /// policy, an incomplete/reordered/forged draw, intervention ancestry,
    /// legacy paths, inconsistent endpoint ancestry, or exact arithmetic
    /// overflow.
    pub fn project_statistical_estimate(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
    ) -> Result<StatisticalEstimateReport, CampaignRepositoryError> {
        self.project_finite_statistical_estimate(name, expected_snapshot, false)
    }

    /// Projects the first owner-authenticated SMC generation after stage zero.
    ///
    /// The initial finite flight must be complete. The repository authenticates
    /// every proposal, execution basis, observation, path, and exact `P/Q`
    /// factor before applying the policy-pinned ESS and systematic-resampling
    /// rule. The resulting generation is derived state and is rebuilt from the
    /// same snapshot after restart.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale snapshot, a policy without an SMC design,
    /// incomplete or forged initial evidence, intervention ancestry, invalid
    /// support, or bounded exact-arithmetic failure.
    pub fn project_initial_smc_generation(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
    ) -> Result<StatisticalGeneration, CampaignRepositoryError> {
        let head = self.head(name)?;
        if head.snapshot_id() != expected_snapshot {
            return Err(CampaignRepositoryError::Stale {
                expected: expected_snapshot,
                current: head.snapshot_id(),
            });
        }
        let snapshot = self.read_snapshot(expected_snapshot.content_id())?;
        self.validate_complete_head(expected_snapshot.content_id())?;
        let policy = self.read_policy(snapshot.snapshot.active_policy().content_id())?;
        self.initial_smc_generation_from_loaded(&snapshot, &policy)
    }

    /// Projects the completed owner-replayed sequential Monte Carlo estimate.
    ///
    /// Every transition request, proposal, admission, observation, and path is
    /// recomputed from the active policy and authenticated roots. Resampling is
    /// replayed from the policy seed at each completed stage; the final stage is
    /// not redundantly resampled.
    ///
    /// # Errors
    ///
    /// Returns an error for a stale or incomplete snapshot, forged generation
    /// evidence, selector or support drift, intervention ancestry, or exact
    /// arithmetic overflow.
    pub fn project_sequential_monte_carlo_estimate(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
    ) -> Result<SequentialMonteCarloEstimateReport, CampaignRepositoryError> {
        let evidence = self.collect_sequential_monte_carlo_evidence(name, expected_snapshot)?;
        verify_sequential_monte_carlo_evidence(&evidence).map_err(Into::into)
    }

    fn project_finite_statistical_estimate(
        &self,
        name: &str,
        expected_snapshot: CampaignSnapshotId,
        allow_smc_initial_stage: bool,
    ) -> Result<StatisticalEstimateReport, CampaignRepositoryError> {
        let head = self.head(name)?;
        if head.snapshot_id() != expected_snapshot {
            return Err(CampaignRepositoryError::Stale {
                expected: expected_snapshot,
                current: head.snapshot_id(),
            });
        }
        let snapshot = self.read_snapshot(expected_snapshot.content_id())?;
        self.validate_complete_head(expected_snapshot.content_id())?;
        let policy_id = snapshot.snapshot.active_policy();
        let policy = self.read_policy(policy_id.content_id())?;
        self.project_finite_statistical_estimate_from_loaded(
            &snapshot,
            &policy,
            allow_smc_initial_stage,
        )
    }

    fn project_finite_statistical_estimate_from_loaded(
        &self,
        snapshot: &LoadedSnapshot,
        policy: &CampaignPolicy,
        allow_smc_initial_stage: bool,
    ) -> Result<StatisticalEstimateReport, CampaignRepositoryError> {
        let evidence = self.collect_finite_statistical_evidence_from_loaded(
            snapshot,
            policy,
            allow_smc_initial_stage,
        )?;
        if allow_smc_initial_stage {
            verify_initial_smc_statistical_evidence(&evidence).map_err(Into::into)
        } else {
            verify_finite_statistical_evidence(&evidence).map_err(Into::into)
        }
    }
}

fn statistical_target_probability(
    evidence: StatisticalProposalEvidence,
) -> Result<StatisticalRational, CampaignRepositoryError> {
    StatisticalRational::new(
        u128::from(evidence.target_mass()),
        u128::from(evidence.target_total()),
    )
    .map_err(Into::into)
}

fn statistical_proposal_probability(
    evidence: StatisticalProposalEvidence,
) -> Result<StatisticalRational, CampaignRepositoryError> {
    StatisticalRational::new(
        u128::from(evidence.proposal_mass()),
        u128::from(evidence.proposal_total()),
    )
    .map_err(Into::into)
}

fn charge_statistical_evidence(
    charged_bytes: &mut usize,
    additional_bytes: usize,
) -> Result<(), CampaignRepositoryError> {
    *charged_bytes = charged_bytes
        .checked_add(additional_bytes)
        .ok_or_else(|| integrity("statistical evidence byte accounting overflows"))?;
    if *charged_bytes > MAX_STATISTICAL_EVIDENCE_BYTES {
        return Err(CampaignCodecError::LimitExceeded {
            limit: "statistical-evidence-bytes",
        }
        .into());
    }
    Ok(())
}

fn remaining_statistical_evidence_bytes(
    charged_bytes: usize,
    wrapper_bytes: usize,
) -> Result<usize, CampaignRepositoryError> {
    charged_bytes
        .checked_add(wrapper_bytes)
        .and_then(|bytes| MAX_STATISTICAL_EVIDENCE_BYTES.checked_sub(bytes))
        .ok_or_else(|| {
            CampaignCodecError::LimitExceeded {
                limit: "statistical-evidence-bytes",
            }
            .into()
        })
}

fn charge_statistical_execution_evidence(
    charged_bytes: &mut usize,
    additional_bytes: usize,
    maximum_bytes: usize,
) -> Result<(), CampaignRepositoryError> {
    *charged_bytes = charged_bytes
        .checked_add(additional_bytes)
        .ok_or_else(|| integrity("statistical execution evidence byte accounting overflows"))?;
    if *charged_bytes > maximum_bytes {
        return Err(CampaignCodecError::LimitExceeded {
            limit: "statistical-evidence-bytes",
        }
        .into());
    }
    Ok(())
}

fn checked_smc_evidence_transition_count(
    stage_count: usize,
    particle_count: u32,
) -> Result<usize, CampaignRepositoryError> {
    let transition_count = stage_count
        .checked_mul(particle_count as usize)
        .ok_or_else(|| integrity("SMC evidence transition count overflows"))?;
    if transition_count > MAX_STATISTICAL_EVIDENCE_ITEMS {
        return Err(CampaignCodecError::LimitExceeded {
            limit: "SMC-evidence-transition-count",
        }
        .into());
    }
    Ok(transition_count)
}

#[cfg(test)]
mod evidence_bounds_tests {
    use super::*;

    #[test]
    fn smc_collector_rejects_oversized_transition_count_before_allocation() {
        assert!(matches!(
            checked_smc_evidence_transition_count(MAX_STATISTICAL_EVIDENCE_ITEMS, 2),
            Err(CampaignRepositoryError::Codec(
                CampaignCodecError::LimitExceeded {
                    limit: "SMC-evidence-transition-count"
                }
            ))
        ));
    }
}
