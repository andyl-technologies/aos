//! Incremental SMC replay with a one-stage source window.
//!
//! A particle of stage `s + 1` extends exactly one outcome of stage `s` (or a
//! stage-zero draw for stage one), so the replay retains compact source
//! summaries for one stage at a time and discards them once the next stage
//! completes. The current generation, the current stage's outcomes, and those
//! summaries are all `O(particle_count)`.

use super::*;

/// Source-observation identity of one SMC particle.
pub(super) type SmcSourceKey = (ObservationId, ProposalId);

/// Opportunity chosen for the next stage by a source's discovered choices.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct SelectedOpportunity {
    pub(super) opportunity: ChoiceOpportunityId,
    pub(super) domain: ChoiceDomainId,
    pub(super) branch_point: BranchPointId,
}

/// Compact facts about one execution that later particles may extend.
///
/// The selector outcome is computed eagerly against the consuming stage's
/// selector, but a mismatch is reported only when a particle actually extends
/// this source, because resampling may drop it before the next stage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct SmcSource {
    pub(super) observation_path: BranchPathId,
    pub(super) reaches_stop: bool,
    pub(super) child_content: ConfigurationArtifactId,
    pub(super) child: ConfigurationId,
    pub(super) path_segments: Vec<BranchPathSegment>,
    pub(super) selected: Result<SelectedOpportunity, &'static str>,
}

impl SmcSource {
    fn from_execution(
        execution: &StatisticalExecutionEvidence,
        consumer: (&SmcOpportunitySelector, Option<&StatisticalDistribution>),
    ) -> Result<Self, CampaignCodecError> {
        let (selector, distribution) = consumer;
        let selected = match distribution {
            None => Err("SMC selector model is not planned"),
            Some(distribution) => match select_smc_opportunity(execution, selector, distribution) {
                Ok(selected) => Ok(SelectedOpportunity {
                    opportunity: selected.opportunity().id()?,
                    domain: selected.domain().id()?,
                    branch_point: selected
                        .opportunity()
                        .branch_point_id(execution.observation().child()),
                }),
                Err(CampaignCodecError::InvalidValue { reason }) => Err(reason),
                Err(error) => return Err(error),
            },
        };
        Ok(Self {
            observation_path: execution.observation().path(),
            reaches_stop: execution
                .observation()
                .stop()
                .reaches(execution.request().stop()),
            child_content: execution.observation().child_content(),
            child: execution.observation().child(),
            path_segments: execution.path().segments().to_vec(),
            selected,
        })
    }
}

/// One generation and the outcomes of its stage replayed so far.
struct SmcStageReplay {
    generation: StatisticalGeneration,
    outcomes: Vec<StatisticalParticleOutcome>,
}

/// Incremental SMC replay over initial draws and then ordered transitions.
pub(crate) struct SmcEvidenceReplay<'a> {
    basis: EvidenceBasis<'a>,
    policy_id: CampaignPolicyId,
    design: &'a SequentialMonteCarloDesign,
    initial: Option<FiniteEvidenceReplay<'a>>,
    sources: BTreeMap<SmcSourceKey, SmcSource>,
    next_sources: BTreeMap<SmcSourceKey, SmcSource>,
    stage: Option<SmcStageReplay>,
    generations: Vec<StatisticalGenerationSummary>,
    normalization_product: StatisticalRational,
    final_outcomes: Option<Vec<StatisticalParticleOutcome>>,
}

impl<'a> SmcEvidenceReplay<'a> {
    /// Starts a replay after checking the basis and the SMC design.
    pub(crate) fn new(basis: EvidenceBasis<'a>) -> Result<Self, CampaignCodecError> {
        let initial = FiniteEvidenceReplay::new(basis, true)?;
        let design = basis
            .policy
            .sequential_monte_carlo_design()
            .ok_or_else(|| invalid("SMC evidence requires an SMC policy"))?;
        Ok(Self {
            basis,
            policy_id: initial.policy_id,
            design,
            initial: Some(initial),
            sources: BTreeMap::new(),
            next_sources: BTreeMap::new(),
            stage: None,
            generations: Vec::with_capacity(design.stages().len()),
            normalization_product: StatisticalRational::one(),
            final_outcomes: None,
        })
    }

    /// Verifies the next stage-zero draw and records it as a stage-one source.
    pub(crate) fn push_initial_draw(
        &mut self,
        draw: &StatisticalDrawEvidence,
    ) -> Result<(), CampaignCodecError> {
        let initial = self
            .initial
            .as_mut()
            .ok_or_else(|| invalid("SMC initial draw follows a transition"))?;
        initial.push(draw)?;

        let execution = draw.execution();
        if !execution
            .observation()
            .stop()
            .reaches(execution.request().stop())
        {
            return Err(invalid("SMC initial draw did not reach its declared stop"));
        }
        let first_stage = self.consumer(1)?;
        insert_smc_source(
            &mut self.sources,
            execution,
            SmcSource::from_execution(execution, first_stage)?,
        )
    }

    /// Verifies the next transition in canonical stage and slot order.
    pub(crate) fn push_transition(
        &mut self,
        transition: &SmcTransitionEvidence,
    ) -> Result<(), CampaignCodecError> {
        if self.final_outcomes.is_some() {
            return Err(invalid(
                "SMC evidence contains transitions after the final stage",
            ));
        }
        self.start_stages()?;
        let design = self.design;
        let replay = self
            .stage
            .as_mut()
            .ok_or_else(|| invalid("SMC evidence generation is missing"))?;
        let stage = replay.generation.next_stage();
        let particle = replay
            .generation
            .slots()
            .get(replay.outcomes.len())
            .ok_or_else(|| invalid("SMC evidence transition coordinate is not canonical"))?;
        if transition.stage() != stage || transition.slot() != particle.slot() {
            return Err(invalid(
                "SMC evidence transition coordinate is not canonical",
            ));
        }

        let execution = transition.execution();
        verify_execution_common(self.basis, execution)?;
        validate_smc_request(
            self.basis,
            &replay.generation,
            particle,
            execution,
            &self.sources,
        )?;

        let next_stage = stage.saturating_add(1);
        let is_final = design.stage(next_stage).is_none();
        if !is_final
            && !execution
                .observation()
                .stop()
                .reaches(execution.request().stop())
        {
            return Err(invalid(
                "nonfinal SMC transition did not reach its declared stop",
            ));
        }

        let source = self
            .sources
            .get(&(particle.observation(), particle.proposal()))
            .ok_or_else(|| invalid("SMC source observation evidence is missing"))?;
        validate_extended_path(&source.path_segments, execution.path())?;

        let proposal_evidence = execution
            .proposal()
            .statistical_evidence()
            .ok_or_else(|| invalid("SMC transition probability evidence is missing"))?;
        let cumulative_target_probability = particle
            .cumulative_target_probability()
            .checked_multiply(target_probability(proposal_evidence)?)?;
        let cumulative_proposal_probability = particle
            .cumulative_proposal_probability()
            .checked_multiply(proposal_probability(proposal_evidence)?)?;
        let branch_weight = target_probability(proposal_evidence)?
            .checked_divide(proposal_probability(proposal_evidence)?)?;
        let estimator_weight = particle
            .estimator_weight()
            .checked_multiply(branch_weight)?;
        let outcome = StatisticalParticleOutcome::new(
            stage,
            particle.slot(),
            particle.id(),
            particle.source_coordinate(),
            execution.proposal().id()?,
            execution.attempt().id()?,
            execution.observation().id()?,
            execution.path().id()?,
            cumulative_target_probability,
            cumulative_proposal_probability,
            estimator_weight,
        )?;
        replay.outcomes.push(outcome);
        let stage_complete = replay.outcomes.len() == replay.generation.slots().len();

        // Final-stage outcomes are never extended, so they need no source.
        if !is_final {
            let consumer = self.consumer(next_stage)?;
            insert_smc_source(
                &mut self.next_sources,
                execution,
                SmcSource::from_execution(execution, consumer)?,
            )?;
        }
        if stage_complete {
            self.complete_stage()?;
        }
        Ok(())
    }

    /// Completes the replay and returns the final-population estimate.
    pub(crate) fn finish(
        mut self,
    ) -> Result<SequentialMonteCarloEstimateReport, CampaignCodecError> {
        self.start_stages()?;
        let outcomes = self
            .final_outcomes
            .take()
            .ok_or_else(|| invalid("SMC evidence transition is missing"))?;
        let diagnostics = particle_weight_diagnostics(&outcomes)?;
        SequentialMonteCarloEstimateReport::new(
            self.basis.snapshot.id()?,
            self.policy_id,
            self.design.resampling().algorithm(),
            self.generations,
            self.normalization_product,
            outcomes,
            diagnostics,
        )
    }

    /// Returns how many source summaries the replay currently retains.
    #[cfg(test)]
    pub(crate) fn retained_source_count(&self) -> usize {
        self.sources.len() + self.next_sources.len()
    }

    /// Returns the selector and distribution of the stage that extends sources.
    fn consumer(
        &self,
        stage: u32,
    ) -> Result<
        (
            &'a SmcOpportunitySelector,
            Option<&'a StatisticalDistribution>,
        ),
        CampaignCodecError,
    > {
        let design = self.design;
        let plan = design
            .stage(stage)
            .ok_or_else(|| invalid("SMC transition stage is not planned"))?;
        let selector = plan.selector();
        Ok((selector, design.distributions().get(&selector.model())))
    }

    fn start_stages(&mut self) -> Result<(), CampaignCodecError> {
        let Some(initial) = self.initial.take() else {
            return Ok(());
        };
        let report = initial.finish()?;
        let generation = StatisticalGeneration::from_initial_report(
            self.policy_id,
            self.basis.policy.campaign_seed(),
            self.design,
            &report,
        )?;
        self.begin_generation(generation)
    }

    fn begin_generation(
        &mut self,
        generation: StatisticalGeneration,
    ) -> Result<(), CampaignCodecError> {
        let expected_stage = match self.generations.last() {
            Some(previous) => previous.next_stage().checked_add(1),
            None => self.design.stages().keys().next().copied(),
        };
        if Some(generation.next_stage()) != expected_stage {
            return Err(invalid("SMC evidence generation stage is not canonical"));
        }
        self.normalization_product = self
            .normalization_product
            .checked_multiply(generation.normalization_factor())?;
        self.generations
            .push(StatisticalGenerationSummary::from_generation(&generation));
        let particle_count = generation.slots().len();
        self.stage = Some(SmcStageReplay {
            generation,
            outcomes: Vec::with_capacity(particle_count),
        });
        Ok(())
    }

    fn complete_stage(&mut self) -> Result<(), CampaignCodecError> {
        let replay = self
            .stage
            .take()
            .ok_or_else(|| invalid("SMC evidence generation is missing"))?;
        let stage = replay.generation.next_stage();

        // The previous stage's sources can never be referenced again.
        self.sources = std::mem::take(&mut self.next_sources);
        if self.design.stage(stage.saturating_add(1)).is_none() {
            self.final_outcomes = Some(replay.outcomes);
            return Ok(());
        }
        let generation = StatisticalGeneration::from_completed_stage(
            self.policy_id,
            self.basis.policy.campaign_seed(),
            self.design,
            stage,
            &replay.outcomes,
        )?;
        self.begin_generation(generation)
    }
}

fn insert_smc_source(
    sources: &mut BTreeMap<SmcSourceKey, SmcSource>,
    execution: &StatisticalExecutionEvidence,
    source: SmcSource,
) -> Result<(), CampaignCodecError> {
    let key = (execution.observation().id()?, execution.proposal().id()?);
    match sources.entry(key) {
        btree_map::Entry::Vacant(entry) => {
            entry.insert(source);
        }
        btree_map::Entry::Occupied(entry) => {
            if *entry.get() != source {
                return Err(invalid(
                    "one observation has conflicting statistical evidence",
                ));
            }
        }
    }
    Ok(())
}
