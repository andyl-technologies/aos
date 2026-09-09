//! Canonical SMC genealogy and exact systematic resampling.
//!
//! The stage-zero finite flight supplies complete canonical endpoints. This
//! module turns those endpoints into the next generation's particle slots. A
//! resampling generation records the average incoming weight as its
//! normalization factor and resets every selected slot's estimator weight to
//! one. The retained cumulative `P(path)` and `Q(path)` values are products of
//! branch-transition probabilities along the selected ancestry. They are audit
//! evidence, not the marginal or joint proposal law of the resampled genealogy;
//! multiplying them into the reset estimator weight would count ancestral
//! importance twice.
//!
//! Repository execution issues exactly one request and proposal per particle
//! slot, waits for every observation in a stage, and derives the next generation
//! by replaying authenticated requests, proposals, attempts, observations, and
//! paths. Every nonfinal particle must reach its declared stop and expose one
//! selector-matching opportunity. A completed report retains slot multiplicity,
//! includes each prefinal resampling normalization factor, and leaves the final
//! population unresampled. It provides both the ordinary fixed-denominator
//! importance estimate and an explicitly finite-sample-biased self-normalized
//! estimate; genealogical dependence precludes an IID uncertainty interval.

use crate::codec::{self, Canonical, Decoder, Encoder};
use std::collections::{BTreeMap, BTreeSet};

use crate::{
    AttemptId, BranchPathId, CampaignCodecError, CampaignHash, CampaignPolicyId, CampaignSeed,
    CampaignSnapshotId, ObservationId, ProposalId, SequentialMonteCarloDesign,
    SmcOpportunitySelector, SmcResamplingAlgorithm, StatisticalEstimateReport,
    StatisticalGenerationId, StatisticalParticleId, StatisticalRational,
    StatisticalWeightDiagnostics,
};

const SMC_GENERATION_SCHEMA_VERSION: u32 = 1;
const MAX_SMC_PARTICLES: usize = 4_096;
const MAX_SMC_GENERATION_BYTES: usize = 16 * 1024 * 1024;
const MAX_SYSTEMATIC_OFFSET_REJECTION_DRAWS: u64 = 256;

/// One owner-authenticated completed SMC particle transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatisticalParticleOutcome {
    stage: u32,
    slot: u32,
    input_particle: StatisticalParticleId,
    source_coordinate: u64,
    proposal: ProposalId,
    attempt: AttemptId,
    observation: ObservationId,
    path: BranchPathId,
    cumulative_target_probability: StatisticalRational,
    cumulative_proposal_probability: StatisticalRational,
    estimator_weight: StatisticalRational,
}

impl StatisticalParticleOutcome {
    // crucible-lint: allow rust-allow -- completed-particle construction keeps every audited identity and exact weight explicit.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn new(
        stage: u32,
        slot: u32,
        input_particle: StatisticalParticleId,
        source_coordinate: u64,
        proposal: ProposalId,
        attempt: AttemptId,
        observation: ObservationId,
        path: BranchPathId,
        cumulative_target_probability: StatisticalRational,
        cumulative_proposal_probability: StatisticalRational,
        estimator_weight: StatisticalRational,
    ) -> Result<Self, CampaignCodecError> {
        if stage == 0
            || usize::try_from(slot).map_or(true, |slot| slot >= MAX_SMC_PARTICLES)
            || cumulative_target_probability.numerator() == 0
            || cumulative_target_probability.numerator()
                > cumulative_target_probability.denominator()
            || cumulative_proposal_probability.numerator() == 0
            || cumulative_proposal_probability.numerator()
                > cumulative_proposal_probability.denominator()
            || estimator_weight.numerator() == 0
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "SMC particle outcome has an invalid bound or weight",
            });
        }
        Ok(Self {
            stage,
            slot,
            input_particle,
            source_coordinate,
            proposal,
            attempt,
            observation,
            path,
            cumulative_target_probability,
            cumulative_proposal_probability,
            estimator_weight,
        })
    }

    /// Returns the completed transition stage.
    #[must_use]
    pub const fn stage(&self) -> u32 {
        self.stage
    }

    /// Returns the stable particle slot within the completed stage.
    #[must_use]
    pub const fn slot(&self) -> u32 {
        self.slot
    }

    /// Returns the exact input particle consumed by this transition.
    #[must_use]
    pub const fn input_particle(&self) -> StatisticalParticleId {
        self.input_particle
    }

    /// Returns the initial finite-flight coordinate retained through ancestry.
    #[must_use]
    pub const fn source_coordinate(&self) -> u64 {
        self.source_coordinate
    }

    /// Returns the selected proposal.
    #[must_use]
    pub const fn proposal(&self) -> ProposalId {
        self.proposal
    }

    /// Returns the semantic attempt, which can be shared by duplicate slots.
    #[must_use]
    pub const fn attempt(&self) -> AttemptId {
        self.attempt
    }

    /// Returns the canonical observation, which can be shared by duplicate slots.
    #[must_use]
    pub const fn observation(&self) -> ObservationId {
        self.observation
    }

    /// Returns the authenticated path for the transition.
    #[must_use]
    pub const fn path(&self) -> BranchPathId {
        self.path
    }

    /// Returns the audited product of target branch probabilities along ancestry.
    #[must_use]
    pub const fn cumulative_target_probability(&self) -> StatisticalRational {
        self.cumulative_target_probability
    }

    /// Returns the audited product of proposal branch probabilities along ancestry.
    #[must_use]
    pub const fn cumulative_proposal_probability(&self) -> StatisticalRational {
        self.cumulative_proposal_probability
    }

    /// Returns the exact estimator weight after this transition.
    #[must_use]
    pub const fn estimator_weight(&self) -> StatisticalRational {
        self.estimator_weight
    }

    /// Returns the semantic identity of this completed transition.
    #[must_use]
    pub fn id(&self) -> StatisticalParticleId {
        StatisticalParticleId::from_hash(CampaignHash::derive(
            "crucible.campaign.smc-particle-outcome.v1",
            &codec::encode(self),
        ))
    }
}

impl Canonical for StatisticalParticleOutcome {
    fn encode(&self, encoder: &mut Encoder) {
        self.stage.encode(encoder);
        self.slot.encode(encoder);
        self.input_particle.encode(encoder);
        self.source_coordinate.encode(encoder);
        self.proposal.encode(encoder);
        self.attempt.encode(encoder);
        self.observation.encode(encoder);
        self.path.encode(encoder);
        self.cumulative_target_probability.encode(encoder);
        self.cumulative_proposal_probability.encode(encoder);
        self.estimator_weight.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            u32::decode(decoder)?,
            u32::decode(decoder)?,
            StatisticalParticleId::decode(decoder)?,
            u64::decode(decoder)?,
            ProposalId::decode(decoder)?,
            AttemptId::decode(decoder)?,
            ObservationId::decode(decoder)?,
            BranchPathId::decode(decoder)?,
            StatisticalRational::decode(decoder)?,
            StatisticalRational::decode(decoder)?,
            StatisticalRational::decode(decoder)?,
        )
    }
}

/// Proven support contract for a completed SMC report.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmcSupportValidation {
    /// Every runtime domain exactly matched one finite, positive policy support.
    ExactFinitePositive,
}

/// Statistical interpretation attached to one SMC point-estimate method.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmcEstimateLabel {
    /// Unnormalized importance estimate with fixed particle-count denominator.
    UnbiasedImportanceSampling,
    /// Realized-weight normalization with finite-sample bias.
    SelfNormalizedFiniteSampleBiased,
}

/// Dependence statement for one realized resampled genealogy.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SmcUncertaintyStatement {
    /// Particles share ancestry, so this report does not claim an IID interval.
    GenealogicallyCorrelatedNoIidInterval,
}

/// Complete owner-replayed estimate after every predeclared SMC stage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SequentialMonteCarloEstimateReport {
    snapshot: CampaignSnapshotId,
    policy: CampaignPolicyId,
    resampling_algorithm: SmcResamplingAlgorithm,
    generations: Vec<StatisticalGeneration>,
    normalization_product: StatisticalRational,
    final_particles: Vec<StatisticalParticleOutcome>,
    diagnostics: StatisticalWeightDiagnostics,
}

impl SequentialMonteCarloEstimateReport {
    pub(crate) fn new(
        snapshot: CampaignSnapshotId,
        policy: CampaignPolicyId,
        resampling_algorithm: SmcResamplingAlgorithm,
        generations: Vec<StatisticalGeneration>,
        normalization_product: StatisticalRational,
        final_particles: Vec<StatisticalParticleOutcome>,
        diagnostics: StatisticalWeightDiagnostics,
    ) -> Result<Self, CampaignCodecError> {
        if generations.is_empty()
            || final_particles.is_empty()
            || final_particles.iter().enumerate().any(|(slot, particle)| {
                usize::try_from(particle.slot()).ok() != Some(slot)
                    || particle.stage()
                        != generations
                            .last()
                            .map_or(0, StatisticalGeneration::next_stage)
            })
            || normalization_product.numerator() == 0
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "SMC estimate report is incomplete or inconsistent",
            });
        }
        Ok(Self {
            snapshot,
            policy,
            resampling_algorithm,
            generations,
            normalization_product,
            final_particles,
            diagnostics,
        })
    }

    /// Returns the exact complete snapshot used by owner replay.
    #[must_use]
    pub const fn snapshot(&self) -> CampaignSnapshotId {
        self.snapshot
    }

    /// Returns the policy that predeclared the complete SMC design.
    #[must_use]
    pub const fn policy(&self) -> CampaignPolicyId {
        self.policy
    }

    /// Returns the versioned deterministic resampling algorithm.
    #[must_use]
    pub const fn resampling_algorithm(&self) -> SmcResamplingAlgorithm {
        self.resampling_algorithm
    }

    /// Returns the validated runtime-support contract.
    #[must_use]
    pub const fn support_validation(&self) -> SmcSupportValidation {
        SmcSupportValidation::ExactFinitePositive
    }

    /// Returns every generation that supplied a post-initial transition.
    #[must_use]
    pub fn generations(&self) -> &[StatisticalGeneration] {
        &self.generations
    }

    /// Returns the product of mean-weight factors recorded before resampling.
    #[must_use]
    pub const fn normalization_product(&self) -> StatisticalRational {
        self.normalization_product
    }

    /// Returns every final particle in slot order, preserving duplicate ancestry.
    #[must_use]
    pub fn final_particles(&self) -> &[StatisticalParticleOutcome] {
        &self.final_particles
    }

    /// Returns descriptive concentration and effective sample size.
    #[must_use]
    pub const fn diagnostics(&self) -> StatisticalWeightDiagnostics {
        self.diagnostics
    }

    /// Returns the dependence statement governing uncertainty interpretation.
    #[must_use]
    pub const fn uncertainty(&self) -> SmcUncertaintyStatement {
        SmcUncertaintyStatement::GenealogicallyCorrelatedNoIidInterval
    }

    /// Returns the label for [`Self::estimate_event`].
    #[must_use]
    pub const fn ordinary_estimate_label(&self) -> SmcEstimateLabel {
        SmcEstimateLabel::UnbiasedImportanceSampling
    }

    /// Returns the label for [`Self::estimate_event_self_normalized`].
    #[must_use]
    pub const fn self_normalized_estimate_label(&self) -> SmcEstimateLabel {
        SmcEstimateLabel::SelfNormalizedFiniteSampleBiased
    }

    /// Returns the ordinary fixed-denominator SMC importance estimate.
    ///
    /// Each slot contributes once, including when its proposal, attempt, or
    /// observation was deduplicated with another slot. The result is not clamped
    /// and can exceed one for a realized finite population.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for an unknown observation or bounded
    /// rational arithmetic overflow.
    pub fn estimate_event(
        &self,
        event: &BTreeSet<ObservationId>,
    ) -> Result<StatisticalRational, CampaignCodecError> {
        self.validate_event(event)?;
        let mut selected = StatisticalRational::new(0, 1)?;
        for particle in &self.final_particles {
            if event.contains(&particle.observation()) {
                selected = selected.checked_add(particle.estimator_weight())?;
            }
        }
        let mean = selected.checked_divide(StatisticalRational::new(
            self.final_particles.len() as u128,
            1,
        )?)?;
        self.normalization_product.checked_multiply(mean)
    }

    /// Returns the realized-weight self-normalized SMC estimate.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for an unknown observation or bounded
    /// rational arithmetic overflow.
    pub fn estimate_event_self_normalized(
        &self,
        event: &BTreeSet<ObservationId>,
    ) -> Result<StatisticalRational, CampaignCodecError> {
        self.validate_event(event)?;
        let mut selected = StatisticalRational::new(0, 1)?;
        let mut all = StatisticalRational::new(0, 1)?;
        for particle in &self.final_particles {
            all = all.checked_add(particle.estimator_weight())?;
            if event.contains(&particle.observation()) {
                selected = selected.checked_add(particle.estimator_weight())?;
            }
        }
        selected.checked_divide(all)
    }

    fn validate_event(&self, event: &BTreeSet<ObservationId>) -> Result<(), CampaignCodecError> {
        if event.iter().any(|observation| {
            !self
                .final_particles
                .iter()
                .any(|particle| particle.observation() == *observation)
        }) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "SMC event contains an unknown observation",
            });
        }
        Ok(())
    }
}

/// One next-generation SMC slot with its exact source and genealogy.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatisticalParticleSlot {
    generation: u32,
    slot: u32,
    parent: StatisticalParticleId,
    source_coordinate: u64,
    proposal: ProposalId,
    attempt: AttemptId,
    observation: ObservationId,
    path: BranchPathId,
    cumulative_target_probability: StatisticalRational,
    cumulative_proposal_probability: StatisticalRational,
    estimator_weight: StatisticalRational,
    resampling_multiplicity: u32,
}

impl StatisticalParticleSlot {
    // crucible-lint: allow rust-allow -- a generation slot retains its complete genealogy and resampling state.
    #[allow(clippy::too_many_arguments)]
    fn new(
        generation: u32,
        slot: u32,
        parent: StatisticalParticleId,
        source_coordinate: u64,
        proposal: ProposalId,
        attempt: AttemptId,
        observation: ObservationId,
        path: BranchPathId,
        cumulative_target_probability: StatisticalRational,
        cumulative_proposal_probability: StatisticalRational,
        estimator_weight: StatisticalRational,
        resampling_multiplicity: u32,
    ) -> Result<Self, CampaignCodecError> {
        if generation == 0
            || usize::try_from(slot).map_or(true, |slot| slot >= MAX_SMC_PARTICLES)
            || cumulative_target_probability.numerator() == 0
            || cumulative_target_probability.numerator()
                > cumulative_target_probability.denominator()
            || cumulative_proposal_probability.numerator() == 0
            || cumulative_proposal_probability.numerator()
                > cumulative_proposal_probability.denominator()
            || estimator_weight.numerator() == 0
            || resampling_multiplicity == 0
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "SMC particle slot has an invalid bound or weight",
            });
        }
        Ok(Self {
            generation,
            slot,
            parent,
            source_coordinate,
            proposal,
            attempt,
            observation,
            path,
            cumulative_target_probability,
            cumulative_proposal_probability,
            estimator_weight,
            resampling_multiplicity,
        })
    }

    /// Returns the one-based particle generation.
    #[must_use]
    pub const fn generation(&self) -> u32 {
        self.generation
    }

    /// Returns the zero-based stable slot within the generation.
    #[must_use]
    pub const fn slot(&self) -> u32 {
        self.slot
    }

    /// Returns the selected particle from the completed parent generation.
    #[must_use]
    pub const fn parent(&self) -> StatisticalParticleId {
        self.parent
    }

    /// Returns the finite-flight coordinate that supplied the source endpoint.
    #[must_use]
    pub const fn source_coordinate(&self) -> u64 {
        self.source_coordinate
    }

    /// Returns the source proposal.
    #[must_use]
    pub const fn proposal(&self) -> ProposalId {
        self.proposal
    }

    /// Returns the source semantic attempt.
    #[must_use]
    pub const fn attempt(&self) -> AttemptId {
        self.attempt
    }

    /// Returns the source canonical observation.
    #[must_use]
    pub const fn observation(&self) -> ObservationId {
        self.observation
    }

    /// Returns the source authenticated branch path.
    #[must_use]
    pub const fn path(&self) -> BranchPathId {
        self.path
    }

    /// Returns the audited product of target branch probabilities along ancestry.
    ///
    /// This value does not describe the resampled genealogy's marginal or joint
    /// target law and is separate from [`Self::estimator_weight`].
    #[must_use]
    pub const fn cumulative_target_probability(&self) -> StatisticalRational {
        self.cumulative_target_probability
    }

    /// Returns the audited product of proposal branch probabilities along ancestry.
    ///
    /// This value does not include ancestor selection under the resampling law
    /// and is separate from [`Self::estimator_weight`].
    #[must_use]
    pub const fn cumulative_proposal_probability(&self) -> StatisticalRational {
        self.cumulative_proposal_probability
    }

    /// Returns the estimator weight carried into the next transition.
    ///
    /// This is one after resampling and the source importance weight when the
    /// generation did not resample.
    #[must_use]
    pub const fn estimator_weight(&self) -> StatisticalRational {
        self.estimator_weight
    }

    /// Returns how many next-generation slots selected this same parent.
    #[must_use]
    pub const fn resampling_multiplicity(&self) -> u32 {
        self.resampling_multiplicity
    }

    /// Returns the semantic identity of this slot and its genealogy.
    #[must_use]
    pub fn id(&self) -> StatisticalParticleId {
        StatisticalParticleId::from_hash(CampaignHash::derive(
            "crucible.campaign.smc-particle.v1",
            &codec::encode(self),
        ))
    }
}

impl Canonical for StatisticalParticleSlot {
    fn encode(&self, encoder: &mut Encoder) {
        self.generation.encode(encoder);
        self.slot.encode(encoder);
        self.parent.encode(encoder);
        self.source_coordinate.encode(encoder);
        self.proposal.encode(encoder);
        self.attempt.encode(encoder);
        self.observation.encode(encoder);
        self.path.encode(encoder);
        self.cumulative_target_probability.encode(encoder);
        self.cumulative_proposal_probability.encode(encoder);
        self.estimator_weight.encode(encoder);
        self.resampling_multiplicity.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            u32::decode(decoder)?,
            u32::decode(decoder)?,
            StatisticalParticleId::decode(decoder)?,
            u64::decode(decoder)?,
            ProposalId::decode(decoder)?,
            AttemptId::decode(decoder)?,
            ObservationId::decode(decoder)?,
            BranchPathId::decode(decoder)?,
            StatisticalRational::decode(decoder)?,
            StatisticalRational::decode(decoder)?,
            StatisticalRational::decode(decoder)?,
            u32::decode(decoder)?,
        )
    }
}

/// Owner-recomputed next-generation input for one completed SMC stage.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatisticalGeneration {
    schema_version: u32,
    policy: CampaignPolicyId,
    completed_stage: u32,
    next_stage: u32,
    selector: SmcOpportunitySelector,
    resampled: bool,
    systematic_offset: Option<u128>,
    normalization_factor: StatisticalRational,
    slots: Vec<StatisticalParticleSlot>,
}

impl StatisticalGeneration {
    pub(crate) fn from_initial_report(
        policy: CampaignPolicyId,
        campaign_seed: CampaignSeed,
        design: &SequentialMonteCarloDesign,
        report: &StatisticalEstimateReport,
    ) -> Result<Self, CampaignCodecError> {
        if report.policy() != policy
            || report.endpoints().len()
                != usize::try_from(design.particle_count()).map_err(|_| {
                    CampaignCodecError::InvalidValue {
                        reason: "SMC particle count cannot be represented",
                    }
                })?
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "SMC initial report disagrees with policy",
            });
        }
        let next_stage = 1;
        let stage = design
            .stage(next_stage)
            .ok_or(CampaignCodecError::InvalidValue {
                reason: "SMC first transition is missing",
            })?;
        let particle_count = u128::from(design.particle_count());
        let threshold = design.resampling().effective_sample_size_threshold();
        let threshold_count = StatisticalRational::new(
            particle_count
                .checked_mul(u128::from(threshold.numerator()))
                .ok_or(CampaignCodecError::InvalidValue {
                    reason: "SMC effective-sample-size threshold overflows",
                })?,
            u128::from(threshold.denominator()),
        )?;
        let resampled = report
            .diagnostics()
            .effective_sample_size()
            .checked_cmp(threshold_count)?
            .is_le();

        let (source_indexes, systematic_offset) = if resampled {
            let selection = systematic_ancestor_indexes(
                campaign_seed,
                next_stage,
                report
                    .endpoints()
                    .iter()
                    .map(|endpoint| endpoint.importance_weight()),
            )?;
            (selection.ancestors, Some(selection.offset))
        } else {
            ((0..report.endpoints().len()).collect(), None)
        };
        let mut multiplicities = vec![0_u32; report.endpoints().len()];
        for source_index in &source_indexes {
            multiplicities[*source_index] = multiplicities[*source_index].checked_add(1).ok_or(
                CampaignCodecError::InvalidValue {
                    reason: "SMC resampling multiplicity overflows",
                },
            )?;
        }

        let normalization_factor = if resampled {
            average_weight(
                report
                    .endpoints()
                    .iter()
                    .map(|endpoint| endpoint.importance_weight()),
                report.endpoints().len(),
            )?
        } else {
            StatisticalRational::one()
        };
        let reset_weight = StatisticalRational::one();
        let mut slots = Vec::with_capacity(source_indexes.len());
        for (slot, source_index) in source_indexes.into_iter().enumerate() {
            let endpoint = &report.endpoints()[source_index];
            let parent = initial_particle_id(policy, source_index, endpoint);
            slots.push(StatisticalParticleSlot::new(
                next_stage,
                u32::try_from(slot).map_err(|_| CampaignCodecError::InvalidValue {
                    reason: "SMC particle slot cannot be represented",
                })?,
                parent,
                endpoint.coordinate(),
                endpoint.proposal(),
                endpoint.attempt(),
                endpoint.observation(),
                endpoint.path(),
                endpoint.target_probability(),
                endpoint.proposal_probability(),
                if resampled {
                    reset_weight
                } else {
                    endpoint.importance_weight()
                },
                multiplicities[source_index],
            )?);
        }
        Self::new(
            policy,
            0,
            next_stage,
            stage.selector().clone(),
            resampled,
            systematic_offset,
            normalization_factor,
            slots,
        )
    }

    pub(crate) fn from_completed_stage(
        policy: CampaignPolicyId,
        campaign_seed: CampaignSeed,
        design: &SequentialMonteCarloDesign,
        completed_stage: u32,
        outcomes: &[StatisticalParticleOutcome],
    ) -> Result<Self, CampaignCodecError> {
        let next_stage =
            completed_stage
                .checked_add(1)
                .ok_or(CampaignCodecError::InvalidValue {
                    reason: "SMC generation stage overflows",
                })?;
        let stage = design
            .stage(next_stage)
            .ok_or(CampaignCodecError::InvalidValue {
                reason: "SMC next transition is not planned",
            })?;
        if outcomes.len()
            != usize::try_from(design.particle_count()).map_err(|_| {
                CampaignCodecError::InvalidValue {
                    reason: "SMC particle count cannot be represented",
                }
            })?
            || outcomes.iter().enumerate().any(|(slot, outcome)| {
                outcome.stage() != completed_stage
                    || usize::try_from(outcome.slot()).ok() != Some(slot)
            })
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "SMC completed stage disagrees with its design",
            });
        }

        let effective_sample_size = effective_sample_size(
            outcomes
                .iter()
                .map(StatisticalParticleOutcome::estimator_weight),
        )?;
        let particle_count = u128::from(design.particle_count());
        let threshold = design.resampling().effective_sample_size_threshold();
        let threshold_count = StatisticalRational::new(
            particle_count
                .checked_mul(u128::from(threshold.numerator()))
                .ok_or(CampaignCodecError::InvalidValue {
                    reason: "SMC effective-sample-size threshold overflows",
                })?,
            u128::from(threshold.denominator()),
        )?;
        let resampled = effective_sample_size.checked_cmp(threshold_count)?.is_le();
        let (source_indexes, systematic_offset) = if resampled {
            let selection = systematic_ancestor_indexes(
                campaign_seed,
                next_stage,
                outcomes
                    .iter()
                    .map(StatisticalParticleOutcome::estimator_weight),
            )?;
            (selection.ancestors, Some(selection.offset))
        } else {
            ((0..outcomes.len()).collect(), None)
        };
        let mut multiplicities = vec![0_u32; outcomes.len()];
        for source_index in &source_indexes {
            multiplicities[*source_index] = multiplicities[*source_index].checked_add(1).ok_or(
                CampaignCodecError::InvalidValue {
                    reason: "SMC resampling multiplicity overflows",
                },
            )?;
        }
        let normalization_factor = if resampled {
            average_weight(
                outcomes
                    .iter()
                    .map(StatisticalParticleOutcome::estimator_weight),
                outcomes.len(),
            )?
        } else {
            StatisticalRational::one()
        };
        let mut slots = Vec::with_capacity(source_indexes.len());
        for (slot, source_index) in source_indexes.into_iter().enumerate() {
            let outcome = &outcomes[source_index];
            slots.push(StatisticalParticleSlot::new(
                next_stage,
                u32::try_from(slot).map_err(|_| CampaignCodecError::InvalidValue {
                    reason: "SMC particle slot cannot be represented",
                })?,
                outcome.id(),
                outcome.source_coordinate(),
                outcome.proposal(),
                outcome.attempt(),
                outcome.observation(),
                outcome.path(),
                outcome.cumulative_target_probability(),
                outcome.cumulative_proposal_probability(),
                if resampled {
                    StatisticalRational::one()
                } else {
                    outcome.estimator_weight()
                },
                multiplicities[source_index],
            )?);
        }
        Self::new(
            policy,
            completed_stage,
            next_stage,
            stage.selector().clone(),
            resampled,
            systematic_offset,
            normalization_factor,
            slots,
        )
    }

    // crucible-lint: allow rust-allow -- generation decoding and derivation share one complete invariant-checking constructor.
    #[allow(clippy::too_many_arguments)]
    fn new(
        policy: CampaignPolicyId,
        completed_stage: u32,
        next_stage: u32,
        selector: SmcOpportunitySelector,
        resampled: bool,
        systematic_offset: Option<u128>,
        normalization_factor: StatisticalRational,
        slots: Vec<StatisticalParticleSlot>,
    ) -> Result<Self, CampaignCodecError> {
        let unit_weight = StatisticalRational::one();
        let normalization_is_valid = if resampled {
            slots
                .iter()
                .all(|particle| particle.estimator_weight() == unit_weight)
        } else {
            normalization_factor == unit_weight
                && slots
                    .iter()
                    .all(|particle| particle.resampling_multiplicity() == 1)
        };
        let mut parent_multiplicities = BTreeMap::new();
        for particle in &slots {
            let multiplicity = parent_multiplicities
                .entry(particle.parent())
                .or_insert(0_u32);
            *multiplicity =
                multiplicity
                    .checked_add(1)
                    .ok_or(CampaignCodecError::InvalidValue {
                        reason: "SMC resampling multiplicity overflows",
                    })?;
        }
        let multiplicities_are_valid = slots.iter().all(|particle| {
            parent_multiplicities.get(&particle.parent()).copied()
                == Some(particle.resampling_multiplicity())
        });

        if next_stage
            != completed_stage
                .checked_add(1)
                .ok_or(CampaignCodecError::InvalidValue {
                    reason: "SMC generation stage overflows",
                })?
            || slots.is_empty()
            || slots.len() > MAX_SMC_PARTICLES
            || normalization_factor.numerator() == 0
            || resampled != systematic_offset.is_some()
            || !normalization_is_valid
            || !multiplicities_are_valid
            || slots.iter().enumerate().any(|(slot, particle)| {
                particle.generation() != next_stage
                    || usize::try_from(particle.slot()).ok() != Some(slot)
            })
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "SMC generation is inconsistent",
            });
        }
        let generation = Self {
            schema_version: SMC_GENERATION_SCHEMA_VERSION,
            policy,
            completed_stage,
            next_stage,
            selector,
            resampled,
            systematic_offset,
            normalization_factor,
            slots,
        };
        codec::ensure_encoded_size(
            &generation,
            MAX_SMC_GENERATION_BYTES,
            "SMC generation encoded bytes",
        )?;
        Ok(generation)
    }

    /// Returns the policy that predeclared this generation.
    #[must_use]
    pub const fn policy(&self) -> CampaignPolicyId {
        self.policy
    }

    /// Returns the completely observed parent stage.
    #[must_use]
    pub const fn completed_stage(&self) -> u32 {
        self.completed_stage
    }

    /// Returns the stage these slots will execute.
    #[must_use]
    pub const fn next_stage(&self) -> u32 {
        self.next_stage
    }

    /// Returns the pre-observation selector for every next-stage slot.
    #[must_use]
    pub const fn selector(&self) -> &SmcOpportunitySelector {
        &self.selector
    }

    /// Returns whether ancestor selection reset the carried estimator weights.
    #[must_use]
    pub const fn resampled(&self) -> bool {
        self.resampled
    }

    /// Returns the exact seeded systematic offset when resampling occurred.
    #[must_use]
    pub const fn systematic_offset(&self) -> Option<u128> {
        self.systematic_offset
    }

    /// Returns the average pre-resampling weight retained for normalization.
    ///
    /// The factor is one for a generation that did not resample.
    #[must_use]
    pub const fn normalization_factor(&self) -> StatisticalRational {
        self.normalization_factor
    }

    /// Returns the complete next generation in stable slot order.
    #[must_use]
    pub fn slots(&self) -> &[StatisticalParticleSlot] {
        &self.slots
    }

    /// Returns the canonical representation used by [`Self::id`].
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes and validates canonical generation bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, oversized, unsupported,
    /// or internally inconsistent state.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        if bytes.len() > MAX_SMC_GENERATION_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "SMC generation encoded bytes",
            });
        }
        codec::decode(bytes)
    }

    /// Returns the semantic identity of the complete generation input.
    #[must_use]
    pub fn id(&self) -> StatisticalGenerationId {
        StatisticalGenerationId::from_hash(CampaignHash::derive(
            "crucible.campaign.smc-generation.v1",
            &self.canonical_bytes(),
        ))
    }
}

impl Canonical for StatisticalGeneration {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.policy.encode(encoder);
        self.completed_stage.encode(encoder);
        self.next_stage.encode(encoder);
        self.selector.encode(encoder);
        self.resampled.encode(encoder);
        self.systematic_offset.encode(encoder);
        self.normalization_factor.encode(encoder);
        self.slots.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        if schema_version != SMC_GENERATION_SCHEMA_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported SMC generation schema version",
            });
        }
        Self::new(
            CampaignPolicyId::decode(decoder)?,
            u32::decode(decoder)?,
            u32::decode(decoder)?,
            SmcOpportunitySelector::decode(decoder)?,
            bool::decode(decoder)?,
            Option::<u128>::decode(decoder)?,
            StatisticalRational::decode(decoder)?,
            decoder.sequence_bounded(
                MAX_SMC_PARTICLES,
                "SMC generation particle count",
                StatisticalParticleSlot::decode,
            )?,
        )
    }
}

fn initial_particle_id(
    policy: CampaignPolicyId,
    slot: usize,
    endpoint: &crate::StatisticalEndpointEstimate,
) -> StatisticalParticleId {
    let mut encoder = Encoder::new();
    policy.encode(&mut encoder);
    0_u32.encode(&mut encoder);
    (slot as u64).encode(&mut encoder);
    endpoint.coordinate().encode(&mut encoder);
    endpoint.proposal().encode(&mut encoder);
    endpoint.attempt().encode(&mut encoder);
    endpoint.observation().encode(&mut encoder);
    endpoint.path().encode(&mut encoder);
    endpoint.target_probability().encode(&mut encoder);
    endpoint.proposal_probability().encode(&mut encoder);
    StatisticalParticleId::from_hash(CampaignHash::derive(
        "crucible.campaign.smc-initial-particle.v1",
        &encoder.finish(),
    ))
}

fn average_weight(
    weights: impl Iterator<Item = StatisticalRational>,
    count: usize,
) -> Result<StatisticalRational, CampaignCodecError> {
    let mut sum = StatisticalRational::new(0, 1)?;
    for weight in weights {
        sum = sum.checked_add(weight)?;
    }
    sum.checked_divide(StatisticalRational::new(count as u128, 1)?)
}

fn effective_sample_size(
    weights: impl Iterator<Item = StatisticalRational>,
) -> Result<StatisticalRational, CampaignCodecError> {
    let mut sum = StatisticalRational::new(0, 1)?;
    let mut sum_squares = StatisticalRational::new(0, 1)?;
    for weight in weights {
        sum = sum.checked_add(weight)?;
        sum_squares = sum_squares.checked_add(weight.checked_multiply(weight)?)?;
    }
    sum.checked_multiply(sum)?.checked_divide(sum_squares)
}

struct SystematicSelection {
    ancestors: Vec<usize>,
    offset: u128,
}

fn systematic_ancestor_indexes(
    campaign_seed: CampaignSeed,
    stage: u32,
    weights: impl Iterator<Item = StatisticalRational>,
) -> Result<SystematicSelection, CampaignCodecError> {
    let integer_masses = common_integer_masses(weights)?;
    let total_mass = checked_mass_total(&integer_masses)?;
    let particle_count = integer_masses.len();
    let offset = systematic_offset(campaign_seed, stage, total_mass)?;
    total_mass
        .checked_mul(particle_count as u128)
        .ok_or(CampaignCodecError::InvalidValue {
            reason: "SMC systematic resampling scale overflows",
        })?;

    let mut ancestors = Vec::with_capacity(particle_count);
    let mut source_index = 0_usize;
    let mut cumulative = integer_masses[0];
    for slot in 0..particle_count {
        let point = offset
            .checked_add((slot as u128).checked_mul(total_mass).ok_or(
                CampaignCodecError::InvalidValue {
                    reason: "SMC systematic resampling point overflows",
                },
            )?)
            .ok_or(CampaignCodecError::InvalidValue {
                reason: "SMC systematic resampling point overflows",
            })?;
        while point
            >= cumulative.checked_mul(particle_count as u128).ok_or(
                CampaignCodecError::InvalidValue {
                    reason: "SMC systematic resampling scale overflows",
                },
            )?
        {
            source_index = source_index
                .checked_add(1)
                .ok_or(CampaignCodecError::InvalidValue {
                    reason: "SMC systematic ancestor index overflows",
                })?;
            let mass =
                integer_masses
                    .get(source_index)
                    .ok_or(CampaignCodecError::InvalidValue {
                        reason: "SMC systematic point exceeds total weight",
                    })?;
            cumulative = cumulative
                .checked_add(*mass)
                .ok_or(CampaignCodecError::InvalidValue {
                    reason: "SMC systematic cumulative mass overflows",
                })?;
        }
        ancestors.push(source_index);
    }
    Ok(SystematicSelection { ancestors, offset })
}

fn common_integer_masses(
    weights: impl Iterator<Item = StatisticalRational>,
) -> Result<Vec<u128>, CampaignCodecError> {
    let weights = weights.collect::<Vec<_>>();
    if weights.is_empty() || weights.len() > MAX_SMC_PARTICLES {
        return Err(CampaignCodecError::InvalidValue {
            reason: "SMC resampling weight set is empty or oversized",
        });
    }
    if weights.iter().any(|weight| weight.numerator() == 0) {
        return Err(CampaignCodecError::InvalidValue {
            reason: "SMC resampling weight is zero",
        });
    }

    // Express every later weight relative to the first. Cancelling factor by
    // factor avoids constructing an overflowing common denominator when the
    // normalized integer masses themselves still fit.
    let anchor = weights[0];
    let mut masses = vec![1_u128];
    for weight in weights.into_iter().skip(1) {
        let mut numerator_factors = [masses[0], weight.numerator(), anchor.denominator()];
        let mut denominator_factors = [weight.denominator(), anchor.numerator()];
        for numerator in &mut numerator_factors {
            for denominator in &mut denominator_factors {
                let divisor = super::greatest_common_divisor_u128(*numerator, *denominator);
                *numerator /= divisor;
                *denominator /= divisor;
            }
        }
        let existing_scale = checked_mass_product(&denominator_factors)?;
        let next_mass = checked_mass_product(&numerator_factors)?;
        for mass in &mut masses {
            *mass = mass
                .checked_mul(existing_scale)
                .ok_or(CampaignCodecError::InvalidValue {
                    reason: "SMC resampling integer mass overflows",
                })?;
        }
        masses.push(next_mass);

        let common_divisor = masses
            .iter()
            .copied()
            .reduce(super::greatest_common_divisor_u128)
            .ok_or(CampaignCodecError::InvalidValue {
                reason: "SMC resampling weight set is empty",
            })?;
        for mass in &mut masses {
            *mass /= common_divisor;
        }
    }
    Ok(masses)
}

fn checked_mass_product(factors: &[u128]) -> Result<u128, CampaignCodecError> {
    factors.iter().try_fold(1_u128, |product, factor| {
        product
            .checked_mul(*factor)
            .ok_or(CampaignCodecError::InvalidValue {
                reason: "SMC resampling integer mass overflows",
            })
    })
}

fn checked_mass_total(masses: &[u128]) -> Result<u128, CampaignCodecError> {
    masses.iter().try_fold(0_u128, |total, mass| {
        total
            .checked_add(*mass)
            .ok_or(CampaignCodecError::InvalidValue {
                reason: "SMC resampling mass total overflows",
            })
    })
}

fn systematic_offset(
    campaign_seed: CampaignSeed,
    stage: u32,
    total_mass: u128,
) -> Result<u128, CampaignCodecError> {
    if total_mass == 0 {
        return Err(CampaignCodecError::InvalidValue {
            reason: "SMC systematic weight total is zero",
        });
    }
    let rejection_threshold = 0_u128.wrapping_sub(total_mass) % total_mass;
    for nonce in 0..MAX_SYSTEMATIC_OFFSET_REJECTION_DRAWS {
        let mut basis = [0_u8; 44];
        basis[..32].copy_from_slice(&campaign_seed.as_bytes());
        basis[32..36].copy_from_slice(&stage.to_be_bytes());
        basis[36..].copy_from_slice(&nonce.to_be_bytes());
        let hash = CampaignHash::derive("crucible.campaign.smc-systematic-offset.v1", &basis);
        let mut sample_bytes = [0_u8; 16];
        sample_bytes.copy_from_slice(&hash.as_bytes()[..16]);
        let sample = u128::from_be_bytes(sample_bytes);
        if sample >= rejection_threshold {
            return Ok(sample % total_mass);
        }
    }
    Err(CampaignCodecError::InvalidValue {
        reason: "SMC systematic offset rejection limit exceeded",
    })
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- fixture construction uses exact panic localization.
    #![allow(clippy::expect_used)]

    use std::collections::BTreeMap;

    use crucible_cas::content_store::{ContentId, ObjectKind};

    use super::*;
    use crate::{
        CampaignSnapshotId, ChoiceDomainSemanticId, ChoiceValue, ExactRational, ProbabilityModelId,
        SelectableSemanticId, SequentialMonteCarloDesign, SmcResamplingAlgorithm,
        SmcResamplingPolicy, SmcStagePlan, StatisticalDistribution, StatisticalEndpointEstimate,
        StatisticalWeightDiagnostics, StopCondition,
    };

    fn content_id(kind: ObjectKind, schema: u32, label: &str) -> ContentId {
        ContentId::for_bytes(kind, schema, label.as_bytes())
    }

    fn policy_id(label: &str) -> CampaignPolicyId {
        CampaignPolicyId::from_content_id(content_id(ObjectKind::Policy, 4, label))
            .expect("policy ID")
    }

    fn snapshot_id(label: &str) -> CampaignSnapshotId {
        CampaignSnapshotId::from_content_id(content_id(ObjectKind::CampaignSnapshot, 3, label))
            .expect("snapshot ID")
    }

    fn endpoint(
        coordinate: u64,
        label: &str,
        target: StatisticalRational,
        proposal: StatisticalRational,
        weight: StatisticalRational,
    ) -> StatisticalEndpointEstimate {
        StatisticalEndpointEstimate::new(
            coordinate,
            ProposalId::from_content_id(content_id(ObjectKind::CampaignFact, 2, label))
                .expect("proposal ID"),
            AttemptId::from_content_id(content_id(ObjectKind::CampaignFact, 3, label))
                .expect("attempt ID"),
            ObservationId::from_content_id(content_id(ObjectKind::Observation, 8, label))
                .expect("observation ID"),
            BranchPathId::from_content_id(content_id(ObjectKind::CampaignFact, 2, label))
                .expect("path ID"),
            target,
            proposal,
            weight,
        )
    }

    fn report(
        policy: CampaignPolicyId,
        labels: [&str; 2],
        weights: [StatisticalRational; 2],
        effective_sample_size: StatisticalRational,
    ) -> StatisticalEstimateReport {
        let endpoints = labels
            .into_iter()
            .zip(weights)
            .enumerate()
            .map(|(coordinate, (label, weight))| {
                endpoint(
                    coordinate as u64,
                    label,
                    StatisticalRational::new(1, 2).expect("target probability"),
                    StatisticalRational::new(1, 2).expect("proposal probability"),
                    weight,
                )
            })
            .collect();
        StatisticalEstimateReport::new(
            snapshot_id("snapshot"),
            policy,
            endpoints,
            StatisticalWeightDiagnostics::new(
                StatisticalRational::new(1, 2).expect("concentration"),
                effective_sample_size,
            ),
        )
    }

    fn design(threshold_numerator: u64, threshold_denominator: u64) -> SequentialMonteCarloDesign {
        let model = ProbabilityModelId::from_hash(CampaignHash::derive("test.model", b"model"));
        let distribution = StatisticalDistribution::new(
            BTreeMap::from([
                (ChoiceValue::Boolean(false), 1),
                (ChoiceValue::Boolean(true), 1),
            ]),
            BTreeMap::from([
                (ChoiceValue::Boolean(false), 1),
                (ChoiceValue::Boolean(true), 1),
            ]),
        )
        .expect("distribution");
        let selector = SmcOpportunitySelector::new(
            SelectableSemanticId::from_hash(CampaignHash::derive(
                "test.declaration",
                b"declaration",
            )),
            ChoiceDomainSemanticId::from_hash(CampaignHash::derive("test.domain", b"domain")),
            "next-choice",
            model,
            StopCondition::NextChoice,
        )
        .expect("selector");
        let resampling = SmcResamplingPolicy::new(
            SmcResamplingAlgorithm::SystematicV1,
            ExactRational::new(threshold_numerator, threshold_denominator).expect("ESS threshold"),
        )
        .expect("resampling policy");
        SequentialMonteCarloDesign::new(
            2,
            BTreeMap::from([(model, distribution)]),
            BTreeMap::from([(1, SmcStagePlan::new(0, selector))]),
            resampling,
        )
        .expect("SMC design")
    }

    #[test]
    fn threshold_equality_resamples_and_resets_estimator_weights() {
        let policy = policy_id("equal-threshold-policy");
        let unit = StatisticalRational::one();
        let initial = report(
            policy,
            ["equal-a", "equal-b"],
            [unit, unit],
            StatisticalRational::new(2, 1).expect("ESS"),
        );

        let generation = StatisticalGeneration::from_initial_report(
            policy,
            CampaignSeed::from_bytes([7; 32]),
            &design(1, 1),
            &initial,
        )
        .expect("generation");

        assert!(generation.resampled());
        assert!(generation.systematic_offset().is_some());
        assert_eq!(generation.normalization_factor(), unit);
        assert!(
            generation
                .slots()
                .iter()
                .all(|particle| particle.estimator_weight() == unit)
        );
        assert_eq!(
            StatisticalGeneration::from_canonical_bytes(&generation.canonical_bytes())
                .expect("canonical round trip"),
            generation
        );
        assert_eq!(
            StatisticalGeneration::from_canonical_bytes(&generation.canonical_bytes())
                .expect("canonical identity")
                .id(),
            generation.id()
        );
    }

    #[test]
    fn effective_sample_size_above_threshold_preserves_weights() {
        let policy = policy_id("no-resample-policy");
        let weights = [
            StatisticalRational::new(1, 2).expect("weight"),
            StatisticalRational::new(3, 2).expect("weight"),
        ];
        let initial = report(
            policy,
            ["preserved-a", "preserved-b"],
            weights,
            StatisticalRational::new(8, 5).expect("ESS"),
        );

        let generation = StatisticalGeneration::from_initial_report(
            policy,
            CampaignSeed::from_bytes([8; 32]),
            &design(1, 2),
            &initial,
        )
        .expect("generation");

        assert!(!generation.resampled());
        assert_eq!(generation.systematic_offset(), None);
        assert_eq!(
            generation.normalization_factor(),
            StatisticalRational::one()
        );
        assert_eq!(
            generation
                .slots()
                .iter()
                .map(StatisticalParticleSlot::estimator_weight)
                .collect::<Vec<_>>(),
            weights
        );
    }

    #[test]
    fn resampling_offset_ignores_observation_identity_and_tracks_duplicate_ancestors() {
        let policy = policy_id("duplicate-policy");
        let weights = [
            StatisticalRational::new(1, 81).expect("weight"),
            StatisticalRational::new(1, 1).expect("weight"),
        ];
        let effective_sample_size = StatisticalRational::new(3362, 3281).expect("ESS");
        let seed = CampaignSeed::from_bytes([9; 32]);
        let design = design(1, 1);
        let first = StatisticalGeneration::from_initial_report(
            policy,
            seed,
            &design,
            &report(
                policy,
                ["first-a", "first-b"],
                weights,
                effective_sample_size,
            ),
        )
        .expect("first generation");
        let second = StatisticalGeneration::from_initial_report(
            policy,
            seed,
            &design,
            &report(
                policy,
                ["different-a", "different-b"],
                weights,
                effective_sample_size,
            ),
        )
        .expect("second generation");

        assert_eq!(first.systematic_offset(), second.systematic_offset());
        assert_eq!(first.slots()[0].parent(), first.slots()[1].parent());
        assert!(
            first
                .slots()
                .iter()
                .all(|particle| particle.resampling_multiplicity() == 2)
        );
    }

    #[test]
    fn generation_decode_rejects_invalid_reset_probability_and_multiplicity_state() {
        let policy = policy_id("decode-policy");
        let initial = report(
            policy,
            ["decode-a", "decode-b"],
            [StatisticalRational::one(), StatisticalRational::one()],
            StatisticalRational::new(2, 1).expect("ESS"),
        );
        let generation = StatisticalGeneration::from_initial_report(
            policy,
            CampaignSeed::from_bytes([10; 32]),
            &design(1, 1),
            &initial,
        )
        .expect("generation");

        let mut invalid_weight = generation.clone();
        invalid_weight.slots[0].estimator_weight =
            StatisticalRational::new(2, 1).expect("invalid reset weight");
        assert!(
            StatisticalGeneration::from_canonical_bytes(&codec::encode(&invalid_weight)).is_err()
        );

        let mut invalid_probability = generation.clone();
        invalid_probability.slots[0].cumulative_target_probability =
            StatisticalRational::new(2, 1).expect("invalid probability");
        assert!(
            StatisticalGeneration::from_canonical_bytes(&codec::encode(&invalid_probability))
                .is_err()
        );

        let mut invalid_normalization = generation.clone();
        invalid_normalization.resampled = false;
        invalid_normalization.systematic_offset = None;
        invalid_normalization.normalization_factor =
            StatisticalRational::new(2, 1).expect("invalid normalization");
        assert!(
            StatisticalGeneration::from_canonical_bytes(&codec::encode(&invalid_normalization))
                .is_err()
        );

        let mut invalid_multiplicity = generation;
        invalid_multiplicity.slots[0].resampling_multiplicity = 2;
        assert!(
            StatisticalGeneration::from_canonical_bytes(&codec::encode(&invalid_multiplicity))
                .is_err()
        );
    }

    #[test]
    fn common_masses_reduce_avoidable_growth_and_refuse_unrepresentable_ratios() {
        assert_eq!(
            common_integer_masses(
                [
                    StatisticalRational::new(2, 3).expect("weight"),
                    StatisticalRational::new(4, 3).expect("weight"),
                ]
                .into_iter(),
            )
            .expect("integer masses"),
            vec![1, 2]
        );
        assert!(
            common_integer_masses(
                [
                    StatisticalRational::new(1, u128::MAX).expect("weight"),
                    StatisticalRational::new(1, u128::MAX - 1).expect("weight"),
                ]
                .into_iter(),
            )
            .is_ok_and(|masses| masses == vec![u128::MAX - 1, u128::MAX])
        );
        assert!(
            common_integer_masses(
                [
                    StatisticalRational::new(1, u128::MAX).expect("weight"),
                    StatisticalRational::new(u128::MAX, 1).expect("weight"),
                ]
                .into_iter(),
            )
            .is_err()
        );
    }

    #[test]
    fn estimate_counts_duplicate_slots_and_keeps_the_ordinary_result_unclamped() {
        let policy = policy_id("duplicate-estimate-policy");
        let generation = StatisticalGeneration::from_initial_report(
            policy,
            CampaignSeed::from_bytes([11; 32]),
            &design(1, 2),
            &report(
                policy,
                ["duplicate-source-a", "duplicate-source-b"],
                [StatisticalRational::one(), StatisticalRational::one()],
                StatisticalRational::new(2, 1).expect("ESS"),
            ),
        )
        .expect("input generation");
        let proposal =
            ProposalId::from_content_id(content_id(ObjectKind::CampaignFact, 2, "shared-proposal"))
                .expect("shared proposal ID");
        let attempt =
            AttemptId::from_content_id(content_id(ObjectKind::CampaignFact, 3, "shared-attempt"))
                .expect("shared attempt ID");
        let observation = ObservationId::from_content_id(content_id(
            ObjectKind::Observation,
            8,
            "shared-observation",
        ))
        .expect("shared observation ID");
        let path =
            BranchPathId::from_content_id(content_id(ObjectKind::CampaignFact, 2, "shared-path"))
                .expect("shared path ID");
        let weights = [
            StatisticalRational::new(2, 1).expect("first weight"),
            StatisticalRational::new(4, 1).expect("second weight"),
        ];
        let outcomes = generation
            .slots()
            .iter()
            .zip(weights)
            .map(|(input, weight)| {
                StatisticalParticleOutcome::new(
                    1,
                    input.slot(),
                    input.id(),
                    input.source_coordinate(),
                    proposal,
                    attempt,
                    observation,
                    path,
                    StatisticalRational::new(1, 2).expect("target probability"),
                    StatisticalRational::new(1, 2).expect("proposal probability"),
                    weight,
                )
                .expect("particle outcome")
            })
            .collect::<Vec<_>>();
        let estimate = SequentialMonteCarloEstimateReport::new(
            snapshot_id("duplicate-estimate-snapshot"),
            policy,
            SmcResamplingAlgorithm::SystematicV1,
            vec![generation],
            StatisticalRational::new(3, 2).expect("normalization product"),
            outcomes,
            StatisticalWeightDiagnostics::new(
                StatisticalRational::new(2, 3).expect("concentration"),
                StatisticalRational::new(9, 5).expect("ESS"),
            ),
        )
        .expect("SMC estimate report");
        let event = BTreeSet::from([observation]);

        assert_eq!(
            estimate.estimate_event(&event).expect("ordinary estimate"),
            StatisticalRational::new(9, 2).expect("unclamped estimate")
        );
        assert_eq!(
            estimate
                .estimate_event_self_normalized(&event)
                .expect("self-normalized estimate"),
            StatisticalRational::one()
        );
        assert_eq!(
            estimate.estimate_event(&BTreeSet::from([ObservationId::from_content_id(
                content_id(ObjectKind::Observation, 8, "unknown-observation",)
            )
            .expect("unknown observation ID")])),
            Err(CampaignCodecError::InvalidValue {
                reason: "SMC event contains an unknown observation"
            })
        );
    }
}
