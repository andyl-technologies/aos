//! Branch requests, candidate sources, budgets, and stop conditions.

use super::*;

/// Per-request semantic limits applied during lazy candidate consumption.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct BranchBudget {
    maximum_proposals: u64,
    maximum_attempts: u64,
}

impl BranchBudget {
    /// Builds a nonempty branch budget.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when either bound is zero or attempts
    /// exceed proposals.
    pub fn new(maximum_proposals: u64, maximum_attempts: u64) -> Result<Self, CampaignCodecError> {
        if maximum_proposals == 0 || maximum_attempts == 0 || maximum_attempts > maximum_proposals {
            return Err(CampaignCodecError::InvalidValue {
                reason: "branch budget is empty or permits more attempts than proposals",
            });
        }
        Ok(Self {
            maximum_proposals,
            maximum_attempts,
        })
    }

    /// Returns the maximum proposals, including deduplicated proposals.
    #[must_use]
    pub const fn maximum_proposals(self) -> u64 {
        self.maximum_proposals
    }

    /// Returns the maximum newly admitted semantic attempts.
    #[must_use]
    pub const fn maximum_attempts(self) -> u64 {
        self.maximum_attempts
    }
}

impl Canonical for BranchBudget {
    fn encode(&self, encoder: &mut Encoder) {
        self.maximum_proposals.encode(encoder);
        self.maximum_attempts.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(u64::decode(decoder)?, u64::decode(decoder)?)
    }
}

/// One scheduler observation that can terminate an attempt after a new quantum.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ObservationCondition {
    /// Stop when the completed quantum reports scheduler-owned quiescence.
    SchedulerQuiescent,
    /// Stop when the completed quantum emits this assertion's violation transition.
    AssertionViolationTransition(String),
    /// Stop when any assertion declared by the scenario newly becomes violated.
    AnyAssertionViolationTransition,
    /// Stop on scheduler quiescence or at an absolute completed-quantum coordinate.
    SchedulerQuiescentOrExecutionQuanta {
        /// Absolute scheduler-quantum coordinate from scenario genesis.
        execution_quanta: u64,
    },
}

impl ObservationCondition {
    pub(crate) fn validate(&self) -> Result<(), CampaignCodecError> {
        match self {
            Self::SchedulerQuiescent => Ok(()),
            Self::AssertionViolationTransition(assertion) => {
                validate_identifier(assertion, "observation assertion is invalid")
            }
            Self::AnyAssertionViolationTransition => Ok(()),
            Self::SchedulerQuiescentOrExecutionQuanta {
                execution_quanta: 0,
            } => Err(CampaignCodecError::InvalidValue {
                reason: "observation stop has a zero execution-quantum bound",
            }),
            Self::SchedulerQuiescentOrExecutionQuanta { .. } => Ok(()),
        }
    }
}

impl Canonical for ObservationCondition {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::SchedulerQuiescent => encoder.u8(0),
            Self::AssertionViolationTransition(assertion) => {
                encoder.u8(1);
                assertion.encode(encoder);
            }
            Self::SchedulerQuiescentOrExecutionQuanta { execution_quanta } => {
                encoder.u8(2);
                execution_quanta.encode(encoder);
            }
            Self::AnyAssertionViolationTransition => encoder.u8(3),
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let condition = match decoder.u8()? {
            0 => Self::SchedulerQuiescent,
            1 => Self::AssertionViolationTransition(
                decoder.string_bounded(MAX_IDENTIFIER_BYTES, "observation-assertion-bytes")?,
            ),
            2 => Self::SchedulerQuiescentOrExecutionQuanta {
                execution_quanta: u64::decode(decoder)?,
            },
            3 => Self::AnyAssertionViolationTransition,
            tag => {
                return Err(CampaignCodecError::UnknownTag {
                    kind: "observation-condition",
                    tag,
                });
            }
        };
        condition.validate()?;
        Ok(condition)
    }
}

/// Semantic execution boundary for an attempt.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StopCondition {
    /// Stop at the next typed choice opportunity or modeled terminal outcome.
    NextChoice,
    /// Stop at a scenario-declared semantic boundary.
    NamedBoundary(String),
    /// Stop at a deterministic virtual-time deadline in nanoseconds.
    VirtualTimeNanoseconds(u64),
    /// Stop after a deterministic modeled event count.
    EventCount(u64),
    /// Run until a modeled terminal outcome.
    Terminal,
    /// Stop at an absolute scheduler-quantum coordinate from scenario genesis.
    ExecutionQuanta(u64),
    /// Stop when either absolute virtual time or scheduler quanta reaches its bound.
    VirtualTimeOrExecutionQuanta {
        /// Deterministic virtual-time deadline in nanoseconds.
        virtual_time_nanoseconds: u64,
        /// Absolute scheduler-quantum coordinate from scenario genesis.
        execution_quanta: u64,
    },
    /// Stop only after a newly completed quantum satisfies an observation.
    Observation(ObservationCondition),
    /// Stop at the next typed choice or an absolute scheduler-quantum timeout.
    NextChoiceOrExecutionQuanta {
        /// Absolute scheduler-quantum coordinate from scenario genesis.
        execution_quanta: u64,
    },
    /// Stop at the primary boundary or an immutable campaign-policy deadline.
    Bounded {
        /// The original semantic boundary, retained for exact replay.
        primary: Box<StopCondition>,
        /// Absolute virtual-time deadline in nanoseconds, if configured.
        virtual_time_nanoseconds: Option<u64>,
        /// Absolute scheduler-quantum deadline, if configured.
        execution_quanta: Option<u64>,
    },
}

impl StopCondition {
    /// Composes an attempt's primary boundary with a campaign-policy deadline.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError::InvalidValue`] for an empty, zero, or
    /// nested policy deadline, or an invalid primary stop.
    pub fn bounded(
        primary: Self,
        virtual_time_nanoseconds: Option<u64>,
        execution_quanta: Option<u64>,
    ) -> Result<Self, CampaignCodecError> {
        let bounded = Self::Bounded {
            primary: Box::new(primary),
            virtual_time_nanoseconds,
            execution_quanta,
        };
        bounded.validate()?;
        Ok(bounded)
    }

    /// Returns the primary semantic stop, without its policy deadline.
    #[must_use]
    pub fn primary(&self) -> &Self {
        match self {
            Self::Bounded { primary, .. } => primary,
            _ => self,
        }
    }

    /// Returns the virtual-time and quantum policy deadlines, when present.
    #[must_use]
    pub const fn bounded_deadlines(&self) -> Option<(Option<u64>, Option<u64>)> {
        match self {
            Self::Bounded {
                virtual_time_nanoseconds,
                execution_quanta,
                ..
            } => Some((*virtual_time_nanoseconds, *execution_quanta)),
            _ => None,
        }
    }

    /// Returns whether reaching a typed choice satisfies this boundary.
    #[must_use]
    pub fn accepts_next_choice(&self) -> bool {
        matches!(
            self.primary(),
            Self::NextChoice | Self::NextChoiceOrExecutionQuanta { .. }
        )
    }

    pub(crate) fn validate(&self) -> Result<(), CampaignCodecError> {
        match self {
            Self::NamedBoundary(name) => validate_identifier(name, "stop boundary is invalid"),
            Self::VirtualTimeNanoseconds(0)
            | Self::EventCount(0)
            | Self::ExecutionQuanta(0)
            | Self::VirtualTimeOrExecutionQuanta {
                virtual_time_nanoseconds: 0,
                ..
            }
            | Self::VirtualTimeOrExecutionQuanta {
                execution_quanta: 0,
                ..
            }
            | Self::NextChoiceOrExecutionQuanta {
                execution_quanta: 0,
            } => Err(CampaignCodecError::InvalidValue {
                reason: "stop condition has a zero bound",
            }),
            Self::Bounded {
                primary,
                virtual_time_nanoseconds,
                execution_quanta,
            } => {
                if matches!(primary.as_ref(), Self::Bounded { .. })
                    || (virtual_time_nanoseconds.is_none() && execution_quanta.is_none())
                    || *virtual_time_nanoseconds == Some(0)
                    || *execution_quanta == Some(0)
                {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "stop condition has an invalid policy deadline",
                    });
                }
                primary.validate()
            }
            Self::Observation(condition) => condition.validate(),
            _ => Ok(()),
        }
    }
}

impl Canonical for StopCondition {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::NextChoice => encoder.u8(0),
            Self::NamedBoundary(name) => {
                encoder.u8(1);
                name.encode(encoder);
            }
            Self::VirtualTimeNanoseconds(value) => {
                encoder.u8(2);
                value.encode(encoder);
            }
            Self::EventCount(value) => {
                encoder.u8(3);
                value.encode(encoder);
            }
            Self::Terminal => encoder.u8(4),
            Self::ExecutionQuanta(value) => {
                encoder.u8(5);
                value.encode(encoder);
            }
            Self::VirtualTimeOrExecutionQuanta {
                virtual_time_nanoseconds,
                execution_quanta,
            } => {
                encoder.u8(6);
                virtual_time_nanoseconds.encode(encoder);
                execution_quanta.encode(encoder);
            }
            Self::NextChoiceOrExecutionQuanta { execution_quanta } => {
                encoder.u8(7);
                execution_quanta.encode(encoder);
            }
            Self::Observation(condition) => {
                encoder.u8(8);
                condition.encode(encoder);
            }
            Self::Bounded {
                primary,
                virtual_time_nanoseconds,
                execution_quanta,
            } => {
                encoder.u8(9);
                primary.encode(encoder);
                virtual_time_nanoseconds.encode(encoder);
                execution_quanta.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let tag = decoder.u8()?;
        decode_stop_condition(decoder, tag, true)
    }
}

fn decode_stop_condition(
    decoder: &mut Decoder<'_>,
    tag: u8,
    allow_bounded: bool,
) -> Result<StopCondition, CampaignCodecError> {
    let condition = match tag {
        0 => StopCondition::NextChoice,
        1 => StopCondition::NamedBoundary(
            decoder.string_bounded(MAX_IDENTIFIER_BYTES, "stop-boundary-name-bytes")?,
        ),
        2 => StopCondition::VirtualTimeNanoseconds(u64::decode(decoder)?),
        3 => StopCondition::EventCount(u64::decode(decoder)?),
        4 => StopCondition::Terminal,
        5 => StopCondition::ExecutionQuanta(u64::decode(decoder)?),
        6 => StopCondition::VirtualTimeOrExecutionQuanta {
            virtual_time_nanoseconds: u64::decode(decoder)?,
            execution_quanta: u64::decode(decoder)?,
        },
        7 => StopCondition::NextChoiceOrExecutionQuanta {
            execution_quanta: u64::decode(decoder)?,
        },
        8 => StopCondition::Observation(ObservationCondition::decode(decoder)?),
        9 if allow_bounded => {
            let primary_tag = decoder.u8()?;
            let primary = decode_stop_condition(decoder, primary_tag, false)?;
            StopCondition::bounded(primary, Option::decode(decoder)?, Option::decode(decoder)?)?
        }
        9 => {
            return Err(CampaignCodecError::InvalidValue {
                reason: "nested policy-bound stop condition",
            });
        }
        tag => {
            return Err(CampaignCodecError::UnknownTag {
                kind: "stop-condition",
                tag,
            });
        }
    };
    condition.validate()?;
    Ok(condition)
}

/// Bounded finite values or one suspended generated source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CandidateSource {
    /// Explicit low-cardinality values consumed in canonical order.
    Finite(FiniteCandidateSource),
    /// Finite values carrying exact masses resolved from the opportunity model.
    ModeledFinite(ModeledFiniteCandidateSource),
    /// One categorical statistical draw with exact target and proposal masses.
    StatisticalFinite(StatisticalFiniteCandidateSource),
    /// One categorical SMC transition for an authenticated generation slot.
    StatisticalSmc(StatisticalSmcCandidateSource),
    /// A deterministic generator resolved from one non-finite opportunity model.
    ModeledGenerated(ModeledGeneratedCandidateSource),
    /// Versioned deterministic generator interpreted from campaign facts.
    Generated(CandidateGeneratorSpecId),
}

/// Nonempty bounded set underlying a finite candidate source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FiniteCandidateSource {
    values: BTreeSet<ChoiceValue>,
    prior_weights: Option<BTreeMap<ChoiceValue, u64>>,
}

/// Bounded finite masses resolved from one exact probability model.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ModeledFiniteCandidateSource {
    model: ProbabilityModelId,
    values: BTreeSet<ChoiceValue>,
    prior_weights: BTreeMap<ChoiceValue, u64>,
}

/// Bounded finite support for one exact with-replacement statistical draw.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatisticalFiniteCandidateSource {
    coordinate: u64,
    model: ProbabilityModelId,
    values: BTreeSet<ChoiceValue>,
    target_masses: BTreeMap<ChoiceValue, u64>,
    proposal_masses: BTreeMap<ChoiceValue, u64>,
    target_total: u64,
    proposal_total: u64,
}

/// Bounded finite support for one exact SMC particle transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StatisticalSmcCandidateSource {
    generation: StatisticalGenerationId,
    input_particle: StatisticalParticleId,
    stage: u32,
    slot: u32,
    model: ProbabilityModelId,
    values: BTreeSet<ChoiceValue>,
    target_masses: BTreeMap<ChoiceValue, u64>,
    proposal_masses: BTreeMap<ChoiceValue, u64>,
    target_total: u64,
    proposal_total: u64,
}

pub(crate) struct StatisticalDistributionRef<'a> {
    pub(crate) target_masses: &'a BTreeMap<ChoiceValue, u64>,
    pub(crate) proposal_masses: &'a BTreeMap<ChoiceValue, u64>,
    pub(crate) target_total: u64,
    pub(crate) proposal_total: u64,
}

/// One portable non-finite model resolution and its deterministic generator.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ModeledGeneratedCandidateSource {
    model: ProbabilityModelId,
    generator: CandidateGeneratorSpecId,
}

impl ModeledGeneratedCandidateSource {
    /// Returns the exact modeled distribution resolved by the adapter.
    #[must_use]
    pub const fn model(self) -> ProbabilityModelId {
        self.model
    }

    /// Returns the deterministic generator retaining the resolved distribution.
    #[must_use]
    pub const fn generator(self) -> CandidateGeneratorSpecId {
        self.generator
    }
}

impl ModeledFiniteCandidateSource {
    /// Returns the exact modeled distribution whose masses were resolved.
    #[must_use]
    pub const fn model(&self) -> ProbabilityModelId {
        self.model
    }

    /// Returns every modeled value and its positive raw mass.
    #[must_use]
    pub const fn prior_weights(&self) -> &BTreeMap<ChoiceValue, u64> {
        &self.prior_weights
    }
}

impl StatisticalFiniteCandidateSource {
    /// Returns the draw coordinate fixed by the active sampling design.
    #[must_use]
    pub const fn coordinate(&self) -> u64 {
        self.coordinate
    }

    /// Returns the exact modeled target distribution.
    #[must_use]
    pub const fn model(&self) -> ProbabilityModelId {
        self.model
    }

    /// Returns every supported value and its positive target mass.
    #[must_use]
    pub const fn target_masses(&self) -> &BTreeMap<ChoiceValue, u64> {
        &self.target_masses
    }

    /// Returns every supported value and its positive proposal mass.
    #[must_use]
    pub const fn proposal_masses(&self) -> &BTreeMap<ChoiceValue, u64> {
        &self.proposal_masses
    }

    /// Returns the exact sum of all target masses.
    #[must_use]
    pub const fn target_total(&self) -> u64 {
        self.target_total
    }

    /// Returns the exact sum of all proposal masses.
    #[must_use]
    pub const fn proposal_total(&self) -> u64 {
        self.proposal_total
    }
}

impl StatisticalSmcCandidateSource {
    /// Returns the owner-recomputed generation supplying this transition.
    #[must_use]
    pub const fn generation(&self) -> StatisticalGenerationId {
        self.generation
    }

    /// Returns the exact input particle selected for this slot.
    #[must_use]
    pub const fn input_particle(&self) -> StatisticalParticleId {
        self.input_particle
    }

    /// Returns the one-based transition stage.
    #[must_use]
    pub const fn stage(&self) -> u32 {
        self.stage
    }

    /// Returns the zero-based particle slot within the stage.
    #[must_use]
    pub const fn slot(&self) -> u32 {
        self.slot
    }

    /// Returns the exact modeled target distribution.
    #[must_use]
    pub const fn model(&self) -> ProbabilityModelId {
        self.model
    }

    /// Returns every supported value and its positive target mass.
    #[must_use]
    pub const fn target_masses(&self) -> &BTreeMap<ChoiceValue, u64> {
        &self.target_masses
    }

    /// Returns every supported value and its positive proposal mass.
    #[must_use]
    pub const fn proposal_masses(&self) -> &BTreeMap<ChoiceValue, u64> {
        &self.proposal_masses
    }

    /// Returns the exact sum of all target masses.
    #[must_use]
    pub const fn target_total(&self) -> u64 {
        self.target_total
    }

    /// Returns the exact sum of all proposal masses.
    #[must_use]
    pub const fn proposal_total(&self) -> u64 {
        self.proposal_total
    }
}

impl FiniteCandidateSource {
    /// Returns finite values in canonical order.
    #[must_use]
    pub const fn values(&self) -> &BTreeSet<ChoiceValue> {
        &self.values
    }

    /// Returns explicit positive proposal weights, when one was authored.
    ///
    /// Uniform finite sources return `None`; each of their values has implicit
    /// weight one.
    #[must_use]
    pub const fn prior_weights(&self) -> Option<&BTreeMap<ChoiceValue, u64>> {
        self.prior_weights.as_ref()
    }
}

impl CandidateSource {
    pub(crate) fn statistical_distribution(&self) -> Option<StatisticalDistributionRef<'_>> {
        match self {
            Self::StatisticalFinite(source) => Some(StatisticalDistributionRef {
                target_masses: source.target_masses(),
                proposal_masses: source.proposal_masses(),
                target_total: source.target_total(),
                proposal_total: source.proposal_total(),
            }),
            Self::StatisticalSmc(source) => Some(StatisticalDistributionRef {
                target_masses: source.target_masses(),
                proposal_masses: source.proposal_masses(),
                target_total: source.target_total(),
                proposal_total: source.proposal_total(),
            }),
            Self::Finite(_)
            | Self::ModeledFinite(_)
            | Self::ModeledGenerated(_)
            | Self::Generated(_) => None,
        }
    }

    /// Builds a nonempty bounded finite source.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for an empty or oversized value set.
    pub fn finite(values: BTreeSet<ChoiceValue>) -> Result<Self, CampaignCodecError> {
        if values.is_empty() || values.len() > MAX_FINITE_VALUES {
            return Err(CampaignCodecError::InvalidValue {
                reason: "finite candidate source is empty or oversized",
            });
        }
        Ok(Self::Finite(FiniteCandidateSource {
            values,
            prior_weights: None,
        }))
    }

    /// Builds a nonempty bounded finite source with explicit proposal weights.
    ///
    /// Weights are normalized by the repository owner together with already
    /// admitted edge weights when constructing PUCT guidance. Their absolute
    /// scale is therefore immaterial, but every retained value must have a
    /// positive weight.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for an empty or oversized map or a zero
    /// weight.
    pub fn weighted_finite(
        prior_weights: BTreeMap<ChoiceValue, u64>,
    ) -> Result<Self, CampaignCodecError> {
        if prior_weights.is_empty()
            || prior_weights.len() > MAX_FINITE_VALUES
            || prior_weights.values().any(|weight| *weight == 0)
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "weighted finite candidate source is empty, oversized, or has zero weight",
            });
        }
        Ok(Self::Finite(FiniteCandidateSource {
            values: prior_weights.keys().cloned().collect(),
            prior_weights: Some(prior_weights),
        }))
    }

    /// Builds a bounded finite source resolved from one exact probability model.
    ///
    /// The repository later requires `model` to equal the referenced
    /// opportunity's model prior. The retained positive masses are the portable
    /// replay basis; their absolute scale is immaterial because guidance
    /// normalization includes every completed or prospective edge.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for an empty or oversized map or a zero
    /// mass.
    pub fn modeled_finite(
        model: ProbabilityModelId,
        prior_weights: BTreeMap<ChoiceValue, u64>,
    ) -> Result<Self, CampaignCodecError> {
        if prior_weights.is_empty()
            || prior_weights.len() > MAX_FINITE_VALUES
            || prior_weights.values().any(|weight| *weight == 0)
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "modeled finite candidate source is empty, oversized, or has zero weight",
            });
        }
        Ok(Self::ModeledFinite(ModeledFiniteCandidateSource {
            model,
            values: prior_weights.keys().cloned().collect(),
            prior_weights,
        }))
    }

    /// Builds one bounded finite target and proposal distribution.
    ///
    /// Every target-support value must have a positive proposal mass. A branch
    /// request using this source admits exactly one categorical draw; multiple
    /// requests therefore form a with-replacement sample stream without
    /// reinterpreting finite enumeration as a probability design.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when either map is empty or oversized,
    /// the maps have different keys, any mass is zero, or either sum exceeds
    /// `u64`.
    pub fn statistical_finite(
        coordinate: u64,
        model: ProbabilityModelId,
        target_masses: BTreeMap<ChoiceValue, u64>,
        proposal_masses: BTreeMap<ChoiceValue, u64>,
    ) -> Result<Self, CampaignCodecError> {
        if target_masses.is_empty()
            || target_masses.len() > MAX_FINITE_VALUES
            || target_masses.keys().ne(proposal_masses.keys())
            || target_masses.values().any(|mass| *mass == 0)
            || proposal_masses.values().any(|mass| *mass == 0)
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "statistical finite source has invalid target or proposal support",
            });
        }
        let target_total = statistical_mass_total(&target_masses)?;
        let proposal_total = statistical_mass_total(&proposal_masses)?;
        Ok(Self::StatisticalFinite(StatisticalFiniteCandidateSource {
            coordinate,
            model,
            values: target_masses.keys().cloned().collect(),
            target_masses,
            proposal_masses,
            target_total,
            proposal_total,
        }))
    }

    /// Builds one bounded SMC target and proposal distribution.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the stage or support is invalid or
    /// either exact mass sum exceeds `u64`.
    // crucible-lint: allow rust-allow -- the SMC source constructor retains every canonical distribution and genealogy field explicitly.
    #[allow(clippy::too_many_arguments)]
    pub fn statistical_smc(
        generation: StatisticalGenerationId,
        input_particle: StatisticalParticleId,
        stage: u32,
        slot: u32,
        model: ProbabilityModelId,
        target_masses: BTreeMap<ChoiceValue, u64>,
        proposal_masses: BTreeMap<ChoiceValue, u64>,
    ) -> Result<Self, CampaignCodecError> {
        if stage == 0
            || target_masses.is_empty()
            || target_masses.len() > MAX_FINITE_VALUES
            || target_masses.keys().ne(proposal_masses.keys())
            || target_masses.values().any(|mass| *mass == 0)
            || proposal_masses.values().any(|mass| *mass == 0)
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "statistical SMC source has invalid stage or support",
            });
        }
        let target_total = statistical_mass_total(&target_masses)?;
        let proposal_total = statistical_mass_total(&proposal_masses)?;
        Ok(Self::StatisticalSmc(StatisticalSmcCandidateSource {
            generation,
            input_particle,
            stage,
            slot,
            model,
            values: target_masses.keys().cloned().collect(),
            target_masses,
            proposal_masses,
            target_total,
            proposal_total,
        }))
    }

    /// Builds a generated candidate source.
    #[must_use]
    pub const fn generated(generator: CandidateGeneratorSpecId) -> Self {
        Self::Generated(generator)
    }

    /// Builds a generated source resolved from one exact probability model.
    #[must_use]
    pub const fn modeled_generated(
        model: ProbabilityModelId,
        generator: CandidateGeneratorSpecId,
    ) -> Self {
        Self::ModeledGenerated(ModeledGeneratedCandidateSource { model, generator })
    }

    /// Returns the exact finite values, if this is an explicit source.
    #[must_use]
    pub fn finite_values(&self) -> Option<&BTreeSet<ChoiceValue>> {
        match self {
            Self::Finite(source) => Some(source.values()),
            Self::ModeledFinite(source) => Some(&source.values),
            Self::StatisticalFinite(source) => Some(&source.values),
            Self::StatisticalSmc(source) => Some(&source.values),
            Self::ModeledGenerated(_) | Self::Generated(_) => None,
        }
    }

    /// Returns the generator identity, if this is a generated source.
    #[must_use]
    pub const fn generator(&self) -> Option<CandidateGeneratorSpecId> {
        match self {
            Self::Finite(_)
            | Self::ModeledFinite(_)
            | Self::StatisticalFinite(_)
            | Self::StatisticalSmc(_) => None,
            Self::ModeledGenerated(source) => Some(source.generator),
            Self::Generated(generator) => Some(*generator),
        }
    }

    /// Returns the positive raw prior weight for one legal source value.
    ///
    /// Uniform finite and generated sources use weight one. `None` means the
    /// value is outside a finite source.
    #[must_use]
    pub fn prior_weight(&self, value: &ChoiceValue) -> Option<u64> {
        match self {
            Self::Finite(source) => source.prior_weights.as_ref().map_or_else(
                || source.values.contains(value).then_some(1),
                |weights| weights.get(value).copied(),
            ),
            Self::ModeledFinite(source) => source.prior_weights.get(value).copied(),
            Self::StatisticalFinite(source) => source.target_masses.get(value).copied(),
            Self::StatisticalSmc(source) => source.target_masses.get(value).copied(),
            Self::ModeledGenerated(_) | Self::Generated(_) => Some(1),
        }
    }

    /// Returns the probability-model identity attached to this source.
    #[must_use]
    pub const fn model_prior(&self) -> Option<ProbabilityModelId> {
        match self {
            Self::ModeledFinite(source) => Some(source.model),
            Self::StatisticalFinite(source) => Some(source.model),
            Self::StatisticalSmc(source) => Some(source.model),
            Self::ModeledGenerated(source) => Some(source.model),
            Self::Finite(_) | Self::Generated(_) => None,
        }
    }
}

impl Canonical for CandidateSource {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Finite(source) => match &source.prior_weights {
                None => {
                    encoder.u8(0);
                    source.values.encode(encoder);
                }
                Some(weights) => {
                    encoder.u8(2);
                    weights.encode(encoder);
                }
            },
            Self::Generated(generator) => {
                encoder.u8(1);
                generator.encode(encoder);
            }
            Self::ModeledFinite(source) => {
                encoder.u8(3);
                source.model.encode(encoder);
                source.prior_weights.encode(encoder);
            }
            Self::ModeledGenerated(source) => {
                encoder.u8(4);
                source.model.encode(encoder);
                source.generator.encode(encoder);
            }
            Self::StatisticalFinite(source) => {
                encoder.u8(5);
                source.coordinate.encode(encoder);
                source.model.encode(encoder);
                source.target_masses.encode(encoder);
                source.proposal_masses.encode(encoder);
            }
            Self::StatisticalSmc(source) => {
                encoder.u8(6);
                source.generation.encode(encoder);
                source.input_particle.encode(encoder);
                source.stage.encode(encoder);
                source.slot.encode(encoder);
                source.model.encode(encoder);
                source.target_masses.encode(encoder);
                source.proposal_masses.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Self::finite(
                decoder.set_bounded(MAX_FINITE_VALUES, "finite-candidate-value-count")?,
            ),
            1 => CandidateGeneratorSpecId::decode(decoder).map(Self::Generated),
            2 => Self::weighted_finite(
                decoder.map_bounded(MAX_FINITE_VALUES, "weighted-finite-candidate-value-count")?,
            ),
            3 => Self::modeled_finite(
                ProbabilityModelId::decode(decoder)?,
                decoder.map_bounded(MAX_FINITE_VALUES, "modeled-finite-candidate-value-count")?,
            ),
            4 => Ok(Self::modeled_generated(
                ProbabilityModelId::decode(decoder)?,
                CandidateGeneratorSpecId::decode(decoder)?,
            )),
            5 => Self::statistical_finite(
                u64::decode(decoder)?,
                ProbabilityModelId::decode(decoder)?,
                decoder.map_bounded(MAX_FINITE_VALUES, "statistical-target-value-count")?,
                decoder.map_bounded(MAX_FINITE_VALUES, "statistical-proposal-value-count")?,
            ),
            6 => Self::statistical_smc(
                StatisticalGenerationId::decode(decoder)?,
                StatisticalParticleId::decode(decoder)?,
                u32::decode(decoder)?,
                u32::decode(decoder)?,
                ProbabilityModelId::decode(decoder)?,
                decoder.map_bounded(MAX_FINITE_VALUES, "SMC-target-value-count")?,
                decoder.map_bounded(MAX_FINITE_VALUES, "SMC-proposal-value-count")?,
            ),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "candidate-source",
                tag,
            }),
        }
    }
}

mod branch_request;
pub use branch_request::{BranchRequest, BranchRequestCause, BranchRequestIdentity};
