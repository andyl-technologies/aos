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
}

impl StopCondition {
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
            } => Err(CampaignCodecError::InvalidValue {
                reason: "stop condition has a zero bound",
            }),
            _ => Ok(()),
        }
    }

    pub(crate) const fn uses_extended_wire_schema(&self) -> bool {
        matches!(
            self,
            Self::ExecutionQuanta(_) | Self::VirtualTimeOrExecutionQuanta { .. }
        )
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
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let condition = match decoder.u8()? {
            0 => Self::NextChoice,
            1 => Self::NamedBoundary(
                decoder.string_bounded(MAX_IDENTIFIER_BYTES, "stop-boundary-name-bytes")?,
            ),
            2 => Self::VirtualTimeNanoseconds(u64::decode(decoder)?),
            3 => Self::EventCount(u64::decode(decoder)?),
            4 => Self::Terminal,
            5 => Self::ExecutionQuanta(u64::decode(decoder)?),
            6 => Self::VirtualTimeOrExecutionQuanta {
                virtual_time_nanoseconds: u64::decode(decoder)?,
                execution_quanta: u64::decode(decoder)?,
            },
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

/// Auditable origin of one additive branch request.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum BranchRequestCause {
    /// Pure planner invocation issued the request.
    Planner(PlannerInvocationId),
    /// Idempotent operator command issued the request.
    Operator(CampaignCommandId),
    /// Non-canonical debugger session issued the request.
    Debugger(DebugSessionId),
    /// Active policy attached its default source.
    ExhaustivePolicy(CampaignPolicyId),
    /// Active policy admitted the scenario-declared default as one exact path.
    ScenarioDefault(CampaignPolicyId),
}

impl Canonical for BranchRequestCause {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Planner(id) => {
                encoder.u8(0);
                id.encode(encoder);
            }
            Self::Operator(id) => {
                encoder.u8(1);
                id.encode(encoder);
            }
            Self::Debugger(id) => {
                encoder.u8(2);
                id.encode(encoder);
            }
            Self::ExhaustivePolicy(id) => {
                encoder.u8(3);
                id.encode(encoder);
            }
            Self::ScenarioDefault(id) => {
                encoder.u8(4);
                id.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => PlannerInvocationId::decode(decoder).map(Self::Planner),
            1 => CampaignCommandId::decode(decoder).map(Self::Operator),
            2 => DebugSessionId::decode(decoder).map(Self::Debugger),
            3 => CampaignPolicyId::decode(decoder).map(Self::ExhaustivePolicy),
            4 => CampaignPolicyId::decode(decoder).map(Self::ScenarioDefault),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "branch-request-cause",
                tag,
            }),
        }
    }
}

/// Immutable additive candidate source attached to one semantic branch point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BranchRequest {
    schema_version: u32,
    branch_point: BranchPointId,
    parent: ConfigurationArtifactId,
    opportunity: ChoiceOpportunityId,
    domain: ChoiceDomainId,
    source: CandidateSource,
    cause: BranchRequestCause,
    budget: BranchBudget,
    stop: StopCondition,
}

impl BranchRequest {
    /// Builds a structurally valid branch request.
    ///
    /// Cross-record parent/opportunity/domain bindings are authenticated by the
    /// repository before publication or use. A modeled finite source emits
    /// schema version 3; the established uniform, explicit, and generated
    /// forms continue to emit version 2 so their keyed identities do not drift.
    /// A modeled generated source emits schema version 4. Extended execution-
    /// budget stops emit schema version 6 while versions 1 through 5 retain
    /// their established stop-condition bytes and identities.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for an invalid stop condition or an
    /// oversized record.
    // crucible-lint: allow rust-allow -- this narrowly scoped exception preserves the surrounding typed boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        branch_point: BranchPointId,
        parent: ConfigurationArtifactId,
        opportunity: ChoiceOpportunityId,
        domain: ChoiceDomainId,
        source: CandidateSource,
        cause: BranchRequestCause,
        budget: BranchBudget,
        stop: StopCondition,
    ) -> Result<Self, CampaignCodecError> {
        let schema_version = match (&cause, &source) {
            (_, CandidateSource::StatisticalSmc(_)) => SMC_BRANCH_REQUEST_SCHEMA_VERSION,
            (_, CandidateSource::StatisticalFinite(_)) => STATISTICAL_BRANCH_REQUEST_SCHEMA_VERSION,
            _ if stop.uses_extended_wire_schema() => BRANCH_REQUEST_SCHEMA_VERSION,
            (BranchRequestCause::ScenarioDefault(_), _) => {
                SCENARIO_DEFAULT_BRANCH_REQUEST_SCHEMA_VERSION
            }
            (_, CandidateSource::ModeledFinite(_)) => 3,
            (_, CandidateSource::ModeledGenerated(_)) => 4,
            (_, CandidateSource::Finite(_) | CandidateSource::Generated(_)) => 2,
        };
        Self::new_for_schema(
            schema_version,
            branch_point,
            parent,
            opportunity,
            domain,
            source,
            cause,
            budget,
            stop,
        )
    }

    // crucible-lint: allow rust-allow -- this narrowly scoped exception preserves the surrounding typed boundary.
    #[allow(clippy::too_many_arguments)]
    fn new_for_schema(
        schema_version: u32,
        branch_point: BranchPointId,
        parent: ConfigurationArtifactId,
        opportunity: ChoiceOpportunityId,
        domain: ChoiceDomainId,
        source: CandidateSource,
        cause: BranchRequestCause,
        budget: BranchBudget,
        stop: StopCondition,
    ) -> Result<Self, CampaignCodecError> {
        let incompatible_source = match (&source, schema_version) {
            (CandidateSource::Finite(source), RECORD_SCHEMA_VERSION) => {
                source.prior_weights().is_some()
            }
            (CandidateSource::ModeledFinite(_), version) => {
                !matches!(version, 3 | BRANCH_REQUEST_SCHEMA_VERSION)
            }
            (CandidateSource::ModeledGenerated(_), version) => {
                !matches!(version, 4 | BRANCH_REQUEST_SCHEMA_VERSION)
            }
            (CandidateSource::StatisticalFinite(_), version) => {
                version != STATISTICAL_BRANCH_REQUEST_SCHEMA_VERSION
            }
            (CandidateSource::StatisticalSmc(_), version) => {
                version != SMC_BRANCH_REQUEST_SCHEMA_VERSION
            }
            (CandidateSource::Finite(_) | CandidateSource::Generated(_), _) => false,
        };
        let incompatible_cause = match cause {
            BranchRequestCause::ScenarioDefault(_) => !matches!(
                schema_version,
                SCENARIO_DEFAULT_BRANCH_REQUEST_SCHEMA_VERSION | BRANCH_REQUEST_SCHEMA_VERSION
            ),
            BranchRequestCause::Planner(_)
            | BranchRequestCause::Operator(_)
            | BranchRequestCause::Debugger(_)
            | BranchRequestCause::ExhaustivePolicy(_) => {
                schema_version == SCENARIO_DEFAULT_BRANCH_REQUEST_SCHEMA_VERSION
            }
        };
        let extended_stop_schema = schema_version == BRANCH_REQUEST_SCHEMA_VERSION
            || schema_version == STATISTICAL_BRANCH_REQUEST_SCHEMA_VERSION
            || schema_version == SMC_BRANCH_REQUEST_SCHEMA_VERSION;
        if !matches!(schema_version, 1..=SMC_BRANCH_REQUEST_SCHEMA_VERSION)
            || incompatible_source
            || incompatible_cause
            || (schema_version == STATISTICAL_BRANCH_REQUEST_SCHEMA_VERSION
                && !matches!(source, CandidateSource::StatisticalFinite(_)))
            || (schema_version == SMC_BRANCH_REQUEST_SCHEMA_VERSION
                && !matches!(source, CandidateSource::StatisticalSmc(_)))
            || (stop.uses_extended_wire_schema() && !extended_stop_schema)
            || (!stop.uses_extended_wire_schema()
                && schema_version == BRANCH_REQUEST_SCHEMA_VERSION)
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported branch-request schema or source",
            });
        }
        stop.validate()?;
        if matches!(
            source,
            CandidateSource::StatisticalFinite(_) | CandidateSource::StatisticalSmc(_)
        ) && (!matches!(cause, BranchRequestCause::Planner(_))
            || budget.maximum_proposals() != 1
            || budget.maximum_attempts() != 1)
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "statistical source requires one planner draw",
            });
        }
        let request = Self {
            schema_version,
            branch_point,
            parent,
            opportunity,
            domain,
            source,
            cause,
            budget,
            stop,
        };
        codec::ensure_encoded_size(
            &request,
            MAX_EXACT_RECORD_BYTES,
            "branch-request-encoded-bytes",
        )?;
        Ok(request)
    }

    /// Validates semantic identities and every finite value against resolved records.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for a parent/opportunity/domain mismatch
    /// or an illegal finite value.
    pub fn validate_resolved(
        &self,
        parent: &ConfigurationArtifact,
        opportunity: &ChoiceOpportunity,
        domain: &ChoiceDomain,
    ) -> Result<(), CampaignCodecError> {
        if parent.id()? != self.parent
            || opportunity.id()? != self.opportunity
            || domain.id()? != self.domain
            || opportunity.domain() != self.domain
            || opportunity.scenario() != parent.scenario()
            || opportunity.branch_point_id(parent.configuration()) != self.branch_point
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "branch request disagrees with parent, opportunity, or domain",
            });
        }
        if self
            .source
            .finite_values()
            .is_some_and(|values| values.iter().any(|value| !domain.contains(value)))
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "branch request contains an illegal finite value",
            });
        }
        if self
            .source
            .model_prior()
            .is_some_and(|model| opportunity.model_prior() != Some(model))
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "branch request modeled prior disagrees with its opportunity",
            });
        }
        Ok(())
    }

    /// Returns the semantic branch point.
    #[must_use]
    pub const fn branch_point(&self) -> BranchPointId {
        self.branch_point
    }

    /// Returns the exact parent configuration artifact.
    #[must_use]
    pub const fn parent(&self) -> ConfigurationArtifactId {
        self.parent
    }

    /// Returns the exact choice opportunity.
    #[must_use]
    pub const fn opportunity(&self) -> ChoiceOpportunityId {
        self.opportunity
    }

    /// Returns the exact effective domain.
    #[must_use]
    pub const fn domain(&self) -> ChoiceDomainId {
        self.domain
    }

    /// Returns the finite or generated suspended source.
    #[must_use]
    pub const fn source(&self) -> &CandidateSource {
        &self.source
    }

    /// Returns the auditable request cause.
    #[must_use]
    pub const fn cause(&self) -> BranchRequestCause {
        self.cause
    }

    /// Returns the per-request semantic budget.
    #[must_use]
    pub const fn budget(&self) -> BranchBudget {
        self.budget
    }

    /// Returns the attempt stop condition.
    #[must_use]
    pub const fn stop(&self) -> &StopCondition {
        &self.stop
    }

    pub(crate) const fn schema_version(&self) -> u32 {
        self.schema_version
    }

    /// Returns strict canonical record-body bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes a strict canonical branch request.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, invalid, or
    /// oversized bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        if bytes.len() > MAX_EXACT_RECORD_BYTES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "branch-request-encoded-bytes",
            });
        }
        codec::decode(bytes)
    }

    /// Returns the exact content-derived request identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<BranchRequestId, CampaignCodecError> {
        BranchRequestId::from_content_id(
            crate::ObjectEnvelope::for_record_versioned(
                crate::CampaignRecordKind::BranchRequest,
                self.schema_version,
                crate::object::content_children(self.content_children())?,
                self.canonical_bytes(),
            )?
            .content_id(),
        )
    }

    pub(crate) fn content_children(&self) -> Vec<(&'static str, ContentId)> {
        let mut children = vec![
            ("parent", self.parent.content_id()),
            ("opportunity", self.opportunity.content_id()),
            ("domain", self.domain.content_id()),
        ];
        match self.source {
            CandidateSource::ModeledGenerated(source) => {
                children.push(("generator", source.generator.content_id()));
            }
            CandidateSource::Generated(generator) => {
                children.push(("generator", generator.content_id()));
            }
            CandidateSource::Finite(_)
            | CandidateSource::ModeledFinite(_)
            | CandidateSource::StatisticalFinite(_) => {}
            CandidateSource::StatisticalSmc(_) => {}
        }
        match self.cause {
            BranchRequestCause::Planner(invocation) => {
                children.push(("planner-invocation", invocation.content_id()));
            }
            BranchRequestCause::ExhaustivePolicy(policy) => {
                children.push(("policy", policy.content_id()));
            }
            BranchRequestCause::ScenarioDefault(policy) => {
                children.push(("policy", policy.content_id()));
            }
            BranchRequestCause::Operator(_) | BranchRequestCause::Debugger(_) => {}
        }
        children
    }
}

impl Canonical for BranchRequest {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.branch_point.encode(encoder);
        self.parent.encode(encoder);
        self.opportunity.encode(encoder);
        self.domain.encode(encoder);
        self.source.encode(encoder);
        self.cause.encode(encoder);
        self.budget.encode(encoder);
        self.stop.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        Self::new_for_schema(
            schema_version,
            BranchPointId::decode(decoder)?,
            ConfigurationArtifactId::decode(decoder)?,
            ChoiceOpportunityId::decode(decoder)?,
            ChoiceDomainId::decode(decoder)?,
            CandidateSource::decode(decoder)?,
            BranchRequestCause::decode(decoder)?,
            BranchBudget::decode(decoder)?,
            StopCondition::decode(decoder)?,
        )
    }
}
