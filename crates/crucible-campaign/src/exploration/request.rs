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
}

impl StopCondition {
    pub(crate) fn validate(&self) -> Result<(), CampaignCodecError> {
        match self {
            Self::NamedBoundary(name) => validate_identifier(name, "stop boundary is invalid"),
            Self::VirtualTimeNanoseconds(0) | Self::EventCount(0) => {
                Err(CampaignCodecError::InvalidValue {
                    reason: "stop condition has a zero bound",
                })
            }
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
            Self::ModeledGenerated(_) | Self::Generated(_) => None,
        }
    }

    /// Returns the generator identity, if this is a generated source.
    #[must_use]
    pub const fn generator(&self) -> Option<CandidateGeneratorSpecId> {
        match self {
            Self::Finite(_) | Self::ModeledFinite(_) => None,
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
            Self::ModeledGenerated(_) | Self::Generated(_) => Some(1),
        }
    }

    /// Returns the probability-model identity attached to this source.
    #[must_use]
    pub const fn model_prior(&self) -> Option<ProbabilityModelId> {
        match self {
            Self::ModeledFinite(source) => Some(source.model),
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
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => PlannerInvocationId::decode(decoder).map(Self::Planner),
            1 => CampaignCommandId::decode(decoder).map(Self::Operator),
            2 => DebugSessionId::decode(decoder).map(Self::Debugger),
            3 => CampaignPolicyId::decode(decoder).map(Self::ExhaustivePolicy),
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
    /// A modeled generated source emits schema version 4.
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
        let schema_version = match &source {
            CandidateSource::ModeledFinite(_) => 3,
            CandidateSource::ModeledGenerated(_) => BRANCH_REQUEST_SCHEMA_VERSION,
            CandidateSource::Finite(_) | CandidateSource::Generated(_) => 2,
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
            (CandidateSource::ModeledFinite(_), version) => version != 3,
            (CandidateSource::ModeledGenerated(_), version) => {
                version != BRANCH_REQUEST_SCHEMA_VERSION
            }
            (CandidateSource::Finite(_) | CandidateSource::Generated(_), _) => false,
        };
        if !matches!(schema_version, 1..=BRANCH_REQUEST_SCHEMA_VERSION) || incompatible_source {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported branch-request schema or source",
            });
        }
        stop.validate()?;
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
            CandidateSource::Finite(_) | CandidateSource::ModeledFinite(_) => {}
        }
        match self.cause {
            BranchRequestCause::Planner(invocation) => {
                children.push(("planner-invocation", invocation.content_id()));
            }
            BranchRequestCause::ExhaustivePolicy(policy) => {
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
