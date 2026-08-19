//! Canonical branch requests, proposals, attempts, and lazy expansion state.
//!
//! These records are portable data interpreted by the campaign coordinator and
//! pure planner. They never contain executable closures, native continuations,
//! daemon reservations, worker handles, or materialization locations.

use std::collections::{BTreeMap, BTreeSet};

use crucible_cas::content_store::ContentId;

use crate::codec::{self, Canonical, Decoder, Encoder};
use crate::policy::{MAX_IDENTIFIER_BYTES, validate_identifier};
use crate::{
    AdmissionOrdinal, AttemptAdmissionId, AttemptId, BranchEdgeId, BranchPathId, BranchPointId,
    BranchRequestId, CampaignCodecError, CampaignCommandId, CampaignPolicyId, CampaignViewId,
    CandidateGeneratorSpecId, ChoiceDomain, ChoiceDomainId, ChoiceOpportunity, ChoiceOpportunityId,
    ChoiceValue, ConfigurationArtifact, ConfigurationArtifactId, DebugSessionId, ExpansionStateId,
    PlannerEngineId, PlannerInvocationId, PlannerStateId, PlannerStepId, PolicyArtifactId,
    ProposalId, SelectionId,
};

const RECORD_SCHEMA_VERSION: u32 = 1;
const MAX_FINITE_VALUES: usize = 4096;
const MAX_BRANCH_PATH_EDGES: usize = 65_536;
const MAX_STEP_PROPOSALS: usize = 4096;
const MAX_GUIDANCE_TERMS: usize = 4096;
const MAX_CONTINUATIONS: usize = 65_536;
const MAX_EXACT_RECORD_BYTES: usize = 32 * 1024 * 1024;

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
    fn validate(&self) -> Result<(), CampaignCodecError> {
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
    /// Versioned deterministic generator interpreted from campaign facts.
    Generated(CandidateGeneratorSpecId),
}

/// Nonempty bounded set underlying a finite candidate source.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FiniteCandidateSource {
    values: BTreeSet<ChoiceValue>,
}

impl FiniteCandidateSource {
    /// Returns finite values in canonical order.
    #[must_use]
    pub const fn values(&self) -> &BTreeSet<ChoiceValue> {
        &self.values
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
        Ok(Self::Finite(FiniteCandidateSource { values }))
    }

    /// Builds a generated candidate source.
    #[must_use]
    pub const fn generated(generator: CandidateGeneratorSpecId) -> Self {
        Self::Generated(generator)
    }

    /// Returns the exact finite values, if this is an explicit source.
    #[must_use]
    pub fn finite_values(&self) -> Option<&BTreeSet<ChoiceValue>> {
        match self {
            Self::Finite(source) => Some(source.values()),
            Self::Generated(_) => None,
        }
    }

    /// Returns the generator identity, if this is a generated source.
    #[must_use]
    pub const fn generator(&self) -> Option<CandidateGeneratorSpecId> {
        match self {
            Self::Finite(_) => None,
            Self::Generated(generator) => Some(*generator),
        }
    }
}

impl Canonical for CandidateSource {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Finite(source) => {
                encoder.u8(0);
                source.values.encode(encoder);
            }
            Self::Generated(generator) => {
                encoder.u8(1);
                generator.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Self::finite(
                decoder.set_bounded(MAX_FINITE_VALUES, "finite-candidate-value-count")?,
            ),
            1 => CandidateGeneratorSpecId::decode(decoder).map(Self::Generated),
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
    /// repository before publication or use.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for an invalid stop condition or an
    /// oversized record.
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
        stop.validate()?;
        let request = Self {
            schema_version: RECORD_SCHEMA_VERSION,
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
            crate::ObjectEnvelope::for_record(
                crate::CampaignRecordKind::BranchRequest,
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
            CandidateSource::Generated(generator) => {
                children.push(("generator", generator.content_id()));
            }
            CandidateSource::Finite(_) => {}
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
        require_schema(u32::decode(decoder)?)?;
        Self::new(
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

/// One canonical candidate emitted by a request continuation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proposal {
    schema_version: u32,
    branch_point: BranchPointId,
    request: BranchRequestId,
    domain: ChoiceDomainId,
    value: ChoiceValue,
    policy: CampaignPolicyId,
    planner_invocation: Option<PlannerInvocationId>,
    ordinal: u64,
    guidance_basis: CampaignViewId,
}

impl Proposal {
    /// Builds a canonical proposal.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the ordinal is zero.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        branch_point: BranchPointId,
        request: BranchRequestId,
        domain: ChoiceDomainId,
        value: ChoiceValue,
        policy: CampaignPolicyId,
        planner_invocation: Option<PlannerInvocationId>,
        ordinal: u64,
        guidance_basis: CampaignViewId,
    ) -> Result<Self, CampaignCodecError> {
        if ordinal == 0 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "proposal ordinal is zero",
            });
        }
        Ok(Self {
            schema_version: RECORD_SCHEMA_VERSION,
            branch_point,
            request,
            domain,
            value,
            policy,
            planner_invocation,
            ordinal,
            guidance_basis,
        })
    }

    /// Validates the proposal against its exact request and domain.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for identity drift or an illegal value.
    pub fn validate_resolved(
        &self,
        request: &BranchRequest,
        domain: &ChoiceDomain,
    ) -> Result<(), CampaignCodecError> {
        if request.id()? != self.request
            || request.branch_point() != self.branch_point
            || request.domain() != self.domain
            || domain.id()? != self.domain
            || !domain.contains(&self.value)
            || request
                .source()
                .finite_values()
                .is_some_and(|values| !values.contains(&self.value))
            || self.ordinal > request.budget().maximum_proposals()
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "proposal disagrees with its request, source, domain, or budget",
            });
        }
        Ok(())
    }

    /// Returns the branch point receiving the proposal.
    #[must_use]
    pub const fn branch_point(&self) -> BranchPointId {
        self.branch_point
    }

    /// Returns the source request.
    #[must_use]
    pub const fn request(&self) -> BranchRequestId {
        self.request
    }

    /// Returns the exact domain.
    #[must_use]
    pub const fn domain(&self) -> ChoiceDomainId {
        self.domain
    }

    /// Returns the proposed legal value.
    #[must_use]
    pub const fn value(&self) -> &ChoiceValue {
        &self.value
    }

    /// Returns the active policy that issued this proposal.
    #[must_use]
    pub const fn policy(&self) -> CampaignPolicyId {
        self.policy
    }

    /// Returns the pure planner invocation, if planner generated.
    #[must_use]
    pub const fn planner_invocation(&self) -> Option<PlannerInvocationId> {
        self.planner_invocation
    }

    /// Returns the request-local one-based proposal ordinal.
    #[must_use]
    pub const fn ordinal(&self) -> u64 {
        self.ordinal
    }

    /// Returns the complete semantic view used for guidance.
    #[must_use]
    pub const fn guidance_basis(&self) -> CampaignViewId {
        self.guidance_basis
    }

    /// Returns strict canonical record-body bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes strict canonical proposal bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, or invalid bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        codec::decode(bytes)
    }

    /// Returns the exact content-derived proposal identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<ProposalId, CampaignCodecError> {
        ProposalId::from_content_id(
            crate::ObjectEnvelope::for_record(
                crate::CampaignRecordKind::Proposal,
                crate::object::content_children(self.content_children())?,
                self.canonical_bytes(),
            )?
            .content_id(),
        )
    }

    pub(crate) fn content_children(&self) -> Vec<(&'static str, ContentId)> {
        let mut children = vec![
            ("request", self.request.content_id()),
            ("domain", self.domain.content_id()),
            ("policy", self.policy.content_id()),
            ("guidance-basis", self.guidance_basis.content_id()),
        ];
        if let Some(invocation) = self.planner_invocation {
            children.push(("planner-invocation", invocation.content_id()));
        }
        children
    }
}

impl Canonical for Proposal {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.branch_point.encode(encoder);
        self.request.encode(encoder);
        self.domain.encode(encoder);
        self.value.encode(encoder);
        self.policy.encode(encoder);
        self.planner_invocation.encode(encoder);
        self.ordinal.encode(encoder);
        self.guidance_basis.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_schema(u32::decode(decoder)?)?;
        Self::new(
            BranchPointId::decode(decoder)?,
            BranchRequestId::decode(decoder)?,
            ChoiceDomainId::decode(decoder)?,
            ChoiceValue::decode(decoder)?,
            CampaignPolicyId::decode(decoder)?,
            Option::decode(decoder)?,
            u64::decode(decoder)?,
            CampaignViewId::decode(decoder)?,
        )
    }
}

/// Authenticated ordered semantic edge path used for guidance backpropagation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BranchPath {
    schema_version: u32,
    edges: Vec<BranchEdgeId>,
}

impl BranchPath {
    /// Builds a bounded branch path; an empty path represents genesis discovery.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the path exceeds 65,536 edges.
    pub fn new(edges: Vec<BranchEdgeId>) -> Result<Self, CampaignCodecError> {
        if edges.len() > MAX_BRANCH_PATH_EDGES {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "branch-path-edge-count",
            });
        }
        Ok(Self {
            schema_version: RECORD_SCHEMA_VERSION,
            edges,
        })
    }

    /// Returns edges from root to leaf.
    #[must_use]
    pub fn edges(&self) -> &[BranchEdgeId] {
        &self.edges
    }

    /// Returns strict canonical bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Returns the exact stored path identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<BranchPathId, CampaignCodecError> {
        BranchPathId::from_content_id(
            crate::ObjectEnvelope::for_record(
                crate::CampaignRecordKind::BranchPath,
                BTreeSet::new(),
                self.canonical_bytes(),
            )?
            .content_id(),
        )
    }
}

impl Canonical for BranchPath {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.edges.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_schema(u32::decode(decoder)?)?;
        Self::new(decoder.sequence_bounded(
            MAX_BRANCH_PATH_EDGES,
            "branch-path-edge-count",
            BranchEdgeId::decode,
        )?)
    }
}

/// Explicit discovery or one-selection branch execution start.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AttemptStart {
    /// Realizes an existing configuration until the next boundary.
    Discover {
        /// Exact starting configuration artifact.
        configuration: ConfigurationArtifactId,
    },
    /// Applies exactly one recorded selection at a known parent.
    Branch {
        /// Semantic edge being realized.
        edge: BranchEdgeId,
        /// Exact parent configuration artifact.
        parent: ConfigurationArtifactId,
        /// Exact recorded selection.
        selection: SelectionId,
    },
}

impl Canonical for AttemptStart {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Discover { configuration } => {
                encoder.u8(0);
                configuration.encode(encoder);
            }
            Self::Branch {
                edge,
                parent,
                selection,
            } => {
                encoder.u8(1);
                edge.encode(encoder);
                parent.encode(encoder);
                selection.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Discover {
                configuration: ConfigurationArtifactId::decode(decoder)?,
            }),
            1 => Ok(Self::Branch {
                edge: BranchEdgeId::decode(decoder)?,
                parent: ConfigurationArtifactId::decode(decoder)?,
                selection: SelectionId::decode(decoder)?,
            }),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "attempt-start",
                tag,
            }),
        }
    }
}

/// Immutable semantic execution attempt independent of placement and retry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Attempt {
    schema_version: u32,
    start: AttemptStart,
    path: BranchPathId,
    stop: StopCondition,
}

impl Attempt {
    /// Builds a semantic attempt.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for an invalid stop condition.
    pub fn new(
        start: AttemptStart,
        path: BranchPathId,
        stop: StopCondition,
    ) -> Result<Self, CampaignCodecError> {
        stop.validate()?;
        Ok(Self {
            schema_version: RECORD_SCHEMA_VERSION,
            start,
            path,
            stop,
        })
    }

    /// Returns discovery or branch start semantics.
    #[must_use]
    pub const fn start(&self) -> AttemptStart {
        self.start
    }

    /// Returns the authenticated root-to-leaf edge path.
    #[must_use]
    pub const fn path(&self) -> BranchPathId {
        self.path
    }

    /// Returns the semantic stop condition.
    #[must_use]
    pub const fn stop(&self) -> &StopCondition {
        &self.stop
    }

    /// Returns strict canonical bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Returns the exact semantic attempt identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<AttemptId, CampaignCodecError> {
        AttemptId::from_content_id(
            crate::ObjectEnvelope::for_record(
                crate::CampaignRecordKind::Attempt,
                crate::object::content_children(self.content_children())?,
                self.canonical_bytes(),
            )?
            .content_id(),
        )
    }

    pub(crate) fn content_children(&self) -> Vec<(&'static str, ContentId)> {
        let mut children = vec![("path", self.path.content_id())];
        match self.start {
            AttemptStart::Discover { configuration } => {
                children.push(("configuration", configuration.content_id()));
            }
            AttemptStart::Branch {
                parent, selection, ..
            } => {
                children.push(("parent", parent.content_id()));
                children.push(("selection", selection.content_id()));
            }
        }
        children
    }
}

impl Canonical for Attempt {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.start.encode(encoder);
        self.path.encode(encoder);
        self.stop.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_schema(u32::decode(decoder)?)?;
        Self::new(
            AttemptStart::decode(decoder)?,
            BranchPathId::decode(decoder)?,
            StopCondition::decode(decoder)?,
        )
    }
}

/// Unique execution basis or an additional deduplicated proposal cause.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum AttemptAdmissionRole {
    /// The one cause that spends attempt budget and fixes estimator provenance.
    ExecutionBasis {
        /// Proposal, absent only for discovery.
        proposal: Option<ProposalId>,
        /// Operator/planner/debugger/policy cause.
        cause: BranchRequestCause,
        /// Global strict-mode order.
        admission_ordinal: AdmissionOrdinal,
    },
    /// Later proposal that converged on an already admitted attempt.
    AdditionalCause {
        /// Deduplicated proposal.
        proposal: ProposalId,
    },
}

impl Canonical for AttemptAdmissionRole {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::ExecutionBasis {
                proposal,
                cause,
                admission_ordinal,
            } => {
                encoder.u8(0);
                proposal.encode(encoder);
                cause.encode(encoder);
                admission_ordinal.encode(encoder);
            }
            Self::AdditionalCause { proposal } => {
                encoder.u8(1);
                proposal.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::ExecutionBasis {
                proposal: Option::decode(decoder)?,
                cause: BranchRequestCause::decode(decoder)?,
                admission_ordinal: AdmissionOrdinal::decode(decoder)?,
            }),
            1 => Ok(Self::AdditionalCause {
                proposal: ProposalId::decode(decoder)?,
            }),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "attempt-admission-role",
                tag,
            }),
        }
    }
}

/// Immutable provenance link from a cause to one semantic attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct AttemptAdmission {
    schema_version: u32,
    attempt: AttemptId,
    role: AttemptAdmissionRole,
}

impl AttemptAdmission {
    /// Builds an attempt admission record.
    #[must_use]
    pub const fn new(attempt: AttemptId, role: AttemptAdmissionRole) -> Self {
        Self {
            schema_version: RECORD_SCHEMA_VERSION,
            attempt,
            role,
        }
    }

    /// Returns the admitted semantic attempt.
    #[must_use]
    pub const fn attempt(self) -> AttemptId {
        self.attempt
    }

    /// Returns execution-basis or additional-cause provenance.
    #[must_use]
    pub const fn role(self) -> AttemptAdmissionRole {
        self.role
    }

    /// Returns strict canonical bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Returns the exact admission-record identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<AttemptAdmissionId, CampaignCodecError> {
        AttemptAdmissionId::from_content_id(
            crate::ObjectEnvelope::for_record(
                crate::CampaignRecordKind::AttemptAdmission,
                crate::object::content_children(self.content_children())?,
                self.canonical_bytes(),
            )?
            .content_id(),
        )
    }

    pub(crate) fn content_children(&self) -> Vec<(String, ContentId)> {
        let mut children = vec![("attempt".to_owned(), self.attempt.content_id())];
        match self.role {
            AttemptAdmissionRole::ExecutionBasis {
                proposal: Some(proposal),
                cause,
                ..
            } => {
                children.push(("proposal".to_owned(), proposal.content_id()));
                add_cause_child(&mut children, cause);
            }
            AttemptAdmissionRole::ExecutionBasis {
                proposal: None,
                cause,
                ..
            } => add_cause_child(&mut children, cause),
            AttemptAdmissionRole::AdditionalCause { proposal } => {
                children.push(("proposal".to_owned(), proposal.content_id()));
            }
        }
        children
    }
}

impl Canonical for AttemptAdmission {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.attempt.encode(encoder);
        self.role.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_schema(u32::decode(decoder)?)?;
        Ok(Self::new(
            AttemptId::decode(decoder)?,
            AttemptAdmissionRole::decode(decoder)?,
        ))
    }
}

/// Coordinator-computed semantic resource accounting for a planner step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PlanningAccounting {
    /// Accepted proposals.
    pub proposals: u64,
    /// Newly admitted attempts.
    pub attempts: u64,
    /// Proposals that reused an existing semantic edge/attempt.
    pub deduplicated: u64,
    /// Deterministic planner fuel consumed.
    pub fuel: u64,
}

impl Canonical for PlanningAccounting {
    fn encode(&self, encoder: &mut Encoder) {
        self.proposals.encode(encoder);
        self.attempts.encode(encoder);
        self.deduplicated.encode(encoder);
        self.fuel.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self {
            proposals: u64::decode(decoder)?,
            attempts: u64::decode(decoder)?,
            deduplicated: u64::decode(decoder)?,
            fuel: u64::decode(decoder)?,
        })
    }
}

/// Exact fixed-point evidence used to rank one continuation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct GuidanceEvidence {
    terms_micros: BTreeMap<String, i64>,
}

impl GuidanceEvidence {
    /// Builds bounded named fixed-point evidence.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for too many or invalid term names.
    pub fn new(terms_micros: BTreeMap<String, i64>) -> Result<Self, CampaignCodecError> {
        if terms_micros.len() > MAX_GUIDANCE_TERMS {
            return Err(CampaignCodecError::LimitExceeded {
                limit: "guidance-evidence-term-count",
            });
        }
        for name in terms_micros.keys() {
            validate_identifier(name, "guidance evidence term is invalid")?;
        }
        Ok(Self { terms_micros })
    }

    /// Returns fixed-point terms in canonical name order.
    #[must_use]
    pub const fn terms_micros(&self) -> &BTreeMap<String, i64> {
        &self.terms_micros
    }
}

impl Canonical for GuidanceEvidence {
    fn encode(&self, encoder: &mut Encoder) {
        self.terms_micros.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(decoder.map_bounded_by(
            MAX_GUIDANCE_TERMS,
            "guidance-evidence-term-count",
            |decoder| {
                decoder.string_bounded(MAX_IDENTIFIER_BYTES, "guidance-evidence-term-name-bytes")
            },
            i64::decode,
        )?)
    }
}

/// Coordinator-accepted result of one pure planner invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannerStep {
    schema_version: u32,
    parent: Option<PlannerStepId>,
    invocation: PlannerInvocationId,
    policy: CampaignPolicyId,
    engine: PlannerEngineId,
    policy_artifact: PolicyArtifactId,
    input_view: CampaignViewId,
    selected_branch_point: BranchPointId,
    selected_source: BranchRequestId,
    issued_proposals: Vec<ProposalId>,
    next_state: PlannerStateId,
    accounting: PlanningAccounting,
    evidence: GuidanceEvidence,
}

impl PlannerStep {
    /// Builds a bounded accepted planner step.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when no proposal was issued or the output
    /// exceeds the per-step bound.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        parent: Option<PlannerStepId>,
        invocation: PlannerInvocationId,
        policy: CampaignPolicyId,
        engine: PlannerEngineId,
        policy_artifact: PolicyArtifactId,
        input_view: CampaignViewId,
        selected_branch_point: BranchPointId,
        selected_source: BranchRequestId,
        issued_proposals: Vec<ProposalId>,
        next_state: PlannerStateId,
        accounting: PlanningAccounting,
        evidence: GuidanceEvidence,
    ) -> Result<Self, CampaignCodecError> {
        if issued_proposals.is_empty() || issued_proposals.len() > MAX_STEP_PROPOSALS {
            return Err(CampaignCodecError::InvalidValue {
                reason: "planner step proposal set is empty or oversized",
            });
        }
        Ok(Self {
            schema_version: RECORD_SCHEMA_VERSION,
            parent,
            invocation,
            policy,
            engine,
            policy_artifact,
            input_view,
            selected_branch_point,
            selected_source,
            issued_proposals,
            next_state,
            accounting,
            evidence,
        })
    }

    /// Returns the prior accepted planner step, if any.
    #[must_use]
    pub const fn parent(&self) -> Option<PlannerStepId> {
        self.parent
    }

    /// Returns the pure invocation accepted by this step.
    #[must_use]
    pub const fn invocation(&self) -> PlannerInvocationId {
        self.invocation
    }

    /// Returns the active policy.
    #[must_use]
    pub const fn policy(&self) -> CampaignPolicyId {
        self.policy
    }

    /// Returns the planner engine.
    #[must_use]
    pub const fn engine(&self) -> PlannerEngineId {
        self.engine
    }

    /// Returns the reproducible planner policy artifact.
    #[must_use]
    pub const fn policy_artifact(&self) -> PolicyArtifactId {
        self.policy_artifact
    }

    /// Returns the complete semantic input view.
    #[must_use]
    pub const fn input_view(&self) -> CampaignViewId {
        self.input_view
    }

    /// Returns the selected branch point.
    #[must_use]
    pub const fn selected_branch_point(&self) -> BranchPointId {
        self.selected_branch_point
    }

    /// Returns the selected suspended source.
    #[must_use]
    pub const fn selected_source(&self) -> BranchRequestId {
        self.selected_source
    }

    /// Returns issued proposal identities in deterministic order.
    #[must_use]
    pub fn issued_proposals(&self) -> &[ProposalId] {
        &self.issued_proposals
    }

    /// Returns the portable post-invocation planner state.
    #[must_use]
    pub const fn next_state(&self) -> PlannerStateId {
        self.next_state
    }

    /// Returns coordinator-computed accepted accounting.
    #[must_use]
    pub const fn accounting(&self) -> PlanningAccounting {
        self.accounting
    }

    /// Returns exact score evidence.
    #[must_use]
    pub const fn evidence(&self) -> &GuidanceEvidence {
        &self.evidence
    }

    /// Returns strict canonical record-body bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Returns the exact content-derived planner-step identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<PlannerStepId, CampaignCodecError> {
        PlannerStepId::from_content_id(
            crate::ObjectEnvelope::for_record(
                crate::CampaignRecordKind::PlannerStep,
                crate::object::content_children(self.content_children())?,
                self.canonical_bytes(),
            )?
            .content_id(),
        )
    }

    pub(crate) fn content_children(&self) -> Vec<(String, ContentId)> {
        let mut children = vec![
            ("invocation".to_owned(), self.invocation.content_id()),
            ("policy".to_owned(), self.policy.content_id()),
            ("engine".to_owned(), self.engine.content_id()),
            (
                "policy-artifact".to_owned(),
                self.policy_artifact.content_id(),
            ),
            ("input-view".to_owned(), self.input_view.content_id()),
            (
                "selected-source".to_owned(),
                self.selected_source.content_id(),
            ),
            ("next-state".to_owned(), self.next_state.content_id()),
        ];
        if let Some(parent) = self.parent {
            children.push(("parent-step".to_owned(), parent.content_id()));
        }
        children.extend(
            self.issued_proposals
                .iter()
                .enumerate()
                .map(|(index, proposal)| (format!("proposal.{index:04x}"), proposal.content_id())),
        );
        children
    }
}

impl Canonical for PlannerStep {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.parent.encode(encoder);
        self.invocation.encode(encoder);
        self.policy.encode(encoder);
        self.engine.encode(encoder);
        self.policy_artifact.encode(encoder);
        self.input_view.encode(encoder);
        self.selected_branch_point.encode(encoder);
        self.selected_source.encode(encoder);
        self.issued_proposals.encode(encoder);
        self.next_state.encode(encoder);
        self.accounting.encode(encoder);
        self.evidence.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_schema(u32::decode(decoder)?)?;
        Self::new(
            Option::decode(decoder)?,
            PlannerInvocationId::decode(decoder)?,
            CampaignPolicyId::decode(decoder)?,
            PlannerEngineId::decode(decoder)?,
            PolicyArtifactId::decode(decoder)?,
            CampaignViewId::decode(decoder)?,
            BranchPointId::decode(decoder)?,
            BranchRequestId::decode(decoder)?,
            decoder.sequence_bounded(
                MAX_STEP_PROPOSALS,
                "planner-step-proposal-count",
                ProposalId::decode,
            )?,
            PlannerStateId::decode(decoder)?,
            PlanningAccounting::decode(decoder)?,
            GuidanceEvidence::decode(decoder)?,
        )
    }
}

/// Derived readiness of one request's suspended continuation.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ContinuationState {
    /// Eligible to yield under current feedback and budgets.
    Ready,
    /// Requires more completed descendant visits before widening.
    WaitingForFeedback {
        /// Visits currently credited.
        completed_visits: u64,
        /// Visits required for the next child.
        required_visits: u64,
    },
    /// Sampling source remains unbounded/open but is not currently ready.
    Open,
    /// Source has a complete exhaustion proof.
    Exhausted,
    /// Request budget or explicit policy permanently closed the source.
    Closed,
}

impl Canonical for ContinuationState {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Ready => encoder.u8(0),
            Self::WaitingForFeedback {
                completed_visits,
                required_visits,
            } => {
                encoder.u8(1);
                completed_visits.encode(encoder);
                required_visits.encode(encoder);
            }
            Self::Open => encoder.u8(2),
            Self::Exhausted => encoder.u8(3),
            Self::Closed => encoder.u8(4),
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Ready),
            1 => {
                let completed_visits = u64::decode(decoder)?;
                let required_visits = u64::decode(decoder)?;
                if required_visits <= completed_visits {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "waiting continuation is already eligible",
                    });
                }
                Ok(Self::WaitingForFeedback {
                    completed_visits,
                    required_visits,
                })
            }
            2 => Ok(Self::Open),
            3 => Ok(Self::Exhausted),
            4 => Ok(Self::Closed),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "continuation-state",
                tag,
            }),
        }
    }
}

/// Exact integer statistics projected for one semantic branch point.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct ExpansionStatistics {
    /// Distinct proposed edges.
    pub admitted_children: u64,
    /// Completed descendant visits credited exactly once.
    pub completed_visits: u64,
    /// Signed fixed-point reward sum in millionths.
    pub reward_sum_micros: i64,
    /// Distinct coverage/semantic novelty events.
    pub novelty_events: u64,
    /// Distinct correctness findings.
    pub findings: u64,
}

impl Canonical for ExpansionStatistics {
    fn encode(&self, encoder: &mut Encoder) {
        self.admitted_children.encode(encoder);
        self.completed_visits.encode(encoder);
        self.reward_sum_micros.encode(encoder);
        self.novelty_events.encode(encoder);
        self.findings.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self {
            admitted_children: u64::decode(decoder)?,
            completed_visits: u64::decode(decoder)?,
            reward_sum_micros: i64::decode(decoder)?,
            novelty_events: u64::decode(decoder)?,
            findings: u64::decode(decoder)?,
        })
    }
}

/// Rebuildable authenticated continuation projection for one branch point.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExpansionState {
    schema_version: u32,
    branch_point: BranchPointId,
    request_root: ContentId,
    proposal_root: ContentId,
    observation_root: ContentId,
    statistics: ExpansionStatistics,
    continuations: BTreeMap<BranchRequestId, ContinuationState>,
}

impl ExpansionState {
    /// Builds a bounded expansion projection over exact semantic roots.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when a root is not a Merkle node or the
    /// continuation map exceeds 65,536 entries.
    pub fn new(
        branch_point: BranchPointId,
        request_root: ContentId,
        proposal_root: ContentId,
        observation_root: ContentId,
        statistics: ExpansionStatistics,
        continuations: BTreeMap<BranchRequestId, ContinuationState>,
    ) -> Result<Self, CampaignCodecError> {
        if [request_root, proposal_root, observation_root]
            .iter()
            .any(|id| id.kind() != crucible_cas::content_store::ObjectKind::MerkleNode)
            || continuations.len() > MAX_CONTINUATIONS
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "expansion state has invalid roots or too many continuations",
            });
        }
        Ok(Self {
            schema_version: RECORD_SCHEMA_VERSION,
            branch_point,
            request_root,
            proposal_root,
            observation_root,
            statistics,
            continuations,
        })
    }

    /// Returns the semantic branch point.
    #[must_use]
    pub const fn branch_point(&self) -> BranchPointId {
        self.branch_point
    }

    /// Returns the request-fact root used to derive this projection.
    #[must_use]
    pub const fn request_root(&self) -> ContentId {
        self.request_root
    }

    /// Returns the proposal-fact root used to derive this projection.
    #[must_use]
    pub const fn proposal_root(&self) -> ContentId {
        self.proposal_root
    }

    /// Returns the observation root used to derive this projection.
    #[must_use]
    pub const fn observation_root(&self) -> ContentId {
        self.observation_root
    }

    /// Returns derived exact statistics.
    #[must_use]
    pub const fn statistics(&self) -> ExpansionStatistics {
        self.statistics
    }

    /// Returns request continuation states in canonical request-ID order.
    #[must_use]
    pub const fn continuations(&self) -> &BTreeMap<BranchRequestId, ContinuationState> {
        &self.continuations
    }

    /// Returns strict canonical projection bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Returns the exact content-derived projection identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(&self) -> Result<ExpansionStateId, CampaignCodecError> {
        ExpansionStateId::from_content_id(
            crate::ObjectEnvelope::for_record(
                crate::CampaignRecordKind::ExpansionState,
                crate::object::content_children(self.content_children())?,
                self.canonical_bytes(),
            )?
            .content_id(),
        )
    }

    pub(crate) fn content_children(&self) -> Vec<(String, ContentId)> {
        let mut children = vec![
            ("requests".to_owned(), self.request_root),
            ("proposals".to_owned(), self.proposal_root),
            ("observations".to_owned(), self.observation_root),
        ];
        children.extend(
            self.continuations
                .keys()
                .enumerate()
                .map(|(index, request)| {
                    (format!("continuation.{index:08x}"), request.content_id())
                }),
        );
        children
    }
}

impl Canonical for ExpansionState {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.branch_point.encode(encoder);
        Canonical::encode(&self.request_root, encoder);
        Canonical::encode(&self.proposal_root, encoder);
        Canonical::encode(&self.observation_root, encoder);
        self.statistics.encode(encoder);
        self.continuations.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_schema(u32::decode(decoder)?)?;
        Self::new(
            BranchPointId::decode(decoder)?,
            ContentId::decode(decoder)?,
            ContentId::decode(decoder)?,
            ContentId::decode(decoder)?,
            ExpansionStatistics::decode(decoder)?,
            decoder.map_bounded(MAX_CONTINUATIONS, "expansion-continuation-count")?,
        )
    }
}

fn add_cause_child(children: &mut Vec<(String, ContentId)>, cause: BranchRequestCause) {
    match cause {
        BranchRequestCause::Planner(invocation) => {
            children.push(("planner-invocation".to_owned(), invocation.content_id()));
        }
        BranchRequestCause::ExhaustivePolicy(policy) => {
            children.push(("policy".to_owned(), policy.content_id()));
        }
        BranchRequestCause::Operator(_) | BranchRequestCause::Debugger(_) => {}
    }
}

fn require_schema(actual: u32) -> Result<(), CampaignCodecError> {
    if actual == RECORD_SCHEMA_VERSION {
        Ok(())
    } else {
        Err(CampaignCodecError::InvalidValue {
            reason: "unsupported exploration record schema version",
        })
    }
}
