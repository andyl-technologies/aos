//! Branch request contracts.

use super::*;

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

/// Immutable identity binding shared by every candidate source at one branch point.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BranchRequestIdentity {
    branch_point: BranchPointId,
    parent: ConfigurationArtifactId,
    opportunity: ChoiceOpportunityId,
    domain: ChoiceDomainId,
}

impl BranchRequestIdentity {
    /// Builds the cross-record identity carried by one branch request.
    #[must_use]
    pub const fn new(
        branch_point: BranchPointId,
        parent: ConfigurationArtifactId,
        opportunity: ChoiceOpportunityId,
        domain: ChoiceDomainId,
    ) -> Self {
        Self {
            branch_point,
            parent,
            opportunity,
            domain,
        }
    }
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
    /// repository before publication or use. Every source, cause, and stop
    /// variant is encoded by the current schema version.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for an invalid stop condition or an
    /// oversized record.
    /// Builds the identity portion accepted by [`Self::new`].
    #[must_use]
    pub const fn identity(
        branch_point: BranchPointId,
        parent: ConfigurationArtifactId,
        opportunity: ChoiceOpportunityId,
        domain: ChoiceDomainId,
    ) -> BranchRequestIdentity {
        BranchRequestIdentity::new(branch_point, parent, opportunity, domain)
    }

    /// Builds a structurally valid branch request from its identity and source policy.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for an invalid stop condition or an
    /// oversized record.
    pub fn new(
        identity: BranchRequestIdentity,
        source: CandidateSource,
        cause: BranchRequestCause,
        budget: BranchBudget,
        stop: StopCondition,
    ) -> Result<Self, CampaignCodecError> {
        Self::new_current(identity, source, cause, budget, stop)
    }

    fn new_current(
        identity: BranchRequestIdentity,
        source: CandidateSource,
        cause: BranchRequestCause,
        budget: BranchBudget,
        stop: StopCondition,
    ) -> Result<Self, CampaignCodecError> {
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
            schema_version: BRANCH_REQUEST_SCHEMA_VERSION,
            branch_point: identity.branch_point,
            parent: identity.parent,
            opportunity: identity.opportunity,
            domain: identity.domain,
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
        if u32::decode(decoder)? != BRANCH_REQUEST_SCHEMA_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported branch-request schema or source",
            });
        }
        Self::new_current(
            Self::identity(
                BranchPointId::decode(decoder)?,
                ConfigurationArtifactId::decode(decoder)?,
                ChoiceOpportunityId::decode(decoder)?,
                ChoiceDomainId::decode(decoder)?,
            ),
            CandidateSource::decode(decoder)?,
            BranchRequestCause::decode(decoder)?,
            BranchBudget::decode(decoder)?,
            StopCondition::decode(decoder)?,
        )
    }
}
