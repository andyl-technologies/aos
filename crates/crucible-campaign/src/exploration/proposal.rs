//! Planner proposals issued from authenticated branch requests.

use super::*;

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
    // crucible-lint: allow rust-allow -- this narrowly scoped exception preserves the surrounding typed boundary.
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
