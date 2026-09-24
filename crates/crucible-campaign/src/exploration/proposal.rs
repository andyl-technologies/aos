//! Planner proposals issued from authenticated branch requests.

use super::*;

/// Exact one-draw probability evidence retained on a statistical proposal.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StatisticalProposalEvidence {
    target_mass: u64,
    target_total: u64,
    proposal_mass: u64,
    proposal_total: u64,
}

impl StatisticalProposalEvidence {
    /// Builds positive raw target and proposal masses for one selected value.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when a mass or total is zero or a mass
    /// exceeds its corresponding total.
    pub fn new(
        target_mass: u64,
        target_total: u64,
        proposal_mass: u64,
        proposal_total: u64,
    ) -> Result<Self, CampaignCodecError> {
        if target_mass == 0
            || target_total == 0
            || proposal_mass == 0
            || proposal_total == 0
            || target_mass > target_total
            || proposal_mass > proposal_total
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "statistical proposal evidence has invalid masses",
            });
        }
        Ok(Self {
            target_mass,
            target_total,
            proposal_mass,
            proposal_total,
        })
    }

    /// Returns the selected value's positive raw target mass.
    #[must_use]
    pub const fn target_mass(self) -> u64 {
        self.target_mass
    }

    /// Returns the positive sum of all target masses.
    #[must_use]
    pub const fn target_total(self) -> u64 {
        self.target_total
    }

    /// Returns the selected value's positive raw proposal mass.
    #[must_use]
    pub const fn proposal_mass(self) -> u64 {
        self.proposal_mass
    }

    /// Returns the positive sum of all proposal masses.
    #[must_use]
    pub const fn proposal_total(self) -> u64 {
        self.proposal_total
    }
}

impl Canonical for StatisticalProposalEvidence {
    fn encode(&self, encoder: &mut Encoder) {
        self.target_mass.encode(encoder);
        self.target_total.encode(encoder);
        self.proposal_mass.encode(encoder);
        self.proposal_total.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
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
    statistical_evidence: Option<StatisticalProposalEvidence>,
    constraint_evidence: Option<crate::ChoiceGroupConstraintEvidence>,
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
        let constraint_evidence = matches!(value, ChoiceValue::Group(_))
            .then(crate::ChoiceGroupConstraintEvidence::admitted);
        Ok(Self {
            schema_version: PROPOSAL_SCHEMA_VERSION,
            branch_point,
            request,
            domain,
            value,
            policy,
            planner_invocation,
            ordinal,
            guidance_basis,
            statistical_evidence: None,
            constraint_evidence,
        })
    }

    /// Builds a proposal and attaches exact evidence when its request is statistical.
    ///
    /// The current schema carries explicit optional statistical evidence for
    /// both statistical and non-statistical requests.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the ordinal is zero, the request ID
    /// disagrees, or the statistical value is absent from the request support.
    // crucible-lint: allow rust-allow -- this narrowly scoped exception preserves the surrounding typed boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn new_for_request(
        branch_point: BranchPointId,
        request_id: BranchRequestId,
        domain: ChoiceDomainId,
        value: ChoiceValue,
        policy: CampaignPolicyId,
        planner_invocation: Option<PlannerInvocationId>,
        ordinal: u64,
        guidance_basis: CampaignViewId,
        request: &BranchRequest,
    ) -> Result<Self, CampaignCodecError> {
        if request.id()? != request_id {
            return Err(CampaignCodecError::InvalidValue {
                reason: "proposal request evidence has the wrong identity",
            });
        }
        let mut proposal = Self::new(
            branch_point,
            request_id,
            domain,
            value,
            policy,
            planner_invocation,
            ordinal,
            guidance_basis,
        )?;
        if let Some(distribution) = request.source().statistical_distribution() {
            let target_mass = distribution
                .target_masses
                .get(&proposal.value)
                .copied()
                .ok_or(CampaignCodecError::InvalidValue {
                    reason: "statistical proposal value is outside request support",
                })?;
            let proposal_mass = distribution
                .proposal_masses
                .get(&proposal.value)
                .copied()
                .ok_or(CampaignCodecError::InvalidValue {
                    reason: "statistical proposal value is outside request support",
                })?;
            proposal.statistical_evidence = Some(StatisticalProposalEvidence::new(
                target_mass,
                distribution.target_total,
                proposal_mass,
                distribution.proposal_total,
            )?);
        }
        Ok(proposal)
    }

    /// Rebuilds a statistical proposal from evidence carried across planner pages.
    ///
    /// The repository authenticates the evidence against the referenced branch
    /// request before admitting the proposal.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the ordinal is zero.
    // crucible-lint: allow rust-allow -- this narrowly scoped exception preserves the surrounding typed boundary.
    #[allow(clippy::too_many_arguments)]
    pub fn new_with_statistical_evidence(
        branch_point: BranchPointId,
        request: BranchRequestId,
        domain: ChoiceDomainId,
        value: ChoiceValue,
        policy: CampaignPolicyId,
        planner_invocation: Option<PlannerInvocationId>,
        ordinal: u64,
        guidance_basis: CampaignViewId,
        statistical_evidence: StatisticalProposalEvidence,
    ) -> Result<Self, CampaignCodecError> {
        let mut proposal = Self::new(
            branch_point,
            request,
            domain,
            value,
            policy,
            planner_invocation,
            ordinal,
            guidance_basis,
        )?;
        proposal.statistical_evidence = Some(statistical_evidence);
        Ok(proposal)
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
        let expected_statistical_evidence = match request.source().statistical_distribution() {
            Some(distribution) => {
                let target_mass = distribution.target_masses.get(&self.value).copied();
                let proposal_mass = distribution.proposal_masses.get(&self.value).copied();
                match (target_mass, proposal_mass) {
                    (Some(target_mass), Some(proposal_mass)) => {
                        Some(StatisticalProposalEvidence::new(
                            target_mass,
                            distribution.target_total,
                            proposal_mass,
                            distribution.proposal_total,
                        )?)
                    }
                    _ => None,
                }
            }
            _ => None,
        };
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
            || (expected_statistical_evidence.is_some() && self.ordinal != 1)
            || self.statistical_evidence != expected_statistical_evidence
            || match (domain, &self.value, self.constraint_evidence) {
                (ChoiceDomain::Group(group), ChoiceValue::Group(value), Some(evidence)) => {
                    evidence.validate_resolved(value, group).is_err()
                }
                (ChoiceDomain::Group(_), _, _)
                | (_, ChoiceValue::Group(_), _)
                | (_, _, Some(_)) => true,
                _ => false,
            }
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

    /// Returns exact one-draw evidence when this proposal is statistical.
    #[must_use]
    pub const fn statistical_evidence(&self) -> Option<StatisticalProposalEvidence> {
        self.statistical_evidence
    }

    /// Returns schema-bound constraint evidence for an atomic group proposal.
    #[must_use]
    pub const fn constraint_evidence(&self) -> Option<crate::ChoiceGroupConstraintEvidence> {
        self.constraint_evidence
    }

    pub(crate) const fn schema_version(&self) -> u32 {
        self.schema_version
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
            crate::ObjectEnvelope::for_record_versioned(
                crate::CampaignRecordKind::Proposal,
                self.schema_version,
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
        self.statistical_evidence.encode(encoder);
        self.constraint_evidence.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let schema_version = u32::decode(decoder)?;
        if schema_version != PROPOSAL_SCHEMA_VERSION {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported exploration record schema version",
            });
        }
        let mut proposal = Self::new(
            BranchPointId::decode(decoder)?,
            BranchRequestId::decode(decoder)?,
            ChoiceDomainId::decode(decoder)?,
            ChoiceValue::decode(decoder)?,
            CampaignPolicyId::decode(decoder)?,
            Option::decode(decoder)?,
            u64::decode(decoder)?,
            CampaignViewId::decode(decoder)?,
        )?;
        proposal.statistical_evidence = Option::decode(decoder)?;
        proposal.constraint_evidence = Option::decode(decoder)?;
        if proposal.constraint_evidence
            != matches!(proposal.value, ChoiceValue::Group(_))
                .then(crate::ChoiceGroupConstraintEvidence::admitted)
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "proposal group constraint evidence is missing or inconsistent",
            });
        }
        Ok(proposal)
    }
}
