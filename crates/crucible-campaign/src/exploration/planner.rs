//! Planner accounting, guidance evidence, and planner-step records.

use super::*;

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
