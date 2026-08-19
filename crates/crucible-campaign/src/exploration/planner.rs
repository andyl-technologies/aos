//! Planner accounting, guidance evidence, and planner-step records.

use super::*;

/// Coordinator-computed semantic resource accounting for a planner step.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PlanningAccounting {
    /// Accepted branch requests.
    pub branch_requests: u64,
    /// Accepted proposals.
    pub proposals: u64,
    /// Newly admitted attempts.
    pub attempts: u64,
    /// Proposals that reused an existing semantic edge/attempt.
    pub deduplicated: u64,
    /// Deterministic planner fuel consumed.
    pub fuel: u64,
}

impl PlanningAccounting {
    const fn has_semantic_outputs(self) -> bool {
        self.branch_requests != 0
            || self.proposals != 0
            || self.attempts != 0
            || self.deduplicated != 0
    }

    fn validate_outputs(
        self,
        branch_requests: usize,
        proposals: usize,
    ) -> Result<(), CampaignCodecError> {
        let branch_requests =
            u64::try_from(branch_requests).map_err(|_| CampaignCodecError::LimitExceeded {
                limit: "planner-step-branch-request-count",
            })?;
        let proposals =
            u64::try_from(proposals).map_err(|_| CampaignCodecError::LimitExceeded {
                limit: "planner-step-proposal-count",
            })?;
        if self.branch_requests != branch_requests
            || self.proposals != proposals
            || self.attempts.checked_add(self.deduplicated) != Some(proposals)
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "planner accounting does not match accepted outputs",
            });
        }
        Ok(())
    }
}

impl Canonical for PlanningAccounting {
    fn encode(&self, encoder: &mut Encoder) {
        self.branch_requests.encode(encoder);
        self.proposals.encode(encoder);
        self.attempts.encode(encoder);
        self.deduplicated.encode(encoder);
        self.fuel.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self {
            branch_requests: u64::decode(decoder)?,
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

/// Exact canonical position in a snapshot-bound continuation scan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct PlanningScanPosition {
    branch_point: BranchPointId,
    source: BranchRequestId,
}

impl PlanningScanPosition {
    /// Builds an exact continuation-key position.
    #[must_use]
    pub const fn new(branch_point: BranchPointId, source: BranchRequestId) -> Self {
        Self {
            branch_point,
            source,
        }
    }

    /// Returns the semantic branch point.
    #[must_use]
    pub const fn branch_point(self) -> BranchPointId {
        self.branch_point
    }

    /// Returns the suspended request at the branch point.
    #[must_use]
    pub const fn source(self) -> BranchRequestId {
        self.source
    }
}

impl Canonical for PlanningScanPosition {
    fn encode(&self, encoder: &mut Encoder) {
        self.branch_point.encode(encoder);
        self.source.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self::new(
            BranchPointId::decode(decoder)?,
            BranchRequestId::decode(decoder)?,
        ))
    }
}

/// Portable cursor for a canonical continuation scan over one planning view.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PlanningScanCursor {
    input_view: CampaignViewId,
    after: Option<PlanningScanPosition>,
}

impl PlanningScanCursor {
    /// Builds a cursor bound to one immutable planning view.
    #[must_use]
    pub const fn new(input_view: CampaignViewId, after: Option<PlanningScanPosition>) -> Self {
        Self { input_view, after }
    }

    /// Returns the immutable planning view that owns the scan.
    #[must_use]
    pub const fn input_view(self) -> CampaignViewId {
        self.input_view
    }

    /// Returns the last completely scanned continuation, if any.
    #[must_use]
    pub const fn after(self) -> Option<PlanningScanPosition> {
        self.after
    }
}

impl Canonical for PlanningScanCursor {
    fn encode(&self, encoder: &mut Encoder) {
        self.input_view.encode(encoder);
        self.after.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self::new(
            CampaignViewId::decode(decoder)?,
            Option::decode(decoder)?,
        ))
    }
}

/// Accepted semantic outcome of one bounded pure planner invocation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlannerDisposition {
    /// Suspends a snapshot-bound frontier scan without issuing semantic work.
    ContinueScan {
        /// Cursor naming the immutable view and last completely scanned key.
        cursor: PlanningScanCursor,
    },
    /// Accepts new request and proposal outputs for one selected continuation.
    Issue {
        /// Continuation selected after completing deterministic ranking.
        selected: PlanningScanPosition,
        /// Newly accepted lazy branch requests in deterministic output order.
        issued_branch_requests: Vec<BranchRequestId>,
        /// Newly accepted proposals in deterministic output order.
        issued_proposals: Vec<ProposalId>,
    },
    /// Completes the snapshot-bound scan with no eligible semantic work.
    NoWork,
}

impl PlannerDisposition {
    /// Returns the selected continuation for an issuing result.
    #[must_use]
    pub const fn selected(&self) -> Option<PlanningScanPosition> {
        match self {
            Self::Issue { selected, .. } => Some(*selected),
            Self::ContinueScan { .. } | Self::NoWork => None,
        }
    }

    /// Returns accepted branch-request identities, or an empty slice.
    #[must_use]
    pub fn issued_branch_requests(&self) -> &[BranchRequestId] {
        match self {
            Self::Issue {
                issued_branch_requests,
                ..
            } => issued_branch_requests,
            Self::ContinueScan { .. } | Self::NoWork => &[],
        }
    }

    /// Returns accepted proposal identities, or an empty slice.
    #[must_use]
    pub fn issued_proposals(&self) -> &[ProposalId] {
        match self {
            Self::Issue {
                issued_proposals, ..
            } => issued_proposals,
            Self::ContinueScan { .. } | Self::NoWork => &[],
        }
    }

    fn validate(
        &self,
        input_view: CampaignViewId,
        accounting: PlanningAccounting,
    ) -> Result<(), CampaignCodecError> {
        match self {
            Self::ContinueScan { cursor } => {
                if cursor.input_view() != input_view || accounting.has_semantic_outputs() {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "continue-scan result has mismatched view or semantic outputs",
                    });
                }
            }
            Self::Issue {
                issued_branch_requests,
                issued_proposals,
                ..
            } => {
                if issued_branch_requests.len() > MAX_STEP_BRANCH_REQUESTS
                    || issued_proposals.is_empty()
                    || issued_proposals.len() > MAX_STEP_PROPOSALS
                    || issued_branch_requests
                        .iter()
                        .copied()
                        .collect::<BTreeSet<_>>()
                        .len()
                        != issued_branch_requests.len()
                    || issued_proposals
                        .iter()
                        .copied()
                        .collect::<BTreeSet<_>>()
                        .len()
                        != issued_proposals.len()
                {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "planner issue result has empty, duplicate, or oversized outputs",
                    });
                }
                accounting
                    .validate_outputs(issued_branch_requests.len(), issued_proposals.len())?;
            }
            Self::NoWork if accounting.has_semantic_outputs() => {
                return Err(CampaignCodecError::InvalidValue {
                    reason: "no-work planner result has semantic outputs",
                });
            }
            Self::NoWork => {}
        }
        Ok(())
    }
}

impl Canonical for PlannerDisposition {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::ContinueScan { cursor } => {
                encoder.u8(0);
                cursor.encode(encoder);
            }
            Self::Issue {
                selected,
                issued_branch_requests,
                issued_proposals,
            } => {
                encoder.u8(1);
                selected.encode(encoder);
                issued_branch_requests.encode(encoder);
                issued_proposals.encode(encoder);
            }
            Self::NoWork => encoder.u8(2),
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::ContinueScan {
                cursor: PlanningScanCursor::decode(decoder)?,
            }),
            1 => Ok(Self::Issue {
                selected: PlanningScanPosition::decode(decoder)?,
                issued_branch_requests: decoder.sequence_bounded(
                    MAX_STEP_BRANCH_REQUESTS,
                    "planner-step-branch-request-count",
                    BranchRequestId::decode,
                )?,
                issued_proposals: decoder.sequence_bounded(
                    MAX_STEP_PROPOSALS,
                    "planner-step-proposal-count",
                    ProposalId::decode,
                )?,
            }),
            2 => Ok(Self::NoWork),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "planner-disposition",
                tag,
            }),
        }
    }
}

/// Planner-reported resource use retained for diagnostics, never authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PlanningUsage {
    /// Branch-request objects produced by the planner.
    pub branch_requests: u64,
    /// Proposal objects produced by the planner.
    pub proposals: u64,
    /// Canonical input objects inspected by the planner.
    pub input_objects: u64,
    /// Canonical input bytes inspected by the planner.
    pub input_bytes: u64,
    /// Deterministic planner fuel claimed by the planner.
    pub fuel: u64,
}

impl Canonical for PlanningUsage {
    fn encode(&self, encoder: &mut Encoder) {
        self.branch_requests.encode(encoder);
        self.proposals.encode(encoder);
        self.input_objects.encode(encoder);
        self.input_bytes.encode(encoder);
        self.fuel.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Ok(Self {
            branch_requests: u64::decode(decoder)?,
            proposals: u64::decode(decoder)?,
            input_objects: u64::decode(decoder)?,
            input_bytes: u64::decode(decoder)?,
            fuel: u64::decode(decoder)?,
        })
    }
}

/// Pure planner output before coordinator authentication and accounting.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlannerProposalDisposition {
    /// Suspends the current snapshot-bound scan without semantic output.
    ContinueScan {
        /// Cursor naming the immutable view and last completely scanned key.
        cursor: PlanningScanCursor,
    },
    /// Proposes semantic outputs for one deterministically selected source.
    Issue {
        /// Continuation selected after completing deterministic ranking.
        selected: PlanningScanPosition,
        /// Proposed lazy branch requests in deterministic output order.
        branch_requests: Vec<BranchRequest>,
        /// Proposed values in deterministic output order.
        proposals: Vec<Proposal>,
    },
    /// Completes the snapshot-bound scan with no eligible semantic work.
    NoWork,
}

impl PlannerProposalDisposition {
    fn validate(&self, invocation: PlannerInvocationId) -> Result<(), CampaignCodecError> {
        match self {
            Self::ContinueScan { .. } | Self::NoWork => Ok(()),
            Self::Issue {
                selected,
                branch_requests,
                proposals,
            } => {
                if branch_requests.len() > MAX_STEP_BRANCH_REQUESTS
                    || proposals.is_empty()
                    || proposals.len() > MAX_STEP_PROPOSALS
                {
                    return Err(CampaignCodecError::InvalidValue {
                        reason: "planner proposal has empty or oversized outputs",
                    });
                }

                let mut request_ids = BTreeSet::new();
                for request in branch_requests {
                    let request_id = request.id()?;
                    if request.cause() != BranchRequestCause::Planner(invocation)
                        || (request_id == selected.source()
                            && request.branch_point() != selected.branch_point())
                        || !request_ids.insert(request_id)
                    {
                        return Err(CampaignCodecError::InvalidValue {
                            reason: "planner proposal has duplicate or mismatched branch requests",
                        });
                    }
                }

                let mut proposal_ids = BTreeSet::new();
                for proposal in proposals {
                    if proposal.branch_point() != selected.branch_point()
                        || proposal.request() != selected.source()
                        || proposal.planner_invocation() != Some(invocation)
                        || !proposal_ids.insert(proposal.id()?)
                    {
                        return Err(CampaignCodecError::InvalidValue {
                            reason: "planner proposal has duplicate or mismatched proposals",
                        });
                    }
                }
                Ok(())
            }
        }
    }
}

impl Canonical for PlannerProposalDisposition {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::ContinueScan { cursor } => {
                encoder.u8(0);
                cursor.encode(encoder);
            }
            Self::Issue {
                selected,
                branch_requests,
                proposals,
            } => {
                encoder.u8(1);
                selected.encode(encoder);
                branch_requests.encode(encoder);
                proposals.encode(encoder);
            }
            Self::NoWork => encoder.u8(2),
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::ContinueScan {
                cursor: PlanningScanCursor::decode(decoder)?,
            }),
            1 => Ok(Self::Issue {
                selected: PlanningScanPosition::decode(decoder)?,
                branch_requests: decoder.sequence_bounded(
                    MAX_STEP_BRANCH_REQUESTS,
                    "planner-proposal-branch-request-count",
                    BranchRequest::decode,
                )?,
                proposals: decoder.sequence_bounded(
                    MAX_STEP_PROPOSALS,
                    "planner-proposal-count",
                    Proposal::decode,
                )?,
            }),
            2 => Ok(Self::NoWork),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "planner-proposal-disposition",
                tag,
            }),
        }
    }
}

/// Bounded pure planner output proposed to the coordinator.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannerStepProposal {
    schema_version: u32,
    invocation: PlannerInvocationId,
    next_state: PlannerState,
    usage_claim: PlanningUsage,
    explanation: GuidanceEvidence,
    disposition: PlannerProposalDisposition,
}

impl PlannerStepProposal {
    /// Builds a structurally valid pure planner result.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for duplicate, oversized, or
    /// invocation-mismatched semantic outputs.
    pub fn new(
        invocation: PlannerInvocationId,
        next_state: PlannerState,
        usage_claim: PlanningUsage,
        explanation: GuidanceEvidence,
        disposition: PlannerProposalDisposition,
    ) -> Result<Self, CampaignCodecError> {
        Self::new_with_encoded_limit(
            invocation,
            next_state,
            usage_claim,
            explanation,
            disposition,
            MAX_EXACT_RECORD_BYTES,
        )
    }

    pub(crate) fn new_with_encoded_limit(
        invocation: PlannerInvocationId,
        next_state: PlannerState,
        usage_claim: PlanningUsage,
        explanation: GuidanceEvidence,
        disposition: PlannerProposalDisposition,
        maximum_encoded_bytes: usize,
    ) -> Result<Self, CampaignCodecError> {
        disposition.validate(invocation)?;
        let proposal = Self {
            schema_version: RECORD_SCHEMA_VERSION,
            invocation,
            next_state,
            usage_claim,
            explanation,
            disposition,
        };
        codec::ensure_encoded_size(
            &proposal,
            maximum_encoded_bytes,
            "planner-step-proposal-encoded-bytes",
        )?;
        Ok(proposal)
    }

    /// Returns the exact invocation this result answers.
    #[must_use]
    pub const fn invocation(&self) -> PlannerInvocationId {
        self.invocation
    }

    /// Returns the proposed portable post-invocation planner state.
    #[must_use]
    pub const fn next_state(&self) -> &PlannerState {
        &self.next_state
    }

    /// Returns planner-claimed diagnostic resource use.
    #[must_use]
    pub const fn usage_claim(&self) -> PlanningUsage {
        self.usage_claim
    }

    /// Returns exact fixed-point explanation evidence.
    #[must_use]
    pub const fn explanation(&self) -> &GuidanceEvidence {
        &self.explanation
    }

    /// Returns the proposed issue, scan suspension, or no-work outcome.
    #[must_use]
    pub const fn disposition(&self) -> &PlannerProposalDisposition {
        &self.disposition
    }

    /// Returns strict canonical result bytes.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes a strict canonical pure planner result.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, invalid, or
    /// oversized bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_exact_record(bytes, "planner-step-proposal-encoded-bytes")
    }
}

impl Canonical for PlannerStepProposal {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version.encode(encoder);
        self.invocation.encode(encoder);
        self.next_state.encode(encoder);
        self.usage_claim.encode(encoder);
        self.explanation.encode(encoder);
        self.disposition.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_schema(u32::decode(decoder)?)?;
        Self::new(
            PlannerInvocationId::decode(decoder)?,
            PlannerState::decode(decoder)?,
            PlanningUsage::decode(decoder)?,
            GuidanceEvidence::decode(decoder)?,
            PlannerProposalDisposition::decode(decoder)?,
        )
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
    disposition: PlannerDisposition,
    next_state: PlannerStateId,
    accounting: PlanningAccounting,
    evidence: GuidanceEvidence,
}

impl PlannerStep {
    /// Builds a bounded accepted planner step.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the disposition, output identities,
    /// or coordinator accounting are structurally inconsistent.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        parent: Option<PlannerStepId>,
        invocation: PlannerInvocationId,
        policy: CampaignPolicyId,
        engine: PlannerEngineId,
        policy_artifact: PolicyArtifactId,
        input_view: CampaignViewId,
        disposition: PlannerDisposition,
        next_state: PlannerStateId,
        accounting: PlanningAccounting,
        evidence: GuidanceEvidence,
    ) -> Result<Self, CampaignCodecError> {
        disposition.validate(input_view, accounting)?;
        Ok(Self {
            schema_version: PLANNER_STEP_SCHEMA_VERSION,
            parent,
            invocation,
            policy,
            engine,
            policy_artifact,
            input_view,
            disposition,
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

    /// Returns the accepted issue, scan suspension, or no-work disposition.
    #[must_use]
    pub const fn disposition(&self) -> &PlannerDisposition {
        &self.disposition
    }

    /// Returns the selected branch point for an issuing result.
    #[must_use]
    pub fn selected_branch_point(&self) -> Option<BranchPointId> {
        self.disposition
            .selected()
            .map(PlanningScanPosition::branch_point)
    }

    /// Returns the selected suspended source for an issuing result.
    #[must_use]
    pub fn selected_source(&self) -> Option<BranchRequestId> {
        self.disposition
            .selected()
            .map(PlanningScanPosition::source)
    }

    /// Returns issued branch-request identities in deterministic order.
    #[must_use]
    pub fn issued_branch_requests(&self) -> &[BranchRequestId] {
        self.disposition.issued_branch_requests()
    }

    /// Returns issued proposal identities in deterministic order.
    #[must_use]
    pub fn issued_proposals(&self) -> &[ProposalId] {
        self.disposition.issued_proposals()
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

    /// Decodes a strict canonical planner step.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed, noncanonical, invalid, or
    /// oversized bytes.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        decode_exact_record(bytes, "planner-step-encoded-bytes")
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
            ("next-state".to_owned(), self.next_state.content_id()),
        ];
        if let Some(parent) = self.parent {
            children.push(("parent-step".to_owned(), parent.content_id()));
        }
        match &self.disposition {
            PlannerDisposition::ContinueScan { cursor } => {
                if let Some(after) = cursor.after() {
                    children.push(("scan-after-source".to_owned(), after.source().content_id()));
                }
            }
            PlannerDisposition::Issue {
                selected,
                issued_branch_requests,
                issued_proposals,
            } => {
                children.push(("selected-source".to_owned(), selected.source().content_id()));
                children.extend(issued_branch_requests.iter().enumerate().map(
                    |(index, request)| {
                        (format!("branch-request.{index:04x}"), request.content_id())
                    },
                ));
                children.extend(
                    issued_proposals
                        .iter()
                        .enumerate()
                        .map(|(index, proposal)| {
                            (format!("proposal.{index:04x}"), proposal.content_id())
                        }),
                );
            }
            PlannerDisposition::NoWork => {}
        }
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
        self.disposition.encode(encoder);
        self.next_state.encode(encoder);
        self.accounting.encode(encoder);
        self.evidence.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        require_schema_version(u32::decode(decoder)?, PLANNER_STEP_SCHEMA_VERSION)?;
        Self::new(
            Option::decode(decoder)?,
            PlannerInvocationId::decode(decoder)?,
            CampaignPolicyId::decode(decoder)?,
            PlannerEngineId::decode(decoder)?,
            PolicyArtifactId::decode(decoder)?,
            CampaignViewId::decode(decoder)?,
            PlannerDisposition::decode(decoder)?,
            PlannerStateId::decode(decoder)?,
            PlanningAccounting::decode(decoder)?,
            GuidanceEvidence::decode(decoder)?,
        )
    }
}
