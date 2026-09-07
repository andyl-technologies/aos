//! Snapshot-bound budget eligibility for one exact planner offer.
//!
//! Request-local continuation state remains independent of funding. This
//! projection binds an invocation's offer to the owner's remaining allowances
//! and deduplication decision; it is not itself authority to spend either budget.
//! Acceptance and cold replay recompute it from the authenticated snapshot.
//!
//! ```text
//! v1 | input_view | position | proposal | remaining_proposals:u128
//!    | remaining_attempts:u128 | new_attempt:bool
//! v2 | <same fields> | remaining_request_attempts:u64
//! ```

use super::*;

/// Owner-derived budget eligibility for an invocation-bound candidate offer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlannerCandidateBudget {
    input_view: CampaignViewId,
    position: PlanningScanPosition,
    proposal: ProposalId,
    remaining_proposals: u128,
    remaining_attempts: u128,
    new_attempt: bool,
    remaining_request_attempts: Option<u64>,
}

impl PlannerCandidateBudget {
    /// Binds remaining allowances and deduplication cost to one exact offer.
    ///
    /// Construction checks structural identity, not repository authority.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if the offer cannot produce a canonical ID.
    pub fn new(
        offer: &Proposal,
        remaining_proposals: u128,
        remaining_attempts: u128,
        new_attempt: bool,
    ) -> Result<Self, CampaignCodecError> {
        Ok(Self {
            input_view: offer.guidance_basis(),
            position: PlanningScanPosition::new(offer.branch_point(), offer.request()),
            proposal: offer.id()?,
            remaining_proposals,
            remaining_attempts,
            new_attempt,
            remaining_request_attempts: None,
        })
    }

    /// Adds exact request-local allowance using the version-2 projection format.
    ///
    /// The allowance counts only execution bases charged to the served request.
    /// Construction does not establish repository authority over this value.
    #[must_use]
    pub const fn with_request_attempts(mut self, remaining: u64) -> Self {
        self.remaining_request_attempts = Some(remaining);
        self
    }

    /// Returns the request-local allowance, or `None` for a legacy v1 projection.
    #[must_use]
    pub const fn remaining_request_attempts(&self) -> Option<u64> {
        self.remaining_request_attempts
    }

    /// Returns whether request-local allowance permits this candidate.
    ///
    /// A convergent candidate spends no request-local attempt. Legacy projections
    /// do not constrain this dimension; their owner still enforces it on admission.
    #[must_use]
    pub const fn request_can_issue(&self) -> bool {
        !self.new_attempt || !matches!(self.remaining_request_attempts, Some(0))
    }

    pub(crate) const fn schema_version(&self) -> u32 {
        if self.remaining_request_attempts.is_some() {
            2
        } else {
            1
        }
    }

    /// Returns the exact served frontier position.
    #[must_use]
    pub const fn position(&self) -> PlanningScanPosition {
        self.position
    }

    /// Returns the proposal allowance remaining in this planning view.
    #[must_use]
    pub const fn remaining_proposals(&self) -> u128 {
        self.remaining_proposals
    }

    /// Returns the unique-attempt allowance remaining in this planning view.
    #[must_use]
    pub const fn remaining_attempts(&self) -> u128 {
        self.remaining_attempts
    }

    /// Returns whether this offer needs a new semantic execution attempt.
    #[must_use]
    pub const fn requires_new_attempt(&self) -> bool {
        self.new_attempt
    }

    /// Returns whether this offer fits every budget dimension in the projection.
    ///
    /// Convergent offers still spend one proposal but spend no attempt allowance.
    #[must_use]
    pub const fn can_issue(&self) -> bool {
        self.request_can_issue()
            && self.remaining_proposals != 0
            && (!self.new_attempt || self.remaining_attempts != 0)
    }

    /// Authenticates the exact offer and planning-view binding.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when the offer differs from this projection.
    pub fn validate_for(&self, offer: &Proposal) -> Result<(), CampaignCodecError> {
        if self.input_view != offer.guidance_basis()
            || self.proposal != offer.id()?
            || self.position != PlanningScanPosition::new(offer.branch_point(), offer.request())
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "planner candidate budget disagrees with its offer",
            });
        }
        Ok(())
    }

    /// Returns the strict canonical encoding, preserving the projection version.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one exact version-1 or version-2 projection without trailing bytes.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for malformed or unsupported encodings.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        codec::decode(bytes)
    }

    /// Returns the content-derived projection identity.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if strict envelope construction fails.
    pub fn id(&self) -> Result<crate::PlannerCandidateBudgetId, CampaignCodecError> {
        crate::PlannerCandidateBudgetId::from_content_id(
            crate::ObjectEnvelope::for_candidate_budget(self)?.content_id(),
        )
    }

    pub(crate) fn content_children(&self) -> Vec<(&'static str, ContentId)> {
        vec![
            ("input-view", self.input_view.content_id()),
            ("request", self.position.source().content_id()),
            ("proposal", self.proposal.content_id()),
        ]
    }
}

impl Canonical for PlannerCandidateBudget {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version().encode(encoder);
        self.input_view.encode(encoder);
        self.position.encode(encoder);
        self.proposal.encode(encoder);
        self.remaining_proposals.encode(encoder);
        self.remaining_attempts.encode(encoder);
        self.new_attempt.encode(encoder);
        if let Some(remaining) = self.remaining_request_attempts {
            remaining.encode(encoder);
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let version = u32::decode(decoder)?;
        if !matches!(version, 1 | 2) {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported planner candidate budget schema version",
            });
        }
        Ok(Self {
            input_view: CampaignViewId::decode(decoder)?,
            position: PlanningScanPosition::decode(decoder)?,
            proposal: ProposalId::decode(decoder)?,
            remaining_proposals: u128::decode(decoder)?,
            remaining_attempts: u128::decode(decoder)?,
            new_attempt: bool::decode(decoder)?,
            remaining_request_attempts: if version == 2 {
                Some(u64::decode(decoder)?)
            } else {
                None
            },
        })
    }
}
