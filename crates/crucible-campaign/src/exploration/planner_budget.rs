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
        })
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

    /// Returns whether this single offer fits the aggregate campaign budgets.
    ///
    /// Convergent offers still spend one proposal but spend no attempt allowance.
    #[must_use]
    pub const fn can_issue(&self) -> bool {
        self.remaining_proposals != 0 && (!self.new_attempt || self.remaining_attempts != 0)
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

    /// Returns the strict version-1 canonical encoding.
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        codec::encode(self)
    }

    /// Decodes one exact version-1 projection without trailing bytes.
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
            crate::ObjectEnvelope::for_record(
                crate::CampaignRecordKind::PlannerCandidateBudget,
                crate::object::content_children(self.content_children())?,
                self.canonical_bytes(),
            )?
            .content_id(),
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
        1_u32.encode(encoder);
        self.input_view.encode(encoder);
        self.position.encode(encoder);
        self.proposal.encode(encoder);
        self.remaining_proposals.encode(encoder);
        self.remaining_attempts.encode(encoder);
        self.new_attempt.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        if u32::decode(decoder)? != 1 {
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
        })
    }
}
