//! Versioned aggregate budget ledger and pure checked accounting transitions.
//!
//! Canonical version 3 uses big-endian fields in this order:
//! ```text
//! u32 version = 3
//! u128 granted_proposals
//! u128 granted_attempts
//! u64 spent_proposals
//! u64 spent_attempts
//! ContentId request_spending
//! ContentId request_admissions
//! ```
//! Spending maps count execution bases. Admission maps retain every
//! proposal-backed execution basis and additional cause by request.
//! A repository must authenticate these totals against its causal transition
//! before treating a decoded ledger as authority. Historical debt is retained,
//! not forgiven; a later grant must cover that debt before new spending.

use super::{BudgetGrant, CampaignCodecError};
use crate::codec::{self, Canonical, Decoder, Encoder};

/// Names a rejected aggregate budget transition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CampaignBudgetError {
    /// The requested proposals exceed the remaining campaign allowance.
    ProposalAllowanceExhausted,
    /// The requested unique attempts exceed the remaining campaign allowance.
    AttemptAllowanceExhausted,
    /// A grant or spending counter cannot represent the resulting exact total.
    CounterOverflow,
}

impl std::fmt::Display for CampaignBudgetError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::ProposalAllowanceExhausted => "campaign proposal allowance exhausted",
            Self::AttemptAllowanceExhausted => "campaign attempt allowance exhausted",
            Self::CounterOverflow => "campaign budget counter overflow",
        })
    }
}

impl std::error::Error for CampaignBudgetError {}

/// Stores exact aggregate campaign grants and canonical spending.
///
/// The ledger counts proposals separately from unique semantic attempts.
/// Additional causes spend proposal allowance but not another attempt; retries
/// of an already accepted operation spend neither. The mutation owner decides
/// those deltas from authenticated indexes before applying this pure ledger.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CampaignBudgetLedger {
    granted_proposals: u128,
    granted_attempts: u128,
    spent_proposals: u64,
    spent_attempts: u64,
    request_spending: crucible_cas::content_store::ContentId,
    request_admissions: crucible_cas::content_store::ContentId,
}

impl CampaignBudgetLedger {
    pub(crate) fn from_accounted_totals(
        granted_proposals: u128,
        granted_attempts: u128,
        spent_proposals: u64,
        spent_attempts: u64,
        request_spending: crucible_cas::content_store::ContentId,
        request_admissions: crucible_cas::content_store::ContentId,
    ) -> Result<Self, CampaignCodecError> {
        super::validate_merkle_roots(&[request_spending, request_admissions])?;
        Ok(Self {
            granted_proposals,
            granted_attempts,
            spent_proposals,
            spent_attempts,
            request_spending,
            request_admissions,
        })
    }

    /// Returns the domain-separated identity of the canonical ledger envelope.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if canonical envelope construction fails.
    pub fn id(self) -> Result<crate::CampaignBudgetLedgerId, CampaignCodecError> {
        crate::CampaignBudgetLedgerId::from_content_id(
            crate::ObjectEnvelope::for_budget_ledger(&self)?.content_id(),
        )
    }

    /// Builds an empty ledger with both request indexes at the same empty root.
    ///
    /// The repository must authenticate every nested request-index entry;
    /// this constructor checks only the root's storage-domain type.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] if `root` is not a Merkle-node identity.
    pub fn empty(root: crucible_cas::content_store::ContentId) -> Result<Self, CampaignCodecError> {
        super::validate_merkle_roots(&[root])?;
        Ok(Self {
            granted_proposals: 0,
            granted_attempts: 0,
            spent_proposals: 0,
            spent_attempts: 0,
            request_spending: root,
            request_admissions: root,
        })
    }

    /// Returns the authenticated request-spending root.
    #[must_use]
    pub const fn request_spending(self) -> crucible_cas::content_store::ContentId {
        self.request_spending
    }

    /// Returns the authenticated index of all proposal-backed admissions.
    #[must_use]
    pub const fn request_admissions(self) -> crucible_cas::content_store::ContentId {
        self.request_admissions
    }

    pub(crate) const fn schema_version(self) -> u32 {
        3
    }

    pub(crate) fn content_children(
        self,
    ) -> Vec<(&'static str, crucible_cas::content_store::ContentId)> {
        vec![
            ("request-spending", self.request_spending),
            ("request-admissions", self.request_admissions),
        ]
    }

    /// Returns the exact cumulative proposal grant.
    #[must_use]
    pub const fn granted_proposals(self) -> u128 {
        self.granted_proposals
    }

    /// Returns the exact cumulative unique-attempt grant.
    #[must_use]
    pub const fn granted_attempts(self) -> u128 {
        self.granted_attempts
    }

    /// Returns cumulative proposal spending.
    #[must_use]
    pub const fn spent_proposals(self) -> u64 {
        self.spent_proposals
    }

    /// Returns cumulative unique-attempt spending.
    #[must_use]
    pub const fn spent_attempts(self) -> u64 {
        self.spent_attempts
    }

    /// Returns proposal allowance after accounting for any historical debt.
    #[must_use]
    pub const fn remaining_proposals(self) -> u128 {
        self.granted_proposals
            .saturating_sub(self.spent_proposals as u128)
    }

    /// Returns attempt allowance after accounting for any historical debt.
    #[must_use]
    pub const fn remaining_attempts(self) -> u128 {
        self.granted_attempts
            .saturating_sub(self.spent_attempts as u128)
    }

    /// Adds one authenticated, previously unapplied grant to both dimensions.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignBudgetError::CounterOverflow`] if either exact total
    /// exceeds `u128`. The original ledger remains unchanged on failure.
    pub fn with_grant(self, grant: BudgetGrant) -> Result<Self, CampaignBudgetError> {
        let granted_proposals = self
            .granted_proposals
            .checked_add(u128::from(grant.proposals()))
            .ok_or(CampaignBudgetError::CounterOverflow)?;
        let granted_attempts = self
            .granted_attempts
            .checked_add(u128::from(grant.attempts()))
            .ok_or(CampaignBudgetError::CounterOverflow)?;
        Ok(Self {
            granted_proposals,
            granted_attempts,
            ..self
        })
    }

    /// Charges an owner's canonical proposal and unique-attempt deltas together.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignBudgetError`] if either allowance is insufficient or
    /// either spending counter overflows. Neither dimension changes on failure.
    pub fn with_spending(self, proposals: u64, attempts: u64) -> Result<Self, CampaignBudgetError> {
        if u128::from(proposals) > self.remaining_proposals() {
            return Err(CampaignBudgetError::ProposalAllowanceExhausted);
        }
        if u128::from(attempts) > self.remaining_attempts() {
            return Err(CampaignBudgetError::AttemptAllowanceExhausted);
        }
        let spent_proposals = self
            .spent_proposals
            .checked_add(proposals)
            .ok_or(CampaignBudgetError::CounterOverflow)?;
        let spent_attempts = self
            .spent_attempts
            .checked_add(attempts)
            .ok_or(CampaignBudgetError::CounterOverflow)?;
        Ok(Self {
            spent_proposals,
            spent_attempts,
            ..self
        })
    }

    /// Returns the canonical version-3 ledger bytes.
    #[must_use]
    pub fn canonical_bytes(self) -> Vec<u8> {
        codec::encode(&self)
    }

    /// Decodes an exact ledger, preserving historical debt if present.
    ///
    /// Decoding establishes shape, not authority. The repository must verify
    /// the totals against the parent ledger and exact causal spending/grant.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] for an unsupported version, truncation,
    /// trailing bytes, or noncanonical encoding.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, CampaignCodecError> {
        codec::decode(bytes)
    }
}

impl Canonical for CampaignBudgetLedger {
    fn encode(&self, encoder: &mut Encoder) {
        self.schema_version().encode(encoder);
        self.granted_proposals.encode(encoder);
        self.granted_attempts.encode(encoder);
        self.spent_proposals.encode(encoder);
        self.spent_attempts.encode(encoder);
        Canonical::encode(&self.request_spending, encoder);
        Canonical::encode(&self.request_admissions, encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        let version = u32::decode(decoder)?;
        if version != 3 {
            return Err(CampaignCodecError::InvalidValue {
                reason: "unsupported campaign budget ledger schema version",
            });
        }
        let value = Self {
            granted_proposals: u128::decode(decoder)?,
            granted_attempts: u128::decode(decoder)?,
            spent_proposals: u64::decode(decoder)?,
            spent_attempts: u64::decode(decoder)?,
            request_spending: crucible_cas::content_store::ContentId::decode(decoder)?,
            request_admissions: crucible_cas::content_store::ContentId::decode(decoder)?,
        };
        super::validate_merkle_roots(&[value.request_spending, value.request_admissions])?;
        Ok(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crucible_cas::content_store::{ContentId, ObjectKind};

    fn empty_ledger() -> Result<CampaignBudgetLedger, CampaignCodecError> {
        CampaignBudgetLedger::empty(ContentId::for_bytes(
            ObjectKind::MerkleNode,
            1,
            b"current-ledger-request-index",
        ))
    }

    #[test]
    fn current_ledger_round_trips_and_exposes_its_exact_child()
    -> Result<(), Box<dyn std::error::Error>> {
        let ledger = empty_ledger()?.with_grant(BudgetGrant::new(3, 2)?)?;
        let bytes = ledger.canonical_bytes();
        assert_eq!(CampaignBudgetLedger::from_canonical_bytes(&bytes)?, ledger);
        let envelope = crate::ObjectEnvelope::for_budget_ledger(&ledger)?;
        assert_eq!(envelope.content_id().schema_version(), 3);
        assert_eq!(envelope.children().len(), 2);
        assert_eq!(ledger.request_spending().kind(), ObjectKind::MerkleNode);
        assert_eq!(ledger.request_admissions().kind(), ObjectKind::MerkleNode);
        Ok(())
    }

    #[test]
    fn ledger_envelopes_bind_totals_and_reject_hidden_children()
    -> Result<(), Box<dyn std::error::Error>> {
        let ledger = empty_ledger()?;
        let envelope = crate::ObjectEnvelope::for_budget_ledger(&ledger)?;
        assert_eq!(ledger.id()?.content_id(), envelope.content_id());
        assert_eq!(
            crate::ObjectEnvelope::from_canonical_bytes(&envelope.canonical_bytes())?.content_id(),
            envelope.content_id()
        );
        let funded = ledger.with_grant(BudgetGrant::new(1, 1)?)?;
        assert_ne!(funded.id()?, ledger.id()?);
        let spent = funded.with_spending(1, 1)?;
        assert_ne!(spent.id()?, funded.id()?);

        let child = crate::ChildReference::new("unexpected", envelope.content_id())?;
        let forged = crate::ObjectEnvelope::for_record_versioned(
            crate::CampaignRecordKind::BudgetLedger,
            ledger.schema_version(),
            std::collections::BTreeSet::from([child]),
            ledger.canonical_bytes(),
        )?;
        assert!(crate::ObjectEnvelope::from_canonical_bytes(&forged.canonical_bytes()).is_err());
        Ok(())
    }

    #[test]
    fn charges_both_dimensions_atomically_and_additional_causes_only_once()
    -> Result<(), Box<dyn std::error::Error>> {
        let original = empty_ledger()?.with_grant(BudgetGrant::new(2, 1)?)?;
        let admitted = original.with_spending(1, 1)?;
        assert_eq!(
            admitted.with_spending(1, 1),
            Err(CampaignBudgetError::AttemptAllowanceExhausted)
        );
        let convergent = admitted.with_spending(1, 0)?;
        assert_eq!(convergent.spent_proposals(), 2);
        assert_eq!(convergent.spent_attempts(), 1);
        assert_eq!(
            convergent.with_spending(1, 0),
            Err(CampaignBudgetError::ProposalAllowanceExhausted)
        );
        assert_eq!(convergent.with_spending(0, 0)?, convergent);
        assert_eq!(original.spent_proposals(), 0);
        Ok(())
    }

    #[test]
    fn canonical_ledger_rejects_unknown_versions_truncation_and_trailing_bytes()
    -> Result<(), Box<dyn std::error::Error>> {
        let ledger = empty_ledger()?
            .with_grant(BudgetGrant::new(u64::MAX, u64::MAX)?)?
            .with_spending(2, 1)?;
        let bytes = ledger.canonical_bytes();
        assert_eq!(CampaignBudgetLedger::from_canonical_bytes(&bytes)?, ledger);
        for length in 0..bytes.len() {
            assert!(CampaignBudgetLedger::from_canonical_bytes(&bytes[..length]).is_err());
        }
        let mut extra = bytes.clone();
        extra.push(0);
        assert!(CampaignBudgetLedger::from_canonical_bytes(&extra).is_err());
        for version in [0_u32, 2, u32::MAX] {
            let mut unknown = bytes.clone();
            unknown[..4].copy_from_slice(&version.to_be_bytes());
            assert!(CampaignBudgetLedger::from_canonical_bytes(&unknown).is_err());
        }
        Ok(())
    }

    #[test]
    fn overflowing_grants_and_spending_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let max = CampaignBudgetLedger {
            granted_proposals: u128::MAX,
            granted_attempts: u128::MAX,
            spent_proposals: u64::MAX,
            spent_attempts: u64::MAX,
            request_spending: empty_ledger()?.request_spending(),
            request_admissions: empty_ledger()?.request_admissions(),
        };
        assert_eq!(
            max.with_grant(BudgetGrant::new(1, 0)?),
            Err(CampaignBudgetError::CounterOverflow)
        );
        assert_eq!(
            max.with_grant(BudgetGrant::new(0, 1)?),
            Err(CampaignBudgetError::CounterOverflow)
        );
        assert_eq!(
            max.with_spending(1, 0),
            Err(CampaignBudgetError::CounterOverflow)
        );
        assert_eq!(
            max.with_spending(0, 1),
            Err(CampaignBudgetError::CounterOverflow)
        );
        let twice = empty_ledger()?
            .with_grant(BudgetGrant::new(u64::MAX, u64::MAX)?)?
            .with_grant(BudgetGrant::new(u64::MAX, u64::MAX)?)?;
        assert_eq!(twice.granted_attempts(), u128::from(u64::MAX) * 2);
        Ok(())
    }
}
