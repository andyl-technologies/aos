//! Versioned aggregate budget ledger and pure checked accounting transitions.
//!
//! Canonical version 1 uses big-endian fields in this order:
//! ```text
//! u32 version = 1
//! u128 granted_proposals
//! u128 granted_attempts
//! u64 spent_proposals
//! u64 spent_attempts
//! ```
//! A repository must authenticate these totals against its causal transition
//! before treating a decoded ledger as authority. Historical debt is retained,
//! not forgiven; a later grant must cover that debt before new spending.

use super::{BudgetGrant, CampaignCodecError};
use crate::codec::{self, Canonical, Decoder, Encoder};

const BUDGET_LEDGER_SCHEMA_VERSION: u32 = 1;

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
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CampaignBudgetLedger {
    granted_proposals: u128,
    granted_attempts: u128,
    spent_proposals: u64,
    spent_attempts: u64,
}

impl CampaignBudgetLedger {
    pub(crate) const fn from_accounted_totals(
        granted_proposals: u128,
        granted_attempts: u128,
        spent_proposals: u64,
        spent_attempts: u64,
    ) -> Self {
        Self {
            granted_proposals,
            granted_attempts,
            spent_proposals,
            spent_attempts,
        }
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

    /// Builds the empty ledger used at campaign genesis.
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            granted_proposals: 0,
            granted_attempts: 0,
            spent_proposals: 0,
            spent_attempts: 0,
        }
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

    /// Returns the fixed-width canonical version-1 ledger bytes.
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
        BUDGET_LEDGER_SCHEMA_VERSION.encode(encoder);
        self.granted_proposals.encode(encoder);
        self.granted_attempts.encode(encoder);
        self.spent_proposals.encode(encoder);
        self.spent_attempts.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        super::require_schema(
            u32::decode(decoder)?,
            BUDGET_LEDGER_SCHEMA_VERSION,
            "campaign-budget-ledger",
        )?;
        Ok(Self {
            granted_proposals: u128::decode(decoder)?,
            granted_attempts: u128::decode(decoder)?,
            spent_proposals: u64::decode(decoder)?,
            spent_attempts: u64::decode(decoder)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ledger_envelopes_bind_totals_and_reject_hidden_children()
    -> Result<(), Box<dyn std::error::Error>> {
        let ledger = CampaignBudgetLedger::empty();
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
        let forged = crate::ObjectEnvelope::for_record(
            crate::CampaignRecordKind::BudgetLedger,
            std::collections::BTreeSet::from([child]),
            ledger.canonical_bytes(),
        )?;
        assert!(crate::ObjectEnvelope::from_canonical_bytes(&forged.canonical_bytes()).is_err());
        Ok(())
    }

    #[test]
    fn charges_both_dimensions_atomically_and_additional_causes_only_once()
    -> Result<(), Box<dyn std::error::Error>> {
        let original = CampaignBudgetLedger::empty().with_grant(BudgetGrant::new(2, 1)?)?;
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
        let ledger = CampaignBudgetLedger::empty()
            .with_grant(BudgetGrant::new(u64::MAX, u64::MAX)?)?
            .with_spending(2, 1)?;
        let bytes = ledger.canonical_bytes();
        assert_eq!(bytes.len(), 52);
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
    fn grants_cover_historical_debt_before_allowing_new_spending()
    -> Result<(), Box<dyn std::error::Error>> {
        let debt = CampaignBudgetLedger {
            spent_proposals: 3,
            spent_attempts: 2,
            ..CampaignBudgetLedger::empty()
        };
        let restored = CampaignBudgetLedger::from_canonical_bytes(&debt.canonical_bytes())?;
        let funded = restored.with_grant(BudgetGrant::new(3, 2)?)?;
        assert_eq!(funded.remaining_attempts(), 0);
        assert_eq!(funded.remaining_proposals(), 0);
        assert!(funded.with_spending(1, 0).is_err());
        assert!(funded.with_spending(0, 1).is_err());
        funded
            .with_grant(BudgetGrant::new(1, 1)?)?
            .with_spending(1, 1)?;
        Ok(())
    }

    #[test]
    fn overflowing_grants_and_spending_fail_closed() -> Result<(), Box<dyn std::error::Error>> {
        let max = CampaignBudgetLedger {
            granted_proposals: u128::MAX,
            granted_attempts: u128::MAX,
            spent_proposals: u64::MAX,
            spent_attempts: u64::MAX,
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
        let twice = CampaignBudgetLedger::empty()
            .with_grant(BudgetGrant::new(u64::MAX, u64::MAX)?)?
            .with_grant(BudgetGrant::new(u64::MAX, u64::MAX)?)?;
        assert_eq!(twice.granted_attempts(), u128::from(u64::MAX) * 2);
        Ok(())
    }
}
