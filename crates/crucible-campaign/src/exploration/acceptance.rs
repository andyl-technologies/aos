//! Canonical branch-request acceptance summaries.
//!
//! Acceptance reports the request source's addressable candidate count and the
//! proposal-budget-visible deduplication window. Some generator definitions,
//! including progressive and modeled-uniform generators, incorporate the
//! request budget into their addressable source. Larger or history-sensitive
//! sources retain explicit ranges so callers never mistake a partial traversal
//! for an exact total.

use super::*;
use crate::codec::{Canonical, Decoder, Encoder};

/// One exact count or an inclusive, explicitly inexact range.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BranchAcceptanceCount {
    /// The owner proved the exact count.
    Exact(u64),
    /// The owner proved inclusive lower and upper bounds.
    Range(BranchAcceptanceRange),
}

/// Inclusive bounds for an inexact branch-acceptance count.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BranchAcceptanceRange {
    minimum: u64,
    maximum: u64,
}

impl BranchAcceptanceRange {
    /// Returns the inclusive lower bound.
    #[must_use]
    pub const fn minimum(self) -> u64 {
        self.minimum
    }

    /// Returns the inclusive upper bound.
    #[must_use]
    pub const fn maximum(self) -> u64 {
        self.maximum
    }
}

impl BranchAcceptanceCount {
    /// Builds validated inclusive bounds, collapsing equal endpoints to exact.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when `minimum` exceeds `maximum`.
    pub fn between(minimum: u64, maximum: u64) -> Result<Self, CampaignCodecError> {
        if minimum > maximum {
            return Err(CampaignCodecError::InvalidValue {
                reason: "branch acceptance count range is inverted",
            });
        }
        Ok(if minimum == maximum {
            Self::Exact(minimum)
        } else {
            Self::Range(BranchAcceptanceRange { minimum, maximum })
        })
    }

    /// Returns the inclusive lower bound.
    #[must_use]
    pub const fn minimum(self) -> u64 {
        match self {
            Self::Exact(value) => value,
            Self::Range(range) => range.minimum,
        }
    }

    /// Returns the inclusive upper bound.
    #[must_use]
    pub const fn maximum(self) -> u64 {
        match self {
            Self::Exact(value) => value,
            Self::Range(range) => range.maximum,
        }
    }

    /// Returns the exact count when the range has one possible value.
    #[must_use]
    pub const fn exact(self) -> Option<u64> {
        match self {
            Self::Exact(value) => Some(value),
            Self::Range(_) => None,
        }
    }
}

impl Canonical for BranchAcceptanceCount {
    fn encode(&self, encoder: &mut Encoder) {
        match self {
            Self::Exact(value) => {
                encoder.u8(0);
                value.encode(encoder);
            }
            Self::Range(range) => {
                encoder.u8(1);
                range.minimum.encode(encoder);
                range.maximum.encode(encoder);
            }
        }
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        match decoder.u8()? {
            0 => Ok(Self::Exact(u64::decode(decoder)?)),
            1 => Self::between(u64::decode(decoder)?, u64::decode(decoder)?),
            tag => Err(CampaignCodecError::UnknownTag {
                kind: "branch-acceptance-count",
                tag,
            }),
        }
    }
}

/// Immutable branch-request counts and semantic budgets at acceptance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BranchAcceptanceSummary {
    validated_cardinality: BranchAcceptanceCount,
    deduplicated_existing_edges: BranchAcceptanceCount,
    remaining_lazy_candidates: BranchAcceptanceCount,
    maximum_proposals: u64,
    maximum_attempts: u64,
}

impl BranchAcceptanceSummary {
    /// Builds a validated acceptance summary.
    ///
    /// # Errors
    ///
    /// Returns [`CampaignCodecError`] when a count exceeds the validated source
    /// cardinality or the budget is empty or internally inconsistent.
    pub fn new(
        validated_cardinality: BranchAcceptanceCount,
        deduplicated_existing_edges: BranchAcceptanceCount,
        remaining_lazy_candidates: BranchAcceptanceCount,
        maximum_proposals: u64,
        maximum_attempts: u64,
    ) -> Result<Self, CampaignCodecError> {
        let cardinality_upper = validated_cardinality.maximum();
        let proposal_window = cardinality_upper.min(maximum_proposals);
        let minimum_sum = u128::from(deduplicated_existing_edges.minimum())
            + u128::from(remaining_lazy_candidates.minimum());
        let maximum_sum = u128::from(deduplicated_existing_edges.maximum())
            + u128::from(remaining_lazy_candidates.maximum());
        if maximum_proposals == 0
            || maximum_attempts == 0
            || maximum_attempts > maximum_proposals
            || deduplicated_existing_edges.maximum() > proposal_window
            || remaining_lazy_candidates.maximum() > proposal_window
            || minimum_sum > u128::from(proposal_window)
            || maximum_sum < u128::from(proposal_window)
        {
            return Err(CampaignCodecError::InvalidValue {
                reason: "branch acceptance summary is inconsistent",
            });
        }
        Ok(Self {
            validated_cardinality,
            deduplicated_existing_edges,
            remaining_lazy_candidates,
            maximum_proposals,
            maximum_attempts,
        })
    }

    /// Returns the validated addressable source cardinality or its bounds.
    ///
    /// This count precedes the separate proposal-window calculation. A
    /// generator whose definition incorporates the request budget can still
    /// have a budget-bounded exact source cardinality.
    #[must_use]
    pub const fn validated_cardinality(self) -> BranchAcceptanceCount {
        self.validated_cardinality
    }

    /// Returns how many budget-visible semantic edges already existed.
    #[must_use]
    pub const fn deduplicated_existing_edges(self) -> BranchAcceptanceCount {
        self.deduplicated_existing_edges
    }

    /// Returns how many budget-visible candidates remain lazily consumable.
    #[must_use]
    pub const fn remaining_lazy_candidates(self) -> BranchAcceptanceCount {
        self.remaining_lazy_candidates
    }

    /// Returns the request's maximum proposal count.
    #[must_use]
    pub const fn maximum_proposals(self) -> u64 {
        self.maximum_proposals
    }

    /// Returns the request's maximum newly admitted attempt count.
    #[must_use]
    pub const fn maximum_attempts(self) -> u64 {
        self.maximum_attempts
    }
}

impl Canonical for BranchAcceptanceSummary {
    fn encode(&self, encoder: &mut Encoder) {
        self.validated_cardinality.encode(encoder);
        self.deduplicated_existing_edges.encode(encoder);
        self.remaining_lazy_candidates.encode(encoder);
        self.maximum_proposals.encode(encoder);
        self.maximum_attempts.encode(encoder);
    }

    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, CampaignCodecError> {
        Self::new(
            BranchAcceptanceCount::decode(decoder)?,
            BranchAcceptanceCount::decode(decoder)?,
            BranchAcceptanceCount::decode(decoder)?,
            u64::decode(decoder)?,
            u64::decode(decoder)?,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn count_bounds_are_canonical_and_ordered() -> Result<(), CampaignCodecError> {
        assert_eq!(
            BranchAcceptanceCount::between(7, 7)?,
            BranchAcceptanceCount::Exact(7)
        );
        assert_eq!(
            BranchAcceptanceCount::between(3, 9)?,
            BranchAcceptanceCount::Range(BranchAcceptanceRange {
                minimum: 3,
                maximum: 9,
            })
        );
        assert!(BranchAcceptanceCount::between(9, 3).is_err());

        let mut alternate = Encoder::new();
        alternate.u8(1);
        7_u64.encode(&mut alternate);
        7_u64.encode(&mut alternate);
        assert!(matches!(
            crate::codec::decode::<BranchAcceptanceCount>(&alternate.finish()),
            Err(CampaignCodecError::NonCanonical)
        ));
        Ok(())
    }

    #[test]
    fn summary_checks_budget_window_relations_with_wide_arithmetic()
    -> Result<(), CampaignCodecError> {
        let maximum = BranchAcceptanceSummary::new(
            BranchAcceptanceCount::Exact(u64::MAX),
            BranchAcceptanceCount::Exact(u64::MAX),
            BranchAcceptanceCount::Exact(0),
            u64::MAX,
            u64::MAX,
        )?;
        assert_eq!(maximum.maximum_proposals(), u64::MAX);

        let wide_ranges = BranchAcceptanceSummary::new(
            BranchAcceptanceCount::Exact(u64::MAX),
            BranchAcceptanceCount::between(0, u64::MAX)?,
            BranchAcceptanceCount::between(0, u64::MAX)?,
            u64::MAX,
            1,
        )?;
        assert_eq!(wide_ranges.remaining_lazy_candidates().maximum(), u64::MAX);

        assert!(
            BranchAcceptanceSummary::new(
                BranchAcceptanceCount::Exact(2),
                BranchAcceptanceCount::Exact(2),
                BranchAcceptanceCount::Exact(1),
                2,
                1,
            )
            .is_err()
        );
        assert!(
            BranchAcceptanceSummary::new(
                BranchAcceptanceCount::Exact(1),
                BranchAcceptanceCount::Exact(0),
                BranchAcceptanceCount::Exact(1),
                1,
                2,
            )
            .is_err()
        );
        Ok(())
    }
}
