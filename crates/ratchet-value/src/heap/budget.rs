//! High-water memory-budget policy for heap escalation.
//!
//! The active runtime does not yet spill cold values or install the Tier-B
//! collector. This module defines the single-knob decision table from RFC-0007:
//! stay in the fast Tier-A arena while comfortably under budget, spill or
//! demote cold/dead pages near the budget, and request Tier-B only when the
//! resident set would remain over budget after all known cheap reclaim.

use thiserror::Error;

/// Default headroom reserved below the hard budget before spill starts.
pub const DEFAULT_BUDGET_HEADROOM_DENOMINATOR: usize = 8;

/// A configured high-water memory budget.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HeapMemoryBudget {
    max_resident_bytes: usize,
}

impl HeapMemoryBudget {
    /// Creates a high-water budget from a maximum resident byte count.
    ///
    /// # Errors
    ///
    /// Returns [`HeapMemoryBudgetError::ZeroBudget`] when
    /// `max_resident_bytes` is zero.
    pub const fn new(max_resident_bytes: usize) -> Result<Self, HeapMemoryBudgetError> {
        if max_resident_bytes == 0 {
            return Err(HeapMemoryBudgetError::ZeroBudget);
        }
        Ok(Self { max_resident_bytes })
    }

    /// Returns the hard resident byte ceiling.
    pub const fn max_resident_bytes(self) -> usize {
        self.max_resident_bytes
    }

    /// Returns the derived soft threshold where cheap reclaim starts.
    ///
    /// The budget remains the only user-facing knob. The soft threshold is
    /// derived from it to preserve headroom before the hard ceiling.
    pub const fn soft_limit_bytes(self) -> usize {
        let headroom = self.max_resident_bytes / DEFAULT_BUDGET_HEADROOM_DENOMINATOR;
        let headroom = if headroom > 1 { headroom } else { 1 };
        self.max_resident_bytes.saturating_sub(headroom)
    }

    /// Classifies one resident-memory sample.
    pub const fn classify(self, sample: HeapMemorySample) -> HeapMemoryBudgetResponse {
        let soft_limit = self.soft_limit_bytes();
        if sample.resident_bytes <= soft_limit {
            return HeapMemoryBudgetResponse::ContinueTierA {
                headroom_bytes: soft_limit - sample.resident_bytes,
                projected_resident_bytes: sample.resident_bytes,
            };
        }

        let desired_reclaim_bytes = sample.resident_bytes.saturating_sub(soft_limit);
        let available_reclaim_bytes = sample.available_reclaim_bytes();
        let reclaim_bytes = min_usize(desired_reclaim_bytes, available_reclaim_bytes);
        let projected_resident_bytes = sample.resident_bytes.saturating_sub(reclaim_bytes);

        if projected_resident_bytes > self.max_resident_bytes {
            return HeapMemoryBudgetResponse::InstallTierB {
                desired_reclaim_bytes,
                available_reclaim_bytes,
                projected_resident_bytes,
                over_budget_bytes: projected_resident_bytes - self.max_resident_bytes,
            };
        }

        HeapMemoryBudgetResponse::SpillCold {
            desired_reclaim_bytes,
            available_reclaim_bytes,
            projected_resident_bytes,
        }
    }
}

/// A resident-memory sample used by the budget decision table.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct HeapMemorySample {
    resident_bytes: usize,
    dead_arena_bytes: usize,
    cold_hash_consed_bytes: usize,
}

impl HeapMemorySample {
    /// Creates a sample with current resident and cheaply reclaimable bytes.
    pub const fn new(
        resident_bytes: usize,
        dead_arena_bytes: usize,
        cold_hash_consed_bytes: usize,
    ) -> Self {
        Self {
            resident_bytes,
            dead_arena_bytes,
            cold_hash_consed_bytes,
        }
    }

    /// Returns current resident bytes.
    pub const fn resident_bytes(self) -> usize {
        self.resident_bytes
    }

    /// Returns dead arena bytes eligible for page advice or region release.
    pub const fn dead_arena_bytes(self) -> usize {
        self.dead_arena_bytes
    }

    /// Returns cold hash-consed bytes eligible for CA-store spill or pageout.
    pub const fn cold_hash_consed_bytes(self) -> usize {
        self.cold_hash_consed_bytes
    }

    /// Returns the total cheap-reclaim capacity known to the runtime.
    pub const fn available_reclaim_bytes(self) -> usize {
        self.dead_arena_bytes
            .saturating_add(self.cold_hash_consed_bytes)
    }
}

/// The memory-budget action selected for one sample.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HeapMemoryBudgetResponse {
    /// Remain in the fast Tier-A arena path without doing reclaim work.
    ContinueTierA {
        /// Bytes remaining before reaching the soft spill threshold.
        headroom_bytes: usize,
        /// Resident bytes projected without cheap reclaim.
        projected_resident_bytes: usize,
    },
    /// Spill cold values or advise reclaimable pages before installing Tier B.
    SpillCold {
        /// Bytes needed to return to the derived soft threshold.
        desired_reclaim_bytes: usize,
        /// Bytes known to be cheaply reclaimable from dead or cold pages.
        available_reclaim_bytes: usize,
        /// Resident bytes projected after selected cheap reclaim.
        projected_resident_bytes: usize,
    },
    /// Install Tier B because cheap reclaim cannot bring residency under budget.
    InstallTierB {
        /// Bytes needed to return to the derived soft threshold.
        desired_reclaim_bytes: usize,
        /// Bytes known to be cheaply reclaimable from dead or cold pages.
        available_reclaim_bytes: usize,
        /// Resident bytes projected after selected cheap reclaim.
        projected_resident_bytes: usize,
        /// Bytes still above the hard budget after cheap reclaim.
        over_budget_bytes: usize,
    },
}

impl HeapMemoryBudgetResponse {
    /// Returns whether this response keeps the evaluator in Tier A.
    pub const fn stays_in_tier_a(self) -> bool {
        matches!(self, Self::ContinueTierA { .. } | Self::SpillCold { .. })
    }

    /// Returns the projected resident bytes after the selected cheap reclaim.
    pub const fn projected_resident_bytes(self) -> usize {
        match self {
            Self::ContinueTierA {
                projected_resident_bytes,
                ..
            }
            | Self::SpillCold {
                projected_resident_bytes,
                ..
            }
            | Self::InstallTierB {
                projected_resident_bytes,
                ..
            } => projected_resident_bytes,
        }
    }
}

/// A memory-budget configuration failure.
#[derive(Clone, Copy, Debug, Error, PartialEq, Eq)]
pub enum HeapMemoryBudgetError {
    /// A high-water budget of zero bytes cannot classify pressure.
    #[error("heap memory budget cannot be zero")]
    ZeroBudget,
}

const fn min_usize(left: usize, right: usize) -> usize {
    if left < right { left } else { right }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn budget(bytes: usize) -> HeapMemoryBudget {
        HeapMemoryBudget::new(bytes).expect("budget is non-zero")
    }

    #[test]
    fn zero_budget_is_rejected() {
        assert_eq!(
            HeapMemoryBudget::new(0),
            Err(HeapMemoryBudgetError::ZeroBudget)
        );
    }

    #[test]
    fn soft_limit_is_derived_from_single_hard_budget() {
        assert_eq!(budget(1024).max_resident_bytes(), 1024);
        assert_eq!(budget(1024).soft_limit_bytes(), 896);
        assert_eq!(budget(1).soft_limit_bytes(), 0);
    }

    #[test]
    fn resident_set_under_soft_limit_stays_in_tier_a() {
        let response = budget(1024).classify(HeapMemorySample::new(512, 0, 0));

        assert_eq!(
            response,
            HeapMemoryBudgetResponse::ContinueTierA {
                headroom_bytes: 384,
                projected_resident_bytes: 512,
            }
        );
        assert!(response.stays_in_tier_a());
        assert_eq!(response.projected_resident_bytes(), 512);
    }

    #[test]
    fn resident_set_at_soft_limit_stays_in_tier_a() {
        let response = budget(1024).classify(HeapMemorySample::new(896, 0, 0));

        assert_eq!(
            response,
            HeapMemoryBudgetResponse::ContinueTierA {
                headroom_bytes: 0,
                projected_resident_bytes: 896,
            }
        );
        assert!(response.stays_in_tier_a());
    }

    #[test]
    fn approaching_budget_spills_cold_values_to_restore_headroom() {
        let response = budget(1024).classify(HeapMemorySample::new(960, 16, 80));

        assert_eq!(
            response,
            HeapMemoryBudgetResponse::SpillCold {
                desired_reclaim_bytes: 64,
                available_reclaim_bytes: 96,
                projected_resident_bytes: 896,
            }
        );
        assert!(response.stays_in_tier_a());
    }

    #[test]
    fn projected_hard_budget_boundary_uses_spill_not_tier_b() {
        let response = budget(1024).classify(HeapMemorySample::new(1100, 76, 0));

        assert_eq!(
            response,
            HeapMemoryBudgetResponse::SpillCold {
                desired_reclaim_bytes: 204,
                available_reclaim_bytes: 76,
                projected_resident_bytes: 1024,
            }
        );
        assert!(response.stays_in_tier_a());
        assert_eq!(response.projected_resident_bytes(), 1024);
    }

    #[test]
    fn no_cheap_reclaim_near_budget_is_a_noop_spill_request() {
        let response = budget(1024).classify(HeapMemorySample::new(960, 0, 0));

        assert_eq!(
            response,
            HeapMemoryBudgetResponse::SpillCold {
                desired_reclaim_bytes: 64,
                available_reclaim_bytes: 0,
                projected_resident_bytes: 960,
            }
        );
        assert!(response.stays_in_tier_a());
    }

    #[test]
    fn over_budget_sample_uses_cheap_reclaim_before_tier_b() {
        let response = budget(1024).classify(HeapMemorySample::new(1100, 32, 128));

        assert_eq!(
            response,
            HeapMemoryBudgetResponse::SpillCold {
                desired_reclaim_bytes: 204,
                available_reclaim_bytes: 160,
                projected_resident_bytes: 940,
            }
        );
        assert!(response.stays_in_tier_a());
    }

    #[test]
    fn tier_b_is_requested_only_when_reclaim_cannot_get_under_budget() {
        let response = budget(1024).classify(HeapMemorySample::new(1300, 64, 64));

        assert_eq!(
            response,
            HeapMemoryBudgetResponse::InstallTierB {
                desired_reclaim_bytes: 404,
                available_reclaim_bytes: 128,
                projected_resident_bytes: 1172,
                over_budget_bytes: 148,
            }
        );
        assert!(!response.stays_in_tier_a());
    }

    #[test]
    fn reclaim_capacity_saturates_instead_of_overflowing() {
        let sample = HeapMemorySample::new(usize::MAX, usize::MAX, usize::MAX);

        assert_eq!(sample.available_reclaim_bytes(), usize::MAX);
        assert_eq!(
            budget(usize::MAX).classify(sample),
            HeapMemoryBudgetResponse::SpillCold {
                desired_reclaim_bytes: usize::MAX / DEFAULT_BUDGET_HEADROOM_DENOMINATOR,
                available_reclaim_bytes: usize::MAX,
                projected_resident_bytes: usize::MAX
                    - (usize::MAX / DEFAULT_BUDGET_HEADROOM_DENOMINATOR),
            }
        );
    }
}
