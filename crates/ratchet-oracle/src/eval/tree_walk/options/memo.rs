//! Content-memo option accessors for `TreeWalkOptions`.
//!
//! Groups the knobs that govern the in-process content-keyed memoization
//! tiers (MEMO-1): the L0 per-worker table, the L1 in-process shared table
//! used under parallel evaluation, the static-cost admission floor, capacity
//! budgets, and the shadow-check (CHECK) modes. All of these are advisory
//! performance settings — none participate in the result-affecting options
//! fingerprint, and none may change evaluation output.

use super::*;

impl TreeWalkOptions {
    /// Replaces the content-memo configuration.
    pub fn set_memo_options(&mut self, memo: MemoOptions) {
        self.memo = memo;
    }

    /// Returns the content-memo configuration.
    pub const fn memo_options(&self) -> &MemoOptions {
        &self.memo
    }

    /// Returns whether the per-worker L0 content-memo tier is active.
    ///
    /// True exactly when the master memo switch and the L0 tier switch are
    /// both enabled.
    pub const fn memo_l0_active(&self) -> bool {
        self.memo.enabled && self.memo.l0_enabled
    }

    /// Returns whether the in-process shared L1 content-memo tier is active.
    ///
    /// With the default (auto) policy the shared tier activates exactly when
    /// parallel workers are configured; an explicit `l1_enabled` override wins
    /// in either direction. The master memo switch always gates the tier.
    pub const fn memo_l1_active(&self) -> bool {
        self.memo.enabled
            && match self.memo.l1_enabled {
                Some(enabled) => enabled,
                None => self.parallel_workers.is_some(),
            }
    }

    /// Returns whether any content-memo tier is active.
    pub const fn memo_active(&self) -> bool {
        self.memo_l0_active() || self.memo_l1_active()
    }
}
