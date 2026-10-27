//! Preserves upper mutation versus shared financial entry on the same Root.
//!
//! The unit mutex moves with the existing financial custody. Shared debits
//! release it before native append arming; upper callers retain its borrowed
//! guard through their original orchestration interval. It grants no healthy
//! continuation and does not serialize an entire Journal append.

use std::sync::{Arc, MutexGuard};

use super::{RootFinancialClosedV1, RootJournalFinancialOriginalV1};
use crate::receiving::{RootInitialReceivingOriginalV1, RootStartupNativeOriginalV1};

/// Excludes shared fees through the same original upper mutation interval.
///
/// Only a genuine permanent handle constructs this borrowed guard. The upper
/// wrapper releases its own orchestration mutex before releasing this guard.
#[must_use = "retain exclusion through the whole original upper interval"]
pub struct RootUpperMutationGuardV1<'original> {
    original: &'original RootJournalFinancialOriginalV1,
    _lock: MutexGuard<'original, ()>,
}

impl RootJournalFinancialOriginalV1 {
    /// Waits for the same original upper or shared-fee interval to finish.
    ///
    /// This is exclusion only. It deliberately permits independently owed
    /// observation paths after refusal. A poisoned exclusion mutex permanently
    /// refuses the native invocation before lending its retained unit guard;
    /// it never clears poison or restores healthy authority.
    #[must_use]
    pub fn enter_upper_mutation_v1(&self) -> RootUpperMutationGuardV1<'_> {
        let lock = match self.original.financial.upper_mutation.lock() {
            Ok(lock) => lock,
            Err(poisoned) => {
                self.original.invocation().latch_refusal();
                poisoned.into_inner()
            }
        };
        RootUpperMutationGuardV1 {
            original: self,
            _lock: lock,
        }
    }

    /// Compares this allocation's real startup link without currentness entry.
    #[must_use]
    pub fn same_startup_allocation_data_v1(&self, startup: &RootStartupNativeOriginalV1) -> bool {
        startup.initial_owner.as_ref().is_some_and(|identity| self.original.has_identity(identity))
    }

    /// Compares the held native startup with this actual permanent original.
    ///
    /// No native observation, namespace adoption or financial mutation occurs.
    ///
    /// # Errors
    /// Refuses a missing or different original startup association, failed
    /// financial custody, or an ended/refused native invocation.
    pub fn require_startup_association_v1(
        &self,
        startup: &RootStartupNativeOriginalV1,
    ) -> Result<(), RootFinancialClosedV1> {
        let mut invocation = self
            .original
            .enter_native()
            .map_err(|_| RootFinancialClosedV1)?;
        let same = startup
            .initial_owner
            .as_ref()
            .is_some_and(|identity| self.original.has_identity(identity));
        if !same || self.failure_v1().is_some() {
            invocation.refuse();
            return Err(RootFinancialClosedV1);
        }
        Ok(())
    }
}

impl RootUpperMutationGuardV1<'_> {
    /// Compares this held exclusion with the same actual financial allocation.
    ///
    /// This is passive affinity DATA. It performs no receiving debit, native
    /// entry, observation or allocation, and cannot construct a mutation guard.
    #[must_use]
    pub fn same_financial_original_data_v1(
        &self,
        original: &RootJournalFinancialOriginalV1,
    ) -> bool {
        self.original.same_original_data_v1(original)
    }

    pub(in crate::receiving) fn matches_permanent_original_v1(
        &self,
        original: &crate::receiving::root_permanent::RootPermanentNativeOriginalV1,
    ) -> bool {
        std::ptr::eq(self.original.original.as_ref(), original)
    }

    /// Permanently denies native entry without replacing an upper cause.
    pub fn refuse_v1(&self) {
        self.original.original.invocation().latch_refusal();
    }

    // The caller keeps both this guard and the actual Initial borrowed. This
    // private affinity check cannot construct a direct financial loan.
    pub(super) fn require_initial_v1(
        &self,
        initial: &RootInitialReceivingOriginalV1,
    ) -> Result<(), RootFinancialClosedV1> {
        let mut invocation = self
            .original
            .original
            .enter_native()
            .map_err(|_| RootFinancialClosedV1)?;
        let same = initial
            .permanent
            .as_ref()
            .is_some_and(|original| Arc::ptr_eq(original, &self.original.original));
        if !same || initial.failure().is_some() {
            invocation.refuse();
            return Err(RootFinancialClosedV1);
        }
        Ok(())
    }
}

impl Drop for RootUpperMutationGuardV1<'_> {
    fn drop(&mut self) {
        // Inner invocation/sums guards unwind before the enclosing upper
        // guard. Deny before the unit mutex releases any waiting shared fee.
        if std::thread::panicking() {
            self.refuse_v1();
        }
    }
}
