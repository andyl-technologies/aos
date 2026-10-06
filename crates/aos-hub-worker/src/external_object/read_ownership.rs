//! Conservative body ownership for an already admitted immutable stage read.
//!
//! The signed lease is independently validated before this window is selected.
//! Its expiry bounds resource retention here; it does not turn admission expiry
//! into a provider settlement rule or extend mutation/publication authority.

use anyhow::{ensure, Result};
use aos_hub_core::storage_authority::lease::{LeaseTimingProfile, ValidatedEpochLease};

/// Pins a finite body resource window to the actual verified read lease.
#[derive(Clone, Copy)]
pub(super) struct ReadWindow {
    pub(super) expires_at: i64,
    maximum_lifetime: i64,
    pub(super) uncertainty: i64,
}

impl ReadWindow {
    /// Selects only the lease's independently configured timing profile.
    ///
    /// # Errors
    /// Refuses mismatched profiles, invalid lifetimes or unsupported timer bounds.
    pub(super) fn from_lease(
        lease: &ValidatedEpochLease,
        profile: &LeaseTimingProfile,
        uncertainty: i64,
    ) -> Result<Self> {
        profile.validate()?;
        ensure!(
            lease.payload.timing_profile == *profile,
            "immutable read timing profile differs"
        );
        // Revalidate the authenticated payload shape without issuing a new lease.
        lease.payload.digest()?;
        Self::checked(
            lease.payload.issued_at.get(),
            lease.payload.not_after.get(),
            profile.maximum_lifetime.get(),
            profile.maximum_clock_uncertainty.get(),
            uncertainty,
        )
    }

    fn checked(
        issued_at: i64,
        expires_at: i64,
        maximum_lifetime: i64,
        maximum_uncertainty: i64,
        uncertainty: i64,
    ) -> Result<Self> {
        let lifetime = expires_at
            .checked_sub(issued_at)
            .ok_or_else(|| anyhow::anyhow!("immutable read lifetime overflow"))?;
        ensure!(
            issued_at >= 0 && lifetime > 0 && lifetime <= maximum_lifetime,
            "immutable read resource lifetime invalid"
        );
        ensure!(
            uncertainty >= 0 && uncertainty <= maximum_uncertainty,
            "immutable read clock unqualified"
        );
        let millis = maximum_lifetime
            .checked_mul(1000)
            .ok_or_else(|| anyhow::anyhow!("immutable read timer overflow"))?;
        // worker::Delay passes milliseconds to setTimeout as an i32. Reject an
        // unsupported profile rather than narrowing or wrapping its duration.
        ensure!(
            millis > 0 && i32::try_from(millis).is_ok(),
            "immutable read profile exceeds supported timer"
        );
        Ok(Self {
            expires_at,
            maximum_lifetime,
            uncertainty,
        })
    }

    /// Computes the remaining conservative ownership bound without truncation.
    ///
    /// # Errors
    /// Refuses expired, overflowing or unbounded observations.
    pub(super) fn remaining(self, now: i64) -> Result<u64> {
        ensure!(now >= 0, "immutable read clock invalid");
        let latest = now
            .checked_add(self.uncertainty)
            .ok_or_else(|| anyhow::anyhow!("immutable read clock overflow"))?;
        let remaining = self
            .expires_at
            .checked_sub(latest)
            .ok_or_else(|| anyhow::anyhow!("immutable read cutoff overflow"))?;
        ensure!(
            remaining > 0 && remaining <= self.maximum_lifetime,
            "immutable read resource window expired or unbounded"
        );
        Ok(u64::try_from(remaining)?)
    }

    /// Checks current immutable ownership without repeating dispatch admission.
    ///
    /// # Errors
    /// Refuses cancellation, a changed binding/floor or the resource cutoff.
    pub(super) fn check(
        self,
        now: i64,
        canceled: bool,
        current: &dyn Fn() -> Result<()>,
    ) -> Result<()> {
        ensure!(!canceled, "immutable read canceled");
        current()?;
        self.remaining(now)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests;
