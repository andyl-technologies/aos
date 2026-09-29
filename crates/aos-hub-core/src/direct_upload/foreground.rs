//! Fixed original public invocation budget carried through private refreshes.
//!
//! The broker mints this capsule once before public body reading or queueing.
//! A new public invocation may carry a new capsule for the same retained business
//! operation; that never settles or erases an earlier unknown provider effect.
//!
//! ```json
//! {"invocationId":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","issuedAt":"100","expiresAt":"130"}
//! ```

use anyhow::{ensure, Result};
use serde::{Deserialize, Serialize};

use super::{valid_direct_digest, WireInteger};

/// Original server-entry deadline, separate from admission and renewed private proofs.
///
/// This structural commitment does not establish cancellation propagation,
/// qualified clock observations or the caller's pre-arrival network budget.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectForegroundBudget {
    /// Unique original public invocation identity, never a stable business address.
    pub invocation_id: String,
    /// Original nominal server-entry Unix seconds from the qualified clock policy.
    pub issued_at: WireInteger,
    /// Fixed exclusive entry deadline, with a positive lifetime of at most 30 seconds.
    pub expires_at: WireInteger,
}

impl DirectForegroundBudget {
    /// Checks canonical invocation identity and the fixed original short lifetime.
    ///
    /// # Errors
    /// Returns a value-free error for malformed identity, reversed or excessive time.
    pub fn validate_shape(&self) -> Result<()> {
        ensure!(
            valid_direct_digest(&self.invocation_id)
                && self
                    .expires_at
                    .get()
                    .checked_sub(self.issued_at.get())
                    .is_some_and(|seconds| seconds > 0 && seconds <= 30),
            "invalid direct foreground budget"
        );
        Ok(())
    }

    /// Checks freshness using the caller's conservative qualified current time.
    ///
    /// # Errors
    /// Returns a value-free error for malformed, future-issued or elapsed budgets.
    pub fn validate_at(&self, latest_now: u64) -> Result<()> {
        self.validate_shape()?;
        ensure!(
            self.issued_at.get() <= latest_now && latest_now < self.expires_at.get(),
            "direct foreground budget elapsed or invalid"
        );
        Ok(())
    }

    /// Checks that a fresh private context narrows the original invocation window.
    ///
    /// This never renews the original deadline or derives authority from polling.
    ///
    /// # Errors
    /// Returns a value-free error for an earlier issue time or extended deadline.
    pub fn validate_context_window(
        &self,
        context_issued_at: WireInteger,
        context_expires_at: WireInteger,
    ) -> Result<()> {
        self.validate_shape()?;
        ensure!(
            self.issued_at.get() <= context_issued_at.get()
                && context_issued_at.get() < context_expires_at.get()
                && context_expires_at.get() <= self.expires_at.get(),
            "direct context exceeds original foreground budget"
        );
        Ok(())
    }
}
