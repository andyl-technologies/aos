//! Validates local collector scheduling against enforced repository timing.
//!
//! These settings contain no lease, clock observation or collection authority.
//! The configured runtime must acquire its original session and qualify every
//! native operation independently. Parsing this table starts no service.
//!
//! ```toml
//! [gc]
//! lease_seconds = 300
//! poll_ms = 1000
//! cycle_interval_ms = 60000
//! mark_batch = 32
//! maintenance_batch = 8
//! deletion_seconds = 86400
//! ```

use serde::Deserialize;
use terrane_format::gc::Windows;

use super::{ConfigError, local_repository::LocalCommitTiming};

/// Holds explicit scheduling bounds for a configured native local collector.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LocalCollector {
    /// Positive whole-session lease duration in seconds.
    pub lease_seconds: u64,
    /// Positive delay between scheduling passes, strictly below half the lease.
    pub poll_ms: u64,
    /// Minimum interval between mark cycles, at least one scheduling delay.
    pub cycle_interval_ms: u64,
    /// Maximum authenticated contexts expanded by one marking batch.
    pub mark_batch: usize,
    /// Maximum recurring lookup hints selected in one maintenance batch.
    pub maintenance_batch: usize,
    /// Full deletion window in seconds, at least the rounded repository grace.
    pub deletion_seconds: u64,
}

impl LocalCollector {
    pub(super) fn validate(&self, timing: &LocalCommitTiming) -> Result<(), ConfigError> {
        let lease_ms = self
            .lease_seconds
            .checked_mul(1_000)
            .ok_or(ConfigError::Invalid("collector lease duration overflows"))?;
        let two_polls = self
            .poll_ms
            .checked_mul(2)
            .ok_or(ConfigError::Invalid("collector scheduling delay overflows"))?;
        if self.lease_seconds == 0
            || self.poll_ms == 0
            || two_polls >= lease_ms
            || self.cycle_interval_ms < self.poll_ms
            || !(1..=256).contains(&self.mark_batch)
            || !(1..=256).contains(&self.maintenance_batch)
        {
            return Err(ConfigError::Invalid(
                "invalid local collector scheduling bounds",
            ));
        }
        self.windows(timing)?;
        Ok(())
    }

    /// Derives conservative whole-second windows from enforced repository timing.
    ///
    /// Rounds both the maximum commit duration and grace upward. Rounding must
    /// preserve a strictly greater grace; a subsecond difference does not permit
    /// silently shortening either bound. Uses the registered 90-day ordinary
    /// reflog default, raised when necessary to at least grace plus commit.
    /// This arithmetic grants no native creation-time or deletion-age evidence.
    ///
    /// # Errors
    /// Rejects unavailable std support, invalid enforced commit timing, loss of
    /// strict grace after rounding, too-short deletion windows and overflow.
    pub fn windows(&self, timing: &LocalCommitTiming) -> Result<Windows, ConfigError> {
        #[cfg(not(feature = "std"))]
        {
            let _ = timing;
            Err(ConfigError::Invalid("local collectors require std support"))
        }

        #[cfg(feature = "std")]
        {
            timing.validated()?;
            let upward = |milliseconds: u64| {
                (milliseconds / 1_000)
                    .checked_add(u64::from(!milliseconds.is_multiple_of(1_000)))
                    .ok_or(ConfigError::Invalid("collector window overflows"))
            };
            let commit = upward(timing.maximum_ms)?;
            let grace = upward(timing.grace_ms)?;
            let retention = grace
                .checked_add(commit)
                .ok_or(ConfigError::Invalid("collector retention overflows"))?
                .max(7_776_000);
            Windows::new(commit, grace, self.deletion_seconds, retention)
                .map_err(|_| ConfigError::Invalid("invalid local collector windows"))
        }
    }
}

#[cfg(all(test, feature = "std"))]
mod tests;
