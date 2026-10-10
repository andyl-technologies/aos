//! Secret-free availability of installed provider routes at an explicit time.
//!
//! Eligibility describes whether the current route and shared allowance permit
//! another reservation. It does not assert provider health, successful evidence
//! acquisition or package coverage. Account identities and quota consumption
//! remain private to the coordinator.
//!
//! ```json
//! {"provider":"osv","availability":{"state":"waiting",
//!  "retryAt":"2026-10-10T00:03:20Z","cause":"spacing-or-cooldown"}}
//! ```

use anyhow::{Result, ensure};
use aos_assessment::time::Timestamp;
use serde::{Deserialize, Serialize};

/// Lists the supported provider profiles in canonical order.
pub const SOURCE_PROFILES: [&str; 7] = [
    "cisa-kev",
    "github-releases",
    "github-tags",
    "go-releases",
    "nvd",
    "osv",
    "repology",
];

/// Projects one installed source without exposing its credential or account.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub struct SourceStatus {
    /// Exact installed source profile, independent of a package project name.
    pub provider: String,
    /// Current reservation availability, independent of evidence coverage.
    pub availability: SourceAvailability,
}

/// Separates missing routes, unavailable authority and reservation delays.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "kebab-case", deny_unknown_fields)]
pub enum SourceAvailability {
    /// Has no complete installed route and quota declaration for this partition.
    Unconfigured {},
    /// Has no live route/grant authority through its next eligible reservation.
    AuthorityUnavailable {},
    /// Permits a reservation at the explicit status time, subject to atomic CAS.
    Eligible {},
    /// Requires a later reservation under an existing shared constraint.
    Waiting {
        /// Earliest projected reservation time; this never grants an allowance.
        #[serde(rename = "retryAt")]
        retry_at: Timestamp,
        /// Constraint responsible for the latest required deadline.
        cause: SourceDelayCause,
    },
}

/// Explains a shared reservation deadline without revealing quota usage.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SourceDelayCause {
    /// Waits for the next fixed UTC quota window.
    QuotaWindow,
    /// Honors minimum spacing or a retained provider cooldown.
    SpacingOrCooldown,
    /// Honors an open provider outage circuit.
    Circuit,
}

impl SourceAvailability {
    /// Describes the reservation state consistently in CLI and web status.
    pub fn description(&self) -> String {
        match self {
            Self::Unconfigured {} => "Not configured".into(),
            Self::AuthorityUnavailable {} => "Route authority unavailable".into(),
            Self::Eligible {} => "Eligible for another reservation".into(),
            Self::Waiting { retry_at, cause } => {
                let reason = match cause {
                    SourceDelayCause::QuotaWindow => "quota window",
                    SourceDelayCause::SpacingOrCooldown => "provider spacing or cooldown",
                    SourceDelayCause::Circuit => "provider outage circuit",
                };
                format!("Waiting until {retry_at} ({reason})")
            }
        }
    }
}

impl SourceStatus {
    /// Validates a bounded public source projection at its explicit status time.
    ///
    /// # Errors
    /// Returns an error for an unsupported profile or an invalid retry deadline.
    pub fn validate(&self, now: &Timestamp) -> Result<()> {
        ensure!(
            SOURCE_PROFILES.contains(&self.provider.as_str()),
            "unsupported public source profile"
        );
        if let SourceAvailability::Waiting { retry_at, .. } = &self.availability {
            let delay = retry_at.unix_seconds().checked_sub(now.unix_seconds());
            // A source hint lasts at most one day. The extra minute bounds
            // source-row reads that follow the page's database time capture.
            ensure!(
                delay.is_some_and(|seconds| (1..=86_460).contains(&seconds)),
                "public source retry deadline is expired or excessive"
            );
        }
        Ok(())
    }
}

/// Supplies private quota facts to the shared availability projection.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SourceBudgetWindow {
    /// Start of the last consumed fixed UTC quota window.
    pub window_start: u64,
    /// Installed fixed window length, at most one day.
    pub window_seconds: u32,
    /// Installed maximum calls per window.
    pub allowance: u32,
    /// Calls already consumed, including uncertain physical attempts.
    pub consumed: u32,
    /// Retained minimum-spacing or provider-cooldown deadline.
    pub next_eligible_at: u64,
    /// Retained outage-circuit deadline.
    pub circuit_until: u64,
}

impl SourceBudgetWindow {
    /// Projects eligibility without resetting quota, health or consumed attempts.
    ///
    /// # Errors
    /// Returns an error for invalid installed bounds, future windows or overflow.
    pub fn availability(
        &self,
        now: &Timestamp,
        authority_until: &Timestamp,
    ) -> Result<SourceAvailability> {
        ensure!(
            (1..=86400).contains(&self.window_seconds)
                && (1..=1_000_000).contains(&self.allowance)
                && self.consumed <= self.allowance
                && self.window_start <= now.unix_seconds(),
            "invalid source quota projection"
        );
        let window_end = self
            .window_start
            .checked_add(u64::from(self.window_seconds))
            .ok_or_else(|| anyhow::anyhow!("source quota window overflows"))?;
        let quota_at = if self.consumed == self.allowance {
            window_end
        } else {
            0
        };
        let (eligible_at, cause) = if self.circuit_until >= self.next_eligible_at.max(quota_at) {
            (self.circuit_until, SourceDelayCause::Circuit)
        } else if self.next_eligible_at >= quota_at {
            (self.next_eligible_at, SourceDelayCause::SpacingOrCooldown)
        } else {
            (quota_at, SourceDelayCause::QuotaWindow)
        };
        if authority_until <= now || eligible_at >= authority_until.unix_seconds() {
            return Ok(SourceAvailability::AuthorityUnavailable {});
        }
        if eligible_at <= now.unix_seconds() {
            return Ok(SourceAvailability::Eligible {});
        }
        Ok(SourceAvailability::Waiting {
            retry_at: Timestamp::from_unix_seconds(eligible_at)?,
            cause,
        })
    }
}
