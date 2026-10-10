//! Shared assessment profile expansion and source freshness options.
//!
//! `all` resolves to today's explicit sorted profile set before admission;
//! no future profile or deployment-specific provider is selected implicitly.

use aos_assessment::input::{FreshnessMode, Profile};

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
pub enum AssessmentProfileArg {
    /// Check eligible upstream package updates
    Updates,
    /// Check supported advisory sources and CVE mappings
    Vulnerabilities,
    /// Check non-authoritative license signals
    LicenseSignals,
    /// Select every explicitly supported assessment profile
    All,
}

/// Expands the selected CLI profiles into the exact canonical request set.
pub fn assessment_profiles(selected: &[AssessmentProfileArg]) -> Vec<Profile> {
    let mut profiles = Vec::new();
    for profile in selected {
        match profile {
            AssessmentProfileArg::Updates => profiles.push(Profile::Updates),
            AssessmentProfileArg::Vulnerabilities => profiles.push(Profile::Vulnerabilities),
            AssessmentProfileArg::LicenseSignals => profiles.push(Profile::LicenseSignals),
            AssessmentProfileArg::All => profiles.extend([
                Profile::LicenseSignals,
                Profile::Updates,
                Profile::Vulnerabilities,
            ]),
        }
    }
    profiles.sort();
    profiles.dedup();
    profiles
}

#[derive(clap::ValueEnum, Clone, Copy, Debug)]
pub enum AssessmentFreshnessArg {
    /// Reuse admitted evidence without contacting providers
    Cached,
    /// Acquire only missing, incomplete or expired source observations
    RefreshStale,
    /// Revalidate selected sources within their configured budgets
    Refresh,
    /// Forbid provider acquisition and preserve visible evidence gaps
    Offline,
}

impl From<AssessmentFreshnessArg> for FreshnessMode {
    fn from(freshness: AssessmentFreshnessArg) -> Self {
        match freshness {
            AssessmentFreshnessArg::Cached => Self::Cached,
            AssessmentFreshnessArg::RefreshStale => Self::RefreshStale,
            AssessmentFreshnessArg::Refresh => Self::Refresh,
            AssessmentFreshnessArg::Offline => Self::Offline,
        }
    }
}
