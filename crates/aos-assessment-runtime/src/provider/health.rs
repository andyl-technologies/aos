//! Shared operational outage classification and bounded retry policy.
//!
//! The policy applies after exact result validation. A store persists these
//! decisions with its attempt receipt; uncertainty never refunds source quota.

use anyhow::Result;
use aos_contract::Sha256Digest;

use super::{ProviderWorkResultV1, WorkOutcome};
use crate::scan::TaskClaim;

/// Exponential delays indexed by the number of previously settled outages.
pub const PROVIDER_BACKOFF_STEPS: [u32; 8] = [20, 40, 80, 160, 320, 640, 1280, 2560];

/// Maximum exponential delay, including jitter, in seconds.
pub const MAX_PROVIDER_BACKOFF_SECONDS: u32 = 3600;

/// Determines whether a validated result establishes an upstream outage.
///
/// Invalid questions, permission denials and incomplete enumeration do not
/// penalize the shared provider. Explicit throttling facts also cover GitHub
/// responses whose status alone would otherwise mean a permission failure.
pub fn provider_result_indicates_outage(result: &ProviderWorkResultV1) -> bool {
    matches!(result.outcome, WorkOutcome::Failed | WorkOutcome::Partial)
        && (result.retry.is_some()
            || result.diagnostics.iter().any(|code| {
                code == "source-request-incomplete"
                    || code == "source-http-429"
                    || code.strip_prefix("source-http-").is_some_and(|status| {
                        status.len() == 3
                            && status.bytes().all(|byte| byte.is_ascii_digit())
                            && status
                                .parse::<u16>()
                                .is_ok_and(|status| (500..=599).contains(&status))
                    })
            }))
}

/// Derives deterministic zero-to-twenty-second jitter for one exact attempt.
///
/// # Errors
/// Returns an error if the attempt cannot be canonically encoded.
pub fn provider_backoff_jitter(claim: &TaskClaim) -> Result<u32> {
    Ok(u32::from(
        Sha256Digest::of_canonical("aos.assessment-provider-backoff-jitter/v1", claim)?.as_bytes()
            [0],
    ) % 21)
}

/// Computes an outage delay without exceeding the installed one-hour ceiling.
pub fn provider_backoff_seconds(prior_failures: u32, jitter: u32) -> u32 {
    PROVIDER_BACKOFF_STEPS
        .get(prior_failures as usize)
        .map_or(MAX_PROVIDER_BACKOFF_SECONDS, |delay| delay + jitter.min(20))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn repeated_outages_reach_a_hard_ceiling_even_with_untrusted_jitter() {
        assert_eq!(provider_backoff_seconds(0, 0), 20);
        assert_eq!(provider_backoff_seconds(0, u32::MAX), 40);
        assert_eq!(provider_backoff_seconds(7, 20), 2580);
        assert_eq!(provider_backoff_seconds(8, 20), 3600);
        assert_eq!(provider_backoff_seconds(u32::MAX, u32::MAX), 3600);
    }
}
