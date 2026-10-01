//! Pure conservative request deadlines used by the actual live issuer adapter.

use anyhow::{ensure, Result};
use aos_hub_core::storage_authority::lease::{control::IssuerRequest, LeaseClock};

/// Checks metadata freshness at the conservative latest clock instant.
///
/// The actual adapter calls this after signing as well as before persistence.
/// A refusal never compensates for or rolls back an already committed CAS.
///
/// # Errors
/// Returns an error for a future-issued/stale request, invalid identity or clock
/// uncertainty, checked time overflow or reaching the exclusive expiry bound.
pub(crate) fn validate_request_deadline(request: &IssuerRequest, clock: LeaseClock) -> Result<()> {
    request.validate(&request.installation, clock.observed_at)?;
    ensure!(clock.uncertainty >= 0, "negative request clock uncertainty");
    let latest = clock
        .observed_at
        .checked_add(clock.uncertainty)
        .ok_or_else(|| anyhow::anyhow!("request clock overflow"))?;
    ensure!(latest < request.expires_at.get(), "issuer request is stale");
    Ok(())
}

#[cfg(test)]
#[path = "hybrid_authority_issuer_tests.rs"]
mod tests;
