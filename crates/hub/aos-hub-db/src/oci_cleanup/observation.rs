//! Canonical retained Managed terminal cleanup bodies without execution authority.
//!
//! The decoder reuses production bounded canonical parsing, intrinsic request
//! shape and complete reply/original correlation. It verifies no MAC, SQL,
//! issuer acceptance, current clock or provider effect. A physically completed
//! upstream reply is distinct from the bytes actually consumed by Native.
//!
//! ```text
//! retained request -> unverified ManagedOciCleanupRequest
//! retained reply -> unverified ManagedOciCleanupReply
//! ```

use anyhow::Result;

use super::{decode_canonical, ManagedOciCleanupReply, ManagedOciCleanupRequest};

#[cfg(test)]
mod tests;

/// Decodes bounded canonical metadata and checks its exact original correlation.
///
/// The returned records are observations, not authenticated receipts or Delete
/// permission. A retained request may be expired; its original intrinsic window
/// remains bounded and no present execution cutoff is manufactured.
///
/// # Errors
/// Refuses oversized, incomplete, noncanonical or expanded JSON; invalid
/// audience, issuer, original or window; and any request/nonce/key/size/R2
/// incarnation/positive-receipt substitution.
pub fn decode_managed_oci_cleanup_observation(
    request: &[u8],
    reply: &[u8],
    deployment: &str,
) -> Result<(ManagedOciCleanupRequest, ManagedOciCleanupReply)> {
    let request: ManagedOciCleanupRequest = decode_canonical(request)?;
    let reply: ManagedOciCleanupReply = decode_canonical(reply)?;
    request.validate_observation_shape(deployment)?;
    reply.validate(&request)?;
    Ok((request, reply))
}
