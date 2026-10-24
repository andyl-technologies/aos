//! Owns the fixed local ownership trust-bootstrap byte format.
//!
//! Decoding returns raw policy/key bytes or unverified artifacts. Protected file
//! admission, trust validation and live issuance remain with the parent owner.
//!
//! ```text
//! bootstrap = "AOSMOL01" || policy-len:u32be || canonical-policy ||
//!             ownership-public-key[32] || sha256(domain || preceding-bytes)
//! ```

use super::{ProtectedLeaseAuthorityErrorV1, fixed_bootstrap_error};

/// Returns bounded raw DATA through the sole portable framing decoder.
pub(super) fn decode_bootstrap(bytes: &[u8])
    -> Result<(Vec<u8>, [u8; 32]), ProtectedLeaseAuthorityErrorV1> {
    aos_sandbox_ownership_protocol::local_bootstrap::
        decode_local_ownership_bootstrap_with_error_v1(bytes, fixed_bootstrap_error)
}

#[cfg(test)]
mod tests;
