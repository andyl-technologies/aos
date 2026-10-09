//! Compatibility error projections for the shared bounded entropy walker.
//!
//! The Core DATA engine owns the sole kernel loop and retry budgets. Existing
//! role-specific callers retain their coarse security error and source names.

pub(crate) use aos_sandbox::tpm_nv_custody::entropy::{EntropySource, KernelEntropy};

use crate::BrokerSessionSecurityError;

pub(crate) fn nonzero_random<const N: usize, Source: EntropySource>(
    source: &mut Source,
) -> Result<[u8; N], BrokerSessionSecurityError> {
    aos_sandbox::tpm_nv_custody::entropy::nonzero_random(source)
        .map_err(|_| BrokerSessionSecurityError::Entropy)
}

/// Fills the same parked buffer and preserves the existing security projection.
pub(crate) fn fill_retained_nonzero(
    output: &mut zeroize::Zeroizing<Vec<u8>>,
) -> Result<(), BrokerSessionSecurityError> {
    aos_sandbox::tpm_nv_custody::entropy::fill_retained_nonzero(output)
        .map_err(|_| BrokerSessionSecurityError::Entropy)
}
