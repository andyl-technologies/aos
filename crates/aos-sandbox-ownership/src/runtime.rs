//! Drives the genuine PID1 Ownership original without exporting its handler.
//!
//! Native owns the exact activation table, F transfer, fixed credentials,
//! protected authority, listener, authenticated records and every native result.
//! The returned error keeps that entire original resident through projection.

use crate::OwnershipServiceReceivingOriginalV1;

/// Retains the complete fixed Ownership original after any entered refusal.
pub struct ProductionOwnershipAuthorityRuntimeErrorV1 {
    original: OwnershipServiceReceivingOriginalV1,
}

impl std::fmt::Debug for ProductionOwnershipAuthorityRuntimeErrorV1 {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.debug_struct("ProductionOwnershipAuthorityRuntimeErrorV1")
            .field("cause", &self.original.failure()).finish_non_exhaustive()
    }
}

impl std::fmt::Display for ProductionOwnershipAuthorityRuntimeErrorV1 {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str("the original Ownership service is unavailable; native custody is retained")
    }
}

impl std::error::Error for ProductionOwnershipAuthorityRuntimeErrorV1 {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.original.failure()
    }
}

/// Runs the fixed role2 service and its local authenticated transaction loop.
///
/// # Errors
/// Returns the owning original for any PID1, financial, credential, journal,
/// protocol-startup or service-integrity refusal. Failed individual connections
/// remain inside that original while a separately paid query/resume may enter.
pub fn run_from_environment() -> Result<(), ProductionOwnershipAuthorityRuntimeErrorV1> {
    let mut original = OwnershipServiceReceivingOriginalV1::new();
    if original.start_local_authority_once_v1().is_err() {
        return Err(ProductionOwnershipAuthorityRuntimeErrorV1 { original });
    }
    match original.run_local_authority_v1() {
        Ok(()) => Ok(()),
        Err(_) => Err(ProductionOwnershipAuthorityRuntimeErrorV1 { original }),
    }
}
