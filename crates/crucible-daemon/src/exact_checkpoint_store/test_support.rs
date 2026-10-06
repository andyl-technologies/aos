//! Finite checkpoint and RAM-root decoding credit for component fixtures.
//!
//! This authority retains portable descriptor and resident accounting only.
//! It does not authenticate a filesystem quota or qualify native placement;
//! production stores obtain their authority from the admitted catalog provider.

use std::sync::Arc;

use crucible_cas::content_store::{StoreError, StorePhysicalQuotaGuard};
use crucible_linux_resource::host_services::{HostServiceAllocator, HostServiceError};

const FIXTURE_DESCRIPTORS: u64 = 128;
/// Complete independently authored resident allowance for component root loans.
pub(super) const FIXTURE_RESIDENT_BYTES: u64 = 256 * 1024 * 1024;

/// Constructs a finite portable account for component checkpoint decoders.
///
/// # Errors
/// Refuses an invalid independently authored allocator ceiling.
pub(crate) fn fixture_ram_root_resources()
-> Result<Arc<dyn StorePhysicalQuotaGuard>, HostServiceError> {
    let resources = HostServiceAllocator::new(1, FIXTURE_DESCRIPTORS, FIXTURE_RESIDENT_BYTES)?;
    Ok(Arc::new(FixtureRamRootResources(resources)))
}

struct FixtureRamRootResources(HostServiceAllocator);

impl StorePhysicalQuotaGuard for FixtureRamRootResources {
    fn reserve_resources(
        &self,
        descriptors: u64,
        resident_bytes: u64,
    ) -> Result<Arc<dyn Send + Sync>, StoreError> {
        self.0
            .reserve_resources(0, descriptors, resident_bytes)
            .map(|loan| Arc::new(loan) as Arc<dyn Send + Sync>)
            .map_err(|_| StoreError::Quota)
    }

    fn verify(&self) -> Result<(), StoreError> {
        Ok(())
    }
}
