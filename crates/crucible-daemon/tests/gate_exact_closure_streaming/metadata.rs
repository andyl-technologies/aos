//! Finite same-origin metadata and descriptor custody for the streaming fixture.
//!
//! This component account adds no installed filesystem quota or native admission.
//! Actual durable placement and headroom remain the real Directory/Graph contract.

use std::sync::Arc;

use crucible_cas::content_store::{StoreError, StorePhysicalQuotaGuard};
use crucible_linux_resource::host_services::HostServiceAllocator;

const RESIDENT_BYTES: u64 = 256 << 20;

pub(super) fn resources() -> Arc<dyn StorePhysicalQuotaGuard> {
    Arc::new(Resources(
        HostServiceAllocator::new(1, 128, RESIDENT_BYTES)
            .unwrap_or_else(|error| panic!("finite original fixture account: {error}")),
    ))
}

struct Resources(HostServiceAllocator);

impl StorePhysicalQuotaGuard for Resources {
    fn decoded_metadata_limit(&self) -> Result<u64, StoreError> {
        Ok(RESIDENT_BYTES)
    }

    fn reserve_resources(
        &self,
        descriptors: u64,
        resident_bytes: u64,
    ) -> Result<crucible_cas::owned_decode::ResourceLoan, StoreError> {
        self.0
            .reserve_resources(0, descriptors, resident_bytes)
            .map(crucible_cas::owned_decode::ResourceLoan::new)
            .map_err(|_| StoreError::Quota)
    }

    fn verify(&self) -> Result<(), StoreError> {
        Ok(())
    }
}
