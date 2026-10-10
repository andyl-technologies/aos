//! Bounded observations of native RAM map and cache borrower lifetimes.

use serde_json::{Map, Value};

/// Observes process-local RAM borrowers without granting a quiescence certificate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct QmpHotForkRamBorrowInventory {
    /// Monotonic generation of the native borrower inventory.
    pub generation: u64,
    /// Currently retained direct guest-memory maps.
    pub direct_maps: u64,
    /// Currently retained bounced guest-memory maps.
    pub bounce_maps: u64,
    /// Currently retained guest-memory caches.
    pub caches: u64,
    /// Currently retained direct guest-memory caches.
    pub direct_caches: u64,
    /// Whether managed RAM paging was requested for this process.
    pub paging_requested: bool,
    /// Whether all paired native borrower observations were consistent.
    pub consistent: bool,
}

impl QmpHotForkRamBorrowInventory {
    pub(super) fn parse(object: &Map<String, Value>) -> Option<Self> {
        let inventory = Self {
            generation: object.get("ram-borrow-generation")?.as_u64()?,
            direct_maps: object.get("ram-direct-maps")?.as_u64()?,
            bounce_maps: object.get("ram-bounce-maps")?.as_u64()?,
            caches: object.get("ram-caches")?.as_u64()?,
            direct_caches: object.get("ram-direct-caches")?.as_u64()?,
            paging_requested: object.get("ram-paging-requested")?.as_bool()?,
            consistent: object.get("ram-borrowers-consistent")?.as_bool()?,
        };
        (!inventory.consistent || inventory.generation != 0).then_some(inventory)
    }

    #[cfg(any(test, feature = "test-support"))]
    pub(super) const fn empty_component() -> Self {
        Self {
            generation: 1,
            direct_maps: 0,
            bounce_maps: 0,
            caches: 0,
            direct_caches: 0,
            paging_requested: false,
            consistent: true,
        }
    }
}
