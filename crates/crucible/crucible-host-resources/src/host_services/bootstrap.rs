//! Admits both original service accounts before publishing their heap controls.
//!
//! The unpublished capacity values are moved into their final controls once.
//! Structural byte charges remain in those same counters for their lifetime;
//! neither publication nor the last borrower resets or refunds those charges.

use std::alloc::Layout;
use std::sync::atomic::AtomicUsize;
use std::sync::{Arc, Mutex};

use super::{HostServiceAllocator, HostServiceError, ServiceCapacity, ServiceUse};

/// Unpublished original resident and metadata service accounts.
///
/// This owner performs no heap allocation. A successful structural admission
/// charges both future accounts before their first shared control is created.
#[derive(Debug)]
pub struct HostServiceBootstrap {
    resources: ServiceCapacity,
    metadata: ServiceCapacity,
}

/// Precharged original accounts awaiting their one fixed publication.
///
/// This token exists only after both original counters admit the structural
/// peak. Fixed initializers borrow it while constructing covered supervision
/// controls, then consume it to publish those same two accounts.
#[derive(Debug)]
pub struct AdmittedHostServiceBootstrap {
    original: HostServiceBootstrap,
    structural_bytes: u64,
}

impl HostServiceBootstrap {
    /// Creates the two original accounts with their authored ceilings.
    ///
    /// # Errors
    /// Refuses zero task, descriptor, resident, or metadata capacity.
    pub fn new(
        tasks: u64,
        descriptors: u64,
        resident_bytes: u64,
        metadata_bytes: u64,
    ) -> Result<Self, HostServiceError> {
        if tasks == 0 || descriptors == 0 || resident_bytes == 0 || metadata_bytes == 0 {
            return Err(HostServiceError::InvalidContract);
        }
        Ok(Self {
            resources: ServiceCapacity {
                tasks,
                descriptors,
                resident_bytes,
                used: Mutex::new(ServiceUse::default()),
            },
            metadata: ServiceCapacity {
                tasks: 1,
                descriptors: 1,
                resident_bytes: metadata_bytes,
                used: Mutex::new(ServiceUse::default()),
            },
        })
    }

    /// Charges the complete structural peak in both unpublished accounts.
    ///
    /// The resident account is checked first. A refusal consumes both
    /// unpublished accounts; no shared control or partial account is exposed.
    /// Successful charges are retained until the original capacities close.
    ///
    /// # Errors
    /// Refuses a charge smaller than both control allocations, either exhausted
    /// ceiling, or poisoned accounting.
    pub fn reserve_structure(
        mut self,
        bytes: u64,
    ) -> Result<AdmittedHostServiceBootstrap, HostServiceError> {
        if bytes < Self::control_bytes()? {
            return Err(HostServiceError::InvalidContract);
        }
        charge_structure(&mut self.resources, bytes)?;
        charge_structure(&mut self.metadata, bytes)?;
        Ok(AdmittedHostServiceBootstrap {
            original: self,
            structural_bytes: bytes,
        })
    }

    /// Returns the combined allocation extent of the two shared controls.
    ///
    /// # Errors
    /// Refuses a layout or byte-count overflow on the compilation target.
    pub fn control_bytes() -> Result<u64, HostServiceError> {
        let (layout, _) = Layout::new::<(AtomicUsize, AtomicUsize)>()
            .extend(Layout::new::<ServiceCapacity>())
            .map_err(|_| HostServiceError::CapacityExhausted)?;
        let bytes = layout
            .pad_to_align()
            .size()
            .checked_mul(2)
            .ok_or(HostServiceError::CapacityExhausted)?;
        u64::try_from(bytes).map_err(|_| HostServiceError::CapacityExhausted)
    }
}

impl AdmittedHostServiceBootstrap {
    pub(super) fn matches_process_capacity(
        &self,
        tasks: u64,
        descriptors: u64,
        resident_bytes: u64,
        metadata_bytes: u64,
    ) -> bool {
        self.original.resources.tasks == tasks
            && self.original.resources.descriptors == descriptors
            && self.original.resources.resident_bytes == resident_bytes
            && self.original.metadata.resident_bytes == metadata_bytes
    }

    /// Returns the structural charge retained in each original account.
    #[must_use]
    pub fn structural_bytes(&self) -> u64 {
        self.structural_bytes
    }

    /// Moves the admitted original accounts into their final shared controls.
    ///
    /// The caller retains these accounts through all allocations covered by
    /// their structural admission. Publication introduces neither a replacement
    /// account nor a new reservation and preserves each existing counter.
    #[must_use]
    pub fn publish(self) -> (HostServiceAllocator, HostServiceAllocator) {
        (
            HostServiceAllocator {
                capacity: Arc::new(self.original.resources),
            },
            HostServiceAllocator {
                capacity: Arc::new(self.original.metadata),
            },
        )
    }
}

fn charge_structure(capacity: &mut ServiceCapacity, bytes: u64) -> Result<(), HostServiceError> {
    let used = capacity
        .used
        .get_mut()
        .map_err(|_| HostServiceError::Unavailable)?;
    let resident_bytes = used
        .resident_bytes
        .checked_add(bytes)
        .ok_or(HostServiceError::CapacityExhausted)?;
    if resident_bytes > capacity.resident_bytes {
        return Err(HostServiceError::CapacityExhausted);
    }
    used.resident_bytes = resident_bytes;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn publication_moves_both_original_counter_values_without_a_refund() {
        let original = HostServiceBootstrap::new(2, 3, 512, 256)
            .unwrap_or_else(|error| panic!("original capacities: {error}"))
            .reserve_structure(144)
            .unwrap_or_else(|error| panic!("original structure: {error}"));
        let (resources, metadata) = original.publish();

        for account in [&resources, &metadata] {
            let used = account
                .capacity
                .used
                .lock()
                .unwrap_or_else(|error| panic!("original counters: {error}"));
            assert_eq!(used.resident_bytes, 144);
            assert_eq!(used.tasks, 0);
            assert_eq!(used.descriptors, 0);
        }

        assert_eq!(resources.maximum_tasks(), 2);
        assert_eq!(resources.maximum_file_descriptors(), 3);
        assert_eq!(resources.maximum_resident_bytes(), 512);
        assert_eq!(metadata.maximum_resident_bytes(), 256);
    }

    #[test]
    fn structure_refuses_each_original_ceiling_before_publication() {
        for (resident, metadata) in [(143, 256), (512, 143)] {
            let original = HostServiceBootstrap::new(2, 3, resident, metadata)
                .unwrap_or_else(|error| panic!("original capacities: {error}"));
            assert!(matches!(
                original.reserve_structure(144),
                Err(HostServiceError::CapacityExhausted)
            ));
        }
    }

    #[test]
    fn original_control_geometry_is_target_derived() {
        eprintln!(
            "bootstrap value={} capacity={} counters={} allocator={} pair_controls={}",
            std::mem::size_of::<HostServiceBootstrap>(),
            std::mem::size_of::<ServiceCapacity>(),
            std::mem::size_of::<ServiceUse>(),
            std::mem::size_of::<HostServiceAllocator>(),
            HostServiceBootstrap::control_bytes()
                .unwrap_or_else(|error| panic!("original control layouts: {error}"))
        );
    }
}
