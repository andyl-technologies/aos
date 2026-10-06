//! Retained per-node admission for host service workers and descriptors.
//!
//! Allocators reserve independently configured host service subsets before
//! creating a thread or opening a descriptor. Cloned leases share one charge;
//! detached workers retain their own clone until their actual termination.
//! Native process ceilings and guest identity do not enter this allocator.

use std::sync::{Arc, Mutex};

/// A refused or uncertain host service resource reservation.
#[derive(Clone, Copy, Debug, thiserror::Error, PartialEq, Eq)]
pub enum HostServiceError {
    /// An explicit ceiling is zero or a request contains no resources.
    #[error("host service resource contract is invalid")]
    InvalidContract,
    /// Configured independently retained service capacity is exhausted.
    #[error("host service capacity is exhausted")]
    CapacityExhausted,
    /// Poisoned accounting prevents proving ownership safely.
    #[error("host service resource ownership is unavailable")]
    Unavailable,
}

#[derive(Debug, Default)]
struct ServiceUse {
    tasks: u64,
    descriptors: u64,
    resident_bytes: u64,
}

#[derive(Debug)]
struct ServiceCapacity {
    tasks: u64,
    descriptors: u64,
    resident_bytes: u64,
    used: Mutex<ServiceUse>,
}

/// Clone-shared independently admitted capacity for one node's host services.
#[derive(Clone, Debug)]
pub struct HostServiceAllocator {
    capacity: Arc<ServiceCapacity>,
}

impl PartialEq for HostServiceAllocator {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.capacity, &other.capacity)
    }
}

impl Eq for HostServiceAllocator {}

impl HostServiceAllocator {
    /// Validates explicit independently admitted host service subset ceilings.
    ///
    /// # Errors
    /// Refuses zero ceilings; it never infers a service capacity from guest CPUs.
    pub fn new(
        tasks: u64,
        descriptors: u64,
        resident_bytes: u64,
    ) -> Result<Self, HostServiceError> {
        if tasks == 0 || descriptors == 0 || resident_bytes == 0 {
            return Err(HostServiceError::InvalidContract);
        }
        Ok(Self {
            capacity: Arc::new(ServiceCapacity {
                tasks,
                descriptors,
                resident_bytes,
                used: Mutex::new(ServiceUse::default()),
            }),
        })
    }

    /// Returns the independently retained service task ceiling.
    pub fn maximum_tasks(&self) -> u64 {
        self.capacity.tasks
    }

    /// Returns the independently retained service descriptor ceiling.
    pub fn maximum_file_descriptors(&self) -> u64 {
        self.capacity.descriptors
    }

    /// Returns the independently retained host service resident-byte ceiling.
    pub fn maximum_resident_bytes(&self) -> u64 {
        self.capacity.resident_bytes
    }

    /// Reserves a complete service peak before any worker or descriptor creation.
    ///
    /// The caller retains a lease in every detached borrower until join or close
    /// actually completes. Creating a clone does not acquire additional capacity.
    ///
    /// # Errors
    /// Refuses empty requests, exhausted capacity, overflow, or poisoned ownership.
    pub fn reserve_resources(
        &self,
        tasks: u64,
        descriptors: u64,
        resident_bytes: u64,
    ) -> Result<HostServiceLease, HostServiceError> {
        if tasks == 0 && descriptors == 0 && resident_bytes == 0 {
            return Err(HostServiceError::InvalidContract);
        }
        let mut used = self
            .capacity
            .used
            .lock()
            .map_err(|_| HostServiceError::Unavailable)?;
        let new_tasks = used
            .tasks
            .checked_add(tasks)
            .ok_or(HostServiceError::CapacityExhausted)?;
        let new_descriptors = used
            .descriptors
            .checked_add(descriptors)
            .ok_or(HostServiceError::CapacityExhausted)?;
        let new_resident_bytes = used
            .resident_bytes
            .checked_add(resident_bytes)
            .ok_or(HostServiceError::CapacityExhausted)?;
        if new_resident_bytes > self.capacity.resident_bytes
            || new_tasks > self.capacity.tasks
            || new_descriptors > self.capacity.descriptors
        {
            return Err(HostServiceError::CapacityExhausted);
        }
        let reservation = Arc::new(ServiceReservation {
            capacity: Arc::clone(&self.capacity),
            tasks,
            descriptors,
            resident_bytes,
        });
        used.tasks = new_tasks;
        used.descriptors = new_descriptors;
        used.resident_bytes = new_resident_bytes;
        Ok(HostServiceLease { reservation })
    }
}

#[derive(Debug)]
struct ServiceReservation {
    capacity: Arc<ServiceCapacity>,
    tasks: u64,
    descriptors: u64,
    resident_bytes: u64,
}

impl Drop for ServiceReservation {
    fn drop(&mut self) {
        if let Ok(mut used) = self.capacity.used.lock()
            && let (Some(tasks), Some(descriptors), Some(resident_bytes)) = (
                used.tasks.checked_sub(self.tasks),
                used.descriptors.checked_sub(self.descriptors),
                used.resident_bytes.checked_sub(self.resident_bytes),
            )
        {
            used.tasks = tasks;
            used.descriptors = descriptors;
            used.resident_bytes = resident_bytes;
        }
        // Uncertain accounting keeps its charge rather than freeing capacity.
    }
}

/// Retained service resource authority shared by all physical borrowers.
#[derive(Clone, Debug)]
#[must_use = "the lease must outlive every descriptor and worker it authorizes"]
pub struct HostServiceLease {
    reservation: Arc<ServiceReservation>,
}

impl HostServiceLease {
    /// Returns the fixed lease value and shared reservation allocation payload.
    ///
    /// This includes the reservation's two Arc counters, but excludes allocator
    /// bookkeeping and the separately retained allocator's capacity allocation.
    /// Callers reserve it before constructing a new lease-owning container.
    pub const fn metadata_bytes() -> u64 {
        (std::mem::size_of::<Self>()
            + std::mem::size_of::<ServiceReservation>()
            + 2 * std::mem::size_of::<usize>()) as u64
    }

    /// Returns the independently admitted task charge shared by this lease.
    pub fn tasks(&self) -> u64 {
        self.reservation.tasks
    }

    /// Returns the independently admitted descriptor charge shared by this lease.
    pub fn file_descriptors(&self) -> u64 {
        self.reservation.descriptors
    }
    /// Returns the independently admitted resident-byte charge shared by this lease.
    pub fn resident_bytes(&self) -> u64 {
        self.reservation.resident_bytes
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- test fixtures panic to localize failed admission or ownership assertions.
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[test]
    fn clones_keep_charge_until_the_last_physical_borrower_finishes() {
        let allocator = HostServiceAllocator::new(1, 4, 4096).unwrap();
        let lease = allocator.reserve_resources(1, 4, 4096).unwrap();
        let borrower = lease.clone();
        drop(lease);
        assert_eq!(
            allocator.reserve_resources(1, 1, 1).unwrap_err(),
            HostServiceError::CapacityExhausted
        );
        drop(borrower);
        let replacement = allocator.reserve_resources(1, 4, 4096).unwrap();
        assert_eq!(replacement.tasks(), 1);
        assert_eq!(replacement.file_descriptors(), 4);
    }

    #[test]
    fn separate_limits_refuse_before_allocation_without_losing_capacity() {
        let allocator = HostServiceAllocator::new(2, 4, 4096).unwrap();
        assert!(allocator.reserve_resources(3, 1, 0).is_err());
        assert!(allocator.reserve_resources(1, 5, 0).is_err());
        assert!(allocator.reserve_resources(0, 0, 4097).is_err());
        let tasks = allocator.reserve_resources(2, 0, 0).unwrap();
        let descriptors = allocator.reserve_resources(0, 4, 0).unwrap();
        assert!(allocator.reserve_resources(1, 0, 0).is_err());
        assert!(allocator.reserve_resources(0, 1, 0).is_err());
        drop(tasks);
        drop(descriptors);
        assert!(allocator.reserve_resources(2, 4, 0).is_ok());
    }
}
