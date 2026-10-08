//! Retained per-node admission for host service workers and descriptors.
//!
//! Allocators reserve independently configured host service subsets before
//! creating a thread or opening a descriptor. Cloned leases share one charge;
//! detached workers retain their own clone until their actual termination.
//! Native process ceilings and guest identity do not enter this allocator.

use std::sync::{Arc, Mutex};

mod bootstrap;

pub use bootstrap::{AdmittedHostServiceBootstrap, HostServiceBootstrap};

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

#[cfg(feature = "test-support")]
pub(crate) enum ResidentProbe {
    Granted(HostServiceLease),
    Refused(HostServiceError),
    Contended,
}

impl PartialEq for HostServiceAllocator {
    fn eq(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.capacity, &other.capacity)
    }
}

impl Eq for HostServiceAllocator {}

impl HostServiceAllocator {
    /// Returns the allocator value and shared capacity allocation payload.
    ///
    /// Callers include this bookkeeping and the two Arc counters in their
    /// retained metadata admission before constructing an allocator.
    pub const fn metadata_bytes() -> u64 {
        (std::mem::size_of::<Self>()
            + std::mem::size_of::<ServiceCapacity>()
            + 2 * std::mem::size_of::<usize>()) as u64
    }

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

    /// Verifies retained accounting without creating a new service reservation.
    ///
    /// The shared capacity remains owned through every allocator and lease.
    /// This check reads the existing counters without changing their ceilings.
    ///
    /// # Errors
    /// Refuses poisoned accounting or counters outside the authored ceilings.
    pub fn verify_live(&self) -> Result<(), HostServiceError> {
        let used = self
            .capacity
            .used
            .lock()
            .map_err(|_| HostServiceError::Unavailable)?;
        if used.tasks > self.capacity.tasks
            || used.descriptors > self.capacity.descriptors
            || used.resident_bytes > self.capacity.resident_bytes
        {
            return Err(HostServiceError::CapacityExhausted);
        }
        Ok(())
    }

    #[cfg(feature = "test-support")]
    pub(crate) fn observed_resident_bytes(&self) -> Option<u64> {
        self.capacity
            .used
            .try_lock()
            .ok()
            .map(|used| used.resident_bytes)
    }

    // This fixed test probe uses the original accounting and concrete lease.
    // The observer retains a granted lease until teardown outside its hook.
    #[cfg(feature = "test-support")]
    pub(crate) fn probe_one_resident_byte(&self) -> ResidentProbe {
        let mut used = match self.capacity.used.try_lock() {
            Ok(used) => used,
            Err(std::sync::TryLockError::WouldBlock) => return ResidentProbe::Contended,
            Err(std::sync::TryLockError::Poisoned(_)) => {
                return ResidentProbe::Refused(HostServiceError::Unavailable);
            }
        };
        let Some(resident_bytes) = used.resident_bytes.checked_add(1) else {
            return ResidentProbe::Refused(HostServiceError::CapacityExhausted);
        };
        if resident_bytes > self.capacity.resident_bytes
            || used.tasks > self.capacity.tasks
            || used.descriptors > self.capacity.descriptors
        {
            return ResidentProbe::Refused(HostServiceError::CapacityExhausted);
        }

        let reservation = ServiceReservation {
            capacity: Arc::clone(&self.capacity),
            tasks: 0,
            descriptors: 0,
            resident_bytes: 1,
        };
        used.resident_bytes = resident_bytes;
        drop(used);
        ResidentProbe::Granted(reservation.into_lease())
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
        self.reserve_completed(
            tasks,
            descriptors,
            resident_bytes,
            ServiceReservation::into_lease,
        )
    }

    /// Reserves byte credit in both existing accounts before allocating leases.
    ///
    /// Both charges are admitted as stack-owned reservations. Only after the
    /// second grant succeeds are their shared lease controls allocated. An
    /// identical account is charged twice, under separate lock acquisitions.
    /// This grants no capacity beyond either authored allocator ceiling.
    ///
    /// # Errors
    /// Refuses empty requests, exhausted capacity, overflow, or poisoned
    /// ownership. A second refusal releases the first charge without creating
    /// either lease control or retaining an accounting lock during rollback.
    pub fn reserve_paired_bytes(
        &self,
        other: &Self,
        bytes: u64,
    ) -> Result<(HostServiceLease, HostServiceLease), HostServiceError> {
        let first = self.reserve_completed(0, 0, bytes, std::convert::identity)?;
        let second = other.reserve_completed(0, 0, bytes, std::convert::identity)?;
        Ok((first.into_lease(), second.into_lease()))
    }

    // Only the fixed lease and identity completions are used here. Their
    // owner remains live before commit, through unlock, and into completion.
    fn reserve_completed<T>(
        &self,
        tasks: u64,
        descriptors: u64,
        resident_bytes: u64,
        complete: impl FnOnce(ServiceReservation) -> T,
    ) -> Result<T, HostServiceError> {
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
        let reservation = ServiceReservation {
            capacity: Arc::clone(&self.capacity),
            tasks,
            descriptors,
            resident_bytes,
        };
        used.tasks = new_tasks;
        used.descriptors = new_descriptors;
        used.resident_bytes = new_resident_bytes;
        // A returned owner may immediately roll back. It must never hold the
        // mutex that its Drop needs to release its original charge.
        drop(used);
        Ok(complete(reservation))
    }
}

#[derive(Debug)]
struct ServiceReservation {
    capacity: Arc<ServiceCapacity>,
    tasks: u64,
    descriptors: u64,
    resident_bytes: u64,
}

impl ServiceReservation {
    fn into_lease(self) -> HostServiceLease {
        #[cfg(test)]
        LEASE_CONTROL_CONSTRUCTIONS.with(|count| count.set(count.get() + 1));

        HostServiceLease {
            reservation: Some(Arc::new(self)),
        }
    }
}

#[cfg(test)]
thread_local! {
    // Witnesses the sole lease-control allocation site, isolated per test.
    static LEASE_CONTROL_CONSTRUCTIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
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
#[must_use = "the lease must outlive every descriptor and worker it authorizes"]
pub struct HostServiceLease {
    reservation: Option<Arc<ServiceReservation>>,
}

impl Clone for HostServiceLease {
    fn clone(&self) -> Self {
        Self {
            reservation: self.reservation.clone(),
        }
    }
}

impl std::fmt::Debug for HostServiceLease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HostServiceLease")
            .field("reservation", self.reservation())
            .finish()
    }
}

impl Drop for HostServiceLease {
    fn drop(&mut self) {
        if let Some(reservation) = self.reservation.take() {
            // Every clone consumes its private Arc this way. The final owner
            // extracts the charge only after the control allocation closes,
            // so its original counters cannot be refunded before deallocation.
            drop(Arc::into_inner(reservation));
        }
    }
}

/// Retains a private pair of original leases through both control closes.
///
/// The provider consumes both freshly admitted halves without retaining
/// independent aliases. Sharing its enclosing owner preserves the pair;
/// this type exposes neither half and creates no resource credit or control.
/// For a complete unaliased pair, both existing controls close before either
/// extracted charge is refunded.
#[must_use = "the original pair must outlive every allocation it funds"]
#[derive(Debug)]
pub struct HostServiceLeasePair {
    first: HostServiceLease,
    second: HostServiceLease,
}

impl HostServiceLeasePair {
    /// Consumes the original leases without cloning or allocating.
    ///
    /// Joint custody requires both halves to remain private to this pair.
    /// Independently retained aliases still own their individual charges;
    /// this constructor cannot establish joint custody for those aliases.
    pub const fn new(first: HostServiceLease, second: HostServiceLease) -> Self {
        Self { first, second }
    }
}

impl Drop for HostServiceLeasePair {
    fn drop(&mut self) {
        let first = self.first.reservation.take().and_then(Arc::into_inner);
        let second = self.second.reservation.take().and_then(Arc::into_inner);
        // Both deallocations precede either ServiceReservation destructor.
        drop((first, second));
    }
}

impl HostServiceLease {
    /// Closes both supplied controls before refunding either extracted charge.
    ///
    /// A provider uses this for a privately retained pair whose halves never
    /// escape or acquire independent aliases. Sharing that complete enclosing
    /// owner preserves the pair. Independently cloned halves do not establish
    /// joint custody: their remaining aliases still own their own charges.
    pub fn close_pair(first: Self, second: Self) {
        drop(HostServiceLeasePair::new(first, second));
    }

    fn reservation(&self) -> &ServiceReservation {
        // Only Drop takes this reference; neither the emptied wrapper nor an
        // Arc or Weak reference to its reservation can escape to a caller.
        match &self.reservation {
            Some(reservation) => reservation,
            None => unreachable!("a live service lease owns its reservation"),
        }
    }

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
        self.reservation().tasks
    }

    /// Returns the independently admitted descriptor charge shared by this lease.
    pub fn file_descriptors(&self) -> u64 {
        self.reservation().descriptors
    }
    /// Returns the independently admitted resident-byte charge shared by this lease.
    pub fn resident_bytes(&self) -> u64 {
        self.reservation().resident_bytes
    }
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- test fixtures panic to localize failed admission or ownership assertions.
    #![allow(clippy::unwrap_used)]

    use super::*;

    #[cfg(feature = "test-support")]
    #[test]
    fn fixed_resident_probe_distinguishes_exhaustion_contention_and_poison() {
        let account = HostServiceAllocator::new(1, 1, 48).unwrap();
        let held = account.reserve_resources(1, 1, 48).unwrap();
        LEASE_CONTROL_CONSTRUCTIONS.with(|count| count.set(0));
        assert!(matches!(
            account.probe_one_resident_byte(),
            ResidentProbe::Refused(HostServiceError::CapacityExhausted)
        ));
        assert_eq!(LEASE_CONTROL_CONSTRUCTIONS.with(std::cell::Cell::get), 0);

        let guard = account.capacity.used.lock().unwrap();
        assert!(matches!(
            account.probe_one_resident_byte(),
            ResidentProbe::Contended
        ));
        drop(guard);
        drop(held);

        let probe = account.probe_one_resident_byte();
        let ResidentProbe::Granted(grant) = probe else {
            panic!("returned original byte must admit the actual fixed lease");
        };
        assert_eq!(grant.resident_bytes(), 1);
        assert_eq!(grant.tasks(), 0);
        assert_eq!(grant.file_descriptors(), 0);
        assert_eq!(LEASE_CONTROL_CONSTRUCTIONS.with(std::cell::Cell::get), 1);
        assert_eq!(account.observed_resident_bytes(), Some(1));
        drop(grant);
        assert_eq!(account.observed_resident_bytes(), Some(0));

        let poisoned = account.clone();
        let result = std::thread::spawn(move || {
            let _guard = poisoned.capacity.used.lock().unwrap();
            panic!("intentional original-account poison control");
        })
        .join();
        assert!(result.is_err());
        assert!(matches!(
            account.probe_one_resident_byte(),
            ResidentProbe::Refused(HostServiceError::Unavailable)
        ));
    }

    #[test]
    fn paired_refusal_allocates_neither_lease_control_and_restores_both_accounts() {
        for short_first in [true, false] {
            let first = HostServiceAllocator::new(1, 1, 16 - u64::from(short_first)).unwrap();
            let second = HostServiceAllocator::new(1, 1, 16 - u64::from(!short_first)).unwrap();
            LEASE_CONTROL_CONSTRUCTIONS.with(|count| count.set(0));

            assert_eq!(
                first.reserve_paired_bytes(&second, 16).unwrap_err(),
                HostServiceError::CapacityExhausted
            );
            assert_eq!(LEASE_CONTROL_CONSTRUCTIONS.with(std::cell::Cell::get), 0);

            assert!(
                first
                    .reserve_resources(0, 0, first.maximum_resident_bytes())
                    .is_ok()
            );
            assert!(
                second
                    .reserve_resources(0, 0, second.maximum_resident_bytes())
                    .is_ok()
            );
        }
    }

    #[test]
    fn paired_controls_exist_only_after_both_charges_and_last_alias_releases() {
        let first = HostServiceAllocator::new(1, 1, 16).unwrap();
        let second = HostServiceAllocator::new(1, 1, 16).unwrap();
        LEASE_CONTROL_CONSTRUCTIONS.with(|count| count.set(0));
        let (first_lease, second_lease) = first.reserve_paired_bytes(&second, 16).unwrap();
        assert_eq!(LEASE_CONTROL_CONSTRUCTIONS.with(std::cell::Cell::get), 2);
        assert!(first.reserve_resources(0, 0, 1).is_err());
        assert!(second.reserve_resources(0, 0, 1).is_err());
        let first_alias = first_lease.clone();
        let second_alias = second_lease.clone();
        drop(first_lease);
        drop(second_lease);
        assert!(first.reserve_resources(0, 0, 1).is_err());
        assert!(second.reserve_resources(0, 0, 1).is_err());
        drop(first_alias);
        drop(second_alias);
        assert!(first.reserve_paired_bytes(&second, 16).is_ok());
    }

    #[test]
    fn paired_identical_account_charges_twice_without_lock_or_alias_waiver() {
        let account = HostServiceAllocator::new(1, 1, 31).unwrap();
        LEASE_CONTROL_CONSTRUCTIONS.with(|count| count.set(0));
        assert_eq!(
            account.reserve_paired_bytes(&account, 16).unwrap_err(),
            HostServiceError::CapacityExhausted
        );
        assert_eq!(LEASE_CONTROL_CONSTRUCTIONS.with(std::cell::Cell::get), 0);
        assert!(account.reserve_resources(0, 0, 31).is_ok());

        let account = HostServiceAllocator::new(1, 1, 32).unwrap();
        let pair = account.reserve_paired_bytes(&account, 16).unwrap();
        assert!(account.reserve_resources(0, 0, 1).is_err());
        drop(pair);
        assert!(account.reserve_resources(0, 0, 32).is_ok());
        assert_eq!(std::mem::size_of::<ServiceReservation>(), 32);
    }

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

    #[test]
    fn live_verification_preserves_full_original_capacity_and_checks_each_ceiling() {
        let allocator = HostServiceAllocator::new(1, 4, 4096).unwrap();
        let lease = allocator.reserve_resources(1, 4, 4096).unwrap();
        allocator.verify_live().unwrap();
        let before = allocator.capacity.used.lock().unwrap();
        assert_eq!(
            (before.tasks, before.descriptors, before.resident_bytes),
            (1, 4, 4096)
        );
        drop(before);
        assert_eq!(
            allocator.reserve_resources(0, 0, 1).unwrap_err(),
            HostServiceError::CapacityExhausted
        );

        for invalid in [(2, 4, 4096), (1, 5, 4096), (1, 4, 4097)] {
            {
                let mut used = allocator.capacity.used.lock().unwrap();
                (used.tasks, used.descriptors, used.resident_bytes) = invalid;
            }
            assert_eq!(
                allocator.verify_live(),
                Err(HostServiceError::CapacityExhausted)
            );
        }
        {
            let mut used = allocator.capacity.used.lock().unwrap();
            (used.tasks, used.descriptors, used.resident_bytes) = (1, 4, 4096);
        }
        allocator.verify_live().unwrap();
        drop(lease);
        let _replacement = allocator.reserve_resources(1, 4, 4096).unwrap();
    }

    #[test]
    fn live_verification_preserves_original_poisoned_accounting_cause() {
        let allocator = HostServiceAllocator::new(1, 4, 4096).unwrap();
        let poisoned = std::panic::catch_unwind(|| {
            let _guard = allocator.capacity.used.lock().unwrap();
            panic!("component forces original accounting poisoning");
        });
        assert!(poisoned.is_err());
        assert_eq!(allocator.verify_live(), Err(HostServiceError::Unavailable));
    }
}
