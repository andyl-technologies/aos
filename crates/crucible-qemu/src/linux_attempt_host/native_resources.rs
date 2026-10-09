//! Serializes concrete monotonic kernel tightening with attempt retirement.
//!
//! Weak handles neither retain an attempt nor release resources. The physical
//! owner closes this gate before process cleanup, cgroup removal or project-ID
//! recycling, so a surviving handle cannot mutate another attempt.

use crate::linux_cgroup::{LinuxQemuCgroupError, LinuxQemuCgroupMemoryControl};
use crucible_linux_resource::{LinuxProjectQuotaController, LinuxProjectQuotaError};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Weak};
use thiserror::Error;

/// Failure tightening the concrete native resource boundary.
#[derive(Debug, Error)]
pub enum LinuxQemuNativeResourceError {
    /// The physical owner retired or an earlier update became uncertain.
    #[error("native resource controller is retired or failed")]
    Retired,
    /// A request attempted to increase the current ceiling or admitted zero.
    #[error("native resource tightening cannot increase a ceiling or admit zero")]
    InvalidLimits,
    /// The pinned cgroup rejected a write or read-back authentication.
    #[error("native memory limit failed: {0}")]
    Cgroup(#[source] LinuxQemuCgroupError),
    /// The pinned project quota rejected installation or authentication.
    #[error("native writable limit failed: {0}")]
    ProjectQuota(#[source] LinuxProjectQuotaError),
}

/// Weak monotonic control over one live cgroup and project-quota reservation.
#[derive(Clone, Debug)]
pub struct LinuxQemuNativeResourceController {
    state: Weak<NativeResourceState>,
}

/// Retains the existing native control allocation until all its aliases close.
///
/// The private actor keeps its paired original credits outside this allocation
/// and outside the enclosing factory allocation. Process retirement and state
/// draining do not discharge a surviving weak controller's allocation tail.
/// This pin creates no control allocation or resource entitlement.
#[cfg(feature = "private-measurement-domain")]
#[derive(Debug)]
#[must_use = "retain external original credit until this actual control closes"]
pub struct OriginalNativeControlRetirement {
    state: Option<Arc<NativeResourceState>>,
}

#[cfg(feature = "private-measurement-domain")]
impl OriginalNativeControlRetirement {
    pub(super) fn retain(state: &Arc<NativeResourceState>) -> Self {
        Self {
            state: Some(Arc::clone(state)),
        }
    }

    /// Returns this target's one native state body and Arc control extent.
    ///
    /// This measurement excludes nested quota controls, pinned descriptors,
    /// allocator bookkeeping and the enclosing factory or actor. It is layout
    /// evidence for original admission, never an amount-based entitlement.
    /// Layout overflow returns `None` without creating an allocation.
    #[must_use]
    pub fn allocation_extent() -> Option<u64> {
        let (layout, _) = std::alloc::Layout::new::<(
            std::sync::atomic::AtomicUsize,
            std::sync::atomic::AtomicUsize,
        )>()
        .extend(std::alloc::Layout::new::<NativeResourceState>())
        .ok()?;
        u64::try_from(layout.pad_to_align().size()).ok()
    }

    /// Frees the same drained control only after its final other alias closes.
    ///
    /// Success certifies this allocation's closure only. The enclosing actor
    /// must separately verify joined process, storage, project and namespace
    /// retirement while retaining their genuine locks and original credits.
    ///
    /// # Errors
    /// Refuses repeated use, live or poisoned state, undrained memory authority,
    /// and any surviving owner, in-flight update or weak controller alias.
    /// Refusal retains this pin without releasing its actual allocation.
    pub fn close(&mut self) -> Result<(), LinuxQemuNativeResourceError> {
        let state = self
            .state
            .as_ref()
            .ok_or(LinuxQemuNativeResourceError::Retired)?;
        let limits = state
            .limits
            .lock()
            .map_err(|_| LinuxQemuNativeResourceError::Retired)?;
        if state.active.load(Ordering::Acquire) || limits.memory.is_some() {
            return Err(LinuxQemuNativeResourceError::Retired);
        }
        drop(limits);

        // No weak handle may remain: Arc::try_unwrap alone frees the body but
        // leaves the allocation header alive for outstanding Weak handles.
        if Arc::strong_count(state) != 1 || Arc::weak_count(state) != 0 {
            return Err(LinuxQemuNativeResourceError::Retired);
        }
        let state = self
            .state
            .take()
            .ok_or(LinuxQemuNativeResourceError::Retired)?;
        match unwrap_without_weak(state) {
            Ok(state) => {
                // The allocation closes before the extracted remaining quota
                // authority drops; external credit covers both until return.
                drop(state);
                Ok(())
            }
            Err(state) => {
                self.state = Some(state);
                Err(LinuxQemuNativeResourceError::Retired)
            }
        }
    }
}

#[cfg(feature = "private-measurement-domain")]
impl Drop for OriginalNativeControlRetirement {
    fn drop(&mut self) {
        if let Some(state) = self.state.take() {
            // Uncertain closure must retain the control, not let a body-drop
            // observation refund its externally retained original purposes.
            std::mem::forget(state);
        }
    }
}

#[cfg(feature = "private-measurement-domain")]
fn unwrap_without_weak<T>(mut value: Arc<T>) -> Result<T, Arc<T>> {
    let observed_weak = Arc::weak_count(&value);
    #[cfg(test)]
    original_retirement_tests::after_weak_snapshot();
    if observed_weak != 0 {
        return Err(value);
    }

    // Counts are refusal prefilters, not a uniqueness certificate. get_mut
    // atomically excludes both other Arc owners and Weak handles. No alias can
    // be issued between this successful gate and consuming the same Arc.
    if Arc::get_mut(&mut value).is_none() {
        return Err(value);
    }
    Arc::try_unwrap(value)
}

#[derive(Debug)]
pub(super) struct NativeResourceState {
    active: AtomicBool,
    limits: Mutex<NativeResourceLimits>,
}

#[derive(Debug)]
struct NativeResourceLimits {
    memory: Option<LinuxQemuCgroupMemoryControl>,
    quota: LinuxProjectQuotaController,
    resident: u64,
    resident_enforced: u64,
    writable: u64,
    failed: bool,
}

impl LinuxQemuNativeResourceController {
    /// Reports whether retirement has closed this incarnation's update gate.
    ///
    /// A failed kernel update does not itself retire physical authority. Use
    /// [`Self::is_physically_retained`] when retaining resources or replacing an
    /// owner; closing admission precedes process reap and update draining.
    #[must_use]
    pub fn is_active(&self) -> bool {
        self.state
            .upgrade()
            .is_some_and(|state| state.active.load(Ordering::Acquire))
    }

    /// Reports whether any physical owner or in-flight update retains this state.
    ///
    /// Closing admission does not discharge this receipt. Resource leases stay
    /// charged until process reap and serialized update draining release the
    /// retained controller, including every pinned descriptor.
    #[must_use]
    pub fn is_physically_retained(&self) -> bool {
        self.state.upgrade().is_some()
    }

    /// Compares opaque owner incarnation identity without exposing reusable IDs.
    #[must_use]
    pub fn same_incarnation(&self, other: &Self) -> bool {
        Weak::ptr_eq(&self.state, &other.state)
    }

    /// Returns the current admitted native resident and writable ceilings.
    ///
    /// Kernel memory is conservatively rounded down to its host page boundary,
    /// and ext4 rounds writable bytes down to its quota block boundary.
    ///
    /// # Errors
    /// Refuses retired, poisoned or uncertain authority.
    pub fn current_limits(&self) -> Result<(u64, u64), LinuxQemuNativeResourceError> {
        let state = self
            .state
            .upgrade()
            .ok_or(LinuxQemuNativeResourceError::Retired)?;
        let authority = state;
        let state = authority
            .limits
            .lock()
            .map_err(|_| LinuxQemuNativeResourceError::Retired)?;
        if !authority.active.load(Ordering::Acquire) || state.failed {
            return Err(LinuxQemuNativeResourceError::Retired);
        }
        Ok((state.resident, state.writable))
    }

    /// Reduces both concrete ceilings within the original complete reservation.
    ///
    /// Updates share one gate with physical retirement. Requests cannot increase
    /// either current ceiling. Writes and read-back validation use retained
    /// descriptors; no path or numeric project identifier grants authority.
    /// Memory is installed first, then writable quota. Partial failure closes
    /// future updates while retaining all physical enforcement for containment.
    ///
    /// # Errors
    /// Refuses retired or failed owners, zero or increased ceilings, or failed
    /// kernel operations. An error after a write does not roll a limit back.
    pub fn tighten(
        &self,
        maximum_resident_bytes: u64,
        maximum_writable_bytes: u64,
    ) -> Result<(), LinuxQemuNativeResourceError> {
        let state = self
            .state
            .upgrade()
            .ok_or(LinuxQemuNativeResourceError::Retired)?;
        let authority = state;
        let mut state = authority
            .limits
            .lock()
            .map_err(|_| LinuxQemuNativeResourceError::Retired)?;
        if !authority.active.load(Ordering::Acquire) || state.failed {
            return Err(LinuxQemuNativeResourceError::Retired);
        }
        if maximum_resident_bytes == 0
            || maximum_writable_bytes == 0
            || maximum_resident_bytes > state.resident
            || maximum_writable_bytes > state.writable
            || crucible_linux_resource::LinuxProjectQuotaLimits::new(maximum_writable_bytes, 1)
                .is_err()
        {
            return Err(LinuxQemuNativeResourceError::InvalidLimits);
        }
        let page_bytes = rustix::param::page_size() as u64;
        let enforced_resident = maximum_resident_bytes / page_bytes * page_bytes;
        if enforced_resident == 0 {
            return Err(LinuxQemuNativeResourceError::InvalidLimits);
        }
        let result = state
            .memory
            .as_ref()
            .ok_or(LinuxQemuNativeResourceError::Retired)?
            .tighten(state.resident_enforced, enforced_resident)
            .map_err(LinuxQemuNativeResourceError::Cgroup)
            .and_then(|()| {
                if !authority.active.load(Ordering::Acquire) {
                    return Err(LinuxQemuNativeResourceError::Retired);
                }
                state
                    .quota
                    .tighten(maximum_writable_bytes)
                    .map_err(LinuxQemuNativeResourceError::ProjectQuota)
            });
        if let Err(error) = result {
            state.failed = true;
            return Err(error);
        }
        state.resident = maximum_resident_bytes;
        state.resident_enforced = enforced_resident;
        state.writable = maximum_writable_bytes;
        Ok(())
    }
}

impl NativeResourceState {
    pub(super) fn new(
        memory: LinuxQemuCgroupMemoryControl,
        quota: LinuxProjectQuotaController,
        resident: u64,
        writable: u64,
    ) -> Arc<Self> {
        Arc::new(Self {
            active: AtomicBool::new(true),
            limits: Mutex::new(NativeResourceLimits {
                memory: Some(memory),
                quota,
                resident,
                resident_enforced: resident,
                writable,
                failed: false,
            }),
        })
    }

    pub(super) fn controller(state: &Arc<Self>) -> LinuxQemuNativeResourceController {
        LinuxQemuNativeResourceController {
            state: Arc::downgrade(state),
        }
    }

    pub(super) fn close(state: &Arc<Self>) {
        state.active.store(false, Ordering::Release);
    }

    pub(super) fn drain(state: &Arc<Self>) {
        // Process cancellation/reap must precede this wait: a memory.max write
        // may otherwise need progress from a guest being contained. Quota IDs
        // cannot be recycled until every retained kernel update has returned.
        let mut joined = state
            .limits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        joined.memory = None;
    }

    pub(super) fn available(state: &Arc<Self>) -> bool {
        state.active.load(Ordering::Acquire)
            && state.limits.lock().is_ok_and(|limits| !limits.failed)
    }
}

#[cfg(all(test, feature = "private-measurement-domain"))]
// crucible-lint: allow rust-allow -- these terminal allocation and original-counter controls deliberately panic on a failed invariant.
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod original_retirement_tests {
    use super::*;

    use crucible_linux_resource::host_services::{HostServiceAllocator, HostServiceLeasePair};

    // This fixed test-only cut exposes the stale weak-count window. It adds no
    // hook, TLS or observer storage to ordinary or private library artifacts.
    thread_local! {
        static WEAK_SNAPSHOT_CUT: std::cell::RefCell<Option<Arc<std::sync::Barrier>>> =
            const { std::cell::RefCell::new(None) };
    }

    pub(super) fn after_weak_snapshot() {
        WEAK_SNAPSHOT_CUT.with(|cut| {
            if let Some(barrier) = cut.borrow().as_ref() {
                barrier.wait();
                barrier.wait();
            }
        });
    }

    #[test]
    fn a_new_weak_after_the_snapshot_cannot_leave_a_successful_control_tail() {
        let allocation = Arc::new(31_u64);
        let worker_alias = Arc::clone(&allocation);
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let worker_barrier = Arc::clone(&barrier);
        let worker = std::thread::spawn(move || {
            worker_barrier.wait();
            let weak_tail = Arc::downgrade(&worker_alias);
            drop(worker_alias);
            worker_barrier.wait();
            worker_barrier.wait();
            drop(weak_tail);
        });

        // The actual helper samples zero Weak handles. Before its atomic gate,
        // the worker replaces its strong alias with a real Weak control tail.
        WEAK_SNAPSHOT_CUT.with(|cut| *cut.borrow_mut() = Some(Arc::clone(&barrier)));
        let outcome = unwrap_without_weak(allocation);
        WEAK_SNAPSHOT_CUT.with(|cut| *cut.borrow_mut() = None);
        barrier.wait();
        worker.join().unwrap();

        let retained = outcome.expect_err("a stale snapshot cannot certify control closure");
        assert_eq!(unwrap_without_weak(retained).unwrap(), 31);
    }

    #[test]
    fn a_unique_strong_owner_cannot_close_a_live_weak_control_tail() {
        let allocation = Arc::new(42_u64);
        let weak = Arc::downgrade(&allocation);
        assert_eq!(Arc::strong_count(&allocation), 1);

        let refused = unwrap_without_weak(allocation).unwrap_err();
        assert!(Weak::ptr_eq(&weak, &Arc::downgrade(&refused)));
        assert_eq!(*weak.upgrade().unwrap(), 42);

        drop(weak);
        assert_eq!(unwrap_without_weak(refused).unwrap(), 42);
    }

    #[test]
    fn a_real_other_owner_prevents_control_extraction_until_join() {
        let allocation = Arc::new(17_u64);
        let worker_alias = Arc::clone(&allocation);
        let barrier = std::sync::Barrier::new(2);
        std::thread::scope(|threads| {
            let worker = threads.spawn(|| {
                barrier.wait();
                assert_eq!(*worker_alias, 17);
                barrier.wait();
                drop(worker_alias);
            });

            barrier.wait();
            let refused = unwrap_without_weak(allocation).unwrap_err();
            assert_eq!(Arc::strong_count(&refused), 2);
            barrier.wait();
            worker.join().unwrap();
            assert_eq!(unwrap_without_weak(refused).unwrap(), 17);
        });
    }

    #[test]
    fn actual_paired_credit_is_external_to_control_and_payload_drop() {
        let first = HostServiceAllocator::new(1, 1, 64).unwrap();
        let second = HostServiceAllocator::new(1, 1, 64).unwrap();
        let (resident, metadata) = first.reserve_paired_bytes(&second, 64).unwrap();
        let external = HostServiceLeasePair::new(resident, metadata);
        let allocation = Arc::new(23_u64);
        let weak = Arc::downgrade(&allocation);

        let allocation = unwrap_without_weak(allocation).unwrap_err();
        for account in [&first, &second] {
            assert!(account.reserve_resources(0, 0, 1).is_err());
        }
        drop(weak);
        let extracted = unwrap_without_weak(allocation).unwrap();
        assert_eq!(extracted, 23);
        for account in [&first, &second] {
            assert!(account.reserve_resources(0, 0, 1).is_err());
        }

        drop(external);
        assert!(first.reserve_resources(0, 0, 64).is_ok());
        assert!(second.reserve_resources(0, 0, 64).is_ok());
        eprintln!(
            "native_retirement_pin={} native_control_extent={} private_host_owner={}",
            std::mem::size_of::<OriginalNativeControlRetirement>(),
            OriginalNativeControlRetirement::allocation_extent().unwrap(),
            std::mem::size_of::<super::super::LinuxQemuAttemptHostOwner>()
        );
        // These real allocation/counter controls certify the terminal primitive,
        // not installed native state, kernel cleanup or whole-purpose funding.
    }
}
