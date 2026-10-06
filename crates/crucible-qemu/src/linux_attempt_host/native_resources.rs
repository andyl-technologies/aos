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
