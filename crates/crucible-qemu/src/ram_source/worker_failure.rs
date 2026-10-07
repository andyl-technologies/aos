//! Complete native page-worker failures retaining their original service lease.
//!
//! The private shared body never exposes its `Arc` or a weak reference. Every
//! observer consumes its strong reference with `Arc::into_inner`, closing the
//! control allocation before destroying the error and its original worker loan.

use std::alloc::Layout;
use std::error::Error;
use std::fmt;
use std::ops::Deref;
use std::sync::atomic::{AtomicBool, AtomicUsize};
use std::sync::{Arc, Mutex};

use crucible::{BackendOperationalCause, SharedOperationalCause};
use crucible_linux_resource::host_services::HostServiceLease;

use super::QemuRamSourceError;

/// Keeps the original loan until the worker's remaining shared controls close.
pub(super) struct WorkerScope {
    failure: Arc<Mutex<Option<QemuRamWorkerFailure>>>,
    service_lease: HostServiceLease,
    _cleanup: Option<crate::launch_cleanup::LaunchCleanup>,
}

impl WorkerScope {
    pub(super) fn new(
        failure: Arc<Mutex<Option<QemuRamWorkerFailure>>>,
        service_lease: HostServiceLease,
        cleanup: Option<crate::launch_cleanup::LaunchCleanup>,
    ) -> Self {
        Self {
            failure,
            service_lease,
            _cleanup: cleanup,
        }
    }

    pub(super) fn finish(
        self,
        result: Result<(), QemuRamSourceError>,
    ) -> Result<(), QemuRamWorkerFailure> {
        let Err(error) = result else {
            return Ok(());
        };
        let error = QemuRamWorkerFailure::new(error, self.service_lease);
        if let Ok(mut failure) = self.failure.lock() {
            *failure = Some(error.clone());
        }
        Err(error)
    }
}

#[derive(Debug)]
struct WorkerFailureBody {
    error: QemuRamSourceError,
    _service_lease: HostServiceLease,
}

impl fmt::Display for WorkerFailureBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.error.fmt(formatter)
    }
}

impl Error for WorkerFailureBody {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(&self.error)
    }
}

/// Shares a complete worker failure with its originally admitted resource lease.
///
/// Cloning shares original custody without allocating another error or acquiring
/// credit. The final observer closes its shared allocation before releasing the
/// retained worker lease. No observer can create a weak or ordinary Arc alias.
#[derive(Clone)]
pub struct QemuRamWorkerFailure {
    shared: SharedOperationalCause<WorkerFailureBody>,
}

impl QemuRamWorkerFailure {
    pub(super) fn allocation_bytes() -> Result<u64, QemuRamSourceError> {
        let bytes = SharedOperationalCause::<WorkerFailureBody>::allocation_bytes()
            .map_err(|_| QemuRamSourceError::Ownership)?;
        u64::try_from(bytes).map_err(|_| QemuRamSourceError::Ownership)
    }

    pub(super) fn startup_metadata_bytes() -> Result<u64, QemuRamSourceError> {
        // These concrete startup controls share the same original worker loan.
        // The lease's value is already inside the final worker-error body.
        let lease_control = HostServiceLease::metadata_bytes()
            .checked_sub(std::mem::size_of::<HostServiceLease>() as u64)
            .ok_or(QemuRamSourceError::Ownership)?;
        Self::allocation_bytes()?
            .checked_add(lease_control)
            .and_then(|bytes| bytes.checked_add(shared_allocation_bytes::<AtomicBool>().ok()?))
            .and_then(|bytes| {
                bytes.checked_add(shared_allocation_bytes::<Mutex<Option<Self>>>().ok()?)
            })
            .ok_or(QemuRamSourceError::Ownership)
    }

    pub(super) fn new(error: QemuRamSourceError, service_lease: HostServiceLease) -> Self {
        Self {
            shared: SharedOperationalCause::new(WorkerFailureBody {
                error,
                _service_lease: service_lease,
            }),
        }
    }

    pub(crate) fn into_backend_cause(self) -> BackendOperationalCause {
        self.shared.into_backend_cause()
    }
}

impl Deref for QemuRamWorkerFailure {
    type Target = QemuRamSourceError;

    fn deref(&self) -> &Self::Target {
        &self.shared.source_ref().error
    }
}

impl AsRef<QemuRamSourceError> for QemuRamWorkerFailure {
    fn as_ref(&self) -> &QemuRamSourceError {
        self
    }
}

impl fmt::Debug for QemuRamWorkerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.as_ref(), formatter)
    }
}

impl fmt::Display for QemuRamWorkerFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self.as_ref(), formatter)
    }
}

impl Error for QemuRamWorkerFailure {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        Some(self.as_ref())
    }
}

impl PartialEq for QemuRamWorkerFailure {
    fn eq(&self, other: &Self) -> bool {
        self.shared == other.shared
    }
}

impl Eq for QemuRamWorkerFailure {}

fn shared_allocation_bytes<T>() -> Result<u64, QemuRamSourceError> {
    let (layout, _) = Layout::new::<[AtomicUsize; 2]>()
        .extend(Layout::new::<T>())
        .map_err(|_| QemuRamSourceError::Ownership)?;
    u64::try_from(layout.pad_to_align().size()).map_err(|_| QemuRamSourceError::Ownership)
}

#[cfg(test)]
mod tests;
