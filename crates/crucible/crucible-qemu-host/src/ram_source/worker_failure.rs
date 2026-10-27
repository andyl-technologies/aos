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
use std::sync::OnceLock;
#[cfg(test)]
use std::sync::{Arc, Mutex};

use crucible_engine::{BackendOperationalCause, SharedOperationalCause};
use crucible_host_resources::host_services::HostServiceLease;

use super::QemuRamSourceError;

/// Keeps the original loan until the worker's remaining shared controls close.
pub(super) struct WorkerScope {
    failure: WorkerFailureJournal,
    _cleanup: Option<crate::launch_cleanup::LaunchCleanup>,
}

impl WorkerScope {
    pub(super) fn new(
        failure: WorkerFailureJournal,
        cleanup: Option<crate::launch_cleanup::LaunchCleanup>,
    ) -> Self {
        Self {
            failure,
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
        let error = self.failure.record(error);
        Err(error)
    }
}

#[derive(Debug)]
struct WorkerFailureBody {
    error: OnceLock<QemuRamSourceError>,
    _service_lease: HostServiceLease,
}

impl fmt::Display for WorkerFailureBody {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.error.get() {
            Some(error) => error.fmt(formatter),
            None => formatter.write_str("RAM source failure is not recorded"),
        }
    }
}

impl Error for WorkerFailureBody {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        self.error.get().map(|error| error as _)
    }
}

/// Owns one prepaid, unpublished failure control before a worker can be born.
///
/// This owner is never cloned. Recording consumes its sole handle, so every
/// published worker failure has exactly one initialized typed cause. Separate
/// launch and worker journals are necessary because a failed thread spawn
/// destroys the closure and its actual worker journal before returning.
pub(super) struct WorkerFailureJournal {
    shared: SharedOperationalCause<WorkerFailureBody>,
}

impl WorkerFailureJournal {
    pub(super) fn new(service_lease: HostServiceLease) -> Self {
        Self {
            shared: SharedOperationalCause::new(WorkerFailureBody {
                error: OnceLock::new(),
                _service_lease: service_lease,
            }),
        }
    }

    pub(super) fn record(self, error: QemuRamSourceError) -> QemuRamWorkerFailure {
        // Only this consuming method can initialize the private journal, and
        // no shared observer exists before the completed failure is returned.
        if self.shared.source_ref().error.set(error).is_err() {
            unreachable!("a linear unpublished worker journal is recorded once");
        }
        QemuRamWorkerFailure {
            shared: self.shared,
        }
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
            .checked_mul(2)
            .ok_or(QemuRamSourceError::Ownership)?
            .checked_add(lease_control)
            .and_then(|bytes| bytes.checked_add(shared_allocation_bytes::<AtomicBool>().ok()?))
            .and_then(|bytes| {
                bytes.checked_add(
                    super::worker_outcome::WorkerOutcome::allocation_peak_bytes().ok()?,
                )
            })
            .and_then(|bytes| bytes.checked_add(super::stop::StopState::journal_peak_bytes()?))
            .ok_or(QemuRamSourceError::Ownership)
    }

    #[cfg(test)]
    pub(super) fn new(error: QemuRamSourceError, service_lease: HostServiceLease) -> Self {
        WorkerFailureJournal::new(service_lease).record(error)
    }

    pub(crate) fn into_backend_cause(self) -> BackendOperationalCause {
        self.shared.into_backend_cause()
    }
}

impl Deref for QemuRamWorkerFailure {
    type Target = QemuRamSourceError;

    fn deref(&self) -> &Self::Target {
        match self.shared.source_ref().error.get() {
            Some(error) => error,
            None => unreachable!("only a recorded journal publishes a worker failure"),
        }
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
