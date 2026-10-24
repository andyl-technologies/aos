//! Delivers one real Rust body result before the native thread returns.
//!
//! This is the source's existing shared failure allocation, enlarged in place.
//! Its opaque aliases cannot create Weak references. The last alias frees the
//! Arc header before dropping the actual result, panic payload and worker loan.

use super::*;
use std::any::Any;
use std::sync::{Mutex, OnceLock};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BodyState {
    NeverStarted,
    Running,
    Returned,
    Panicked,
}

struct OutcomeBody {
    state: BodyState,
    failure: Option<QemuRamWorkerFailure>,
    panic: Option<Box<dyn Any + Send>>,
    uncertain: bool,
    // Actual outcomes and the control body close before this original loan.
    _lease: crucible_host_resources::host_services::HostServiceLease,
}

// The join record must remain outside the result mutex: abandonment neither
// waits for worker delivery nor allocates another recipient.
struct OutcomeAllocation {
    body: Mutex<OutcomeBody>,
    abandoned: OnceLock<AbandonedWorker>,
    live_receiver: OnceLock<QemuRamSourceService>,
}

struct AbandonedWorker {
    _native: NativeJoinOwner,
    _launch_join: Option<crate::launch_cleanup::LaunchSourceJoin>,
    _stop: stop::StopState,
    _birth: (Option<HostSupervisionError>, Option<HostSupervisionError>),
}

pub(super) struct WorkerOutcome {
    shared: Option<Arc<OutcomeAllocation>>,
}

pub(super) struct OutcomeSnapshot {
    pub(super) delivered: bool,
    pub(super) failure: Option<QemuRamWorkerFailure>,
    pub(super) panic: Option<QemuRamWorkerPanic>,
    pub(super) uncertain: bool,
}

/// Retains the actual caught panic payload and its original worker loan.
///
/// Cloning shares the existing outcome allocation. Physical native join and
/// operational history remain distinct; this receipt never grants work.
#[derive(Clone)]
pub struct QemuRamWorkerPanic {
    outcome: WorkerOutcome,
}

impl std::fmt::Debug for QemuRamWorkerPanic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("QemuRamWorkerPanic { retained_payload: true }")
    }
}

impl std::fmt::Display for QemuRamWorkerPanic {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("RAM source worker panicked")
    }
}

impl std::error::Error for QemuRamWorkerPanic {}

impl PartialEq for QemuRamWorkerPanic {
    fn eq(&self, other: &Self) -> bool {
        match (&self.outcome.shared, &other.outcome.shared) {
            (Some(left), Some(right)) => Arc::ptr_eq(left, right),
            _ => false,
        }
    }
}

impl Eq for QemuRamWorkerPanic {}

impl Clone for WorkerOutcome {
    fn clone(&self) -> Self {
        Self {
            shared: self.shared.as_ref().map(Arc::clone),
        }
    }
}

impl Drop for WorkerOutcome {
    fn drop(&mut self) {
        if let Some(shared) = self.shared.take() {
            // The only aliases use this Drop. No Weak reference can retain the
            // control allocation past destruction of its original debit.
            drop(Arc::into_inner(shared));
        }
    }
}

impl WorkerOutcome {
    pub(super) fn new(lease: crucible_host_resources::host_services::HostServiceLease) -> Self {
        Self {
            shared: Some(Arc::new(OutcomeAllocation {
                body: Mutex::new(OutcomeBody {
                    state: BodyState::Running,
                    failure: None,
                    panic: None,
                    uncertain: false,
                    _lease: lease,
                }),
                abandoned: OnceLock::new(),
                live_receiver: OnceLock::new(),
            })),
        }
    }

    pub(super) fn allocation_bytes() -> Result<u64, QemuRamSourceError> {
        let (layout, _) = std::alloc::Layout::new::<[std::sync::atomic::AtomicUsize; 2]>()
            .extend(std::alloc::Layout::new::<OutcomeAllocation>())
            .map_err(|_| QemuRamSourceError::Ownership)?;
        u64::try_from(layout.pad_to_align().size()).map_err(|_| QemuRamSourceError::Ownership)
    }

    /// Covers the real allocation and overlapping construction/retention frames.
    ///
    /// # Errors
    /// Refuses an unrepresentable complete control peak.
    pub(super) fn allocation_peak_bytes() -> Result<u64, QemuRamSourceError> {
        Self::allocation_bytes()?
            .checked_add(std::mem::size_of::<OutcomeAllocation>() as u64)
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<QemuRamSourceService>() as u64))
            .and_then(|bytes| bytes.checked_add(std::mem::size_of::<Self>() as u64))
            .ok_or(QemuRamSourceError::Ownership)
    }

    /// Keeps the complete active service for a receiver whose reap is unknown.
    ///
    /// # Panics
    /// Panics if the private preparation invariant is violated and the live
    /// service has no original outcome allocation.
    pub(super) fn retain_live_receiver(self, source: QemuRamSourceService) {
        // Preparation installs this same allocation before publishing the
        // uncloneable service. Only this consuming path initializes this cell;
        // delivery and ordinary abandonment use separate recipients.
        let Some(shared) = self.shared.as_ref() else {
            unreachable!("a live Source owns its original outcome allocation");
        };
        shared.live_receiver.get_or_init(|| source);
        // Retain the actual recipient without canceling the service, dropping
        // its wake socket, or discarding the unique native join owner.
        std::mem::forget(self);
    }

    /// Borrows the actual retained facade without querying its native owner.
    #[cfg(test)]
    pub(super) fn retained_live_receiver(&self) -> Option<&QemuRamSourceService> {
        self.shared.as_ref()?.live_receiver.get()
    }

    /// Retains the same native owner and containing join debt until Main exits.
    pub(super) fn retain_abandoned(
        self,
        native: NativeJoinOwner,
        launch_join: Option<crate::launch_cleanup::LaunchSourceJoin>,
        stop: stop::StopState,
        birth: (Option<HostSupervisionError>, Option<HostSupervisionError>),
    ) {
        // Every live facade has its allocation; only Drop takes shared away.
        // The service consumes its sole worker once. No delivery/snapshot path
        // writes abandoned, so this initialization cannot contend or overwrite.
        if let Some(shared) = self.shared.as_ref() {
            shared.abandoned.get_or_init(|| AbandonedWorker {
                _native: native,
                _launch_join: launch_join,
                _stop: stop,
                _birth: birth,
            });
        }
        // This existing strong reference keeps the actual record, result and
        // prepaid worker loan together. A returned Rust body or TLS destructor
        // cannot substitute for the unique native join that did not occur.
        std::mem::forget(self);
    }

    pub(super) fn no_birth(&self, failure: Option<QemuRamWorkerFailure>) {
        let Some(shared) = self.shared.as_ref() else {
            return;
        };
        let (mut body, poisoned) = match shared.body.lock() {
            Ok(body) => (body, false),
            Err(poisoned) => (poisoned.into_inner(), true),
        };
        body.uncertain |= poisoned;
        body.failure = failure;
        body.state = BodyState::NeverStarted;
    }

    pub(super) fn deliver(&self, outcome: std::thread::Result<Result<(), QemuRamWorkerFailure>>) {
        let Some(shared) = self.shared.as_ref() else {
            return;
        };
        let (mut body, poisoned) = match shared.body.lock() {
            Ok(body) => (body, false),
            Err(poison) => (poison.into_inner(), true),
        };
        body.uncertain |= poisoned;
        // This source closure invokes delivery exactly once, including unwind.
        match outcome {
            Ok(result) => {
                body.failure = result.err();
                body.state = BodyState::Returned;
            }
            Err(payload) => {
                body.panic = Some(payload);
                body.state = BodyState::Panicked;
            }
        }
    }

    pub(super) fn snapshot(&self) -> OutcomeSnapshot {
        let uncertain = || OutcomeSnapshot {
            delivered: false,
            failure: None,
            panic: None,
            uncertain: true,
        };
        let Some(shared) = self.shared.as_ref() else {
            return uncertain();
        };
        let (body, poisoned) = match shared.body.try_lock() {
            Ok(body) => (body, false),
            Err(std::sync::TryLockError::Poisoned(poison)) => (poison.into_inner(), true),
            Err(std::sync::TryLockError::WouldBlock) => return uncertain(),
        };
        OutcomeSnapshot {
            delivered: body.state != BodyState::Running,
            failure: body.failure.clone(),
            panic: (body.state == BodyState::Panicked).then(|| QemuRamWorkerPanic {
                outcome: self.clone(),
            }),
            uncertain: body.uncertain || poisoned,
        }
    }

    #[cfg(test)]
    pub(super) fn allocation_header_offset() -> usize {
        std::alloc::Layout::new::<[std::sync::atomic::AtomicUsize; 2]>()
            .extend(std::alloc::Layout::new::<OutcomeAllocation>())
            .unwrap()
            .1
    }

    #[cfg(test)]
    pub(super) fn allocation_address(&self) -> Option<usize> {
        self.shared
            .as_ref()
            .map(|shared| Arc::as_ptr(shared) as usize)
    }
}
