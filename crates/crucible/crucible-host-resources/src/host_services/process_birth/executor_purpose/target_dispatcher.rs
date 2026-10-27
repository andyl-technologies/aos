//! Prepays one persistent Target dispatcher from its actual containing Main.
//!
//! The descriptor window borrows the existing paid host-table remainder. One
//! task and fixed stack/control overlap debit the same original Main counters;
//! nothing here creates another process allowance or native family bank.

use super::*;
use crate::host_services::native_join::{NativeJoinObservation, NativeJoinOwner};

const STACK_REQUEST_BYTES: u64 = 2 * 1024 * 1024;
// One actual shared epoll, wake eventfd and pinned namespace descriptor.
const DESCRIPTOR_WINDOW: u64 = 3;

type CleanupEntry = Result<Arc<HostOperationGuard>, crate::host_supervision::HostSupervisionError>;

#[derive(Debug, Default)]
struct RetainedDispatcherCleanup {
    entered: std::sync::OnceLock<CleanupEntry>,
    completed: bool,
}

impl RetainedDispatcherCleanup {
    fn enter(
        &self,
        origin: &HostOperationGuard,
    ) -> Result<Arc<HostOperationGuard>, ServiceBirthError> {
        if self.completed {
            return Err(ServiceBirthError::policy(
                "Target dispatcher Cleanup already completed",
            ));
        }
        let entered = self
            .entered
            .get_or_init(|| origin.begin_original_cleanup_control().map(Arc::new));
        let cleanup = entered
            .as_ref()
            .map_err(|source| ServiceBirthError::from(*source))?;
        cleanup.verify_operation_class(HostOperationClass::Cleanup)?;
        Ok(Arc::clone(cleanup))
    }

    fn verify_identity(&self, supplied: &Arc<HostOperationGuard>) -> Result<(), ServiceBirthError> {
        let entered = self.entered.get().ok_or_else(|| {
            ServiceBirthError::policy("Target dispatcher Cleanup has not been entered")
        })?;
        let saved = entered
            .as_ref()
            .map_err(|source| ServiceBirthError::from(*source))?;
        if !Arc::ptr_eq(saved, supplied) {
            return Err(ServiceBirthError::policy(
                "Target dispatcher Cleanup operation is foreign",
            ));
        }
        Ok(())
    }

    fn verify(&self, supplied: &Arc<HostOperationGuard>) -> Result<(), ServiceBirthError> {
        self.verify_identity(supplied)?;
        supplied.verify_operation_class(HostOperationClass::Cleanup)?;
        Ok(())
    }

    fn complete(&mut self, cleanup: &Arc<HostOperationGuard>) -> Result<(), ServiceBirthError> {
        self.verify(cleanup)?;
        cleanup.complete()?;
        self.completed = true;
        // Free this completed control record once the caller drops its alias.
        // The monotonic latch prevents a second admission after removing it.
        drop(self.entered.take());
        Ok(())
    }

    fn control_bytes() -> Option<u64> {
        let (layout, _) = std::alloc::Layout::new::<(
            std::sync::atomic::AtomicUsize,
            std::sync::atomic::AtomicUsize,
        )>()
        .extend(std::alloc::Layout::new::<HostOperationGuard>())
        .ok()?;
        layout.pad_to_align().size().try_into().ok()
    }
}

/// Retains the actual Main payer of one permanent Target dispatcher.
///
/// The process factory keeps this outside the dispatcher allocation through
/// physical worker join and closure of every job/control/descriptor borrower.
/// Numerical getters describe this debit and cannot construct another purpose.
#[must_use = "retain until the actual dispatcher and its aliases have retired"]
pub struct AuthenticatedTargetDispatcherPurpose {
    issuer: Arc<AuthenticatedNativeSlotPurpose>,
    epoch: u64,
    descriptors: Option<HostServiceLease>,
    task: Option<HostServiceLease>,
    metadata: Option<HostServiceLeasePair>,
    worker: Option<std::thread::ThreadId>,
    birth_attempted: bool,
    startup_original: Option<Arc<HostOperationGuard>>,
    cleanup: RetainedDispatcherCleanup,
}

impl AuthenticatedNativeSubdivision {
    /// Prepays the single dispatcher inside this subdivision's containing Main.
    ///
    /// `control_peak` includes the producer's actual fixed control and runtime
    /// overlap. It is a requested limit, never a constructor for credit.
    ///
    /// # Errors
    /// Refuses changed Main/family ownership, unavailable original capacity,
    /// absent paid descriptor remainder, or an occupied or insufficient window.
    pub fn reserve_target_dispatcher_purpose(
        &self,
        control_peak: u64,
        original: &Arc<HostOperationGuard>,
    ) -> Result<AuthenticatedTargetDispatcherPurpose, super::NativePoolRefusal> {
        let result = (|| {
            self.verify_native_preparation(original)?;
            let cleanup_bytes = RetainedDispatcherCleanup::control_bytes().ok_or_else(|| {
                ServiceBirthError::policy("Target dispatcher Cleanup extent overflows")
            })?;
            let extent = STACK_REQUEST_BYTES
                .checked_add(cleanup_bytes)
                .and_then(|bytes| bytes.checked_add(control_peak))
                .and_then(|bytes| bytes.checked_add(3 * HostServiceLease::metadata_bytes()))
                .filter(|bytes| control_peak != 0 && *bytes > STACK_REQUEST_BYTES)
                .ok_or_else(|| ServiceBirthError::policy("Target dispatcher extent is invalid"))?;
            let prepared = super::native_pool::PreparedRefusal::reserve(&self.owner)?;
            // Credit exists before lease controls, the descriptor census, eventfds,
            // dispatcher state or the actual thread are constructed.
            let metadata = self
                .owner
                .owner
                .reserve_metadata(extent)
                .map_err(ServiceBirthError::from)?;
            let task = self
                .owner
                .owner
                .reserve_resident(1, 0, 0)
                .map_err(ServiceBirthError::from)?;
            let (epoch, descriptors) = self
                .owner
                .host_descriptors
                .lock()
                .map_err(|_| {
                    ServiceBirthError::policy("Target host descriptor custody is uncertain")
                })?
                .as_mut()
                .ok_or_else(|| ServiceBirthError::policy("Target host descriptor payer is absent"))?
                .reserve_target_window(DESCRIPTOR_WINDOW, original)?;
            let purpose = AuthenticatedTargetDispatcherPurpose {
                issuer: Arc::clone(&self.owner),
                epoch,
                descriptors: Some(descriptors),
                task: Some(task),
                metadata: Some(metadata),
                worker: None,
                birth_attempted: false,
                startup_original: Some(Arc::clone(original)),
                cleanup: RetainedDispatcherCleanup::default(),
            };
            // Construct the nominal owner before the unconditional postcut.
            Ok((purpose, prepared))
        })();
        let after = self.verify_native_preparation(original).err();
        super::native_pool::finish_dispatcher(result, after)
    }
}

impl std::fmt::Debug for AuthenticatedTargetDispatcherPurpose {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("AuthenticatedTargetDispatcherPurpose")
            .field("epoch", &self.epoch)
            .field("birth_attempted", &self.birth_attempted)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedTargetDispatcherPurpose {
    /// Returns the explicit requested stack for this already-paid worker.
    #[must_use]
    pub const fn stack_request_bytes(&self) -> usize {
        STACK_REQUEST_BYTES as usize
    }

    /// Checks the same Main and live descriptor window before a physical effect.
    ///
    /// # Errors
    /// Refuses retired, expired, foreign or uncertain containing authority.
    pub fn check(&self) -> Result<(), ServiceBirthError> {
        self.issuer.check()?;
        self.issuer
            .host_descriptors
            .lock()
            .map_err(|_| ServiceBirthError::policy("Target descriptor window is uncertain"))?
            .as_ref()
            .ok_or_else(|| ServiceBirthError::policy("Target descriptor window is absent"))?
            .check_target_window(self.epoch)
    }

    /// Borrows a startup wait from the exact Target Preparation that paid birth.
    ///
    /// Main's initial Preparation may already be completed at this later first
    /// Target. The retained borrow is that Target's existing operation; it is
    /// neither a new guard nor a renewed interval.
    ///
    /// # Errors
    /// Refuses changed Main custody, an absent startup borrow, or a completed,
    /// cancelled or expired Target Preparation.
    pub fn startup_wait_slice(&self) -> Result<std::time::Duration, ServiceBirthError> {
        self.check()?;
        self.startup_original
            .as_ref()
            .ok_or_else(|| {
                ServiceBirthError::policy("Target dispatcher startup observation ended")
            })?
            .wait_slice()
            .map_err(ServiceBirthError::from)
    }

    /// Releases the startup borrow after its independent post-observation.
    ///
    /// This drops only an alias of the saved Target Preparation. It neither
    /// completes that operation nor returns worker, task or descriptor credit.
    pub fn release_startup_observation(&mut self) {
        self.startup_original = None;
    }

    /// Corroborates this payer against its actual retained native subdivision.
    #[must_use]
    pub fn belongs_to(&self, subdivision: &AuthenticatedNativeSubdivision) -> bool {
        Arc::ptr_eq(&self.issuer, &subdivision.owner)
    }

    /// Checks transferred operation custody against the same Main supervisor.
    ///
    /// # Errors
    /// Refuses an operation outside this actual Main or failed operation status.
    pub fn verify_original(
        &self,
        operation: &Arc<HostOperationGuard>,
    ) -> Result<(), ServiceBirthError> {
        self.check()?;
        if !operation.shares_outer_cap(&self.issuer.supervisor) {
            return Err(ServiceBirthError::policy(
                "Target job original belongs to another Main",
            ));
        }
        operation.wait_slice().map_err(ServiceBirthError::from)?;
        Ok(())
    }

    /// Enters and retains this dispatcher's same Cleanup result once.
    ///
    /// The first admission refusal is permanent. Retry borrows the same guard,
    /// never a fresh interval or the separately retained outer Main Cleanup.
    ///
    /// # Errors
    /// Returns the saved admission failure or the same Cleanup's terminal state.
    pub fn retained_cleanup(&self) -> Result<Arc<HostOperationGuard>, ServiceBirthError> {
        self.cleanup.enter(&self.issuer.original)
    }

    /// Checks an already-entered exact Cleanup and retained physical custody.
    ///
    /// This never initializes the saved result. A different operation beneath
    /// the same outer cap is not a substitute for this dispatcher's guard.
    ///
    /// # Errors
    /// Refuses missing, foreign or terminal Cleanup, changed family pins, or
    /// uncertain retained descriptor ownership. It does not admit new work.
    pub fn verify_cleanup(
        &self,
        cleanup: &Arc<HostOperationGuard>,
    ) -> Result<(), ServiceBirthError> {
        self.cleanup.verify(cleanup)?;
        self.issuer.family.check_retained_custody()?;
        self.issuer
            .host_descriptors
            .lock()
            .map_err(|_| ServiceBirthError::policy("Target descriptor custody is uncertain"))?
            .as_ref()
            .ok_or_else(|| ServiceBirthError::policy("Target descriptor owner is absent"))?
            .check()?;
        self.cleanup.verify(cleanup)
    }

    /// Completes only the saved Cleanup after actual worker and window return.
    ///
    /// Its completed record may then close; this purpose can never re-enter
    /// Cleanup or become a new worker payer after successful completion.
    ///
    /// # Errors
    /// Refuses surviving resources, a different saved operation or the same
    /// Cleanup's independent postcheck/completion failure.
    pub fn complete_cleanup(
        &mut self,
        cleanup: &Arc<HostOperationGuard>,
    ) -> Result<(), ServiceBirthError> {
        if !self.is_physically_retired() {
            return Err(ServiceBirthError::policy(
                "Target dispatcher resources remain held",
            ));
        }
        self.verify_cleanup(cleanup)?;
        self.cleanup.complete(cleanup)
    }

    /// Borrows the first Cleanup admission refusal without retrying admission.
    #[must_use]
    pub fn cleanup_admission_failure(
        &self,
    ) -> Option<&crate::host_supervision::HostSupervisionError> {
        self.cleanup
            .entered
            .get()
            .and_then(|result| result.as_ref().err())
    }

    /// Reports factual closure of this worker's task and descriptor window.
    #[must_use]
    pub fn is_physically_retired(&self) -> bool {
        self.worker.is_none() && self.task.is_none() && self.descriptors.is_none()
    }

    /// Starts this purpose's one real worker with its explicit stack request.
    ///
    /// # Errors
    /// Refuses unsupported native join before thread birth, repeated birth,
    /// stale payer authority, or a kernel thread error.
    pub fn spawn_worker<F>(
        &mut self,
        name: &str,
        body: F,
    ) -> Result<NativeJoinOwner, ServiceBirthError>
    where
        F: FnOnce() + Send + 'static,
    {
        #[cfg(not(all(target_os = "linux", target_env = "gnu")))]
        {
            let _ = (name, body);
            Err(ServiceBirthError::policy(
                "nonblocking Target worker join is unsupported on this platform",
            ))
        }
        #[cfg(all(target_os = "linux", target_env = "gnu"))]
        {
            self.check()?;
            if self.birth_attempted {
                return Err(ServiceBirthError::policy(
                    "Target dispatcher worker was already born",
                ));
            }
            self.birth_attempted = true;
            let worker = std::thread::Builder::new()
                .name(name.to_owned())
                .stack_size(self.stack_request_bytes())
                .spawn(body)
                .map_err(|source| ServiceBirthError::Kernel {
                    operation: "start actual Target dispatcher worker",
                    source,
                })?;
            self.worker = Some(worker.thread().id());
            Ok(NativeJoinOwner::from_worker(worker))
        }
    }

    /// Observes the exact worker's native return without waiting or detaching.
    ///
    /// Only the saved guard's private identity and real ThreadId are checked
    /// here. Live policy and descriptor locks are separate observations; they
    /// cannot prevent recording an actual irreversible task/TLS return.
    ///
    /// # Errors
    /// Refuses a different saved guard/worker, a foreign process, or the first
    /// unexpected native status while retaining the same owner.
    pub fn observe_worker_return(
        &mut self,
        worker: &mut NativeJoinOwner,
        cleanup: &Arc<HostOperationGuard>,
    ) -> Result<NativeJoinObservation, ServiceBirthError> {
        self.cleanup.verify_identity(cleanup)?;
        if self.worker != Some(worker.thread_id()) {
            return Err(ServiceBirthError::policy(
                "Target dispatcher worker identity changed",
            ));
        }
        let observed = worker.poll().map_err(ServiceBirthError::NativeJoin)?;
        if observed == NativeJoinObservation::Returned {
            self.worker = None;
        }
        Ok(observed)
    }

    /// Closes the remaining window after the worker and actual queue retire.
    ///
    /// The factory calls this only after closing its queue/control aliases and
    /// performing real join (or proving the worker was never successfully born).
    /// A refused post-join close retains the same debit for a later attempt.
    ///
    /// # Errors
    /// Refuses a surviving real worker, stale Main, or uncertain window close.
    pub fn retire_worker_debits(
        &mut self,
        cleanup: &Arc<HostOperationGuard>,
    ) -> Result<(), ServiceBirthError> {
        self.verify_cleanup(cleanup)?;
        if self.worker.is_some() {
            return Err(ServiceBirthError::policy(
                "Target worker has not physically joined",
            ));
        }
        if self.is_physically_retired() {
            return Ok(());
        }
        self.issuer
            .host_descriptors
            .lock()
            .map_err(|_| ServiceBirthError::policy("Target window closure is uncertain"))?
            .as_mut()
            .ok_or_else(|| ServiceBirthError::policy("Target window owner is absent"))?
            .close_target_window(self.epoch)?;
        self.descriptors = None;
        self.task = None;
        // A joined or failed pthread allocation can remain in Main's cache.
        // Exactly one birth is permitted; this constant charge remains held.
        if let Some(metadata) = self.metadata.take() {
            std::mem::forget(metadata);
        }
        Ok(())
    }
}

impl Drop for AuthenticatedTargetDispatcherPurpose {
    fn drop(&mut self) {
        // An unfinished owner cannot assert thread, queue or descriptor closure.
        // Whole containing Main retirement remains the final physical boundary.
        std::mem::forget(self.descriptors.take());
        std::mem::forget(self.task.take());
        std::mem::forget(self.metadata.take());
    }
}

#[cfg(test)]
mod tests;
