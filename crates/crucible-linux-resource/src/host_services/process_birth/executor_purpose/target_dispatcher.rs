//! Prepays one persistent Target dispatcher from its actual containing Main.
//!
//! The descriptor window borrows the existing paid host-table remainder. One
//! task and fixed stack/control overlap debit the same original Main counters;
//! nothing here creates another process allowance or native family bank.

use super::*;

const STACK_REQUEST_BYTES: u64 = 2 * 1024 * 1024;
// One actual shared epoll, wake eventfd and pinned namespace descriptor.
const DESCRIPTOR_WINDOW: u64 = 3;

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
            let extent = STACK_REQUEST_BYTES
                .checked_add(control_peak)
                .and_then(|bytes| bytes.checked_add(3 * HostServiceLease::metadata_bytes()))
                .filter(|bytes| control_peak != 0 && *bytes > STACK_REQUEST_BYTES)
                .ok_or_else(|| ServiceBirthError::policy("Target dispatcher extent is invalid"))?;
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
            };
            // Construct the nominal owner before the unconditional postcut.
            Ok(purpose)
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

    /// Starts once-entered cleanup in this same Main's retained supervisor.
    ///
    /// # Errors
    /// Refuses unavailable or expired original Main cleanup policy.
    pub fn begin_cleanup(&self) -> Result<HostOperationGuard, ServiceBirthError> {
        self.issuer
            .original
            .begin_original_cleanup_control()
            .map_err(ServiceBirthError::from)
    }

    /// Reports factual closure of this worker's task and descriptor window.
    #[must_use]
    pub fn is_physically_retired(&self) -> bool {
        self.worker.is_none() && self.task.is_none() && self.descriptors.is_none()
    }

    /// Starts this purpose's one real worker with its explicit stack request.
    ///
    /// # Errors
    /// Refuses repeated birth, stale payer authority, or a kernel thread error.
    pub fn spawn_worker<T, F>(
        &mut self,
        name: &str,
        body: F,
    ) -> Result<std::thread::JoinHandle<T>, ServiceBirthError>
    where
        T: Send + 'static,
        F: FnOnce() -> T + Send + 'static,
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
        Ok(worker)
    }

    /// Joins the same finished worker while retaining its task and window.
    ///
    /// The process factory first closes its actual returned controls and queue
    /// aliases. This method checks the genuine handle and performs real join;
    /// a caller cannot substitute a numeric thread ID or completion flag.
    ///
    /// # Errors
    /// Refuses another or unfinished worker or stale authority. A refusal
    /// returns the same wait authority before any join.
    pub fn try_join_worker<T>(
        &mut self,
        worker: std::thread::JoinHandle<T>,
    ) -> Result<std::thread::Result<T>, (std::thread::JoinHandle<T>, ServiceBirthError)> {
        if self.worker != Some(worker.thread().id()) || !worker.is_finished() {
            return Err((
                worker,
                ServiceBirthError::policy("Target dispatcher worker is foreign or still running"),
            ));
        }
        if let Err(source) = self.check() {
            return Err((worker, source));
        }
        let joined = worker.join();
        self.worker = None;
        // Actual join is irreversible. The caller retains this owner and can
        // retry only the remaining window close, never another worker birth.
        Ok(joined)
    }

    /// Closes the remaining window after the worker and actual queue retire.
    ///
    /// The factory calls this only after closing its queue/control aliases and
    /// performing real join (or proving the worker was never successfully born).
    /// A refused post-join close retains the same debit for a later attempt.
    ///
    /// # Errors
    /// Refuses a surviving real worker, stale Main, or uncertain window close.
    pub fn retire_worker_debits(&mut self) -> Result<(), ServiceBirthError> {
        if self.worker.is_some() {
            return Err(ServiceBirthError::policy(
                "Target worker has not physically joined",
            ));
        }
        if self.is_physically_retired() {
            return Ok(());
        }
        self.check()?;
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
