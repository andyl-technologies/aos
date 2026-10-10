//! Bounds direct component mutex ingress with the caller's retained original.
//!
//! The optional original belongs only to the direct component alias. Worker,
//! listener and ordinary shutdown behavior retain their existing paths. A
//! refused original never reopens admission or manufactures a new operation.

use super::*;
use crucible_linux_resource::host_supervision::HostOperationGuard;

impl<L, V> LocalExecutorPoolService<L, V>
where
    L: AssignmentLedger,
    V: AttemptAdmissionValidator + Send + Sync,
{
    /// Binds this existing alias to its genuine caller-owned original.
    ///
    /// # Errors
    /// Refuses expired supervision or an already bound component alias.
    pub(crate) fn bind_original(
        mut self,
        original: Arc<HostOperationGuard>,
    ) -> Result<Self, LocalExecutorPoolServiceError<L::Error>> {
        original.wait_slice()?;
        if self.original.is_some() {
            return Err(LocalExecutorPoolServiceError::ShuttingDown);
        }
        self.original = Some(original);
        Ok(self)
    }

    /// Checks the saved original before the actual pool state.
    ///
    /// # Errors
    /// Refuses canceled/expired original or terminal pool state.
    pub(super) fn require_running_for_call(
        &self,
    ) -> Result<(), LocalExecutorPoolServiceError<L::Error>> {
        if let Some(original) = &self.original {
            original.wait_slice()?;
        }
        self.shared.require_running()
    }

    /// Acquires the actual actor only within the saved original interval.
    ///
    /// # Errors
    /// Refuses original supervision or poisoned actor ownership.
    pub(super) fn lock_executor_for_call(
        &self,
        changes_ownership: bool,
    ) -> Result<
        MutexGuard<'_, LocalExecutorCapabilityService<L, V>>,
        LocalExecutorPoolServiceError<L::Error>,
    > {
        let Some(original) = &self.original else {
            return if changes_ownership {
                self.shared.lock_executor()
            } else {
                self.shared.lock_executor_read_only()
            };
        };
        loop {
            let slice = original.wait_slice()?;
            match self.shared.executor.try_lock() {
                Ok(executor) => {
                    original.wait_slice()?;
                    if changes_ownership {
                        self.shared.bump_ownership_revision();
                    }
                    return Ok(executor);
                }
                Err(std::sync::TryLockError::WouldBlock) => thread::park_timeout(slice),
                Err(std::sync::TryLockError::Poisoned(poisoned)) => {
                    drop(poisoned.into_inner());
                    self.poison_for_call();
                    return Err(LocalExecutorPoolServiceError::SupervisorPoisoned);
                }
            }
        }
    }

    /// Pins terminal custody without entering ordinary shutdown locks.
    pub(super) fn poison_for_call(&self) {
        if self.original.is_some() {
            // Preserve actual terminal worker custody without entering ordinary
            // shutdown's mutexes after an original ingress refusal or panic.
            self.shared.state.store(POOL_POISONED, Ordering::Release);
            increment(&self.shared.counters.worker_panics);
            self.shared.ready.notify_all();
        } else {
            self.shared.poison();
        }
    }
}
