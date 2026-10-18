//! Lends genuine containing Main payer and original custody to Target jobs.

use super::*;
use crucible_host_resources::host_services::process_birth::AuthenticatedTargetDispatcherPurpose;

/// Transfers the exact Target operation and fixed family epoch into its job.
///
/// Only the retained original slot constructs this move-only witness. The
/// actual cgroup controls must corroborate its same pinned workload before
/// publication; neither a path, guard class nor copied epoch issues a job.
pub(crate) struct TargetWatcherOriginal {
    roster: Weak<Mutex<NativeRoster>>,
    index: usize,
    source_generation: u64,
    target_epoch: u64,
    original: Arc<HostOperationGuard>,
    cleanup: Arc<fork_target::TargetCleanup>,
}

impl TargetWatcherOriginal {
    /// Checks the same operation while a shared roster borrow is pending.
    /// Once acquired, the actual Cleanup guard pins its slot through return.
    pub(crate) fn wait_slice(
        &mut self,
        draining: bool,
    ) -> Result<(std::time::Duration, bool), OriginalActorAccountError> {
        if draining {
            return Ok((self.cleanup.guard()?.wait_slice()?, true));
        }
        Ok((self.original.wait_slice()?, true))
    }

    pub(crate) fn operation(&self) -> &Arc<HostOperationGuard> {
        &self.original
    }

    /// Corroborates actual directories against the retained nominal Target.
    ///
    /// # Errors
    /// Refuses foreign or expired operations, generations, parents or children.
    pub(crate) fn verify_control(
        &self,
        parent: &std::os::fd::OwnedFd,
        child: &std::os::fd::OwnedFd,
    ) -> Result<(), OriginalActorAccountError> {
        let roster = self
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let state = roster
            .lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let slot = state
            .slots
            .get(self.index)
            .filter(|slot| slot.active == Some(self.source_generation))
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let (epoch, operation) = slot
            .fork_target
            .watcher_preparation()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        if epoch != self.target_epoch || !Arc::ptr_eq(operation, &self.original) {
            return Err(OriginalActorAccountError::Unavailable);
        }
        let normal = slot
            .credit
            .as_ref()
            .and_then(|credit| credit.original.as_ref())
            .and_then(|original| original.normal.as_ref())
            .ok_or(OriginalActorAccountError::Unavailable)?;
        normal.verify_native_preparation(&self.original)?;
        normal.family().verify_workload_directory(parent)?;
        let child = rustix::fs::fstat(child).map_err(|_| OriginalActorAccountError::Unavailable)?;
        if slot
            .installed_process
            .as_ref()
            .is_none_or(|source| source.matches_source_directory(child.st_dev, child.st_ino))
        {
            return Err(OriginalActorAccountError::Unavailable);
        }
        normal.verify_native_preparation(&self.original)?;
        Ok(())
    }
}

impl NativeAccountAttempt {
    /// Observes the actual prepaid node capacity for this same Main dispatcher.
    pub(crate) fn target_dispatcher_capacity(&self) -> Result<usize, OriginalActorAccountError> {
        self.require_original()?;
        let held = self
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let state = held
            .lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let normal = state
            .slots
            .get(self.index)
            .filter(|slot| slot.active == Some(self.generation))
            .and_then(|slot| slot.credit.as_ref())
            .and_then(|credit| credit.original.as_ref())
            .and_then(|original| original.normal.as_ref())
            .ok_or(OriginalActorAccountError::Unavailable)?;
        normal.pool_node_capacity().map_err(Into::into)
    }

    /// Borrows the actual normal Main payer before permanent worker birth.
    ///
    /// # Errors
    /// Refuses absent normal authority, stale original custody or Main capacity.
    pub(crate) fn reserve_target_dispatcher_purpose(
        &self,
        control_peak: u64,
    ) -> Result<AuthenticatedTargetDispatcherPurpose, OriginalActorAccountError> {
        self.require_original()?;
        let held = self
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let state = held
            .lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let normal = state
            .slots
            .get(self.index)
            .filter(|slot| slot.active == Some(self.generation))
            .and_then(|slot| slot.credit.as_ref())
            .and_then(|credit| credit.original.as_ref())
            .and_then(|original| original.normal.as_ref())
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let original = state
            .slots
            .get(self.index)
            .and_then(|slot| slot.fork_target.watcher_preparation())
            .map(|(_, original)| original)
            .ok_or(OriginalActorAccountError::Unavailable)?;
        normal
            .reserve_target_dispatcher_purpose(control_peak, original)
            .map_err(Into::into)
    }

    /// Checks this dispatcher's genuine containing Main before Target birth.
    ///
    /// # Errors
    /// Refuses foreign issuer pointers, expired originals or uncertain windows.
    pub(crate) fn verify_target_dispatcher_purpose(
        &self,
        purpose: &AuthenticatedTargetDispatcherPurpose,
    ) -> Result<(), OriginalActorAccountError> {
        self.require_original()?;
        let held = self
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let state = held
            .lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let normal = state
            .slots
            .get(self.index)
            .filter(|slot| slot.active == Some(self.generation))
            .and_then(|slot| slot.credit.as_ref())
            .and_then(|credit| credit.original.as_ref())
            .and_then(|original| original.normal.as_ref())
            .ok_or(OriginalActorAccountError::Unavailable)?;
        if !purpose.belongs_to(normal) {
            return Err(OriginalActorAccountError::Unavailable);
        }
        purpose.check().map_err(Into::into)
    }

    /// Transfers the occupied Target epoch and its saved live operation.
    ///
    /// # Errors
    /// Refuses absent, retired, expired or quarantined Target custody.
    pub(crate) fn target_watcher_original(
        &self,
    ) -> Result<TargetWatcherOriginal, OriginalActorAccountError> {
        self.require_original()?;
        let held = self
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let state = held
            .lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let (epoch, original) = state
            .slots
            .get(self.index)
            .filter(|slot| slot.active == Some(self.generation))
            .and_then(|slot| slot.fork_target.watcher_preparation())
            .ok_or(OriginalActorAccountError::Unavailable)?;
        original.wait_slice()?;
        Ok(TargetWatcherOriginal {
            roster: Weak::clone(&self.roster),
            index: self.index,
            source_generation: self.generation,
            target_epoch: epoch,
            original: Arc::clone(original),
            cleanup: Arc::clone(
                state
                    .slots
                    .get(self.index)
                    .ok_or(OriginalActorAccountError::Unavailable)?
                    .fork_target
                    .watcher_cleanup()?,
            ),
        })
    }
}
