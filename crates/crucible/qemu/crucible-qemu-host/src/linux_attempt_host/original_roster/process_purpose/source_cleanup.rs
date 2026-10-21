//! Lends the actual Source cleanup through its first-bound incarnation.
//!
//! This weak identity never owns a construction/return loan or a new operation.
//! The Source controller may itself hold a failed Node, so the proof must never
//! strongly retain that controller and create an owner cycle.

use super::*;

#[derive(Clone)]
pub(crate) struct SourceCleanupLender {
    roster: RosterWeak,
    index: usize,
    generation: u64,
    process_generation: Option<u64>,
}

/// Retains only a borrowed step identity for an already-issued Source Cleanup.
pub(crate) struct SourceCleanupOriginal {
    lender: SourceCleanupLender,
    original: Arc<HostOperationGuard>,
}

impl std::fmt::Debug for SourceCleanupOriginal {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SourceCleanupOriginal")
            .field("generation", &self.lender.generation)
            .field("process_generation", &self.lender.process_generation)
            .finish_non_exhaustive()
    }
}

impl InstalledIncarnationRetirement {
    pub(crate) fn source_cleanup_lender(
        &self,
    ) -> Result<SourceCleanupLender, OriginalActorAccountError> {
        if self.subdivision_index != 0 {
            return Err(OriginalActorAccountError::Unavailable);
        }
        Ok(SourceCleanupLender {
            roster: RosterWeak::clone(&self.roster),
            index: self.index,
            generation: self.generation,
            process_generation: Some(self.process_generation),
        })
    }
}

impl SourceCleanupLender {
    /// Binds a late helper to the actual still-installed Source incarnation.
    ///
    /// A construction receiver has no process generation. It cannot be retained
    /// unchanged by a later helper: the genuine installed allocation supplies
    /// that generation after the same controller is independently authenticated.
    pub(crate) fn current_incarnation(&self) -> Result<Self, OriginalActorAccountError> {
        let controller = self.controller()?;
        let attempt = NativeAccountAttempt {
            roster: RosterWeak::clone(&self.roster),
            index: self.index,
            generation: self.generation,
        };
        attempt.bound_source_cleanup_lender(controller.as_ref())
    }

    pub(crate) fn controller(
        &self,
    ) -> Result<
        crate::linux_attempt_host::original_node::RetainedNativeFreshLaunchError,
        OriginalActorAccountError,
    > {
        let roster = self
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let state = roster
            .try_lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let slot = state
            .slots
            .get(self.index)
            .filter(|slot| slot.active == Some(self.generation))
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let purpose = slot
            .installed_process
            .as_ref()
            .filter(|purpose| purpose.ready && purpose.sound)
            .ok_or(OriginalActorAccountError::Unavailable)?;
        if let Some(expected) = self.process_generation {
            let allocation = purpose.journal.incarnations[0]
                .as_ref()
                .ok_or(OriginalActorAccountError::Unavailable)?;
            if allocation.process_generation != expected || allocation.physical_retired {
                return Err(OriginalActorAccountError::Unavailable);
            }
        }
        slot.source_controller
            .as_ref()
            .cloned()
            .ok_or(OriginalActorAccountError::Unavailable)
    }

    pub(crate) fn retained_original(
        self,
    ) -> Result<SourceCleanupOriginal, OriginalActorAccountError> {
        // First validate the bound incarnation, then release its metadata lock
        // before the once-cached entry can touch the Original operation table.
        let controller = self.controller()?;
        let attempt = NativeAccountAttempt {
            roster: RosterWeak::clone(&self.roster),
            index: self.index,
            generation: self.generation,
        };
        let original = attempt.cleanup_entry()?;
        let current = self.controller()?;
        if !controller.same_owner(&current) || !controller.cleanup_matches(&original) {
            return Err(OriginalActorAccountError::Unavailable);
        }
        Ok(SourceCleanupOriginal {
            lender: self,
            original,
        })
    }
}

impl SourceCleanupOriginal {
    pub(crate) fn original(&self) -> &HostOperationGuard {
        &self.original
    }

    pub(crate) fn checked_original(
        &self,
    ) -> Result<&HostOperationGuard, crucible_host_resources::host_supervision::HostSupervisionError>
    {
        let unavailable =
            || crucible_host_resources::host_supervision::HostSupervisionError::Unavailable;
        let current = self.lender.controller().map_err(|_| unavailable())?;
        if current.cleanup_matches(&self.original) {
            Ok(&self.original)
        } else {
            Err(unavailable())
        }
    }
}

impl NativeAccountAttempt {
    /// Borrows the actual Source incarnation without entering a new operation.
    ///
    /// A late launch refusal retains this identity in its same returned owner;
    /// the controller itself must not keep a permanent weak roster alias.
    ///
    /// # Errors
    /// Refuses unavailable or mismatched controller, generation or Source custody.
    pub(in crate::linux_attempt_host) fn bound_source_cleanup_lender(
        &self,
        expected: &crate::linux_attempt_host::original_node::OriginalNativeFreshLaunchError,
    ) -> Result<SourceCleanupLender, OriginalActorAccountError> {
        let roster = self
            .roster
            .upgrade()
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let state = roster
            .try_lock()
            .map_err(|_| OriginalActorAccountError::Unavailable)?;
        let slot = state
            .slots
            .get(self.index)
            .filter(|slot| slot.active == Some(self.generation))
            .ok_or(OriginalActorAccountError::Unavailable)?;
        if !slot
            .source_controller
            .as_ref()
            .is_some_and(|controller| std::ptr::eq(controller.as_ref(), expected))
        {
            return Err(OriginalActorAccountError::Unavailable);
        }
        let purpose = slot
            .installed_process
            .as_ref()
            .filter(|purpose| purpose.ready && purpose.sound)
            .ok_or(OriginalActorAccountError::Unavailable)?;
        let allocation = purpose.journal.incarnations[0]
            .as_ref()
            .filter(|allocation| !allocation.physical_retired)
            .ok_or(OriginalActorAccountError::Unavailable)?;
        Ok(SourceCleanupLender {
            roster: RosterWeak::clone(&self.roster),
            index: self.index,
            generation: self.generation,
            process_generation: Some(allocation.process_generation),
        })
    }

    pub(in crate::linux_attempt_host) fn helper_cleanup_lender(&self) -> SourceCleanupLender {
        SourceCleanupLender {
            roster: RosterWeak::clone(&self.roster),
            index: self.index,
            generation: self.generation,
            process_generation: None,
        }
    }
}

impl std::fmt::Debug for SourceCleanupLender {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SourceCleanupLender")
            .field("generation", &self.generation)
            .field("process_generation", &self.process_generation)
            .finish_non_exhaustive()
    }
}

impl SourceCleanupLender {
    pub(crate) fn same_identity(&self, other: &Self) -> bool {
        RosterWeak::ptr_eq(&self.roster, &other.roster)
            && self.index == other.index
            && self.generation == other.generation
            && self.process_generation == other.process_generation
    }
}

#[cfg(test)]
mod tests;
