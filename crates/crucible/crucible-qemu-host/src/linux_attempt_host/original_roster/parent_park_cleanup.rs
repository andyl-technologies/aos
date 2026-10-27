//! Lends the original slot's saved Cleanup without permitting another clock.

use super::*;
use crucible_host_resources::host_supervision::HostSupervisionError;

/// Retains one genuine original account's finite physical-disposition phase.
///
/// Construction is private to the actual attempt. The existing guard Arc is
/// charged once in its slot; this inline witness clones only the already-paid
/// roster control. It neither issues a Source nor completes either lender.
pub struct OriginalParentParkCleanup {
    guard: Arc<HostOperationGuard>,
    roster: RosterWeak,
    index: usize,
    generation: u64,
}

impl NativeAccountAttempt {
    pub(in crate::linux_attempt_host) fn retain_parent_park_cleanup(
        &self,
    ) -> Result<OriginalParentParkCleanup, OriginalActorAccountError> {
        Ok(OriginalParentParkCleanup {
            guard: self.cleanup()?,
            roster: RosterWeak::clone(&self.roster),
            index: self.index,
            generation: self.generation,
        })
    }
}

impl OriginalParentParkCleanup {
    pub(crate) fn verify_node(
        &self,
        binding: &OriginalNativeNodeBinding,
    ) -> Result<(), OriginalActorAccountError> {
        if !RosterWeak::ptr_eq(&self.roster, &binding.roster)
            || self.index != binding.index
            || self.generation != binding.generation
        {
            return Err(OriginalActorAccountError::Unavailable);
        }
        Ok(())
    }

    pub(crate) fn guard(&self) -> &HostOperationGuard {
        &self.guard
    }

    /// Waits on this same phase without restarting its original Cleanup clock.
    ///
    /// # Errors
    /// Returns the retained phase's real expiration or unavailable ownership.
    pub fn wait_for_change(&self) -> Result<(), HostSupervisionError> {
        self.guard.wait_for_change()
    }
}
