//! Returns exact World accounting after member and containing-body closure.

// SPDX-License-Identifier: Apache-2.0

use super::*;

impl AuthenticatedNativeWorldClaim {
    /// Returns this World only after its actual members and body have closed.
    ///
    /// Unlike the pending-aware sweep, this strict operation refuses a retained
    /// containing body. Never-born abort uses it only after destroying Pending
    /// and closing its exact body lease.
    ///
    /// # Errors
    /// Retains the same World on live members/body, changed Main or uncertainty.
    pub fn finish_after_members_returned(&mut self) -> Result<(), ServiceBirthError> {
        match self.try_finish_after_members_returned()? {
            NativeWorldReturn::Returned => Ok(()),
            NativeWorldReturn::PendingBody => Err(ServiceBirthError::policy(
                "native World still retains containing-body custody",
            )),
        }
    }

    /// Returns exact accounting or observes its still-retained containing body.
    ///
    /// The same ledger lock validates all members, epochs and return arithmetic
    /// before reporting pending body custody. A pending result changes no debt,
    /// descriptor window or claim. A returned result follows the actual physical
    /// descriptor return before committing ledger reuse.
    ///
    /// # Errors
    /// Refuses live/inconsistent members, stale Main, lost descriptor custody,
    /// accounting corruption or uncertain synchronization/physical return.
    pub fn try_finish_after_members_returned(
        &mut self,
    ) -> Result<NativeWorldReturn, ServiceBirthError> {
        let Some(held) = self.held.as_ref() else {
            return Ok(NativeWorldReturn::Returned);
        };
        held.root.check()?;
        let mut ledger = held
            .ledger
            .lock()
            .map_err(|_| ServiceBirthError::policy("native World retirement is uncertain"))?;
        let (index, used, peak, tables) = match ledger.prepare_world_return(self.epoch)? {
            ledger::WorldReturnPreparation::PendingBody => {
                return Ok(NativeWorldReturn::PendingBody);
            }
            ledger::WorldReturnPreparation::Ready {
                index,
                used,
                peak,
                tables,
            } => (index, used, peak, tables),
        };
        held.root
            .owner
            .host_descriptors
            .lock()
            .map_err(|_| ServiceBirthError::policy("Main descriptor owner is uncertain"))?
            .as_mut()
            .ok_or_else(|| ServiceBirthError::policy("Main descriptor owner is absent"))?
            .close_pool_assignment(peak, tables)?;
        ledger.commit_world_return(index, self.epoch, used);
        drop(ledger);
        drop(self.held.take());
        Ok(NativeWorldReturn::Returned)
    }
}
