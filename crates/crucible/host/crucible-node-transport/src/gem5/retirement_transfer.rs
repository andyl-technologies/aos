//! Moves the same reclaimed native capsule to its original preallocated supervisor.
//!
//! The transfer consumes neither modeled journals nor owner credit. It requires
//! the genuine original Shutdown reply and actual group-empty reaping proof.
//! Durable full-world history authentication remains the installed supervisor's
//! separate release obligation; this mechanical move supplies no such authority.

use super::*;

impl Gem5NativeProcess {
    /// Transfers complete reclaimed original handles without dropping native history.
    ///
    /// The original prebirth slot receives the same Child, session, source and
    /// prefix/private-ACK/Shutdown/reap obligations. The driver remains present
    /// with no Child, so its later Drop cannot transfer the capsule twice.
    ///
    /// # Errors
    /// Refuses missing original custody, unresolved operations, non-graceful
    /// containment, an uncertain Shutdown or absent actual reaping/group proof.
    pub fn transfer_gracefully_reclaimed_to_supervisor(&mut self) -> Result<(), ProviderError> {
        if self.graceful_retirement_transferred {
            return Ok(());
        }
        if self.child.is_none()
            || self.supervisor.is_none()
            || !self.graceful_retirement_requested
            || self.pending.is_some()
            || self.unresolved.is_some()
            || self.unresolved_capture.is_some()
        {
            return Err(ProviderError::Conflict(
                "original graceful capsule is not transferable",
            ));
        }
        let state = self.quarantine.as_ref().ok_or(ProviderError::Correlation(
            "original graceful reclamation holder is absent",
        ))?;
        if state
            .shutdown
            .as_ref()
            .is_none_or(|exchange| !exchange.acknowledged())
            || state.census_diagnostic().is_some()
        {
            return Err(ProviderError::Conflict(
                "original graceful Shutdown remains uncertain",
            ));
        }
        if self.poll_reclamation()?.is_none() {
            return Err(ProviderError::Conflict(
                "original native group is not actually reclaimed",
            ));
        }
        // Every fallible check precedes the transfer. This uses precisely the
        // same infallible whole-capsule handoff as Drop, without freeing a slot.
        self.transfer_original_custody();
        self.graceful_retirement_transferred = true;
        Ok(())
    }
}
