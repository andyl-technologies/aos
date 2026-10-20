//! Retains Network workers' one native PID1 escrow descriptor at appentry.
//!
//! The table supplies descriptor DATA only. The role owner separately verifies
//! the exact activation name, authenticated PID1 record, live Netd Source,
//! child identity, native controls and original prepaid financial subdivision.

use super::{Error, FixedInitialActivationTable, OwnedFd};

/// Keeps the original child-escrow table and every acquired native prefix.
///
/// This owner is not a Source constructor. An entered failed table must remain
/// resident until deliberate process termination; abandoning it aborts before
/// its acquired descriptors are released.
#[must_use]
pub struct NetworkWorkerChildInitialTableV2 {
    original: FixedInitialActivationTable<1>,
}

impl NetworkWorkerChildInitialTableV2 {
    /// Creates empty fixed destinations without inspecting the descriptor table.
    #[must_use]
    pub const fn new() -> Self {
        Self { original: FixedInitialActivationTable::new() }
    }

    /// Captures the exact original descriptor at entry three once.
    ///
    /// # Errors
    /// Retains the first duplication, flag or complete-table refusal. Reentry
    /// cannot resample or replace any previously acquired native prefix.
    pub fn observe_once(&mut self) -> Result<(), &Error> {
        self.original.observe_once(
            1,
            "Network child origin table",
            "count exceeds one slot",
            "observation is closed",
        )
    }

    /// Moves the same complete one-entry prefix without another observation.
    #[must_use]
    pub fn take_completed_entries(&mut self) -> Option<[Option<OwnedFd>; 1]> {
        self.original.take_completed_entries()
    }

    /// Borrows the original native refusal without performing another operation.
    #[must_use]
    pub fn failure(&self) -> Option<&Error> {
        self.original.failure()
    }
}

impl Default for NetworkWorkerChildInitialTableV2 {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for NetworkWorkerChildInitialTableV2 {
    fn drop(&mut self) {
        self.original.abort_if_armed();
    }
}
