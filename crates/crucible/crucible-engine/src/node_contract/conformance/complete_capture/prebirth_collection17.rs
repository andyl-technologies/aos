//! Lends the same retained archive before its collecting target is bound.
//!
//! This DATA-only facade retains the existing ticket issuance and target-phase
//! guards. It creates no graph, World, cold group or native import permission.

use super::*;
use crate::node_state::{CompleteOriginalNativeTicket, CompleteOriginalRestorationSource};

impl CollectingCompleteRestorationSource {
    /// Borrows the actual current17 archive before any target binding begins.
    ///
    /// The actual same-source native ticket and all four issued tickets remain
    /// mandatory. A subsequent synchronous collection loan rechecks these
    /// guards and complete production validation independently. This borrowed
    /// archive does not grant allocation credit or a bound restoration context.
    ///
    /// # Errors
    /// Refuses another ticket/archive/actor, a non-current17 family, missing
    /// issuance, busy phase guards or any started/failed/bound target attempt.
    pub fn original_restored_prebirth_source_data(
        &self,
        ticket: &CompleteOriginalNativeTicket,
    ) -> Result<&CompleteOriginalRestorationSource, RuntimeError> {
        self.original
            .authenticate_restored_prebirth_ticket_data(ticket)?;
        let archive = &self.original;
        archive.authenticate_restored_prebirth_ticket_data(ticket)?;
        Ok(archive)
    }

    /// Declares fixed workspace before borrowing the same prebirth archive.
    pub fn original_restored_prebirth_source_counter_scratch_data() -> usize {
        CompleteOriginalRestorationSource::restored_prebirth_source_counter_scratch_data()
            + std::mem::size_of::<&Self>()
            + std::mem::size_of::<&CompleteOriginalNativeTicket>()
            + std::mem::size_of::<Result<&CompleteOriginalRestorationSource, RuntimeError>>()
    }
}
