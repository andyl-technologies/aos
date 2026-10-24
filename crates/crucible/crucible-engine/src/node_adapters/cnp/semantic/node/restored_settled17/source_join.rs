//! Joins an inert Source record to the actual already validated Node25 World.

use super::*;
use crate::node_contract::SavedRuntimeActivation;

impl CnpRestoredSettledValidatedNode17 {
    /// Checks the complete archived World without issuing a fresh activation.
    ///
    /// # Errors
    /// Refuses a different World, including another activation with equal owners.
    pub(crate) fn authenticate_source_world17_data(
        &self,
        world: &SavedRuntimeActivation,
    ) -> Result<(), RuntimeError> {
        if self.record.base.active.as_ref() != Some(world) {
            return Err(RuntimeError::ForeignAuthority);
        }
        let Some(record::HistoricalWorld17::World(installed)) = &self.record.activation else {
            return Err(RuntimeError::InvalidReceipt);
        };
        if installed.record != *world {
            return Err(RuntimeError::ForeignAuthority);
        }
        Ok(())
    }
}
