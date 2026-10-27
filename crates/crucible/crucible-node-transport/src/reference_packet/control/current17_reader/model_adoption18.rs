//! Moves the current model only after its enclosing decoder enters18 custody.
//!
//! The enclosing owner retains this Control and every historical field. Taking
//! the model makes the old graph's validation fail; callers must not publish
//! the depleted Control as a complete17 graph or reconstruct a legacy model.

use super::*;
use crate::reference_packet::continuation_models::settled_reader::adoption18::CurrentModel18Adoption;
use crate::reference_packet::service::PacketConnectedSourceProgram;

impl CurrentControl17Data {
    /// Transfers the same decoded model into the enclosing18 attempt.
    ///
    /// The enclosing decoder must already belong to the retained18 owner.
    /// Independent original admission covers model validation and constructor
    /// work. All other Control fields stay in their original allocations.
    ///
    /// # Errors
    /// Refuses invalid local identity joins, an occupied destination, absent
    /// model, inconsistent history or a different complete program definition.
    /// A refused model validation keeps the model in the spent destination.
    pub(crate) fn prepare_current_model18_into(
        &mut self,
        program: &PacketConnectedSourceProgram,
        output: &mut Option<CurrentModel18Adoption>,
    ) -> Result<(), ProviderError> {
        self.authenticate_local_groups_data()?;
        CurrentModel18Adoption::prepare_into(&mut self.program.model, program, output)
    }
}
