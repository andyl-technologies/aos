//! Lends the same Control selection across its real Discover/Realize/Admit phases.
//!
//! The unopened constructor predicate stays separate. This DATA loan checks the
//! actual local phase and closed physical model without collecting inventory.
//! Only the genuine private boot can combine it with a current connection read.

use super::*;
use std::mem::size_of;

impl PacketControl {
    /// Borrows the selected source at the exact pending birth transition.
    ///
    /// Read and publication sit on opposite sides of Realize and Admit. Neither
    /// the completed-record count nor this reference constructs a boot scope;
    /// the real boot separately authenticates its origin, policy and phase.
    ///
    /// # Errors
    /// Refuses creator drift, fencing, another phase, a restored/active model,
    /// or an open/failed physical gate. No model inventory is allocated.
    pub(in super::super) fn original_native_birth_selection_data(
        &self,
        completed: usize,
        publication: bool,
    ) -> Result<&PacketControlSelection, ProviderError> {
        let (realized, admitted) = match (completed, publication) {
            (0, _) | (1, false) => (false, false),
            (1, true) | (2, false) => (true, false),
            (2, true) => (true, true),
            _ => return Err(ProviderError::Correlation("native birth Control phase")),
        };
        if self.capture_creator != std::process::id()
            || !self.immediate
            || self.fenced
            || self.realized != realized
            || self.admitted != admitted
            || self.staged.is_some()
            || self.active.is_some()
            || self.complete_restored_hold.is_some()
            || !self.program.original_native_birth_gate_closed_data()?
        {
            return Err(ProviderError::Correlation("native birth Control scope"));
        }
        Ok(&self.selection)
    }

    /// Names new borrowed phase/return views before any actual boot read.
    pub(in super::super) const fn original_native_birth_selection_counter_scratch_data() -> usize {
        size_of::<&Self>()
            .saturating_add(size_of::<&PacketControlSelection>())
            .saturating_add(size_of::<Result<&PacketControlSelection, ProviderError>>())
            .saturating_add(size_of::<&NativeProgram>())
            .saturating_add(size_of::<&PacketProgram>())
            .saturating_add(size_of::<&super::super::connected::PacketConnectedProgram>())
            .saturating_add(size_of::<Result<bool, ProviderError>>())
            .saturating_add(size_of::<(usize, bool)>())
            .saturating_add(size_of::<(bool, bool)>())
            .saturating_add(size_of::<usize>())
            .saturating_add(3 * size_of::<bool>())
    }
}
