//! Retains the closed restoration-input writer selection at original birth.

use super::*;
use crate::reference_packet::service::complete_restore::{
    PACKET_CANONICAL_RESTORE_INPUTS_FEATURE, PacketNative5CompleteRestoreSelection,
    PacketNative5RestoreInputEmitterSelection, canonical_restore_inputs_schema,
};

impl PacketControl {
    /// Binds the canonical restoration-input declaration before any native request.
    ///
    /// This stores expected data only. The true fresh-key prepare verifier and
    /// current SDK writer association must authenticate the actual upload route.
    ///
    /// # Errors
    /// Refuses foreign origin, used/repeated birth or a changed selected12 tuple.
    pub fn bind_complete_original_restore_input_emitter_selection(
        &mut self,
        selection: PacketNative5RestoreInputEmitterSelection,
    ) -> Result<(), ProviderError> {
        if self.capture_creator != std::process::id() {
            return Err(ProviderError::Correlation(
                "restore input emitter foreign creator",
            ));
        }
        if self.complete_restore_input_emitter_selection.is_some()
            || self.realized
            || self.admitted
            || self.staged.is_some()
            || self.active.is_some()
            || self.fenced
            || self.native_effect_attempted
            || self.current_operation.is_some()
            || !self.originals.is_empty()
            || !self.begins.is_empty()
            || !self.begin_requests.is_empty()
            || !self.content.is_empty()
            || self.content_bytes != 0
            || !self.terminals.is_empty()
        {
            return Err(ProviderError::Conflict(
                "restore input emitter is not unused original birth",
            ));
        }
        self.authenticate_complete_restore_input_emitter_declaration()?;
        self.complete_restore_input_emitter_selection = Some(selection);
        Ok(())
    }

    /// Compares original writer declaration with the authenticated installed policy.
    ///
    /// # Errors
    /// Refuses foreign origin, changed selection or an incomplete selected tuple.
    pub fn authenticate_complete_restore_input_emitter_selection(
        &self,
        expected: Option<PacketNative5RestoreInputEmitterSelection>,
    ) -> Result<(), ProviderError> {
        if self.capture_creator != std::process::id() {
            return Err(ProviderError::Correlation(
                "restore input emitter foreign creator",
            ));
        }
        if self.complete_restore_input_emitter_selection != expected {
            return Err(ProviderError::Correlation(
                "restore input emitter selection differs",
            ));
        }
        if expected.is_some() {
            self.authenticate_complete_restore_input_emitter_declaration()?;
        }
        Ok(())
    }

    fn authenticate_complete_restore_input_emitter_declaration(&self) -> Result<(), ProviderError> {
        self.authenticate_complete_restore_selection(Some(
            PacketNative5CompleteRestoreSelection::SourceSignedTransfer12,
        ))?;
        let schema = canonical_restore_inputs_schema()?;
        if !self
            .selection
            .provider
            .implementation
            .formats
            .contains(&schema)
            || !self.selection.realization.bindings.iter().all(|binding| {
                binding
                    .compatibility
                    .implementation
                    .formats
                    .contains(&schema)
            })
            || !self
                .selection
                .provider
                .extensions_supported
                .iter()
                .any(|feature| feature.as_str() == PACKET_CANONICAL_RESTORE_INPUTS_FEATURE)
        {
            return Err(ProviderError::Correlation(
                "restore input emitter original declaration differs",
            ));
        }
        Ok(())
    }
}
