//! Retains separately selected restore grammar as original Control birth data.

use super::*;
use crate::reference_packet::service::complete_restore::{
    PacketNative5CompleteRestoreSelection, complete_restore_selected_schemas,
};

impl PacketControl {
    /// Binds complete restoration grammar before any original request or effect.
    ///
    /// Binding declaration data grants no restoration permission. The native
    /// keyed verifier and exact source/Core target association remain required.
    ///
    /// # Errors
    /// Refuses another origin, repeated/used birth, incomplete owning metadata
    /// or any changed full selected provider/binding schema.
    pub fn bind_complete_original_restore_selection(
        &mut self,
        selected: PacketNative5CompleteRestoreSelection,
    ) -> Result<(), ProviderError> {
        if self.capture_creator != std::process::id() {
            return Err(ProviderError::Correlation(
                "complete restore selection foreign creator",
            ));
        }
        if self.complete_restore_selection.is_some()
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
                "complete restore selection is not unused original birth",
            ));
        }
        self.authenticate_complete_restore_declaration(selected)?;
        self.complete_restore_selection = Some(selected);
        Ok(())
    }

    /// Compares retained grammar with the independently authenticated policy.
    ///
    /// # Errors
    /// Refuses foreign origin, changed selection or an incomplete owning tuple.
    pub fn authenticate_complete_restore_selection(
        &self,
        expected: Option<PacketNative5CompleteRestoreSelection>,
    ) -> Result<(), ProviderError> {
        if self.capture_creator != std::process::id() {
            return Err(ProviderError::Correlation(
                "complete restore selection foreign creator",
            ));
        }
        if self.complete_coordinator.is_none()
            || self.complete_storage.is_none()
            || self.complete_restore_selection != expected
        {
            return Err(ProviderError::Correlation(
                "complete restore original selection differs",
            ));
        }
        if let Some(selected) = expected {
            self.authenticate_complete_restore_declaration(selected)?;
        }
        Ok(())
    }

    fn authenticate_complete_restore_declaration(
        &self,
        selected: PacketNative5CompleteRestoreSelection,
    ) -> Result<(), ProviderError> {
        if self.complete_coordinator.is_none()
            || self.complete_storage.is_none()
            || self.complete_protocol_metadata_limits.is_none()
            || self.complete_ack_emitter_selection.is_none()
            || self.complete_confirmation_selection.is_none()
            || !matches!(
                self.complete_capture_profile,
                Some(PacketNative5CaptureProfile::OwnedProtocol11 { .. })
            )
        {
            return Err(ProviderError::Correlation(
                "complete restore original declaration is incomplete",
            ));
        }
        self.authenticate_complete_protocol_metadata_limits(
            self.complete_protocol_metadata_limits,
        )?;
        for schema in complete_restore_selected_schemas(selected)? {
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
            {
                return Err(ProviderError::Correlation(
                    "complete restore original schema differs",
                ));
            }
        }
        Ok(())
    }
}
