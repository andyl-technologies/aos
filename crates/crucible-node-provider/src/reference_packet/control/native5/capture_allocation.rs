//! Binds the actual selected Observe allocation family at unused Control birth.

use super::*;
use crate::reference_packet::service::capture_allocation::{
    PACKET_NATIVE_CAPTURE_ALLOCATION_FEATURE, PacketNative5CaptureAllocationSelection,
    capture_allocation_record_schema, capture_allocation_schema,
};

impl PacketControl {
    /// Binds the expected allocation producer before the first native request.
    ///
    /// The retained selection is data. A report is issued only by the actual
    /// native observer and cannot replace current original Capture admission.
    ///
    /// # Errors
    /// Refuses foreign origin, used or repeated birth and incomplete full tuples.
    pub fn bind_complete_original_capture_allocation_selection(
        &mut self,
        selection: PacketNative5CaptureAllocationSelection,
    ) -> Result<(), ProviderError> {
        self.authenticate_capture_allocation_creator()?;
        if self.complete_capture_allocation_selection.is_some()
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
                "capture allocation is not unused original birth",
            ));
        }
        self.authenticate_capture_allocation_declaration()?;
        self.complete_capture_allocation_selection = Some(selection);
        Ok(())
    }

    /// Compares the original selection with the independently installed policy.
    ///
    /// # Errors
    /// Refuses foreign origin, a changed selection or incomplete owning tuple.
    pub fn authenticate_complete_capture_allocation_selection(
        &self,
        expected: Option<PacketNative5CaptureAllocationSelection>,
    ) -> Result<(), ProviderError> {
        self.authenticate_capture_allocation_creator()?;
        if self.complete_capture_allocation_selection != expected {
            return Err(ProviderError::Correlation(
                "capture allocation selection differs",
            ));
        }
        if expected.is_some() {
            self.authenticate_capture_allocation_declaration()?;
        }
        Ok(())
    }

    fn authenticate_capture_allocation_creator(&self) -> Result<(), ProviderError> {
        if self.capture_creator != std::process::id() {
            return Err(ProviderError::Correlation(
                "capture allocation foreign creator",
            ));
        }
        Ok(())
    }

    fn authenticate_capture_allocation_declaration(&self) -> Result<(), ProviderError> {
        if !matches!(
            self.complete_capture_profile,
            Some(PacketNative5CaptureProfile::OwnedProtocol11 { .. })
        ) || self.complete_protocol_metadata_limits.is_none()
            || self.complete_ack_emitter_selection.is_none()
            || self.complete_coordinator.is_none()
            || self.complete_storage.is_none()
        {
            return Err(ProviderError::Correlation(
                "capture allocation owning tuple is absent",
            ));
        }
        self.authenticate_complete_protocol_metadata_limits(
            self.complete_protocol_metadata_limits,
        )?;
        for schema in [
            capture_allocation_schema()?,
            capture_allocation_record_schema()?,
        ] {
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
                    "capture allocation full schema differs",
                ));
            }
        }
        if !self
            .selection
            .provider
            .extensions_supported
            .iter()
            .any(|feature| feature.as_str() == PACKET_NATIVE_CAPTURE_ALLOCATION_FEATURE)
        {
            return Err(ProviderError::Correlation(
                "capture allocation feature is absent",
            ));
        }
        Ok(())
    }
}
