//! Retains born native metadata limits as Control correlation data.
//!
//! Matching these fields never substitutes for the current native metadata walk,
//! actual record/alias allocation facts or source/factory memory admission.

use super::*;
use crate::reference_packet::service::{
    PacketNative5CaptureProfile, PacketNative5ProtocolMetadataLimits,
};

impl PacketControl {
    /// Binds both actual native metadata allocations before original dispatch.
    ///
    /// The endpoint supplies facts directly from its two retained reservations.
    /// This comparison data cannot authorize capture or replace a current walk.
    ///
    /// # Errors
    /// Refuses foreign origin, absent row selection, invalid facts, repeated
    /// binding or any original request, realization, activation or effect.
    pub fn bind_complete_original_protocol_metadata_birth_facts(
        &mut self,
        facts: crate::reference_packet::service::PacketNative5ProtocolMetadataBirthFacts,
    ) -> Result<(), ProviderError> {
        if self.capture_creator != std::process::id() {
            return Err(ProviderError::Correlation(
                "native metadata facts foreign creator",
            ));
        }
        let limits = self
            .complete_protocol_metadata_limits
            .ok_or(ProviderError::Correlation("native metadata limits absent"))?;
        facts.validate_data(&limits)?;
        self.authenticate_complete_protocol_metadata_limits(Some(limits))?;
        if self.complete_protocol_metadata_birth_facts.is_some()
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
                "native metadata facts are not unused original birth",
            ));
        }
        self.complete_protocol_metadata_birth_facts = Some(facts);
        Ok(())
    }

    /// Compares retained born facts with both actual endpoint reservations.
    ///
    /// # Errors
    /// Refuses foreign origin, changed backing facts, invalid row correspondence
    /// or a partially selected owning profile. Old None data remains unchanged.
    pub fn authenticate_complete_protocol_metadata_birth_facts(
        &self,
        expected: Option<crate::reference_packet::service::PacketNative5ProtocolMetadataBirthFacts>,
    ) -> Result<(), ProviderError> {
        if self.capture_creator != std::process::id() {
            return Err(ProviderError::Correlation(
                "native metadata facts foreign creator",
            ));
        }
        self.authenticate_complete_protocol_metadata_limits(
            self.complete_protocol_metadata_limits,
        )?;
        if self.complete_protocol_metadata_birth_facts != expected {
            return Err(ProviderError::Correlation(
                "native metadata original allocation differs",
            ));
        }
        match (self.complete_protocol_metadata_limits, expected) {
            (Some(limits), Some(facts)) => facts.validate_data(&limits),
            (None, None) => Ok(()),
            _ => Err(ProviderError::Correlation(
                "native metadata facts are incomplete",
            )),
        }
    }

    /// Binds the native row selection before any original dispatch or effect.
    ///
    /// # Errors
    /// Refuses foreign origin, invalid limits, an unselected owning profile,
    /// missing ACK mechanism, repeated selection or any used Control lifetime.
    pub fn bind_complete_original_protocol_metadata_limits(
        &mut self,
        selected: PacketNative5ProtocolMetadataLimits,
    ) -> Result<(), ProviderError> {
        if self.capture_creator != std::process::id() {
            return Err(ProviderError::Correlation(
                "native metadata selection foreign creator",
            ));
        }
        selected.validate_data()?;
        if self.complete_coordinator.is_none()
            || self.complete_storage.is_none()
            || !matches!(
                self.complete_capture_profile,
                Some(PacketNative5CaptureProfile::OwnedProtocol11 { .. })
            )
            || self.complete_ack_emitter_selection.is_none()
            || self.complete_protocol_metadata_limits.is_some()
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
                "native metadata selection is not unused owning birth",
            ));
        }
        self.complete_protocol_metadata_limits = Some(selected);
        Ok(())
    }

    /// Compares born limits with the independently authenticated native policy.
    ///
    /// The unselected route preserves old None data and cannot activate an
    /// owning codec by accepting absent row limits.
    ///
    /// # Errors
    /// Refuses foreign origin, missing original birth, changed limits or a
    /// selection that disagrees with the retained owning profile.
    pub fn authenticate_complete_protocol_metadata_limits(
        &self,
        expected: Option<PacketNative5ProtocolMetadataLimits>,
    ) -> Result<(), ProviderError> {
        if self.capture_creator != std::process::id() {
            return Err(ProviderError::Correlation(
                "native metadata selection foreign creator",
            ));
        }
        if let Some(limits) = expected {
            limits.validate_data()?;
        }
        if self.complete_coordinator.is_none()
            || self.complete_storage.is_none()
            || self.complete_protocol_metadata_limits != expected
            || matches!(
                self.complete_capture_profile,
                Some(PacketNative5CaptureProfile::OwnedProtocol11 { .. })
            ) != expected.is_some()
            || expected.is_some() && self.complete_ack_emitter_selection.is_none()
        {
            return Err(ProviderError::Correlation(
                "native metadata original selection differs",
            ));
        }
        Ok(())
    }
}
