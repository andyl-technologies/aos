//! Defines immutable Capture-selection DATA checks and policy byte views.

use super::*;

impl Native5PolicyData {
    /// Returns the original immutable policy DATA projection.
    ///
    /// # Errors
    /// Preserves the original schema, correlation, content and byte-credit refusals.
    pub fn with_capture_allocation_selection(
        mut self,
        selection: Option<
            super::super::capture_allocation::PacketNative5CaptureAllocationSelection,
        >,
    ) -> Result<Self, ProviderError> {
        if self.capture_allocation_selection.is_some()
            || self.capture_allocation_definitions.is_some()
        {
            return Err(capture_refused());
        }
        let Some(selection) = selection else {
            return Ok(self);
        };
        let schemas = [
            super::super::capture_allocation::capture_allocation_schema()?,
            super::super::capture_allocation::capture_allocation_record_schema()?,
        ];
        self.capture_allocation_selection = Some(selection);
        self.capture_allocation_definitions = Some(schemas.map(|schema| schema.definition));
        self.validate_immutable_content()?;
        serialized_credit(&self.protocol_view(), 512 * 1024)?;
        Ok(self)
    }

    /// Checks the unchanged immutable policy DATA.
    ///
    /// # Errors
    /// Preserves the original schema, correlation, content and byte-credit refusals.
    pub fn validate_capture_allocation_content(&self) -> Result<(), ProviderError> {
        use super::super::capture_allocation::*;
        match (
            self.capture_allocation_selection,
            self.capture_allocation_definitions.as_ref(),
        ) {
            (None, None) => Ok(()),
            (
                Some(PacketNative5CaptureAllocationSelection::OriginalObserve12),
                Some(definitions),
            ) => {
                let schemas = [
                    capture_allocation_schema()?,
                    capture_allocation_record_schema()?,
                ];
                if !matches!(
                    self.capture_profile,
                    super::super::PacketNative5CaptureProfile::OwnedProtocol11 { .. }
                ) || self.protocol_metadata_limits.is_none()
                    || self.ack_emitter_selection
                        != Some(super::super::PacketNative5AckEmitterSelection::CanonicalSdkBlob5)
                    || self.native_codec_metadata_extent
                        != Some(client::CanonicalAckCodecMetadataExtent::CanonicalAck512KiB)
                    || !self
                        .selection
                        .provider
                        .extensions_supported
                        .iter()
                        .any(|feature| feature.as_str() == PACKET_NATIVE_CAPTURE_ALLOCATION_FEATURE)
                    || schemas.iter().zip(definitions).any(|(schema, definition)| {
                        !self
                            .selection
                            .provider
                            .implementation
                            .formats
                            .contains(schema)
                            || &schema.definition != definition
                    })
                {
                    return Err(capture_refused());
                }
                Ok(())
            }
            _ => Err(capture_refused()),
        }
    }

    /// Returns the original immutable policy DATA projection.
    pub fn capture_allocation_selection(
        &self,
    ) -> Option<super::super::capture_allocation::PacketNative5CaptureAllocationSelection> {
        self.capture_allocation_selection
    }
}

pub(super) struct CapturePolicyView<'a>(pub(super) &'a Native5PolicyData);

macro_rules! capture_view {
    ($wrapper:ident, $old:ident, $tag:literal) => {
        impl Serialize for $wrapper<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                if self.0.capture_allocation_selection.is_some() {
                    (
                        $tag,
                        &self.0.capture_allocation_selection,
                        &self.0.capture_allocation_definitions,
                        super::restore_input_policy::$old(self.0),
                    )
                        .serialize(serializer)
                } else {
                    super::restore_input_policy::$old(self.0).serialize(serializer)
                }
            }
        }
    };
}

capture_view!(
    CapturePolicyView,
    InputPolicyView,
    "source-private.native5-policy-capture-allocation/17"
);

fn capture_refused() -> ProviderError {
    ProviderError::Correlation("native original Observe allocation selection differs")
}
