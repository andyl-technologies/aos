//! Binds the explicit canonical restore-input family without changing old views.

use super::super::complete_restore::{
    PACKET_CANONICAL_RESTORE_INPUTS_FEATURE, PacketNative5CompleteRestoreSelection,
    PacketNative5RestoreInputEmitterSelection, canonical_restore_inputs_schema,
};
use super::*;

impl Native5PolicyData {
    /// Returns the original immutable policy DATA projection.
    ///
    /// # Errors
    /// Preserves the original schema, correlation, content and byte-credit refusals.
    pub fn with_restore_input_emitter_selection(
        mut self,
        selection: Option<PacketNative5RestoreInputEmitterSelection>,
    ) -> Result<Self, ProviderError> {
        if self.restore_input_emitter_selection.is_some()
            || self.restore_input_emitter_definition.is_some()
        {
            return Err(refused());
        }
        let Some(selection) = selection else {
            return Ok(self);
        };
        if self.complete_restore_selection
            != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
            || !matches!(
                self.capture_profile,
                super::super::PacketNative5CaptureProfile::OwnedProtocol11 { .. }
            )
        {
            return Err(refused());
        }
        let schema = canonical_restore_inputs_schema()?;
        if !self
            .selection
            .provider
            .implementation
            .formats
            .contains(&schema)
        {
            return Err(refused());
        }
        self.restore_input_emitter_selection = Some(selection);
        self.restore_input_emitter_definition = Some(schema.definition);
        self.validate_immutable_content()?;
        serialized_credit(&self.protocol_view(), 512 * 1024)?;
        Ok(self)
    }

    /// Checks the unchanged immutable policy DATA.
    ///
    /// # Errors
    /// Preserves the original schema, correlation, content and byte-credit refusals.
    pub fn validate_restore_input_emitter_content(&self) -> Result<(), ProviderError> {
        match (
            self.restore_input_emitter_selection,
            self.restore_input_emitter_definition.as_ref(),
        ) {
            (None, None) => Ok(()),
            (
                Some(PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12),
                Some(definition),
            ) => {
                let schema = canonical_restore_inputs_schema()?;
                if !self
                    .selection
                    .provider
                    .extensions_supported
                    .iter()
                    .any(|feature| feature.as_str() == PACKET_CANONICAL_RESTORE_INPUTS_FEATURE)
                    || self.selection.realization.bindings.iter().any(|binding| {
                        !binding
                            .compatibility
                            .implementation
                            .formats
                            .contains(&schema)
                    })
                    || self.complete_restore_selection
                        != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
                    || !matches!(
                        self.capture_profile,
                        super::super::PacketNative5CaptureProfile::OwnedProtocol11 { .. }
                    )
                    || definition != &schema.definition
                    || !self
                        .selection
                        .provider
                        .implementation
                        .formats
                        .contains(&schema)
                {
                    return Err(refused());
                }
                Ok(())
            }
            _ => Err(refused()),
        }
    }

    /// Returns the original immutable policy DATA projection.
    pub fn restore_input_emitter_selection(
        &self,
    ) -> Option<PacketNative5RestoreInputEmitterSelection> {
        self.restore_input_emitter_selection
    }

    /// Returns the original immutable policy DATA projection.
    pub fn restore_input_emitter_definition(&self) -> Option<&ContentRef> {
        self.restore_input_emitter_definition.as_ref()
    }
}

pub(super) struct InputPolicyView<'a>(pub(super) &'a Native5PolicyData);

macro_rules! selected_view {
    ($wrapper:ident, $old:ident, $tag:literal) => {
        impl Serialize for $wrapper<'_> {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                if self.0.restore_input_emitter_selection.is_some() {
                    (
                        $tag,
                        &self.0.restore_input_emitter_selection,
                        &self.0.restore_input_emitter_definition,
                        super::restore_transfer_policy::$old(self.0),
                    )
                        .serialize(serializer)
                } else {
                    super::restore_transfer_policy::$old(self.0).serialize(serializer)
                }
            }
        }
    };
}

selected_view!(
    InputPolicyView,
    TransferPolicyView,
    "source-private.native5-policy-restore-input-emitter/16"
);

fn refused() -> ProviderError {
    ProviderError::Correlation("native selected restore input emitter differs")
}
