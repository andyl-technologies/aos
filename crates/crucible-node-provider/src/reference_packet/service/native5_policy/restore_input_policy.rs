//! Binds the explicit canonical restore-input family without changing old views.

use super::super::complete_restore::{
    PACKET_CANONICAL_RESTORE_INPUTS_FEATURE, PacketNative5CompleteRestoreSelection,
    PacketNative5RestoreInputEmitterSelection, canonical_restore_inputs_schema,
};
use super::*;

impl Native5Policy {
    pub(in crate::reference_packet::service) fn with_restore_input_emitter_selection(
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

    pub(crate) fn restore_input_emitter_selection(
        &self,
    ) -> Option<PacketNative5RestoreInputEmitterSelection> {
        self.restore_input_emitter_selection
    }

    pub(crate) fn restore_input_emitter_definition(&self) -> Option<&ContentRef> {
        self.restore_input_emitter_definition.as_ref()
    }

    pub(super) fn validate_restore_input_emitter_content(&self) -> Result<(), ProviderError> {
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

    pub(super) fn validate_restore_input_emitter_negotiation(
        &self,
        authority: &ConnectionAuthority,
    ) -> Result<(), ProviderError> {
        if self.restore_input_emitter_selection.is_none() {
            return Ok(());
        }
        if self.restore_input_emitter_definition.is_none()
            || !authority
                .selected_features()
                .iter()
                .any(|feature| feature.as_str() == PACKET_CANONICAL_RESTORE_INPUTS_FEATURE)
        {
            return Err(refused());
        }
        authority.ensure_live()
    }
}

pub(super) struct InputPolicyView<'a>(pub(super) &'a Native5Policy);
pub(super) struct InputCompactPolicyView<'a>(pub(super) &'a Native5Policy);
pub(super) struct InputOwnedPolicyView<'a>(pub(super) &'a Native5Policy);

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
selected_view!(
    InputCompactPolicyView,
    TransferCompactPolicyView,
    "source-private.native5-policy-compact-restore-input-emitter/16"
);
selected_view!(
    InputOwnedPolicyView,
    TransferOwnedPolicyView,
    "source-private.native5-policy-owned-restore-input-emitter/16"
);

fn refused() -> ProviderError {
    ProviderError::Correlation("native selected restore input emitter differs")
}
