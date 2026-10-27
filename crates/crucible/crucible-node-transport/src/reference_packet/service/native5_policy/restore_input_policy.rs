//! Binds the explicit canonical restore-input family without changing old views.

use super::super::complete_restore::{
    PACKET_CANONICAL_RESTORE_INPUTS_FEATURE, PacketNative5RestoreInputEmitterSelection,
};
use super::*;

impl Native5Policy {
    pub(in crate::reference_packet::service) fn with_restore_input_emitter_selection(
        self,
        selection: Option<PacketNative5RestoreInputEmitterSelection>,
    ) -> Result<Self, ProviderError> {
        match self.data.with_restore_input_emitter_selection(selection) {
            Ok(data) => Ok(Self { data }),
            Err(error) => Err(error),
        }
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
        self.data.validate_restore_input_emitter_content()
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
