//! Binds the closed canonical restoration uploader to the actual sealed codec.

use super::*;
use crate::reference_packet::service::complete_restore::*;

impl ControllerNative5Policy {
    pub(super) fn from_source_restore_input_emitter_installation(
        authority: &ConnectionAuthority,
        selection: PacketControlSelection,
        coordinator: InstalledContent,
        profile: crate::reference_packet::service::PacketNative5CaptureProfile,
        metadata_extent: CanonicalAckCodecMetadataExtent,
    ) -> Result<Self, ProviderError> {
        let mut policy = Self::from_source_complete_restore_transfer_installation(
            authority,
            selection,
            coordinator,
            profile,
            Some(metadata_extent),
        )?;
        let schema = canonical_restore_inputs_schema()?;
        if !policy
            .selection
            .provider
            .implementation
            .formats
            .contains(&schema)
            || !policy
                .selection
                .provider
                .extensions_supported
                .iter()
                .any(|feature| feature.as_str() == PACKET_CANONICAL_RESTORE_INPUTS_FEATURE)
            || policy.selection.realization.bindings.iter().any(|binding| {
                !binding
                    .compatibility
                    .implementation
                    .formats
                    .contains(&schema)
            })
        {
            return Err(refused());
        }
        policy.restore_input_emitter_selection =
            Some(PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12);
        policy.restore_input_emitter_definition = Some(schema.definition);
        policy.validate_current_restore(authority)?;
        serialized_credit(
            &policy.protocol_view(),
            metadata_extent.maximum_encoded_bytes(),
        )?;
        Ok(policy)
    }

    pub(super) fn validate_current_input_emitter(
        &self,
        authority: &ConnectionAuthority,
    ) -> Result<(), ProviderError> {
        match (
            self.restore_input_emitter_selection,
            self.restore_input_emitter_definition.as_ref(),
        ) {
            (None, None) => Ok(()),
            (
                Some(PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12),
                Some(_),
            ) => {
                if self.complete_restore_selection != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
                    || !matches!(self.capture_profile, crate::reference_packet::service::PacketNative5CaptureProfile::OwnedProtocol11 { .. })
                    || !authority.selected_features().iter().any(|feature| feature.as_str() == PACKET_CANONICAL_RESTORE_INPUTS_FEATURE)
                { return Err(refused()); }
                authority.ensure_live()
            }
            _ => Err(refused()),
        }
    }
}

pub(super) struct ControllerInputEmitterView<'a> {
    pub(super) policy: &'a ControllerNative5Policy,
    pub(super) encoding: controller_restore::Encoding,
}

impl serde::Serialize for ControllerInputEmitterView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use controller_restore::{ControllerTransferView, Encoding};
        let encoding = self.encoding;
        let old = ControllerTransferView {
            policy: self.policy,
            encoding,
        };
        let Some(selection) = self.policy.restore_input_emitter_selection else {
            return serde::Serialize::serialize(&old, serializer);
        };
        let tag = match self.encoding {
            Encoding::Ordinary => "source-private.controller-policy-restore-input-emitter/16",
            Encoding::Compact => {
                "source-private.controller-policy-compact-restore-input-emitter/16"
            }
            Encoding::Owned => "source-private.controller-policy-owned-restore-input-emitter/16",
        };
        serde::Serialize::serialize(
            &(
                tag,
                selection,
                &self.policy.restore_input_emitter_definition,
                old,
            ),
            serializer,
        )
    }
}

impl<S: ProviderStream> Connection<S> {
    /// Observes the same installed sealed uploader selection after current checks.
    ///
    /// # Errors
    /// Refuses foreign origins, revoked registration, absent codec or changed negotiation.
    pub fn original_native5_restore_input_emitter_selection(
        &self,
    ) -> Result<Option<PacketNative5RestoreInputEmitterSelection>, ProviderError> {
        self.authenticate_native5_source_codec()?;
        let codec = self.native5_codec.as_ref().ok_or_else(refused)?;
        let selected = match codec.as_ref() {
            Native5CodecOwner::ControllerPacket(policy) => {
                policy.validate_current_input_emitter(&self.authority)?;
                policy.restore_input_emitter_selection
            }
            Native5CodecOwner::NativePacket(policy) => {
                let selection = policy.restore_input_emitter_selection();
                if selection.is_some()
                    && (policy.restore_input_emitter_definition().is_none()
                        || !self.authority.selected_features().iter().any(|feature| {
                            feature.as_str() == PACKET_CANONICAL_RESTORE_INPUTS_FEATURE
                        }))
                {
                    return Err(refused());
                }
                selection
            }
        };
        Ok(selected)
    }

    pub(crate) fn install_native5_controller_restore_input_emitter_codec_with_metadata_extent(
        &mut self,
        bank: &mut Option<crate::transport::original_frames::OriginalFrameReservation>,
        selection: PacketControlSelection,
        coordinator: InstalledContent,
        profile: crate::reference_packet::service::PacketNative5CaptureProfile,
        metadata_extent: CanonicalAckCodecMetadataExtent,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.check_authority()?;
        if self.role != EndpointRole::Controller {
            return Err(refused());
        }
        let policy = ControllerNative5Policy::from_source_restore_input_emitter_installation(
            &self.authority,
            selection,
            coordinator,
            profile,
            metadata_extent,
        )?;
        self.install_original_native5_codec(
            bank,
            Native5CodecOwner::ControllerPacket(Box::new(policy)),
        )
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original canonical restoration input codec differs")
}
