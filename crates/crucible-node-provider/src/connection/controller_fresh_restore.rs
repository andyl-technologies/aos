//! Retains the explicitly installed host-side fresh13 codec choice.

use super::*;
use crate::reference_packet::service::fresh_restore_allocation::{self as fresh, *};

impl ControllerNative5Policy {
    pub(super) fn from_source_fresh_restore_installation(
        authority: &ConnectionAuthority,
        selection: PacketControlSelection,
        coordinator: InstalledContent,
        profile: crate::reference_packet::service::PacketNative5CaptureProfile,
        metadata_extent: CanonicalAckCodecMetadataExtent,
    ) -> Result<Self, ProviderError> {
        let mut policy = Self::from_source_restore_input_emitter_installation(
            authority,
            selection,
            coordinator,
            profile,
            metadata_extent,
        )?;
        let schemas = fresh::policy::selected_schemas()?;
        let definitions = schemas.map(|schema| schema.definition);
        fresh::policy::validate_selection_content(&policy.selection, &definitions)?;
        policy.fresh_restore_allocation_selection =
            Some(PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13);
        policy.fresh_restore_allocation_definitions = Some(definitions);
        policy.validate_current_fresh_restore(authority)?;
        serialized_credit(
            &policy.protocol_view(),
            metadata_extent.maximum_encoded_bytes(),
        )?;
        Ok(policy)
    }

    pub(super) fn validate_current_fresh_restore(
        &self,
        authority: &ConnectionAuthority,
    ) -> Result<(), ProviderError> {
        match (
            self.fresh_restore_allocation_selection,
            self.fresh_restore_allocation_definitions.as_ref(),
        ) {
            (None, None) => Ok(()),
            (Some(PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13), Some(_)) => {
                if self.complete_restore_selection != Some(crate::reference_packet::service::complete_restore::PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
                    || self.restore_input_emitter_selection != Some(crate::reference_packet::service::complete_restore::PacketNative5RestoreInputEmitterSelection::CanonicalSdkRestoreInputs12)
                { return Err(refused()); }
                fresh::policy::validate_selection_negotiation(authority)
            }
            _ => Err(refused()),
        }
    }
}

pub(super) fn verify_selected_fresh(
    policy: &ControllerNative5Policy,
    authority: &ConnectionAuthority,
    envelope: &Envelope,
    body: &ReceivedBody,
) -> Result<bool, ProviderError> {
    if policy.fresh_restore_allocation_selection.is_none() {
        return if fresh::policy::contains_selected_data(envelope) {
            Err(refused())
        } else {
            Ok(false)
        };
    }
    fresh::policy::verify_envelope(&policy.selection, authority, envelope, body)
}

pub(super) struct ControllerFreshRestoreView<'a> {
    pub(super) policy: &'a ControllerNative5Policy,
    pub(super) encoding: controller_restore::Encoding,
}

impl serde::Serialize for ControllerFreshRestoreView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use controller_restore::Encoding;
        let (tag, old) = match self.encoding {
            Encoding::Ordinary => (
                "source-private.controller-policy-fresh-restore-allocation/18",
                controller_input_emitter::ControllerInputEmitterView {
                    policy: self.policy,
                    encoding: Encoding::Ordinary,
                },
            ),
            Encoding::Compact => (
                "source-private.controller-policy-compact-fresh-restore-allocation/18",
                controller_input_emitter::ControllerInputEmitterView {
                    policy: self.policy,
                    encoding: Encoding::Compact,
                },
            ),
            Encoding::Owned => (
                "source-private.controller-policy-owned-fresh-restore-allocation/18",
                controller_input_emitter::ControllerInputEmitterView {
                    policy: self.policy,
                    encoding: Encoding::Owned,
                },
            ),
        };
        if self.policy.fresh_restore_allocation_selection.is_some() {
            serde::Serialize::serialize(
                &(
                    tag,
                    self.policy.fresh_restore_allocation_selection,
                    &self.policy.fresh_restore_allocation_definitions,
                    old,
                ),
                serializer,
            )
        } else {
            serde::Serialize::serialize(&old, serializer)
        }
    }
}

impl Native5CodecOwner {
    pub(crate) fn fresh_restore_selection_data(
        &self,
        authority: &ConnectionAuthority,
    ) -> Result<Option<PacketNative5FreshRestoreAllocationSelection>, ProviderError> {
        match self {
            Self::ControllerPacket(policy) => {
                policy.validate_current_negotiation(authority)?;
                Ok(policy.fresh_restore_allocation_selection)
            }
            Self::NativePacket(policy) => {
                authority.ensure_live()?;
                Ok(policy.fresh_restore_allocation_selection())
            }
        }
    }

    pub(crate) fn fresh_restore_controller_selection_data(
        &self,
        authority: &ConnectionAuthority,
    ) -> Result<&PacketControlSelection, ProviderError> {
        let Self::ControllerPacket(policy) = self else {
            return Err(refused());
        };
        policy.validate_current_negotiation(authority)?;
        if policy.fresh_restore_allocation_selection
            != Some(PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13)
        {
            return Err(refused());
        }
        Ok(&policy.selection)
    }
}

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn install_native5_controller_fresh_restore_allocation_codec_with_metadata_extent(
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
        let policy = ControllerNative5Policy::from_source_fresh_restore_installation(
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
    ProviderError::Correlation("original fresh restoration allocation codec differs")
}

impl<S: ProviderStream> Connection<S> {
    /// Selects closed additional Prepare syntax from the actual installed codec.
    ///
    /// The parsed binding remains DATA; the real completed-query owner and
    /// Source MAC must authenticate it independently. Commit and receipt syntax
    /// keeps its original two-request/one-response extension roster.
    pub(crate) fn original_selected_restore_transfer_projection_data<'a>(
        &self,
        envelope: &'a Envelope,
    ) -> Result<CompleteRestoreTransferProjection<'a>, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        let selected = self
            .native5_codec
            .as_ref()
            .ok_or_else(refused)?
            .fresh_restore_selection_data(&self.authority)?;
        let binding = envelope
            .extensions
            .contains_key(PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING);
        if binding {
            if selected != Some(PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13) {
                return Err(refused());
            }
            CompleteRestoreTransferProjection::from_envelope_with_fresh_binding_data(envelope)
        } else {
            CompleteRestoreTransferProjection::from_envelope(envelope)
        }
    }
}
