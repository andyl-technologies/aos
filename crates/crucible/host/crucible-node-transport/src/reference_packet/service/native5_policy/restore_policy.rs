//! Binds the selected complete restoration mechanism to immutable native policy.
//!
//! The portable selection and syntax checks allow only its registered frames.
//! The native boot's actual fresh key verifier remains the sole token issuer.

use super::super::complete_restore::*;
use super::*;
use crucible_source_birth_data::profile::reference_packet::service::native5_policy::Native5CompleteRestorePolicyInput;

impl Native5Policy {
    pub(in crate::reference_packet::service) fn from_original_launch_with_complete_restore(
        selection: PacketControlSelection,
        coordinator: InstalledContent,
        profile: super::super::PacketNative5CaptureProfile,
        confirmation: super::super::PacketNative5ConfirmationSelection,
        emitter: super::super::PacketNative5AckEmitterSelection,
        extent: crate::client::CanonicalAckCodecMetadataExtent,
        metadata: super::super::PacketNative5ProtocolMetadataLimits,
        restoration: PacketNative5CompleteRestoreSelection,
    ) -> Result<Self, ProviderError> {
        match Native5PolicyData::from_original_launch_with_complete_restore(
            Native5CompleteRestorePolicyInput {
                selection,
                coordinator,
                profile,
                confirmation,
                emitter,
                extent,
                metadata,
                restoration,
            },
        ) {
            Ok(data) => Ok(Self { data }),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn complete_restore_selection(
        &self,
    ) -> Option<PacketNative5CompleteRestoreSelection> {
        self.complete_restore_selection
    }

    pub(crate) fn complete_restore_definitions(&self) -> Option<&[ContentRef; 3]> {
        self.complete_restore_definitions.as_ref()
    }

    pub(super) fn validate_complete_restore_content(&self) -> Result<(), ProviderError> {
        self.data.validate_complete_restore_content()
    }

    pub(super) fn validate_complete_restore_negotiation(
        &self,
        authority: &ConnectionAuthority,
    ) -> Result<(), ProviderError> {
        self.validate_complete_restore_transfer_negotiation(authority)?;
        if self.complete_restore_selection.is_some()
            && [
                PACKET_COMPLETE_RESTORE_FEATURE,
                PACKET_COMPLETE_RESTORE_PROOF_EXTENSION,
                PACKET_COMPLETE_RESTORE_RECEIPT_EXTENSION,
            ]
            .iter()
            .any(|key| {
                !authority
                    .selected_features()
                    .iter()
                    .any(|feature| feature.as_str() == *key)
                    || !authority.envelope_extensions().contains(*key)
            })
        {
            return Err(ProviderError::Correlation(
                "native complete restore negotiation differs",
            ));
        }
        authority.ensure_live()
    }

    pub(super) fn verify_complete_restore_envelope(
        &self,
        authority: &ConnectionAuthority,
        envelope: &Envelope,
        received: &ReceivedBody,
    ) -> Result<bool, ProviderError> {
        if self.verify_complete_restore_transfer_envelope(authority, envelope, received)? {
            return Ok(true);
        }
        if !envelope.extensions.keys().any(|key| {
            [
                PACKET_COMPLETE_RESTORE_FEATURE,
                PACKET_COMPLETE_RESTORE_PROOF_EXTENSION,
                PACKET_COMPLETE_RESTORE_RECEIPT_EXTENSION,
            ]
            .contains(&key.as_str())
        }) {
            return Ok(false);
        }
        if self.complete_restore_selection
            != Some(PacketNative5CompleteRestoreSelection::SourceSignedOwned11)
            || self.complete_restore_definitions.is_none()
            || envelope.node_id.0.as_ref()
                != Some(&self.selection.realization.bindings[0].compatibility.node_id)
        {
            return Err(ProviderError::Correlation(
                "native complete restore mechanism absent",
            ));
        }
        self.validate_complete_restore_negotiation(authority)?;
        let _projection = crate::connection::CompleteRestoreProjection::from_envelope(envelope)?;
        match (envelope.message, received) {
            (MessageKind::Request, ReceivedBody::Request(request)) => {
                if !matches!(request.as_ref(), RequestBody::Begin(begin)
                    if begin.kind == crate::bodies::BeginKind::PrepareRestore)
                {
                    return Err(ProviderError::Correlation(
                        "native complete restore original request kind",
                    ));
                }
            }
            (MessageKind::Response, ReceivedBody::Response(response)) => {
                if !matches!(
                    response.shape,
                    crate::bodies::ResponseShape::Completed {
                        operation_state: crate::bodies::OperationState::Completed,
                        ..
                    }
                ) || !matches!(
                    response.result,
                    Some(crate::bodies::MethodResult::PrepareRestore(_))
                ) {
                    return Err(ProviderError::Correlation(
                        "native complete restore original result kind",
                    ));
                }
            }
            _ => {
                return Err(ProviderError::Correlation(
                    "native complete restore original message kind",
                ));
            }
        }
        Ok(true)
    }
}

pub(super) struct CompleteRestoreCompactPolicyView<'a>(pub(super) &'a Native5Policy);
impl Serialize for CompleteRestoreCompactPolicyView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0.complete_restore_selection {
            Some(selection) => (
                "source-private.native5-policy-compact-complete-restore/14",
                selection,
                &self.0.complete_restore_definitions,
                Native5CompactPolicyView(self.0),
            )
                .serialize(serializer),
            None => Native5CompactPolicyView(self.0).serialize(serializer),
        }
    }
}

pub(super) struct CompleteRestoreOwnedPolicyView<'a>(pub(super) &'a Native5Policy);
impl Serialize for CompleteRestoreOwnedPolicyView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0.complete_restore_selection {
            Some(selection) => (
                "source-private.native5-policy-owned-complete-restore/14",
                selection,
                &self.0.complete_restore_definitions,
                NativeOwnedMetadataPolicyView(self.0),
            )
                .serialize(serializer),
            None => NativeOwnedMetadataPolicyView(self.0).serialize(serializer),
        }
    }
}

impl crate::retained_metadata::ObserveMetadata for PacketNative5CompleteRestoreSelection {
    fn observe_metadata(
        &self,
        _observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        match self {
            Self::SourceSignedOwned11 | Self::SourceSignedTransfer12 => Ok(()),
        }
    }
}
