//! Validates separately selected source-signed controller restore traffic.

use super::*;
use crate::reference_packet::service::complete_restore::*;

impl ControllerNative5Policy {
    pub(super) fn from_source_complete_restore_installation(
        authority: &ConnectionAuthority,
        selection: PacketControlSelection,
        coordinator: InstalledContent,
        profile: crate::reference_packet::service::PacketNative5CaptureProfile,
        metadata_extent: Option<CanonicalAckCodecMetadataExtent>,
    ) -> Result<Self, ProviderError> {
        if !matches!(
            profile,
            crate::reference_packet::service::PacketNative5CaptureProfile::OwnedProtocol11 { .. }
        ) {
            return Err(ProviderError::Correlation(
                "complete restore requires owning profile",
            ));
        }
        let mut policy = Self::from_source_ack_emitter_with_metadata_extent(
            authority,
            selection,
            coordinator,
            profile,
            metadata_extent,
        )?;
        let schemas = [
            complete_restore_request_schema()?,
            complete_restore_proof_schema()?,
            complete_restore_receipt_schema()?,
        ];
        if schemas.iter().any(|schema| {
            !policy
                .selection
                .provider
                .implementation
                .formats
                .contains(schema)
        }) {
            return Err(ProviderError::Correlation(
                "complete restore source schema absent",
            ));
        }
        policy.complete_restore_selection =
            Some(PacketNative5CompleteRestoreSelection::SourceSignedOwned11);
        policy.complete_restore_definitions = Some(schemas.map(|schema| schema.definition));
        policy.validate_current_restore(authority)?;
        serialized_credit(
            &policy.protocol_view(),
            policy.metadata_extent.map_or(
                256 * 1024,
                CanonicalAckCodecMetadataExtent::maximum_encoded_bytes,
            ),
        )?;
        Ok(policy)
    }

    pub(super) fn validate_current_restore(
        &self,
        authority: &ConnectionAuthority,
    ) -> Result<(), ProviderError> {
        match (
            self.complete_restore_selection,
            self.complete_restore_definitions.as_ref(),
        ) {
            (None, None) => {
                self.validate_current_transfer(authority)?;
                return self.validate_current_input_emitter(authority);
            }
            (
                Some(
                    PacketNative5CompleteRestoreSelection::SourceSignedOwned11
                    | PacketNative5CompleteRestoreSelection::SourceSignedTransfer12,
                ),
                Some(_),
            ) => {}
            _ => {
                return Err(ProviderError::Correlation(
                    "complete restore immutable definition mismatch",
                ));
            }
        }
        for key in [
            PACKET_COMPLETE_RESTORE_FEATURE,
            PACKET_COMPLETE_RESTORE_PROOF_EXTENSION,
            PACKET_COMPLETE_RESTORE_RECEIPT_EXTENSION,
        ] {
            if !authority
                .selected_features()
                .iter()
                .any(|feature| feature.as_str() == key)
                || !authority.envelope_extensions().contains(key)
            {
                return Err(ProviderError::Correlation(
                    "complete restore negotiation absent",
                ));
            }
        }
        self.validate_current_transfer(authority)?;
        self.validate_current_input_emitter(authority)?;
        authority.ensure_live()
    }
}

pub(super) enum Encoding {
    Ordinary,
    Compact,
    Owned,
}
pub(super) struct ControllerRestoreView<'a> {
    pub(super) policy: &'a ControllerNative5Policy,
    pub(super) encoding: Encoding,
}
impl serde::Serialize for ControllerRestoreView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        macro_rules! selected {
            ($tag:literal, $view:expr) => {
                match self.policy.complete_restore_selection {
                    None => serde::Serialize::serialize(&$view, serializer),
                    Some(choice) => serde::Serialize::serialize(
                        &(
                            $tag,
                            choice,
                            &self.policy.complete_restore_definitions,
                            $view,
                        ),
                        serializer,
                    ),
                }
            };
        }
        match self.encoding {
            Encoding::Ordinary => selected!(
                "source-private.controller-policy-complete-restore/14",
                self.policy.base_protocol_view()
            ),
            Encoding::Compact => selected!(
                "source-private.controller-policy-compact-complete-restore/14",
                self.policy.base_compact_protocol_view()
            ),
            Encoding::Owned => selected!(
                "source-private.controller-policy-owned-complete-restore/14",
                self.policy.base_owned_protocol_view()
            ),
        }
    }
}

pub(super) fn verify_selected_restore(
    policy: &ControllerNative5Policy,
    authority: &ConnectionAuthority,
    envelope: &Envelope,
    body: &ReceivedBody,
) -> Result<bool, ProviderError> {
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
    policy.validate_current_restore(authority)?;
    if policy.complete_restore_selection
        != Some(PacketNative5CompleteRestoreSelection::SourceSignedOwned11)
        || controller_node(policy) != envelope.node_id.0.as_ref()
    {
        return Err(ProviderError::Correlation(
            "complete restore selected node mismatch",
        ));
    }
    super::super::CompleteRestoreProjection::from_envelope(envelope)?;
    match (envelope.message, body) {
        (MessageKind::Request, ReceivedBody::Request(request)) => {
            if !matches!(request.as_ref(), RequestBody::Begin(begin) if matches!(begin.decoded_arguments()?, crate::bodies::BeginArguments::PrepareRestore(_)))
            {
                return Err(ProviderError::Correlation(
                    "complete restore baseline request differs",
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
                    "complete restore baseline result differs",
                ));
            }
        }
        _ => {
            return Err(ProviderError::Correlation(
                "complete restore message differs",
            ));
        }
    }
    Ok(true)
}

impl ControllerNative5Policy {
    pub(super) fn from_source_complete_restore_transfer_installation(
        authority: &ConnectionAuthority,
        selection: PacketControlSelection,
        coordinator: InstalledContent,
        profile: crate::reference_packet::service::PacketNative5CaptureProfile,
        metadata_extent: Option<CanonicalAckCodecMetadataExtent>,
    ) -> Result<Self, ProviderError> {
        let mut policy = Self::from_source_complete_restore_installation(
            authority,
            selection,
            coordinator,
            profile,
            metadata_extent,
        )?;
        let schemas = crate::reference_packet::Native5Policy::complete_restore_transfer_schemas()?;
        if schemas.iter().any(|schema| {
            !policy
                .selection
                .provider
                .implementation
                .formats
                .contains(schema)
        }) {
            return Err(ProviderError::Correlation(
                "restore transfer source schemas absent",
            ));
        }
        policy.complete_restore_selection =
            Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12);
        policy.complete_restore_transfer_definitions =
            Some(schemas.map(|schema| schema.definition));
        policy.validate_current_restore(authority)?;
        serialized_credit(
            &policy.protocol_view(),
            policy.metadata_extent.map_or(
                256 * 1024,
                CanonicalAckCodecMetadataExtent::maximum_encoded_bytes,
            ),
        )?;
        Ok(policy)
    }

    fn validate_current_transfer(
        &self,
        authority: &ConnectionAuthority,
    ) -> Result<(), ProviderError> {
        use crate::reference_packet::service::complete_restore::transfer::*;
        if self.complete_restore_selection
            != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        {
            return if self.complete_restore_transfer_definitions.is_none() {
                Ok(())
            } else {
                Err(ProviderError::Correlation(
                    "unselected restore transfer definitions",
                ))
            };
        }
        if self.complete_restore_transfer_definitions.is_none() {
            return Err(ProviderError::Correlation(
                "restore transfer definitions absent",
            ));
        }
        for key in [
            PACKET_COMPLETE_RESTORE_PREPARE_EXTENSION,
            PACKET_COMPLETE_RESTORE_PREPARE_PROOF_EXTENSION,
            PACKET_COMPLETE_RESTORE_PREPARE_RECEIPT_EXTENSION,
            PACKET_COMPLETE_RESTORE_COMMIT_EXTENSION,
            PACKET_COMPLETE_RESTORE_COMMIT_PROOF_EXTENSION,
            PACKET_COMPLETE_RESTORE_COMMIT_RECEIPT_EXTENSION,
        ] {
            if !authority
                .selected_features()
                .iter()
                .any(|feature| feature.as_str() == key)
                || !authority.envelope_extensions().contains(key)
            {
                return Err(ProviderError::Correlation(
                    "restore transfer phase negotiation absent",
                ));
            }
        }
        for key in [PACKET_COMPLETE_RESTORE_TRANSFER_FEATURE,
            crate::reference_packet::service::complete_restore::PACKET_NATIVE_RESTORED_RECORD_FEATURE] {
            if !authority.selected_features().iter().any(|feature| feature.as_str() == key) {
                return Err(ProviderError::Correlation("restore transfer feature absent"));
            }
        }
        authority.ensure_live()
    }
}

pub(super) struct ControllerTransferView<'a> {
    pub(super) policy: &'a ControllerNative5Policy,
    pub(super) encoding: Encoding,
}
impl serde::Serialize for ControllerTransferView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let view = ControllerRestoreView {
            policy: self.policy,
            encoding: match self.encoding {
                Encoding::Ordinary => Encoding::Ordinary,
                Encoding::Compact => Encoding::Compact,
                Encoding::Owned => Encoding::Owned,
            },
        };
        if self.policy.complete_restore_selection
            != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        {
            return serde::Serialize::serialize(&view, serializer);
        }
        let tag = match self.encoding {
            Encoding::Ordinary => "source-private.controller-policy-restore-transfer/15",
            Encoding::Compact => "source-private.controller-policy-compact-restore-transfer/15",
            Encoding::Owned => "source-private.controller-policy-owned-restore-transfer/15",
        };
        serde::Serialize::serialize(
            &(
                tag,
                &self.policy.complete_restore_transfer_definitions,
                view,
            ),
            serializer,
        )
    }
}

pub(super) fn verify_selected_transfer(
    policy: &ControllerNative5Policy,
    authority: &ConnectionAuthority,
    envelope: &Envelope,
    body: &ReceivedBody,
) -> Result<bool, ProviderError> {
    use crate::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreTransferPhase::{Prepare, Commit};
    if !envelope.extensions.keys().any(|key| {
        [Prepare, Commit].into_iter().any(|phase| {
            [
                phase.request_extension(),
                phase.proof_extension(),
                phase.receipt_extension(),
            ]
            .contains(&key.as_str())
        })
    }) {
        return Ok(false);
    }
    policy.validate_current_restore(authority)?;
    if policy.complete_restore_selection
        != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
        || controller_node(policy) != envelope.node_id.0.as_ref()
    {
        return Err(ProviderError::Correlation(
            "restore transfer source node differs",
        ));
    }
    if envelope.extensions.contains_key(crate::reference_packet::service::fresh_restore_allocation::PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING) {
        if policy.fresh_restore_allocation_selection != Some(crate::reference_packet::service::fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13) {
            return Err(ProviderError::Correlation("unselected fresh Prepare binding"));
        }
        super::super::CompleteRestoreTransferProjection::from_envelope_with_fresh_binding_data(envelope)?;
    } else {
        super::super::CompleteRestoreTransferProjection::from_envelope(envelope)?;
    }
    match (envelope.message, body) {
        (MessageKind::Request, ReceivedBody::Request(request))
            if matches!(request.as_ref(), RequestBody::Begin(begin)
            if matches!(begin.decoded_arguments()?, crate::bodies::BeginArguments::PrepareRestore(_))) =>
            {}
        (MessageKind::Response, ReceivedBody::Response(response))
            if matches!(
                response.shape,
                crate::bodies::ResponseShape::Completed {
                    operation_state: crate::bodies::OperationState::Completed,
                    ..
                }
            ) && matches!(
                response.result,
                Some(crate::bodies::MethodResult::PrepareRestore(_))
            ) => {}
        _ => {
            return Err(ProviderError::Correlation(
                "restore transfer baseline differs",
            ));
        }
    }
    authority.ensure_live()?;
    Ok(true)
}
