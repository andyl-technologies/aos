//! Owns the immutable source-five native wire verifier and complete codec view.
//!
//! Only the native service factory constructs this policy after its original
//! private launch and measured executable checks. Its portable view preserves
//! every frozen field; it grants no source capture or restoration permission.

#[cfg(test)]
use crate::connection::serialized_credit;
use crucible_node_format::*;
use crucible_source_birth_data::profile::reference_packet::service::native5_policy::Native5PolicyData;
use serde::Serialize;

use super::super::{
    continuation_contracts::PACKET_COMPLETE_LINEAGE_FEATURE,
    control::PacketControlSelection,
    coordinator::PacketNative5CoordinatorInstallation,
    input::{PACKET_INPUT_FEATURE, PacketInputContext},
};
use crate::{
    ProviderError,
    bodies::RequestBody,
    connection::{BodySchemaVerifier, ReceivedBody},
    envelope::{Envelope, MessageKind, Method},
    handshake::ConnectionAuthority,
    reference_service::InstalledContent,
};

mod capture_metadata;
mod fresh_restore_policy;
mod report_startup;
mod restore_input_policy;
mod restore_policy;
mod restore_transfer_policy;

/// Retains the live owner's immutable policy DATA behind its original factory.
#[repr(transparent)]
pub(crate) struct Native5Policy {
    data: Native5PolicyData,
}

impl std::ops::Deref for Native5Policy {
    type Target = Native5PolicyData;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl Serialize for Native5Policy {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        self.data.serialize(serializer)
    }
}

impl Native5Policy {
    /// Borrows the same immutable policy selection for selected activation DATA checks.
    pub(crate) fn original_restoration_activation_selection_data(&self) -> &PacketControlSelection {
        &self.selection
    }

    pub(crate) fn authenticate_owned11_snapshot_definition(&self) -> Result<(), ProviderError> {
        if self.capture_allocation_selection.is_some()
            || self.fresh_restore_allocation_selection.is_some()
        {
            // The selected quote owner cannot be omitted from the old full
            // snapshot11 class. A separate full owning codec must replace this
            // refusal before selected Capture can be promoted.
            return Err(ProviderError::Correlation(
                "selected Capture owning codec not installed",
            ));
        }
        let schema = super::native_owned11_snapshot_schema()?;
        if !matches!(
            self.capture_profile,
            super::PacketNative5CaptureProfile::OwnedProtocol11 { .. }
        ) || !self
            .selection
            .provider
            .implementation
            .formats
            .contains(&schema)
        {
            return Err(ProviderError::Correlation(
                "native owned11 full snapshot definition",
            ));
        }
        Ok(())
    }

    // A distinct exhaustive leaf preserves all selected fields and actual
    // coordinator backing capacity without changing earlier codec editions.
    pub(crate) fn borrowed_owned11_protocol_view(&self) -> impl Serialize + '_ {
        fresh_restore_policy::FreshOwnedPolicyView(self)
    }

    fn original_owned11_protocol_view(&self) -> impl Serialize + '_ {
        let Native5PolicyData {
            selection,
            coordinator,
            definition,
            connected,
            capture_profile,
            confirmation_selection,
            confirmation_definition,
            ack_emitter_selection,
            ack_emitter_definition,
            native_codec_metadata_extent,
            protocol_metadata_limits: _,
            complete_restore_selection: _,
            complete_restore_definitions: _,
            complete_restore_transfer_definitions: _,
            restore_input_emitter_selection: _,
            restore_input_emitter_definition: _,
            capture_allocation_selection: _,
            capture_allocation_definitions: _,
            fresh_restore_allocation_selection: _,
            fresh_restore_allocation_definitions: _,
        } = &self.data;
        (
            "source-private.native5-policy-owned/11",
            selection,
            (
                &coordinator.reference,
                coordinator.bytes.allocation_capacity(),
                crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::new(
                    coordinator.bytes.as_slice(),
                ),
            ),
            definition,
            connected,
            capture_profile,
            confirmation_selection,
            confirmation_definition,
            ack_emitter_selection,
            ack_emitter_definition,
            native_codec_metadata_extent,
        )
    }

    pub(crate) fn observe_owned11_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.observe_retained_metadata(observer)
    }

    pub(crate) fn observe_retained_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        let Native5PolicyData {
            selection,
            coordinator,
            definition,
            connected,
            capture_profile,
            confirmation_selection,
            confirmation_definition,
            ack_emitter_selection,
            ack_emitter_definition,
            native_codec_metadata_extent,
            protocol_metadata_limits,
            complete_restore_selection,
            complete_restore_definitions,
            complete_restore_transfer_definitions,
            restore_input_emitter_selection,
            restore_input_emitter_definition,
            capture_allocation_selection,
            capture_allocation_definitions,
            fresh_restore_allocation_selection,
            fresh_restore_allocation_definitions,
        } = &self.data;
        observer.observe(selection)?;
        observer.observe(coordinator)?;
        observer.observe(definition)?;
        observer.observe(connected)?;
        observer.observe(capture_profile)?;
        observer.observe(confirmation_selection)?;
        observer.observe(confirmation_definition)?;
        observer.observe(ack_emitter_selection)?;
        observer.observe(ack_emitter_definition)?;
        observer.observe(native_codec_metadata_extent)?;
        observer.observe(protocol_metadata_limits)?;
        observer.observe(complete_restore_selection)?;
        observer.observe(complete_restore_definitions)?;
        observer.observe(complete_restore_transfer_definitions)?;
        observer.observe(restore_input_emitter_selection)?;
        observer.observe(restore_input_emitter_definition)?;
        // The absent branch has the exact old traversal population as well as
        // old serialized bytes. Populated fields retain every independent row,
        // including an inconsistent partial value that immutable validation
        // will separately refuse.
        if capture_allocation_selection.is_some() || capture_allocation_definitions.is_some() {
            observer.observe(capture_allocation_selection)?;
            observer.observe(capture_allocation_definitions)?;
        }
        if fresh_restore_allocation_selection.is_some()
            || fresh_restore_allocation_definitions.is_some()
        {
            observer.observe(fresh_restore_allocation_selection)?;
            observer.observe(fresh_restore_allocation_definitions)?;
        }
        Ok(())
    }

    pub(super) fn from_original_launch(
        selection: PacketControlSelection,
        coordinator: InstalledContent,
    ) -> Result<Self, ProviderError> {
        match Native5PolicyData::from_original_launch(selection, coordinator) {
            Ok(data) => Ok(Self { data }),
            Err(error) => Err(error),
        }
    }

    pub(super) fn from_original_launch_with_profile(
        selection: PacketControlSelection,
        coordinator: InstalledContent,
        capture_profile: super::PacketNative5CaptureProfile,
    ) -> Result<Self, ProviderError> {
        match Native5PolicyData::from_original_launch_with_profile(
            selection,
            coordinator,
            capture_profile,
        ) {
            Ok(data) => Ok(Self { data }),
            Err(error) => Err(error),
        }
    }

    #[cfg(test)]
    fn prepare_original_profile(
        selection: PacketControlSelection,
        coordinator: InstalledContent,
        capture_profile: super::PacketNative5CaptureProfile,
    ) -> Result<Self, ProviderError> {
        match Native5PolicyData::prepare_original_profile(selection, coordinator, capture_profile) {
            Ok(data) => Ok(Self { data }),
            Err(error) => Err(error),
        }
    }

    pub(super) fn from_original_launch_with_confirmation(
        selection: PacketControlSelection,
        coordinator: InstalledContent,
        profile: super::PacketNative5CaptureProfile,
        confirmation: super::PacketNative5ConfirmationSelection,
    ) -> Result<Self, ProviderError> {
        match Native5PolicyData::from_original_launch_with_confirmation(
            selection,
            coordinator,
            profile,
            confirmation,
        ) {
            Ok(data) => Ok(Self { data }),
            Err(error) => Err(error),
        }
    }

    pub(super) fn from_original_launch_with_ack_emitter(
        selection: PacketControlSelection,
        coordinator: InstalledContent,
        profile: super::PacketNative5CaptureProfile,
        confirmation: super::PacketNative5ConfirmationSelection,
        emitter: super::PacketNative5AckEmitterSelection,
    ) -> Result<Self, ProviderError> {
        match Native5PolicyData::from_original_launch_with_ack_emitter(
            selection,
            coordinator,
            profile,
            confirmation,
            emitter,
        ) {
            Ok(data) => Ok(Self { data }),
            Err(error) => Err(error),
        }
    }

    pub(super) fn from_original_launch_with_ack_emitter_metadata_extent(
        selection: PacketControlSelection,
        coordinator: InstalledContent,
        profile: super::PacketNative5CaptureProfile,
        confirmation: super::PacketNative5ConfirmationSelection,
        emitter: super::PacketNative5AckEmitterSelection,
        extent: crate::client::CanonicalAckCodecMetadataExtent,
    ) -> Result<Self, ProviderError> {
        match Native5PolicyData::from_original_launch_with_ack_emitter_metadata_extent(
            selection,
            coordinator,
            profile,
            confirmation,
            emitter,
            extent,
        ) {
            Ok(data) => Ok(Self { data }),
            Err(error) => Err(error),
        }
    }

    pub(super) fn from_original_launch_with_protocol_metadata(
        selection: PacketControlSelection,
        coordinator: InstalledContent,
        profile: super::PacketNative5CaptureProfile,
        confirmation: super::PacketNative5ConfirmationSelection,
        emitter: super::PacketNative5AckEmitterSelection,
        extent: crate::client::CanonicalAckCodecMetadataExtent,
        metadata: super::PacketNative5ProtocolMetadataLimits,
    ) -> Result<Self, ProviderError> {
        match Native5PolicyData::from_original_launch_with_protocol_metadata(
            selection,
            coordinator,
            profile,
            confirmation,
            emitter,
            extent,
            metadata,
        ) {
            Ok(data) => Ok(Self { data }),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn protocol_metadata_limits(
        &self,
    ) -> Option<super::PacketNative5ProtocolMetadataLimits> {
        self.protocol_metadata_limits
    }

    pub(crate) fn authenticate_original_control_selection(
        &self,
        selection: &PacketControlSelection,
    ) -> Result<(), ProviderError> {
        if selection != &self.selection {
            return Err(ProviderError::Correlation(
                "native ACK Control selection differs",
            ));
        }
        Ok(())
    }

    pub(crate) fn ack_emitter_selection(&self) -> Option<super::PacketNative5AckEmitterSelection> {
        self.ack_emitter_selection
    }

    pub(crate) fn ack_emitter_definition(&self) -> Option<&ContentRef> {
        self.ack_emitter_definition.as_ref()
    }

    pub(crate) fn confirmation_selection(
        &self,
    ) -> Option<super::PacketNative5ConfirmationSelection> {
        self.confirmation_selection
    }

    pub(crate) fn confirmation_definition(&self) -> Option<&ContentRef> {
        self.confirmation_definition.as_ref()
    }

    pub(crate) fn capture_profile(&self) -> &super::PacketNative5CaptureProfile {
        &self.capture_profile
    }

    pub(crate) fn compact_protocol_view(&self) -> impl Serialize + '_ {
        fresh_restore_policy::FreshCompactPolicyView(self)
    }

    fn original_compact_protocol_view(&self) -> impl Serialize + '_ {
        (
            &self.selection,
            (
                &self.coordinator.reference,
                self.coordinator.bytes.allocation_capacity(),
                crate::protocol_snapshot::compact_bytes::BorrowedCompactBytes::new(
                    self.coordinator.bytes.as_slice(),
                ),
            ),
            &self.definition,
            &self.connected,
            &self.capture_profile,
        )
    }

    pub(crate) fn validate_installation(
        &self,
        authority: &ConnectionAuthority,
    ) -> Result<(), ProviderError> {
        self.validate_immutable_content()?;
        self.validate_current_negotiation(authority)
    }

    // All fields are privately owned immutable values validated at construction.
    // No callback, decoder or mutable accessor changes them after publication.
    fn validate_immutable_content(&self) -> Result<(), ProviderError> {
        self.data.validate_immutable_content()
    }

    // Each frame retains both live fences and every negotiated tuple predicate.
    fn validate_current_negotiation(
        &self,
        authority: &ConnectionAuthority,
    ) -> Result<(), ProviderError> {
        self.validate_capture_allocation_negotiation(authority)?;
        self.validate_fresh_restore_allocation_negotiation(authority)?;
        self.validate_complete_restore_negotiation(authority)?;
        authority.ensure_live()?;
        if self.ack_emitter_selection.is_some()
            && (!authority
                .selected_features()
                .iter()
                .any(|id| id.as_str() == super::ack_emitter::PACKET_NATIVE_CANONICAL_ACK_FEATURE)
                || !authority.selected_features().iter().any(|id| {
                    id.as_str() == super::ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_FEATURE
                })
                || !authority
                    .envelope_extensions()
                    .contains(super::ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_FEATURE))
        {
            return Err(ProviderError::Correlation(
                "native5 canonical ACK feature absent",
            ));
        }
        let binding = self
            .selection
            .realization
            .bindings
            .first()
            .ok_or(ProviderError::Correlation("native5 source binding missing"))?;
        if binding.authority.session_id != *authority.session_id()
            || binding.authority.incarnation_id != *authority.incarnation_id()
            || !authority
                .selected_features()
                .iter()
                .any(|id| id.as_str() == PACKET_COMPLETE_LINEAGE_FEATURE)
            || !authority
                .selected_features()
                .iter()
                .any(|id| id.as_str() == PACKET_INPUT_FEATURE)
            || !authority
                .envelope_extensions()
                .contains(PACKET_INPUT_FEATURE)
            || authority.limits().frame_bytes.get() > 65_536
            || authority.limits().blob_chunk_bytes.get() > 4096
        {
            return Err(ProviderError::Correlation(
                "native5 source negotiation changed",
            ));
        }
        authority.ensure_live()
    }
}

struct Native5CompactPolicyView<'a>(&'a Native5Policy);

impl Serialize for Native5CompactPolicyView<'_> {
    fn serialize<T: serde::Serializer>(&self, serializer: T) -> Result<T::Ok, T::Error> {
        let policy = self.0;
        if let Some(metadata) = policy.protocol_metadata_limits {
            return (
                "source-private.native5-policy-compact-selected-metadata/13",
                metadata,
                policy.native_codec_metadata_extent,
                Native5CompactLegacyPolicyView(policy),
            )
                .serialize(serializer);
        }
        match policy.native_codec_metadata_extent {
            None => Native5CompactLegacyPolicyView(policy).serialize(serializer),
            Some(extent) => (
                "source-private.native5-policy-compact-metadata/12",
                extent,
                Native5CompactLegacyPolicyView(policy),
            )
                .serialize(serializer),
        }
    }
}

struct Native5CompactLegacyPolicyView<'a>(&'a Native5Policy);

impl Serialize for Native5CompactLegacyPolicyView<'_> {
    fn serialize<T: serde::Serializer>(&self, serializer: T) -> Result<T::Ok, T::Error> {
        let policy = self.0;
        if let Some(emitter) = policy.ack_emitter_selection {
            return (
                "source-private.native5-policy-canonical-ack/9",
                policy.original_compact_protocol_view(),
                policy.confirmation_selection,
                &policy.confirmation_definition,
                emitter,
                &policy.ack_emitter_definition,
            )
                .serialize(serializer);
        }
        match policy.confirmation_selection {
            None => policy
                .original_compact_protocol_view()
                .serialize(serializer),
            Some(selection) => (
                "source-private.native5-policy-confirmed/8",
                policy.original_compact_protocol_view(),
                selection,
                &policy.confirmation_definition,
            )
                .serialize(serializer),
        }
    }
}

impl BodySchemaVerifier for Native5Policy {
    fn verify(
        &self,
        authority: &ConnectionAuthority,
        envelope: &Envelope,
        received: &ReceivedBody,
    ) -> Result<(), ProviderError> {
        self.validate_current_negotiation(authority)?;
        if super::restored_input_reactive17::verify_selected_wire_header_data(
            &self.selection,
            authority,
            envelope,
        )? {
            return authority.ensure_live();
        }
        if self.verify_fresh_restore_allocation_envelope(authority, envelope, received)? {
            return authority.ensure_live();
        }
        if envelope
            .body
            .get("extensions")
            .is_some_and(|value| value.as_object().is_none_or(|values| !values.is_empty()))
        {
            return Err(ProviderError::Correlation(
                "native5 body extensions unsupported",
            ));
        }
        if super::complete_restore::restoration_observe::verify_selected_wire_header_data(
            &self.selection,
            authority,
            envelope,
        )? {
            return authority.ensure_live();
        }
        if super::complete_restore::activation::verify_selected_wire_header_data(
            &self.selection,
            authority,
            envelope,
        )? {
            return authority.ensure_live();
        }
        if self.verify_complete_restore_envelope(authority, envelope, received)? {
            return authority.ensure_live();
        }
        if let Some(proof) = envelope
            .extensions
            .get(super::ack_emitter::PACKET_CANONICAL_ACK_ADMISSION_FEATURE)
        {
            if self.ack_emitter_selection
                != Some(super::PacketNative5AckEmitterSelection::CanonicalSdkBlob5)
                || envelope.extensions.len() != 1
                || envelope.message != MessageKind::Request
                || envelope.method != Method::Admit
                || envelope.node_id.0.as_ref()
                    != Some(&self.selection.realization.bindings[0].compatibility.node_id)
                || !matches!(received, ReceivedBody::Request(request) if matches!(request.as_ref(), RequestBody::Admit(_)))
            {
                return Err(ProviderError::Correlation(
                    "native5 assigned Admit proof scope",
                ));
            }
            super::ack_emitter::validate_proof_value(proof)?;
            // Syntax acceptance cannot install the native marker. The owning
            // endpoint verifier still checks its original key and full context.
            return authority.ensure_live();
        }
        if envelope
            .extensions
            .contains_key(super::confirmation::PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION)
        {
            if self.confirmation_selection
                != Some(super::PacketNative5ConfirmationSelection::AfterProtocolPoll5)
                || self.confirmation_definition.is_none()
                || envelope.node_id.0.as_ref()
                    != Some(&self.selection.realization.bindings[0].compatibility.node_id)
                || !authority.selected_features().iter().any(|feature| {
                    feature.as_str()
                        == super::confirmation::PACKET_NATIVE_AFTER_CONFIRMATION_FEATURE
                })
                || !authority
                    .envelope_extensions()
                    .contains(super::confirmation::PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION)
            {
                return Err(ProviderError::Correlation(
                    "native5 confirmation mechanism not installed",
                ));
            }
            let _projection = crate::connection::ConfirmationProjection::from_envelope(envelope)?;
            match (envelope.message, received) {
                (MessageKind::Request, ReceivedBody::Request(request)) => {
                    let RequestBody::Poll(poll) = request.as_ref() else {
                        return Err(ProviderError::Correlation(
                            "native5 confirmation request method",
                        ));
                    };
                    if poll.after_observation_sequence.get() != 0 || !poll.extensions.is_empty() {
                        return Err(ProviderError::Correlation(
                            "native5 confirmation Poll arguments",
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
                    ) || !matches!(response.result, Some(crate::bodies::MethodResult::Poll(_)))
                    {
                        return Err(ProviderError::Correlation(
                            "native5 confirmation Poll result",
                        ));
                    }
                }
                _ => {
                    return Err(ProviderError::Correlation(
                        "native5 confirmation message kind",
                    ));
                }
            }
            return authority.ensure_live();
        }
        if envelope.message != MessageKind::Request || envelope.method != Method::Input {
            if !envelope.extensions.is_empty() {
                return Err(ProviderError::Correlation(
                    "native5 request-only input context",
                ));
            }
            return authority.ensure_live();
        }
        let ReceivedBody::Request(request) = received else {
            return Err(ProviderError::Correlation(
                "native5 original Input body absent",
            ));
        };
        let RequestBody::Input(request) = request.as_ref() else {
            return Err(ProviderError::Correlation(
                "native5 original Input method changed",
            ));
        };
        let context = PacketInputContext::decode(&envelope.extensions)?;
        let cut = context.cut();
        let binding = &self.selection.realization.bindings[0];
        let owner = &self.selection.realization.owner_bindings[0];
        if cut.session_id != *authority.session_id()
            || cut.incarnation_id != *authority.incarnation_id()
            || cut.node_id != binding.compatibility.node_id
            || cut.execution_owner_id != owner.owner.id
            || cut.owner_generation != binding.authority.owner_generation
            || cut.input_epoch != binding.authority.input_epoch
            || envelope.node_id.0.as_ref() != Some(&cut.node_id)
            || envelope.execution_owner_id.0.as_ref() != Some(&cut.execution_owner_id)
            || envelope.capture_owner_id.0.is_some()
            || envelope.operation_id.0.is_some()
            || request.binding_hash != owner.identity()?
            || request.owner_generation != cut.owner_generation
            || request.input_epoch != cut.input_epoch
            || request.batch_id != cut.batch_id
            || request.batch_sequence != cut.batch_sequence
            || request.batch_hash != cut.batch_hash
            || !request.extensions.is_empty()
            || request.events.iter().any(|event| {
                !event.extensions.is_empty() || event.destination.node_id != cut.node_id
            })
            || matches!(&context, PacketInputContext::Commit { input_request_id, .. }
                if envelope.request_id.0.as_ref() == Some(input_request_id))
        {
            return Err(ProviderError::Correlation(
                "native5 original Input correlation changed",
            ));
        }
        let batch = InputBatch {
            schema_version: 1,
            execution_owner_id: cut.execution_owner_id.clone(),
            input_epoch: request.input_epoch.clone(),
            batch_id: request.batch_id.clone(),
            batch_sequence: request.batch_sequence,
            events: request.events.clone(),
            extensions: Extensions::new(),
        };
        if batch.identity()? != cut.batch_hash {
            return Err(ProviderError::Correlation(
                "native5 original complete Input batch changed",
            ));
        }
        authority.ensure_live()
    }
}

impl crate::reference_packet::endpoint::PacketEndpointPolicy for Native5Policy {
    fn authenticate_invocation_capture_snapshot_definition(&self) -> Result<(), ProviderError> {
        Native5Policy::authenticate_invocation_capture_snapshot_definition(self)
    }

    fn authenticate_startup_capture_snapshot_definition(&self) -> Result<(), ProviderError> {
        Native5Policy::authenticate_startup_capture_snapshot_definition(self)
    }

    fn authenticate_owned11_snapshot_definition(&self) -> Result<(), ProviderError> {
        Native5Policy::authenticate_owned11_snapshot_definition(self)
    }

    fn authenticate_source(
        &self,
        authority: &ConnectionAuthority,
        selection: &PacketControlSelection,
    ) -> Result<(), ProviderError> {
        self.validate_installation(authority)?;
        if selection != &self.selection {
            return Err(ProviderError::Correlation(
                "native5 installed endpoint source changed",
            ));
        }
        authority.ensure_live()
    }

    fn consuming_schema(&self, _: &ContentRef, _: &Envelope) -> Result<ContentRef, ProviderError> {
        Ok(self.definition.clone())
    }
}

impl crate::blob::BlobSchemaVerifier for Native5Policy {
    fn verify_schema(
        &self,
        schema: &ContentRef,
        content: &ContentRef,
        bytes: &[u8],
    ) -> Result<(), ProviderError> {
        if schema != &self.definition {
            return Err(ProviderError::Correlation(
                "native5 consuming schema not installed",
            ));
        }
        content.verify(bytes)?;
        if content.media_type == "application/octet-stream" {
            return if bytes.len() <= 1024 {
                Ok(())
            } else {
                Err(ProviderError::ResourceExhausted(
                    "native5 original input payload",
                ))
            };
        }
        if content.media_type == "application/vnd.crucible.input-inventory+json" {
            let value = canonical::parse_json(bytes, 65_536)?;
            if canonical::canonical_json(&value)? != bytes {
                return Err(ProviderError::Frame(
                    "native5 delivery inventory canonical bytes",
                ));
            }
            let rows = value
                .as_array()
                .ok_or(ProviderError::Frame("native5 delivery inventory shape"))?;
            if rows.len() > 4 {
                return Err(ProviderError::ResourceExhausted(
                    "native5 delivery inventory population",
                ));
            }
            let _: Vec<crate::input_commit::CommittedDeliveryV1> =
                serde_json::from_value(value).map_err(ContractError::from)?;
            return Ok(());
        }
        if content.media_type != "application/json" {
            return Err(ProviderError::Correlation(
                "native5 source media unsupported",
            ));
        }
        // Only this exact retained initial installation has the component-derived
        // startup extent. Ordinary Control/template objects keep their old cap.
        let maximum = if content == &self.coordinator.reference {
            super::super::coordinator::PACKET_NATIVE5_COORDINATOR_INSTALLATION_BYTES
        } else {
            super::super::coordinator::PACKET_CONNECTED_COORDINATOR_BYTES
        };
        let value = canonical::parse_json(bytes, maximum)?;
        if canonical::canonical_json(&value)? != bytes {
            return Err(ProviderError::Frame(
                "native5 source object canonical bytes",
            ));
        }
        if content == &self.coordinator.reference {
            return if bytes == self.coordinator.bytes.as_slice() {
                Ok(())
            } else {
                Err(ProviderError::Correlation(
                    "native5 installed coordinator changed",
                ))
            };
        }
        match value.get("schema").and_then(serde_json::Value::as_str) {
            Some("crucible/coordinator-initial/1") => self.connected.validate_body(bytes),
            Some("source-owned.packet-common-grant.v5") => {
                let _: super::super::common::PacketNative5CommonGrant =
                    serde_json::from_value(value).map_err(ContractError::from)?;
                Ok(())
            }
            Some("source-owned.packet-consumption.v1")
            | Some("source-owned.packet-consumption.v4") => {
                #[derive(serde::Deserialize)]
                #[serde(deny_unknown_fields)]
                struct Consumption {
                    schema: String,
                    operation: Id,
                    outputs: Vec<Id>,
                }
                let body: Consumption =
                    serde_json::from_value(value).map_err(ContractError::from)?;
                body.operation.validate()?;
                if !matches!(
                    body.schema.as_str(),
                    "source-owned.packet-consumption.v1" | "source-owned.packet-consumption.v4"
                ) || body.outputs.len() > 8
                    || body.outputs.windows(2).any(|pair| pair[0] >= pair[1])
                {
                    return Err(ProviderError::Correlation("native5 consumption population"));
                }
                for output in body.outputs {
                    output.validate()?;
                }
                Ok(())
            }
            _ => Err(ProviderError::Correlation(
                "native5 original source object kind",
            )),
        }
    }
}

#[cfg(test)]
pub(crate) fn controlled_native5_policy(
    selection: PacketControlSelection,
    coordinator: InstalledContent,
) -> Result<std::rc::Rc<Native5Policy>, ProviderError> {
    Ok(std::rc::Rc::new(Native5Policy::from_original_launch(
        selection,
        coordinator,
    )?))
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
#[path = "native5_policy/metadata_tests.rs"]
mod metadata_tests;

struct NativeOwnedMetadataPolicyView<'a>(&'a Native5Policy);

impl Serialize for NativeOwnedMetadataPolicyView<'_> {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        match self.0.protocol_metadata_limits {
            None => self
                .0
                .original_owned11_protocol_view()
                .serialize(serializer),
            Some(metadata) => (
                "source-private.native5-policy-owned-selected/13",
                metadata,
                self.0.original_owned11_protocol_view(),
            )
                .serialize(serializer),
        }
    }
}

impl Native5Policy {
    pub(crate) fn authenticate_startup_capture_snapshot_definition(
        &self,
    ) -> Result<(), ProviderError> {
        use super::native_snapshot::authenticate_native_owned13_snapshot_schema_data;
        if self.capture_allocation_selection != Some(super::capture_allocation::PacketNative5CaptureAllocationSelection::OriginalObserve12)
            || self.fresh_restore_allocation_selection().is_some()
            || !matches!(self.capture_profile, super::PacketNative5CaptureProfile::OwnedProtocol11 { .. })
            || self.selection.realization.bindings.len() != 1
        {
            return Err(ProviderError::Correlation("native startup Capture schema selection differs"));
        }
        let select = |formats: &[SchemaRef]| -> Result<(), ProviderError> {
            let mut found = false;
            for schema in formats {
                if schema.id.as_str() == "source-owned.packet-native-continuation/13" {
                    if found {
                        return Err(ProviderError::Correlation(
                            "duplicate startup Capture schema",
                        ));
                    }
                    authenticate_native_owned13_snapshot_schema_data(schema)?;
                    found = true;
                }
            }
            if !found {
                return Err(ProviderError::Correlation(
                    "startup Capture full schema absent",
                ));
            }
            Ok(())
        };
        select(&self.selection.provider.implementation.formats)?;
        select(
            &self.selection.realization.bindings[0]
                .compatibility
                .implementation
                .formats,
        )
    }

    pub(crate) fn authenticate_invocation_capture_snapshot_definition(
        &self,
    ) -> Result<(), ProviderError> {
        use super::native_snapshot::authenticate_native_owned14_snapshot_schema_data;
        if self.capture_allocation_selection != Some(super::capture_allocation::PacketNative5CaptureAllocationSelection::OriginalObserve12)
            || self.fresh_restore_allocation_selection() != Some(super::fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13)
            || !matches!(self.capture_profile, super::PacketNative5CaptureProfile::OwnedProtocol11 { .. })
            || self.selection.realization.bindings.len() != 1
        {
            return Err(ProviderError::Correlation("native invocation Capture schema selection differs"));
        }
        let select = |formats: &[SchemaRef]| -> Result<(), ProviderError> {
            let mut found = false;
            for schema in formats {
                if schema.id.as_str() == "source-owned.packet-native-continuation/14" {
                    if found {
                        return Err(ProviderError::Correlation(
                            "duplicate invocation Capture schema",
                        ));
                    }
                    authenticate_native_owned14_snapshot_schema_data(schema)?;
                    found = true;
                }
            }
            if !found {
                return Err(ProviderError::Correlation(
                    "invocation Capture full schema absent",
                ));
            }
            Ok(())
        };
        select(&self.selection.provider.implementation.formats)?;
        select(
            &self.selection.realization.bindings[0]
                .compatibility
                .implementation
                .formats,
        )
    }
}

mod settled;

mod settled17_reader;
pub(crate) use settled17_reader::{HistoricalNativePolicy17, read_native17_policy_root_data};

impl Native5Policy {
    // This reusable sequential window names the actual new adapter values.
    // It adds no retained allocation and does not price an opaque serializer S.
    pub(crate) const CONSTRUCTION_ADAPTER_SCRATCH_DATA: usize = std::mem::size_of::<Result<Native5PolicyData, ProviderError>>() // lower return
        + std::mem::size_of::<Result<Native5PolicyData, ProviderError>>() // match input
        + std::mem::size_of::<Native5PolicyData>() // Ok binding / moved DATA
        + std::mem::size_of::<Native5PolicyData>() // wrapper field initializer
        + std::mem::size_of::<Self>() // upper aggregate initializer
        + std::mem::size_of::<Self>() // owned Ok input
        + std::mem::size_of::<Result<Self, ProviderError>>() // outer initializer
        + std::mem::size_of::<Result<Self, ProviderError>>() // outer return
        + std::mem::size_of::<ProviderError>() // Err binding
        + std::mem::size_of::<ProviderError>() // owned Err input
        + std::mem::size_of::<&Self>() // immutable receiver
        + std::mem::size_of::<&Native5PolicyData>() // field loan
        + std::mem::size_of::<&Native5PolicyData>() // returned loan
        + std::mem::size_of::<&Native5PolicyData>(); // exhaustive observer root loan
}
