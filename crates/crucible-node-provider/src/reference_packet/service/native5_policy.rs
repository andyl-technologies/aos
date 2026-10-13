//! Owns the immutable source-five native wire verifier and complete codec view.
//!
//! Only the native service factory constructs this policy after its original
//! private launch and measured executable checks. Its portable view preserves
//! every frozen field; it grants no source capture or restoration permission.

use crucible_node_contract::*;
use serde::Serialize;

use super::super::{
    continuation_contracts::{
        PACKET_COMPLETE_LINEAGE_FEATURE, PACKET_NATIVE5_IMPLEMENTATION,
        complete_packet_ingress_schema,
    },
    control::PacketControlSelection,
    coordinator::PacketNative5CoordinatorInstallation,
    input::{PACKET_INPUT_FEATURE, PacketInputContext},
};
use crate::{
    ProviderError,
    bodies::RequestBody,
    connection::{BodySchemaVerifier, ReceivedBody, serialized_credit},
    envelope::{Envelope, MessageKind, Method},
    handshake::ConnectionAuthority,
    reference_service::InstalledContent,
};

#[derive(Serialize)]
pub(crate) struct Native5Policy {
    selection: PacketControlSelection,
    coordinator: InstalledContent,
    definition: ContentRef,
    connected: PacketNative5CoordinatorInstallation,
}

impl Native5Policy {
    pub(super) fn from_original_launch(
        selection: PacketControlSelection,
        coordinator: InstalledContent,
    ) -> Result<Self, ProviderError> {
        serialized_credit(&selection, 65_536)?;
        coordinator.reference.verify(coordinator.bytes.as_slice())?;
        let connected =
            PacketNative5CoordinatorInstallation::decode(coordinator.bytes.as_slice(), &selection)?;
        let schema = complete_packet_ingress_schema()?;
        if selection.provider.implementation.implementation_id.as_str()
            != PACKET_NATIVE5_IMPLEMENTATION
            || !selection.provider.implementation.formats.contains(&schema)
        {
            return Err(ProviderError::Correlation(
                "native5 source codec not installed",
            ));
        }
        let policy = Self {
            selection,
            coordinator,
            definition: schema.definition,
            connected,
        };
        serialized_credit(&policy.protocol_view(), 256 * 1024)?;
        Ok(policy)
    }

    pub(crate) fn protocol_view(&self) -> impl Serialize + '_ {
        self
    }

    pub(crate) fn validate_installation(
        &self,
        authority: &ConnectionAuthority,
    ) -> Result<(), ProviderError> {
        authority.ensure_live()?;
        self.connected.validate(&self.selection)?;
        self.coordinator
            .reference
            .verify(self.coordinator.bytes.as_slice())?;
        if self.selection.realization.bindings.len() != 1
            || self.selection.realization.owner_bindings.len() != 1
            || self.selection.realization.owners.len() != 1
            || self.selection.realization.descriptors.len() != 1
        {
            return Err(ProviderError::Correlation(
                "native5 complete local owner population",
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

impl BodySchemaVerifier for Native5Policy {
    fn verify(
        &self,
        authority: &ConnectionAuthority,
        envelope: &Envelope,
        received: &ReceivedBody,
    ) -> Result<(), ProviderError> {
        self.validate_installation(authority)?;
        if envelope
            .body
            .get("extensions")
            .is_some_and(|value| value.as_object().is_none_or(|values| !values.is_empty()))
        {
            return Err(ProviderError::Correlation(
                "native5 body extensions unsupported",
            ));
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
        let value = canonical::parse_json(
            bytes,
            super::super::coordinator::PACKET_CONNECTED_COORDINATOR_BYTES,
        )?;
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
