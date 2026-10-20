//! Checks the explicitly selected inline artifact before native effect dispatch.

use super::*;
use crate::{
    bodies::RequestBody,
    connection::ReceivedBody,
    envelope::{Envelope, MessageKind},
    handshake::ConnectionAuthority,
    reference_packet::control::PacketControlSelection,
};

pub(crate) fn verify_selected_wire_data(
    selection: &PacketControlSelection,
    authority: &ConnectionAuthority,
    original: &Envelope,
    body: &ReceivedBody,
) -> Result<bool, ProviderError> {
    if let Some(value) = original
        .extensions
        .get(upload::PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE)
    {
        authenticate_restoration_activation_selection_data(selection, authority)?;
        crate::connection::serialized_credit(value, MAXIMUM_RESTORATION_ACTIVATION_ARTIFACT_BYTES)?;
        let artifact = upload::PacketRestorationActivationUploadArtifact::deserialize(value)
            .map_err(crucible_node_format::ContractError::from)?;
        artifact.validate_data()?;
        verify_selected_wire_header_data(selection, authority, original)?;
        let ReceivedBody::Request(body) = body else {
            return Err(invalid());
        };
        let RequestBody::BlobBegin(body) = body.as_ref() else {
            return Err(invalid());
        };
        if &body.content != artifact.request.content_ref_data() {
            return Err(invalid());
        }
        return Ok(true);
    }
    let Some(value) = original
        .extensions
        .get(PACKET_RESTORATION_ACTIVATION_FEATURE)
    else {
        return Ok(false);
    };
    authenticate_restoration_activation_selection_data(selection, authority)?;
    // The fixed selected artifact ingress is admitted before Child/receive.
    // Recount raw bounded geometry before creating this additional typed owner;
    // the endpoint independently retains and authenticates the actual phase.
    crate::connection::serialized_credit(value, MAXIMUM_RESTORATION_ACTIVATION_ARTIFACT_BYTES)?;
    let artifact = PacketRestorationActivationArtifact::deserialize(value)
        .map_err(crucible_node_format::ContractError::from)?;
    artifact.validate_data()?;
    if original.message != MessageKind::Request
        || original.extensions.len() != 1
        || original.method != artifact.request.phase.method()
        || original.node_id.0.as_ref() != Some(&artifact.request.scope.target.node)
        || original.execution_owner_id.0.as_ref() != Some(&artifact.request.scope.target.owner)
        || original.session_id.0.as_ref() != Some(authority.session_id())
        || original.incarnation_id.0.as_ref() != Some(authority.incarnation_id())
        || original.operation_id.0.is_some()
        || original.capture_owner_id.0.is_some()
    {
        return Err(invalid());
    }
    let command = match body {
        ReceivedBody::Request(body) => match body.as_ref() {
            RequestBody::Activate(body) => PacketRestorationActivationCommand::Arm(body.clone()),
            RequestBody::WorldActivate(body) => {
                PacketRestorationActivationCommand::WorldActivate(body.clone())
            }
            _ => return Err(invalid()),
        },
        _ => return Err(invalid()),
    };
    command.authenticate_request_data(&artifact.request)?;
    let target = &artifact.request.scope.target;
    let [owner] = selection.realization.owners.as_slice() else {
        return Err(invalid());
    };
    if target.prepared_token != selection.prepared_token
        || target.admission != selection.admission
        || target.transaction != selection.transaction
        || target.gate != selection.gate
        || target.world != selection.world
        || target.owner != owner.id
    {
        return Err(invalid());
    }
    authority.ensure_live()?;
    Ok(true)
}

/// Closes native ingress framing without constructing an artifact/context DTO.
///
/// The actual native boot moves the original into its sticky attempt before
/// deserializing or authenticating the MAC. Fixed pre-Child ingress covers the
/// full bounded raw/DOM owner independently of the untrusted signed row.
pub(crate) fn verify_selected_wire_header_data(
    selection: &PacketControlSelection,
    authority: &ConnectionAuthority,
    original: &Envelope,
) -> Result<bool, ProviderError> {
    let feature = if original
        .extensions
        .contains_key(PACKET_RESTORATION_ACTIVATION_FEATURE)
    {
        PACKET_RESTORATION_ACTIVATION_FEATURE
    } else if original
        .extensions
        .contains_key(upload::PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE)
    {
        upload::PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE
    } else {
        return Ok(false);
    };
    authenticate_restoration_activation_selection_data(selection, authority)?;
    let [binding] = selection.realization.bindings.as_slice() else {
        return Err(invalid());
    };
    let [owner] = selection.realization.owners.as_slice() else {
        return Err(invalid());
    };
    if original.message != MessageKind::Request
        || original.extensions.len() != 1
        || original.session_id.0.as_ref() != Some(authority.session_id())
        || original.incarnation_id.0.as_ref() != Some(authority.incarnation_id())
        || original.node_id.0.as_ref() != Some(&binding.compatibility.node_id)
        || original.execution_owner_id.0.as_ref() != Some(&owner.id)
        || original.request_id.0.is_none()
        || original.sequence.get() == 0
        || original.operation_id.0.is_some()
        || original.capture_owner_id.0.is_some()
        || original
            .body
            .get("extensions")
            .and_then(serde_json::Value::as_object)
            .is_none_or(|body| !body.is_empty())
        || (feature == PACKET_RESTORATION_ACTIVATION_FEATURE
            && !matches!(original.method, Method::Activate | Method::WorldActivate))
        || (feature == upload::PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE
            && original.method != Method::BlobBegin)
    {
        return Err(invalid());
    }
    let value = original.extensions.get(feature).ok_or_else(invalid)?;
    crate::connection::serialized_credit(value, MAXIMUM_RESTORATION_ACTIVATION_ARTIFACT_BYTES)?;
    let artifact = value
        .as_object()
        .filter(|value| {
            value.len() == 2 && value.contains_key("request") && value.contains_key("proof")
        })
        .ok_or_else(invalid)?;
    let request = artifact["request"].as_object().ok_or_else(invalid)?;
    let expected: &[&str] = if feature == PACKET_RESTORATION_ACTIVATION_FEATURE {
        &["schema", "phase", "scope", "native_allocation"]
    } else {
        &[
            "schema",
            "scope",
            "role",
            "coordinator",
            "manifest",
            "maximum_frame_bytes",
            "chunk_bytes",
            "maximum_requests",
            "native_allocation",
        ]
    };
    if request.len() != expected.len()
        || request.get("schema").and_then(serde_json::Value::as_str) != Some(feature)
    {
        return Err(invalid());
    }
    for key in expected {
        if !request.contains_key(*key) {
            return Err(invalid());
        }
    }
    authority.ensure_live()?;
    Ok(true)
}

pub(super) fn counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<&serde_json::Map<String, serde_json::Value>>() * 4
        + size_of::<Option<&serde_json::Map<String, serde_json::Value>>>() * 3
        + size_of::<Result<&serde_json::Map<String, serde_json::Value>, ProviderError>>() * 2
        + size_of::<Option<&serde_json::Value>>() * 2
        + size_of::<Result<&serde_json::Value, ProviderError>>()
        + size_of::<&[&str]>()
        + size_of::<[&str; 9]>()
        + size_of::<std::slice::Iter<'static, &'static str>>()
        + size_of::<Option<&str>>()
        + size_of::<&str>()
        + size_of::<Result<bool, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
}
