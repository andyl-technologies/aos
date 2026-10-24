//! Closes observation framing without parsing a native artifact before custody.

use super::*;
use crate::{
    connection::ReceivedBody,
    envelope::{Envelope, MessageKind, Method},
    handshake::ConnectionAuthority,
    reference_packet::control::PacketControlSelection,
};
use serde_json::Value;

/// Validates borrowed selected framing before native typed artifact parsing.
///
/// # Errors
/// Refuses altered full selection, envelope routing, closed outer key sets,
/// fixed allowance/proof tags or the independently bounded inline extent.
pub(crate) fn verify_selected_wire_header_data(
    selection: &PacketControlSelection,
    authority: &ConnectionAuthority,
    original: &Envelope,
) -> Result<bool, ProviderError> {
    let Some(value) = original.extensions.get(PACKET_RESTORATION_OBSERVE_FEATURE) else {
        return Ok(false);
    };
    authenticate_restoration_observe_selection_data(selection, authority)?;
    let [binding] = selection.realization.bindings.as_slice() else {
        return Err(invalid());
    };
    let [owner] = selection.realization.owners.as_slice() else {
        return Err(invalid());
    };
    if original.message != MessageKind::Request
        || original.method != Method::Observe
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
            .and_then(Value::as_object)
            .is_none_or(|value| !value.is_empty())
    {
        return Err(invalid());
    }
    crate::connection::serialized_credit(value, MAXIMUM_RESTORATION_OBSERVE_ARTIFACT_BYTES)?;
    let artifact = value.as_object().ok_or_else(invalid)?;
    closed(artifact, &["request", "proof"])?;
    let request = artifact
        .get("request")
        .and_then(Value::as_object)
        .ok_or_else(invalid)?;
    closed(
        request,
        &[
            "schema",
            "scope",
            "world_original",
            "world_terminal",
            "maximum_items",
            "native_allocation",
        ],
    )?;
    if request.get("schema").and_then(Value::as_str) != Some(PACKET_RESTORATION_OBSERVE_FEATURE)
        || request.get("maximum_items").and_then(Value::as_str) != Some("1")
    {
        return Err(invalid());
    }
    let proof = artifact
        .get("proof")
        .and_then(Value::as_object)
        .ok_or_else(invalid)?;
    closed(proof, &["schema", "algorithm", "context_digest", "mac"])?;
    if proof.get("schema").and_then(Value::as_str)
        != Some("source-owned.packet-restoration-observe-proof/1")
        || proof.get("algorithm").and_then(Value::as_str) != Some("blake3-256-mac")
    {
        return Err(invalid());
    }
    authority.ensure_live()?;
    Ok(true)
}

// The Controller path already owns its sticky assigned original before this
// additional validation. Native calls ONLY the borrowed header helper above;
// its own once boot slot owns the raw original before the first Deserialize.
/// Validates the already retained Controller artifact and ordinary body.
///
/// # Errors
/// Refuses malformed bounded artifact data, wrong typed body or any changed
/// baseline/immutable target field. A match issues no native observation.
pub(crate) fn verify_selected_wire_data(
    selection: &PacketControlSelection,
    authority: &ConnectionAuthority,
    original: &Envelope,
    received: &ReceivedBody,
) -> Result<bool, ProviderError> {
    if !verify_selected_wire_header_data(selection, authority, original)? {
        return Ok(false);
    }
    let artifact = PacketRestorationObservationArtifact::deserialize(
        original
            .extensions
            .get(PACKET_RESTORATION_OBSERVE_FEATURE)
            .ok_or_else(invalid)?,
    )
    .map_err(crucible_node_format::ContractError::from)?;
    artifact.validate_data()?;
    let ReceivedBody::Request(body) = received else {
        return Err(invalid());
    };
    let crate::bodies::RequestBody::Observe(body) = body.as_ref() else {
        return Err(invalid());
    };
    artifact.request.authenticate_body_data(body)?;
    let target = &artifact.request.scope.target;
    let [owner] = selection.realization.owners.as_slice() else {
        return Err(invalid());
    };
    if target.session != *authority.session_id()
        || target.incarnation != *authority.incarnation_id()
        || original.node_id.0.as_ref() != Some(&target.node)
        || target.owner != owner.id
        || original.execution_owner_id.0.as_ref() != Some(&target.owner)
        || target.prepared_token != selection.prepared_token
        || target.admission != selection.admission
        || target.transaction != selection.transaction
        || target.gate != selection.gate
        || target.world != selection.world
    {
        return Err(invalid());
    }
    authority.ensure_live()?;
    Ok(true)
}

fn closed(value: &serde_json::Map<String, Value>, expected: &[&str]) -> Result<(), ProviderError> {
    if value.len() != expected.len() {
        return Err(invalid());
    }
    for key in expected {
        if !value.contains_key(*key) {
            return Err(invalid());
        }
    }
    Ok(())
}

pub(super) fn counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<&ReceivedBody>()
        + size_of::<&crate::bodies::RequestBody>()
        + size_of::<&crate::bodies::ObserveRequest>()
        + size_of::<&PacketRestorationActivationScope>()
        + 3 * size_of::<&serde_json::Map<String, Value>>()
        + size_of::<Option<&serde_json::Map<String, Value>>>()
        + size_of::<Option<&Value>>()
        + size_of::<Option<&str>>()
        + size_of::<[&str; 2]>()
        + size_of::<[&str; 4]>()
        + size_of::<[&str; 6]>()
        + size_of::<&[&str]>()
        + size_of::<std::slice::Iter<'static, &'static str>>()
        + size_of::<Result<bool, ProviderError>>()
        + size_of::<Result<&serde_json::Map<String, Value>, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<&Envelope>()
        + size_of::<&PacketControlSelection>()
        + size_of::<&ConnectionAuthority>()
        + size_of::<&crucible_node_format::NodeBinding>()
        + size_of::<&crucible_node_format::OwnerRef>()
}
