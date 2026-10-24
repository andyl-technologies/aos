//! Checks the separately negotiated17 wire family beneath retained originals.
//!
//! The native receiver uses only borrowed closed header checks after its actual
//! raw-first slot is installed. Controller checks may decode the artifact
//! beneath its already retained assigned original; no MAC or scope is issued.

use super::*;
use crate::connection::ReceivedBody;
use crate::handshake::ConnectionAuthority;
use crate::reference_packet::control::PacketControlSelection;
use serde_json::Value;

pub(crate) fn verify_selected_wire_header_data(
    selection: &PacketControlSelection,
    authority: &ConnectionAuthority,
    original: &Envelope,
) -> Result<bool, ProviderError> {
    let Some(value) = original.extensions.get(RESTORED_INPUT_REACTIVE17_FEATURE) else {
        return verify_selected_response_header_data(selection, authority, original);
    };
    authenticate_restored_input_reactive17_selection_data(selection, authority)?;
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
        || original.capture_owner_id.0.is_some()
        || original.request_id.0.is_none()
        || original.sequence.get() == 0
        || !matches!(
            original.method,
            Method::Input
                | Method::Begin
                | Method::Poll
                | Method::Retire
                | Method::Observe
                | Method::BlobBegin
                | Method::BlobChunk
                | Method::BlobFinish
        )
        || matches!(original.method, Method::Begin | Method::Poll)
            != original.operation_id.0.is_some()
        || !empty(original.body.get("extensions"))
    {
        return Err(invalid());
    }
    crate::connection::serialized_credit(value, MAXIMUM_RESTORED_INPUT_REACTIVE17_ARTIFACT_BYTES)?;
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
            "command",
            "scope",
            "first_observation",
            "current_record",
            "current_model",
            "history_prefix",
            "history_next_sequence",
            "native_allocation",
        ],
    )?;
    let proof = artifact
        .get("proof")
        .and_then(Value::as_object)
        .ok_or_else(invalid)?;
    closed(proof, &["schema", "algorithm", "context_digest", "mac"])?;
    if request.get("schema").and_then(Value::as_str) != Some(REQUEST_SCHEMA)
        || proof.get("schema").and_then(Value::as_str) != Some(PROOF_SCHEMA)
        || proof.get("algorithm").and_then(Value::as_str) != Some("blake3-256-mac")
    {
        return Err(invalid());
    }
    authority.ensure_live()?;
    Ok(true)
}

pub(crate) fn verify_selected_wire_data(
    selection: &PacketControlSelection,
    authority: &ConnectionAuthority,
    original: &Envelope,
    received: &ReceivedBody,
) -> Result<bool, ProviderError> {
    if original.message == MessageKind::Request
        && verify_selected_wire_header_data(selection, authority, original)?
    {
        let artifact: PacketRestoredInputReactive17Artifact = serde::Deserialize::deserialize(
            original
                .extensions
                .get(RESTORED_INPUT_REACTIVE17_FEATURE)
                .ok_or_else(invalid)?,
        )
        .map_err(crucible_node_format::ContractError::from)?;
        artifact.validate_data()?;
        artifact.request.authenticate_assigned_data(original)?;
        if !matches!(received, ReceivedBody::Request(_)) {
            return Err(invalid());
        }
        let target = &artifact.request.scope.target;
        if target.session != *authority.session_id()
            || target.incarnation != *authority.incarnation_id()
            || original.node_id.0.as_ref() != Some(&target.node)
            || original.execution_owner_id.0.as_ref() != Some(&target.owner)
            || target.prepared_token != selection.prepared_token
            || target.admission != selection.admission
            || target.transaction != selection.transaction
            || target.gate != selection.gate
            || target.world != selection.world
        {
            return Err(invalid());
        }
        return Ok(true);
    }
    // The Connection has already matched this response to its retained actual
    // original and required that original's distinct Input17 request class.
    // This only selects the new typed result-extension shape;
    // Source separately authenticates actual postproof and SDK currentness.
    let Some(extensions) = original.body.get("extensions").and_then(Value::as_object) else {
        return Ok(false);
    };
    let Some(value) = extensions.get(RESTORED_INPUT_REACTIVE17_FEATURE) else {
        return Ok(false);
    };
    if !verify_selected_response_header_data(selection, authority, original)? {
        return Err(invalid());
    }
    if original.message != MessageKind::Response
        || original.method != Method::Input
        || !original.extensions.is_empty()
        || extensions.len() != 1
        || original.body.get("status").and_then(Value::as_str) != Some("completed")
        || original.body.get("operation_state").and_then(Value::as_str) != Some("completed")
        || !matches!(received,ReceivedBody::Response(body) if matches!(body.result.as_ref(),Some(MethodResult::Input(_))))
    {
        return Err(invalid());
    }
    let checkpoint: PacketRestoredInputReactive17PostCheckpointData =
        serde::Deserialize::deserialize(value)
            .map_err(crucible_node_format::ContractError::from)?;
    checkpoint.validate_data()?;
    authority.ensure_live()?;
    Ok(true)
}

fn verify_selected_response_header_data(
    selection: &PacketControlSelection,
    authority: &ConnectionAuthority,
    original: &Envelope,
) -> Result<bool, ProviderError> {
    let Some(extensions) = original.body.get("extensions").and_then(Value::as_object) else {
        return Ok(false);
    };
    let Some(value) = extensions.get(RESTORED_INPUT_REACTIVE17_FEATURE) else {
        return Ok(false);
    };
    authenticate_restored_input_reactive17_selection_data(selection, authority)?;
    let [binding] = selection.realization.bindings.as_slice() else {
        return Err(invalid());
    };
    let [owner] = selection.realization.owners.as_slice() else {
        return Err(invalid());
    };
    if original.message != MessageKind::Response
        || original.method != Method::Input
        || !original.extensions.is_empty()
        || extensions.len() != 1
        || original.body.len() != 4
        || original.session_id.0.as_ref() != Some(authority.session_id())
        || original.incarnation_id.0.as_ref() != Some(authority.incarnation_id())
        || original.node_id.0.as_ref() != Some(&binding.compatibility.node_id)
        || original.execution_owner_id.0.as_ref() != Some(&owner.id)
        || original.capture_owner_id.0.is_some()
        || original.operation_id.0.is_some()
        || original.request_id.0.is_none()
        || original.sequence.get() == 0
        || original.body.get("status").and_then(Value::as_str) != Some("completed")
        || original.body.get("operation_state").and_then(Value::as_str) != Some("completed")
    {
        return Err(invalid());
    }
    let checkpoint = value.as_object().ok_or_else(invalid)?;
    closed(checkpoint, &["schema", "current_record", "current_model"])?;
    if checkpoint.get("schema").and_then(Value::as_str)
        != Some("source-owned.packet-restored-input-reactive-post-checkpoint/17")
    {
        return Err(invalid());
    }
    for field in ["current_record", "current_model"] {
        let reference = checkpoint
            .get(field)
            .and_then(Value::as_object)
            .ok_or_else(invalid)?;
        closed(reference, &["hash", "length", "media_type"])?;
        let hash = reference
            .get("hash")
            .and_then(Value::as_object)
            .ok_or_else(invalid)?;
        closed(hash, &["algorithm", "domain", "digest"])?;
        let length = reference
            .get("length")
            .and_then(Value::as_str)
            .ok_or_else(invalid)?;
        if reference.get("media_type").and_then(Value::as_str) != Some("application/json")
            || hash.get("algorithm").and_then(Value::as_str) != Some("blake3-256")
            || hash.get("domain").and_then(Value::as_str) != Some("cnp.blob.v1")
            || hash
                .get("digest")
                .and_then(Value::as_str)
                .is_none_or(|digest| {
                    digest.len() != 64
                        || !digest
                            .bytes()
                            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                })
            || length.is_empty()
            || length.starts_with('0')
            || length.len() > 20
            || length
                .parse::<u64>()
                .ok()
                .is_none_or(|length| length == 0 || length > 65_536)
        {
            return Err(invalid());
        }
    }
    if checkpoint.get("current_record") == checkpoint.get("current_model") {
        return Err(invalid());
    }
    authority.ensure_live()?;
    Ok(true)
}

fn closed(value: &serde_json::Map<String, Value>, fields: &[&str]) -> Result<(), ProviderError> {
    if value.len() != fields.len() || fields.iter().any(|name| !value.contains_key(*name)) {
        return Err(invalid());
    }
    Ok(())
}

fn empty(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_object)
        .is_some_and(|value| value.is_empty())
}
