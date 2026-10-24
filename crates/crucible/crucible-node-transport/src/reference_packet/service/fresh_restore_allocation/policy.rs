//! Checks the installed fresh13 field grammar without decoding owned DTOs.
//!
//! Full schema definitions are constructed only at installation. Per-frame
//! acceptance borrows selected feature/key names and existing scalar values;
//! it does not authenticate a report key or issue startup/allocation rights.

use crucible_source_birth_data::profile::reference_packet::service::fresh_restore_allocation::policy::{
    refused,
};

pub(crate) use crucible_source_birth_data::profile::reference_packet::service::fresh_restore_allocation::policy::{
    selected_schemas,
    validate_selection_content,
};

use super::*;
use crate::{
    bodies::{MethodResult, RequestBody, ResponseShape},
    connection::ReceivedBody,
    envelope::{Envelope, MessageKind, Method},
    handshake::ConnectionAuthority,
    reference_packet::control::PacketControlSelection,
};
use serde_json::Value;

pub(crate) fn validate_selection_negotiation(
    authority: &ConnectionAuthority,
) -> Result<(), ProviderError> {
    if !authority
        .selected_features()
        .iter()
        .any(|feature| feature.as_str() == PACKET_FRESH_RESTORE_ALLOCATION_FEATURE)
        || [
            PACKET_FRESH_RESTORE_ALLOCATION_QUERY,
            PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING,
        ]
        .iter()
        .any(|key| !authority.envelope_extensions().contains(*key))
    {
        return Err(refused());
    }
    authority.ensure_live()
}

pub(crate) fn verify_envelope(
    selection: &PacketControlSelection,
    authority: &ConnectionAuthority,
    envelope: &Envelope,
    received: &ReceivedBody,
) -> Result<bool, ProviderError> {
    let query = envelope
        .extensions
        .contains_key(PACKET_FRESH_RESTORE_ALLOCATION_QUERY);
    let binding = envelope
        .extensions
        .get(PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING);
    let receipt = envelope
        .body
        .get("extensions")
        .and_then(Value::as_object)
        .and_then(|extensions| extensions.get(PACKET_FRESH_RESTORE_ALLOCATION_RECEIPT));
    if !query && binding.is_none() && receipt.is_none() {
        return Ok(false);
    }
    validate_selection_negotiation(authority)?;
    let [installed] = selection.realization.bindings.as_slice() else {
        return Err(refused());
    };
    if envelope.session_id.0.as_ref() != Some(&installed.authority.session_id)
        || envelope.incarnation_id.0.as_ref() != Some(&installed.authority.incarnation_id)
        || envelope.node_id.0.as_ref() != Some(&installed.compatibility.node_id)
        || envelope.execution_owner_id.0.as_ref()
            != Some(&installed.compatibility.execution_owner.id)
        || envelope.capture_owner_id.0.is_some()
        || envelope.operation_id.0.is_some()
        || envelope.request_id.0.is_none()
    {
        return Err(refused());
    }
    if query {
        crate::connection::authenticate_original_report_query_header_data(
            selection,
            super::super::report_startup::PacketNativeReportStartupPurpose::FreshCompletedAdmit13,
            envelope,
        )?;
        if !matches!(received, ReceivedBody::Request(request) if matches!(request.as_ref(), RequestBody::Observe(_)))
        {
            return Err(refused());
        }
        return Ok(true);
    }
    if let Some(binding) = binding {
        if envelope.message != MessageKind::Request
            || envelope.method != Method::Begin
            || receipt.is_some()
            || envelope.extensions.len() != 3
        {
            return Err(refused());
        }
        validate_prepare_binding_value(binding)?;
        // The unchanged transfer verifier must still check its own exact proof.
        return Ok(false);
    }
    if envelope.message != MessageKind::Response
        || envelope.method != Method::Observe
        || !envelope.extensions.is_empty()
        || envelope
            .body
            .get("extensions")
            .and_then(Value::as_object)
            .is_none_or(|v| v.len() != 1)
    {
        return Err(refused());
    }
    let ReceivedBody::Response(response) = received else {
        return Err(refused());
    };
    let ResponseShape::Completed { .. } = &response.shape else {
        return Err(refused());
    };
    let Some(MethodResult::Observe(result)) = &response.result else {
        return Err(refused());
    };
    if !result.observations.is_empty() || result.next_sequence.get() != 0 || !result.complete {
        return Err(refused());
    }
    let receipt = receipt
        .ok_or_else(refused)?
        .as_object()
        .ok_or_else(refused)?;
    if receipt.len() != 2
        || receipt.get("schema").and_then(Value::as_str)
            != Some(PACKET_FRESH_RESTORE_ALLOCATION_RECEIPT)
    {
        return Err(refused());
    }
    validate_allocation_reference_value(receipt.get("allocation").ok_or_else(refused)?)?;
    Ok(true)
}

pub(crate) fn contains_selected_data(envelope: &Envelope) -> bool {
    envelope
        .extensions
        .contains_key(PACKET_FRESH_RESTORE_ALLOCATION_QUERY)
        || envelope
            .extensions
            .contains_key(PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING)
        || envelope
            .body
            .get("extensions")
            .and_then(Value::as_object)
            .is_some_and(|v| v.contains_key(PACKET_FRESH_RESTORE_ALLOCATION_RECEIPT))
}

pub(crate) fn validate_prepare_binding_value(value: &Value) -> Result<(), ProviderError> {
    let object = value.as_object().ok_or_else(refused)?;
    if object.len() != 4
        || object.get("schema").and_then(Value::as_str)
            != Some(PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING)
    {
        return Err(refused());
    }
    for key in ["assigned_query", "completed_query_response"] {
        encoded_digest(object.get(key).ok_or_else(refused)?)?;
    }
    validate_allocation_reference_value(object.get("allocation").ok_or_else(refused)?)
}

fn encoded_digest(value: &Value) -> Result<(), ProviderError> {
    let value = value.as_str().ok_or_else(refused)?;
    if value.len() != 43
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
    {
        return Err(refused());
    }
    Ok(())
}

pub(crate) fn validate_allocation_reference_value(value: &Value) -> Result<(), ProviderError> {
    let object = value.as_object().ok_or_else(refused)?;
    let hash = object
        .get("hash")
        .and_then(Value::as_object)
        .ok_or_else(refused)?;
    let length = object
        .get("length")
        .and_then(Value::as_str)
        .ok_or_else(refused)?;
    let parsed = length.parse::<u64>().map_err(|_| refused())?;
    if object.len() != 3
        || hash.len() != 3
        || hash.get("algorithm").and_then(Value::as_str) != Some("blake3-256")
        || hash.get("domain").and_then(Value::as_str) != Some("cnp.blob.v1")
        || hash
            .get("digest")
            .and_then(Value::as_str)
            .is_none_or(|digest| {
                digest.len() != 64
                    || !digest
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            })
        || object.get("media_type").and_then(Value::as_str)
            != Some(PACKET_FRESH_RESTORE_ALLOCATION_MEDIA)
        || parsed == 0
        || parsed > MAXIMUM_FRESH_RESTORE_ALLOCATION_REPORT_BYTES as u64
        || (length.len() > 1 && length.starts_with('0'))
    {
        return Err(refused());
    }
    Ok(())
}
