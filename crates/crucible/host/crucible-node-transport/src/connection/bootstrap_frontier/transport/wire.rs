//! Checks bootstrap wire correspondence without allocating or parsing method DTOs.

use super::*;
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA;
use base64::Engine;
use crucible_node_format::{Bytes, U64};
use serde_json::{Map, Value};

pub(super) fn authenticate_data(
    authority: &ConnectionAuthority,
    original: &Envelope,
    request: &PacketNativeImport18BootstrapRequest,
    proof: Option<&PacketNativeImport18BootstrapAckProof>,
) -> Result<(), ProviderError> {
    original.validate()?;
    request.validate_data()?;
    if original.message != MessageKind::Request
        || original.method != crate::envelope::Method::NativeImport18Bootstrap
        || original.sequence.get() != 2
        || original.session_id.0.as_ref() != Some(authority.session_id())
        || original.incarnation_id.0.as_ref() != Some(authority.incarnation_id())
        || original.request_id.0.is_none()
        || original.node_id.0.is_some()
        || original.execution_owner_id.0.is_some()
        || original.capture_owner_id.0.is_some()
        || original.operation_id.0.is_some()
    {
        return Err(refused());
    }
    roster(
        &original.body,
        &["schema", "recipe_identity", "initial_funding"],
    )?;
    exact(
        &original.body,
        "schema",
        NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA,
    )?;
    digest(&original.body, "recipe_identity", &request.recipe_identity)?;
    let row = original
        .body
        .get("initial_funding")
        .and_then(Value::as_object)
        .ok_or_else(refused)?;
    roster(
        row,
        &[
            "retained_requested_bytes",
            "maximum_simultaneous_transient_bytes",
            "declared_counter_scratch_bytes",
        ],
    )?;
    for (field, expected) in [
        (
            "retained_requested_bytes",
            request.initial_funding.retained_requested_bytes,
        ),
        (
            "maximum_simultaneous_transient_bytes",
            request.initial_funding.maximum_simultaneous_transient_bytes,
        ),
        (
            "declared_counter_scratch_bytes",
            request.initial_funding.declared_counter_scratch_bytes,
        ),
    ] {
        numeric(row, field, expected)?;
    }
    match proof {
        None if original.extensions.is_empty() => Ok(()),
        Some(proof) if original.extensions.len() == 1 => {
            proof.validate_data()?;
            let fields = original
                .extensions
                .get(NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF)
                .and_then(Value::as_object)
                .ok_or_else(refused)?;
            roster(fields, &["schema", "algorithm", "context_digest", "mac"])?;
            exact(fields, "schema", &proof.schema)?;
            exact(fields, "algorithm", &proof.algorithm)?;
            digest(fields, "context_digest", &proof.context_digest)?;
            digest(fields, "mac", &proof.mac)
        }
        _ => Err(refused()),
    }
}

fn roster(map: &Map<String, Value>, fields: &[&str]) -> Result<(), ProviderError> {
    if map.len() != fields.len() || fields.iter().any(|field| !map.contains_key(*field)) {
        return Err(refused());
    }
    Ok(())
}

fn exact(map: &Map<String, Value>, field: &str, expected: &str) -> Result<(), ProviderError> {
    if map.get(field).and_then(Value::as_str) != Some(expected) {
        return Err(refused());
    }
    Ok(())
}

fn digest(map: &Map<String, Value>, field: &str, expected: &Bytes) -> Result<(), ProviderError> {
    let mut encoded = [0u8; 44];
    let length = base64::engine::general_purpose::STANDARD_NO_PAD
        .encode_slice(expected.as_slice(), &mut encoded)
        .map_err(|_| refused())?;
    if map.get(field).and_then(Value::as_str).map(str::as_bytes) != Some(&encoded[..length]) {
        return Err(refused());
    }
    Ok(())
}

fn numeric(map: &Map<String, Value>, field: &str, expected: U64) -> Result<(), ProviderError> {
    let text = map.get(field).and_then(Value::as_str).ok_or_else(refused)?;
    if text.is_empty()
        || text.len() > 20
        || (text.len() > 1 && text.starts_with('0'))
        || !text.bytes().all(|byte| byte.is_ascii_digit())
        || text.parse::<u64>().ok() != Some(expected.get())
    {
        return Err(refused());
    }
    Ok(())
}
