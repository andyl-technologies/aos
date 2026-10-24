//! Borrows the closed bootstrap envelope, request and sole proof before decoding.
//!
//! This structural DATA walk allocates nothing. It narrows arbitrary strict JSON
//! to the defining bounded DTO grammar before any serde clone or diagnostic.
//! Numeric validity, digest decoding, original correspondence, SDK assignment,
//! cryptographic verification and resource permission remain separate checks.

use super::*;
use crate::reference_packet::service::complete_restore::PACKET_COMPLETE_RESTORE_ALGORITHM;
use crate::reference_packet::service::complete_restore::import18::bootstrap_ack::{
    NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF, NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA,
};
use crucible_node_format::values::MAX_ID_BYTES;
use serde_json::{Map, Value};

/// Borrows the two closed nested DTO values in the same original strict tree.
pub(super) struct Closed<'a> {
    /// Borrows the exact closed body without cloning its tree.
    pub(super) request: &'a Value,
    /// Borrows the sole closed proof extension in the same tree.
    pub(super) proof: &'a Value,
}

/// Checks complete field rosters and bounded decoded leaves without cloning.
///
/// # Errors
/// Refuses another method/kind, unknown or missing fields, non-object structure,
/// another schema/algorithm, non-string numeric DATA or oversized typed leaves.
pub(super) fn inspect_data(value: &Value) -> Result<Closed<'_>, ProviderError> {
    let root = object(
        value,
        &[
            "protocol",
            "message",
            "session_id",
            "incarnation_id",
            "node_id",
            "execution_owner_id",
            "capture_owner_id",
            "request_id",
            "operation_id",
            "sequence",
            "method",
            "body",
            "extensions",
        ],
    )?;
    exact(root, "protocol", "CNP/1")?;
    exact(root, "message", "request")?;
    exact(root, "method", "native_import18_bootstrap")?;
    for field in [
        "session_id",
        "incarnation_id",
        "node_id",
        "execution_owner_id",
        "capture_owner_id",
        "request_id",
        "operation_id",
    ] {
        let value = root.get(field).ok_or_else(refused)?;
        if !value.is_null() {
            text(value, MAX_ID_BYTES)?;
        }
    }
    text(root.get("sequence").ok_or_else(refused)?, 20)?;

    let request = root.get("body").ok_or_else(refused)?;
    let body = object(request, &["schema", "recipe_identity", "initial_funding"])?;
    exact(body, "schema", NATIVE_IMPORT18_BOOTSTRAP_REQUEST_SCHEMA)?;
    width(body, "recipe_identity", 43)?;
    let initial = object(
        body.get("initial_funding").ok_or_else(refused)?,
        &[
            "retained_requested_bytes",
            "maximum_simultaneous_transient_bytes",
            "declared_counter_scratch_bytes",
        ],
    )?;
    for value in initial.values() {
        text(value, 20)?;
    }

    let extensions = object(
        root.get("extensions").ok_or_else(refused)?,
        &[NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF],
    )?;
    let proof = extensions
        .get(NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF)
        .ok_or_else(refused)?;
    let fields = object(proof, &["schema", "algorithm", "context_digest", "mac"])?;
    exact(fields, "schema", NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF)?;
    exact(fields, "algorithm", PACKET_COMPLETE_RESTORE_ALGORITHM)?;
    width(fields, "context_digest", 43)?;
    width(fields, "mac", 43)?;
    Ok(Closed { request, proof })
}

fn object<'a>(value: &'a Value, fields: &[&str]) -> Result<&'a Map<String, Value>, ProviderError> {
    let map = value.as_object().ok_or_else(refused)?;
    if map.len() != fields.len() || fields.iter().any(|field| !map.contains_key(*field)) {
        return Err(refused());
    }
    Ok(map)
}

fn text(value: &Value, maximum: usize) -> Result<&str, ProviderError> {
    let text = value.as_str().ok_or_else(refused)?;
    if text.is_empty() || text.len() > maximum {
        return Err(refused());
    }
    Ok(text)
}

fn exact(map: &Map<String, Value>, field: &str, expected: &str) -> Result<(), ProviderError> {
    if map.get(field).and_then(Value::as_str) != Some(expected) {
        return Err(refused());
    }
    Ok(())
}

fn width(map: &Map<String, Value>, field: &str, expected: usize) -> Result<(), ProviderError> {
    if text(map.get(field).ok_or_else(refused)?, expected)?.len() != expected {
        return Err(refused());
    }
    Ok(())
}

/// Names actual borrowed object/field walks and fixed structural controls.
pub(super) fn counter_scratch_data() -> usize {
    size_of::<Closed<'static>>()
        + size_of::<Result<Closed<'static>, ProviderError>>()
        + size_of::<&Value>() * 5
        + size_of::<&Map<String, Value>>() * 5
        + size_of::<[&str; 13]>()
        + size_of::<[&str; 7]>()
        + size_of::<[&str; 3]>() * 2
        + size_of::<[&str; 4]>()
        + size_of::<[&str; 1]>()
        + size_of::<std::array::IntoIter<&str, 7>>()
        + size_of::<std::slice::Iter<'static, &'static str>>()
        + size_of::<serde_json::map::Values<'static>>()
        + size_of::<&str>() * 3
        + size_of::<&[&str]>()
        + size_of::<Option<&str>>()
        + size_of::<Option<&Value>>()
        + size_of::<usize>() * 3
        + size_of::<Result<(), ProviderError>>() * 4
}
