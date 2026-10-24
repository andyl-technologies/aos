//! Borrows closed restore request/proof/receipt data without copying a DTO.
//!
//! Syntax does not prove the signed archive, actual Core target, mapping, boot
//! key, original request or installation. Those are the genuine issuer's duties.

use crate::reference_packet::service::complete_restore::*;
use crate::{
    ProviderError,
    envelope::{Envelope, MessageKind, Method},
};
use serde_json::{Map, Value};

pub(super) fn invalid() -> ProviderError {
    ProviderError::Correlation("complete restore borrowed grammar")
}
pub(super) fn object<'a>(
    value: &'a Value,
    keys: &[&str],
) -> Result<&'a Map<String, Value>, ProviderError> {
    let value = value.as_object().ok_or_else(invalid)?;
    if value.len() != keys.len() || keys.iter().any(|key| !value.contains_key(*key)) {
        return Err(invalid());
    }
    Ok(value)
}
pub(super) fn field<'a>(
    value: &'a Map<String, Value>,
    key: &str,
) -> Result<&'a Value, ProviderError> {
    value.get(key).ok_or_else(invalid)
}
pub(super) fn text<'a>(value: &'a Map<String, Value>, key: &str) -> Result<&'a str, ProviderError> {
    field(value, key)?.as_str().ok_or_else(invalid)
}
pub(super) fn integer(value: &Value) -> Result<u64, ProviderError> {
    let value = value.as_str().ok_or_else(invalid)?;
    if value.is_empty()
        || value.len() > 20
        || value.len() > 1 && value.starts_with('0')
        || !value.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(invalid());
    }
    value.parse().map_err(|_| invalid())
}
pub(super) fn identifier(value: &str) -> Result<(), ProviderError> {
    if value.len() > 128
        || !value
            .bytes()
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric())
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b':' | b'/' | b'-'))
    {
        return Err(invalid());
    }
    Ok(())
}
pub(super) fn hash(value: &Value, expected_domain: Option<&str>) -> Result<(), ProviderError> {
    let hash = object(value, &["algorithm", "domain", "digest"])?;
    let domain = text(hash, "domain")?;
    let digest = text(hash, "digest")?;
    if text(hash, "algorithm")? != "blake3-256"
        || domain.is_empty()
        || domain.len() > 128
        || !domain.is_ascii()
        || expected_domain.is_some_and(|expected| expected != domain)
        || digest.len() != 64
        || !digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(invalid());
    }
    Ok(())
}
pub(super) fn content(value: &Value) -> Result<(), ProviderError> {
    let content = object(value, &["hash", "length", "media_type"])?;
    hash(field(content, "hash")?, Some("cnp.blob.v1"))?;
    integer(field(content, "length")?)?;
    let media = text(content, "media_type")?;
    if media.is_empty() || media.len() > 128 || !media.bytes().all(|b| (0x20..=0x7e).contains(&b)) {
        return Err(invalid());
    }
    Ok(())
}
pub(super) fn digest(value: &Value) -> Result<(), ProviderError> {
    let encoded = value.as_str().ok_or_else(invalid)?;
    if encoded.len() != 43
        || !encoded
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_'))
        || !encoded.as_bytes().last().is_some_and(|b| {
            matches!(
                b,
                b'A' | b'E'
                    | b'I'
                    | b'M'
                    | b'Q'
                    | b'U'
                    | b'Y'
                    | b'c'
                    | b'g'
                    | b'k'
                    | b'o'
                    | b's'
                    | b'w'
                    | b'0'
                    | b'4'
                    | b'8'
            )
        })
    {
        return Err(invalid());
    }
    Ok(())
}
pub(super) fn request(value: &Value) -> Result<(), ProviderError> {
    let request = object(
        value,
        &[
            "schema",
            "archive_index",
            "capture_manifest",
            "owner_state",
            "journal",
            "source_runtime",
            "backend_implementation",
            "backend_schema",
            "archived_cut",
            "archived_ordinal",
            "target_world",
            "target_owner",
            "target_owner_binding",
            "target_activation",
            "target_generation",
            "target_owner_generation",
            "mapping",
            "nonce",
        ],
    )?;
    if text(request, "schema")? != PACKET_COMPLETE_RESTORE_FEATURE {
        return Err(invalid());
    }
    for key in [
        "archive_index",
        "capture_manifest",
        "owner_state",
        "journal",
        "source_runtime",
        "backend_implementation",
        "mapping",
    ] {
        content(field(request, key)?)?;
    }
    let schema = object(
        field(request, "backend_schema")?,
        &["id", "version", "definition", "extensions"],
    )?;
    identifier(text(schema, "id")?)?;
    if field(schema, "version")?
        .as_u64()
        .is_none_or(|n| n > u16::MAX as u64)
        || !field(schema, "extensions")?.is_object()
    {
        return Err(invalid());
    }
    content(field(schema, "definition")?)?;
    let cut = object(
        field(request, "archived_cut")?,
        &["time_ps", "microstep", "phase"],
    )?;
    integer(field(cut, "time_ps")?)?;
    integer(field(cut, "microstep")?)?;
    if field(cut, "phase")?.as_u64().is_none_or(|n| n > 3) {
        return Err(invalid());
    }
    for key in [
        "archived_ordinal",
        "target_generation",
        "target_owner_generation",
    ] {
        integer(field(request, key)?)?;
    }
    for key in ["target_world", "target_owner_binding"] {
        hash(field(request, key)?, None)?;
    }
    for key in ["target_owner", "target_activation"] {
        identifier(text(request, key)?)?;
    }
    digest(field(request, "nonce")?)?;
    crate::connection::serialized_credit(value, MAXIMUM_COMPLETE_RESTORE_REQUEST_BYTES)?;
    Ok(())
}
fn proof(value: &Value) -> Result<(), ProviderError> {
    let proof = object(value, &["schema", "algorithm", "context_digest", "mac"])?;
    if text(proof, "schema")? != PACKET_COMPLETE_RESTORE_PROOF_EXTENSION
        || text(proof, "algorithm")? != PACKET_COMPLETE_RESTORE_ALGORITHM
    {
        return Err(invalid());
    }
    for key in ["context_digest", "mac"] {
        digest(field(proof, key)?)?;
    }
    crate::connection::serialized_credit(value, MAXIMUM_COMPLETE_RESTORE_PROOF_BYTES)?;
    Ok(())
}
fn receipt(value: &Value) -> Result<(), ProviderError> {
    let receipt = object(
        value,
        &[
            "schema",
            "algorithm",
            "request_digest",
            "context_digest",
            "installed_mapping",
            "native_sequence",
            "assigned_response",
            "mac",
        ],
    )?;
    if text(receipt, "schema")? != PACKET_COMPLETE_RESTORE_RECEIPT_EXTENSION
        || text(receipt, "algorithm")? != PACKET_COMPLETE_RESTORE_ALGORITHM
    {
        return Err(invalid());
    }
    for key in [
        "request_digest",
        "context_digest",
        "assigned_response",
        "mac",
    ] {
        digest(field(receipt, key)?)?;
    }
    content(field(receipt, "installed_mapping")?)?;
    integer(field(receipt, "native_sequence")?)?;
    crate::connection::serialized_credit(value, MAXIMUM_COMPLETE_RESTORE_RECEIPT_BYTES)?;
    Ok(())
}

/// Validates historical11 syntax without retaining an unused live-issuer loan.
pub(crate) struct CompleteRestoreProjection;

impl CompleteRestoreProjection {
    pub(crate) fn from_envelope(envelope: &Envelope) -> Result<Self, ProviderError> {
        if envelope.method != Method::Begin
            || envelope.node_id.0.is_none()
            || envelope.request_id.0.is_none()
            || envelope
                .body
                .get("extensions")
                .and_then(Value::as_object)
                .is_none_or(|v| !v.is_empty())
        {
            return Err(invalid());
        }
        match envelope.message {
            MessageKind::Request if envelope.extensions.len() == 2 => {
                let request_value = envelope
                    .extensions
                    .get(PACKET_COMPLETE_RESTORE_FEATURE)
                    .ok_or_else(invalid)?;
                let proof_value = envelope
                    .extensions
                    .get(PACKET_COMPLETE_RESTORE_PROOF_EXTENSION)
                    .ok_or_else(invalid)?;
                request(request_value)?;
                proof(proof_value)?;
                Ok(Self)
            }
            MessageKind::Response if envelope.extensions.len() == 1 => {
                let value = envelope
                    .extensions
                    .get(PACKET_COMPLETE_RESTORE_RECEIPT_EXTENSION)
                    .ok_or_else(invalid)?;
                receipt(value)?;
                Ok(Self)
            }
            _ => Err(invalid()),
        }
    }
}
