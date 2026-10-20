//! Hashes actual assigned envelopes without removing correlation or sequence.

use super::*;
use crate::{
    bodies::{BeginArguments, RequestBody, decode_request},
    envelope::{Envelope, MessageKind, Method},
};

/// Hashes an actual assigned PrepareRestore request with only its proof removed.
///
/// The original envelope is borrowed without mutation. The enclosing SDK must
/// retain its original slot, assigned sequence, cut and buffers before signing.
/// These bounded serialization allocations remain charged source scratch.
///
/// # Errors
/// Refuses an invalid or unrelated request, absent request extension, unknown
/// envelope extension or canonical serialization failure.
pub fn complete_restore_assigned_request_digest(
    original: &Envelope,
    maximum_frame_bytes: usize,
) -> Result<[u8; 32], ProviderError> {
    original.validate()?;
    if original.method != Method::Begin
        || original.message != MessageKind::Request
        || !original
            .extensions
            .contains_key(PACKET_COMPLETE_RESTORE_FEATURE)
        || original.extensions.keys().any(|key| {
            key != PACKET_COMPLETE_RESTORE_FEATURE && key != PACKET_COMPLETE_RESTORE_PROOF_EXTENSION
        })
    {
        return Err(ProviderError::Correlation(
            "complete restore assigned request shape",
        ));
    }
    let RequestBody::Begin(begin) = decode_request(original.method, &original.body)? else {
        return Err(ProviderError::Correlation(
            "complete restore assigned Begin absent",
        ));
    };
    if !matches!(
        begin.decoded_arguments()?,
        BeginArguments::PrepareRestore(_)
    ) {
        return Err(ProviderError::Correlation("complete restore assigned kind"));
    }
    assigned_digest(
        original,
        PACKET_COMPLETE_RESTORE_PROOF_EXTENSION,
        maximum_frame_bytes,
    )
}

/// Hashes the actual correlated assigned response with only its receipt removed.
///
/// The caller provides its retained original request and actual response slot.
/// An empty receipt field or a caller-proposed sequence cannot replace that
/// ownership predicate; this helper checks data correspondence only.
///
/// # Errors
/// Refuses invalid envelopes, changed correlation or unknown response extensions.
pub fn complete_restore_assigned_response_digest(
    original: &Envelope,
    response: &Envelope,
    maximum_frame_bytes: usize,
) -> Result<[u8; 32], ProviderError> {
    complete_restore_assigned_request_digest(original, maximum_frame_bytes)?;
    response.validate()?;
    original.matches_response(response)?;
    if response
        .extensions
        .keys()
        .any(|key| key != PACKET_COMPLETE_RESTORE_RECEIPT_EXTENSION)
    {
        return Err(ProviderError::Correlation(
            "complete restore response extension",
        ));
    }
    assigned_digest(
        response,
        PACKET_COMPLETE_RESTORE_RECEIPT_EXTENSION,
        maximum_frame_bytes,
    )
}

fn assigned_digest(
    original: &Envelope,
    excluded_key: &str,
    maximum_frame_bytes: usize,
) -> Result<[u8; 32], ProviderError> {
    let mut value =
        serde_json::to_value(original).map_err(crucible_node_format::ContractError::from)?;
    value
        .get_mut("extensions")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or(ProviderError::Correlation(
            "complete restore extension map absent",
        ))?
        .remove(excluded_key);
    let canonical = canonical::canonical_json(&value)?;
    if canonical.len() > maximum_frame_bytes {
        return Err(ProviderError::ResourceExhausted(
            "complete restore assigned frame extent",
        ));
    }
    Ok(*blake3::hash(&canonical).as_bytes())
}
