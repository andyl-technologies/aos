//! Hashes actual assigned envelopes without removing correlation or sequence.

use super::*;

#[path = "fresh_assigned.rs"]
mod fresh;
use crate::{
    bodies::{BeginArguments, RequestBody, decode_request},
    envelope::{Envelope, MessageKind, Method},
};
pub(crate) use fresh::authenticate_fresh_prepare_shape;
pub use fresh::{
    complete_restore_fresh_prepare_assigned_request_digest,
    complete_restore_fresh_prepare_assigned_response_digest,
    complete_restore_fresh_prepare_digest_counter_scratch_data,
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
pub fn complete_restore_transfer_assigned_request_digest(
    original: &Envelope,
    phase: PacketCompleteRestoreTransferPhase,
    maximum_frame_bytes: usize,
) -> Result<[u8; 32], ProviderError> {
    original.validate()?;
    if original.method != Method::Begin
        || original.message != MessageKind::Request
        || !original.extensions.contains_key(phase.request_extension())
        || original
            .extensions
            .keys()
            .any(|key| key != phase.request_extension() && key != phase.proof_extension())
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
    assigned_digest(original, phase.proof_extension(), maximum_frame_bytes)
}

/// Hashes the actual correlated assigned response with only its receipt removed.
///
/// The caller provides its retained original request and actual response slot.
/// An empty receipt field or a caller-proposed sequence cannot replace that
/// ownership predicate; this helper checks data correspondence only.
///
/// # Errors
/// Refuses invalid envelopes, changed correlation or unknown response extensions.
pub fn complete_restore_transfer_assigned_response_digest(
    original: &Envelope,
    response: &Envelope,
    phase: PacketCompleteRestoreTransferPhase,
    maximum_frame_bytes: usize,
) -> Result<[u8; 32], ProviderError> {
    complete_restore_transfer_assigned_request_digest(original, phase, maximum_frame_bytes)?;
    response.validate()?;
    original.matches_response(response)?;
    if response
        .extensions
        .keys()
        .any(|key| key != phase.receipt_extension())
    {
        return Err(ProviderError::Correlation(
            "complete restore response extension",
        ));
    }
    assigned_digest(response, phase.receipt_extension(), maximum_frame_bytes)
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

/// Hashes a retained complete envelope including proof or receipt and sequence.
///
/// # Errors
/// Refuses invalid envelope data or an encoding beyond its admitted frame bound.
pub fn complete_restore_transfer_original_digest(
    original: &Envelope,
    maximum_frame_bytes: usize,
) -> Result<[u8; 32], ProviderError> {
    original.validate()?;
    Ok(*blake3::hash(&bounded_canonical(original, maximum_frame_bytes)?).as_bytes())
}
