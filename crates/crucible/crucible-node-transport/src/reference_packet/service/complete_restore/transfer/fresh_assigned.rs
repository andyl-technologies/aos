//! Digests selected Prepare originals while retaining their completed-query binding.
//!
//! These helpers validate data shape only. The actual installed SDK mode and
//! Source action authenticate the completed query and keyed report separately.

use super::*;
use crate::reference_packet::service::fresh_restore_allocation::{
    PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING, policy::validate_prepare_binding_value,
};
use serde_json::Value;
use std::mem::size_of;

/// Hashes selected Prepare with only its own proof removed.
///
/// The full Fresh binding, assigned sequence and correlation remain committed.
/// This helper neither selects a codec nor authenticates a Source report MAC.
/// Existing assignment serialization banks remain separately admitted.
///
/// # Errors
/// Refuses missing or foreign binding data, another phase, unknown extensions,
/// an invalid baseline PrepareRestore body or an excessive canonical encoding.
pub fn complete_restore_fresh_prepare_assigned_request_digest(
    original: &Envelope,
    maximum_frame_bytes: usize,
) -> Result<[u8; 32], ProviderError> {
    authenticate_fresh_prepare_shape(original, true)?;
    let RequestBody::Begin(begin) = decode_request(original.method, &original.body)? else {
        return Err(refused());
    };
    if !matches!(
        begin.decoded_arguments()?,
        BeginArguments::PrepareRestore(_)
    ) {
        return Err(refused());
    }
    super::assigned_digest(
        original,
        PacketCompleteRestoreTransferPhase::Prepare.proof_extension(),
        maximum_frame_bytes,
    )
}

/// Hashes a correlated selected Prepare response with only its receipt removed.
///
/// # Errors
/// Refuses an invalid selected original, changed response correlation, unknown
/// response extensions or an excessive canonical encoding.
pub fn complete_restore_fresh_prepare_assigned_response_digest(
    original: &Envelope,
    response: &Envelope,
    maximum_frame_bytes: usize,
) -> Result<[u8; 32], ProviderError> {
    complete_restore_fresh_prepare_assigned_request_digest(original, maximum_frame_bytes)?;
    response.validate()?;
    original.matches_response(response)?;
    let receipt = PacketCompleteRestoreTransferPhase::Prepare.receipt_extension();
    if response.extensions.keys().any(|key| key != receipt) {
        return Err(refused());
    }
    super::assigned_digest(response, receipt, maximum_frame_bytes)
}

/// Returns extra borrowed grammar views for selected Prepare digest validation.
///
/// The legacy Begin decoding and canonical serialization phases keep their
/// existing full allocation rows. Compiler frames and recursive frames remain
/// separate; these terms name the new fixed binding/map/iterator work only.
pub fn complete_restore_fresh_prepare_digest_counter_scratch_data() -> usize {
    size_of::<(&Envelope, &Value, &serde_json::Map<String, Value>)>()
        + size_of::<std::collections::btree_map::Keys<'static, String, Value>>()
        + size_of::<std::array::IntoIter<&str, 2>>()
        + size_of::<std::str::Bytes<'static>>()
        + size_of::<std::slice::Iter<'static, u8>>()
        + size_of::<[usize; 3]>()
        + size_of::<u64>()
}

/// Checks unsigned reservation or signed digest syntax without cloning the DOM.
pub(crate) fn authenticate_fresh_prepare_shape(
    original: &Envelope,
    allow_proof: bool,
) -> Result<(), ProviderError> {
    original.validate()?;
    let phase = PacketCompleteRestoreTransferPhase::Prepare;
    if original.message != MessageKind::Request
        || original.method != Method::Begin
        || original.body.get("kind").and_then(Value::as_str) != Some("prepare_restore")
        || !original.extensions.contains_key(phase.request_extension())
        || original.extensions.keys().any(|key| {
            key != phase.request_extension()
                && key != PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING
                && !(allow_proof && key == phase.proof_extension())
        })
    {
        return Err(refused());
    }
    validate_prepare_binding_value(
        original
            .extensions
            .get(PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING)
            .ok_or_else(refused)?,
    )
}

fn refused() -> ProviderError {
    ProviderError::Correlation("selected Fresh assigned Prepare shape differs")
}

#[cfg(test)]
#[path = "fresh_assigned_tests.rs"]
mod tests;
