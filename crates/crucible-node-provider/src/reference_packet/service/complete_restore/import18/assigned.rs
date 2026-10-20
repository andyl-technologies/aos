//! Hashes exact import18 assignments without widening older extension guards.

use super::*;
use crate::{
    bodies::{BeginArguments, RequestBody, decode_request},
    envelope::{MessageKind, Method},
};

/// Hashes the full same assigned request after removing only its new phase proof.
///
/// The binding and inert request payload must both be present. The new proof
/// may be absent while the genuine SDK still owns its signing slot. Unknown
/// extensions and old phase proofs refuse. This DATA check issues no SDK slot,
/// current request, cut renewal, Source permission or native phase token.
///
/// # Errors
/// Refuses malformed/unrelated envelopes, another Begin kind, missing binding
/// or payload, any foreign extension or bounded serialization failure.
pub fn native_import18_assigned_request_digest(
    original: &Envelope,
    phase: PacketNativeImport18Phase,
    maximum_frame_bytes: usize,
) -> Result<[u8; 32], ProviderError> {
    original.validate()?;
    if original.method != Method::Begin
        || original.message != MessageKind::Request
        || !original.extensions.contains_key(phase.request_extension())
        || !original.extensions.contains_key(NATIVE_IMPORT18_EXTENSION)
        || original.extensions.keys().any(|key| {
            key != phase.request_extension()
                && key != NATIVE_IMPORT18_EXTENSION
                && key != phase.proof_extension()
        })
    {
        return Err(invalid());
    }
    let RequestBody::Begin(begin) = decode_request(original.method, &original.body)? else {
        return Err(invalid());
    };
    if !matches!(
        begin.decoded_arguments()?,
        BeginArguments::PrepareRestore(_)
    ) {
        return Err(invalid());
    }
    assigned(original, phase.proof_extension(), maximum_frame_bytes)
}

/// Hashes the same correlated Native17 response after removing only its new receipt.
///
/// The actual private publisher retains its once-only assignment and all partial
/// output before this helper. A matching digest creates no publication or lease.
///
/// # Errors
/// Refuses an unrelated original/response, foreign response extensions, missing
/// original proof or bounded canonical serialization failure.
pub fn native_import18_assigned_response_digest(
    original: &Envelope,
    response: &Envelope,
    phase: PacketNativeImport18Phase,
    maximum_frame_bytes: usize,
) -> Result<[u8; 32], ProviderError> {
    native_import18_assigned_request_digest(original, phase, maximum_frame_bytes)?;
    if !original.extensions.contains_key(phase.proof_extension()) {
        return Err(invalid());
    }
    response.validate()?;
    original.matches_response(response)?;
    if response
        .extensions
        .keys()
        .any(|key| key != phase.receipt_extension())
    {
        return Err(invalid());
    }
    assigned(response, phase.receipt_extension(), maximum_frame_bytes)
}

fn assigned(
    original: &Envelope,
    excluded: &str,
    maximum: usize,
) -> Result<[u8; 32], ProviderError> {
    let mut value = serde_json::to_value(original).map_err(ContractError::from)?;
    value
        .get_mut("extensions")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(invalid)?
        .remove(excluded);
    let bytes = bounded(&value, maximum)?;
    Ok(*blake3::hash(&bytes).as_bytes())
}
