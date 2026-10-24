//! Computes inert domain-separated observation proof and common-scope data.

use super::*;
use crate::envelope::{Envelope, MessageKind};
use crucible_node_format::{ContractError, canonical};

#[derive(Serialize)]
pub(super) struct ProofView<'a> {
    schema: &'a str,
    algorithm: &'a str,
    context_digest: &'a str,
    mac: &'a str,
}

const ALGORITHM: &str = "blake3-256-mac";
const PROOF_SCHEMA: &str = "source-owned.packet-restoration-observe-proof/1";
const KEY_DOMAIN: &str = "source-owned.packet-restoration-observe-key/1";

/// Hashes the exact phase context without constructing proof or MAC owners.
///
/// # Errors
/// Refuses invalid or oversized context data or failed canonical construction.
pub fn restoration_observe_context_digest_data(
    context: &PacketRestorationObservationContext,
) -> Result<[u8; 32], ProviderError> {
    context.validate_data()?;
    Ok(*blake3::hash(&bounded(context)?).as_bytes())
}

/// Counts the exact closed encoded proof width without allocating its strings.
///
/// Both digests are exactly 32 bytes and therefore 43 unpadded base64 symbols.
/// The serializer sees the same strings as a genuine proof. This supplies frame
/// capacity only and does not supply a proof or authenticating digest.
///
/// # Errors
/// Refuses a checked serializer-counter overflow or the selected artifact cap.
pub fn maximum_restoration_observe_proof_encoded_bytes_data() -> Result<usize, ProviderError> {
    let digest = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    crate::connection::serialized_credit(
        &ProofView {
            schema: PROOF_SCHEMA,
            algorithm: ALGORITHM,
            context_digest: digest,
            mac: digest,
        },
        MAXIMUM_RESTORATION_OBSERVE_ARTIFACT_BYTES,
    )
}

/// Computes proof data over the whole actual independently derived observation context.
///
/// The real Source issuer must bind this context to its retained private key,
/// original assigned marker and same once Window before this helper is called.
/// It separately admits these canonical and normalized construction owners.
///
/// # Errors
/// Refuses invalid context data or bounded canonical serialization failure.
pub fn restoration_observe_proof_data(
    key: &[u8; 32],
    context: &PacketRestorationObservationContext,
) -> Result<PacketRestorationObservationProof, ProviderError> {
    context.validate_data()?;
    let bytes = bounded(context)?;
    let derived = blake3::derive_key(KEY_DOMAIN, key);
    Ok(PacketRestorationObservationProof {
        schema: PROOF_SCHEMA.to_owned(),
        algorithm: ALGORITHM.to_owned(),
        context_digest: Bytes::new(blake3::hash(&bytes).as_bytes().to_vec()),
        mac: Bytes::new(blake3::keyed_hash(&derived, &bytes).as_bytes().to_vec()),
    })
}

/// Verifies closed MAC data without creating an observation phase owner or grant.
///
/// Native callers retain the actual incoming raw/typed artifact before this
/// separately precharged operation, then authenticate the same current boot,
/// completed Commit, original connection, Source and private phase association.
///
/// # Errors
/// Refuses another context, key or proof grammar, truncated digests,
/// changed MAC data or bounded canonical serialization failure.
pub fn verify_restoration_observe_proof_data(
    key: &[u8; 32],
    context: &PacketRestorationObservationContext,
    proof: &PacketRestorationObservationProof,
) -> Result<(), ProviderError> {
    context.validate_data()?;
    validate_proof_data(proof)?;
    let bytes = bounded(context)?;
    let derived = blake3::derive_key(KEY_DOMAIN, key);
    if blake3::hash(&bytes) != *proof.context_digest.as_slice()
        || blake3::keyed_hash(&derived, &bytes) != *proof.mac.as_slice()
    {
        return Err(invalid());
    }
    Ok(())
}

/// Hashes an actual assigned request without only its nested observation proof.
///
/// The unsigned request extension is mandatory, including during preparation.
/// Only the nested proof may be absent before sealing. Every Envelope field and
/// the complete unsigned request remain in the digest; no sequence is rewritten.
///
/// # Errors
/// Refuses another method, missing assigned identity/sequence, foreign
/// routing fields, any other extension or a bounded serialization failure.
pub fn restoration_observe_assigned_request_digest(
    original: &Envelope,
    maximum_frame_bytes: usize,
) -> Result<[u8; 32], ProviderError> {
    original.validate()?;
    if original.message != MessageKind::Request
        || original.method != crate::envelope::Method::Observe
        || original.sequence.get() == 0
        || original.request_id.0.is_none()
        || original.node_id.0.is_none()
        || original.execution_owner_id.0.is_none()
        || original.operation_id.0.is_some()
        || original.capture_owner_id.0.is_some()
        || original.extensions.len() != 1
        || original.body.get("extensions").is_none_or(|value| {
            value
                .as_object()
                .is_none_or(|extensions| !extensions.is_empty())
        })
    {
        return Err(invalid());
    }
    let extension = original
        .extensions
        .get(PACKET_RESTORATION_OBSERVE_FEATURE)
        .and_then(serde_json::Value::as_object)
        .ok_or_else(invalid)?;
    if !extension.contains_key("request") {
        return Err(invalid());
    }
    for key in extension.keys() {
        if key != "request" && key != "proof" {
            return Err(invalid());
        }
    }
    // Check both independent encoded extents before constructing additional
    // typed request or baseline-body owners from this retained original.
    crate::connection::serialized_credit(original, maximum_frame_bytes)?;
    crate::connection::serialized_credit(extension, MAXIMUM_RESTORATION_OBSERVE_ARTIFACT_BYTES)?;
    let request = PacketRestorationObservationRequest::deserialize(
        extension.get("request").ok_or_else(invalid)?,
    )
    .map_err(ContractError::from)?;
    request.validate_data()?;
    let target = &request.scope.target;
    if original.session_id.0.as_ref() != Some(&target.session)
        || original.incarnation_id.0.as_ref() != Some(&target.incarnation)
        || original.node_id.0.as_ref() != Some(&target.node)
        || original.execution_owner_id.0.as_ref() != Some(&target.owner)
    {
        return Err(invalid());
    }
    let body_value = serde_json::Value::Object(original.body.clone());
    let body =
        crate::bodies::ObserveRequest::deserialize(&body_value).map_err(ContractError::from)?;
    request.authenticate_body_data(&body)?;
    let mut value = serde_json::to_value(original).map_err(ContractError::from)?;
    value
        .get_mut("extensions")
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|extensions| extensions.get_mut(PACKET_RESTORATION_OBSERVE_FEATURE))
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(invalid)?
        .remove("proof");
    let encoded = canonical::canonical_json(&value)?;
    if encoded.len() > maximum_frame_bytes {
        return Err(ProviderError::ResourceExhausted(
            "observation assigned frame extent",
        ));
    }
    Ok(*blake3::hash(&encoded).as_bytes())
}

pub(super) fn bounded(value: &impl Serialize) -> Result<Vec<u8>, ProviderError> {
    crate::connection::serialized_credit(value, MAXIMUM_RESTORATION_OBSERVE_ARTIFACT_BYTES)?;
    let value = serde_json::to_value(value).map_err(ContractError::from)?;
    let bytes = canonical::canonical_json(&value)?;
    if bytes.len() > MAXIMUM_RESTORATION_OBSERVE_ARTIFACT_BYTES {
        return Err(ProviderError::ResourceExhausted(
            "observation artifact extent",
        ));
    }
    Ok(bytes)
}

pub(super) fn validate_proof_data(
    proof: &PacketRestorationObservationProof,
) -> Result<(), ProviderError> {
    if proof.schema != PROOF_SCHEMA
        || proof.algorithm != ALGORITHM
        || proof.context_digest.as_slice().len() != 32
        || proof.mac.as_slice().len() != 32
    {
        return Err(invalid());
    }
    Ok(())
}

pub(super) fn counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<&serde_json::Map<String,serde_json::Value>>()
        + size_of::<Option<&serde_json::Map<String,serde_json::Value>>>()
        + size_of::<Option<&mut serde_json::Map<String,serde_json::Value>>>()
        + size_of::<Option<&serde_json::Value>>()
        + size_of::<Option<&mut serde_json::Value>>()
        + size_of::<serde_json::map::Keys<'static>>()
        + size_of::<Option<serde_json::Value>>()
        + size_of::<Option<&str>>()
        + size_of::<Result<crate::bodies::ObserveRequest,serde_json::Error>>()
        + size_of::<serde_json::Value>() + size_of::<Vec<u8>>()
        + size_of::<Result<Vec<u8>, ProviderError>>()
        + size_of::<serde_json::Value>()
        + size_of::<crate::bodies::ObserveRequest>()
        + size_of::<&crate::bodies::ObserveRequest>()
        + size_of::<Result<usize,ProviderError>>()
        + crate::retained_metadata::serialization_storage::original_serialization_counter_scratch_data()
}

/// Lends the defining closed first-observation proof layout to future counters.
pub(crate) const fn restoration_observe_proof_layout_data()
-> (&'static str, &'static str, usize, usize) {
    (PROOF_SCHEMA, "blake3-256-mac", 32, 32)
}
