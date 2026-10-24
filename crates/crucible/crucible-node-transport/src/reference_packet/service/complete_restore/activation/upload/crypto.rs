//! Computes inert domain-separated activation proof and common-scope data.

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
const PROOF_SCHEMA: &str = "source-owned.packet-restoration-activation-upload-proof/1";
const KEY_DOMAIN: &str = "source-owned.packet-restoration-activation-upload-key/1";

/// Hashes the exact phase context without constructing proof or MAC owners.
///
/// # Errors
/// Refuses invalid or oversized context data or failed canonical construction.
pub fn restoration_activation_upload_context_digest_data(
    context: &PacketRestorationActivationUploadContext,
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
pub fn maximum_restoration_activation_upload_proof_encoded_bytes_data()
-> Result<usize, ProviderError> {
    let digest = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    crate::connection::serialized_credit(
        &ProofView {
            schema: PROOF_SCHEMA,
            algorithm: ALGORITHM,
            context_digest: digest,
            mac: digest,
        },
        MAXIMUM_RESTORATION_ACTIVATION_ARTIFACT_BYTES,
    )
}

/// Computes proof data over the whole actual independently derived phase context.
///
/// The real Source issuer must bind this context to its retained private key,
/// original assigned marker and same once Window before this helper is called.
/// It separately admits these canonical and normalized construction owners.
///
/// # Errors
/// Refuses invalid context data or bounded canonical serialization failure.
pub fn restoration_activation_upload_proof_data(
    key: &[u8; 32],
    context: &PacketRestorationActivationUploadContext,
) -> Result<PacketRestorationActivationProof, ProviderError> {
    context.validate_data()?;
    let bytes = bounded(context)?;
    let derived = blake3::derive_key(KEY_DOMAIN, key);
    Ok(PacketRestorationActivationProof {
        schema: PROOF_SCHEMA.to_owned(),
        algorithm: ALGORITHM.to_owned(),
        context_digest: Bytes::new(blake3::hash(&bytes).as_bytes().to_vec()),
        mac: Bytes::new(blake3::keyed_hash(&derived, &bytes).as_bytes().to_vec()),
    })
}

/// Verifies closed MAC data without creating an activation phase owner or grant.
///
/// Native callers retain the actual incoming raw/typed artifact before this
/// separately precharged operation, then authenticate the same current boot,
/// completed Commit, original connection, Source and private phase association.
///
/// # Errors
/// Refuses another context, phase, key or proof grammar, truncated digests,
/// changed MAC data or bounded canonical serialization failure.
pub fn verify_restoration_activation_upload_proof_data(
    key: &[u8; 32],
    context: &PacketRestorationActivationUploadContext,
    proof: &PacketRestorationActivationProof,
) -> Result<(), ProviderError> {
    context.validate_data()?;
    if proof.schema != PROOF_SCHEMA
        || proof.algorithm != ALGORITHM
        || proof.context_digest.as_slice().len() != 32
        || proof.mac.as_slice().len() != 32
    {
        return Err(invalid());
    }
    let bytes = bounded(context)?;
    let derived = blake3::derive_key(KEY_DOMAIN, key);
    if blake3::hash(&bytes) != *proof.context_digest.as_slice()
        || blake3::keyed_hash(&derived, &bytes) != *proof.mac.as_slice()
    {
        return Err(invalid());
    }
    Ok(())
}

/// Hashes an actual assigned request without only its nested activation proof.
///
/// The unsigned request extension is mandatory, including during preparation.
/// Only the nested proof may be absent before sealing. Every Envelope field and
/// the complete unsigned request remain in the digest; no sequence is rewritten.
///
/// # Errors
/// Refuses another phase/method, missing assigned identity/sequence, foreign
/// routing fields, any other extension or a bounded serialization failure.
pub fn restoration_activation_upload_assigned_request_digest(
    original: &Envelope,
    role: PacketRestorationActivationUploadRole,
    maximum_frame_bytes: usize,
) -> Result<[u8; 32], ProviderError> {
    original.validate()?;
    if original.message != MessageKind::Request
        || original.method != Method::BlobBegin
        || original.sequence.get() == 0
        || original.request_id.0.is_none()
        || original.node_id.0.is_none()
        || original.execution_owner_id.0.is_none()
        || original.operation_id.0.is_some()
        || original.capture_owner_id.0.is_some()
        || original
            .extensions
            .keys()
            .any(|key| key != PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE)
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
        .get(PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE)
        .and_then(serde_json::Value::as_object)
        .ok_or_else(invalid)?;
    if !extension.contains_key("request")
        || extension
            .keys()
            .any(|key| key != "request" && key != "proof")
    {
        return Err(invalid());
    }
    let request = PacketRestorationActivationUploadRequest::deserialize(
        extension.get("request").ok_or_else(invalid)?,
    )
    .map_err(ContractError::from)?;
    request.validate_data()?;
    if request.role != role {
        return Err(invalid());
    }
    if original.body.get("content")
        != Some(&serde_json::to_value(request.content_ref_data()).map_err(ContractError::from)?)
    {
        return Err(invalid());
    }
    crate::connection::serialized_credit(original, maximum_frame_bytes)?;
    let mut value = serde_json::to_value(original).map_err(ContractError::from)?;
    value
        .get_mut("extensions")
        .and_then(serde_json::Value::as_object_mut)
        .and_then(|extensions| extensions.get_mut(PACKET_RESTORATION_ACTIVATION_UPLOAD_FEATURE))
        .and_then(serde_json::Value::as_object_mut)
        .ok_or_else(invalid)?
        .remove("proof");
    let encoded = canonical::canonical_json(&value)?;
    if encoded.len() > maximum_frame_bytes {
        return Err(ProviderError::ResourceExhausted(
            "activation assigned frame extent",
        ));
    }
    Ok(*blake3::hash(&encoded).as_bytes())
}

pub(super) fn bounded(value: &impl Serialize) -> Result<Vec<u8>, ProviderError> {
    crate::connection::serialized_credit(value, MAXIMUM_RESTORATION_ACTIVATION_ARTIFACT_BYTES)?;
    let value = serde_json::to_value(value).map_err(ContractError::from)?;
    let bytes = canonical::canonical_json(&value)?;
    if bytes.len() > MAXIMUM_RESTORATION_ACTIVATION_ARTIFACT_BYTES {
        return Err(ProviderError::ResourceExhausted(
            "activation artifact extent",
        ));
    }
    Ok(bytes)
}
