//! Keeps bootstrap-only key domains separate from ordinary ACK5 admission.

use super::*;

const PROOF_DOMAIN: &str = "source-owned.packet-native-import-bootstrap-ack-key/18";
const RECEIPT_DOMAIN: &str = "source-owned.packet-native-import-bootstrap-ack-receipt-key/18";
// The closed context has nine base64(32) strings, fixed schema/algorithm, and
// three independently serialized U64 fields of at most twenty decimal bytes.
const MAXIMUM_CONTEXT_BYTES: usize = 873;

/// Hashes the complete new context under its exact closed encoded bound.
///
/// # Errors
/// Refuses invalid context DATA or canonical serialization failure.
pub fn native_import18_bootstrap_ack_context_digest_data(
    context: &PacketNativeImport18BootstrapAckContext,
) -> Result<[u8; 32], ProviderError> {
    let bytes = context_bytes(context)?;
    Ok(*blake3::hash(&bytes).as_bytes())
}

/// Computes distinct proof DATA from independently authenticated original operands.
///
/// The caller retains its assigned original and all partial output before this
/// separately admitted helper. A carried key or matching proof cannot issue a
/// Source occurrence, native bootstrap allowance or ordinary readiness.
///
/// # Errors
/// Refuses context syntax, its exact encoded bound or serialization failure.
pub fn native_import18_bootstrap_ack_proof_data(
    key: &[u8; 32],
    context: &PacketNativeImport18BootstrapAckContext,
) -> Result<PacketNativeImport18BootstrapAckProof, ProviderError> {
    let bytes = context_bytes(context)?;
    let derived = blake3::derive_key(PROOF_DOMAIN, key);
    let mac = blake3::keyed_hash(&derived, &bytes);
    Ok(PacketNativeImport18BootstrapAckProof {
        schema: NATIVE_IMPORT18_BOOTSTRAP_ACK_PROOF.into(),
        algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.into(),
        context_digest: Bytes::new(blake3::hash(&bytes).as_bytes().to_vec()),
        mac: Bytes::new(mac.as_bytes().to_vec()),
    })
}

/// Verifies exact new-context correspondence without issuing a native token.
///
/// # Errors
/// Refuses invalid DATA, another context/key/domain, or a mismatched MAC.
pub fn verify_native_import18_bootstrap_ack_proof_data(
    key: &[u8; 32],
    context: &PacketNativeImport18BootstrapAckContext,
    proof: &PacketNativeImport18BootstrapAckProof,
) -> Result<(), ProviderError> {
    proof.validate_data()?;
    let bytes = context_bytes(context)?;
    let derived = blake3::derive_key(PROOF_DOMAIN, key);
    if blake3::hash(&bytes) != *proof.context_digest.as_slice()
        || blake3::keyed_hash(&derived, &bytes) != *proof.mac.as_slice()
    {
        return Err(invalid());
    }
    Ok(())
}

/// Computes a bootstrap-only receipt bound to the actual assigned response.
///
/// The native owner separately retains the sole response, spends publication
/// once, and authenticates its original channel/Hello/Source/current occurrence.
/// This helper never sets ordinary Control admission or model flags.
///
/// # Errors
/// Refuses invalid context DATA or canonical serialization failure.
pub fn native_import18_bootstrap_ack_receipt_data(
    key: &[u8; 32],
    context: &PacketNativeImport18BootstrapAckContext,
    assigned_response: &[u8; 32],
) -> Result<PacketNativeImport18BootstrapAckReceipt, ProviderError> {
    let context_digest = native_import18_bootstrap_ack_context_digest_data(context)?;
    let material = receipt_material(&context_digest, assigned_response);
    let derived = blake3::derive_key(RECEIPT_DOMAIN, key);
    Ok(PacketNativeImport18BootstrapAckReceipt {
        schema: NATIVE_IMPORT18_BOOTSTRAP_ACK_RECEIPT.into(),
        algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.into(),
        state: PacketNativeImport18BootstrapAckState::BootstrapOnly,
        context_digest: Bytes::new(context_digest.to_vec()),
        assigned_response: Bytes::new(assigned_response.to_vec()),
        mac: Bytes::new(blake3::keyed_hash(&derived, &material).as_bytes().to_vec()),
    })
}

/// Verifies the bootstrap-only response against its actual independently assigned bytes.
///
/// # Errors
/// Refuses another context, response, key/domain, receipt grammar or MAC.
pub fn verify_native_import18_bootstrap_ack_receipt_data(
    key: &[u8; 32],
    context: &PacketNativeImport18BootstrapAckContext,
    assigned_response: &[u8; 32],
    receipt: &PacketNativeImport18BootstrapAckReceipt,
) -> Result<(), ProviderError> {
    receipt.validate_data()?;
    let context_digest = native_import18_bootstrap_ack_context_digest_data(context)?;
    same_digest(&context_digest, receipt.context_digest.as_slice())?;
    same_digest(assigned_response, receipt.assigned_response.as_slice())?;
    let derived = blake3::derive_key(RECEIPT_DOMAIN, key);
    let material = receipt_material(&context_digest, assigned_response);
    if blake3::keyed_hash(&derived, &material) != *receipt.mac.as_slice() {
        return Err(invalid());
    }
    Ok(())
}

fn receipt_material(context: &[u8; 32], assigned: &[u8; 32]) -> [u8; 64] {
    let mut material = [0; 64];
    material[..32].copy_from_slice(context);
    material[32..].copy_from_slice(assigned);
    material
}

fn context_bytes(
    context: &PacketNativeImport18BootstrapAckContext,
) -> Result<Vec<u8>, ProviderError> {
    context.validate_data()?;
    bounded(context, MAXIMUM_CONTEXT_BYTES)
}
