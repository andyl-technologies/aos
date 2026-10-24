//! Computes separate request and completed-response MAC data.

use super::*;

const REQUEST_KEY_DOMAIN: &str = "source-owned.packet-complete-restore-key/11";
const RECEIPT_KEY_DOMAIN: &str = "source-owned.packet-complete-restore-receipt-key/11";

/// Computes inert proof data after the source has authenticated all actual owners.
///
/// The actual assigned request, original cut, key and full normalized input banks
/// must already be retained. Serialization allocations are separately charged.
///
/// # Errors
/// Refuses invalid context data or canonical serialization failure.
pub fn complete_restore_proof_data(
    fresh_birth_key: &[u8; 32],
    context: &PacketCompleteRestoreContext,
) -> Result<PacketCompleteRestoreProof, ProviderError> {
    let canonical = context.canonical_bytes()?;
    let key = blake3::derive_key(REQUEST_KEY_DOMAIN, fresh_birth_key);
    let proof = PacketCompleteRestoreProof {
        schema: PACKET_COMPLETE_RESTORE_PROOF_EXTENSION.to_owned(),
        algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.to_owned(),
        context_digest: digest(&canonical),
        mac: Bytes::new(blake3::keyed_hash(&key, &canonical).as_bytes().to_vec()),
    };
    proof.validate_data()?;
    Ok(proof)
}

/// Verifies request MAC correspondence using constant-time BLAKE3 hash equality.
///
/// A native private issuer must independently authenticate its fresh boot,
/// registration, full policy, assigned original and prepared mapping, then spend
/// its one-shot installation slot before the first mechanical effect.
///
/// # Errors
/// Refuses invalid data, another key or any changed normalized context.
pub fn verify_complete_restore_proof_data(
    fresh_birth_key: &[u8; 32],
    context: &PacketCompleteRestoreContext,
    proof: &PacketCompleteRestoreProof,
) -> Result<(), ProviderError> {
    proof.validate_data()?;
    let canonical = context.canonical_bytes()?;
    let key = blake3::derive_key(REQUEST_KEY_DOMAIN, fresh_birth_key);
    if blake3::hash(&canonical) != *proof.context_digest.as_slice()
        || blake3::keyed_hash(&key, &canonical) != *proof.mac.as_slice()
    {
        return Err(ProviderError::Correlation(
            "complete restore proof correspondence",
        ));
    }
    Ok(())
}

#[derive(Serialize)]
struct ReceiptMacInput<'a> {
    schema: &'static str,
    algorithm: &'a str,
    request_digest: &'a Bytes,
    context_digest: &'a Bytes,
    installed_mapping: &'a ContentRef,
    native_sequence: U64,
    assigned_response: &'a Bytes,
}

fn receipt_mac_bytes(receipt: &PacketCompleteRestoreReceipt) -> Result<Vec<u8>, ProviderError> {
    bounded_canonical(
        &ReceiptMacInput {
            schema: "source-owned.packet-complete-restore-receipt-input/11",
            algorithm: &receipt.algorithm,
            request_digest: &receipt.request_digest,
            context_digest: &receipt.context_digest,
            installed_mapping: &receipt.installed_mapping,
            native_sequence: receipt.native_sequence,
            assigned_response: &receipt.assigned_response,
        },
        MAXIMUM_COMPLETE_RESTORE_RECEIPT_BYTES,
    )
}

/// Computes completed receipt data from the actual retained response identity.
///
/// The caller supplies the digest of its actual assigned response envelope with
/// only the receipt extension removed. This helper cannot establish that the
/// native installation happened, and cannot issue its opaque success token.
///
/// # Errors
/// Refuses an invalid request, context, mapping correspondence or serialization.
pub fn complete_restore_receipt_data(
    fresh_birth_key: &[u8; 32],
    request: &PacketCompleteRestoreRequest,
    context: &PacketCompleteRestoreContext,
    native_sequence: U64,
    assigned_response: &[u8; 32],
) -> Result<PacketCompleteRestoreReceipt, ProviderError> {
    request.validate_data()?;
    let canonical_context = context.canonical_bytes()?;
    let canonical_request = bounded_canonical(request, MAXIMUM_COMPLETE_RESTORE_REQUEST_BYTES)?;
    if blake3::hash(&canonical_request) != *context.request_binding.as_slice() {
        return Err(ProviderError::Correlation(
            "complete restore request binding",
        ));
    }
    let mut receipt = PacketCompleteRestoreReceipt {
        schema: PACKET_COMPLETE_RESTORE_RECEIPT_EXTENSION.to_owned(),
        algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.to_owned(),
        request_digest: digest(&canonical_request),
        context_digest: digest(&canonical_context),
        installed_mapping: request.mapping.clone(),
        native_sequence,
        assigned_response: Bytes::new(assigned_response.to_vec()),
        mac: Bytes::new(vec![0; 32]),
    };
    let key = blake3::derive_key(RECEIPT_KEY_DOMAIN, fresh_birth_key);
    receipt.mac = Bytes::new(
        blake3::keyed_hash(&key, &receipt_mac_bytes(&receipt)?)
            .as_bytes()
            .to_vec(),
    );
    receipt.validate_data()?;
    Ok(receipt)
}

/// Verifies a completed receipt against the actual correlated response.
///
/// The caller obtains sequence and base-envelope digest from its original
/// response slot, not fields copied from the receipt. Cryptographic success
/// still requires the source's full Core, signed journal and target conjunction.
///
/// # Errors
/// Refuses another key, request, context, mapping, response sequence or body.
pub fn verify_complete_restore_receipt_data(
    fresh_birth_key: &[u8; 32],
    request: &PacketCompleteRestoreRequest,
    context: &PacketCompleteRestoreContext,
    actual_native_sequence: U64,
    actual_assigned_response: &[u8; 32],
    receipt: &PacketCompleteRestoreReceipt,
) -> Result<(), ProviderError> {
    receipt.validate_data()?;
    request.validate_data()?;
    let canonical_context = context.canonical_bytes()?;
    let canonical_request = bounded_canonical(request, MAXIMUM_COMPLETE_RESTORE_REQUEST_BYTES)?;
    let key = blake3::derive_key(RECEIPT_KEY_DOMAIN, fresh_birth_key);
    if receipt.native_sequence != actual_native_sequence
        || receipt.installed_mapping != request.mapping
        || blake3::hash(&canonical_request) != *context.request_binding.as_slice()
        || blake3::hash(&canonical_request) != *receipt.request_digest.as_slice()
        || blake3::hash(&canonical_context) != *receipt.context_digest.as_slice()
        || blake3::Hash::from_bytes(*actual_assigned_response)
            != *receipt.assigned_response.as_slice()
        || blake3::keyed_hash(&key, &receipt_mac_bytes(receipt)?) != *receipt.mac.as_slice()
    {
        return Err(ProviderError::Correlation(
            "complete restore receipt correspondence",
        ));
    }
    Ok(())
}
