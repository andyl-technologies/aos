//! Computes phase-specific MAC data without constructing a native lease or token.

use super::*;

fn keyed(domain: &str, key: &[u8; 32], bytes: &[u8]) -> Bytes {
    let derived = blake3::derive_key(domain, key);
    Bytes::new(blake3::keyed_hash(&derived, bytes).as_bytes().to_vec())
}

fn receipt_input(receipt: &impl Serialize) -> Result<Vec<u8>, ProviderError> {
    let mut value =
        serde_json::to_value(receipt).map_err(crucible_node_format::ContractError::from)?;
    value
        .as_object_mut()
        .ok_or(ProviderError::Correlation("restore receipt object"))?
        .remove("mac");
    bounded_canonical(&value, MAXIMUM_COMPLETE_RESTORE_TRANSFER_RECEIPT_BYTES)
}

fn authenticate_receipt(
    actual: &impl Serialize,
    expected: &impl Serialize,
) -> Result<(), ProviderError> {
    let actual = bounded_canonical(actual, MAXIMUM_COMPLETE_RESTORE_TRANSFER_RECEIPT_BYTES)?;
    let expected = bounded_canonical(expected, MAXIMUM_COMPLETE_RESTORE_TRANSFER_RECEIPT_BYTES)?;
    if blake3::hash(&actual) != blake3::hash(&expected) {
        return Err(ProviderError::Correlation(
            "restore transfer receipt correspondence",
        ));
    }
    Ok(())
}

/// Computes inert prepare proof data over the complete independently derived context.
///
/// The issuer must retain actual owners and charge canonical scratch separately.
///
/// # Errors
/// Refuses an invalid context or bounded canonical serialization failure.
pub fn complete_restore_prepare_proof_data(
    key: &[u8; 32],
    context: &PacketCompleteRestorePrepareContext,
) -> Result<PacketCompleteRestoreTransferProof, ProviderError> {
    context.validate_data()?;
    let bytes = bounded_canonical(context, MAXIMUM_COMPLETE_RESTORE_TRANSFER_CONTEXT_BYTES)?;
    let proof = PacketCompleteRestoreTransferProof {
        schema: PacketCompleteRestoreTransferPhase::Prepare
            .proof_extension()
            .to_owned(),
        algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.to_owned(),
        context_digest: digest(&bytes),
        mac: keyed(
            "source-owned.packet-complete-restore-prepare-key/12",
            key,
            &bytes,
        ),
    };
    proof.validate_data(PacketCompleteRestoreTransferPhase::Prepare)?;
    Ok(proof)
}

/// Verifies prepare MAC data without issuing installation or allocation authority.
///
/// # Errors
/// Refuses a foreign key, phase, context, truncated proof or changed MAC.
pub fn verify_complete_restore_prepare_proof_data(
    key: &[u8; 32],
    context: &PacketCompleteRestorePrepareContext,
    proof: &PacketCompleteRestoreTransferProof,
) -> Result<(), ProviderError> {
    proof.validate_data(PacketCompleteRestoreTransferPhase::Prepare)?;
    let expected = complete_restore_prepare_proof_data(key, context)?;
    same_digest(&proof.context_digest, &expected.context_digest)?;
    same_digest(&proof.mac, &expected.mac)
}

/// Computes inert commit proof data over the complete independently derived context.
///
/// The issuer must retain actual owners and charge canonical scratch separately.
///
/// # Errors
/// Refuses an invalid context or bounded canonical serialization failure.
pub fn complete_restore_commit_proof_data(
    key: &[u8; 32],
    context: &PacketCompleteRestoreCommitContext,
) -> Result<PacketCompleteRestoreTransferProof, ProviderError> {
    context.validate_data()?;
    let bytes = bounded_canonical(context, MAXIMUM_COMPLETE_RESTORE_TRANSFER_CONTEXT_BYTES)?;
    let proof = PacketCompleteRestoreTransferProof {
        schema: PacketCompleteRestoreTransferPhase::Commit
            .proof_extension()
            .to_owned(),
        algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.to_owned(),
        context_digest: digest(&bytes),
        mac: keyed(
            "source-owned.packet-complete-restore-commit-key/12",
            key,
            &bytes,
        ),
    };
    proof.validate_data(PacketCompleteRestoreTransferPhase::Commit)?;
    Ok(proof)
}

/// Verifies commit MAC data without issuing installation or allocation authority.
///
/// # Errors
/// Refuses a foreign key, phase, context, truncated proof or changed MAC.
pub fn verify_complete_restore_commit_proof_data(
    key: &[u8; 32],
    context: &PacketCompleteRestoreCommitContext,
    proof: &PacketCompleteRestoreTransferProof,
) -> Result<(), ProviderError> {
    proof.validate_data(PacketCompleteRestoreTransferPhase::Commit)?;
    let expected = complete_restore_commit_proof_data(key, context)?;
    same_digest(&proof.context_digest, &expected.context_digest)?;
    same_digest(&proof.mac, &expected.mac)
}

/// Computes an input-only lease receipt from the actual assigned response.
///
/// The private native issuer must already retain its exact finite input banks;
/// this helper cannot establish that admission or construct the private lease.
///
/// # Errors
/// Refuses invalid request/context bindings, sequence or canonical extent.
pub fn complete_restore_prepare_receipt_data(
    key: &[u8; 32],
    request: &PacketCompleteRestorePrepareRequest,
    context: &PacketCompleteRestorePrepareContext,
    native_sequence: U64,
    actual_assigned_response: &[u8; 32],
) -> Result<PacketCompleteRestorePrepareReceipt, ProviderError> {
    context.authenticate_request_data(request)?;
    let context_bytes =
        bounded_canonical(context, MAXIMUM_COMPLETE_RESTORE_TRANSFER_CONTEXT_BYTES)?;
    let mut receipt = PacketCompleteRestorePrepareReceipt {
        schema: PACKET_COMPLETE_RESTORE_PREPARE_RECEIPT_EXTENSION.to_owned(),
        algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.to_owned(),
        prepare_digest: digest(&bounded_canonical(
            request,
            MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES,
        )?),
        context_digest: digest(&context_bytes),
        input_roster: request.input_roster_digest_data()?,
        transfer_token: keyed(
            "source-owned.packet-complete-restore-transfer-token-key/12",
            key,
            &context_bytes,
        ),
        generation: request.generation,
        native_sequence,
        assigned_response: Bytes::new(actual_assigned_response.to_vec()),
        mac: Bytes::new(vec![0; 32]),
    };
    receipt.mac = keyed(
        "source-owned.packet-complete-restore-prepare-receipt-key/12",
        key,
        &receipt_input(&receipt)?,
    );
    receipt.validate_data()?;
    Ok(receipt)
}

/// Verifies an input receipt against its actual original response sequence/body.
///
/// # Errors
/// Refuses another response, request, lease, generation, key or context.
pub fn verify_complete_restore_prepare_receipt_data(
    key: &[u8; 32],
    request: &PacketCompleteRestorePrepareRequest,
    context: &PacketCompleteRestorePrepareContext,
    native_sequence: U64,
    actual_assigned_response: &[u8; 32],
    receipt: &PacketCompleteRestorePrepareReceipt,
) -> Result<(), ProviderError> {
    receipt.validate_data()?;
    let expected = complete_restore_prepare_receipt_data(
        key,
        request,
        context,
        native_sequence,
        actual_assigned_response,
    )?;
    authenticate_receipt(receipt, &expected)
}

/// Computes a completed receipt only from the same retained commit context.
///
/// The native consumer issues this data only after its genuine one-shot token
/// and hash-verified inputs have completed mechanical installation.
///
/// # Errors
/// Refuses invalid context/request correspondence, mapping, sequence or extent.
pub fn complete_restore_commit_receipt_data(
    key: &[u8; 32],
    request: &PacketCompleteRestoreCommitRequest,
    context: &PacketCompleteRestoreCommitContext,
    native_sequence: U64,
    actual_assigned_response: &[u8; 32],
) -> Result<PacketCompleteRestoreCommitReceipt, ProviderError> {
    request.validate_data()?;
    context.validate_data()?;
    let request_bytes =
        bounded_canonical(request, MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES)?;
    same_digest(&context.commit_request, &digest(&request_bytes))?;
    same_digest(&context.transfer_token, &request.transfer_token)?;
    same_digest(&context.prepare_request, &request.prepare_request_digest)?;
    same_digest(&context.prepare_response, &request.prepare_response_digest)?;
    same_digest(
        &context.input_roster,
        &request.prepare.input_roster_digest_data()?,
    )?;
    let mut receipt = PacketCompleteRestoreCommitReceipt {
        schema: PACKET_COMPLETE_RESTORE_COMMIT_RECEIPT_EXTENSION.to_owned(),
        algorithm: PACKET_COMPLETE_RESTORE_ALGORITHM.to_owned(),
        commit_digest: digest(&request_bytes),
        context_digest: digest(&bounded_canonical(
            context,
            MAXIMUM_COMPLETE_RESTORE_TRANSFER_CONTEXT_BYTES,
        )?),
        installed_mapping: request.prepare.restoration.mapping.clone(),
        transfer_token: Bytes::new(request.transfer_token.as_slice().to_vec()),
        native_sequence,
        assigned_response: Bytes::new(actual_assigned_response.to_vec()),
        mac: Bytes::new(vec![0; 32]),
    };
    receipt.mac = keyed(
        "source-owned.packet-complete-restore-commit-receipt-key/12",
        key,
        &receipt_input(&receipt)?,
    );
    receipt.validate_data()?;
    Ok(receipt)
}

/// Verifies completed MAC data against the actual assigned commit response.
///
/// # Errors
/// Refuses changed response identity, key, original chain, lease or mapping.
pub fn verify_complete_restore_commit_receipt_data(
    key: &[u8; 32],
    request: &PacketCompleteRestoreCommitRequest,
    context: &PacketCompleteRestoreCommitContext,
    native_sequence: U64,
    actual_assigned_response: &[u8; 32],
    receipt: &PacketCompleteRestoreCommitReceipt,
) -> Result<(), ProviderError> {
    receipt.validate_data()?;
    let expected = complete_restore_commit_receipt_data(
        key,
        request,
        context,
        native_sequence,
        actual_assigned_response,
    )?;
    authenticate_receipt(receipt, &expected)
}
