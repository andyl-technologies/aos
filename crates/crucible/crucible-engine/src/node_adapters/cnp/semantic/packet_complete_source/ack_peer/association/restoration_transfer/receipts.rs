//! Reauthenticates actual retained SDK originals against Source-normalized banks.
//!
//! These predicates issue no claim and never renew Query. Both the exact signed
//! envelope and the separately domain-separated native receipt remain necessary.

use super::super::restore_transfer_banks::OriginalRestoreTransferBanks;
use super::*;

pub(super) fn authenticate_prepare_pair(
    transfer: &OriginalRestoreTransferBanks,
    request: &Envelope,
    response: &Envelope,
    key: &[u8; 32],
    maximum: usize,
) -> Result<(), RuntimeError> {
    let phase = PacketCompleteRestoreTransferPhase::Prepare;
    if serde_json::to_value(request).map_err(|_| RuntimeError::InvalidReceipt)?
        != *transfer.signer()?.value(phase, 3)?
        || response.extensions.len() != 1
        || response
            .extensions
            .get(PACKET_COMPLETE_RESTORE_PREPARE_RECEIPT_EXTENSION)
            != Some(transfer.signer()?.value(phase, 4)?)
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    let data: PacketCompleteRestorePrepareRequest =
        Deserialize::deserialize(transfer.signer()?.value(phase, 0)?)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    let context: PacketCompleteRestorePrepareContext =
        Deserialize::deserialize(transfer.signer()?.value(phase, 1)?)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    let proof: PacketCompleteRestoreTransferProof =
        Deserialize::deserialize(transfer.signer()?.value(phase, 2)?)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    let receipt: PacketCompleteRestorePrepareReceipt =
        Deserialize::deserialize(transfer.signer()?.value(phase, 4)?)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    let assigned = complete_restore_fresh_prepare_assigned_request_digest(request, maximum)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    if context.assigned_prepare.as_slice() != assigned
        || request
            .extensions
            .get(PACKET_COMPLETE_RESTORE_PREPARE_EXTENSION)
            != Some(transfer.signer()?.value(phase, 0)?)
        || request
            .extensions
            .get(PACKET_COMPLETE_RESTORE_PREPARE_PROOF_EXTENSION)
            != Some(transfer.signer()?.value(phase, 2)?)
        || data.generation != transfer.signer()?.generation()
        || data.restoration.nonce.as_slice() != transfer.signer()?.nonce()
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    verify_complete_restore_prepare_proof_data(key, &context, &proof)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let digest =
        complete_restore_fresh_prepare_assigned_response_digest(request, response, maximum)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    verify_complete_restore_prepare_receipt_data(
        key,
        &data,
        &context,
        response.sequence,
        &digest,
        &receipt,
    )
    .map_err(|_| RuntimeError::InvalidReceipt)?;
    authenticate_completed_body(request, response, &data.restoration, &data.transaction_id)
}

pub(super) fn authenticate_completed_body(
    request: &Envelope,
    response: &Envelope,
    expected: &PacketCompleteRestoreRequest,
    transaction: &Id,
) -> Result<(), RuntimeError> {
    request
        .matches_response(response)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let body = crucible_node_transport::bodies::decode_request(request.method, &request.body)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let result = crucible_node_transport::bodies::decode_response(&body, &response.body)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    if !matches!(result.shape, ResponseShape::Completed { ref extensions, .. } if extensions.is_empty())
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    let Some(MethodResult::PrepareRestore(result)) = result.result else {
        return Err(RuntimeError::InvalidReceipt);
    };
    if &result.transaction_id != transaction
        || result.world_binding_hash != expected.target_world
        || result.owner_binding_hash != expected.target_owner_binding
        || result.staged_owner_ids.as_slice() != std::slice::from_ref(&expected.target_owner)
        || result.validated_manifest != expected.capture_manifest
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    Ok(())
}

pub(super) fn authenticate_commit_pair(
    transfer: &OriginalRestoreTransferBanks,
    request: &Envelope,
    response: &Envelope,
    capture_terminal: &Envelope,
    canonical_mapping: &[u8],
    key: &[u8; 32],
    maximum: usize,
) -> Result<(), RuntimeError> {
    let phase = PacketCompleteRestoreTransferPhase::Commit;
    if serde_json::to_value(request).map_err(|_| RuntimeError::InvalidReceipt)?
        != *transfer.signer()?.value(phase, 3)?
        || response.extensions.len() != 1
        || response
            .extensions
            .get(PACKET_COMPLETE_RESTORE_COMMIT_RECEIPT_EXTENSION)
            != Some(transfer.signer()?.value(phase, 4)?)
        || request
            .extensions
            .get(PACKET_COMPLETE_RESTORE_COMMIT_EXTENSION)
            != Some(transfer.signer()?.value(phase, 0)?)
        || request
            .extensions
            .get(PACKET_COMPLETE_RESTORE_COMMIT_PROOF_EXTENSION)
            != Some(transfer.signer()?.value(phase, 2)?)
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    let data: PacketCompleteRestoreCommitRequest =
        Deserialize::deserialize(transfer.signer()?.value(phase, 0)?)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    let context: PacketCompleteRestoreCommitContext =
        Deserialize::deserialize(transfer.signer()?.value(phase, 1)?)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    let proof: PacketCompleteRestoreTransferProof =
        Deserialize::deserialize(transfer.signer()?.value(phase, 2)?)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    let receipt: PacketCompleteRestoreCommitReceipt =
        Deserialize::deserialize(transfer.signer()?.value(phase, 4)?)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    let assigned = complete_restore_transfer_assigned_request_digest(request, phase, maximum)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    if context.restoration.assigned_restore.as_slice() != assigned
        || serde_json::to_value(&data.prepare).map_err(|_| RuntimeError::InvalidReceipt)?
            != *transfer
                .signer()?
                .value(PacketCompleteRestoreTransferPhase::Prepare, 0)?
        || data.capture_terminal != *capture_terminal
        || data.prepare.generation != transfer.signer()?.generation()
        || data.prepare.restoration.nonce.as_slice() != transfer.signer()?.nonce()
    {
        return Err(RuntimeError::InvalidReceipt);
    }
    context
        .authenticate_request_data(&data, canonical_mapping)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    verify_complete_restore_commit_proof_data(key, &context, &proof)
        .map_err(|_| RuntimeError::InvalidReceipt)?;
    let digest =
        complete_restore_transfer_assigned_response_digest(request, response, phase, maximum)
            .map_err(|_| RuntimeError::InvalidReceipt)?;
    verify_complete_restore_commit_receipt_data(
        key,
        &data,
        &context,
        response.sequence,
        &digest,
        &receipt,
    )
    .map_err(|_| RuntimeError::InvalidReceipt)?;
    authenticate_completed_body(
        request,
        response,
        &data.prepare.restoration,
        &data.prepare.transaction_id,
    )
}
