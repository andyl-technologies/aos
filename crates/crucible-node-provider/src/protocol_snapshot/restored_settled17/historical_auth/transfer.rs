//! Authenticates the whole ACK/Prepare/Commit chain and both assigned receipts.

use super::shared::*;
use super::*;
use crate::bodies::{BeginArguments, MethodResult, RequestBody, decode_request};
use crate::envelope::Method;
use crate::reference_packet::service::complete_restore::transfer::*;
use crate::reference_packet::service::fresh_restore_allocation::PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING;
use crucible_node_contract::{ContractError, Validate};
use serde::Deserialize;

/// Checks Prepare against the original authenticated ACK and actual terminal.
///
/// # Errors
/// Refuses a changed birth context, target/body, assigned envelope, complete
/// request/input roster, proof, response receipt or per-direction chronology.
pub(crate) fn authenticate_historical_prepare_data(
    key: &[u8; 32],
    ack: &HistoricalAck17<'_>,
    data: &HistoricalPrepare17<'_>,
    maximum_frame: usize,
) -> Result<(), ProviderError> {
    authenticate_historical_ack_data(key, ack, maximum_frame)?;
    let response = completed_pair(data.pair, Method::Begin, maximum_frame)?;
    follows(ack.pair, data.pair)?;
    data.context.authenticate_request_data(data.request)?;
    same_birth(
        ack.context,
        &[
            &data.context.source_birth,
            &data.context.kernel_binding,
            &data.context.policy_binding,
            &data.context.host_registration,
            &data.context.native_registration,
            &data.context.hello_request,
            &data.context.hello_response,
        ],
    )?;
    extension(
        data.pair.original,
        PACKET_COMPLETE_RESTORE_PREPARE_EXTENSION,
        data.request,
        MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES,
    )?;
    extension(
        data.pair.original,
        PACKET_COMPLETE_RESTORE_PREPARE_PROOF_EXTENSION,
        data.proof,
        MAXIMUM_COMPLETE_RESTORE_TRANSFER_PROOF_BYTES,
    )?;
    authenticate_target(ack, data.request, data.pair.original)?;
    digest_matches(
        &data.context.assigned_prepare,
        &prepare_assigned(data.pair.original, maximum_frame)?,
    )?;
    verify_complete_restore_prepare_proof_data(key, data.context, data.proof)?;

    let receipt = PacketCompleteRestorePrepareReceipt::deserialize(
        data.pair
            .terminal
            .extensions
            .get(PACKET_COMPLETE_RESTORE_PREPARE_RECEIPT_EXTENSION)
            .ok_or_else(invalid)?,
    )
    .map_err(ContractError::from)?;
    let assigned = if fresh_prepare(data.pair.original) {
        complete_restore_fresh_prepare_assigned_response_digest(
            data.pair.original,
            data.pair.terminal,
            maximum_frame,
        )?
    } else {
        complete_restore_transfer_assigned_response_digest(
            data.pair.original,
            data.pair.terminal,
            PacketCompleteRestoreTransferPhase::Prepare,
            maximum_frame,
        )?
    };
    verify_complete_restore_prepare_receipt_data(
        key,
        data.request,
        data.context,
        data.pair.terminal.sequence,
        &assigned,
        &receipt,
    )?;
    restore_result(&response, ack.selection, data.request)?;
    Ok(())
}

/// Checks the completed Commit against its entire original prepared lease chain.
///
/// # Errors
/// Refuses any earlier ACK/Prepare failure, changed full original/terminal
/// digest or sequence, mapping/context, native proof, held body or Commit receipt.
pub(crate) fn authenticate_historical_commit_data(
    key: &[u8; 32],
    ack: &HistoricalAck17<'_>,
    prepare: &HistoricalPrepare17<'_>,
    data: &HistoricalCommit17<'_>,
    canonical_mapping: &[u8],
    maximum_frame: usize,
) -> Result<(), ProviderError> {
    authenticate_historical_prepare_data(key, ack, prepare, maximum_frame)?;
    let response = completed_pair(data.pair, Method::Begin, maximum_frame)?;
    follows(prepare.pair, data.pair)?;
    data.context
        .authenticate_request_data(data.request, canonical_mapping)?;
    same_birth(
        ack.context,
        &[
            &data.context.restoration.source_birth,
            &data.context.restoration.kernel_binding,
            &data.context.restoration.policy_binding,
            &data.context.restoration.host_registration,
            &data.context.restoration.native_registration,
            &data.context.restoration.hello_request,
            &data.context.restoration.hello_response,
        ],
    )?;
    same_value(
        &data.request.prepare,
        prepare.request,
        MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES,
    )?;
    extension(
        data.pair.original,
        PACKET_COMPLETE_RESTORE_COMMIT_EXTENSION,
        data.request,
        MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES,
    )?;
    extension(
        data.pair.original,
        PACKET_COMPLETE_RESTORE_COMMIT_PROOF_EXTENSION,
        data.proof,
        MAXIMUM_COMPLETE_RESTORE_TRANSFER_PROOF_BYTES,
    )?;
    authenticate_target(ack, &data.request.prepare, data.pair.original)?;
    if prepare.pair.original.request_id.0.as_ref() != Some(&data.request.prepare_request_id)
        || prepare.pair.original.sequence != data.request.prepare_request_sequence
        || prepare.pair.terminal.sequence != data.request.prepare_response_sequence
    {
        return Err(invalid());
    }
    digest_matches(
        &data.request.prepare_request_digest,
        &complete_restore_transfer_original_digest(prepare.pair.original, maximum_frame)?,
    )?;
    digest_matches(
        &data.request.prepare_response_digest,
        &complete_restore_transfer_original_digest(prepare.pair.terminal, maximum_frame)?,
    )?;
    let prepare_receipt = PacketCompleteRestorePrepareReceipt::deserialize(
        prepare
            .pair
            .terminal
            .extensions
            .get(PACKET_COMPLETE_RESTORE_PREPARE_RECEIPT_EXTENSION)
            .ok_or_else(invalid)?,
    )
    .map_err(ContractError::from)?;
    if data.request.transfer_token != prepare_receipt.transfer_token {
        return Err(invalid());
    }
    digest_matches(
        &data.context.restoration.assigned_restore,
        &complete_restore_transfer_assigned_request_digest(
            data.pair.original,
            PacketCompleteRestoreTransferPhase::Commit,
            maximum_frame,
        )?,
    )?;
    verify_complete_restore_commit_proof_data(key, data.context, data.proof)?;

    let receipt = PacketCompleteRestoreCommitReceipt::deserialize(
        data.pair
            .terminal
            .extensions
            .get(PACKET_COMPLETE_RESTORE_COMMIT_RECEIPT_EXTENSION)
            .ok_or_else(invalid)?,
    )
    .map_err(ContractError::from)?;
    let assigned = complete_restore_transfer_assigned_response_digest(
        data.pair.original,
        data.pair.terminal,
        PacketCompleteRestoreTransferPhase::Commit,
        maximum_frame,
    )?;
    verify_complete_restore_commit_receipt_data(
        key,
        data.request,
        data.context,
        data.pair.terminal.sequence,
        &assigned,
        &receipt,
    )?;
    let result = restore_result(&response, ack.selection, &data.request.prepare)?;
    verify_reference(&result.closed_gate_receipt, data.held, crate::reference_packet::service::complete_restore::maximum_complete_restore_held_evidence_bytes()?)?;
    authenticate_held(data, ack.native_pid, maximum_frame)
}

pub(super) fn authenticate_held(
    data: &HistoricalCommit17<'_>,
    native_pid: U64,
    maximum_frame: usize,
) -> Result<(), ProviderError> {
    let held = data.held;
    held.validate_data()?;
    let request = &data.request.prepare;
    let target = &request.restoration;
    if held.native_pid != native_pid
        || held.target_world != target.target_world
        || held.target_owner != target.target_owner
        || held.target_owner_binding != target.target_owner_binding
        || held.target_activation != target.target_activation
        || held.target_generation != target.target_generation
        || held.captured_owner_state != target.owner_state
        || held.captured_control != request.native_control
        || held.captured_journal != target.journal
        || held.mapping != target.mapping
        || held.context_digest != data.proof.context_digest
    {
        return Err(invalid());
    }
    verify_reference(&held.restore_commit, data.pair.original, maximum_frame)?;
    Ok(())
}

fn same_birth(
    ack: &PacketCanonicalAckAdmissionContext,
    actual: &[&crucible_node_contract::Bytes; 7],
) -> Result<(), ProviderError> {
    for (actual, expected) in actual.iter().zip([
        &ack.source_birth,
        &ack.kernel_binding,
        &ack.policy_binding,
        &ack.host_registration,
        &ack.native_registration,
        &ack.hello_request,
        &ack.hello_response,
    ]) {
        if *actual != expected {
            return Err(invalid());
        }
    }
    Ok(())
}

fn fresh_prepare(original: &Envelope) -> bool {
    original
        .extensions
        .contains_key(PACKET_FRESH_RESTORE_ALLOCATION_PREPARE_BINDING)
}

fn prepare_assigned(original: &Envelope, maximum_frame: usize) -> Result<[u8; 32], ProviderError> {
    if fresh_prepare(original) {
        complete_restore_fresh_prepare_assigned_request_digest(original, maximum_frame)
    } else {
        complete_restore_transfer_assigned_request_digest(
            original,
            PacketCompleteRestoreTransferPhase::Prepare,
            maximum_frame,
        )
    }
}

fn authenticate_target(
    ack: &HistoricalAck17<'_>,
    request: &PacketCompleteRestorePrepareRequest,
    original: &Envelope,
) -> Result<(), ProviderError> {
    let [binding] = ack.selection.realization.bindings.as_slice() else {
        return Err(invalid());
    };
    let [owner] = ack.selection.realization.owner_bindings.as_slice() else {
        return Err(invalid());
    };
    let RequestBody::Begin(begin) = decode_request(original.method, &original.body)? else {
        return Err(invalid());
    };
    let BeginArguments::PrepareRestore(arguments) = begin.decoded_arguments()? else {
        return Err(invalid());
    };
    let target = &request.restoration;
    if original.session_id.0.as_ref() != Some(&ack.bindings.authority.session)
        || original.incarnation_id.0.as_ref() != Some(&ack.bindings.authority.incarnation)
        || original.node_id.0.as_ref() != Some(&binding.compatibility.node_id)
        || original.capture_owner_id.0.as_ref() != Some(&owner.owner.id)
        || original.execution_owner_id.0.is_some()
        || original.operation_id.0.is_none()
        || target.target_world != ack.selection.world
        || target.target_owner != owner.owner.id
        || target.target_owner_binding != owner.identity()?
        || target.target_owner_generation != binding.authority.owner_generation
        || begin.binding_hash != target.target_owner_binding
        || begin.activation_id.0.as_ref() != Some(&target.target_activation)
        || begin.world_generation != target.target_generation
        || begin.owner_generation != target.target_owner_generation
        || !begin.extensions.is_empty()
        || arguments.transaction_id != request.transaction_id
        || arguments.capture_manifest != target.capture_manifest
        || arguments.expected_world_binding_hash != target.target_world
        || arguments.expected_owner_binding_hash != target.target_owner_binding
        || arguments.destination_owner_ids.len() != 1
        || arguments.destination_owner_ids.first() != Some(&target.target_owner)
    {
        return Err(invalid());
    }
    Ok(())
}

fn restore_result<'a>(
    response: &'a ResponseBody,
    selection: &PacketControlSelection,
    request: &PacketCompleteRestorePrepareRequest,
) -> Result<&'a crate::bodies::PrepareRestoreResult, ProviderError> {
    let Some(MethodResult::PrepareRestore(result)) = response.result.as_ref() else {
        return Err(invalid());
    };
    result.validate()?;
    let target = &request.restoration;
    if result.transaction_id != request.transaction_id
        || result.prepared_token != selection.prepared_token
        || result.world_binding_hash != target.target_world
        || result.owner_binding_hash != target.target_owner_binding
        || result.staged_owner_ids.len() != 1
        || result.staged_owner_ids.first() != Some(&target.target_owner)
        || result.validated_manifest != target.capture_manifest
    {
        return Err(invalid());
    }
    Ok(result)
}
