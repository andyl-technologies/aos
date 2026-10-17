//! Inspects completed input custody after the same actual Commit has settled.
//!
//! The publication path still refuses any existing Commit. This separate reader
//! compares its retained Prepare and native receipt before visiting the same
//! six ACK ledgers. It creates no request, cut, retry, Source proof or authority.

use super::*;
use base64::Engine;
use std::mem::size_of;

impl OriginalCompleteRestoreInputUpload {
    /// Rechecks the same completed upload beneath its actual completed Commit.
    ///
    /// This read-only association predicate grants no restoration permission.
    /// Source must independently verify both keyed native receipts and the real
    /// original target/currentness before using the historical ACK chain.
    ///
    /// # Errors
    /// Refuses a foreign actor/emitter, missing or unsettled Prepare/Commit,
    /// changed full originals, another lease/mapping or incomplete ACK owners.
    pub fn authenticate_completed_original_after_commit(
        &self,
        controller: &CnpController,
        emitter: &OriginalCanonicalRestoreInputEmitter,
    ) -> Result<(), ProviderError> {
        emitter.authenticate_original(controller)?;
        if controller.original_native5_complete_restore_selection()?
            != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
            || controller.original_complete_restore.is_some()
        {
            return Err(refused());
        }
        let prepare = PrepareInputs::borrow_original_prepare(controller)?;
        let commit = controller
            .original_complete_restore_commit
            .as_ref()
            .ok_or_else(refused)?;
        commit.validate_owned_snapshot()?;
        let response = commit.response.as_ref().ok_or_else(refused)?;
        commit.original.validate()?;
        response.validate()?;
        commit.original.matches_response(response)?;
        let request = match CompleteRestoreTransferProjection::from_envelope(&commit.original)? {
            CompleteRestoreTransferProjection::Request {
                phase: PacketCompleteRestoreTransferPhase::Commit,
                request,
                ..
            } => request,
            _ => return Err(refused()),
        };
        let receipt = match CompleteRestoreTransferProjection::from_envelope(response)? {
            CompleteRestoreTransferProjection::Receipt {
                phase: PacketCompleteRestoreTransferPhase::Commit,
                receipt,
            } => receipt,
            _ => return Err(refused()),
        };
        if response.body.get("status").and_then(Value::as_str) != Some("completed")
            || response.body.get("operation_state").and_then(Value::as_str) != Some("completed")
            || receipt
                .get("native_sequence")
                .and_then(Value::as_str)
                .is_none_or(|v| v.parse::<u64>().ok() != Some(response.sequence.get()))
        {
            return Err(refused());
        }
        authenticate_completed_commit_baselines(&prepare, &commit.original, response, request)?;
        authenticate_commit_correspondence(
            &prepare,
            request,
            receipt,
            controller.maximum_frame()?,
        )?;
        self.authenticate_completed_inputs(controller, &prepare)
    }
}

impl CnpController {
    /// Returns fixed borrowed views for completed upload/Commit inspection.
    ///
    /// Existing whole-envelope digest/typed/serialization rows remain separate
    /// obligations. This number neither quotes their dynamic backing nor grants
    /// permission to enter the walk.
    pub fn original_complete_restore_input_inspection_counter_scratch_data() -> usize {
        size_of::<PrepareInputs<'static>>()
            + size_of::<Result<PrepareInputs<'static>, ProviderError>>()
            + size_of::<CompleteRestoreTransferProjection<'static>>()
            + size_of::<Result<CompleteRestoreTransferProjection<'static>, ProviderError>>()
            + size_of::<Option<&super::super::assigned_restore::AssignedOriginalCompleteRestore>>()
            + size_of::<
                Result<
                    &super::super::assigned_restore::AssignedOriginalCompleteRestore,
                    ProviderError,
                >,
            >()
            + size_of::<Option<&Envelope>>()
            + size_of::<Result<&Envelope, ProviderError>>()
            + size_of::<Option<&Value>>()
            + size_of::<Result<&Value, ProviderError>>()
            + size_of::<(&Envelope, &Envelope, &Value, &Value)>()
            + size_of::<(&CnpController, &OriginalCanonicalRestoreInputEmitter)>()
            + size_of::<[u8; 32]>()
            + size_of::<[(&str, &Envelope); 2]>()
            + size_of::<std::array::IntoIter<(&str, &Envelope), 2>>()
            + size_of::<[u8; 32]>()
            + size_of::<&[u8]>()
            + size_of::<Result<usize, base64::DecodeSliceError>>()
            + size_of::<Result<(), ProviderError>>()
            + size_of::<Result<[u8; 32], ProviderError>>()
    }
}

// The caller first validates both actual SDK owning slots and the full closed
// Commit/receipt grammar. Keeping this borrowed comparison separate permits
// data controls without constructing a fake controller, grant or completion.
fn authenticate_commit_correspondence(
    prepare: &PrepareInputs<'_>,
    commit: &Value,
    receipt: &Value,
    maximum: usize,
) -> Result<(), ProviderError> {
    let original = prepare.original;
    let response = prepare.response;
    let expected = original
        .extensions
        .get(PACKET_COMPLETE_RESTORE_PREPARE_EXTENSION)
        .ok_or_else(refused)?;
    let prepare_receipt = response
        .extensions
        .get(PACKET_COMPLETE_RESTORE_PREPARE_RECEIPT_EXTENSION)
        .ok_or_else(refused)?;
    if commit.get("prepare") != Some(expected)
        || commit.get("prepare_request_id").and_then(Value::as_str)
            != Some(prepare.request_id.as_str())
        || inputs::decimal(commit.get("prepare_request_sequence").ok_or_else(refused)?)?
            != original.sequence.get()
        || inputs::decimal(
            commit
                .get("prepare_response_sequence")
                .ok_or_else(refused)?,
        )? != response.sequence.get()
        || commit.get("transfer_token") != prepare_receipt.get("transfer_token")
        || receipt.get("transfer_token") != prepare_receipt.get("transfer_token")
        || receipt.get("installed_mapping")
            != expected.get("restoration").and_then(|r| r.get("mapping"))
    {
        return Err(refused());
    }
    for (field, envelope) in [
        ("prepare_request_digest", original),
        ("prepare_response_digest", response),
    ] {
        let actual = complete_restore_transfer_original_digest(envelope, maximum)?;
        // The closed projection validates exact digest grammar first. Borrow
        // its text and decode into the fixed stack bank; Bytes::deserialize
        // would independently allocate an encoded String and a 33-byte Vec.
        let encoded = commit
            .get(field)
            .and_then(Value::as_str)
            .ok_or_else(refused)?;
        let mut expected = [0u8; 32];
        let written = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode_slice(encoded, &mut expected)
            .map_err(|_| refused())?;
        if written != expected.len() || expected != actual {
            return Err(refused());
        }
    }
    Ok(())
}

fn authenticate_completed_commit_baselines(
    prepare: &PrepareInputs<'_>,
    commit_original: &Envelope,
    commit_response: &Envelope,
    commit: &Value,
) -> Result<(), ProviderError> {
    let transaction = prepare
        .original
        .body
        .get("arguments")
        .and_then(|v| v.get("transaction_id"))
        .and_then(Value::as_str)
        .ok_or_else(refused)?;
    let original_prepare = prepare
        .original
        .extensions
        .get(PACKET_COMPLETE_RESTORE_PREPARE_EXTENSION)
        .ok_or_else(refused)?;
    if original_prepare
        .get("transaction_id")
        .and_then(Value::as_str)
        != Some(transaction)
        || commit
            .get("prepare")
            .and_then(|v| v.get("transaction_id"))
            .and_then(Value::as_str)
            != Some(transaction)
        || commit_original
            .body
            .get("arguments")
            .and_then(|v| v.get("transaction_id"))
            .and_then(Value::as_str)
            != Some(transaction)
        || commit_response
            .body
            .get("result")
            .and_then(|v| v.get("transaction_id"))
            .and_then(Value::as_str)
            != Some(transaction)
    {
        return Err(refused());
    }
    Ok(())
}

#[cfg(test)]
mod tests;
