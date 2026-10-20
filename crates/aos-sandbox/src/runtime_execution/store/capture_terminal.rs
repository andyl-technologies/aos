//! Extends the one already-settled terminal marker under the same writer.
//!
//! This metadata append cannot issue an effect, change the global sequence,
//! complete a second effect or settle a second capacity reservation. The Host
//! caller must hold its private genuine Storage/post gate before invoking it.

use aos_sandbox_core::{DecodeLimits, ExecutionOutputModeV1, decode_execution_spec_v1};
use aos_sandbox_protocol::host_execution::capture_terminal::{
    HostExecutionTerminalMarkerDataV3, encode_capture_terminal_marker_data_v3,
};
use aos_sandbox_protocol::storage_capture_result::CaptureCompleteRecordDataV2;

use super::*;

pub(super) fn decode_marker(bytes: &[u8])
    -> Result<HostExecutionTerminalMarkerDataV3<'_>, JournalRuntimeExecutionError>
{
    HostExecutionTerminalMarkerDataV3::decode_v3(bytes)
        .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)
}

pub(super) fn validate_result(
    effect: &DurableExecutionEffectV1,
    result: &CaptureCompleteRecordDataV2,
    correlation: &HostOutputCorrelationV1,
    claim: &RetainedClaim,
) -> Result<(), JournalRuntimeExecutionError> {
    let admission = effect.admission();
    let completion = effect.completion().ok_or(JournalRuntimeExecutionError::WrongPhase)?;
    if effect.phase() != EffectPhaseV1::Complete
        || !completion_observes_terminal_execution(effect, completion)?
        || result.host_settlement_digest != effect.record_commitment()
        || result.execution != *admission.execution().as_bytes()
        || result.execution != *correlation.execution.as_bytes()
        || result.create_operation != *correlation.create_operation.as_bytes()
        || result.assignment_digest != correlation.assignment_digest
        || result.claim_digest != correlation.claim_digest
        || result.claim_digest != claim.record_digest
        || result.create_operation != claim.create_operation
        || claim.stream_limits != Some((result.stdout.maximum_bytes, result.stderr.maximum_bytes))
    {
        return Err(JournalRuntimeExecutionError::RecordConflict);
    }

    // A zero-byte Capture is distinct from Stream. Read the existing canonical
    // spec with the same bounded Core decoder; a logical claim alone is not a
    // physical mode witness. Native Storage provenance is never inferred here.
    let specification = decode_execution_spec_v1(admission.specification_bytes(), DecodeLimits {
        maximum_bytes: admission.specification_bytes().len(),
        ..DecodeLimits::default()
    }).map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?;
    if specification.execution() != admission.execution()
        || specification.io().output_mode() != (ExecutionOutputModeV1::Capture {
            maximum_stdout_bytes: result.stdout.maximum_bytes,
            maximum_stderr_bytes: result.stderr.maximum_bytes,
        })
    {
        return Err(JournalRuntimeExecutionError::RecordConflict);
    }
    Ok(())
}

impl JournalRuntimeExecutionStoreV1<'_> {
    pub(super) fn validate_capture_terminal_result_v3(
        &self,
        effect: &DurableExecutionEffectV1,
        result: &CaptureCompleteRecordDataV2,
    ) -> Result<(), JournalRuntimeExecutionError> {
        let execution = effect.admission().execution();
        let correlation = self.authority.get(&host_output_key(execution))?
            .and_then(HostOutputCorrelationV1::decode)
            .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
        let claim = self.load_accepted_output_v2(execution)?
            .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
        validate_result(effect, result, &correlation, &claim)
    }

    pub(crate) fn capture_terminal_marker_v3(
        &self,
        effect: &DurableExecutionEffectV1,
    ) -> Result<Option<&[u8]>, JournalRuntimeExecutionError> {
        let execution = effect.admission().execution();
        let stored = self.load_effect(effect.issue().idempotency().operation().as_bytes())?
            .ok_or(JournalRuntimeExecutionError::MissingRecord)?;
        if &stored != effect || !self.terminal_marker_proves_admission(effect.admission())? {
            return Err(JournalRuntimeExecutionError::RecordConflict);
        }
        let bytes = self.authority.get(&terminal_key(execution))?
            .ok_or(JournalRuntimeExecutionError::CorruptRecord)?;
        let decoded = decode_marker(bytes)?;
        if decoded.original_bytes_v3().get(32..48)
            != Some(effect.issue().idempotency().operation().as_bytes().as_slice())
            || decoded.original_bytes_v3().get(48..80)
                != Some(effect.record_commitment().as_bytes().as_slice())
        {
            return Err(JournalRuntimeExecutionError::RecordConflict);
        }
        match decoded.capture_complete_v3() {
            Some(result) => {
                self.validate_capture_terminal_result_v3(effect, result)?;
                Ok(Some(bytes))
            }
            None => Ok(None),
        }
    }

    pub(crate) fn extend_capture_terminal_marker_v3(
        &mut self,
        effect: &DurableExecutionEffectV1,
        result: CaptureCompleteRecordDataV2,
    ) -> Result<(), JournalRuntimeExecutionError> {
        if self.capture_terminal_append_uncertain {
            return Err(JournalRuntimeExecutionError::CaptureTerminalReadbackUnknown);
        }
        self.validate_capture_terminal_result_v3(effect, &result)?;
        if let Some(bytes) = self.capture_terminal_marker_v3(effect)? {
            return if decode_marker(bytes)?.capture_complete_v3() == Some(&result) {
                Ok(())
            } else {
                Err(JournalRuntimeExecutionError::RecordConflict)
            };
        }
        // The established marker proves C1 and its already-settled reservation.
        // There is no reservation lookup/settlement or effect mutation here.
        let key = terminal_key(effect.admission().execution());
        let original = self.authority.get(&key)?
            .ok_or(JournalRuntimeExecutionError::MissingRecord)?;
        let bytes = encode_capture_terminal_marker_data_v3(original, result)
            .map_err(|_| JournalRuntimeExecutionError::RecordConflict)?;
        let digest = ObjectDigest::from_bytes(Sha256::digest(bytes).into());
        let transaction = JournalTransaction::new(
            transaction_id(b"capture-terminal-marker-v3", digest),
            vec![JournalRecord::put(RecordNamespace::Effect, key.clone(), bytes.to_vec())],
        )?;
        let expected_sequence = predicted_commit_sequence(self.authority.snapshot()?.sequence(), 1)
            .map_err(|_| JournalRuntimeExecutionError::CorruptRecord)?;
        let preflight = self.authority.preflight_transactions(std::slice::from_ref(&transaction))?;
        self.authority.validate_preflight_for_effect(&preflight, std::slice::from_ref(&transaction))?;

        // Set this before entry. A failed syscall/readback may follow durable
        // append; only a new protected cold claim may classify exact bytes.
        self.capture_terminal_append_uncertain = true;
        let committed = self.authority.commit(&transaction)
            .map_err(JournalRuntimeExecutionError::CaptureTerminalOutcomeUnknown)?;
        if committed.commit_sequence != expected_sequence
            || self.authority.get(&key).map_err(JournalRuntimeExecutionError::CaptureTerminalOutcomeUnknown)?
                != Some(bytes.as_slice())
        {
            return Err(JournalRuntimeExecutionError::CaptureTerminalReadbackUnknown);
        }
        self.capture_terminal_append_uncertain = false;
        Ok(())
    }
}
