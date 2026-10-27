//! Borrows actual Chunk/Finish inputs against an independently authenticated seed.
//!
//! Context and digest arguments are correspondence DATA. The actual private
//! scope must supply the genuine same-Boot published seed, validate its Source
//! MAC, exact latest prior publication/poststate, offset grid and new native
//! debit. These helpers cannot find that owner or issue a continuation token.

use super::*;
use crate::reference_packet::service::restored_settled_capture::upload::{
    PacketRestoredSettledCaptureUploadOrdinal, PacketRestoredSettledCaptureUploadRequest,
};
use crucible_node_format::Id;

type ContinuationInput<'a> = (
    &'a Envelope,
    NativeCapture17UploadInput<'a>,
    &'a PacketRestoredSettledCaptureUploadContinuation,
);

type QuoteParts<'a> = (
    &'a Envelope,
    NativeCapture17UploadInput<'a>,
    PacketNativeStartupAllocationRow,
);

fn authenticate_identity(
    continuation: &PacketRestoredSettledCaptureUploadContinuation,
    transfer: &Id,
    capture_operation: &Id,
    seed_context_digest: &[u8],
) -> Result<(), ProviderError> {
    if continuation.schema != restored_settled_capture_upload_schema_ids_data().2
        || seed_context_digest.len() != 32
        || continuation.context_digest.as_slice() != seed_context_digest
        || &continuation.transfer_id != transfer
        || &continuation.capture_operation != capture_operation
    {
        return Err(invalid());
    }
    Ok(())
}

fn authenticate_routing(
    original: &Envelope,
    request: &PacketRestoredSettledCaptureUploadRequest,
) -> Result<(), ProviderError> {
    let target = &request.capture.scope.target;
    if original.protocol != "CNP/1"
        || original.message != MessageKind::Request
        || !matches!(original.method, Method::BlobChunk | Method::BlobFinish)
        || original.request_id.0.is_none()
        || original.sequence.get() == 0
        || original.sequence < request.capture.history_next_sequence
        || original.operation_id.0.is_some()
        || original.execution_owner_id.0.is_some()
        || original.session_id.0.as_ref() != Some(&target.session)
        || original.incarnation_id.0.as_ref() != Some(&target.incarnation)
        || original.node_id.0.as_ref() != Some(&target.node)
        || original.capture_owner_id.0.as_ref() != Some(&request.capture.capture_owner)
        || original.extensions.len() != 1
        || !original
            .extensions
            .contains_key(RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE)
    {
        return Err(invalid());
    }
    Ok(())
}

impl NativeRestoredSettledCaptureUploadAttempt {
    fn continuation_upload17_input_data<'a>(
        &'a self,
    ) -> Result<ContinuationInput<'a>, ProviderError> {
        let original = self.original_data()?;
        let key = |transfer: &'a Id| -> Result<NativeCapture17UploadKey<'a>, ProviderError> {
            Ok(NativeCapture17UploadKey {
                origin: RequestOrigin::Controller,
                session: original.session_id.0.as_ref().ok_or_else(invalid)?,
                incarnation: original.incarnation_id.0.as_ref().ok_or_else(invalid)?,
                transfer,
            })
        };
        match self.phase17_data()? {
            source_occurrence17::NativeCapture17PhaseData::Chunk { body, continuation } => {
                if original.method != Method::BlobChunk || !body.extensions.is_empty() {
                    return Err(invalid());
                }
                Ok((
                    original,
                    NativeCapture17UploadInput::Chunk {
                        key: key(&body.transfer_id)?,
                        offset: body.offset,
                        bytes: &body.bytes,
                    },
                    continuation,
                ))
            }
            source_occurrence17::NativeCapture17PhaseData::Finish { body, continuation } => {
                if original.method != Method::BlobFinish || !body.extensions.is_empty() {
                    return Err(invalid());
                }
                Ok((
                    original,
                    NativeCapture17UploadInput::Finish {
                        key: key(&body.transfer_id)?,
                    },
                    continuation,
                ))
            }
            source_occurrence17::NativeCapture17PhaseData::UploadBegin { .. }
            | source_occurrence17::NativeCapture17PhaseData::Capture { .. }
            | source_occurrence17::NativeCapture17PhaseData::Confirmation { .. } => Err(invalid()),
        }
    }

    /// Borrows the actual continuation input and its seed-signed bound as DATA.
    ///
    /// The scope provides the actual retained seed context and the 32-byte
    /// context digest from its Source-verified proof. No context serialization,
    /// digest recomputation, native owner lookup or permission is performed.
    ///
    /// # Errors
    /// Refuses a non-Chunk/Finish or nonvacant owner, wrong native definition,
    /// seed/request/continuation/routing disagreement or invalid row arithmetic.
    pub(crate) fn continuation_upload17_quote_parts_data(
        &self,
        seed: &PacketRestoredSettledCaptureUploadContext,
        seed_context_digest: &[u8],
    ) -> Result<QuoteParts<'_>, ProviderError> {
        if self.upload_action.is_some()
            || self.base.checkpoint.is_some()
            || self.base.outputs.is_some()
            || self.base.terminal.is_some()
            || self.base.prepared_reply.is_some()
        {
            return Err(invalid());
        }
        let (original, input, continuation) = self.continuation_upload17_input_data()?;
        let (request_schema, context_schema, _) = restored_settled_capture_upload_schema_ids_data();
        let request = &seed.request;
        if seed.schema != context_schema
            || seed.assigned_request.as_slice().len() != 32
            || request.schema != request_schema
        {
            return Err(invalid());
        }
        let expected_content = match request.ordinal {
            PacketRestoredSettledCaptureUploadOrdinal::HistoryPrefix => {
                &request.capture.history_prefix
            }
            PacketRestoredSettledCaptureUploadOrdinal::RuntimeObject => {
                &request.capture.runtime_object
            }
        };
        if &request.content != expected_content || input.key_data().transfer != &request.transfer_id
        {
            return Err(invalid());
        }
        authenticate_identity(
            continuation,
            &request.transfer_id,
            &request.capture.capture_operation,
            seed_context_digest,
        )?;
        authenticate_routing(original, request)?;
        crate::reference_packet::service::native_snapshot::authenticate_native_restored_settled17_snapshot_definition_data(
            &request.capture.native_schema,
        )?;
        request.native_allocation.requested_peak_data()?;
        Ok((original, input, request.native_allocation))
    }

    /// Installs the actual predebited continuation and retains any short-row failure.
    ///
    /// The immutable source correspondence is rechecked before installation.
    /// The actual native scope independently owns the debit and its exact stored
    /// receiver/input quote; this method neither issues nor renews that grant.
    ///
    /// # Errors
    /// Refuses another seed/phase, reused custody, a Blob-short admitted row or
    /// demand above the seed bound, keeping every installed failure owner.
    pub(crate) fn install_continuation_upload17_action_data(
        &mut self,
        storage: NativeCapture17UploadStorageData,
        row: PacketNativeStartupAllocationRow,
        seed: &PacketRestoredSettledCaptureUploadContext,
        seed_context_digest: &[u8],
    ) -> Result<(), ProviderError> {
        let result = (|| {
            let (_, _, signed) =
                self.continuation_upload17_quote_parts_data(seed, seed_context_digest)?;
            NativeCapture17UploadActionAttempt::install_into_data(
                storage,
                row,
                &mut self.upload_action,
            )?;
            signed.authenticate_actual_data(&row)
        })();
        if result.is_err() {
            self.interrupt_data();
        }
        result
    }

    /// Executes only the retained real Chunk/Finish through the scope's exact token.
    ///
    /// The genuine scope authenticates the same actual input quotation before
    /// mutation. The actual typed body, real Blob partials and produced reply
    /// remain in this once owner throughout; no context is reconstructed here.
    ///
    /// # Errors
    /// Refuses failed/reused/noncontinuation custody, another input/receiver or
    /// a primitive/reply/private-fence error, retaining and poisoning partials.
    pub(crate) fn execute_continuation_upload17_data(
        &mut self,
        receiver: &mut BlobReceiver,
        scope: &OriginalNativeCapture17Read,
    ) -> Result<(), ProviderError> {
        let result = (|| {
            self.continuation_upload17_input_data()?;
            if self.base.prepared_reply.is_some() || self.base.terminal.is_some() {
                return Err(invalid());
            }
            let original = self.base.original.as_ref().ok_or_else(invalid)?;
            let input = match self.base.body.as_ref().ok_or_else(invalid)? {
                Body::BlobChunk(body) => NativeCapture17UploadInput::Chunk {
                    key: NativeCapture17UploadKey {
                        origin: RequestOrigin::Controller,
                        session: original.session_id.0.as_ref().ok_or_else(invalid)?,
                        incarnation: original.incarnation_id.0.as_ref().ok_or_else(invalid)?,
                        transfer: &body.transfer_id,
                    },
                    offset: body.offset,
                    bytes: &body.bytes,
                },
                Body::BlobFinish(body) => NativeCapture17UploadInput::Finish {
                    key: NativeCapture17UploadKey {
                        origin: RequestOrigin::Controller,
                        session: original.session_id.0.as_ref().ok_or_else(invalid)?,
                        incarnation: original.incarnation_id.0.as_ref().ok_or_else(invalid)?,
                        transfer: &body.transfer_id,
                    },
                },
                _ => return Err(invalid()),
            };
            let transaction = self.upload_action.as_mut().ok_or_else(invalid)?;
            transaction.execute_and_produce_reply_data(receiver, scope, input)?;
            self.base.prepared_reply = Some(transaction.reply_data()?.clone());
            Ok(())
        })();
        if result.is_err() {
            self.interrupt_data();
        }
        result
    }

    /// Names the actual borrowed continuation/routing/schema and effect split views.
    pub(crate) fn continuation_upload17_counter_scratch_data() -> usize {
        size_of::<&Self>()
            + size_of::<ContinuationInput<'static>>()
            + size_of::<Result<ContinuationInput<'static>, ProviderError>>()
            + size_of::<QuoteParts<'static>>()
            + size_of::<Result<QuoteParts<'static>, ProviderError>>()
            + size_of::<NativeCapture17UploadInput<'static>>()
            + size_of::<NativeCapture17UploadKey<'static>>()
            + size_of::<&PacketRestoredSettledCaptureUploadContext>()
            + size_of::<&PacketRestoredSettledCaptureUploadRequest>()
            + size_of::<&Envelope>()
            + size_of::<(
                &mut Self,
                NativeCapture17UploadStorageData,
                PacketNativeStartupAllocationRow,
                &PacketRestoredSettledCaptureUploadContext,
                &[u8],
            )>()
            + size_of::<(&mut Self, &mut BlobReceiver, &OriginalNativeCapture17Read)>()
            + size_of::<&PacketRestoredSettledCaptureUploadContinuation>()
            + size_of::<&[u8]>()
            + size_of::<&Id>() * 2
            + size_of::<&ContentRef>()
            + size_of::<(&str, &str, &str)>()
            + size_of::<&mut BlobReceiver>()
            + size_of::<&OriginalNativeCapture17Read>()
            + size_of::<&mut NativeCapture17UploadActionAttempt>()
            + size_of::<Result<(), ProviderError>>()
            + source_occurrence17::capture17_phase_counter_scratch_data()
            + native_capture17_upload_action_counter_scratch_data()
            + crate::reference_packet::service::native_snapshot::native_restored_settled17_snapshot_schema_counter_scratch_data()
    }
}

#[cfg(test)]
#[path = "continuation_tests.rs"]
mod tests;
