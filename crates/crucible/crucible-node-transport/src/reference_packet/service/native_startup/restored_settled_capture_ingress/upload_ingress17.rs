//! Retains the distinct Blob-only CaptureUpload17 ingress and transaction.
//!
//! Fifteen shared Capture fields own the raw and typed upload partials. This
//! wrapper adds the real upload action as a sixteenth field. The final-Capture
//! registration and receipt slots must be absent; observation and serialization
//! refuse populated slots rather than silently omitting their owners.

use super::upload17::{
    NativeCapture17UploadActionAttempt, native_capture17_upload_action_counter_scratch_data,
};
use super::*;
use crate::blob::{
    BlobReceiver, NativeCapture17UploadInput, NativeCapture17UploadKey,
    NativeCapture17UploadStorageData,
};
use crate::envelope::RequestOrigin;
use crate::reference_packet::service::ack_emitter::OriginalNativeCapture17Read;
use std::cell::RefCell;

/// Owns the common ingress fields and a separately retained upload action.
pub(crate) struct NativeRestoredSettledCaptureUploadAttempt {
    base: NativeRestoredSettledCaptureAttempt,
    upload_action: Option<NativeCapture17UploadActionAttempt>,
}

impl NativeRestoredSettledCaptureUploadAttempt {
    /// Initializes only raw custody after the real parent spends this occurrence.
    pub(crate) fn new_data(ordinal: u64) -> Self {
        Self {
            base: NativeRestoredSettledCaptureAttempt::new_data(ordinal),
            upload_action: None,
        }
    }

    fn authenticate_blob_method_data(&self) -> Result<(), ProviderError> {
        if !matches!(
            self.base.original_data()?.method,
            Method::BlobBegin | Method::BlobChunk | Method::BlobFinish
        ) {
            return Err(invalid());
        }
        Ok(())
    }

    /// Retains the actual raw original before enforcing the Blob-only family.
    ///
    /// # Errors
    /// Preserves raw custody on failed base validation or a non-Blob method and
    /// permanently poisons the wrapper without entering another family.
    pub(crate) fn retain_original_data(&mut self, original: Envelope) -> Result<(), ProviderError> {
        let result = self
            .base
            .retain_original_data(original)
            .and_then(|()| self.authenticate_blob_method_data());
        if result.is_err() {
            self.interrupt_data();
        }
        result
    }

    /// Borrows the same retained original, including raw/failed custody.
    ///
    /// # Errors
    /// Refuses an occurrence without an installed raw original.
    pub(crate) fn original_data(&self) -> Result<&Envelope, ProviderError> {
        self.base.original_data()
    }

    /// Delegates real decoding only after the closed Blob family check.
    ///
    /// # Errors
    /// Preserves each raw/typed partial and poisons wrong methods, reused stages,
    /// malformed bodies/extensions, failed validation or finite frame bounds.
    pub(crate) fn decode_body_data(&mut self, maximum_frame: usize) -> Result<(), ProviderError> {
        let result = self
            .authenticate_blob_method_data()
            .and_then(|()| self.base.decode_body_data(maximum_frame));
        if result.is_err() {
            self.interrupt_data();
        }
        result
    }

    /// Borrows only a complete actual upload phase without authenticating its MAC.
    ///
    /// # Errors
    /// Refuses failed/incomplete custody or any final-Capture/confirmation phase.
    pub(crate) fn phase17_data(
        &self,
    ) -> Result<source_occurrence17::NativeCapture17PhaseData<'_>, ProviderError> {
        self.authenticate_blob_method_data()?;
        let phase = self.base.phase17_data()?;
        match phase {
            source_occurrence17::NativeCapture17PhaseData::UploadBegin { .. }
            | source_occurrence17::NativeCapture17PhaseData::Chunk { .. }
            | source_occurrence17::NativeCapture17PhaseData::Finish { .. } => Ok(phase),
            source_occurrence17::NativeCapture17PhaseData::Capture { .. }
            | source_occurrence17::NativeCapture17PhaseData::Confirmation { .. } => Err(invalid()),
        }
    }

    /// Delegates the actual assigned Begin context and Source-MAC verification.
    ///
    /// # Errors
    /// Preserves failed Context/typed custody and poisons non-Begin phases,
    /// invalid assignment, wrong actual Boot key, or malformed/MAC-invalid data.
    pub(crate) fn authenticate_upload_source_data(
        &mut self,
        key: &[u8; 32],
        maximum_frame: usize,
    ) -> Result<(), ProviderError> {
        let result = (|| {
            if self.original_data()?.method != Method::BlobBegin {
                return Err(invalid());
            }
            self.base
                .authenticate_upload_source_data(key, maximum_frame)
        })();
        if result.is_err() {
            self.interrupt_data();
        }
        result
    }

    /// Rechecks the actual retained assigned seed with the genuine Boot key.
    ///
    /// # Errors
    /// Refuses another phase, incomplete/changed original or invalid Source MAC;
    /// it supplies no continuation lease or native action permission.
    pub(crate) fn authenticate_retained_upload_source17_data(
        &self,
        key: &[u8; 32],
        maximum_frame: usize,
    ) -> Result<(), ProviderError> {
        self.authenticate_blob_method_data()?;
        self.base
            .authenticate_retained_upload_source17_data(key, maximum_frame)
    }

    fn assigned_upload17_input_data(
        &self,
    ) -> Result<
        (
            &Envelope,
            NativeCapture17UploadInput<'_>,
            PacketNativeStartupAllocationRow,
        ),
        ProviderError,
    > {
        let source_occurrence17::NativeCapture17PhaseData::UploadBegin { body, artifact, .. } =
            self.phase17_data()?
        else {
            return Err(invalid());
        };
        let original = self.original_data()?;
        Ok((
            original,
            NativeCapture17UploadInput::Begin {
                key: NativeCapture17UploadKey {
                    origin: RequestOrigin::Controller,
                    session: original.session_id.0.as_ref().ok_or_else(invalid)?,
                    incarnation: original.incarnation_id.0.as_ref().ok_or_else(invalid)?,
                    transfer: &body.transfer_id,
                },
                content: &body.content,
            },
            artifact.request.native_allocation,
        ))
    }

    /// Borrows the actual assigned Begin before any upload transaction is installed.
    ///
    /// Chunk/Finish execution remains closed until its genuine seed chronology
    /// joins. Their actual raw/typed state is retained by this family meanwhile.
    ///
    /// # Errors
    /// Refuses another phase, existing transaction/output/terminal or reused reply.
    pub(crate) fn assigned_upload17_quote_parts_data(
        &self,
    ) -> Result<
        (
            &Envelope,
            NativeCapture17UploadInput<'_>,
            PacketNativeStartupAllocationRow,
        ),
        ProviderError,
    > {
        if self.upload_action.is_some()
            || self.base.checkpoint.is_some()
            || self.base.outputs.is_some()
            || self.base.terminal.is_some()
            || self.base.prepared_reply.is_some()
        {
            return Err(invalid());
        }
        let parts = self.assigned_upload17_input_data()?;
        let artifact = self.base.upload.as_ref().ok_or_else(invalid)?;
        crate::reference_packet::service::native_snapshot::authenticate_native_restored_settled17_snapshot_definition_data(
            &artifact.request.capture.native_schema,
        )?;
        Ok(parts)
    }

    /// Installs the actual predebited transaction and keeps short-row failure.
    ///
    /// # Errors
    /// Refuses a reused/wrong phase or independently short row; partial custody
    /// remains installed and the base/transaction cannot be reopened.
    pub(crate) fn install_upload17_action_data(
        &mut self,
        storage: NativeCapture17UploadStorageData,
        row: PacketNativeStartupAllocationRow,
    ) -> Result<(), ProviderError> {
        let result = self
            .assigned_upload17_quote_parts_data()
            .map(|_| ())
            .and_then(|()| {
                NativeCapture17UploadActionAttempt::install_into_data(
                    storage,
                    row,
                    &mut self.upload_action,
                )
            });
        if result.is_err() {
            self.interrupt_data();
        }
        result
    }

    /// Executes the real assigned Begin and retains its separately admitted reply clone.
    ///
    /// # Errors
    /// Refuses failed/reused/foreign Source custody or actual primitive/reply
    /// failure, keeping every nested partial and permanently poisoning the base.
    pub(crate) fn execute_assigned_upload17_data(
        &mut self,
        receiver: &mut BlobReceiver,
        scope: &OriginalNativeCapture17Read,
    ) -> Result<(), ProviderError> {
        let result = (|| {
            if self.base.stage != Stage::Typed
                || self.base.prepared_reply.is_some()
                || self.base.terminal.is_some()
            {
                return Err(invalid());
            }
            let original = self.base.original.as_ref().ok_or_else(invalid)?;
            let Some(Body::BlobBegin(body)) = self.base.body.as_ref() else {
                return Err(invalid());
            };
            let input = NativeCapture17UploadInput::Begin {
                key: NativeCapture17UploadKey {
                    origin: RequestOrigin::Controller,
                    session: original.session_id.0.as_ref().ok_or_else(invalid)?,
                    incarnation: original.incarnation_id.0.as_ref().ok_or_else(invalid)?,
                    transfer: &body.transfer_id,
                },
                content: &body.content,
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

    /// Borrows the same retained original and real completed reply clone.
    ///
    /// # Errors
    /// Refuses failed/partial custody or a clone differing from its real Blob result.
    pub(crate) fn prepared_upload17_reply_parts_data(
        &self,
    ) -> Result<(&Envelope, &Map<String, Value>), ProviderError> {
        self.phase17_data()?;
        let original = self.original_data()?;
        let reply = self.base.prepared_reply.as_ref().ok_or_else(invalid)?;
        if self
            .upload_action
            .as_ref()
            .ok_or_else(invalid)?
            .reply_data()?
            != reply
        {
            return Err(invalid());
        }
        Ok((original, reply))
    }

    /// Starts the once publication before parent transport work.
    ///
    /// # Errors
    /// Refuses an absent actual reply, failed transaction or repeated publication.
    pub(crate) fn begin_upload17_publication_data(&mut self) -> Result<(), ProviderError> {
        self.prepared_upload17_reply_parts_data()?;
        self.upload_action
            .as_mut()
            .ok_or_else(invalid)?
            .begin_publication_data()
    }

    /// Retains the actual routed terminal under its independently admitted clone row.
    ///
    /// # Errors
    /// Refuses reused custody, routing/body mismatch or terminal extensions.
    pub(crate) fn retain_upload17_terminal_data(
        &mut self,
        terminal: &Envelope,
    ) -> Result<(), ProviderError> {
        let (original, body) = self.prepared_upload17_reply_parts_data()?;
        original.matches_response(terminal)?;
        if self.base.terminal.is_some() || &terminal.body != body || !terminal.extensions.is_empty()
        {
            return Err(invalid());
        }
        self.base.terminal = Some(terminal.clone());
        Ok(())
    }

    /// Completes bookkeeping only after the private parent's actual publication proof.
    ///
    /// # Errors
    /// Refuses changed/absent terminal, incomplete reply or repeated publication.
    pub(crate) fn complete_upload17_publication_data(
        &mut self,
        terminal: &Envelope,
        record: usize,
    ) -> Result<(), ProviderError> {
        self.prepared_upload17_reply_parts_data()?;
        if self.base.terminal.as_ref() != Some(terminal) {
            return Err(invalid());
        }
        self.upload_action
            .as_mut()
            .ok_or_else(invalid)?
            .complete_publication_data(record)
    }

    /// Poisons both base and transaction without discarding any retained state.
    pub(crate) fn interrupt_data(&mut self) {
        self.base.interrupt_data();
        if let Some(action) = &mut self.upload_action {
            action.interrupt_data();
        }
    }

    /// Observes the same sixteen source fields with actual aliases and capacities.
    ///
    /// # Errors
    /// Refuses exhausted caller banks, overflow or unavailable child metadata.
    pub(crate) fn observe_settled_history_metadata_data(
        &self,
        observer: &mut MetadataObserver<'_>,
    ) -> Result<(), ProviderError> {
        let Self {
            base,
            upload_action,
        } = self;
        let NativeRestoredSettledCaptureAttempt {
            ordinal,
            original,
            body,
            arguments,
            capture,
            capture_context,
            upload,
            upload_context,
            continuation,
            confirmation,
            registration,
            checkpoint,
            outputs,
            terminal,
            prepared_reply,
            confirmation_receipt,
            stage,
        } = base;
        if registration.is_some() || confirmation_receipt.is_some() {
            return Err(invalid());
        }
        observer.observe(ordinal)?;
        observer.observe(original)?;
        if let Some(body) = body {
            match body {
                Body::Capture(value) => observer.observe(value)?,
                Body::BlobBegin(value) => {
                    let BlobBeginRequest {
                        transfer_id,
                        content,
                        extensions,
                    } = value;
                    observer.observe(transfer_id)?;
                    observer.observe(content)?;
                    observer.observe(extensions)?;
                }
                Body::BlobChunk(value) => {
                    let BlobChunkRequest {
                        transfer_id,
                        offset,
                        bytes,
                        extensions,
                    } = value;
                    observer.observe(transfer_id)?;
                    observer.observe(offset)?;
                    observer.observe(bytes)?;
                    observer.observe(extensions)?;
                }
                Body::BlobFinish(value) => {
                    let BlobFinishRequest {
                        transfer_id,
                        extensions,
                    } = value;
                    observer.observe(transfer_id)?;
                    observer.observe(extensions)?;
                }
                Body::Confirmation(value) => {
                    let PollRequest {
                        after_observation_sequence,
                        extensions,
                    } = value;
                    observer.observe(after_observation_sequence)?;
                    observer.observe(extensions)?;
                }
            }
        }
        if let Some(arguments) = arguments {
            let CaptureArguments {
                capture_id,
                participant_ids,
                cut_id,
                cut,
                event_ordinal,
                ordering_profile,
                preservation_contract,
            } = arguments;
            observer.observe(capture_id)?;
            observer.observe(participant_ids)?;
            observer.observe(cut_id)?;
            observer.observe(cut)?;
            observer.observe(event_ordinal)?;
            observer.observe(ordering_profile)?;
            observer.observe(preservation_contract)?;
        }
        observer.observe(capture)?;
        observer.observe(capture_context)?;
        observer.observe(upload)?;
        observer.observe(upload_context)?;
        observer.observe(continuation)?;
        if let Some(value) = confirmation {
            let PacketRestoredSettledAfterConfirmationRequest {
                schema,
                capture_request_id,
                capture_request_hash,
                capture_operation_id,
                capture_terminal_hash,
                capture_terminal_sequence,
                settled_capture_request,
                native_snapshot_ref,
                native_control_ref,
                native_anchor_ref,
            } = value;
            observer.observe(schema)?;
            observer.observe(capture_request_id)?;
            observer.observe(capture_request_hash)?;
            observer.observe(capture_operation_id)?;
            observer.observe(capture_terminal_hash)?;
            observer.observe(capture_terminal_sequence)?;
            observer.observe(settled_capture_request)?;
            observer.observe(native_snapshot_ref)?;
            observer.observe(native_control_ref)?;
            observer.observe(native_anchor_ref)?;
        }
        if let Some(action) = upload_action {
            action.observe_current17_metadata_data(observer)?;
        }
        if let Some(checkpoint) = checkpoint {
            checkpoint.observe_settled_history_metadata_data(observer)?;
        }
        if let Some(output) = outputs {
            output.observe_current17_metadata_data(observer)?;
        }
        observer.observe(terminal)?;
        observer.observe(prepared_reply)?;
        let stage = match stage {
            Stage::Receiving => 0usize,
            Stage::Raw => 1,
            Stage::Typed => 2,
            Stage::Failed => 3,
        };
        observer.observe(&stage)
    }
}

impl serde::Serialize for NativeRestoredSettledCaptureUploadAttempt {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeStruct;
        let Self {
            base,
            upload_action,
        } = self;
        let NativeRestoredSettledCaptureAttempt {
            ordinal,
            original,
            body,
            arguments,
            capture,
            capture_context,
            upload,
            upload_context,
            continuation,
            confirmation,
            registration,
            checkpoint,
            outputs,
            terminal,
            prepared_reply,
            confirmation_receipt,
            stage,
        } = base;
        if registration.is_some() || confirmation_receipt.is_some() {
            return Err(serde::ser::Error::custom(
                "Capture owners in upload ingress",
            ));
        }
        let mut fields = serializer.serialize_struct("NativeCaptureUploadIngress17", 16)?;
        fields.serialize_field("ordinal", ordinal)?;
        fields.serialize_field("original", original)?;
        fields.serialize_field("body", body)?;
        fields.serialize_field("arguments", arguments)?;
        fields.serialize_field("capture", capture)?;
        fields.serialize_field("capture_context", capture_context)?;
        fields.serialize_field("upload", upload)?;
        fields.serialize_field("upload_context", upload_context)?;
        fields.serialize_field("continuation", continuation)?;
        fields.serialize_field("confirmation", confirmation)?;
        fields.serialize_field("upload_action", upload_action)?;
        fields.serialize_field("checkpoint", checkpoint)?;
        fields.serialize_field("outputs", outputs)?;
        fields.serialize_field("terminal", terminal)?;
        fields.serialize_field("prepared_reply", prepared_reply)?;
        fields.serialize_field("stage", stage)?;
        fields.end()
    }
}

/// Derives the enlarged wrapper receive row from the unchanged base ingress.
///
/// This adds actual wrapper/RefCell/shared-header layouts conservatively, never
/// treating the old DATA census as allocation credit. Effect/transport rows are
/// still independently admitted by the genuine Source/native occurrence.
///
/// # Errors
/// Refuses the same invalid frame/extent as the base or checked layout overflow.
pub fn original_restored_settled_capture_upload_ingress_row_data(
    maximum_frame: usize,
) -> Result<PacketNativeStartupAllocationRow, ProviderError> {
    let mut row = original_restored_settled_capture_ingress_row_data(maximum_frame)?;
    let fixed = sum(&[
        size_of::<NativeRestoredSettledCaptureUploadAttempt>(),
        size_of::<RefCell<NativeRestoredSettledCaptureUploadAttempt>>(),
        crate::retained_metadata::requested_storage::shared_header_storage_data(
            1,
            std::mem::align_of::<RefCell<NativeRestoredSettledCaptureUploadAttempt>>(),
        )?,
    ])?;
    row.retained_requested_bytes = row.retained_requested_bytes.checked_add(quantity(fixed)?)?;
    row.declared_counter_scratch_bytes = row.declared_counter_scratch_bytes.checked_add(
        quantity(original_restored_settled_capture_upload_ingress_counter_scratch_data())?,
    )?;
    row.requested_peak_data()?;
    Ok(row)
}

/// Names only this defining wrapper, disjoint loans and transaction controls.
///
/// The unchanged base counter is composed by the row caller, not called here,
/// avoiding a receiver/Scope/wrapper counter dependency cycle.
pub fn original_restored_settled_capture_upload_ingress_counter_scratch_data() -> usize {
    size_of::<NativeRestoredSettledCaptureUploadAttempt>()
        + size_of::<RefCell<NativeRestoredSettledCaptureUploadAttempt>>()
        + size_of::<NativeCapture17UploadInput<'static>>()
        + size_of::<NativeCapture17UploadKey<'static>>()
        + size_of::<(
            &Envelope,
            NativeCapture17UploadInput<'static>,
            PacketNativeStartupAllocationRow,
        )>()
        + size_of::<
            Result<
                (
                    &Envelope,
                    NativeCapture17UploadInput<'static>,
                    PacketNativeStartupAllocationRow,
                ),
                ProviderError,
            >,
        >()
        + size_of::<Result<(&Envelope, &Map<String, Value>), ProviderError>>()
        + size_of::<[usize; 3]>()
        + field_view_bytes(
            |value: &'static NativeRestoredSettledCaptureUploadAttempt| {
                let NativeRestoredSettledCaptureUploadAttempt {
                    base,
                    upload_action,
                } = value;
                let NativeRestoredSettledCaptureAttempt {
                    ordinal,
                    original,
                    body,
                    arguments,
                    capture,
                    capture_context,
                    upload,
                    upload_context,
                    continuation,
                    confirmation,
                    registration,
                    checkpoint,
                    outputs,
                    terminal,
                    prepared_reply,
                    confirmation_receipt,
                    stage,
                } = base;
                (
                    ordinal,
                    original,
                    body,
                    arguments,
                    capture,
                    capture_context,
                    upload,
                    upload_context,
                    continuation,
                    confirmation,
                    registration,
                    upload_action,
                    checkpoint,
                    outputs,
                    terminal,
                    prepared_reply,
                    confirmation_receipt,
                    stage,
                )
            },
        )
        + size_of::<&mut MetadataObserver<'static>>()
        + size_of::<Result<(), ProviderError>>()
        + native_capture17_upload_action_counter_scratch_data()
        + crate::reference_packet::service::native_snapshot::native_restored_settled17_snapshot_schema_counter_scratch_data()
}

#[cfg(test)]
#[path = "upload_ingress17_tests.rs"]
mod tests;

#[path = "upload_ingress17/published.rs"]
mod published;
pub(crate) use published::{
    NativePublishedCapture17UploadData, native_published_capture17_upload_counter_scratch_data,
};

#[path = "upload_ingress17/continuation.rs"]
mod continuation;
