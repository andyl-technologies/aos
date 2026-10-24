//! Borrows a genuine immutable completed upload without granting continuation.
//!
//! The actual private native scope must still join this owner to its same Boot,
//! receiving index/Rc, original literal, saved publication record and seed MAC.
//! Historical DATA cannot construct this loan or assert a current model cut.

use super::*;
use crate::blob::{BlobProgress, NativeCapture17UploadAttempt, VerifiedTransfer};
use source_occurrence17::NativeCapture17PhaseData;

/// Borrows the real normal published occurrence and its immutable Blob result.
///
/// This loan preserves the original and typed phase separately. It grants no
/// Source, model, schema, consuming-pin or native action right. Earlier completed
/// uploads remain borrowable after later uploads advance the same Blob ledger;
/// only the explicit current-receiver method asserts the saved latest poststate.
pub(crate) struct NativePublishedCapture17UploadData<'a> {
    original: &'a Envelope,
    phase: NativeCapture17PhaseData<'a>,
    input: NativeCapture17UploadInput<'a>,
    terminal: &'a Envelope,
    reply: &'a Map<String, Value>,
    record: usize,
    storage: &'a NativeCapture17UploadStorageData,
    admitted: PacketNativeStartupAllocationRow,
    effect: &'a NativeCapture17UploadAttempt,
}

fn phase_input<'a>(
    original: &'a Envelope,
    phase: &NativeCapture17PhaseData<'a>,
) -> Result<NativeCapture17UploadInput<'a>, ProviderError> {
    let session = original.session_id.0.as_ref().ok_or_else(invalid)?;
    let incarnation = original.incarnation_id.0.as_ref().ok_or_else(invalid)?;
    match phase {
        NativeCapture17PhaseData::UploadBegin { body, .. } => {
            let body: &'a BlobBeginRequest = body;
            Ok(NativeCapture17UploadInput::Begin {
                key: NativeCapture17UploadKey {
                    origin: RequestOrigin::Controller,
                    session,
                    incarnation,
                    transfer: &body.transfer_id,
                },
                content: &body.content,
            })
        }
        NativeCapture17PhaseData::Chunk { body, .. } => {
            let body: &'a BlobChunkRequest = body;
            Ok(NativeCapture17UploadInput::Chunk {
                key: NativeCapture17UploadKey {
                    origin: RequestOrigin::Controller,
                    session,
                    incarnation,
                    transfer: &body.transfer_id,
                },
                offset: body.offset,
                bytes: &body.bytes,
            })
        }
        NativeCapture17PhaseData::Finish { body, .. } => {
            let body: &'a BlobFinishRequest = body;
            Ok(NativeCapture17UploadInput::Finish {
                key: NativeCapture17UploadKey {
                    origin: RequestOrigin::Controller,
                    session,
                    incarnation,
                    transfer: &body.transfer_id,
                },
            })
        }
        NativeCapture17PhaseData::Capture { .. }
        | NativeCapture17PhaseData::Confirmation { .. } => Err(invalid()),
    }
}

impl NativeRestoredSettledCaptureUploadAttempt {
    /// Names this immutable published lender and its defining completion checks.
    pub(crate) fn published_upload17_counter_scratch_data() -> usize {
        native_published_capture17_upload_counter_scratch_data()
    }

    /// Borrows an actual normal published upload under its immutable once owner.
    ///
    /// The private completion producer saves its record only after real native
    /// publication. The caller must authenticate that exact record, Source key
    /// and ancestry independently; the stored number alone grants no right.
    /// No current receiver predicate is applied to a historical seed here.
    ///
    /// # Errors
    /// Refuses raw/failed/inflight custody, absent result/reply/terminal/record,
    /// another phase or quote, and any routing or full reply-body disagreement.
    pub(crate) fn published_upload17_data(
        &self,
    ) -> Result<NativePublishedCapture17UploadData<'_>, ProviderError> {
        if self.base.stage != Stage::Typed {
            return Err(invalid());
        }
        let original = self.original_data()?;
        let phase = self.phase17_data()?;
        let input = phase_input(original, &phase)?;
        let action = self.upload_action.as_ref().ok_or_else(invalid)?;
        let (storage, admitted, record, effect, reply) =
            action.published_upload17_parts_data(input)?;
        let prepared = self.base.prepared_reply.as_ref().ok_or_else(invalid)?;
        let terminal = self.base.terminal.as_ref().ok_or_else(invalid)?;
        original.matches_response(terminal)?;
        if prepared != reply || &terminal.body != prepared || !terminal.extensions.is_empty() {
            return Err(invalid());
        }
        if let NativeCapture17PhaseData::UploadBegin { artifact, .. } = &phase {
            artifact
                .request
                .native_allocation
                .authenticate_actual_data(&admitted)?;
        }
        Ok(NativePublishedCapture17UploadData {
            original,
            phase,
            input,
            terminal,
            reply,
            record,
            storage,
            admitted,
            effect,
        })
    }
}

impl<'a> NativePublishedCapture17UploadData<'a> {
    /// Borrows the exact original retained by this native upload occurrence.
    pub(crate) fn original_data(&self) -> &'a Envelope {
        self.original
    }

    /// Borrows its actual decoded Begin, Chunk or Finish phase and signed context.
    pub(crate) fn phase_data(&self) -> &NativeCapture17PhaseData<'a> {
        &self.phase
    }

    /// Borrows the full actual retained terminal, including routing and sequence.
    pub(crate) fn terminal_data(&self) -> &'a Envelope {
        self.terminal
    }

    /// Borrows its real Blob reply, exactly matched to prepared and terminal copies.
    pub(crate) fn reply_data(&self) -> &'a Map<String, Value> {
        self.reply
    }

    /// Returns the saved actual publication occurrence as correspondence DATA.
    pub(crate) fn publication_record_data(&self) -> usize {
        self.record
    }

    /// Borrows the actual independently derived immutable Blob quotation.
    pub(crate) fn storage_data(&self) -> &'a NativeCapture17UploadStorageData {
        self.storage
    }

    /// Returns the complete real admitted phase row as read-only historical DATA.
    pub(crate) fn admitted_row_data(&self) -> PacketNativeStartupAllocationRow {
        self.admitted
    }

    /// Returns the actual quotation's Blob-only requested axes, without credit.
    pub(crate) fn requested_row_data(&self) -> PacketNativeStartupAllocationRow {
        self.storage.row_data()
    }

    /// Borrows actual retained progress when this occurrence is Begin or Chunk.
    pub(crate) fn progress_data(&self) -> Option<&'a BlobProgress> {
        self.effect.completed_progress17_data()
    }

    /// Borrows real verified possession when this occurrence is Finish.
    pub(crate) fn verified_data(&self) -> Option<&'a VerifiedTransfer> {
        self.effect.verified_data()
    }

    /// Checks that the immediately preceding occurrence still owns today's poststate.
    ///
    /// The native scope calls this only for its genuine latest prior upload.
    /// An older valid seed remains lendable but will fail this method after
    /// later legitimate progress. The check creates no continuation permission.
    ///
    /// # Errors
    /// Refuses another actual ledger/supervisor/input, changed completed result,
    /// or any intervening difference in the complete saved receiver transcript.
    pub(crate) fn authenticate_current_receiver_data(
        &self,
        receiver: &BlobReceiver,
    ) -> Result<(), ProviderError> {
        self.effect.authenticate_current_completed_receiver17_data(
            receiver,
            self.storage,
            self.input,
        )
    }
}

/// Names the immutable ingress/transaction loans and defining Blob checks.
pub(crate) fn native_published_capture17_upload_counter_scratch_data() -> usize {
    size_of::<NativePublishedCapture17UploadData<'static>>()
        + size_of::<Result<NativePublishedCapture17UploadData<'static>, ProviderError>>()
        + size_of::<&NativeRestoredSettledCaptureUploadAttempt>()
        + size_of::<NativeCapture17PhaseData<'static>>()
        + size_of::<&NativeCapture17PhaseData<'static>>()
        + size_of::<NativeCapture17UploadInput<'static>>()
        + size_of::<Result<NativeCapture17UploadInput<'static>, ProviderError>>()
        + size_of::<&Envelope>() * 2
        + size_of::<&Map<String, Value>>() * 2
        + size_of::<&NativeCapture17UploadStorageData>()
        + size_of::<PacketNativeStartupAllocationRow>() * 2
        + size_of::<Result<(), ProviderError>>()
        + NativeCapture17UploadActionAttempt::published_upload17_counter_scratch_data()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::envelope::Nullable;
    use crate::reference_packet::service::restored_settled_capture::upload::RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE;
    use crucible_node_format::{Id, canonical};
    use serde_json::json;

    #[test]
    fn raw_and_failed_typed_custody_cannot_lend_a_published_upload() {
        let mut original = crate::envelope::tests::request();
        original.method = Method::BlobBegin;
        original.node_id = Nullable(Some(Id::new("node").unwrap()));
        original.execution_owner_id = Nullable(None);
        original.capture_owner_id = Nullable(Some(Id::new("capture").unwrap()));
        original.operation_id = Nullable(None);
        original.body = json!({
            "transfer_id":"transfer",
            "content":canonical::content_ref(b"actual", "application/json").unwrap(),
            "extensions":{},
        })
        .as_object()
        .unwrap()
        .clone();
        original.extensions.clear();
        // This retained raw fixture deliberately lacks a valid Source artifact.
        original
            .extensions
            .insert(RESTORED_SETTLED_CAPTURE_UPLOAD_FEATURE.into(), Value::Null);
        let mut attempt = NativeRestoredSettledCaptureUploadAttempt::new_data(1);
        attempt.retain_original_data(original.clone()).unwrap();
        let before = serde_json::to_vec(&attempt).unwrap();

        assert!(attempt.published_upload17_data().is_err());
        assert_eq!(serde_json::to_vec(&attempt).unwrap(), before);
        assert!(attempt.decode_body_data(65536).is_err());
        let failed = serde_json::to_vec(&attempt).unwrap();
        assert!(attempt.published_upload17_data().is_err());
        assert_eq!(attempt.original_data().unwrap(), &original);
        assert_eq!(serde_json::to_vec(&attempt).unwrap(), failed);
        assert!(attempt.upload_action.is_none());
        assert!(attempt.base.terminal.is_none());
    }
}
