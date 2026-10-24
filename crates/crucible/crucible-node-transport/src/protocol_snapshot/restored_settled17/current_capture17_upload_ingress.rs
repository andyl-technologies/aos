//! Borrows the distinct sixteen-field Blob-only CaptureUpload17 ingress.
//!
//! The unchanged Capture base supplies actual raw and typed owners; the upload
//! transaction retains real aliases separately. The six final-Capture-only
//! slots are required literal nulls from that actual closed wrapper. No missing
//! field is synthesized, no old reader is widened, and no live owner is built.

use super::{
    current_actions::CurrentCaptureStage17,
    current_capture17_upload::{
        BorrowedCurrentCaptureUpload17, read_current_capture17_upload_data,
    },
    current_contracts::CurrentDto17,
    current_lineage17::{BorrowedLineageField17, loan},
    current_ordinary::read_ordinary17,
};
use crate::{
    ProviderError,
    envelope::Envelope,
    protocol_snapshot::owned11::typed::{Fields, Ledger, invalid, plain_string},
    reference_packet::service::restored_settled_capture::upload::{
        PacketRestoredSettledCaptureUploadArtifact, PacketRestoredSettledCaptureUploadContext,
        PacketRestoredSettledCaptureUploadContinuation,
    },
};
use serde_json::{Map, Value};
use std::mem::size_of;

/// Borrows every actual field without constructing an operational native owner.
pub(crate) struct BorrowedCurrentCaptureUploadIngress17<'body, 'rows> {
    pub(crate) definition: &'body [u8],
    pub(crate) ordinal: u64,
    pub(crate) original: BorrowedLineageField17<'body, 'rows, Option<Envelope>>,
    pub(crate) body: &'body [u8],
    pub(crate) arguments: &'body [u8],
    pub(crate) capture: &'body [u8],
    pub(crate) capture_context: &'body [u8],
    pub(crate) upload: BorrowedLineageField17<
        'body,
        'rows,
        Option<CurrentDto17<PacketRestoredSettledCaptureUploadArtifact>>,
    >,
    pub(crate) upload_context: BorrowedLineageField17<
        'body,
        'rows,
        Option<CurrentDto17<PacketRestoredSettledCaptureUploadContext>>,
    >,
    pub(crate) continuation: BorrowedLineageField17<
        'body,
        'rows,
        Option<CurrentDto17<PacketRestoredSettledCaptureUploadContinuation>>,
    >,
    pub(crate) confirmation: &'body [u8],
    pub(crate) upload_action: Option<BorrowedCurrentCaptureUpload17<'body, 'rows>>,
    pub(crate) checkpoint: &'body [u8],
    pub(crate) outputs: &'body [u8],
    pub(crate) terminal: BorrowedLineageField17<'body, 'rows, Option<Envelope>>,
    pub(crate) prepared_reply: BorrowedLineageField17<'body, 'rows, Option<Map<String, Value>>>,
    pub(crate) stage: CurrentCaptureStage17,
}

/// Borrows the exact Blob-only source roster and its real metadata prefix.
///
/// Native Source/once/currentness/publication proof is not inferred from these
/// DATA fields. The parent whole reader supplies genuine completed ledger and
/// supervisor roots before any nonnull transaction's repeated alias edges.
///
/// # Errors
/// Refuses missing/unknown/reordered fields, nonnull final-Capture slots, another
/// body family, malformed typed/partial data, metadata or real alias mismatch.
pub(crate) fn read_current_capture17_upload_ingress_data<'body, 'rows>(
    input: &'body [u8],
    ledger: &mut Ledger<'rows, '_, '_>,
) -> Result<BorrowedCurrentCaptureUploadIngress17<'body, 'rows>, ProviderError> {
    let mut fields = Fields::object(input)?;
    let ordinal_raw = fields.named("ordinal")?;
    let original_raw = fields.named("original")?;
    let body = fields.named("body")?;
    let arguments = fields.named("arguments")?;
    let capture = fields.named("capture")?;
    let capture_context = fields.named("capture_context")?;
    let upload_raw = fields.named("upload")?;
    let upload_context_raw = fields.named("upload_context")?;
    let continuation_raw = fields.named("continuation")?;
    let confirmation = fields.named("confirmation")?;
    let action_raw = fields.named("upload_action")?;
    let checkpoint = fields.named("checkpoint")?;
    let outputs = fields.named("outputs")?;
    let terminal_raw = fields.named("terminal")?;
    let prepared_raw = fields.named("prepared_reply")?;
    let stage_raw = fields.named("stage")?;
    fields.finish()?;

    // These exact source slots exist, but this wrapper has no mutable base loan
    // or final-Capture constructor. It poisons non-Blob input before decoding.
    for forbidden in [
        arguments,
        capture,
        capture_context,
        confirmation,
        checkpoint,
        outputs,
    ] {
        if forbidden != b"null" {
            return Err(invalid());
        }
    }
    let ordinal = ledger.read::<u64>(ordinal_raw, true)?.ok_or_else(invalid)?;
    let original = loan(original_raw, ledger)?;
    if body != b"null" {
        let mut fields = Fields::object(body)?;
        let kind = plain_string(fields.named("kind")?)?;
        let data = fields.named("data")?;
        fields.finish()?;
        if !matches!(kind, "blob_begin" | "blob_chunk" | "blob_finish") {
            return Err(invalid());
        }
        if read_ordinary17(kind, data, ledger, false)?.is_some() {
            return Err(invalid());
        }
    }
    let upload = loan(upload_raw, ledger)?;
    let upload_context = loan(upload_context_raw, ledger)?;
    let continuation = loan(continuation_raw, ledger)?;
    let upload_action = if action_raw == b"null" {
        None
    } else {
        Some(read_current_capture17_upload_data(action_raw, ledger)?)
    };
    let terminal = loan(terminal_raw, ledger)?;
    let prepared_reply = loan(prepared_raw, ledger)?;
    let stage = match plain_string(stage_raw)? {
        "receiving" => CurrentCaptureStage17::Receiving,
        "raw" => CurrentCaptureStage17::Raw,
        "typed" => CurrentCaptureStage17::Typed,
        "failed" => CurrentCaptureStage17::Failed,
        _ => return Err(invalid()),
    };
    Ok(BorrowedCurrentCaptureUploadIngress17 {
        definition: input,
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
        upload_action,
        checkpoint,
        outputs,
        terminal,
        prepared_reply,
        stage,
    })
}

/// Names defining borrowed ingress/DTO/transaction/parser and field-loop controls.
pub(crate) fn current_capture17_upload_ingress_counter_scratch_data() -> usize {
    size_of::<BorrowedCurrentCaptureUploadIngress17<'static, 'static>>()
        + size_of::<BorrowedLineageField17<'static, 'static, Option<Envelope>>>() * 2
        + size_of::<BorrowedLineageField17<'static, 'static, Option<Map<String, Value>>>>()
        + size_of::<Fields<'static>>() * 2
        + size_of::<[&[u8]; 6]>()
        + size_of::<std::array::IntoIter<&'static [u8], 6>>()
        + size_of::<Option<BorrowedCurrentCaptureUpload17<'static, 'static>>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<BorrowedCurrentCaptureUploadIngress17<'static, 'static>, ProviderError>>(
        )
        + super::current_capture17_upload::current_capture17_upload_counter_scratch_data()
}
