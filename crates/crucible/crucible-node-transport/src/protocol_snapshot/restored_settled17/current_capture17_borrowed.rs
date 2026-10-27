//! Borrows the complete current Capture17 ledger without rebuilding host owners.
//!
//! The source emits seventeen independent fields. Metadata follows its actual
//! observer, including the checkpoint's expected lineage before its boxed record.
//! Signed DTO loans keep their original row cursors for separately priced owners.

use super::{
    current_actions::CurrentCaptureStage17,
    current_contracts::*,
    current_lineage17::{BorrowedLineageField17, loan},
    current_ordinary::read_ordinary17,
    current_shared::read_reference17,
};
use crate::{
    ProviderError,
    bodies::{BeginRequest, CaptureArguments},
    envelope::Envelope,
    protocol_snapshot::owned11::typed::{
        Fields, HistoricalType, Ledger, invalid, plain_string, unsigned,
    },
    reference_packet::{
        PacketGrant, PacketInventory,
        connected::PacketConnectedNativeRecord,
        control::PacketNativeRecord,
        service::{
            complete_restore::PacketNativeRestoredRecord,
            restored_settled_capture::{upload::*, *},
            restored_settled_confirmation::*,
        },
    },
    retained_metadata::{aliases::MetadataSharedKind, records::MetadataRecordKind},
};
use crucible_node_format::{ContentRef, U64};
use serde_json::{Map, Value};
use std::mem::{align_of, size_of};

pub(crate) use output::{ActiveOutput17, ActiveRecorder17, ActiveRole17, BorrowedCaptureOutputs17};

/// Retains the actual registration's identity join and full immutable request.
pub(crate) struct BorrowedCaptureRegistration17<'body, 'rows> {
    pub(crate) identity_group: usize,
    pub(crate) creator: u32,
    pub(crate) request: BorrowedLineageField17<'body, 'rows, Envelope>,
    pub(crate) arguments: BorrowedLineageField17<'body, 'rows, CurrentDto17<CaptureArguments>>,
    pub(crate) begin: BorrowedLineageField17<'body, 'rows, CurrentDto17<BeginRequest>>,
}

/// Borrows all independent proof, output and publication slots of one Capture.
pub(crate) struct BorrowedCurrentCapture17<'body, 'rows> {
    definition: &'body [u8],
    pub(crate) ordinal: u64,
    pub(crate) original: BorrowedLineageField17<'body, 'rows, Option<Envelope>>,
    pub(crate) body: &'body [u8],
    pub(crate) arguments:
        BorrowedLineageField17<'body, 'rows, Option<CurrentDto17<CaptureArguments>>>,
    pub(crate) capture: BorrowedLineageField17<
        'body,
        'rows,
        Option<CurrentDto17<PacketRestoredSettledCaptureArtifact>>,
    >,
    pub(crate) capture_context: BorrowedLineageField17<
        'body,
        'rows,
        Option<CurrentDto17<PacketRestoredSettledCaptureContext>>,
    >,
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
    pub(crate) confirmation: BorrowedLineageField17<
        'body,
        'rows,
        Option<CurrentDto17<PacketRestoredSettledAfterConfirmationRequest>>,
    >,
    pub(crate) registration: Option<BorrowedCaptureRegistration17<'body, 'rows>>,
    pub(crate) checkpoint: &'body [u8],
    pub(crate) outputs: Option<BorrowedCaptureOutputs17<'body>>,
    pub(crate) terminal: BorrowedLineageField17<'body, 'rows, Option<Envelope>>,
    pub(crate) prepared_reply: BorrowedLineageField17<'body, 'rows, Option<Map<String, Value>>>,
    pub(crate) confirmation_receipt: BorrowedLineageField17<'body, 'rows, Option<Value>>,
    pub(crate) stage: CurrentCaptureStage17,
}

impl BorrowedCurrentCapture17<'_, '_> {
    pub(crate) fn definition_data(&self) -> &[u8] {
        self.definition
    }
}

fn discard<T: HistoricalType>(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
) -> Result<(), ProviderError> {
    if ledger.read::<T>(input, false)?.is_some() {
        return Err(invalid());
    }
    Ok(())
}

fn registration<'body, 'rows>(
    input: &'body [u8],
    ledger: &mut Ledger<'rows, '_, '_>,
) -> Result<Option<BorrowedCaptureRegistration17<'body, 'rows>>, ProviderError> {
    if input == b"null" {
        return Ok(None);
    }
    let mut fields = Fields::object(input)?;
    if plain_string(fields.named("capture_identity_role")?)? != "current-native-control-identity" {
        return Err(invalid());
    }
    let creator_raw = fields.named("creator")?;
    let request_raw = fields.named("request")?;
    let arguments_raw = fields.named("arguments")?;
    let begin_raw = fields.named("begin")?;
    fields.finish()?;

    let identity_group = read_reference17(
        ledger,
        MetadataSharedKind::NativeControlIdentity,
        (size_of::<()>(), align_of::<()>()),
    )?;
    let creator = ledger.read::<u32>(creator_raw, true)?.ok_or_else(invalid)?;
    let request = loan(request_raw, ledger)?;
    let arguments = loan(arguments_raw, ledger)?;
    let begin = loan(begin_raw, ledger)?;
    Ok(Some(BorrowedCaptureRegistration17 {
        identity_group,
        creator,
        request,
        arguments,
        begin,
    }))
}

fn producer_record(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
    let mut fields = Fields::object(input)?;
    discard::<String>(fields.named("schema")?, ledger)?;
    discard::<U64>(fields.named("native_pid")?, ledger)?;
    discard::<Envelope>(fields.named("original")?, ledger)?;
    discard::<PacketInventory>(fields.named("inventory")?, ledger)?;
    discard::<Option<PacketGrant>>(fields.named("grant")?, ledger)?;
    fields.finish()
}

fn checkpoint(input: &[u8], ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
    if input == b"null" {
        return Ok(());
    }
    let mut fields = Fields::object(input)?;
    let restored = fields.named("restored")?;
    let underlying = fields.named("underlying")?;
    let expected = fields.named("expected_lineage")?;
    let validated = fields.named("validated")?;
    fields.finish()?;

    discard::<Option<CurrentDto17<PacketNativeRestoredRecord>>>(restored, ledger)?;
    discard::<Option<CurrentDto17<PacketNativeRestoredRecord>>>(expected, ledger)?;
    if underlying != b"null" {
        let mut fields = Fields::object(underlying)?;
        let kind = plain_string(fields.named("kind")?)?;
        let data = fields.named("data")?;
        fields.finish()?;
        let layout = match kind {
            "producer" => {
                producer_record(data, ledger)?;
                (
                    size_of::<PacketNativeRecord>(),
                    align_of::<PacketNativeRecord>(),
                )
            }
            "reactive" => {
                discard::<CurrentDto17<PacketConnectedNativeRecord>>(data, ledger)?;
                (
                    size_of::<PacketConnectedNativeRecord>(),
                    align_of::<PacketConnectedNativeRecord>(),
                )
            }
            _ => return Err(invalid()),
        };
        if ledger.row_aligned(MetadataRecordKind::Vector, layout.0, layout.1)? != 1 {
            return Err(invalid());
        }
    }
    discard::<bool>(validated, ledger)
}

/// Walks the exact seventeen-field source owner in the existing aggregate pass.
///
/// # Errors
/// Refuses missing/extra/reordered fields, invalid tagged children, unmatched
/// source rows or identities, malformed closed receipts or incomplete cut markers.
pub(crate) fn read_current_capture17_borrowed_data<'body, 'rows>(
    input: &'body [u8],
    ledger: &mut Ledger<'rows, '_, '_>,
) -> Result<BorrowedCurrentCapture17<'body, 'rows>, ProviderError> {
    let mut fields = Fields::object(input)?;
    let ordinal_raw = fields.named("ordinal")?;
    let original_raw = fields.named("original")?;
    let body = fields.named("body")?;
    let arguments_raw = fields.named("arguments")?;
    let capture_raw = fields.named("capture")?;
    let capture_context_raw = fields.named("capture_context")?;
    let upload_raw = fields.named("upload")?;
    let upload_context_raw = fields.named("upload_context")?;
    let continuation_raw = fields.named("continuation")?;
    let confirmation_raw = fields.named("confirmation")?;
    let registration_raw = fields.named("registration")?;
    let checkpoint_raw = fields.named("checkpoint")?;
    let outputs_raw = fields.named("outputs")?;
    let terminal_raw = fields.named("terminal")?;
    let prepared_reply_raw = fields.named("prepared_reply")?;
    let confirmation_receipt_raw = fields.named("confirmation_receipt")?;
    let stage_raw = fields.named("stage")?;
    fields.finish()?;

    let ordinal = ledger.read::<u64>(ordinal_raw, true)?.ok_or_else(invalid)?;
    let original = loan(original_raw, ledger)?;
    if body != b"null" {
        let mut body_fields = Fields::object(body)?;
        let kind = plain_string(body_fields.named("kind")?)?;
        let data = body_fields.named("data")?;
        body_fields.finish()?;
        if !matches!(
            kind,
            "capture" | "blob_begin" | "blob_chunk" | "blob_finish" | "confirmation"
        ) {
            return Err(invalid());
        }
        if read_ordinary17(kind, data, ledger, false)?.is_some() {
            return Err(invalid());
        }
    }
    let arguments = loan(arguments_raw, ledger)?;
    let capture = loan(capture_raw, ledger)?;
    let capture_context = loan(capture_context_raw, ledger)?;
    let upload = loan(upload_raw, ledger)?;
    let upload_context = loan(upload_context_raw, ledger)?;
    let continuation = loan(continuation_raw, ledger)?;
    let confirmation = loan(confirmation_raw, ledger)?;
    let registration = registration(registration_raw, ledger)?;
    checkpoint(checkpoint_raw, ledger)?;
    let outputs = if outputs_raw == b"null" {
        None
    } else {
        Some(output::read(outputs_raw, ledger)?)
    };
    let terminal = loan(terminal_raw, ledger)?;
    let prepared_reply = loan(prepared_reply_raw, ledger)?;
    let confirmation_receipt = loan(confirmation_receipt_raw, ledger)?;
    if confirmation_receipt_raw != b"null" {
        receipt::check(confirmation_receipt_raw)?;
    }
    let stage = match plain_string(stage_raw)? {
        "receiving" => CurrentCaptureStage17::Receiving,
        "raw" => CurrentCaptureStage17::Raw,
        "typed" => CurrentCaptureStage17::Typed,
        "failed" => CurrentCaptureStage17::Failed,
        _ => return Err(invalid()),
    };
    Ok(BorrowedCurrentCapture17 {
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
        registration,
        checkpoint: checkpoint_raw,
        outputs,
        terminal,
        prepared_reply,
        confirmation_receipt,
        stage,
    })
}

mod output;
mod receipt;

#[path = "current_capture17_borrowed/history.rs"]
mod history;
pub(crate) use history::{
    historical_capture17_counter_scratch_data, read_historical_capture17_borrowed_data,
};

pub(in crate::protocol_snapshot::restored_settled17) use history::{
    historical_capture17_cut_counter_scratch_data, historical_capture17_cut_fields_data,
};
