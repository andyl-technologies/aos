//! Validates ordinary saved Capture attempts without granting a current cut.
//!
//! ```text
//! CaptureHistory17 = {ordinal,original,body,arguments,capture,capture_context,
//!   upload,upload_context,continuation,confirmation,checkpoint,outputs,
//!   terminal,prepared_reply,stage}
//! ```
//!
//! The ordinary writer emits fifteen fields, including failed raw prefixes.
//! The separately selected current-Capture reader requires seventeen fields.
//! Framing completes before metadata is consumed, so the previous seventeen-
//! field grammar can remain accepted without retrying a partially spent ledger.

use super::*;

struct HistoricalCaptureFields17<'a> {
    ordinal: &'a [u8],
    original: &'a [u8],
    body: &'a [u8],
    arguments: &'a [u8],
    capture: &'a [u8],
    capture_context: &'a [u8],
    upload: &'a [u8],
    upload_context: &'a [u8],
    continuation: &'a [u8],
    confirmation: &'a [u8],
    checkpoint: &'a [u8],
    outputs: &'a [u8],
    terminal: &'a [u8],
    prepared_reply: &'a [u8],
    stage: &'a [u8],
}

impl<'a> HistoricalCaptureFields17<'a> {
    fn read(input: &'a [u8]) -> Result<Self, ProviderError> {
        let mut fields = Fields::object(input)?;
        let value = Self {
            ordinal: fields.named("ordinal")?,
            original: fields.named("original")?,
            body: fields.named("body")?,
            arguments: fields.named("arguments")?,
            capture: fields.named("capture")?,
            capture_context: fields.named("capture_context")?,
            upload: fields.named("upload")?,
            upload_context: fields.named("upload_context")?,
            continuation: fields.named("continuation")?,
            confirmation: fields.named("confirmation")?,
            checkpoint: fields.named("checkpoint")?,
            outputs: fields.named("outputs")?,
            terminal: fields.named("terminal")?,
            prepared_reply: fields.named("prepared_reply")?,
            stage: fields.named("stage")?,
        };
        fields.finish()?;
        Ok(value)
    }

    fn validate(self, ledger: &mut Ledger<'_, '_, '_>) -> Result<(), ProviderError> {
        discard::<u64>(self.ordinal, ledger)?;
        discard::<Option<Envelope>>(self.original, ledger)?;
        if self.body != b"null" {
            let mut fields = Fields::object(self.body)?;
            let kind = plain_string(fields.named("kind")?)?;
            let data = fields.named("data")?;
            fields.finish()?;
            if !matches!(
                kind,
                "capture" | "blob_begin" | "blob_chunk" | "blob_finish" | "confirmation"
            ) || read_ordinary17(kind, data, ledger, false)?.is_some()
            {
                return Err(invalid());
            }
        }
        discard::<Option<CurrentDto17<CaptureArguments>>>(self.arguments, ledger)?;
        discard::<Option<CurrentDto17<PacketRestoredSettledCaptureArtifact>>>(
            self.capture,
            ledger,
        )?;
        discard::<Option<CurrentDto17<PacketRestoredSettledCaptureContext>>>(
            self.capture_context,
            ledger,
        )?;
        discard::<Option<CurrentDto17<PacketRestoredSettledCaptureUploadArtifact>>>(
            self.upload,
            ledger,
        )?;
        discard::<Option<CurrentDto17<PacketRestoredSettledCaptureUploadContext>>>(
            self.upload_context,
            ledger,
        )?;
        discard::<Option<CurrentDto17<PacketRestoredSettledCaptureUploadContinuation>>>(
            self.continuation,
            ledger,
        )?;
        discard::<Option<CurrentDto17<PacketRestoredSettledAfterConfirmationRequest>>>(
            self.confirmation,
            ledger,
        )?;
        checkpoint(self.checkpoint, ledger)?;
        // An ordinary retained owner cannot stand in for a live recorder cut.
        // The selected-current reader validates that distinct schema.
        if self.outputs != b"null" && output::read(self.outputs, ledger)?.active_role.is_some() {
            return Err(invalid());
        }
        discard::<Option<Envelope>>(self.terminal, ledger)?;
        discard::<Option<Map<String, Value>>>(self.prepared_reply, ledger)?;
        if !matches!(
            plain_string(self.stage)?,
            "receiving" | "raw" | "typed" | "failed"
        ) {
            return Err(invalid());
        }
        Ok(())
    }
}

/// Validates an actual historical writer roster without rebuilding live owners.
///
/// # Errors
/// Refuses unsupported framing, child shapes, source metadata or active output
/// cuts in ordinary retained attempts. The existing full-current grammar is
/// independently validated when the ordinary fifteen-field framing does not fit.
pub(crate) fn read_historical_capture17_borrowed_data(
    input: &[u8],
    ledger: &mut Ledger<'_, '_, '_>,
) -> Result<(), ProviderError> {
    match HistoricalCaptureFields17::read(input) {
        Ok(fields) => fields.validate(ledger),
        Err(_) => read_current_capture17_borrowed_data(input, ledger).map(|_| ()),
    }
}

/// Counts the additional fixed framing, result and borrowed output headers.
pub(crate) fn historical_capture17_counter_scratch_data() -> usize {
    2 * size_of::<HistoricalCaptureFields17<'static>>()
        + size_of::<Result<HistoricalCaptureFields17<'static>, ProviderError>>()
        + Fields::counter_scratch_data()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<BorrowedCaptureOutputs17<'static>>()
}

/// Borrows the extra evidence emitted only by the seventeen-field active cut.
pub(in crate::protocol_snapshot::restored_settled17) struct HistoricalCaptureCutFields17<'a> {
    /// Borrows the separately recorded registration and its original identity.
    pub(in crate::protocol_snapshot::restored_settled17) registration: &'a [u8],
    /// Borrows the independently recorded confirmation receipt slot.
    pub(in crate::protocol_snapshot::restored_settled17) confirmation_receipt: &'a [u8],
}

/// Distinguishes ordinary history from the separately decorated active-cut wire.
///
/// This framing-only walk consumes no metadata or constructor credit. The
/// enclosing complete graph reader still validates every ordinary field. A
/// fifteen-field historical Capture does not contain a second registration;
/// its actual registration belongs to the independently checked before graph.
///
/// # Errors
/// Refuses missing, duplicate, extra or reordered fields in either exact roster.
pub(in crate::protocol_snapshot::restored_settled17) fn historical_capture17_cut_fields_data(
    input: &[u8],
) -> Result<Option<HistoricalCaptureCutFields17<'_>>, ProviderError> {
    if HistoricalCaptureFields17::read(input).is_ok() {
        return Ok(None);
    }

    let mut fields = Fields::object(input)?;
    for name in [
        "ordinal",
        "original",
        "body",
        "arguments",
        "capture",
        "capture_context",
        "upload",
        "upload_context",
        "continuation",
        "confirmation",
    ] {
        fields.named(name)?;
    }
    let registration = fields.named("registration")?;
    for name in ["checkpoint", "outputs", "terminal", "prepared_reply"] {
        fields.named(name)?;
    }
    let confirmation_receipt = fields.named("confirmation_receipt")?;
    fields.named("stage")?;
    fields.finish()?;
    Ok(Some(HistoricalCaptureCutFields17 {
        registration,
        confirmation_receipt,
    }))
}

/// Names both framing passes and the surviving borrowed cut controls.
pub(in crate::protocol_snapshot::restored_settled17) fn historical_capture17_cut_counter_scratch_data()
-> usize {
    historical_capture17_counter_scratch_data()
        + size_of::<HistoricalCaptureCutFields17<'static>>()
        + size_of::<Result<Option<HistoricalCaptureCutFields17<'static>>, ProviderError>>()
        + size_of::<std::array::IntoIter<&'static str, 10>>()
        + size_of::<std::array::IntoIter<&'static str, 4>>()
        + size_of::<Result<&'static [u8], ProviderError>>()
}

#[cfg(test)]
#[path = "history_tests.rs"]
mod tests;
