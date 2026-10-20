//! Lends actual SDK18 partials for independently prepared flat history.
//!
//! No view serializes, clones or decodes recursive JSON. The caller prepares
//! every actual body and extension with its separately funded literal codec.
//! Missing, failed and unexpected typed/raw fields are observable without a
//! completed-result check. These loans supply no Session or native permission.

use super::*;
use crate::connection::{ReceivedBody, ReceivedFrame};
use crate::transport::RetainedFrame;
use serde_json::Map;

/// Borrows a genuine capsule through a nonescaping, origin-guarded callback.
pub struct OriginalNativeImport18PartialHistoryData<'a> {
    owner: &'a OriginalNativeImport18Assignment,
}

/// Borrows every initialized modeled Prepare field, including missing partials.
///
/// Live literal-slot, deadline, Controller and metadata-profile tokens are not
/// exposed as historical authority. Private construction prevents a caller
/// from substituting a completed-only DTO for this actual owner occurrence.
pub struct OriginalNativeImport18PreparePartialData<'a> {
    _phase: &'a AssignedPhase<PacketCompleteRestorePrepareRequest>,
    /// Names the actual stage; no failure or completion is inferred from it.
    pub stage: &'static str,
    /// Borrows the actual optional assigned request ID.
    pub request_id: &'a Option<Id>,
    /// Borrows the actual optional baseline, including its extension operands.
    pub baseline: &'a Option<BeginRequest>,
    /// Borrows the moved request even before validation succeeds.
    pub request: &'a PacketCompleteRestorePrepareRequest,
    /// Borrows the independently owned normalized body partial.
    pub body: &'a Option<Value>,
    /// Borrows the independently owned payload partial.
    pub payload: &'a Option<Value>,
    /// Borrows the independently owned binding projection partial.
    pub binding_value: &'a Option<Value>,
    /// Borrows the actual typed proof without validating its phase.
    pub proof: &'a Option<PacketNativeImport17Proof>,
    /// Borrows the independently owned proof projection partial.
    pub proof_value: &'a Option<Value>,
    /// Borrows the actual original with its recursive operands explicit.
    pub original: Option<OriginalNativeImport18EnvelopePartialData<'a>>,
    /// Borrows all retained framed bytes, including a failed prefix.
    pub bytes: &'a [u8],
    /// Borrows the raw wire bank without normalizing its Value.
    pub raw: Option<OriginalNativeImport18RawPartialData<'a>>,
    /// Borrows the independent response literal, even before body validation.
    pub response: Option<OriginalNativeImport18EnvelopePartialData<'a>>,
    /// Borrows any actual received variant, without a closed-result filter.
    pub received: Option<OriginalNativeImport18ReceivedPartialData<'a>>,
    /// Borrows the separately decoded response, including a failed partial.
    pub decoded: &'a Option<ResponseBody>,
    /// Borrows the actual optional retained receipt without implying readiness.
    pub prepare_receipt: &'a Option<PacketNativeImport17PrepareReceipt>,
}

/// Borrows a literal envelope and explicitly exposes recursive body/extensions.
///
/// The envelope loan supplies literal scalar/correlation fields. It does not
/// make direct recursive Envelope Serialize, Clone, equality or Drop safe.
pub struct OriginalNativeImport18EnvelopePartialData<'a> {
    envelope: &'a Envelope,
    /// Borrows the structural body map without a Value adapter pass.
    pub body: &'a Map<String, Value>,
    /// Borrows every actual extension Value, without key filtering.
    pub extensions: &'a Extensions,
}

/// Borrows actual retained wire bytes and their independent raw JSON owner.
pub struct OriginalNativeImport18RawPartialData<'a> {
    _raw: &'a RetainedFrame,
    /// Borrows the full literal raw Value without clone or normalization.
    pub value: &'a Value,
    /// Borrows exact unframed wire bytes.
    pub bytes: &'a [u8],
}

/// Borrows any actual received variant and its independently owned envelope.
pub struct OriginalNativeImport18ReceivedPartialData<'a> {
    _received: &'a ReceivedFrame,
    /// Borrows the actual literal, exposing all recursive operands explicitly.
    pub envelope: OriginalNativeImport18EnvelopePartialData<'a>,
    /// Borrows Request, Response or Notification unchanged, including Values.
    pub body: &'a ReceivedBody,
}

impl OriginalNativeImport18Assignment {
    /// Lends initialized history fields without a completion or result filter.
    ///
    /// The caller admits the defining fixed counter before entry and separately
    /// owns its closure captures and prepared output banks. No schema, parser,
    /// hash, metadata walk, formatter or allocation runs here. R cannot contain
    /// a loan from the callback's universally quantified view lifetime.
    ///
    /// # Errors
    /// Refuses a foreign process/thread or returns the callback error after
    /// running the creator-origin postguard on either callback outcome.
    pub fn with_partial_history_data<R>(
        &self,
        inspect: impl for<'view> FnOnce(
            OriginalNativeImport18PartialHistoryData<'view>,
        ) -> Result<R, ProviderError>,
    ) -> Result<R, ProviderError> {
        self.controller.ensure_current()?;
        let result = inspect(OriginalNativeImport18PartialHistoryData { owner: self });
        self.controller.ensure_current()?;
        result
    }

    /// Names actual view, loan, iterator, result and creator-origin controls.
    ///
    /// Callback captures and independently retained output banks are separate
    /// caller costs. This fixed DATA counter supplies no constructor credit.
    pub fn partial_history_counter_scratch_data<R>() -> usize {
        partial_counter_scratch_data::<R>() + input_upload::partial_history_counter_scratch_data()
    }
}

impl<'a> OriginalNativeImport18PartialHistoryData<'a> {
    /// Borrows the actual retained binding, independent backend and byte bank.
    pub fn inputs_data(&self) -> (&'a PacketNativeImport18Binding, &'a SchemaRef, &'a [u8]) {
        (
            &self.owner.binding,
            &self.owner.expected_backend_schema,
            &self.owner.normalization,
        )
    }

    /// Borrows the real Prepare slot without success or receipt-family checks.
    pub fn prepare_data(&self) -> OriginalNativeImport18PreparePartialData<'a> {
        prepare_partial_data(&self.owner.prepare)
    }

    /// Borrows all actual upload owners, failed or unfinished frames included.
    pub fn uploads_data(&self) -> input_upload::OriginalNativeImport18UploadBankPartialData<'a> {
        self.owner.uploads.partial_history_data()
    }
}

impl<'a> OriginalNativeImport18EnvelopePartialData<'a> {
    /// Borrows literal correlation fields without copying recursive children.
    pub fn envelope_data(&self) -> &'a Envelope {
        self.envelope
    }
}

fn prepare_partial_data(
    phase: &AssignedPhase<PacketCompleteRestorePrepareRequest>,
) -> OriginalNativeImport18PreparePartialData<'_> {
    let AssignedPhase {
        stage,
        request_id,
        baseline,
        request,
        body,
        payload,
        binding_value,
        proof,
        proof_value,
        original,
        bytes,
        literal_slot: _,
        cut: _,
        json_profile: _,
        raw,
        response,
        received,
        decoded,
        prepare_receipt,
    } = phase;
    let stage = match stage {
        Stage::Preparing => "preparing",
        Stage::Unsigned => "unsigned",
        Stage::Sealing => "sealing",
        Stage::Sealed => "sealed",
        Stage::Publishing => "publishing",
        Stage::RawReceived => "raw_received",
        Stage::Decoding => "decoding",
        Stage::Complete => "complete",
    };
    OriginalNativeImport18PreparePartialData {
        _phase: phase,
        stage,
        request_id,
        baseline,
        request,
        body,
        payload,
        binding_value,
        proof,
        proof_value,
        original: original.as_ref().map(envelope_partial_data),
        bytes,
        raw: raw.as_ref().map(raw_partial_data),
        response: response.as_ref().map(envelope_partial_data),
        received: received.as_ref().map(received_partial_data),
        decoded,
        prepare_receipt,
    }
}

pub(in super::super) fn envelope_partial_data(
    envelope: &Envelope,
) -> OriginalNativeImport18EnvelopePartialData<'_> {
    OriginalNativeImport18EnvelopePartialData {
        envelope,
        body: &envelope.body,
        extensions: &envelope.extensions,
    }
}

pub(in super::super) fn raw_partial_data(
    raw: &RetainedFrame,
) -> OriginalNativeImport18RawPartialData<'_> {
    OriginalNativeImport18RawPartialData {
        _raw: raw,
        value: &raw.value,
        bytes: &raw.bytes,
    }
}

pub(in super::super) fn received_partial_data(
    received: &ReceivedFrame,
) -> OriginalNativeImport18ReceivedPartialData<'_> {
    OriginalNativeImport18ReceivedPartialData {
        _received: received,
        envelope: envelope_partial_data(&received.envelope),
        body: &received.body,
    }
}

pub(in super::super) fn partial_counter_scratch_data<R>() -> usize {
    size_of::<OriginalNativeImport18PartialHistoryData<'static>>()
        + size_of::<OriginalNativeImport18PreparePartialData<'static>>()
        + size_of::<OriginalNativeImport18EnvelopePartialData<'static>>()
        + size_of::<Option<OriginalNativeImport18EnvelopePartialData<'static>>>()
        + size_of::<OriginalNativeImport18RawPartialData<'static>>()
        + size_of::<Option<OriginalNativeImport18RawPartialData<'static>>>()
        + size_of::<OriginalNativeImport18ReceivedPartialData<'static>>()
        + size_of::<Option<OriginalNativeImport18ReceivedPartialData<'static>>>()
        + size_of::<&OriginalNativeImport18Assignment>()
        + size_of::<&AssignedPhase<PacketCompleteRestorePrepareRequest>>()
        + size_of::<&OriginalNativeImport18PartialHistoryData<'static>>()
        + size_of::<&OriginalNativeImport18PreparePartialData<'static>>()
        + size_of::<&OriginalNativeImport18EnvelopePartialData<'static>>()
        + size_of::<Option<&Envelope>>()
        + size_of::<Option<&RetainedFrame>>()
        + size_of::<Option<&ReceivedFrame>>()
        + size_of::<&Stage>()
        + size_of::<&Envelope>()
        + size_of::<&RetainedFrame>()
        + size_of::<&ReceivedFrame>()
        + size_of::<&ReceivedBody>()
        + size_of::<&Map<String, Value>>()
        + size_of::<&Extensions>()
        + size_of::<&Value>()
        // The exhaustive phase destructure keeps four independent Value loans
        // and both independent original/response Envelope loans live together.
        + size_of::<&Option<Value>>() * 4
        + size_of::<&Option<Envelope>>() * 2
        + size_of::<&Option<RetainedFrame>>()
        + size_of::<&Option<ReceivedFrame>>()
        + size_of::<&Option<ResponseBody>>()
        + size_of::<&Option<Id>>()
        + size_of::<&Option<BeginRequest>>()
        + size_of::<&Option<PacketNativeImport17Proof>>()
        + size_of::<&Option<PacketNativeImport17PrepareReceipt>>()
        + size_of::<&[u8]>()
        + size_of::<&Vec<u8>>()
        + size_of::<&str>()
        + size_of::<(&PacketNativeImport18Binding, &SchemaRef, &[u8])>()
        + size_of::<&PacketCompleteRestorePrepareRequest>()
        + size_of::<&Rc<ProtocolCaptureOwner>>()
        + size_of::<&ProtocolCaptureOwner>()
        + size_of::<std::thread::Thread>()
        + size_of::<std::thread::ThreadId>()
        + size_of::<&std::thread::ThreadId>()
        + size_of::<&u32>()
        + size_of::<u32>()
        + size_of::<R>()
        + size_of::<Result<R, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn literal_partial_exposes_null_and_every_extension_without_normalization() {
        let envelope = Envelope {
            protocol: "CNP/1".to_owned(),
            message: crate::envelope::MessageKind::Response,
            session_id: Nullable(None),
            incarnation_id: Nullable(None),
            node_id: Nullable(None),
            execution_owner_id: Nullable(None),
            capture_owner_id: Nullable(None),
            request_id: Nullable(None),
            operation_id: Nullable(None),
            sequence: U64::new(1),
            method: Method::Begin,
            body: Map::from_iter([("retained_null".to_owned(), Value::Null)]),
            extensions: Extensions::from_iter([(
                "uninterpreted".to_owned(),
                serde_json::json!({"$serde_json::private::RawValue":"null"}),
            )]),
        };
        let view = envelope_partial_data(&envelope);

        assert!(std::ptr::eq(view.envelope_data(), &envelope));
        assert!(std::ptr::eq(view.body, &envelope.body));
        assert!(std::ptr::eq(view.extensions, &envelope.extensions));
        assert_eq!(view.body.get("retained_null"), Some(&Value::Null));
        assert!(view.body.get("missing").is_none());
        assert!(view.extensions["uninterpreted"].is_object());
    }

    #[test]
    fn raw_partial_keeps_actual_bytes_and_null_owner_distinct_from_absence() {
        let raw = RetainedFrame {
            value: Value::Null,
            bytes: b"null".to_vec(),
        };
        let missing: Option<OriginalNativeImport18RawPartialData<'_>> = None;
        let retained = Some(raw_partial_data(&raw));

        assert!(missing.is_none());
        let retained = retained.unwrap();
        assert!(std::ptr::eq(retained.value, &raw.value));
        assert_eq!(retained.value, &Value::Null);
        assert_eq!(retained.bytes, b"null");
        assert_eq!(retained.bytes.as_ptr(), raw.bytes.as_ptr());
    }
}
