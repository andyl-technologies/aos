//! Produces the distinct final Poll from actual retained Capture/After custody.

use super::*;
use crate::reference_packet::service::restored_settled_confirmation::{
    PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_FEATURE as FEATURE,
    PACKET_RESTORED_SETTLED_AFTER_CONFIRMATION_RECEIPT_SCHEMA as RECEIPT_SCHEMA,
    PACKET_RESTORED_SETTLED_CAPTURE_TERMINAL_DOMAIN as TERMINAL_DOMAIN,
    PacketRestoredSettledAfterConfirmationRequest as Request,
};

/// Borrows actual same-bank Capture and output owners without granting access.
#[derive(Clone, Copy)]
pub(crate) struct NativeCapture17ConfirmationInputs<'a> {
    pub(crate) original: &'a Envelope,
    pub(crate) body: &'a PollRequest,
    pub(crate) request: &'a Request,
    pub(crate) capture_original: &'a Envelope,
    pub(crate) capture_terminal: &'a Envelope,
    pub(crate) after: &'a ContentRef,
    pub(crate) after_capacity: usize,
}

pub(crate) struct NativeCapture17ConfirmationStorageData {
    pub(super) owner: Rc<()>,
    pub(super) input: [u8; 32],
    pub(super) originals: usize,
    pub(super) row: PacketNativeStartupAllocationRow,
    pub(super) hash_row: PacketNativeStartupAllocationRow,
    pub(super) body: Shape,
    pub(super) receipt: Shape,
    pub(super) envelope: Shape,
    pub(super) capture_original: Shape,
    pub(super) capture_terminal: Shape,
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum ConfirmationPhase {
    Failed,
    Complete,
}

/// Preserves all original/canonical/hash/body/receipt children on failure.
pub(crate) struct NativeCapture17ConfirmationAttempt {
    pub(super) owner: Rc<()>,
    pub(super) creator: u32,
    pub(super) original: Option<[u8; 32]>,
    pub(super) admitted: PacketNativeStartupAllocationRow,
    pub(super) hash: Option<NativePendingCapture17RequestHashAttempt>,
    pub(super) capture_request_dom: Option<Value>,
    pub(super) capture_request_bytes: Vec<u8>,
    pub(super) capture_request_ref: Option<ContentRef>,
    pub(super) capture_terminal_dom: Option<Value>,
    pub(super) capture_terminal_bytes: Vec<u8>,
    pub(super) capture_terminal_hash: Option<HashRef>,
    pub(super) body: Option<Map<String, Value>>,
    pub(super) receipt: Option<Value>,
    pub(super) phase: ConfirmationPhase,
}

#[derive(Serialize)]
struct Receipt<'a> {
    schema: &'static str,
    capture: &'a Request,
    native_after_ref: &'a ContentRef,
    native_after_capacity: U64,
}

#[derive(Serialize)]
struct Result17<'a> {
    operation_id: &'a Id,
    operation_state: OperationState,
    outcome: &'a Map<String, Value>,
    observations: [(); 0],
    next_observation_sequence: U64,
}

#[derive(Serialize)]
struct Completed<'a> {
    status: &'static str,
    operation_state: OperationState,
    result: Result17<'a>,
    extensions: Extensions,
}

fn completed(input: NativeCapture17ConfirmationInputs<'_>) -> Completed<'_> {
    Completed {
        status: "completed",
        operation_state: OperationState::Completed,
        result: Result17 {
            operation_id: &input.request.capture_operation_id,
            operation_state: OperationState::Completed,
            outcome: &input.capture_terminal.body,
            observations: [],
            next_observation_sequence: U64::new(1),
        },
        extensions: Extensions::new(),
    }
}

fn project_receipt(out: &mut Projection, request: &Request) -> Result<(), ProviderError> {
    project_object(
        out,
        &[
            "schema",
            "capture",
            "native_after_ref",
            "native_after_capacity",
        ],
    )?;
    out.add_string(RECEIPT_SCHEMA)?;
    out.add_value(request)?;
    project_reference(out)?;
    out.add_unescaped_ascii_extent(20)
}

#[derive(Serialize)]
struct InputIdentity<'a> {
    original: &'a Envelope,
    body: &'a PollRequest,
    request: &'a Request,
    capture_original: &'a Envelope,
    capture_terminal: &'a Envelope,
    after: &'a ContentRef,
    after_capacity: usize,
}

fn input_identity(input: NativeCapture17ConfirmationInputs<'_>) -> Result<[u8; 32], ProviderError> {
    let mut sink = OriginalIdentity(blake3::Hasher::new_derive_key(
        "source-private.native-capture-confirmation-input/17",
    ));
    serde_json::to_writer(
        &mut sink,
        &InputIdentity {
            original: input.original,
            body: input.body,
            request: input.request,
            capture_original: input.capture_original,
            capture_terminal: input.capture_terminal,
            after: input.after,
            after_capacity: input.after_capacity,
        },
    )
    .map_err(|_| refused())?;
    Ok(*sink.0.finalize().as_bytes())
}

// Only the defining typed ContentRef roster is compared. The live token still
// supplies actual published output provenance; equivalent JSON is DATA only.
pub(super) fn matches_reference_data(value: &Value, reference: &ContentRef) -> bool {
    let ContentRef {
        hash,
        length,
        media_type,
    } = reference;
    let HashRef {
        algorithm,
        domain,
        digest,
    } = hash;
    let Some(fields) = value.as_object() else {
        return false;
    };
    let Some(hash) = fields.get("hash").and_then(Value::as_object) else {
        return false;
    };
    fields.len() == 3
        && hash.len() == 3
        && hash.get("algorithm").and_then(Value::as_str) == Some(algorithm.as_str())
        && hash.get("domain").and_then(Value::as_str) == Some(domain.as_str())
        && hash.get("digest").and_then(Value::as_str) == Some(digest.as_str())
        && fields.get("media_type").and_then(Value::as_str) == Some(media_type.as_str())
        && fields
            .get("length")
            .and_then(Value::as_str)
            .is_some_and(|value| matches_reference_length_data(value, *length))
}

// ContentRef carries canonical U64 text. Numeric aliases must not acquire a
// correspondence match merely because the native integer parser accepts them.
fn matches_reference_length_data(value: &str, expected: U64) -> bool {
    let bytes = value.as_bytes();
    if bytes.is_empty()
        || (bytes.len() > 1 && bytes[0] == b'0')
        || !bytes.iter().all(u8::is_ascii_digit)
    {
        return false;
    }

    value.parse::<u64>().ok() == Some(expected.get())
}

fn reference_length_counter_scratch_data() -> usize {
    size_of::<&str>()
        + size_of::<U64>()
        + size_of::<&[u8]>()
        + size_of::<std::slice::Iter<'static, u8>>()
        + size_of::<Option<&u8>>()
        + size_of::<&u8>()
        + size_of::<Option<u64>>()
        + size_of::<Result<u64, std::num::ParseIntError>>()
        + size_of::<bool>()
}

fn matches_capture_result_data(body: &Map<String, Value>, request: &Request) -> bool {
    let Some(result) = body.get("result").and_then(Value::as_object) else {
        return false;
    };
    let Some(owners) = result.get("owner_state_refs").and_then(Value::as_array) else {
        return false;
    };
    result.len() == 3
        && owners.len() == 1
        && result
            .get("capture_manifest")
            .is_some_and(|value| matches_reference_data(value, &request.native_snapshot_ref))
        && matches_reference_data(&owners[0], &request.native_control_ref)
        && result
            .get("unchanged_cut_receipt")
            .is_some_and(|value| matches_reference_data(value, &request.native_anchor_ref))
}

impl NativeCapture17ConfirmationStorageData {
    pub(crate) fn row_data(&self) -> PacketNativeStartupAllocationRow {
        self.row
    }
    pub(crate) fn body_data(&self) -> &Shape {
        &self.body
    }
    pub(crate) fn receipt_data(&self) -> &Shape {
        &self.receipt
    }
    pub(crate) fn envelope_data(&self) -> &Shape {
        &self.envelope
    }

    /// Checks actual Control/full borrowed inputs without borrowing native state.
    /// # Errors
    /// Refuses a foreign Control, changed complete inputs/cache length or fields.
    pub(crate) fn authenticate_data(
        &self,
        control: &PacketControl,
        input: NativeCapture17ConfirmationInputs<'_>,
    ) -> Result<(), ProviderError> {
        authenticate_owner(control, &self.owner, control.capture_creator)?;
        if self.input != input_identity(input)? || self.originals != control.originals.len() {
            return Err(refused());
        }
        control.authenticate_capture17_confirmation_fields_data(input)
    }
}

impl NativeCapture17ConfirmationAttempt {
    // This constructs only a failed retained destination. It carries no phase
    // permission; the private token is checked separately before any effect.
    pub(super) fn failed_data(
        control: &PacketControl,
        admitted: PacketNativeStartupAllocationRow,
    ) -> Self {
        Self {
            owner: Rc::clone(&control.capture_identity),
            creator: control.capture_creator,
            original: None,
            admitted: admitted,
            hash: None,
            capture_request_dom: None,
            capture_request_bytes: Vec::new(),
            capture_request_ref: None,
            capture_terminal_dom: None,
            capture_terminal_bytes: Vec::new(),
            capture_terminal_hash: None,
            body: None,
            receipt: None,
            phase: ConfirmationPhase::Failed,
        }
    }
}

impl PacketControl {
    /// Names actual formatter demand before any final-Poll quote traversal.
    /// # Errors
    /// Refuses foreign/busy Control edges or checked formatter overflow.
    pub(crate) fn capture17_confirmation_prequote_work_data(
        &self,
    ) -> Result<(usize, usize), ProviderError> {
        Ok((
            self.pending_capture17_formatter_work_data()?.max(20),
            capture17_producer_counter_scratch_data(),
        ))
    }

    // Only the private action can establish that these are the same actual
    // published Capture, terminal and After output. This checks DATA shape and
    // current cache correspondence without canonical hashing or typed decoding.
    fn authenticate_capture17_confirmation_fields_data(
        &self,
        input: NativeCapture17ConfirmationInputs<'_>,
    ) -> Result<(), ProviderError> {
        let NativeCapture17ConfirmationInputs {
            original,
            body,
            request,
            capture_original,
            capture_terminal,
            after,
            after_capacity,
        } = input;
        let id = original.request_id.0.as_ref().ok_or_else(refused)?;
        let capture_id = capture_original.request_id.0.as_ref().ok_or_else(refused)?;
        let operation = capture_original
            .operation_id
            .0
            .as_ref()
            .ok_or_else(refused)?;
        let (capture_hash, cached) = self.originals.get(capture_id).ok_or_else(refused)?;
        capture_original.matches_response(capture_terminal)?;
        if self.capture_creator != std::process::id()
            || self.complete_coordinator.is_none()
            || self.complete_storage.is_none()
            || original.message != MessageKind::Request
            || original.method != Method::Poll
            || original.sequence.get() == 0
            || original.operation_id.0.as_ref() != Some(operation)
            || request.capture_operation_id != *operation
            || request.capture_request_id != *capture_id
            || request.capture_request_hash != *capture_hash
            || request.capture_terminal_sequence != capture_terminal.sequence
            || original.session_id != capture_original.session_id
            || original.incarnation_id != capture_original.incarnation_id
            || original.node_id != capture_original.node_id
            || original.capture_owner_id != capture_original.capture_owner_id
            || original.execution_owner_id.0.is_some()
            || original.extensions.len() != 1
            || !original.extensions.contains_key(FEATURE)
            || original.body.len() != 2
            || original
                .body
                .get("after_observation_sequence")
                .and_then(Value::as_str)
                != Some("0")
            || original
                .body
                .get("extensions")
                .and_then(Value::as_object)
                .is_none_or(|extensions| !extensions.is_empty())
            || body.after_observation_sequence != U64::new(0)
            || !body.extensions.is_empty()
            || capture_original.method != Method::Begin
            || !capture_terminal.extensions.is_empty()
            || !matches_capture_result_data(&capture_terminal.body, request)
            || cached.body != capture_terminal.body
            || !cached.evidence.is_empty()
            || self.terminals.get(operation) != Some(&capture_terminal.body)
            || capture_terminal.body.get("status").and_then(Value::as_str) != Some("completed")
            || capture_terminal
                .body
                .get("operation_state")
                .and_then(Value::as_str)
                != Some("completed")
            || self.current_operation.is_some()
            || self.fenced
            || !self.immediate
            || self.originals.len() >= ORIGINALS
            || self.originals.contains_key(id)
            || after.media_type != "application/json"
            || after.length.get() == 0
            || u64::try_from(after_capacity).map_err(|_| exhausted())? < after.length.get()
            || after == &request.native_snapshot_ref
            || after == &request.native_control_ref
            || after == &request.native_anchor_ref
        {
            return Err(refused());
        }
        Ok(())
    }

    /// Quotes the actual completed outcome, exact receipt and full hash banks.
    ///
    /// Parent prepared/full-terminal/prefix copies remain independent. The row
    /// retains producer+cache body banks, one receipt, both complete canonical
    /// Capture correspondence banks, Poll normative-hash owner and split nodes.
    /// # Errors
    /// Refuses changed current fields, a frame above its actual ceiling, overflow
    /// or a short complete bound. The caller first admits prequote T/S.
    pub(crate) fn quote_capture17_confirmation_data(
        &self,
        input: NativeCapture17ConfirmationInputs<'_>,
        maximum_frame: usize,
        maximum: usize,
    ) -> Result<NativeCapture17ConfirmationStorageData, ProviderError> {
        self.authenticate_capture17_confirmation_fields_data(input)?;
        let original =
            actual_serialization_storage_data(input.original, Default::default(), maximum)?;
        if original.maximum_encoded_bytes > maximum_frame {
            return Err(exhausted());
        }
        let body =
            actual_serialization_storage_data(&completed(input), Default::default(), maximum)?;
        let mut out = Projection::new(maximum)?;
        project_receipt(&mut out, input.request)?;
        let receipt = out.finish(maximum)?;
        let mut out = Projection::new(maximum)?;
        project_terminal_header(&mut out, input.original)?;
        out.add_value(&completed(input))?;
        project_object(&mut out, &[FEATURE])?;
        project_receipt(&mut out, input.request)?;
        let envelope = out.finish(maximum)?;
        let capture_original =
            actual_serialization_storage_data(input.capture_original, Default::default(), maximum)?;
        let capture_terminal =
            actual_serialization_storage_data(input.capture_terminal, Default::default(), maximum)?;
        let hash = Self::quote_capture17_confirmation_request_hash_data(input.original, maximum)?;
        let hash_row = hash.row_data();
        let retained = sum(&[
            size_of::<NativeCapture17ConfirmationStorageData>(),
            size_of::<NativeCapture17ConfirmationAttempt>(),
            insertion::<Id, (HashRef, PacketControlReply)>(self.originals.len())?,
            input
                .original
                .request_id
                .0
                .as_ref()
                .ok_or_else(refused)?
                .as_str()
                .len(),
            multiply(2, body.retained_value_backing_bytes)?,
            receipt.retained_value_backing_bytes,
            capture_original.retained_value_backing_bytes,
            capture_original.maximum_encoded_bytes,
            capture_terminal.retained_value_backing_bytes,
            capture_terminal.maximum_encoded_bytes,
            "blake3-256".len() + "cnp.blob.v1".len() + 64 + "application/json".len(),
            "blake3-256".len() + TERMINAL_DOMAIN.len() + 64,
            "blake3-256".len() + "cnp.request.v1".len() + 64,
            usize::try_from(hash_row.retained_requested_bytes.get()).map_err(|_| exhausted())?,
        ])?;
        let transient = sum(&[
            original.requested_total()?,
            body.requested_total()?,
            receipt.requested_total()?,
            envelope.requested_total()?,
            capture_original.requested_total()?,
            capture_terminal.requested_total()?,
            usize::try_from(hash_row.maximum_simultaneous_transient_bytes.get())
                .map_err(|_| exhausted())?,
        ])?;
        let priced = row(
            retained,
            transient,
            capture17_producer_counter_scratch_data(),
            maximum,
        )?;
        Ok(NativeCapture17ConfirmationStorageData {
            owner: Rc::clone(&self.capture_identity),
            input: input_identity(input)?,
            originals: self.originals.len(),
            row: priced,
            hash_row,
            body,
            receipt,
            envelope,
            capture_original,
            capture_terminal,
        })
    }
}

impl NativeCapture17ConfirmationAttempt {
    /// Borrows the real complete body and receipt, without proving publication.
    /// # Errors
    /// Refuses failed/partial owners, foreign Control or another original.
    pub(crate) fn completed_data(
        &self,
        control: &PacketControl,
        original: &Envelope,
    ) -> Result<(&Map<String, Value>, &Value), ProviderError> {
        authenticate_owner(control, &self.owner, self.creator)?;
        if !matches!(self.phase, ConfirmationPhase::Complete)
            || self.original != Some(original_identity(original)?)
        {
            return Err(refused());
        }
        Ok((
            self.body.as_ref().ok_or_else(refused)?,
            self.receipt.as_ref().ok_or_else(refused)?,
        ))
    }
}

pub(super) fn counter_scratch_data() -> usize {
    reference_length_counter_scratch_data()
        + size_of::<NativeCapture17ConfirmationInputs<'static>>()
        + size_of::<InputIdentity<'static>>()
        + size_of::<NativeCapture17ConfirmationStorageData>()
        + size_of::<NativeCapture17ConfirmationAttempt>()
        + size_of::<Option<NativeCapture17ConfirmationAttempt>>()
        + size_of::<ConfirmationPhase>()
        + size_of::<Completed<'static>>()
        + size_of::<Result17<'static>>()
        + size_of::<Receipt<'static>>()
        + size_of::<&ContentRef>()
        + size_of::<&HashRef>()
        + size_of::<&U64>()
        + size_of::<&String>() * 4
        + size_of::<Option<&Map<String, Value>>>() * 2
        + size_of::<Option<&Vec<Value>>>()
        + size_of::<Result<u64, std::num::ParseIntError>>()
        + size_of::<Result<NativeCapture17ConfirmationStorageData, ProviderError>>()
        + size_of::<Result<(&Map<String, Value>, &Value), ProviderError>>()
        + size_of::<[usize; 14]>()
        + size_of::<[usize; 7]>()
        + size_of::<Result<Value, serde_json::Error>>()
        + size_of::<Result<HashRef, ContractError>>()
        + size_of::<Result<ContentRef, ContractError>>()
        + size_of::<Result<u64, std::num::TryFromIntError>>()
}
