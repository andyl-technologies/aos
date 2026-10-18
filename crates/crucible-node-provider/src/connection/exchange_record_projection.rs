//! Bounds the retained successful ordinary proof record before construction.
//!
//! The exchange codec stores canonical buffers as integer arrays, independently
//! of its full original Envelopes and typed ACK cache. This counter follows that
//! exact grammar. Negotiated raw ACK bytes remain a separate receive/error
//! allowance; only closed successful ACKs can become a completed native record.

use super::*;
use crate::bodies::{MethodResult, OperationState, ResponseShape};
use crate::retained_metadata::{
    MetadataObserver,
    serialization_storage::{
        OriginalSerializationStorageData, OriginalSerializationStorageProjection,
    },
};
use crucible_node_contract::U64;

const USIZE_DECIMAL_DIGITS: usize = usize::MAX.ilog10() as usize + 1;

#[derive(Clone, Copy)]
enum ProofProjectionKind {
    Observe,
    Capture,
    AfterConfirmation,
}

impl ProofProjectionKind {
    fn prefixes(self) -> (&'static str, &'static str) {
        match self {
            Self::Observe => ("packet-proof-", "packet-transfer-"),
            Self::Capture => ("packet-capture-proof-", "packet-capture-transfer-"),
            Self::AfterConfirmation => ("packet-after-proof-", "packet-after-transfer-"),
        }
    }
}

// This strengthens only the separately selected original Capture codec. It
// supplies no allocation right; preparation and the Source startup/capture
// admissions remain independent. Ordinary publication performs no new check.
pub(super) fn original_capture_proof_literals_required<S: ProviderStream>(
    connection: &Connection<S>,
) -> Result<bool, ProviderError> {
    let selected = matches!(
        connection.native5_codec.as_deref(),
        Some(Native5CodecOwner::NativePacket(policy))
            if policy.capture_allocation_selection().is_some()
    );
    // Realize and other pre-ACK startup exchanges precede the private native
    // admission. Their ordinary proof path must remain reachable. Only an
    // actually installed admission starts this selected correspondence guard;
    // count consumers below separately require that guarded phase.
    if !selected || connection.original_canonical_ack_admission.is_none() {
        return Ok(false);
    }
    connection.protocol_owner.ensure_current()?;
    connection.authenticate_native5_source_codec()?;
    connection.original_native_owned11_admission()?;
    if connection.role != EndpointRole::Provider {
        return Err(refused());
    }
    Ok(true)
}

pub(super) fn authenticate_current_proof_literal<S: ProviderStream>(
    connection: &Connection<S>,
    record: &ExchangeRecord,
    index: usize,
    response: &Envelope,
) -> Result<(), ProviderError> {
    if !original_capture_proof_literals_required(connection)? {
        return Err(refused());
    }
    {
        // Rejoin the immutable retained reply with this same actor/bank's
        // physically sent original. The temporary loan ends before the raw
        // incoming frame is borrowed; no independent header authority exists.
        let sent = record.original_sent_frame(connection, index)?;
        sent.original().matches_response(response)?;
    }
    let slot = connection.reader.original_slot().ok_or_else(refused)?;
    let bank = connection
        .original_frames
        .as_ref()
        .ok_or_else(refused)?
        .try_borrow()
        .map_err(|_| refused())?;
    let frame = bank.frame(slot).ok_or_else(refused)?;
    authenticate_proof_literal(response, frame)?;
    connection.protocol_owner.ensure_current()
}

/// Compares one retained incoming literal with its exact typed original.
///
/// # Errors
/// Refuses incomplete I/O, malformed framing, another direction or changed
/// canonical envelope correspondence. No completed owner is issued here.
pub(super) fn authenticate_proof_literal(
    response: &Envelope,
    frame: crate::transport::original_frames::OriginalFrame<'_>,
) -> Result<(), ProviderError> {
    use crate::transport::original_frames::FrameDirection;
    if frame.direction != FrameDirection::Incoming
        || !frame.complete
        || frame.transferred != frame.bytes.len()
        || frame.bytes.len() < 4
    {
        return Err(refused());
    }
    let header: [u8; 4] = frame.bytes[..4].try_into().map_err(|_| refused())?;
    if usize::try_from(u32::from_be_bytes(header)).ok() != Some(frame.bytes.len() - 4) {
        return Err(refused());
    }
    // This closed scanner compares actual scalar/key spelling and UTF-16
    // ordering without another DOM or encoded copy. In particular, whitespace
    // or escaped aliases cannot enlarge a continuing successful literal.
    crate::protocol_snapshot::owned11::correspondence::envelope(response, &frame.bytes[4..])
}

/// Bounds encoded state, without granting allocation, I/O or Capture rights.
pub(crate) struct OriginalPacketCompletedRecordEncodingData {
    pub(crate) maximum_encoded_bytes: usize,
    pub(crate) maximum_originals: usize,
    pub(crate) maximum_acknowledgements: usize,
    pub(crate) maximum_canonical_bytes: usize,
    // Only a fully completed selected canonical-literal publication may use
    // this suffix bound. Raw receive/error admission still uses negotiated R.
    pub(crate) maximum_completed_incoming_framed_bytes: usize,
    pub(crate) maximum_observed_nodes: usize,
    pub(crate) maximum_capacity_records: usize,
    pub(crate) maximum_serialized_value_nodes: usize,
    pub(crate) maximum_serialized_capacity_records: usize,
    pub(crate) frame_bank_views: usize,
    pub(crate) declared_counter_scratch_bytes: usize,
}

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn quote_original_packet_completed_record_encoding_data(
        &self,
        prefix: &OriginalPacketPrefixStorageData,
        originals_serialized_nodes: usize,
        originals_serialized_records: usize,
        maximum: usize,
    ) -> Result<OriginalPacketCompletedRecordEncodingData, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        if self.role != EndpointRole::Provider
            || prefix.frames != add(prefix.requests, 1)?
            || prefix.frames == 0
        {
            return Err(refused());
        }
        let canonical_bytes = prefix
            .outgoing_framed_bytes
            .checked_sub(mul(prefix.frames, 4)?)
            .ok_or_else(exhausted)?;
        let mut maximum_ack = 0;
        let mut maximum_ack_nodes = 0;
        let mut maximum_ack_records = 0;
        for method in [Method::BlobBegin, Method::BlobChunk, Method::BlobFinish] {
            let ack = project_ack_record_entry(
                &self.authority,
                ProofProjectionKind::Observe,
                method,
                maximum,
            )?;
            maximum_ack = maximum_ack.max(ack.maximum_encoded_bytes);
            maximum_ack_nodes = maximum_ack_nodes.max(ack.serialized_value_nodes);
            maximum_ack_records = maximum_ack_records.max(ack.serialized_capacity_records);
        }
        let data = completed_record_encoding_data(
            prefix.frames,
            prefix.requests,
            canonical_bytes,
            maximum_ack,
            add(
                originals_serialized_nodes,
                mul(prefix.requests, maximum_ack_nodes)?,
            )?,
            add(
                originals_serialized_records,
                mul(prefix.requests, maximum_ack_records)?,
            )?,
            maximum,
        )?;
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        Ok(data)
    }
}

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn quote_original_continuation_completed_incoming_data(
        &self,
        plan: &OriginalContinuationPrefixStorageData,
        maximum: usize,
    ) -> Result<usize, ProviderError> {
        if !original_capture_proof_literals_required(self)? {
            return Err(refused());
        }
        let kind = match plan.kind {
            OriginalContinuationPrefixKind::Capture => ProofProjectionKind::Capture,
            OriginalContinuationPrefixKind::AfterConfirmation => {
                ProofProjectionKind::AfterConfirmation
            }
        };
        let mut envelope_and_cache = 0;
        for method in [Method::BlobBegin, Method::BlobChunk, Method::BlobFinish] {
            envelope_and_cache = envelope_and_cache.max(
                project_ack_record_entry(&self.authority, kind, method, maximum)?
                    .maximum_encoded_bytes,
            );
        }
        // The actual selected publisher checks this same closed successful
        // family AND canonical raw correspondence before continuing. One
        // rejected/error frame still uses full R and cannot reach a later cut.
        mul(plan.exchange.requests, add(envelope_and_cache, 4)?)
    }
}

impl OriginalPacketCompletedRecordEncodingData {
    /// Checks the actual immutable completed record before adopting its owner.
    pub(crate) fn authenticate_completed_original<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        record: &ExchangeRecord,
    ) -> Result<(), ProviderError> {
        connection.protocol_owner.ensure_current()?;
        connection.authenticate_native5_source_codec()?;
        let (actor, bank) = record.original_actor.as_ref().ok_or_else(refused)?;
        let current_bank = connection.original_frames.as_ref().ok_or_else(refused)?;
        if !Rc::ptr_eq(actor, &connection.protocol_owner) || !Rc::ptr_eq(bank, current_bank) {
            return Err(refused());
        }
        self.authenticate_record_shape(record)?;
        for original in &record.originals[1..] {
            if original.session_id.0.as_ref() != Some(connection.authority.session_id())
                || original.incarnation_id.0.as_ref() != Some(connection.authority.incarnation_id())
            {
                return Err(refused());
            }
        }
        for slot in 0..record.originals.len() {
            // The actual bank loan verifies full physical header/body progress
            // and same canonical bytes. It neither reencodes nor copies them.
            record.original_sent_frame(connection, slot)?;
        }
        connection.protocol_owner.ensure_current()
    }

    fn authenticate_record_shape(&self, record: &ExchangeRecord) -> Result<(), ProviderError> {
        if record.originals.is_empty()
            || record.originals.len() > self.maximum_originals
            || record.sent != record.originals.len()
            || record.canonical.len() != record.originals.len()
            || record.original_slots.len() != record.originals.len()
            || record.original_slots.iter().any(Option::is_none)
            || record.acknowledgements.len() != record.originals.len() - 1
            || record.acknowledgements.len() > self.maximum_acknowledgements
            || record.originals[0].message != MessageKind::Response
            || record.originals[0].method != Method::Observe
        {
            return Err(refused());
        }
        let canonical = record
            .canonical
            .iter()
            .try_fold(0usize, |sum, bytes| add(sum, bytes.len()))?;
        if canonical > self.maximum_canonical_bytes {
            return Err(exhausted());
        }
        for (original, received) in record.originals[1..].iter().zip(&record.acknowledgements) {
            authenticate_successful_ack(original, received)?;
        }
        let mut observer = MetadataObserver::new();
        record.observe_owned12_capture_children(&mut observer)?;
        let actual = observer.finish();
        if actual.observed_nodes > self.maximum_observed_nodes
            || actual.capacity_records > self.maximum_capacity_records
        {
            return Err(exhausted());
        }
        super::super::serialized_credit(
            &record.original_protocol_view(),
            self.maximum_encoded_bytes,
        )?;
        Ok(())
    }
}

fn completed_record_encoding_data(
    frames: usize,
    requests: usize,
    canonical: usize,
    maximum_ack: usize,
    serialized_nodes: usize,
    serialized_records: usize,
    maximum: usize,
) -> Result<OriginalPacketCompletedRecordEncodingData, ProviderError> {
    let mut fixed = OriginalSerializationStorageProjection::new(maximum)?;
    fixed.add_object()?;
    for key in [
        "originals",
        "originals_capacity",
        "canonical",
        "canonical_capacity",
        "acknowledgements",
        "acknowledgements_capacity",
        "sent",
        "original_slots",
        "original_slots_capacity",
        "original_actor",
    ] {
        fixed.add_field(key)?;
    }
    // Five capacity/progress fields are native usize numbers, not quoted U64.
    for _ in 0..5 {
        fixed.add_value(&usize::MAX)?;
    }
    fixed.add_value(&Some("same-original-endpoint"))?;
    let fixed = fixed.finish(maximum)?;
    // Originals retain complete outgoing Envelopes; their canonical buffers
    // separately encode each byte as a decimal u8 plus an array separator.
    // Each canonical row is [byte_array, capacity]. Slots contain Some(usize).
    let maximum_encoded_bytes = sum(&[
        fixed.maximum_encoded_bytes,
        canonical,
        add(frames, 2)?,
        mul(canonical, 4)?,
        mul(frames, add(USIZE_DECIMAL_DIGITS, 6)?)?,
        2,
        mul(requests, add(maximum_ack, 1)?)?,
        2,
        mul(frames, add(USIZE_DECIMAL_DIGITS, 1)?)?,
        2,
    ])?;
    if maximum_encoded_bytes > maximum {
        return Err(exhausted());
    }
    Ok(OriginalPacketCompletedRecordEncodingData {
        maximum_encoded_bytes,
        maximum_originals: frames,
        maximum_acknowledgements: requests,
        maximum_canonical_bytes: canonical,
        // The full cached ACK entry includes its Envelope and typed duplicate
        // result, so this safely dominates its canonical raw Envelope body.
        maximum_completed_incoming_framed_bytes: mul(requests, add(maximum_ack, 4)?)?,
        // Value strings/arrays add at most one typed visit to each logical
        // event. Envelopes additionally contain seven Nullable/Option scopes;
        // count all three possible wrapper visits independently. Canonical
        // byte banks use the actual selected capacity/length walk below.
        maximum_observed_nodes: sum(&[
            mul(serialized_nodes, 2)?,
            mul(add(frames, requests)?, 3 * 7)?,
            mul(frames, 3)?,
            8,
        ])?,
        // Include the actual Vecs, each response Box and actor/bank alias rows
        // in addition to serialized key/string/container backing records.
        maximum_capacity_records: sum(&[serialized_records, frames, requests, 8])?,
        // These are the actual ten-field codec's serde events: independent
        // originals/canonical/ACK/slot arrays, per-canonical tuple+byte array,
        // every initialized integer byte, capacity scalar and populated slot.
        maximum_serialized_value_nodes: sum(&[
            fixed.serialized_value_nodes, serialized_nodes, 4,
            mul(frames, 4)?, canonical,
        ])?,
        maximum_serialized_capacity_records: sum(&[
            fixed.serialized_capacity_records, serialized_records, 4,
            mul(frames, 2)?,
        ])?,
        frame_bank_views: 1,
        declared_counter_scratch_bytes: sum(&[
            crate::protocol_snapshot::owned11::correspondence::closed_envelope_comparison_scratch_data(),
            std::mem::size_of::<OriginalPacketCompletedRecordEncodingData>(),
            std::mem::size_of::<OriginalSerializationStorageProjection>(),
            std::mem::size_of::<
                crate::retained_metadata::serialization_storage::OriginalSerializationStorageData,
            >(),
        ])?,
    })
}

fn project_ack_record_entry(
    authority: &ConnectionAuthority,
    kind: ProofProjectionKind,
    method: Method,
    maximum: usize,
) -> Result<OriginalSerializationStorageData, ProviderError> {
    let mut projection = OriginalSerializationStorageProjection::new(maximum)?;
    projection.add_array_extent(2)?;
    projection.add_object()?;
    for key in ["protocol", "message"] {
        projection.add_field(key)?;
    }
    projection.add_string("CNP/1")?;
    projection.add_value(&MessageKind::Response)?;
    for (key, value) in [
        ("session_id", authority.session_id()),
        ("incarnation_id", authority.incarnation_id()),
    ] {
        projection.add_field(key)?;
        projection.add_value(value)?;
    }
    for key in [
        "node_id",
        "execution_owner_id",
        "capture_owner_id",
        "operation_id",
    ] {
        projection.add_field(key)?;
        if matches!(kind, ProofProjectionKind::AfterConfirmation) && key != "execution_owner_id" {
            projection.add_unescaped_ascii_extent(128)?;
        } else {
            projection.add_value(&())?;
        }
    }
    projection.add_field("request_id")?;
    projection.add_unescaped_ascii_extent(kind.prefixes().0.len() + 20)?;
    projection.add_field("sequence")?;
    projection.add_value(&U64::new(u64::MAX))?;
    projection.add_field("method")?;
    projection.add_value(&method)?;
    projection.add_field("body")?;
    project_ack_shape(&mut projection, kind, method)?;
    projection.add_field("extensions")?;
    projection.add_object()?;
    projection.add_array_extent(3)?;
    projection.add_string("Response")?;
    project_ack_shape(&mut projection, kind, method)?;
    projection.add_array_extent(2)?;
    projection.add_string(match method {
        Method::BlobBegin => "BlobBegin",
        Method::BlobChunk => "BlobChunk",
        Method::BlobFinish => "BlobFinish",
        _ => return Err(refused()),
    })?;
    project_ack_result(&mut projection, kind, method)?;
    projection.finish(maximum)
}

fn project_ack_shape(
    out: &mut OriginalSerializationStorageProjection,
    kind: ProofProjectionKind,
    method: Method,
) -> Result<(), ProviderError> {
    out.add_object()?;
    for key in ["status", "operation_state", "result", "extensions"] {
        out.add_field(key)?;
    }
    out.add_string("completed")?;
    out.add_value(&OperationState::Completed)?;
    project_ack_result(out, kind, method)?;
    out.add_object()
}

fn project_ack_result(
    out: &mut OriginalSerializationStorageProjection,
    kind: ProofProjectionKind,
    method: Method,
) -> Result<(), ProviderError> {
    out.add_object()?;
    out.add_field("transfer_id")?;
    out.add_unescaped_ascii_extent(kind.prefixes().1.len() + 20)?;
    match method {
        Method::BlobBegin | Method::BlobChunk => {
            out.add_field("next_offset")?;
            out.add_value(&U64::new(u64::MAX))?;
            if method == Method::BlobBegin {
                out.add_field("maximum_chunk_bytes")?;
                out.add_value(&U64::new(1_048_576))?;
            }
        }
        Method::BlobFinish => {
            out.add_field("content")?;
            out.add_object()?;
            for key in ["hash", "length", "media_type"] {
                out.add_field(key)?;
            }
            out.add_object()?;
            for key in ["algorithm", "domain", "digest"] {
                out.add_field(key)?;
            }
            out.add_string("blake3-256")?;
            out.add_string("cnp.blob.v1")?;
            out.add_unescaped_ascii_extent(64)?;
            out.add_value(&U64::new(u64::MAX))?;
            out.add_string_extent(128)?;
        }
        _ => return Err(refused()),
    }
    Ok(())
}

pub(super) fn authenticate_successful_ack(
    original: &Envelope,
    received: &ReceivedFrame,
) -> Result<(), ProviderError> {
    let ReceivedBody::Response(response) = &received.body else {
        return Err(refused());
    };
    let ResponseShape::Completed {
        operation_state: OperationState::Completed,
        extensions,
        ..
    } = &response.shape
    else {
        return Err(refused());
    };
    let reply = &received.envelope;
    if original.message != MessageKind::Request
        || reply.message != MessageKind::Response
        || reply.method != original.method
        || reply.request_id != original.request_id
        || reply.session_id != original.session_id
        || reply.incarnation_id != original.incarnation_id
        || reply.node_id != original.node_id
        || reply.execution_owner_id != original.execution_owner_id
        || reply.capture_owner_id != original.capture_owner_id
        || reply.operation_id != original.operation_id
        || !reply.extensions.is_empty()
        || !extensions.is_empty()
    {
        return Err(refused());
    }
    let request = original.request_id.0.as_ref().ok_or_else(refused)?;
    let kind = [
        ProofProjectionKind::Observe,
        ProofProjectionKind::Capture,
        ProofProjectionKind::AfterConfirmation,
    ]
    .into_iter()
    .find(|kind| has_decimal_suffix(request.as_str(), kind.prefixes().0))
    .ok_or_else(refused)?;
    if !matches!(kind, ProofProjectionKind::AfterConfirmation)
        && (original.node_id.0.is_some()
            || original.execution_owner_id.0.is_some()
            || original.capture_owner_id.0.is_some()
            || original.operation_id.0.is_some())
    {
        return Err(refused());
    }
    let transfer = match (original.method, response.result.as_ref()) {
        (Method::BlobBegin, Some(MethodResult::BlobBegin(result))) => &result.transfer_id,
        (Method::BlobChunk, Some(MethodResult::BlobChunk(result))) => &result.transfer_id,
        (Method::BlobFinish, Some(MethodResult::BlobFinish(result))) => {
            if result.content.hash.algorithm != "blake3-256"
                || result.content.hash.domain != "cnp.blob.v1"
                || result.content.hash.digest.len() != 64
                || result.content.media_type.len() > 128
            {
                return Err(refused());
            }
            &result.transfer_id
        }
        _ => return Err(refused()),
    };
    if original
        .body
        .get("transfer_id")
        .and_then(serde_json::Value::as_str)
        != Some(transfer.as_str())
        || !has_decimal_suffix(transfer.as_str(), kind.prefixes().1)
    {
        return Err(refused());
    }
    Ok(())
}

fn has_decimal_suffix(value: &str, prefix: &str) -> bool {
    value.strip_prefix(prefix).is_some_and(|suffix| {
        !suffix.is_empty() && suffix.len() <= 20 && suffix.bytes().all(|byte| byte.is_ascii_digit())
    })
}

fn add(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_add(right).ok_or_else(exhausted)
}

fn mul(left: usize, right: usize) -> Result<usize, ProviderError> {
    left.checked_mul(right).ok_or_else(exhausted)
}

fn sum(values: &[usize]) -> Result<usize, ProviderError> {
    values.iter().try_fold(0, |total, value| add(total, *value))
}

fn refused() -> ProviderError {
    ProviderError::Correlation("native completed ordinary proof record differs")
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("native completed ordinary proof record encoding")
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- Closed codec fixtures deliberately panic on invalid setup.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;
    use crate::bodies::{
        BlobBeginRequest, BlobBeginResult, BlobChunkRequest, BlobChunkResult, BlobFinishRequest,
        BlobFinishResult,
    };
    use crucible_node_contract::{Bytes, ContentRef, Extensions};
    use serde::Serialize;

    fn object(value: impl Serialize) -> serde_json::Map<String, serde_json::Value> {
        serde_json::to_value(value)
            .unwrap()
            .as_object()
            .unwrap()
            .clone()
    }

    fn fixture() -> (ConnectionAuthority, ExchangeRecord) {
        let (_, authority) = crate::handshake::tests::authority();
        let transfer = Id::new("packet-transfer-18446744073709551615").unwrap();
        let content = ContentRef {
            hash: crucible_node_contract::canonical::hash("cnp.blob.v1", b"actual content")
                .unwrap(),
            length: U64::new(b"actual content".len() as u64),
            media_type: "application/json".into(),
        };
        let mut original = crate::envelope::tests::request();
        original.message = MessageKind::Response;
        original.method = Method::Observe;
        original.extensions.clear();
        let mut record = ExchangeRecord {
            originals: vec![original],
            canonical: Vec::new(),
            acknowledgements: Vec::new(),
            sent: 0,
            original_slots: Vec::new(),
            original_actor: None,
        };
        for (method, request, result) in [
            (
                Method::BlobBegin,
                object(BlobBeginRequest {
                    transfer_id: transfer.clone(),
                    content: content.clone(),
                    extensions: Extensions::new(),
                }),
                object(BlobBeginResult {
                    transfer_id: transfer.clone(),
                    next_offset: U64::new(0),
                    maximum_chunk_bytes: U64::new(1_048_576),
                }),
            ),
            (
                Method::BlobChunk,
                object(BlobChunkRequest {
                    transfer_id: transfer.clone(),
                    offset: U64::new(0),
                    bytes: Bytes::new(vec![0, 127, 255]),
                    extensions: Extensions::new(),
                }),
                object(BlobChunkResult {
                    transfer_id: transfer.clone(),
                    next_offset: U64::new(3),
                }),
            ),
            (
                Method::BlobFinish,
                object(BlobFinishRequest {
                    transfer_id: transfer.clone(),
                    extensions: Extensions::new(),
                }),
                object(BlobFinishResult {
                    transfer_id: transfer.clone(),
                    content,
                }),
            ),
        ] {
            let mut request_envelope = crate::envelope::tests::request();
            request_envelope.message = MessageKind::Request;
            request_envelope.method = method;
            request_envelope.session_id =
                crate::envelope::Nullable(Some(authority.session_id().clone()));
            request_envelope.incarnation_id =
                crate::envelope::Nullable(Some(authority.incarnation_id().clone()));
            request_envelope.node_id = crate::envelope::Nullable(None);
            request_envelope.execution_owner_id = crate::envelope::Nullable(None);
            request_envelope.capture_owner_id = crate::envelope::Nullable(None);
            request_envelope.operation_id = crate::envelope::Nullable(None);
            request_envelope.request_id = crate::envelope::Nullable(Some(
                Id::new(format!("packet-proof-{}", record.originals.len())).unwrap(),
            ));
            request_envelope.body = request;
            request_envelope.extensions.clear();
            let typed = crate::bodies::decode_request(method, &request_envelope.body).unwrap();
            let mut reply = request_envelope.clone();
            reply.message = MessageKind::Response;
            reply.body = object(ResponseShape::Completed {
                operation_state: OperationState::Completed,
                result,
                extensions: Extensions::new(),
            });
            let body = crate::bodies::decode_response(&typed, &reply.body).unwrap();
            record.originals.push(request_envelope);
            record.acknowledgements.push(ReceivedFrame {
                envelope: reply,
                body: ReceivedBody::Response(Box::new(body)),
            });
        }
        for (index, original) in record.originals.iter().enumerate() {
            record.canonical.push(
                crucible_node_contract::canonical::canonical_json(
                    &serde_json::to_value(original).unwrap(),
                )
                .unwrap(),
            );
            record.original_slots.push(Some(index));
        }
        record.sent = record.originals.len();
        (authority, record)
    }

    fn quote(
        authority: &ConnectionAuthority,
        record: &ExchangeRecord,
    ) -> OriginalPacketCompletedRecordEncodingData {
        let maximum = 8 * 1024 * 1024;
        let acks = [Method::BlobBegin, Method::BlobChunk, Method::BlobFinish]
            .into_iter()
            .map(|method| {
                project_ack_record_entry(authority, ProofProjectionKind::Observe, method, maximum)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let ack = acks
            .iter()
            .map(|data| data.maximum_encoded_bytes)
            .max()
            .unwrap();
        let ack_nodes = acks
            .iter()
            .map(|data| data.serialized_value_nodes)
            .max()
            .unwrap();
        let ack_records = acks
            .iter()
            .map(|data| data.serialized_capacity_records)
            .max()
            .unwrap();
        let originals = record
            .originals
            .iter()
            .map(|original| {
                crate::retained_metadata::serialization_storage::actual_serialization_storage_data(
                    original,
                    Default::default(),
                    maximum,
                )
                .unwrap()
            })
            .collect::<Vec<_>>();
        let nodes: usize = originals
            .iter()
            .map(|data| data.serialized_value_nodes)
            .sum();
        let records: usize = originals
            .iter()
            .map(|data| data.serialized_capacity_records)
            .sum();
        completed_record_encoding_data(
            record.originals.len(),
            record.acknowledgements.len(),
            record.canonical.iter().map(Vec::len).sum(),
            ack,
            nodes + ack_nodes * record.acknowledgements.len(),
            records + ack_records * record.acknowledgements.len(),
            maximum,
        )
        .unwrap()
    }

    #[test]
    fn selected_proof_literal_guard_checks_actual_bank_without_dropping_refused_raw() {
        use crate::transport::original_frames::{FrameDirection, OriginalFrameReservation};
        let (authority, record) = fixture();
        let bound = quote(&authority, &record);
        let mut successful_raw_bytes = 0usize;
        for received in &record.acknowledgements {
            let canonical = crucible_node_contract::canonical::canonical_json(
                &serde_json::to_value(&received.envelope).unwrap(),
            )
            .unwrap();
            for canonical_spelling in [true, false] {
                let mut body = canonical.clone();
                if !canonical_spelling {
                    body.insert(1, b' ');
                    // Generic raw JSON still describes the same Envelope. The
                    // selected guard must reject the enlarged spelling itself.
                    let parsed =
                        crucible_node_contract::canonical::parse_json(&body, 65_536).unwrap();
                    assert_eq!(
                        serde_json::from_value::<Envelope>(parsed).unwrap(),
                        received.envelope,
                    );
                }
                let mut framed = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
                framed.extend_from_slice(&body);
                let mut bank = OriginalFrameReservation::reserve(65_540, 1).unwrap();
                let slot = bank.begin(FrameDirection::Incoming, 65_540).unwrap();
                bank.append(slot, &framed).unwrap();
                bank.finish(slot).unwrap();
                let before = serde_json::to_vec(&bank.protocol_view()).unwrap();

                let actual =
                    authenticate_proof_literal(&received.envelope, bank.frame(slot).unwrap());

                assert_eq!(actual.is_ok(), canonical_spelling);
                assert_eq!(serde_json::to_vec(&bank.protocol_view()).unwrap(), before);
                assert_eq!(bank.frame(slot).unwrap().bytes, framed);
                if canonical_spelling {
                    successful_raw_bytes += framed.len();
                }
            }
        }
        assert!(successful_raw_bytes <= bound.maximum_completed_incoming_framed_bytes);
        assert!(bound.maximum_completed_incoming_framed_bytes < 3 * 65_540);
    }

    #[test]
    fn completed_record_bound_covers_real_three_family_decode_and_integer_banks() {
        let (authority, record) = fixture();
        let bound = quote(&authority, &record);
        bound.authenticate_record_shape(&record).unwrap();

        let encoded = crucible_node_contract::canonical::canonical_json(
            &serde_json::to_value(record.original_protocol_view()).unwrap(),
        )
        .unwrap();
        assert!(encoded.len() <= bound.maximum_encoded_bytes);
        let view = serde_json::to_value(record.original_protocol_view()).unwrap();
        assert!(
            view["canonical"][0][0]
                .as_array()
                .unwrap()
                .iter()
                .all(serde_json::Value::is_u64)
        );
        assert_eq!(view["acknowledgements"][0][1][2][0], "BlobBegin");
        assert_eq!(view["acknowledgements"][1][1][2][0], "BlobChunk");
        assert_eq!(view["acknowledgements"][2][1][2][0], "BlobFinish");
    }

    #[test]
    fn completed_record_bound_refuses_partial_changed_header_and_open_ack_cache() {
        let (authority, mut record) = fixture();
        let bound = quote(&authority, &record);
        record.sent -= 1;
        assert!(bound.authenticate_record_shape(&record).is_err());
        record.sent += 1;
        let request = record.acknowledgements[0].envelope.request_id.clone();
        record.acknowledgements[0].envelope.request_id =
            crate::envelope::Nullable(Some(Id::new("foreign").unwrap()));
        assert!(bound.authenticate_record_shape(&record).is_err());
        record.acknowledgements[0].envelope.request_id = request;
        record.acknowledgements[0].envelope.extensions.insert(
            "unbounded-cache".into(),
            serde_json::json!({"unexpected":[1,2,3]}),
        );
        assert!(bound.authenticate_record_shape(&record).is_err());
    }

    #[test]
    fn completed_record_counter_refuses_integer_array_extent_overflow_and_one_short() {
        assert!(completed_record_encoding_data(2, 1, usize::MAX, 1, 0, 0, usize::MAX).is_err());
        let (authority, record) = fixture();
        let bound = quote(&authority, &record);
        let exact = completed_record_encoding_data(1, 0, 1, 0, 0, 0, usize::MAX).unwrap();
        assert!(
            completed_record_encoding_data(1, 0, 1, 0, 0, 0, exact.maximum_encoded_bytes - 1)
                .is_err()
        );
        assert!(bound.maximum_encoded_bytes > bound.maximum_canonical_bytes);
    }
}
