//! Checks one exact native incoming-Capture to settled-terminal data transition.
//!
//! Sealed decoder owners preserve original ordinary-serde byte order and every
//! capacity row. Only the correlation-map removal, literal suffix/counters and
//! reader last-slot may change. This data predicate grants no live source,
//! physical cut, registrar, restoration or fresh-key association.

use super::{HistoricalNativeState, SealedHistoricalNativeState};
use crate::protocol_snapshot::owned11::{
    correspondence,
    state::{next, tag},
    typed::{Fields, invalid, plain_string, unsigned},
};
use crate::transport::original_frames::{FrameDirection, OriginalFrame};
use crate::{ProviderError, envelope::Envelope};
use base64::Engine;
use crucible_node_format::ContentRef;

struct Parts<'a> {
    class: super::super::shared::NativeArchiveClass,
    connection: [&'a [u8]; 15],
    blobs: &'a [u8],
    service: &'a [u8],
    capture_allocation: Option<&'a [u8]>,
    records: &'a [u8],
    aliases: &'a [u8],
}

fn parts(input: &[u8]) -> Result<Parts<'_>, ProviderError> {
    let mut outer = Fields::array(input)?;
    tag(&mut outer, "source-private.cnp-protocol/11")?;
    let mut state = Fields::array(next(&mut outer)?)?;
    let format = plain_string(next(&mut state)?)?;
    let class = super::super::shared::NativeArchiveClass::read(format)?;
    let connection = array(next(&mut state)?)?;
    let blobs = next(&mut state)?;
    let service = next(&mut state)?;
    let capture_allocation = if class.capture() {
        Some(next(&mut state)?)
    } else {
        None
    };
    state.finish()?;
    let records = next(&mut outer)?;
    let aliases = next(&mut outer)?;
    outer.finish()?;
    Ok(Parts {
        class,
        connection,
        blobs,
        service,
        capture_allocation,
        records,
        aliases,
    })
}

fn array<const N: usize>(input: &[u8]) -> Result<[&[u8]; N], ProviderError> {
    let mut fields = Fields::array(input)?;
    let mut values = [b"".as_slice(); N];
    for value in &mut values {
        *value = next(&mut fields)?;
    }
    fields.finish()?;
    Ok(values)
}

impl SealedHistoricalNativeState {
    /// Checks exact static owners and all three proof/ACK transfers through terminal.
    ///
    /// The before owner must be the original NativeIncomingCapture cut and the
    /// after owner the immediate HostSettled cut, before Poll/fourth-body traffic.
    /// The exact reference order is snapshot, anchor, then Control.
    /// The source separately authenticates signed archive provenance, endpoint
    /// model/Control settlement and Core/fresh-target installation context.
    ///
    /// # Errors
    /// Refuses partial owners, changed static fields/capacities/aliases, another
    /// original request, altered literal prefix, extra/missing/reordered transfer
    /// bodies or ACKs, changed hashes, counters, scopes, reader or terminal.
    pub fn authenticate_capture_predecessor_data(
        &self,
        after: &SealedHistoricalNativeState,
        capture_request: &Envelope,
        capture_terminal: &Envelope,
        expected_three: [&ContentRef; 3],
    ) -> Result<(), ProviderError> {
        let before_state = self.historical()?;
        let after_state = after.historical()?;
        before_state.authenticate_capture_correspondence()?;
        after_state.authenticate_capture_correspondence()?;
        if capture_request.message != crate::envelope::MessageKind::Request
            || capture_request.method != crate::envelope::Method::Begin
            || capture_request
                .body
                .get("kind")
                .and_then(serde_json::Value::as_str)
                != Some("capture")
        {
            return Err(invalid());
        }
        capture_request.matches_response(capture_terminal)?;
        if expected_three[0] == expected_three[1]
            || expected_three[0] == expected_three[2]
            || expected_three[1] == expected_three[2]
        {
            return Err(invalid());
        }
        let before = parts(&self.encoded)?;
        let later = parts(&after.encoded)?;
        if before.class != later.class
            || before.blobs != later.blobs
            || before.service != later.service
            || before.aliases != later.aliases
        {
            return Err(invalid());
        }
        for i in [0, 1, 2, 4, 5, 8, 9, 10, 11, 12, 13] {
            if before.connection[i] != later.connection[i] {
                return Err(invalid());
            }
        }
        match (before.capture_allocation, later.capture_allocation) {
            (None, None) => {}
            (Some(first), Some(last)) => capture_allocation_static(first, last)?,
            _ => return Err(invalid()),
        }
        for state in [before_state, after_state] {
            if let Some(owner) = &state.capture_allocation
                && owner.capture_request_data() != Some(capture_request)
            {
                return Err(invalid());
            }
        }
        static_token(before.connection[14], later.connection[14])?;
        frame_capacity(before.connection[6], later.connection[6])?;
        let (a, b) = self.correlation_capacity_span;
        let (c, d) = after.correlation_capacity_span;
        if before.records.get(..a) != later.records.get(..c)
            || before.records.get(b..) != later.records.get(d..)
            || a > b
            || c > d
            || b > before.records.len()
            || d > later.records.len()
        {
            return Err(invalid());
        }
        correlations(before_state, after_state, capture_request)?;
        let before_count = before_state.connection.frames.frames().count();
        if before_count == 0
            || before_state.connection.reader.last_original_slot != Some(before_count - 1)
        {
            return Err(invalid());
        }
        let last = before_state
            .connection
            .frames
            .frame(before_count - 1)
            .ok_or_else(invalid)?;
        if last.direction != FrameDirection::Incoming {
            return Err(invalid());
        }
        correspondence::envelope(capture_request, complete(&last)?)?;
        for (i, original) in before_state.connection.frames.frames().enumerate() {
            let new = after_state.connection.frames.frame(i).ok_or_else(invalid)?;
            if original.direction != new.direction
                || original.bytes != new.bytes
                || original.transferred != new.transferred
                || original.complete != new.complete
            {
                return Err(invalid());
            }
        }
        slot_prefix(before.connection[6], later.connection[6], before_count)?;
        suffix(
            before_state,
            after_state,
            before_count,
            later.connection[6],
            capture_terminal,
            expected_three,
        )?;
        Ok(())
    }
}

fn static_token(before: &[u8], after: &[u8]) -> Result<(), ProviderError> {
    let before: [_; 6] = array(before)?;
    let after: [_; 6] = array(after)?;
    for i in [0, 2, 3, 4, 5] {
        if before[i] != after[i] {
            return Err(invalid());
        }
    }
    let old: [_; 10] = array(before[1])?;
    let new: [_; 10] = array(after[1])?;
    for i in [0, 1, 2, 3, 5, 6, 7, 8, 9] {
        if old[i] != new[i] {
            return Err(invalid());
        }
    }
    frame_capacity(old[4], new[4])
}

fn frame_capacity(before: &[u8], after: &[u8]) -> Result<(), ProviderError> {
    let before: [_; 8] = array(before)?;
    let after: [_; 8] = array(after)?;
    for i in [0, 1, 4, 5] {
        if before[i] != after[i] {
            return Err(invalid());
        }
    }
    Ok(())
}

fn slot_prefix(before: &[u8], after: &[u8], count: usize) -> Result<(), ProviderError> {
    let before: [_; 8] = array(before)?;
    let after: [_; 8] = array(after)?;
    let mut old = Fields::array(before[7])?;
    let mut new = Fields::array(after[7])?;
    for _ in 0..count {
        if next(&mut old)? != next(&mut new)? {
            return Err(invalid());
        }
    }
    old.finish()
}

fn correlations(
    before: &HistoricalNativeState,
    after: &HistoricalNativeState,
    request: &Envelope,
) -> Result<(), ProviderError> {
    let a = &before.connection.correlations;
    let b = &after.connection.correlations;
    if a.session != b.session
        || a.incarnation != b.incarnation
        || a.session.allocated_capacity() != b.session.allocated_capacity()
        || a.incarnation.allocated_capacity() != b.incarnation.allocated_capacity()
        || a.maximum_requests != b.maximum_requests
        || a.extensions != b.extensions
        || a.failed
        || b.failed
        || a.continuation_installed != b.continuation_installed
        || !a.pending.is_empty()
        || !a.writing_responses.is_empty()
        || a.received_requests.len() != 1
        || a.received_requests.values().next() != Some(request)
        || !b.pending.is_empty()
        || !b.writing_responses.is_empty()
        || !b.received_requests.is_empty()
        || request.sequence.get().checked_add(1) != Some(a.next_received.get())
    {
        return Err(invalid());
    }
    for (old, new) in a.extensions.iter().zip(&b.extensions) {
        if old.capacity() != new.capacity() {
            return Err(invalid());
        }
    }
    if before.connection.reader.maximum_bytes != after.connection.reader.maximum_bytes
        || before.connection.reader.maximum_nesting != after.connection.reader.maximum_nesting
        || before.connection.reader.failed
        || after.connection.reader.failed
    {
        return Err(invalid());
    }
    Ok(())
}

#[derive(Clone, Copy)]
struct Header<'a> {
    body: &'a [u8],
    session: &'a str,
    incarnation: &'a str,
    scope: [Option<&'a str>; 4],
    message: &'a str,
    method: &'a str,
    id: &'a str,
    sequence: u64,
}

fn nullable(input: &[u8]) -> Result<Option<&str>, ProviderError> {
    if input == b"null" {
        Ok(None)
    } else {
        Ok(Some(plain_string(input)?))
    }
}
fn counter(input: &[u8]) -> Result<u64, ProviderError> {
    let text = plain_string(input)?;
    if text.is_empty()
        || text.len() > 20
        || text.len() > 1 && text.starts_with('0')
        || !text.bytes().all(|b| b.is_ascii_digit())
    {
        return Err(invalid());
    }
    text.parse().map_err(|_| invalid())
}
fn header(input: &[u8]) -> Result<Header<'_>, ProviderError> {
    let mut f = Fields::object(input)?;
    let body = f.named("body")?;
    let capture = nullable(f.named("capture_owner_id")?)?;
    let execution = nullable(f.named("execution_owner_id")?)?;
    if f.named("extensions")? != b"{}" {
        return Err(invalid());
    }
    let incarnation = plain_string(f.named("incarnation_id")?)?;
    let message = plain_string(f.named("message")?)?;
    let method = plain_string(f.named("method")?)?;
    let node = nullable(f.named("node_id")?)?;
    let operation = nullable(f.named("operation_id")?)?;
    if plain_string(f.named("protocol")?)? != "CNP/1" {
        return Err(invalid());
    }
    let id = plain_string(f.named("request_id")?)?;
    let sequence = counter(f.named("sequence")?)?;
    let session = plain_string(f.named("session_id")?)?;
    f.finish()?;
    Ok(Header {
        body,
        session,
        incarnation,
        scope: [capture, execution, node, operation],
        message,
        method,
        id,
        sequence,
    })
}
fn complete<'a>(frame: &OriginalFrame<'a>) -> Result<&'a [u8], ProviderError> {
    if !frame.complete || frame.transferred != frame.bytes.len() || frame.bytes.len() < 4 {
        return Err(invalid());
    }
    let n = u32::from_be_bytes(frame.bytes[..4].try_into().map_err(|_| invalid())?);
    if usize::try_from(n).map_err(|_| invalid())? != frame.bytes.len() - 4 {
        return Err(invalid());
    }
    Ok(&frame.bytes[4..])
}

#[derive(Clone, Copy)]
enum Expect {
    Begin,
    Chunk(usize),
    Finish,
}
#[derive(Clone, Copy)]
struct Pending<'a> {
    header: Header<'a>,
    transfer: &'a str,
    object: usize,
    result: Expect,
}

fn suffix(
    before: &HistoricalNativeState,
    after: &HistoricalNativeState,
    prefix: usize,
    raw_bank: &[u8],
    terminal: &Envelope,
    references: [&ContentRef; 3],
) -> Result<(), ProviderError> {
    let mut pending: [Option<Pending<'_>>; 32] = [None; 32];
    let mut object = 0usize;
    let mut transfer = None;
    let mut transfers: [Option<&str>; 3] = [None; 3];
    let mut used = 0usize;
    let mut hasher = blake3::Hasher::new();
    let mut sent = before.connection.correlations.next_sent.get();
    let mut received = before.connection.correlations.next_received.get();
    let mut terminal_seen = false;
    let mut last_incoming = None;
    let mut largest_chunk = [0usize; 3];
    let mut peer_chunk = [0usize; 3];
    let bank = array::<8>(raw_bank)?;
    let window = usize::try_from(before.connection.authority.limits.requests.get())
        .map_err(|_| invalid())?
        .min(32);
    let chunk = usize::try_from(before.connection.authority.limits.blob_chunk_bytes.get())
        .map_err(|_| invalid())?
        .min(4096);
    if window == 0 || chunk == 0 {
        return Err(invalid());
    }
    let mut window_outgoing = 0usize;
    let mut draining = false;
    let mut raw_slots = Fields::array(bank[7])?;
    for _ in 0..prefix {
        next(&mut raw_slots)?;
    }
    for (index, frame) in after.connection.frames.frames().enumerate().skip(prefix) {
        if terminal_seen {
            return Err(invalid());
        }
        let direction = frame.direction;
        let bytes = complete(&frame)?;
        let h = header(bytes)?;
        let descriptor = array::<6>(next(&mut raw_slots)?)?;
        let expected_direction = match direction {
            FrameDirection::Incoming => "incoming",
            FrameDirection::Outgoing => "outgoing",
        };
        if plain_string(descriptor[0])? != expected_direction
            || unsigned(descriptor[2])?
                != u64::try_from(frame.bytes.len()).map_err(|_| invalid())?
            || unsigned(descriptor[3])?
                != u64::try_from(frame.transferred).map_err(|_| invalid())?
            || descriptor[4] != b"true"
        {
            return Err(invalid());
        }
        if h.message == "request" {
            descriptor_id(descriptor[5], h.id)?;
        } else if descriptor[5] != b"null" {
            return Err(invalid());
        }
        if h.session != before.connection.correlations.session.as_str()
            || h.incarnation != before.connection.correlations.incarnation.as_str()
        {
            return Err(invalid());
        }
        match direction {
            FrameDirection::Outgoing => {
                if h.sequence != sent {
                    return Err(invalid());
                }
                sent = sent.checked_add(1).ok_or_else(invalid)?;
                if h.message == "response" {
                    if object != 3 || transfer.is_some() || pending.iter().any(Option::is_some) {
                        return Err(invalid());
                    }
                    correspondence::envelope(terminal, bytes)?;
                    terminal_seen = true;
                    continue;
                }
                if h.message != "request"
                    || h.scope.iter().any(Option::is_some)
                    || pending.iter().flatten().any(|old| old.header.id == h.id)
                {
                    return Err(invalid());
                }
                if draining || window_outgoing == window {
                    return Err(invalid());
                }
                window_outgoing += 1;
                sequence_id(h.id, "packet-capture-proof-", h.sequence)?;
                let free = pending
                    .iter()
                    .position(Option::is_none)
                    .ok_or_else(invalid)?;
                let reference = references.get(object).copied().ok_or_else(invalid)?;
                let mut body = Fields::object(h.body)?;
                let result = match h.method {
                    "blob_begin" => {
                        if transfer.is_some() {
                            return Err(invalid());
                        }
                        correspondence::content_reference(reference, body.named("content")?)?;
                        if body.named("extensions")? != b"{}" {
                            return Err(invalid());
                        }
                        let id = plain_string(body.named("transfer_id")?)?;
                        sequence_id(id, "packet-capture-transfer-", h.sequence)?;
                        if transfers.iter().flatten().any(|old| *old == id) {
                            return Err(invalid());
                        }
                        transfers[object] = Some(id);
                        transfer = Some(id);
                        used = 0;
                        hasher = content_hasher(reference.length.get());
                        Expect::Begin
                    }
                    "blob_chunk" => {
                        let encoded = plain_string(body.named("bytes")?)?;
                        if body.named("extensions")? != b"{}"
                            || counter(body.named("offset")?)?
                                != u64::try_from(used).map_err(|_| invalid())?
                        {
                            return Err(invalid());
                        }
                        if Some(plain_string(body.named("transfer_id")?)?) != transfer {
                            return Err(invalid());
                        }
                        let mut decoded = [0u8; 4096];
                        let count = base64::engine::general_purpose::URL_SAFE_NO_PAD
                            .decode_slice(encoded, &mut decoded)
                            .map_err(|_| invalid())?;
                        let remaining = usize::try_from(reference.length.get())
                            .map_err(|_| invalid())?
                            .checked_sub(used)
                            .ok_or_else(invalid)?;
                        if count == 0 || count != chunk.min(remaining) {
                            return Err(invalid());
                        }
                        used = used.checked_add(count).ok_or_else(invalid)?;
                        if u64::try_from(used).map_err(|_| invalid())? > reference.length.get() {
                            return Err(invalid());
                        }
                        largest_chunk[object] = largest_chunk[object].max(count);
                        hasher.update(&decoded[..count]);
                        Expect::Chunk(used)
                    }
                    "blob_finish" => {
                        if body.named("extensions")? != b"{}"
                            || Some(plain_string(body.named("transfer_id")?)?) != transfer
                            || u64::try_from(used).map_err(|_| invalid())? != reference.length.get()
                            || reference.hash.algorithm != "blake3-256"
                            || reference.hash.domain != "cnp.blob.v1"
                            || hasher.finalize().to_hex().as_str() != reference.hash.digest
                        {
                            return Err(invalid());
                        }
                        Expect::Finish
                    }
                    _ => return Err(invalid()),
                };
                body.finish()?;
                let id = transfer.ok_or_else(invalid)?;
                pending[free] = Some(Pending {
                    header: h,
                    transfer: id,
                    object,
                    result,
                });
                if matches!(result, Expect::Finish) {
                    object += 1;
                    transfer = None;
                }
            }
            FrameDirection::Incoming => {
                if !draining && window_outgoing != window && !(object == 3 && transfer.is_none()) {
                    return Err(invalid());
                }
                draining = true;
                if h.sequence != received || h.message != "response" {
                    return Err(invalid());
                }
                received = received.checked_add(1).ok_or_else(invalid)?;
                last_incoming = Some(index);
                let i = pending
                    .iter()
                    .position(|entry| entry.is_some_and(|p| p.header.id == h.id))
                    .ok_or_else(invalid)?;
                let p = pending[i].ok_or_else(invalid)?;
                if h.method != p.header.method || h.scope != p.header.scope {
                    return Err(invalid());
                }
                acknowledge(h.body, p, references[p.object], &mut peer_chunk[p.object])?;
                pending[i] = None;
                if pending.iter().all(Option::is_none) {
                    window_outgoing = 0;
                    draining = false;
                }
            }
        }
    }
    raw_slots.finish()?;
    if !terminal_seen
        || object != 3
        || pending.iter().any(Option::is_some)
        || sent != after.connection.correlations.next_sent.get()
        || received != after.connection.correlations.next_received.get()
        || after.connection.reader.last_original_slot != last_incoming
    {
        return Err(invalid());
    }
    for i in 0..3 {
        if peer_chunk[i] == 0 || largest_chunk[i] > peer_chunk[i] {
            return Err(invalid());
        }
    }
    Ok(())
}

fn acknowledge(
    body: &[u8],
    pending: Pending<'_>,
    reference: &ContentRef,
    peer_chunk: &mut usize,
) -> Result<(), ProviderError> {
    let mut body = Fields::object(body)?;
    if body.named("extensions")? != b"{}"
        || plain_string(body.named("operation_state")?)? != "completed"
    {
        return Err(invalid());
    }
    let mut result = Fields::object(body.named("result")?)?;
    match pending.result {
        Expect::Begin => {
            *peer_chunk = usize::try_from(counter(result.named("maximum_chunk_bytes")?)?)
                .map_err(|_| invalid())?;
            if *peer_chunk == 0
                || *peer_chunk > 1_048_576
                || counter(result.named("next_offset")?)? != 0
            {
                return Err(invalid());
            }
        }
        Expect::Chunk(offset) => {
            if counter(result.named("next_offset")?)?
                != u64::try_from(offset).map_err(|_| invalid())?
            {
                return Err(invalid());
            }
        }
        Expect::Finish => correspondence::content_reference(reference, result.named("content")?)?,
    }
    if plain_string(result.named("transfer_id")?)? != pending.transfer {
        return Err(invalid());
    }
    result.finish()?;
    if plain_string(body.named("status")?)? != "completed" {
        return Err(invalid());
    }
    body.finish()
}

fn content_hasher(length: u64) -> blake3::Hasher {
    let mut hasher = blake3::Hasher::new();
    hasher.update(b"CNP/1\0");
    hasher.update(&11u32.to_be_bytes());
    hasher.update(b"cnp.blob.v1");
    hasher.update(&length.to_be_bytes());
    hasher
}

fn sequence_id(id: &str, prefix: &str, sequence: u64) -> Result<(), ProviderError> {
    let suffix = id.strip_prefix(prefix).ok_or_else(invalid)?;
    if suffix.is_empty()
        || suffix.len() > 20
        || suffix.len() > 1 && suffix.starts_with('0')
        || !suffix.bytes().all(|byte| byte.is_ascii_digit())
        || suffix.parse::<u64>().map_err(|_| invalid())? != sequence
    {
        return Err(invalid());
    }
    Ok(())
}

fn descriptor_id(input: &[u8], expected: &str) -> Result<(), ProviderError> {
    let mut bytes = Fields::array(input)?;
    for byte in expected.bytes() {
        if unsigned(next(&mut bytes)?)? != u64::from(byte) {
            return Err(invalid());
        }
    }
    bytes.finish()
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "tests exact original ACK and frame data"
)]
mod tests {
    use super::*;

    #[test]
    fn finish_ack_requires_actual_full_reference_and_exact_transfer() {
        let reference =
            crucible_node_format::canonical::content_ref(b"actual", "application/octet-stream")
                .unwrap();
        let pending = Pending {
            header: Header {
                body: b"{}",
                session: "s",
                incarnation: "i",
                scope: [None; 4],
                message: "request",
                method: "blob_finish",
                id: "packet-capture-proof-27",
                sequence: 27,
            },
            transfer: "packet-capture-transfer-25",
            object: 0,
            result: Expect::Finish,
        };
        let body = |content: &ContentRef, transfer: &str| {
            crucible_node_format::canonical::canonical_json(&serde_json::json!({
                "extensions": {}, "operation_state": "completed", "status": "completed",
                "result": { "content": content, "transfer_id": transfer }
            }))
            .unwrap()
        };
        let mut chunk = 0;
        acknowledge(
            &body(&reference, pending.transfer),
            pending,
            &reference,
            &mut chunk,
        )
        .unwrap();

        let foreign =
            crucible_node_format::canonical::content_ref(b"foreign", "application/octet-stream")
                .unwrap();
        assert!(
            acknowledge(
                &body(&foreign, pending.transfer),
                pending,
                &reference,
                &mut chunk
            )
            .is_err()
        );
        assert!(
            acknowledge(
                &body(&reference, "foreign-transfer"),
                pending,
                &reference,
                &mut chunk
            )
            .is_err()
        );
    }

    #[test]
    fn assigned_capture_names_and_frame_progress_cannot_be_relabelled() {
        sequence_id("packet-capture-proof-27", "packet-capture-proof-", 27).unwrap();
        assert!(sequence_id("packet-capture-proof-027", "packet-capture-proof-", 27).is_err());
        assert!(sequence_id("packet-capture-proof-28", "packet-capture-proof-", 27).is_err());
        descriptor_id(b"[97,98]", "ab").unwrap();
        assert!(descriptor_id(b"[97,98,99]", "ab").is_err());
        assert!(descriptor_id(b"null", "ab").is_err());

        let bytes = b"\0\0\0\x02{}";
        let frame = |transferred, done| OriginalFrame {
            direction: FrameDirection::Incoming,
            bytes,
            transferred,
            complete: done,
        };
        assert_eq!(complete(&frame(bytes.len(), true)).unwrap(), b"{}");
        assert!(complete(&frame(bytes.len() - 1, true)).is_err());
        assert!(complete(&frame(bytes.len(), false)).is_err());
    }
}

// Both fourth-owner frame views are independently checked aliases of each
// connection's complete bank. Their changing suffix is checked once through
// that bank below; all other original Observe/currency/report data stays exact.
fn capture_allocation_static(before: &[u8], after: &[u8]) -> Result<(), ProviderError> {
    let first = array::<11>(before)?;
    let last = array::<11>(after)?;
    if plain_string(first[0])? != "source-private.native-capture-allocation-owner/12"
        || first[0] != last[0]
    {
        return Err(invalid());
    }
    for i in [1, 2, 3, 4, 6, 7, 8, 9, 10] {
        if first[i] != last[i] {
            return Err(invalid());
        }
    }
    let first_sdk = array::<5>(first[5])?;
    let last_sdk = array::<5>(last[5])?;
    for i in 0..4 {
        if first_sdk[i] != last_sdk[i] {
            return Err(invalid());
        }
    }
    frame_capacity(first_sdk[4], last_sdk[4])
}
