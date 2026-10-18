//! Authenticates one completed held-proof transfer before its Commit response.
//!
//! Only the actual native held token supplies the expected reference and bytes.
//! This data witness retains the original actor/bank and an exhaustive literal
//! prefix commitment. It grants no model, source, capture or installation right.

use super::*;
use crate::bodies::{MethodResult, OperationState, ResponseShape};
use crate::protocol_snapshot::owned11::correspondence;
use crate::protocol_snapshot::owned11::{
    OriginalOwned11Fields as Fields, original_owned11_plain_string as plain_string,
    original_owned11_unsigned as unsigned,
};
use crate::transport::original_frames::{FrameDirection, OriginalFrameReservation};
use crucible_node_contract::{ContentRef, U64};
use std::cell::RefCell;

/// Retains correspondence to an actual completed, noninterleaved proof suffix.
pub(crate) struct CompletedHeldProof {
    actor: Rc<crate::protocol_snapshot::ProtocolCaptureOwner>,
    bank: Rc<RefCell<OriginalFrameReservation>>,
    prefix_slots: usize,
    prefix_digest: blake3::Hash,
    commit_sequence: U64,
    next_received: u64,
    next_sent: u64,
}

impl CompletedHeldProof {
    pub(super) fn authenticate_exchange<S: ProviderStream>(
        connection: &Connection<S>,
        commit: &Envelope,
        record: &ExchangeRecord,
        reference: &ContentRef,
        bytes: &[u8],
    ) -> Result<Self, ProviderError> {
        connection.protocol_owner.ensure_current()?;
        connection.authenticate_native5_source_codec()?;
        authenticate_content_bytes(reference, bytes)?;
        let originals = record.originals();
        let replies = record.acknowledgements();
        if originals.len() < 3
            || record.sent() != originals.len()
            || replies.len() != originals.len()
            || record.canonical_frames().len() != originals.len()
        {
            return Err(refused());
        }
        let bank_owner = connection.original_frames.as_ref().ok_or_else(refused)?;
        let bank = bank_owner.try_borrow().map_err(|_| borrowed())?;
        if !bank.complete() {
            return Err(refused());
        }
        let prefix_slots = bank.frames().count();
        let mut commit_slot = None;
        for (index, frame) in bank.frames().enumerate() {
            if frame.direction == FrameDirection::Incoming
                && literal_sequence(frame.bytes)? == commit.sequence
            {
                if commit_slot.is_some() {
                    return Err(refused());
                }
                complete_literal(&frame)?;
                correspondence::envelope(commit, &frame.bytes[4..])?;
                commit_slot = Some(index);
            }
        }
        let commit_slot = commit_slot.ok_or_else(refused)?;
        if prefix_slots.checked_sub(commit_slot + 1) != originals.len().checked_mul(2) {
            return Err(refused());
        }
        let first = originals.first().ok_or_else(refused)?;
        let transfer = first
            .body
            .get("transfer_id")
            .and_then(serde_json::Value::as_str)
            .ok_or_else(refused)?;
        let mut offset = 0usize;
        let mut maximum_chunk = 0u64;
        for (index, (original, reply)) in originals.iter().zip(replies).enumerate() {
            let sent = record.original_sent_frame(connection, index)?;
            let frame = sent.literal();
            let sent_slot = bank
                .frames()
                .enumerate()
                .find_map(|(slot, item)| {
                    (std::ptr::eq(item.bytes.as_ptr(), frame.bytes.as_ptr())
                        && item.bytes.len() == frame.bytes.len())
                    .then_some(slot)
                })
                .ok_or_else(refused)?;
            if sent_slot <= commit_slot
                || original.message != MessageKind::Request
                || original.sequence.get()
                    != first
                        .sequence
                        .get()
                        .checked_add(u64::try_from(index).map_err(|_| refused())?)
                        .ok_or_else(refused)?
                || original.protocol != commit.protocol
                || original.session_id != commit.session_id
                || original.incarnation_id != commit.incarnation_id
                || original.node_id.0.is_some()
                || original.capture_owner_id.0.is_some()
                || original.execution_owner_id.0.is_some()
                || original.operation_id.0.is_some()
                || !original.extensions.is_empty()
                || original
                    .body
                    .get("transfer_id")
                    .and_then(serde_json::Value::as_str)
                    != Some(transfer)
                || original
                    .body
                    .get("extensions")
                    .and_then(serde_json::Value::as_object)
                    .is_none_or(|v| !v.is_empty())
                || !reply.envelope.extensions.is_empty()
            {
                return Err(refused());
            }
            original.matches_response(&reply.envelope)?;
            if reply.envelope.sequence.get()
                != commit
                    .sequence
                    .get()
                    .checked_add(1)
                    .and_then(|n| n.checked_add(u64::try_from(index).ok()?))
                    .ok_or_else(refused)?
            {
                return Err(refused());
            }
            let ReceivedBody::Response(response) = &reply.body else {
                return Err(refused());
            };
            if !matches!(&response.shape, ResponseShape::Completed { operation_state: OperationState::Completed, extensions, .. } if extensions.is_empty())
            {
                return Err(refused());
            }
            if index == 0 {
                if original.method != Method::BlobBegin || original.body.len() != 3 {
                    return Err(refused());
                }
                let mut envelope = Fields::object(sent.canonical_body())?;
                let mut body = Fields::object(envelope.named("body")?)?;
                correspondence::content_reference(reference, body.named("content")?)?;
                let Some(MethodResult::BlobBegin(result)) = &response.result else {
                    return Err(refused());
                };
                if result.transfer_id.as_str() != transfer
                    || result.next_offset.get() != 0
                    || result.maximum_chunk_bytes.get() == 0
                {
                    return Err(refused());
                }
                maximum_chunk = result.maximum_chunk_bytes.get();
            } else if index + 1 == originals.len() {
                if original.method != Method::BlobFinish
                    || original.body.len() != 2
                    || offset != bytes.len()
                {
                    return Err(refused());
                }
                let Some(MethodResult::BlobFinish(result)) = &response.result else {
                    return Err(refused());
                };
                if result.transfer_id.as_str() != transfer || result.content != *reference {
                    return Err(refused());
                }
            } else {
                if original.method != Method::BlobChunk || original.body.len() != 4 {
                    return Err(refused());
                }
                let body = borrowed_field(sent.canonical_body(), "body")?;
                if borrowed_u64_field(body, "offset")?
                    != u64::try_from(offset).map_err(|_| refused())?
                {
                    return Err(refused());
                }
                let encoded = original
                    .body
                    .get("bytes")
                    .and_then(serde_json::Value::as_str)
                    .ok_or_else(refused)?;
                let length = decoded_length(encoded)?;
                if length == 0 || u64::try_from(length).map_err(|_| refused())? > maximum_chunk {
                    return Err(refused());
                }
                let end = offset
                    .checked_add(length)
                    .filter(|n| *n <= bytes.len())
                    .ok_or_else(refused)?;
                authenticate_base64(encoded, &bytes[offset..end])?;
                offset = end;
                let Some(MethodResult::BlobChunk(result)) = &response.result else {
                    return Err(refused());
                };
                if result.transfer_id.as_str() != transfer
                    || result.next_offset.get() != u64::try_from(offset).map_err(|_| refused())?
                {
                    return Err(refused());
                }
            }
            let mut found = None;
            for (slot, frame) in bank.frames().enumerate().skip(commit_slot + 1) {
                if frame.direction == FrameDirection::Incoming
                    && literal_sequence(frame.bytes)? == reply.envelope.sequence
                {
                    if found.is_some() {
                        return Err(refused());
                    }
                    complete_literal(&frame)?;
                    correspondence::envelope(&reply.envelope, &frame.bytes[4..])?;
                    found = Some(slot);
                }
            }
            if found.is_none() {
                return Err(refused());
            }
        }
        let result = Self {
            actor: Rc::clone(&connection.protocol_owner),
            bank: Rc::clone(bank_owner),
            prefix_slots,
            prefix_digest: prefix_digest(&bank, prefix_slots)?,
            commit_sequence: commit.sequence,
            next_received: commit
                .sequence
                .get()
                .checked_add(1)
                .and_then(|n| n.checked_add(u64::try_from(replies.len()).ok()?))
                .ok_or_else(refused)?,
            next_sent: originals
                .last()
                .ok_or_else(refused)?
                .sequence
                .get()
                .checked_add(1)
                .ok_or_else(refused)?,
        };
        connection
            .guard
            .original_restore_response_after_proof_sequence(commit, &result)?;
        Ok(result)
    }

    pub(crate) fn counter_boundary(&self, request: &Envelope) -> Result<(u64, u64), ProviderError> {
        if request.sequence != self.commit_sequence {
            return Err(refused());
        }
        Ok((self.next_received, self.next_sent))
    }

    pub(super) fn authenticate_retained<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        request: &Envelope,
    ) -> Result<(), ProviderError> {
        self.actor.ensure_current()?;
        connection.authenticate_native5_source_codec()?;
        if !Rc::ptr_eq(&self.actor, &connection.protocol_owner)
            || connection
                .original_frames
                .as_ref()
                .is_none_or(|bank| !Rc::ptr_eq(bank, &self.bank))
        {
            return Err(refused());
        }
        self.counter_boundary(request)?;
        let bank = self.bank.try_borrow().map_err(|_| borrowed())?;
        let count = bank.frames().count();
        if count < self.prefix_slots
            || count > self.prefix_slots.checked_add(1).ok_or_else(refused)?
            || prefix_digest(&bank, self.prefix_slots)? != self.prefix_digest
        {
            return Err(refused());
        }
        if count != self.prefix_slots {
            let frame = bank.frame(self.prefix_slots).ok_or_else(refused)?;
            if frame.direction != FrameDirection::Outgoing
                || !frame.bytes.is_empty()
                || frame.transferred != 0
                || frame.complete
            {
                return Err(refused());
            }
        }
        Ok(())
    }
}

fn complete_literal(
    frame: &crate::transport::original_frames::OriginalFrame<'_>,
) -> Result<(), ProviderError> {
    if !frame.complete || frame.transferred != frame.bytes.len() || frame.bytes.len() < 4 {
        return Err(refused());
    }
    let header: [u8; 4] = frame.bytes[..4].try_into().map_err(|_| refused())?;
    if usize::try_from(u32::from_be_bytes(header)).map_err(|_| refused())? != frame.bytes.len() - 4
    {
        return Err(refused());
    }
    Ok(())
}

fn literal_sequence(bytes: &[u8]) -> Result<U64, ProviderError> {
    Ok(U64::new(borrowed_u64_field(
        bytes.get(4..).ok_or_else(refused)?,
        "sequence",
    )?))
}

/// Compares exact ordinary CNP blob framing without allocating a HashRef clone.
pub(super) fn authenticate_content_bytes(
    reference: &ContentRef,
    bytes: &[u8],
) -> Result<(), ProviderError> {
    reference.validate()?;
    let length = u64::try_from(bytes.len()).map_err(|_| refused())?;
    if reference.length.get() != length {
        return Err(refused());
    }
    let domain = b"cnp.blob.v1";
    let mut hash = blake3::Hasher::new();
    hash.update(b"CNP/1\0");
    hash.update(
        &u32::try_from(domain.len())
            .map_err(|_| refused())?
            .to_be_bytes(),
    );
    hash.update(domain);
    hash.update(&length.to_be_bytes());
    hash.update(bytes);
    let digest = hash.finalize().to_hex();
    if reference.hash.digest.as_bytes() != digest.as_bytes() {
        return Err(refused());
    }
    Ok(())
}

/// Scans a bounded borrowed object without assuming the requested key is first.
pub(super) fn borrowed_field<'a>(input: &'a [u8], name: &str) -> Result<&'a [u8], ProviderError> {
    let mut fields = Fields::object(input)?;
    let mut result = None;
    let mut count = 0usize;
    while let Some((key, value)) = fields.pair()? {
        count = count
            .checked_add(1)
            .filter(|n| *n <= 64)
            .ok_or_else(refused)?;
        if plain_string(key)? == name {
            if result.replace(value).is_some() {
                return Err(refused());
            }
        }
    }
    fields.finish()?;
    result.ok_or_else(refused)
}

/// Reads the CNP U64 string representation after the complete field scan.
/// Numeric JSON tokens, escaped digits and noncanonical decimal strings refuse.
pub(super) fn borrowed_u64_field(input: &[u8], name: &str) -> Result<u64, ProviderError> {
    unsigned(plain_string(borrowed_field(input, name)?)?.as_bytes())
}

pub(super) fn decoded_length(encoded: &str) -> Result<usize, ProviderError> {
    let remainder = encoded.len() % 4;
    if remainder == 1 {
        return Err(refused());
    }
    (encoded.len() / 4)
        .checked_mul(3)
        .and_then(|n| {
            n.checked_add(match remainder {
                2 => 1,
                3 => 2,
                _ => 0,
            })
        })
        .ok_or_else(refused)
}

pub(super) fn authenticate_base64(encoded: &str, bytes: &[u8]) -> Result<(), ProviderError> {
    use base64::Engine;
    let mut position = 0usize;
    for chunk in bytes.chunks(3) {
        let mut buffer = [0u8; 4];
        let count = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode_slice(chunk, &mut buffer)
            .map_err(|_| refused())?;
        let end = position.checked_add(count).ok_or_else(refused)?;
        if encoded.as_bytes().get(position..end) != Some(&buffer[..count]) {
            return Err(refused());
        }
        position = end;
    }
    if position != encoded.len() {
        return Err(refused());
    }
    Ok(())
}

fn prefix_digest(
    bank: &OriginalFrameReservation,
    count: usize,
) -> Result<blake3::Hash, ProviderError> {
    let mut hash =
        blake3::Hasher::new_derive_key("source-private.complete-restore-held-proof-literals/12");
    for index in 0..count {
        let frame = bank.frame(index).ok_or_else(refused)?;
        complete_literal(&frame)?;
        hash.update(&[match frame.direction {
            FrameDirection::Incoming => 0,
            FrameDirection::Outgoing => 1,
        }]);
        hash.update(
            &u64::try_from(frame.bytes.len())
                .map_err(|_| refused())?
                .to_le_bytes(),
        );
        hash.update(frame.bytes);
    }
    Ok(hash.finalize())
}

fn refused() -> ProviderError {
    ProviderError::Correlation("completed held proof original suffix differs")
}
fn borrowed() -> ProviderError {
    ProviderError::Conflict("completed held proof literal bank borrowed")
}

#[cfg(test)]
// crucible-lint: allow panic-shortcut -- These data-only controls panic on failed invariants.
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    fn complete_incoming(bank: &mut OriginalFrameReservation, payload: &[u8]) -> usize {
        let slot = bank
            .begin(FrameDirection::Incoming, payload.len() + 4)
            .unwrap();
        let length = u32::try_from(payload.len()).unwrap();
        bank.append(slot, &length.to_be_bytes()).unwrap();
        bank.append(slot, payload).unwrap();
        bank.finish(slot).unwrap();
        slot
    }

    #[test]
    fn held_proof_content_comparison_uses_exact_cnp_blob_domain_and_length() {
        let body = b"same retained held bytes";
        let mut root = canonical::content_ref(body, "application/json").unwrap();
        authenticate_content_bytes(&root, body).unwrap();
        assert!(authenticate_content_bytes(&root, b"changed held bytes").is_err());
        root.length = U64::new(root.length.get() + 1);
        assert!(authenticate_content_bytes(&root, body).is_err());
        root.length = U64::new(u64::try_from(body.len()).unwrap());
        root.hash.domain = "foreign-domain".into();
        assert!(authenticate_content_bytes(&root, body).is_err());
    }

    #[test]
    fn held_proof_field_scan_handles_later_keys_and_refuses_duplicates() {
        let object = br#"{"body":{},"method":"begin","sequence":"18446744073709551615"}"#;
        assert_eq!(borrowed_u64_field(object, "sequence").unwrap(), u64::MAX);
        let chunk = br#"{"bytes":"AA","extensions":{},"offset":"7","transfer_id":"t"}"#;
        assert_eq!(borrowed_u64_field(chunk, "offset").unwrap(), 7);
        assert!(borrowed_field(br#"{"sequence":"2","sequence":"3"}"#, "sequence").is_err());
        assert!(borrowed_field(br#"{"body":{}}"#, "sequence").is_err());
        for invalid in [
            &br#"{"body":{},"sequence":7}"#[..],
            &br#"{"body":{},"sequence":"07"}"#[..],
            &br#"{"body":{},"sequence":"18446744073709551616"}"#[..],
            &br#"{"body":{},"sequence":"\u0037"}"#[..],
        ] {
            assert!(borrowed_u64_field(invalid, "sequence").is_err());
        }

        let mut bank = OriginalFrameReservation::reserve(256, 4).unwrap();
        let slot = complete_incoming(&mut bank, object);
        assert_eq!(
            literal_sequence(bank.frame(slot).unwrap().bytes).unwrap(),
            U64::new(u64::MAX)
        );
        let invalid = complete_incoming(&mut bank, br#"{"body":{},"sequence":7}"#);
        assert!(literal_sequence(bank.frame(invalid).unwrap().bytes).is_err());
    }

    #[test]
    fn held_proof_base64_checks_exact_bytes_and_canonical_tail_bits() {
        for (text, bytes) in [
            ("AA", &[0][..]),
            ("AAE", &[0, 1][..]),
            ("AAEC", &[0, 1, 2][..]),
        ] {
            assert_eq!(decoded_length(text).unwrap(), bytes.len());
            authenticate_base64(text, bytes).unwrap();
        }
        assert!(authenticate_base64("AB", &[0]).is_err());
        assert!(authenticate_base64("AAF", &[0, 1]).is_err());
        assert!(authenticate_base64("AAEC", &[0, 1, 3]).is_err());
        assert!(authenticate_base64("AA==", &[0]).is_err());
        assert!(decoded_length("A").is_err());
    }

    #[test]
    fn held_proof_prefix_preserves_old_bytes_when_response_slot_is_reserved() {
        let mut bank = OriginalFrameReservation::reserve(256, 4).unwrap();
        let old_slot = complete_incoming(&mut bank, br#"{"sequence":"2"}"#);
        let old_bytes = bank.frame(old_slot).unwrap().bytes.to_vec();
        let digest = prefix_digest(&bank, 1).unwrap();

        let response = bank.begin(FrameDirection::Outgoing, 128).unwrap();

        assert_eq!(response, 1);
        assert_eq!(prefix_digest(&bank, 1).unwrap(), digest);
        assert_eq!(bank.frame(old_slot).unwrap().bytes, old_bytes);
        assert!(prefix_digest(&bank, 2).is_err());
    }

    #[test]
    fn held_proof_prefix_refuses_partial_progress_and_wrong_header_extent() {
        let mut bank = OriginalFrameReservation::reserve(256, 4).unwrap();
        let slot = bank.begin(FrameDirection::Incoming, 32).unwrap();
        bank.append(slot, &16u32.to_be_bytes()).unwrap();
        bank.append(slot, b"{}").unwrap();
        assert!(prefix_digest(&bank, 1).is_err());

        bank.finish(slot).unwrap();
        assert!(prefix_digest(&bank, 1).is_err());

        let mut outgoing = OriginalFrameReservation::reserve(256, 4).unwrap();
        let slot = outgoing.begin(FrameDirection::Outgoing, 6).unwrap();
        outgoing.append(slot, &2u32.to_be_bytes()).unwrap();
        outgoing.append(slot, b"{}").unwrap();
        outgoing.advance(slot, 5).unwrap();
        assert!(outgoing.finish(slot).is_err());
        assert!(prefix_digest(&outgoing, 1).is_err());
    }

    #[test]
    fn completed_proof_does_not_weaken_generic_latest_restore_guard() {
        use crate::envelope::{Nullable, tests::request};
        use std::collections::BTreeSet;

        let mut guard = CorrelationGuard::new(
            Id::new("session-1").unwrap(),
            Id::new("provider-1").unwrap(),
            2,
            BTreeSet::new(),
        )
        .unwrap();
        let mut commit = request();
        commit.sequence = U64::new(2);
        commit.method = Method::Begin;
        commit.body.insert(
            "kind".into(),
            serde_json::Value::String("prepare_restore".into()),
        );
        guard.receive(&commit).unwrap();
        guard
            .authenticate_incoming_complete_restore(&commit)
            .unwrap();

        let mut proof = request();
        proof.sequence = U64::new(2);
        proof.method = Method::BlobFinish;
        proof.request_id = Nullable(Some(Id::new("held-proof-finish").unwrap()));
        guard.register_request(proof.clone()).unwrap();
        proof.message = MessageKind::Response;
        proof.sequence = U64::new(3);
        guard.receive(&proof).unwrap();

        assert!(
            guard
                .authenticate_incoming_complete_restore(&commit)
                .is_err()
        );
        assert_eq!(guard.incoming_requests().count(), 1);
        assert_eq!(guard.pending_requests().count(), 0);
    }
}

#[path = "restore_held_proof/settled.rs"]
mod settled_history;
