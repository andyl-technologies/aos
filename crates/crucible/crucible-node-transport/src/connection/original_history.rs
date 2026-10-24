//! Lends actual original literal history without copying or granting authority.

use super::*;
use crate::transport::original_frames::{FrameDirection, OriginalFrame, OriginalFrameReservation};
use serde_json::Value;
use std::cell::Ref;

/// Borrows the same original native-five literal bank under its surviving actor.
///
/// The held borrow prevents bank mutation until this view is released. It grants
/// no source admission, new physical cut, fresh registration or replay rights.
pub struct OriginalNative5FrameHistory<'a> {
    actor: &'a crate::protocol_snapshot::ProtocolCaptureOwner,
    authority: &'a ConnectionAuthority,
    original: Ref<'a, OriginalFrameReservation>,
}

impl OriginalNative5FrameHistory<'_> {
    /// Authenticates the exact typed original at one explicit literal position.
    ///
    /// This source-class check uses the actual canonical writer representation;
    /// generic whitespace-tolerant transport inputs gain no canonical-source
    /// correspondence. Callers retain their transcript cursor and check every
    /// slot, so this method grants neither cursor advance nor uniqueness itself.
    ///
    /// # Errors
    /// Refuses a stale actor, wrong direction/index, partial header/body/progress
    /// or any full-envelope mismatch. It allocates no DOM or encoded buffer.
    pub fn authenticate_original_envelope(
        &self,
        original: &Envelope,
        direction: crate::transport::original_frames::FrameDirection,
        literal_index: usize,
    ) -> Result<(), ProviderError> {
        self.actor.ensure_current()?;
        self.authority.ensure_live()?;
        authenticate_original_frame_data(&self.original, original, direction, literal_index)
    }

    /// References one unique complete canonical incoming original without copying.
    ///
    /// This checks literal correspondence only. A caller that needs a completed
    /// transaction must separately authenticate its actual pair and receipt.
    /// It creates the same ordinary ContentRef as the canonical body constructor;
    /// no response Value, encoded bank or native authorization is produced.
    ///
    /// # Errors
    /// Refuses stale live owners, absent or repeated matching originals, wrong
    /// direction, incomplete progress, malformed headers or noncanonical bodies.
    pub fn original_canonical_reference_data(
        &self,
        original: &Envelope,
    ) -> Result<crucible_node_format::ContentRef, ProviderError> {
        self.actor.ensure_current()?;
        self.authority.ensure_live()?;
        let reference = unique_original_reference_data(&self.original, original)?;
        self.actor.ensure_current()?;
        self.authority.ensure_live()?;
        Ok(reference)
    }

    /// Names the explicit immutable-history, canonical comparison and hash views.
    ///
    /// The resulting ContentRef backing is a separate caller-owned constructor
    /// obligation. This getter creates no bank, parser, reference or permission.
    pub fn original_canonical_reference_counter_scratch_data() -> usize {
        use std::mem::size_of;
        crate::protocol_snapshot::owned11::correspondence::envelope_comparison_scratch_data()
            + crate::protocol_snapshot::owned11::correspondence::envelope_counter_scratch_data()
            + size_of::<Self>()
            + size_of::<&Self>()
            + size_of::<Result<Self, ProviderError>>()
            + size_of::<Ref<'static, OriginalFrameReservation>>()
            + size_of::<Result<Ref<'static, OriginalFrameReservation>, std::cell::BorrowError>>()
            + size_of::<Result<Ref<'static, OriginalFrameReservation>, ProviderError>>()
            + size_of::<&OriginalFrameReservation>()
            + size_of::<&Envelope>()
            + size_of::<OriginalFrame<'static>>()
            + size_of::<Option<OriginalFrame<'static>>>()
            + size_of::<FrameDirection>()
            + size_of::<Option<&'static [u8]>>()
            + size_of::<Result<&'static [u8], ProviderError>>()
            + size_of::<crucible_node_format::ContentRef>()
            + size_of::<Result<crucible_node_format::ContentRef, ProviderError>>()
            + size_of::<Result<crucible_node_format::ContentRef, crucible_node_format::ContractError>>()
            + size_of::<crucible_node_format::HashRef>()
            + size_of::<Result<crucible_node_format::HashRef, crucible_node_format::ContractError>>()
            + size_of::<crucible_node_format::U64>()
            + size_of::<blake3::Hasher>()
            + size_of::<blake3::Hash>()
            // Pinned ArrayString<64> hex payload/length and domain-length scalar.
            + size_of::<[u8; 64]>()
            + 2 * size_of::<u32>()
            + size_of::<[u8; 8]>()
            + size_of::<String>()
            + size_of::<&str>()
            + size_of::<&[u8]>()
            + size_of::<Result<u32, std::num::TryFromIntError>>()
            + size_of::<Result<u64, std::num::TryFromIntError>>()
            + size_of::<[u8; 4]>()
            + size_of::<Result<[u8; 4], std::array::TryFromSliceError>>()
            + size_of::<usize>()
            + size_of::<Option<usize>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
            + crate::transport::original_frames::original_history_guard_counter_scratch_data()
    }

    /// Borrows all actual framed originals with their exact progress and identities.
    ///
    /// # Errors
    /// Refuses a foreign process/thread or revoked original registration before
    /// returning any byte loan. Source guards must also bracket journal effects.
    pub fn frames(&self) -> Result<impl Iterator<Item = OriginalFrame<'_>>, ProviderError> {
        self.actor.ensure_current()?;
        self.authority.ensure_live()?;
        Ok(self.original.frames())
    }
}

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn original_native5_frame_history(
        &self,
    ) -> Result<OriginalNative5FrameHistory<'_>, ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        self.authority.ensure_live()?;
        if self.fenced {
            return Err(ProviderError::Correlation(
                "original history connection fenced",
            ));
        }
        self.guard
            .protocol_cut(crate::protocol_snapshot::ProtocolCaptureCut::HostSettled)?;
        let bank = self
            .original_frames
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "original native frame bank absent",
            ))?;
        let original = bank
            .try_borrow()
            .map_err(|_| ProviderError::Conflict("original native frame bank borrowed"))?;
        if !original.complete() {
            return Err(ProviderError::Correlation(
                "original literal history incomplete",
            ));
        }
        Ok(OriginalNative5FrameHistory {
            actor: &self.protocol_owner,
            authority: &self.authority,
            original,
        })
    }
}

impl<S: ProviderStream> Connection<S> {
    // A selected Host prefix must prove raw/canonical correspondence before
    // using its closed successful literal extent. The full raw/error phase is
    // unchanged, and the exact reader-owned bank retains any refusal.
    pub(crate) fn authenticate_current_restore_prefix_literal(
        &self,
        envelope: &Envelope,
    ) -> Result<(), ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        self.authority.ensure_live()?;
        if self.fenced || self.role != EndpointRole::Controller {
            return Err(ProviderError::Correlation(
                "selected restore Host prefix actor differs",
            ));
        }
        let slot = self
            .reader
            .original_slot()
            .ok_or(ProviderError::Correlation(
                "selected restore prefix literal absent",
            ))?;
        let bank = self
            .original_frames
            .as_ref()
            .ok_or(ProviderError::Correlation(
                "selected restore prefix original bank absent",
            ))?
            .try_borrow()
            .map_err(|_| {
                ProviderError::Conflict("selected restore prefix original bank borrowed")
            })?;
        let frame = bank.frame(slot).ok_or(ProviderError::Correlation(
            "selected restore prefix frame absent",
        ))?;
        if frame.direction != crate::transport::original_frames::FrameDirection::Incoming
            || !frame.complete
            || frame.transferred != frame.bytes.len()
            || frame.bytes.len() < 4
        {
            return Err(ProviderError::Correlation(
                "selected restore prefix literal incomplete",
            ));
        }
        let header: [u8; 4] = frame.bytes[..4]
            .try_into()
            .map_err(|_| ProviderError::Frame("selected restore prefix header absent"))?;
        if usize::try_from(u32::from_be_bytes(header)).ok() != Some(frame.bytes.len() - 4) {
            return Err(ProviderError::Frame(
                "selected restore prefix header differs",
            ));
        }
        crate::protocol_snapshot::owned11::correspondence::envelope(envelope, &frame.bytes[4..])
    }
}

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn receive_original_restore_transfer_prefix(
        &mut self,
        original: &Envelope,
        phase: crate::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreTransferPhase,
    ) -> Result<Option<ReceivedFrame>, ProviderError> {
        use crate::reference_packet::service::{
            complete_restore::PacketNative5CompleteRestoreSelection,
            fresh_restore_allocation::PacketNative5FreshRestoreAllocationSelection,
        };
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        if self.role != EndpointRole::Controller
            || self.original_native5_complete_restore_selection()?
                != Some(PacketNative5CompleteRestoreSelection::SourceSignedTransfer12)
            || self
                .native5_codec
                .as_deref()
                .ok_or(ProviderError::Correlation(
                    "selected restore prefix codec absent",
                ))?
                .fresh_restore_selection_data(&self.authority)?
                != Some(PacketNative5FreshRestoreAllocationSelection::CompletedAdmit13)
            || !self
                .guard
                .pending_requests()
                .any(|pending| pending == original)
        {
            return Err(ProviderError::Correlation(
                "selected restore prefix original differs",
            ));
        }
        self.ensure_no_pending_native_restore_response()?;
        self.check_authority()?;
        let result = self.receive_original_restore_transfer_prefix_inner(original, phase);
        match &result {
            Ok(None) => self.contain(ConnectionFailure::Read),
            Err(_) => self.contain(ConnectionFailure::Protocol),
            _ => {}
        }
        result
    }

    fn receive_original_restore_transfer_prefix_inner(
        &mut self,
        original: &Envelope,
        phase: crate::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreTransferPhase,
    ) -> Result<Option<ReceivedFrame>, ProviderError> {
        let Some(value) = self.reader.read()? else {
            return Ok(None);
        };
        let envelope: Envelope =
            serde_json::from_value(value).map_err(crucible_node_format::ContractError::from)?;
        let chunk = usize::try_from(self.authority.limits().blob_chunk_bytes.get())
            .map_err(|_| ProviderError::ResourceExhausted("selected restore chunk platform bound"))?
            .min(4096);
        authenticate_restore_prefix_header_data(original, phase, chunk, &envelope)?;
        if envelope.message == MessageKind::Request {
            self.authenticate_current_restore_prefix_literal(&envelope)?;
        }
        // Only the closed Blob request scalar grammar reaches typed decoding.
        // Error responses keep the ordinary complete generic raw/DOM work bound.
        let body = self.validate_body(&envelope, true)?;
        self.retain_original_request_id(&envelope, self.reader.original_slot())?;
        self.authority.with_live(|| self.guard.receive(&envelope))?;
        Ok(Some(ReceivedFrame { envelope, body }))
    }
}

fn authenticate_restore_prefix_header_data(
    original: &Envelope,
    phase: crate::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreTransferPhase,
    chunk: usize,
    envelope: &Envelope,
) -> Result<(), ProviderError> {
    use crate::reference_packet::service::complete_restore::transfer::PacketCompleteRestoreTransferPhase;
    let refused = || ProviderError::Correlation("selected restore pretyped prefix shape differs");
    if envelope.message == MessageKind::Response {
        return original.matches_response(envelope);
    }
    if envelope.message != MessageKind::Request
        || phase != PacketCompleteRestoreTransferPhase::Commit
        || chunk == 0
        || envelope.protocol != original.protocol
        || envelope.session_id != original.session_id
        || envelope.incarnation_id != original.incarnation_id
        || envelope.node_id.0.is_some()
        || envelope.execution_owner_id.0.is_some()
        || envelope.capture_owner_id.0.is_some()
        || envelope.operation_id.0.is_some()
        || !envelope.extensions.is_empty()
    {
        return Err(refused());
    }
    let body = &envelope.body;
    let fields: &[&str] = match envelope.method {
        Method::BlobBegin => &["transfer_id", "content", "extensions"],
        Method::BlobChunk => &["transfer_id", "offset", "bytes", "extensions"],
        Method::BlobFinish => &["transfer_id", "extensions"],
        _ => return Err(refused()),
    };
    if body.len() != fields.len()
        || fields.iter().any(|key| !body.contains_key(*key))
        || !matches!(body.get("extensions"),Some(Value::Object(value)) if value.is_empty())
        || body
            .get("transfer_id")
            .and_then(Value::as_str)
            .is_none_or(|id| id.is_empty() || id.len() > 128)
        || envelope
            .request_id
            .0
            .as_ref()
            .is_none_or(|id| id.as_str().len() > 128)
    {
        return Err(refused());
    }
    match envelope.method {
        Method::BlobBegin => {
            let content = body
                .get("content")
                .and_then(Value::as_object)
                .ok_or_else(refused)?;
            let hash = content
                .get("hash")
                .and_then(Value::as_object)
                .ok_or_else(refused)?;
            if content.len() != 3
                || hash.len() != 3
                || content
                    .get("length")
                    .and_then(Value::as_str)
                    .is_none_or(|s| s.is_empty() || s.len() > 20)
                || content.get("media_type").and_then(Value::as_str) != Some("application/json")
                || hash.get("algorithm").and_then(Value::as_str) != Some("blake3-256")
                || hash.get("domain").and_then(Value::as_str) != Some("cnp.blob.v1")
                || hash
                    .get("digest")
                    .and_then(Value::as_str)
                    .is_none_or(|s| s.len() != 64)
            {
                return Err(refused());
            }
        }
        Method::BlobChunk => {
            let encoded = chunk.div_ceil(3).checked_mul(4).ok_or_else(refused)?;
            if body
                .get("offset")
                .and_then(Value::as_str)
                .is_none_or(|s| s.is_empty() || s.len() > 20)
                || body
                    .get("bytes")
                    .and_then(Value::as_str)
                    .is_none_or(|s| s.is_empty() || s.len() > encoded)
            {
                return Err(refused());
            }
        }
        Method::BlobFinish => {}
        _ => return Err(refused()),
    }
    Ok(())
}

#[cfg(test)]
#[path = "restore_prefix_header_tests.rs"]
mod restore_prefix_header_tests;

fn authenticate_original_frame_data(
    bank: &OriginalFrameReservation,
    original: &Envelope,
    direction: FrameDirection,
    literal_index: usize,
) -> Result<(), ProviderError> {
    let frame = bank.frame(literal_index).ok_or(ProviderError::Correlation(
        "original literal position absent",
    ))?;
    if frame.direction != direction
        || !frame.complete
        || frame.transferred != frame.bytes.len()
        || frame.bytes.len() < 4
    {
        return Err(ProviderError::Correlation(
            "original literal direction/progress differs",
        ));
    }
    let header: [u8; 4] = frame.bytes[..4]
        .try_into()
        .map_err(|_| ProviderError::Correlation("original literal header absent"))?;
    if usize::try_from(u32::from_be_bytes(header)).ok() != Some(frame.bytes.len() - 4) {
        return Err(ProviderError::Correlation(
            "original literal header differs",
        ));
    }
    crate::protocol_snapshot::owned11::correspondence::envelope(original, &frame.bytes[4..])
}

fn unique_original_reference_data(
    bank: &OriginalFrameReservation,
    original: &Envelope,
) -> Result<crucible_node_format::ContentRef, ProviderError> {
    if !bank.complete() {
        return Err(ProviderError::Correlation(
            "canonical original history incomplete",
        ));
    }
    let mut selected = None;
    let mut index = 0usize;
    while let Some(frame) = bank.frame(index) {
        if frame.direction == FrameDirection::Incoming
            && authenticate_original_frame_data(bank, original, FrameDirection::Incoming, index)
                .is_ok()
        {
            if selected.is_some() {
                return Err(ProviderError::Correlation(
                    "canonical original response repeated",
                ));
            }
            selected = Some(frame.bytes.get(4..).ok_or(ProviderError::Correlation(
                "canonical original response header absent",
            ))?);
        }
        index = index
            .checked_add(1)
            .ok_or(ProviderError::ResourceExhausted(
                "canonical original response cursor",
            ))?;
    }
    let selected = selected.ok_or(ProviderError::Correlation(
        "canonical original response absent",
    ))?;
    crucible_node_format::canonical::content_ref(selected, "application/json")
        .map_err(ProviderError::from)
}

#[cfg(test)]
mod canonical_reference_tests {
    use super::*;
    use crucible_node_format::canonical;

    // These are literal-bank DATA fixtures. They construct no live actor,
    // completed transaction, Source receipt, scope or native permission.
    fn original() -> Envelope {
        let mut original = crate::envelope::tests::request();
        original.message = crate::envelope::MessageKind::Response;
        original.body.insert(
            "canonical-nested-data".into(),
            serde_json::json!({"empty": {}, "nested": [[], {"text": "quoted\"value"}]}),
        );
        original
    }

    fn canonical_body(original: &Envelope) -> Vec<u8> {
        let value = serde_json::to_value(original).unwrap();
        canonical::canonical_json(&value).unwrap()
    }

    fn append(
        bank: &mut OriginalFrameReservation,
        direction: FrameDirection,
        body: &[u8],
        finish: bool,
        header_adjustment: u32,
    ) {
        let length = u32::try_from(body.len()).unwrap() + header_adjustment;
        let slot = bank.begin(direction, body.len() + 4).unwrap();
        bank.append(slot, &length.to_be_bytes()).unwrap();
        bank.append(slot, body).unwrap();
        if direction == FrameDirection::Outgoing {
            bank.advance(slot, body.len() + 4).unwrap();
        }
        if finish {
            bank.finish(slot).unwrap();
        }
    }

    fn snapshot(bank: &OriginalFrameReservation) -> Vec<u8> {
        serde_json::to_vec(&bank.protocol_view()).unwrap()
    }

    #[test]
    fn unique_canonical_incoming_reference_matches_the_real_content_constructor() {
        let original = original();
        let body = canonical_body(&original);
        let mut bank = OriginalFrameReservation::reserve(65536, 8).unwrap();
        append(&mut bank, FrameDirection::Outgoing, &body, true, 0);
        append(&mut bank, FrameDirection::Incoming, &body, true, 0);
        let before = snapshot(&bank);

        assert_eq!(
            unique_original_reference_data(&bank, &original).unwrap(),
            canonical::content_ref(&body, "application/json").unwrap()
        );
        assert_eq!(snapshot(&bank), before);
    }

    #[test]
    fn missing_direction_progress_header_and_full_body_cannot_supply_a_reference() {
        let original = original();
        let body = canonical_body(&original);
        let mut different = original.clone();
        different.sequence = crucible_node_format::U64::new(original.sequence.get() + 1);
        let different = canonical_body(&different);
        let noncanonical = String::from_utf8(body.clone()).unwrap().replace(':', ": ");

        let cases = [
            (FrameDirection::Outgoing, body.as_slice(), true, 0),
            (FrameDirection::Incoming, body.as_slice(), false, 0),
            (FrameDirection::Incoming, body.as_slice(), true, 1),
            (FrameDirection::Incoming, different.as_slice(), true, 0),
            (FrameDirection::Incoming, noncanonical.as_bytes(), true, 0),
        ];
        let empty = OriginalFrameReservation::reserve(65536, 8).unwrap();
        assert!(unique_original_reference_data(&empty, &original).is_err());

        for (direction, bytes, complete, header_adjustment) in cases {
            let mut bank = OriginalFrameReservation::reserve(65536, 8).unwrap();
            append(&mut bank, direction, bytes, complete, header_adjustment);
            let before = snapshot(&bank);

            assert!(unique_original_reference_data(&bank, &original).is_err());
            assert_eq!(snapshot(&bank), before);
        }
    }

    #[test]
    fn a_repeated_matching_incoming_original_refuses_without_changing_the_bank() {
        let original = original();
        let body = canonical_body(&original);
        let mut bank = OriginalFrameReservation::reserve(65536, 8).unwrap();
        append(&mut bank, FrameDirection::Incoming, &body, true, 0);
        append(&mut bank, FrameDirection::Incoming, &body, true, 0);
        let before = snapshot(&bank);

        assert!(unique_original_reference_data(&bank, &original).is_err());
        assert_eq!(snapshot(&bank), before);
    }
}

mod input17_prefix;
pub use input17_prefix::{
    OriginalRestoredInput17LiteralPrefixData, OriginalRestoredInput17LiteralPrefixIdentityData,
};
