//! Lends actual original literal history without copying or granting authority.

use super::*;
use crate::transport::original_frames::{OriginalFrame, OriginalFrameReservation};
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
        let frame = self
            .original
            .frame(literal_index)
            .ok_or(ProviderError::Correlation(
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
        phase: crate::reference_packet::service::complete_restore::PacketCompleteRestoreTransferPhase,
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
        phase: crate::reference_packet::service::complete_restore::PacketCompleteRestoreTransferPhase,
    ) -> Result<Option<ReceivedFrame>, ProviderError> {
        let Some(value) = self.reader.read()? else {
            return Ok(None);
        };
        let envelope: Envelope =
            serde_json::from_value(value).map_err(crucible_node_contract::ContractError::from)?;
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
    phase: crate::reference_packet::service::complete_restore::PacketCompleteRestoreTransferPhase,
    chunk: usize,
    envelope: &Envelope,
) -> Result<(), ProviderError> {
    use crate::reference_packet::service::complete_restore::PacketCompleteRestoreTransferPhase;
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
