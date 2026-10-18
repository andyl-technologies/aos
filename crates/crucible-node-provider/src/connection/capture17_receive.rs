//! Receives closed Capture17 originals beneath actual prepaid native custody.
//!
//! The normal reader, selected codec and correlation guard remain authoritative
//! for their respective transport checks. Raw native custody precedes every
//! independently returning typed policy result and correlation mutation.

use super::*;
use crate::reference_packet::service::ack_emitter::OriginalNativeCapture17Read;

impl<S: ProviderStream> Connection<S> {
    /// Receives the single original belonging to the genuine native occurrence.
    ///
    /// # Errors
    /// Refuses foreign/stale admission, unsupported traffic, invalid policy or
    /// sequence/custody disagreement. Existing incidents retain partial frames.
    pub(crate) fn receive_original_capture17_data(
        &mut self,
        scope: &OriginalNativeCapture17Read,
    ) -> Result<bool, ProviderError> {
        scope.begin_receive_data(self)?;
        self.ensure_no_pending_native_restore_response()?;
        self.check_authority()?;
        if self.role != EndpointRole::Provider {
            return Err(refused());
        }
        self.guard
            .protocol_cut(crate::protocol_snapshot::ProtocolCaptureCut::HostSettled)?;
        let result = self.receive_original_capture17_inner(scope);
        match &result {
            Ok(false) => self.contain(ConnectionFailure::Read),
            Err(_) => self.contain(ConnectionFailure::Protocol),
            _ => {}
        }
        result
    }

    fn receive_original_capture17_inner(
        &mut self,
        scope: &OriginalNativeCapture17Read,
    ) -> Result<bool, ProviderError> {
        let Some(value) = self.reader.read()? else {
            return Ok(false);
        };
        let original: Envelope =
            serde_json::from_value(value).map_err(crucible_node_contract::ContractError::from)?;
        scope.retain_original_data(self, original)?;
        let original = scope.original_data()?;
        let ReceivedBody::Request(body) = self.validate_body(&original, true)? else {
            return Err(refused());
        };
        if !matches!(
            body.as_ref(),
            RequestBody::Begin(_)
                | RequestBody::BlobBegin(_)
                | RequestBody::BlobChunk(_)
                | RequestBody::BlobFinish(_)
                | RequestBody::Poll(_)
        ) {
            return Err(refused());
        }
        self.retain_original_request_id(&original, self.reader.original_slot())?;
        self.authority.with_live(|| self.guard.receive(&original))?;
        self.guard
            .authenticate_incoming_capture17_cut_data(&original)?;
        drop(original);
        scope.complete_receive_data(self)?;
        Ok(true)
    }

    /// Identifies the complete incoming frame owned by this exact read.
    ///
    /// # Errors
    /// Refuses missing/partial custody or changed literal correspondence.
    pub(crate) fn original_native_capture17_literal_slot_data(
        &self,
        original: &Envelope,
    ) -> Result<usize, ProviderError> {
        let slot = self.reader.original_slot().ok_or_else(refused)?;
        self.authenticate_original_native_capture17_literal_data(original, slot)?;
        Ok(slot)
    }

    /// Rejoins exact incoming bytes without constructing an admission or model.
    ///
    /// # Errors
    /// Refuses foreign/revoked admission, another method/feature, partial frame,
    /// changed framing or any complete original-field correspondence mismatch.
    pub(crate) fn authenticate_original_native_capture17_literal_data(
        &self,
        original: &Envelope,
        slot: usize,
    ) -> Result<(), ProviderError> {
        use crate::transport::original_frames::FrameDirection;
        self.original_native_owned11_admission()?
            .authenticate_current(self)?;
        if self.role != EndpointRole::Provider
            || !crate::session::is_native_capture17_original_data(original)
        {
            return Err(refused());
        }
        let bank = self
            .original_frames
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow()
            .map_err(|_| refused())?;
        let frame = bank.frame(slot).ok_or_else(refused)?;
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
        crate::protocol_snapshot::owned11::correspondence::envelope(original, &frame.bytes[4..])?;
        self.authority.ensure_live()?;
        Ok(())
    }

    /// Rechecks the sole incoming correlation without changing normal cuts.
    ///
    /// # Errors
    /// Refuses another current request, outgoing owner or failed correlation.
    pub(crate) fn authenticate_native_capture17_incoming_data(
        &self,
        original: &Envelope,
    ) -> Result<(), ProviderError> {
        self.guard
            .authenticate_incoming_capture17_cut_data(original)
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("Capture17 requires its actual prepaid native receive")
}

/// Names the independently returning decoder, raw framing and borrowed views.
pub(crate) fn native_capture17_receive_counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<&OriginalNativeCapture17Read>()
        + size_of::<Option<serde_json::Value>>()
        + size_of::<Result<Option<serde_json::Value>, ProviderError>>()
        + size_of::<Envelope>()
        + size_of::<Result<Envelope, serde_json::Error>>()
        + size_of::<ReceivedBody>()
        + size_of::<Result<ReceivedBody, ProviderError>>()
        + size_of::<Box<RequestBody>>()
        + size_of::<std::cell::Ref<'static, Envelope>>()
        + size_of::<Result<bool, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<[u8; 4]>()
        + size_of::<Result<[u8; 4], std::array::TryFromSliceError>>()
        + size_of::<Result<usize, std::num::TryFromIntError>>()
}
