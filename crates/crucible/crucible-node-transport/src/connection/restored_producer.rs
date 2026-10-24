//! Receives a separately reserved closed Producer lifecycle without a generic fallback.
//!
//! The actual native witness spends ingress before reading. Raw and typed
//! owners remain in its sticky attempt before policy, sequence or dispatch
//! checks can fail. Existing transport incidents and containment stay intact.

use super::*;
use crate::reference_packet::control::PacketControl;
use crate::reference_packet::service::ack_emitter::OriginalRestoredProducerRead;

impl<S: ProviderStream> Connection<S> {
    /// Receives one closed Observe under its irrevocably spent native scope.
    ///
    /// # Errors
    /// Refuses malformed/unsupported traffic, policy or sequence disagreement,
    /// revoked authority and stale or conflicting native custody.
    pub(crate) fn receive_original_restored_producer_data(
        &mut self,
        scope: &OriginalRestoredProducerRead<'_>,
        control: &PacketControl,
        records: &[ExchangeRecord],
    ) -> Result<bool, ProviderError> {
        scope.begin_receive_data(self)?;
        self.ensure_no_pending_native_restore_response()?;
        self.check_authority()?;
        if self.role != EndpointRole::Provider {
            return Err(refused());
        }
        self.guard
            .protocol_cut(crate::protocol_snapshot::ProtocolCaptureCut::HostSettled)?;
        let result = self.receive_original_restored_producer_inner(scope, control, records);
        match &result {
            Ok(false) => self.contain(ConnectionFailure::Read),
            Err(_) => self.contain(ConnectionFailure::Protocol),
            _ => {}
        }
        result
    }

    fn receive_original_restored_producer_inner(
        &mut self,
        scope: &OriginalRestoredProducerRead<'_>,
        control: &PacketControl,
        records: &[ExchangeRecord],
    ) -> Result<bool, ProviderError> {
        let Some(value) = self.reader.read()? else {
            return Ok(false);
        };
        let envelope: Envelope =
            serde_json::from_value(value).map_err(crucible_node_format::ContractError::from)?;
        scope.retain_original_data(self, control, records, envelope)?;
        let original = scope.original_data()?;
        // The closed raw/body owner already retained its own typed Producer method.
        // This independent ordinary decoder preserves negotiated codec/policy
        // validation; its returning owner is part of the ingress work quote.
        let ReceivedBody::Request(body) = self.validate_body(&original, true)? else {
            return Err(refused());
        };
        if !matches!(
            body.as_ref(),
            RequestBody::Begin(_)
                | RequestBody::Poll(_)
                | RequestBody::Retire(_)
                | RequestBody::Observe(_)
                | RequestBody::BlobBegin(_)
                | RequestBody::BlobChunk(_)
                | RequestBody::BlobFinish(_)
        ) {
            return Err(refused());
        }
        self.retain_original_request_id(&original, self.reader.original_slot())?;
        self.authority.with_live(|| self.guard.receive(&original))?;
        scope.authenticate_receive_data(self)?;
        drop(original);
        scope.complete_receive_data(self)?;
        Ok(true)
    }

    /// Identifies the actual received original in the same retained native bank.
    ///
    /// # Errors
    /// Refuses absent, incomplete, foreign or canonically mismatching literals.
    pub(crate) fn original_restored_producer_literal_slot_data(
        &self,
        original: &Envelope,
    ) -> Result<usize, ProviderError> {
        let slot = self.reader.original_slot().ok_or_else(refused)?;
        self.authenticate_original_restored_producer_literal_data(original, slot)?;
        Ok(slot)
    }

    /// Checks an earlier complete incoming literal without reconstructing an owner.
    ///
    /// # Errors
    /// Refuses revoked authority, another role/method, conflicting bank custody,
    /// an incomplete frame/header or any original correspondence mismatch.
    pub(crate) fn authenticate_original_restored_producer_literal_data(
        &self,
        original: &Envelope,
        slot: usize,
    ) -> Result<(), ProviderError> {
        use crate::transport::original_frames::FrameDirection;
        self.original_native_owned11_admission()?
            .authenticate_current(self)?;
        if self.role != EndpointRole::Provider
            || !matches!(
                original.method,
                Method::Begin
                    | Method::Poll
                    | Method::Retire
                    | Method::Observe
                    | Method::BlobBegin
                    | Method::BlobChunk
                    | Method::BlobFinish
            )
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
}

fn refused() -> ProviderError {
    ProviderError::Correlation("closed Producer lifecycle requires its retained native receive")
}

/// Counts the independently returning policy decoder and raw receive views.
pub(crate) fn original_restored_producer_receive_counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<&OriginalRestoredProducerRead<'static>>()
        + size_of::<&PacketControl>()
        + size_of::<&[ExchangeRecord]>()
        + size_of::<Option<serde_json::Value>>()
        + size_of::<Result<Option<serde_json::Value>, ProviderError>>()
        + size_of::<Envelope>()
        + size_of::<Result<Envelope, serde_json::Error>>()
        + size_of::<Result<Envelope, crucible_node_format::ContractError>>()
        + size_of::<std::cell::Ref<'static, Envelope>>()
        + size_of::<Result<std::cell::Ref<'static, Envelope>, ProviderError>>()
        + size_of::<ReceivedBody>()
        + size_of::<Result<ReceivedBody, ProviderError>>()
        + size_of::<Box<RequestBody>>()
        + size_of::<&RequestBody>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<
            Result<
                std::cell::Ref<
                    'static,
                    crate::transport::original_frames::OriginalFrameReservation,
                >,
                ProviderError,
            >,
        >()
        + crate::connection::original_restoration_release_literal_counter_scratch_data()
        + size_of::<Result<bool, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
}
