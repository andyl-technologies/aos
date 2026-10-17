//! Hashes the same actual controller Observe literal without reconstruction.

use super::*;
use crate::reference_packet::service::capture_allocation::NATIVE_CAPTURE_ALLOCATION_OBSERVE_DOMAIN;
use crate::transport::original_frames::FrameDirection;

impl<S: ProviderStream> Connection<S> {
    pub(crate) fn original_capture_allocation_observe_hash_data(
        &self,
        original: &Envelope,
    ) -> Result<[u8; 32], ProviderError> {
        self.protocol_owner.ensure_current()?;
        self.authenticate_native5_source_codec()?;
        if self.fenced
            || self.role != EndpointRole::Controller
            || original.message != MessageKind::Request
            || original.method != Method::Observe
        {
            return Err(refused());
        }
        let id = original.request_id.0.as_ref().ok_or_else(refused)?;
        let bank = self
            .original_frames
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow()
            .map_err(|_| refused())?;
        let frame = bank.original_outgoing_request_frame_data(id)?;
        if frame.direction != FrameDirection::Outgoing
            || !frame.complete
            || frame.transferred != frame.bytes.len()
            || frame.bytes.len() < 4
        {
            return Err(refused());
        }
        let body = &frame.bytes[4..];
        let header: [u8; 4] = frame.bytes[..4].try_into().map_err(|_| refused())?;
        if usize::try_from(u32::from_be_bytes(header)).ok() != Some(body.len()) {
            return Err(refused());
        }
        crate::protocol_snapshot::owned11::correspondence::envelope(original, body)?;
        let domain = NATIVE_CAPTURE_ALLOCATION_OBSERVE_DOMAIN;
        let mut hash = blake3::Hasher::new();
        hash.update(b"CNP/1\0");
        hash.update(
            &u32::try_from(domain.len())
                .map_err(|_| refused())?
                .to_be_bytes(),
        );
        hash.update(domain.as_bytes());
        hash.update(
            &u64::try_from(body.len())
                .map_err(|_| refused())?
                .to_be_bytes(),
        );
        hash.update(body);
        self.authority.ensure_live()?;
        self.protocol_owner.ensure_current()?;
        Ok(*hash.finalize().as_bytes())
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("original capture allocation Observe literal")
}
