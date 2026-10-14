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
