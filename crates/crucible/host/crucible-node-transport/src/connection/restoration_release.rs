//! Lends actual retained native World literals under the same original actor.
//!
//! A slot is a local index, never authority. Every loan checks the current
//! admitted native connection, retained complete wire header/body and full
//! original envelope correspondence before it returns borrowed canonical bytes.

use super::*;
use crate::transport::original_frames::{FrameDirection, OriginalFrame};
use std::cell::Ref;

fn authenticate(original: &Envelope, frame: OriginalFrame<'_>) -> Result<(), ProviderError> {
    if original.method != Method::WorldActivate
        || frame.direction != FrameDirection::Incoming
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
    crate::protocol_snapshot::owned11::correspondence::envelope(original, &frame.bytes[4..])
}

fn body_at_slot(
    slot: usize,
) -> impl for<'a> FnOnce(
    &'a crate::transport::original_frames::OriginalFrameReservation,
) -> Option<&'a [u8]> {
    move |bank| bank.frame(slot).and_then(frame_body)
}

fn frame_body<'a>(frame: OriginalFrame<'a>) -> Option<&'a [u8]> {
    frame.bytes.get(4..)
}

impl<S: ProviderStream> Connection<S> {
    /// Returns the actual received World slot without minting a release right.
    ///
    /// # Errors
    /// Refuses another role, stale original connection, wrong current reader or
    /// incomplete/mismatching literal. The original must already be retained.
    pub(crate) fn original_restoration_incoming_literal_slot_data(
        &self,
        original: &Envelope,
    ) -> Result<usize, ProviderError> {
        self.original_native_owned11_admission()?
            .authenticate_current(self)?;
        if self.role != EndpointRole::Provider {
            return Err(refused());
        }
        let slot = self.reader.original_slot().ok_or_else(refused)?;
        let bank = self
            .original_frames
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow()
            .map_err(|_| refused())?;
        authenticate(original, bank.frame(slot).ok_or_else(refused)?)?;
        self.authority.ensure_live()?;
        Ok(slot)
    }

    /// Borrows one earlier World original from its same current native bank.
    ///
    /// # Errors
    /// Refuses another role/actor, busy or absent bank, invalid index or changed
    /// full canonical original. It performs no parsing allocation or I/O.
    pub(crate) fn original_restoration_incoming_literal_data(
        &self,
        original: &Envelope,
        slot: usize,
    ) -> Result<Ref<'_, [u8]>, ProviderError> {
        self.original_native_owned11_admission()?
            .authenticate_current(self)?;
        if self.role != EndpointRole::Provider {
            return Err(refused());
        }
        let bank = self
            .original_frames
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow()
            .map_err(|_| refused())?;
        authenticate(original, bank.frame(slot).ok_or_else(refused)?)?;
        self.authority.ensure_live()?;
        Ref::filter_map(bank, body_at_slot(slot)).map_err(|_| refused())
    }
}

fn refused() -> ProviderError {
    ProviderError::Correlation("restoration World original literal differs")
}

pub(crate) fn original_restoration_release_literal_counter_scratch_data() -> usize {
    use crate::transport::original_frames::OriginalFrameReservation;
    use std::cell::BorrowError;
    use std::mem::size_of;
    std::mem::size_of_val(&body_at_slot(0))
        + size_of::<OriginalFrame<'static>>()
        + size_of::<Option<OriginalFrame<'static>>>()
        + size_of::<Ref<'static, OriginalFrameReservation>>()
        + size_of::<Result<Ref<'static, OriginalFrameReservation>, BorrowError>>()
        + size_of::<Result<Ref<'static, [u8]>, Ref<'static, OriginalFrameReservation>>>()
        + size_of::<Result<Ref<'static, [u8]>, ProviderError>>()
        + size_of::<Result<(), ProviderError>>()
        + size_of::<Result<usize, ProviderError>>()
        + size_of::<Option<usize>>()
        + size_of::<[u8; 4]>()
        + size_of::<Result<[u8; 4], std::array::TryFromSliceError>>()
        + crate::protocol_snapshot::owned11::correspondence::envelope_comparison_scratch_data()
        + crate::protocol_snapshot::owned11::correspondence::envelope_counter_scratch_data()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(
        bytes: &[u8],
        direction: FrameDirection,
        complete: bool,
        transferred: usize,
    ) -> OriginalFrame<'_> {
        OriginalFrame {
            direction,
            bytes,
            transferred,
            complete,
        }
    }

    #[test]
    fn world_literal_requires_full_original_header_and_completed_incoming_bytes() {
        let mut original = crate::envelope::tests::request();
        original.method = Method::WorldActivate;
        original
            .extensions
            .insert("retained-mac".into(), serde_json::json!({"mac":"actual"}));
        let body = crucible_node_format::canonical::canonical_json(
            &serde_json::to_value(&original).unwrap(),
        )
        .unwrap();
        let mut bytes = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
        bytes.extend_from_slice(&body);

        authenticate(
            &original,
            frame(&bytes, FrameDirection::Incoming, true, bytes.len()),
        )
        .unwrap();

        let mut changed = original.clone();
        changed
            .extensions
            .insert("retained-mac".into(), serde_json::json!({"mac":"foreign"}));
        assert!(
            authenticate(
                &changed,
                frame(&bytes, FrameDirection::Incoming, true, bytes.len())
            )
            .is_err()
        );
        assert!(
            authenticate(
                &original,
                frame(&bytes, FrameDirection::Outgoing, true, bytes.len())
            )
            .is_err()
        );
        assert!(
            authenticate(
                &original,
                frame(&bytes, FrameDirection::Incoming, false, bytes.len())
            )
            .is_err()
        );
        assert!(
            authenticate(
                &original,
                frame(&bytes, FrameDirection::Incoming, true, bytes.len() - 1)
            )
            .is_err()
        );
        bytes[3] ^= 1;
        assert!(
            authenticate(
                &original,
                frame(&bytes, FrameDirection::Incoming, true, bytes.len())
            )
            .is_err()
        );
    }
}
