//! Retains literal-bank construction before either backing allocation.
//!
//! A present destination records an attempted reservation, including refusal.
//! It is not a completed transport bank, and cannot be retried or refunded.

use super::*;
use std::mem::size_of;

impl OriginalFrameReservation {
    /// Installs the literal owner before reserving bytes or descriptors.
    ///
    /// This private constructor supplies storage only. Its caller retains the
    /// destination and refusal, and exposes the bank only after `Ok(())`.
    ///
    /// # Errors
    /// Refuses an occupied destination, invalid limits, allocation failure or
    /// actual capacity beyond the exact finite requested backing.
    pub(crate) fn reserve_retained_into_data(
        maximum_bytes: usize,
        maximum_frames: usize,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        let requested =
            Self::retained_reservation_requested_bytes_data(maximum_bytes, maximum_frames)?;
        Self::reserve_retained_with_backing_data(maximum_bytes, maximum_frames, requested, output)
    }

    fn reserve_retained_with_backing_data(
        maximum_bytes: usize,
        maximum_frames: usize,
        admitted_bytes: usize,
        output: &mut Option<Self>,
    ) -> Result<(), ProviderError> {
        if output.is_some() {
            return Err(ProviderError::Conflict(
                "original frame reservation already attempted",
            ));
        }
        Self::retained_reservation_requested_bytes_data(maximum_bytes, maximum_frames)?;
        let slots = maximum_frames.checked_mul(2).ok_or_else(exhausted)?;
        let slot_bytes = slots.checked_mul(size_of::<Slot>()).ok_or_else(exhausted)?;

        *output = Some(Self {
            bytes: Vec::new(),
            slots: Vec::new(),
            maximum_bytes,
            maximum_frames,
            incoming: 0,
            outgoing: 0,
        });
        let bank = output.as_mut().ok_or_else(exhausted)?;

        if maximum_bytes > admitted_bytes {
            return Err(exhausted());
        }
        bank.bytes
            .try_reserve_exact(maximum_bytes)
            .map_err(|_| exhausted())?;
        if bank.bytes.capacity() > maximum_bytes {
            return Err(exhausted());
        }

        let remaining = admitted_bytes
            .checked_sub(bank.bytes.capacity())
            .ok_or_else(exhausted)?;
        if slot_bytes > remaining {
            return Err(exhausted());
        }
        bank.slots
            .try_reserve_exact(slots)
            .map_err(|_| exhausted())?;
        if bank.slots.capacity() > slots || bank.allocated_bytes() > admitted_bytes {
            return Err(exhausted());
        }
        Ok(())
    }

    /// Counts the same literal bytes and two actual descriptor directions.
    ///
    /// # Errors
    /// Refuses invalid positive limits or checked descriptor/layout overflow.
    pub(crate) fn retained_reservation_requested_bytes_data(
        maximum_bytes: usize,
        maximum_frames: usize,
    ) -> Result<usize, ProviderError> {
        if !(4..=MAX_ORIGINAL_FRAME_BYTES).contains(&maximum_bytes)
            || maximum_frames == 0
            || maximum_frames > MAX_ORIGINAL_FRAMES_PER_DIRECTION
        {
            return Err(exhausted());
        }
        let slots = maximum_frames.checked_mul(2).ok_or_else(exhausted)?;
        let descriptors = slots.checked_mul(size_of::<Slot>()).ok_or_else(exhausted)?;
        maximum_bytes.checked_add(descriptors).ok_or_else(exhausted)
    }

    /// Names concrete empty-owner construction and destination move windows.
    pub(crate) fn retained_reservation_constructor_transient_data() -> usize {
        size_of::<Self>()
            + size_of::<Option<Self>>()
            + size_of::<Vec<u8>>()
            + size_of::<Vec<Slot>>()
    }

    /// Names direct checked reservation, allocation and borrowed-owner controls.
    pub(crate) fn retained_reservation_counter_scratch_data() -> usize {
        // Public two limits/requested bytes; inner three limits and
        // slots/slot_bytes/remaining; defining quote's two limits and two
        // descriptor intermediates. These frames coexist across the calls.
        size_of::<usize>() * (3 + 6 + 4)
            + size_of::<&mut Option<Self>>() * 2
            + size_of::<&mut Self>()
            + size_of::<Option<&mut Self>>()
            + size_of::<Result<&mut Self, ProviderError>>()
            + size_of::<Option<usize>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Result<(), std::collections::TryReserveError>>()
            + size_of::<std::collections::TryReserveError>()
            + size_of::<Result<(), ProviderError>>()
    }
}

fn exhausted() -> ProviderError {
    ProviderError::ResourceExhausted("retained original frame reservation")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn descriptor_refusal_keeps_the_actual_literal_allocation_and_closes_retry()
    -> Result<(), ProviderError> {
        let required = OriginalFrameReservation::retained_reservation_requested_bytes_data(64, 2)?;
        let mut output = None;
        assert!(
            OriginalFrameReservation::reserve_retained_with_backing_data(
                64,
                2,
                required - 1,
                &mut output,
            )
            .is_err()
        );

        let bank = output.as_ref().ok_or_else(exhausted)?;
        assert_eq!(bank.bytes.capacity(), 64);
        assert_eq!(bank.slots.capacity(), 0);
        assert!(bank.bytes.is_empty());
        assert!(bank.slots.is_empty());
        let pointer = bank.bytes.as_ptr();

        assert!(OriginalFrameReservation::reserve_retained_into_data(64, 2, &mut output).is_err());
        assert_eq!(
            output.as_ref().ok_or_else(exhausted)?.bytes.as_ptr(),
            pointer
        );
        Ok(())
    }

    #[test]
    fn exact_constructor_keeps_the_real_two_direction_geometry() -> Result<(), ProviderError> {
        let mut output = None;
        OriginalFrameReservation::reserve_retained_into_data(64, 2, &mut output)?;
        let bank = output.as_mut().ok_or_else(exhausted)?;
        let required = OriginalFrameReservation::retained_reservation_requested_bytes_data(64, 2)?;
        assert_eq!(bank.allocated_bytes(), required);
        assert_eq!(bank.slots.capacity(), 4);

        let slot = bank.begin(FrameDirection::Incoming, 5)?;
        bank.append(slot, &[0, 0, 0, 1, b'0'])?;
        bank.finish(slot)?;
        assert_eq!(
            bank.frame(slot).ok_or_else(exhausted)?.bytes,
            b"\0\0\0\x010"
        );
        assert_eq!(bank.allocated_bytes(), required);
        Ok(())
    }
}
