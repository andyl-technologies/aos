//! Delivers owned and borrowed inputs through the same checked guest writer.
// SPDX-License-Identifier: GPL-2.0-only

use super::*;

impl PluginWhiteboxDoorbell {
    /// Delivers one host-to-guest white-box input at its exact delivery icount.
    ///
    /// This method is the safe core for marker acknowledgments, control writes,
    /// and later app-random replies. It does not write early: if the current
    /// icount is before the input's delivery icount, it returns `NotReady`.
    ///
    /// # Errors
    ///
    /// Returns [`WhiteboxDoorbellError`] when white-box mode is disabled, the
    /// input is late, its target range and payload length disagree, or the
    /// guest-input writer fails loudly.
    pub fn inject_guest_input<W>(
        &self,
        capability: &WhiteboxGuestInputCapability,
        writer: &mut W,
        current_icount: u64,
        input: &WhiteboxGuestInput,
    ) -> Result<WhiteboxGuestInputOutcome, WhiteboxDoorbellError>
    where
        W: WhiteboxGuestInputWriter + ?Sized,
    {
        self.inject_guest_input_slice(
            capability,
            writer,
            current_icount,
            input.delivery_icount(),
            input.payload_range(),
            input.payload(),
        )
    }

    /// Delivers borrowed input bytes without constructing an owned payload.
    ///
    /// The writer consumes the slice synchronously. The same capability, range
    /// and exact delivery checks apply to owned and borrowed inputs.
    ///
    /// # Errors
    /// Returns the original disabled-mode, range, delivery or writer refusal.
    pub(crate) fn inject_guest_input_slice<W>(
        &self,
        _capability: &WhiteboxGuestInputCapability,
        writer: &mut W,
        current_icount: u64,
        delivery_icount: u64,
        payload_range: GuestMemoryRange,
        payload: &[u8],
    ) -> Result<WhiteboxGuestInputOutcome, WhiteboxDoorbellError>
    where
        W: WhiteboxGuestInputWriter + ?Sized,
    {
        if !self.mode.is_on() {
            return Err(WhiteboxDoorbellError::InputWhileDisabled);
        }
        if payload_range.len() != payload.len() {
            return Err(WhiteboxDoorbellError::InputPayloadLengthMismatch {
                range_len: payload_range.len(),
                payload_len: payload.len(),
            });
        }
        self.validate_payload_range(payload_range)?;
        if current_icount < delivery_icount {
            return Ok(WhiteboxGuestInputOutcome::NotReady { delivery_icount });
        }
        if current_icount > delivery_icount {
            return Err(WhiteboxDoorbellError::InputDeliveryAlreadyPassed {
                delivery_icount,
                current_icount,
            });
        }

        writer
            .write_whitebox_input(delivery_icount, payload_range, payload)
            .map_err(|source| WhiteboxDoorbellError::GuestInputWrite {
                delivery_icount,
                source,
            })?;
        Ok(WhiteboxGuestInputOutcome::Delivered(
            WhiteboxGuestInputInjection {
                delivery_icount,
                payload_range,
                payload_len: payload.len(),
            },
        ))
    }
}

#[cfg(test)]
mod tests;
