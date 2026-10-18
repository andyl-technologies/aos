//! Rejoins completed observation exchanges with their immutable literal custody.
//!
//! This checker allocates no DTO or canonical bank. Private completed native
//! owners provide publication provenance; this independent loan checks every
//! actual sent frame and successful ACK in the same current connection bank.

use super::*;
use crate::envelope::MessageKind;

impl ExchangeRecord {
    /// Checks one actually published response and its complete proof/ACK prefix.
    ///
    /// # Errors
    /// Refuses partial, foreign, duplicated or changed literals, missing ACKs,
    /// wrong response correlation or unsuccessful proof replies.
    pub(crate) fn authenticate_observation17_publication_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        original: &Envelope,
        terminal: &Envelope,
    ) -> Result<(), ProviderError> {
        connection.protocol_owner.ensure_current()?;
        connection.authenticate_native5_source_codec()?;
        if self.originals.is_empty()
            || self.sent != self.originals.len()
            || self.canonical.len() != self.originals.len()
            || self.original_slots.len() != self.originals.len()
            || self.acknowledgements.len().checked_add(1) != Some(self.originals.len())
        {
            return Err(refused());
        }
        original.matches_response(terminal)?;
        authenticate_incoming(connection, original)?;

        let mut replies = self.acknowledgements.iter();
        let mut found_terminal = false;
        for (index, outgoing) in self.originals.iter().enumerate() {
            let sent = self.original_sent_frame(connection, index)?;
            if sent.original() != outgoing {
                return Err(refused());
            }
            crate::protocol_snapshot::owned11::correspondence::envelope(
                outgoing,
                sent.canonical_body(),
            )?;
            match outgoing.message {
                MessageKind::Response if outgoing == terminal && !found_terminal => {
                    found_terminal = true;
                }
                MessageKind::Request => {
                    let reply = replies.next().ok_or_else(refused)?;
                    outgoing.matches_response(&reply.envelope)?;
                    completed_record_projection::authenticate_successful_ack(outgoing, reply)?;
                    authenticate_incoming(connection, &reply.envelope)?;
                }
                _ => return Err(refused()),
            }
        }
        if !found_terminal || replies.next().is_some() {
            return Err(refused());
        }
        connection.protocol_owner.ensure_current()
    }
}

impl ExchangeRecord {
    /// Rejoins the sole actual upload response with complete literal custody.
    ///
    /// This is transport DATA only. The genuine native occurrence separately
    /// authenticates its Source, independent row, real receiver result and once
    /// state. A zero-evidence ACK never becomes a current-model proof.
    ///
    /// # Errors
    /// Refuses partial/foreign/lost literals, another phase/body, extra frames or
    /// ACKs, unresolved correlation, a reserved/unfinished bank or fenced owner.
    pub(crate) fn authenticate_capture17_upload_publication_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        original: &Envelope,
        terminal: &Envelope,
    ) -> Result<(), ProviderError> {
        connection.protocol_owner.ensure_current()?;
        connection.authenticate_native5_source_codec()?;
        if connection.fenced
            || connection.role != EndpointRole::Provider
            || self.originals.as_slice() != std::slice::from_ref(terminal)
            || self.sent != 1
            || self.canonical.len() != 1
            || self.original_slots.len() != 1
            || !self.acknowledgements.is_empty()
        {
            return Err(refused());
        }
        original.matches_response(terminal)?;
        connection.authenticate_capture17_upload_completed_body_data(original, &terminal.body)?;
        authenticate_incoming(connection, original)?;
        let sent = self.original_sent_frame(connection, 0)?;
        if sent.original() != terminal {
            return Err(refused());
        }
        crate::protocol_snapshot::owned11::correspondence::envelope(
            terminal,
            sent.canonical_body(),
        )?;
        if !connection
            .original_frames
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow()
            .map_err(|_| refused())?
            .complete()
        {
            return Err(refused());
        }
        connection
            .guard
            .protocol_cut(crate::protocol_snapshot::ProtocolCaptureCut::HostSettled)?;
        connection.authority.ensure_live()?;
        connection.protocol_owner.ensure_current()
    }

    /// Rechecks a real completed upload while the sole next original is incoming.
    ///
    /// The native lender independently authenticates the actual prior private
    /// owner and Source seed. This method checks immutable original/terminal
    /// transport correspondence; it never treats the current incoming request
    /// as a globally settled cut or grants another Blob/native effect.
    ///
    /// # Errors
    /// Refuses a partial/foreign prior record, changed source literal or normal
    /// reply, nonincreasing original sequence, or another current incoming cut.
    pub(crate) fn authenticate_capture17_upload_predecessor_data<S: ProviderStream>(
        &self,
        connection: &Connection<S>,
        original: &Envelope,
        terminal: &Envelope,
        current: &Envelope,
    ) -> Result<(), ProviderError> {
        connection.protocol_owner.ensure_current()?;
        connection.authenticate_native5_source_codec()?;
        if connection.fenced
            || connection.role != EndpointRole::Provider
            || self.originals.as_slice() != std::slice::from_ref(terminal)
            || self.sent != 1
            || self.canonical.len() != 1
            || self.original_slots.len() != 1
            || !self.acknowledgements.is_empty()
        {
            return Err(refused());
        }
        original.matches_response(terminal)?;
        connection.authenticate_capture17_upload_completed_body_data(original, &terminal.body)?;
        authenticate_incoming(connection, original)?;
        let sent = self.original_sent_frame(connection, 0)?;
        if sent.original() != terminal {
            return Err(refused());
        }
        crate::protocol_snapshot::owned11::correspondence::envelope(
            terminal,
            sent.canonical_body(),
        )?;
        if !connection
            .original_frames
            .as_ref()
            .ok_or_else(refused)?
            .try_borrow()
            .map_err(|_| refused())?
            .complete()
        {
            return Err(refused());
        }
        if original.sequence.get() >= current.sequence.get() {
            return Err(refused());
        }
        connection.authenticate_native_capture17_incoming_data(current)?;
        connection.authority.ensure_live()?;
        connection.protocol_owner.ensure_current()
    }
}

fn authenticate_incoming<S: ProviderStream>(
    connection: &Connection<S>,
    original: &Envelope,
) -> Result<(), ProviderError> {
    let bank = connection
        .original_frames
        .as_ref()
        .ok_or_else(refused)?
        .try_borrow()
        .map_err(|_| refused())?;
    authenticate_incoming_bank(&bank, original)
}

fn authenticate_incoming_bank(
    bank: &crate::transport::original_frames::OriginalFrameReservation,
    original: &Envelope,
) -> Result<(), ProviderError> {
    let mut found = false;
    for frame in bank.frames() {
        if frame.direction != crate::transport::original_frames::FrameDirection::Incoming {
            continue;
        }
        // Any partial incoming frame poisons this purported completed cut;
        // it cannot be hidden by finding an earlier matching complete frame.
        if !frame.complete || frame.transferred != frame.bytes.len() || frame.bytes.len() < 4 {
            return Err(refused());
        }
        let header: [u8; 4] = frame.bytes[..4].try_into().map_err(|_| refused())?;
        if usize::try_from(u32::from_be_bytes(header)).ok() != Some(frame.bytes.len() - 4) {
            return Err(refused());
        }
        if completed_record_projection::authenticate_proof_literal(original, frame).is_ok()
            && std::mem::replace(&mut found, true)
        {
            return Err(refused());
        }
    }
    if !found {
        return Err(refused());
    }
    Ok(())
}

/// Names this defining scan's borrowed headers and bounded comparison workspace.
pub(crate) fn counter_scratch_data() -> usize {
    use std::mem::size_of;
    size_of::<&ExchangeRecord>()
        + size_of::<&Envelope>() * 5
        + size_of::<std::slice::Iter<'static, ReceivedFrame>>()
        + size_of::<std::iter::Enumerate<std::slice::Iter<'static, Envelope>>>()
        + size_of::<
            std::cell::Ref<'static, crate::transport::original_frames::OriginalFrameReservation>,
        >()
        + size_of::<crate::transport::original_frames::OriginalFrame<'static>>()
        + size_of::<Option<&ReceivedFrame>>()
        + size_of::<Result<OriginalSentFrameView<'static>, ProviderError>>()
        + size_of::<[u8; 4]>()
        + size_of::<bool>() * 2
        + crate::protocol_snapshot::owned11::correspondence::envelope_counter_scratch_data()
        + crate::protocol_snapshot::owned11::correspondence::envelope_comparison_scratch_data()
        + crate::transport::original_frames::original_frames_iterator_counter_scratch_data()
}

fn refused() -> ProviderError {
    ProviderError::Correlation("native17 observation publication literal or ACK custody differs")
}

#[cfg(test)]
mod tests {
    // crucible-lint: allow panic-shortcut -- These controls deliberately panic on invalid literal-bank setup.
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crate::transport::original_frames::{FrameDirection, OriginalFrameReservation};

    fn literal(original: &Envelope) -> Vec<u8> {
        let body = crucible_node_contract::canonical::canonical_json(
            &serde_json::to_value(original).unwrap(),
        )
        .unwrap();
        let mut framed = u32::try_from(body.len()).unwrap().to_be_bytes().to_vec();
        framed.extend_from_slice(&body);
        framed
    }

    fn append(bank: &mut OriginalFrameReservation, bytes: &[u8], complete: bool) {
        let slot = bank.begin(FrameDirection::Incoming, bytes.len()).unwrap();
        bank.append(slot, bytes).unwrap();
        if complete {
            bank.finish(slot).unwrap();
        }
    }

    #[test]
    fn borrowed_bank_correspondence_is_repeatable_without_growing_retained_banks() {
        // This exercises literal DATA only. No native Boot, published owner,
        // Control, signature, action grant or positive current loan is invented.
        let original = crate::envelope::tests::request();
        let bytes = literal(&original);
        let mut bank = OriginalFrameReservation::reserve(16_384, 8).unwrap();
        append(&mut bank, &bytes, true);
        let before = bank.allocated_bytes();
        let count = bank.frames().count();

        for _ in 0..32 {
            authenticate_incoming_bank(&bank, &original).unwrap();
        }

        assert_eq!(bank.allocated_bytes(), before);
        assert_eq!(bank.frames().count(), count);
        let mut foreign = original.clone();
        foreign.sequence = crucible_node_contract::U64::new(original.sequence.get() + 1);
        assert!(authenticate_incoming_bank(&bank, &foreign).is_err());
    }

    #[test]
    fn duplicate_or_partial_incoming_owner_cannot_hide_behind_a_complete_match() {
        let original = crate::envelope::tests::request();
        let bytes = literal(&original);
        let mut duplicate = OriginalFrameReservation::reserve(16_384, 8).unwrap();
        append(&mut duplicate, &bytes, true);
        append(&mut duplicate, &bytes, true);
        assert!(authenticate_incoming_bank(&duplicate, &original).is_err());

        let mut partial = OriginalFrameReservation::reserve(16_384, 8).unwrap();
        append(&mut partial, &bytes, true);
        append(&mut partial, &bytes, false);
        assert!(authenticate_incoming_bank(&partial, &original).is_err());
        assert_eq!(partial.frames().count(), 2);
        assert!(!partial.frames().last().unwrap().complete);
    }

    #[test]
    fn malformed_framing_or_wrong_direction_cannot_supply_incoming_custody() {
        let original = crate::envelope::tests::request();
        let bytes = literal(&original);
        let mut malformed = OriginalFrameReservation::reserve(16_384, 8).unwrap();
        append(&mut malformed, &bytes, true);
        let mut bad_header = bytes.clone();
        bad_header[..4].copy_from_slice(&0_u32.to_be_bytes());
        append(&mut malformed, &bad_header, true);
        assert!(authenticate_incoming_bank(&malformed, &original).is_err());

        let mut outgoing = OriginalFrameReservation::reserve(16_384, 8).unwrap();
        let slot = outgoing
            .begin(FrameDirection::Outgoing, bytes.len())
            .unwrap();
        outgoing.append(slot, &bytes).unwrap();
        outgoing.advance(slot, bytes.len()).unwrap();
        outgoing.finish(slot).unwrap();
        assert!(authenticate_incoming_bank(&outgoing, &original).is_err());
    }
}
