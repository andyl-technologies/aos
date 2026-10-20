//! Checks immutable exchange plans, send frontiers and literal/ACK associations.

use crate::ProviderError;
use crate::connection::native17_borrowed_bytes::*;
use crate::protocol_snapshot::owned11::typed::{Fields, invalid};

#[derive(Clone, Copy)]
pub(crate) struct BorrowedExchange17<'a> {
    pub(crate) originals: &'a [u8],
    pub(crate) acknowledgements: &'a [u8],
    pub(crate) sent: usize,
}

impl<'a> BorrowedExchange17<'a> {
    pub(crate) fn read(input: &'a [u8], frames: Frames17<'a>) -> Result<Self, ProviderError> {
        let originals = field(input, "originals")?;
        let canonical = field(input, "canonical")?;
        let acknowledgements = field(input, "acknowledgements")?;
        let slots = field(input, "original_slots")?;
        let sent = quantity(field(input, "sent")?)?;
        let length = count(originals)?;
        if count(canonical)? != length || count(slots)? != length || sent != length {
            return Err(invalid());
        }
        if field(input, "original_actor")? == b"null" {
            if sent != 0 || count(acknowledgements)? != 0 {
                return Err(invalid());
            }
        }
        let mut ack_index = 0usize;
        for index in 0..length {
            let original = item(originals, index)?;
            let slot = item(slots, index)?;
            if slot == b"null" {
                return Err(invalid());
            }
            let frame = frames.frame(quantity(slot)?)?;
            let canonical = Bytes17::array(item(item(canonical, index)?, 0)?)?;
            if frame.incoming || !frame.complete || frame.transferred != frame.bytes.len() {
                return Err(invalid());
            }
            frame
                .bytes
                .range(4, frame.bytes.len().checked_sub(4).ok_or_else(invalid)?)?
                .equal(canonical)?;
            canonical.canonical(original)?;
            if field(original, "message")? == b"\"request\"" {
                let acknowledgement = item(acknowledgements, ack_index)?;
                matches_response(original, item(acknowledgement, 0)?)?;
                frames.authenticate_incoming(item(acknowledgement, 0)?)?;
                ack_index = ack_index.checked_add(1).ok_or_else(invalid)?;
            }
        }
        if count(acknowledgements)? != ack_index {
            return Err(invalid());
        }
        Ok(Self {
            originals,
            acknowledgements,
            sent,
        })
    }

    pub(crate) fn terminal(self) -> Result<&'a [u8], ProviderError> {
        item(self.originals, 0)
    }

    pub(crate) fn require_completed_proof(self) -> Result<&'a [u8], ProviderError> {
        if self.sent == 0 || count(self.acknowledgements)?.checked_add(1) != Some(self.sent) {
            return Err(invalid());
        }
        let last = item(
            self.acknowledgements,
            count(self.acknowledgements)?
                .checked_sub(1)
                .ok_or_else(invalid)?,
        )?;
        let mut body = Fields::array(item(last, 1)?)?;
        if next(&mut body)? != b"\"Response\""
            || field(next(&mut body)?, "status")? != b"\"completed\""
        {
            return Err(invalid());
        }
        // The raw response remains independent of its typed cache. Both must
        // actually state completion before this record closes a Fresh frontier.
        let envelope = item(last, 0)?;
        if field(field(envelope, "body")?, "status")? != b"\"completed\"" {
            return Err(invalid());
        }
        Ok(envelope)
    }
}
