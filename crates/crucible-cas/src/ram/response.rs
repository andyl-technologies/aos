//! External original credits for immutable host-side transfer frames.
//!
//! The portable CRUCRT01 codec remains the only wire representation. Payload
//! ownership is private host state and never crosses the process boundary.

use std::io::{Read, Write};

use crucible_protocol::ram_transfer::{
    MAX_TRANSFER_FRAME_BYTES, RamTransferControl, RamTransferMessage,
};
use crucible_ram::{Limits, RootRecord};

use crate::owned_decode::{DecodeBudget, DecodeScratch};

use super::codec_ownership::admission;
use super::{RamStoreError, logical};

/// Owns one immutable transfer message and its original allocation credit.
///
/// The credit closes after every owned string and byte buffer. Borrowed message
/// access does not transfer allocation ownership or execution authority.
pub struct RamTransferResponse {
    message: RamTransferMessage,
    credit: Option<DecodeScratch>,
}

impl RamTransferResponse {
    pub(super) fn new(message: RamTransferMessage, credit: DecodeScratch) -> Self {
        Self {
            message,
            credit: Some(credit),
        }
    }

    pub(super) fn inline(message: RamTransferMessage) -> Self {
        debug_assert!(matches!(
            message.control,
            RamTransferControl::Cancel
                | RamTransferControl::Canceled
                | RamTransferControl::Fail { .. }
        ));
        Self {
            message,
            credit: None,
        }
    }

    /// Borrows the authenticated channel's immutable frame contents.
    pub fn message(&self) -> &RamTransferMessage {
        &self.message
    }

    /// Reads the initial offer under the channel owner's current original.
    ///
    /// The archive coordinator authenticates the channel and owning checkpoint
    /// before using this entry. Length admission precedes body allocation and
    /// reads, and the unchanged portable decoder must produce an Offer.
    ///
    /// # Errors
    /// Refuses supervision, transport errors, oversized or malformed frames,
    /// allocation limits, and controls other than the initial Offer.
    pub fn read_offer<R: Read>(
        reader: &mut R,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
    ) -> Result<Self, RamStoreError> {
        let response =
            Self::read_bounded(reader, original, boundary, MAX_TRANSFER_FRAME_BYTES, true)?;
        if !matches!(response.message.control, RamTransferControl::Offer(_)) {
            return Err(RamStoreError::Invalid("transfer admission requires offer"));
        }
        Ok(response)
    }

    pub(super) fn read_bounded<R: Read>(
        reader: &mut R,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
        maximum: usize,
        offer: bool,
    ) -> Result<Self, RamStoreError> {
        check(original, boundary)?;
        let mut prefix = [0_u8; 4];
        reader
            .read_exact(&mut prefix)
            .map_err(crucible_protocol::ram_transfer::RamTransferCodecError::from)?;
        let length = u32::from_be_bytes(prefix) as usize;
        if length > maximum || length > MAX_TRANSFER_FRAME_BYTES {
            return Err(RamStoreError::Limit("transfer frame bytes"));
        }
        let credit = original
            .reserve_scratch_bytes(frame_peak(length + 4, offer)?)
            .map_err(admission)?;
        check(original, boundary)?;
        let mut frame = Vec::with_capacity(length + 4);
        frame.extend_from_slice(&prefix);
        frame.resize(length + 4, 0);
        reader
            .read_exact(&mut frame[4..])
            .map_err(crucible_protocol::ram_transfer::RamTransferCodecError::from)?;
        check(original, boundary)?;
        let message = RamTransferMessage::decode(&frame)?;
        drop(frame);
        original.verify_live().map_err(admission)?;
        Ok(Self::new(message, credit))
    }

    /// Writes the existing portable frame under the transport's current owner.
    ///
    /// Retained source credit remains passive when a different current caller
    /// writes the frame; that caller prepays its own temporary codec storage.
    ///
    /// # Errors
    /// Refuses original supervision, malformed controls, resource exhaustion,
    /// and transport write or flush failures.
    pub fn write<W: Write>(
        &self,
        writer: &mut W,
        original: &DecodeBudget,
        boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
    ) -> Result<(), RamStoreError> {
        check(original, boundary)?;
        if self.credit.is_none() {
            let frame = self.inline_frame()?;
            writer
                .write_all(frame.as_slice())
                .map_err(crucible_protocol::ram_transfer::RamTransferCodecError::from)?;
        } else {
            self.with_encoded(original, |bytes| {
                writer
                    .write_all(bytes)
                    .map_err(crucible_protocol::ram_transfer::RamTransferCodecError::from)?;
                Ok(())
            })?;
        }
        check(original, boundary)?;
        writer
            .flush()
            .map_err(crucible_protocol::ram_transfer::RamTransferCodecError::from)?;
        original.verify_live().map_err(admission)
    }

    pub(super) fn with_encoded<T>(
        &self,
        original: &DecodeBudget,
        consume: impl FnOnce(&[u8]) -> Result<T, RamStoreError>,
    ) -> Result<T, RamStoreError> {
        original.verify_live().map_err(admission)?;
        if self.credit.is_none() {
            return consume(self.inline_frame()?.as_slice());
        }
        let _extra = match &self.credit {
            Some(credit) if credit.original_account().same_account(original) => None,
            _ => Some(
                original
                    .reserve_scratch_bytes(message_peak(&self.message.control)?)
                    .map_err(admission)?,
            ),
        };
        let bytes = self.message.encode()?;
        let result = consume(&bytes);
        drop(bytes);
        result
    }

    pub(super) fn into_parts(self) -> (RamTransferMessage, Option<DecodeScratch>) {
        (self.message, self.credit)
    }

    #[cfg(test)]
    pub(super) fn alter_for_test(&mut self, alter: impl FnOnce(&mut RamTransferMessage)) {
        alter(&mut self.message);
    }

    fn inline_frame(&self) -> Result<InlineFrame, RamStoreError> {
        let (tag, code) = match self.message.control {
            RamTransferControl::Cancel => (7, None),
            RamTransferControl::Canceled => (8, None),
            RamTransferControl::Fail { code } => (9, Some(code)),
            _ => return Err(RamStoreError::Invalid("uncredited transfer payload")),
        };
        let mut bytes = [0_u8; 47];
        let length = if code.is_some() { 47 } else { 45 };
        bytes[..4].copy_from_slice(&((length - 4) as u32).to_be_bytes());
        bytes[4..12].copy_from_slice(b"CRUCRT01");
        bytes[12] = tag;
        bytes[13..45].copy_from_slice(&self.message.operation);
        if let Some(code) = code {
            bytes[45..47].copy_from_slice(&code.to_be_bytes());
        }
        Ok(InlineFrame { bytes, length })
    }
}

struct InlineFrame {
    bytes: [u8; 47],
    length: usize,
}

impl InlineFrame {
    fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.length]
    }
}

pub(super) fn check(
    original: &DecodeBudget,
    boundary: &mut dyn FnMut() -> Result<(), RamStoreError>,
) -> Result<(), RamStoreError> {
    original.verify_live().map_err(admission)?;
    boundary()?;
    original.verify_live().map_err(admission)
}

pub(super) fn frame_peak(length: usize, offer: bool) -> Result<u64, RamStoreError> {
    let bytes = length
        .checked_mul(4)
        .and_then(|bytes| bytes.checked_add(8))
        .and_then(|bytes| u64::try_from(bytes).ok())
        .ok_or(RamStoreError::Limit("transfer frame allocation"))?;
    if offer {
        bytes
            .checked_add(RootRecord::decoding_memory_bound(Limits::default()).map_err(logical)?)
            .ok_or(RamStoreError::Limit("transfer offer allocation"))
    } else {
        Ok(bytes)
    }
}

pub(super) fn message_peak(control: &RamTransferControl) -> Result<u64, RamStoreError> {
    let length = match control {
        RamTransferControl::Offer(offer) => 83_usize
            .checked_add(offer.whole_world_root.len())
            .and_then(|n| n.checked_add(offer.ram_root.len()))
            .and_then(|n| n.checked_add(offer.root_record.len()))
            .and_then(|n| n.checked_add(offer.destination.len())),
        RamTransferControl::ObjectChunk { object, bytes, .. } => 70_usize
            .checked_add(object.len())
            .and_then(|n| n.checked_add(bytes.len())),
        _ => Some(1024),
    }
    .ok_or(RamStoreError::Limit("transfer frame allocation"))?;
    frame_peak(length, matches!(control, RamTransferControl::Offer(_)))
}

pub(super) fn offer_peak(
    offer: &crucible_protocol::ram_transfer::RamTransferOffer,
) -> Result<u64, RamStoreError> {
    let length = 83_usize
        .checked_add(offer.whole_world_root.len())
        .and_then(|n| n.checked_add(offer.ram_root.len()))
        .and_then(|n| n.checked_add(offer.root_record.len()))
        .and_then(|n| n.checked_add(offer.destination.len()))
        .ok_or(RamStoreError::Limit("transfer offer allocation"))?;
    frame_peak(length, true)
}

pub(super) fn decode_local(
    response: &RamTransferResponse,
    source_original: &DecodeBudget,
    destination_original: &DecodeBudget,
) -> Result<RamTransferResponse, RamStoreError> {
    destination_original.verify_live().map_err(admission)?;
    let credit = destination_original
        .reserve_scratch_bytes(message_peak(&response.message.control)?)
        .map_err(admission)?;
    response.with_encoded(source_original, |bytes| {
        let message = RamTransferMessage::decode(bytes)?;
        destination_original.verify_live().map_err(admission)?;
        Ok(RamTransferResponse::new(message, credit))
    })
}
