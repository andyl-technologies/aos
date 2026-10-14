//! Precharged literal frame storage with nonrenewing lifetime slots.
//!
//! A reservation owns byte and descriptor capacity before a child exists. The
//! transport writes into this same bank without allocation; failed and partial
//! frames retain their slot and observed prefix. No frame is reconstructed.

use crate::ProviderError;

/// Limits one endpoint's retained literal framing bytes.
pub const MAX_ORIGINAL_FRAME_BYTES: usize = 512 * 1024 * 1024;
/// Limits each direction's lifetime frame count without slot refunds.
pub const MAX_ORIGINAL_FRAMES_PER_DIRECTION: usize = 4096;

/// Identifies the local direction of literal transport bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FrameDirection {
    /// Bytes actually read from the original peer.
    Incoming,
    /// Original planned bytes and their actual publication prefix.
    Outgoing,
}

/// Borrows one original frame and its actual transport progress.
pub struct OriginalFrame<'a> {
    /// Identifies this endpoint's frame direction.
    pub direction: FrameDirection,
    /// Contains literal received bytes or the original complete send proposal.
    pub bytes: &'a [u8],
    /// Counts bytes actually read or written, including the four-byte header.
    pub transferred: usize,
    /// Reports complete I/O, independently of semantic validity.
    pub complete: bool,
}

#[derive(Clone)]
struct Slot {
    direction: FrameDirection,
    start: usize,
    length: usize,
    transferred: usize,
    complete: bool,
    request: Option<([u8; 128], usize)>,
}

/// Owns preallocated literal bytes and lifetime frame descriptors.
///
/// Reservation grants no schema, source, process or capture authority. Its owner
/// must charge the returned allocation and separate snapshot/temporary buffers
/// before constructing either endpoint's child.
pub struct OriginalFrameReservation {
    bytes: Vec<u8>,
    slots: Vec<Slot>,
    maximum_bytes: usize,
    maximum_frames: usize,
    incoming: usize,
    outgoing: usize,
}

impl OriginalFrameReservation {
    /// Reserves both lifetime directions and their shared finite byte bank.
    ///
    /// # Errors
    /// Refuses zero or excessive limits, overflow, and allocator refusal before
    /// any stream exists. Reserved slots and bytes are never refunded.
    pub fn reserve(maximum_bytes: usize, maximum_frames: usize) -> Result<Self, ProviderError> {
        if !(4..=MAX_ORIGINAL_FRAME_BYTES).contains(&maximum_bytes)
            || maximum_frames == 0
            || maximum_frames > MAX_ORIGINAL_FRAMES_PER_DIRECTION
        {
            return Err(ProviderError::ResourceExhausted(
                "original frame reservation limits",
            ));
        }
        let mut bytes = Vec::new();
        let mut slots = Vec::new();
        bytes
            .try_reserve_exact(maximum_bytes)
            .map_err(|_| ProviderError::ResourceExhausted("original frame byte bank"))?;
        slots
            .try_reserve_exact(maximum_frames * 2)
            .map_err(|_| ProviderError::ResourceExhausted("original frame descriptor bank"))?;
        Ok(Self {
            bytes,
            slots,
            maximum_bytes,
            maximum_frames,
            incoming: 0,
            outgoing: 0,
        })
    }

    /// Reports actual retained capacities, including descriptor storage.
    pub fn allocated_bytes(&self) -> usize {
        self.bytes.capacity() + self.slots.capacity() * std::mem::size_of::<Slot>()
    }

    /// Borrows every original slot, including failed and unsent frames.
    pub fn frames(&self) -> impl Iterator<Item = OriginalFrame<'_>> {
        self.slots.iter().map(|slot| OriginalFrame {
            direction: slot.direction,
            bytes: &self.bytes[slot.start..slot.start + slot.length],
            transferred: slot.transferred,
            complete: slot.complete,
        })
    }

    pub(crate) fn authenticate_completed_send(
        &self,
        index: usize,
        canonical: &[u8],
    ) -> Result<(), ProviderError> {
        let slot = self
            .slots
            .get(index)
            .ok_or(ProviderError::Frame("sent original slot absent"))?;
        let expected = canonical
            .len()
            .checked_add(4)
            .ok_or(ProviderError::Frame("sent original extent"))?;
        let length = u32::try_from(canonical.len())
            .map_err(|_| ProviderError::Frame("sent original header"))?;
        if slot.direction != FrameDirection::Outgoing
            || !slot.complete
            || slot.transferred != slot.length
            || slot.length != expected
            || self.bytes.get(slot.start..slot.start + 4) != Some(length.to_be_bytes().as_slice())
            || self.bytes.get(slot.start + 4..slot.start + slot.length) != Some(canonical)
        {
            return Err(ProviderError::Frame(
                "sent original literal bytes or progress differ",
            ));
        }
        Ok(())
    }

    pub(crate) fn borrowed_original_slot(&self, index: usize) -> OriginalFrame<'_> {
        let slot = &self.slots[index];
        OriginalFrame {
            direction: slot.direction,
            bytes: &self.bytes[slot.start..slot.start + slot.length],
            transferred: slot.transferred,
            complete: slot.complete,
        }
    }

    pub(crate) fn authenticate_exact_prefix_of(&self, current: &Self) -> Result<(), ProviderError> {
        if self.maximum_bytes != current.maximum_bytes
            || self.maximum_frames != current.maximum_frames
            || self.bytes.capacity() != current.bytes.capacity()
            || self.slots.capacity() != current.slots.capacity()
            || self.slots.is_empty()
            || self.slots.len() > current.slots.len()
            || self.incoming > current.incoming
            || self.outgoing > current.outgoing
            || !current.bytes.starts_with(&self.bytes)
            || self
                .slots
                .iter()
                .any(|slot| !slot.complete || slot.transferred != slot.length)
            || current
                .slots
                .iter()
                .any(|slot| !slot.complete || slot.transferred != slot.length)
            || self.slots.iter().zip(&current.slots).any(|(old, now)| {
                old.direction != now.direction
                    || old.start != now.start
                    || old.length != now.length
                    || old.transferred != now.transferred
                    || old.complete != now.complete
                    || old.request != now.request
            })
        {
            return Err(ProviderError::Correlation(
                "native capture literal antecedent differs",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_empty_copy(&self, target: &Self) -> Result<(), ProviderError> {
        if !target.bytes.is_empty()
            || !target.slots.is_empty()
            || target.incoming != 0
            || target.outgoing != 0
        {
            return Err(ProviderError::Conflict(
                "original history target already used",
            ));
        }
        if self.maximum_bytes != target.maximum_bytes
            || self.maximum_frames != target.maximum_frames
            || self.bytes.capacity() != target.bytes.capacity()
            || self.slots.capacity() != target.slots.capacity()
        {
            return Err(ProviderError::ResourceExhausted(
                "complete original history reservation differs",
            ));
        }
        Ok(())
    }

    pub(crate) fn copy_into_empty(&self, target: &mut Self) -> Result<(), ProviderError> {
        self.validate_empty_copy(target)?;
        target.bytes.extend_from_slice(&self.bytes);
        target.slots.extend_from_slice(&self.slots);
        target.incoming = self.incoming;
        target.outgoing = self.outgoing;
        Ok(())
    }

    pub(crate) fn storage_facts(
        &self,
        maximum_frame_bytes: usize,
    ) -> crate::protocol_snapshot::OriginalProtocolStorageFacts {
        let descriptor_bytes = self.slots.capacity() * std::mem::size_of::<Slot>();
        crate::protocol_snapshot::OriginalProtocolStorageFacts {
            maximum_frame_bytes,
            maximum_history_bytes: self.maximum_bytes,
            maximum_frames_per_direction: self.maximum_frames,
            byte_capacity: self.bytes.capacity(),
            descriptor_capacity: self.slots.capacity(),
            descriptor_bytes,
            allocated_bytes: self.allocated_bytes(),
            retained_bytes: self.bytes.len(),
            incoming_frames: self.incoming,
            outgoing_frames: self.outgoing,
            all_io_complete: self.complete(),
        }
    }

    pub(crate) fn complete(&self) -> bool {
        self.slots.iter().all(|slot| slot.complete)
    }

    pub(crate) fn protocol_view(&self) -> impl serde::Serialize + '_ {
        (
            &self.maximum_bytes,
            &self.maximum_frames,
            &self.incoming,
            &self.outgoing,
            self.bytes.capacity(),
            self.slots.capacity(),
            &self.bytes,
            crate::protocol_snapshot::Sequence(|| {
                self.slots.iter().map(|slot| {
                    (
                        match slot.direction {
                            FrameDirection::Incoming => "incoming",
                            FrameDirection::Outgoing => "outgoing",
                        },
                        slot.start,
                        slot.length,
                        slot.transferred,
                        slot.complete,
                        slot.request
                            .as_ref()
                            .map(|(bytes, length)| &bytes[..*length]),
                    )
                })
            }),
        )
    }

    pub(crate) fn begin(
        &mut self,
        direction: FrameDirection,
        allowance: usize,
    ) -> Result<usize, ProviderError> {
        let count = match direction {
            FrameDirection::Incoming => self.incoming,
            FrameDirection::Outgoing => self.outgoing,
        };
        if count == self.maximum_frames || allowance > self.maximum_bytes - self.bytes.len() {
            return Err(ProviderError::ResourceExhausted(
                "original frame lifetime bank",
            ));
        }
        let index = self.slots.len();
        self.slots.push(Slot {
            direction,
            start: self.bytes.len(),
            length: 0,
            transferred: 0,
            complete: false,
            request: None,
        });
        match direction {
            FrameDirection::Incoming => self.incoming += 1,
            FrameDirection::Outgoing => self.outgoing += 1,
        }
        Ok(index)
    }

    pub(crate) fn append(&mut self, index: usize, bytes: &[u8]) -> Result<(), ProviderError> {
        let slot = self
            .slots
            .get_mut(index)
            .ok_or(ProviderError::Frame("original frame slot absent"))?;
        if slot.start + slot.length != self.bytes.len()
            || bytes.len() > self.maximum_bytes - self.bytes.len()
        {
            return Err(ProviderError::ResourceExhausted(
                "original frame append allowance",
            ));
        }
        self.bytes.extend_from_slice(bytes);
        slot.length += bytes.len();
        if slot.direction == FrameDirection::Incoming {
            slot.transferred += bytes.len();
        }
        Ok(())
    }

    pub(crate) fn retain_request(
        &mut self,
        index: usize,
        id: &crucible_node_contract::Id,
    ) -> Result<(), ProviderError> {
        let direction = self
            .slots
            .get(index)
            .ok_or(ProviderError::Frame("original request slot absent"))?
            .direction;
        let bytes = id.as_str().as_bytes();
        if self.slots.iter().any(|slot| {
            slot.direction == direction
                && slot
                    .request
                    .as_ref()
                    .is_some_and(|(original, length)| &original[..*length] == bytes)
        }) {
            return Err(ProviderError::Conflict(
                "native5 lifetime request identity already used",
            ));
        }
        let mut original = [0; 128];
        original[..bytes.len()].copy_from_slice(bytes);
        self.slots[index].request = Some((original, bytes.len()));
        Ok(())
    }

    pub(crate) fn matches_send(&self, index: usize, header: &[u8], bytes: &[u8]) -> bool {
        self.slots.get(index).is_some_and(|slot| {
            slot.direction == FrameDirection::Outgoing
                && slot.transferred == 0
                && !slot.complete
                && slot.length == header.len() + bytes.len()
                && self.bytes.get(slot.start..slot.start + header.len()) == Some(header)
                && self
                    .bytes
                    .get(slot.start + header.len()..slot.start + slot.length)
                    == Some(bytes)
        })
    }

    pub(crate) fn advance(&mut self, index: usize, count: usize) -> Result<(), ProviderError> {
        let slot = self
            .slots
            .get_mut(index)
            .ok_or(ProviderError::Frame("original frame slot absent"))?;
        let next = slot
            .transferred
            .checked_add(count)
            .filter(|next| *next <= slot.length)
            .ok_or(ProviderError::Frame("original frame progress changed"))?;
        slot.transferred = next;
        Ok(())
    }

    pub(crate) fn finish(&mut self, index: usize) -> Result<(), ProviderError> {
        let slot = self
            .slots
            .get_mut(index)
            .ok_or(ProviderError::Frame("original frame slot absent"))?;
        if slot.transferred != slot.length || slot.length < 4 {
            return Err(ProviderError::Frame("original frame incomplete"));
        }
        slot.complete = true;
        Ok(())
    }
}

mod decoded;
pub use decoded::DecodedOriginalFrameData;

#[cfg(test)]
mod antecedent_tests;
