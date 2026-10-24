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

    /// Borrows one exact original slot without rescanning its earlier history.
    ///
    /// Returns None for an absent position or inconsistent stored byte range.
    /// The view preserves partial progress and grants no interpretation authority.
    pub fn frame(&self, index: usize) -> Option<OriginalFrame<'_>> {
        let slot = self.slots.get(index)?;
        let end = slot.start.checked_add(slot.length)?;
        Some(OriginalFrame {
            direction: slot.direction,
            bytes: self.bytes.get(slot.start..end)?,
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

    pub(crate) fn snapshot_allocation_facts(
        &self,
    ) -> crate::protocol_snapshot::ProtocolSnapshotLiteralAllocationFacts {
        crate::protocol_snapshot::ProtocolSnapshotLiteralAllocationFacts {
            maximum_history_bytes: self.maximum_bytes,
            maximum_frames_per_direction: self.maximum_frames,
            byte_capacity: self.bytes.capacity(),
            descriptor_capacity: self.slots.capacity(),
            descriptor_bytes: self.slots.capacity() * std::mem::size_of::<Slot>(),
            retained_bytes: self.bytes.len(),
            allocated_bytes: self.allocated_bytes(),
        }
    }

    pub(crate) fn outgoing_original_id_slots(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.direction == FrameDirection::Outgoing && slot.request.is_some())
            .count()
    }

    pub(crate) fn contains_original_id(&self, id: &str) -> bool {
        self.slots.iter().any(|slot| {
            slot.request
                .as_ref()
                .is_some_and(|(bytes, length)| &bytes[..*length] == id.as_bytes())
        })
    }

    /// Checks unused lifetime bytes and directional slots without reservation.
    pub(crate) fn preflight_framed_suffix(
        &self,
        outgoing_frames: usize,
        outgoing_framed_bytes: usize,
        incoming_frames: usize,
        incoming_framed_bytes: usize,
    ) -> Result<(), ProviderError> {
        let outgoing = self.outgoing.checked_add(outgoing_frames);
        let incoming = self.incoming.checked_add(incoming_frames);
        let bytes = self
            .bytes
            .len()
            .checked_add(outgoing_framed_bytes)
            .and_then(|value| value.checked_add(incoming_framed_bytes));
        let slots = self
            .slots
            .len()
            .checked_add(outgoing_frames)
            .and_then(|value| value.checked_add(incoming_frames));
        if !self.complete()
            || outgoing.is_none_or(|value| value > self.maximum_frames)
            || incoming.is_none_or(|value| value > self.maximum_frames)
            || bytes.is_none_or(|value| value > self.maximum_bytes || value > self.bytes.capacity())
            || slots.is_none_or(|value| value > self.slots.capacity())
        {
            return Err(ProviderError::ResourceExhausted(
                "original confirmation lifetime frame bank exhausted",
            ));
        }
        Ok(())
    }

    pub(crate) fn complete(&self) -> bool {
        self.slots.iter().all(|slot| slot.complete)
    }

    pub(crate) fn maximum_encoding_growth(
        &self,
        compact: bool,
    ) -> Result<(usize, usize), ProviderError> {
        let exhausted = || ProviderError::ResourceExhausted("after protocol encoding bound");
        let bytes = if compact {
            self.maximum_bytes
                .div_ceil(3)
                .checked_mul(4)
                .and_then(|n| {
                    self.maximum_bytes
                        .div_ceil(3072)
                        .checked_mul(3)
                        .and_then(|overhead| n.checked_add(overhead))
                })
                .and_then(|n| n.checked_add(64))
                .ok_or_else(exhausted)?
        } else {
            self.maximum_bytes
                .checked_mul(4)
                .and_then(|n| n.checked_add(1))
                .ok_or_else(exhausted)?
        };
        // This is the exact existing descriptor serializer with maximal integer
        // tokens and byte-array ID expansion, not a modeled future descriptor.
        let maximum_request_id = [255_u8; 128];
        let descriptor = crate::connection::serialized_credit(
            &(
                "outgoing",
                usize::MAX,
                usize::MAX,
                usize::MAX,
                false,
                Some(maximum_request_id.as_slice()),
            ),
            1024,
        )?;
        let descriptors = self
            .maximum_frames
            .checked_mul(2)
            .and_then(|n| {
                descriptor
                    .checked_add(1)
                    .and_then(|width| n.checked_mul(width))
            })
            .and_then(|n| n.checked_add(2))
            .ok_or_else(exhausted)?;
        Ok((bytes, descriptors))
    }

    /// Bounds full selected compact literals and initialized descriptors.
    ///
    /// The caller derives the proposed initialized suffix from its closed
    /// original publication plan. These data cannot reserve bank credit or
    /// authorize traffic. Both per-direction limits and the existing B/F banks
    /// remain unchanged; incomplete current I/O cannot become a completed cut.
    pub(crate) fn selected_initialized_encoding_data(
        &self,
        maximum_retained_bytes: usize,
        maximum_incoming_frames: usize,
        maximum_outgoing_frames: usize,
    ) -> Result<(usize, usize), ProviderError> {
        let exhausted = || {
            ProviderError::ResourceExhausted("selected initialized original frame encoding bound")
        };
        if !self.complete()
            || maximum_retained_bytes < self.bytes.len()
            || maximum_retained_bytes > self.maximum_bytes
            || maximum_incoming_frames < self.incoming
            || maximum_incoming_frames > self.maximum_frames
            || maximum_outgoing_frames < self.outgoing
            || maximum_outgoing_frames > self.maximum_frames
        {
            return Err(exhausted());
        }
        let bytes = maximum_retained_bytes
            .div_ceil(3)
            .checked_mul(4)
            .and_then(|bytes| {
                maximum_retained_bytes
                    .div_ceil(3072)
                    .checked_mul(3)
                    .and_then(|overhead| bytes.checked_add(overhead))
            })
            .and_then(|bytes| bytes.checked_add(64))
            .ok_or_else(exhausted)?;
        let request = [255u8; 128];
        let descriptor = crate::connection::serialized_credit(
            &(
                "outgoing",
                usize::MAX,
                usize::MAX,
                usize::MAX,
                false,
                Some(request.as_slice()),
            ),
            1024,
        )?;
        let descriptors = maximum_incoming_frames
            .checked_add(maximum_outgoing_frames)
            .and_then(|frames| {
                descriptor
                    .checked_add(1)
                    .and_then(|width| frames.checked_mul(width))
            })
            .and_then(|bytes| bytes.checked_add(2))
            .ok_or_else(exhausted)?;
        Ok((bytes, descriptors))
    }

    pub(crate) fn protocol_view(&self) -> impl serde::Serialize + '_ {
        self.protocol_view_with_encoding(false)
    }

    pub(crate) fn protocol_view_with_encoding(&self, compact: bool) -> impl serde::Serialize + '_ {
        (
            &self.maximum_bytes,
            &self.maximum_frames,
            &self.incoming,
            &self.outgoing,
            self.bytes.capacity(),
            self.slots.capacity(),
            crate::protocol_snapshot::ProtocolBytes {
                bytes: &self.bytes,
                compact,
            },
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
        id: &crucible_node_format::Id,
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

#[cfg(test)]
mod after_encoding_bound_tests;

#[cfg(test)]
mod confirmation_suffix_tests {
    // crucible-lint: allow panic-shortcut -- Literal-bank refusal controls deliberately panic on invalid test setup.
    #![allow(clippy::unwrap_used)]

    use super::*;
    use crucible_node_format::Id;

    #[test]
    fn original_confirmation_bank_checks_actual_lifetime_extents_without_mutation() {
        let mut bank = OriginalFrameReservation::reserve(64, 2).unwrap();
        for direction in [FrameDirection::Incoming, FrameDirection::Outgoing] {
            let slot = bank.begin(direction, 5).unwrap();
            bank.append(slot, &[0, 0, 0, 1, b'a']).unwrap();
            bank.retain_request(
                slot,
                &Id::new(if direction == FrameDirection::Incoming {
                    "poll"
                } else {
                    "old-proof"
                })
                .unwrap(),
            )
            .unwrap();
            if direction == FrameDirection::Outgoing {
                bank.advance(slot, 5).unwrap();
            }
            bank.finish(slot).unwrap();
        }
        let original = serde_json::to_vec(&bank.protocol_view()).unwrap();

        assert!(bank.preflight_framed_suffix(1, 20, 1, 34).is_ok());
        assert!(bank.preflight_framed_suffix(1, 20, 1, 35).is_err());
        assert!(bank.preflight_framed_suffix(2, 10, 1, 5).is_err());
        assert!(bank.preflight_framed_suffix(1, usize::MAX, 1, 5).is_err());
        assert!(bank.contains_original_id("poll"));
        assert!(bank.contains_original_id("old-proof"));
        assert!(!bank.contains_original_id("new-proof"));
        assert_eq!(bank.outgoing_original_id_slots(), 1);
        assert_eq!(serde_json::to_vec(&bank.protocol_view()).unwrap(), original);
    }

    #[test]
    fn original_confirmation_bank_refuses_partial_io_without_resetting_slot() {
        let mut bank = OriginalFrameReservation::reserve(64, 2).unwrap();
        let slot = bank.begin(FrameDirection::Incoming, 5).unwrap();
        bank.append(slot, &[0, 0]).unwrap();
        let original = serde_json::to_vec(&bank.protocol_view()).unwrap();

        assert!(bank.preflight_framed_suffix(1, 5, 1, 5).is_err());
        assert_eq!(serde_json::to_vec(&bank.protocol_view()).unwrap(), original);
        assert!(!bank.complete());
    }
}

mod compact_data;
pub use compact_data::{DecodedCompactOriginalFrames, ValidatedCompactOriginalFrames};

pub(crate) fn original_frame_bank_layout() -> usize {
    std::mem::size_of::<std::cell::RefCell<OriginalFrameReservation>>()
}

impl OriginalFrameReservation {
    /// Observes actual backing vectors and every initialized descriptor field.
    ///
    /// Literal bytes and fixed request-ID arrays are already inline in those
    /// charged vectors; their scalar bytes introduce no additional heap banks.
    pub(crate) fn observe_owned11_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        let Self {
            bytes,
            slots,
            maximum_bytes,
            maximum_frames,
            incoming,
            outgoing,
        } = self;
        observer.vector::<u8>(bytes.capacity())?;
        observer.vector::<Slot>(slots.capacity())?;
        observer.observe(maximum_bytes)?;
        observer.observe(maximum_frames)?;
        observer.observe(incoming)?;
        observer.observe(outgoing)?;
        for slot in slots {
            let Slot {
                direction,
                start,
                length,
                transferred,
                complete,
                request,
            } = slot;
            let incoming = match direction {
                FrameDirection::Incoming => true,
                FrameDirection::Outgoing => false,
            };
            observer.observe(&incoming)?;
            observer.observe(start)?;
            observer.observe(length)?;
            observer.observe(transferred)?;
            observer.observe(complete)?;
            // Both the array and its optional discriminator live in Slot. The
            // retained length is scalar metadata, never a String allocation.
            observer.observe(&request.as_ref().map(|(_, length)| *length))?;
        }
        Ok(())
    }
}

/// Reports the actual private descriptor layout to the checked data decoder.
pub(crate) const fn original_frame_slot_layout() -> usize {
    std::mem::size_of::<Slot>()
}

#[cfg(test)]
mod selected_initialized_encoding_tests {
    use super::*;
    type TestResult = Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn selected_initialized_bound_covers_actual_compact_bank_without_using_spare_as_content()
    -> TestResult {
        let mut bank = OriginalFrameReservation::reserve(4096, 16)?;
        for direction in [FrameDirection::Incoming, FrameDirection::Outgoing] {
            let slot = bank.begin(direction, 5)?;
            bank.append(slot, &[0, 0, 0, 1, b'0'])?;
            bank.retain_request(slot, &crucible_node_format::Id::new("original")?)?;
            if direction == FrameDirection::Outgoing {
                bank.advance(slot, 5)?;
            }
            bank.finish(slot)?;
        }
        let original = serde_json::to_vec(&bank.protocol_view_with_encoding(true))?;
        let (literal, descriptors) = bank.selected_initialized_encoding_data(10, 1, 1)?;
        let compact = crate::connection::serialized_credit(
            &crate::protocol_snapshot::ProtocolBytes {
                bytes: &bank.bytes,
                compact: true,
            },
            usize::MAX,
        )?;
        let full = bank.maximum_encoding_growth(true)?;

        assert!(compact <= literal);
        assert!(original.len() <= literal + descriptors + 6 * 20 + 10);
        assert!(literal < full.0);
        assert!(descriptors < full.1);
        assert_eq!(
            serde_json::to_vec(&bank.protocol_view_with_encoding(true))?,
            original
        );
        Ok(())
    }

    #[test]
    fn selected_initialized_bound_refuses_short_direction_bytes_and_partial_io_without_mutation()
    -> TestResult {
        let mut bank = OriginalFrameReservation::reserve(64, 2)?;
        let slot = bank.begin(FrameDirection::Incoming, 5)?;
        bank.append(slot, &[0, 0, 0, 1, b'0'])?;
        let partial = serde_json::to_vec(&bank.protocol_view_with_encoding(true))?;
        assert!(bank.selected_initialized_encoding_data(5, 1, 0).is_err());
        assert_eq!(
            serde_json::to_vec(&bank.protocol_view_with_encoding(true))?,
            partial
        );
        bank.finish(slot)?;
        let complete = serde_json::to_vec(&bank.protocol_view_with_encoding(true))?;
        assert!(bank.selected_initialized_encoding_data(4, 1, 0).is_err());
        assert!(bank.selected_initialized_encoding_data(5, 0, 0).is_err());
        assert!(bank.selected_initialized_encoding_data(65, 1, 0).is_err());
        assert!(bank.selected_initialized_encoding_data(5, 3, 0).is_err());
        assert!(
            bank.selected_initialized_encoding_data(usize::MAX, 1, 0)
                .is_err()
        );
        bank.selected_initialized_encoding_data(5, 1, 0)?;
        assert_eq!(
            serde_json::to_vec(&bank.protocol_view_with_encoding(true))?,
            complete
        );
        Ok(())
    }
}

impl OriginalFrameReservation {
    pub(crate) fn original_outgoing_request_frame_data(
        &self,
        id: &crucible_node_format::Id,
    ) -> Result<OriginalFrame<'_>, ProviderError> {
        let mut slots = self.slots.iter().enumerate().filter(|(_, slot)| {
            slot.direction == FrameDirection::Outgoing
                && slot
                    .request
                    .as_ref()
                    .is_some_and(|(bytes, length)| &bytes[..*length] == id.as_str().as_bytes())
        });
        let (index, _) = slots.next().ok_or(ProviderError::Frame(
            "original outgoing request literal absent",
        ))?;
        if slots.next().is_some() {
            return Err(ProviderError::Frame(
                "original outgoing request literal repeats",
            ));
        }
        self.frame(index).ok_or(ProviderError::Frame(
            "original outgoing request slot absent",
        ))
    }
}

#[cfg(test)]
mod allocation_literal_tests {
    //! Literal-bank DATA custody; no connection or Source rights are modeled.
    use super::*;
    use crucible_node_format::Id;

    #[test]
    fn original_observe_literal_missing_partial_and_complete_preserve_bank() {
        let id = Id::new("observe-data").unwrap();
        let mut bank = OriginalFrameReservation::reserve(4096, 4).unwrap();
        assert!(bank.original_outgoing_request_frame_data(&id).is_err());
        let slot = bank.begin(FrameDirection::Outgoing, 64).unwrap();
        bank.retain_request(slot, &id).unwrap();
        let body = b"{}";
        bank.append(slot, &2u32.to_be_bytes()).unwrap();
        bank.append(slot, body).unwrap();
        let partial = bank.original_outgoing_request_frame_data(&id).unwrap();
        assert!(!partial.complete);
        assert_eq!(partial.transferred, 0);
        let pointer = partial.bytes.as_ptr();
        assert!(
            bank.original_outgoing_request_frame_data(&Id::new("missing").unwrap())
                .is_err()
        );
        assert_eq!(
            bank.original_outgoing_request_frame_data(&id)
                .unwrap()
                .bytes
                .as_ptr(),
            pointer
        );
        bank.advance(slot, body.len() + 4).unwrap();
        bank.finish(slot).unwrap();
        let completed = bank.original_outgoing_request_frame_data(&id).unwrap();
        assert!(completed.complete);
        assert_eq!(completed.transferred, completed.bytes.len());
        assert_eq!(completed.bytes.as_ptr(), pointer);
    }
}

// Defining views used by immutable complete-history and indexed-frame checks.
pub(crate) fn original_history_guard_counter_scratch_data() -> usize {
    std::mem::size_of::<std::slice::Iter<'static, Slot>>()
        + std::mem::size_of::<Option<&'static Slot>>()
        + std::mem::size_of::<&Slot>()
        + std::mem::size_of::<Option<usize>>()
        + std::mem::size_of::<bool>()
}

/// Reports the actual native descriptor alignment for explicit17 capacity rows.
pub(crate) const fn original_frame_slot_alignment_data() -> usize {
    std::mem::align_of::<Slot>()
}

pub(crate) mod current17;

/// Names the exact retained-bank iterator header used by private borrowed scans.
/// This is layout DATA and confers no custody, allocation or protocol right.
pub(crate) const fn original_frames_iterator_counter_scratch_data() -> usize {
    std::mem::size_of::<std::slice::Iter<'static, Slot>>()
        + std::mem::size_of::<&OriginalFrameReservation>()
}

/// Counts the fixed views and checked offset in one retained frame lookup.
///
/// This quotes the defining `frame` method's headers without granting a bank
/// borrow, constructing a frame, or authenticating its transport progress.
pub(crate) const fn original_frame_view_counter_scratch_data() -> usize {
    std::mem::size_of::<&OriginalFrameReservation>()
        + std::mem::size_of::<&Slot>()
        + std::mem::size_of::<Option<&Slot>>()
        + 2 * std::mem::size_of::<usize>()
        + std::mem::size_of::<Option<usize>>()
        + std::mem::size_of::<Option<&[u8]>>()
        + std::mem::size_of::<std::ops::Range<usize>>()
        + std::mem::size_of::<OriginalFrame<'static>>()
        + std::mem::size_of::<Option<OriginalFrame<'static>>>()
}

#[path = "original_frames/retained_reservation.rs"]
mod retained_reservation;
