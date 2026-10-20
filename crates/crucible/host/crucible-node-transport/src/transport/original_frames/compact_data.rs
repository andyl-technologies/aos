//! Reconstructs compact historical literal banks after a borrowed complete preflight.
//!
//! The eight-field tuple retains exact limits, capacities, lifetime counts,
//! raw compact bytes and every slot's progress and request ID. Partial data is
//! retained as partial data. It supplies neither an original physical cut nor
//! a connection installer, source issuer or permission to replay old I/O.
//!
//! ```text
//! [B,F,incoming,outgoing,byte_capacity,slot_capacity,compact_bytes,slots]
//! ```

use super::*;
use crate::protocol_snapshot::compact_bytes::ValidatedCompactBytes;

/// Borrows a fully validated compact historical frame bank.
pub struct ValidatedCompactOriginalFrames<'a> {
    raw: ValidatedCompactBytes<'a>,
    slots: &'a [u8],
    maximum_bytes: usize,
    maximum_frames: usize,
    incoming: usize,
    outgoing: usize,
    byte_capacity: usize,
    slot_capacity: usize,
    allocated_bytes: usize,
}

impl<'a> ValidatedCompactOriginalFrames<'a> {
    /// Names fixed validation controls beside the actual borrowed compact leaf.
    ///
    /// No original byte/descriptor backing is reconstructed by this path. Its
    /// request IDs and frame headers use exactly the declared fixed arrays.
    pub const fn validation_counter_scratch_data() -> usize {
        use std::mem::size_of;
        size_of::<Self>()
            + size_of::<CompactFrameCursor<'static>>()
            + size_of::<Slot>()
            + size_of::<FrameDirection>()
            + size_of::<[u8; 128]>()
            + size_of::<[u8; 4]>()
            + size_of::<Option<([u8; 128], usize)>>()
            + size_of::<Result<Option<([u8; 128], usize)>, ProviderError>>()
            + size_of::<usize>() * 14
            + size_of::<bool>() * 2
            + size_of::<Result<Self, ProviderError>>()
            + size_of::<Result<usize, ProviderError>>()
            + size_of::<Result<(), ProviderError>>()
            + ValidatedCompactBytes::validation_counter_scratch_data()
    }

    /// Checks the complete grammar, capacities, headers and lifetime slot roster.
    ///
    /// All validation precedes byte or descriptor allocation. Parsed request IDs
    /// use fixed stack storage; escaped direction strings are never dispatched
    /// to a serde parser. The immutable encoded input remains borrowed.
    ///
    /// # Errors
    /// Refuses malformed or trailing data, insufficient complete bank allowance,
    /// invalid progress/headers/counts, overflow or differing compact byte lengths.
    pub fn validate(
        input: &'a [u8],
        maximum_input: usize,
        maximum_allocation: usize,
    ) -> Result<Self, ProviderError> {
        if input.len() > maximum_input {
            return Err(Self::credit());
        }
        let mut cursor = CompactFrameCursor::new(input);
        cursor.require(b'[')?;
        let maximum_bytes = cursor.number()?;
        let maximum_frames = cursor.field_number()?;
        let incoming = cursor.field_number()?;
        let outgoing = cursor.field_number()?;
        let byte_capacity = cursor.field_number()?;
        let slot_capacity = cursor.field_number()?;
        let allocated_bytes = slot_capacity
            .checked_mul(std::mem::size_of::<Slot>())
            .and_then(|bytes| bytes.checked_add(byte_capacity))
            .ok_or_else(Self::credit)?;
        if !(4..=MAX_ORIGINAL_FRAME_BYTES).contains(&maximum_bytes)
            || !(1..=MAX_ORIGINAL_FRAMES_PER_DIRECTION).contains(&maximum_frames)
            || incoming > maximum_frames
            || outgoing > maximum_frames
            || byte_capacity < maximum_bytes
            || byte_capacity > MAX_ORIGINAL_FRAME_BYTES
            || slot_capacity < maximum_frames * 2
            || slot_capacity > MAX_ORIGINAL_FRAMES_PER_DIRECTION * 2
            || allocated_bytes > maximum_allocation
        {
            return Err(Self::credit());
        }
        cursor.require(b',')?;
        cursor.whitespace();
        let raw_start = cursor.position;
        // Only fixed compact-byte grammar is permitted here. Its complete leaf
        // validation rejects unknown tags, escapes, padding and length mismatch.
        cursor.require(b'[')?;
        cursor.require(b'"')?;
        while cursor
            .input
            .get(cursor.position)
            .is_some_and(|byte| *byte != b'"')
        {
            if matches!(cursor.input[cursor.position], b'\\' | 0..=31) {
                return Err(Self::invalid());
            }
            cursor.position += 1;
        }
        cursor.require(b'"')?;
        cursor.require(b',')?;
        cursor.number()?;
        cursor.require(b',')?;
        cursor.require(b'[')?;
        if !cursor.take(b']') {
            loop {
                cursor.require(b'"')?;
                while cursor
                    .input
                    .get(cursor.position)
                    .is_some_and(|byte| *byte != b'"')
                {
                    if matches!(cursor.input[cursor.position], b'\\' | 0..=31) {
                        return Err(Self::invalid());
                    }
                    cursor.position += 1;
                }
                cursor.require(b'"')?;
                if cursor.take(b']') {
                    break;
                }
                cursor.require(b',')?;
            }
        }
        cursor.require(b']')?;
        let raw = ValidatedCompactBytes::validate(
            &input[raw_start..cursor.position],
            maximum_input,
            maximum_bytes,
        )?;
        cursor.require(b',')?;
        let slot_start = cursor.position;
        let mut plan = Self {
            raw,
            slots: &[],
            maximum_bytes,
            maximum_frames,
            incoming,
            outgoing,
            byte_capacity,
            slot_capacity,
            allocated_bytes,
        };
        plan.walk_slots(&mut cursor, |_| {})?;
        plan.slots = &input[slot_start..cursor.position];
        cursor.require(b']')?;
        cursor.whitespace();
        if cursor.position != input.len() {
            return Err(Self::invalid());
        }
        Ok(plan)
    }

    /// Reports both explicitly admitted original-capacity data banks.
    pub const fn allocated_bytes(&self) -> usize {
        self.allocated_bytes
    }

    /// Builds exactly two final historical data banks with the recorded capacities.
    ///
    /// The whole-owner caller admits this requested storage separately from
    /// allocator rounding, stack storage and original live ownership. No fresh
    /// lifetime allowance or current registration is created by reconstruction.
    ///
    /// # Errors
    /// Refuses failed or differing exact reservations. The encoded owner remains
    /// borrowed on every refusal and no connection is modified.
    pub fn reconstruct(&self) -> Result<DecodedCompactOriginalFrames, ProviderError> {
        let mut bytes = Vec::new();
        let mut slots = Vec::new();
        bytes
            .try_reserve_exact(self.byte_capacity)
            .map_err(|_| Self::credit())?;
        slots
            .try_reserve_exact(self.slot_capacity)
            .map_err(|_| Self::credit())?;
        if bytes.capacity() != self.byte_capacity || slots.capacity() != self.slot_capacity {
            return Err(Self::credit());
        }
        self.raw.fill_preowned(&mut bytes)?;
        let mut cursor = CompactFrameCursor::new(self.slots);
        self.walk_slots(&mut cursor, |slot| slots.push(slot))?;
        Ok(DecodedCompactOriginalFrames {
            bank: OriginalFrameReservation {
                bytes,
                slots,
                maximum_bytes: self.maximum_bytes,
                maximum_frames: self.maximum_frames,
                incoming: self.incoming,
                outgoing: self.outgoing,
            },
        })
    }

    fn walk_slots(
        &self,
        cursor: &mut CompactFrameCursor<'_>,
        mut retain: impl FnMut(Slot),
    ) -> Result<(), ProviderError> {
        cursor.require(b'[')?;
        let mut incoming = 0usize;
        let mut outgoing = 0usize;
        let mut end = 0usize;
        let mut count = 0usize;
        if !cursor.take(b']') {
            loop {
                count = count.checked_add(1).ok_or_else(Self::invalid)?;
                if count > self.slot_capacity {
                    return Err(Self::invalid());
                }
                cursor.require(b'[')?;
                let direction = if cursor.literal(b"\"incoming\"") {
                    incoming += 1;
                    FrameDirection::Incoming
                } else if cursor.literal(b"\"outgoing\"") {
                    outgoing += 1;
                    FrameDirection::Outgoing
                } else {
                    return Err(Self::invalid());
                };
                let start = cursor.field_number()?;
                let length = cursor.field_number()?;
                let transferred = cursor.field_number()?;
                cursor.require(b',')?;
                let complete = if cursor.literal(b"true") {
                    true
                } else if cursor.literal(b"false") {
                    false
                } else {
                    return Err(Self::invalid());
                };
                cursor.require(b',')?;
                let request = cursor.request()?;
                cursor.require(b']')?;
                let next = start
                    .checked_add(length)
                    .filter(|next| *next <= self.raw.decoded_length())
                    .ok_or_else(Self::invalid)?;
                if start != end
                    || transferred > length
                    || incoming > self.maximum_frames
                    || outgoing > self.maximum_frames
                    || (direction == FrameDirection::Incoming && transferred != length)
                    || (complete && (length < 5 || transferred != length))
                {
                    return Err(Self::invalid());
                }
                if length >= 4 {
                    let mut header = [0; 4];
                    self.raw.copy_range(start, &mut header)?;
                    let declared = u32::from_be_bytes(header) as usize;
                    if declared == 0
                        || (complete && declared != length - 4)
                        || (!complete && length - 4 > declared)
                        || (direction == FrameDirection::Outgoing && declared != length - 4)
                    {
                        return Err(Self::invalid());
                    }
                } else if direction == FrameDirection::Outgoing && length != 0 {
                    return Err(Self::invalid());
                }
                retain(Slot {
                    direction,
                    start,
                    length,
                    transferred,
                    complete,
                    request,
                });
                end = next;
                if cursor.take(b']') {
                    break;
                }
                cursor.require(b',')?;
            }
        }
        if end != self.raw.decoded_length()
            || incoming != self.incoming
            || outgoing != self.outgoing
        {
            return Err(Self::invalid());
        }
        Ok(())
    }

    fn invalid() -> ProviderError {
        ProviderError::Frame("compact historical frame grammar")
    }
    fn credit() -> ProviderError {
        ProviderError::ResourceExhausted("compact historical frame banks")
    }
}

/// Owns historical compact frame data without a live connection association.
pub struct DecodedCompactOriginalFrames {
    bank: OriginalFrameReservation,
}

impl DecodedCompactOriginalFrames {
    /// Borrows all historical raw slots and their unchanged transport progress.
    pub fn frames(&self) -> impl Iterator<Item = OriginalFrame<'_>> {
        self.bank.frames()
    }

    /// Borrows one exact historical slot without scanning preceding descriptors.
    pub fn frame(&self, index: usize) -> Option<OriginalFrame<'_>> {
        self.bank.frame(index)
    }

    /// Reports the final byte and descriptor vector capacities together.
    pub fn allocated_bytes(&self) -> usize {
        self.bank.allocated_bytes()
    }

    /// Counts one complete historical prefix with the original bank capacities.
    ///
    /// Later appended slots remain outside the saved cut. This data-only loan
    /// neither renews lifetime credit nor reconstructs a live receiving phase.
    pub(crate) fn original_storage_prefix_data(
        &self,
        last_slot: usize,
        maximum_frame_bytes: usize,
    ) -> Result<crate::protocol_snapshot::OriginalProtocolStorageFacts, ProviderError> {
        let count = last_slot
            .checked_add(1)
            .ok_or_else(CompactFrameCursor::invalid)?;
        let prefix = self
            .bank
            .slots
            .get(..count)
            .ok_or_else(CompactFrameCursor::invalid)?;
        let mut facts = self.bank.storage_facts(maximum_frame_bytes);
        facts.retained_bytes = 0;
        facts.incoming_frames = 0;
        facts.outgoing_frames = 0;
        facts.all_io_complete = true;
        for slot in prefix {
            if !slot.complete
                || slot.transferred != slot.length
                || slot.start != facts.retained_bytes
            {
                return Err(CompactFrameCursor::invalid());
            }
            facts.retained_bytes = facts
                .retained_bytes
                .checked_add(slot.length)
                .ok_or_else(CompactFrameCursor::invalid)?;
            let direction = match slot.direction {
                FrameDirection::Incoming => &mut facts.incoming_frames,
                FrameDirection::Outgoing => &mut facts.outgoing_frames,
            };
            *direction = direction
                .checked_add(1)
                .ok_or_else(CompactFrameCursor::invalid)?;
        }
        Ok(facts)
    }
}

struct CompactFrameCursor<'a> {
    input: &'a [u8],
    position: usize,
}

impl<'a> CompactFrameCursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, position: 0 }
    }

    fn invalid() -> ProviderError {
        ProviderError::Frame("invalid bounded original frame data")
    }

    fn whitespace(&mut self) {
        while self
            .input
            .get(self.position)
            .is_some_and(|byte| matches!(byte, b' ' | b'\t' | b'\r' | b'\n'))
        {
            self.position += 1;
        }
    }

    fn take(&mut self, byte: u8) -> bool {
        self.whitespace();
        if self.input.get(self.position) == Some(&byte) {
            self.position += 1;
            true
        } else {
            false
        }
    }

    fn require(&mut self, byte: u8) -> Result<(), ProviderError> {
        if self.take(byte) {
            Ok(())
        } else {
            Err(Self::invalid())
        }
    }

    fn literal(&mut self, literal: &[u8]) -> bool {
        self.whitespace();
        if self.input[self.position..].starts_with(literal) {
            self.position += literal.len();
            true
        } else {
            false
        }
    }

    fn number(&mut self) -> Result<usize, ProviderError> {
        self.whitespace();
        let first = *self.input.get(self.position).ok_or_else(Self::invalid)?;
        if !first.is_ascii_digit() {
            return Err(Self::invalid());
        }
        self.position += 1;
        let mut number = usize::from(first - b'0');
        while let Some(byte) = self
            .input
            .get(self.position)
            .filter(|byte| byte.is_ascii_digit())
        {
            if first == b'0' {
                return Err(Self::invalid());
            }
            number = number
                .checked_mul(10)
                .and_then(|number| number.checked_add(usize::from(*byte - b'0')))
                .ok_or_else(Self::invalid)?;
            self.position += 1;
        }
        Ok(number)
    }

    fn field_number(&mut self) -> Result<usize, ProviderError> {
        self.require(b',')?;
        self.number()
    }

    fn byte(&mut self) -> Result<u8, ProviderError> {
        u8::try_from(self.number()?).map_err(|_| Self::invalid())
    }

    fn request(&mut self) -> Result<Option<([u8; 128], usize)>, ProviderError> {
        if self.literal(b"null") {
            return Ok(None);
        }
        self.require(b'[')?;
        let mut bytes = [0; 128];
        let mut length = 0;
        if self.take(b']') {
            return Err(Self::invalid());
        }
        loop {
            if length == bytes.len() {
                return Err(Self::invalid());
            }
            bytes[length] = self.byte()?;
            length += 1;
            if self.take(b']') {
                break;
            }
            self.require(b',')?;
        }
        if !bytes[0].is_ascii_alphanumeric()
            || !bytes[..length]
                .iter()
                .all(|byte| byte.is_ascii_alphanumeric() || b"._:/-".contains(byte))
        {
            return Err(Self::invalid());
        }
        Ok(Some((bytes, length)))
    }
}

#[cfg(test)]
#[expect(
    clippy::unwrap_used,
    reason = "historical banks preserve exact bytes, progress and capacities"
)]
mod tests {
    use super::*;

    #[test]
    fn complete_and_partial_originals_keep_exact_capacities_and_lifetime_counts() {
        let mut original = OriginalFrameReservation::reserve(8192, 8).unwrap();
        let incoming = original.begin(FrameDirection::Incoming, 8192).unwrap();
        original.append(incoming, b"\0\0\0\x02{}").unwrap();
        original.finish(incoming).unwrap();
        let outgoing = original.begin(FrameDirection::Outgoing, 8192 - 6).unwrap();
        original.append(outgoing, b"\0\0\0\x03abc").unwrap();
        original.advance(outgoing, 2).unwrap();
        let encoded = serde_json::to_vec(&original.protocol_view_with_encoding(true)).unwrap();
        let plan = ValidatedCompactOriginalFrames::validate(
            &encoded,
            encoded.len(),
            original.allocated_bytes(),
        )
        .unwrap();
        let restored = plan.reconstruct().unwrap();

        assert_eq!(restored.allocated_bytes(), original.allocated_bytes());
        assert_eq!(restored.bank.bytes.capacity(), original.bytes.capacity());
        assert_eq!(restored.bank.slots.capacity(), original.slots.capacity());
        assert_eq!(restored.bank.incoming, 1);
        assert_eq!(restored.bank.outgoing, 1);
        assert_eq!(
            serde_json::to_vec(&restored.bank.protocol_view_with_encoding(true)).unwrap(),
            encoded
        );
        assert!(!restored.frames().nth(1).unwrap().complete);
        assert_eq!(restored.frames().nth(1).unwrap().transferred, 2);
        assert!(
            ValidatedCompactOriginalFrames::validate(
                &encoded,
                encoded.len(),
                original.allocated_bytes() - 1
            )
            .is_err()
        );
    }

    #[test]
    fn truncated_header_and_empty_spare_banks_remain_data_only() {
        for partial in [b"".as_slice(), b"\0", b"\0\0\0"] {
            let mut original = OriginalFrameReservation::reserve(64, 2).unwrap();
            let slot = original.begin(FrameDirection::Incoming, 64).unwrap();
            original.append(slot, partial).unwrap();
            let encoded = serde_json::to_vec(&original.protocol_view_with_encoding(true)).unwrap();
            let plan = ValidatedCompactOriginalFrames::validate(
                &encoded,
                encoded.len(),
                original.allocated_bytes(),
            )
            .unwrap();
            let restored = plan.reconstruct().unwrap();
            assert_eq!(restored.bank.bytes.capacity(), 64);
            assert_eq!(restored.bank.slots.capacity(), 4);
            assert_eq!(restored.frames().next().unwrap().bytes, partial);
            assert!(!restored.frames().next().unwrap().complete);
        }
        let empty = OriginalFrameReservation::reserve(64, 2).unwrap();
        let encoded = serde_json::to_vec(&empty.protocol_view_with_encoding(true)).unwrap();
        let restored = ValidatedCompactOriginalFrames::validate(
            &encoded,
            encoded.len(),
            empty.allocated_bytes(),
        )
        .unwrap()
        .reconstruct()
        .unwrap();
        assert_eq!(restored.bank.bytes.capacity(), 64);
        assert_eq!(restored.bank.slots.capacity(), 4);
        assert!(restored.frames().next().is_none());
    }
}

#[cfg(test)]
mod historical_prefix_tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn append(
        bank: &mut OriginalFrameReservation,
        direction: FrameDirection,
        body: &[u8],
    ) -> Result<usize, ProviderError> {
        let slot = bank.begin(direction, bank.maximum_bytes - bank.bytes.len())?;
        bank.append(
            slot,
            &u32::try_from(body.len())
                .map_err(|_| CompactFrameCursor::invalid())?
                .to_be_bytes(),
        )?;
        bank.append(slot, body)?;
        if direction == FrameDirection::Outgoing {
            bank.advance(slot, body.len() + 4)?;
        }
        bank.finish(slot)?;
        Ok(slot)
    }

    #[test]
    fn saved_prefix_keeps_original_capacities_after_real_appended_slots() -> TestResult {
        let mut bank = OriginalFrameReservation::reserve(8192, 8)?;
        append(&mut bank, FrameDirection::Outgoing, b"hello")?;
        let observe = append(&mut bank, FrameDirection::Incoming, b"observe")?;
        let saved = bank.storage_facts(65536);
        append(&mut bank, FrameDirection::Outgoing, b"proof")?;
        append(&mut bank, FrameDirection::Incoming, b"ack")?;
        let restored = DecodedCompactOriginalFrames { bank };

        assert_eq!(
            restored.original_storage_prefix_data(observe, 65536)?,
            saved
        );
        assert_ne!(restored.bank.storage_facts(65536), saved);
        for changed in [
            crate::protocol_snapshot::OriginalProtocolStorageFacts {
                retained_bytes: saved.retained_bytes + 1,
                ..saved
            },
            crate::protocol_snapshot::OriginalProtocolStorageFacts {
                incoming_frames: saved.incoming_frames + 1,
                ..saved
            },
            crate::protocol_snapshot::OriginalProtocolStorageFacts {
                byte_capacity: saved.byte_capacity + 1,
                ..saved
            },
        ] {
            assert_ne!(
                restored.original_storage_prefix_data(observe, 65536)?,
                changed
            );
        }
        Ok(())
    }

    #[test]
    fn incomplete_suffix_cannot_replace_an_incomplete_saved_prefix() -> TestResult {
        let mut bank = OriginalFrameReservation::reserve(8192, 8)?;
        let observe = append(&mut bank, FrameDirection::Incoming, b"observe")?;
        let saved = bank.storage_facts(65536);
        let partial = bank.begin(FrameDirection::Incoming, 4096)?;
        bank.append(partial, b"\0\0")?;
        let restored = DecodedCompactOriginalFrames { bank };

        assert_eq!(
            restored.original_storage_prefix_data(observe, 65536)?,
            saved
        );
        assert!(
            restored
                .original_storage_prefix_data(partial, 65536)
                .is_err()
        );
        assert!(
            restored
                .original_storage_prefix_data(usize::MAX, 65536)
                .is_err()
        );
        assert!(
            restored
                .original_storage_prefix_data(partial + 1, 65536)
                .is_err()
        );
        Ok(())
    }
}

impl DecodedCompactOriginalFrames {
    pub(crate) fn observe_historical_retained_metadata(
        &self,
        observer: &mut crate::retained_metadata::MetadataObserver,
    ) -> Result<(), ProviderError> {
        self.bank.observe_owned11_metadata(observer)
    }
}

impl ValidatedCompactOriginalFrames<'_> {
    /// Adds the exact final byte/descriptor vectors to the optional native17 plan.
    ///
    /// # Errors
    /// Refuses overflow or target backing beyond the caller's finite admission.
    pub(crate) fn native17_target_data(
        &self,
        ledger: &mut crate::protocol_snapshot::owned11::typed::Ledger<'_, '_, '_>,
    ) -> Result<(), ProviderError> {
        ledger.native17_target_vector_data::<u8>(self.byte_capacity)?;
        ledger.native17_target_vector_data::<Slot>(self.slot_capacity)
    }
}

pub(crate) mod current17;
