//! Stable ring snapshots and bounded snapshot decoding.

use super::*;

/// A compact, process-private frame record used by quiescent ring snapshots.
///
/// Unlike [`FrameEntry`], this representation stores only the valid payload.
/// A hostile canonical checkpoint therefore cannot amplify a short frame into
/// the full shared-memory slot size before the destination ring is restored.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SnapshotFrameEntry {
    /// The consumer icount at which the frame becomes visible.
    pub delivery_icount: u64,
    /// The producer node id.
    pub src_node: u32,
    /// The per-producer sequence number.
    pub seq: u32,
    /// The number of valid payload bytes.
    pub len: u16,
    delivery_state: u8,
    delivery_attempts: u32,
    last_delivery_attempt_icount: u64,
    /// The valid payload bytes, with no fixed-capacity unused tail.
    pub data: Vec<u8>,
}

impl SnapshotFrameEntry {
    pub(super) fn from_live(frame: &FrameEntry) -> Result<Self, SpscRingError> {
        let canonical = frame.canonicalized_for_snapshot()?;
        let len = usize::from(canonical.len);
        let delivery_state = canonical.delivery_state().map_err(
            |FrameDeliveryStateError::UnknownState { state }| {
                SpscRingError::InvalidFrameDeliveryState { state }
            },
        )? as u8;
        let mut data = Vec::new();
        data.try_reserve_exact(len)
            .map_err(|_| SpscRingError::SnapshotPayloadAllocationFailed { len })?;
        data.extend_from_slice(&canonical.data[..len]);
        Ok(Self {
            delivery_icount: canonical.delivery_icount,
            src_node: canonical.src_node,
            seq: canonical.seq,
            len: canonical.len,
            delivery_state,
            delivery_attempts: canonical.delivery_attempts(),
            last_delivery_attempt_icount: canonical.last_delivery_attempt_icount(),
            data,
        })
    }

    fn validate(&self) -> Result<FrameDeliveryState, SpscRingError> {
        let len = usize::from(self.len);
        if len > MAX_FRAME_DATA || len != self.data.len() {
            return Err(SpscRingError::InvalidFrameLength {
                len,
                capacity: MAX_FRAME_DATA,
            });
        }
        let state = match self.delivery_state {
            FRAME_DELIVERY_PENDING => FrameDeliveryState::Pending,
            FRAME_DELIVERY_RETAINED => FrameDeliveryState::Retained,
            state => return Err(SpscRingError::InvalidFrameDeliveryState { state }),
        };
        match state {
            FrameDeliveryState::Pending
                if self.delivery_attempts != 0 || self.last_delivery_attempt_icount != 0 =>
            {
                return Err(SpscRingError::InvalidFrameDeliveryAttempts {
                    state: self.delivery_state,
                    attempts: self.delivery_attempts,
                });
            }
            FrameDeliveryState::Retained
                if self.delivery_attempts == 0
                    || self.delivery_attempts > MAX_FRAME_DELIVERY_ATTEMPTS =>
            {
                return Err(SpscRingError::InvalidFrameDeliveryAttempts {
                    state: self.delivery_state,
                    attempts: self.delivery_attempts,
                });
            }
            FrameDeliveryState::Retained
                if self.last_delivery_attempt_icount < self.delivery_icount =>
            {
                return Err(SpscRingError::InvalidFrameDeliveryAttemptIcount {
                    delivery_icount: self.delivery_icount,
                    attempt_icount: self.last_delivery_attempt_icount,
                });
            }
            _ => {}
        }
        Ok(state)
    }

    pub(super) fn to_live(&self) -> Result<FrameEntry, SpscRingError> {
        let state = self.validate()?;
        let frame = FrameEntry::new(self.delivery_icount, self.src_node, self.seq, &self.data)
            .map_err(
                |FrameEntryError::PayloadLengthExceedsCapacity { len, capacity }| {
                    SpscRingError::InvalidFrameLength { len, capacity }
                },
            )?;
        if state == FrameDeliveryState::Retained {
            frame.mark_delivery_retained().map_err(
                |FrameDeliveryStateError::UnknownState { state }| {
                    SpscRingError::InvalidFrameDeliveryState { state }
                },
            )?;
        }
        frame.restore_delivery_attempt(self.delivery_attempts, self.last_delivery_attempt_icount);
        Ok(frame)
    }

    /// Returns the consumer-owned canonical delivery state.
    ///
    /// # Errors
    ///
    /// Returns [`FrameDeliveryStateError::UnknownState`] when the stored state
    /// byte is not defined by this ABI version.
    pub fn delivery_state(&self) -> Result<FrameDeliveryState, FrameDeliveryStateError> {
        match self.delivery_state {
            FRAME_DELIVERY_PENDING => Ok(FrameDeliveryState::Pending),
            FRAME_DELIVERY_RETAINED => Ok(FrameDeliveryState::Retained),
            state => Err(FrameDeliveryStateError::UnknownState { state }),
        }
    }

    /// Returns the number of concrete guest delivery attempts.
    #[must_use]
    pub const fn delivery_attempts(&self) -> u32 {
        self.delivery_attempts
    }

    /// Returns the coordinate of the most recent guest delivery attempt.
    #[must_use]
    pub const fn last_delivery_attempt_icount(&self) -> u64 {
        self.last_delivery_attempt_icount
    }

    /// Returns the deterministic per-consumer delivery-order key.
    #[must_use]
    pub const fn delivery_key(&self) -> FrameDeliveryKey {
        FrameDeliveryKey {
            delivery_icount: self.delivery_icount,
            src_node: self.src_node,
            seq: self.seq,
        }
    }

    /// Returns the valid payload bytes.
    ///
    /// # Errors
    ///
    /// Compact snapshot construction validates the payload length, so this
    /// method currently always succeeds and retains parity with [`FrameEntry`].
    pub fn payload(&self) -> Result<&[u8], FrameEntryError> {
        Ok(&self.data)
    }

    /// Returns `true`; compact snapshots contain no padding bytes.
    #[must_use]
    pub const fn padding_bytes_are_zero(&self) -> bool {
        true
    }
}

impl PartialEq<FrameEntry> for SnapshotFrameEntry {
    fn eq(&self, other: &FrameEntry) -> bool {
        self.delivery_icount == other.delivery_icount
            && self.src_node == other.src_node
            && self.seq == other.seq
            && self.len == other.len
            && self.delivery_state() == other.delivery_state()
            && self.delivery_attempts == other.delivery_attempts()
            && self.last_delivery_attempt_icount == other.last_delivery_attempt_icount()
            && other.payload().is_ok_and(|payload| self.data == payload)
    }
}

/// A quiescent FIFO snapshot of an SPSC ring.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpscRingSnapshot {
    /// Live frames in `read_idx..write_idx` FIFO order.
    pub frames: Vec<SnapshotFrameEntry>,
}

impl SpscRingSnapshot {
    const CANONICAL_FRAME_METADATA_BYTES: usize = 8 + 4 + 4 + 2 + 1 + 4 + 8;

    /// Builds a compact snapshot from live shared-memory frames.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when any source frame is not canonicalizable.
    pub fn from_live_frames(frames: &[FrameEntry]) -> Result<Self, SpscRingError> {
        let mut compact = Vec::new();
        compact.try_reserve_exact(frames.len()).map_err(|_| {
            SpscRingError::SnapshotAllocationFailed {
                count: frames.len(),
            }
        })?;
        for frame in frames {
            compact.push(SnapshotFrameEntry::from_live(frame)?);
        }
        Ok(Self { frames: compact })
    }

    /// Serializes the live frames into padding-independent canonical bytes.
    ///
    /// The encoding is little-endian and contains the frame count followed by
    /// each frame's delivery icount, source node, sequence, payload length,
    /// consumer-owned delivery state, delivery-attempt count, and valid payload
    /// bytes. Frame padding and unused payload capacity are excluded so
    /// equivalent logical snapshots content-address identically.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError::InvalidFrameLength`] when any frame advertises a
    /// payload length larger than [`MAX_FRAME_DATA`], or
    /// [`SpscRingError::SnapshotLengthOverflow`] when the frame count cannot fit
    /// in the canonical encoding, or
    /// [`SpscRingError::SnapshotByteAllocationFailed`] when the exact bounded
    /// canonical representation cannot be reserved.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SpscRingError> {
        let encoded_len = self.canonical_len()?;
        let mut bytes = Vec::new();
        bytes
            .try_reserve_exact(encoded_len)
            .map_err(|_| SpscRingError::SnapshotByteAllocationFailed { len: encoded_len })?;
        self.append_canonical_bytes(&mut bytes)?;
        Ok(bytes)
    }

    /// Appends the canonical representation to an enclosing byte buffer.
    ///
    /// The method reserves only the exact additional length. An enclosing codec
    /// that has already reserved its complete representation therefore streams
    /// the ring directly into that allocation without a temporary ring-sized
    /// byte vector.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when a frame is noncanonical, its encoded
    /// length overflows, or the additional byte capacity cannot be reserved.
    pub fn append_canonical_bytes(&self, bytes: &mut Vec<u8>) -> Result<(), SpscRingError> {
        let encoded_len = self.canonical_len()?;
        let frame_count = u64::try_from(self.frames.len()).map_err(|_| {
            SpscRingError::SnapshotLengthOverflow {
                len: self.frames.len(),
            }
        })?;
        bytes
            .try_reserve_exact(encoded_len)
            .map_err(|_| SpscRingError::SnapshotByteAllocationFailed { len: encoded_len })?;
        bytes.extend_from_slice(&frame_count.to_le_bytes());
        for canonical in &self.frames {
            let delivery_state = canonical.validate()?;
            let payload_len = usize::from(canonical.len);
            bytes.extend_from_slice(&canonical.delivery_icount.to_le_bytes());
            bytes.extend_from_slice(&canonical.src_node.to_le_bytes());
            bytes.extend_from_slice(&canonical.seq.to_le_bytes());
            bytes.extend_from_slice(&canonical.len.to_le_bytes());
            bytes.push(delivery_state as u8);
            bytes.extend_from_slice(&canonical.delivery_attempts.to_le_bytes());
            bytes.extend_from_slice(&canonical.last_delivery_attempt_icount.to_le_bytes());
            bytes.extend_from_slice(&canonical.data[..payload_len]);
        }
        Ok(())
    }

    /// Returns the exact length of the canonical byte representation.
    ///
    /// This validates every compact frame without allocating the encoded byte
    /// stream, allowing an enclosing checkpoint codec to enforce its own
    /// aggregate limit before reserving memory.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when a frame is noncanonical or when the
    /// encoded length cannot fit in `usize`.
    pub fn canonical_len(&self) -> Result<usize, SpscRingError> {
        let mut encoded_len = core::mem::size_of::<u64>();
        for frame in &self.frames {
            frame.validate()?;
            encoded_len = encoded_len
                .checked_add(Self::CANONICAL_FRAME_METADATA_BYTES)
                .and_then(|len| len.checked_add(frame.data.len()))
                .ok_or(SpscRingError::SnapshotLengthOverflow {
                    len: self.frames.len(),
                })?;
        }
        Ok(encoded_len)
    }

    /// Decodes a snapshot from [`SpscRingSnapshot::canonical_bytes`].
    ///
    /// The decoder accepts only the canonical little-endian byte stream and
    /// rejects truncated frames, impossible payload lengths, and trailing bytes.
    /// Decoded frames retain only valid payload bytes. Fixed-capacity
    /// [`FrameEntry`] slots are rebuilt only when restoring into a destination
    /// ring.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError::SnapshotDecodeTruncated`] when the byte stream
    /// ends before a field or payload is complete,
    /// [`SpscRingError::InvalidFrameLength`] when a frame length exceeds
    /// [`MAX_FRAME_DATA`], [`SpscRingError::SnapshotFrameCountOverflow`] when
    /// the encoded frame count cannot fit in memory on this target, or
    /// [`SpscRingError::SnapshotAllocationFailed`] when the bounded decoded
    /// metadata cannot be reserved,
    /// [`SpscRingError::SnapshotPayloadAllocationFailed`] when a valid payload
    /// cannot be reserved, or
    /// [`SpscRingError::SnapshotDecodeTrailingBytes`] when extra bytes remain
    /// after the declared frames.
    pub fn from_canonical_bytes(bytes: &[u8], max_frames: usize) -> Result<Self, SpscRingError> {
        let mut cursor = SnapshotByteCursor::new(bytes);
        let frame_count = cursor.read_u64()?;
        let frame_count = usize::try_from(frame_count)
            .map_err(|_| SpscRingError::SnapshotFrameCountOverflow { count: frame_count })?;
        if frame_count > max_frames {
            return Err(SpscRingError::SnapshotTooLarge {
                len: frame_count,
                capacity: max_frames as u64,
            });
        }
        let minimum_body_bytes = frame_count
            .checked_mul(Self::CANONICAL_FRAME_METADATA_BYTES)
            .ok_or(SpscRingError::SnapshotFrameCountOverflow {
                count: frame_count as u64,
            })?;
        let available_body_bytes = bytes.len().saturating_sub(core::mem::size_of::<u64>());
        if minimum_body_bytes > available_body_bytes {
            return Err(SpscRingError::SnapshotDecodeTruncated {
                offset: core::mem::size_of::<u64>(),
                needed: minimum_body_bytes,
                available: available_body_bytes,
            });
        }
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(frame_count)
            .map_err(|_| SpscRingError::SnapshotAllocationFailed { count: frame_count })?;

        for _ in 0..frame_count {
            let delivery_icount = cursor.read_u64()?;
            let src_node = cursor.read_u32()?;
            let seq = cursor.read_u32()?;
            let len = usize::from(cursor.read_u16()?);
            let delivery_state = cursor.read_u8()?;
            let delivery_attempts = cursor.read_u32()?;
            let last_delivery_attempt_icount = cursor.read_u64()?;
            if len > MAX_FRAME_DATA {
                return Err(SpscRingError::InvalidFrameLength {
                    len,
                    capacity: MAX_FRAME_DATA,
                });
            }
            let payload = cursor.read_bytes(len)?;
            let mut data = Vec::new();
            data.try_reserve_exact(len)
                .map_err(|_| SpscRingError::SnapshotPayloadAllocationFailed { len })?;
            data.extend_from_slice(payload);
            let frame = SnapshotFrameEntry {
                delivery_icount,
                src_node,
                seq,
                len: len as u16,
                delivery_state,
                delivery_attempts,
                last_delivery_attempt_icount,
                data,
            };
            frame.validate()?;
            frames.push(frame);
        }

        cursor.finish()?;
        Ok(Self { frames })
    }
}

pub(super) struct SnapshotByteCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SnapshotByteCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_u16(&mut self) -> Result<u16, SpscRingError> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u8(&mut self) -> Result<u8, SpscRingError> {
        Ok(self.read_bytes(1)?[0])
    }

    fn read_u32(&mut self) -> Result<u32, SpscRingError> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64(&mut self) -> Result<u64, SpscRingError> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], SpscRingError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(SpscRingError::SnapshotDecodeTruncated {
                offset: self.offset,
                needed: len,
                available: self.bytes.len().saturating_sub(self.offset),
            })?;
        if end > self.bytes.len() {
            return Err(SpscRingError::SnapshotDecodeTruncated {
                offset: self.offset,
                needed: len,
                available: self.bytes.len().saturating_sub(self.offset),
            });
        }
        let bytes = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn finish(&self) -> Result<(), SpscRingError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(SpscRingError::SnapshotDecodeTrailingBytes {
                offset: self.offset,
                available: self.bytes.len() - self.offset,
            })
        }
    }
}
