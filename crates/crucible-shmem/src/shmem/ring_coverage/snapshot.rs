//! Stable ring snapshots and bounded snapshot decoding.

use super::*;

/// A quiescent FIFO snapshot of an SPSC ring.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpscRingSnapshot {
    /// Live frames in `read_idx..write_idx` FIFO order.
    pub frames: Vec<FrameEntry>,
}

impl SpscRingSnapshot {
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
    /// in the canonical encoding.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SpscRingError> {
        let frame_count = u64::try_from(self.frames.len()).map_err(|_| {
            SpscRingError::SnapshotLengthOverflow {
                len: self.frames.len(),
            }
        })?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&frame_count.to_le_bytes());
        for frame in &self.frames {
            let canonical = frame.canonicalized_for_snapshot()?;
            let payload_len = usize::from(canonical.len);
            bytes.extend_from_slice(&canonical.delivery_icount.to_le_bytes());
            bytes.extend_from_slice(&canonical.src_node.to_le_bytes());
            bytes.extend_from_slice(&canonical.seq.to_le_bytes());
            bytes.extend_from_slice(&canonical.len.to_le_bytes());
            let delivery_state = canonical.delivery_state().map_err(
                |FrameDeliveryStateError::UnknownState { state }| {
                    SpscRingError::InvalidFrameDeliveryState { state }
                },
            )?;
            bytes.push(delivery_state as u8);
            bytes.extend_from_slice(&canonical.delivery_attempts().to_le_bytes());
            bytes.extend_from_slice(&canonical.data[..payload_len]);
        }
        Ok(bytes)
    }

    /// Decodes a snapshot from [`SpscRingSnapshot::canonical_bytes`].
    ///
    /// The decoder accepts only the canonical little-endian byte stream and
    /// rejects truncated frames, impossible payload lengths, and trailing bytes.
    /// Decoded frames are rebuilt through [`FrameEntry::new`] so padding and
    /// unused payload capacity are normalized before the snapshot is returned.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError::SnapshotDecodeTruncated`] when the byte stream
    /// ends before a field or payload is complete,
    /// [`SpscRingError::InvalidFrameLength`] when a frame length exceeds
    /// [`MAX_FRAME_DATA`], [`SpscRingError::SnapshotFrameCountOverflow`] when
    /// the encoded frame count cannot fit in memory on this target, or
    /// [`SpscRingError::SnapshotDecodeTrailingBytes`] when extra bytes remain
    /// after the declared frames.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, SpscRingError> {
        let mut cursor = SnapshotByteCursor::new(bytes);
        let frame_count = cursor.read_u64()?;
        let _frame_count_fits_target = usize::try_from(frame_count)
            .map_err(|_| SpscRingError::SnapshotFrameCountOverflow { count: frame_count })?;
        let mut frames = Vec::new();

        for _ in 0..frame_count {
            let delivery_icount = cursor.read_u64()?;
            let src_node = cursor.read_u32()?;
            let seq = cursor.read_u32()?;
            let len = usize::from(cursor.read_u16()?);
            let delivery_state = cursor.read_u8()?;
            let delivery_attempts = cursor.read_u32()?;
            if len > MAX_FRAME_DATA {
                return Err(SpscRingError::InvalidFrameLength {
                    len,
                    capacity: MAX_FRAME_DATA,
                });
            }
            let payload = cursor.read_bytes(len)?;
            let frame = FrameEntry::new(delivery_icount, src_node, seq, payload).map_err(
                |FrameEntryError::PayloadLengthExceedsCapacity { len, capacity }| {
                    SpscRingError::InvalidFrameLength { len, capacity }
                },
            )?;
            match delivery_state {
                FRAME_DELIVERY_PENDING => {}
                FRAME_DELIVERY_RETAINED => frame.mark_delivery_retained().map_err(
                    |FrameDeliveryStateError::UnknownState { state }| {
                        SpscRingError::InvalidFrameDeliveryState { state }
                    },
                )?,
                state => return Err(SpscRingError::InvalidFrameDeliveryState { state }),
            }
            frame.restore_delivery_attempts(delivery_attempts);
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
