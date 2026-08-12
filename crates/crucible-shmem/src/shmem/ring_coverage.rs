//! SPSC ring storage plus deterministic coverage bitmap operations.

use super::*;

/// A Lamport SPSC ring header shared by exactly one producer and one consumer.
#[repr(C, align(128))]
pub struct RingHeader {
    pub(super) read_idx: AtomicU64,
    _pad_read: [u8; 56],
    pub(super) write_idx: AtomicU64,
    _pad_write: [u8; 56],
}

impl Clone for RingHeader {
    fn clone(&self) -> Self {
        Self {
            read_idx: AtomicU64::new(self.read_idx.load(Ordering::Acquire)),
            _pad_read: [0; 56],
            write_idx: AtomicU64::new(self.write_idx.load(Ordering::Acquire)),
            _pad_write: [0; 56],
        }
    }
}

/// Byte offset of [`RingHeader`]'s consumer-owned read index.
pub const RING_HEADER_READ_IDX_OFFSET: usize = core::mem::offset_of!(RingHeader, read_idx);
/// Byte offset of [`RingHeader`]'s consumer cache-line padding.
pub const RING_HEADER_PAD_READ_OFFSET: usize = core::mem::offset_of!(RingHeader, _pad_read);
/// Byte offset of [`RingHeader`]'s producer-owned write index.
pub const RING_HEADER_WRITE_IDX_OFFSET: usize = core::mem::offset_of!(RingHeader, write_idx);
/// Byte offset of [`RingHeader`]'s producer cache-line padding.
pub const RING_HEADER_PAD_WRITE_OFFSET: usize = core::mem::offset_of!(RingHeader, _pad_write);
/// Wire size of one [`RingHeader`].
pub const RING_HEADER_SIZE: usize = core::mem::size_of::<RingHeader>();
/// Wire alignment of one [`RingHeader`].
pub const RING_HEADER_ALIGN: usize = core::mem::align_of::<RingHeader>();

const _: () = assert!(RING_HEADER_READ_IDX_OFFSET == 0);
const _: () = assert!(RING_HEADER_PAD_READ_OFFSET == 8);
const _: () = assert!(RING_HEADER_WRITE_IDX_OFFSET == 64);
const _: () = assert!(RING_HEADER_PAD_WRITE_OFFSET == 72);
const _: () = assert!(RING_HEADER_SIZE == 128);
const _: () = assert!(RING_HEADER_ALIGN == 128);

impl RingHeader {
    /// Builds an empty SPSC ring header.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            read_idx: AtomicU64::new(0),
            _pad_read: [0; 56],
            write_idx: AtomicU64::new(0),
            _pad_write: [0; 56],
        }
    }

    /// Returns the exact number of live frames in this ring.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError::InvalidCapacity`] when `entries` is empty or not
    /// power-of-two sized, or [`SpscRingError::CorruptIndices`] when the shared
    /// producer/consumer indices describe an impossible live count.
    pub fn live_len(&self, entries: &[FrameEntry]) -> Result<u64, SpscRingError> {
        let capacity = validated_capacity(entries)?;
        let tail = self.write_idx.load(Ordering::Acquire);
        let head = self.read_idx.load(Ordering::Acquire);
        live_count(head, tail, capacity)
    }

    /// Enqueues one frame into producer-owned storage.
    ///
    /// The producer writes the frame bytes before publishing the new
    /// `write_idx` with release ordering. The consumer acquire-loads
    /// `write_idx` before reading the entry.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError::InvalidCapacity`] when `entries` is empty or not
    /// power-of-two sized, [`SpscRingError::CorruptIndices`] when the header
    /// contains an impossible live count, or [`SpscRingError::QueueFull`] when
    /// the ring is full.
    pub fn enqueue(
        &self,
        entries: &mut [FrameEntry],
        frame: &FrameEntry,
    ) -> Result<(), SpscRingError> {
        let capacity = validated_capacity(entries)?;
        let tail = self.write_idx.load(Ordering::Relaxed);
        let head = self.read_idx.load(Ordering::Acquire);
        let live = live_count(head, tail, capacity)?;
        if live == capacity {
            return Err(SpscRingError::QueueFull { capacity });
        }

        let slot = (tail & (capacity - 1)) as usize;
        entries[slot] = frame.clone();
        self.write_idx
            .store(tail.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    /// Enqueues one novel coverage observation into producer-owned storage.
    ///
    /// The producer copies the complete entry before release-publishing the new
    /// write index. The host acquire-loads that index only at a quantum boundary.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when the coverage slice has invalid capacity,
    /// the ring indices are corrupt, or the fixed queue is full.
    pub fn enqueue_coverage(
        &self,
        entries: &mut [CoverageEntry],
        entry: CoverageEntry,
    ) -> Result<(), SpscRingError> {
        let capacity = validated_capacity(entries)?;
        let tail = self.write_idx.load(Ordering::Relaxed);
        let head = self.read_idx.load(Ordering::Acquire);
        let live = live_count(head, tail, capacity)?;
        if live == capacity {
            return Err(SpscRingError::QueueFull { capacity });
        }

        let slot = (tail & (capacity - 1)) as usize;
        entries[slot] = entry;
        self.write_idx
            .store(tail.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    /// Enqueues one observational white-box marker into producer-owned storage.
    ///
    /// The plugin copies the complete marker before release-publishing the new
    /// write index. The host acquire-loads that index only at a quantum
    /// boundary, so marker transport cannot affect guest execution.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when the marker slice has invalid capacity,
    /// the ring indices are corrupt, or the fixed queue is full.
    pub fn enqueue_whitebox_marker(
        &self,
        entries: &mut [WhiteboxMarkerEntry],
        entry: WhiteboxMarkerEntry,
    ) -> Result<(), SpscRingError> {
        let capacity = validated_capacity(entries)?;
        let tail = self.write_idx.load(Ordering::Relaxed);
        let head = self.read_idx.load(Ordering::Acquire);
        let live = live_count(head, tail, capacity)?;
        if live == capacity {
            return Err(SpscRingError::QueueFull { capacity });
        }

        let slot = (tail & (capacity - 1)) as usize;
        entries[slot] = entry;
        self.write_idx
            .store(tail.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    /// Enqueues one complete guest-introspection record entry.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when the entry slice has invalid capacity,
    /// shared indices are corrupt, or the fixed queue is full.
    pub fn enqueue_guest_introspection(
        &self,
        entries: &mut [GuestIntrospectionEntry],
        entry: GuestIntrospectionEntry,
    ) -> Result<(), SpscRingError> {
        let capacity = validated_capacity(entries)?;
        let tail = self.write_idx.load(Ordering::Relaxed);
        let head = self.read_idx.load(Ordering::Acquire);
        let live = live_count(head, tail, capacity)?;
        if live == capacity {
            return Err(SpscRingError::QueueFull { capacity });
        }
        let slot = (tail & (capacity - 1)) as usize;
        entries[slot] = entry;
        self.write_idx
            .store(tail.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    /// Enqueues one validated accelerator request or completion.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when the backing slice or shared indices are
    /// invalid or the bounded queue is full.
    pub fn enqueue_accelerator(
        &self,
        entries: &mut [AcceleratorEntry],
        entry: AcceleratorEntry,
    ) -> Result<(), SpscRingError> {
        let capacity = validated_capacity(entries)?;
        let tail = self.write_idx.load(Ordering::Relaxed);
        let head = self.read_idx.load(Ordering::Acquire);
        let live = live_count(head, tail, capacity)?;
        if live == capacity {
            return Err(SpscRingError::QueueFull { capacity });
        }
        entries[(tail & (capacity - 1)) as usize] = entry;
        self.write_idx.store(tail.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    /// Returns the next frame's delivery icount without consuming it.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when `entries` has invalid capacity or the ring
    /// indices describe more live entries than the capacity can hold.
    pub fn peek_delivery_icount(
        &self,
        entries: &[FrameEntry],
    ) -> Result<Option<u64>, SpscRingError> {
        let capacity = validated_capacity(entries)?;
        let head = self.read_idx.load(Ordering::Relaxed);
        let tail = self.write_idx.load(Ordering::Acquire);
        if live_count(head, tail, capacity)? == 0 {
            return Ok(None);
        }

        let slot = (head & (capacity - 1)) as usize;
        Ok(Some(entries[slot].delivery_icount))
    }

    /// Returns the next frame without consuming it.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when `entries` has invalid capacity or the ring
    /// indices describe more live entries than the capacity can hold.
    pub fn peek(&self, entries: &[FrameEntry]) -> Result<Option<FrameEntry>, SpscRingError> {
        let capacity = validated_capacity(entries)?;
        let head = self.read_idx.load(Ordering::Relaxed);
        let tail = self.write_idx.load(Ordering::Acquire);
        if live_count(head, tail, capacity)? == 0 {
            return Ok(None);
        }

        let slot = (head & (capacity - 1)) as usize;
        Ok(Some(entries[slot].clone()))
    }

    /// Dequeues one frame from consumer-owned storage.
    ///
    /// The consumer acquire-loads `write_idx`, copies the entry, then frees the
    /// slot by release-storing the incremented `read_idx` for the producer.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when `entries` has invalid capacity or the ring
    /// indices describe more live entries than the capacity can hold.
    pub fn dequeue(&self, entries: &[FrameEntry]) -> Result<Option<FrameEntry>, SpscRingError> {
        let capacity = validated_capacity(entries)?;
        let head = self.read_idx.load(Ordering::Relaxed);
        let tail = self.write_idx.load(Ordering::Acquire);
        if live_count(head, tail, capacity)? == 0 {
            return Ok(None);
        }

        let slot = (head & (capacity - 1)) as usize;
        let frame = entries[slot].clone();
        self.read_idx.store(head.wrapping_add(1), Ordering::Release);
        Ok(Some(frame))
    }

    /// Dequeues the next plugin-to-host coverage observation.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when the coverage slice has invalid capacity or
    /// the shared indices describe more live entries than the queue can hold.
    pub fn dequeue_coverage(
        &self,
        entries: &[CoverageEntry],
    ) -> Result<Option<CoverageEntry>, SpscRingError> {
        let capacity = validated_capacity(entries)?;
        let head = self.read_idx.load(Ordering::Relaxed);
        let tail = self.write_idx.load(Ordering::Acquire);
        if live_count(head, tail, capacity)? == 0 {
            return Ok(None);
        }

        let slot = (head & (capacity - 1)) as usize;
        let entry = entries[slot];
        self.read_idx.store(head.wrapping_add(1), Ordering::Release);
        Ok(Some(entry))
    }

    /// Dequeues the next plugin-to-host observational white-box marker.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when the marker slice has invalid capacity or
    /// the shared indices describe more live entries than the queue can hold.
    pub fn dequeue_whitebox_marker(
        &self,
        entries: &[WhiteboxMarkerEntry],
    ) -> Result<Option<WhiteboxMarkerEntry>, SpscRingError> {
        let capacity = validated_capacity(entries)?;
        let head = self.read_idx.load(Ordering::Relaxed);
        let tail = self.write_idx.load(Ordering::Acquire);
        if live_count(head, tail, capacity)? == 0 {
            return Ok(None);
        }

        let slot = (head & (capacity - 1)) as usize;
        let entry = entries[slot];
        self.read_idx.store(head.wrapping_add(1), Ordering::Release);
        Ok(Some(entry))
    }

    /// Dequeues the next guest-introspection record entry.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when the entry slice has invalid capacity,
    /// shared indices describe more live entries than the queue can hold, or
    /// the next untrusted cross-process entry is malformed. A malformed entry
    /// is not consumed, allowing the caller to treat the channel as failed.
    pub fn dequeue_guest_introspection(
        &self,
        entries: &[GuestIntrospectionEntry],
    ) -> Result<Option<GuestIntrospectionEntry>, SpscRingError> {
        let capacity = validated_capacity(entries)?;
        let head = self.read_idx.load(Ordering::Relaxed);
        let tail = self.write_idx.load(Ordering::Acquire);
        if live_count(head, tail, capacity)? == 0 {
            return Ok(None);
        }
        let slot = (head & (capacity - 1)) as usize;
        let entry = entries[slot]
            .validate()
            .map_err(|source| SpscRingError::InvalidGuestIntrospectionEntry { source })?;
        self.read_idx.store(head.wrapping_add(1), Ordering::Release);
        Ok(Some(entry))
    }

    /// Dequeues and validates one accelerator request or completion.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when geometry or indices are invalid, or the
    /// next cross-process entry is malformed. Malformed entries remain queued.
    pub fn dequeue_accelerator(
        &self,
        entries: &[AcceleratorEntry],
    ) -> Result<Option<AcceleratorEntry>, SpscRingError> {
        let capacity = validated_capacity(entries)?;
        let head = self.read_idx.load(Ordering::Relaxed);
        let tail = self.write_idx.load(Ordering::Acquire);
        if live_count(head, tail, capacity)? == 0 {
            return Ok(None);
        }
        let entry = entries[(head & (capacity - 1)) as usize]
            .validate()
            .map_err(|source| SpscRingError::InvalidAcceleratorEntry { source })?;
        self.read_idx.store(head.wrapping_add(1), Ordering::Release);
        Ok(Some(entry))
    }

    /// Peeks at the next validated guest-introspection entry without consuming it.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when the entry slice or shared indices are
    /// invalid, or the next cross-process entry is malformed.
    pub fn peek_guest_introspection(
        &self,
        entries: &[GuestIntrospectionEntry],
    ) -> Result<Option<GuestIntrospectionEntry>, SpscRingError> {
        let capacity = validated_capacity(entries)?;
        let head = self.read_idx.load(Ordering::Relaxed);
        let tail = self.write_idx.load(Ordering::Acquire);
        if live_count(head, tail, capacity)? == 0 {
            return Ok(None);
        }
        let slot = (head & (capacity - 1)) as usize;
        entries[slot]
            .validate()
            .map(Some)
            .map_err(|source| SpscRingError::InvalidGuestIntrospectionEntry { source })
    }

    /// Commits consumption of a previously peeked guest-introspection entry.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when the queue changed unexpectedly, is empty,
    /// or its next validated entry does not carry `expected_sequence`.
    pub fn commit_guest_introspection(
        &self,
        entries: &[GuestIntrospectionEntry],
        expected_sequence: u64,
    ) -> Result<(), SpscRingError> {
        let capacity = validated_capacity(entries)?;
        let head = self.read_idx.load(Ordering::Relaxed);
        let tail = self.write_idx.load(Ordering::Acquire);
        if live_count(head, tail, capacity)? == 0 {
            return Err(SpscRingError::GuestIntrospectionSequenceMismatch {
                expected: expected_sequence,
                actual: 0,
            });
        }
        let slot = (head & (capacity - 1)) as usize;
        let entry = entries[slot]
            .validate()
            .map_err(|source| SpscRingError::InvalidGuestIntrospectionEntry { source })?;
        if entry.sequence() != expected_sequence {
            return Err(SpscRingError::GuestIntrospectionSequenceMismatch {
                expected: expected_sequence,
                actual: entry.sequence(),
            });
        }
        self.read_idx.store(head.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    /// Captures the live ring entries in FIFO order under quiescence.
    ///
    /// This method is not concurrency-safe; callers must ensure the producer and
    /// consumer are paused.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when `entries` has invalid capacity or the ring
    /// indices describe more live entries than the capacity can hold.
    pub fn snapshot(&self, entries: &[FrameEntry]) -> Result<SpscRingSnapshot, SpscRingError> {
        let capacity = validated_capacity(entries)?;
        let head = self.read_idx.load(Ordering::Acquire);
        let tail = self.write_idx.load(Ordering::Acquire);
        let live = live_count(head, tail, capacity)?;
        let mut frames = Vec::with_capacity(live as usize);
        for offset in 0..live {
            let slot = ((head.wrapping_add(offset)) & (capacity - 1)) as usize;
            frames.push(entries[slot].canonicalized_for_snapshot()?);
        }

        Ok(SpscRingSnapshot { frames })
    }

    /// Restores a quiesced ring from a FIFO snapshot and normalizes indices.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError::InvalidCapacity`] when `entries` is empty or not
    /// power-of-two sized, or [`SpscRingError::SnapshotTooLarge`] when the
    /// snapshot does not fit in the ring.
    pub fn restore(
        &self,
        entries: &mut [FrameEntry],
        snapshot: &SpscRingSnapshot,
    ) -> Result<(), SpscRingError> {
        let capacity = validated_capacity(entries)?;
        if snapshot.frames.len() as u64 > capacity {
            return Err(SpscRingError::SnapshotTooLarge {
                len: snapshot.frames.len(),
                capacity,
            });
        }

        for (slot, frame) in snapshot.frames.iter().enumerate() {
            entries[slot] = frame.clone();
        }
        self.read_idx.store(0, Ordering::Release);
        self.write_idx
            .store(snapshot.frames.len() as u64, Ordering::Release);
        Ok(())
    }

    /// Returns the current consumer-owned read index.
    #[must_use]
    pub fn read_index(&self) -> u64 {
        self.read_idx.load(Ordering::Acquire)
    }

    /// Returns the current producer-owned write index.
    #[must_use]
    pub fn write_index(&self) -> u64 {
        self.write_idx.load(Ordering::Acquire)
    }

    /// Returns `true` when the cache-line padding bytes are zero.
    #[must_use]
    pub fn padding_bytes_are_zero(&self) -> bool {
        self._pad_read.iter().all(|byte| *byte == 0)
            && self._pad_write.iter().all(|byte| *byte == 0)
    }
}

impl Default for RingHeader {
    fn default() -> Self {
        Self::new()
    }
}

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
    /// each frame's delivery icount, source node, sequence, payload length, and
    /// valid payload bytes. Frame padding and unused payload capacity are excluded
    /// so equivalent logical snapshots content-address identically.
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

/// A compact plugin-to-host basic-block coverage observation.
///
/// Each coverage map index is published at most once for a plugin process. The
/// SPSC ring order supplies the deterministic sequence, so the entry carries no
/// independently mutable sequence counter.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(C, align(64))]
pub struct CoverageEntry {
    pub(super) current_icount: u64,
    pub(super) guest_pc: u64,
    pub(super) map_index: u64,
    pub(super) vcpu_index: u32,
    pub(super) block_len: u32,
    pub(super) _reserved: [u8; 32],
}

/// Byte offset of [`CoverageEntry`]'s exact TB-entry icount.
pub const COVERAGE_ENTRY_CURRENT_ICOUNT_OFFSET: usize =
    core::mem::offset_of!(CoverageEntry, current_icount);
/// Byte offset of [`CoverageEntry`]'s guest basic-block address.
pub const COVERAGE_ENTRY_GUEST_PC_OFFSET: usize = core::mem::offset_of!(CoverageEntry, guest_pc);
/// Byte offset of [`CoverageEntry`]'s fixed-map index.
pub const COVERAGE_ENTRY_MAP_INDEX_OFFSET: usize = core::mem::offset_of!(CoverageEntry, map_index);
/// Byte offset of [`CoverageEntry`]'s QEMU vCPU index.
pub const COVERAGE_ENTRY_VCPU_INDEX_OFFSET: usize =
    core::mem::offset_of!(CoverageEntry, vcpu_index);
/// Byte offset of [`CoverageEntry`]'s translated block byte length.
pub const COVERAGE_ENTRY_BLOCK_LEN_OFFSET: usize = core::mem::offset_of!(CoverageEntry, block_len);
/// Byte offset of [`CoverageEntry`]'s zeroed forward-compatibility bytes.
pub const COVERAGE_ENTRY_RESERVED_OFFSET: usize = core::mem::offset_of!(CoverageEntry, _reserved);
/// Wire size of one [`CoverageEntry`].
pub const COVERAGE_ENTRY_SIZE: usize = core::mem::size_of::<CoverageEntry>();
/// Wire alignment of one [`CoverageEntry`].
pub const COVERAGE_ENTRY_ALIGN: usize = core::mem::align_of::<CoverageEntry>();

const _: () = assert!(COVERAGE_ENTRY_CURRENT_ICOUNT_OFFSET == 0);
const _: () = assert!(COVERAGE_ENTRY_GUEST_PC_OFFSET == 8);
const _: () = assert!(COVERAGE_ENTRY_MAP_INDEX_OFFSET == 16);
const _: () = assert!(COVERAGE_ENTRY_VCPU_INDEX_OFFSET == 24);
const _: () = assert!(COVERAGE_ENTRY_BLOCK_LEN_OFFSET == 28);
const _: () = assert!(COVERAGE_ENTRY_RESERVED_OFFSET == 32);
const _: () = assert!(COVERAGE_ENTRY_SIZE == 64);
const _: () = assert!(COVERAGE_ENTRY_ALIGN == 64);

impl CoverageEntry {
    /// Builds one validated novel coverage observation.
    ///
    /// # Errors
    ///
    /// Returns [`CoverageEntryError::InvalidBlockLength`] for a zero-length
    /// block, or [`CoverageEntryError::MapIndexOutOfRange`] when `map_index` is
    /// outside the ABI-fixed coverage-map cardinality.
    pub fn new(
        current_icount: u64,
        vcpu_index: u32,
        guest_pc: u64,
        block_len: u32,
        map_index: u64,
    ) -> Result<Self, CoverageEntryError> {
        if block_len == 0 {
            return Err(CoverageEntryError::InvalidBlockLength { block_len });
        }
        if map_index >= u64::from(COVERAGE_QUEUE_CAPACITY) {
            return Err(CoverageEntryError::MapIndexOutOfRange {
                map_index,
                map_entries: COVERAGE_QUEUE_CAPACITY,
            });
        }
        Ok(Self {
            current_icount,
            guest_pc,
            map_index,
            vcpu_index,
            block_len,
            _reserved: [0; 32],
        })
    }

    /// Returns the exact icount before the covered block's first instruction.
    #[must_use]
    pub const fn current_icount(self) -> u64 {
        self.current_icount
    }

    /// Returns the QEMU vCPU that executed the block.
    #[must_use]
    pub const fn vcpu_index(self) -> u32 {
        self.vcpu_index
    }

    /// Returns the guest basic-block address.
    #[must_use]
    pub const fn guest_pc(self) -> u64 {
        self.guest_pc
    }

    /// Returns the translated block byte length.
    #[must_use]
    pub const fn block_len(self) -> u32 {
        self.block_len
    }

    /// Returns the fixed coverage-map index first reached by this observation.
    #[must_use]
    pub const fn map_index(self) -> u64 {
        self.map_index
    }

    /// Validates an entry loaded from shared memory.
    ///
    /// # Errors
    ///
    /// Returns [`CoverageEntryError`] for an invalid block length, out-of-range
    /// map index, or nonzero reserved bytes.
    pub fn validate(self) -> Result<Self, CoverageEntryError> {
        let validated = Self::new(
            self.current_icount,
            self.vcpu_index,
            self.guest_pc,
            self.block_len,
            self.map_index,
        )?;
        if self._reserved.iter().any(|byte| *byte != 0) {
            return Err(CoverageEntryError::NonzeroReservedBytes);
        }
        Ok(validated)
    }
}
