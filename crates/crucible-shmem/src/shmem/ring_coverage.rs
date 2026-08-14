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

    /// Returns the exact number of live accelerator entries in this ring.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError::InvalidCapacity`] when `entries` is empty or not
    /// power-of-two sized, or [`SpscRingError::CorruptIndices`] when the shared
    /// producer/consumer indices describe an impossible live count.
    pub fn live_accelerator_len(&self, entries: &[AcceleratorEntry]) -> Result<u64, SpscRingError> {
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
        self.write_idx
            .store(tail.wrapping_add(1), Ordering::Release);
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

#[path = "ring_coverage/coverage_entry.rs"]
mod coverage_entry;
#[path = "ring_coverage/snapshot.rs"]
mod snapshot;

pub use coverage_entry::*;
use snapshot::SnapshotByteCursor;
pub use snapshot::SpscRingSnapshot;
