//! SPSC ring storage plus deterministic coverage bitmap operations.

use super::*;

const RING_PRODUCER_HELD: u64 = 1_u64 << 63;
const RING_PRODUCER_COUNT_MASK: u64 = !RING_PRODUCER_HELD;

/// One exact view of a ring's reversible producer-admission barrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingProducerBarrierSnapshot {
    held: bool,
    in_flight: u64,
}

impl RingProducerBarrierSnapshot {
    /// Returns whether later producer publications are rejected.
    #[must_use]
    pub const fn held(self) -> bool {
        self.held
    }

    /// Returns the number of producer publications admitted before the hold.
    #[must_use]
    pub const fn in_flight(self) -> u64 {
        self.in_flight
    }

    /// Returns whether this ring is held with no admitted producer remaining.
    #[must_use]
    pub const fn quiescent(self) -> bool {
        self.held && self.in_flight == 0
    }
}

pub(crate) struct RingProducerAdmission<'a> {
    ring: &'a RingHeader,
}

impl Drop for RingProducerAdmission<'_> {
    fn drop(&mut self) {
        let previous = self.ring.producer_state.fetch_sub(1, Ordering::SeqCst);
        if previous & RING_PRODUCER_COUNT_MASK == 0 {
            std::process::abort();
        }
    }
}

/// A Lamport SPSC ring header shared by exactly one producer and one consumer.
#[repr(C, align(128))]
pub struct RingHeader {
    pub(super) read_idx: AtomicU64,
    _pad_read: [u8; 56],
    pub(super) write_idx: AtomicU64,
    producer_state: AtomicU64,
    _pad_write: [u8; 48],
}

impl Clone for RingHeader {
    fn clone(&self) -> Self {
        Self {
            read_idx: AtomicU64::new(self.read_idx.load(Ordering::Acquire)),
            _pad_read: [0; 56],
            write_idx: AtomicU64::new(self.write_idx.load(Ordering::Acquire)),
            // Admission counts are process-local coordination, not logical
            // ring content. A future hot-fork clone must install its own
            // explicit child disposition rather than inherit live guards.
            producer_state: AtomicU64::new(0),
            _pad_write: [0; 48],
        }
    }
}

/// Byte offset of [`RingHeader`]'s consumer-owned read index.
pub const RING_HEADER_READ_IDX_OFFSET: usize = core::mem::offset_of!(RingHeader, read_idx);
/// Byte offset of [`RingHeader`]'s consumer cache-line padding.
pub const RING_HEADER_PAD_READ_OFFSET: usize = core::mem::offset_of!(RingHeader, _pad_read);
/// Byte offset of [`RingHeader`]'s producer-owned write index.
pub const RING_HEADER_WRITE_IDX_OFFSET: usize = core::mem::offset_of!(RingHeader, write_idx);
/// Byte offset of [`RingHeader`]'s producer-admission state.
pub const RING_HEADER_PRODUCER_STATE_OFFSET: usize =
    core::mem::offset_of!(RingHeader, producer_state);
/// Byte offset of [`RingHeader`]'s producer cache-line padding.
pub const RING_HEADER_PAD_WRITE_OFFSET: usize = core::mem::offset_of!(RingHeader, _pad_write);
/// Wire size of one [`RingHeader`].
pub const RING_HEADER_SIZE: usize = core::mem::size_of::<RingHeader>();
/// Wire alignment of one [`RingHeader`].
pub const RING_HEADER_ALIGN: usize = core::mem::align_of::<RingHeader>();

const _: () = assert!(RING_HEADER_READ_IDX_OFFSET == 0);
const _: () = assert!(RING_HEADER_PAD_READ_OFFSET == 8);
const _: () = assert!(RING_HEADER_WRITE_IDX_OFFSET == 64);
const _: () = assert!(RING_HEADER_PRODUCER_STATE_OFFSET == 72);
const _: () = assert!(RING_HEADER_PAD_WRITE_OFFSET == 80);
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
            producer_state: AtomicU64::new(0),
            _pad_write: [0; 48],
        }
    }

    /// Holds the reversible hot-fork producer barrier for this ring.
    ///
    /// Producers admitted before the hold remain counted until their
    /// publication attempt returns. Producers racing the hold cannot enter
    /// after the held bit becomes visible.
    #[must_use]
    pub fn hold_hot_fork_producers(&self) -> RingProducerBarrierSnapshot {
        self.producer_state
            .fetch_or(RING_PRODUCER_HELD, Ordering::SeqCst);
        self.producer_barrier_snapshot()
    }

    /// Releases the reversible hot-fork producer barrier for this ring.
    #[must_use]
    pub fn release_hot_fork_producers(&self) -> RingProducerBarrierSnapshot {
        self.producer_state
            .fetch_and(!RING_PRODUCER_HELD, Ordering::SeqCst);
        self.producer_barrier_snapshot()
    }

    /// Returns one exact producer-admission snapshot for this ring.
    #[must_use]
    pub fn producer_barrier_snapshot(&self) -> RingProducerBarrierSnapshot {
        let state = self.producer_state.load(Ordering::SeqCst);
        RingProducerBarrierSnapshot {
            held: state & RING_PRODUCER_HELD != 0,
            in_flight: state & RING_PRODUCER_COUNT_MASK,
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
        let _producer = self
            .enter_producer()
            .ok_or(SpscRingError::ProducerBarrierHeld)?;
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
        let _producer = self
            .enter_producer()
            .ok_or(SpscRingError::ProducerBarrierHeld)?;
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
        let _producer = self
            .enter_producer()
            .ok_or(SpscRingError::ProducerBarrierHeld)?;
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
        let _producer = self
            .enter_producer()
            .ok_or(SpscRingError::ProducerBarrierHeld)?;
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
        let _producer = self
            .enter_producer()
            .ok_or(SpscRingError::ProducerBarrierHeld)?;
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

    pub(crate) fn enter_producer(&self) -> Option<RingProducerAdmission<'_>> {
        self.enter_producer_with_hook(|| {})
    }

    fn enter_producer_with_hook(
        &self,
        after_initial_load: impl FnOnce(),
    ) -> Option<RingProducerAdmission<'_>> {
        let mut observed = self.producer_state.load(Ordering::SeqCst);
        after_initial_load();
        loop {
            if observed & RING_PRODUCER_HELD != 0 {
                return None;
            }
            let count = observed & RING_PRODUCER_COUNT_MASK;
            let Some(next_count) = count.checked_add(1) else {
                std::process::abort();
            };
            if next_count > RING_PRODUCER_COUNT_MASK {
                std::process::abort();
            }
            match self.producer_state.compare_exchange(
                observed,
                next_count,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_previous) => return Some(RingProducerAdmission { ring: self }),
                Err(actual) => observed = actual,
            }
        }
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

    /// Peeks at the next white-box envelope without releasing its slot.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when the entry slice has invalid capacity or
    /// the shared indices describe more live entries than the queue can hold.
    pub fn peek_whitebox_marker(
        &self,
        entries: &[WhiteboxMarkerEntry],
    ) -> Result<Option<WhiteboxMarkerEntry>, SpscRingError> {
        let capacity = validated_capacity(entries)?;
        let head = self.read_idx.load(Ordering::Relaxed);
        let tail = self.write_idx.load(Ordering::Acquire);
        if live_count(head, tail, capacity)? == 0 {
            return Ok(None);
        }

        Ok(Some(entries[(head & (capacity - 1)) as usize]))
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
        let live = live as usize;
        let mut frames = Vec::new();
        frames
            .try_reserve_exact(live)
            .map_err(|_| SpscRingError::SnapshotAllocationFailed { count: live })?;
        for offset in 0..live {
            let offset = offset as u64;
            let slot = ((head.wrapping_add(offset)) & (capacity - 1)) as usize;
            frames.push(SnapshotFrameEntry::from_live(&entries[slot])?);
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
            entries[slot] = frame.to_live()?;
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

    pub(crate) fn producer_state_raw(&self) -> u64 {
        self.producer_state.load(Ordering::SeqCst)
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
pub use snapshot::{SnapshotFrameEntry, SpscRingSnapshot};

#[cfg(test)]
mod producer_barrier_tests {
    use std::sync::{Arc, Barrier};

    use super::*;

    #[test]
    fn hold_rejects_late_producers_and_waits_for_admitted_publication() {
        let ring = RingHeader::new();
        let admitted = ring
            .enter_producer()
            .unwrap_or_else(|| panic!("open producer gate should admit"));

        let held = ring.hold_hot_fork_producers();
        assert!(held.held());
        assert_eq!(held.in_flight(), 1);
        assert!(!held.quiescent());
        assert!(ring.enter_producer().is_none());

        drop(admitted);
        assert!(ring.producer_barrier_snapshot().quiescent());
        let released = ring.release_hot_fork_producers();
        assert!(!released.held());
        assert_eq!(released.in_flight(), 0);
        assert!(ring.enter_producer().is_some());
    }

    #[test]
    fn hold_between_load_and_admission_cas_rejects_racing_producer() {
        let ring = Arc::new(RingHeader::new());
        let loaded = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        let racing_ring = Arc::clone(&ring);
        let racing_loaded = Arc::clone(&loaded);
        let racing_resume = Arc::clone(&resume);
        let producer = std::thread::spawn(move || {
            racing_ring
                .enter_producer_with_hook(|| {
                    racing_loaded.wait();
                    racing_resume.wait();
                })
                .is_some()
        });

        loaded.wait();
        assert!(ring.hold_hot_fork_producers().quiescent());
        resume.wait();
        let admitted = producer
            .join()
            .unwrap_or_else(|_panic| panic!("producer thread should finish"));
        assert!(!admitted);
        assert!(ring.producer_barrier_snapshot().quiescent());
    }
}
