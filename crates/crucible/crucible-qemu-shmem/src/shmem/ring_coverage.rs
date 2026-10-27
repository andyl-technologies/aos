//! SPSC ring storage plus deterministic coverage bitmap operations.

use super::*;

const RING_ADMISSION_HELD: u64 = 1_u64 << 63;
const RING_ADMISSION_COUNT_MASK: u64 = !RING_ADMISSION_HELD;

/// One exact view of a ring's reversible producer-admission barrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingProducerBarrierSnapshot {
    held: bool,
    in_flight: u64,
}

/// One exact view of a ring's reversible consumer-admission barrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RingConsumerBarrierSnapshot {
    held: bool,
    in_flight: u64,
}

impl RingConsumerBarrierSnapshot {
    /// Returns whether later consumer operations are rejected.
    #[must_use]
    pub const fn held(self) -> bool {
        self.held
    }

    /// Returns the number of consumer operations admitted before the hold.
    #[must_use]
    pub const fn in_flight(self) -> u64 {
        self.in_flight
    }

    /// Returns whether this ring is held with no admitted consumer remaining.
    #[must_use]
    pub const fn quiescent(self) -> bool {
        self.held && self.in_flight == 0
    }
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
        if previous & RING_ADMISSION_COUNT_MASK == 0 {
            std::process::abort();
        }
    }
}

pub(crate) struct RingConsumerAdmission<'a> {
    ring: &'a RingHeader,
}

impl Drop for RingConsumerAdmission<'_> {
    fn drop(&mut self) {
        let previous = self.ring.consumer_state.fetch_sub(1, Ordering::SeqCst);
        if previous & RING_ADMISSION_COUNT_MASK == 0 {
            std::process::abort();
        }
    }
}

/// A Lamport SPSC ring header shared by exactly one producer and one consumer.
#[repr(C, align(128))]
pub struct RingHeader {
    pub(super) read_idx: AtomicU64,
    consumer_state: AtomicU64,
    _pad_read: [u8; 48],
    pub(super) write_idx: AtomicU64,
    producer_state: AtomicU64,
    _pad_write: [u8; 48],
}

impl Clone for RingHeader {
    fn clone(&self) -> Self {
        Self {
            read_idx: AtomicU64::new(self.read_idx.load(Ordering::Acquire)),
            consumer_state: AtomicU64::new(0),
            _pad_read: [0; 48],
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
/// Byte offset of [`RingHeader`]'s consumer-admission state.
pub const RING_HEADER_CONSUMER_STATE_OFFSET: usize =
    core::mem::offset_of!(RingHeader, consumer_state);
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
const _: () = assert!(RING_HEADER_CONSUMER_STATE_OFFSET == 8);
const _: () = assert!(RING_HEADER_PAD_READ_OFFSET == 16);
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
            consumer_state: AtomicU64::new(0),
            _pad_read: [0; 48],
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
            .fetch_or(RING_ADMISSION_HELD, Ordering::SeqCst);
        self.producer_barrier_snapshot()
    }

    /// Releases the reversible hot-fork producer barrier for this ring.
    #[must_use]
    pub fn release_hot_fork_producers(&self) -> RingProducerBarrierSnapshot {
        self.producer_state
            .fetch_and(!RING_ADMISSION_HELD, Ordering::SeqCst);
        self.producer_barrier_snapshot()
    }

    /// Returns one exact producer-admission snapshot for this ring.
    #[must_use]
    pub fn producer_barrier_snapshot(&self) -> RingProducerBarrierSnapshot {
        let state = self.producer_state.load(Ordering::SeqCst);
        RingProducerBarrierSnapshot {
            held: state & RING_ADMISSION_HELD != 0,
            in_flight: state & RING_ADMISSION_COUNT_MASK,
        }
    }

    /// Holds the reversible hot-fork consumer barrier for this ring.
    ///
    /// Consumers admitted before the hold remain counted until their
    /// operation returns. Consumers racing the hold cannot advance the shared
    /// read index after the held bit becomes visible.
    #[must_use]
    pub fn hold_hot_fork_consumers(&self) -> RingConsumerBarrierSnapshot {
        self.consumer_state
            .fetch_or(RING_ADMISSION_HELD, Ordering::SeqCst);
        self.consumer_barrier_snapshot()
    }

    /// Releases the reversible hot-fork consumer barrier for this ring.
    #[must_use]
    pub fn release_hot_fork_consumers(&self) -> RingConsumerBarrierSnapshot {
        self.consumer_state
            .fetch_and(!RING_ADMISSION_HELD, Ordering::SeqCst);
        self.consumer_barrier_snapshot()
    }

    /// Returns one exact consumer-admission snapshot for this ring.
    #[must_use]
    pub fn consumer_barrier_snapshot(&self) -> RingConsumerBarrierSnapshot {
        let state = self.consumer_state.load(Ordering::SeqCst);
        RingConsumerBarrierSnapshot {
            held: state & RING_ADMISSION_HELD != 0,
            in_flight: state & RING_ADMISSION_COUNT_MASK,
        }
    }

    /// Reserves both admissions of a drained ring for a stopped restore.
    ///
    /// This storage reservation does not authenticate a checkpoint or stop.
    /// Its caller retains the successfully loaded, natively stopped executor
    /// and joins the captured endpoint to the independently loaded canonical
    /// prefix. Reservation excludes both ring sides without changing either
    /// cursor, allowing the original request claim to refuse without mutation.
    /// Dropping the reservation releases only its own admission barriers.
    ///
    /// # Errors
    ///
    /// Refuses an admitted operation, an existing barrier, or undrained bytes.
    /// Refusal preserves both cursors and all preexisting admission state.
    pub fn prepare_drained_cursor_while_stopped(
        &self,
        endpoint: u64,
    ) -> Result<PreparedStoppedRingCursor<'_>, SpscRingError> {
        self.consumer_state
            .compare_exchange(0, RING_ADMISSION_HELD, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| SpscRingError::RestoreCursorBusy)?;
        let consumer = StoppedCursorAdmission(&self.consumer_state);
        self.producer_state
            .compare_exchange(0, RING_ADMISSION_HELD, Ordering::SeqCst, Ordering::SeqCst)
            .map_err(|_| SpscRingError::RestoreCursorBusy)?;
        let producer = StoppedCursorAdmission(&self.producer_state);
        let read = self.read_idx.load(Ordering::Acquire);
        let write = self.write_idx.load(Ordering::Acquire);
        if read != write {
            return Err(SpscRingError::RestoreCursorNotDrained { read, write });
        }

        Ok(PreparedStoppedRingCursor {
            ring: self,
            endpoint,
            _consumer: consumer,
            _producer: producer,
        })
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

    /// Discards every queued coverage observation at a paused restore boundary.
    ///
    /// This producer-side operation preserves the consumer-owned read index and
    /// release-publishes the producer index at that exact cursor. The caller
    /// must hold an authenticated pause that prevents both coverage callbacks
    /// and the host consumer from running for the duration of the operation.
    /// It is used only by the ABI-versioned logical-time restore transaction;
    /// ordinary queue consumers must drain entries instead.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when producer admission is held, the coverage
    /// slice has invalid capacity, or the shared indices are corrupt.
    pub fn discard_coverage_at_restore(
        &self,
        entries: &[CoverageEntry],
    ) -> Result<u64, SpscRingError> {
        let _producer = self
            .enter_producer()
            .ok_or(SpscRingError::ProducerBarrierHeld)?;
        let capacity = validated_capacity(entries)?;
        let tail = self.write_idx.load(Ordering::Relaxed);
        let head = self.read_idx.load(Ordering::Acquire);
        let _live = live_count(head, tail, capacity)?;
        self.write_idx.store(head, Ordering::Release);
        Ok(head)
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

    pub(crate) fn enter_consumer(&self) -> Option<RingConsumerAdmission<'_>> {
        self.enter_consumer_with_hook(|| {})
    }

    fn enter_producer_with_hook(
        &self,
        after_initial_load: impl FnOnce(),
    ) -> Option<RingProducerAdmission<'_>> {
        let mut observed = self.producer_state.load(Ordering::SeqCst);
        after_initial_load();
        loop {
            if observed & RING_ADMISSION_HELD != 0 {
                return None;
            }
            let count = observed & RING_ADMISSION_COUNT_MASK;
            let Some(next_count) = count.checked_add(1) else {
                std::process::abort();
            };
            if next_count > RING_ADMISSION_COUNT_MASK {
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

    fn enter_consumer_with_hook(
        &self,
        after_initial_load: impl FnOnce(),
    ) -> Option<RingConsumerAdmission<'_>> {
        let mut observed = self.consumer_state.load(Ordering::SeqCst);
        after_initial_load();
        loop {
            if observed & RING_ADMISSION_HELD != 0 {
                return None;
            }
            let count = observed & RING_ADMISSION_COUNT_MASK;
            let Some(next_count) = count.checked_add(1) else {
                std::process::abort();
            };
            if next_count > RING_ADMISSION_COUNT_MASK {
                std::process::abort();
            }
            match self.consumer_state.compare_exchange(
                observed,
                next_count,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_previous) => return Some(RingConsumerAdmission { ring: self }),
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
        let _consumer = self
            .enter_consumer()
            .ok_or(SpscRingError::ConsumerBarrierHeld)?;
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
    /// Returns [`SpscRingError`] when consumer admission is held, the coverage
    /// slice has invalid capacity, or the shared indices describe more live
    /// entries than the queue can hold.
    pub fn dequeue_coverage(
        &self,
        entries: &[CoverageEntry],
    ) -> Result<Option<CoverageEntry>, SpscRingError> {
        let _consumer = self
            .enter_consumer()
            .ok_or(SpscRingError::ConsumerBarrierHeld)?;
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
    /// Returns [`SpscRingError`] when consumer admission is held, the marker
    /// slice has invalid capacity, or the shared indices describe more live
    /// entries than the queue can hold.
    pub fn dequeue_whitebox_marker(
        &self,
        entries: &[WhiteboxMarkerEntry],
    ) -> Result<Option<WhiteboxMarkerEntry>, SpscRingError> {
        let _consumer = self
            .enter_consumer()
            .ok_or(SpscRingError::ConsumerBarrierHeld)?;
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

    /// Observes whether a white-box envelope is available without copying it.
    ///
    /// This advisory observation neither validates an entry nor admits a
    /// consumer. The SPSC consumer must still peek or dequeue before using an
    /// entry; a producer publication after an empty observation remains pending.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when the entry slice has invalid capacity or
    /// the shared indices describe more live entries than the queue can hold.
    pub fn has_whitebox_marker(
        &self,
        entries: &[WhiteboxMarkerEntry],
    ) -> Result<bool, SpscRingError> {
        let capacity = validated_capacity(entries)?;
        let head = self.read_idx.load(Ordering::Relaxed);
        let tail = self.write_idx.load(Ordering::Acquire);
        live_count(head, tail, capacity).map(|count| count != 0)
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
    /// Returns [`SpscRingError`] when consumer admission is held, the entry
    /// slice has invalid capacity, shared indices describe more live entries
    /// than the queue can hold, or the next untrusted cross-process entry is
    /// malformed. A malformed entry is not consumed, allowing the caller to
    /// treat the channel as failed.
    pub fn dequeue_guest_introspection(
        &self,
        entries: &[GuestIntrospectionEntry],
    ) -> Result<Option<GuestIntrospectionEntry>, SpscRingError> {
        let _consumer = self
            .enter_consumer()
            .ok_or(SpscRingError::ConsumerBarrierHeld)?;
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
    /// Returns [`SpscRingError`] when consumer admission is held, geometry or
    /// indices are invalid, or the next cross-process entry is malformed.
    /// Malformed entries remain queued.
    pub fn dequeue_accelerator(
        &self,
        entries: &[AcceleratorEntry],
    ) -> Result<Option<AcceleratorEntry>, SpscRingError> {
        let _consumer = self
            .enter_consumer()
            .ok_or(SpscRingError::ConsumerBarrierHeld)?;
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
    /// Returns [`SpscRingError`] when consumer admission is held, the queue
    /// changed unexpectedly, is empty, or its next validated entry does not
    /// carry `expected_sequence`.
    pub fn commit_guest_introspection(
        &self,
        entries: &[GuestIntrospectionEntry],
        expected_sequence: u64,
    ) -> Result<(), SpscRingError> {
        let _consumer = self
            .enter_consumer()
            .ok_or(SpscRingError::ConsumerBarrierHeld)?;
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

    pub(crate) fn consumer_state_raw(&self) -> u64 {
        self.consumer_state.load(Ordering::SeqCst)
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
#[path = "ring_coverage/whitebox_availability_tests.rs"]
mod whitebox_availability_tests;

#[cfg(test)]
mod admission_barrier_tests {
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

    #[test]
    fn hold_rejects_late_consumers_without_advancing_the_ring() {
        let ring = RingHeader::new();
        let frame = FrameEntry::new(11, 0, 1, b"packet")
            .unwrap_or_else(|error| panic!("valid frame should build: {error}"));
        let mut entries = vec![FrameEntry::default(); 2];
        ring.enqueue(&mut entries, &frame)
            .unwrap_or_else(|error| panic!("open producer gate should enqueue: {error}"));

        assert!(ring.hold_hot_fork_consumers().quiescent());
        assert_eq!(
            ring.dequeue(&entries),
            Err(SpscRingError::ConsumerBarrierHeld)
        );
        assert_eq!(ring.read_index(), 0);

        let released = ring.release_hot_fork_consumers();
        assert!(!released.held());
        assert_eq!(ring.dequeue(&entries), Ok(Some(frame)));
        assert_eq!(ring.read_index(), 1);
    }

    #[test]
    fn hold_between_load_and_admission_cas_rejects_racing_consumer() {
        let ring = Arc::new(RingHeader::new());
        let loaded = Arc::new(Barrier::new(2));
        let resume = Arc::new(Barrier::new(2));
        let racing_ring = Arc::clone(&ring);
        let racing_loaded = Arc::clone(&loaded);
        let racing_resume = Arc::clone(&resume);
        let consumer = std::thread::spawn(move || {
            racing_ring
                .enter_consumer_with_hook(|| {
                    racing_loaded.wait();
                    racing_resume.wait();
                })
                .is_some()
        });

        loaded.wait();
        assert!(ring.hold_hot_fork_consumers().quiescent());
        resume.wait();
        let admitted = consumer
            .join()
            .unwrap_or_else(|_panic| panic!("consumer thread should finish"));
        assert!(!admitted);
        assert!(ring.consumer_barrier_snapshot().quiescent());
    }
}

/// Holds both ring admissions until the original stopped request transaction.
///
/// Its endpoint is a prepared physical cursor, not checkpoint or native phase
/// authority. Construction validates the drained ring while retaining both
/// admission barriers; no further fallible storage operation occurs at commit.
pub struct PreparedStoppedRingCursor<'a> {
    ring: &'a RingHeader,
    endpoint: u64,
    _consumer: StoppedCursorAdmission<'a>,
    _producer: StoppedCursorAdmission<'a>,
}

impl PreparedStoppedRingCursor<'_> {
    /// Commits the captured endpoint while both ring admissions remain held.
    ///
    /// The caller invokes this inside its original claimed restore fields
    /// effect, after every fallible request preflight. This changes only the
    /// physical cursors; canonical sequences and native permission are separate.
    pub fn commit(self) {
        self.ring.read_idx.store(self.endpoint, Ordering::Release);
        self.ring.write_idx.store(self.endpoint, Ordering::Release);
    }
}

// Only a successful zero-to-held claim constructs this guard. A stopped
// restore never releases a barrier owned by another transaction.
struct StoppedCursorAdmission<'a>(&'a AtomicU64);

impl Drop for StoppedCursorAdmission<'_> {
    fn drop(&mut self) {
        self.0.store(0, Ordering::SeqCst);
    }
}

#[cfg(test)]
mod stopped_cursor_tests {
    use super::*;

    #[test]
    fn stopped_cursor_rebinds_only_a_drained_unowned_ring() -> Result<(), SpscRingError> {
        let ring = RingHeader::default();
        let prepared = ring.prepare_drained_cursor_while_stopped(37)?;
        assert_eq!((ring.read_index(), ring.write_index()), (0, 0));
        assert!(ring.producer_barrier_snapshot().quiescent());
        assert!(ring.consumer_barrier_snapshot().quiescent());
        drop(prepared);
        assert_eq!((ring.read_index(), ring.write_index()), (0, 0));
        assert!(!ring.producer_barrier_snapshot().held());
        assert!(!ring.consumer_barrier_snapshot().held());
        ring.prepare_drained_cursor_while_stopped(37)?.commit();
        assert_eq!((ring.read_index(), ring.write_index()), (37, 37));
        assert_eq!(ring.producer_barrier_snapshot().in_flight(), 0);
        assert!(!ring.consumer_barrier_snapshot().held());
        let producer = ring
            .enter_producer()
            .unwrap_or_else(|| panic!("producer must be admitted"));
        assert!(matches!(
            ring.prepare_drained_cursor_while_stopped(91),
            Err(SpscRingError::RestoreCursorBusy)
        ));
        assert_eq!((ring.read_index(), ring.write_index()), (37, 37));
        assert!(!ring.consumer_barrier_snapshot().held());
        drop(producer);
        assert!(ring.hold_hot_fork_consumers().held());
        assert!(matches!(
            ring.prepare_drained_cursor_while_stopped(91),
            Err(SpscRingError::RestoreCursorBusy)
        ));
        assert!(ring.consumer_barrier_snapshot().held());
        assert!(!ring.release_hot_fork_consumers().held());
        ring.write_idx.store(38, Ordering::Release);
        assert!(matches!(
            ring.prepare_drained_cursor_while_stopped(91),
            Err(SpscRingError::RestoreCursorNotDrained {
                read: 37,
                write: 38
            })
        ));
        assert_eq!((ring.read_index(), ring.write_index()), (37, 38));
        assert!(!ring.producer_barrier_snapshot().held());
        assert!(!ring.consumer_barrier_snapshot().held());
        Ok(())
    }
}
