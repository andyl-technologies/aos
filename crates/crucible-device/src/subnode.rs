//! The uniform I/O sub-node trait and its deterministic core.
//!
//! This module owns the shared abstraction behind every request/response I/O
//! sub-node — disk and 9p, with network links reusing the in-flight ordering
//! pieces for frame delivery. It defines:
//! - [`IoSubNode`]: the trait a concrete device implements. It supplies a
//!   per-request `compute` (the COMPUTE step: status + payload, may touch the
//!   host filesystem/overlay at any wall-clock instant) and inherits the
//!   uniform request inbox, response outbox, virtual clock, in-flight queue,
//!   `advance_to`, and snapshot/restore wiring from [`IoCore`].
//! - [`IoCore`]: the reusable lifecycle engine. It owns the
//!   [`VirtualClock`], the in-process harness inbox and outbox (deterministic
//!   [`BoundedQueue`]s), the shmem bridge for
//!   real [`crucible_shmem::RingHeader`] / [`crucible_shmem::FrameEntry`] rings,
//!   and the delivery-ordered [`InflightQueue`].
//!
//! The COMPUTE-then-DELIVER split is the crux ([IO-2], [IO-31]): on
//! [`IoCore::process_inbox`], each arrived request is COMPUTEd *now* and its
//! `delivery_icount = ceil_ns_to_icount(virtual_ns(request_icount) + latency)`
//! is fixed; the response then sits in the in-flight queue, *invisible* until
//! [`IoCore::advance_to`] moves the clock to its delivery icount. Host COMPUTE
//! wall-clock never enters the delivery icount or any payload byte.
//! ```text
//! enqueue_request(t) -> inbox                         (ARRIVE)
//! process_inbox(device):                              (COMPUTE)
//!   for each request:
//!     (status, payload) = device.compute(request)     -- host FS/overlay now
//!     delivery = ceil_ns_to_icount(vt(t) + latency)    -- pure virtual time
//!     inflight.insert(PendingResponse{ delivery, .. }) (PENDING)
//! next_exact_local_event() = inflight head delivery    (scheduler reads this)
//! advance_to(limit):                                   (DELIVER)
//!   clock.advance_to(limit)
//!   outbox <- inflight.drain_due(limit)                (visible at exact icount)
//! ```
//! The shmem-backed methods [`IoCore::process_shmem_inbox`] and
//! [`IoCore::advance_to_shmem`] perform the same lifecycle against real SPSC ring
//! storage: freeing VM-to-device slots wakes the producer, publishing
//! device-to-VM responses wakes the consumer, and a full response ring leaves
//! not-yet-published responses in flight at their original `delivery_icount`.

use crucible_shmem::{
    FrameDeliveryKey, FrameEntry, NodeSlot, RingHeader, SpscRingError, WakeAction,
};

use crate::backpressure::{BackpressureState, BoundedQueue, PushError};
use crate::clock::VirtualClock;
use crate::error::DeviceError;
use crate::inflight::{InflightQueue, PendingResponse};
use crate::request::{ComputedResponse, LatencyModel, Request, Response};

mod frame;
mod io_core_private;
mod snapshot;

use frame::{frame_from_pending_response, request_from_frame};
pub use snapshot::{
    IoCoreSnapshotCodecError, ShmemDeliveryResult, ShmemDequeueResult, ShmemInboxProcess,
};

/// A concrete I/O sub-node: the COMPUTE half of the uniform lifecycle.
///
/// Implementors supply the device semantics — how a request maps to a response
/// status and payload, and the latency model — while [`IoCore`] supplies the
/// uniform clock, rings, in-flight tracking, `advance_to`, and snapshot/restore.
/// Every method MUST be a deterministic function of the request and the device's
/// owned state ([IO-4]); none may read the host clock, host scheduling, or host
/// filesystem ordering.
pub trait IoSubNode {
    /// The latency model this device applies to derive completion times.
    type Latency: LatencyModel;

    /// Device-owned state needed to roll back a failed COMPUTE transaction.
    type ComputeCheckpoint;

    /// Returns the device's latency model.
    fn latency_model(&self) -> &Self::Latency;

    /// Captures device-owned state before COMPUTE mutates it.
    fn compute_checkpoint(&self) -> Self::ComputeCheckpoint;

    /// Restores device-owned state when response scheduling cannot be committed.
    fn restore_compute_checkpoint(&mut self, checkpoint: Self::ComputeCheckpoint);

    /// COMPUTEs the response status and payload for `request`.
    ///
    /// This is the host-access step: the implementor may read its overlay, base
    /// image, or served tree at any wall-clock instant. The returned value MUST
    /// be a pure function of the request and the device's owned state — the
    /// wall-clock duration of this call MUST NOT influence the result ([IO-31]).
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the device cannot COMPUTE a response (for
    /// example a malformed request the device rejects before producing wire
    /// bytes). Devices that answer errors *in band* (an error-status response)
    /// return `Ok` with [`crate::request::ResponseStatus::Error`] instead.
    fn compute(&mut self, request: &Request) -> Result<ComputedResponse, DeviceError>;
}

/// Failure from shared-memory delivery with an exact publication count.
///
/// A nonzero `published` count is a guest-visible commit boundary: callers must
/// not roll back device or evaluator state after observing it.
#[derive(Debug)]
pub struct ShmemDeliveryFailure {
    /// Number of response frames release-published before the failure.
    pub published: usize,
    /// Underlying deterministic device or shared-memory failure.
    pub source: DeviceError,
}

/// The deterministic lifecycle engine shared by every I/O sub-node.
///
/// `IoCore` owns the virtual clock, the inbound request ring, the outbound
/// response ring, and the delivery-ordered in-flight queue. A concrete device
/// composes an `IoCore` and drives it with [`IoCore::process_inbox`] (COMPUTE)
/// and [`IoCore::advance_to`] (DELIVER). The core never advances its own clock
/// and never reads host time ([IO-1]).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoCore {
    clock: VirtualClock,
    inbox: BoundedQueue<Request>,
    outbox: BoundedQueue<PendingResponse>,
    inflight: InflightQueue,
    /// The source-node id stamped into delivery keys (the sub-node's own id).
    src_node: u32,
    /// The next per-request sequence number, for deterministic tie-breaking.
    next_seq: u32,
}

/// A captured, restorable snapshot of an [`IoCore`]'s deterministic state.
///
/// This is the device-agnostic half of a sub-node's `MaterializedState`
/// contribution: the clock cursor, the pending inbound requests, the in-flight
/// responses with their delivery icounts, and the outbound responses awaiting
/// pickup. Restoring it reproduces a state byte-identical to an uninterrupted
/// run ([IO-31] lifecycle replay). Concrete devices extend it with their own
/// overlay/fid/RNG state in later changesets.
///
/// The rings' monotonic `write_idx`/`read_idx` counters are intentionally *not*
/// persisted: only the live depth (the buffered entries) is architecturally
/// observable, so restore rebuilds the indices from zero by re-pushing the
/// captured entries. Two snapshots with identical live contents are equal
/// regardless of how many wraps the original counters had seen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IoCoreSnapshot {
    /// The sub-node's current icount at snapshot time.
    pub current_icount: u64,
    /// The fixed virtual-time shift in bits.
    pub shift_bits: u8,
    /// The sub-node's source-node id.
    pub src_node: u32,
    /// The next per-request sequence number.
    pub next_seq: u32,
    /// The inbound-ring capacity in entries.
    pub inbox_capacity: u64,
    /// The outbound-ring capacity in entries.
    pub outbox_capacity: u64,
    /// The pending inbound requests, in arrival order.
    pub inbox: Vec<Request>,
    /// The in-flight responses, in delivery order.
    pub inflight: Vec<PendingResponse>,
    /// The outbound responses awaiting consumer pickup, in delivery order.
    pub outbox: Vec<PendingResponse>,
}

impl IoCore {
    /// Creates an I/O core with the given clock shift, node id, and ring sizes.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::Clock`] when `shift_bits >= 64`, and
    /// [`DeviceError::RingFull`] (the capacity-shape rejection) when either ring
    /// capacity is zero or not a power of two.
    pub fn new(
        shift_bits: u8,
        src_node: u32,
        inbox_capacity: u64,
        outbox_capacity: u64,
    ) -> Result<Self, DeviceError> {
        Ok(Self {
            clock: VirtualClock::new(shift_bits)?,
            inbox: BoundedQueue::new(inbox_capacity)?,
            outbox: BoundedQueue::new(outbox_capacity)?,
            inflight: InflightQueue::new(),
            src_node,
            next_seq: 0,
        })
    }

    /// Returns the sub-node's current icount.
    #[must_use]
    pub fn current_icount(&self) -> u64 {
        self.clock.current_icount()
    }

    /// Returns the fixed virtual-time shift in bits.
    #[must_use]
    pub fn shift_bits(&self) -> u8 {
        self.clock.shift_bits()
    }

    /// Returns the producer's inbound backpressure condition.
    #[must_use]
    pub fn inbox_state(&self) -> BackpressureState {
        self.inbox.state()
    }

    /// Returns the number of in-flight (computed-not-delivered) responses.
    #[must_use]
    pub fn inflight_len(&self) -> usize {
        self.inflight.len()
    }

    /// Returns the next computed response without crossing its delivery boundary.
    #[must_use]
    pub(crate) fn next_pending_response(&self) -> Option<&PendingResponse> {
        self.inflight.entries().first()
    }

    /// Copies the in-flight queue for a device-owned transactional rewrite.
    pub(crate) fn take_inflight_from_snapshot(&self) -> Vec<PendingResponse> {
        self.inflight.entries().to_vec()
    }

    /// Verifies that `count` device-generated responses can receive sequence IDs.
    pub(crate) fn check_response_sequence_capacity(&self, count: usize) -> Result<(), DeviceError> {
        let count = u32::try_from(count).map_err(|_| DeviceError::ResponseSequenceOverflow {
            sequence: self.next_seq,
        })?;
        self.next_seq
            .checked_add(count)
            .ok_or(DeviceError::ResponseSequenceOverflow {
                sequence: self.next_seq,
            })?;
        Ok(())
    }

    /// Discards every computed response that has not yet been delivered.
    ///
    /// Returns the discarded responses in deterministic delivery order. Crash
    /// fault handling uses this to void a node's in-flight I/O without advancing
    /// the device clock or making any response visible.
    pub fn discard_inflight(&mut self) -> Vec<PendingResponse> {
        self.inflight.drain_all()
    }

    /// Removes every computed response for a device-owned transactional rewrite.
    pub(crate) fn take_inflight(&mut self) -> Vec<PendingResponse> {
        self.inflight.drain_all()
    }

    /// Reinstalls responses after a device-owned transactional rewrite.
    pub(crate) fn replace_inflight(
        &mut self,
        responses: impl IntoIterator<Item = PendingResponse>,
    ) {
        for response in responses {
            self.inflight.insert(response);
        }
    }

    /// Advances the clock and publishes at most one due response locally.
    ///
    /// The returned copy identifies the exact response that crossed the
    /// delivery boundary. `None` means either no response is due or the bounded
    /// outbox is full; in both cases every unpublished response remains in
    /// flight unchanged.
    pub(crate) fn deliver_one(
        &mut self,
        limit: u64,
    ) -> Result<Option<PendingResponse>, DeviceError> {
        self.clock.advance_to(limit)?;
        let mut due = self.inflight.drain_due(limit).into_iter();
        let Some(pending) = due.next() else {
            return Ok(None);
        };
        let observed = pending.clone();
        if let Err(rejected) = self.outbox.push(pending) {
            self.inflight.insert(rejected.into_item());
            self.replace_inflight(due);
            return Ok(None);
        }
        self.replace_inflight(due);
        Ok(Some(observed))
    }

    /// Advances the clock and publishes at most one due response to shmem.
    ///
    /// The returned response crossed the ring boundary before it is reported.
    /// A full ring returns `None` without consuming or mutating the response.
    pub(crate) fn deliver_one_shmem(
        &mut self,
        limit: u64,
        outbox: &RingHeader,
        outbox_entries: &mut [FrameEntry],
        _consumer_slot: &NodeSlot,
    ) -> Result<Option<PendingResponse>, DeviceError> {
        self.clock.advance_to(limit)?;
        let mut due = self.inflight.drain_due(limit).into_iter();
        let Some(pending) = due.next() else {
            return Ok(None);
        };
        let frame = match frame_from_pending_response(&pending) {
            Ok(frame) => frame,
            Err(error) => {
                self.inflight.insert(pending);
                self.replace_inflight(due);
                return Err(error);
            }
        };
        match outbox.enqueue(outbox_entries, &frame) {
            Ok(()) => {
                self.replace_inflight(due);
                Ok(Some(pending))
            }
            Err(SpscRingError::QueueFull { .. }) => {
                self.inflight.insert(pending);
                self.replace_inflight(due);
                Ok(None)
            }
            Err(error) => {
                self.inflight.insert(pending);
                self.replace_inflight(due);
                Err(DeviceError::from(error))
            }
        }
    }

    /// Schedules an externally released response at the current exact icount.
    ///
    /// Recovery and timeout events use this entry point to release a completion
    /// that a device retained during COMPUTE. Scheduling at the current clock
    /// coordinate preserves the event's authoritative virtual-time ordering.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::ResponseSequenceOverflow`] if the canonical
    /// completion-order sequence is exhausted.
    pub fn schedule_response_now(&mut self, response: Response) -> Result<(), DeviceError> {
        let delivery_icount = self.clock.current_icount();
        self.insert_computed_response(delivery_icount, response)
    }

    /// Schedules a fully computed response from an exact virtual-time boundary.
    ///
    /// Device-owned service queues use this after real work completes. The
    /// computed response's dynamic latency and duplicate gaps are applied from
    /// `base_completion_nanos`, then converted with the core's fixed clock.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for invalid response shape, time/sequence
    /// overflow, or a completion that would be inserted in the past.
    pub(crate) fn schedule_computed_response_at_nanos(
        &mut self,
        base_completion_nanos: u64,
        computed: ComputedResponse,
    ) -> Result<(), DeviceError> {
        self.insert_computed_at_nanos(base_completion_nanos, computed)
    }

    /// Enqueues a request into the inbound ring (the ARRIVE step).
    ///
    /// The request lands at the requester's emit icount; it is COMPUTEd later by
    /// [`IoCore::process_inbox`].
    ///
    /// # Errors
    ///
    /// Returns [`PushError`] (carrying the rejected request) when the inbound
    /// ring is full; the producer must block at its boundary and re-push the
    /// handed-back request after the device drains the inbox ([IO-32]). The
    /// request is not consumed.
    pub fn enqueue_request(&mut self, request: Request) -> Result<(), PushError<Request>> {
        self.inbox.push(request)
    }

    /// COMPUTEs every pending request and inserts each response in flight.
    ///
    /// For each inbound request this drives `device.compute` (the host-access
    /// COMPUTE step) and fixes `delivery_icount = ceil_ns_to_icount(
    /// virtual_ns(request_icount) + latency_ns(request))` ([IO-2]). The response
    /// is inserted into the delivery-ordered in-flight queue; it stays invisible
    /// until [`IoCore::advance_to`] reaches its delivery icount.
    ///
    /// The host wall-clock instant of `compute` influences neither the
    /// `delivery_icount` nor any payload byte ([IO-31]).
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::CompletionOverflow`] when the latency pushes the
    /// completion past the representable nanosecond range, [`DeviceError::Clock`]
    /// or [`DeviceError::IcountOverflow`] when virtual-time conversion fails,
    /// [`DeviceError::DeliveryInPast`] when a computed `delivery_icount` lands
    /// strictly before the sub-node's current icount (the fail-loud guard of
    /// RFC §15.1.1, [IO-31]), and any [`DeviceError`] the device's `compute`
    /// raises. On error the offending request and every later inbox entry remain
    /// queued for an exact retry.
    pub fn process_inbox<D>(&mut self, device: &mut D) -> Result<(), DeviceError>
    where
        D: IoSubNode,
    {
        while let Some(request) = self.inbox.front().cloned() {
            self.compute_request(device, request)?;
            let _committed = self.inbox.pop();
        }
        Ok(())
    }

    /// Drains a real shared-memory request ring and COMPUTEs each request.
    ///
    /// This is the shmem-backed form of [`IoCore::process_inbox`]. It consumes
    /// `FrameEntry` values from a VM-to-device [`RingHeader`], maps each frame to
    /// the uniform [`Request`] shape, wakes the producer slot after freeing each
    /// ring entry, and inserts the COMPUTEd response into the ordered in-flight
    /// queue. No request is dropped or reordered: frames are consumed in SPSC FIFO
    /// order, then completions are ordered by `(delivery_icount, src_node, seq)`.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the ring is corrupt, a frame advertises an
    /// invalid payload length, the producer wake fails, or COMPUTE/delivery-time
    /// validation fails.
    pub fn process_shmem_inbox<D>(
        &mut self,
        device: &mut D,
        inbox: &RingHeader,
        inbox_entries: &[FrameEntry],
        producer_slot: &NodeSlot,
    ) -> Result<ShmemInboxProcess, DeviceError>
    where
        D: IoSubNode,
    {
        let mut result = ShmemInboxProcess {
            processed: 0,
            request_kinds: Vec::new(),
            first_request_icount: None,
            producer_wakes: Vec::new(),
        };
        loop {
            let one =
                self.process_one_shmem_request(device, inbox, inbox_entries, producer_slot)?;
            if one.processed == 0 {
                break;
            }
            result.processed += one.processed;
            result.request_kinds.extend(one.request_kinds);
            if result.first_request_icount.is_none() {
                result.first_request_icount = one.first_request_icount;
            }
            result.producer_wakes.extend(one.producer_wakes);
        }
        Ok(result)
    }

    /// Dequeues and COMPUTEs at most one shared-memory request.
    ///
    /// This single-request form lets a host dispatcher pin the head request's
    /// completion coordinate before dispatching exactly that request to a
    /// worker. It preserves the same SPSC dequeue, producer wake, and COMPUTE
    /// semantics as [`Self::process_shmem_inbox`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::process_shmem_inbox`].
    pub fn process_one_shmem_request<D>(
        &mut self,
        device: &mut D,
        inbox: &RingHeader,
        inbox_entries: &[FrameEntry],
        producer_slot: &NodeSlot,
    ) -> Result<ShmemInboxProcess, DeviceError>
    where
        D: IoSubNode,
    {
        let mut request_kinds = Vec::new();
        let mut first_request_icount = None;
        let mut producer_wakes = Vec::new();
        let processed = if let Some(frame) = inbox.peek(inbox_entries)? {
            first_request_icount.get_or_insert(frame.delivery_icount);
            let request = request_from_frame(&frame)?;
            request_kinds.push(request.payload.first().copied());
            self.compute_request(device, request)?;
            let committed = inbox
                .dequeue(inbox_entries)?
                .ok_or(DeviceError::InvalidComputedResponse)?;
            if committed != frame {
                return Err(DeviceError::InvalidComputedResponse);
            }
            let wake = producer_slot.wake_for_device_io_release()?;
            producer_wakes.push(wake);
            1
        } else {
            0
        };
        Ok(ShmemInboxProcess {
            processed,
            request_kinds,
            first_request_icount,
            producer_wakes,
        })
    }

    /// Computes the exact delivery icount for a request under a latency model.
    ///
    /// `delivery_icount = ceil_ns_to_icount(virtual_ns(request_icount) + latency)`
    /// — a pure function of the request icount, the modeled latency, and the
    /// fixed shift ([IO-2], [IO-22]).
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::CompletionOverflow`] when the nanosecond sum
    /// overflows `u64`, and [`DeviceError::Clock`] / [`DeviceError::IcountOverflow`]
    /// when a virtual-time conversion fails.
    pub fn compute_delivery_icount<L>(
        &self,
        request: &Request,
        latency: &L,
    ) -> Result<u64, DeviceError>
    where
        L: LatencyModel,
    {
        let base_ns = self.clock.virtual_ns(request.request_icount)?;
        let latency_ns = latency.latency_ns(request);
        let completion_ns =
            base_ns
                .checked_add(latency_ns)
                .ok_or(DeviceError::CompletionOverflow {
                    request_icount: request.request_icount,
                    latency_ns,
                })?;
        self.clock.ceil_ns_to_icount(completion_ns)
    }

    /// Returns the in-flight head's delivery icount: the next exact local event.
    ///
    /// This is what the scheduler reads to bound the requester's horizon
    /// ([IO-3], [IO-31]). Returns `None` when nothing is in flight.
    #[must_use]
    pub fn next_exact_local_event(&self) -> Option<u64> {
        self.inflight.next_exact_local_event()
    }

    /// Advances the clock to `limit` and DELIVERs every due response.
    ///
    /// Drains exactly the in-flight responses whose `delivery_icount <= limit`,
    /// in deterministic `(delivery_icount, src_node, seq)` order, pushing each
    /// onto the outbound ring at its exact delivery icount ([IO-2], [SCHED-29]).
    /// The clock advances to `limit` (never backward).
    ///
    /// If the outbound ring fills mid-drain, delivery stops at that boundary:
    /// the undelivered responses remain in flight (still ordered, still at their
    /// exact icounts) and the producer is backpressured ([IO-32]). The returned
    /// count is the number of responses made visible on the outbound ring.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::ClockRegression`] when `limit` is below the current
    /// icount.
    pub fn advance_to(&mut self, limit: u64) -> Result<usize, DeviceError> {
        self.clock.advance_to(limit)?;
        let due = self.inflight.drain_due(limit);
        let mut delivered = 0;
        let mut requeue: Vec<PendingResponse> = Vec::new();
        let mut iter = due.into_iter();
        for pending in iter.by_ref() {
            // The full-ring check gates the push, so `push` cannot reject below;
            // a `PushError` would only arise from a logic error, in which case
            // the handed-back item is re-queued in flight (never dropped).
            match self.outbox.push(pending) {
                Ok(()) => delivered += 1,
                Err(rejected) => {
                    // Outbound ring full: stop at this boundary, keep the rest in
                    // flight at their exact delivery icounts (never drop/reorder).
                    requeue.push(rejected.into_item());
                    break;
                }
            }
            if self.outbox.state() == BackpressureState::Blocked {
                // Ring just filled: stop before attempting another push.
                break;
            }
        }
        // Any responses past the backpressure boundary go back in flight.
        for pending in requeue.into_iter().chain(iter) {
            self.inflight.insert(pending);
        }
        Ok(delivered)
    }

    /// Advances the clock and publishes due responses to a real shmem ring.
    ///
    /// This is the shmem-backed form of [`IoCore::advance_to`]. It drains due
    /// in-flight responses in deterministic order and release-publishes each as a
    /// [`FrameEntry`] into the device-to-VM [`RingHeader`]. If the response ring
    /// is full, the not-yet-published response and all later due responses are
    /// reinserted into the in-flight queue at their original delivery icounts, so
    /// backpressure never drops, reorders, or re-times a response. When at least
    /// one response is published, the consumer slot is woken with
    /// [`NodeSlot::wake_for_frame_delivery`].
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::ClockRegression`] when `limit` is below the current
    /// icount, [`DeviceError`] for oversized response frames or corrupt ring
    /// state, and [`DeviceError::ShmemWake`] when the consumer wake fails after a
    /// successful publication.
    pub fn advance_to_shmem_with_commit_status(
        &mut self,
        limit: u64,
        outbox: &RingHeader,
        outbox_entries: &mut [FrameEntry],
        consumer_slot: &NodeSlot,
    ) -> Result<ShmemDeliveryResult, ShmemDeliveryFailure> {
        self.clock
            .advance_to(limit)
            .map_err(|source| ShmemDeliveryFailure {
                published: 0,
                source,
            })?;
        let due = self.inflight.drain_due(limit);
        let mut delivered = 0;
        let mut remaining = due.into_iter();
        while let Some(pending) = remaining.next() {
            let frame = match frame_from_pending_response(&pending) {
                Ok(frame) => frame,
                Err(error) => {
                    self.requeue_pending(pending, remaining);
                    return Err(ShmemDeliveryFailure {
                        published: delivered,
                        source: error,
                    });
                }
            };
            match outbox.enqueue(outbox_entries, &frame) {
                Ok(()) => delivered += 1,
                Err(SpscRingError::QueueFull { .. }) => {
                    self.requeue_pending(pending, remaining);
                    break;
                }
                Err(error) => {
                    self.requeue_pending(pending, remaining);
                    return Err(ShmemDeliveryFailure {
                        published: delivered,
                        source: DeviceError::from(error),
                    });
                }
            }
        }

        let consumer_wake = if delivered == 0 {
            None
        } else {
            Some(consumer_slot.wake_for_frame_delivery().map_err(|source| {
                ShmemDeliveryFailure {
                    published: delivered,
                    source: DeviceError::from(source),
                }
            })?)
        };
        Ok(ShmemDeliveryResult {
            delivered,
            consumer_wake,
        })
    }

    /// Advances the clock and publishes due responses to a real shmem ring.
    ///
    /// # Errors
    ///
    /// Returns the underlying delivery error. Callers that own a transactional
    /// boundary should use [`Self::advance_to_shmem_with_commit_status`] so they
    /// can distinguish failures before and after publication.
    pub fn advance_to_shmem(
        &mut self,
        limit: u64,
        outbox: &RingHeader,
        outbox_entries: &mut [FrameEntry],
        consumer_slot: &NodeSlot,
    ) -> Result<ShmemDeliveryResult, DeviceError> {
        self.advance_to_shmem_with_commit_status(limit, outbox, outbox_entries, consumer_slot)
            .map_err(|failure| failure.source)
    }

    /// Pops the next delivered response from the outbound ring, if any.
    ///
    /// Returns responses in the deterministic delivery order they were made
    /// visible. Popping frees an outbound slot, waking a backpressured producer
    /// ([IO-32]).
    pub fn pop_response(&mut self) -> Option<PendingResponse> {
        self.outbox.pop()
    }

    /// Dequeues one shared-memory frame and wakes the producer if a slot was freed.
    ///
    /// This helper is the consumer-side half of deterministic full-ring
    /// backpressure. A successful dequeue release-frees a ring slot via
    /// [`RingHeader::dequeue`], then wakes the producer with
    /// [`NodeSlot::wake_for_device_io_release`] so a producer blocked on a full
    /// ring can retry the exact same frame.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the ring is corrupt or the wake fails.
    pub fn dequeue_shmem_frame_and_wake_producer(
        ring: &RingHeader,
        entries: &[FrameEntry],
        producer_slot: &NodeSlot,
    ) -> Result<ShmemDequeueResult, DeviceError> {
        let frame = ring.dequeue(entries)?;
        let producer_wake = if frame.is_some() {
            Some(producer_slot.wake_for_device_io_release()?)
        } else {
            None
        };
        Ok(ShmemDequeueResult {
            frame,
            producer_wake,
        })
    }

    /// Captures the core's deterministic state for snapshot/restore.
    ///
    /// The snapshot holds the clock cursor, pending inbox requests, in-flight
    /// responses with their delivery icounts, and outbound responses — all in
    /// deterministic order. Restoring via [`IoCore::restore`] reproduces a
    /// byte-identical state ([IO-31] lifecycle replay).
    #[must_use]
    pub fn snapshot(&self) -> IoCoreSnapshot {
        IoCoreSnapshot {
            current_icount: self.clock.current_icount(),
            shift_bits: self.clock.shift_bits(),
            src_node: self.src_node,
            next_seq: self.next_seq,
            inbox_capacity: self.inbox.capacity(),
            outbox_capacity: self.outbox.capacity(),
            inbox: self.inbox.iter().cloned().collect(),
            inflight: self.inflight.entries().to_vec(),
            outbox: self.outbox.iter().cloned().collect(),
        }
    }

    /// Reconstructs an [`IoCore`] from a captured snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::Clock`] when the snapshot's shift is invalid,
    /// [`DeviceError::RingFull`] when a ring capacity is not a power of two, and
    /// [`DeviceError::ClockRegression`] is impossible here (the clock is set
    /// directly). A ring whose captured contents exceed its capacity is rejected
    /// with [`DeviceError::RingFull`].
    pub fn restore(snapshot: &IoCoreSnapshot) -> Result<Self, DeviceError> {
        let mut clock = VirtualClock::new(snapshot.shift_bits)?;
        clock.advance_to(snapshot.current_icount)?;

        let mut inbox = BoundedQueue::new(snapshot.inbox_capacity)?;
        for request in &snapshot.inbox {
            inbox
                .push(request.clone())
                .map_err(|rejected| DeviceError::RingFull {
                    capacity: rejected.capacity,
                })?;
        }

        let mut outbox = BoundedQueue::new(snapshot.outbox_capacity)?;
        for pending in &snapshot.outbox {
            outbox
                .push(pending.clone())
                .map_err(|rejected| DeviceError::RingFull {
                    capacity: rejected.capacity,
                })?;
        }

        let mut inflight = InflightQueue::new();
        for pending in &snapshot.inflight {
            inflight.insert(pending.clone());
        }

        Ok(Self {
            clock,
            inbox,
            outbox,
            inflight,
            src_node: snapshot.src_node,
            next_seq: snapshot.next_seq,
        })
    }
}
