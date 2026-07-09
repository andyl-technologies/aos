//! The uniform I/O sub-node trait and its deterministic core.
//!
//! This module owns the shared abstraction behind every request/response I/O
//! sub-node — disk and 9p, with network links reusing the in-flight ordering
//! pieces for frame delivery. It defines:
//!
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
//!
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
//!
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
use crate::request::{LatencyModel, Request, Response};

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

    /// Returns the device's latency model.
    fn latency_model(&self) -> &Self::Latency;

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
    fn compute(&mut self, request: &Request) -> Result<Response, DeviceError>;
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

/// Result of draining a shared-memory request ring into an [`IoCore`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShmemInboxProcess {
    /// Number of request frames consumed and COMPUTEd.
    pub processed: usize,
    /// Wake actions issued to the request producer as ring slots were freed.
    pub producer_wakes: Vec<WakeAction>,
}

/// Result of publishing due responses into a shared-memory response ring.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShmemDeliveryResult {
    /// Number of due responses published to the shared-memory ring.
    pub delivered: usize,
    /// Wake issued to the response consumer after at least one frame was published.
    pub consumer_wake: Option<WakeAction>,
}

/// Result of consuming one frame from a shared-memory ring and waking its producer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShmemDequeueResult {
    /// The frame dequeued from the ring, if one was present.
    pub frame: Option<FrameEntry>,
    /// Wake issued to the producer after a live slot was freed.
    pub producer_wake: Option<WakeAction>,
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

    /// Discards every computed response that has not yet been delivered.
    ///
    /// Returns the discarded responses in deterministic delivery order. Crash
    /// fault handling uses this to void a node's in-flight I/O without advancing
    /// the device clock or making any response visible.
    pub fn discard_inflight(&mut self) -> Vec<PendingResponse> {
        self.inflight.drain_all()
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
    /// raises. On error the remaining inbox entries are preserved for a later
    /// retry; the offending request is consumed.
    pub fn process_inbox<D>(&mut self, device: &mut D) -> Result<(), DeviceError>
    where
        D: IoSubNode,
    {
        while let Some(request) = self.inbox.pop() {
            self.compute_request(device, request)?;
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
        let mut processed = 0;
        let mut producer_wakes = Vec::new();
        while let Some(frame) = inbox.dequeue(inbox_entries)? {
            let wake = producer_slot.wake_for_device_io_release()?;
            producer_wakes.push(wake);
            let request = request_from_frame(&frame)?;
            self.compute_request(device, request)?;
            processed += 1;
        }
        Ok(ShmemInboxProcess {
            processed,
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
    pub fn advance_to_shmem(
        &mut self,
        limit: u64,
        outbox: &RingHeader,
        outbox_entries: &mut [FrameEntry],
        consumer_slot: &NodeSlot,
    ) -> Result<ShmemDeliveryResult, DeviceError> {
        self.clock.advance_to(limit)?;
        let due = self.inflight.drain_due(limit);
        let mut delivered = 0;
        let mut remaining = due.into_iter();
        while let Some(pending) = remaining.next() {
            let frame = match frame_from_pending_response(&pending) {
                Ok(frame) => frame,
                Err(error) => {
                    self.requeue_pending(pending, remaining);
                    return Err(error);
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
                    return Err(DeviceError::from(error));
                }
            }
        }

        let consumer_wake = if delivered == 0 {
            None
        } else {
            Some(consumer_slot.wake_for_frame_delivery()?)
        };
        Ok(ShmemDeliveryResult {
            delivered,
            consumer_wake,
        })
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

    /// COMPUTEs one request and inserts its response in delivery order.
    fn compute_request<D>(&mut self, device: &mut D, request: Request) -> Result<(), DeviceError>
    where
        D: IoSubNode,
    {
        let delivery_icount = self.compute_delivery_icount(&request, device.latency_model())?;
        // Fail-loud guard ([IO-31], [IO-34]): a response whose delivery is
        // already in the consumer's past can never be made visible at its exact
        // icount, and enqueueing it would corrupt the global delivery order.
        let current_icount = self.clock.current_icount();
        if delivery_icount < current_icount {
            return Err(DeviceError::DeliveryInPast {
                delivery_icount,
                current_icount,
            });
        }
        let response = device.compute(&request)?;
        let seq = self.next_seq;
        self.next_seq = self.next_seq.wrapping_add(1);
        let key = FrameDeliveryKey {
            delivery_icount,
            src_node: self.src_node,
            seq,
        };
        self.inflight.insert(PendingResponse::new(key, response));
        Ok(())
    }

    /// Re-inserts a pending response and the remaining due responses in order.
    fn requeue_pending(
        &mut self,
        pending: PendingResponse,
        remaining: impl IntoIterator<Item = PendingResponse>,
    ) {
        self.inflight.insert(pending);
        for pending in remaining {
            self.inflight.insert(pending);
        }
    }
}

/// Converts an inbound shmem frame into the uniform request shape.
fn request_from_frame(frame: &FrameEntry) -> Result<Request, DeviceError> {
    Ok(Request::new(
        frame.delivery_icount,
        frame.seq,
        frame.payload()?.to_vec(),
    ))
}

/// Converts a pending response into an outbound shmem frame.
fn frame_from_pending_response(pending: &PendingResponse) -> Result<FrameEntry, DeviceError> {
    Ok(FrameEntry::new(
        pending.delivery_icount(),
        pending.key.src_node,
        pending.key.seq,
        &pending.response.payload,
    )?)
}
