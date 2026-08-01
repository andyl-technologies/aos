//! The 9p sub-node: an [`IoSubNode`] over a read-only filesystem tree.
//!
//! This module owns [`NinepDevice`], which implements the COMPUTE half of the
//! uniform lifecycle for 9p I/O. It decodes a 9p request frame from the request
//! payload, dispatches it through the [`NinepServer`] against the served
//! [`FsTree`] ([IO-13]..[IO-17]), and returns the encoded reply frame as the
//! response payload. The deterministic completion time is supplied by
//! [`NinepLatency`] and applied by the [`IoCore`] the device composes ([IO-22]).
//!
//! It also owns [`NinepSnapshot`], the device half of a `MaterializedState`
//! contribution: the uniform-core snapshot, the server's fid table + negotiated
//! `msize`, and the device RNG cursor — **never** the served tree
//! bytes ([IO-19], [TEMP-9]). [`NinepDevice::restore`] re-supplies the
//! content-addressed tree and re-arms the fid table and in-flight queue.
//!
//! ```text
//! request payload  = 9p request frame   (rides the SLOT_9P_IO ring)
//! compute(req):
//!   server.handle(bytes) -> 9p reply frame
//!   malformed / mutating / unknown -> Rlerror frame (never panic)
//! response payload = 9p reply frame
//! delivery_icount  = ceil(vt(request_icount) + NinepLatency::latency_ns)
//! ```

use crucible_shmem::{FrameEntry, NodeSlot, RingHeader};

use crate::clock::ceil_ns_to_icount;
use crate::error::DeviceError;
use crate::fault::{DeviceRng, IoFaultOutcome, IoFaults};
use crate::inflight::PendingResponse;
use crate::request::{LatencyModel, Request, Response, ResponseStatus};
use crate::subnode::{IoCore, IoCoreSnapshot, IoSubNode, ShmemDeliveryResult, ShmemInboxProcess};

use super::codec::{self, Message, TMessage};
use super::server::{NinepServer, NinepServerSnapshot};
use super::tree::FsTree;

/// The deterministic completion-latency model for the 9p device.
///
/// Latency is `base_op_ns(message kind) + per_byte_ns * frame_len` — a pure
/// function of the request frame and the device's configured parameters, with no
/// host-timing term ([IO-22]). Distinct per-op floors let a heavy `readdir`/
/// `read` cost more than a trivial `clunk`/`version`. All arithmetic saturates so
/// an adversarial frame length cannot panic; no floating point is used ([IO-24]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NinepLatency {
    /// Fixed latency floor for a metadata/control message, in virtual ns.
    pub control_ns: u64,
    /// Fixed latency floor for a `read`/`readdir` data message, in virtual ns.
    pub data_ns: u64,
    /// Per-frame-byte transfer cost added to every message, in virtual ns.
    pub per_byte_ns: u64,
}

impl NinepLatency {
    /// Creates a latency model from explicit control, data, and per-byte params.
    #[must_use]
    pub fn new(control_ns: u64, data_ns: u64, per_byte_ns: u64) -> Self {
        Self {
            control_ns,
            data_ns,
            per_byte_ns,
        }
    }

    /// Returns the modeled latency for a request frame of `frame_len` bytes.
    ///
    /// The op class is derived from decoding the frame's type byte; a frame that
    /// fails to decode is modeled with the control floor so its `Rlerror` reply
    /// still completes at a deterministic, host-independent icount. Saturating
    /// throughout so a hostile `frame_len` yields `u64::MAX` rather than
    /// overflowing.
    #[must_use]
    pub fn latency_for(&self, frame: &[u8]) -> u64 {
        let variable = self.per_byte_ns.saturating_mul(frame.len() as u64);
        let base = match Message::decode(frame) {
            Ok(message) => match message.body {
                TMessage::Read { .. } | TMessage::Readdir { .. } => self.data_ns,
                _ => self.control_ns,
            },
            Err(_) => self.control_ns,
        };
        base.saturating_add(variable)
    }
}

impl Default for NinepLatency {
    /// A modest default model: a control floor, a higher data floor, small/byte.
    fn default() -> Self {
        Self {
            control_ns: 800,
            data_ns: 1_200,
            per_byte_ns: 1,
        }
    }
}

impl LatencyModel for NinepLatency {
    /// Derives latency from the encoded 9p request frame in the payload.
    fn latency_ns(&self, request: &Request) -> u64 {
        self.latency_for(&request.payload)
    }
}

/// A 9p device sub-node over a read-only filesystem tree.
///
/// Composes an [`IoCore`] (clock, rings, in-flight queue) with the device state
/// (the [`NinepServer`] protocol engine and its served [`FsTree`], the latency
/// model, and the RNG cursor). Drive it with [`IoCore`]'s lifecycle
/// methods reached through [`NinepDevice::core_mut`], or the convenience wrappers
/// [`NinepDevice::submit`] / [`NinepDevice::advance_to`] /
/// [`NinepDevice::next_response`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NinepDevice {
    core: IoCore,
    server: NinepServer,
    latency: NinepLatency,
    /// The active I/O fault table applied to completions ([IO-25], [IO-26]).
    faults: IoFaults,
    /// The per-device RNG stream cursor (draws consumed so far, [IO-23]).
    ///
    /// Advanced by [`NinepDevice::resolve_response`] as the seeded per-device RNG
    /// draws each completion's faults; captured in the snapshot and re-derived on
    /// restore via [`NinepDevice::rng`] so a fork resumes the same draw sequence.
    /// Fault-free 9p (the default) never draws, so the cursor stays zero.
    rng_position: u64,
}

impl NinepDevice {
    /// Builds a 9p device over `tree` with the given core and latency model.
    ///
    /// The tree is held read-only and never mutated ([IO-13]); the server starts
    /// with an empty fid table and the fixed maximum `msize` until the first
    /// `Tversion` pins it ([IO-16]).
    #[must_use]
    pub fn new(core: IoCore, tree: FsTree, latency: NinepLatency) -> Self {
        Self {
            core,
            server: NinepServer::new(tree),
            latency,
            faults: IoFaults::none(),
            rng_position: 0,
        }
    }

    /// Returns a shared reference to the composed [`IoCore`].
    #[must_use]
    pub fn core(&self) -> &IoCore {
        &self.core
    }

    /// Returns a mutable reference to the composed [`IoCore`].
    ///
    /// Use this to reach the full uniform lifecycle (`enqueue_request`,
    /// `process_inbox`, `advance_to`, `pop_response`, `next_exact_local_event`)
    /// when the convenience wrappers are not enough.
    pub fn core_mut(&mut self) -> &mut IoCore {
        &mut self.core
    }

    /// Returns a shared reference to the protocol server (fid table, `msize`).
    #[must_use]
    pub fn server(&self) -> &NinepServer {
        &self.server
    }

    /// Returns the device RNG stream cursor (draws consumed so far, [IO-23]).
    #[must_use]
    pub fn rng_position(&self) -> u64 {
        self.rng_position
    }

    /// Returns a read-only view of the active I/O fault table ([IO-26]).
    #[must_use]
    pub fn faults(&self) -> &IoFaults {
        &self.faults
    }

    /// Activates an I/O fault table for subsequent completions ([IO-25], [IO-26]).
    ///
    /// The 9p device applies exactly the same fault taxonomy as the block device
    /// and the network link: latency/jitter/reorder/bandwidth shift the reply
    /// delivery icount, loss turns the reply into an error status, duplicate emits
    /// a second reply, and corrupt flips seeded bits in the read payload. The
    /// active set is part of the device's `MaterializedState` contribution, so a
    /// fork resumes with identical fault behavior ([IO-26]).
    pub fn set_faults(&mut self, faults: IoFaults) {
        self.faults = faults;
    }

    /// Builds a seeded RNG positioned at this device's captured cursor ([IO-23]).
    ///
    /// Forks the device stream by name-hash from the engine's decision-RNG
    /// `root_seed` in `domain` for `name` ([DET-25]) and resumes it at the
    /// captured cursor, so the returned RNG's next draw is byte-identical to the
    /// uninterrupted run's. The caller supplies the engine root seed and the
    /// device's stable stream domain and name (the engine owns the name-hash).
    #[must_use]
    pub fn rng(&self, root_seed: u64, domain: &str, name: &str) -> DeviceRng {
        DeviceRng::restore(root_seed, domain, name, self.rng_position)
    }

    /// Resolves a modeled reply through the active fault table ([IO-25]).
    ///
    /// Applies the uniform I/O fault taxonomy to a modeled
    /// `(delivery_icount, status, payload)` triple — the reply
    /// [`NinepDevice::submit`]'s COMPUTE step would deliver — drawing every
    /// probabilistic choice from `rng` in the fixed model order and advancing the
    /// device RNG cursor to match ([IO-21], [IO-23]). The returned
    /// [`IoFaultOutcome`] carries the perturbed primary reply, an optional
    /// duplicate, and which faults fired. Nanosecond shifts are converted to
    /// icounts with the device's fixed clock shift, so the result is a pure
    /// function of the inputs, the table, and the RNG position ([IO-22], [IO-24]).
    pub fn resolve_response(
        &mut self,
        primary_icount: u64,
        status: ResponseStatus,
        payload: Vec<u8>,
        rng: &mut DeviceRng,
    ) -> IoFaultOutcome {
        let shift_bits = self.core.shift_bits();
        let outcome = self
            .faults
            .resolve(primary_icount, status, payload, rng, |ns| {
                ceil_ns_to_icount(ns, shift_bits).unwrap_or(u64::MAX)
            });
        self.rng_position = rng.position();
        outcome
    }

    /// Enqueues an encoded 9p request frame and COMPUTEs it immediately.
    ///
    /// This is the ARRIVE+COMPUTE convenience path for the in-process double
    /// ([IO-27]): the `frame` bytes are wrapped into the uniform [`Request`] at
    /// `request_icount`, enqueued, and COMPUTEd, fixing the response's
    /// `delivery_icount`. The response stays in flight until
    /// [`NinepDevice::advance_to`] reaches that icount. The `request_id` is the
    /// 9p tag recovered from the frame header (or zero for a too-short frame), so
    /// the uniform correlation id tracks the 9p tag.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::RingFull`] when the inbound ring is full (the
    /// producer must drain and retry, [IO-32]), or any error
    /// [`IoCore::process_inbox`] raises (clock/overflow/past-delivery guards),
    /// including a [`DeviceError::NinepCodec`] if the server's own reply fails to
    /// encode.
    pub fn submit(&mut self, request_icount: u64, frame: &[u8]) -> Result<(), DeviceError> {
        let tag = frame
            .get(5..7)
            .map(|b| u32::from(u16::from_le_bytes([b[0], b[1]])))
            .unwrap_or(0);
        let uniform = Request::new(request_icount, tag, frame.to_vec());
        self.core
            .enqueue_request(uniform)
            .map_err(|rejected| DeviceError::RingFull {
                capacity: rejected.capacity,
            })?;
        // Borrow split: process_inbox needs `&mut self.core` and `&mut server`
        // simultaneously, so serve through a detached server view.
        Self::process_pending(&mut self.core, &mut self.server, &self.latency)
    }

    /// Drains raw 9p request frames from a shared-memory inbox ring.
    ///
    /// Each dequeued frame is converted to the uniform [`Request`] payload,
    /// COMPUTEd through the read-only 9p server, and inserted into the in-flight
    /// queue. The VM producer slot is woken as each request-ring entry is freed,
    /// so a producer blocked on a full `(vm slot -> SLOT_9P_IO)` ring can retry
    /// without dropping or reordering the request ([IO-32]).
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for corrupt ring state, invalid frame payload
    /// length, wake failure, or any 9p COMPUTE/delivery-time error.
    pub fn process_shmem_inbox(
        &mut self,
        inbox: &RingHeader,
        inbox_entries: &[FrameEntry],
        producer_slot: &NodeSlot,
    ) -> Result<ShmemInboxProcess, DeviceError> {
        let mut node = NinepServerNode {
            server: &mut self.server,
            latency: &self.latency,
        };
        self.core
            .process_shmem_inbox(&mut node, inbox, inbox_entries, producer_slot)
    }

    /// Advances the clock to `limit` and DELIVERs every due response ([IO-2]).
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError::ClockRegression`] when `limit` is below the current
    /// icount.
    pub fn advance_to(&mut self, limit: u64) -> Result<usize, DeviceError> {
        self.core.advance_to(limit)
    }

    /// Advances the clock and publishes due 9p replies to a shmem ring.
    ///
    /// Replies are emitted as raw 9p payload frames on the `(SLOT_9P_IO -> vm
    /// slot)` ring. If the ring fills, undelivered replies remain in flight at
    /// their original `delivery_icount`; when at least one reply is published,
    /// the VM consumer slot is woken.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for clock regression, oversized reply frames,
    /// corrupt ring state, or wake failure.
    pub fn advance_to_shmem(
        &mut self,
        limit: u64,
        outbox: &RingHeader,
        outbox_entries: &mut [FrameEntry],
        consumer_slot: &NodeSlot,
    ) -> Result<ShmemDeliveryResult, DeviceError> {
        self.core
            .advance_to_shmem(limit, outbox, outbox_entries, consumer_slot)
    }

    /// Pops the next delivered response, returning its raw 9p reply frame.
    ///
    /// Returns `None` when no response has been made visible yet. The payload is
    /// a complete, well-formed 9p reply frame ([IO-18]).
    pub fn next_response(&mut self) -> Option<Vec<u8>> {
        self.core
            .pop_response()
            .map(|pending| pending.response.payload)
    }

    /// COMPUTEs every pending inbox request through the 9p server view.
    ///
    /// Factored out so [`NinepDevice::submit`] satisfies the borrow checker:
    /// `IoCore::process_inbox` takes the core mutably and an [`IoSubNode`]
    /// mutably, and the device cannot hand `&mut self` to both. The detached
    /// [`NinepServerNode`] borrows only the device sub-fields the COMPUTE step
    /// needs.
    ///
    /// # Errors
    ///
    /// Propagates any [`DeviceError`] from [`IoCore::process_inbox`].
    fn process_pending(
        core: &mut IoCore,
        server: &mut NinepServer,
        latency: &NinepLatency,
    ) -> Result<(), DeviceError> {
        let mut node = NinepServerNode { server, latency };
        core.process_inbox(&mut node)
    }

    /// Snapshots the device half of a `MaterializedState` ([IO-19], [IO-23]).
    ///
    /// Captures the uniform-core snapshot (clock, rings, in-flight responses),
    /// the server's fid table and negotiated `msize`, the latency model (part of
    /// the `World`, [IO-22]), and the device RNG cursor — **never**
    /// the served tree bytes ([TEMP-9]).
    #[must_use]
    pub fn snapshot(&self) -> NinepSnapshot {
        NinepSnapshot {
            core: self.core.snapshot(),
            server: self.server.snapshot(),
            latency: self.latency,
            faults: self.faults.clone(),
            rng_position: self.rng_position,
        }
    }

    /// Restores a device from a snapshot stacked over the served tree.
    ///
    /// The served `tree` is re-supplied (it is the shared, content-addressed
    /// `World`, never carried in the snapshot, [IO-19], [TEMP-9]); the fid table,
    /// negotiated `msize`, latency model, RNG position, and in-flight responses
    /// are restored verbatim. Open directory caches are reconstructed from the
    /// tree on demand, so the restored device answers byte-identically to an
    /// uninterrupted run ([IO-19], [IO-28]).
    ///
    /// # Errors
    ///
    /// Returns any [`DeviceError`] [`IoCore::restore`] raises.
    pub fn restore(snapshot: &NinepSnapshot, tree: FsTree) -> Result<Self, DeviceError> {
        let core = IoCore::restore(&snapshot.core)?;
        let server = NinepServer::restore(&snapshot.server, tree);
        Ok(Self {
            core,
            server,
            latency: snapshot.latency,
            // Restore the active fault table so post-restore replies are perturbed
            // identically ([IO-26]); omitting it would silently diverge.
            faults: snapshot.faults.clone(),
            rng_position: snapshot.rng_position,
        })
    }
}

/// The detached COMPUTE view a [`NinepDevice`] hands to [`IoCore::process_inbox`].
///
/// Borrows only the device fields the COMPUTE step touches (the server and the
/// latency model), sidestepping the `&mut self`-to-both-args borrow conflict. It
/// is the concrete [`IoSubNode`]: every request frame is dispatched through the
/// [`NinepServer`], which answers malformed/mutating/unknown messages with an
/// `Rlerror` frame, never a panic ([IO-17], [IO-18]).
struct NinepServerNode<'a> {
    server: &'a mut NinepServer,
    latency: &'a NinepLatency,
}

impl<'a> IoSubNode for NinepServerNode<'a> {
    type Latency = NinepLatency;

    fn latency_model(&self) -> &Self::Latency {
        self.latency
    }

    fn compute(&mut self, request: &Request) -> Result<Response, DeviceError> {
        // Dispatch the 9p request frame. Hostile/mutating/unknown bytes yield a
        // well-formed Rlerror reply frame ([IO-17], [IO-18]); the only Err here
        // is a pathological reply that cannot be encoded, which is an internal
        // bug, not external input.
        let reply = self.server.handle(&request.payload)?;
        // The status is Ok unless the reply is an Rlerror frame; map the 9p
        // reply type byte (offset 4) to the uniform status so the core's
        // coincident-delivery ordering and any fault hooks see the outcome.
        let status = match reply.get(4) {
            Some(&codec::RLERROR) => ResponseStatus::Error,
            _ => ResponseStatus::Ok,
        };
        Ok(Response::new(request.request_id, status, reply))
    }
}

/// The device half of a 9p sub-node's `MaterializedState` ([IO-19], [IO-23]).
///
/// Holds the uniform-core snapshot (clock, rings, in-flight responses), the
/// server's fid table and negotiated `msize`, the latency model (part of the
/// `World`, [IO-22]), and the device RNG cursor. It **never** holds
/// the served tree bytes ([TEMP-9]); restore re-supplies the content-addressed
/// tree, whose open caches are pure functions of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NinepSnapshot {
    /// The uniform-core snapshot: clock, rings, in-flight responses.
    pub core: IoCoreSnapshot,
    /// The protocol server snapshot: the fid table and negotiated `msize`.
    pub server: NinepServerSnapshot,
    /// The latency model parameters, restored so post-restore completion icounts
    /// match an uninterrupted run ([IO-22]).
    pub latency: NinepLatency,
    /// The active I/O fault table, restored so post-restore replies are perturbed
    /// identically ([IO-25], [IO-26]).
    pub faults: IoFaults,
    /// The per-device RNG stream cursor (draws consumed so far, [IO-23]).
    pub rng_position: u64,
}

impl NinepSnapshot {
    /// Returns the in-flight responses captured in the snapshot.
    #[must_use]
    pub fn inflight(&self) -> &[PendingResponse] {
        &self.core.inflight
    }

    /// Returns the captured fid table as `(fid, entry)` pairs in fid order.
    #[must_use]
    pub fn fids(&self) -> &[(u32, super::server::FidEntry)] {
        &self.server.fids
    }
}
