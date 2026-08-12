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
//! `msize`, exact fault directives, visibility continuation, and session
//! identity — **never** the served tree
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

use std::collections::BTreeMap;

use crucible_shmem::{FrameEntry, NodeSlot, RingHeader};

use crate::error::DeviceError;
use crate::inflight::PendingResponse;
use crate::request::{ComputedResponse, LatencyModel, Request, Response, ResponseStatus};
use crate::subnode::{IoCore, IoCoreSnapshot, IoSubNode, ShmemDeliveryResult, ShmemInboxProcess};

use super::codec::{self, GetattrReply, Message, Qid, QidType, TMessage};
use super::fault::{
    NinepObjectVersion, NinepRequestIdentity, NinepResultDirective, NinepVisibilityLookup,
    NinepVisibilityPolicy, NinepVisibilityRelease, NinepVisibilityState,
    ResolvedNinepRequestDirective,
};
use super::server::{NinepServer, NinepServerSnapshot};
use super::tree::{FsTree, Node};

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

/// A fid owned by the signal-driven overlay rather than the immutable server.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NinepVirtualFid {
    /// Binds permanently to an explicit stale or misdirected object result.
    Exact(NinepObjectVersion),
    /// Resolves the path through the current committed-versus-visible overlay.
    VisiblePath(String),
}

impl NinepVirtualFid {
    fn validate(&self) -> Result<(), DeviceError> {
        match self {
            Self::Exact(object) => object.validate(),
            Self::VisiblePath(path) => NinepObjectVersion {
                path: path.clone(),
                version: 0,
                mode: 0o100_000,
                data: Vec::new(),
                deleted: false,
            }
            .validate(),
        }
    }

    fn path(&self) -> &str {
        match self {
            Self::Exact(object) => &object.path,
            Self::VisiblePath(path) => path,
        }
    }
}

/// A 9p device sub-node over a read-only filesystem tree.
///
/// Composes an [`IoCore`] (clock, rings, in-flight queue) with the device state
/// (the [`NinepServer`] protocol engine and its served [`FsTree`], the latency
/// model, and signal-driven request state). Drive it with [`IoCore`]'s lifecycle
/// methods reached through [`NinepDevice::core_mut`], or the convenience wrappers
/// [`NinepDevice::submit`] / [`NinepDevice::advance_to`] /
/// [`NinepDevice::next_response`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NinepDevice {
    core: IoCore,
    server: NinepServer,
    latency: NinepLatency,
    require_fault_directives: bool,
    directives: BTreeMap<NinepRequestIdentity, ResolvedNinepRequestDirective>,
    visibility: NinepVisibilityState,
    virtual_fids: BTreeMap<u32, NinepVirtualFid>,
    session_epoch: u64,
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
            require_fault_directives: false,
            directives: BTreeMap::new(),
            visibility: NinepVisibilityState::default(),
            virtual_fids: BTreeMap::new(),
            session_epoch: 0,
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

    /// Returns the deterministic latency model used for request completions.
    #[must_use]
    pub const fn latency_model(&self) -> &NinepLatency {
        &self.latency
    }

    /// Requires every subsequently computed request to carry an exact directive.
    pub fn require_fault_directives(&mut self) {
        self.require_fault_directives = true;
    }

    /// Installs the resolve decision for one exact ring-head request.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] when the directive is malformed or duplicated.
    pub fn install_fault_directive(
        &mut self,
        request_icount: u64,
        transport_sequence: u32,
        frame: &[u8],
        directive: ResolvedNinepRequestDirective,
    ) -> Result<(), DeviceError> {
        directive.validate_for(request_icount, transport_sequence, frame)?;
        if self.directives.contains_key(&directive.identity) {
            return Err(DeviceError::InvalidNinepFaultDirective {
                reason: "9p request directive is already installed",
            });
        }
        self.directives.insert(directive.identity, directive);
        Ok(())
    }

    /// Commits one object update to the visibility continuation.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for invalid content, conflicting identity, or a
    /// bounded-state overflow.
    pub fn commit_visibility_update(
        &mut self,
        update_id: [u8; 32],
        object: NinepObjectVersion,
        policy: NinepVisibilityPolicy,
        release: NinepVisibilityRelease,
        data_lag_nanos: u64,
    ) -> Result<u64, DeviceError> {
        self.visibility.commit(
            update_id,
            object,
            policy,
            release,
            self.session_epoch,
            data_lag_nanos,
        )
    }

    /// Advances the visible frontier from exact time and event evidence.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] if checkpointed visibility state is inconsistent.
    pub fn advance_visibility(
        &mut self,
        now_nanos: u64,
        observed_events: &BTreeMap<[u8; 32], u64>,
    ) -> Result<(u64, u64), DeviceError> {
        self.visibility
            .advance_visibility(self.session_epoch, now_nanos, observed_events)
    }

    /// Returns the committed-versus-visible continuation.
    #[must_use]
    pub const fn visibility_state(&self) -> &NinepVisibilityState {
        &self.visibility
    }

    /// Returns the current negotiated visibility session identity.
    #[must_use]
    pub const fn session_epoch(&self) -> u64 {
        self.session_epoch
    }

    /// Enqueues an encoded 9p request frame and COMPUTEs it immediately.
    ///
    /// The `frame` bytes are wrapped into the uniform [`Request`] at
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
        Self::process_pending(
            &mut self.core,
            &mut self.server,
            &self.latency,
            self.require_fault_directives,
            &mut self.directives,
            &self.visibility,
            &mut self.virtual_fids,
            &mut self.session_epoch,
        )
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
            require_fault_directives: self.require_fault_directives,
            directives: &mut self.directives,
            visibility: &self.visibility,
            virtual_fids: &mut self.virtual_fids,
            session_epoch: &mut self.session_epoch,
        };
        self.core
            .process_shmem_inbox(&mut node, inbox, inbox_entries, producer_slot)
    }

    /// Dequeues and computes at most one shared-memory 9p request.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for ring corruption, a missing or mismatched
    /// required directive, protocol encoding failure, or wake failure.
    pub fn process_one_shmem_request(
        &mut self,
        inbox: &RingHeader,
        inbox_entries: &[FrameEntry],
        producer_slot: &NodeSlot,
    ) -> Result<ShmemInboxProcess, DeviceError> {
        let mut node = NinepServerNode {
            server: &mut self.server,
            latency: &self.latency,
            require_fault_directives: self.require_fault_directives,
            directives: &mut self.directives,
            visibility: &self.visibility,
            virtual_fids: &mut self.virtual_fids,
            session_epoch: &mut self.session_epoch,
        };
        self.core
            .process_one_shmem_request(&mut node, inbox, inbox_entries, producer_slot)
    }

    /// Computes and schedules one already-decoded request without touching a
    /// shared-memory ring.
    ///
    /// Transactional host adapters use this method on a cloned device to finish
    /// every directive, protocol, latency, response-shape, and sequence check
    /// before they dequeue the corresponding live request-ring entry.
    ///
    /// # Errors
    ///
    /// Returns [`DeviceError`] for any COMPUTE or completion-scheduling failure.
    pub fn compute_detached_request(&mut self, request: Request) -> Result<(), DeviceError> {
        let mut node = NinepServerNode {
            server: &mut self.server,
            latency: &self.latency,
            require_fault_directives: self.require_fault_directives,
            directives: &mut self.directives,
            visibility: &self.visibility,
            virtual_fids: &mut self.virtual_fids,
            session_epoch: &mut self.session_epoch,
        };
        self.core.compute_request(&mut node, request)
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

    /// Advances and publishes replies while preserving the exact commit status
    /// of a failure.
    ///
    /// # Errors
    ///
    /// Returns a failure containing the number of frames already published.
    pub fn advance_to_shmem_with_commit_status(
        &mut self,
        limit: u64,
        outbox: &RingHeader,
        outbox_entries: &mut [FrameEntry],
        consumer_slot: &NodeSlot,
    ) -> Result<ShmemDeliveryResult, crate::subnode::ShmemDeliveryFailure> {
        self.core
            .advance_to_shmem_with_commit_status(limit, outbox, outbox_entries, consumer_slot)
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
    #[allow(
        clippy::too_many_arguments,
        reason = "the detached 9p server node borrows each independently owned device state field"
    )]
    fn process_pending(
        core: &mut IoCore,
        server: &mut NinepServer,
        latency: &NinepLatency,
        require_fault_directives: bool,
        directives: &mut BTreeMap<NinepRequestIdentity, ResolvedNinepRequestDirective>,
        visibility: &NinepVisibilityState,
        virtual_fids: &mut BTreeMap<u32, NinepVirtualFid>,
        session_epoch: &mut u64,
    ) -> Result<(), DeviceError> {
        let mut node = NinepServerNode {
            server,
            latency,
            require_fault_directives,
            directives,
            visibility,
            virtual_fids,
            session_epoch,
        };
        core.process_inbox(&mut node)
    }

    /// Snapshots the device half of a `MaterializedState` ([IO-19], [IO-23]).
    ///
    /// Captures the uniform-core snapshot (clock, rings, in-flight responses),
    /// the server's fid table and negotiated `msize`, the latency model (part of
    /// the `World`, [IO-22]), exact directives, visibility continuation, and
    /// session identity — **never**
    /// the served tree bytes ([TEMP-9]).
    #[must_use]
    pub fn snapshot(&self) -> NinepSnapshot {
        NinepSnapshot {
            core: self.core.snapshot(),
            server: self.server.snapshot(),
            latency: self.latency,
            require_fault_directives: self.require_fault_directives,
            directives: self.directives.clone(),
            visibility: self.visibility.clone(),
            virtual_fids: self.virtual_fids.clone(),
            session_epoch: self.session_epoch,
        }
    }

    /// Restores a device from a snapshot stacked over the served tree.
    ///
    /// The served `tree` is re-supplied (it is the shared, content-addressed
    /// `World`, never carried in the snapshot, [IO-19], [TEMP-9]); the fid table,
    /// negotiated `msize`, latency model, directives, visibility state, session
    /// identity, and in-flight responses are restored verbatim. Open directory caches are reconstructed from the
    /// tree on demand, so the restored device answers byte-identically to an
    /// uninterrupted run ([IO-19], [IO-28]).
    ///
    /// # Errors
    ///
    /// Returns any [`DeviceError`] [`IoCore::restore`] raises.
    pub fn restore(snapshot: &NinepSnapshot, tree: FsTree) -> Result<Self, DeviceError> {
        snapshot.visibility.validate()?;
        for (identity, directive) in &snapshot.directives {
            if identity != &directive.identity {
                return Err(DeviceError::InvalidNinepFaultDirective {
                    reason: "9p checkpoint directive index is inconsistent",
                });
            }
            match &directive.result {
                NinepResultDirective::Errno(0) => {
                    return Err(DeviceError::InvalidNinepFaultDirective {
                        reason: "9p checkpoint directive has zero errno",
                    });
                }
                NinepResultDirective::Stale(object) | NinepResultDirective::Misdirected(object) => {
                    object.validate()?
                }
                NinepResultDirective::Normal | NinepResultDirective::Errno(_) => {}
            }
        }
        for binding in snapshot.virtual_fids.values() {
            binding.validate()?;
        }
        let core = IoCore::restore(&snapshot.core)?;
        let server = NinepServer::restore(&snapshot.server, tree);
        Ok(Self {
            core,
            server,
            latency: snapshot.latency,
            require_fault_directives: snapshot.require_fault_directives,
            directives: snapshot.directives.clone(),
            visibility: snapshot.visibility.clone(),
            virtual_fids: snapshot.virtual_fids.clone(),
            session_epoch: snapshot.session_epoch,
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
    require_fault_directives: bool,
    directives: &'a mut BTreeMap<NinepRequestIdentity, ResolvedNinepRequestDirective>,
    visibility: &'a NinepVisibilityState,
    virtual_fids: &'a mut BTreeMap<u32, NinepVirtualFid>,
    session_epoch: &'a mut u64,
}

impl<'a> IoSubNode for NinepServerNode<'a> {
    type Latency = NinepLatency;
    type ComputeCheckpoint = (NinepServer, BTreeMap<u32, NinepVirtualFid>, u64);

    fn latency_model(&self) -> &Self::Latency {
        self.latency
    }

    fn compute_checkpoint(&self) -> Self::ComputeCheckpoint {
        (
            self.server.clone(),
            self.virtual_fids.clone(),
            *self.session_epoch,
        )
    }

    fn restore_compute_checkpoint(&mut self, checkpoint: Self::ComputeCheckpoint) {
        *self.server = checkpoint.0;
        *self.virtual_fids = checkpoint.1;
        *self.session_epoch = checkpoint.2;
    }

    fn compute(&mut self, request: &Request) -> Result<ComputedResponse, DeviceError> {
        let message = Message::decode(&request.payload).ok();
        let begins_session = message
            .as_ref()
            .is_some_and(|message| matches!(message.body, TMessage::Version { .. }));
        if begins_session && *self.session_epoch == u64::MAX {
            return Err(DeviceError::InvalidNinepFaultDirective {
                reason: "9p session epoch overflow",
            });
        }
        let identity = ResolvedNinepRequestDirective::fault_free(
            request.request_icount,
            request.request_id,
            &request.payload,
        )?
        .identity;
        let directive = self.directives.get(&identity).cloned();
        if self.require_fault_directives && directive.is_none() {
            return Err(DeviceError::MissingNinepFaultDirective { tag: identity.tag });
        }
        if let Some(directive) = &directive {
            directive.validate_for(request.request_icount, request.request_id, &request.payload)?;
        }

        let reply = match directive.as_ref().map(|directive| &directive.result) {
            Some(NinepResultDirective::Errno(errno)) => {
                codec::encode_rlerror(identity.tag, *errno)?
            }
            Some(NinepResultDirective::Stale(object))
            | Some(NinepResultDirective::Misdirected(object)) => object_reply(
                message
                    .as_ref()
                    .ok_or(DeviceError::InvalidNinepFaultDirective {
                        reason: "9p object result requires a decodable request",
                    })?,
                object,
                NinepVirtualFid::Exact(object.clone()),
                self.virtual_fids,
            )?,
            Some(NinepResultDirective::Normal) | None => {
                let layered = message
                    .as_ref()
                    .map(|message| {
                        visibility_reply(
                            message,
                            self.server,
                            self.visibility,
                            *self.session_epoch,
                            self.virtual_fids,
                        )
                    })
                    .transpose()?
                    .flatten();
                if let Some(reply) = layered {
                    reply
                } else {
                    let reply = self.server.handle(&request.payload)?;
                    if let Some(message) = &message {
                        match message.body {
                            TMessage::Version { .. } => self.virtual_fids.clear(),
                            TMessage::Clunk { fid } => {
                                self.virtual_fids.remove(&fid);
                            }
                            _ => {}
                        }
                    }
                    reply
                }
            }
        };
        if directive.is_some() {
            self.directives.remove(&identity);
        }
        if begins_session {
            *self.session_epoch += 1;
        }
        // The status is Ok unless the reply is an Rlerror frame; map the 9p
        // reply type byte (offset 4) to the uniform status so the core's
        // coincident-delivery ordering and any fault hooks see the outcome.
        let status = match reply.get(4) {
            Some(&codec::RLERROR) => ResponseStatus::Error,
            _ => ResponseStatus::Ok,
        };
        Ok(ComputedResponse::primary(Response::new(
            request.request_id,
            status,
            reply,
        )))
    }
}

fn request_fid(message: &TMessage) -> Option<u32> {
    match message {
        TMessage::Walk { fid, .. }
        | TMessage::Lopen { fid, .. }
        | TMessage::Read { fid, .. }
        | TMessage::Readdir { fid, .. }
        | TMessage::Getattr { fid, .. }
        | TMessage::Readlink { fid }
        | TMessage::Statfs { fid }
        | TMessage::Clunk { fid }
        | TMessage::Xattrwalk { fid, .. }
        | TMessage::Fsync { fid } => Some(*fid),
        TMessage::Version { .. }
        | TMessage::Attach { .. }
        | TMessage::Flush { .. }
        | TMessage::Mutating { .. }
        | TMessage::Unknown { .. } => None,
    }
}

fn canonical_path(components: &[String]) -> String {
    if components.is_empty() {
        String::from("/")
    } else {
        format!("/{}", components.join("/"))
    }
}

fn fid_path(
    server: &NinepServer,
    virtual_fids: &BTreeMap<u32, NinepVirtualFid>,
    fid: u32,
) -> Option<String> {
    virtual_fids
        .get(&fid)
        .map(|binding| binding.path().to_owned())
        .or_else(|| {
            server
                .fids()
                .get(&fid)
                .map(|entry| canonical_path(&entry.path))
        })
}

fn visibility_reply(
    message: &Message,
    server: &NinepServer,
    visibility: &NinepVisibilityState,
    session: u64,
    virtual_fids: &mut BTreeMap<u32, NinepVirtualFid>,
) -> Result<Option<Vec<u8>>, DeviceError> {
    if let TMessage::Walk {
        fid,
        newfid,
        wnames,
    } = &message.body
    {
        let Some(start) = fid_path(server, virtual_fids, *fid) else {
            return Ok(None);
        };
        let mut components = if start == "/" {
            Vec::new()
        } else {
            start
                .trim_start_matches('/')
                .split('/')
                .map(str::to_owned)
                .collect()
        };
        let mut qids = Vec::new();
        let mut overlay_touched = virtual_fids.contains_key(fid);
        for name in wnames {
            if super::tree::validate_component(name).is_err() {
                return Ok(Some(codec::encode_rlerror(
                    message.tag,
                    super::errno::EINVAL,
                )?));
            }
            let parent_path = canonical_path(&components);
            let parent_is_directory = match visibility.lookup_object(session, &parent_path) {
                NinepVisibilityLookup::Object(object) => {
                    overlay_touched = true;
                    object.mode & 0o170_000 == 0o040_000
                }
                NinepVisibilityLookup::Deleted => {
                    overlay_touched = true;
                    false
                }
                NinepVisibilityLookup::Base => matches!(
                    server.tree().resolve(&components),
                    Some(Node::Directory { .. })
                ),
            };
            if !parent_is_directory {
                if qids.is_empty() {
                    return Ok(Some(codec::encode_rlerror(
                        message.tag,
                        super::errno::ENOTDIR,
                    )?));
                }
                break;
            }
            components.push(name.clone());
            let path = canonical_path(&components);
            match visibility.lookup_object(session, &path) {
                NinepVisibilityLookup::Object(object) => {
                    qids.push(object_qid(&object));
                    overlay_touched = true;
                }
                NinepVisibilityLookup::Deleted => {
                    overlay_touched = true;
                    components.pop();
                    break;
                }
                NinepVisibilityLookup::Base => match server.tree().qid(&components) {
                    Some(qid) => qids.push(qid),
                    None => {
                        components.pop();
                        break;
                    }
                },
            }
        }
        if !overlay_touched {
            return Ok(None);
        }
        if qids.is_empty() && !wnames.is_empty() {
            return Ok(Some(codec::encode_rlerror(
                message.tag,
                super::errno::ENOENT,
            )?));
        }
        virtual_fids.insert(
            *newfid,
            NinepVirtualFid::VisiblePath(canonical_path(&components)),
        );
        return Ok(Some(codec::encode_rwalk(message.tag, &qids)?));
    }

    let Some(fid) = request_fid(&message.body) else {
        return Ok(None);
    };
    if virtual_fids.contains_key(&fid) {
        match message.body {
            TMessage::Clunk { .. } => {
                virtual_fids.remove(&fid);
                return Ok(Some(codec::encode_rclunk(message.tag)?));
            }
            TMessage::Fsync { .. } => {
                return Ok(Some(codec::encode_rfsync(message.tag)?));
            }
            TMessage::Statfs { .. } => {
                return Ok(Some(server.tree().statfs().encode(message.tag)?));
            }
            _ => {}
        }
    }
    if let Some(NinepVirtualFid::Exact(object)) = virtual_fids.get(&fid).cloned() {
        return object_reply(
            message,
            &object,
            NinepVirtualFid::Exact(object.clone()),
            virtual_fids,
        )
        .map(Some);
    }
    let Some(path) = fid_path(server, virtual_fids, fid) else {
        return Ok(None);
    };
    match visibility.lookup_object(session, &path) {
        NinepVisibilityLookup::Base => {
            if virtual_fids.contains_key(&fid) {
                Ok(Some(codec::encode_rlerror(
                    message.tag,
                    super::errno::ENOENT,
                )?))
            } else {
                Ok(None)
            }
        }
        NinepVisibilityLookup::Deleted => Ok(Some(codec::encode_rlerror(
            message.tag,
            super::errno::ENOENT,
        )?)),
        NinepVisibilityLookup::Object(object) => object_reply(
            message,
            &object,
            NinepVirtualFid::VisiblePath(path),
            virtual_fids,
        )
        .map(Some),
    }
}

fn object_qid(object: &NinepObjectVersion) -> Qid {
    let kind = match object.mode & 0o170_000 {
        0o040_000 => QidType::Dir,
        0o120_000 => QidType::Symlink,
        _ => QidType::File,
    };
    Qid {
        kind,
        version: object.version,
        path: super::tree::qid_path(&object.components()),
    }
}

fn object_reply(
    message: &Message,
    object: &NinepObjectVersion,
    binding: NinepVirtualFid,
    virtual_fids: &mut BTreeMap<u32, NinepVirtualFid>,
) -> Result<Vec<u8>, DeviceError> {
    object.validate()?;
    let tag = message.tag;
    if object.deleted {
        return codec::encode_rlerror(tag, super::errno::ENOENT).map_err(DeviceError::from);
    }
    let qid = object_qid(object);
    let reply = match &message.body {
        TMessage::Walk { newfid, wnames, .. } => {
            virtual_fids.insert(*newfid, binding.clone());
            let qids = if wnames.is_empty() {
                Vec::new()
            } else {
                vec![qid]
            };
            codec::encode_rwalk(tag, &qids)?
        }
        TMessage::Lopen { fid, .. } => {
            virtual_fids.insert(*fid, binding.clone());
            codec::encode_rlopen(tag, &qid, 0)?
        }
        TMessage::Read { offset, count, .. } => {
            if object.mode & 0o170_000 != 0o100_000 {
                codec::encode_rlerror(
                    tag,
                    if object.mode & 0o170_000 == 0o040_000 {
                        super::errno::EISDIR
                    } else {
                        super::errno::EINVAL
                    },
                )?
            } else {
                let start = usize::try_from(*offset).unwrap_or(usize::MAX);
                let end = start.saturating_add(*count as usize).min(object.data.len());
                let data = object.data.get(start..end).unwrap_or(&[]);
                codec::encode_rread(tag, data)?
            }
        }
        TMessage::Readdir { offset, count, .. } => {
            if object.mode & 0o170_000 != 0o040_000 {
                codec::encode_rlerror(tag, super::errno::ENOTDIR)?
            } else {
                let mut data = Vec::new();
                let entries = [(1_u64, qid, "."), (2_u64, qid, "..")];
                for (cookie, entry_qid, name) in entries {
                    if cookie <= *offset {
                        continue;
                    }
                    let mut encoded = Vec::new();
                    codec::push_dirent(&mut encoded, &entry_qid, cookie, 4, name)?;
                    if data.len().saturating_add(encoded.len()) > *count as usize {
                        if data.is_empty() {
                            return Ok(codec::encode_rlerror(tag, super::errno::EMSGSIZE)?);
                        }
                        break;
                    }
                    data.extend_from_slice(&encoded);
                }
                codec::encode_rreaddir(tag, &data)?
            }
        }
        TMessage::Getattr { request_mask, .. } => {
            let size = u64::try_from(object.data.len()).unwrap_or(u64::MAX);
            GetattrReply {
                valid: *request_mask,
                qid,
                mode: object.mode,
                uid: 0,
                gid: 0,
                nlink: 1,
                rdev: 0,
                size,
                blksize: 4096,
                blocks: size.saturating_add(511) / 512,
            }
            .encode(tag)?
        }
        TMessage::Readlink { .. } => {
            if object.mode & 0o170_000 != 0o120_000 {
                codec::encode_rlerror(tag, super::errno::EINVAL)?
            } else {
                let target = std::str::from_utf8(&object.data).map_err(|_| {
                    DeviceError::InvalidNinepFaultDirective {
                        reason: "9p symlink target is not UTF-8",
                    }
                })?;
                codec::encode_rreadlink(tag, target)?
            }
        }
        TMessage::Xattrwalk { newfid, .. } => {
            virtual_fids.insert(*newfid, binding);
            codec::encode_rxattrwalk(tag, 0)?
        }
        _ => {
            return Err(DeviceError::InvalidNinepFaultDirective {
                reason: "9p object result does not support this request shape",
            });
        }
    };
    Ok(reply)
}

/// The device half of a 9p sub-node's `MaterializedState` ([IO-19], [IO-23]).
///
/// Holds the uniform-core snapshot (clock, rings, in-flight responses), the
/// server's fid table and negotiated `msize`, the latency model (part of the
/// `World`, [IO-22]), exact directives, visibility continuation, and session
/// identity. It **never** holds
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
    /// Whether every compute requires an authenticated request directive.
    pub require_fault_directives: bool,
    /// Installed directives not yet consumed by their exact requests.
    pub directives: BTreeMap<NinepRequestIdentity, ResolvedNinepRequestDirective>,
    /// Committed-versus-visible object versions and frontiers.
    pub visibility: NinepVisibilityState,
    /// Fids bound to scenario-owned object versions outside the immutable tree.
    pub virtual_fids: BTreeMap<u32, NinepVirtualFid>,
    /// Monotone negotiated-session identity for per-session visibility.
    pub session_epoch: u64,
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
