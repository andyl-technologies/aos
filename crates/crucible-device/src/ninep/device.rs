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
use super::server::{MAX_MSIZE, MIN_MSIZE, NinepServer, NinepServerSnapshot};
use super::tree::{FsTree, Node};

/// The deterministic completion-latency model for the 9p device.
///
/// Latency is `base_op_ns(message kind) + per_byte_ns * frame_len` — a pure
/// function of the request frame and the device's configured parameters, with no
/// host-timing term ([IO-22]). Distinct per-op floors let a heavy `readdir`/
/// `read` cost more than a trivial `clunk`/`version`. All arithmetic saturates so
/// an adversarial frame length cannot panic; no floating point is used ([IO-24]).
#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
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

#[path = "device/core.rs"]
mod core;
#[path = "device/request_execution.rs"]
mod request_execution;
#[path = "device/snapshot.rs"]
mod snapshot;

use request_execution::*;
pub use snapshot::{NinepSnapshot, NinepSnapshotCodecError};
