//! The network-link sub-node: a directed `A -> B` edge that schedules frames.
//!
//! This module owns [`NetLink`], the link sub-node of RFC-0010 §15.4. A link
//! carries [`Frame`]s from a source VM node to a destination over the
//! [`SLOT_NET_ROUTER`] shmem slot: given a frame emitted by the source at icount
//! `t`, the link computes the destination
//! `delivery_icount = ic(vt(t) + effective_latency)` and applies the effective
//! fault table at RESOLVE ([IO-20]).
//!
//! Unlike the block and 9p sub-nodes (whose completion is an *exact* local
//! event), the link is **the one source of conservative uncertainty**
//! (§15.4.2): its base latency supplies the scheduler's lookahead bound, so the
//! link enforces a strictly positive latency floor ([IO-33]), clamps sub-floor
//! latency faults up to that floor, raises a recompute signal when the
//! conservative minimum latency bound changes, and fails loudly when a
//! reorder/jitter shift would deliver into the consumer's past ([IO-34]).
//!
//! ```text
//! emit(frame, t):                                  (SOURCE emits)
//!   base_ns    = vt(t)
//!   eff_lat    = max(base_latency + faults.added_latency, floor)   // clamp (IO-33)
//!   delivery_ns = base_ns + eff_lat
//!              += serialization_delay(len, bandwidth)
//!              += jitter_shift(draw) + reorder_shift(draw)
//!   delivery_icount = ceil_ns_to_icount(delivery_ns)
//!   if delivery_icount <= consumer_frontier: FAIL-LOUD or clamp (IO-34)
//!   loss?      DROP (no delivery)
//!   duplicate? emit a 2nd delivery at delivery_ns + gap
//!   corrupt?   mutate payload bytes
//! advance_to(limit): drain frames with delivery_icount <= limit  (DESTINATION sees)
//! ```
//!
//! The concrete QEMU transport drains and fills the `SLOT_NET_ROUTER` rings in
//! `crucible-qemu`'s network I/O servicer. This device-level type deliberately
//! owns only deterministic scheduling and fault transforms. It references the
//! slot constant and stamps each delivery's `src_node`/`seq` into a
//! [`FrameDeliveryKey`] so the modeled order matches the transport.
//!
//! The probabilistic transforms consume RNG draws; [`NetLink::emit_from_rng`]
//! draws them from the seeded per-device RNG ([`crate::fault::DeviceRng`]) forked
//! by name-hash in their fixed order ([IO-21]), and [`NetLink::emit`] accepts
//! injected draws for unit testing.

use crucible_shmem::{FrameDeliveryKey, SLOT_NET_ROUTER};

use crate::clock::VirtualClock;
use crate::error::DeviceError;
use crate::inflight::{InflightQueue, PendingResponse};
use crate::request::{Response, ResponseStatus};

use crate::fault::DeviceRng;

use super::fault::{
    LinkCorruptionStrategy, LinkFaults, checked_serialization_delay_bits_per_sec, corrupt_payload,
    jitter_shift_ns, reorder_shift_ns,
};

#[path = "link/frame.rs"]
mod frame;

pub use frame::*;

/// A directed network link sub-node: `A -> B` frame delivery with faults.
///
/// Composes a [`VirtualClock`] and a delivery-ordered [`InflightQueue`] (reusing
/// the foundation's in-flight machinery) with the link's base latency, latency
/// floor, and effective fault table. Frames are emitted with [`NetLink::emit`],
/// advanced to a limit with [`NetLink::advance_to`], and drained with
/// [`NetLink::next_delivery`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetLink {
    clock: VirtualClock,
    inflight: InflightQueue,
    /// The source node id stamped into delivery keys.
    src_node: u32,
    /// The link's base latency in virtual nanoseconds (strictly positive, [IO-33]).
    base_latency_ns: u64,
    /// The strictly-positive minimum link-latency floor in virtual nanoseconds.
    floor_ns: u64,
    /// The effective fault table applied at RESOLVE.
    faults: LinkFaults,
    /// The next per-frame sequence number, for deterministic tie-breaking.
    next_seq: u32,
    /// Set when a conservative latency-bound change requires scheduler recompute.
    lookahead_recompute_pending: bool,
    /// The per-device RNG stream cursor (draws consumed so far, [IO-23]).
    ///
    /// Advanced by [`NetLink::emit_from_rng`] as the seeded per-device RNG
    /// produces each frame's draws; captured in the snapshot and re-derived on
    /// restore via [`NetLink::rng`] so a fork resumes the same draw sequence.
    rng_position: u64,
}

#[path = "link/delivery.rs"]
mod delivery;
#[path = "link/emit.rs"]
mod emit;

#[path = "link/snapshot.rs"]
mod snapshot;

pub use snapshot::{LinkSnapshot, LinkSnapshotCodecError};

mod corruption;

use corruption::*;
