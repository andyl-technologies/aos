//! `crucible-device` owns deterministic I/O sub-node models.
//!
//! Spec index: RFC-0010 files 15.
//!
//! This L1 crate models a disk, a 9p server, and a network link as **uniform
//! simulation sub-nodes**: each is a scheduling node with an icount-derived
//! virtual clock, a request inbox, a response outbox, and a deterministic
//! completion model. The shared lifecycle abstraction is backed by both an
//! in-process harness queue and real `crucible-shmem` SPSC rings for the block
//! and 9p request/response paths.
//!
//! # The COMPUTE-then-DELIVER lifecycle
//!
//! I/O completion is a **scheduled event, not a freeze of virtual time**. When
//! a request arrives at the requester's icount `t`, the sub-node COMPUTEs its
//! status and payload *now* (touching host state at any wall-clock instant) and
//! fixes `delivery_icount = ceil_ns_to_icount(virtual_ns(t) + latency)`. The
//! response's architectural *visibility* is then gated until the consumer clock
//! reaches that icount. Host COMPUTE wall-clock never enters the delivery icount
//! or any payload byte ([IO-2], [IO-4], [IO-31]).
//!
//! # Module map
//!
//! - [`clock`]: the icount-derived [`VirtualClock`] and the fixed-shift
//!   virtual-time map, including the [TIME-4] [`ceil_ns_to_icount`] ns-to-icount
//!   direction.
//! - [`request`]: the device-agnostic [`Request`], [`Response`], and
//!   [`LatencyModel`] vocabulary.
//! - [`inflight`]: the [`InflightQueue`] of computed-not-delivered responses,
//!   ordered by `delivery_icount` so its head is the `next_exact_local_event`.
//! - [`backpressure`]: the [`BoundedQueue`] modeling deterministic full-ring
//!   block-and-wake backpressure ([IO-32]).
//! - [`subnode`]: the [`IoSubNode`] trait and the [`IoCore`] lifecycle engine
//!   that ties the clock, rings, and in-flight queue together.
//! - [`block`]: the block device sub-node (CS-IO-2, tasks T-IO-2..5) — a
//!   read-only content-addressed base image, an in-memory 4 KiB copy-on-write
//!   overlay with dirty tracking, the versioned little-endian block wire ABI,
//!   the deterministic completion model, and snapshot/restore/materialize.
//! - [`ninep`]: the 9p filesystem sub-node (CS-IO-3, tasks T-IO-6..8) — a
//!   read-only 9P2000.L server over a deterministic content-addressed tree, with
//!   path-hashed QIDs, sorted enumeration, fixed/content-derived attributes, the
//!   `EROFS` read-only boundary, `msize` enforcement, and snapshot/restore of the
//!   fid table ([IO-13]..[IO-19]).
//! - [`netlink`]: the network-link sub-node (CS-IO-4, tasks T-IO-9 / T-IO-16) —
//!   a directed `A -> B` edge that schedules each frame over `SLOT_NET_ROUTER`,
//!   modeling latency/jitter/reorder/bandwidth/loss/duplicate/corrupt as
//!   deterministic perturbations of the delivery icount and/or payload, with the
//!   strictly-positive latency floor, sub-floor clamp, lookahead-recompute
//!   signal, and into-the-past fail-loud guard ([IO-20], [IO-33], [IO-34]).
//! - [`fault`]: the shared I/O fault taxonomy (CS-IO-5, tasks T-IO-10 / T-IO-12)
//!   — the seeded per-device RNG ([`fault::DeviceRng`]) forked by name-hash, the
//!   [`fault::Probability`] and integer-only transforms shared with the network
//!   link, and the uniform [`fault::IoFaults`] completion-fault table applied to
//!   block and 9p completions exactly as the link applies its faults ([IO-21],
//!   [IO-23], [IO-25], [IO-26]).
//! - [`error`]: the [`DeviceError`] taxonomy returned across the crate.
//! - [`harness`]: the in-process device test harness (CS-IO-6, tasks
//!   T-IO-13 / T-IO-14) — a uniform [`HarnessDevice`] adapter over all three
//!   sub-nodes, the [`Script`]/[`run_script`] driver, the run-twice determinism
//!   and divergence-localization helpers, and the idle-vs-busy-poll equivalence
//!   proof plus the documented §15.8 spike conclusion ([IO-27]..[IO-30]).
//!
//! # Determinism
//!
//! Every completion time and probabilistic device choice is a pure function of
//! `(request icount, modeled latency, per-device RNG draw)` — no host
//! wall-clock, scheduling, filesystem, or inode dependence ([IO-1], [IO-4]).
//! All ordering-significant collections are explicitly ordered; no
//! default-hasher iteration appears on any response path.

#![forbid(unsafe_code)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

pub mod backpressure;
pub mod block;
pub mod clock;
pub mod error;
pub mod fault;
pub mod harness;
pub mod inflight;
pub mod netlink;
pub mod ninep;
pub mod request;
pub mod subnode;

pub use backpressure::{BackpressureState, BoundedQueue, PushError};
pub use block::{
    BLOCK_ABI_VERSION, BaseImage, BlockCodecError, BlockDevice, BlockErrorCode, BlockLatency,
    BlockOp, BlockRequest, BlockRequestIdentity, BlockResponse, BlockSnapshot, BlockStatus,
    BlockTransportPending, BlockTransportRequestIds, BlockTransportReset, BlockTransportResolved,
    BlockTransportUnadmitted, BlockTransportUndelivered, CowOverlay, OverlayDelta, PAGE_SIZE,
    install_cross_device_misdirected_persistence,
};
pub use clock::{VirtualClock, ceil_ns_to_icount};
pub use error::DeviceError;
pub use fault::{DeviceRng, IoFaultOutcome, IoFaults, Probability, ResolvedResponse};
pub use harness::{
    BUSY_POLL_SPIKE, BlockHarness, BusyPollSpike, DeliveryLog, DeliveryRecord, DivergedField,
    Divergence, HarnessDevice, IdleBusyPoll, LinkRequest, LogComparison, NetLinkHarness,
    NinepHarness, Script, Step, compare_logs, idle_busy_poll_equivalence, localize_divergence,
    run_script, run_twice,
};
pub use inflight::{InflightQueue, PendingResponse};
pub use netlink::{
    Delivery, Frame, FrameDraws, Ipv4FragmentationError, Ipv4FragmentationOutcome, LINK_SLOT,
    LinkCorruptionStrategy, LinkFaults, LinkSnapshot, NetLink, NetworkResponseError,
    NetworkResponseHeaders, NetworkResponseKind, NetworkResponseOutcome,
    NetworkResponseSpecification, PastDeliveryPolicy, ResolveOutcome, ResolvedNetworkFrameEffects,
    ResolvedNetworkFrameEffectsError, fragment_ethernet_ipv4, generate_network_response,
};
pub use ninep::{
    FsTree, FsTreeDecodeError, NinepDevice, NinepLatency, NinepServer, NinepServerSnapshot,
    NinepSnapshot, Node, Qid, QidType,
};
pub use request::{
    AdditionalCompletion, AffineLatency, ComputedResponse, LatencyModel, Request, RequestId,
    Response, ResponseStatus,
};
pub use subnode::{
    IoCore, IoCoreSnapshot, IoSubNode, ShmemDeliveryResult, ShmemDequeueResult, ShmemInboxProcess,
};
