//! The network-link sub-node: inter-VM frame delivery with deterministic faults.
//!
//! This module assembles the network-link sub-node of RFC-0010 §15.4 from two
//! focused submodules and re-exports their public surface:
//!
//! - [`fault`]: the effective fault table ([`LinkFaults`]) and the pure,
//!   integer-only fault transforms — bandwidth serialization, jitter/reorder
//!   shifts, Bernoulli [`Probability`], and payload corruption ([IO-20]).
//! - [`ipv4`]: the bounded Ethernet/IPv4 parser and exact fragmentation and
//!   later-hop re-fragmentation encoder.
//! - [`response`]: portable ICMPv4, ICMPv6, TCP-reset, and exact opaque
//!   Ethernet response generation with protocol suppression rules and checksums.
//! - [`link`]: the [`NetLink`] sub-node — the directed `A -> B` edge that
//!   schedules each [`Frame`] over the
//!   [`SLOT_NET_ROUTER`](crucible_shmem::SLOT_NET_ROUTER) slot, enforces the
//!   strictly-positive latency floor, clamps sub-floor latency faults, raises the
//!   scheduler lookahead-recompute signal when the conservative minimum latency
//!   bound changes ([IO-33]), and clamps-or-fails-loud on a reorder/jitter shift
//!   into the consumer's past ([IO-34]).
//!
//! # Why the link is special among sub-nodes
//!
//! The block and 9p sub-nodes produce *exact* local events; the network link is
//! the **one source of conservative uncertainty** (§15.4.2). Its base latency
//! `L(A->B)` is what *sets* the scheduler's lookahead bound, so the floor lives
//! at the link: a zero-latency link would give a peer zero lookahead and collapse
//! the system to single-instruction lockstep. A fixed latency fault that raises
//! the conservative minimum effective latency only widens lookahead (safe); a
//! fault that would lower it below the floor is clamped; and any change to that
//! scalar bound triggers a lookahead recompute at the next quantum boundary,
//! never mid-RUN. Jitter, reorder, and bandwidth can delay individual frames, but
//! their minimum additional delay is zero and therefore does not change the
//! scheduler's scalar lookahead edge.
//!
//! # Determinism and the RNG seam
//!
//! Every probabilistic transform (jitter magnitude, reorder shift, loss
//! decisions, duplicate timing, corruption decision, and corruption selectors)
//! is a pure function of draw values carried in [`FrameDraws`]. The seeded
//! per-device RNG ([`crate::fault::DeviceRng`]) forked by name-hash produces
//! those draws in their fixed consumption order via
//! [`FrameDraws::from_rng_for_faults`] and [`NetLink::emit_from_rng`] ([IO-21]);
//! the snapshot captures the RNG cursor so a fork resumes the same sequence
//! ([IO-23]). The same frame and the same draws always yield byte-identical
//! deliveries ([IO-4], [IO-22]). No floating point, no host clock, and no
//! default-hasher iteration appears on any delivery path ([IO-24]).

pub mod fault;
pub mod ipv4;
pub mod link;
pub mod response;

pub use fault::{
    LinkCorruptionStrategy, LinkFaults, Probability, corrupt_payload, jitter_shift_ns,
    reorder_shift_ns,
};
pub use ipv4::{Ipv4FragmentationError, Ipv4FragmentationOutcome, fragment_ethernet_ipv4};
pub use link::{
    Delivery, Frame, FrameDraws, LINK_SLOT, LinkSnapshot, LinkSnapshotCodecError, NetLink,
    PastDeliveryPolicy, ResolveOutcome, ResolvedNetworkFrameEffects,
    ResolvedNetworkFrameEffectsError,
};
pub use response::{
    NetworkResponseError, NetworkResponseHeaders, NetworkResponseKind, NetworkResponseOutcome,
    NetworkResponseSpecification, generate_network_response,
};

#[cfg(test)]
#[path = "netlink_delivery_test.rs"]
mod delivery_tests;
#[cfg(test)]
#[path = "netlink_fault_replay_test.rs"]
mod fault_replay_tests;
#[cfg(test)]
#[path = "netlink_test_support.rs"]
mod test_support;
