//! Engine-side bridge to deterministic I/O scheduling sub-nodes.
//!
//! Block, 9p, and network operations cross this module through the typed
//! signal-driven adapters. Device overlay construction remains here because
//! materialized checkpoints share the same content-addressed overlay shape.
//! Every operation handled here was already emitted by a modeled guest/device endpoint.
//! This module is not a host-side workload generator and MUST NOT be used to originate application traffic.

use std::collections::BTreeMap;

use crucible_device::{
    DeviceError, DeviceRng, Frame, FrameDraws, NetLink, PastDeliveryPolicy, ResolveOutcome,
};

use crate::{
    Decision, DeviceId, DeviceOverlayDelta, DeviceRngState, RngDecision, RngStreamId,
    RngStreamPosition, Seed,
};

/// The orientation of one directed runtime link.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum NetworkLinkDirection {
    /// The link carries frames from endpoint A to endpoint B.
    EndpointAToEndpointB,
    /// The link carries frames from endpoint B to endpoint A.
    EndpointBToEndpointA,
}

/// The deterministic result of emitting one network frame.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkEmitDecisionRecord {
    /// Deliveries produced by the effective link model.
    pub outcome: ResolveOutcome,
    /// Fixed-order draw vector consumed by the link.
    pub draws: FrameDraws,
    /// Raw draws recorded in schedule order.
    pub decisions: Vec<Decision>,
}

fn link_rng_draw_decisions(stream: &RngStreamId, draws: &FrameDraws) -> Vec<Decision> {
    [draws.jitter, draws.reorder, draws.loss]
        .into_iter()
        .chain(draws.additional_loss.iter().copied())
        .chain([draws.duplicate, draws.corrupt])
        .chain(draws.corrupt_bits.iter().copied())
        .map(|value| {
            Decision::RngDraw(RngDecision {
                stream: stream.clone(),
                value,
            })
        })
        .collect()
}

/// Returns the canonical decision-stream id stored in a device overlay.
#[must_use]
pub fn device_stream_id(device: &DeviceId) -> RngStreamId {
    RngStreamId::for_device(device.name.clone())
}

/// Builds a device overlay delta with its deterministic stream cursor.
#[must_use]
pub fn device_overlay(
    device: &DeviceId,
    parent: crate::ContentHash,
    delta: crate::ContentHash,
    resolved: crate::ContentHash,
    rng_position: u64,
) -> DeviceOverlayDelta {
    let mut streams = BTreeMap::new();
    streams.insert(
        device_stream_id(device),
        RngStreamPosition::new(rng_position),
    );
    DeviceOverlayDelta::new(parent, delta, resolved, DeviceRngState { streams })
}

mod link_emission;

pub use link_emission::*;
