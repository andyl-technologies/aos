//! Engine-side bridge to deterministic I/O scheduling sub-nodes.
//!
//! Block, 9p, and network operations cross this module through the typed
//! signal-driven adapters. Device overlay construction remains here because
//! materialized checkpoints share the same content-addressed overlay shape.
//! Every operation handled here was already emitted by a modeled guest/device endpoint.
//! This module is not a host-side workload generator and MUST NOT be used to originate application traffic.

use std::collections::BTreeMap;

use crucible_device::{
    DeviceError, DeviceRng, Frame, FrameDraws, LinkFrameDrawKey, NetLink, PastDeliveryPolicy,
    ResolveOutcome,
};

use crate::{
    Decision, DeviceId, DeviceOverlayDelta, DeviceRngState, RngDecision, RngDrawAddress,
    RngStreamId, RngStreamPosition, Seed,
};

/// The orientation of one directed runtime link.
#[derive(
    Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, serde::Serialize, serde::Deserialize,
)]
pub enum NetworkLinkDirection {
    /// The link carries frames from endpoint A to endpoint B.
    EndpointAToEndpointB,
    /// The link carries frames from endpoint B to endpoint A.
    EndpointBToEndpointA,
}

impl NetworkLinkDirection {
    /// Returns the stable wire code: `0` for A to B, `1` for B to A.
    #[must_use]
    pub const fn code(self) -> u8 {
        match self {
            Self::EndpointAToEndpointB => 0,
            Self::EndpointBToEndpointA => 1,
        }
    }

    /// Returns the direction for a stable wire code.
    #[must_use]
    pub const fn from_code(code: u8) -> Option<Self> {
        match code {
            0 => Some(Self::EndpointAToEndpointB),
            1 => Some(Self::EndpointBToEndpointA),
            _ => None,
        }
    }

    /// Returns the stable textual label used in canonical material.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::EndpointAToEndpointB => "a-to-b",
            Self::EndpointBToEndpointA => "b-to-a",
        }
    }

    /// Returns the event-key draw identity of frame `producer_sequence` in this direction.
    #[must_use]
    pub fn frame_draw_key(self, producer_sequence: u64) -> LinkFrameDrawKey {
        LinkFrameDrawKey {
            direction: self.code(),
            producer_sequence,
        }
    }
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

/// Records a frame's draws in their fixed order, each at its role index.
///
/// The role index is the draw's position in [`FrameDraws`] order, which is the
/// event-stream position the keyed derivation consumed ([SCHED-50]).
fn link_rng_draw_decisions(
    stream: &RngStreamId,
    direction: NetworkLinkDirection,
    producer_sequence: u64,
    draws: &FrameDraws,
) -> Vec<Decision> {
    [draws.jitter, draws.reorder, draws.loss]
        .into_iter()
        .chain(draws.additional_loss.iter().copied())
        .chain([draws.duplicate, draws.corrupt])
        .chain(draws.corruption_selectors.iter().copied())
        .zip(0_u64..)
        .map(|(value, role)| {
            Decision::RngDraw(RngDecision {
                stream: stream.clone(),
                address: RngDrawAddress::LinkFrame {
                    direction,
                    producer_sequence,
                    role,
                },
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
