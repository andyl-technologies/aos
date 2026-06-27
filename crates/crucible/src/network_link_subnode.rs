//! Deterministic network-link sub-node model.
//!
//! Network links are scheduler-owned sub-nodes that transform VM-emitted frames
//! through the reserved `SLOT_NET_ROUTER` path. A link computes the frame's
//! modeled delivery point from the emitting VM's icount, the declared link
//! transport, and an effective fault table whose probabilistic choices have
//! already been drawn and recorded by the scheduler.

use crate::{
    BackendInput, Icount, LinkDef, LinkLossProbability, NodeId, ScheduledEvent, ScheduledEventKey,
    ScheduledEventPayload, SchedulerNodeId, SchedulingNodeKind, Shift, SimDuration,
    TimeConversionError, VirtualTime,
};
use std::error::Error;
use std::fmt;

const LINK_PROBABILITY_DENOMINATOR: u64 = 1_000_000;
const NANOS_PER_SECOND: u128 = 1_000_000_000;

/// The reserved shared-memory slot used by the network router executor.
pub const NETWORK_ROUTER_SLOT_NAME: &str = "SLOT_NET_ROUTER";

/// The reserved shared-memory slot index used by the network router executor.
pub const NETWORK_ROUTER_SLOT_INDEX: u32 = 31;

/// The scheduler node name used by the existing shmem/sim slot bridge.
pub const NETWORK_ROUTER_SLOT_NODE_NAME: &str = "slot-31";

/// One VM-emitted frame entering the modeled network router.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NetworkLinkFrame {
    /// Source-local frame sequence from the VM-to-router ring.
    pub sequence: u64,
    /// Source VM icount when the frame became modeled input.
    pub emit_icount: Icount,
    /// Payload bytes carried by the frame.
    pub payload: Vec<u8>,
}

/// Seeded effective network faults for one directed frame delivery.
///
/// The scheduler owns the decision RNG and records the raw draws. This table is
/// therefore a pure input to the link model: it names active perturbations and
/// provides the deterministic draw values consumed by each probabilistic or
/// variable-delay operation.
#[derive(Clone, Debug, Default, PartialEq, Eq, Hash)]
pub struct NetworkLinkEffectiveFaults {
    /// Draw used for the declared link jitter window.
    pub link_jitter_draw: u64,
    /// Extra fixed latency from effective latency faults.
    pub extra_latency: SimDuration,
    /// Additional bandwidth limit contributed by active faults.
    pub bandwidth_bps: Option<u64>,
    /// Additional reorder-delay window.
    pub reorder_window: SimDuration,
    /// Draw used for the reorder-delay window.
    pub reorder_draw: u64,
    /// Draw used for the link's declared loss probability.
    pub link_loss_draw: u64,
    /// Additional effective loss probability.
    pub additional_loss_rate: LinkLossProbability,
    /// Draw used for the additional effective loss probability.
    pub additional_loss_draw: u64,
    /// Effective duplicate probability.
    pub duplicate_rate: LinkLossProbability,
    /// Draw used for the duplicate probability.
    pub duplicate_draw: u64,
    /// Effective corruption probability.
    pub corruption_rate: LinkLossProbability,
    /// Draw used for the corruption probability.
    pub corruption_draw: u64,
    /// Draw selecting which payload bit is flipped when corruption fires.
    pub corruption_bit_draw: u64,
}

/// The deterministic perturbations applied to one frame.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NetworkLinkPerturbations {
    /// Declared one-way base latency.
    pub base_latency: SimDuration,
    /// Serialization delay from the effective bandwidth cap.
    pub bandwidth_delay: SimDuration,
    /// Seeded delay from the declared link jitter window.
    pub jitter_delay: SimDuration,
    /// Extra fixed latency from effective latency faults.
    pub extra_latency: SimDuration,
    /// Seeded delay from active reorder faults.
    pub reorder_delay: SimDuration,
    /// Whether the declared link loss probability dropped the frame.
    pub link_loss_fired: bool,
    /// Whether an additional effective loss fault dropped the frame.
    pub additional_loss_fired: bool,
    /// Whether an effective duplicate fault emitted a second frame.
    pub duplicate_fired: bool,
    /// Whether an effective corruption fault mutated the payload.
    pub corruption_fired: bool,
}

/// One modeled delivery emitted by a network link.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NetworkLinkDelivery {
    /// Source-local frame sequence that produced this delivery.
    pub frame_sequence: u64,
    /// Copy index: `0` for the original frame and `1` for a duplicate.
    pub copy_index: u8,
    /// Icount at which the target VM may observe the frame.
    pub delivery_icount: Icount,
    /// Virtual time at which the target VM may observe the frame.
    pub delivery_time: VirtualTime,
    /// Payload after deterministic corruption, if any.
    pub payload: Vec<u8>,
}

impl NetworkLinkDelivery {
    /// Builds the scheduler event that delivers this frame to `link.target()`.
    ///
    /// The event producer remains the source VM, matching the source-local
    /// frame sequence used by the shmem ring. The modeled `SLOT_NET_ROUTER`
    /// still applies the link before this backend input becomes visible to the
    /// target VM.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkLinkError::EventSequenceOverflow`] when the source-local
    /// frame sequence and copy index cannot be encoded as one event sequence.
    pub fn to_scheduled_event(
        &self,
        link: &NetworkLinkSubNode,
    ) -> Result<ScheduledEvent, NetworkLinkError> {
        Ok(ScheduledEvent {
            key: ScheduledEventKey::from_parts(
                self.delivery_time,
                link.target.clone(),
                link.source.clone(),
                self.event_sequence()?,
            ),
            payload: ScheduledEventPayload::BackendInput(BackendInput {
                node: link.target.node.clone(),
                payload: self.payload.clone(),
            }),
        })
    }

    /// Returns the deterministic scheduler-event sequence assigned by the link.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkLinkError::EventSequenceOverflow`] when the source-local
    /// frame sequence and copy index cannot be encoded as one event sequence.
    pub fn event_sequence(&self) -> Result<u64, NetworkLinkError> {
        delivery_sequence(self.frame_sequence, self.copy_index)
    }
}

/// The result of applying one directed link to one frame.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NetworkLinkPlan {
    /// The perturbations that were evaluated for the frame.
    pub perturbations: NetworkLinkPerturbations,
    /// Whether the frame was dropped by loss.
    pub dropped: bool,
    /// Deliveries emitted for the frame, empty when dropped.
    pub deliveries: Vec<NetworkLinkDelivery>,
}

/// A deterministic directed network-link sub-node.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct NetworkLinkSubNode {
    link: LinkDef,
    source: SchedulerNodeId,
    target: SchedulerNodeId,
    router: SchedulerNodeId,
    shift: Shift,
}

impl NetworkLinkSubNode {
    /// Builds a directed network link over a declared world link.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkLinkError`] when either endpoint is not a VM scheduler
    /// node, the directed endpoints are not the declared link endpoints, or the
    /// fixed icount shift is invalid.
    pub fn new(
        link: LinkDef,
        source: SchedulerNodeId,
        target: SchedulerNodeId,
        shift: Shift,
    ) -> Result<Self, NetworkLinkError> {
        if source.kind != SchedulingNodeKind::Vm {
            return Err(NetworkLinkError::InvalidEndpointKind {
                endpoint: source,
                role: NetworkLinkEndpointRole::Source,
            });
        }
        if target.kind != SchedulingNodeKind::Vm {
            return Err(NetworkLinkError::InvalidEndpointKind {
                endpoint: target,
                role: NetworkLinkEndpointRole::Target,
            });
        }
        if !link_has_directed_endpoints(&link, &source.node, &target.node) {
            return Err(NetworkLinkError::EndpointMismatch {
                link,
                source: source.node,
                target: target.node,
            });
        }
        let _ = Icount { retired: 0 }.to_virtual(shift)?;

        Ok(Self {
            link,
            source,
            target,
            router: network_router_node(),
            shift,
        })
    }

    /// Returns the declared world link backing this directed sub-node.
    #[must_use]
    pub const fn link(&self) -> &LinkDef {
        &self.link
    }

    /// Returns the source VM endpoint.
    #[must_use]
    pub const fn source(&self) -> &SchedulerNodeId {
        &self.source
    }

    /// Returns the target VM endpoint.
    #[must_use]
    pub const fn target(&self) -> &SchedulerNodeId {
        &self.target
    }

    /// Returns the modeled router producer node.
    #[must_use]
    pub const fn router(&self) -> &SchedulerNodeId {
        &self.router
    }

    /// Returns the fixed icount shift used for frame delivery conversion.
    #[must_use]
    pub const fn shift(&self) -> Shift {
        self.shift
    }

    /// Applies this link's effective fault table to one frame.
    ///
    /// # Errors
    ///
    /// Returns [`NetworkLinkError`] when bandwidth delay or delivery time
    /// overflows, an effective bandwidth cap is zero, the resulting delivery
    /// event sequence cannot be represented, or virtual-time conversion fails.
    pub fn plan_frame(
        &self,
        frame: NetworkLinkFrame,
        faults: &NetworkLinkEffectiveFaults,
    ) -> Result<NetworkLinkPlan, NetworkLinkError> {
        let bandwidth_bps = effective_bandwidth(self.link.bandwidth_bps(), faults.bandwidth_bps);
        let bandwidth_delay = bandwidth_delay(frame.payload.len(), bandwidth_bps)?;
        let jitter_delay = uniform_delay(self.link.jitter(), faults.link_jitter_draw);
        let reorder_delay = uniform_delay(faults.reorder_window, faults.reorder_draw);

        let link_loss_fired = bernoulli_fires(self.link.loss(), faults.link_loss_draw);
        let additional_loss_fired =
            bernoulli_fires(faults.additional_loss_rate, faults.additional_loss_draw);
        let dropped = link_loss_fired || additional_loss_fired;

        let duplicate_fired =
            !dropped && bernoulli_fires(faults.duplicate_rate, faults.duplicate_draw);
        let corruption_fired =
            !dropped && bernoulli_fires(faults.corruption_rate, faults.corruption_draw);

        let perturbations = NetworkLinkPerturbations {
            base_latency: self.link.latency(),
            bandwidth_delay,
            jitter_delay,
            extra_latency: faults.extra_latency,
            reorder_delay,
            link_loss_fired,
            additional_loss_fired,
            duplicate_fired,
            corruption_fired,
        };

        if dropped {
            return Ok(NetworkLinkPlan {
                perturbations,
                dropped: true,
                deliveries: Vec::new(),
            });
        }

        let exact_delivery_time = self.delivery_time(frame.emit_icount, &perturbations)?;
        let delivery_icount = exact_delivery_time.to_icount_ceil(self.shift)?;
        let observable_delivery_time = delivery_icount.to_virtual(self.shift)?;
        let delivery_time = VirtualTime {
            ticks: observable_delivery_time.nanos,
        };
        let payload =
            corrupt_payload_if_needed(frame.payload, corruption_fired, faults.corruption_bit_draw);
        let mut deliveries = vec![NetworkLinkDelivery {
            frame_sequence: frame.sequence,
            copy_index: 0,
            delivery_icount,
            delivery_time,
            payload: payload.clone(),
        }];
        if duplicate_fired {
            deliveries.push(NetworkLinkDelivery {
                frame_sequence: frame.sequence,
                copy_index: 1,
                delivery_icount,
                delivery_time,
                payload,
            });
        }
        for delivery in &deliveries {
            ensure_delivery_sequence(delivery.frame_sequence, delivery.copy_index)?;
        }

        Ok(NetworkLinkPlan {
            perturbations,
            dropped: false,
            deliveries,
        })
    }

    fn delivery_time(
        &self,
        emit_icount: Icount,
        perturbations: &NetworkLinkPerturbations,
    ) -> Result<crate::VirtualInstant, NetworkLinkError> {
        let mut delivery = emit_icount.to_virtual(self.shift)?;
        for delay in [
            perturbations.base_latency,
            perturbations.bandwidth_delay,
            perturbations.jitter_delay,
            perturbations.extra_latency,
            perturbations.reorder_delay,
        ] {
            delivery = add_duration(delivery, delay)?;
        }
        Ok(delivery)
    }
}

/// Returns the modeled scheduler node for the reserved network router slot.
#[must_use]
pub fn network_router_node() -> SchedulerNodeId {
    SchedulerNodeId {
        node: NodeId {
            name: NETWORK_ROUTER_SLOT_NODE_NAME.to_owned(),
        },
        kind: SchedulingNodeKind::Vm,
    }
}

/// Sorts link deliveries in deterministic scheduler-observation order.
pub fn sort_network_link_deliveries(deliveries: &mut [NetworkLinkDelivery]) {
    deliveries.sort_by(|left, right| {
        left.delivery_time
            .cmp(&right.delivery_time)
            .then_with(|| left.delivery_icount.cmp(&right.delivery_icount))
            .then_with(|| left.frame_sequence.cmp(&right.frame_sequence))
            .then_with(|| left.copy_index.cmp(&right.copy_index))
    });
}

/// The endpoint role used in directed-link validation errors.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum NetworkLinkEndpointRole {
    /// Source endpoint of a directed link.
    Source,
    /// Target endpoint of a directed link.
    Target,
}

/// A deterministic network-link planning failure.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NetworkLinkError {
    /// A directed endpoint was not a VM scheduler node.
    InvalidEndpointKind {
        /// Endpoint that failed validation.
        endpoint: SchedulerNodeId,
        /// Endpoint role that failed validation.
        role: NetworkLinkEndpointRole,
    },
    /// The directed endpoints are not the declared world link endpoints.
    EndpointMismatch {
        /// Declared world link.
        link: LinkDef,
        /// Requested source node.
        source: NodeId,
        /// Requested target node.
        target: NodeId,
    },
    /// Virtual-time conversion failed.
    TimeConversion(TimeConversionError),
    /// Effective bandwidth was zero.
    ZeroBandwidth,
    /// Serialization delay could not be represented as a `u64` nanosecond span.
    BandwidthDelayOverflow {
        /// Payload length in bytes.
        bytes: usize,
        /// Effective bandwidth in bits per virtual second.
        bandwidth_bps: u64,
    },
    /// Delivery virtual time overflowed.
    DeliveryTimeOverflow,
    /// Delivery event sequence overflowed.
    EventSequenceOverflow {
        /// Source-local frame sequence.
        frame_sequence: u64,
        /// Copy index within that source-local frame.
        copy_index: u8,
    },
}

impl fmt::Display for NetworkLinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidEndpointKind { endpoint, role } => {
                write!(
                    f,
                    "network link {role:?} endpoint {} has invalid scheduler kind {:?}",
                    endpoint.node.name, endpoint.kind
                )
            }
            Self::EndpointMismatch { source, target, .. } => write!(
                f,
                "network link endpoints {} -> {} do not match declared link",
                source.name, target.name
            ),
            Self::TimeConversion(source) => write!(f, "{source}"),
            Self::ZeroBandwidth => f.write_str("network link bandwidth limit is zero"),
            Self::BandwidthDelayOverflow {
                bytes,
                bandwidth_bps,
            } => write!(
                f,
                "network link serialization delay overflow for {bytes} bytes at {bandwidth_bps} bps"
            ),
            Self::DeliveryTimeOverflow => f.write_str("network link delivery time overflow"),
            Self::EventSequenceOverflow {
                frame_sequence,
                copy_index,
            } => write!(
                f,
                "network link event sequence overflow for frame {frame_sequence} copy {copy_index}"
            ),
        }
    }
}

impl Error for NetworkLinkError {}

impl From<TimeConversionError> for NetworkLinkError {
    fn from(source: TimeConversionError) -> Self {
        Self::TimeConversion(source)
    }
}

fn link_has_directed_endpoints(link: &LinkDef, source: &NodeId, target: &NodeId) -> bool {
    let (left, right) = link.endpoints();
    (source == left && target == right) || (source == right && target == left)
}

fn effective_bandwidth(link_bps: Option<u64>, fault_bps: Option<u64>) -> Option<u64> {
    match (link_bps, fault_bps) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(bps), None) | (None, Some(bps)) => Some(bps),
        (None, None) => None,
    }
}

fn bandwidth_delay(
    payload_len: usize,
    bandwidth_bps: Option<u64>,
) -> Result<SimDuration, NetworkLinkError> {
    let Some(bandwidth_bps) = bandwidth_bps else {
        return Ok(SimDuration { nanos: 0 });
    };
    if bandwidth_bps == 0 {
        return Err(NetworkLinkError::ZeroBandwidth);
    }
    let bits =
        (payload_len as u128)
            .checked_mul(8)
            .ok_or(NetworkLinkError::BandwidthDelayOverflow {
                bytes: payload_len,
                bandwidth_bps,
            })?;
    let numerator =
        bits.checked_mul(NANOS_PER_SECOND)
            .ok_or(NetworkLinkError::BandwidthDelayOverflow {
                bytes: payload_len,
                bandwidth_bps,
            })?;
    let divisor = u128::from(bandwidth_bps);
    let delay =
        numerator
            .checked_add(divisor - 1)
            .ok_or(NetworkLinkError::BandwidthDelayOverflow {
                bytes: payload_len,
                bandwidth_bps,
            })?
            / divisor;
    let nanos = u64::try_from(delay).map_err(|_| NetworkLinkError::BandwidthDelayOverflow {
        bytes: payload_len,
        bandwidth_bps,
    })?;
    Ok(SimDuration { nanos })
}

fn uniform_delay(window: SimDuration, draw: u64) -> SimDuration {
    if window.nanos == 0 {
        return SimDuration { nanos: 0 };
    }
    let modulo = u128::from(window.nanos) + 1;
    SimDuration {
        nanos: (u128::from(draw) % modulo) as u64,
    }
}

fn bernoulli_fires(rate: LinkLossProbability, draw: u64) -> bool {
    let threshold = u64::from(rate.millionths());
    threshold != 0 && draw % LINK_PROBABILITY_DENOMINATOR < threshold
}

fn corrupt_payload_if_needed(mut payload: Vec<u8>, fired: bool, draw: u64) -> Vec<u8> {
    if !fired || payload.is_empty() {
        return payload;
    }
    let bit_count = (payload.len() as u128) * 8;
    let bit = u128::from(draw) % bit_count;
    let byte_index = (bit / 8) as usize;
    let bit_index = (bit % 8) as u8;
    payload[byte_index] ^= 1_u8 << bit_index;
    payload
}

fn add_duration(
    instant: crate::VirtualInstant,
    duration: SimDuration,
) -> Result<crate::VirtualInstant, NetworkLinkError> {
    let Some(nanos) = instant.nanos.checked_add(duration.nanos) else {
        return Err(NetworkLinkError::DeliveryTimeOverflow);
    };
    Ok(crate::VirtualInstant { nanos })
}

fn ensure_delivery_sequence(frame_sequence: u64, copy_index: u8) -> Result<(), NetworkLinkError> {
    delivery_sequence(frame_sequence, copy_index).map(|_| ())
}

fn delivery_sequence(frame_sequence: u64, copy_index: u8) -> Result<u64, NetworkLinkError> {
    frame_sequence
        .checked_mul(2)
        .and_then(|sequence| sequence.checked_add(u64::from(copy_index)))
        .ok_or(NetworkLinkError::EventSequenceOverflow {
            frame_sequence,
            copy_index,
        })
}
