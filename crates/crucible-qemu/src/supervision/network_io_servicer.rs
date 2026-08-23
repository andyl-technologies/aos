//! Deterministic network-ring servicer for a live QEMU guest.
//!
//! The servicer owns an independent writable mapping limited to the directed
//! `(vm -> SLOT_NET_ROUTER)` and `(SLOT_NET_ROUTER -> vm)` rings. It drains
//! guest-originated Ethernet frames, recognizes the certifying probe frame, and
//! schedules exactly one reply at a fixed icount offset. No host networking API
//! participates.

use std::os::fd::BorrowedFd;

use crucible_shmem::{
    FrameDeliveryKey, FrameEntry, FrameEntryError, LookaheadGateError, MappedDirectedRingMut,
    MappedNodeRingPairMut, MappedSetupRegion, MappedSetupRegionAccessError, NodeSlotError,
    NodeSlotSnapshot, SLOT_NET_ROUTER, SchedulerWakePublicationError, SetupRegionMapError,
    SpscRingError, authorize_advance_ceiling, mmap_setup_region,
};
use thiserror::Error;

/// Experimental EtherType reserved for the live certifying exchange.
pub const LIVE_NETWORK_ETHERTYPE: [u8; 2] = [0x88, 0xb5];
/// Guest-to-router probe payload.
pub const LIVE_NETWORK_PROBE_PAYLOAD: &[u8] = b"crucible-network-probe-v1";
/// Router-to-guest reply payload.
pub const LIVE_NETWORK_REPLY_PAYLOAD: &[u8] = b"crucible-network-reply-v1";
/// Guest-to-router acknowledgement payload.
pub const LIVE_NETWORK_ACK_PAYLOAD: &[u8] = b"crucible-network-ack-v1";
/// Router frame used before guest-driver initialization to force real backpressure.
pub const LIVE_NETWORK_BACKPRESSURE_PAYLOAD: &[u8] = b"crucible-network-backpressure-v1";
/// Guest acknowledgement for the exact boot-time backpressure canary.
pub const LIVE_NETWORK_BACKPRESSURE_ACK_PAYLOAD: &[u8] = b"crucible-network-backpressure-ack-v1";
/// Fixed logical latency between probe emission and reply delivery.
///
/// The deliberately broad window lets the guest enter its blocking receive
/// before the router publishes the response. Logical delivery is exact and
/// identical across runs.
pub const LIVE_NETWORK_REPLY_LATENCY_ICOUNT: u64 = 100_000_000;

const ETHERNET_HEADER_LEN: usize = 14;
const MINIMUM_ETHERNET_FRAME_LEN: usize = 60;
const ROUTER_MAC: [u8; 6] = [0x02, 0x00, 0x00, 0x00, 0x00, 0x01];

/// One guest TX frame observed by the live network servicer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveNetworkTxObservation {
    /// Plugin-stamped guest emission icount.
    pub emit_icount: u64,
    /// Per-source sequence number assigned by the plugin.
    pub sequence: u32,
    /// Exact Ethernet bytes emitted by the guest.
    pub payload: Vec<u8>,
}

/// Cumulative deterministic evidence from one live network run.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LiveNetworkIoSnapshot {
    /// Guest TX frames in shared-memory FIFO order.
    pub tx_frames: Vec<LiveNetworkTxObservation>,
    /// Delivery icount of the scheduled reply, when enqueued.
    pub reply_delivery_icount: Option<u64>,
    /// Whether the guest emitted the post-RX acknowledgement frame.
    pub acknowledgement_seen: bool,
    /// Whether guest userspace acknowledged the exact retained boot-time frame.
    pub backpressure_acknowledgement_seen: bool,
}

/// Result of one network-ring servicing pass.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LiveNetworkIoServiceStep {
    /// Number of guest TX frames drained this pass.
    pub drained: usize,
    /// Whether this pass enqueued the deterministic reply.
    pub reply_enqueued: bool,
    /// Whether an acknowledgement was observed during this pass.
    pub acknowledgement_seen: bool,
    /// Whether this pass observed the retained-frame acknowledgement.
    pub backpressure_acknowledgement_seen: bool,
}

/// Host-side deterministic router for a single live guest.
pub struct QemuLiveNetworkIoServicer {
    region: MappedSetupRegion,
    vm_slot: u32,
    reply_sequence: u32,
    snapshot: LiveNetworkIoSnapshot,
}

impl QemuLiveNetworkIoServicer {
    /// Maps the setup region and binds the VM/router directed ring pair.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveNetworkIoServicerError::MapRegion`] when the shared
    /// memory descriptor cannot be mapped.
    pub fn from_shmem_fd(
        shmem_fd: BorrowedFd<'_>,
        region_len: u64,
        vm_slot: u32,
    ) -> Result<Self, QemuLiveNetworkIoServicerError> {
        let region = mmap_setup_region(shmem_fd, region_len)
            .map_err(|source| QemuLiveNetworkIoServicerError::MapRegion { source })?;
        Ok(Self {
            region,
            vm_slot,
            reply_sequence: 0,
            snapshot: LiveNetworkIoSnapshot::default(),
        })
    }

    /// Builds the boot-time frame that must encounter the unready guest NIC.
    ///
    /// The caller publishes these bytes through the production scheduler hot
    /// path, which assigns the canonical router sequence and validates that its
    /// delivery coordinate is strictly in the future.
    #[must_use]
    pub fn boot_backpressure_probe() -> Vec<u8> {
        let mut payload = vec![0_u8; MINIMUM_ETHERNET_FRAME_LEN];
        payload[..6].fill(0xff);
        payload[6..12].copy_from_slice(&ROUTER_MAC);
        payload[12..14].copy_from_slice(&LIVE_NETWORK_ETHERTYPE);
        payload[14..14 + LIVE_NETWORK_BACKPRESSURE_PAYLOAD.len()]
            .copy_from_slice(LIVE_NETWORK_BACKPRESSURE_PAYLOAD);
        payload
    }

    /// Advances the servicer's router sequence after a hot-path publication.
    ///
    /// # Errors
    ///
    /// Returns a typed error if the hot path did not publish the sequence the
    /// servicer expected to precede its next deterministic reply.
    pub fn observe_router_publication(
        &mut self,
        frame: FrameDeliveryKey,
    ) -> Result<(), QemuLiveNetworkIoServicerError> {
        if frame.src_node != SLOT_NET_ROUTER as u32 || frame.seq != self.reply_sequence {
            return Err(QemuLiveNetworkIoServicerError::RouterSequenceMismatch {
                expected: self.reply_sequence,
                actual: frame,
            });
        }
        self.reply_sequence = self
            .reply_sequence
            .checked_add(1)
            .ok_or(QemuLiveNetworkIoServicerError::ReplySequenceOverflow)?;
        Ok(())
    }

    /// Drains guest TX and schedules the fixed reply for the first valid probe.
    ///
    /// The reply is stamped at `probe.emit_icount + 100_000_000`. Enqueue publication
    /// precedes the VM-slot futex wake, so a parked plugin observes complete
    /// frame bytes before it can inject the frame into QEMU.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the mapped rings are unavailable or corrupt,
    /// probe timing overflows, reply construction fails, or the guest wake fails.
    pub fn service(&mut self) -> Result<LiveNetworkIoServiceStep, QemuLiveNetworkIoServicerError> {
        self.service_with_before_reply(|| {})
    }

    /// Services the rings and invokes `before_reply` immediately before the
    /// first deterministic reply is published.
    ///
    /// This hook supports diagnostic instrumentation around publication without
    /// changing the reply's logical `delivery_icount`. The certifying path does
    /// not introduce a wall-clock delay here because network RX is not frozen
    /// while the guest executes.
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::service`].
    pub fn service_with_before_reply(
        &mut self,
        before_reply: impl FnOnce(),
    ) -> Result<LiveNetworkIoServiceStep, QemuLiveNetworkIoServicerError> {
        let mut step = LiveNetworkIoServiceStep::default();
        let mut before_reply = Some(before_reply);
        loop {
            // Release the mapped ring borrow before processing the frame. A
            // completed scheduler quantum may own the same outbound consumer,
            // so both sources feed one observation path without overlapping
            // mutable mappings or losing a completion-drained frame.
            let frame = {
                let router_slot = SLOT_NET_ROUTER as u32;
                let pair = self
                    .region
                    .node_directed_ring_pair_mut(
                        self.vm_slot,
                        self.vm_slot,
                        router_slot,
                        router_slot,
                        self.vm_slot,
                    )
                    .map_err(|source| QemuLiveNetworkIoServicerError::RegionAccess { source })?;
                pair.first
                    .header
                    .dequeue(pair.first.entries)
                    .map_err(|source| QemuLiveNetworkIoServicerError::Ring { source })?
            };
            let Some(frame) = frame else {
                break;
            };
            let payload = frame
                .payload()
                .map_err(|source| QemuLiveNetworkIoServicerError::Frame { source })?
                .to_vec();
            let observation = LiveNetworkTxObservation {
                emit_icount: frame.delivery_icount,
                sequence: frame.seq,
                payload,
            };
            self.process_observation(observation, &mut step, &mut before_reply)?;
        }
        Ok(step)
    }

    /// Processes frames drained by scheduler-quantum completion.
    ///
    /// The scheduler hot path and the live router are alternate consumers of
    /// the same guest-to-router SPSC ring. A quantum that completes between
    /// router service passes owns any frames it drains; feeding those owned
    /// frames through this method preserves the single-consumer contract while
    /// retaining the exact ACK/probe semantics of [`Self::service`].
    ///
    /// # Errors
    ///
    /// Returns the same errors as [`Self::service`], plus a sequence-range
    /// error if a completion report cannot be represented by the shared-memory
    /// frame sequence domain.
    pub fn service_completed_frames_with_before_reply(
        &mut self,
        frames: Vec<crate::QemuNodeEmittedFrame>,
        before_reply: impl FnOnce(),
    ) -> Result<LiveNetworkIoServiceStep, QemuLiveNetworkIoServicerError> {
        let mut step = LiveNetworkIoServiceStep::default();
        let mut before_reply = Some(before_reply);
        for frame in frames {
            let sequence = u32::try_from(frame.sequence).map_err(|_error| {
                QemuLiveNetworkIoServicerError::OutboundSequenceOutOfRange {
                    sequence: frame.sequence,
                }
            })?;
            let observation = LiveNetworkTxObservation {
                emit_icount: frame.emit_icount.retired,
                sequence,
                payload: frame.payload,
            };
            self.process_observation(observation, &mut step, &mut before_reply)?;
        }
        Ok(step)
    }

    fn process_observation(
        &mut self,
        observation: LiveNetworkTxObservation,
        step: &mut LiveNetworkIoServiceStep,
        before_reply: &mut Option<impl FnOnce()>,
    ) -> Result<(), QemuLiveNetworkIoServicerError> {
        step.drained += 1;
        if is_live_network_ack(&observation.payload) {
            step.acknowledgement_seen = true;
            self.snapshot.acknowledgement_seen = true;
        }
        if is_live_network_backpressure_ack(&observation.payload) {
            step.backpressure_acknowledgement_seen = true;
            self.snapshot.backpressure_acknowledgement_seen = true;
        }

        if self.snapshot.reply_delivery_icount.is_none()
            && is_live_network_probe(&observation.payload)
        {
            self.publish_reply(&observation, before_reply)?;
            step.reply_enqueued = true;
        }
        self.snapshot.tx_frames.push(observation);
        Ok(())
    }

    fn publish_reply(
        &mut self,
        observation: &LiveNetworkTxObservation,
        before_reply: &mut Option<impl FnOnce()>,
    ) -> Result<(), QemuLiveNetworkIoServicerError> {
        let delivery_icount = observation
            .emit_icount
            .checked_add(LIVE_NETWORK_REPLY_LATENCY_ICOUNT)
            .ok_or(QemuLiveNetworkIoServicerError::DeliveryIcountOverflow {
                emit_icount: observation.emit_icount,
            })?;
        let reply_payload = live_network_reply(&observation.payload)?;
        let router_slot = SLOT_NET_ROUTER as u32;
        let reply = FrameEntry::new(
            delivery_icount,
            router_slot,
            self.reply_sequence,
            &reply_payload,
        )
        .map_err(|source| QemuLiveNetworkIoServicerError::Frame { source })?;
        if let Some(before_reply) = before_reply.take() {
            before_reply();
        }

        let pair = self
            .region
            .node_directed_ring_pair_mut(
                self.vm_slot,
                self.vm_slot,
                router_slot,
                router_slot,
                self.vm_slot,
            )
            .map_err(|source| QemuLiveNetworkIoServicerError::RegionAccess { source })?;
        let MappedNodeRingPairMut {
            node_slot, second, ..
        } = pair;
        let MappedDirectedRingMut {
            header: inbound_header,
            entries: inbound_entries,
            ..
        } = second;
        let slot_snapshot = node_slot.snapshot();
        let delivery_ceiling = slot_snapshot.max_advance_icount.min(delivery_icount);
        let ceiling =
            authorize_advance_ceiling(slot_snapshot.current_icount, delivery_ceiling, None)
                .map_err(
                    |source| QemuLiveNetworkIoServicerError::CeilingAuthorization { source },
                )?;
        node_slot
            .publish_scheduler_inbox_and_ceiling(
                self.vm_slot,
                router_slot,
                inbound_header,
                inbound_entries,
                std::slice::from_ref(&reply),
                ceiling,
            )
            .map_err(|source| QemuLiveNetworkIoServicerError::ReplyPublication { source })?;
        self.reply_sequence = self
            .reply_sequence
            .checked_add(1)
            .ok_or(QemuLiveNetworkIoServicerError::ReplySequenceOverflow)?;
        self.snapshot.reply_delivery_icount = Some(delivery_icount);
        Ok(())
    }

    /// Returns a copy of all deterministic evidence observed so far.
    #[must_use]
    pub fn snapshot(&self) -> LiveNetworkIoSnapshot {
        self.snapshot.clone()
    }

    /// Reads the live guest's published node-slot state.
    ///
    /// # Errors
    ///
    /// Returns [`QemuLiveNetworkIoServicerError::RegionAccess`] when the VM slot
    /// cannot be borrowed from the mapped setup region.
    pub fn vm_node_snapshot(&self) -> Result<NodeSlotSnapshot, QemuLiveNetworkIoServicerError> {
        Ok(self
            .region
            .node_slot(self.vm_slot)
            .map_err(|source| QemuLiveNetworkIoServicerError::RegionAccess { source })?
            .snapshot())
    }

    /// Publishes an exact scheduler ceiling and wakes the parked guest.
    ///
    /// This is used only after a scheduler quantum has completed idle and a
    /// concrete inbound event is already present. The caller first authorizes
    /// the reply delivery icount, waits for the plugin to inject it, and then
    /// authorizes the post-delivery execution horizon.
    ///
    /// # Errors
    ///
    /// Returns a typed error when the VM slot cannot be borrowed, the ceiling
    /// is behind the published guest icount, or the slot/wake publication fails.
    pub fn authorize_guest_ceiling(
        &self,
        max_advance_icount: u64,
    ) -> Result<(), QemuLiveNetworkIoServicerError> {
        let slot = self
            .region
            .node_slot(self.vm_slot)
            .map_err(|source| QemuLiveNetworkIoServicerError::RegionAccess { source })?;
        let current_icount = slot.snapshot().current_icount;
        let ceiling = authorize_advance_ceiling(current_icount, max_advance_icount, None)
            .map_err(|source| QemuLiveNetworkIoServicerError::CeilingAuthorization { source })?;
        slot.publish_scheduler_ceiling(ceiling)
            .map(|_wake| ())
            .map_err(|source| QemuLiveNetworkIoServicerError::CeilingPublication { source })
    }
}

fn is_live_network_probe(frame: &[u8]) -> bool {
    ethernet_payload(frame) == Some(LIVE_NETWORK_PROBE_PAYLOAD)
}

fn is_live_network_ack(frame: &[u8]) -> bool {
    ethernet_payload(frame) == Some(LIVE_NETWORK_ACK_PAYLOAD)
}

pub(crate) fn is_live_network_backpressure_ack(frame: &[u8]) -> bool {
    ethernet_payload(frame) == Some(LIVE_NETWORK_BACKPRESSURE_ACK_PAYLOAD)
}

fn ethernet_payload(frame: &[u8]) -> Option<&[u8]> {
    if frame.len() < ETHERNET_HEADER_LEN
        || frame[12..14] != LIVE_NETWORK_ETHERTYPE
        || frame.len() < ETHERNET_HEADER_LEN + LIVE_NETWORK_PROBE_PAYLOAD.len()
    {
        return None;
    }
    let payload = &frame[ETHERNET_HEADER_LEN..];
    let meaningful_len = payload.iter().rposition(|byte| *byte != 0)? + 1;
    Some(&payload[..meaningful_len])
}

fn live_network_reply(probe: &[u8]) -> Result<Vec<u8>, QemuLiveNetworkIoServicerError> {
    if probe.len() < ETHERNET_HEADER_LEN {
        return Err(QemuLiveNetworkIoServicerError::MalformedProbe {
            length: probe.len(),
        });
    }
    let mut reply = vec![0_u8; MINIMUM_ETHERNET_FRAME_LEN];
    reply[..6].copy_from_slice(&probe[6..12]);
    reply[6..12].copy_from_slice(&ROUTER_MAC);
    reply[12..14].copy_from_slice(&LIVE_NETWORK_ETHERTYPE);
    reply[14..14 + LIVE_NETWORK_REPLY_PAYLOAD.len()].copy_from_slice(LIVE_NETWORK_REPLY_PAYLOAD);
    Ok(reply)
}

/// Failure while servicing the live network ring pair.
#[derive(Debug, Error)]
pub enum QemuLiveNetworkIoServicerError {
    /// The shared-memory descriptor could not be mapped.
    #[error("could not map live network shared-memory region")]
    MapRegion {
        /// Mapping failure.
        #[source]
        source: SetupRegionMapError,
    },
    /// The VM/router directed ring pair could not be borrowed.
    #[error("could not access live network shared-memory ring pair")]
    RegionAccess {
        /// Typed mapped-region access failure.
        #[source]
        source: MappedSetupRegionAccessError,
    },
    /// A frame failed ABI validation or construction.
    #[error("live network frame operation failed")]
    Frame {
        /// Typed frame failure.
        #[source]
        source: FrameEntryError,
    },
    /// An SPSC ring operation failed.
    #[error("live network ring operation failed")]
    Ring {
        /// Typed ring failure.
        #[source]
        source: SpscRingError,
    },
    /// Reply delivery timing overflowed the icount domain.
    #[error("live network reply delivery icount overflowed after emit icount {emit_icount}")]
    DeliveryIcountOverflow {
        /// Probe emission icount.
        emit_icount: u64,
    },
    /// The response sequence counter overflowed.
    #[error("live network reply sequence overflowed")]
    ReplySequenceOverflow,
    /// A scheduler hot-path publication disagreed with the router sequence.
    #[error(
        "live network router sequence mismatch: expected {expected}, observed frame {actual:?}"
    )]
    RouterSequenceMismatch {
        /// Sequence the servicer expected the hot path to publish.
        expected: u32,
        /// Actual canonical frame key found in shared memory.
        actual: FrameDeliveryKey,
    },
    /// A completion report carried a frame sequence outside the ABI domain.
    #[error("live network outbound sequence {sequence} exceeds the u32 ABI domain")]
    OutboundSequenceOutOfRange {
        /// Sequence reported by scheduler-quantum completion.
        sequence: u64,
    },
    /// A probe was too short to contain an Ethernet source address.
    #[error("live network probe is malformed at {length} bytes")]
    MalformedProbe {
        /// Observed frame length.
        length: usize,
    },
    /// Ordered reply, ceiling, and wake publication failed.
    #[error("could not publish live network reply, ceiling, and wake atomically")]
    ReplyPublication {
        /// Typed ordered scheduler-wake failure.
        #[source]
        source: SchedulerWakePublicationError,
    },
    /// The requested event-boundary ceiling was invalid.
    #[error("live network scheduler ceiling authorization failed")]
    CeilingAuthorization {
        /// Typed lookahead failure.
        #[source]
        source: LookaheadGateError,
    },
    /// Publishing an authorized event-boundary ceiling failed.
    #[error("live network scheduler ceiling publication failed")]
    CeilingPublication {
        /// Typed node-slot failure.
        #[source]
        source: NodeSlotError,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame_with(payload: &[u8]) -> Vec<u8> {
        let mut frame = vec![0_u8; MINIMUM_ETHERNET_FRAME_LEN];
        frame[..6].copy_from_slice(&[0xff; 6]);
        frame[6..12].copy_from_slice(&[0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        frame[12..14].copy_from_slice(&LIVE_NETWORK_ETHERTYPE);
        frame[14..14 + payload.len()].copy_from_slice(payload);
        frame
    }

    #[test]
    fn probe_and_ack_are_exact_protocol_payloads() {
        assert!(is_live_network_probe(&frame_with(
            LIVE_NETWORK_PROBE_PAYLOAD
        )));
        assert!(!is_live_network_probe(&frame_with(
            LIVE_NETWORK_ACK_PAYLOAD
        )));
        assert!(is_live_network_ack(&frame_with(LIVE_NETWORK_ACK_PAYLOAD)));
        assert!(is_live_network_backpressure_ack(&frame_with(
            LIVE_NETWORK_BACKPRESSURE_ACK_PAYLOAD
        )));
    }

    #[test]
    fn reply_targets_guest_source_and_uses_router_source() {
        let probe = frame_with(LIVE_NETWORK_PROBE_PAYLOAD);
        let reply = live_network_reply(&probe).unwrap_or_else(|error| {
            panic!("valid probe should build a reply: {error}");
        });
        assert_eq!(&reply[..6], &probe[6..12]);
        assert_eq!(&reply[6..12], &ROUTER_MAC);
        assert_eq!(&reply[12..14], &LIVE_NETWORK_ETHERTYPE);
        assert_eq!(ethernet_payload(&reply), Some(LIVE_NETWORK_REPLY_PAYLOAD));
    }
}
