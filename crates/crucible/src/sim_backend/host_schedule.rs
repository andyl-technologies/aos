//! Canonical host-visible schedule events emitted by the simulation double.

use super::*;

/// A canonical host-side ordering event observed while driving [`SimDouble`].
///
/// The event vocabulary deliberately excludes the synthetic guest fingerprint
/// and other double-only state. It records only ordering visible to the host
/// scheduler or shared-memory transport so tests can compare it with the real
/// plugin path.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SimDoubleHostScheduleEvent {
    /// The host-authorized quantum advanced or paused at an earlier delivery.
    HorizonAdvance {
        /// Icount before the advance request.
        from_icount: u64,
        /// Icount requested by the host for this quantum.
        requested_icount: u64,
        /// Icount reached by the backend before returning control.
        reached_icount: u64,
        /// Backend result reported to the host.
        outcome: AdvanceOutcome,
    },
    /// An inbound frame became visible to the guest through a shared SPSC ring.
    FrameDelivery {
        /// Source physical slot.
        src_slot: u32,
        /// Producer sequence number.
        sequence: u32,
        /// Consumer icount at which the frame became visible.
        delivery_icount: u64,
        /// Delivered payload bytes.
        payload: Vec<u8>,
    },
    /// A guest-emitted frame was posted to an outbound shared SPSC ring.
    FrameEmission {
        /// Physical destination slot.
        dst_slot: u32,
        /// Producer sequence number stamped on the outbound frame.
        sequence: u32,
        /// Consumer icount at which the frame is deliverable.
        delivery_icount: u64,
        /// Emitted payload bytes.
        payload: Vec<u8>,
    },
    /// A deterministic device callback completed host-side I/O.
    IoCompletion {
        /// Stable device or executor label.
        device: String,
        /// Completion sequence within the device stream.
        sequence: u64,
        /// Icount at which the completion became host-observable.
        completion_icount: u64,
        /// Completion payload or status bytes.
        payload: Vec<u8>,
    },
    /// A host-visible snapshot was captured.
    Snapshot {
        /// Content-addressed checkpoint identifier.
        checkpoint_id: ContentHash,
        /// Execution fingerprint recorded in the checkpoint.
        fingerprint: ContentHash,
        /// Captured checkpoint representation.
        kind: CheckpointKind,
    },
}

/// Encodes a host-observable schedule into a stable byte representation.
///
/// The encoding is versioned, length-prefixes variable data, and assigns a
/// fixed tag to every event and outcome variant. It is the comparison surface
/// shared by the in-process double and production-plugin integration gates.
#[must_use]
pub fn sim_double_host_schedule_canonical_bytes(
    schedule: &[SimDoubleHostScheduleEvent],
) -> Vec<u8> {
    let mut bytes = b"crucible.sim-double.host-schedule.v1\0".to_vec();
    push_u64(&mut bytes, schedule.len() as u64);
    for event in schedule {
        match event {
            SimDoubleHostScheduleEvent::HorizonAdvance {
                from_icount,
                requested_icount,
                reached_icount,
                outcome,
            } => {
                bytes.push(0);
                push_u64(&mut bytes, *from_icount);
                push_u64(&mut bytes, *requested_icount);
                push_u64(&mut bytes, *reached_icount);
                match outcome {
                    AdvanceOutcome::ReachedHorizon => bytes.push(0),
                    AdvanceOutcome::Paused { at } => {
                        bytes.push(1);
                        push_u64(&mut bytes, at.retired);
                    }
                }
            }
            SimDoubleHostScheduleEvent::FrameDelivery {
                src_slot,
                sequence,
                delivery_icount,
                payload,
            } => {
                bytes.push(1);
                push_u32(&mut bytes, *src_slot);
                push_u32(&mut bytes, *sequence);
                push_u64(&mut bytes, *delivery_icount);
                push_bytes(&mut bytes, payload);
            }
            SimDoubleHostScheduleEvent::FrameEmission {
                dst_slot,
                sequence,
                delivery_icount,
                payload,
            } => {
                bytes.push(2);
                push_u32(&mut bytes, *dst_slot);
                push_u32(&mut bytes, *sequence);
                push_u64(&mut bytes, *delivery_icount);
                push_bytes(&mut bytes, payload);
            }
            SimDoubleHostScheduleEvent::IoCompletion {
                device,
                sequence,
                completion_icount,
                payload,
            } => {
                bytes.push(3);
                push_bytes(&mut bytes, device.as_bytes());
                push_u64(&mut bytes, *sequence);
                push_u64(&mut bytes, *completion_icount);
                push_bytes(&mut bytes, payload);
            }
            SimDoubleHostScheduleEvent::Snapshot {
                checkpoint_id,
                fingerprint,
                kind,
            } => {
                bytes.push(4);
                bytes.extend_from_slice(&checkpoint_id.bytes);
                bytes.extend_from_slice(&fingerprint.bytes);
                bytes.push(match kind {
                    CheckpointKind::Fat => 0,
                    CheckpointKind::Thin => 1,
                });
            }
        }
    }
    bytes
}

fn push_u32(bytes: &mut Vec<u8>, value: u32) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_u64(bytes: &mut Vec<u8>, value: u64) {
    bytes.extend_from_slice(&value.to_le_bytes());
}

fn push_bytes(bytes: &mut Vec<u8>, value: &[u8]) {
    push_u64(bytes, value.len() as u64);
    bytes.extend_from_slice(value);
}
