//! Canonical checkpoint codec and network-continuation tests.

use super::*;
use crucible::{Icount, IrqVector, PreemptionKind, VcpuId};
use crucible_device::{BaseImage, BlockDevice, BlockLatency, IoCore};
use crucible_shmem::{RegionConfig, RegionHeader, RegionLayout};

#[test]
fn host_io_checkpoint_codec_round_trips_device_free_state() {
    let binding = ContentHash::from_bytes(b"host-io-checkpoint-binding");
    let checkpoint = QemuHostIoCheckpoint::without_devices(binding);
    let bytes = checkpoint
        .to_canonical_bytes()
        .unwrap_or_else(|error| panic!("encode host I/O checkpoint: {error}"));
    assert_eq!(
        QemuHostIoCheckpoint::from_canonical_bytes(&bytes, binding)
            .unwrap_or_else(|error| panic!("decode host I/O checkpoint: {error}")),
        checkpoint
    );
    assert_eq!(
        QemuHostIoCheckpoint::from_canonical_bytes(
            &bytes,
            ContentHash::from_bytes(b"wrong binding")
        ),
        Err(QemuHostIoCheckpointCodecError::ExecutionBinding)
    );
    assert!(matches!(
        host_io_codec::encode_checkpoint(&checkpoint, 64),
        Err(QemuHostIoCheckpointCodecError::ResourceLimit {
            field: "host-I/O checkpoint",
            configured: 64,
            hard: 68_719_476_736,
            ..
        })
    ));
    let mut old_version = bytes;
    old_version[..b"crucible.qemu-host-io-checkpoint.v2\0".len()]
        .copy_from_slice(b"crucible.qemu-host-io-checkpoint.v1\0");
    assert_eq!(
        QemuHostIoCheckpoint::from_canonical_bytes(&old_version, binding),
        Err(QemuHostIoCheckpointCodecError::Version)
    );
}

#[test]
fn host_io_checkpoint_codec_round_trips_block_state() {
    let binding = ContentHash::from_bytes(b"host-io-block-binding");
    let layout = RegionLayout::for_config(RegionConfig::new(1, 8, 0))
        .unwrap_or_else(|error| panic!("valid test region: {error}"));
    let region_header = RegionHeader::new(layout).snapshot();
    let device = BlockDevice::new(
        IoCore::new(8, crucible_shmem::SLOT_BLK_IO as u32, 8, 8)
            .unwrap_or_else(|error| panic!("valid test core: {error}")),
        BaseImage::new(vec![0; 8_192]),
        BlockLatency::default(),
    );
    let checkpoint = QemuHostIoCheckpoint {
        execution_binding: binding,
        block: Some(QemuLiveBlockIoServicerCheckpoint {
            execution_binding: binding,
            storage_device: Some(ContentHash::from_bytes(b"storage identity")),
            region_header,
            vm_slot: 0,
            size_bytes: 8_192,
            device: device.snapshot(),
            requests: SpscRingSnapshot { frames: Vec::new() },
            responses: SpscRingSnapshot { frames: Vec::new() },
            frames_processed: 4,
            frames_delivered: 3,
        }),
        ninep: None,
        #[cfg(target_os = "linux")]
        accelerator: None,
    };
    let bytes = checkpoint
        .to_canonical_bytes()
        .unwrap_or_else(|error| panic!("encode block host I/O checkpoint: {error}"));
    assert_eq!(
        QemuHostIoCheckpoint::from_canonical_bytes(&bytes, binding)
            .unwrap_or_else(|error| panic!("decode block host I/O checkpoint: {error}")),
        checkpoint
    );
}

#[test]
fn node_continuation_codec_round_trips_complete_state() {
    let binding = ContentHash::from_bytes(b"node-continuation-binding");
    let retained_inbound = crucible_shmem::FrameEntry::new(72, 31, 5, &[4, 5])
        .unwrap_or_else(|error| panic!("inbound frame should encode: {error}"));
    retained_inbound
        .record_delivery_attempt(72, crucible_shmem::MAX_FRAME_DELIVERY_ATTEMPTS)
        .unwrap_or_else(|error| panic!("inbound attempt should encode: {error}"));
    retained_inbound
        .mark_delivery_retained()
        .unwrap_or_else(|error| panic!("inbound frame should retain: {error}"));
    let checkpoint = QemuNodeContinuationCheckpoint {
        execution_binding: binding,
        last_observed_time: VirtualTime { ticks: 70 },
        logical_time_calibration: crate::QemuLogicalTimeCalibration {
            logical_icount: 70,
            raw_icount: 65,
        },
        console_observation_boundary: VirtualTime { ticks: 69 },
        pending_preemption: Some(PreemptionDecision {
            node: NodeId {
                name: String::from("vm-0"),
            },
            at: Icount { retired: 71 },
            kind: PreemptionKind::InterruptAt {
                target_vcpu: VcpuId { index: 1 },
                irq: IrqVector { vector: 32 },
            },
        }),
        pending_network_outputs: vec![crate::QemuNodeEmittedFrame {
            source: NodeId {
                name: String::from("vm-0"),
            },
            destination: NodeId {
                name: String::from("vm-1"),
            },
            emit_icount: Icount { retired: 68 },
            sequence: 4,
            payload: vec![1, 2, 3],
        }],
        network_transport: QemuNetworkTransportCheckpoint {
            inbound: ring_snapshot(vec![retained_inbound]),
            outbound: ring_snapshot(vec![
                crucible_shmem::FrameEntry::new(68, 0, 6, &[6, 7])
                    .unwrap_or_else(|error| panic!("outbound frame should encode: {error}")),
            ]),
            queue_capacity: 64,
            router_slot: 31,
            next_router_inbound_sequence: 6,
            next_host_outbound_sequence: 6,
            next_plugin_outbound_sequence: 7,
        },
        next_fault_command_sequence: 7,
        next_fault_event_sequence: 9,
    };
    let bytes = checkpoint
        .to_compact_binary()
        .unwrap_or_else(|error| panic!("node continuation should encode: {error}"));
    let restored = QemuNodeContinuationCheckpoint::from_compact_binary(&bytes, binding)
        .unwrap_or_else(|error| panic!("node continuation should decode: {error}"));
    assert_eq!(restored, checkpoint);
    assert_eq!(
        restored.network_transport.inbound.frames[0].delivery_state(),
        Ok(crucible_shmem::FrameDeliveryState::Retained)
    );
    assert_eq!(
        restored
            .to_compact_binary()
            .unwrap_or_else(|error| panic!("restored continuation should encode: {error}")),
        bytes
    );
}

#[test]
fn network_transport_binds_host_and_plugin_cursors_around_live_frames() {
    let mut transport = QemuNetworkTransportCheckpoint {
        inbound: SpscRingSnapshot { frames: Vec::new() },
        outbound: ring_snapshot(vec![
            crucible_shmem::FrameEntry::new(68, 0, 9, &[1])
                .unwrap_or_else(|error| panic!("first frame should encode: {error}")),
            crucible_shmem::FrameEntry::new(69, 0, 10, &[2])
                .unwrap_or_else(|error| panic!("second frame should encode: {error}")),
        ]),
        queue_capacity: 64,
        router_slot: 31,
        next_router_inbound_sequence: 0,
        next_host_outbound_sequence: 0,
        next_plugin_outbound_sequence: 0,
    };

    transport
        .bind_outbound_sequence(9)
        .unwrap_or_else(|error| panic!("contiguous transport should bind: {error}"));

    assert_eq!(transport.next_host_outbound_sequence, 9);
    assert_eq!(transport.next_plugin_outbound_sequence(), 11);
    assert_eq!(transport.validate_outbound_sequences(), Ok(()));
}

#[test]
fn network_transport_rejects_a_gap_or_inconsistent_plugin_cursor() {
    let frame = crucible_shmem::FrameEntry::new(68, 0, 10, &[1])
        .unwrap_or_else(|error| panic!("frame should encode: {error}"));
    let mut gap = QemuNetworkTransportCheckpoint {
        inbound: SpscRingSnapshot { frames: Vec::new() },
        outbound: ring_snapshot(vec![frame]),
        queue_capacity: 64,
        router_slot: 31,
        next_router_inbound_sequence: 0,
        next_host_outbound_sequence: 0,
        next_plugin_outbound_sequence: 0,
    };
    assert_eq!(
        gap.bind_outbound_sequence(9),
        Err(QemuNodeCheckpointCodecError::NetworkTransport)
    );

    gap.next_host_outbound_sequence = 10;
    gap.next_plugin_outbound_sequence = 12;
    assert_eq!(
        gap.validate_outbound_sequences(),
        Err(QemuNodeCheckpointCodecError::NetworkTransport)
    );
}

#[test]
fn network_transport_rejects_noncanonical_retained_state() {
    let retained_non_head = crucible_shmem::FrameEntry::new(69, 31, 1, &[2])
        .unwrap_or_else(|error| panic!("retained frame should encode: {error}"));
    retained_non_head
        .record_delivery_attempt(69, crucible_shmem::MAX_FRAME_DELIVERY_ATTEMPTS)
        .unwrap_or_else(|error| panic!("retained attempt should encode: {error}"));
    retained_non_head
        .mark_delivery_retained()
        .unwrap_or_else(|error| panic!("frame should retain: {error}"));
    let inbound = QemuNetworkTransportCheckpoint {
        inbound: ring_snapshot(vec![
            crucible_shmem::FrameEntry::new(68, 31, 0, &[1])
                .unwrap_or_else(|error| panic!("head frame should encode: {error}")),
            retained_non_head,
        ]),
        outbound: SpscRingSnapshot { frames: Vec::new() },
        queue_capacity: 64,
        router_slot: 31,
        next_router_inbound_sequence: 2,
        next_host_outbound_sequence: 0,
        next_plugin_outbound_sequence: 0,
    };
    assert_eq!(
        inbound.retained_inbound_head(),
        Err(QemuNodeCheckpointCodecError::NetworkTransport)
    );

    let retained_outbound = crucible_shmem::FrameEntry::new(68, 0, 0, &[1])
        .unwrap_or_else(|error| panic!("outbound frame should encode: {error}"));
    retained_outbound
        .record_delivery_attempt(68, crucible_shmem::MAX_FRAME_DELIVERY_ATTEMPTS)
        .unwrap_or_else(|error| panic!("retained attempt should encode: {error}"));
    retained_outbound
        .mark_delivery_retained()
        .unwrap_or_else(|error| panic!("frame should retain: {error}"));
    let outbound = QemuNetworkTransportCheckpoint {
        inbound: SpscRingSnapshot { frames: Vec::new() },
        outbound: ring_snapshot(vec![retained_outbound]),
        queue_capacity: 64,
        router_slot: 31,
        next_router_inbound_sequence: 0,
        next_host_outbound_sequence: 0,
        next_plugin_outbound_sequence: 1,
    };
    assert_eq!(
        outbound.validate_outbound_sequences(),
        Err(QemuNodeCheckpointCodecError::NetworkTransport)
    );
}

#[test]
fn network_transport_authenticates_inbound_producer_provenance() {
    let transport =
        |frames: Vec<crucible_shmem::FrameEntry>, next_sequence| QemuNetworkTransportCheckpoint {
            inbound: ring_snapshot(frames),
            outbound: SpscRingSnapshot { frames: Vec::new() },
            queue_capacity: 64,
            router_slot: 31,
            next_router_inbound_sequence: next_sequence,
            next_host_outbound_sequence: 0,
            next_plugin_outbound_sequence: 0,
        };
    let frame = |src_node, sequence| {
        crucible_shmem::FrameEntry::new(72 + u64::from(sequence), src_node, sequence, &[1])
            .unwrap_or_else(|error| panic!("inbound frame should encode: {error}"))
    };

    assert_eq!(
        transport(vec![frame(31, 5), frame(31, 6)], 7).validate(),
        Ok(())
    );
    for invalid in [
        transport(vec![frame(30, 5)], 6),
        transport(vec![frame(31, 5), frame(31, 7)], 8),
        transport(vec![frame(31, 5)], 12),
    ] {
        assert_eq!(
            invalid.validate(),
            Err(QemuNodeCheckpointCodecError::NetworkTransport)
        );
    }
    let mut invalid_capacity = transport(vec![frame(31, 5)], 6);
    invalid_capacity.queue_capacity = 3;
    assert_eq!(
        invalid_capacity.validate(),
        Err(QemuNodeCheckpointCodecError::NetworkTransport)
    );
}

#[test]
fn network_transport_rejects_impossible_retained_attempt_state() {
    let pending = crucible_shmem::FrameEntry::new(72, 31, 0, &[1])
        .unwrap_or_else(|error| panic!("pending frame should encode: {error}"));
    pending
        .record_delivery_attempt(72, crucible_shmem::MAX_FRAME_DELIVERY_ATTEMPTS)
        .unwrap_or_else(|error| panic!("test attempt should record: {error}"));
    let retained = crucible_shmem::FrameEntry::new(72, 31, 0, &[1])
        .unwrap_or_else(|error| panic!("retained frame should encode: {error}"));
    retained
        .mark_delivery_retained()
        .unwrap_or_else(|error| panic!("test retained state should mark: {error}"));

    for frame in [pending, retained] {
        let attempts = frame.delivery_attempts();
        let state = if attempts == 0 {
            crucible_shmem::FRAME_DELIVERY_RETAINED
        } else {
            crucible_shmem::FRAME_DELIVERY_PENDING
        };
        assert_eq!(
            SpscRingSnapshot::from_live_frames(&[frame]),
            Err(crucible_shmem::SpscRingError::InvalidFrameDeliveryAttempts { state, attempts })
        );
    }
}

fn ring_snapshot(frames: Vec<crucible_shmem::FrameEntry>) -> SpscRingSnapshot {
    SpscRingSnapshot::from_live_frames(&frames)
        .unwrap_or_else(|error| panic!("test frames should snapshot: {error}"))
}

#[test]
fn node_continuation_codec_rejects_wrong_binding_and_trailing_bytes() {
    let binding = ContentHash::from_bytes(b"node-continuation-binding");
    let checkpoint = QemuNodeContinuationCheckpoint {
        execution_binding: binding,
        last_observed_time: VirtualTime { ticks: 1 },
        logical_time_calibration: crate::QemuLogicalTimeCalibration {
            logical_icount: 1,
            raw_icount: 1,
        },
        console_observation_boundary: VirtualTime { ticks: 1 },
        pending_preemption: None,
        pending_network_outputs: Vec::new(),
        network_transport: QemuNetworkTransportCheckpoint::empty(),
        next_fault_command_sequence: 2,
        next_fault_event_sequence: 1,
    };
    let mut bytes = checkpoint
        .to_compact_binary()
        .unwrap_or_else(|error| panic!("node continuation should encode: {error}"));
    assert_eq!(
        QemuNodeContinuationCheckpoint::from_compact_binary(
            &bytes,
            ContentHash::from_bytes(b"wrong")
        ),
        Err(QemuNodeCheckpointCodecError::ExecutionBinding)
    );
    let mut old_version = bytes.clone();
    old_version[..b"crucible.qemu-node-continuation.v7\0".len()]
        .copy_from_slice(b"crucible.qemu-node-continuation.v6\0");
    assert_eq!(
        QemuNodeContinuationCheckpoint::from_compact_binary(&old_version, binding),
        Err(QemuNodeCheckpointCodecError::Unsupported)
    );
    bytes.push(0);
    assert_eq!(
        QemuNodeContinuationCheckpoint::from_compact_binary(&bytes, binding),
        Err(QemuNodeCheckpointCodecError::Trailing)
    );
}

#[test]
fn node_continuation_round_trips_large_and_full_capacity_compact_rings() {
    const FRAMES_ABOVE_OLD_LIMIT: usize = 16_384;
    const PAYLOAD_ABOVE_OLD_LIMIT: usize = 4_066;
    const MAX_QUEUE_FRAMES: usize = 1_048_576;

    {
        let checkpoint =
            node_checkpoint_with_inbound_ring(FRAMES_ABOVE_OLD_LIMIT, PAYLOAD_ABOVE_OLD_LIMIT);
        let bytes = checkpoint
            .to_compact_binary()
            .unwrap_or_else(|error| panic!("large ring should encode: {error}"));
        assert!(
            bytes.len() > 64 * 1024 * 1024,
            "test must cross the obsolete 64 MiB decoder ceiling"
        );
        let restored = QemuNodeContinuationCheckpoint::from_compact_binary(
            &bytes,
            checkpoint.execution_binding,
        )
        .unwrap_or_else(|error| panic!("large ring should decode: {error}"));
        assert_eq!(restored, checkpoint);
    }

    {
        let checkpoint = node_checkpoint_with_inbound_ring(MAX_QUEUE_FRAMES, 0);
        let bytes = checkpoint
            .to_compact_binary()
            .unwrap_or_else(|error| panic!("full-capacity ring should encode: {error}"));
        let restored = QemuNodeContinuationCheckpoint::from_compact_binary(
            &bytes,
            checkpoint.execution_binding,
        )
        .unwrap_or_else(|error| panic!("full-capacity ring should decode: {error}"));
        assert_eq!(
            restored.network_transport.inbound.frames.len(),
            MAX_QUEUE_FRAMES
        );
        assert_eq!(restored, checkpoint);
    }
}

#[test]
fn node_continuation_decode_reports_typed_collection_resource_limit() {
    const MAGIC: &[u8] = b"crucible.qemu-node-continuation.v7\0";
    let checkpoint = node_checkpoint_with_inbound_ring(1, 0);
    let mut bytes = checkpoint
        .to_compact_binary()
        .unwrap_or_else(|error| panic!("fixture should encode: {error}"));
    let pending_count_offset = MAGIC.len() + 32 + 4 * 8 + 1;
    let requested = MAX_NODE_CONTINUATION_FRAMES as u64 + 1;
    bytes[pending_count_offset..pending_count_offset + 8].copy_from_slice(&requested.to_le_bytes());

    assert_eq!(
        QemuNodeContinuationCheckpoint::from_compact_binary(&bytes, checkpoint.execution_binding,),
        Err(QemuNodeCheckpointCodecError::ResourceLimit {
            field: "pending frame count",
            current: 0,
            requested,
            configured: MAX_NODE_CONTINUATION_FRAMES as u64,
            hard: MAX_NODE_CONTINUATION_FRAMES as u64,
        })
    );
}

fn node_checkpoint_with_inbound_ring(
    frame_count: usize,
    payload_len: usize,
) -> QemuNodeContinuationCheckpoint {
    let binding = ContentHash::from_bytes(b"large-node-continuation-binding");
    QemuNodeContinuationCheckpoint {
        execution_binding: binding,
        last_observed_time: VirtualTime { ticks: 1 },
        logical_time_calibration: crate::QemuLogicalTimeCalibration {
            logical_icount: 1,
            raw_icount: 1,
        },
        console_observation_boundary: VirtualTime { ticks: 1 },
        pending_preemption: None,
        pending_network_outputs: Vec::new(),
        network_transport: QemuNetworkTransportCheckpoint {
            inbound: synthetic_compact_ring(frame_count, payload_len, 31),
            outbound: SpscRingSnapshot { frames: Vec::new() },
            queue_capacity: frame_count as u32,
            router_slot: 31,
            next_router_inbound_sequence: frame_count as u64,
            next_host_outbound_sequence: 0,
            next_plugin_outbound_sequence: 0,
        },
        next_fault_command_sequence: 2,
        next_fault_event_sequence: 1,
    }
}

pub(crate) fn synthetic_compact_ring(
    frame_count: usize,
    payload_len: usize,
    source: u32,
) -> SpscRingSnapshot {
    const METADATA_BYTES: usize = 8 + 4 + 4 + 2 + 1 + 4 + 8;
    let encoded_len = 8 + frame_count * (METADATA_BYTES + payload_len);
    let mut bytes = Vec::with_capacity(encoded_len);
    bytes.extend_from_slice(&(frame_count as u64).to_le_bytes());
    let payload = vec![0x5a; payload_len];
    for sequence in 0..frame_count {
        bytes.extend_from_slice(&(sequence as u64).to_le_bytes());
        bytes.extend_from_slice(&source.to_le_bytes());
        bytes.extend_from_slice(&(sequence as u32).to_le_bytes());
        bytes.extend_from_slice(&(payload_len as u16).to_le_bytes());
        bytes.push(crucible_shmem::FRAME_DELIVERY_PENDING);
        bytes.extend_from_slice(&0_u32.to_le_bytes());
        bytes.extend_from_slice(&0_u64.to_le_bytes());
        bytes.extend_from_slice(&payload);
    }
    SpscRingSnapshot::from_canonical_bytes(&bytes, frame_count)
        .unwrap_or_else(|error| panic!("synthetic compact ring should decode: {error}"))
}
