//! Borrowed continuation comparisons and typed artifact admission controls.

use super::*;
use crucible::{Icount, IrqVector, PreemptionKind, VcpuId};
use crucible_device::{
    BaseImage, BlockDevice, BlockLatency, FsTree, IoCore, NinepDevice, NinepLatency, Node,
};
use crucible_shmem::{FrameEntry, RegionConfig, RegionHeader, RegionLayout};

type NodeMutation = (&'static str, fn(&mut QemuNodeContinuationCheckpoint));

fn node_fixture(binding: ContentHash) -> QemuNodeContinuationCheckpoint {
    let inbound = FrameEntry::new(72, 31, 5, &[4, 5]).unwrap();
    inbound
        .record_delivery_attempt(72, crucible_shmem::MAX_FRAME_DELIVERY_ATTEMPTS)
        .unwrap();
    inbound.mark_delivery_retained().unwrap();
    let outbound = FrameEntry::new(68, 0, 6, &[6, 7]).unwrap();

    QemuNodeContinuationCheckpoint {
        execution_binding: binding,
        last_observed_time: VirtualTime { ticks: 70 },
        logical_time_calibration: crate::QemuLogicalTimeCalibration {
            logical_icount: 70,
            raw_icount: 1,
        },
        console_observation_boundary: VirtualTime { ticks: 69 },
        pending_preemption: Some(PreemptionDecision {
            node: NodeId {
                name: "vm-0".into(),
            },
            at: crucible::SimInstant { ticks: 71 },
            kind: PreemptionKind::InterruptAt {
                target_vcpu: VcpuId { index: 1 },
                irq: IrqVector { vector: 32 },
            },
        }),
        pending_network_outputs: vec![crate::QemuNodeEmittedFrame {
            source: NodeId {
                name: "vm-0".into(),
            },
            destination: NodeId {
                name: "vm-1".into(),
            },
            emit_icount: Icount { retired: 68 },
            sequence: 4,
            payload: vec![1, 2, 3],
        }],
        network_transport: QemuNetworkTransportCheckpoint {
            inbound: SpscRingSnapshot::from_live_frames(&[inbound]).unwrap(),
            outbound: SpscRingSnapshot::from_live_frames(&[outbound]).unwrap(),
            queue_capacity: 64,
            router_slot: 31,
            next_router_inbound_sequence: 6,
            next_host_outbound_sequence: 6,
            next_plugin_outbound_sequence: 7,
        },
        next_fault_command_sequence: 7,
        next_fault_event_sequence: 9,
    }
}

#[test]
fn comparison_authenticates_each_binding_before_ignoring_only_that_identity() {
    let left_binding = ContentHash::from_bytes(b"baseline capture");
    let right_binding = ContentHash::from_bytes(b"candidate capture");
    let left_bytes = node_fixture(left_binding).to_compact_binary().unwrap();
    let right_bytes = node_fixture(right_binding).to_compact_binary().unwrap();
    let left =
        QemuNodeContinuationCheckpoint::from_compact_binary(&left_bytes, left_binding).unwrap();
    let right =
        QemuNodeContinuationCheckpoint::from_compact_binary(&right_bytes, right_binding).unwrap();

    assert_ne!(left, right);
    assert!(left.same_scheduler_continuation(&right));
    assert!(right.same_scheduler_continuation(&left));
    assert!(
        QemuNodeContinuationCheckpoint::from_compact_binary(&right_bytes, left_binding).is_err()
    );

    let mut trailing = right_bytes;
    trailing.push(0);
    assert!(QemuNodeContinuationCheckpoint::from_compact_binary(&trailing, right_binding).is_err());
}

#[test]
fn comparison_preserves_every_scheduler_and_pending_work_field() {
    let reference = node_fixture(ContentHash::from_bytes(b"reference"));
    let changes: &[NodeMutation] = &[
        ("last observed time", |node| {
            node.last_observed_time.ticks += 1
        }),
        ("logical calibration", |node| {
            node.logical_time_calibration.logical_icount += 1
        }),
        ("raw calibration", |node| {
            node.logical_time_calibration.raw_icount += 1
        }),
        ("console boundary", |node| {
            node.console_observation_boundary.ticks += 1
        }),
        ("preemption presence", |node| node.pending_preemption = None),
        ("preemption node", |node| {
            node.pending_preemption
                .as_mut()
                .unwrap()
                .node
                .name
                .push('x')
        }),
        ("preemption time", |node| {
            node.pending_preemption.as_mut().unwrap().at.ticks += 1
        }),
        ("preemption kind", |node| {
            node.pending_preemption.as_mut().unwrap().kind = PreemptionKind::InterruptAt {
                target_vcpu: VcpuId { index: 2 },
                irq: IrqVector { vector: 33 },
            };
        }),
        ("pending output count", |node| {
            node.pending_network_outputs.clear()
        }),
        ("pending output source", |node| {
            node.pending_network_outputs[0].source.name.push('x')
        }),
        ("pending output destination", |node| {
            node.pending_network_outputs[0].destination.name.push('x')
        }),
        ("pending output time", |node| {
            node.pending_network_outputs[0].emit_icount.retired += 1
        }),
        ("pending output sequence", |node| {
            node.pending_network_outputs[0].sequence += 1
        }),
        ("pending output bytes", |node| {
            node.pending_network_outputs[0].payload[0] ^= 1
        }),
        ("fault command sequence", |node| {
            node.next_fault_command_sequence += 1
        }),
        ("fault event sequence", |node| {
            node.next_fault_event_sequence += 1
        }),
    ];

    for (label, change) in changes {
        let mut candidate = reference.clone();
        candidate.execution_binding = ContentHash::from_bytes(b"other capture");
        change(&mut candidate);
        assert!(
            !reference.same_scheduler_continuation(&candidate),
            "{label}"
        );
    }
}

#[test]
fn comparison_preserves_all_transport_metadata_and_frame_bytes() {
    let reference = node_fixture(ContentHash::from_bytes(b"reference"));
    let changes: &[NodeMutation] = &[
        ("inbound ring", |node| {
            node.network_transport.inbound.frames.clear()
        }),
        ("outbound ring", |node| {
            node.network_transport.outbound.frames.clear()
        }),
        ("queue capacity", |node| {
            node.network_transport.queue_capacity *= 2
        }),
        ("router slot", |node| {
            node.network_transport.router_slot += 1
        }),
        ("router inbound sequence", |node| {
            node.network_transport.next_router_inbound_sequence += 1
        }),
        ("host outbound sequence", |node| {
            node.network_transport.next_host_outbound_sequence += 1
        }),
        ("plugin outbound sequence", |node| {
            node.network_transport.next_plugin_outbound_sequence += 1
        }),
        ("inbound bytes", |node| {
            node.network_transport.inbound.frames[0].data[0] ^= 1
        }),
        ("inbound time", |node| {
            node.network_transport.inbound.frames[0].delivery_icount += 1
        }),
        ("inbound source", |node| {
            node.network_transport.inbound.frames[0].src_node += 1
        }),
        ("inbound sequence", |node| {
            node.network_transport.inbound.frames[0].seq += 1
        }),
        ("inbound valid length", |node| {
            node.network_transport.inbound.frames[0].len -= 1
        }),
        ("outbound bytes", |node| {
            node.network_transport.outbound.frames[0].data[0] ^= 1
        }),
        ("outbound time", |node| {
            node.network_transport.outbound.frames[0].delivery_icount += 1
        }),
        ("outbound source", |node| {
            node.network_transport.outbound.frames[0].src_node += 1
        }),
        ("outbound sequence", |node| {
            node.network_transport.outbound.frames[0].seq += 1
        }),
        ("outbound valid length", |node| {
            node.network_transport.outbound.frames[0].len -= 1
        }),
    ];

    for (label, change) in changes {
        let mut candidate = reference.clone();
        change(&mut candidate);
        assert!(
            !reference.same_scheduler_continuation(&candidate),
            "{label}"
        );
    }

    // Delivery state and attempts are private canonical ring fields. Replacing
    // the retained inbound frame with a real fresh frame changes those values.
    let fresh = FrameEntry::new(72, 31, 5, &[4, 5]).unwrap();
    let mut candidate = reference.clone();
    candidate.network_transport.inbound = SpscRingSnapshot::from_live_frames(&[fresh]).unwrap();
    assert!(!reference.same_scheduler_continuation(&candidate));
}

fn host_fixture(binding: ContentHash) -> QemuHostIoCheckpoint {
    let layout = RegionLayout::for_config(RegionConfig::new(1, 8))
        .unwrap_or_else(|error| panic!("valid test region: {error}"));
    let region_header = RegionHeader::new(layout).snapshot();
    let block = BlockDevice::new(
        IoCore::new(crucible_shmem::SLOT_BLK_IO as u32, 8, 8)
            .unwrap_or_else(|error| panic!("valid block core: {error}")),
        BaseImage::new(vec![0; 8_192]),
        BlockLatency::default(),
    );
    let tree = FsTree::try_new(Node::Directory {
        children: std::collections::BTreeMap::new(),
    })
    .unwrap_or_else(|error| panic!("valid 9p tree: {error}"));
    let ninep = NinepDevice::new(
        IoCore::new(crucible_shmem::SLOT_9P_IO as u32, 8, 8)
            .unwrap_or_else(|error| panic!("valid 9p core: {error}")),
        tree,
        NinepLatency::default(),
    );
    QemuHostIoCheckpoint {
        execution_binding: binding,
        block: Some(QemuLiveBlockIoServicerCheckpoint {
            world_binding: None,
            execution_binding: binding,
            storage_device: Some(ContentHash::from_bytes(b"storage identity")),
            region_header,
            vm_slot: 0,
            size_bytes: 8_192,
            device: block.snapshot(),
            requests: SpscRingSnapshot { frames: Vec::new() },
            responses: SpscRingSnapshot { frames: Vec::new() },
            frames_processed: 4,
            frames_delivered: 3,
        }),
        ninep: Some(QemuLive9pIoServicerCheckpoint {
            world_binding: None,
            execution_binding: binding,
            tree: ContentHash::from_bytes(b"tree identity"),
            region_header,
            vm_slot: 0,
            device: ninep.snapshot(),
            requests: SpscRingSnapshot { frames: Vec::new() },
            responses: SpscRingSnapshot { frames: Vec::new() },
            pending_fault_opportunities: Vec::new(),
            frames_processed: 6,
            frames_delivered: 5,
        }),
        #[cfg(target_os = "linux")]
        accelerator: None,
    }
}

fn rebound_host(reference: &QemuHostIoCheckpoint) -> QemuHostIoCheckpoint {
    let binding = ContentHash::from_bytes(b"different authenticated capture");
    let mut candidate = reference.clone();
    candidate.execution_binding = binding;
    candidate.block.as_mut().unwrap().execution_binding = binding;
    candidate.ninep.as_mut().unwrap().execution_binding = binding;
    candidate
}

#[test]
fn borrowed_host_comparison_preserves_old_rebinding_semantics() {
    let reference = host_fixture(ContentHash::from_bytes(b"reference"));
    let candidate = rebound_host(&reference);
    let encoded = candidate.to_canonical_bytes().unwrap();
    let decoded =
        QemuHostIoCheckpoint::from_canonical_bytes(&encoded, candidate.execution_binding).unwrap();

    assert!(reference.same_device_continuation(&decoded));
    assert!(decoded.same_device_continuation(&reference));
    let mut inconsistent = candidate;
    inconsistent.ninep.as_mut().unwrap().execution_binding = reference.execution_binding;
    assert!(!reference.same_device_continuation(&inconsistent));
    assert!(inconsistent.to_canonical_bytes().is_err());
    assert!(
        QemuHostIoCheckpoint::from_canonical_bytes(&encoded, reference.execution_binding).is_err()
    );
}

#[test]
fn borrowed_host_comparison_keeps_every_block_and_ninep_field() {
    type HostMutation = (&'static str, fn(&mut QemuHostIoCheckpoint));
    let reference = host_fixture(ContentHash::from_bytes(b"reference"));
    let changes: &[HostMutation] = &[
        ("block World ownership", |candidate| {
            candidate.block.as_mut().unwrap().world_binding = Some(world_binding());
        }),
        ("ninep World ownership", |candidate| {
            candidate.ninep.as_mut().unwrap().world_binding = Some(world_binding());
        }),
        ("ninep pending fault opportunity", |candidate| {
            let mut frame = Vec::new();
            frame.extend_from_slice(&19_u32.to_le_bytes());
            frame.push(100);
            frame.extend_from_slice(&u16::MAX.to_le_bytes());
            frame.extend_from_slice(&65536_u32.to_le_bytes());
            frame.extend_from_slice(&6_u16.to_le_bytes());
            frame.extend_from_slice(b"9P2000");
            let opportunity =
                crucible_device::NinepRequestOpportunity::from_frame(1, 0, frame).unwrap();
            candidate
                .ninep
                .as_mut()
                .unwrap()
                .pending_fault_opportunities
                .push((1, opportunity, false));
        }),
        ("block presence", |candidate| {
            candidate.block = None;
        }),
        ("ninep presence", |candidate| {
            candidate.ninep = None;
        }),
        ("block storage identity", |candidate| {
            candidate.block.as_mut().unwrap().storage_device = None;
        }),
        ("block region header", |candidate| {
            candidate.block.as_mut().unwrap().region_header =
                RegionHeader::new(RegionLayout::for_config(RegionConfig::new(2, 8)).unwrap())
                    .snapshot();
        }),
        ("block slot", |candidate| {
            candidate.block.as_mut().unwrap().vm_slot += 1;
        }),
        ("block size", |candidate| {
            candidate.block.as_mut().unwrap().size_bytes += 4096;
        }),
        ("block complete device", |candidate| {
            candidate.block.as_mut().unwrap().device.base_hash[0] ^= 1;
        }),
        ("block requests", |candidate| {
            candidate.block.as_mut().unwrap().requests =
                SpscRingSnapshot::from_live_frames(&[FrameEntry::new(1, 1, 1, &[2]).unwrap()])
                    .unwrap();
        }),
        ("block responses", |candidate| {
            candidate.block.as_mut().unwrap().responses =
                SpscRingSnapshot::from_live_frames(&[FrameEntry::new(1, 1, 1, &[2]).unwrap()])
                    .unwrap();
        }),
        ("block processed", |candidate| {
            candidate.block.as_mut().unwrap().frames_processed += 1;
        }),
        ("block delivered", |candidate| {
            candidate.block.as_mut().unwrap().frames_delivered += 1;
        }),
        ("ninep tree", |candidate| {
            candidate.ninep.as_mut().unwrap().tree = ContentHash::from_bytes(b"other tree");
        }),
        ("ninep region header", |candidate| {
            candidate.ninep.as_mut().unwrap().region_header =
                RegionHeader::new(RegionLayout::for_config(RegionConfig::new(2, 8)).unwrap())
                    .snapshot();
        }),
        ("ninep slot", |candidate| {
            candidate.ninep.as_mut().unwrap().vm_slot += 1;
        }),
        ("ninep complete device", |candidate| {
            candidate.ninep.as_mut().unwrap().device.session_epoch += 1;
        }),
        ("ninep requests", |candidate| {
            candidate.ninep.as_mut().unwrap().requests =
                SpscRingSnapshot::from_live_frames(&[FrameEntry::new(1, 1, 1, &[2]).unwrap()])
                    .unwrap();
        }),
        ("ninep responses", |candidate| {
            candidate.ninep.as_mut().unwrap().responses =
                SpscRingSnapshot::from_live_frames(&[FrameEntry::new(1, 1, 1, &[2]).unwrap()])
                    .unwrap();
        }),
        ("ninep processed", |candidate| {
            candidate.ninep.as_mut().unwrap().frames_processed += 1;
        }),
        ("ninep delivered", |candidate| {
            candidate.ninep.as_mut().unwrap().frames_delivered += 1;
        }),
    ];

    for (label, change) in changes {
        let mut candidate = rebound_host(&reference);
        change(&mut candidate);

        // This is the former public method's exact clone/rebind/Eq behavior.
        // The new implementation must agree without creating that clone.
        let mut rebound = candidate.clone();
        rebound.execution_binding = reference.execution_binding;
        if let Some(block) = &mut rebound.block {
            block.execution_binding = reference.execution_binding;
        }
        if let Some(ninep) = &mut rebound.ninep {
            ninep.execution_binding = reference.execution_binding;
        }
        assert_ne!(reference, rebound, "{label}");
        assert!(!reference.same_device_continuation(&candidate), "{label}");
    }
}

fn world_binding() -> crate::QemuWorldIoBinding {
    use crucible::{
        ContentAddressedBlobRef, NodeTemplate, ReadyPoint, VmArchitecture, WhiteBoxPolicy, World,
        WorldBlockLatency, WorldIoCoreConfig, WorldIoNode, WorldNode, WorldNodeDef,
    };

    let owner = NodeId { name: "vm".into() };
    let definitions = vec![
        WorldNodeDef::Vm(WorldNode {
            id: owner.clone(),
            arch: VmArchitecture::X86_64,
            memory_mib: NodeTemplate::DEFAULT_MEMORY_MIB,
            cmdline: String::new(),
            ready_point: ReadyPoint::FixedIcount {
                icount: Icount { retired: 0 },
            },
            white_box: WhiteBoxPolicy::Disabled,
            smp_vcpus: 1,
            kernel: None,
            root_image: None,
            initrd: None,
        }),
        WorldNodeDef::Io(WorldIoNode::block(
            NodeId {
                name: "disk".into(),
            },
            owner,
            WorldIoCoreConfig::new(),
            ContentAddressedBlobRef::from_hash(ContentHash::from_bytes(b"base image")),
            4096,
            WorldBlockLatency::new(0, 0, 0, 0, 0),
        )),
    ];
    let world = World::from_node_defs_and_links(definitions, Vec::new()).unwrap();
    crate::QemuWorldIoBinding::from_world(
        &world,
        &NodeId {
            name: "disk".into(),
        },
    )
    .unwrap()
}
