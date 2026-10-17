//! Physical reply-ring identity remains separate from canonical queue selection.

use crate::{
    BaseImage, BlockDevice, BlockLatency, BlockRequest, DeviceError, FsTree, IoCore, NinepDevice,
    NinepLatency, Node, SelectedDeliveryOutcome,
};
use crucible_shmem::{
    DirectedRing, FrameEntry, MappedDirectedRingMut, NodeSlot, RegionAllocation, RegionConfig,
    RingHeader, SLOT_9P_IO, SLOT_BLK_IO,
};

fn ok<T, E: std::fmt::Debug>(value: Result<T, E>) -> T {
    value.unwrap_or_else(|error| panic!("mapped transport fixture: {error:?}"))
}

fn descriptor(source: usize) -> DirectedRing {
    let allocation = ok(RegionAllocation::new_model(RegionConfig::new(1, 4)));
    *allocation
        .rings()
        .iter()
        .find(|ring| ring.src_slot == source as u32 && ring.dst_slot == 0)
        .unwrap_or_else(|| panic!("original reserved response descriptor"))
}

fn mapped<'a>(
    descriptor: DirectedRing,
    header: &'a RingHeader,
    entries: &'a mut [FrameEntry],
) -> MappedDirectedRingMut<'a> {
    MappedDirectedRingMut {
        descriptor,
        header,
        entries,
    }
}

fn block() -> BlockDevice {
    let mut device = BlockDevice::new(
        ok(IoCore::new(0, 4, 4)),
        BaseImage::new(vec![0xa5; 4096]),
        BlockLatency::new(0, 0, 0, 0, 0),
    );
    ok(device.submit(9, &BlockRequest::read(7, 0, 8)));
    ok(device.submit(9, &BlockRequest::read(8, 8, 8)));
    device
}

fn ninep() -> NinepDevice {
    let tree = ok(FsTree::try_new(Node::Directory {
        children: Default::default(),
    }));
    let mut device = NinepDevice::new(ok(IoCore::new(1, 4, 4)), tree, NinepLatency::new(0, 0, 0));
    let version = b"9P2000.L";
    let mut wire = Vec::new();
    wire.extend_from_slice(&(7_u32 + 4 + 2 + version.len() as u32).to_le_bytes());
    wire.push(crate::ninep::codec::TVERSION);
    wire.extend_from_slice(&u16::MAX.to_le_bytes());
    wire.extend_from_slice(&4096_u32.to_le_bytes());
    wire.extend_from_slice(&(version.len() as u16).to_le_bytes());
    wire.extend_from_slice(version);
    ok(device.submit(9, &wire));
    device
}

#[test]
fn ordinary_block_transport_refuses_foreign_ring_without_mutation() {
    let mut device = block();
    let before = device.snapshot();
    let ring = RingHeader::new();
    let mut entries = vec![FrameEntry::default(); 4];
    let consumer = NodeSlot::new(crucible_shmem::KIND_VM);

    assert!(matches!(
        device.advance_to_mapped_ring(
            9,
            mapped(descriptor(SLOT_9P_IO), &ring, &mut entries),
            &consumer
        ),
        Err(DeviceError::ShmemResponseSource { .. })
    ));
    assert_eq!(device.snapshot(), before);
    assert!(ok(ring.peek(&entries)).is_none());

    assert_eq!(
        ok(device.advance_to_mapped_ring(
            9,
            mapped(descriptor(SLOT_BLK_IO), &ring, &mut entries),
            &consumer
        ))
        .delivered,
        2
    );
    for expected in &before.core.inflight {
        let frame = ok(ring.dequeue(&entries)).unwrap_or_else(|| panic!("published response"));
        assert_eq!(frame.src_node, SLOT_BLK_IO as u32);
        assert_eq!(frame.seq, expected.key.seq);
        assert_eq!(ok(frame.payload()), expected.response.payload);
    }
    assert_eq!(device.core().snapshot().src_node, before.core.src_node);
}

#[test]
fn ordinary_ninep_transport_preserves_world_key_and_refuses_foreign_ring() {
    let mut device = ninep();
    let before = device.core().snapshot();
    let head = &before.inflight[0];
    let consumer = NodeSlot::new(crucible_shmem::KIND_VM);
    let ring = RingHeader::new();
    let mut entries = vec![FrameEntry::default(); 4];

    let failure = device
        .advance_to_mapped_ring_with_commit_status(
            9,
            mapped(descriptor(SLOT_BLK_IO), &ring, &mut entries),
            &consumer,
        )
        .err()
        .unwrap_or_else(|| panic!("foreign 9p ring accepted"));
    assert_eq!(failure.published, 0);
    assert_eq!(device.core().snapshot(), before);
    assert!(ok(ring.peek(&entries)).is_none());

    assert_eq!(
        ok(device.advance_to_mapped_ring_with_commit_status(
            9,
            mapped(descriptor(SLOT_9P_IO), &ring, &mut entries),
            &consumer
        ))
        .delivered,
        1
    );
    let frame = ok(ring.dequeue(&entries)).unwrap_or_else(|| panic!("published 9p response"));
    assert_eq!(frame.src_node, SLOT_9P_IO as u32);
    assert_eq!(frame.delivery_icount, head.key.delivery_icount);
    assert_eq!(frame.seq, head.key.seq);
    assert_eq!(ok(frame.payload()), head.response.payload);
    assert_eq!(device.core().snapshot().src_node, before.src_node);
}

#[test]
fn raw_ring_publication_keeps_original_model_source() {
    let mut device = block();
    let before = device.core().snapshot();
    let ring = RingHeader::new();
    let mut entries = vec![FrameEntry::default(); 4];
    let head = &before.inflight[0];

    assert_eq!(
        ok(device.deliver_selected_to_shmem(
            9,
            head.key,
            &head.response.payload,
            &ring,
            &mut entries
        )),
        SelectedDeliveryOutcome::Published
    );
    let frame = ok(ring.dequeue(&entries)).unwrap_or_else(|| panic!("original generic response"));
    assert_eq!(frame.src_node, before.src_node);
}
