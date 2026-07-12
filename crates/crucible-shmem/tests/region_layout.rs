//! Checks the shared-memory region header, geometry, and slot allocator.

#![forbid(unsafe_code)]

use crucible_shmem::{
    ABI_VERSION, COVERAGE_ENTRY_ALIGN, COVERAGE_ENTRY_BLOCK_LEN_OFFSET,
    COVERAGE_ENTRY_CURRENT_ICOUNT_OFFSET, COVERAGE_ENTRY_GUEST_PC_OFFSET,
    COVERAGE_ENTRY_MAP_INDEX_OFFSET, COVERAGE_ENTRY_RESERVED_OFFSET, COVERAGE_ENTRY_SIZE,
    COVERAGE_ENTRY_VCPU_INDEX_OFFSET, COVERAGE_QUEUE_CAPACITY, DEFAULT_QUEUE_CAPACITY,
    FINGERPRINT_SAMPLE_SLOT_ALIGN, FINGERPRINT_SAMPLE_SLOT_SIZE, FRAME_ENTRY_ALIGN,
    FRAME_ENTRY_DATA_OFFSET, FRAME_ENTRY_DELIVERY_ICOUNT_OFFSET,
    FRAME_ENTRY_LEN_OFFSET, FRAME_ENTRY_PAD_OFFSET, FRAME_ENTRY_SEQ_OFFSET, FRAME_ENTRY_SIZE,
    FRAME_ENTRY_SRC_NODE_OFFSET, KIND_9P, KIND_BLK, KIND_NET, LAYOUT_TARGET_SUPPORTED,
    LAYOUT_TARGET_TRIPLE, MAX_NODES, MAX_VM_NODES, NODE_SLOT_ALIGN,
    NODE_SLOT_CURRENT_ICOUNT_OFFSET, NODE_SLOT_CURRENT_NS_OFFSET,
    NODE_SLOT_DEVICE_IO_ACTIVE_OFFSET, NODE_SLOT_IDLE_WAKE_ICOUNT_OFFSET, NODE_SLOT_KIND_OFFSET,
    NODE_SLOT_MAX_ADVANCE_ICOUNT_OFFSET, NODE_SLOT_PAD0_OFFSET, NODE_SLOT_PUBLISH_GEN_OFFSET,
    NODE_SLOT_RESERVED_OFFSET, NODE_SLOT_SIZE, NODE_SLOT_STATUS_OFFSET,
    NODE_SLOT_WAKE_SIGNAL_OFFSET, REGION_HEADER_ABI_VERSION_OFFSET, REGION_HEADER_ALIGN,
    REGION_HEADER_ENTRY_STRIDE_OFFSET, REGION_HEADER_ICOUNT_SHIFT_OFFSET,
    REGION_HEADER_MAGIC_OFFSET, REGION_HEADER_NODE_COUNT_OFFSET,
    REGION_HEADER_PAUSE_REQUESTED_OFFSET, REGION_HEADER_QUEUE_CAPACITY_OFFSET,
    REGION_HEADER_REGION_SIZE_OFFSET, REGION_HEADER_RESERVED_OFFSET,
    REGION_HEADER_RING_COUNT_OFFSET, REGION_HEADER_RING_DATA_OFF_OFFSET,
    REGION_HEADER_RING_HDR_OFF_OFFSET, REGION_HEADER_SHUTDOWN_REQUESTED_OFFSET, REGION_HEADER_SIZE,
    REGION_MAGIC, RESERVED_SLOTS, RING_HEADER_ALIGN, RING_HEADER_PAD_READ_OFFSET,
    RING_HEADER_PAD_WRITE_OFFSET, RING_HEADER_READ_IDX_OFFSET, RING_HEADER_SIZE,
    RING_HEADER_WRITE_IDX_OFFSET, RegionAllocation, RegionConfig, RegionHeader,
    RegionHeaderSnapshot, RegionLayout, RegionLayoutError, ReservedExecutorSlot, SLOT_9P_IO,
    SLOT_BLK_IO, SLOT_NET_ROUTER, validate_layout_target,
};

#[cfg(all(
    target_arch = "x86_64",
    target_abi = "",
    target_endian = "little",
    target_env = "gnu",
    target_os = "linux",
    target_pointer_width = "64"
))]
use crucible_shmem::{DirectedRing, KIND_VM, STATUS_DONE, STATUS_IDLE};

#[test]
fn region_header_layout_matches_wire_contract() {
    assert_eq!(REGION_HEADER_SIZE, 256);
    assert_eq!(REGION_HEADER_ALIGN, 128);
    assert_eq!(LAYOUT_TARGET_TRIPLE, "x86_64-unknown-linux-gnu");
    assert_eq!(REGION_HEADER_MAGIC_OFFSET, 0);
    assert_eq!(REGION_HEADER_ABI_VERSION_OFFSET, 8);
    assert_eq!(REGION_HEADER_NODE_COUNT_OFFSET, 12);
    assert_eq!(REGION_HEADER_QUEUE_CAPACITY_OFFSET, 16);
    assert_eq!(REGION_HEADER_RING_COUNT_OFFSET, 20);
    assert_eq!(REGION_HEADER_RING_HDR_OFF_OFFSET, 24);
    assert_eq!(REGION_HEADER_RING_DATA_OFF_OFFSET, 32);
    assert_eq!(REGION_HEADER_ENTRY_STRIDE_OFFSET, 40);
    assert_eq!(REGION_HEADER_REGION_SIZE_OFFSET, 48);
    assert_eq!(REGION_HEADER_ICOUNT_SHIFT_OFFSET, 56);
    assert_eq!(REGION_HEADER_PAUSE_REQUESTED_OFFSET, 60);
    assert_eq!(REGION_HEADER_SHUTDOWN_REQUESTED_OFFSET, 61);
    assert_eq!(REGION_HEADER_RESERVED_OFFSET, 62);

    assert_eq!(MAX_NODES, 32);
    assert_eq!(RESERVED_SLOTS, 3);
    assert_eq!(MAX_VM_NODES, 29);
    assert_eq!(SLOT_NET_ROUTER, 31);
    assert_eq!(SLOT_BLK_IO, 30);
    assert_eq!(SLOT_9P_IO, 29);
    assert_eq!(NODE_SLOT_SIZE, 128);
    assert_eq!(NODE_SLOT_ALIGN, 128);
    assert_eq!(NODE_SLOT_CURRENT_ICOUNT_OFFSET, 0);
    assert_eq!(NODE_SLOT_CURRENT_NS_OFFSET, 8);
    assert_eq!(NODE_SLOT_IDLE_WAKE_ICOUNT_OFFSET, 24);
    assert_eq!(NODE_SLOT_MAX_ADVANCE_ICOUNT_OFFSET, 16);
    assert_eq!(NODE_SLOT_WAKE_SIGNAL_OFFSET, 32);
    assert_eq!(NODE_SLOT_STATUS_OFFSET, 36);
    assert_eq!(NODE_SLOT_KIND_OFFSET, 37);
    assert_eq!(NODE_SLOT_DEVICE_IO_ACTIVE_OFFSET, 38);
    assert_eq!(NODE_SLOT_PAD0_OFFSET, 39);
    assert_eq!(NODE_SLOT_PUBLISH_GEN_OFFSET, 40);
    assert_eq!(NODE_SLOT_RESERVED_OFFSET, 44);
    assert_eq!(FRAME_ENTRY_DELIVERY_ICOUNT_OFFSET, 0);
    assert_eq!(FRAME_ENTRY_SRC_NODE_OFFSET, 8);
    assert_eq!(FRAME_ENTRY_SEQ_OFFSET, 12);
    assert_eq!(FRAME_ENTRY_LEN_OFFSET, 16);
    assert_eq!(FRAME_ENTRY_PAD_OFFSET, 18);
    assert_eq!(FRAME_ENTRY_DATA_OFFSET, 24);
    assert_eq!(FRAME_ENTRY_SIZE, 24 + 4608);
    assert_eq!(FRAME_ENTRY_ALIGN, 8);
    assert_eq!(RING_HEADER_READ_IDX_OFFSET, 0);
    assert_eq!(RING_HEADER_PAD_READ_OFFSET, 8);
    assert_eq!(RING_HEADER_WRITE_IDX_OFFSET, 64);
    assert_eq!(RING_HEADER_PAD_WRITE_OFFSET, 72);
    assert_eq!(RING_HEADER_SIZE, 128);
    assert_eq!(RING_HEADER_ALIGN, 128);
    assert_eq!(COVERAGE_QUEUE_CAPACITY, 65_536);
    assert_eq!(COVERAGE_ENTRY_CURRENT_ICOUNT_OFFSET, 0);
    assert_eq!(COVERAGE_ENTRY_GUEST_PC_OFFSET, 8);
    assert_eq!(COVERAGE_ENTRY_MAP_INDEX_OFFSET, 16);
    assert_eq!(COVERAGE_ENTRY_VCPU_INDEX_OFFSET, 24);
    assert_eq!(COVERAGE_ENTRY_BLOCK_LEN_OFFSET, 28);
    assert_eq!(COVERAGE_ENTRY_RESERVED_OFFSET, 32);
    assert_eq!(COVERAGE_ENTRY_SIZE, 64);
    assert_eq!(COVERAGE_ENTRY_ALIGN, 64);
}

#[test]
fn region_layout_computes_offsets_and_directed_rings() {
    let layout = layout(RegionConfig::new(2, DEFAULT_QUEUE_CAPACITY, 3));

    assert_eq!(layout.vm_node_count, 2);
    assert_eq!(layout.node_count, MAX_NODES as u32);
    assert_eq!(layout.queue_capacity, DEFAULT_QUEUE_CAPACITY);
    assert_eq!(layout.ring_count, 2 * RESERVED_SLOTS as u32 * 2);
    assert_eq!(layout.node_slots_off, REGION_HEADER_SIZE as u64);
    assert_eq!(
        layout.ring_hdr_off,
        (REGION_HEADER_SIZE + MAX_NODES * NODE_SLOT_SIZE) as u64
    );
    assert_eq!(
        layout.ring_data_off,
        layout.ring_hdr_off + u64::from(layout.ring_count) * RING_HEADER_SIZE as u64
    );
    assert_eq!(layout.entry_stride, FRAME_ENTRY_SIZE as u64);
    let frame_data_end =
        layout.ring_data_off + layout.frame_entry_count() * FRAME_ENTRY_SIZE as u64;
    let expected_coverage_ring_hdr_off =
        frame_data_end.div_ceil(RING_HEADER_ALIGN as u64) * RING_HEADER_ALIGN as u64;
    assert_eq!(layout.coverage_ring_count, layout.vm_node_count);
    assert_eq!(layout.coverage_queue_capacity, COVERAGE_QUEUE_CAPACITY);
    assert_eq!(layout.coverage_ring_hdr_off, expected_coverage_ring_hdr_off);
    assert_eq!(
        layout.coverage_ring_data_off,
        layout.coverage_ring_hdr_off
            + u64::from(layout.coverage_ring_count) * RING_HEADER_SIZE as u64
    );
    assert_eq!(layout.coverage_entry_stride, COVERAGE_ENTRY_SIZE as u64);
    let coverage_data_end =
        layout.coverage_ring_data_off + layout.coverage_entry_count() * COVERAGE_ENTRY_SIZE as u64;
    assert_eq!(layout.fingerprint_sample_count, layout.vm_node_count);
    assert_eq!(
        layout.fingerprint_sample_stride,
        FINGERPRINT_SAMPLE_SLOT_SIZE as u64
    );
    assert_eq!(
        layout.fingerprint_sample_off,
        coverage_data_end.div_ceil(FINGERPRINT_SAMPLE_SLOT_ALIGN as u64)
            * FINGERPRINT_SAMPLE_SLOT_ALIGN as u64
    );
    assert_eq!(
        layout.region_size,
        layout.fingerprint_sample_off
            + u64::from(layout.fingerprint_sample_count) * layout.fingerprint_sample_stride
    );
    assert_eq!(
        layout.frame_entry_count(),
        u64::from(layout.ring_count) * u64::from(DEFAULT_QUEUE_CAPACITY)
    );
}

#[test]
fn region_header_records_computed_geometry() {
    let layout = layout(RegionConfig::new(3, 16, 7));
    let header = RegionHeader::new(layout);

    assert_eq!(
        header.snapshot(),
        RegionHeaderSnapshot {
            magic: REGION_MAGIC,
            abi_version: ABI_VERSION,
            node_count: MAX_NODES as u32,
            queue_capacity: 16,
            ring_count: 3 * RESERVED_SLOTS as u32 * 2,
            ring_hdr_off: layout.ring_hdr_off,
            ring_data_off: layout.ring_data_off,
            entry_stride: FRAME_ENTRY_SIZE as u64,
            region_size: layout.region_size,
            icount_shift: 7,
            pause_requested: 0,
            shutdown_requested: 0,
        }
    );
    assert!(header.reserved_bytes_are_zero());
}

#[test]
fn region_layout_rejects_invalid_shapes() {
    assert_eq!(
        RegionLayout::for_config(RegionConfig::new(MAX_VM_NODES as u32 + 1, 16, 0)),
        Err(RegionLayoutError::TooManyVmNodes {
            requested: MAX_VM_NODES as u32 + 1,
            max: MAX_VM_NODES as u32,
        })
    );
    assert_eq!(
        RegionLayout::for_config(RegionConfig::new(1, 0, 0)),
        Err(RegionLayoutError::InvalidQueueCapacity { capacity: 0 })
    );
    assert_eq!(
        RegionLayout::for_config(RegionConfig::new(1, 3, 0)),
        Err(RegionLayoutError::InvalidQueueCapacity { capacity: 3 })
    );
    assert_eq!(
        RegionLayout::for_config(RegionConfig::new(1, 8, 64)),
        Err(RegionLayoutError::InvalidIcountShift { shift_bits: 64 })
    );
}

#[test]
#[cfg(not(all(
    target_arch = "x86_64",
    target_abi = "",
    target_endian = "little",
    target_env = "gnu",
    target_os = "linux",
    target_pointer_width = "64"
)))]
fn region_allocation_rejects_unpinned_developer_targets() {
    const { assert!(!LAYOUT_TARGET_SUPPORTED) };
    assert!(matches!(
        validate_layout_target(),
        Err(RegionLayoutError::UnsupportedTarget {
            expected: LAYOUT_TARGET_TRIPLE,
            ..
        })
    ));
    assert!(matches!(
        RegionAllocation::new(RegionConfig::new(1, 8, 0)),
        Err(RegionLayoutError::UnsupportedTarget { .. })
    ));
}

#[test]
#[cfg(all(
    target_arch = "x86_64",
    target_abi = "",
    target_endian = "little",
    target_env = "gnu",
    target_os = "linux",
    target_pointer_width = "64"
))]
fn region_allocation_initializes_slots_rings_and_storage() {
    const { assert!(LAYOUT_TARGET_SUPPORTED) };
    assert_eq!(validate_layout_target(), Ok(()));

    let allocation = allocation(RegionConfig::new(2, 8, 4));
    let layout = allocation.layout();

    assert_eq!(allocation.header().snapshot().node_count, MAX_NODES as u32);
    assert_eq!(allocation.slots().len(), MAX_NODES);
    assert_eq!(allocation.ring_headers().len(), layout.ring_count as usize);
    assert_eq!(
        allocation.frame_entries().len(),
        layout.frame_entry_count() as usize
    );
    assert_eq!(allocation.rings().len(), layout.ring_count as usize);

    assert_slot(&allocation, 0, KIND_VM, STATUS_IDLE);
    assert_slot(&allocation, 1, KIND_VM, STATUS_IDLE);
    assert_slot(&allocation, 2, KIND_VM, STATUS_DONE);
    assert_slot(&allocation, SLOT_NET_ROUTER, KIND_NET, STATUS_IDLE);
    assert_slot(&allocation, SLOT_BLK_IO, KIND_BLK, STATUS_IDLE);
    assert_slot(&allocation, SLOT_9P_IO, KIND_9P, STATUS_IDLE);
    assert!(allocation.header().reserved_bytes_are_zero());
    assert!(
        allocation
            .slots()
            .iter()
            .all(|slot| slot.reserved_bytes_are_zero())
    );
    assert!(
        allocation
            .ring_headers()
            .iter()
            .all(|ring| ring.padding_bytes_are_zero())
    );
    assert!(
        allocation
            .frame_entries()
            .iter()
            .all(|entry| entry.padding_bytes_are_zero())
    );
    assert!(
        allocation
            .frame_entries()
            .iter()
            .all(|entry| entry.payload() == Ok([].as_slice()))
    );

    assert_eq!(
        allocation.rings(),
        &[
            ring(0, 0, SLOT_NET_ROUTER),
            ring(1, SLOT_NET_ROUTER, 0),
            ring(2, 0, SLOT_BLK_IO),
            ring(3, SLOT_BLK_IO, 0),
            ring(4, 0, SLOT_9P_IO),
            ring(5, SLOT_9P_IO, 0),
            ring(6, 1, SLOT_NET_ROUTER),
            ring(7, SLOT_NET_ROUTER, 1),
            ring(8, 1, SLOT_BLK_IO),
            ring(9, SLOT_BLK_IO, 1),
            ring(10, 1, SLOT_9P_IO),
            ring(11, SLOT_9P_IO, 1),
        ]
    );
}

#[test]
fn reserved_executor_slot_constants_are_stable() {
    assert_eq!(
        ReservedExecutorSlot::all(),
        [
            ReservedExecutorSlot::NetRouter,
            ReservedExecutorSlot::BlockIo,
            ReservedExecutorSlot::NineP,
        ]
    );
    assert_eq!(ReservedExecutorSlot::NetRouter.slot(), SLOT_NET_ROUTER);
    assert_eq!(ReservedExecutorSlot::BlockIo.slot(), SLOT_BLK_IO);
    assert_eq!(ReservedExecutorSlot::NineP.slot(), SLOT_9P_IO);
    assert_eq!(ReservedExecutorSlot::NetRouter.kind(), KIND_NET);
    assert_eq!(ReservedExecutorSlot::BlockIo.kind(), KIND_BLK);
    assert_eq!(ReservedExecutorSlot::NineP.kind(), KIND_9P);
}

fn layout(config: RegionConfig) -> RegionLayout {
    match RegionLayout::for_config(config) {
        Ok(layout) => layout,
        Err(error) => panic!("region layout should be valid: {error}"),
    }
}

#[cfg(all(
    target_arch = "x86_64",
    target_abi = "",
    target_endian = "little",
    target_env = "gnu",
    target_os = "linux",
    target_pointer_width = "64"
))]
fn allocation(config: RegionConfig) -> RegionAllocation {
    match RegionAllocation::new(config) {
        Ok(allocation) => allocation,
        Err(error) => panic!("region allocation should be valid: {error}"),
    }
}

#[cfg(all(
    target_arch = "x86_64",
    target_abi = "",
    target_endian = "little",
    target_env = "gnu",
    target_os = "linux",
    target_pointer_width = "64"
))]
fn assert_slot(allocation: &RegionAllocation, slot: usize, kind: u8, status: u8) {
    let snapshot = allocation.slots()[slot].snapshot();
    assert_eq!(snapshot.kind, kind);
    assert_eq!(snapshot.status, status);
    assert_eq!(snapshot.max_advance_icount, 0);
}

#[cfg(all(
    target_arch = "x86_64",
    target_abi = "",
    target_endian = "little",
    target_env = "gnu",
    target_os = "linux",
    target_pointer_width = "64"
))]
fn ring(index: u32, src_slot: usize, dst_slot: usize) -> DirectedRing {
    DirectedRing {
        index,
        src_slot: src_slot as u32,
        dst_slot: dst_slot as u32,
    }
}
