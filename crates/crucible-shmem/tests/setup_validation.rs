//! Checks setup-time shared-memory mapping and header validation.

#![forbid(unsafe_code)]

use crucible_shmem::{
    ABI_VERSION, DEFAULT_QUEUE_CAPACITY, FRAME_ENTRY_DATA_OFFSET,
    FRAME_ENTRY_DELIVERY_ICOUNT_OFFSET, FRAME_ENTRY_LEN_OFFSET, FRAME_ENTRY_SEQ_OFFSET,
    FRAME_ENTRY_SIZE, FRAME_ENTRY_SRC_NODE_OFFSET, FrameEntry, GuestIntrospectionEntry,
    GuestIntrospectionRingDirection, KIND_9P, KIND_BLK, KIND_NET, KIND_VM, MAX_NODES,
    NODE_SLOT_KIND_OFFSET, NODE_SLOT_SIZE, NODE_SLOT_STATUS_OFFSET,
    REGION_HEADER_ABI_VERSION_OFFSET, REGION_HEADER_ENTRY_STRIDE_OFFSET,
    REGION_HEADER_FAULT_PAYLOAD_ARENA_BYTES_OFFSET, REGION_HEADER_ICOUNT_SHIFT_OFFSET,
    REGION_HEADER_MAGIC_OFFSET, REGION_HEADER_NODE_COUNT_OFFSET,
    REGION_HEADER_QUEUE_CAPACITY_OFFSET, REGION_HEADER_REGION_SIZE_OFFSET,
    REGION_HEADER_RING_COUNT_OFFSET, REGION_HEADER_RING_DATA_OFF_OFFSET,
    REGION_HEADER_RING_HDR_OFF_OFFSET, REGION_HEADER_SIZE, REGION_MAGIC,
    RING_HEADER_READ_IDX_OFFSET, RING_HEADER_SIZE, RING_HEADER_WRITE_IDX_OFFSET, RegionAllocation,
    RegionConfig, RegionHeader, RegionHeaderSnapshot, RegionLayout, RegionSetupValidationError,
    SLOT_9P_IO, SLOT_BLK_IO, SLOT_NET_ROUTER, STATUS_DONE, STATUS_IDLE, SpscRingError,
    ValidatedSetupRegion, WhiteboxMarkerEntry, validate_setup_region_header,
};

#[cfg(unix)]
use crucible_shmem::{
    DequeuedFaultCommand, DequeuedFaultResult, FAULT_COMMAND_ABI_MAJOR, FAULT_COMMAND_ABI_MINOR,
    FAULT_COMMAND_FLAG_NONE, FAULT_COMMAND_SEMANTIC_VERSION, FaultBoundaryPhase,
    FaultCommandHeaderV1, FaultCommandKind, FaultResultHeaderV1, FaultResultStatus,
    MappedSetupRegion, MappedSetupRegionAccessError, SetupRegionMapError, dequeue_fault_command,
    dequeue_fault_result, enqueue_fault_command, enqueue_fault_result, mmap_setup_region,
};
#[cfg(unix)]
use std::io::Write;
#[cfg(unix)]
use std::os::fd::AsFd;
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
static NEXT_TEMP_ID: AtomicU64 = AtomicU64::new(0);

#[test]
fn setup_region_header_validation_accepts_magic_abi_and_region_len() {
    let (layout, snapshot) = valid_snapshot();

    assert_eq!(
        validate_setup_region_header(snapshot, layout.region_size),
        Ok(ValidatedSetupRegion {
            region_len: layout.region_size,
            abi_version: ABI_VERSION,
        })
    );
}

#[test]
fn setup_region_header_validation_rejects_invalid_abi_marker() {
    let (layout, snapshot) = valid_snapshot();

    assert_eq!(
        validate_setup_region_header(
            RegionHeaderSnapshot {
                magic: 0,
                ..snapshot
            },
            layout.region_size,
        ),
        Err(RegionSetupValidationError::InvalidMagic {
            actual: 0,
            expected: REGION_MAGIC,
        })
    );
    assert_eq!(
        validate_setup_region_header(
            RegionHeaderSnapshot {
                abi_version: ABI_VERSION - 1,
                ..snapshot
            },
            layout.region_size,
        ),
        Err(RegionSetupValidationError::AbiVersionMismatch {
            actual: ABI_VERSION - 1,
            expected: ABI_VERSION,
        })
    );
    assert_eq!(
        validate_setup_region_header(
            RegionHeaderSnapshot {
                abi_version: ABI_VERSION + 1,
                ..snapshot
            },
            layout.region_size,
        ),
        Err(RegionSetupValidationError::AbiVersionMismatch {
            actual: ABI_VERSION + 1,
            expected: ABI_VERSION,
        })
    );
}

#[test]
fn setup_region_header_validation_rejects_wrong_region_len() {
    let (layout, snapshot) = valid_snapshot();
    let short_region_len = layout.region_size - 1;

    assert_eq!(
        validate_setup_region_header(snapshot, short_region_len),
        Err(RegionSetupValidationError::RegionLengthMismatch {
            setup_region_len: short_region_len,
            header_region_size: layout.region_size,
        })
    );
    assert_eq!(
        validate_setup_region_header(snapshot, REGION_HEADER_SIZE as u64 - 1),
        Err(RegionSetupValidationError::RegionTooSmall {
            region_len: REGION_HEADER_SIZE as u64 - 1,
            minimum_len: REGION_HEADER_SIZE as u64,
        })
    );
}

#[test]
fn setup_region_header_validation_rejects_invalid_geometry() {
    let (layout, snapshot) = valid_snapshot();

    assert_eq!(
        validate_setup_region_header(
            RegionHeaderSnapshot {
                ring_data_off: snapshot.ring_data_off + RING_HEADER_SIZE as u64,
                ..snapshot
            },
            layout.region_size,
        ),
        Err(RegionSetupValidationError::InvalidRingDataOffset {
            actual: snapshot.ring_data_off + RING_HEADER_SIZE as u64,
            expected: snapshot.ring_data_off,
        })
    );
}

#[test]
fn setup_region_bytes_materialize_a_valid_initial_memfd_image() {
    let allocation = match RegionAllocation::new_model(RegionConfig::new(2, 4, 3)) {
        Ok(allocation) => allocation,
        Err(error) => panic!("valid region allocation should build: {error}"),
    };
    let layout = allocation.layout();
    let bytes = match allocation.setup_region_bytes() {
        Ok(bytes) => bytes,
        Err(error) => panic!("setup-region bytes should serialize: {error}"),
    };

    assert_eq!(bytes.len(), layout.region_size as usize);
    assert_eq!(
        validate_setup_region_header(header_snapshot_from_bytes(&bytes), layout.region_size),
        Ok(ValidatedSetupRegion {
            region_len: layout.region_size,
            abi_version: ABI_VERSION,
        })
    );

    for slot in 0..MAX_NODES {
        let base = layout.node_slots_off as usize + slot * NODE_SLOT_SIZE;
        let expected_kind = if slot < 2 {
            KIND_VM
        } else if slot == SLOT_NET_ROUTER {
            KIND_NET
        } else if slot == SLOT_BLK_IO {
            KIND_BLK
        } else if slot == SLOT_9P_IO {
            KIND_9P
        } else {
            KIND_VM
        };
        let expected_status =
            if slot < 2 || slot == SLOT_NET_ROUTER || slot == SLOT_BLK_IO || slot == SLOT_9P_IO {
                STATUS_IDLE
            } else {
                STATUS_DONE
            };

        assert_eq!(read_u8(&bytes, base + NODE_SLOT_KIND_OFFSET), expected_kind);
        assert_eq!(
            read_u8(&bytes, base + NODE_SLOT_STATUS_OFFSET),
            expected_status
        );
    }
}

#[test]
fn setup_region_bytes_include_ring_indices_and_frame_entries() {
    let mut allocation = match RegionAllocation::new_model(RegionConfig::new(1, 4, 0)) {
        Ok(allocation) => allocation,
        Err(error) => panic!("valid region allocation should build: {error}"),
    };
    let frame = match FrameEntry::new(17, 0, 3, b"ping") {
        Ok(frame) => frame,
        Err(error) => panic!("valid frame should build: {error}"),
    };
    if let Err(error) = allocation.enqueue_directed_frame(0, SLOT_NET_ROUTER as u32, &frame) {
        panic!("directed frame enqueue should succeed: {error}");
    }

    let layout = allocation.layout();
    let ring = match allocation
        .rings()
        .iter()
        .find(|ring| ring.src_slot == 0 && ring.dst_slot == SLOT_NET_ROUTER as u32)
    {
        Some(ring) => ring,
        None => panic!("VM-to-network-router ring should exist"),
    };
    let bytes = match allocation.setup_region_bytes() {
        Ok(bytes) => bytes,
        Err(error) => panic!("setup-region bytes should serialize: {error}"),
    };
    let ring_base = layout.ring_hdr_off as usize + ring.index as usize * RING_HEADER_SIZE;
    let frame_base = layout.ring_data_off as usize
        + ring.index as usize * layout.queue_capacity as usize * FRAME_ENTRY_SIZE;

    assert_eq!(read_u64(&bytes, ring_base + RING_HEADER_READ_IDX_OFFSET), 0);
    assert_eq!(
        read_u64(&bytes, ring_base + RING_HEADER_WRITE_IDX_OFFSET),
        1
    );
    assert_eq!(
        read_u64(&bytes, frame_base + FRAME_ENTRY_DELIVERY_ICOUNT_OFFSET),
        frame.delivery_icount
    );
    assert_eq!(
        read_u32(&bytes, frame_base + FRAME_ENTRY_SRC_NODE_OFFSET),
        frame.src_node
    );
    assert_eq!(
        read_u32(&bytes, frame_base + FRAME_ENTRY_SEQ_OFFSET),
        frame.seq
    );
    assert_eq!(
        read_u16(&bytes, frame_base + FRAME_ENTRY_LEN_OFFSET),
        frame.len
    );
    assert_eq!(
        &bytes[frame_base + FRAME_ENTRY_DATA_OFFSET..frame_base + FRAME_ENTRY_DATA_OFFSET + 4],
        b"ping"
    );
}

#[test]
#[cfg(unix)]
fn mmap_setup_region_maps_exact_region_len_before_header_validation() {
    let temp = temp_region_file();
    let region_len = REGION_HEADER_SIZE as u64;
    if let Err(error) = temp.set_len(region_len) {
        panic!("failed to size temporary setup region: {error}");
    }

    let mapped = match mmap_setup_region(temp.as_fd(), region_len) {
        Ok(mapped) => mapped,
        Err(error) => panic!("setup region mmap should succeed: {error}"),
    };

    assert_eq!(mapped.region_len(), region_len);
    assert_eq!(
        mapped.validate_header(),
        Err(RegionSetupValidationError::InvalidMagic {
            actual: 0,
            expected: REGION_MAGIC,
        })
    );
}

#[test]
#[cfg(unix)]
fn mmap_setup_region_rejects_lengths_smaller_than_header() {
    let temp = temp_region_file();
    let region_len = REGION_HEADER_SIZE as u64 - 1;

    assert_eq!(
        mmap_setup_region(temp.as_fd(), region_len).map(|mapped| mapped.region_len()),
        Err(SetupRegionMapError::RegionTooSmall {
            region_len,
            minimum_len: REGION_HEADER_SIZE as u64,
        })
    );
}

#[test]
#[cfg(unix)]
fn mmap_setup_region_rejects_short_backing_before_mapping() {
    let temp = temp_region_file();
    let region_len = REGION_HEADER_SIZE as u64;
    let backing_len = region_len - 1;
    if let Err(error) = temp.set_len(backing_len) {
        panic!("failed to size short temporary setup region: {error}");
    }

    assert_eq!(
        mmap_setup_region(temp.as_fd(), region_len).map(|mapped| mapped.region_len()),
        Err(SetupRegionMapError::BackingTooShort {
            backing_len,
            region_len,
        })
    );
}

#[test]
#[cfg(unix)]
fn mmap_setup_region_exposes_node_slot_and_distinct_directed_rings() {
    let allocation = match RegionAllocation::new_model(RegionConfig::new(1, 4, 0)) {
        Ok(allocation) => allocation,
        Err(error) => panic!("valid region allocation should build: {error}"),
    };
    let mut mapped = mapped_region_from_allocation(&allocation);

    let view = match mapped.node_directed_ring_pair_mut(
        0,
        SLOT_NET_ROUTER as u32,
        0,
        0,
        SLOT_NET_ROUTER as u32,
    ) {
        Ok(view) => view,
        Err(error) => panic!("mapped node/ring view should bind: {error}"),
    };
    assert_eq!(view.node_slot.snapshot().kind, KIND_VM);
    assert_eq!(view.first.descriptor.src_slot, SLOT_NET_ROUTER as u32);
    assert_eq!(view.first.descriptor.dst_slot, 0);
    assert_eq!(view.second.descriptor.src_slot, 0);
    assert_eq!(view.second.descriptor.dst_slot, SLOT_NET_ROUTER as u32);

    let frame = match FrameEntry::new(11, 0, 1, b"packet") {
        Ok(frame) => frame,
        Err(error) => panic!("valid frame should build: {error}"),
    };
    if let Err(error) = view.second.header.enqueue(view.second.entries, &frame) {
        panic!("mapped outbound ring should accept frame: {error}");
    }
    assert_eq!(
        view.second.header.peek(view.second.entries),
        Ok(Some(frame.clone()))
    );
    assert_eq!(view.first.header.peek(view.first.entries), Ok(None));
}

#[test]
#[cfg(unix)]
fn mmap_setup_region_rejects_duplicate_mutable_directed_ring_view() {
    let allocation = match RegionAllocation::new_model(RegionConfig::new(1, 4, 0)) {
        Ok(allocation) => allocation,
        Err(error) => panic!("valid region allocation should build: {error}"),
    };
    let mut mapped = mapped_region_from_allocation(&allocation);

    assert_eq!(
        mapped
            .node_directed_ring_pair_mut(0, 0, SLOT_NET_ROUTER as u32, 0, SLOT_NET_ROUTER as u32,)
            .map(|view| view.first.descriptor)
            .err(),
        Some(MappedSetupRegionAccessError::DuplicateDirectedRing { ring_index: 0 })
    );
}

#[test]
#[cfg(unix)]
fn mmap_setup_region_round_trips_whitebox_marker_ring_entries() {
    let allocation = match RegionAllocation::new_model(RegionConfig::new(1, 4, 0)) {
        Ok(allocation) => allocation,
        Err(error) => panic!("valid region allocation should build: {error}"),
    };
    let mut mapped = mapped_region_from_allocation(&allocation);
    let marker = match WhiteboxMarkerEntry::new(913, 2, 4, b"MARK") {
        Ok(marker) => marker,
        Err(error) => panic!("valid marker entry should build: {error}"),
    };

    let ring = match mapped.whitebox_marker_ring_mut(0) {
        Ok(ring) => ring,
        Err(error) => panic!("mapped marker ring should bind: {error}"),
    };
    if let Err(error) = ring.header.enqueue_whitebox_marker(ring.entries, marker) {
        panic!("mapped marker ring should enqueue: {error}");
    }
    let consumed = match ring.header.dequeue_whitebox_marker(ring.entries) {
        Ok(Some(entry)) => entry,
        Ok(None) => panic!("mapped marker ring should contain one entry"),
        Err(error) => panic!("mapped marker ring should dequeue: {error}"),
    };

    assert_eq!(consumed.validate(), Ok(marker));
    assert_eq!(ring.header.dequeue_whitebox_marker(ring.entries), Ok(None));
}

#[test]
#[cfg(unix)]
fn mmap_setup_region_round_trips_one_bounded_selectable_reply() {
    let allocation = match RegionAllocation::new_model(RegionConfig::new(1, 4, 0)) {
        Ok(allocation) => allocation,
        Err(error) => panic!("valid region allocation should build: {error}"),
    };
    let mut mapped = mapped_region_from_allocation(&allocation);
    let reply = match WhiteboxMarkerEntry::new(1_207, 0, 0xff07, b"CRUCSRPL1") {
        Ok(reply) => reply,
        Err(error) => panic!("valid selectable reply entry should build: {error}"),
    };

    let ring = match mapped.selectable_reply_ring_mut(0) {
        Ok(ring) => ring,
        Err(error) => panic!("mapped selectable reply ring should bind: {error}"),
    };
    if let Err(error) = ring.header.enqueue_whitebox_marker(ring.entries, reply) {
        panic!("mapped selectable reply ring should enqueue: {error}");
    }
    assert_eq!(
        ring.header.enqueue_whitebox_marker(ring.entries, reply),
        Err(SpscRingError::QueueFull { capacity: 1 })
    );
    let consumed = match ring.header.dequeue_whitebox_marker(ring.entries) {
        Ok(Some(entry)) => entry,
        Ok(None) => panic!("mapped selectable reply ring should contain one entry"),
        Err(error) => panic!("mapped selectable reply ring should dequeue: {error}"),
    };

    assert_eq!(consumed.validate(), Ok(reply));
    assert_eq!(ring.header.dequeue_whitebox_marker(ring.entries), Ok(None));
}

#[test]
#[cfg(unix)]
fn mmap_setup_region_round_trips_fault_command_transport() {
    let allocation = match RegionAllocation::new_model(RegionConfig::new(1, 4, 0)) {
        Ok(allocation) => allocation,
        Err(error) => panic!("valid region allocation should build: {error}"),
    };
    let mut mapped = mapped_region_from_allocation(&allocation);
    let view = match mapped.fault_command_transport_mut(0) {
        Ok(view) => view,
        Err(error) => panic!("mapped fault command transport should bind: {error}"),
    };
    let payload = b"memory mutation";
    let hash = |bytes: &[u8]| *blake3::hash(bytes).as_bytes();
    let command = FaultCommandHeaderV1 {
        abi_major: FAULT_COMMAND_ABI_MAJOR,
        abi_minor: FAULT_COMMAND_ABI_MINOR,
        command_kind: FaultCommandKind::MemoryMutation,
        command_flags: FAULT_COMMAND_FLAG_NONE,
        phase: FaultBoundaryPhase::NodeBoundary,
        semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
        command_sequence: 1,
        target_node_hash: hash(b"node-0"),
        target_icount: 10,
        authorization_ceiling_icount: 10,
        binding_hash: hash(b"binding"),
        opportunity_hash: [0; 32],
        expected_precondition_hash: hash(b"before"),
        payload_hash: hash(&[]),
        payload_offset: 0,
        payload_length: 0,
    };
    if let Err(error) = enqueue_fault_command(
        view.ring,
        view.slots,
        view.arena_header,
        view.arena,
        view.arena_region_offset,
        command,
        payload,
    ) {
        panic!("mapped fault command transport should enqueue: {error}");
    }
    let dequeued = match dequeue_fault_command(
        view.ring,
        view.slots,
        view.arena_header,
        view.arena,
        view.arena_region_offset,
    ) {
        Ok(Some(command)) => command,
        Ok(None) => panic!("mapped fault command transport should contain one command"),
        Err(error) => panic!("mapped fault command transport should dequeue: {error}"),
    };
    assert!(matches!(
        dequeued,
        DequeuedFaultCommand::Valid { header, payload: actual }
            if header.command_sequence == 1 && actual == payload
    ));

    let result_view = match mapped.fault_result_transport_mut(0) {
        Ok(view) => view,
        Err(error) => panic!("mapped fault result transport should bind: {error}"),
    };
    let before = hash(b"before");
    let result = FaultResultHeaderV1 {
        abi_major: FAULT_COMMAND_ABI_MAJOR,
        abi_minor: FAULT_COMMAND_ABI_MINOR,
        command_kind: FaultCommandKind::MemoryMutation as u16,
        status: FaultResultStatus::Applied,
        semantic_version: FAULT_COMMAND_SEMANTIC_VERSION,
        command_sequence: 1,
        observed_icount: 10,
        applied_icount: 10,
        capability_version: 1,
        phase: FaultBoundaryPhase::NodeBoundary,
        before_hash: before,
        after_hash: hash(b"after"),
        evidence_hash: hash(b"evidence"),
        result_payload_hash: hash(&[]),
        result_offset: 0,
        result_length: 0,
    };
    if let Err(error) = enqueue_fault_result(
        result_view.ring,
        result_view.slots,
        result_view.arena_header,
        result_view.arena,
        result_view.arena_region_offset,
        result,
        b"applied",
    ) {
        panic!("mapped fault result transport should enqueue: {error}");
    }
    let dequeued = match dequeue_fault_result(
        result_view.ring,
        result_view.slots,
        result_view.arena_header,
        result_view.arena,
        result_view.arena_region_offset,
    ) {
        Ok(Some(result)) => result,
        Ok(None) => panic!("mapped fault result transport should contain one result"),
        Err(error) => panic!("mapped fault result transport should dequeue: {error}"),
    };
    assert!(matches!(
        dequeued,
        DequeuedFaultResult::Valid { header, payload: actual }
            if header.command_sequence == 1 && actual == b"applied"
    ));
}

#[test]
#[cfg(unix)]
fn mmap_setup_region_keeps_guest_introspection_directions_distinct() {
    const CLOSE_RECORD: &[u8] =
        b"CRGI\x01\x00\x07\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00";
    let allocation = match RegionAllocation::new_model(RegionConfig::new(1, 4, 0)) {
        Ok(allocation) => allocation,
        Err(error) => panic!("valid region allocation should build: {error}"),
    };
    let mut mapped = mapped_region_from_allocation(&allocation);
    let request = match GuestIntrospectionEntry::new(7, CLOSE_RECORD) {
        Ok(entry) => entry,
        Err(error) => panic!("valid guest-introspection entry should build: {error}"),
    };

    {
        let mut host_rings = match mapped.host_guest_introspection_rings_mut(0) {
            Ok(rings) => rings,
            Err(error) => panic!("mapped host role should bind: {error}"),
        };
        assert_eq!(
            host_rings.requests.direction(),
            GuestIntrospectionRingDirection::Request
        );
        assert_eq!(
            host_rings.responses.direction(),
            GuestIntrospectionRingDirection::Response
        );
        if let Err(error) = host_rings.requests.enqueue(request) {
            panic!("mapped request ring should enqueue: {error}");
        }
        assert_eq!(host_rings.responses.dequeue(), Ok(None));
    }

    let mut plugin_rings = match mapped.plugin_guest_introspection_rings_mut(0) {
        Ok(rings) => rings,
        Err(error) => panic!("mapped plugin role should bind: {error}"),
    };
    assert_eq!(
        plugin_rings.requests.direction(),
        GuestIntrospectionRingDirection::Request
    );
    assert_eq!(
        plugin_rings.responses.direction(),
        GuestIntrospectionRingDirection::Response
    );
    assert_eq!(plugin_rings.requests.dequeue(), Ok(Some(request)));
}

#[path = "setup_validation/support.rs"]
mod support;

use support::*;
