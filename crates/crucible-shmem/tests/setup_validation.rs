//! Checks setup-time shared-memory mapping and header validation.

#![forbid(unsafe_code)]

use crucible_shmem::{
    ABI_VERSION, DEFAULT_QUEUE_CAPACITY, FRAME_ENTRY_DATA_OFFSET,
    FRAME_ENTRY_DELIVERY_ICOUNT_OFFSET, FRAME_ENTRY_LEN_OFFSET, FRAME_ENTRY_SEQ_OFFSET,
    FRAME_ENTRY_SIZE, FRAME_ENTRY_SRC_NODE_OFFSET, FrameEntry, GuestIntrospectionEntry,
    GuestIntrospectionRingDirection, KIND_9P, KIND_BLK, KIND_NET, KIND_VM, MAX_NODES,
    NODE_SLOT_KIND_OFFSET, NODE_SLOT_SIZE, NODE_SLOT_STATUS_OFFSET,
    REGION_HEADER_ABI_VERSION_OFFSET, REGION_HEADER_ENTRY_STRIDE_OFFSET,
    REGION_HEADER_ICOUNT_SHIFT_OFFSET, REGION_HEADER_MAGIC_OFFSET, REGION_HEADER_NODE_COUNT_OFFSET,
    REGION_HEADER_QUEUE_CAPACITY_OFFSET, REGION_HEADER_REGION_SIZE_OFFSET,
    REGION_HEADER_RING_COUNT_OFFSET, REGION_HEADER_RING_DATA_OFF_OFFSET,
    REGION_HEADER_RING_HDR_OFF_OFFSET, REGION_HEADER_SIZE, REGION_MAGIC,
    RING_HEADER_READ_IDX_OFFSET, RING_HEADER_SIZE, RING_HEADER_WRITE_IDX_OFFSET, RegionAllocation,
    RegionConfig, RegionHeader, RegionHeaderSnapshot, RegionLayout, RegionSetupValidationError,
    SLOT_9P_IO, SLOT_BLK_IO, SLOT_NET_ROUTER, STATUS_DONE, STATUS_IDLE, ValidatedSetupRegion,
    WhiteboxMarkerEntry, validate_setup_region_header,
};

#[cfg(unix)]
use crucible_shmem::{
    MappedSetupRegion, MappedSetupRegionAccessError, SetupRegionMapError, mmap_setup_region,
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

fn valid_snapshot() -> (RegionLayout, RegionHeaderSnapshot) {
    let layout = match RegionLayout::for_config(RegionConfig::new(2, DEFAULT_QUEUE_CAPACITY, 3)) {
        Ok(layout) => layout,
        Err(error) => panic!("valid setup region layout should build: {error}"),
    };
    let header = RegionHeader::new(layout);
    (layout, header.snapshot())
}

fn header_snapshot_from_bytes(bytes: &[u8]) -> RegionHeaderSnapshot {
    RegionHeaderSnapshot {
        magic: read_u64(bytes, REGION_HEADER_MAGIC_OFFSET),
        abi_version: read_u32(bytes, REGION_HEADER_ABI_VERSION_OFFSET),
        node_count: read_u32(bytes, REGION_HEADER_NODE_COUNT_OFFSET),
        queue_capacity: read_u32(bytes, REGION_HEADER_QUEUE_CAPACITY_OFFSET),
        ring_count: read_u32(bytes, REGION_HEADER_RING_COUNT_OFFSET),
        ring_hdr_off: read_u64(bytes, REGION_HEADER_RING_HDR_OFF_OFFSET),
        ring_data_off: read_u64(bytes, REGION_HEADER_RING_DATA_OFF_OFFSET),
        entry_stride: read_u64(bytes, REGION_HEADER_ENTRY_STRIDE_OFFSET),
        region_size: read_u64(bytes, REGION_HEADER_REGION_SIZE_OFFSET),
        icount_shift: read_u32(bytes, REGION_HEADER_ICOUNT_SHIFT_OFFSET),
        pause_requested: 0,
        shutdown_requested: 0,
    }
}

fn read_u8(bytes: &[u8], offset: usize) -> u8 {
    bytes[offset]
}

fn read_u16(bytes: &[u8], offset: usize) -> u16 {
    let mut out = [0; 2];
    out.copy_from_slice(&bytes[offset..offset + 2]);
    u16::from_le_bytes(out)
}

fn read_u32(bytes: &[u8], offset: usize) -> u32 {
    let mut out = [0; 4];
    out.copy_from_slice(&bytes[offset..offset + 4]);
    u32::from_le_bytes(out)
}

fn read_u64(bytes: &[u8], offset: usize) -> u64 {
    let mut out = [0; 8];
    out.copy_from_slice(&bytes[offset..offset + 8]);
    u64::from_le_bytes(out)
}

#[cfg(unix)]
fn temp_region_file() -> std::fs::File {
    let mut path = std::env::temp_dir();
    path.push(format!(
        "crucible-shmem-setup-validation-{}-{}",
        std::process::id(),
        unique_temp_suffix()
    ));

    let file = match std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(&path)
    {
        Ok(file) => file,
        Err(error) => panic!("failed to create temporary setup region: {error}"),
    };
    if let Err(error) = std::fs::remove_file(&path) {
        panic!("failed to unlink temporary setup region: {error}");
    }
    file
}

#[cfg(unix)]
fn unique_temp_suffix() -> u64 {
    NEXT_TEMP_ID.fetch_add(1, Ordering::Relaxed)
}

#[cfg(unix)]
fn mapped_region_from_allocation(allocation: &RegionAllocation) -> MappedSetupRegion {
    let layout = allocation.layout();
    let bytes = match allocation.setup_region_bytes() {
        Ok(bytes) => bytes,
        Err(error) => panic!("setup-region bytes should serialize: {error}"),
    };
    let mut temp = temp_region_file();
    if let Err(error) = temp.set_len(layout.region_size) {
        panic!("failed to size temporary setup region: {error}");
    }
    if let Err(error) = temp.write_all(&bytes) {
        panic!("failed to write temporary setup region: {error}");
    }
    match mmap_setup_region(temp.as_fd(), layout.region_size) {
        Ok(mapped) => mapped,
        Err(error) => panic!("setup region mmap should succeed: {error}"),
    }
}
