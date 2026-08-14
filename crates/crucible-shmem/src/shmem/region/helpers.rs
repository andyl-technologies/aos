//! ABI-target validation, geometry helpers, and canonical byte writers.

use super::*;

/// Validates that the current compilation target matches the pinned ABI target.
///
/// # Errors
///
/// Returns [`RegionLayoutError::UnsupportedTarget`] when compiled for anything
/// other than `x86_64-unknown-linux-gnu`.
pub fn validate_layout_target() -> Result<(), RegionLayoutError> {
    if LAYOUT_TARGET_SUPPORTED {
        Ok(())
    } else {
        Err(RegionLayoutError::UnsupportedTarget {
            expected: LAYOUT_TARGET_TRIPLE,
            actual: compiled_layout_target(),
        })
    }
}

pub(super) fn compiled_layout_target() -> &'static str {
    if LAYOUT_TARGET_SUPPORTED {
        LAYOUT_TARGET_TRIPLE
    } else if cfg!(all(
        target_arch = "x86_64",
        target_abi = "x32",
        target_endian = "little",
        target_env = "gnu",
        target_os = "linux",
        target_pointer_width = "32"
    )) {
        "x86_64-unknown-linux-gnux32"
    } else if cfg!(all(
        target_arch = "x86_64",
        target_endian = "little",
        target_env = "musl",
        target_os = "linux"
    )) {
        "x86_64-unknown-linux-musl"
    } else if cfg!(all(
        target_arch = "x86_64",
        target_endian = "little",
        target_os = "linux"
    )) {
        "x86_64-unknown-linux-non-gnu"
    } else if cfg!(target_os = "macos")
        && cfg!(target_arch = "aarch64")
        && cfg!(target_endian = "little")
    {
        "aarch64-apple-darwin"
    } else if cfg!(target_endian = "big") {
        "unsupported-big-endian"
    } else {
        "unsupported-target"
    }
}

pub(crate) fn directed_rings(vm_node_count: u32) -> Result<Vec<DirectedRing>, RegionLayoutError> {
    let mut rings = Vec::new();
    for vm_slot in 0..vm_node_count {
        for executor in ReservedExecutorSlot::all() {
            let executor_slot =
                u32::try_from(executor.slot()).map_err(|_| RegionLayoutError::GeometryOverflow)?;
            let outbound_index =
                u32::try_from(rings.len()).map_err(|_| RegionLayoutError::GeometryOverflow)?;
            rings.push(DirectedRing {
                index: outbound_index,
                src_slot: vm_slot,
                dst_slot: executor_slot,
            });
            let inbound_index =
                u32::try_from(rings.len()).map_err(|_| RegionLayoutError::GeometryOverflow)?;
            rings.push(DirectedRing {
                index: inbound_index,
                src_slot: executor_slot,
                dst_slot: vm_slot,
            });
        }
    }
    Ok(rings)
}

pub(super) fn layout_from_setup_region_geometry(
    snapshot: RegionHeaderSnapshot,
    region_len: u64,
) -> Result<RegionLayout, RegionSetupValidationError> {
    let rings_per_vm = (RESERVED_SLOTS as u32)
        .checked_mul(2)
        .ok_or(RegionSetupValidationError::GeometryOverflow)?;
    if snapshot.ring_count == 0 || !snapshot.ring_count.is_multiple_of(rings_per_vm) {
        return Err(RegionSetupValidationError::InvalidRingCount {
            ring_count: snapshot.ring_count,
            rings_per_vm,
        });
    }

    let vm_node_count = snapshot.ring_count / rings_per_vm;
    let layout = RegionLayout::for_config(
        RegionConfig::new(
            vm_node_count,
            snapshot.queue_capacity,
            snapshot.icount_shift,
        )
        .with_fault_payload_arena_bytes(snapshot.fault_payload_arena_bytes),
    )
    .map_err(|source| RegionSetupValidationError::InvalidLayout { source })?;

    if snapshot.node_count != layout.node_count {
        return Err(RegionSetupValidationError::InvalidNodeCount {
            actual: snapshot.node_count,
            expected: layout.node_count,
        });
    }
    if snapshot.ring_hdr_off != layout.ring_hdr_off {
        return Err(RegionSetupValidationError::InvalidRingHeaderOffset {
            actual: snapshot.ring_hdr_off,
            expected: layout.ring_hdr_off,
        });
    }
    if snapshot.ring_data_off != layout.ring_data_off {
        return Err(RegionSetupValidationError::InvalidRingDataOffset {
            actual: snapshot.ring_data_off,
            expected: layout.ring_data_off,
        });
    }
    if snapshot.entry_stride != layout.entry_stride {
        return Err(RegionSetupValidationError::InvalidEntryStride {
            actual: snapshot.entry_stride,
            expected: layout.entry_stride,
        });
    }
    if layout.region_size != region_len {
        return Err(RegionSetupValidationError::LayoutRegionLengthMismatch {
            setup_region_len: region_len,
            layout_region_size: layout.region_size,
        });
    }

    Ok(layout)
}

pub(super) fn node_slot_for_physical_index(vm_node_count: u32, slot: usize) -> NodeSlot {
    if slot < vm_node_count as usize {
        NodeSlot::new_with_status(KIND_VM, STATUS_IDLE)
    } else if slot == SLOT_NET_ROUTER {
        NodeSlot::new_with_status(KIND_NET, STATUS_IDLE)
    } else if slot == SLOT_BLK_IO {
        NodeSlot::new_with_status(KIND_BLK, STATUS_IDLE)
    } else if slot == SLOT_9P_IO {
        NodeSlot::new_with_status(KIND_9P, STATUS_IDLE)
    } else {
        NodeSlot::new_with_status(KIND_VM, STATUS_DONE)
    }
}

pub(super) fn usize_to_u64(value: usize) -> Result<u64, RegionLayoutError> {
    u64::try_from(value).map_err(|_| RegionLayoutError::GeometryOverflow)
}

pub(super) fn checked_align_up(value: u64, alignment: u64) -> Result<u64, RegionLayoutError> {
    let mask = alignment
        .checked_sub(1)
        .ok_or(RegionLayoutError::GeometryOverflow)?;
    if !alignment.is_power_of_two() {
        return Err(RegionLayoutError::GeometryOverflow);
    }
    value
        .checked_add(mask)
        .map(|value| value & !mask)
        .ok_or(RegionLayoutError::GeometryOverflow)
}

pub(super) fn checked_segment_offset(
    segment: &'static str,
    index: usize,
    base: u64,
    len: usize,
    region_len: usize,
) -> Result<usize, RegionSerializationError> {
    let offset = u64::try_from(index)
        .ok()
        .and_then(|index| index.checked_mul(u64::try_from(len).ok()?))
        .and_then(|offset| base.checked_add(offset))
        .ok_or(RegionSerializationError::SegmentOffsetOverflow { segment, index })?;
    let offset = usize::try_from(offset)
        .map_err(|_error| RegionSerializationError::SegmentOffsetOverflow { segment, index })?;
    let end = offset
        .checked_add(len)
        .ok_or(RegionSerializationError::SegmentOffsetOverflow { segment, index })?;
    if end > region_len {
        return Err(RegionSerializationError::SegmentOutOfBounds {
            segment,
            index,
            offset,
            len,
            region_len,
        });
    }
    Ok(offset)
}

pub(super) fn write_region_header_bytes(
    bytes: &mut [u8],
    snapshot: RegionHeaderSnapshot,
) -> Result<(), RegionSerializationError> {
    let region_len = bytes.len();
    let header_len = REGION_HEADER_SIZE;
    if header_len > region_len {
        return Err(RegionSerializationError::SegmentOutOfBounds {
            segment: "region header",
            index: 0,
            offset: 0,
            len: header_len,
            region_len,
        });
    }
    let header = &mut bytes[..header_len];
    write_u64_at(header, REGION_HEADER_MAGIC_OFFSET, snapshot.magic);
    write_u32_at(
        header,
        REGION_HEADER_ABI_VERSION_OFFSET,
        snapshot.abi_version,
    );
    write_u32_at(header, REGION_HEADER_NODE_COUNT_OFFSET, snapshot.node_count);
    write_u32_at(
        header,
        REGION_HEADER_QUEUE_CAPACITY_OFFSET,
        snapshot.queue_capacity,
    );
    write_u32_at(header, REGION_HEADER_RING_COUNT_OFFSET, snapshot.ring_count);
    write_u64_at(
        header,
        REGION_HEADER_RING_HDR_OFF_OFFSET,
        snapshot.ring_hdr_off,
    );
    write_u64_at(
        header,
        REGION_HEADER_RING_DATA_OFF_OFFSET,
        snapshot.ring_data_off,
    );
    write_u64_at(
        header,
        REGION_HEADER_ENTRY_STRIDE_OFFSET,
        snapshot.entry_stride,
    );
    write_u64_at(
        header,
        REGION_HEADER_REGION_SIZE_OFFSET,
        snapshot.region_size,
    );
    write_u32_at(
        header,
        REGION_HEADER_ICOUNT_SHIFT_OFFSET,
        snapshot.icount_shift,
    );
    write_u8_at(
        header,
        REGION_HEADER_PAUSE_REQUESTED_OFFSET,
        snapshot.pause_requested,
    );
    write_u8_at(
        header,
        REGION_HEADER_SHUTDOWN_REQUESTED_OFFSET,
        snapshot.shutdown_requested,
    );
    write_u32_at(
        header,
        REGION_HEADER_FAULT_PAYLOAD_ARENA_BYTES_OFFSET,
        snapshot.fault_payload_arena_bytes,
    );
    Ok(())
}

pub(super) fn write_node_slot_bytes(bytes: &mut [u8], snapshot: NodeSlotSnapshot) {
    write_u64_at(
        bytes,
        NODE_SLOT_CURRENT_ICOUNT_OFFSET,
        snapshot.current_icount,
    );
    write_u64_at(bytes, NODE_SLOT_CURRENT_NS_OFFSET, snapshot.current_ns);
    write_u64_at(
        bytes,
        NODE_SLOT_MAX_ADVANCE_ICOUNT_OFFSET,
        snapshot.max_advance_icount,
    );
    write_u64_at(
        bytes,
        NODE_SLOT_IDLE_WAKE_ICOUNT_OFFSET,
        snapshot.idle_wake_icount,
    );
    write_u32_at(bytes, NODE_SLOT_WAKE_SIGNAL_OFFSET, snapshot.wake_signal);
    write_u8_at(bytes, NODE_SLOT_STATUS_OFFSET, snapshot.status);
    write_u8_at(bytes, NODE_SLOT_KIND_OFFSET, snapshot.kind);
    write_u8_at(
        bytes,
        NODE_SLOT_DEVICE_IO_ACTIVE_OFFSET,
        snapshot.device_io_active,
    );
    write_u32_at(bytes, NODE_SLOT_PUBLISH_GEN_OFFSET, snapshot.publish_gen);
    write_u32_at(
        bytes,
        NODE_SLOT_CONTROL_BOUNDARY_ACK_OFFSET,
        snapshot.control_boundary_ack,
    );
}

pub(super) fn write_ring_header_bytes(bytes: &mut [u8], ring_header: &RingHeader) {
    write_u64_at(bytes, RING_HEADER_READ_IDX_OFFSET, ring_header.read_index());
    write_u64_at(
        bytes,
        RING_HEADER_WRITE_IDX_OFFSET,
        ring_header.write_index(),
    );
}

pub(super) fn write_frame_entry_bytes(bytes: &mut [u8], frame: &FrameEntry) {
    write_u64_at(
        bytes,
        FRAME_ENTRY_DELIVERY_ICOUNT_OFFSET,
        frame.delivery_icount,
    );
    write_u32_at(bytes, FRAME_ENTRY_SRC_NODE_OFFSET, frame.src_node);
    write_u32_at(bytes, FRAME_ENTRY_SEQ_OFFSET, frame.seq);
    write_u16_at(bytes, FRAME_ENTRY_LEN_OFFSET, frame.len);
    bytes[FRAME_ENTRY_PAD_OFFSET..FRAME_ENTRY_PAD_OFFSET + frame._pad.len()]
        .copy_from_slice(&frame._pad);
    bytes[FRAME_ENTRY_DATA_OFFSET..FRAME_ENTRY_DATA_OFFSET + MAX_FRAME_DATA]
        .copy_from_slice(&frame.data);
}

pub(super) fn write_coverage_entry_bytes(bytes: &mut [u8], entry: &CoverageEntry) {
    write_u64_at(
        bytes,
        COVERAGE_ENTRY_CURRENT_ICOUNT_OFFSET,
        entry.current_icount,
    );
    write_u64_at(bytes, COVERAGE_ENTRY_GUEST_PC_OFFSET, entry.guest_pc);
    write_u64_at(bytes, COVERAGE_ENTRY_MAP_INDEX_OFFSET, entry.map_index);
    write_u32_at(bytes, COVERAGE_ENTRY_VCPU_INDEX_OFFSET, entry.vcpu_index);
    write_u32_at(bytes, COVERAGE_ENTRY_BLOCK_LEN_OFFSET, entry.block_len);
    bytes[COVERAGE_ENTRY_RESERVED_OFFSET..COVERAGE_ENTRY_SIZE].copy_from_slice(&entry._reserved);
}

pub(super) fn write_whitebox_marker_entry_bytes(bytes: &mut [u8], entry: &WhiteboxMarkerEntry) {
    write_u64_at(
        bytes,
        WHITEBOX_MARKER_ENTRY_CURRENT_ICOUNT_OFFSET,
        entry.current_icount,
    );
    write_u32_at(
        bytes,
        WHITEBOX_MARKER_ENTRY_VCPU_INDEX_OFFSET,
        entry.vcpu_index,
    );
    write_u16_at(bytes, WHITEBOX_MARKER_ENTRY_KIND_OFFSET, entry.kind);
    write_u16_at(
        bytes,
        WHITEBOX_MARKER_ENTRY_PAYLOAD_LEN_OFFSET,
        entry.payload_len,
    );
    bytes[WHITEBOX_MARKER_ENTRY_PAYLOAD_OFFSET..WHITEBOX_MARKER_ENTRY_RESERVED_OFFSET]
        .copy_from_slice(&entry.payload);
    bytes[WHITEBOX_MARKER_ENTRY_RESERVED_OFFSET..WHITEBOX_MARKER_ENTRY_SIZE]
        .copy_from_slice(&entry._reserved);
}

pub(super) fn write_guest_introspection_entry_bytes(
    bytes: &mut [u8],
    entry: &GuestIntrospectionEntry,
) {
    write_u64_at(
        bytes,
        GUEST_INTROSPECTION_ENTRY_SEQUENCE_OFFSET,
        entry.sequence,
    );
    write_u16_at(bytes, GUEST_INTROSPECTION_ENTRY_LEN_OFFSET, entry.len);
    bytes[GUEST_INTROSPECTION_ENTRY_PAD_OFFSET..GUEST_INTROSPECTION_ENTRY_DATA_OFFSET]
        .copy_from_slice(&entry._pad);
    bytes[GUEST_INTROSPECTION_ENTRY_DATA_OFFSET..GUEST_INTROSPECTION_ENTRY_RESERVED_OFFSET]
        .copy_from_slice(&entry.data);
    bytes[GUEST_INTROSPECTION_ENTRY_RESERVED_OFFSET..GUEST_INTROSPECTION_ENTRY_SIZE]
        .copy_from_slice(&entry._reserved);
}

pub(super) fn write_u8_at(bytes: &mut [u8], offset: usize, value: u8) {
    bytes[offset] = value;
}

pub(super) fn write_u16_at(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

pub(super) fn write_u32_at(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

pub(super) fn write_u64_at(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

pub(crate) fn validate_pending_input_source(
    input_index: usize,
    expected_src_slot: u32,
    frame: &FrameEntry,
) -> Result<(), SchedulerWakePublicationError> {
    if frame.src_node == expected_src_slot {
        Ok(())
    } else {
        Err(SchedulerWakePublicationError::FrameSourceMismatch {
            input_index,
            expected_src_slot,
            frame_src_node: frame.src_node,
        })
    }
}

pub(crate) fn preflight_ring_enqueue_capacity(
    ring: &RingHeader,
    entries: &[FrameEntry],
    batch_count: impl TryInto<u64>,
) -> Result<(), SpscRingError> {
    let capacity = validated_capacity(entries)?;
    let live = live_count(ring.read_index(), ring.write_index(), capacity)?;
    let batch_count = batch_count.try_into().unwrap_or(u64::MAX);
    if batch_count > capacity.saturating_sub(live) {
        Err(SpscRingError::QueueFull { capacity })
    } else {
        Ok(())
    }
}

pub(super) fn wake_all_slots_for_control<'a>(
    slots: impl IntoIterator<Item = &'a NodeSlot>,
) -> Result<WakeAllResult, RegionControlError> {
    let mut slots_signaled = 0;
    let mut waiters_woken = 0_u64;
    for (slot_index, slot) in slots.into_iter().enumerate() {
        let action = slot
            .wake_after_signal_increment()
            .map_err(|source| RegionControlError::WakeSlot { slot_index, source })?;
        let WakeAction::Wake { futex, .. } = action;
        slots_signaled += 1;
        waiters_woken += u64::from(futex.waiters_woken);
    }
    Ok(WakeAllResult {
        slots_signaled,
        waiters_woken,
    })
}
