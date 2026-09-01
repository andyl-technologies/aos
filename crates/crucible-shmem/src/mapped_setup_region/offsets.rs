//! Setup-region seal validation and checked segment-offset calculation.

use super::*;

#[cfg(target_os = "linux")]
pub(super) fn verify_setup_region_shrink_seal(
    fd: BorrowedFd<'_>,
) -> Result<(), SetupRegionMapError> {
    // SAFETY: `fd` is borrowed and live. `F_GET_SEALS` reads descriptor metadata
    // without modifying the underlying file.
    let seals = unsafe { libc::fcntl(fd.as_raw_fd(), libc::F_GET_SEALS) };
    if seals < 0 {
        let errno = std::io::Error::last_os_error().raw_os_error().unwrap_or(0);
        if errno == libc::EINVAL {
            return Ok(());
        }
        return Err(SetupRegionMapError::SealQueryFailed { errno });
    }
    if seals & libc::F_SEAL_SHRINK == 0 {
        return Err(SetupRegionMapError::MissingShrinkSeal { seals });
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub(super) const fn verify_setup_region_shrink_seal(
    _fd: BorrowedFd<'_>,
) -> Result<(), SetupRegionMapError> {
    Ok(())
}

pub(super) fn directed_ring_descriptor(
    vm_node_count: u32,
    src_slot: u32,
    dst_slot: u32,
) -> Result<DirectedRing, MappedSetupRegionAccessError> {
    directed_rings(vm_node_count)
        .map_err(|source| MappedSetupRegionAccessError::RingTopology { source })?
        .into_iter()
        .find(|ring| ring.src_slot == src_slot && ring.dst_slot == dst_slot)
        .ok_or(MappedSetupRegionAccessError::UnknownDirectedRing { src_slot, dst_slot })
}

pub(super) fn mapped_node_slot_offset(
    layout: RegionLayout,
    region_len: usize,
    slot: u32,
) -> Result<usize, MappedSetupRegionAccessError> {
    if slot >= layout.node_count {
        return Err(MappedSetupRegionAccessError::UnknownNodeSlot { slot });
    }
    mapped_segment_offset(
        "node slot",
        slot,
        layout.node_slots_off,
        NODE_SLOT_SIZE,
        NODE_SLOT_ALIGN,
        region_len,
    )
}

pub(super) fn mapped_ring_header_offset(
    layout: RegionLayout,
    region_len: usize,
    ring: DirectedRing,
) -> Result<usize, MappedSetupRegionAccessError> {
    if ring.index >= layout.ring_count {
        return Err(MappedSetupRegionAccessError::SegmentOffsetOverflow {
            segment: "ring header",
            index: ring.index,
        });
    }
    mapped_segment_offset(
        "ring header",
        ring.index,
        layout.ring_hdr_off,
        RING_HEADER_SIZE,
        RING_HEADER_ALIGN,
        region_len,
    )
}

pub(super) fn mapped_ring_entries_offset(
    layout: RegionLayout,
    region_len: usize,
    ring: DirectedRing,
) -> Result<usize, MappedSetupRegionAccessError> {
    if ring.index >= layout.ring_count {
        return Err(MappedSetupRegionAccessError::SegmentOffsetOverflow {
            segment: "frame entry",
            index: ring.index,
        });
    }
    let capacity = usize::try_from(layout.queue_capacity).map_err(|_error| {
        MappedSetupRegionAccessError::SegmentOffsetOverflow {
            segment: "frame entry",
            index: ring.index,
        }
    })?;
    let byte_len = capacity.checked_mul(FRAME_ENTRY_SIZE).ok_or(
        MappedSetupRegionAccessError::SegmentOffsetOverflow {
            segment: "frame entry",
            index: ring.index,
        },
    )?;
    mapped_segment_offset(
        "frame entry",
        ring.index,
        layout.ring_data_off,
        byte_len,
        FRAME_ENTRY_ALIGN,
        region_len,
    )
}

pub(super) fn mapped_coverage_ring_header_offset(
    layout: RegionLayout,
    region_len: usize,
    vm_slot: u32,
) -> Result<usize, MappedSetupRegionAccessError> {
    mapped_segment_offset(
        "coverage ring header",
        vm_slot,
        layout.coverage_ring_hdr_off,
        RING_HEADER_SIZE,
        RING_HEADER_ALIGN,
        region_len,
    )
}

pub(super) fn mapped_coverage_ring_entries_offset(
    layout: RegionLayout,
    region_len: usize,
    vm_slot: u32,
) -> Result<usize, MappedSetupRegionAccessError> {
    let capacity = usize::try_from(layout.coverage_queue_capacity).map_err(|_error| {
        MappedSetupRegionAccessError::SegmentOffsetOverflow {
            segment: "coverage entry",
            index: vm_slot,
        }
    })?;
    let byte_len = capacity.checked_mul(COVERAGE_ENTRY_SIZE).ok_or(
        MappedSetupRegionAccessError::SegmentOffsetOverflow {
            segment: "coverage entry",
            index: vm_slot,
        },
    )?;
    mapped_segment_offset(
        "coverage entry",
        vm_slot,
        layout.coverage_ring_data_off,
        byte_len,
        COVERAGE_ENTRY_ALIGN,
        region_len,
    )
}

pub(super) fn mapped_fingerprint_sample_offset(
    layout: RegionLayout,
    region_len: usize,
    vm_slot: u32,
) -> Result<usize, MappedSetupRegionAccessError> {
    mapped_segment_offset(
        "fingerprint sample",
        vm_slot,
        layout.fingerprint_sample_off,
        FINGERPRINT_SAMPLE_SLOT_SIZE,
        FINGERPRINT_SAMPLE_SLOT_ALIGN,
        region_len,
    )
}

pub(super) fn mapped_whitebox_marker_ring_header_offset(
    layout: RegionLayout,
    region_len: usize,
    vm_slot: u32,
) -> Result<usize, MappedSetupRegionAccessError> {
    mapped_segment_offset(
        "white-box marker ring header",
        vm_slot,
        layout.whitebox_marker_ring_hdr_off,
        RING_HEADER_SIZE,
        RING_HEADER_ALIGN,
        region_len,
    )
}

pub(super) fn mapped_whitebox_marker_ring_entries_offset(
    layout: RegionLayout,
    region_len: usize,
    vm_slot: u32,
) -> Result<usize, MappedSetupRegionAccessError> {
    let capacity = usize::try_from(layout.whitebox_marker_queue_capacity).map_err(|_error| {
        MappedSetupRegionAccessError::SegmentOffsetOverflow {
            segment: "white-box marker entry",
            index: vm_slot,
        }
    })?;
    let byte_len = capacity.checked_mul(WHITEBOX_MARKER_ENTRY_SIZE).ok_or(
        MappedSetupRegionAccessError::SegmentOffsetOverflow {
            segment: "white-box marker entry",
            index: vm_slot,
        },
    )?;
    mapped_segment_offset(
        "white-box marker entry",
        vm_slot,
        layout.whitebox_marker_ring_data_off,
        byte_len,
        WHITEBOX_MARKER_ENTRY_ALIGN,
        region_len,
    )
}

pub(super) fn validate_fault_vm_slot(
    layout: RegionLayout,
    vm_slot: u32,
    segment: &'static str,
) -> Result<(), MappedSetupRegionAccessError> {
    if vm_slot >= layout.vm_node_count {
        return Err(MappedSetupRegionAccessError::UnknownFaultTransport {
            segment,
            vm_slot,
            vm_node_count: layout.vm_node_count,
        });
    }
    Ok(())
}

pub(super) fn mapped_fault_ring_header_offset(
    base: u64,
    count: u32,
    region_len: usize,
    vm_slot: u32,
    segment: &'static str,
) -> Result<usize, MappedSetupRegionAccessError> {
    if vm_slot >= count {
        return Err(MappedSetupRegionAccessError::UnknownFaultTransport {
            segment,
            vm_slot,
            vm_node_count: count,
        });
    }
    mapped_segment_offset(
        segment,
        vm_slot,
        base,
        RING_HEADER_SIZE,
        RING_HEADER_ALIGN,
        region_len,
    )
}

pub(super) fn mapped_guest_introspection_ring_header_offset(
    layout: RegionLayout,
    region_len: usize,
    ring_index: u32,
) -> Result<usize, MappedSetupRegionAccessError> {
    mapped_segment_offset(
        "guest-introspection ring header",
        ring_index,
        layout.guest_introspection_ring_hdr_off,
        RING_HEADER_SIZE,
        RING_HEADER_ALIGN,
        region_len,
    )
}

pub(super) fn mapped_accelerator_ring_header_offset(
    layout: RegionLayout,
    region_len: usize,
    ring_index: u32,
) -> Result<usize, MappedSetupRegionAccessError> {
    mapped_segment_offset(
        "accelerator ring header",
        ring_index,
        layout.accelerator_ring_hdr_off,
        RING_HEADER_SIZE,
        RING_HEADER_ALIGN,
        region_len,
    )
}

pub(super) fn mapped_fault_slot_offset(
    base: u64,
    count: u32,
    capacity: u32,
    slot_size: usize,
    region_len: usize,
    vm_slot: u32,
    segment: &'static str,
) -> Result<usize, MappedSetupRegionAccessError> {
    if vm_slot >= count {
        return Err(MappedSetupRegionAccessError::UnknownFaultTransport {
            segment,
            vm_slot,
            vm_node_count: count,
        });
    }
    let byte_len = usize::try_from(capacity)
        .ok()
        .and_then(|capacity| capacity.checked_mul(slot_size))
        .ok_or(MappedSetupRegionAccessError::SegmentOffsetOverflow {
            segment,
            index: vm_slot,
        })?;
    mapped_segment_offset(segment, vm_slot, base, byte_len, 64, region_len)
}

pub(super) fn mapped_fault_arena_header_offset(
    base: u64,
    count: u32,
    region_len: usize,
    vm_slot: u32,
    segment: &'static str,
) -> Result<usize, MappedSetupRegionAccessError> {
    if vm_slot >= count {
        return Err(MappedSetupRegionAccessError::UnknownFaultTransport {
            segment,
            vm_slot,
            vm_node_count: count,
        });
    }
    mapped_segment_offset(
        segment,
        vm_slot,
        base,
        FAULT_PAYLOAD_ARENA_HEADER_BYTES,
        FAULT_PAYLOAD_ARENA_HEADER_BYTES,
        region_len,
    )
}

pub(super) fn mapped_guest_introspection_ring_entries_offset(
    layout: RegionLayout,
    region_len: usize,
    ring_index: u32,
) -> Result<usize, MappedSetupRegionAccessError> {
    let capacity =
        usize::try_from(layout.guest_introspection_queue_capacity).map_err(|_error| {
            MappedSetupRegionAccessError::SegmentOffsetOverflow {
                segment: "guest-introspection entry",
                index: ring_index,
            }
        })?;
    let byte_len = capacity.checked_mul(GUEST_INTROSPECTION_ENTRY_SIZE).ok_or(
        MappedSetupRegionAccessError::SegmentOffsetOverflow {
            segment: "guest-introspection entry",
            index: ring_index,
        },
    )?;
    mapped_segment_offset(
        "guest-introspection entry",
        ring_index,
        layout.guest_introspection_ring_data_off,
        byte_len,
        GUEST_INTROSPECTION_ENTRY_ALIGN,
        region_len,
    )
}

pub(super) fn mapped_accelerator_ring_entries_offset(
    layout: RegionLayout,
    region_len: usize,
    ring_index: u32,
) -> Result<usize, MappedSetupRegionAccessError> {
    let capacity = usize::try_from(layout.accelerator_queue_capacity).map_err(|_error| {
        MappedSetupRegionAccessError::SegmentOffsetOverflow {
            segment: "accelerator entry",
            index: ring_index,
        }
    })?;
    let byte_len = capacity.checked_mul(ACCELERATOR_ENTRY_SIZE).ok_or(
        MappedSetupRegionAccessError::SegmentOffsetOverflow {
            segment: "accelerator entry",
            index: ring_index,
        },
    )?;
    mapped_segment_offset(
        "accelerator entry",
        ring_index,
        layout.accelerator_ring_data_off,
        byte_len,
        ACCELERATOR_ENTRY_ALIGN,
        region_len,
    )
}

pub(super) fn mapped_fault_arena_offset(
    base: u64,
    stride: u64,
    count: u32,
    region_len: usize,
    vm_slot: u32,
    segment: &'static str,
) -> Result<usize, MappedSetupRegionAccessError> {
    if vm_slot >= count {
        return Err(MappedSetupRegionAccessError::UnknownFaultTransport {
            segment,
            vm_slot,
            vm_node_count: count,
        });
    }
    let len = usize::try_from(stride).map_err(|_| {
        MappedSetupRegionAccessError::SegmentOffsetOverflow {
            segment,
            index: vm_slot,
        }
    })?;
    mapped_segment_offset(segment, vm_slot, base, len, 1, region_len)
}

pub(super) fn mapped_segment_offset(
    segment: &'static str,
    index: u32,
    base: u64,
    len: usize,
    alignment: usize,
    region_len: usize,
) -> Result<usize, MappedSetupRegionAccessError> {
    let len_u64 = u64::try_from(len)
        .map_err(|_error| MappedSetupRegionAccessError::SegmentOffsetOverflow { segment, index })?;
    let offset = u64::from(index)
        .checked_mul(len_u64)
        .and_then(|offset| base.checked_add(offset))
        .ok_or(MappedSetupRegionAccessError::SegmentOffsetOverflow { segment, index })?;
    let offset = usize::try_from(offset)
        .map_err(|_error| MappedSetupRegionAccessError::SegmentOffsetOverflow { segment, index })?;
    let end = offset
        .checked_add(len)
        .ok_or(MappedSetupRegionAccessError::SegmentOffsetOverflow { segment, index })?;
    if end > region_len {
        return Err(MappedSetupRegionAccessError::SegmentOutOfBounds {
            segment,
            index,
            offset,
            len,
            region_len,
        });
    }
    if !offset.is_multiple_of(alignment) {
        return Err(MappedSetupRegionAccessError::SegmentUnaligned {
            segment,
            index,
            offset,
            alignment,
        });
    }
    Ok(offset)
}
