//! Owned setup-region mappings and typed accessors.

use std::os::fd::{AsRawFd, BorrowedFd};
use std::ptr::NonNull;

use thiserror::Error;

use super::{
    DirectedRing, FRAME_ENTRY_ALIGN, FRAME_ENTRY_SIZE, FrameEntry, NODE_SLOT_ALIGN, NODE_SLOT_SIZE,
    NodeSlot, REGION_HEADER_ALIGN, REGION_HEADER_SIZE, RING_HEADER_ALIGN, RING_HEADER_SIZE,
    RegionHeader, RegionLayout, RegionLayoutError, RegionSetupValidationError, RingHeader,
    ValidatedSetupRegion, directed_rings, layout_from_setup_region_header,
    validate_setup_region_header,
};

/// An owned setup-time `mmap` of the shared-memory region descriptor.
pub struct MappedSetupRegion {
    ptr: NonNull<u8>,
    len: usize,
    region_len: u64,
}

/// A mutable view of one mapped directed ring.
pub struct MappedDirectedRingMut<'a> {
    /// Directed ring descriptor from the validated region topology.
    pub descriptor: DirectedRing,
    /// Ring header shared by the producer and consumer.
    pub header: &'a RingHeader,
    /// Frame-entry backing storage for this ring.
    pub entries: &'a mut [FrameEntry],
}

/// A mutable view of two distinct mapped directed rings and one node slot.
pub struct MappedNodeRingPairMut<'a> {
    /// Node slot associated with the consumer VM.
    pub node_slot: &'a NodeSlot,
    /// First directed ring requested by the caller.
    pub first: MappedDirectedRingMut<'a>,
    /// Second directed ring requested by the caller.
    pub second: MappedDirectedRingMut<'a>,
}

impl MappedSetupRegion {
    /// Returns the mapped length supplied by the control-protocol `Setup` frame.
    #[must_use]
    pub const fn region_len(&self) -> u64 {
        self.region_len
    }

    /// Returns an acquire snapshot of the mapped region header.
    #[must_use]
    pub fn header_snapshot(&self) -> super::RegionHeaderSnapshot {
        // SAFETY: `mmap_setup_region` checks the mapping is large enough for
        // `RegionHeader` and aligned for the ABI before constructing `Self`.
        let header = unsafe { &*self.ptr.as_ptr().cast::<RegionHeader>() };
        header.snapshot()
    }

    /// Validates the mapped header against the current shared-memory ABI.
    ///
    /// # Errors
    ///
    /// Returns [`RegionSetupValidationError`] when the header magic, ABI
    /// version, or region-size field does not match the setup contract.
    pub fn validate_header(&self) -> Result<ValidatedSetupRegion, RegionSetupValidationError> {
        validate_setup_region_header(self.header_snapshot(), self.region_len)
    }

    /// Recomputes the validated shared-memory layout from the mapped header.
    ///
    /// # Errors
    ///
    /// Returns [`RegionSetupValidationError`] when the mapped header no longer
    /// matches the current shared-memory ABI or geometry.
    pub fn layout(&self) -> Result<RegionLayout, RegionSetupValidationError> {
        layout_from_setup_region_header(self.header_snapshot(), self.region_len)
    }

    /// Borrows one mapped node slot and two distinct directed rings.
    ///
    /// This accessor is the runtime bridge for host adapters that need a VM
    /// slot plus an inbound and outbound SPSC ring from an owned mapping. It
    /// validates the header before deriving typed references and rejects aliasing
    /// ring requests so the returned frame-entry slices are disjoint.
    ///
    /// # Errors
    ///
    /// Returns [`MappedSetupRegionAccessError`] when the mapped header is
    /// invalid, a requested node or directed ring is absent, the same ring is
    /// requested twice, or a computed typed segment would be out of bounds.
    pub fn node_directed_ring_pair_mut(
        &mut self,
        node_slot: u32,
        first_src_slot: u32,
        first_dst_slot: u32,
        second_src_slot: u32,
        second_dst_slot: u32,
    ) -> Result<MappedNodeRingPairMut<'_>, MappedSetupRegionAccessError> {
        let layout = self
            .layout()
            .map_err(|source| MappedSetupRegionAccessError::Header { source })?;
        let first_descriptor =
            directed_ring_descriptor(layout.vm_node_count, first_src_slot, first_dst_slot)?;
        let second_descriptor =
            directed_ring_descriptor(layout.vm_node_count, second_src_slot, second_dst_slot)?;
        if first_descriptor.index == second_descriptor.index {
            return Err(MappedSetupRegionAccessError::DuplicateDirectedRing {
                ring_index: first_descriptor.index,
            });
        }

        let node_slot_offset = mapped_node_slot_offset(layout, self.len, node_slot)?;
        let first_header_offset = mapped_ring_header_offset(layout, self.len, first_descriptor)?;
        let second_header_offset = mapped_ring_header_offset(layout, self.len, second_descriptor)?;
        let first_entries_offset = mapped_ring_entries_offset(layout, self.len, first_descriptor)?;
        let second_entries_offset =
            mapped_ring_entries_offset(layout, self.len, second_descriptor)?;
        let first_entry_count = usize::try_from(layout.queue_capacity).map_err(|_error| {
            MappedSetupRegionAccessError::SegmentOffsetOverflow {
                segment: "frame entry",
                index: first_descriptor.index,
            }
        })?;
        let second_entry_count = usize::try_from(layout.queue_capacity).map_err(|_error| {
            MappedSetupRegionAccessError::SegmentOffsetOverflow {
                segment: "frame entry",
                index: second_descriptor.index,
            }
        })?;

        let base = self.ptr.as_ptr();
        // SAFETY: all offsets and byte lengths were checked against the owned
        // mapping, alignment was validated for each typed segment, and duplicate
        // ring indices were rejected so the returned mutable slices are disjoint.
        let (node_slot_ref, first_header, second_header, first_entries, second_entries) = unsafe {
            (
                &*base.add(node_slot_offset).cast::<NodeSlot>(),
                &*base.add(first_header_offset).cast::<RingHeader>(),
                &*base.add(second_header_offset).cast::<RingHeader>(),
                core::slice::from_raw_parts_mut(
                    base.add(first_entries_offset).cast::<FrameEntry>(),
                    first_entry_count,
                ),
                core::slice::from_raw_parts_mut(
                    base.add(second_entries_offset).cast::<FrameEntry>(),
                    second_entry_count,
                ),
            )
        };
        Ok(MappedNodeRingPairMut {
            node_slot: node_slot_ref,
            first: MappedDirectedRingMut {
                descriptor: first_descriptor,
                header: first_header,
                entries: first_entries,
            },
            second: MappedDirectedRingMut {
                descriptor: second_descriptor,
                header: second_header,
                entries: second_entries,
            },
        })
    }
}

impl Drop for MappedSetupRegion {
    fn drop(&mut self) {
        // SAFETY: `ptr` and `len` were returned by `mmap` and are owned by this
        // value until `Drop`.
        unsafe {
            libc::munmap(self.ptr.as_ptr().cast::<libc::c_void>(), self.len);
        }
    }
}

/// Maps a setup shared-memory descriptor for exactly the `Setup.region_len`.
///
/// # Errors
///
/// Returns [`SetupRegionMapError`] when `region_len` cannot fit in `usize`, is
/// too small for a [`RegionHeader`], or when `mmap` fails or returns a mapping
/// unsuitable for the shared-memory ABI.
pub fn mmap_setup_region(
    fd: BorrowedFd<'_>,
    region_len: u64,
) -> Result<MappedSetupRegion, SetupRegionMapError> {
    let len = usize::try_from(region_len)
        .map_err(|_| SetupRegionMapError::RegionLenTooLarge { region_len })?;
    let minimum_len = REGION_HEADER_SIZE as u64;
    if region_len < minimum_len {
        return Err(SetupRegionMapError::RegionTooSmall {
            region_len,
            minimum_len,
        });
    }

    // SAFETY: the returned mapping is checked before being wrapped. The fd is
    // borrowed for the syscall only; the mapping owns the resulting address.
    let raw = unsafe {
        libc::mmap(
            core::ptr::null_mut(),
            len,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_SHARED,
            fd.as_raw_fd(),
            0,
        )
    };
    if raw == libc::MAP_FAILED {
        return Err(SetupRegionMapError::MmapFailed {
            errno: last_os_error(),
        });
    }

    let Some(ptr) = NonNull::new(raw.cast::<u8>()) else {
        unmap_setup_region(raw, len);
        return Err(SetupRegionMapError::NullMapping);
    };
    if !(ptr.as_ptr() as usize).is_multiple_of(REGION_HEADER_ALIGN) {
        unmap_setup_region(raw, len);
        return Err(SetupRegionMapError::UnalignedMapping {
            alignment: REGION_HEADER_ALIGN,
        });
    }

    Ok(MappedSetupRegion {
        ptr,
        len,
        region_len,
    })
}

/// An error produced while borrowing typed objects from a mapped setup region.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum MappedSetupRegionAccessError {
    /// The mapped region header failed ABI or geometry validation.
    #[error("mapped setup region header validation failed")]
    Header {
        /// Underlying header validation error.
        source: RegionSetupValidationError,
    },
    /// A node slot index was outside the validated physical slot table.
    #[error("mapped setup region has no node slot {slot}")]
    UnknownNodeSlot {
        /// Rejected physical node slot.
        slot: u32,
    },
    /// A directed ring was absent from the validated topology.
    #[error("mapped setup region has no directed ring from slot {src_slot} to slot {dst_slot}")]
    UnknownDirectedRing {
        /// Producer slot.
        src_slot: u32,
        /// Consumer slot.
        dst_slot: u32,
    },
    /// The validated ring topology could not be enumerated.
    #[error("mapped setup region directed-ring topology is invalid")]
    RingTopology {
        /// Underlying layout error.
        source: RegionLayoutError,
    },
    /// The same directed ring was requested for both mutable views.
    #[error("mapped setup region directed ring {ring_index} was requested twice")]
    DuplicateDirectedRing {
        /// Duplicated directed-ring index.
        ring_index: u32,
    },
    /// A typed segment offset overflowed local address arithmetic.
    #[error("mapped setup region {segment} index {index} offset overflowed")]
    SegmentOffsetOverflow {
        /// Segment kind being borrowed.
        segment: &'static str,
        /// Segment index within its array.
        index: u32,
    },
    /// A typed segment would extend beyond the mapping.
    #[error(
        "mapped setup region {segment} index {index} at byte {offset} with length {len} extends past mapping length {region_len}"
    )]
    SegmentOutOfBounds {
        /// Segment kind being borrowed.
        segment: &'static str,
        /// Segment index within its array.
        index: u32,
        /// Computed byte offset.
        offset: usize,
        /// Segment length in bytes.
        len: usize,
        /// Total mapped length in bytes.
        region_len: usize,
    },
    /// A typed segment offset did not satisfy the ABI alignment.
    #[error(
        "mapped setup region {segment} index {index} at byte {offset} is not aligned to {alignment}"
    )]
    SegmentUnaligned {
        /// Segment kind being borrowed.
        segment: &'static str,
        /// Segment index within its array.
        index: u32,
        /// Computed byte offset.
        offset: usize,
        /// Required byte alignment.
        alignment: usize,
    },
}

/// An error produced while mapping a setup shared-memory descriptor.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SetupRegionMapError {
    /// The `Setup.region_len` cannot be represented as a process-local mapping length.
    #[error("setup region length {region_len} cannot fit in usize")]
    RegionLenTooLarge {
        /// The rejected `Setup.region_len`.
        region_len: u64,
    },
    /// The `Setup.region_len` is too small to contain a shared-memory header.
    #[error("setup region length {region_len} is smaller than header size {minimum_len}")]
    RegionTooSmall {
        /// The rejected `Setup.region_len`.
        region_len: u64,
        /// The minimum mappable length required for the header.
        minimum_len: u64,
    },
    /// The OS rejected the shared-memory `mmap`.
    #[error("setup region mmap failed with errno {errno}")]
    MmapFailed {
        /// Raw OS errno value.
        errno: i32,
    },
    /// The OS returned a null mapping address.
    #[error("setup region mmap returned a null address")]
    NullMapping,
    /// The mapping base is not aligned for [`RegionHeader`].
    #[error("setup region mmap base is not aligned to {alignment} bytes")]
    UnalignedMapping {
        /// Required ABI alignment.
        alignment: usize,
    },
}

fn directed_ring_descriptor(
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

fn mapped_node_slot_offset(
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

fn mapped_ring_header_offset(
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

fn mapped_ring_entries_offset(
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

fn mapped_segment_offset(
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

fn unmap_setup_region(ptr: *mut libc::c_void, len: usize) {
    // SAFETY: callers pass an address and length returned by `mmap`.
    unsafe {
        libc::munmap(ptr, len);
    }
}

fn last_os_error() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}
