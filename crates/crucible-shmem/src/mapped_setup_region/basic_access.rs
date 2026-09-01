//! Header, node, directed-ring, coverage, and marker mapped access.

use super::*;

impl MappedSetupRegion {
    pub(super) fn base_ptr(&self) -> *mut u8 {
        self.address as *mut u8
    }

    /// Returns the mapped length supplied by the control-protocol `Setup` frame.
    #[must_use]
    pub const fn region_len(&self) -> u64 {
        self.region_len
    }

    /// Borrows the mapped region header for cross-process atomic operations.
    ///
    /// The reference remains tied to this mapping's lifetime. Callers must use
    /// the header's atomic accessors and must not retain the reference after the
    /// mapping owner is dropped.
    #[must_use]
    pub fn header(&self) -> &RegionHeader {
        // SAFETY: `mmap_setup_region` validates that the live mapping is large
        // enough and correctly aligned for `RegionHeader` before constructing
        // `Self`. The returned borrow cannot outlive this mapping owner.
        unsafe { &*self.base_ptr().cast::<RegionHeader>() }
    }

    /// Returns an acquire snapshot of the mapped region header.
    #[must_use]
    pub fn header_snapshot(&self) -> crate::RegionHeaderSnapshot {
        self.header().snapshot()
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

    /// Borrows one mapped node slot after validating the current region geometry.
    ///
    /// The returned reference remains tied to this mapping, while the slot's
    /// interior atomic fields support the plugin and scheduler's cross-process
    /// publication protocol without requiring a mutable mapping borrow.
    ///
    /// # Errors
    ///
    /// Returns [`MappedSetupRegionAccessError`] when the mapped header is
    /// invalid, the requested slot is absent, or its typed segment would be out
    /// of bounds or misaligned.
    pub fn node_slot(&self, node_slot: u32) -> Result<&NodeSlot, MappedSetupRegionAccessError> {
        let layout = self
            .layout()
            .map_err(|source| MappedSetupRegionAccessError::Header { source })?;
        let node_slot_offset = mapped_node_slot_offset(layout, self.len, node_slot)?;
        let base = self.base_ptr();
        // SAFETY: `mapped_node_slot_offset` validated the slot index, byte
        // range, and ABI alignment against this live owned mapping.
        Ok(unsafe { &*base.add(node_slot_offset).cast::<NodeSlot>() })
    }

    /// Borrows one mapped node slot, its fingerprint sample, and two distinct
    /// directed rings.
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
        let fingerprint_sample_offset =
            mapped_fingerprint_sample_offset(layout, self.len, node_slot)?;
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

        let base = self.base_ptr();
        let mapped_parts = {
            // SAFETY: all offsets and byte lengths were checked against the owned
            // mapping, alignment was validated for each typed segment, and duplicate
            // ring indices were rejected so the returned mutable slices are disjoint.
            unsafe {
                (
                    &*base.add(node_slot_offset).cast::<NodeSlot>(),
                    &*base
                        .add(fingerprint_sample_offset)
                        .cast::<FingerprintSampleSlot>(),
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
            }
        };
        let (
            node_slot_ref,
            fingerprint_sample,
            first_header,
            second_header,
            first_entries,
            second_entries,
        ) = mapped_parts;
        Ok(MappedNodeRingPairMut {
            node_slot: node_slot_ref,
            fingerprint_sample,
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

    /// Borrows one VM's dedicated plugin-to-host coverage ring.
    ///
    /// The VM slot is also the coverage-ring index. The current ABI allocates
    /// exactly one ring per logical VM and fixes its capacity to the coverage-map
    /// cardinality, so producer overflow indicates an ABI or novelty invariant
    /// violation rather than normal backpressure.
    /// The caller must retain the plugin-producer/host-consumer ownership split
    /// documented on [`MappedCoverageRingMut`].
    ///
    /// # Errors
    ///
    /// Returns [`MappedSetupRegionAccessError`] when the mapped header is
    /// invalid, `vm_slot` does not name a logical VM, or a computed coverage
    /// segment is out of bounds or misaligned.
    pub fn coverage_ring_mut(
        &mut self,
        vm_slot: u32,
    ) -> Result<MappedCoverageRingMut<'_>, MappedSetupRegionAccessError> {
        let layout = self
            .layout()
            .map_err(|source| MappedSetupRegionAccessError::Header { source })?;
        if vm_slot >= layout.vm_node_count {
            return Err(MappedSetupRegionAccessError::UnknownCoverageRing {
                vm_slot,
                vm_node_count: layout.vm_node_count,
            });
        }
        let header_offset = mapped_coverage_ring_header_offset(layout, self.len, vm_slot)?;
        let entries_offset = mapped_coverage_ring_entries_offset(layout, self.len, vm_slot)?;
        let entry_count = usize::try_from(layout.coverage_queue_capacity).map_err(|_error| {
            MappedSetupRegionAccessError::SegmentOffsetOverflow {
                segment: "coverage entry",
                index: vm_slot,
            }
        })?;
        let base = self.base_ptr();
        // SAFETY: the coverage offset helpers validate the complete typed ranges
        // and alignments inside this owned mapping. Each VM slot names a distinct
        // header and entry slice, and this exclusive mapping borrow prevents a
        // second safe mutable coverage view while the returned view is live.
        let (header, entries) = unsafe {
            (
                &*base.add(header_offset).cast::<RingHeader>(),
                core::slice::from_raw_parts_mut(
                    base.add(entries_offset).cast::<CoverageEntry>(),
                    entry_count,
                ),
            )
        };
        Ok(MappedCoverageRingMut {
            vm_slot,
            header,
            entries,
        })
    }

    /// Borrows one VM's dedicated plugin-to-host white-box marker ring.
    ///
    /// # Errors
    ///
    /// Returns [`MappedSetupRegionAccessError`] when the mapped header is
    /// invalid, `vm_slot` does not name a logical VM, or a computed marker
    /// segment is out of bounds or misaligned.
    pub fn whitebox_marker_ring_mut(
        &mut self,
        vm_slot: u32,
    ) -> Result<MappedWhiteboxMarkerRingMut<'_>, MappedSetupRegionAccessError> {
        let layout = self
            .layout()
            .map_err(|source| MappedSetupRegionAccessError::Header { source })?;
        if vm_slot >= layout.whitebox_marker_ring_count {
            return Err(MappedSetupRegionAccessError::UnknownWhiteboxMarkerRing {
                vm_slot,
                vm_node_count: layout.vm_node_count,
            });
        }
        let header_offset = mapped_whitebox_marker_ring_header_offset(layout, self.len, vm_slot)?;
        let entries_offset = mapped_whitebox_marker_ring_entries_offset(layout, self.len, vm_slot)?;
        let entry_count =
            usize::try_from(layout.whitebox_marker_queue_capacity).map_err(|_error| {
                MappedSetupRegionAccessError::SegmentOffsetOverflow {
                    segment: "white-box marker entry",
                    index: vm_slot,
                }
            })?;
        let base = self.base_ptr();
        // SAFETY: the marker offset helpers validate the complete typed ranges
        // and alignments inside this owned mapping. Each VM names a distinct
        // SPSC slice, and the exclusive mapping borrow prevents safe aliasing.
        let (header, entries) = unsafe {
            (
                &*base.add(header_offset).cast::<RingHeader>(),
                core::slice::from_raw_parts_mut(
                    base.add(entries_offset).cast::<WhiteboxMarkerEntry>(),
                    entry_count,
                ),
            )
        };
        Ok(MappedWhiteboxMarkerRingMut {
            vm_slot,
            header,
            entries,
        })
    }
}
