//! Owned setup-region mappings and typed accessors.

use std::mem::MaybeUninit;
use std::os::fd::{AsRawFd, BorrowedFd};
use std::ptr::NonNull;

use thiserror::Error;

use super::{
    ACCELERATOR_ENTRY_ALIGN, ACCELERATOR_ENTRY_SIZE, AcceleratorEntry,
    AcceleratorRingDirection,
    COVERAGE_ENTRY_ALIGN, COVERAGE_ENTRY_SIZE, CoverageEntry, DirectedRing,
    FAULT_COMMAND_SLOT_V1_BYTES, FAULT_EVENT_SLOT_V1_BYTES, FAULT_PAYLOAD_ARENA_HEADER_BYTES,
    FAULT_RESULT_SLOT_V1_BYTES, FINGERPRINT_SAMPLE_SLOT_ALIGN, FINGERPRINT_SAMPLE_SLOT_SIZE,
    FRAME_ENTRY_ALIGN, FRAME_ENTRY_SIZE, FaultCommandSlotV1, FaultEventSlotV1,
    FaultPayloadArenaHeader, FaultResultSlotV1, FingerprintSampleSlot, FrameEntry,
    GUEST_INTROSPECTION_ENTRY_ALIGN, GUEST_INTROSPECTION_ENTRY_SIZE, GuestIntrospectionEntry,
    GuestIntrospectionRingDirection, NODE_SLOT_ALIGN, NODE_SLOT_SIZE, NodeSlot,
    REGION_HEADER_ALIGN, REGION_HEADER_SIZE, RING_HEADER_ALIGN, RING_HEADER_SIZE, RegionHeader,
    RegionLayout, RegionLayoutError, RegionSetupValidationError, RingHeader, SpscRingError,
    ValidatedSetupRegion, WHITEBOX_MARKER_ENTRY_ALIGN, WHITEBOX_MARKER_ENTRY_SIZE,
    WhiteboxMarkerEntry, directed_rings, layout_from_setup_region_header,
    validate_setup_region_header,
};

/// Producer-only access to one directional accelerator ring.
pub struct MappedAcceleratorProducerRingMut<'a> {
    /// Logical VM that owns this direction.
    pub vm_slot: u32,
    /// Fixed producer/consumer direction.
    pub direction: AcceleratorRingDirection,
    header: &'a RingHeader,
    entries: &'a mut [AcceleratorEntry],
}

impl MappedAcceleratorProducerRingMut<'_> {
    /// Enqueues one validated accelerator record.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] for invalid geometry, indices, or exhaustion.
    pub fn enqueue(&mut self, entry: AcceleratorEntry) -> Result<(), SpscRingError> {
        self.header.enqueue_accelerator(self.entries, entry)
    }
}

/// Consumer-only access to one directional accelerator ring.
pub struct MappedAcceleratorConsumerRingMut<'a> {
    /// Logical VM that owns this direction.
    pub vm_slot: u32,
    /// Fixed producer/consumer direction.
    pub direction: AcceleratorRingDirection,
    header: &'a RingHeader,
    entries: &'a mut [AcceleratorEntry],
}

impl MappedAcceleratorConsumerRingMut<'_> {
    /// Dequeues and validates one accelerator record.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] for invalid geometry, indices, or records.
    pub fn dequeue(&mut self) -> Result<Option<AcceleratorEntry>, SpscRingError> {
        self.header.dequeue_accelerator(self.entries)
    }
}

/// QEMU/plugin-side accelerator roles.
pub struct MappedPluginAcceleratorRingsMut<'a> {
    /// Job request producer.
    pub requests: MappedAcceleratorProducerRingMut<'a>,
    /// Completion consumer.
    pub completions: MappedAcceleratorConsumerRingMut<'a>,
}

/// Host-side accelerator adapter roles.
pub struct MappedHostAcceleratorRingsMut<'a> {
    /// Job request consumer.
    pub requests: MappedAcceleratorConsumerRingMut<'a>,
    /// Completion producer.
    pub completions: MappedAcceleratorProducerRingMut<'a>,
}

/// An owned setup-time `mmap` of the shared-memory region descriptor.
pub struct MappedSetupRegion {
    /// Process-local address of the uniquely owned mapping.
    ///
    /// The address is stored as an integer so ownership may move between
    /// scheduler threads. Typed pointers are reconstructed only inside the
    /// layout-checked accessors below, and the mapping remains uniquely owned
    /// until `Drop`.
    address: usize,
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

/// A mutable view of one VM's dedicated plugin-to-host coverage ring.
///
/// The mapping process must use this view for exactly one SPSC role: the plugin
/// mutates entry slots and `write_idx`, while the host only copies published
/// entries and advances `read_idx`. The two processes never take mutable Rust
/// references to the same mapping inside one address space.
pub struct MappedCoverageRingMut<'a> {
    /// VM slot that exclusively produces this ring.
    pub vm_slot: u32,
    /// SPSC header shared by the plugin producer and host consumer.
    pub header: &'a RingHeader,
    /// Compact coverage-entry backing storage.
    pub entries: &'a mut [CoverageEntry],
}

/// A mutable view of one VM's plugin-to-host white-box marker ring.
///
/// The plugin is the sole entry/write-index producer and the host is the sole
/// read-index consumer. Marker traffic is observational and never shares a
/// causal frame ring.
pub struct MappedWhiteboxMarkerRingMut<'a> {
    /// VM slot that exclusively produces this ring.
    pub vm_slot: u32,
    /// SPSC header shared by the plugin producer and host consumer.
    pub header: &'a RingHeader,
    /// Bounded marker-entry backing storage.
    pub entries: &'a mut [WhiteboxMarkerEntry],
}

/// A mutable view of one VM's host-to-plugin fault command transport.
pub struct MappedFaultCommandTransportMut<'a> {
    /// VM slot whose plugin exclusively consumes the transport.
    pub vm_slot: u32,
    /// Host-producer/plugin-consumer SPSC ring header.
    pub ring: &'a RingHeader,
    /// Fixed command slot storage.
    pub slots: &'a mut [FaultCommandSlotV1],
    /// Circular payload arena cursors.
    pub arena_header: &'a FaultPayloadArenaHeader,
    /// Circular payload arena bytes.
    pub arena: &'a mut [u8],
    /// Region-relative offset of `arena` for command envelopes.
    pub arena_region_offset: u64,
}

/// A mutable view of one VM's plugin-to-host fault result transport.
pub struct MappedFaultResultTransportMut<'a> {
    /// VM slot whose plugin exclusively produces the transport.
    pub vm_slot: u32,
    /// Plugin-producer/host-consumer SPSC ring header.
    pub ring: &'a RingHeader,
    /// Fixed result slot storage.
    pub slots: &'a mut [FaultResultSlotV1],
    /// Circular result-payload arena cursors.
    pub arena_header: &'a FaultPayloadArenaHeader,
    /// Circular result-payload arena bytes.
    pub arena: &'a mut [u8],
    /// Region-relative offset of `arena` for result envelopes.
    pub arena_region_offset: u64,
}

/// A mutable view of one VM's plugin-to-host fault rule-event transport.
pub struct MappedFaultEventTransportMut<'a> {
    /// VM slot whose plugin exclusively produces the transport.
    pub vm_slot: u32,
    /// Plugin-producer/host-consumer SPSC ring header.
    pub ring: &'a RingHeader,
    /// Fixed event slot storage.
    pub slots: &'a mut [FaultEventSlotV1],
    /// Circular event-payload arena cursors.
    pub arena_header: &'a FaultPayloadArenaHeader,
    /// Circular event-payload arena bytes.
    pub arena: &'a mut [u8],
    /// Region-relative offset of `arena` for event envelopes.
    pub arena_region_offset: u64,
}

/// Producer-only access to one directional guest-introspection ring.
pub struct MappedGuestIntrospectionProducerRingMut<'a> {
    vm_slot: u32,
    direction: GuestIntrospectionRingDirection,
    header: &'a RingHeader,
    entries: &'a mut [GuestIntrospectionEntry],
}

impl MappedGuestIntrospectionProducerRingMut<'_> {
    /// Returns the logical VM associated with this producer.
    #[must_use]
    pub const fn vm_slot(&self) -> u32 {
        self.vm_slot
    }

    /// Returns the fixed producer-to-consumer direction.
    #[must_use]
    pub const fn direction(&self) -> GuestIntrospectionRingDirection {
        self.direction
    }

    /// Enqueues one complete validated `CRGI` record entry.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when the ring geometry or indices are invalid
    /// or the bounded queue is full.
    pub fn enqueue(&mut self, entry: GuestIntrospectionEntry) -> Result<(), SpscRingError> {
        self.header.enqueue_guest_introspection(self.entries, entry)
    }
}

/// Consumer-only access to one directional guest-introspection ring.
pub struct MappedGuestIntrospectionConsumerRingMut<'a> {
    vm_slot: u32,
    direction: GuestIntrospectionRingDirection,
    header: &'a RingHeader,
    entries: &'a mut [GuestIntrospectionEntry],
}

impl MappedGuestIntrospectionConsumerRingMut<'_> {
    /// Returns the logical VM associated with this consumer.
    #[must_use]
    pub const fn vm_slot(&self) -> u32 {
        self.vm_slot
    }

    /// Returns the fixed producer-to-consumer direction.
    #[must_use]
    pub const fn direction(&self) -> GuestIntrospectionRingDirection {
        self.direction
    }

    /// Dequeues and validates the next complete `CRGI` record entry.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when the ring geometry or indices are invalid
    /// or the next untrusted cross-process entry is malformed.
    pub fn dequeue(&mut self) -> Result<Option<GuestIntrospectionEntry>, SpscRingError> {
        self.header.dequeue_guest_introspection(self.entries)
    }
}

/// Host-side role view: request producer and response consumer.
pub struct MappedHostGuestIntrospectionRingsMut<'a> {
    /// Host-to-plugin request producer.
    pub requests: MappedGuestIntrospectionProducerRingMut<'a>,
    /// Plugin-to-host response consumer.
    pub responses: MappedGuestIntrospectionConsumerRingMut<'a>,
}

/// Plugin-side role view: request consumer and response producer.
pub struct MappedPluginGuestIntrospectionRingsMut<'a> {
    /// Host-to-plugin request consumer.
    pub requests: MappedGuestIntrospectionConsumerRingMut<'a>,
    /// Plugin-to-host response producer.
    pub responses: MappedGuestIntrospectionProducerRingMut<'a>,
}

/// Role-preserving process-lifetime handle for plugin guest-introspection rings.
///
/// The handle erases the mapping borrow so a pinned QEMU callback owner can
/// retain it. Its private raw addresses are process-local adapter state and are
/// never stored in shared memory. Methods preserve the plugin's sole request
/// consumer and response producer roles.
pub struct DetachedPluginGuestIntrospectionRings {
    request_header: NonNull<RingHeader>,
    request_entries: NonNull<GuestIntrospectionEntry>,
    request_capacity: usize,
    response_header: NonNull<RingHeader>,
    response_entries: NonNull<GuestIntrospectionEntry>,
    response_capacity: usize,
}

impl MappedPluginGuestIntrospectionRingsMut<'_> {
    /// Detaches this role view for a process-lifetime callback owner.
    ///
    /// # Safety
    ///
    /// The caller must retain the owning [`MappedSetupRegion`] without moving,
    /// unmapping, or creating another plugin-side view for these rings until
    /// the returned handle is dropped. QEMU callbacks using the handle must be
    /// serialized according to the SPSC role contract.
    #[must_use]
    pub unsafe fn detach_for_mapping_lifetime(self) -> DetachedPluginGuestIntrospectionRings {
        let request_entries = self.requests.entries.as_mut_ptr();
        let response_entries = self.responses.entries.as_mut_ptr();
        // SAFETY: validated guest-introspection queues have fixed nonzero
        // capacity, so each slice supplies a non-null first-entry address.
        let request_entries = unsafe { NonNull::new_unchecked(request_entries) };
        // SAFETY: same invariant as the request queue above.
        let response_entries = unsafe { NonNull::new_unchecked(response_entries) };
        DetachedPluginGuestIntrospectionRings {
            request_header: NonNull::from(self.requests.header),
            request_entries,
            request_capacity: self.requests.entries.len(),
            response_header: NonNull::from(self.responses.header),
            response_entries,
            response_capacity: self.responses.entries.len(),
        }
    }
}

impl DetachedPluginGuestIntrospectionRings {
    /// Peeks at the next validated host request without consuming it.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when ring indices or the next shared entry are
    /// malformed.
    pub fn peek_request(&mut self) -> Result<Option<GuestIntrospectionEntry>, SpscRingError> {
        // SAFETY: the detach contract retains the mapping and unique plugin
        // role for this exact entry range while the handle is live.
        let entries = unsafe {
            core::slice::from_raw_parts_mut(self.request_entries.as_ptr(), self.request_capacity)
        };
        // SAFETY: the same detach contract retains the shared header.
        unsafe { self.request_header.as_ref() }.peek_guest_introspection(entries)
    }

    /// Commits a previously peeked host request after guest delivery succeeds.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when the queue changed or its next entry does
    /// not have `expected_sequence`.
    pub fn commit_request(&mut self, expected_sequence: u64) -> Result<(), SpscRingError> {
        // SAFETY: the detach contract retains the mapping and unique plugin
        // role for this exact entry range while the handle is live.
        let entries = unsafe {
            core::slice::from_raw_parts_mut(self.request_entries.as_ptr(), self.request_capacity)
        };
        // SAFETY: the same detach contract retains the shared header.
        unsafe { self.request_header.as_ref() }
            .commit_guest_introspection(entries, expected_sequence)
    }

    /// Enqueues one validated guest response for the host consumer.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when ring indices are invalid or the response
    /// queue is full.
    pub fn enqueue_response(
        &mut self,
        entry: GuestIntrospectionEntry,
    ) -> Result<(), SpscRingError> {
        // SAFETY: the detach contract retains the mapping and unique plugin
        // role for this exact entry range while the handle is live.
        let entries = unsafe {
            core::slice::from_raw_parts_mut(self.response_entries.as_ptr(), self.response_capacity)
        };
        // SAFETY: the same detach contract retains the shared header.
        unsafe { self.response_header.as_ref() }.enqueue_guest_introspection(entries, entry)
    }
}

struct GuestIntrospectionRawRingMut<'a> {
    header: &'a RingHeader,
    entries: &'a mut [GuestIntrospectionEntry],
}

struct GuestIntrospectionRingPairMut<'a> {
    request: GuestIntrospectionRawRingMut<'a>,
    response: GuestIntrospectionRawRingMut<'a>,
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
    fn base_ptr(&self) -> *mut u8 {
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
    pub fn header_snapshot(&self) -> super::RegionHeaderSnapshot {
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

        let base = self.base_ptr();
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

    /// Borrows one VM's host-to-plugin fault command transport.
    ///
    /// # Errors
    ///
    /// Returns [`MappedSetupRegionAccessError`] when the mapped header is
    /// invalid, `vm_slot` is not a logical VM, or any transport segment is out
    /// of bounds or misaligned.
    pub fn fault_command_transport_mut(
        &mut self,
        vm_slot: u32,
    ) -> Result<MappedFaultCommandTransportMut<'_>, MappedSetupRegionAccessError> {
        let layout = self
            .layout()
            .map_err(|source| MappedSetupRegionAccessError::Header { source })?;
        validate_fault_vm_slot(layout, vm_slot, "fault command transport")?;
        let ring_offset = mapped_fault_ring_header_offset(
            layout.fault_command_ring_hdr_off,
            layout.fault_command_ring_count,
            self.len,
            vm_slot,
            "fault command ring header",
        )?;
        let slots_offset = mapped_fault_slot_offset(
            layout.fault_command_slot_off,
            layout.fault_command_ring_count,
            layout.fault_command_queue_capacity,
            FAULT_COMMAND_SLOT_V1_BYTES,
            self.len,
            vm_slot,
            "fault command slot",
        )?;
        let arena_header_offset = mapped_fault_arena_header_offset(
            layout.fault_command_arena_hdr_off,
            layout.fault_command_ring_count,
            self.len,
            vm_slot,
            "fault command arena header",
        )?;
        let arena_offset = mapped_fault_arena_offset(
            layout.fault_command_arena_off,
            layout.fault_command_arena_stride,
            layout.fault_command_ring_count,
            self.len,
            vm_slot,
            "fault command arena",
        )?;
        let slot_count = usize::try_from(layout.fault_command_queue_capacity).map_err(|_| {
            MappedSetupRegionAccessError::SegmentOffsetOverflow {
                segment: "fault command slot",
                index: vm_slot,
            }
        })?;
        let arena_len = usize::try_from(layout.fault_command_arena_stride).map_err(|_| {
            MappedSetupRegionAccessError::SegmentOffsetOverflow {
                segment: "fault command arena",
                index: vm_slot,
            }
        })?;
        let base = self.base_ptr();
        // SAFETY: the helpers validate complete, pairwise-disjoint aligned
        // ranges for this VM. The exclusive mapping borrow prevents another
        // safe mutable transport view while these slices are live.
        let (ring, slots, arena_header, arena) = unsafe {
            (
                &*base.add(ring_offset).cast::<RingHeader>(),
                core::slice::from_raw_parts_mut(
                    base.add(slots_offset).cast::<FaultCommandSlotV1>(),
                    slot_count,
                ),
                &*base
                    .add(arena_header_offset)
                    .cast::<FaultPayloadArenaHeader>(),
                core::slice::from_raw_parts_mut(base.add(arena_offset), arena_len),
            )
        };
        Ok(MappedFaultCommandTransportMut {
            vm_slot,
            ring,
            slots,
            arena_header,
            arena,
            arena_region_offset: layout.fault_command_arena_off
                + u64::from(vm_slot) * layout.fault_command_arena_stride,
        })
    }

    /// Borrows one VM's plugin-to-host fault result transport.
    ///
    /// # Errors
    ///
    /// Returns [`MappedSetupRegionAccessError`] when the mapped header is
    /// invalid, `vm_slot` is not a logical VM, or any transport segment is out
    /// of bounds or misaligned.
    pub fn fault_result_transport_mut(
        &mut self,
        vm_slot: u32,
    ) -> Result<MappedFaultResultTransportMut<'_>, MappedSetupRegionAccessError> {
        let layout = self
            .layout()
            .map_err(|source| MappedSetupRegionAccessError::Header { source })?;
        validate_fault_vm_slot(layout, vm_slot, "fault result transport")?;
        let ring_offset = mapped_fault_ring_header_offset(
            layout.fault_result_ring_hdr_off,
            layout.fault_result_ring_count,
            self.len,
            vm_slot,
            "fault result ring header",
        )?;
        let slots_offset = mapped_fault_slot_offset(
            layout.fault_result_slot_off,
            layout.fault_result_ring_count,
            layout.fault_result_queue_capacity,
            FAULT_RESULT_SLOT_V1_BYTES,
            self.len,
            vm_slot,
            "fault result slot",
        )?;
        let arena_header_offset = mapped_fault_arena_header_offset(
            layout.fault_result_arena_hdr_off,
            layout.fault_result_ring_count,
            self.len,
            vm_slot,
            "fault result arena header",
        )?;
        let arena_offset = mapped_fault_arena_offset(
            layout.fault_result_arena_off,
            layout.fault_result_arena_stride,
            layout.fault_result_ring_count,
            self.len,
            vm_slot,
            "fault result arena",
        )?;
        let slot_count = usize::try_from(layout.fault_result_queue_capacity).map_err(|_| {
            MappedSetupRegionAccessError::SegmentOffsetOverflow {
                segment: "fault result slot",
                index: vm_slot,
            }
        })?;
        let arena_len = usize::try_from(layout.fault_result_arena_stride).map_err(|_| {
            MappedSetupRegionAccessError::SegmentOffsetOverflow {
                segment: "fault result arena",
                index: vm_slot,
            }
        })?;
        let base = self.base_ptr();
        // SAFETY: the helpers validate complete, pairwise-disjoint aligned
        // ranges for this VM. The exclusive mapping borrow prevents another
        // safe mutable transport view while these slices are live.
        let (ring, slots, arena_header, arena) = unsafe {
            (
                &*base.add(ring_offset).cast::<RingHeader>(),
                core::slice::from_raw_parts_mut(
                    base.add(slots_offset).cast::<FaultResultSlotV1>(),
                    slot_count,
                ),
                &*base
                    .add(arena_header_offset)
                    .cast::<FaultPayloadArenaHeader>(),
                core::slice::from_raw_parts_mut(base.add(arena_offset), arena_len),
            )
        };
        Ok(MappedFaultResultTransportMut {
            vm_slot,
            ring,
            slots,
            arena_header,
            arena,
            arena_region_offset: layout.fault_result_arena_off
                + u64::from(vm_slot) * layout.fault_result_arena_stride,
        })
    }

    /// Borrows one VM's plugin-to-host fault rule-event transport.
    ///
    /// # Errors
    ///
    /// Returns [`MappedSetupRegionAccessError`] when the mapped header is
    /// invalid, `vm_slot` is not a logical VM, or any event transport segment
    /// is out of bounds or misaligned.
    pub fn fault_event_transport_mut(
        &mut self,
        vm_slot: u32,
    ) -> Result<MappedFaultEventTransportMut<'_>, MappedSetupRegionAccessError> {
        let layout = self
            .layout()
            .map_err(|source| MappedSetupRegionAccessError::Header { source })?;
        validate_fault_vm_slot(layout, vm_slot, "fault event transport")?;
        let ring_offset = mapped_fault_ring_header_offset(
            layout.fault_event_ring_hdr_off,
            layout.fault_event_ring_count,
            self.len,
            vm_slot,
            "fault event ring header",
        )?;
        let slots_offset = mapped_fault_slot_offset(
            layout.fault_event_slot_off,
            layout.fault_event_ring_count,
            layout.fault_event_queue_capacity,
            FAULT_EVENT_SLOT_V1_BYTES,
            self.len,
            vm_slot,
            "fault event slot",
        )?;
        let arena_header_offset = mapped_fault_arena_header_offset(
            layout.fault_event_arena_hdr_off,
            layout.fault_event_ring_count,
            self.len,
            vm_slot,
            "fault event arena header",
        )?;
        let arena_offset = mapped_fault_arena_offset(
            layout.fault_event_arena_off,
            layout.fault_event_arena_stride,
            layout.fault_event_ring_count,
            self.len,
            vm_slot,
            "fault event arena",
        )?;
        let slot_count = usize::try_from(layout.fault_event_queue_capacity).map_err(|_| {
            MappedSetupRegionAccessError::SegmentOffsetOverflow {
                segment: "fault event slot",
                index: vm_slot,
            }
        })?;
        let arena_len = usize::try_from(layout.fault_event_arena_stride).map_err(|_| {
            MappedSetupRegionAccessError::SegmentOffsetOverflow {
                segment: "fault event arena",
                index: vm_slot,
            }
        })?;
        let base = self.base_ptr();
        // SAFETY: all event transport ranges are validated, aligned, and
        // disjoint; the exclusive mapping borrow prevents another mutable view.
        let (ring, slots, arena_header, arena) = unsafe {
            (
                &*base.add(ring_offset).cast::<RingHeader>(),
                core::slice::from_raw_parts_mut(
                    base.add(slots_offset).cast::<FaultEventSlotV1>(),
                    slot_count,
                ),
                &*base
                    .add(arena_header_offset)
                    .cast::<FaultPayloadArenaHeader>(),
                core::slice::from_raw_parts_mut(base.add(arena_offset), arena_len),
            )
        };
        Ok(MappedFaultEventTransportMut {
            vm_slot,
            ring,
            slots,
            arena_header,
            arena,
            arena_region_offset: layout.fault_event_arena_off
                + u64::from(vm_slot) * layout.fault_event_arena_stride,
        })
    }

    /// Borrows one VM's host-side guest-introspection role view.
    ///
    /// # Errors
    ///
    /// Returns [`MappedSetupRegionAccessError`] when `vm_slot` is absent or the
    /// request or response segment is invalid.
    pub fn host_guest_introspection_rings_mut(
        &mut self,
        vm_slot: u32,
    ) -> Result<MappedHostGuestIntrospectionRingsMut<'_>, MappedSetupRegionAccessError> {
        let GuestIntrospectionRingPairMut { request, response } =
            self.guest_introspection_ring_pair_mut(vm_slot)?;
        Ok(MappedHostGuestIntrospectionRingsMut {
            requests: MappedGuestIntrospectionProducerRingMut {
                vm_slot,
                direction: GuestIntrospectionRingDirection::Request,
                header: request.header,
                entries: request.entries,
            },
            responses: MappedGuestIntrospectionConsumerRingMut {
                vm_slot,
                direction: GuestIntrospectionRingDirection::Response,
                header: response.header,
                entries: response.entries,
            },
        })
    }

    /// Borrows one VM's plugin-side guest-introspection role view.
    ///
    /// # Errors
    ///
    /// Returns [`MappedSetupRegionAccessError`] when `vm_slot` is absent or the
    /// request or response segment is invalid.
    pub fn plugin_guest_introspection_rings_mut(
        &mut self,
        vm_slot: u32,
    ) -> Result<MappedPluginGuestIntrospectionRingsMut<'_>, MappedSetupRegionAccessError> {
        let GuestIntrospectionRingPairMut { request, response } =
            self.guest_introspection_ring_pair_mut(vm_slot)?;
        Ok(MappedPluginGuestIntrospectionRingsMut {
            requests: MappedGuestIntrospectionConsumerRingMut {
                vm_slot,
                direction: GuestIntrospectionRingDirection::Request,
                header: request.header,
                entries: request.entries,
            },
            responses: MappedGuestIntrospectionProducerRingMut {
                vm_slot,
                direction: GuestIntrospectionRingDirection::Response,
                header: response.header,
                entries: response.entries,
            },
        })
    }

    /// Borrows one VM's QEMU/plugin-side accelerator role pair.
    ///
    /// # Errors
    ///
    /// Returns [`MappedSetupRegionAccessError`] when the VM or either fixed
    /// shared-memory segment is invalid.
    pub fn plugin_accelerator_rings_mut(
        &mut self,
        vm_slot: u32,
    ) -> Result<MappedPluginAcceleratorRingsMut<'_>, MappedSetupRegionAccessError> {
        let (request_header, request_entries, completion_header, completion_entries) =
            self.accelerator_ring_pair_mut(vm_slot)?;
        Ok(MappedPluginAcceleratorRingsMut {
            requests: MappedAcceleratorProducerRingMut {
                vm_slot,
                direction: AcceleratorRingDirection::Request,
                header: request_header,
                entries: request_entries,
            },
            completions: MappedAcceleratorConsumerRingMut {
                vm_slot,
                direction: AcceleratorRingDirection::Completion,
                header: completion_header,
                entries: completion_entries,
            },
        })
    }

    /// Borrows one VM's host-side accelerator adapter role pair.
    ///
    /// # Errors
    ///
    /// Returns [`MappedSetupRegionAccessError`] when the VM or either fixed
    /// shared-memory segment is invalid.
    pub fn host_accelerator_rings_mut(
        &mut self,
        vm_slot: u32,
    ) -> Result<MappedHostAcceleratorRingsMut<'_>, MappedSetupRegionAccessError> {
        let (request_header, request_entries, completion_header, completion_entries) =
            self.accelerator_ring_pair_mut(vm_slot)?;
        Ok(MappedHostAcceleratorRingsMut {
            requests: MappedAcceleratorConsumerRingMut {
                vm_slot,
                direction: AcceleratorRingDirection::Request,
                header: request_header,
                entries: request_entries,
            },
            completions: MappedAcceleratorProducerRingMut {
                vm_slot,
                direction: AcceleratorRingDirection::Completion,
                header: completion_header,
                entries: completion_entries,
            },
        })
    }

    fn accelerator_ring_pair_mut(
        &mut self,
        vm_slot: u32,
    ) -> Result<(
        &RingHeader,
        &mut [AcceleratorEntry],
        &RingHeader,
        &mut [AcceleratorEntry],
    ), MappedSetupRegionAccessError> {
        let layout = self.layout().map_err(|source| {
            MappedSetupRegionAccessError::Header { source }
        })?;
        if vm_slot >= layout.vm_node_count {
            return Err(MappedSetupRegionAccessError::UnknownGuestIntrospectionRing {
                vm_slot,
                vm_node_count: layout.vm_node_count,
            });
        }
        let request_index = AcceleratorRingDirection::Request.ring_index(vm_slot)
            .ok_or(MappedSetupRegionAccessError::SegmentOffsetOverflow {
                segment: "accelerator ring",
                index: vm_slot,
            })?;
        let completion_index = AcceleratorRingDirection::Completion.ring_index(vm_slot)
            .ok_or(MappedSetupRegionAccessError::SegmentOffsetOverflow {
                segment: "accelerator ring",
                index: vm_slot,
            })?;
        let request_header_offset = mapped_accelerator_ring_header_offset(
            layout, self.len, request_index,
        )?;
        let completion_header_offset = mapped_accelerator_ring_header_offset(
            layout, self.len, completion_index,
        )?;
        let request_entries_offset = mapped_accelerator_ring_entries_offset(
            layout, self.len, request_index,
        )?;
        let completion_entries_offset = mapped_accelerator_ring_entries_offset(
            layout, self.len, completion_index,
        )?;
        let count = usize::try_from(layout.accelerator_queue_capacity).map_err(|_error| {
            MappedSetupRegionAccessError::SegmentOffsetOverflow {
                segment: "accelerator entry",
                index: vm_slot,
            }
        })?;
        let base = self.base_ptr();
        // SAFETY: both offset helpers validate complete aligned ranges. The
        // request and completion indices are distinct and their fixed strides
        // cannot overlap; the exclusive mapping borrow prevents aliasing.
        Ok(unsafe {
            (
                &*base.add(request_header_offset).cast::<RingHeader>(),
                core::slice::from_raw_parts_mut(
                    base.add(request_entries_offset).cast::<AcceleratorEntry>(),
                    count,
                ),
                &*base.add(completion_header_offset).cast::<RingHeader>(),
                core::slice::from_raw_parts_mut(
                    base.add(completion_entries_offset).cast::<AcceleratorEntry>(),
                    count,
                ),
            )
        })
    }

    fn guest_introspection_ring_pair_mut(
        &mut self,
        vm_slot: u32,
    ) -> Result<GuestIntrospectionRingPairMut<'_>, MappedSetupRegionAccessError> {
        let layout = self
            .layout()
            .map_err(|source| MappedSetupRegionAccessError::Header { source })?;
        if vm_slot >= layout.vm_node_count {
            return Err(
                MappedSetupRegionAccessError::UnknownGuestIntrospectionRing {
                    vm_slot,
                    vm_node_count: layout.vm_node_count,
                },
            );
        }
        let request_index = GuestIntrospectionRingDirection::Request
            .ring_index(vm_slot)
            .ok_or(MappedSetupRegionAccessError::SegmentOffsetOverflow {
                segment: "guest-introspection ring",
                index: vm_slot,
            })?;
        let response_index = GuestIntrospectionRingDirection::Response
            .ring_index(vm_slot)
            .ok_or(MappedSetupRegionAccessError::SegmentOffsetOverflow {
                segment: "guest-introspection ring",
                index: vm_slot,
            })?;
        let request_header_offset =
            mapped_guest_introspection_ring_header_offset(layout, self.len, request_index)?;
        let response_header_offset =
            mapped_guest_introspection_ring_header_offset(layout, self.len, response_index)?;
        let request_entries_offset =
            mapped_guest_introspection_ring_entries_offset(layout, self.len, request_index)?;
        let response_entries_offset =
            mapped_guest_introspection_ring_entries_offset(layout, self.len, response_index)?;
        let entry_count =
            usize::try_from(layout.guest_introspection_queue_capacity).map_err(|_error| {
                MappedSetupRegionAccessError::SegmentOffsetOverflow {
                    segment: "guest-introspection entry",
                    index: request_index,
                }
            })?;
        if request_header_offset == response_header_offset
            || request_entries_offset == response_entries_offset
        {
            return Err(MappedSetupRegionAccessError::SegmentOffsetOverflow {
                segment: "guest-introspection ring",
                index: vm_slot,
            });
        }
        let base = self.base_ptr();
        // SAFETY: the offset helpers validate every complete aligned range in
        // this owned mapping. Request and response indices are distinct and
        // each fixed-size segment uses its ring index as a non-overlapping
        // stride. The exclusive mapping borrow prevents any other safe mutable
        // view for the lifetime of the returned role pair.
        let pair = unsafe {
            GuestIntrospectionRingPairMut {
                request: GuestIntrospectionRawRingMut {
                    header: &*base.add(request_header_offset).cast::<RingHeader>(),
                    entries: core::slice::from_raw_parts_mut(
                        base.add(request_entries_offset)
                            .cast::<GuestIntrospectionEntry>(),
                        entry_count,
                    ),
                },
                response: GuestIntrospectionRawRingMut {
                    header: &*base.add(response_header_offset).cast::<RingHeader>(),
                    entries: core::slice::from_raw_parts_mut(
                        base.add(response_entries_offset)
                            .cast::<GuestIntrospectionEntry>(),
                        entry_count,
                    ),
                },
            }
        };
        Ok(pair)
    }

    /// Borrows one VM's dedicated plugin-to-host fingerprint sample slot.
    ///
    /// The VM slot is also the fingerprint-slot index. The interior atomic
    /// fields support the plugin's boundary publication and the host's post-
    /// `finish_quantum` read without a mutable mapping borrow.
    ///
    /// # Errors
    ///
    /// Returns [`MappedSetupRegionAccessError`] when the mapped header is
    /// invalid, `vm_slot` does not name a logical VM, or the computed
    /// fingerprint segment is out of bounds or misaligned.
    pub fn fingerprint_sample(
        &self,
        vm_slot: u32,
    ) -> Result<&FingerprintSampleSlot, MappedSetupRegionAccessError> {
        let layout = self
            .layout()
            .map_err(|source| MappedSetupRegionAccessError::Header { source })?;
        if vm_slot >= layout.fingerprint_sample_count {
            return Err(MappedSetupRegionAccessError::SegmentOffsetOverflow {
                segment: "fingerprint sample",
                index: vm_slot,
            });
        }
        let offset = mapped_fingerprint_sample_offset(layout, self.len, vm_slot)?;
        let base = self.base_ptr();
        // SAFETY: `mapped_fingerprint_sample_offset` validated the slot index,
        // byte range, and ABI alignment against this live owned mapping.
        Ok(unsafe { &*base.add(offset).cast::<FingerprintSampleSlot>() })
    }
}

impl Drop for MappedSetupRegion {
    fn drop(&mut self) {
        // SAFETY: `ptr` and `len` were returned by `mmap` and are owned by this
        // value until `Drop`.
        unsafe {
            libc::munmap(self.base_ptr().cast::<libc::c_void>(), self.len);
        }
    }
}

/// Maps a setup shared-memory descriptor for exactly the `Setup.region_len`.
///
/// The descriptor's current length is checked before `mmap`, so an immediately
/// short backing file is rejected without touching memory beyond the file.
/// On Linux, a descriptor that supports memfd seals must carry `F_SEAL_SHRINK`
/// before the mapping is touched. Descriptors that do not support seals retain
/// a point-in-time size check, so their callers must separately prevent
/// truncation for the mapping's lifetime.
///
/// # Errors
///
/// Returns [`SetupRegionMapError`] when `region_len` cannot fit in `usize`, is
/// too small for a [`RegionHeader`], the descriptor cannot be inspected or is
/// shorter than `region_len`, or when `mmap` fails or returns a mapping
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

    let backing_len = setup_region_backing_len(fd)?;
    if backing_len < region_len {
        return Err(SetupRegionMapError::BackingTooShort {
            backing_len,
            region_len,
        });
    }
    verify_setup_region_shrink_seal(fd)?;

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
        address: ptr.as_ptr() as usize,
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
    /// A VM slot was outside the dedicated coverage-ring table.
    #[error(
        "mapped setup region has no coverage ring for VM slot {vm_slot}; VM count is {vm_node_count}"
    )]
    UnknownCoverageRing {
        /// Rejected VM slot.
        vm_slot: u32,
        /// Number of logical VM slots in the region.
        vm_node_count: u32,
    },
    /// A VM slot was outside the dedicated white-box marker-ring table.
    #[error(
        "mapped setup region has no white-box marker ring for VM slot {vm_slot}; VM count is {vm_node_count}"
    )]
    UnknownWhiteboxMarkerRing {
        /// Rejected VM slot.
        vm_slot: u32,
        /// Number of logical VM slots in the region.
        vm_node_count: u32,
    },
    /// A VM slot was outside a per-VM fault command/result transport table.
    #[error(
        "mapped setup region has no {segment} for VM slot {vm_slot}; VM count is {vm_node_count}"
    )]
    UnknownFaultTransport {
        /// Transport segment being requested.
        segment: &'static str,
        /// Rejected VM slot.
        vm_slot: u32,
        /// Number of logical VM slots in the region.
        vm_node_count: u32,
    },

    /// A VM slot was outside the guest-introspection ring table.
    #[error(
        "mapped setup region has no guest-introspection ring for VM slot {vm_slot}; VM count is {vm_node_count}"
    )]
    UnknownGuestIntrospectionRing {
        /// Rejected VM slot.
        vm_slot: u32,
        /// Number of logical VM slots in the region.
        vm_node_count: u32,
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
    /// The descriptor's current backing length could not be inspected.
    #[error("setup region fstat failed with errno {errno}")]
    FstatFailed {
        /// Raw OS errno value.
        errno: i32,
    },
    /// The descriptor reported a negative backing length.
    #[error("setup region backing length {backing_len} is negative")]
    NegativeBackingLength {
        /// Rejected signed backing length reported by `fstat`.
        backing_len: i64,
    },
    /// The descriptor backing is shorter than the advertised setup region.
    #[error(
        "setup region backing length {backing_len} is smaller than advertised length {region_len}"
    )]
    BackingTooShort {
        /// Current descriptor backing length.
        backing_len: u64,
        /// Length advertised by the control-protocol `Setup` frame.
        region_len: u64,
    },
    /// A seal-capable Linux memfd could still be shrunk after validation.
    #[error("setup memfd is missing F_SEAL_SHRINK (reported seals {seals:#x})")]
    MissingShrinkSeal {
        /// Seal mask returned by `fcntl(F_GET_SEALS)`.
        seals: i32,
    },
    /// Inspecting Linux memfd seals failed unexpectedly.
    #[error("setup region seal query failed with errno {errno}")]
    SealQueryFailed {
        /// Raw operating-system error number.
        errno: i32,
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

#[cfg(target_os = "linux")]
fn verify_setup_region_shrink_seal(fd: BorrowedFd<'_>) -> Result<(), SetupRegionMapError> {
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
const fn verify_setup_region_shrink_seal(_fd: BorrowedFd<'_>) -> Result<(), SetupRegionMapError> {
    Ok(())
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

fn mapped_coverage_ring_header_offset(
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

fn mapped_coverage_ring_entries_offset(
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

fn mapped_fingerprint_sample_offset(
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

fn mapped_whitebox_marker_ring_header_offset(
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

fn mapped_whitebox_marker_ring_entries_offset(
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

fn validate_fault_vm_slot(
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

fn mapped_fault_ring_header_offset(
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

fn mapped_guest_introspection_ring_header_offset(
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

fn mapped_accelerator_ring_header_offset(
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

fn mapped_fault_slot_offset(
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

fn mapped_fault_arena_header_offset(
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

fn mapped_guest_introspection_ring_entries_offset(
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

fn mapped_accelerator_ring_entries_offset(
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

fn mapped_fault_arena_offset(
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

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use std::ffi::CString;
    use std::io;
    use std::os::fd::{AsFd, AsRawFd, FromRawFd, OwnedFd};

    use super::*;

    #[test]
    fn owned_mapping_can_move_to_a_session_thread() {
        fn assert_send<T: Send>() {}
        assert_send::<MappedSetupRegion>();
    }

    #[test]
    fn seal_capable_memfd_must_prevent_shrink_before_mapping()
    -> Result<(), Box<dyn std::error::Error>> {
        let fd = test_memfd()?;
        let region_len = REGION_HEADER_SIZE as u64;
        let truncate = unsafe {
            // SAFETY: `fd` is live and the header size fits in `off_t`.
            libc::ftruncate(fd.as_raw_fd(), REGION_HEADER_SIZE as libc::off_t)
        };
        if truncate != 0 {
            return Err(Box::new(io::Error::last_os_error()));
        }

        assert_eq!(
            mmap_setup_region(fd.as_fd(), region_len).map(|mapped| mapped.region_len()),
            Err(SetupRegionMapError::MissingShrinkSeal { seals: 0 })
        );

        let add_seal = unsafe {
            // SAFETY: `fd` is a live memfd created with `MFD_ALLOW_SEALING`.
            libc::fcntl(fd.as_raw_fd(), libc::F_ADD_SEALS, libc::F_SEAL_SHRINK)
        };
        if add_seal != 0 {
            return Err(Box::new(io::Error::last_os_error()));
        }

        let mapped = mmap_setup_region(fd.as_fd(), region_len)?;
        assert_eq!(mapped.region_len(), region_len);
        Ok(())
    }

    fn test_memfd() -> io::Result<OwnedFd> {
        let name = CString::new("crucible-shmem-seal-test")
            .map_err(|error| io::Error::new(io::ErrorKind::InvalidInput, error))?;
        let raw_fd = unsafe {
            // SAFETY: `name` is a valid NUL-terminated C string.
            libc::memfd_create(name.as_ptr(), libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING)
        };
        if raw_fd < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful `memfd_create` returned a new descriptor whose
        // ownership is transferred exactly once into `OwnedFd`.
        Ok(unsafe { OwnedFd::from_raw_fd(raw_fd) })
    }
}
mod os_mapping;
use os_mapping::*;
