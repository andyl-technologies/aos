//! Typed mapped views over shared-memory device and fault rings.

use super::*;

/// Producer-only access to one directional accelerator ring.
pub struct MappedAcceleratorProducerRingMut<'a> {
    /// Logical VM that owns this direction.
    pub vm_slot: u32,
    /// Fixed producer/consumer direction.
    pub direction: AcceleratorRingDirection,
    pub(super) header: &'a RingHeader,
    pub(super) entries: &'a mut [AcceleratorEntry],
}

impl MappedAcceleratorProducerRingMut<'_> {
    /// Returns the exact number of entries awaiting consumption.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when the ring geometry or indices are invalid.
    pub fn live_len(&self) -> Result<u64, SpscRingError> {
        self.header.live_accelerator_len(self.entries)
    }

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
    pub(super) header: &'a RingHeader,
    pub(super) entries: &'a mut [AcceleratorEntry],
}

impl MappedAcceleratorConsumerRingMut<'_> {
    /// Returns the exact number of entries awaiting consumption.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when the ring geometry or indices are invalid.
    pub fn live_len(&self) -> Result<u64, SpscRingError> {
        self.header.live_accelerator_len(self.entries)
    }

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

/// Role-preserving process-lifetime handle for plugin accelerator rings.
///
/// The private addresses are process-local adapter state. They are never part
/// of the public shared-memory ABI, and methods retain the plugin's sole
/// request-producer and completion-consumer roles.
pub struct DetachedPluginAcceleratorRings {
    pub(super) request_header: NonNull<RingHeader>,
    pub(super) request_entries: NonNull<AcceleratorEntry>,
    pub(super) request_capacity: usize,
    pub(super) completion_header: NonNull<RingHeader>,
    pub(super) completion_entries: NonNull<AcceleratorEntry>,
    pub(super) completion_capacity: usize,
}

impl MappedPluginAcceleratorRingsMut<'_> {
    /// Detaches this role pair for a process-lifetime callback owner.
    ///
    /// # Safety
    ///
    /// The caller must retain the owning [`MappedSetupRegion`] without
    /// unmapping it or creating another plugin role view until this handle is
    /// dropped. Callback access must remain serialized by the SPSC contract.
    #[must_use]
    pub unsafe fn detach_for_mapping_lifetime(self) -> DetachedPluginAcceleratorRings {
        // SAFETY: validated accelerator rings have fixed nonzero capacity.
        let request_entries = unsafe { NonNull::new_unchecked(self.requests.entries.as_mut_ptr()) };
        // SAFETY: the same invariant holds for the completion ring.
        let completion_entries =
            unsafe { NonNull::new_unchecked(self.completions.entries.as_mut_ptr()) };
        DetachedPluginAcceleratorRings {
            request_header: NonNull::from(self.requests.header),
            request_entries,
            request_capacity: self.requests.entries.len(),
            completion_header: NonNull::from(self.completions.header),
            completion_entries,
            completion_capacity: self.completions.entries.len(),
        }
    }
}

impl DetachedPluginAcceleratorRings {
    /// Builds a detached plugin role from validated process-local ring parts.
    ///
    /// # Safety
    ///
    /// Both headers and entry ranges must remain live and correctly aligned
    /// until the handle is dropped. Each capacity must be nonzero, and no
    /// other plugin producer/consumer may access the same roles concurrently.
    #[must_use]
    pub unsafe fn from_raw_parts(
        request_header: *const RingHeader,
        request_entries: *mut AcceleratorEntry,
        request_capacity: usize,
        completion_header: *const RingHeader,
        completion_entries: *mut AcceleratorEntry,
        completion_capacity: usize,
    ) -> Option<Self> {
        if request_capacity == 0 || completion_capacity == 0 {
            return None;
        }
        Some(Self {
            request_header: NonNull::new(request_header.cast_mut())?,
            request_entries: NonNull::new(request_entries)?,
            request_capacity,
            completion_header: NonNull::new(completion_header.cast_mut())?,
            completion_entries: NonNull::new(completion_entries)?,
            completion_capacity,
        })
    }

    /// Enqueues one accelerator request for the host adapter.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] for malformed indices, records, or exhaustion.
    pub fn enqueue_request(&mut self, entry: AcceleratorEntry) -> Result<(), SpscRingError> {
        // SAFETY: the detach contract retains the unique producer range.
        let entries = unsafe {
            core::slice::from_raw_parts_mut(self.request_entries.as_ptr(), self.request_capacity)
        };
        // SAFETY: the mapping retains this validated header.
        unsafe { self.request_header.as_ref() }.enqueue_accelerator(entries, entry)
    }

    /// Dequeues one validated completion from the host adapter.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] for malformed indices or record bytes.
    pub fn dequeue_completion(&mut self) -> Result<Option<AcceleratorEntry>, SpscRingError> {
        // SAFETY: the detach contract retains the unique consumer range.
        let entries = unsafe {
            core::slice::from_raw_parts_mut(
                self.completion_entries.as_ptr(),
                self.completion_capacity,
            )
        };
        // SAFETY: the mapping retains this validated header.
        unsafe { self.completion_header.as_ref() }.dequeue_accelerator(entries)
    }
}

/// An owned setup-time `mmap` of the shared-memory region descriptor.
pub struct MappedSetupRegion {
    /// Process-local address of the uniquely owned mapping.
    ///
    /// The address is stored as an integer so ownership may move between
    /// scheduler threads. Typed pointers are reconstructed only inside the
    /// layout-checked accessors below, and the mapping remains uniquely owned
    /// until `Drop`.
    pub(super) address: usize,
    pub(super) len: usize,
    pub(super) region_len: u64,
}

pub(super) type AcceleratorRingPairMut<'a> = (
    &'a RingHeader,
    &'a mut [AcceleratorEntry],
    &'a RingHeader,
    &'a mut [AcceleratorEntry],
);

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
    pub(super) vm_slot: u32,
    pub(super) direction: GuestIntrospectionRingDirection,
    pub(super) header: &'a RingHeader,
    pub(super) entries: &'a mut [GuestIntrospectionEntry],
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
    pub(super) vm_slot: u32,
    pub(super) direction: GuestIntrospectionRingDirection,
    pub(super) header: &'a RingHeader,
    pub(super) entries: &'a mut [GuestIntrospectionEntry],
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
    pub(super) request_header: NonNull<RingHeader>,
    pub(super) request_entries: NonNull<GuestIntrospectionEntry>,
    pub(super) request_capacity: usize,
    pub(super) response_header: NonNull<RingHeader>,
    pub(super) response_entries: NonNull<GuestIntrospectionEntry>,
    pub(super) response_capacity: usize,
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

pub(super) struct GuestIntrospectionRawRingMut<'a> {
    pub(super) header: &'a RingHeader,
    pub(super) entries: &'a mut [GuestIntrospectionEntry],
}

pub(super) struct GuestIntrospectionRingPairMut<'a> {
    pub(super) request: GuestIntrospectionRawRingMut<'a>,
    pub(super) response: GuestIntrospectionRawRingMut<'a>,
}

/// A mutable view of two distinct mapped directed rings, one node slot, and
/// that node's fingerprint-sample slot.
pub struct MappedNodeRingPairMut<'a> {
    /// Node slot associated with the consumer VM.
    pub node_slot: &'a NodeSlot,
    /// Fingerprint sample slot associated with the consumer VM.
    pub fingerprint_sample: &'a FingerprintSampleSlot,
    /// First directed ring requested by the caller.
    pub first: MappedDirectedRingMut<'a>,
    /// Second directed ring requested by the caller.
    pub second: MappedDirectedRingMut<'a>,
}
