//! Shared-memory region headers, geometry, validation, and initialization.

use super::*;

/// A shared-memory region header describing the ABI identity and geometry.
#[repr(C, align(128))]
pub struct RegionHeader {
    magic: AtomicU64,
    abi_version: AtomicU32,
    node_count: AtomicU32,
    queue_capacity: AtomicU32,
    ring_count: AtomicU32,
    ring_hdr_off: AtomicU64,
    ring_data_off: AtomicU64,
    entry_stride: AtomicU64,
    region_size: AtomicU64,
    icount_shift: AtomicU32,
    pause_requested: AtomicU8,
    shutdown_requested: AtomicU8,
    _reserved: [u8; 194],
}

impl Clone for RegionHeader {
    fn clone(&self) -> Self {
        Self {
            magic: AtomicU64::new(self.magic.load(Ordering::Acquire)),
            abi_version: AtomicU32::new(self.abi_version.load(Ordering::Acquire)),
            node_count: AtomicU32::new(self.node_count.load(Ordering::Acquire)),
            queue_capacity: AtomicU32::new(self.queue_capacity.load(Ordering::Acquire)),
            ring_count: AtomicU32::new(self.ring_count.load(Ordering::Acquire)),
            ring_hdr_off: AtomicU64::new(self.ring_hdr_off.load(Ordering::Acquire)),
            ring_data_off: AtomicU64::new(self.ring_data_off.load(Ordering::Acquire)),
            entry_stride: AtomicU64::new(self.entry_stride.load(Ordering::Acquire)),
            region_size: AtomicU64::new(self.region_size.load(Ordering::Acquire)),
            icount_shift: AtomicU32::new(self.icount_shift.load(Ordering::Acquire)),
            pause_requested: AtomicU8::new(self.pause_requested.load(Ordering::Acquire)),
            shutdown_requested: AtomicU8::new(self.shutdown_requested.load(Ordering::Acquire)),
            _reserved: [0; 194],
        }
    }
}

/// Byte offset of [`RegionHeader`]'s magic field.
pub const REGION_HEADER_MAGIC_OFFSET: usize = core::mem::offset_of!(RegionHeader, magic);
/// Byte offset of [`RegionHeader`]'s ABI version field.
pub const REGION_HEADER_ABI_VERSION_OFFSET: usize =
    core::mem::offset_of!(RegionHeader, abi_version);
/// Byte offset of [`RegionHeader`]'s physical node-count field.
pub const REGION_HEADER_NODE_COUNT_OFFSET: usize = core::mem::offset_of!(RegionHeader, node_count);
/// Byte offset of [`RegionHeader`]'s per-ring queue-capacity field.
pub const REGION_HEADER_QUEUE_CAPACITY_OFFSET: usize =
    core::mem::offset_of!(RegionHeader, queue_capacity);
/// Byte offset of [`RegionHeader`]'s directed-ring-count field.
pub const REGION_HEADER_RING_COUNT_OFFSET: usize = core::mem::offset_of!(RegionHeader, ring_count);
/// Byte offset of [`RegionHeader`]'s ring-header sub-region offset field.
pub const REGION_HEADER_RING_HDR_OFF_OFFSET: usize =
    core::mem::offset_of!(RegionHeader, ring_hdr_off);
/// Byte offset of [`RegionHeader`]'s frame-entry storage offset field.
pub const REGION_HEADER_RING_DATA_OFF_OFFSET: usize =
    core::mem::offset_of!(RegionHeader, ring_data_off);
/// Byte offset of [`RegionHeader`]'s frame-entry stride field.
pub const REGION_HEADER_ENTRY_STRIDE_OFFSET: usize =
    core::mem::offset_of!(RegionHeader, entry_stride);
/// Byte offset of [`RegionHeader`]'s total region-size field.
pub const REGION_HEADER_REGION_SIZE_OFFSET: usize =
    core::mem::offset_of!(RegionHeader, region_size);
/// Byte offset of [`RegionHeader`]'s fixed icount-shift field.
pub const REGION_HEADER_ICOUNT_SHIFT_OFFSET: usize =
    core::mem::offset_of!(RegionHeader, icount_shift);
/// Byte offset of [`RegionHeader`]'s coordinated-pause flag.
pub const REGION_HEADER_PAUSE_REQUESTED_OFFSET: usize =
    core::mem::offset_of!(RegionHeader, pause_requested);
/// Byte offset of [`RegionHeader`]'s shutdown flag.
pub const REGION_HEADER_SHUTDOWN_REQUESTED_OFFSET: usize =
    core::mem::offset_of!(RegionHeader, shutdown_requested);
/// Byte offset of [`RegionHeader`]'s reserved forward-compatibility bytes.
pub const REGION_HEADER_RESERVED_OFFSET: usize = core::mem::offset_of!(RegionHeader, _reserved);
/// Wire size of one [`RegionHeader`].
pub const REGION_HEADER_SIZE: usize = core::mem::size_of::<RegionHeader>();
/// Wire alignment of one [`RegionHeader`].
pub const REGION_HEADER_ALIGN: usize = core::mem::align_of::<RegionHeader>();

pub(super) const _: () = assert!(REGION_HEADER_MAGIC_OFFSET == 0);
pub(super) const _: () = assert!(REGION_HEADER_ABI_VERSION_OFFSET == 8);
pub(super) const _: () = assert!(REGION_HEADER_NODE_COUNT_OFFSET == 12);
pub(super) const _: () = assert!(REGION_HEADER_QUEUE_CAPACITY_OFFSET == 16);
pub(super) const _: () = assert!(REGION_HEADER_RING_COUNT_OFFSET == 20);
pub(super) const _: () = assert!(REGION_HEADER_RING_HDR_OFF_OFFSET == 24);
pub(super) const _: () = assert!(REGION_HEADER_RING_DATA_OFF_OFFSET == 32);
pub(super) const _: () = assert!(REGION_HEADER_ENTRY_STRIDE_OFFSET == 40);
pub(super) const _: () = assert!(REGION_HEADER_REGION_SIZE_OFFSET == 48);
pub(super) const _: () = assert!(REGION_HEADER_ICOUNT_SHIFT_OFFSET == 56);
pub(super) const _: () = assert!(REGION_HEADER_PAUSE_REQUESTED_OFFSET == 60);
pub(super) const _: () = assert!(REGION_HEADER_SHUTDOWN_REQUESTED_OFFSET == 61);
pub(super) const _: () = assert!(REGION_HEADER_RESERVED_OFFSET == 62);
pub(super) const _: () = assert!(REGION_HEADER_SIZE == 256);
pub(super) const _: () = assert!(REGION_HEADER_ALIGN == 128);

impl RegionHeader {
    /// Builds a zero-reserved region header from a computed layout.
    #[must_use]
    pub fn new(layout: RegionLayout) -> Self {
        Self {
            magic: AtomicU64::new(REGION_MAGIC),
            abi_version: AtomicU32::new(ABI_VERSION),
            node_count: AtomicU32::new(layout.node_count),
            queue_capacity: AtomicU32::new(layout.queue_capacity),
            ring_count: AtomicU32::new(layout.ring_count),
            ring_hdr_off: AtomicU64::new(layout.ring_hdr_off),
            ring_data_off: AtomicU64::new(layout.ring_data_off),
            entry_stride: AtomicU64::new(layout.entry_stride),
            region_size: AtomicU64::new(layout.region_size),
            icount_shift: AtomicU32::new(layout.icount_shift),
            pause_requested: AtomicU8::new(0),
            shutdown_requested: AtomicU8::new(0),
            _reserved: [0; 194],
        }
    }

    /// Returns an acquire snapshot of every public header field.
    #[must_use]
    pub fn snapshot(&self) -> RegionHeaderSnapshot {
        RegionHeaderSnapshot {
            magic: self.magic.load(Ordering::Acquire),
            abi_version: self.abi_version.load(Ordering::Acquire),
            node_count: self.node_count.load(Ordering::Acquire),
            queue_capacity: self.queue_capacity.load(Ordering::Acquire),
            ring_count: self.ring_count.load(Ordering::Acquire),
            ring_hdr_off: self.ring_hdr_off.load(Ordering::Acquire),
            ring_data_off: self.ring_data_off.load(Ordering::Acquire),
            entry_stride: self.entry_stride.load(Ordering::Acquire),
            region_size: self.region_size.load(Ordering::Acquire),
            icount_shift: self.icount_shift.load(Ordering::Acquire),
            pause_requested: self.pause_requested.load(Ordering::Acquire),
            shutdown_requested: self.shutdown_requested.load(Ordering::Acquire),
        }
    }

    /// Requests a coordinated pause and wakes every node slot.
    ///
    /// The flag is release-stored before the wake-all pass, so a node that wakes
    /// and acquire-loads [`RegionHeader::control_action`] observes the pause
    /// request before deciding whether to run another quantum.
    ///
    /// # Errors
    ///
    /// Returns [`RegionControlError`] when any slot's non-private futex wake
    /// fails.
    pub fn request_pause<'a>(
        &self,
        slots: impl IntoIterator<Item = &'a NodeSlot>,
    ) -> Result<WakeAllResult, RegionControlError> {
        self.pause_requested.store(1, Ordering::Release);
        wake_all_slots_for_control(slots)
    }

    /// Clears a coordinated pause request.
    ///
    /// This only updates the flag; callers that need to resume parked nodes must
    /// publish the appropriate per-node scheduling state and wake those nodes.
    pub fn clear_pause(&self) {
        self.pause_requested.store(0, Ordering::Release);
    }

    /// Requests shutdown and wakes every node slot.
    ///
    /// The flag is release-stored before the wake-all pass, so parked nodes wake,
    /// acquire-observe [`RegionControlAction::Shutdown`], mark themselves done,
    /// and exit.
    ///
    /// # Errors
    ///
    /// Returns [`RegionControlError`] when any slot's non-private futex wake
    /// fails.
    pub fn request_shutdown<'a>(
        &self,
        slots: impl IntoIterator<Item = &'a NodeSlot>,
    ) -> Result<WakeAllResult, RegionControlError> {
        self.shutdown_requested.store(1, Ordering::Release);
        wake_all_slots_for_control(slots)
    }

    /// Returns the node-side action implied by the global control flags.
    #[must_use]
    pub fn control_action(&self) -> RegionControlAction {
        if self.shutdown_requested.load(Ordering::Acquire) != 0 {
            RegionControlAction::Shutdown
        } else if self.pause_requested.load(Ordering::Acquire) != 0 {
            RegionControlAction::Pause
        } else {
            RegionControlAction::Continue
        }
    }

    /// Returns whether a coordinated pause is currently requested.
    #[must_use]
    pub fn pause_requested(&self) -> bool {
        self.pause_requested.load(Ordering::Acquire) != 0
    }

    /// Returns whether shutdown is currently requested.
    #[must_use]
    pub fn shutdown_requested(&self) -> bool {
        self.shutdown_requested.load(Ordering::Acquire) != 0
    }

    /// Returns `true` when all forward-compatible reserved header bytes are zero.
    #[must_use]
    pub fn reserved_bytes_are_zero(&self) -> bool {
        self._reserved.iter().all(|byte| *byte == 0)
    }
}

/// A node-side action derived from the region's global control flags.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RegionControlAction {
    /// No global pause or shutdown flag is set.
    Continue,
    /// The node must quiesce at a quantum boundary and stay parked for snapshot.
    Pause,
    /// The node must wake, publish done status, and exit.
    Shutdown,
}

/// Result of waking every node for a global control flag change.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WakeAllResult {
    /// Number of node slots whose wake signal was incremented.
    pub slots_signaled: usize,
    /// Total number of futex waiters reported woken across all slots.
    pub waiters_woken: u64,
}

/// An acquire snapshot of the shared-memory region header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegionHeaderSnapshot {
    /// The region magic.
    pub magic: u64,
    /// The ABI version.
    pub abi_version: u32,
    /// The physical node slot count recorded in the header.
    pub node_count: u32,
    /// The per-ring queue capacity in frame entries.
    pub queue_capacity: u32,
    /// The number of directed rings allocated in the region.
    pub ring_count: u32,
    /// The byte offset from region base to the first ring header.
    pub ring_hdr_off: u64,
    /// The byte offset from region base to the first frame-entry slot.
    pub ring_data_off: u64,
    /// The byte stride between frame-entry slots.
    pub entry_stride: u64,
    /// The total mapped region size in bytes.
    pub region_size: u64,
    /// The fixed icount shift used to derive virtual nanoseconds.
    pub icount_shift: u32,
    /// Nonzero when the scheduler requested a coordinated pause.
    pub pause_requested: u8,
    /// Nonzero when the scheduler requested shutdown.
    pub shutdown_requested: u8,
}

/// A setup-time region whose header matched the compiled shared-memory ABI and geometry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValidatedSetupRegion {
    /// The mapped byte length supplied by the control-protocol `Setup` frame.
    pub region_len: u64,
    /// The ABI version observed in the region header.
    pub abi_version: u32,
}

/// Validates the setup-time shared-memory header snapshot before slot access.
///
/// The plugin calls this after mapping exactly the `region_len` carried by the
/// control-protocol `Setup` frame. The check accepts only the current
/// [`REGION_MAGIC`], the current [`ABI_VERSION`], a header `region_size` equal
/// to the mapped length, and geometry that can be recomputed by the current
/// layout model.
///
/// # Errors
///
/// Returns [`RegionSetupValidationError`] when the mapped length is too small
/// for a header, the magic or ABI version does not match this crate, the
/// header's `region_size` differs from the `Setup` length, or the header
/// geometry does not match this crate's layout model.
pub fn validate_setup_region_header(
    snapshot: RegionHeaderSnapshot,
    region_len: u64,
) -> Result<ValidatedSetupRegion, RegionSetupValidationError> {
    validate_setup_region_header_and_layout(snapshot, region_len)
        .map(|(validated, _layout)| validated)
}

pub(super) fn validate_setup_region_header_and_layout(
    snapshot: RegionHeaderSnapshot,
    region_len: u64,
) -> Result<(ValidatedSetupRegion, RegionLayout), RegionSetupValidationError> {
    let minimum_len = REGION_HEADER_SIZE as u64;
    if region_len < minimum_len {
        return Err(RegionSetupValidationError::RegionTooSmall {
            region_len,
            minimum_len,
        });
    }

    if snapshot.magic != REGION_MAGIC {
        return Err(RegionSetupValidationError::InvalidMagic {
            actual: snapshot.magic,
            expected: REGION_MAGIC,
        });
    }

    if snapshot.abi_version != ABI_VERSION {
        return Err(RegionSetupValidationError::AbiVersionMismatch {
            actual: snapshot.abi_version,
            expected: ABI_VERSION,
        });
    }

    if snapshot.region_size != region_len {
        return Err(RegionSetupValidationError::RegionLengthMismatch {
            setup_region_len: region_len,
            header_region_size: snapshot.region_size,
        });
    }

    let layout = layout_from_setup_region_geometry(snapshot, region_len)?;

    Ok((
        ValidatedSetupRegion {
            region_len,
            abi_version: snapshot.abi_version,
        },
        layout,
    ))
}

pub(super) fn layout_from_setup_region_header(
    snapshot: RegionHeaderSnapshot,
    region_len: u64,
) -> Result<RegionLayout, RegionSetupValidationError> {
    validate_setup_region_header_and_layout(snapshot, region_len).map(|(_validated, layout)| layout)
}

/// A requested shared-memory region shape.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegionConfig {
    /// Number of logical VM nodes to allocate into physical VM slots.
    pub vm_node_count: u32,
    /// Capacity of every directed SPSC ring in frame entries.
    pub queue_capacity: u32,
    /// Fixed icount shift used to derive virtual nanoseconds.
    pub icount_shift: u32,
}

impl RegionConfig {
    /// Builds a region configuration.
    #[must_use]
    pub const fn new(vm_node_count: u32, queue_capacity: u32, icount_shift: u32) -> Self {
        Self {
            vm_node_count,
            queue_capacity,
            icount_shift,
        }
    }
}

/// Computed offsets and counts for a shared-memory region allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RegionLayout {
    /// Number of logical VM nodes represented in physical VM slots.
    pub vm_node_count: u32,
    /// Number of physical node slots present in the fixed slot array.
    pub node_count: u32,
    /// Capacity of every directed SPSC ring in frame entries.
    pub queue_capacity: u32,
    /// Number of directed rings allocated for VM-to-executor traffic.
    pub ring_count: u32,
    /// Byte offset from region base to the fixed node slot array.
    pub node_slots_off: u64,
    /// Byte offset from region base to the first ring header.
    pub ring_hdr_off: u64,
    /// Byte offset from region base to the first frame-entry slot.
    pub ring_data_off: u64,
    /// Byte stride between frame-entry slots.
    pub entry_stride: u64,
    /// Number of plugin-to-host coverage rings, one per logical VM.
    pub coverage_ring_count: u32,
    /// Fixed entry capacity of every coverage ring.
    pub coverage_queue_capacity: u32,
    /// Byte offset from region base to the first coverage ring header.
    pub coverage_ring_hdr_off: u64,
    /// Byte offset from region base to the first coverage entry.
    pub coverage_ring_data_off: u64,
    /// Byte stride between coverage entries.
    pub coverage_entry_stride: u64,
    /// Number of per-node fingerprint sample slots, one per logical VM.
    pub fingerprint_sample_count: u32,
    /// Byte offset from region base to the first fingerprint sample slot.
    pub fingerprint_sample_off: u64,
    /// Byte stride between fingerprint sample slots.
    pub fingerprint_sample_stride: u64,
    /// Total mapped region size in bytes.
    pub region_size: u64,
    /// Fixed icount shift used to derive virtual nanoseconds.
    pub icount_shift: u32,
}

impl RegionLayout {
    /// Computes the region geometry for `config`.
    ///
    /// # Errors
    ///
    /// Returns [`RegionLayoutError`] when the VM count, queue capacity, icount
    /// shift, or computed byte geometry is outside the ABI-supported range.
    pub fn for_config(config: RegionConfig) -> Result<Self, RegionLayoutError> {
        if config.vm_node_count > MAX_VM_NODES as u32 {
            return Err(RegionLayoutError::TooManyVmNodes {
                requested: config.vm_node_count,
                max: MAX_VM_NODES as u32,
            });
        }
        if config.queue_capacity == 0 || !config.queue_capacity.is_power_of_two() {
            return Err(RegionLayoutError::InvalidQueueCapacity {
                capacity: config.queue_capacity,
            });
        }
        if config.icount_shift >= 64 {
            return Err(RegionLayoutError::InvalidIcountShift {
                shift_bits: config.icount_shift,
            });
        }

        let ring_count = config
            .vm_node_count
            .checked_mul(RESERVED_SLOTS as u32)
            .and_then(|count| count.checked_mul(2))
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let node_slots_off = usize_to_u64(REGION_HEADER_SIZE)?;
        let ring_hdr_off = usize_to_u64(REGION_HEADER_SIZE)?
            .checked_add(usize_to_u64(MAX_NODES)? * usize_to_u64(NODE_SLOT_SIZE)?)
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let ring_data_off = ring_hdr_off
            .checked_add(u64::from(ring_count) * usize_to_u64(RING_HEADER_SIZE)?)
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let entry_stride = usize_to_u64(FRAME_ENTRY_SIZE)?;
        let entry_count = u64::from(ring_count)
            .checked_mul(u64::from(config.queue_capacity))
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let frame_data_end = ring_data_off
            .checked_add(
                entry_count
                    .checked_mul(entry_stride)
                    .ok_or(RegionLayoutError::GeometryOverflow)?,
            )
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let coverage_ring_count = config.vm_node_count;
        let coverage_queue_capacity = COVERAGE_QUEUE_CAPACITY;
        let coverage_ring_hdr_off =
            checked_align_up(frame_data_end, usize_to_u64(RING_HEADER_ALIGN)?)?;
        let coverage_ring_data_off = coverage_ring_hdr_off
            .checked_add(
                u64::from(coverage_ring_count)
                    .checked_mul(usize_to_u64(RING_HEADER_SIZE)?)
                    .ok_or(RegionLayoutError::GeometryOverflow)?,
            )
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let coverage_entry_stride = usize_to_u64(COVERAGE_ENTRY_SIZE)?;
        let coverage_entry_count = u64::from(coverage_ring_count)
            .checked_mul(u64::from(coverage_queue_capacity))
            .ok_or(RegionLayoutError::GeometryOverflow)?;
        let coverage_data_end = coverage_ring_data_off
            .checked_add(
                coverage_entry_count
                    .checked_mul(coverage_entry_stride)
                    .ok_or(RegionLayoutError::GeometryOverflow)?,
            )
            .ok_or(RegionLayoutError::GeometryOverflow)?;

        // Additive ABI v3 section: one fingerprint sample slot per logical VM,
        // appended after the coverage data with the slot's own alignment.
        let fingerprint_sample_count = config.vm_node_count;
        let fingerprint_sample_stride = usize_to_u64(FINGERPRINT_SAMPLE_SLOT_SIZE)?;
        let fingerprint_sample_off =
            checked_align_up(coverage_data_end, usize_to_u64(FINGERPRINT_SAMPLE_SLOT_ALIGN)?)?;
        let region_size = fingerprint_sample_off
            .checked_add(
                u64::from(fingerprint_sample_count)
                    .checked_mul(fingerprint_sample_stride)
                    .ok_or(RegionLayoutError::GeometryOverflow)?,
            )
            .ok_or(RegionLayoutError::GeometryOverflow)?;

        Ok(Self {
            vm_node_count: config.vm_node_count,
            node_count: MAX_NODES as u32,
            queue_capacity: config.queue_capacity,
            ring_count,
            node_slots_off,
            ring_hdr_off,
            ring_data_off,
            entry_stride,
            coverage_ring_count,
            coverage_queue_capacity,
            coverage_ring_hdr_off,
            coverage_ring_data_off,
            coverage_entry_stride,
            fingerprint_sample_count,
            fingerprint_sample_off,
            fingerprint_sample_stride,
            region_size,
            icount_shift: config.icount_shift,
        })
    }

    /// Returns the number of frame-entry slots in the backing storage.
    #[must_use]
    pub fn frame_entry_count(&self) -> u64 {
        u64::from(self.ring_count) * u64::from(self.queue_capacity)
    }

    /// Returns the number of coverage-entry slots in the backing storage.
    #[must_use]
    pub fn coverage_entry_count(&self) -> u64 {
        u64::from(self.coverage_ring_count) * u64::from(self.coverage_queue_capacity)
    }
}

/// A directed SPSC ring allocation between two physical slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DirectedRing {
    /// Ring index in the header and backing-storage arrays.
    pub index: u32,
    /// Physical producer slot.
    pub src_slot: u32,
    /// Physical consumer slot.
    pub dst_slot: u32,
}

/// A reserved executor endpoint in the physical slot array.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservedExecutorSlot {
    /// Deterministic network router endpoint.
    NetRouter,
    /// Block-device I/O endpoint.
    BlockIo,
    /// 9p filesystem I/O endpoint.
    NineP,
}

impl ReservedExecutorSlot {
    /// Returns every reserved executor endpoint in deterministic ring order.
    #[must_use]
    pub const fn all() -> [Self; RESERVED_SLOTS] {
        [Self::NetRouter, Self::BlockIo, Self::NineP]
    }

    /// Returns the physical slot occupied by this executor.
    #[must_use]
    pub const fn slot(self) -> usize {
        match self {
            Self::NetRouter => SLOT_NET_ROUTER,
            Self::BlockIo => SLOT_BLK_IO,
            Self::NineP => SLOT_9P_IO,
        }
    }

    /// Returns the [`NodeSlot`] kind value used for this executor.
    #[must_use]
    pub const fn kind(self) -> u8 {
        match self {
            Self::NetRouter => KIND_NET,
            Self::BlockIo => KIND_BLK,
            Self::NineP => KIND_9P,
        }
    }
}

/// An owned, typed shared-memory region allocation for layout tests and builders.
pub struct RegionAllocation {
    header: RegionHeader,
    slots: Vec<NodeSlot>,
    ring_headers: Vec<RingHeader>,
    frame_entries: Vec<FrameEntry>,
    coverage_ring_headers: Vec<RingHeader>,
    coverage_entries: Vec<CoverageEntry>,
    rings: Vec<DirectedRing>,
    layout: RegionLayout,
}

impl Clone for RegionAllocation {
    fn clone(&self) -> Self {
        Self {
            header: self.header.clone(),
            slots: self.slots.clone(),
            ring_headers: self.ring_headers.clone(),
            frame_entries: self.frame_entries.clone(),
            coverage_ring_headers: self.coverage_ring_headers.clone(),
            coverage_entries: self.coverage_entries.clone(),
            rings: self.rings.clone(),
            layout: self.layout,
        }
    }
}

/// A scheduler-owned input frame to publish into one consumer's inbox.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingInputPublication {
    /// Physical slot that produces this frame.
    pub src_slot: u32,
    /// Frame to append to the directed inbox from `src_slot` to the consumer.
    pub frame: FrameEntry,
}

impl PendingInputPublication {
    /// Builds a pending input publication.
    #[must_use]
    pub const fn new(src_slot: u32, frame: FrameEntry) -> Self {
        Self { src_slot, frame }
    }
}

/// Result of publishing scheduler inputs, ceiling, and wake for one node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SchedulerWakePublication {
    /// Physical slot that consumed the published inputs and ceiling.
    pub dst_slot: u32,
    /// Number of input frames enqueued before the wake signal was incremented.
    pub pending_input_count: usize,
    /// The max-advance icount published before the wake signal was incremented.
    pub max_advance_icount: u64,
    /// The wake action returned by the node slot.
    pub wake: WakeAction,
}

#[derive(Clone, Debug)]
pub(super) struct SchedulerWakeEnqueuePlan {
    ring_index: usize,
    entry_range: std::ops::Range<usize>,
    input_index: usize,
}

impl RegionAllocation {
    /// Allocates and initializes a typed shared-memory region model.
    ///
    /// # Errors
    ///
    /// Returns [`RegionLayoutError`] if the compiled target is not the pinned
    /// ABI layout target, the requested layout is invalid, or a computed count
    /// cannot fit in memory indexes on this host.
    pub fn new(config: RegionConfig) -> Result<Self, RegionLayoutError> {
        validate_layout_target()?;
        Self::new_model(config)
    }

    /// Allocates and initializes a typed shared-memory model without target validation.
    ///
    /// This constructor is for in-process harnesses that need the canonical
    /// slot, ring, and frame-entry topology on developer hosts that are not the
    /// pinned ABI target. Use [`Self::new`] when the allocation is evidence for
    /// the mapped shared-memory ABI on the pinned target.
    ///
    /// # Errors
    ///
    /// Returns [`RegionLayoutError`] if the requested layout is invalid or a
    /// computed count cannot fit in memory indexes on this host.
    pub fn new_model(config: RegionConfig) -> Result<Self, RegionLayoutError> {
        let layout = RegionLayout::for_config(config)?;
        let header = RegionHeader::new(layout);
        let slots = (0..MAX_NODES)
            .map(|slot| node_slot_for_physical_index(layout.vm_node_count, slot))
            .collect::<Vec<_>>();
        let ring_headers = (0..layout.ring_count)
            .map(|_| RingHeader::new())
            .collect::<Vec<_>>();
        let entry_count = usize::try_from(layout.frame_entry_count())
            .map_err(|_| RegionLayoutError::GeometryOverflow)?;
        let frame_entries = (0..entry_count)
            .map(|_| FrameEntry::default())
            .collect::<Vec<_>>();
        let rings = directed_rings(layout.vm_node_count)?;
        let coverage_ring_headers = (0..layout.coverage_ring_count)
            .map(|_| RingHeader::new())
            .collect::<Vec<_>>();
        let coverage_entry_count = usize::try_from(layout.coverage_entry_count())
            .map_err(|_| RegionLayoutError::GeometryOverflow)?;
        let coverage_entries = (0..coverage_entry_count)
            .map(|_| CoverageEntry::default())
            .collect::<Vec<_>>();

        Ok(Self {
            header,
            slots,
            ring_headers,
            frame_entries,
            coverage_ring_headers,
            coverage_entries,
            rings,
            layout,
        })
    }

    /// Returns the initialized region header.
    #[must_use]
    pub fn header(&self) -> &RegionHeader {
        &self.header
    }

    /// Returns the fixed physical node slot array.
    #[must_use]
    pub fn slots(&self) -> &[NodeSlot] {
        &self.slots
    }

    /// Returns the directed ring headers.
    #[must_use]
    pub fn ring_headers(&self) -> &[RingHeader] {
        &self.ring_headers
    }

    /// Returns the frame-entry backing storage.
    #[must_use]
    pub fn frame_entries(&self) -> &[FrameEntry] {
        &self.frame_entries
    }

    /// Returns the plugin-to-host coverage ring headers.
    #[must_use]
    pub fn coverage_ring_headers(&self) -> &[RingHeader] {
        &self.coverage_ring_headers
    }

    /// Returns the plugin-to-host coverage-entry backing storage.
    #[must_use]
    pub fn coverage_entries(&self) -> &[CoverageEntry] {
        &self.coverage_entries
    }

    /// Returns the deterministic directed-ring map.
    #[must_use]
    pub fn rings(&self) -> &[DirectedRing] {
        &self.rings
    }

    /// Returns the computed region layout.
    #[must_use]
    pub fn layout(&self) -> RegionLayout {
        self.layout
    }

    /// Returns a node slot by physical slot index.
    #[must_use]
    pub fn node_slot(&self, slot_index: u32) -> Option<&NodeSlot> {
        usize::try_from(slot_index)
            .ok()
            .and_then(|index| self.slots.get(index))
    }

    /// Serializes the allocation into setup-region bytes for a host memfd.
    ///
    /// The returned byte vector has length [`RegionLayout::region_size`] and
    /// uses the exact `#[repr(C)]` offsets exported by this crate. It exists for
    /// host setup paths that must initialize a shared-memory descriptor before
    /// handing it to the QEMU plugin through the control protocol.
    ///
    /// # Errors
    ///
    /// Returns [`RegionSerializationError`] when the region size or a computed
    /// segment offset cannot be represented on this host.
    pub fn setup_region_bytes(&self) -> Result<Vec<u8>, RegionSerializationError> {
        let region_len = usize::try_from(self.layout.region_size).map_err(|_error| {
            RegionSerializationError::RegionSizeTooLarge {
                region_size: self.layout.region_size,
            }
        })?;
        let mut bytes = vec![0; region_len];

        write_region_header_bytes(&mut bytes, self.header.snapshot())?;
        for (index, slot) in self.slots.iter().enumerate() {
            let base = checked_segment_offset(
                "node slot",
                index,
                self.layout.node_slots_off,
                NODE_SLOT_SIZE,
                region_len,
            )?;
            write_node_slot_bytes(&mut bytes[base..base + NODE_SLOT_SIZE], slot.snapshot());
        }
        for (index, ring_header) in self.ring_headers.iter().enumerate() {
            let base = checked_segment_offset(
                "ring header",
                index,
                self.layout.ring_hdr_off,
                RING_HEADER_SIZE,
                region_len,
            )?;
            write_ring_header_bytes(&mut bytes[base..base + RING_HEADER_SIZE], ring_header);
        }
        for (index, frame_entry) in self.frame_entries.iter().enumerate() {
            let base = checked_segment_offset(
                "frame entry",
                index,
                self.layout.ring_data_off,
                FRAME_ENTRY_SIZE,
                region_len,
            )?;
            write_frame_entry_bytes(&mut bytes[base..base + FRAME_ENTRY_SIZE], frame_entry);
        }
        for (index, ring_header) in self.coverage_ring_headers.iter().enumerate() {
            let base = checked_segment_offset(
                "coverage ring header",
                index,
                self.layout.coverage_ring_hdr_off,
                RING_HEADER_SIZE,
                region_len,
            )?;
            write_ring_header_bytes(&mut bytes[base..base + RING_HEADER_SIZE], ring_header);
        }
        for (index, coverage_entry) in self.coverage_entries.iter().enumerate() {
            let base = checked_segment_offset(
                "coverage entry",
                index,
                self.layout.coverage_ring_data_off,
                COVERAGE_ENTRY_SIZE,
                region_len,
            )?;
            write_coverage_entry_bytes(
                &mut bytes[base..base + COVERAGE_ENTRY_SIZE],
                coverage_entry,
            );
        }

        Ok(bytes)
    }

    /// Enqueues a frame into the directed ring from `src_slot` to `dst_slot`.
    ///
    /// # Errors
    ///
    /// Returns [`RegionAllocationAccessError`] when the directed ring does not
    /// exist, the backing range cannot be represented locally, or the SPSC
    /// enqueue operation rejects the frame.
    pub fn enqueue_directed_frame(
        &mut self,
        src_slot: u32,
        dst_slot: u32,
        frame: &FrameEntry,
    ) -> Result<(), RegionAllocationAccessError> {
        let ring_index = self.ring_index(src_slot, dst_slot)?;
        let entry_range = self.entry_range(ring_index)?;
        self.ring_headers[ring_index].enqueue(&mut self.frame_entries[entry_range], frame)?;
        Ok(())
    }

    /// Enqueues one plugin-produced coverage entry for `vm_slot`.
    ///
    /// This model helper uses the same SPSC publication primitive as the mapped
    /// plugin path and exists for cross-process transport tests.
    ///
    /// # Errors
    ///
    /// Returns [`RegionAllocationAccessError`] when the VM slot is absent, its
    /// fixed backing range cannot be represented, or the coverage ring rejects
    /// the entry.
    pub fn enqueue_coverage_entry(
        &mut self,
        vm_slot: u32,
        entry: CoverageEntry,
    ) -> Result<(), RegionAllocationAccessError> {
        if vm_slot >= self.layout.coverage_ring_count {
            return Err(RegionAllocationAccessError::UnknownCoverageRing {
                vm_slot,
                vm_node_count: self.layout.vm_node_count,
            });
        }
        let ring_index = usize::try_from(vm_slot).map_err(|_error| {
            RegionAllocationAccessError::CoverageEntryRangeOverflow { vm_slot }
        })?;
        let capacity = usize::try_from(self.layout.coverage_queue_capacity).map_err(|_error| {
            RegionAllocationAccessError::CoverageEntryRangeOverflow { vm_slot }
        })?;
        let start = ring_index
            .checked_mul(capacity)
            .ok_or(RegionAllocationAccessError::CoverageEntryRangeOverflow { vm_slot })?;
        let end = start
            .checked_add(capacity)
            .ok_or(RegionAllocationAccessError::CoverageEntryRangeOverflow { vm_slot })?;
        if end > self.coverage_entries.len() {
            return Err(RegionAllocationAccessError::CoverageEntryRangeOverflow { vm_slot });
        }
        self.coverage_ring_headers[ring_index]
            .enqueue_coverage(&mut self.coverage_entries[start..end], entry)?;
        Ok(())
    }

    /// Publishes pending inputs, then the scheduler ceiling, then the futex wake.
    ///
    /// This is the scheduler-side handoff primitive for RUN publication. Every
    /// pending frame is release-published to its directed inbox before the node
    /// slot release-stores `max_advance_icount` and increments `wake_signal`, so
    /// a woken plugin can acquire-observe a consistent `(ceiling,
    /// pending-inputs)` snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerWakePublicationError`] when the consumer slot does not
    /// exist, an inbox ring is missing or full, or the node slot rejects the
    /// scheduler ceiling or futex wake.
    pub fn publish_scheduler_inputs_and_ceiling(
        &mut self,
        dst_slot: u32,
        pending_inputs: &[PendingInputPublication],
        ceiling: AdvanceCeiling,
    ) -> Result<SchedulerWakePublication, SchedulerWakePublicationError> {
        let dst_index = self.slot_index(dst_slot)?;
        self.slots[dst_index].validate_scheduler_ceiling(ceiling)?;
        let enqueue_plans = self.scheduler_wake_enqueue_plans(dst_slot, pending_inputs)?;
        self.preflight_scheduler_wake_capacity(&enqueue_plans)?;

        for plan in enqueue_plans {
            let frame = &pending_inputs[plan.input_index].frame;
            self.ring_headers[plan.ring_index]
                .enqueue(&mut self.frame_entries[plan.entry_range], frame)
                .map_err(RegionAllocationAccessError::from)?;
        }

        let wake = self.slots[dst_index].publish_prevalidated_scheduler_ceiling(ceiling)?;
        Ok(SchedulerWakePublication {
            dst_slot,
            pending_input_count: pending_inputs.len(),
            max_advance_icount: ceiling.max_advance_icount,
            wake,
        })
    }

    /// Returns the head frame of a directed ring without consuming it.
    ///
    /// # Errors
    ///
    /// Returns [`RegionAllocationAccessError`] when the directed ring does not
    /// exist, the backing range cannot be represented locally, or the SPSC peek
    /// operation rejects the ring state.
    pub fn peek_directed_frame(
        &self,
        src_slot: u32,
        dst_slot: u32,
    ) -> Result<Option<FrameEntry>, RegionAllocationAccessError> {
        let ring_index = self.ring_index(src_slot, dst_slot)?;
        let entry_range = self.entry_range(ring_index)?;
        Ok(self.ring_headers[ring_index].peek(&self.frame_entries[entry_range])?)
    }

    /// Returns the head frame's delivery icount without consuming it.
    ///
    /// # Errors
    ///
    /// Returns [`RegionAllocationAccessError`] when the directed ring does not
    /// exist, the backing range cannot be represented locally, or the SPSC peek
    /// operation rejects the ring state.
    pub fn peek_directed_delivery_icount(
        &self,
        src_slot: u32,
        dst_slot: u32,
    ) -> Result<Option<u64>, RegionAllocationAccessError> {
        let ring_index = self.ring_index(src_slot, dst_slot)?;
        let entry_range = self.entry_range(ring_index)?;
        Ok(self.ring_headers[ring_index].peek_delivery_icount(&self.frame_entries[entry_range])?)
    }

    /// Dequeues the head frame from a directed ring.
    ///
    /// # Errors
    ///
    /// Returns [`RegionAllocationAccessError`] when the directed ring does not
    /// exist, the backing range cannot be represented locally, or the SPSC
    /// dequeue operation rejects the ring state.
    pub fn dequeue_directed_frame(
        &self,
        src_slot: u32,
        dst_slot: u32,
    ) -> Result<Option<FrameEntry>, RegionAllocationAccessError> {
        let ring_index = self.ring_index(src_slot, dst_slot)?;
        let entry_range = self.entry_range(ring_index)?;
        Ok(self.ring_headers[ring_index].dequeue(&self.frame_entries[entry_range])?)
    }

    fn slot_index(&self, slot: u32) -> Result<usize, SchedulerWakePublicationError> {
        let index = usize::try_from(slot)
            .map_err(|_error| SchedulerWakePublicationError::UnknownNodeSlot { slot })?;
        if index >= self.slots.len() {
            Err(SchedulerWakePublicationError::UnknownNodeSlot { slot })
        } else {
            Ok(index)
        }
    }

    fn scheduler_wake_enqueue_plans(
        &self,
        dst_slot: u32,
        pending_inputs: &[PendingInputPublication],
    ) -> Result<Vec<SchedulerWakeEnqueuePlan>, SchedulerWakePublicationError> {
        let mut plans = Vec::with_capacity(pending_inputs.len());
        for (input_index, input) in pending_inputs.iter().enumerate() {
            validate_pending_input_source(input_index, input.src_slot, &input.frame)?;
            let ring_index = self.ring_index(input.src_slot, dst_slot)?;
            let entry_range = self.entry_range(ring_index)?;
            plans.push(SchedulerWakeEnqueuePlan {
                ring_index,
                entry_range,
                input_index,
            });
        }
        Ok(plans)
    }

    fn preflight_scheduler_wake_capacity(
        &self,
        plans: &[SchedulerWakeEnqueuePlan],
    ) -> Result<(), RegionAllocationAccessError> {
        let mut checked_rings = Vec::new();
        for plan in plans {
            if checked_rings.contains(&plan.ring_index) {
                continue;
            }
            checked_rings.push(plan.ring_index);
            let ring = &self.ring_headers[plan.ring_index];
            let batch_count = plans
                .iter()
                .filter(|candidate| candidate.ring_index == plan.ring_index)
                .count() as u64;
            let entries = self.entry_range(plan.ring_index)?;
            preflight_ring_enqueue_capacity(ring, &self.frame_entries[entries], batch_count)?;
        }
        Ok(())
    }

    fn ring_index(
        &self,
        src_slot: u32,
        dst_slot: u32,
    ) -> Result<usize, RegionAllocationAccessError> {
        let ring = self
            .rings
            .iter()
            .find(|ring| ring.src_slot == src_slot && ring.dst_slot == dst_slot)
            .ok_or(RegionAllocationAccessError::UnknownDirectedRing { src_slot, dst_slot })?;
        usize::try_from(ring.index).map_err(|_error| {
            RegionAllocationAccessError::RingIndexOutOfRange {
                ring_index: ring.index,
            }
        })
    }

    fn entry_range(
        &self,
        ring_index: usize,
    ) -> Result<std::ops::Range<usize>, RegionAllocationAccessError> {
        let reported_ring_index = u32::try_from(ring_index).unwrap_or(u32::MAX);
        let capacity = usize::try_from(self.layout.queue_capacity).map_err(|_error| {
            RegionAllocationAccessError::RingEntryRangeOverflow {
                ring_index: reported_ring_index,
            }
        })?;
        let start = ring_index.checked_mul(capacity).ok_or(
            RegionAllocationAccessError::RingEntryRangeOverflow {
                ring_index: reported_ring_index,
            },
        )?;
        let end = start.checked_add(capacity).ok_or(
            RegionAllocationAccessError::RingEntryRangeOverflow {
                ring_index: reported_ring_index,
            },
        )?;
        if end > self.frame_entries.len() {
            return Err(RegionAllocationAccessError::RingEntryRangeOverflow {
                ring_index: reported_ring_index,
            });
        }
        Ok(start..end)
    }
}

/// An error produced while accessing a typed region allocation.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RegionAllocationAccessError {
    /// A directed shared-memory ring does not exist.
    #[error("region allocation has no directed ring from slot {src_slot} to slot {dst_slot}")]
    UnknownDirectedRing {
        /// Producer slot.
        src_slot: u32,
        /// Consumer slot.
        dst_slot: u32,
    },
    /// A VM slot does not have a plugin-to-host coverage ring.
    #[error(
        "region allocation has no coverage ring for VM slot {vm_slot}; VM count is {vm_node_count}"
    )]
    UnknownCoverageRing {
        /// Rejected VM slot.
        vm_slot: u32,
        /// Logical VM count.
        vm_node_count: u32,
    },
    /// A ring index could not be represented as a local vector index.
    #[error("region allocation ring index {ring_index} is outside the local ring table")]
    RingIndexOutOfRange {
        /// Rejected ring index.
        ring_index: u32,
    },
    /// A ring's backing frame-entry range overflowed.
    #[error("region allocation frame-entry range overflowed for ring {ring_index}")]
    RingEntryRangeOverflow {
        /// Rejected ring index.
        ring_index: u32,
    },
    /// A VM's compact coverage-entry range overflowed.
    #[error("region allocation coverage-entry range overflowed for VM slot {vm_slot}")]
    CoverageEntryRangeOverflow {
        /// Rejected VM slot.
        vm_slot: u32,
    },
    /// The shared-memory SPSC ring operation failed.
    #[error("region allocation SPSC ring operation failed")]
    SpscRing {
        /// Underlying SPSC ring error.
        #[from]
        source: SpscRingError,
    },
}

/// An error produced while publishing scheduler inputs, ceiling, and wake.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SchedulerWakePublicationError {
    /// The consumer physical slot does not exist in the region.
    #[error("region allocation has no node slot {slot}")]
    UnknownNodeSlot {
        /// Rejected physical slot index.
        slot: u32,
    },
    /// The directed inbox publication failed.
    #[error("scheduler wake inbox publication failed")]
    RegionAccess {
        /// Underlying region access error.
        #[from]
        source: RegionAllocationAccessError,
    },
    /// The consumer node slot rejected the ceiling or wake.
    #[error("scheduler wake node-slot publication failed")]
    NodeSlot {
        /// Underlying node-slot error.
        #[from]
        source: NodeSlotError,
    },
    /// A pending input's embedded source did not match its directed ring source.
    #[error(
        "scheduler wake pending input {input_index} frame source {frame_src_node} does not match ring source {expected_src_slot}"
    )]
    FrameSourceMismatch {
        /// Index in the pending-input batch.
        input_index: usize,
        /// Source slot selected for the directed ring.
        expected_src_slot: u32,
        /// Source node stamped into the frame entry.
        frame_src_node: u32,
    },
}

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

pub(super) fn directed_rings(vm_node_count: u32) -> Result<Vec<DirectedRing>, RegionLayoutError> {
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
    let layout = RegionLayout::for_config(RegionConfig::new(
        vm_node_count,
        snapshot.queue_capacity,
        snapshot.icount_shift,
    ))
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

pub(super) fn validate_pending_input_source(
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

pub(super) fn preflight_ring_enqueue_capacity(
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
