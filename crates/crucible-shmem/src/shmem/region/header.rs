//! Shared-memory region header layout, snapshots, and setup validation.

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
    _control_padding: [u8; 2],
    fault_payload_arena_bytes: AtomicU32,
    _reserved: [u8; 188],
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
            _control_padding: [0; 2],
            fault_payload_arena_bytes: AtomicU32::new(
                self.fault_payload_arena_bytes.load(Ordering::Acquire),
            ),
            _reserved: [0; 188],
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
/// Byte offset of [`RegionHeader`]'s alignment padding after control flags.
pub const REGION_HEADER_CONTROL_PADDING_OFFSET: usize =
    core::mem::offset_of!(RegionHeader, _control_padding);
/// Byte offset of [`RegionHeader`]'s per-direction fault payload-arena size.
pub const REGION_HEADER_FAULT_PAYLOAD_ARENA_BYTES_OFFSET: usize =
    core::mem::offset_of!(RegionHeader, fault_payload_arena_bytes);
/// Byte offset of [`RegionHeader`]'s reserved forward-compatibility bytes.
pub const REGION_HEADER_RESERVED_OFFSET: usize = core::mem::offset_of!(RegionHeader, _reserved);
/// Wire size of one [`RegionHeader`].
pub const REGION_HEADER_SIZE: usize = core::mem::size_of::<RegionHeader>();
/// Wire alignment of one [`RegionHeader`].
pub const REGION_HEADER_ALIGN: usize = core::mem::align_of::<RegionHeader>();

const _: () = assert!(REGION_HEADER_MAGIC_OFFSET == 0);
const _: () = assert!(REGION_HEADER_ABI_VERSION_OFFSET == 8);
const _: () = assert!(REGION_HEADER_NODE_COUNT_OFFSET == 12);
const _: () = assert!(REGION_HEADER_QUEUE_CAPACITY_OFFSET == 16);
const _: () = assert!(REGION_HEADER_RING_COUNT_OFFSET == 20);
const _: () = assert!(REGION_HEADER_RING_HDR_OFF_OFFSET == 24);
const _: () = assert!(REGION_HEADER_RING_DATA_OFF_OFFSET == 32);
const _: () = assert!(REGION_HEADER_ENTRY_STRIDE_OFFSET == 40);
const _: () = assert!(REGION_HEADER_REGION_SIZE_OFFSET == 48);
const _: () = assert!(REGION_HEADER_ICOUNT_SHIFT_OFFSET == 56);
const _: () = assert!(REGION_HEADER_PAUSE_REQUESTED_OFFSET == 60);
const _: () = assert!(REGION_HEADER_SHUTDOWN_REQUESTED_OFFSET == 61);
const _: () = assert!(REGION_HEADER_CONTROL_PADDING_OFFSET == 62);
const _: () = assert!(REGION_HEADER_FAULT_PAYLOAD_ARENA_BYTES_OFFSET == 64);
const _: () = assert!(REGION_HEADER_RESERVED_OFFSET == 68);
const _: () = assert!(REGION_HEADER_SIZE == 256);
const _: () = assert!(REGION_HEADER_ALIGN == 128);

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
            _control_padding: [0; 2],
            fault_payload_arena_bytes: AtomicU32::new(layout.fault_payload_arena_bytes),
            _reserved: [0; 188],
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
            fault_payload_arena_bytes: self.fault_payload_arena_bytes.load(Ordering::Acquire),
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
        self._control_padding.iter().all(|byte| *byte == 0)
            && self._reserved.iter().all(|byte| *byte == 0)
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
    /// Bytes in each per-node, per-direction fault payload arena.
    pub fault_payload_arena_bytes: u32,
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
