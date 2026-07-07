//! `crucible-shmem` owns the shared-memory ABI.
//!
//! Spec index: RFC-0010 files 13.
//!
//! This L1 crate is the single source of truth for the `#[repr(C)]` region
//! layout, per-node clocks, status words, and SPSC frame queues described by
//! its indexed RFC-0010 file. It is an unsafe-boundary crate because future
//! implementations map shared memory and expose layout-checked accessors.
//!
//! Module map: the crate root owns the initial frame-entry layout, the
//! delivery-icount contract, the Lamport SPSC frame queue, and the per-node
//! advance-ceiling slot. Future modules will split region headers and status
//! words.
//!
//! Unsafe boundary discipline: mmap, pointer, and atomic details stay private;
//! public callers use safe typed region accessors and safe SPSC push/pop
//! wrappers that uphold alignment, lifetime, and ordering invariants.
//!
//! Frame-entry wire layout:
//!
//! ```text
//! offset  size  field
//! 0       8     delivery_icount
//! 8       4     src_node
//! 12      4     seq
//! 16      2     len
//! 18      6     padding
//! 24      N     payload bytes
//! ```
//!
//! Per-node slot wire layout:
//!
//! ```text
//! offset  size  field
//! 0       8     current_icount
//! 8       8     current_ns
//! 16      8     max_advance_icount
//! 24      8     idle_wake_icount
//! 32      4     wake_signal
//! 36      1     status
//! 37      1     kind
//! 38      1     device_io_active
//! 39      1     padding
//! 40      4     publish_gen
//! 44      84    reserved
//! ```
//!
//! SPSC ring header wire layout:
//!
//! ```text
//! offset  size  field
//! 0       8     read_idx
//! 8       56    read-cacheline padding
//! 64      8     write_idx
//! 72      56    write-cacheline padding
//! ```

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]

mod abi_header;
#[cfg(unix)]
mod mapped_setup_region;

use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};

pub use abi_header::generated_c_header;
#[cfg(unix)]
pub use mapped_setup_region::{
    MappedDirectedRingMut, MappedNodeRingPairMut, MappedSetupRegion, MappedSetupRegionAccessError,
    SetupRegionMapError, mmap_setup_region,
};

use thiserror::Error;

/// The maximum frame payload carried by a shared-memory [`FrameEntry`].
///
/// This RFC-fixed value is sector-aligned, leaves room for a 4 KiB block
/// response plus protocol headroom, and still fits in [`FrameEntry::len`].
pub const MAX_FRAME_DATA: usize = 4608;

/// The default power-of-two capacity, in frame entries, for one SPSC ring.
pub const DEFAULT_QUEUE_CAPACITY: u32 = 64;

/// Eight-byte ASCII magic identifying a Crucible shared-memory region.
pub const REGION_MAGIC: u64 = u64::from_le_bytes(*b"CRUCSHM1");
/// Current shared-memory ABI version.
pub const ABI_VERSION: u32 = 1;
/// Compile-time physical slot capacity of one shared-memory region.
pub const MAX_NODES: usize = 32;
/// Number of physical slots reserved for executor endpoints.
pub const RESERVED_SLOTS: usize = 3;
/// Maximum number of logical VM nodes that fit in one region allocation.
pub const MAX_VM_NODES: usize = MAX_NODES - RESERVED_SLOTS;
/// Physical slot used by the deterministic network router executor.
pub const SLOT_NET_ROUTER: usize = MAX_NODES - 1;
/// Physical slot used by the block I/O executor.
pub const SLOT_BLK_IO: usize = MAX_NODES - 2;
/// Physical slot used by the 9p filesystem I/O executor.
pub const SLOT_9P_IO: usize = MAX_NODES - 3;
/// The pinned target triple for the ABI layout table.
pub const LAYOUT_TARGET_TRIPLE: &str = "x86_64-unknown-linux-gnu";
/// Whether this crate was compiled for the pinned ABI layout target.
pub const LAYOUT_TARGET_SUPPORTED: bool = cfg!(all(
    target_arch = "x86_64",
    target_abi = "",
    target_endian = "little",
    target_env = "gnu",
    target_os = "linux",
    target_pointer_width = "64"
));

const _: () = assert!(MAX_FRAME_DATA <= u16::MAX as usize);

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
const _: () = assert!(REGION_HEADER_RESERVED_OFFSET == 62);
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

fn validate_setup_region_header_and_layout(
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

fn layout_from_setup_region_header(
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
        let region_size = ring_data_off
            .checked_add(
                entry_count
                    .checked_mul(entry_stride)
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
            region_size,
            icount_shift: config.icount_shift,
        })
    }

    /// Returns the number of frame-entry slots in the backing storage.
    #[must_use]
    pub fn frame_entry_count(&self) -> u64 {
        u64::from(self.ring_count) * u64::from(self.queue_capacity)
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
struct SchedulerWakeEnqueuePlan {
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

        Ok(Self {
            header,
            slots,
            ring_headers,
            frame_entries,
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

fn compiled_layout_target() -> &'static str {
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

fn directed_rings(vm_node_count: u32) -> Result<Vec<DirectedRing>, RegionLayoutError> {
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

fn layout_from_setup_region_geometry(
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

fn node_slot_for_physical_index(vm_node_count: u32, slot: usize) -> NodeSlot {
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

fn usize_to_u64(value: usize) -> Result<u64, RegionLayoutError> {
    u64::try_from(value).map_err(|_| RegionLayoutError::GeometryOverflow)
}

fn checked_segment_offset(
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

fn write_region_header_bytes(
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

fn write_node_slot_bytes(bytes: &mut [u8], snapshot: NodeSlotSnapshot) {
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

fn write_ring_header_bytes(bytes: &mut [u8], ring_header: &RingHeader) {
    write_u64_at(bytes, RING_HEADER_READ_IDX_OFFSET, ring_header.read_index());
    write_u64_at(
        bytes,
        RING_HEADER_WRITE_IDX_OFFSET,
        ring_header.write_index(),
    );
}

fn write_frame_entry_bytes(bytes: &mut [u8], frame: &FrameEntry) {
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

fn write_u8_at(bytes: &mut [u8], offset: usize, value: u8) {
    bytes[offset] = value;
}

fn write_u16_at(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32_at(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64_at(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn validate_pending_input_source(
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

fn preflight_ring_enqueue_capacity(
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

fn wake_all_slots_for_control<'a>(
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

/// A Lamport SPSC ring header shared by exactly one producer and one consumer.
#[repr(C, align(128))]
pub struct RingHeader {
    read_idx: AtomicU64,
    _pad_read: [u8; 56],
    write_idx: AtomicU64,
    _pad_write: [u8; 56],
}

impl Clone for RingHeader {
    fn clone(&self) -> Self {
        Self {
            read_idx: AtomicU64::new(self.read_idx.load(Ordering::Acquire)),
            _pad_read: [0; 56],
            write_idx: AtomicU64::new(self.write_idx.load(Ordering::Acquire)),
            _pad_write: [0; 56],
        }
    }
}

/// Byte offset of [`RingHeader`]'s consumer-owned read index.
pub const RING_HEADER_READ_IDX_OFFSET: usize = core::mem::offset_of!(RingHeader, read_idx);
/// Byte offset of [`RingHeader`]'s consumer cache-line padding.
pub const RING_HEADER_PAD_READ_OFFSET: usize = core::mem::offset_of!(RingHeader, _pad_read);
/// Byte offset of [`RingHeader`]'s producer-owned write index.
pub const RING_HEADER_WRITE_IDX_OFFSET: usize = core::mem::offset_of!(RingHeader, write_idx);
/// Byte offset of [`RingHeader`]'s producer cache-line padding.
pub const RING_HEADER_PAD_WRITE_OFFSET: usize = core::mem::offset_of!(RingHeader, _pad_write);
/// Wire size of one [`RingHeader`].
pub const RING_HEADER_SIZE: usize = core::mem::size_of::<RingHeader>();
/// Wire alignment of one [`RingHeader`].
pub const RING_HEADER_ALIGN: usize = core::mem::align_of::<RingHeader>();

const _: () = assert!(RING_HEADER_READ_IDX_OFFSET == 0);
const _: () = assert!(RING_HEADER_PAD_READ_OFFSET == 8);
const _: () = assert!(RING_HEADER_WRITE_IDX_OFFSET == 64);
const _: () = assert!(RING_HEADER_PAD_WRITE_OFFSET == 72);
const _: () = assert!(RING_HEADER_SIZE == 128);
const _: () = assert!(RING_HEADER_ALIGN == 128);

impl RingHeader {
    /// Builds an empty SPSC ring header.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            read_idx: AtomicU64::new(0),
            _pad_read: [0; 56],
            write_idx: AtomicU64::new(0),
            _pad_write: [0; 56],
        }
    }

    /// Enqueues one frame into producer-owned storage.
    ///
    /// The producer writes the frame bytes before publishing the new
    /// `write_idx` with release ordering. The consumer acquire-loads
    /// `write_idx` before reading the entry.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError::InvalidCapacity`] when `entries` is empty or not
    /// power-of-two sized, [`SpscRingError::CorruptIndices`] when the header
    /// contains an impossible live count, or [`SpscRingError::QueueFull`] when
    /// the ring is full.
    pub fn enqueue(
        &self,
        entries: &mut [FrameEntry],
        frame: &FrameEntry,
    ) -> Result<(), SpscRingError> {
        let capacity = validated_capacity(entries)?;
        let tail = self.write_idx.load(Ordering::Relaxed);
        let head = self.read_idx.load(Ordering::Acquire);
        let live = live_count(head, tail, capacity)?;
        if live == capacity {
            return Err(SpscRingError::QueueFull { capacity });
        }

        let slot = (tail & (capacity - 1)) as usize;
        entries[slot] = frame.clone();
        self.write_idx
            .store(tail.wrapping_add(1), Ordering::Release);
        Ok(())
    }

    /// Returns the next frame's delivery icount without consuming it.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when `entries` has invalid capacity or the ring
    /// indices describe more live entries than the capacity can hold.
    pub fn peek_delivery_icount(
        &self,
        entries: &[FrameEntry],
    ) -> Result<Option<u64>, SpscRingError> {
        let capacity = validated_capacity(entries)?;
        let head = self.read_idx.load(Ordering::Relaxed);
        let tail = self.write_idx.load(Ordering::Acquire);
        if live_count(head, tail, capacity)? == 0 {
            return Ok(None);
        }

        let slot = (head & (capacity - 1)) as usize;
        Ok(Some(entries[slot].delivery_icount))
    }

    /// Returns the next frame without consuming it.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when `entries` has invalid capacity or the ring
    /// indices describe more live entries than the capacity can hold.
    pub fn peek(&self, entries: &[FrameEntry]) -> Result<Option<FrameEntry>, SpscRingError> {
        let capacity = validated_capacity(entries)?;
        let head = self.read_idx.load(Ordering::Relaxed);
        let tail = self.write_idx.load(Ordering::Acquire);
        if live_count(head, tail, capacity)? == 0 {
            return Ok(None);
        }

        let slot = (head & (capacity - 1)) as usize;
        Ok(Some(entries[slot].clone()))
    }

    /// Dequeues one frame from consumer-owned storage.
    ///
    /// The consumer acquire-loads `write_idx`, copies the entry, then frees the
    /// slot by release-storing the incremented `read_idx` for the producer.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when `entries` has invalid capacity or the ring
    /// indices describe more live entries than the capacity can hold.
    pub fn dequeue(&self, entries: &[FrameEntry]) -> Result<Option<FrameEntry>, SpscRingError> {
        let capacity = validated_capacity(entries)?;
        let head = self.read_idx.load(Ordering::Relaxed);
        let tail = self.write_idx.load(Ordering::Acquire);
        if live_count(head, tail, capacity)? == 0 {
            return Ok(None);
        }

        let slot = (head & (capacity - 1)) as usize;
        let frame = entries[slot].clone();
        self.read_idx.store(head.wrapping_add(1), Ordering::Release);
        Ok(Some(frame))
    }

    /// Captures the live ring entries in FIFO order under quiescence.
    ///
    /// This method is not concurrency-safe; callers must ensure the producer and
    /// consumer are paused.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError`] when `entries` has invalid capacity or the ring
    /// indices describe more live entries than the capacity can hold.
    pub fn snapshot(&self, entries: &[FrameEntry]) -> Result<SpscRingSnapshot, SpscRingError> {
        let capacity = validated_capacity(entries)?;
        let head = self.read_idx.load(Ordering::Acquire);
        let tail = self.write_idx.load(Ordering::Acquire);
        let live = live_count(head, tail, capacity)?;
        let mut frames = Vec::with_capacity(live as usize);
        for offset in 0..live {
            let slot = ((head.wrapping_add(offset)) & (capacity - 1)) as usize;
            frames.push(entries[slot].canonicalized_for_snapshot()?);
        }

        Ok(SpscRingSnapshot { frames })
    }

    /// Restores a quiesced ring from a FIFO snapshot and normalizes indices.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError::InvalidCapacity`] when `entries` is empty or not
    /// power-of-two sized, or [`SpscRingError::SnapshotTooLarge`] when the
    /// snapshot does not fit in the ring.
    pub fn restore(
        &self,
        entries: &mut [FrameEntry],
        snapshot: &SpscRingSnapshot,
    ) -> Result<(), SpscRingError> {
        let capacity = validated_capacity(entries)?;
        if snapshot.frames.len() as u64 > capacity {
            return Err(SpscRingError::SnapshotTooLarge {
                len: snapshot.frames.len(),
                capacity,
            });
        }

        for (slot, frame) in snapshot.frames.iter().enumerate() {
            entries[slot] = frame.clone();
        }
        self.read_idx.store(0, Ordering::Release);
        self.write_idx
            .store(snapshot.frames.len() as u64, Ordering::Release);
        Ok(())
    }

    /// Returns the current consumer-owned read index.
    #[must_use]
    pub fn read_index(&self) -> u64 {
        self.read_idx.load(Ordering::Acquire)
    }

    /// Returns the current producer-owned write index.
    #[must_use]
    pub fn write_index(&self) -> u64 {
        self.write_idx.load(Ordering::Acquire)
    }

    /// Returns `true` when the cache-line padding bytes are zero.
    #[must_use]
    pub fn padding_bytes_are_zero(&self) -> bool {
        self._pad_read.iter().all(|byte| *byte == 0)
            && self._pad_write.iter().all(|byte| *byte == 0)
    }
}

impl Default for RingHeader {
    fn default() -> Self {
        Self::new()
    }
}

/// A quiescent FIFO snapshot of an SPSC ring.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SpscRingSnapshot {
    /// Live frames in `read_idx..write_idx` FIFO order.
    pub frames: Vec<FrameEntry>,
}

impl SpscRingSnapshot {
    /// Serializes the live frames into padding-independent canonical bytes.
    ///
    /// The encoding is little-endian and contains the frame count followed by
    /// each frame's delivery icount, source node, sequence, payload length, and
    /// valid payload bytes. Frame padding and unused payload capacity are excluded
    /// so equivalent logical snapshots content-address identically.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError::InvalidFrameLength`] when any frame advertises a
    /// payload length larger than [`MAX_FRAME_DATA`], or
    /// [`SpscRingError::SnapshotLengthOverflow`] when the frame count cannot fit
    /// in the canonical encoding.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, SpscRingError> {
        let frame_count = u64::try_from(self.frames.len()).map_err(|_| {
            SpscRingError::SnapshotLengthOverflow {
                len: self.frames.len(),
            }
        })?;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&frame_count.to_le_bytes());
        for frame in &self.frames {
            let canonical = frame.canonicalized_for_snapshot()?;
            let payload_len = usize::from(canonical.len);
            bytes.extend_from_slice(&canonical.delivery_icount.to_le_bytes());
            bytes.extend_from_slice(&canonical.src_node.to_le_bytes());
            bytes.extend_from_slice(&canonical.seq.to_le_bytes());
            bytes.extend_from_slice(&canonical.len.to_le_bytes());
            bytes.extend_from_slice(&canonical.data[..payload_len]);
        }
        Ok(bytes)
    }

    /// Decodes a snapshot from [`SpscRingSnapshot::canonical_bytes`].
    ///
    /// The decoder accepts only the canonical little-endian byte stream and
    /// rejects truncated frames, impossible payload lengths, and trailing bytes.
    /// Decoded frames are rebuilt through [`FrameEntry::new`] so padding and
    /// unused payload capacity are normalized before the snapshot is returned.
    ///
    /// # Errors
    ///
    /// Returns [`SpscRingError::SnapshotDecodeTruncated`] when the byte stream
    /// ends before a field or payload is complete,
    /// [`SpscRingError::InvalidFrameLength`] when a frame length exceeds
    /// [`MAX_FRAME_DATA`], [`SpscRingError::SnapshotFrameCountOverflow`] when
    /// the encoded frame count cannot fit in memory on this target, or
    /// [`SpscRingError::SnapshotDecodeTrailingBytes`] when extra bytes remain
    /// after the declared frames.
    pub fn from_canonical_bytes(bytes: &[u8]) -> Result<Self, SpscRingError> {
        let mut cursor = SnapshotByteCursor::new(bytes);
        let frame_count = cursor.read_u64()?;
        let _frame_count_fits_target = usize::try_from(frame_count)
            .map_err(|_| SpscRingError::SnapshotFrameCountOverflow { count: frame_count })?;
        let mut frames = Vec::new();

        for _ in 0..frame_count {
            let delivery_icount = cursor.read_u64()?;
            let src_node = cursor.read_u32()?;
            let seq = cursor.read_u32()?;
            let len = usize::from(cursor.read_u16()?);
            if len > MAX_FRAME_DATA {
                return Err(SpscRingError::InvalidFrameLength {
                    len,
                    capacity: MAX_FRAME_DATA,
                });
            }
            let payload = cursor.read_bytes(len)?;
            let frame = FrameEntry::new(delivery_icount, src_node, seq, payload).map_err(
                |FrameEntryError::PayloadLengthExceedsCapacity { len, capacity }| {
                    SpscRingError::InvalidFrameLength { len, capacity }
                },
            )?;
            frames.push(frame);
        }

        cursor.finish()?;
        Ok(Self { frames })
    }
}

struct SnapshotByteCursor<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> SnapshotByteCursor<'a> {
    const fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn read_u16(&mut self) -> Result<u16, SpscRingError> {
        let bytes = self.read_bytes(2)?;
        Ok(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn read_u32(&mut self) -> Result<u32, SpscRingError> {
        let bytes = self.read_bytes(4)?;
        Ok(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn read_u64(&mut self) -> Result<u64, SpscRingError> {
        let bytes = self.read_bytes(8)?;
        Ok(u64::from_le_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    fn read_bytes(&mut self, len: usize) -> Result<&'a [u8], SpscRingError> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or(SpscRingError::SnapshotDecodeTruncated {
                offset: self.offset,
                needed: len,
                available: self.bytes.len().saturating_sub(self.offset),
            })?;
        if end > self.bytes.len() {
            return Err(SpscRingError::SnapshotDecodeTruncated {
                offset: self.offset,
                needed: len,
                available: self.bytes.len().saturating_sub(self.offset),
            });
        }
        let bytes = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(bytes)
    }

    fn finish(&self) -> Result<(), SpscRingError> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(SpscRingError::SnapshotDecodeTrailingBytes {
                offset: self.offset,
                available: self.bytes.len() - self.offset,
            })
        }
    }
}

/// A shared-memory frame whose delivery time is carried in band.
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct FrameEntry {
    /// The consumer icount at which the frame becomes visible.
    pub delivery_icount: u64,
    /// The producer node id.
    pub src_node: u32,
    /// The per-producer sequence number.
    pub seq: u32,
    /// The number of valid bytes in [`FrameEntry::data`].
    pub len: u16,
    _pad: [u8; 6],
    /// The fixed-capacity frame payload buffer.
    pub data: [u8; MAX_FRAME_DATA],
}

/// Byte offset of [`FrameEntry`]'s delivery-icount field.
pub const FRAME_ENTRY_DELIVERY_ICOUNT_OFFSET: usize =
    core::mem::offset_of!(FrameEntry, delivery_icount);
/// Byte offset of [`FrameEntry`]'s source-node field.
pub const FRAME_ENTRY_SRC_NODE_OFFSET: usize = core::mem::offset_of!(FrameEntry, src_node);
/// Byte offset of [`FrameEntry`]'s producer-sequence field.
pub const FRAME_ENTRY_SEQ_OFFSET: usize = core::mem::offset_of!(FrameEntry, seq);
/// Byte offset of [`FrameEntry`]'s payload-length field.
pub const FRAME_ENTRY_LEN_OFFSET: usize = core::mem::offset_of!(FrameEntry, len);
/// Byte offset of [`FrameEntry`]'s reserved padding bytes.
pub const FRAME_ENTRY_PAD_OFFSET: usize = core::mem::offset_of!(FrameEntry, _pad);
/// Byte offset of [`FrameEntry`]'s payload data.
pub const FRAME_ENTRY_DATA_OFFSET: usize = core::mem::offset_of!(FrameEntry, data);
/// Wire size of one [`FrameEntry`].
pub const FRAME_ENTRY_SIZE: usize = core::mem::size_of::<FrameEntry>();
/// Wire alignment of one [`FrameEntry`].
pub const FRAME_ENTRY_ALIGN: usize = core::mem::align_of::<FrameEntry>();

const _: () = assert!(FRAME_ENTRY_DELIVERY_ICOUNT_OFFSET == 0);
const _: () = assert!(FRAME_ENTRY_SRC_NODE_OFFSET == 8);
const _: () = assert!(FRAME_ENTRY_SEQ_OFFSET == 12);
const _: () = assert!(FRAME_ENTRY_LEN_OFFSET == 16);
const _: () = assert!(FRAME_ENTRY_PAD_OFFSET == 18);
const _: () = assert!(FRAME_ENTRY_DATA_OFFSET == 24);
const _: () = assert!(FRAME_ENTRY_SIZE == FRAME_ENTRY_DATA_OFFSET + MAX_FRAME_DATA);
const _: () = assert!(FRAME_ENTRY_ALIGN == 8);
const _: () = assert!(core::mem::offset_of!(FrameEntry, delivery_icount) == 0);
const _: () = assert!(core::mem::offset_of!(FrameEntry, src_node) == 8);
const _: () = assert!(core::mem::offset_of!(FrameEntry, seq) == 12);
const _: () = assert!(core::mem::offset_of!(FrameEntry, len) == 16);
const _: () = assert!(core::mem::offset_of!(FrameEntry, data) == FRAME_ENTRY_DATA_OFFSET);
#[rustfmt::skip]
const _: () = assert!(core::mem::size_of::<FrameEntry>() == FRAME_ENTRY_DATA_OFFSET + MAX_FRAME_DATA);
const _: () = assert!(core::mem::align_of::<FrameEntry>() == 8);

/// Node status: actively retiring instructions or processing an I/O burst.
pub const STATUS_RUNNING: u8 = 0;
/// Node status: idle, waiting for a timer, frame, or raised ceiling.
pub const STATUS_IDLE: u8 = 1;
/// Node status: simulation complete.
pub const STATUS_DONE: u8 = 2;

/// Node kind: a QEMU guest VM.
pub const KIND_VM: u8 = 0;
/// Node kind: a network-link or routing I/O node.
pub const KIND_NET: u8 = 1;
/// Node kind: a block-device I/O node.
pub const KIND_BLK: u8 = 2;
/// Node kind: a 9p-filesystem I/O node.
pub const KIND_9P: u8 = 3;

/// The advance-ceiling futex uses the cross-process operation, not private futexes.
pub const FUTEX_PRIVATE: bool = false;

/// A per-node shared-memory slot for clock and advance-ceiling handoff.
#[repr(C, align(128))]
pub struct NodeSlot {
    current_icount: AtomicU64,
    current_ns: AtomicU64,
    max_advance_icount: AtomicU64,
    idle_wake_icount: AtomicU64,
    wake_signal: AtomicU32,
    status: AtomicU8,
    kind: AtomicU8,
    device_io_active: AtomicU8,
    _pad0: u8,
    publish_gen: AtomicU32,
    _reserved: [u8; 84],
}

impl Clone for NodeSlot {
    fn clone(&self) -> Self {
        Self {
            current_icount: AtomicU64::new(self.current_icount.load(Ordering::Acquire)),
            current_ns: AtomicU64::new(self.current_ns.load(Ordering::Acquire)),
            max_advance_icount: AtomicU64::new(self.max_advance_icount.load(Ordering::Acquire)),
            idle_wake_icount: AtomicU64::new(self.idle_wake_icount.load(Ordering::Acquire)),
            wake_signal: AtomicU32::new(self.wake_signal.load(Ordering::Acquire)),
            status: AtomicU8::new(self.status.load(Ordering::Acquire)),
            kind: AtomicU8::new(self.kind.load(Ordering::Acquire)),
            device_io_active: AtomicU8::new(self.device_io_active.load(Ordering::Acquire)),
            _pad0: 0,
            publish_gen: AtomicU32::new(self.publish_gen.load(Ordering::Acquire)),
            _reserved: [0; 84],
        }
    }
}

/// Byte offset of [`NodeSlot`]'s canonical current icount field.
pub const NODE_SLOT_CURRENT_ICOUNT_OFFSET: usize = core::mem::offset_of!(NodeSlot, current_icount);
/// Byte offset of [`NodeSlot`]'s derived current virtual-time field.
pub const NODE_SLOT_CURRENT_NS_OFFSET: usize = core::mem::offset_of!(NodeSlot, current_ns);
/// Byte offset of [`NodeSlot`]'s scheduler-published advance ceiling.
pub const NODE_SLOT_MAX_ADVANCE_ICOUNT_OFFSET: usize =
    core::mem::offset_of!(NodeSlot, max_advance_icount);
/// Byte offset of [`NodeSlot`]'s idle wake icount field.
pub const NODE_SLOT_IDLE_WAKE_ICOUNT_OFFSET: usize =
    core::mem::offset_of!(NodeSlot, idle_wake_icount);
/// Byte offset of [`NodeSlot`]'s futex wake-signal field.
pub const NODE_SLOT_WAKE_SIGNAL_OFFSET: usize = core::mem::offset_of!(NodeSlot, wake_signal);
/// Byte offset of [`NodeSlot`]'s status field.
pub const NODE_SLOT_STATUS_OFFSET: usize = core::mem::offset_of!(NodeSlot, status);
/// Byte offset of [`NodeSlot`]'s kind field.
pub const NODE_SLOT_KIND_OFFSET: usize = core::mem::offset_of!(NodeSlot, kind);
/// Byte offset of [`NodeSlot`]'s device-I/O-active field.
pub const NODE_SLOT_DEVICE_IO_ACTIVE_OFFSET: usize =
    core::mem::offset_of!(NodeSlot, device_io_active);
/// Byte offset of [`NodeSlot`]'s single-byte alignment padding.
pub const NODE_SLOT_PAD0_OFFSET: usize = core::mem::offset_of!(NodeSlot, _pad0);
/// Byte offset of [`NodeSlot`]'s publish-generation field.
pub const NODE_SLOT_PUBLISH_GEN_OFFSET: usize = core::mem::offset_of!(NodeSlot, publish_gen);
/// Byte offset of [`NodeSlot`]'s reserved forward-compatibility bytes.
pub const NODE_SLOT_RESERVED_OFFSET: usize = core::mem::offset_of!(NodeSlot, _reserved);
/// Wire size of one [`NodeSlot`].
pub const NODE_SLOT_SIZE: usize = core::mem::size_of::<NodeSlot>();
/// Wire alignment of one [`NodeSlot`].
pub const NODE_SLOT_ALIGN: usize = core::mem::align_of::<NodeSlot>();

const _: () = assert!(NODE_SLOT_CURRENT_ICOUNT_OFFSET == 0);
const _: () = assert!(NODE_SLOT_CURRENT_NS_OFFSET == 8);
const _: () = assert!(NODE_SLOT_MAX_ADVANCE_ICOUNT_OFFSET == 16);
const _: () = assert!(NODE_SLOT_IDLE_WAKE_ICOUNT_OFFSET == 24);
const _: () = assert!(NODE_SLOT_WAKE_SIGNAL_OFFSET == 32);
const _: () = assert!(NODE_SLOT_STATUS_OFFSET == 36);
const _: () = assert!(NODE_SLOT_KIND_OFFSET == 37);
const _: () = assert!(NODE_SLOT_DEVICE_IO_ACTIVE_OFFSET == 38);
const _: () = assert!(NODE_SLOT_PAD0_OFFSET == 39);
const _: () = assert!(NODE_SLOT_PUBLISH_GEN_OFFSET == 40);
const _: () = assert!(NODE_SLOT_RESERVED_OFFSET == 44);
const _: () = assert!(NODE_SLOT_SIZE == 128);
const _: () = assert!(NODE_SLOT_ALIGN == 128);

impl NodeSlot {
    /// Builds a zeroed node slot with `max_advance_icount` held at the boot barrier.
    #[must_use]
    pub const fn new(kind: u8) -> Self {
        Self::new_with_status(kind, STATUS_IDLE)
    }

    const fn new_with_status(kind: u8, status: u8) -> Self {
        Self {
            current_icount: AtomicU64::new(0),
            current_ns: AtomicU64::new(0),
            max_advance_icount: AtomicU64::new(0),
            idle_wake_icount: AtomicU64::new(0),
            wake_signal: AtomicU32::new(0),
            status: AtomicU8::new(status),
            kind: AtomicU8::new(kind),
            device_io_active: AtomicU8::new(0),
            _pad0: 0,
            publish_gen: AtomicU32::new(0),
            _reserved: [0; 84],
        }
    }

    /// Publishes a scheduler-computed advance ceiling and returns the wake action.
    ///
    /// The ceiling is release-stored so the governed node can acquire-load it
    /// before deciding whether more advancement is authorized.
    ///
    /// # Errors
    ///
    /// Returns [`NodeSlotError::CeilingBeforePublishedCurrent`] when the ceiling
    /// is already behind the slot's published current icount, or
    /// [`NodeSlotError::FutexWake`] when the non-private futex wake syscall
    /// fails.
    pub fn publish_scheduler_ceiling(
        &self,
        ceiling: AdvanceCeiling,
    ) -> Result<WakeAction, NodeSlotError> {
        self.validate_scheduler_ceiling(ceiling)?;

        self.publish_prevalidated_scheduler_ceiling(ceiling)
    }

    /// Publishes pending inbox frames, then the scheduler ceiling, then the wake.
    ///
    /// This borrowed-ring variant is for runtime adapters that hold one node
    /// slot and one inbound SPSC ring rather than a typed [`RegionAllocation`].
    /// It validates the ceiling and ring capacity before publishing any frame,
    /// release-publishes every frame to the inbox, release-publishes the
    /// ceiling, and only then increments the non-private futex wake word.
    ///
    /// # Errors
    ///
    /// Returns [`SchedulerWakePublicationError`] when the node slot rejects the
    /// ceiling, an input frame is stamped with a different source than
    /// `src_slot`, the inbox rejects the batch, or the futex wake fails.
    pub fn publish_scheduler_inbox_and_ceiling(
        &self,
        dst_slot: u32,
        src_slot: u32,
        inbox: &RingHeader,
        inbox_entries: &mut [FrameEntry],
        pending_inputs: &[FrameEntry],
        ceiling: AdvanceCeiling,
    ) -> Result<SchedulerWakePublication, SchedulerWakePublicationError> {
        self.validate_scheduler_ceiling(ceiling)?;
        for (input_index, frame) in pending_inputs.iter().enumerate() {
            validate_pending_input_source(input_index, src_slot, frame)?;
        }
        preflight_ring_enqueue_capacity(inbox, inbox_entries, pending_inputs.len())
            .map_err(RegionAllocationAccessError::from)?;

        for frame in pending_inputs {
            inbox
                .enqueue(inbox_entries, frame)
                .map_err(RegionAllocationAccessError::from)?;
        }

        let wake = self.publish_prevalidated_scheduler_ceiling(ceiling)?;
        Ok(SchedulerWakePublication {
            dst_slot,
            pending_input_count: pending_inputs.len(),
            max_advance_icount: ceiling.max_advance_icount,
            wake,
        })
    }

    /// Loads the scheduler-published ceiling with acquire ordering.
    #[must_use]
    pub fn load_node_ceiling(&self) -> u64 {
        self.max_advance_icount.load(Ordering::Acquire)
    }

    /// Publishes that this node has plugin-submitted device I/O in flight.
    pub fn mark_device_io_active(&self) {
        self.publish_device_io_active(true);
    }

    /// Publishes that this node no longer has plugin-submitted device I/O in flight.
    pub fn clear_device_io_active(&self) {
        self.publish_device_io_active(false);
    }

    /// Returns whether plugin-submitted device I/O is currently active.
    #[must_use]
    pub fn load_device_io_active(&self) -> bool {
        self.device_io_active.load(Ordering::Acquire) != 0
    }

    /// Checks whether a node may advance to `next_icount` under the current ceiling.
    ///
    /// # Errors
    ///
    /// Returns [`NodeSlotError::NodeAdvancePastCeiling`] when `next_icount`
    /// exceeds the acquire-loaded scheduler ceiling.
    pub fn check_node_may_advance_to(&self, next_icount: u64) -> Result<(), NodeSlotError> {
        let max_advance_icount = self.load_node_ceiling();
        if next_icount > max_advance_icount {
            Err(NodeSlotError::NodeAdvancePastCeiling {
                next_icount,
                max_advance_icount,
            })
        } else {
            Ok(())
        }
    }

    /// Publishes the reached icount and derived virtual time while the node runs.
    ///
    /// # Errors
    ///
    /// Returns [`NodeSlotError`] when the reached icount exceeds the published
    /// ceiling or cannot be converted to virtual nanoseconds under `shift_bits`.
    pub fn publish_reached_icount(
        &self,
        reached_icount: u64,
        shift_bits: u8,
    ) -> Result<(), NodeSlotError> {
        self.check_node_may_advance_to(reached_icount)?;
        let current_ns = icount_to_virtual_ns(reached_icount, shift_bits)?;
        self.publish_state(reached_icount, current_ns, None, STATUS_RUNNING);
        Ok(())
    }

    /// Publishes that the node is idle and prepares the futex wait precondition.
    ///
    /// # Errors
    ///
    /// Returns [`NodeSlotError`] when `reached_icount` exceeds the published
    /// ceiling, `idle_wake_icount` is behind `reached_icount`, or virtual-time
    /// conversion fails under `shift_bits`.
    pub fn publish_idle(
        &self,
        reached_icount: u64,
        idle_wake_icount: u64,
        shift_bits: u8,
    ) -> Result<FutexWait, NodeSlotError> {
        self.check_node_may_advance_to(reached_icount)?;
        if idle_wake_icount < reached_icount {
            return Err(NodeSlotError::IdleWakeBeforeCurrent {
                current_icount: reached_icount,
                idle_wake_icount,
            });
        }

        let current_ns = icount_to_virtual_ns(reached_icount, shift_bits)?;
        self.publish_state(
            reached_icount,
            current_ns,
            Some(idle_wake_icount),
            STATUS_IDLE,
        );
        Ok(self.prepare_futex_wait())
    }

    /// Publishes that a node quiesced at a pause boundary.
    ///
    /// # Errors
    ///
    /// Returns [`NodeSlotError`] when virtual-time conversion fails under
    /// `shift_bits`.
    pub fn publish_pause_quiesced(
        &self,
        reached_icount: u64,
        shift_bits: u8,
    ) -> Result<(), NodeSlotError> {
        let current_ns = icount_to_virtual_ns(reached_icount, shift_bits)?;
        self.publish_state(
            reached_icount,
            current_ns,
            Some(reached_icount),
            STATUS_IDLE,
        );
        Ok(())
    }

    /// Computes the race-free futex wait decision after an idle publish.
    #[must_use]
    pub fn prepare_futex_wait(&self) -> FutexWait {
        let expected = self.wake_signal.load(Ordering::Acquire);
        if self.is_runnable_after_idle_publish() {
            FutexWait::Runnable
        } else {
            FutexWait::Wait { expected }
        }
    }

    /// Returns `true` if a futex wait on `expected` is still warranted.
    #[must_use]
    pub fn futex_wait_still_valid(&self, expected: u32) -> bool {
        self.wake_signal.load(Ordering::Acquire) == expected
            && !self.is_runnable_after_idle_publish()
    }

    /// Marks a woken node as running.
    pub fn mark_running(&self) {
        self.publish_gen.fetch_add(1, Ordering::AcqRel);
        self.status.store(STATUS_RUNNING, Ordering::Release);
        self.publish_gen.fetch_add(1, Ordering::AcqRel);
    }

    /// Marks a node as done after it observes shutdown.
    pub fn mark_done(&self) {
        self.publish_gen.fetch_add(1, Ordering::AcqRel);
        self.status.store(STATUS_DONE, Ordering::Release);
        self.publish_gen.fetch_add(1, Ordering::AcqRel);
    }

    /// Wakes a node because an inbound frame became actionable.
    ///
    /// # Errors
    ///
    /// Returns [`FutexError`] when the Linux futex wake syscall fails for an
    /// unexpected reason. Non-Linux developer-tooling builds return a no-op
    /// success with zero woken waiters.
    pub fn wake_for_frame_delivery(&self) -> Result<WakeAction, FutexError> {
        self.wake_after_signal_increment()
    }

    /// Wakes a node because an in-flight device-I/O hold was released.
    ///
    /// # Errors
    ///
    /// Returns [`FutexError`] when the Linux futex wake syscall fails for an
    /// unexpected reason. Non-Linux developer-tooling builds return a no-op
    /// success with zero woken waiters.
    pub fn wake_for_device_io_release(&self) -> Result<WakeAction, FutexError> {
        self.wake_after_signal_increment()
    }

    /// Issues a non-private futex wake on this node's wake-signal word.
    ///
    /// # Errors
    ///
    /// Returns [`FutexError`] when the Linux futex syscall fails for a reason
    /// other than no waiters. Non-Linux developer-tooling builds return a
    /// no-op success with zero woken waiters.
    pub fn futex_wake_nonprivate(&self, max_waiters: u32) -> Result<FutexWakeResult, FutexError> {
        futex_wake_nonprivate(&self.wake_signal, max_waiters)
    }

    /// Waits on this node's wake-signal word using non-private `FUTEX_WAIT`.
    ///
    /// # Errors
    ///
    /// Returns [`FutexError`] when the Linux futex syscall fails for an
    /// unexpected reason. Non-Linux developer-tooling builds return
    /// [`FutexWaitOutcome::Noop`] after the race-free pre-check.
    pub fn futex_wait_nonprivate(&self, wait: FutexWait) -> Result<FutexWaitOutcome, FutexError> {
        match wait {
            FutexWait::Runnable => Ok(FutexWaitOutcome::Runnable),
            FutexWait::Wait { expected } => {
                if self.futex_wait_still_valid(expected) {
                    self.futex_wait_word_nonprivate(expected)
                } else {
                    Ok(FutexWaitOutcome::ValueChanged)
                }
            }
        }
    }

    /// Calls non-private `FUTEX_WAIT` directly on the wake-signal word.
    ///
    /// This is the safe syscall wrapper used after the race-free re-check. A
    /// concurrent wake that changes the word before the syscall parks returns
    /// [`FutexWaitOutcome::ValueChanged`].
    ///
    /// # Errors
    ///
    /// Returns [`FutexError`] when the Linux futex syscall fails for an
    /// unexpected reason. Non-Linux developer-tooling builds return
    /// [`FutexWaitOutcome::Noop`].
    pub fn futex_wait_word_nonprivate(
        &self,
        expected: u32,
    ) -> Result<FutexWaitOutcome, FutexError> {
        futex_wait_nonprivate(&self.wake_signal, expected)
    }

    /// Returns a stable snapshot of the slot's published fields.
    #[must_use]
    pub fn snapshot(&self) -> NodeSlotSnapshot {
        loop {
            let before = self.publish_gen.load(Ordering::Acquire);
            if !before.is_multiple_of(2) {
                continue;
            }
            let snapshot = NodeSlotSnapshot {
                current_icount: self.current_icount.load(Ordering::Acquire),
                current_ns: self.current_ns.load(Ordering::Acquire),
                max_advance_icount: self.max_advance_icount.load(Ordering::Acquire),
                idle_wake_icount: self.idle_wake_icount.load(Ordering::Acquire),
                wake_signal: self.wake_signal.load(Ordering::Acquire),
                status: self.status.load(Ordering::Acquire),
                kind: self.kind.load(Ordering::Acquire),
                device_io_active: self.device_io_active.load(Ordering::Acquire),
                publish_gen: before,
            };
            let after = self.publish_gen.load(Ordering::Acquire);
            if before == after && after.is_multiple_of(2) {
                return snapshot;
            }
        }
    }

    /// Returns `true` when all forward-compatible reserved slot bytes are zero.
    #[must_use]
    pub fn reserved_bytes_are_zero(&self) -> bool {
        self._pad0 == 0 && self._reserved.iter().all(|byte| *byte == 0)
    }

    fn publish_state(
        &self,
        current_icount: u64,
        current_ns: u64,
        idle_wake_icount: Option<u64>,
        status: u8,
    ) {
        self.publish_gen.fetch_add(1, Ordering::AcqRel);
        self.current_icount.store(current_icount, Ordering::Release);
        self.current_ns.store(current_ns, Ordering::Release);
        if let Some(idle_wake_icount) = idle_wake_icount {
            self.idle_wake_icount
                .store(idle_wake_icount, Ordering::Release);
        }
        self.status.store(status, Ordering::Release);
        self.publish_gen.fetch_add(1, Ordering::AcqRel);
    }

    fn publish_device_io_active(&self, active: bool) {
        self.publish_gen.fetch_add(1, Ordering::AcqRel);
        self.device_io_active
            .store(u8::from(active), Ordering::Release);
        self.publish_gen.fetch_add(1, Ordering::AcqRel);
    }

    fn validate_scheduler_ceiling(&self, ceiling: AdvanceCeiling) -> Result<(), NodeSlotError> {
        let current_icount = self.current_icount.load(Ordering::Acquire);
        if ceiling.max_advance_icount < current_icount {
            Err(NodeSlotError::CeilingBeforePublishedCurrent {
                current_icount,
                max_advance_icount: ceiling.max_advance_icount,
            })
        } else {
            Ok(())
        }
    }

    fn publish_prevalidated_scheduler_ceiling(
        &self,
        ceiling: AdvanceCeiling,
    ) -> Result<WakeAction, NodeSlotError> {
        self.max_advance_icount
            .store(ceiling.max_advance_icount, Ordering::Release);

        self.wake_after_signal_increment()
            .map_err(|source| NodeSlotError::FutexWake { source })
    }

    fn is_runnable_after_idle_publish(&self) -> bool {
        let status = self.status.load(Ordering::Acquire);
        let max_advance_icount = self.max_advance_icount.load(Ordering::Acquire);
        let idle_wake_icount = self.idle_wake_icount.load(Ordering::Acquire);
        status != STATUS_IDLE || max_advance_icount >= idle_wake_icount
    }

    fn wake_after_signal_increment(&self) -> Result<WakeAction, FutexError> {
        let previous = self.wake_signal.fetch_add(1, Ordering::Release);
        let futex = self.futex_wake_nonprivate(1)?;
        Ok(WakeAction::Wake {
            previous,
            new: previous.wrapping_add(1),
            futex,
        })
    }
}

impl Default for NodeSlot {
    fn default() -> Self {
        Self::new(KIND_VM)
    }
}

/// A stable acquire snapshot of a [`NodeSlot`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeSlotSnapshot {
    /// The node's published current icount.
    pub current_icount: u64,
    /// The derived virtual-time nanoseconds for [`Self::current_icount`].
    pub current_ns: u64,
    /// The scheduler-published maximum advance icount.
    pub max_advance_icount: u64,
    /// The idle wake icount.
    pub idle_wake_icount: u64,
    /// The futex wake signal value.
    pub wake_signal: u32,
    /// The node status.
    pub status: u8,
    /// The node kind.
    pub kind: u8,
    /// Nonzero while device I/O is active.
    pub device_io_active: u8,
    /// The even publish generation observed for this snapshot.
    pub publish_gen: u32,
}

/// A scheduler wake action for a parked node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WakeAction {
    /// The wake signal was incremented and a non-private futex wake was issued.
    Wake {
        /// The wake signal value before the release increment.
        previous: u32,
        /// The wake signal value after the release increment.
        new: u32,
        /// The result of issuing `FUTEX_WAKE` on the wake-signal word.
        futex: FutexWakeResult,
    },
}

/// A node-side futex wait decision after publishing an idle precondition.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FutexWait {
    /// The node is already runnable and must not enter `FUTEX_WAIT`.
    Runnable,
    /// The node should wait on `wake_signal` while it still equals `expected`.
    Wait {
        /// The observed futex word used as the `FUTEX_WAIT` expected value.
        expected: u32,
    },
}

/// Result of a non-private futex wake syscall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FutexWakeResult {
    /// Number of waiters woken by the syscall.
    pub waiters_woken: u32,
    /// Whether the private futex flag was used.
    pub futex_private: bool,
}

/// Result of a non-private futex wait syscall.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FutexWaitOutcome {
    /// The node was already runnable and no syscall was needed.
    Runnable,
    /// The futex word changed before the wait could park.
    ValueChanged,
    /// The wait was interrupted by a signal.
    Interrupted,
    /// The futex wait returned because a waker woke this waiter.
    Woken,
    /// The non-Linux developer-tooling shim compiled the wait path to a no-op.
    Noop,
}

/// A futex syscall error.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FutexError {
    /// The futex syscall failed unexpectedly.
    #[error("{operation} syscall failed with errno {errno}")]
    Syscall {
        /// The futex operation being attempted.
        operation: &'static str,
        /// The OS errno value.
        errno: i32,
    },
    /// The futex syscall returned an invalid nonnegative count.
    #[error("{operation} syscall returned invalid count {count}")]
    InvalidReturnCount {
        /// The futex operation being attempted.
        operation: &'static str,
        /// The raw return count.
        count: i64,
    },
}

/// An error produced while updating global region control flags.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RegionControlError {
    /// A slot wake failed while broadcasting a control-flag update.
    #[error("waking node slot {slot_index} for control flag failed")]
    WakeSlot {
        /// The index in the caller-provided slot iterator.
        slot_index: usize,
        /// The futex wake failure.
        #[source]
        source: FutexError,
    },
}

/// Converts an icount into virtual nanoseconds with the fixed shift.
///
/// # Errors
///
/// Returns [`NodeSlotError::InvalidShift`] when `shift_bits >= 64`, and
/// [`NodeSlotError::VirtualTimeOverflow`] when the shifted value does not fit in
/// `u64`.
pub fn icount_to_virtual_ns(icount: u64, shift_bits: u8) -> Result<u64, NodeSlotError> {
    if shift_bits >= 64 {
        return Err(NodeSlotError::InvalidShift { shift_bits });
    }
    let nanos_per_icount = 1_u64 << shift_bits;
    icount
        .checked_mul(nanos_per_icount)
        .ok_or(NodeSlotError::VirtualTimeOverflow { icount, shift_bits })
}

#[cfg(target_os = "linux")]
fn futex_wake_nonprivate(
    wake_signal: &AtomicU32,
    max_waiters: u32,
) -> Result<FutexWakeResult, FutexError> {
    // SAFETY: `wake_signal` is an aligned live `AtomicU32` valid for this syscall.
    let raw = unsafe {
        libc::syscall(
            libc::SYS_futex,
            wake_signal.as_ptr(),
            libc::FUTEX_WAKE,
            max_waiters,
        )
    };
    if raw < 0 {
        return Err(last_futex_error("FUTEX_WAKE"));
    }

    let waiters_woken = u32::try_from(raw).map_err(|_| FutexError::InvalidReturnCount {
        operation: "FUTEX_WAKE",
        count: raw,
    })?;
    Ok(FutexWakeResult {
        waiters_woken,
        futex_private: FUTEX_PRIVATE,
    })
}

#[cfg(not(target_os = "linux"))]
fn futex_wake_nonprivate(
    _wake_signal: &AtomicU32,
    _max_waiters: u32,
) -> Result<FutexWakeResult, FutexError> {
    Ok(FutexWakeResult {
        waiters_woken: 0,
        futex_private: FUTEX_PRIVATE,
    })
}

#[cfg(target_os = "linux")]
fn futex_wait_nonprivate(
    wake_signal: &AtomicU32,
    expected: u32,
) -> Result<FutexWaitOutcome, FutexError> {
    // SAFETY: `wake_signal` is aligned and live, and the null timeout is never dereferenced.
    let raw = unsafe {
        libc::syscall(
            libc::SYS_futex,
            wake_signal.as_ptr(),
            libc::FUTEX_WAIT,
            expected,
            core::ptr::null::<libc::timespec>(),
        )
    };
    if raw == 0 {
        return Ok(FutexWaitOutcome::Woken);
    }

    let errno = last_errno();
    match errno {
        libc::EAGAIN => Ok(FutexWaitOutcome::ValueChanged),
        libc::EINTR => Ok(FutexWaitOutcome::Interrupted),
        _ => Err(FutexError::Syscall {
            operation: "FUTEX_WAIT",
            errno,
        }),
    }
}

#[cfg(not(target_os = "linux"))]
fn futex_wait_nonprivate(
    _wake_signal: &AtomicU32,
    _expected: u32,
) -> Result<FutexWaitOutcome, FutexError> {
    Ok(FutexWaitOutcome::Noop)
}

#[cfg(target_os = "linux")]
fn last_futex_error(operation: &'static str) -> FutexError {
    FutexError::Syscall {
        operation,
        errno: last_errno(),
    }
}

#[cfg(target_os = "linux")]
fn last_errno() -> i32 {
    std::io::Error::last_os_error().raw_os_error().unwrap_or(0)
}

impl FrameEntry {
    /// Builds a frame entry with an in-band delivery icount.
    ///
    /// # Errors
    ///
    /// Returns [`FrameEntryError::PayloadLengthExceedsCapacity`] when `payload`
    /// is too large for [`MAX_FRAME_DATA`].
    pub fn new(
        delivery_icount: u64,
        src_node: u32,
        seq: u32,
        payload: &[u8],
    ) -> Result<Self, FrameEntryError> {
        if payload.len() > MAX_FRAME_DATA {
            return Err(FrameEntryError::PayloadLengthExceedsCapacity {
                len: payload.len(),
                capacity: MAX_FRAME_DATA,
            });
        }

        let mut data = [0; MAX_FRAME_DATA];
        data[..payload.len()].copy_from_slice(payload);

        Ok(Self {
            delivery_icount,
            src_node,
            seq,
            len: payload.len() as u16,
            _pad: [0; 6],
            data,
        })
    }

    /// Returns `true` when this frame is visible at `consumer_current_icount`.
    #[must_use]
    pub fn is_deliverable_at(&self, consumer_current_icount: u64) -> bool {
        self.delivery_icount <= consumer_current_icount
    }

    /// Returns the deterministic per-consumer delivery-order key.
    #[must_use]
    pub fn delivery_key(&self) -> FrameDeliveryKey {
        FrameDeliveryKey {
            delivery_icount: self.delivery_icount,
            src_node: self.src_node,
            seq: self.seq,
        }
    }

    /// Returns the valid payload bytes.
    ///
    /// # Errors
    ///
    /// Returns [`FrameEntryError::PayloadLengthExceedsCapacity`] when a frame
    /// read from shared memory advertises a length greater than
    /// [`MAX_FRAME_DATA`].
    pub fn payload(&self) -> Result<&[u8], FrameEntryError> {
        let len = usize::from(self.len);
        if len > MAX_FRAME_DATA {
            Err(FrameEntryError::PayloadLengthExceedsCapacity {
                len,
                capacity: MAX_FRAME_DATA,
            })
        } else {
            Ok(&self.data[..len])
        }
    }

    /// Returns `true` when the frame-entry padding bytes are zero.
    #[must_use]
    pub fn padding_bytes_are_zero(&self) -> bool {
        self._pad.iter().all(|byte| *byte == 0)
    }

    fn canonicalized_for_snapshot(&self) -> Result<Self, SpscRingError> {
        let len = usize::from(self.len);
        if len > MAX_FRAME_DATA {
            return Err(SpscRingError::InvalidFrameLength {
                len,
                capacity: MAX_FRAME_DATA,
            });
        }

        let mut canonical = self.clone();
        canonical._pad = [0; 6];
        canonical.data[len..].fill(0);
        Ok(canonical)
    }
}

impl Default for FrameEntry {
    fn default() -> Self {
        Self {
            delivery_icount: 0,
            src_node: 0,
            seq: 0,
            len: 0,
            _pad: [0; 6],
            data: [0; MAX_FRAME_DATA],
        }
    }
}

/// The deterministic order key for frames visible to one consumer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct FrameDeliveryKey {
    /// The consumer icount at which the frame becomes visible.
    pub delivery_icount: u64,
    /// The producer node id.
    pub src_node: u32,
    /// The per-producer sequence number.
    pub seq: u32,
}

/// Returns all currently deliverable frames in deterministic visibility order.
#[must_use]
pub fn deliverable_frames_at(
    frames: &[FrameEntry],
    consumer_current_icount: u64,
) -> Vec<&FrameEntry> {
    let mut deliverable = frames
        .iter()
        .filter(|frame| frame.is_deliverable_at(consumer_current_icount))
        .collect::<Vec<_>>();

    deliverable.sort_by_key(|frame| frame.delivery_key());

    deliverable
}

/// An advance authorization bounded by the lookahead gate.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AdvanceCeiling {
    current_icount: u64,
    max_advance_icount: u64,
}

impl AdvanceCeiling {
    /// Returns the consumer icount observed before authorization.
    #[must_use]
    pub fn current_icount(&self) -> u64 {
        self.current_icount
    }

    /// Returns the scheduler-authorized maximum icount the consumer may reach.
    #[must_use]
    pub fn max_advance_icount(&self) -> u64 {
        self.max_advance_icount
    }
}

/// Authorizes a max-advance ceiling under the conservative lookahead gate.
///
/// When `earliest_possible_delivery_icount` is present, the returned ceiling is
/// strictly before that icount. The scheduler must publish a fresh
/// authorization once the input group is present and deliverable.
///
/// # Errors
///
/// Returns [`LookaheadGateError::CeilingBeforeCurrent`] when `max_advance_icount`
/// is behind `current_icount`, and
/// [`LookaheadGateError::AdvanceReachesPossibleDelivery`] when the requested
/// ceiling would reach or pass an input that could become visible.
pub fn authorize_advance_ceiling(
    current_icount: u64,
    max_advance_icount: u64,
    earliest_possible_delivery_icount: Option<u64>,
) -> Result<AdvanceCeiling, LookaheadGateError> {
    if max_advance_icount < current_icount {
        return Err(LookaheadGateError::CeilingBeforeCurrent {
            current_icount,
            max_advance_icount,
        });
    }

    if let Some(earliest_possible_delivery_icount) = earliest_possible_delivery_icount
        && max_advance_icount >= earliest_possible_delivery_icount
    {
        return Err(LookaheadGateError::AdvanceReachesPossibleDelivery {
            max_advance_icount,
            earliest_possible_delivery_icount,
        });
    }

    Ok(AdvanceCeiling {
        current_icount,
        max_advance_icount,
    })
}

/// Verifies that a newly enqueued frame has not already missed its delivery.
///
/// # Errors
///
/// Returns [`LookaheadGateError::DeliveryAlreadyPassed`] when the consumer has
/// already reached or passed the frame's delivery icount.
pub fn validate_frame_delivery_is_future(
    frame: &FrameEntry,
    consumer_current_icount: u64,
) -> Result<(), LookaheadGateError> {
    if frame.delivery_icount <= consumer_current_icount {
        Err(LookaheadGateError::DeliveryAlreadyPassed {
            consumer_current_icount,
            frame: frame.delivery_key(),
        })
    } else {
        Ok(())
    }
}

/// A validation error for shared-memory frame entries.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum FrameEntryError {
    /// The advertised payload length does not fit in [`MAX_FRAME_DATA`].
    #[error("frame payload length {len} exceeds capacity {capacity}")]
    PayloadLengthExceedsCapacity {
        /// The requested or advertised payload length.
        len: usize,
        /// The configured frame payload capacity.
        capacity: usize,
    },
}

/// An error produced while validating a mapped setup region header.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RegionSetupValidationError {
    /// The mapped length is too small to contain a shared-memory header.
    #[error("setup region length {region_len} is smaller than header size {minimum_len}")]
    RegionTooSmall {
        /// The rejected `Setup.region_len`.
        region_len: u64,
        /// The minimum mappable length required for the header.
        minimum_len: u64,
    },
    /// The region header magic is not [`REGION_MAGIC`].
    #[error("setup region magic {actual:#x} does not match expected {expected:#x}")]
    InvalidMagic {
        /// Magic value read from the mapped header.
        actual: u64,
        /// Required magic value.
        expected: u64,
    },
    /// The region header ABI version is not [`ABI_VERSION`].
    #[error("setup region ABI version {actual} does not match expected {expected}")]
    AbiVersionMismatch {
        /// ABI version read from the mapped header.
        actual: u32,
        /// ABI version compiled into this crate.
        expected: u32,
    },
    /// The header's region size does not match the control-protocol setup length.
    #[error(
        "setup region length {setup_region_len} does not match header region_size {header_region_size}"
    )]
    RegionLengthMismatch {
        /// Length from the control-protocol `Setup` frame.
        setup_region_len: u64,
        /// Length read from the mapped region header.
        header_region_size: u64,
    },
    /// The directed-ring count cannot represent any valid VM-node count.
    #[error("setup region ring count {ring_count} is not a positive multiple of {rings_per_vm}")]
    InvalidRingCount {
        /// Ring count read from the mapped region header.
        ring_count: u32,
        /// Required directed-ring count per VM node.
        rings_per_vm: u32,
    },
    /// The header geometry cannot be recomputed by the current layout model.
    #[error("setup region layout is invalid")]
    InvalidLayout {
        /// Underlying layout-model error.
        source: RegionLayoutError,
    },
    /// The header node count does not match the fixed ABI slot array.
    #[error("setup region node count {actual} does not match expected {expected}")]
    InvalidNodeCount {
        /// Node count read from the mapped region header.
        actual: u32,
        /// Required physical node count.
        expected: u32,
    },
    /// The header ring-header offset does not match the recomputed layout.
    #[error("setup region ring header offset {actual} does not match expected {expected}")]
    InvalidRingHeaderOffset {
        /// Offset read from the mapped region header.
        actual: u64,
        /// Required offset from the recomputed layout.
        expected: u64,
    },
    /// The header frame-entry offset does not match the recomputed layout.
    #[error("setup region ring data offset {actual} does not match expected {expected}")]
    InvalidRingDataOffset {
        /// Offset read from the mapped region header.
        actual: u64,
        /// Required offset from the recomputed layout.
        expected: u64,
    },
    /// The header frame-entry stride does not match the ABI entry size.
    #[error("setup region entry stride {actual} does not match expected {expected}")]
    InvalidEntryStride {
        /// Stride read from the mapped region header.
        actual: u64,
        /// Required frame-entry stride.
        expected: u64,
    },
    /// The recomputed layout size does not match the control-protocol setup length.
    #[error(
        "setup region length {setup_region_len} does not match computed layout size {layout_region_size}"
    )]
    LayoutRegionLengthMismatch {
        /// Length from the control-protocol `Setup` frame.
        setup_region_len: u64,
        /// Length recomputed from the header geometry.
        layout_region_size: u64,
    },
    /// The layout recomputation overflowed.
    #[error("setup region geometry overflowed during validation")]
    GeometryOverflow,
}

/// An error produced while validating or allocating a shared-memory region.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RegionLayoutError {
    /// The crate was compiled for a target outside the pinned ABI layout target.
    #[error("shared-memory layout target {actual} is unsupported; expected {expected}")]
    UnsupportedTarget {
        /// The target triple required by the ABI.
        expected: &'static str,
        /// The target class observed at compile time.
        actual: &'static str,
    },
    /// The requested logical VM count cannot fit beside reserved executor slots.
    #[error("requested {requested} VM nodes exceeds maximum {max}")]
    TooManyVmNodes {
        /// The requested logical VM node count.
        requested: u32,
        /// The maximum logical VM node count.
        max: u32,
    },
    /// The per-ring queue capacity was zero or not a power of two.
    #[error("queue capacity {capacity} is not a nonzero power of two")]
    InvalidQueueCapacity {
        /// The rejected per-ring capacity.
        capacity: u32,
    },
    /// The fixed icount shift cannot be represented in `u64` conversions.
    #[error("icount shift {shift_bits} cannot be represented as u64")]
    InvalidIcountShift {
        /// The rejected shift value.
        shift_bits: u32,
    },
    /// The computed region byte geometry overflowed an integer.
    #[error("computed shared-memory region geometry overflowed")]
    GeometryOverflow,
}

/// An error produced while serializing an initialized region for setup handoff.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum RegionSerializationError {
    /// The region size cannot fit in a process-local byte vector.
    #[error("shared-memory region size {region_size} cannot fit in usize")]
    RegionSizeTooLarge {
        /// Computed region size in bytes.
        region_size: u64,
    },
    /// A segment offset overflowed while serializing the region.
    #[error("shared-memory {segment} index {index} offset overflowed")]
    SegmentOffsetOverflow {
        /// Segment kind being serialized.
        segment: &'static str,
        /// Segment index within its array.
        index: usize,
    },
    /// A segment would extend beyond the computed region length.
    #[error(
        "shared-memory {segment} index {index} at byte {offset} with length {len} extends past region length {region_len}"
    )]
    SegmentOutOfBounds {
        /// Segment kind being serialized.
        segment: &'static str,
        /// Segment index within its array.
        index: usize,
        /// Computed byte offset.
        offset: usize,
        /// Segment length in bytes.
        len: usize,
        /// Total region length in bytes.
        region_len: usize,
    },
}

/// An error produced by SPSC ring operations.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SpscRingError {
    /// The backing entry slice is empty or not power-of-two sized.
    #[error("SPSC ring capacity {capacity} is not a nonzero power of two")]
    InvalidCapacity {
        /// The invalid backing entry count.
        capacity: usize,
    },
    /// The ring cannot accept another frame.
    #[error("SPSC ring is full at capacity {capacity}")]
    QueueFull {
        /// The ring capacity in frame entries.
        capacity: u64,
    },
    /// The live entry count exceeds the configured capacity.
    #[error(
        "SPSC ring indices are corrupt: read_idx={read_idx} write_idx={write_idx} capacity={capacity}"
    )]
    CorruptIndices {
        /// The consumer-owned read index.
        read_idx: u64,
        /// The producer-owned write index.
        write_idx: u64,
        /// The ring capacity in frame entries.
        capacity: u64,
    },
    /// A quiescent snapshot cannot fit in the target ring.
    #[error("SPSC snapshot length {len} exceeds ring capacity {capacity}")]
    SnapshotTooLarge {
        /// The number of frames in the snapshot.
        len: usize,
        /// The ring capacity in frame entries.
        capacity: u64,
    },
    /// A frame in the ring or snapshot advertises an impossible payload length.
    #[error("SPSC frame payload length {len} exceeds capacity {capacity}")]
    InvalidFrameLength {
        /// The invalid frame payload length.
        len: usize,
        /// The maximum payload capacity in bytes.
        capacity: usize,
    },
    /// The snapshot frame count cannot fit in the canonical byte encoding.
    #[error("SPSC snapshot length {len} cannot be encoded as u64")]
    SnapshotLengthOverflow {
        /// The number of frames in the snapshot.
        len: usize,
    },
    /// The encoded snapshot frame count cannot fit in this target's memory size.
    #[error("SPSC snapshot frame count {count} cannot fit in usize")]
    SnapshotFrameCountOverflow {
        /// The rejected encoded frame count.
        count: u64,
    },
    /// The canonical snapshot byte stream ended before the declared field.
    #[error(
        "SPSC snapshot decode truncated at byte {offset}: needed {needed} bytes, available {available}"
    )]
    SnapshotDecodeTruncated {
        /// The byte offset where the decoder needed more input.
        offset: usize,
        /// The number of bytes needed for the current field.
        needed: usize,
        /// The bytes remaining in the input.
        available: usize,
    },
    /// The canonical snapshot byte stream contained bytes after declared frames.
    #[error("SPSC snapshot decode left {available} trailing bytes at byte {offset}")]
    SnapshotDecodeTrailingBytes {
        /// The byte offset where declared frames ended.
        offset: usize,
        /// The number of bytes left after declared frames.
        available: usize,
    },
}

/// A lookahead-gate validation error.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum LookaheadGateError {
    /// A scheduler attempted to publish a ceiling behind the consumer.
    #[error("max advance icount {max_advance_icount} is before current icount {current_icount}")]
    CeilingBeforeCurrent {
        /// The consumer icount observed before authorization.
        current_icount: u64,
        /// The requested maximum advance icount.
        max_advance_icount: u64,
    },
    /// A scheduler attempted to let a node reach an input's possible delivery.
    #[error(
        "max advance icount {max_advance_icount} reaches possible delivery icount {earliest_possible_delivery_icount}"
    )]
    AdvanceReachesPossibleDelivery {
        /// The requested maximum advance icount.
        max_advance_icount: u64,
        /// The earliest icount at which an input could become visible.
        earliest_possible_delivery_icount: u64,
    },
    /// A frame was enqueued after the consumer reached its delivery icount.
    #[error(
        "frame {frame:?} delivery icount is not in the future of consumer icount {consumer_current_icount}"
    )]
    DeliveryAlreadyPassed {
        /// The consumer icount observed when the frame was enqueued.
        consumer_current_icount: u64,
        /// The late frame's deterministic delivery key.
        frame: FrameDeliveryKey,
    },
}

fn validated_capacity(entries: &[FrameEntry]) -> Result<u64, SpscRingError> {
    if entries.is_empty() || !entries.len().is_power_of_two() {
        return Err(SpscRingError::InvalidCapacity {
            capacity: entries.len(),
        });
    }
    Ok(entries.len() as u64)
}

fn live_count(read_idx: u64, write_idx: u64, capacity: u64) -> Result<u64, SpscRingError> {
    let live = write_idx
        .checked_sub(read_idx)
        .ok_or(SpscRingError::CorruptIndices {
            read_idx,
            write_idx,
            capacity,
        })?;
    if live > capacity {
        Err(SpscRingError::CorruptIndices {
            read_idx,
            write_idx,
            capacity,
        })
    } else {
        Ok(live)
    }
}

/// An error produced by the per-node advance-ceiling slot.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum NodeSlotError {
    /// A process requested an invalid fixed icount shift.
    #[error("icount shift {shift_bits} cannot be represented as u64")]
    InvalidShift {
        /// The rejected shift value.
        shift_bits: u8,
    },
    /// The virtual-time nanosecond view overflowed `u64`.
    #[error("icount {icount} shifted by {shift_bits} bits overflows virtual nanoseconds")]
    VirtualTimeOverflow {
        /// The icount being converted.
        icount: u64,
        /// The fixed shift value.
        shift_bits: u8,
    },
    /// A scheduler attempted to publish a ceiling behind the node's current icount.
    #[error(
        "max advance icount {max_advance_icount} is before published current icount {current_icount}"
    )]
    CeilingBeforePublishedCurrent {
        /// The node's published current icount.
        current_icount: u64,
        /// The rejected maximum advance icount.
        max_advance_icount: u64,
    },
    /// A node attempted to advance past the scheduler-published ceiling.
    #[error("node attempted to advance to icount {next_icount} past ceiling {max_advance_icount}")]
    NodeAdvancePastCeiling {
        /// The icount the node attempted to reach.
        next_icount: u64,
        /// The scheduler-published ceiling.
        max_advance_icount: u64,
    },
    /// A node published an idle wake behind its current icount.
    #[error("idle wake icount {idle_wake_icount} is before current icount {current_icount}")]
    IdleWakeBeforeCurrent {
        /// The node's current icount.
        current_icount: u64,
        /// The rejected idle wake icount.
        idle_wake_icount: u64,
    },
    /// A non-private futex wake failed after `wake_signal` was incremented.
    #[error("non-private futex wake failed after incrementing wake_signal: {source}")]
    FutexWake {
        /// The futex syscall failure.
        source: FutexError,
    },
}
