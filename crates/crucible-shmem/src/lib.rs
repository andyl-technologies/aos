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
//!
//! Plugin-to-host coverage entry wire layout:
//!
//! ```text
//! offset  size  field
//! 0       8     current_icount
//! 8       8     guest_pc
//! 16      8     map_index
//! 24      4     vcpu_index
//! 28      4     block_len
//! 32      32    reserved (zero)
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
    MappedCoverageRingMut, MappedDirectedRingMut, MappedNodeRingPairMut, MappedSetupRegion,
    MappedSetupRegionAccessError, SetupRegionMapError, mmap_setup_region,
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
pub const ABI_VERSION: u32 = 2;
const _: () = assert!(ABI_VERSION == include!("abi_version.in"));
/// Fixed number of entries in each plugin-to-host coverage queue.
///
/// The capacity equals the default coverage-map cardinality. The plugin emits
/// each newly reached map entry at most once, so a correctly paired producer
/// cannot overflow before the host drains at a quantum boundary.
pub const COVERAGE_QUEUE_CAPACITY: u32 = 65_536;
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

#[path = "shmem/delivery_errors.rs"]
mod delivery_errors;
#[path = "shmem/frame_node.rs"]
mod frame_node;
#[path = "shmem/region.rs"]
mod region;
#[path = "shmem/ring_coverage.rs"]
mod ring_coverage;

pub use delivery_errors::*;
pub use frame_node::*;
pub use region::*;
pub use ring_coverage::*;
