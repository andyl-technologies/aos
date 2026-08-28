//! SPDX-License-Identifier: MIT OR Apache-2.0
//! `crucible-shmem` implements the public shared-memory process ABI.
//!
//! Spec index: RFC-0010 files 13.
//!
//! This permissively dual-licensed L1 crate is the Rust implementation of the
//! versioned, independently implementable process ABI declared by
//! `interface/crucible-shmem-abi.toml`. The generated C header is a peer view
//! of that public contract, not a QEMU-internal FFI surface. The mapped region
//! contains only fixed-width values, byte arrays, offsets, and shared atomics;
//! it never contains native pointers, callback tables, or QEMU-private types.
//! Keeping this transport process-shaped avoids socket round trips and payload
//! copies on the data path while allowing Apache-licensed hosts and GPL
//! QEMU-side code to implement the same protocol independently. The current
//! scheduler ceiling publication performs a non-private futex wake even when
//! no peer is parked, and the host writes QEMU's plugin eventfd at least once
//! per quantum. Frame delivery and service/backpressure producer release can
//! add futex wakes; unchanged-icount retries and serviced host I/O can add
//! eventfd writes, so this is not a zero-syscall steady state. These wakeups carry no
//! timing decision or payload. A future waiter-armed optimization may make the
//! futex wake conditional without changing the public process boundary.
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
//! License boundary: code linked into QEMU belongs in the GPL-2.0-only
//! `crucible-qemu-plugin` crate. This crate MUST remain usable without QEMU
//! headers, symbols, or implementation-private structures.
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
//! 44      4     control_boundary_ack
//! 48      8     device_completion_deadline_icount
//! 56      8     preemption_at_icount
//! 64      8     preemption_deadline_icount
//! 72      8     preemption_ceiling_icount
//! 80      4     preemption_published_sequence
//! 84      4     preemption_consumed_sequence
//! 88      4     preemption_arg0
//! 92      4     preemption_arg1
//! 96      1     preemption_kind
//! 97      7     padding
//! 104     8     logical_time_raw_icount
//! 112     8     logical_time_restore_target
//! 120     4     logical_time_restore_request
//! 124     4     logical_time_restore_ack
//! ```
//!
//! SPSC ring header wire layout:
//!
//! ```text
//! offset  size  field
//! 0       8     read_idx
//! 8       8     consumer_state
//! 16      48    read-cacheline padding
//! 64      8     write_idx
//! 72      8     producer_state
//! 80      48    write-cacheline padding
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
//!
//! Plugin-to-host white-box marker entry wire layout:
//!
//! ```text
//! offset  size  field
//! 0       8     current_icount
//! 8       4     vcpu_index
//! 12      2     marker kind
//! 14      2     payload length
//! 16      4608  decoded marker payload
//! 4624    48    reserved (zero)
//! ```
//!
//! Fault command/result transport slot wire layout:
//!
//! ```text
//! offset  size       field
//! 0       8          reservation_start logical cursor
//! 8       8          payload_start logical cursor
//! 16      8          reservation_end logical cursor
//! 24      216/188    encoded command/result header
//! 240/212 16/44      reserved (zero)
//! ```
//!
//! Fault event transport slot wire layout:
//!
//! ```text
//! offset  size  field
//! 0       8     reservation_start logical cursor
//! 8       8     payload_start logical cursor
//! 16      8     reservation_end logical cursor
//! 24      320   encoded event header
//! 344     40    reserved (zero)
//! ```
//!
//! Fault payload arena header wire layout:
//!
//! ```text
//! offset  size  field
//! 0       8     read_cursor
//! 8       56    read-cacheline padding
//! 64      8     write_cursor
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
    DetachedPluginAcceleratorRings, DetachedPluginGuestIntrospectionRings,
    MappedAcceleratorConsumerRingMut, MappedAcceleratorProducerRingMut, MappedCoverageRingMut,
    MappedDirectedRingMut, MappedFaultCommandTransportMut, MappedFaultEventTransportMut,
    MappedFaultResultTransportMut, MappedGuestIntrospectionConsumerRingMut,
    MappedGuestIntrospectionProducerRingMut, MappedHostAcceleratorRingsMut,
    MappedHostGuestIntrospectionRingsMut, MappedNodeRingPairMut, MappedPluginAcceleratorRingsMut,
    MappedPluginGuestIntrospectionRingsMut, MappedRingIoBarrierSnapshot,
    MappedSelectableReplyRingMut, MappedSetupRegion, MappedSetupRegionAccessError,
    MappedWhiteboxMarkerRingMut, SetupRegionMapError, mmap_setup_region,
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
///
/// Version 8 adds the per-node logical-time calibration restore transaction so
/// a fresh plugin can reconstruct idle-jump time after QEMU loads VMState.
/// Version 9 adds typed node-fault commands and an independent lossless stream
/// for actual QEMU fault-rule occurrences.
/// Version 10 appends bounded bidirectional guest-introspection rings per VM.
/// Version 11 appends bounded accelerator request/completion rings per VM.
/// Version 12 adds an explicit accelerator completion-capacity field and moves
/// accelerator payload bytes to preserve a canonical bounded result envelope.
/// Version 13 adds the canonical typed fault-command/result/event transports.
/// Version 14 assigns the former node-slot padding at offset 44 to the plugin's
/// drained-control-boundary publication acknowledgement.
/// Version 15 assigns one frame-entry padding byte to the consumer-owned
/// canonical backpressure-retention state.
/// Version 18 appends one single-entry host-to-plugin selectable-reply ring per
/// logical VM without changing any prior section offset.
/// Version 19 assigns producer cache-line padding to reversible hot-fork
/// producer admission. Version 20 assigns consumer cache-line padding to the
/// matching reversible consumer admission barrier.
pub const ABI_VERSION: u32 = 20;
const _: () = assert!(ABI_VERSION == include!("abi_version.in"));
/// Fixed number of entries in each plugin-to-host coverage queue.
///
/// The capacity equals the default coverage-map cardinality. The plugin emits
/// each newly reached map entry at most once, so a correctly paired producer
/// cannot overflow before the host drains at a quantum boundary.
pub const COVERAGE_QUEUE_CAPACITY: u32 = 65_536;
/// Fixed entries in each plugin-to-host white-box marker queue.
///
/// The queue is drained at quantum boundaries. Exhaustion is a fail-loud
/// infrastructure error rather than causal guest backpressure.
pub const WHITEBOX_MARKER_QUEUE_CAPACITY: u32 = 1_024;
/// Fixed entries in each host-to-plugin selectable-reply queue.
///
/// A catalog permits only one pending request per VM generation. The single
/// slot is therefore both sufficient and the hard bounded transport shape.
pub const SELECTABLE_REPLY_QUEUE_CAPACITY: u32 = 1;
/// Fixed entry capacity of each guest-introspection request or response ring.
pub const GUEST_INTROSPECTION_QUEUE_CAPACITY: u32 = 64;
/// Number of fixed-direction guest-introspection rings allocated per VM.
pub const GUEST_INTROSPECTION_RINGS_PER_VM: u32 = 2;
/// Per-VM ring offset for host-to-plugin requests.
pub const GUEST_INTROSPECTION_REQUEST_RING_OFFSET: u32 = 0;
/// Per-VM ring offset for plugin-to-host responses.
pub const GUEST_INTROSPECTION_RESPONSE_RING_OFFSET: u32 = 1;
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
#[path = "shmem/fault_clock_evidence.rs"]
mod fault_clock_evidence;
#[path = "shmem/fault_command.rs"]
mod fault_command;
#[path = "shmem/fault_event.rs"]
mod fault_event;
#[path = "shmem/fault_instruction_evidence.rs"]
mod fault_instruction_evidence;
#[path = "shmem/fault_memory.rs"]
mod fault_memory;
#[path = "shmem/fault_memory_batch.rs"]
mod fault_memory_batch;
#[path = "shmem/fault_memory_evidence.rs"]
mod fault_memory_evidence;
#[path = "shmem/fault_node.rs"]
mod fault_node;
#[path = "shmem/fault_register_evidence.rs"]
mod fault_register_evidence;
#[path = "shmem/fault_target_manifest.rs"]
mod fault_target_manifest;
#[path = "shmem/fault_terminal_evidence.rs"]
mod fault_terminal_evidence;
#[path = "shmem/fingerprint_sample.rs"]
mod fingerprint_sample;
#[path = "shmem/frame_node.rs"]
mod frame_node;
#[path = "shmem/region.rs"]
mod region;
#[path = "shmem/ring_accelerator.rs"]
mod ring_accelerator;
#[path = "shmem/ring_coverage.rs"]
mod ring_coverage;
#[path = "shmem/ring_guest_introspection.rs"]
mod ring_guest_introspection;
#[path = "shmem/ring_whitebox_marker.rs"]
mod ring_whitebox_marker;

pub use delivery_errors::*;
pub use fault_clock_evidence::*;
pub use fault_command::*;
pub use fault_event::*;
pub use fault_instruction_evidence::*;
pub use fault_memory::*;
pub use fault_memory_batch::*;
pub use fault_memory_evidence::*;
pub use fault_node::*;
pub use fault_register_evidence::*;
pub use fault_target_manifest::*;
pub use fault_terminal_evidence::*;
pub use fingerprint_sample::*;
pub use frame_node::*;
pub use region::*;
pub use ring_accelerator::*;
pub use ring_coverage::*;
pub use ring_guest_introspection::*;
pub use ring_whitebox_marker::*;
