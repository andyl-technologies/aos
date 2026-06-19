//! `crucible-shmem` owns the shared-memory ABI.
//!
//! Spec index: RFC-0010 files 13.
//!
//! This L1 crate is the single source of truth for the `#[repr(C)]` region
//! layout, per-node clocks, status words, and SPSC frame queues described by
//! its indexed RFC-0010 file. It is an unsafe-boundary crate because future
//! implementations map shared memory and expose layout-checked accessors.
//!
//! Module map: the crate root currently reserves the shared-memory ABI
//! boundary; future modules will split region headers, node clocks, status
//! words, and SPSC frame queues.
//!
//! Shared-memory layout sketch:
//!
//! ```text
//! region-header
//! node-clock-table
//! status-words
//! spsc-frame-queues
//! ```

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
