//! `crucible-shmem` owns the shared-memory ABI.
//!
//! This L1 crate is the single source of truth for the `#[repr(C)]` region
//! layout, per-node clocks, status words, and SPSC frame queues described by
//! RFC-0010 files 13 and 27. It is an unsafe-boundary crate because future
//! implementations map shared memory and expose layout-checked accessors.

#![deny(unsafe_op_in_unsafe_fn)]
