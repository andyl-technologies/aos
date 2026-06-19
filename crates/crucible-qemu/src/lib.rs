//! `crucible-qemu` owns host-side QEMU integration.
//!
//! This L2 crate will build launch arguments, supervise QEMU children, map the
//! shared-memory region, speak QMP, and implement the engine backend trait
//! described by RFC-0010 files 10, 11, and 27. It is an unsafe-boundary crate
//! because future implementations may cross FFI and raw descriptor boundaries.

#![deny(unsafe_op_in_unsafe_fn)]
