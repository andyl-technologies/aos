//! `crucible-qemu-plugin` owns the in-VM QEMU plugin.
//!
//! This L2 crate builds the `cdylib` loaded by QEMU. Later tasks will add the
//! QEMU TCG plugin entry points, time-control hooks, and device callbacks
//! specified by RFC-0010 files 11, 12, and 27. It is an unsafe-boundary crate
//! because the plugin speaks QEMU's C ABI and may read guest memory.

#![deny(unsafe_op_in_unsafe_fn)]
