//! `crucible-qemu` owns host-side QEMU integration.
//!
//! Spec index: RFC-0010 files 10, 11.
//!
//! This L2 crate will build launch arguments, supervise QEMU children, map the
//! shared-memory region, speak QMP, and implement the engine backend trait
//! described by its indexed RFC-0010 files. It is an unsafe-boundary crate
//! because future implementations may cross FFI and raw descriptor boundaries.
//!
//! Module map: the crate root currently reserves the host-QEMU boundary; future
//! modules will split launch construction, QMP, shared-memory mapping, and the
//! engine backend adapter.
//!
//! Unsafe boundary discipline: descriptor, shared-memory, monitor, and FFI
//! details stay private; public callers use a safe host-driver API that
//! validates process and mapping invariants before touching raw state.

#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]
#![deny(rustdoc::broken_intra_doc_links)]
