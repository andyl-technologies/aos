//! `crucible-sim` owns Crucible's deterministic core primitives.
//!
//! This L0 crate is the future home for seeded decision streams, ordered
//! collections, deterministic selection, virtual-time arithmetic, and the
//! content-addressing seam described by RFC-0010 files 04, 08, 09, and 27.
//! It intentionally has no QEMU, transport, scheduler-policy, or wall-clock
//! surface.

#![forbid(unsafe_code)]
