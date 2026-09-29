//! Owns Linux kernel surfaces and host-tier kernel mechanisms.
//!
//! This foundation establishes the Linux-only boundary in CRATE-10 and
//! CRATE-11. FUSE, EROFS, block, virtiofs, sealing, quotas, and mount inspection
//! from specification 14 and 27-29 are implemented by later tasks. No kernel
//! surface is available in this foundation, and no unsafe bindings exist yet.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(target_os = "linux"))]
compile_error!("terrane-fs requires Linux (CRATE-11)");
