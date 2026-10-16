//! Owns Linux kernel surfaces and host-tier kernel mechanisms.
//!
//! The host-cache, publisher I/O, local publisher transport and verity modules
//! provide the native boundaries for host-tier policy. Kernel surfaces are
//! added by their implementation tasks; declaring a module does not register
//! a surface or establish its conformance.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(target_os = "linux"))]
compile_error!("terrane-fs requires Linux (CRATE-11)");

pub mod host_cache;
pub mod publisher_io;
pub mod publisher_local;
pub mod verity;
