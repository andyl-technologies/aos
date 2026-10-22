//! Owns Linux kernel surfaces and host-tier kernel mechanisms.
//!
//! The host-cache, host-quota, publisher I/O, local publisher transport and
//! verity modules provide native boundaries for host-tier policy. Surfaces are
//! added by their implementation tasks; declaring a module does not register
//! a surface or establish its conformance.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(target_os = "linux"))]
compile_error!("terrane-linux requires Linux (CRATE-11)");

pub mod configured;
#[cfg(feature = "tokio")]
pub mod configured_sdk;
pub mod host_cache;
pub mod host_quota;
pub mod publisher_io;
pub mod publisher_local;
pub mod quota_confinement;
#[cfg(feature = "surface-fuse")]
pub mod structural_index;
pub mod verity;
