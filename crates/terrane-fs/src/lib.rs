//! Provides the terrane-fs layer of RFC-0024 Terrane.
//!
//! This foundation reserves the crate boundary described by CRATE-34.

#![deny(unsafe_op_in_unsafe_fn)]

#[cfg(not(target_os = "linux"))]
compile_error!("terrane-fs requires Linux (CRATE-11)");
