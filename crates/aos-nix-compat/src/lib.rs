//! Nix store-format compatibility helpers for RFC-0007.
//!
//! This crate owns the Nix-specific wire formats and file-system helpers that
//! are not part of the reusable `ratchet` evaluator engine:
//!
//! - [`drv`] parses the narrow `.drv` ATerm surfaces used for fixed-output
//!   derivation discovery and closure traversal.
//! - [`drv_materialize`] safely installs native evaluator `.drv` bytes into the
//!   configured store directory.

#![forbid(unsafe_code)]

pub mod drv;
pub mod drv_materialize;
