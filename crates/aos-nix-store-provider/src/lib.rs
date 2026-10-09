//! Package-owned Nix store ability provider.
//!
//! The provider owns local database convergence and persistent content-addressed
//! objects. Database effects use an explicitly realized `nix-store` executable;
//! object effects use the exact executable bundled into the authenticated
//! provider artifact and retain objects through resource-owned GC roots.

#![forbid(unsafe_code)]

pub mod handler;

mod artifact;
mod process;
