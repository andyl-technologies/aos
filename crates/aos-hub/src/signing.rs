//! Registry artifact signing primitives re-exported from [`aos_hub_core::signing`].
//!
//! The pure Ed25519 [`sign_release_tag`], [`sign_partition`], and
//! [`verify_release_tag`] functions are shared by native and Worker runtimes.
//! Custody resolution, topology mutation, and publication remain outside this
//! module and are governed by retained-control operations.

pub use aos_hub_core::signing::*;
