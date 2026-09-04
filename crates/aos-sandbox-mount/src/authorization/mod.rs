//! Mount-broker authorization primitives.
//!
//! This module separates canonical authority semantics from transport framing,
//! signature verification, durable admission, and kernel effects.

mod admission_v1;
mod config_v1;
pub(crate) mod semantics_v1;

pub(crate) use admission_v1::VerifiedMountAdmissionV1;
pub use admission_v1::{MountAdmissionError, MountAuthorityV1};
pub use config_v1::MountAuthorityConfigError;
