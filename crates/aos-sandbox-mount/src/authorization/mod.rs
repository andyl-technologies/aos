//! Mount-broker authorization primitives.
//!
//! This module separates canonical authority semantics from transport framing,
//! signature verification, durable admission, and kernel effects.

mod admission_v1;
pub(crate) mod semantics_v1;

pub(crate) use admission_v1::VerifiedMountAdmissionV1;
pub use admission_v1::{MountAdmissionError, MountAuthorityConfigError, MountAuthorityV1};
