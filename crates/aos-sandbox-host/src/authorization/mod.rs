//! Host-specific signed broker authority and canonical semantics.
//!
//! [`HostAuthorityV1`] adapts protected shared admission to the host audience.
//! [`semantics_v1`] re-exports the pure protocol-owned definition of each
//! signed host verb, target, and argument commitment. It intentionally exposes
//! no node-local catalog or kernel-identity type.

mod admission_v1;
pub mod semantics_v1;

pub use admission_v1::{HostAdmissionError, HostAuthorityConfigError, HostAuthorityV1};
