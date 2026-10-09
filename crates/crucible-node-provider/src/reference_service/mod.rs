//! Immutable installed profile for the controlled checksum CNP service.
//!
//! [`ReferenceProfile`] binds model, configuration, ports, implementation
//! artifacts and explicit guarantee limits. Native launch and protocol dispatch
//! use independently authenticated host custody.

pub mod profile;

pub use profile::{ProfileContent, ReferenceProfile};
