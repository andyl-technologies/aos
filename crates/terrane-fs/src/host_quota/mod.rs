//! Owns native host quota inspection and its registered local query transport.
//!
//! PROTO-60 keeps kernel query privilege in a host-supplied service. This module
//! declaration provides no query implementation or enforcement evidence.

/// Retains fresh-bucket observations for administrative native enrollment.
pub mod initial_enrollment;

mod namespace;
pub use namespace::require_host_root_namespace_boundary;
