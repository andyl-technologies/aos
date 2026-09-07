//! Host compatibility facade for portable runtime authority semantics.
//!
//! The byte-exact compiler is owned by
//! [`aos_sandbox_protocol::semantics::host`]. This module preserves the host
//! crate's established API while adding no node-local data or encoding logic.

pub use aos_sandbox_protocol::semantics::host::{
    CanonicalHostSemanticsV1, HostSemanticError, canonical_host_semantics_v1, runtime_handle_v1,
    runtime_resource_handle,
};
