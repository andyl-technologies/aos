//! OCI-owned external staging, composition and conditional semantic readback.
//!
//! The producer uses real OCI reservation originals and the existing permanent
//! full-key object guard. Generic metadata PUT, direct-upload staging and copy
//! qualification never enable this workflow.

mod config;
pub(super) mod state;

#[cfg(target_arch = "wasm32")]
mod provider;

#[cfg(target_arch = "wasm32")]
mod storage;

#[cfg(target_arch = "wasm32")]
pub(super) use storage::closed_copy_source;

#[cfg(target_arch = "wasm32")]
mod runtime;

#[cfg(target_arch = "wasm32")]
pub(crate) use runtime::{fetch, stage};

#[cfg(test)]
mod tests;

#[cfg(target_arch = "wasm32")]
mod transport;

#[cfg(target_arch = "wasm32")]
mod projection;

#[cfg(target_arch = "wasm32")]
mod source;

#[cfg(target_arch = "wasm32")]
pub(crate) use source::fetch as source_fetch;

#[cfg(target_arch = "wasm32")]
mod compose;

#[cfg(target_arch = "wasm32")]
pub(crate) mod byte_stream;

mod cleanup_state;

#[cfg(target_arch = "wasm32")]
mod cleanup;

#[cfg(target_arch = "wasm32")]
pub(crate) use cleanup::fetch as cleanup_fetch;
