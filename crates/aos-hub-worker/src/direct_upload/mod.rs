//! Direct-upload control broker, original journals and physical publication guards.
//!
//! Compact metadata crosses Native; clients send UploadPart bytes to their
//! exact provider capability. Durable records precede capability exposure and
//! effects, and separate bounded verification queues consume immutable stages.

pub(crate) mod journal;
#[cfg(any(target_arch = "wasm32", test))]
mod batches;

#[cfg(any(target_arch = "wasm32", test))]
mod complete;

#[cfg(any(target_arch = "wasm32", test))]
mod control;

#[cfg(target_arch = "wasm32")]
mod effects;

#[cfg(target_arch = "wasm32")]
mod authority;

#[cfg(target_arch = "wasm32")]
pub(crate) mod config;
#[cfg(target_arch = "wasm32")]
pub(crate) mod deployment;
#[cfg(target_arch = "wasm32")]
pub(crate) mod storage;
#[cfg(target_arch = "wasm32")]
pub(crate) mod broker;
#[cfg(target_arch = "wasm32")]
pub(crate) mod managed;
#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) mod provider_capacity;
#[cfg(target_arch = "wasm32")]
pub(crate) mod verification;
#[cfg(target_arch = "wasm32")]
pub(crate) mod conformance;

#[cfg(target_arch = "wasm32")]
pub use storage::HybridDirectUpload;
#[cfg(target_arch = "wasm32")]
pub(crate) use broker::fetch;
