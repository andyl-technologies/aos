//! Bounded storage-local mirror producer and durable original recovery.
//!
//! Native chooses trust and destination authority. The producer owns private
//! multipart bytes, exact verification and physical uncertainty. It admits no
//! generic external writes, does not manufacture direct-upload client sessions,
//! and cannot release a final reservation without the exact Native commit.

#[cfg(target_arch = "wasm32")]
pub(crate) mod batch;
pub(crate) mod buffers;
#[cfg(any(test, target_arch = "wasm32"))]
pub(crate) mod guard_state;
#[cfg(target_arch = "wasm32")]
pub(crate) mod inspection;
#[cfg(target_arch = "wasm32")]
pub(crate) mod inventory;
#[cfg(target_arch = "wasm32")]
pub(crate) mod membership;
pub(crate) mod pack;
pub(crate) mod verify;

#[cfg(target_arch = "wasm32")]
pub(crate) mod runtime;

#[cfg(target_arch = "wasm32")]
pub(crate) mod acceptance;

#[cfg(target_arch = "wasm32")]
pub(crate) mod guard_proof;

#[cfg(all(target_arch = "wasm32", feature = "do-e2e"))]
pub(crate) mod candidate;
