//! Storage-side same-binding copy bytes and permanent original ownership.
//!
//! Byte helpers require an already admitted immutable source and exact range.
//! They never create a business admission, lease or terminal guard receipt.

mod bytes;

#[cfg(target_arch = "wasm32")]
mod stream;

#[cfg(target_arch = "wasm32")]
mod window;

#[cfg(target_arch = "wasm32")]
mod lifetime;

#[cfg(all(target_arch = "wasm32", feature = "do-e2e"))]
mod conformance;

#[cfg(all(target_arch = "wasm32", feature = "do-e2e"))]
pub(crate) use conformance::fetch as conformance_fetch;
