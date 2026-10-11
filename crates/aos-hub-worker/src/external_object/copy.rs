//! Storage-side same-binding copy bytes and permanent original ownership.
//!
//! Byte helpers require an already admitted immutable source and exact range.
//! They never create a business admission, lease or terminal guard receipt.

mod bytes;

#[cfg(any(test, feature = "do-e2e"))]
mod observation;

mod hash_range;

pub(super) mod config;

mod protocol;

pub(super) mod source_protocol;

mod discovery;

mod read_control;

mod list_cursor;

mod provider_receipt;

pub(in crate::external_object) mod state;

#[cfg(target_arch = "wasm32")]
pub(super) mod closure;

#[cfg(target_arch = "wasm32")]
pub(super) mod source;

#[cfg(target_arch = "wasm32")]
mod storage;

#[cfg(target_arch = "wasm32")]
mod executor;

#[cfg(target_arch = "wasm32")]
mod metadata;

#[cfg(target_arch = "wasm32")]
mod reads;

#[cfg(target_arch = "wasm32")]
pub(crate) use reads::execute as execute_scan_read;

#[cfg(target_arch = "wasm32")]
pub(crate) use executor::fetch as fetch_control;

#[cfg(target_arch = "wasm32")]
pub(crate) use metadata::fetch as fetch_metadata;

#[cfg(target_arch = "wasm32")]
pub(super) mod stream;

#[cfg(target_arch = "wasm32")]
pub(super) mod window;

#[cfg(target_arch = "wasm32")]
pub(super) mod lifetime;

#[cfg(all(target_arch = "wasm32", feature = "do-e2e"))]
mod conformance;

#[cfg(all(target_arch = "wasm32", feature = "do-e2e"))]
pub(crate) use conformance::fetch as conformance_fetch;
