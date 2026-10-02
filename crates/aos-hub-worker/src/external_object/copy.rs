//! Storage-side same-binding copy bytes and permanent original ownership.
//!
//! Byte helpers require an already admitted immutable source and exact range.
//! They never create a business admission, lease or terminal guard receipt.

mod bytes;

mod hash_range;

mod config;

mod protocol;

mod source_protocol;

mod discovery;

mod read_control;

mod list_cursor;

mod provider_receipt;

pub(in crate::external_object) mod state;

#[cfg(target_arch = "wasm32")]
mod closure;

#[cfg(target_arch = "wasm32")]
mod source;

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
mod stream;

#[cfg(target_arch = "wasm32")]
mod window;

#[cfg(target_arch = "wasm32")]
mod lifetime;

#[cfg(all(target_arch = "wasm32", feature = "do-e2e"))]
mod conformance;

#[cfg(all(target_arch = "wasm32", feature = "do-e2e"))]
pub(crate) use conformance::fetch as conformance_fetch;
