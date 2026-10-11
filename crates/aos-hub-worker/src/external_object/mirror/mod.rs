//! External mirror ownership beneath the existing permanent physical-key gate.
//!
//! A retained owner blocks every other mutation and semantic inspection until
//! the exact positive Native commit is acknowledged. Expiry is not settlement.

mod config;
mod control;
pub(super) mod state;

#[cfg(target_arch = "wasm32")]
mod storage;

#[cfg(target_arch = "wasm32")]
pub(super) use storage::closed_source;

#[cfg(target_arch = "wasm32")]
mod provider;

#[cfg(target_arch = "wasm32")]
mod reads;

#[cfg(target_arch = "wasm32")]
mod source;

#[cfg(target_arch = "wasm32")]
mod runtime;

#[cfg(target_arch = "wasm32")]
pub(crate) use runtime::dispatch;

#[cfg(target_arch = "wasm32")]
mod guard;

#[cfg(target_arch = "wasm32")]
pub(crate) use guard::address as guard_address;
