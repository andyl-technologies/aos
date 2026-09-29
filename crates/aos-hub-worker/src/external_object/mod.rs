//! Bounded external metadata execution with persistent per-key uncertainty.
//!
//! This first consumer accepts metadata PUT and historical guarded HEAD only.
//! Bodies and credentials stay at the byte executor. A compact addressed DO
//! retains admission floors, pending turns and permanent terminal receipts.
//! Configuration is independently reviewed input, not provider qualification.
//! No domain is enabled by this module or by its local fault fixture.

mod config;
mod protocol;
mod state;

#[cfg(target_arch = "wasm32")]
mod executor;
#[cfg(target_arch = "wasm32")]
mod storage;

#[cfg(target_arch = "wasm32")]
pub(crate) use executor::{deny_legacy, fetch, PATH};
#[cfg(target_arch = "wasm32")]
pub use storage::ExternalObjectGuard;

#[cfg(test)]
mod tests;
