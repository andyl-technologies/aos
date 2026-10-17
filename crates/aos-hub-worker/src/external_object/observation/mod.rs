//! Retained metadata-only read slots beside physical mutation ownership.

pub(super) mod protocol;
pub(super) mod reply;
pub(super) mod state;

#[cfg(target_arch = "wasm32")]
mod executor;
#[cfg(target_arch = "wasm32")]
mod semantic;
#[cfg(target_arch = "wasm32")]
mod storage;

#[cfg(target_arch = "wasm32")]
pub(crate) use executor::fetch;
pub(super) use protocol::Pending;
#[cfg(target_arch = "wasm32")]
pub(crate) use semantic::fetch as fetch_semantic;

#[cfg(test)]
mod tests;
