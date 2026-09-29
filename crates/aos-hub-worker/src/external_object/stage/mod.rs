//! Retained private staging and destination multipart sessions in physical guards.
//!
//! Provider bodies and credentials stay at the ordinary byte executor. The same
//! addressed object retains session ownership, explicit delegated grant tails,
//! pending turns and immutable terminal acknowledgements. Pure immutable reads
//! may retry their exact source after positive provider closure; mutations keep
//! unknown-outcome fences. Configuration is default-off and independently pinned.

mod config;
mod protocol;
pub(super) mod state;

#[cfg(target_arch = "wasm32")]
mod executor;
#[cfg(target_arch = "wasm32")]
mod planning;
#[cfg(target_arch = "wasm32")]
mod profiles;
#[cfg(target_arch = "wasm32")]
mod storage;

#[cfg(target_arch = "wasm32")]
pub(crate) use executor::{execute_stage, fetch};
#[cfg(target_arch = "wasm32")]
pub(in crate::external_object) use planning::prepare_observation_read_lease;
#[cfg(target_arch = "wasm32")]
pub(crate) use planning::{
    prepare_stage_read_recovery, prepare_stage_request, presign_registered_parts,
};
#[cfg(target_arch = "wasm32")]
pub(crate) use profiles::resolve_external_profiles;

#[cfg(target_arch = "wasm32")]
pub(super) use storage::verify_observable_destination;

#[cfg(test)]
mod tests;
