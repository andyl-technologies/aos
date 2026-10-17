//! Retained private staging and destination multipart sessions in physical guards.
//!
//! Provider bodies and credentials stay at the ordinary byte executor. The same
//! addressed object retains session ownership, explicit delegated grant tails,
//! pending turns and immutable terminal acknowledgements. Pure immutable reads
//! may retry their exact source after positive provider closure; mutations keep
//! unknown-outcome fences. Configuration is default-off and independently pinned.

mod closed;
mod config;
#[cfg(all(feature = "do-e2e", any(test, target_arch = "wasm32")))]
pub(super) mod lease_scale;
mod protocol;
#[cfg(any(test, target_arch = "wasm32"))]
mod renewal;
pub(super) mod state;

#[cfg(target_arch = "wasm32")]
mod direct_guard;
#[cfg(target_arch = "wasm32")]
mod inspection;
#[cfg(target_arch = "wasm32")]
pub(crate) use inspection::{admit_stage_read, read_stage_metadata};
#[cfg(target_arch = "wasm32")]
mod executor;
#[cfg(target_arch = "wasm32")]
pub(in crate::external_object) mod planning;
#[cfg(target_arch = "wasm32")]
mod profiles;
#[cfg(target_arch = "wasm32")]
mod storage;

#[cfg(target_arch = "wasm32")]
pub(crate) use direct_guard::{
    check_direct_available, direct_abort, direct_baseline, direct_final, direct_source,
    prepare_direct_destination,
};

#[cfg(target_arch = "wasm32")]
pub(crate) use executor::{
    execute_stage, execute_stage_observed, execute_stage_with_signal, fetch,
};
#[cfg(target_arch = "wasm32")]
pub(in crate::external_object) use planning::acquire_configured_lease;
#[cfg(target_arch = "wasm32")]
pub(in crate::external_object) use planning::prepare_observation_read_lease;
#[cfg(target_arch = "wasm32")]
pub(crate) use planning::{
    prepare_stage_read_recovery, prepare_stage_request, prepare_stage_request_with_cutoff,
    presign_registered_parts,
};
#[cfg(target_arch = "wasm32")]
pub(crate) use profiles::resolve_external_profiles;

#[cfg(target_arch = "wasm32")]
pub(super) use storage::{closed_copy_source, verify_observable_destination};

#[cfg(test)]
mod tests;

#[cfg(all(feature = "do-e2e", any(test, target_arch = "wasm32")))]
pub(crate) mod observation;

#[cfg(all(feature = "do-e2e", target_arch = "wasm32"))]
pub(crate) use executor::execute_stage_observed_with_fault;
