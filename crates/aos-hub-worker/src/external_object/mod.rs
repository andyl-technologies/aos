//! Bounded external metadata execution with persistent per-key uncertainty.
//!
//! It accepts metadata PUT, historical guarded HEAD and qualified private-stage
//! controls. None of these receipts enables provider domains or business flows.
//! Bodies and credentials stay at the byte executor. A compact addressed DO
//! retains admission floors, pending turns and permanent terminal receipts.
//! Configuration is independently reviewed input, not provider qualification.
//! No domain is enabled by this module or by its local fault fixture.

mod config;
mod copy;
mod delete_config;
mod deletion;
mod observation;
mod protocol;
mod stage;
mod state;

#[cfg(all(target_arch = "wasm32", feature = "do-e2e"))]
pub(crate) use copy::conformance_fetch as copy_conformance_fetch;

#[cfg(target_arch = "wasm32")]
mod executor;
#[cfg(target_arch = "wasm32")]
mod frozen;
#[cfg(target_arch = "wasm32")]
mod storage;
#[cfg(target_arch = "wasm32")]
pub(crate) use frozen::check_cleanup_ready;

#[cfg(target_arch = "wasm32")]
pub(crate) use executor::{deny_legacy, fetch, PATH};
#[cfg(target_arch = "wasm32")]
pub(crate) use executor::{execute_delete_plan, execute_probe_plan, lookup_delete_plan};
#[cfg(target_arch = "wasm32")]
pub(crate) use observation::fetch as fetch_observation;
#[cfg(target_arch = "wasm32")]
pub(crate) use observation::fetch_semantic as fetch_semantic_observation;
#[cfg(target_arch = "wasm32")]
pub use storage::ExternalObjectGuard;

#[cfg(target_arch = "wasm32")]
pub(crate) use stage::resolve_external_profiles;
#[cfg(target_arch = "wasm32")]
pub(crate) use stage::{admit_stage_read, read_stage_metadata};
#[cfg(target_arch = "wasm32")]
pub(crate) use stage::{
    check_direct_available, direct_abort, direct_baseline, direct_final, direct_source,
    prepare_direct_destination,
};
#[cfg(target_arch = "wasm32")]
pub(crate) use stage::{execute_stage, execute_stage_observed, fetch as fetch_stage};
#[cfg(target_arch = "wasm32")]
pub(crate) use stage::{
    prepare_stage_read_recovery, prepare_stage_request, prepare_stage_request_with_cutoff,
    presign_registered_parts,
};

#[cfg(test)]
mod frozen_tests;
#[cfg(test)]
mod tests;
