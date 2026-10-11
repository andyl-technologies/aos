//! Worker-only material custody and fresh metadata probe/adoption producers.
//!
//! Staging alone admits no normal binding work. An actual positive provider
//! probe and fresh current SQL metadata are required for adoption. Validated
//! material retention is renewed by authenticated adoption; expired idle material
//! requires operator staging and another genuine queued validation task.

mod state;

#[cfg(target_arch = "wasm32")]
mod frozen;
#[cfg(target_arch = "wasm32")]
mod probe;
#[cfg(target_arch = "wasm32")]
mod runtime;
#[cfg(target_arch = "wasm32")]
pub(crate) use runtime::{fetch, handle, reply_adoption, response, revoke_material, Outcome};
#[cfg(target_arch = "wasm32")]
mod expiry;
#[cfg(target_arch = "wasm32")]
pub(crate) use expiry::{expire_material, schedule_expiry};

/// Identifies the closed private custody control routes.
pub(crate) fn is_path(path: &str) -> bool {
    use aos_hub_core::storage_work::binding_custody::*;
    matches!(
        path,
        STORAGE_CREDENTIAL_CUSTODY_PATH
            | STORAGE_CREDENTIAL_CUSTODY_PROBE_PATH
            | STORAGE_BINDING_ADOPTION_PATH
            | STORAGE_FROZEN_CLEANUP_CUSTODY_PATH
            | STORAGE_FROZEN_CLEANUP_CREDENTIAL_STAGE_PATH
            | STORAGE_FROZEN_DELETE_CUSTODY_PATH
    )
}

#[cfg(test)]
mod tests;
