//! Physical publication reservations and independent fresh receipt lookup.
//!
//! The reservation lives in the permanent physical-key object alongside legacy
//! mutation fences. Original admission, full Complete, verified source and exact
//! protected profile are retained before provider effects. Unknown effects and
//! acknowledged publication records have no expiration-based retirement.
//!
//! ```text
//! direct-guard/owner/v1 -> retained original reservation
//! direct-guard/effect/v1/<operation> -> exact attempt and positive receipt
//! direct-guard/final/v1/<reservation> -> acknowledged immutable publication
//! direct-guard/external-effect/v1/<operation> -> reserved external dispatch
//! direct-guard/native/v1/<reservation>/<nonce>/receipt -> authenticated Native commit
//! direct-guard/native/v1/<reservation>/<nonce>/body/<index> -> bounded body chunk
//! ```

mod state;

#[cfg(target_arch = "wasm32")]
mod effects;
#[cfg(target_arch = "wasm32")]
mod lookup;
#[cfg(target_arch = "wasm32")]
mod runtime;
#[cfg(target_arch = "wasm32")]
mod transport;

#[cfg(target_arch = "wasm32")]
pub(crate) use lookup::{fetch, physical_lookup};
#[cfg(target_arch = "wasm32")]
pub(crate) use runtime::{
    check_external_stage, deny_legacy, physical_fetch, verify_external_dispatch,
};
#[cfg(target_arch = "wasm32")]
pub(crate) use transport::{
    acknowledge_native_commit, promote_external, promote_managed, read_publication,
    reserve_baseline,
};

#[cfg(test)]
mod tests;

#[cfg(any(test, feature = "do-e2e"))]
pub(crate) mod fixture;

#[cfg(all(feature = "do-e2e", target_arch = "wasm32"))]
mod conformance;
#[cfg(all(feature = "do-e2e", target_arch = "wasm32"))]
pub(crate) use conformance::{
    fetch as conformance_fetch, physical_fetch as conformance_physical_fetch,
};
