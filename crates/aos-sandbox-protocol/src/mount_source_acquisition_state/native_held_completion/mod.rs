//! Pure Root journal sidecars and exact native held-completion transitions.
//!
//! [`RootNativeHeldSidecarV1`] retains the immutable original Root scope, actual
//! response transaction identity, stable assertions and append-once controls.
//! [`validate_native_root_graph_v1`] first validates the entire existing Mount
//! graph, then joins every sidecar to its actual canonical companion records.
//! [`validate_native_root_transition_v1`] checks exact before/after snapshots.
//! These results are data, never a protected append, signing or custody permit.
//!
//! ```text
//! key = aos.mount.native-held-completion.v1\0 | Mount_attempt[32]
//! AOSMHC01 | version:u16be=1 | flags:u16be=0 | reserved[4] |
//! original_Root_scope[224] | response_CAS_transaction[16] |
//! lengths:u32be[4] | R | S | optional_native_verifier | suffix
//! ```
//!
//! The legacy JSON codec, graph validator and mutation scopes remain separate.
//! No descriptor, private clock, original planning token or current authority is
//! reconstructed. Root-local Accepted never enables manager custody or handoff.

mod admission;
mod codec;
mod evidence;
mod graph;
mod reducer;

pub use admission::RootNativeAdmissionBindingV1;
pub use codec::{
    ROOT_NATIVE_HELD_KEY_BYTES_V1, RootNativeHeldSidecarV1, native_root_sidecar_key_v1,
};
pub use evidence::{MAXIMUM_ROOT_NATIVE_VERIFIER_BYTES_V1, RootNativeTerminalVerifierV1};
pub use graph::{RootNativeHeldGraphV1, validate_native_root_graph_v1};
pub use reducer::{
    RootNativeHeldTransitionV1, RootNativeTransitionKindV1,
    validate_native_root_cold_transition_v1, validate_native_root_transition_v1,
};

/// Bounds one binary Root sidecar including every permitted nested archive.
pub const MAXIMUM_ROOT_NATIVE_HELD_SIDECAR_BYTES_V1: usize = 109_902;

const _: () =
    assert!(MAXIMUM_ROOT_NATIVE_HELD_SIDECAR_BYTES_V1 < super::format::MAXIMUM_VALUE_BYTES);

#[cfg(test)]
mod tests;
