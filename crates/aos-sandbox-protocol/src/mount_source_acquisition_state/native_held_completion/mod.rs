//! Pure Root journal sidecars and exact native held-completion transitions.
//!
//! [`RootNativeHeldSidecarV1`] retains the immutable original Root scope, actual
//! response transaction identity, stable assertions and append-once controls.
//! [`validate_native_root_graph_v1`] first validates the entire existing Mount
//! graph, then joins every sidecar to its actual canonical companion records.
//! [`validate_native_root_transition_v1`] checks exact before/after snapshots.
//! These results are data, never a protected append, signing or custody permit.
//!
//! [`RootNativeHeldSidecarV2`] separately retains immutable admission and first-R
//! cuts. [`validate_native_root_graph_v2`] validates today's entire legacy graph
//! before reconstructing those historical bytes; it never infers a cut from a
//! v1 sidecar. Historical byte equality is not physical equality at today's keys.
//! [`RootNativeNoEscapeTerminalV2`] is a standalone marker codec; no sidecar or
//! owner reducer accepts it yet.
//!
//! ```text
//! key = aos.mount.native-held-completion.v1\0 | Mount_attempt[32]
//! AOSMHC01 | version:u16be=1 | flags:u16be=0 | reserved[4] |
//! original_Root_scope[224] | response_CAS_transaction[16] |
//! lengths:u32be[4] | R | S | optional_native_verifier | suffix
//!
//! key = aos.mount.native-held-completion.v2\0 | Mount_attempt[32]
//! AOSMHC02 | version:u16be=2 | flags:u16be=0 | reserved[4] |
//! original_Root_scope[224] | response_CAS_transaction[16] |
//! lengths:u32be[7] | R | S | optional_native_verifier | suffix |
//! AdmissionCut | optional_DispositionCut | optional_NoInterestTerminal
//! ```
//!
//! The legacy JSON codec, graph validator and mutation scopes remain separate.
//! No descriptor, private clock, original planning token or current authority is
//! reconstructed. Root-local Accepted never enables manager custody or handoff.

mod admission;
mod codec;
mod codec_v2;
mod cut;
mod evidence;
mod graph;
mod graph_v2;
mod no_escape_terminal;
mod ordinary_inventory_v6;
mod original_v5;
mod pending_v5;
mod recovery_v2;
mod reducer;
mod reducer_v2;

pub use admission::RootNativeAdmissionBindingV1;
pub use codec::{
    ROOT_NATIVE_HELD_KEY_BYTES_V1, RootNativeHeldSidecarV1, native_root_sidecar_key_v1,
};
pub use codec_v2::{
    MAXIMUM_ROOT_NATIVE_HELD_SIDECAR_BYTES_V2, ROOT_NATIVE_HELD_KEY_BYTES_V2,
    ROOT_NATIVE_NO_INTEREST_TERMINAL_BYTES_V1, RootNativeHeldSidecarV2,
    RootNativeNoInterestTerminalV1, native_root_sidecar_key_v2,
};
pub use cut::{
    MAXIMUM_ROOT_NATIVE_CUT_ACQUISITION_BYTES_V1, MAXIMUM_ROOT_NATIVE_CUT_BYTES_V1,
    MAXIMUM_ROOT_NATIVE_CUT_HEAD_BYTES_V1, RootNativeCutKindV1, RootNativeCutV1,
    RootNativeReconstructedCutV1,
};
pub use evidence::{MAXIMUM_ROOT_NATIVE_VERIFIER_BYTES_V1, RootNativeTerminalVerifierV1};
pub use graph::{RootNativeHeldGraphV1, validate_native_root_graph_v1};
pub use graph_v2::{RootNativeDataClassV2, RootNativeHeldGraphV2, validate_native_root_graph_v2};
pub use no_escape_terminal::{ROOT_NATIVE_NO_ESCAPE_TERMINAL_BYTES_V2, RootNativeNoEscapeTerminalV2};
pub use ordinary_inventory_v6::{
    OriginalInventoryTransitionKindV6, OriginalInventoryTransitionV6,
    validate_original_inventory_transition_v6,
};
pub use original_v5::{
    original_root_remaining_v5, validate_original_root_preparation_v5,
    validate_original_root_transition_v5,
};
pub use pending_v5::{
    has_original_pending_closed_cut_v5, validate_original_pending_closed_transition_v5,
};
pub use reducer::{
    RootNativeHeldTransitionV1, RootNativeTransitionKindV1,
    validate_native_root_cold_transition_v1, validate_native_root_transition_v1,
};
pub use reducer_v2::{
    RootNativeAdmissionBindingV2, RootNativeHeldTransitionV2, RootNativeTransitionKindV2,
    validate_native_root_cold_transition_v2, validate_native_root_transition_v2,
};

/// Bounds one binary Root sidecar including every permitted nested archive.
pub const MAXIMUM_ROOT_NATIVE_HELD_SIDECAR_BYTES_V1: usize = 109_902;

const _: () =
    assert!(MAXIMUM_ROOT_NATIVE_HELD_SIDECAR_BYTES_V1 < super::format::MAXIMUM_VALUE_BYTES);

#[cfg(test)]
mod tests;
