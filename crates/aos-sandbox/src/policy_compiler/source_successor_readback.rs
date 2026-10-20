//! Fixed Source-purpose first-successor readback and signature verification.
//!
//! ```text
//! AOSSSO02 | version2 | phase1 | reserved5 | fresh-nonce16 | Root-intent32 |
//! approval896 | genesis-receipt672 | genesis-ACK192 | receipt536-or-zero |
//! ACK192-or-zero | actual-names48 | sequence8 | signer-generation8 |
//! current-Tree-head32 | current-lineage-head32 | current-Tree32 |
//! current-generation8 | Source-purpose-signature64
//! ```
//!
//! Resource purposes AOSSSO04/05 retain approval1072 and independently decoded
//! historical genesis672/848, yielding exact packets2960/3136. The legacy
//! purposes retain their exact 2784 bytes and distinct signature domains.
//!
//! These bytes authenticate comparison DATA only. The fresh challenge
//! does not replace the archived Root nonce/deadline or mint Root authority.


use aos_sandbox_core::ObjectDigest;

use crate::hierarchy::genesis_profile::SourceGenesisErrorV1;

use aos_sandbox_ledger_replay::replay::phase_records::RootFirstSourceSuccessorIntentV2;
use super::source_hold_readback::PinnedSourceHoldReadbackSignerV1;

pub use aos_sandbox_ledger_replay::source_signer_data::source_successor_readback::*;

/// Verifies canonical signed DATA while preserving the existing Native error class.
///
/// # Errors
/// Preserves malformed, signature, saved-join, history and mechanical failures.
pub fn verify_source_first_successor_readback_v2(
    packet: &[u8], signer: &PinnedSourceHoldReadbackSignerV1,
    fresh_nonce: [u8;16], context: &RootFirstSourceSuccessorIntentV2,
) -> Result<VerifiedSourceFirstSuccessorReadbackV2, SourceGenesisErrorV1> {
    aos_sandbox_ledger_replay::source_signer_data::source_successor_readback::verify_source_first_successor_readback_v2(packet, signer, fresh_nonce, context)
        .map_err(SourceGenesisErrorV1::from)
}

/// Verifies canonical signed DATA while preserving the existing Native error class.
///
/// # Errors
/// Preserves malformed, signature, saved-join, history and mechanical failures.
pub fn verify_source_project_continuation_readback_v3(
    packet: &[u8], signer: &PinnedSourceHoldReadbackSignerV1,
    fresh_nonce: [u8;16], context: &RootFirstSourceSuccessorIntentV2,
) -> Result<VerifiedSourceProjectContinuationReadbackV3, SourceGenesisErrorV1> {
    aos_sandbox_ledger_replay::source_signer_data::source_successor_readback::verify_source_project_continuation_readback_v3(packet, signer, fresh_nonce, context)
        .map_err(SourceGenesisErrorV1::from)
}

/// Verifies canonical signed DATA while preserving the existing Native error class.
///
/// # Errors
/// Preserves malformed, signature, saved-join, history and mechanical failures.
pub fn verify_source_resource_first_successor_readback_v4(
    packet: &[u8], signer: &PinnedSourceHoldReadbackSignerV1,
    fresh_nonce: [u8;16], context: &RootFirstSourceSuccessorIntentV2,
) -> Result<VerifiedSourceFirstSuccessorReadbackV2, SourceGenesisErrorV1> {
    aos_sandbox_ledger_replay::source_signer_data::source_successor_readback::verify_source_resource_first_successor_readback_v4(packet, signer, fresh_nonce, context)
        .map_err(SourceGenesisErrorV1::from)
}

/// Verifies canonical signed DATA while preserving the existing Native error class.
///
/// # Errors
/// Preserves malformed, signature, saved-join, history and mechanical failures.
pub fn verify_source_resource_project_continuation_readback_v5(
    packet: &[u8], signer: &PinnedSourceHoldReadbackSignerV1,
    fresh_nonce: [u8;16], context: &RootFirstSourceSuccessorIntentV2,
) -> Result<VerifiedSourceProjectContinuationReadbackV3, SourceGenesisErrorV1> {
    aos_sandbox_ledger_replay::source_signer_data::source_successor_readback::verify_source_resource_project_continuation_readback_v5(packet, signer, fresh_nonce, context)
        .map_err(SourceGenesisErrorV1::from)
}
