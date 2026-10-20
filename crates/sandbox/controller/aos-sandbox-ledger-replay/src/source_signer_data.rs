//! Owns canonical Source signer comparison framing, cryptographic DATA and errors.
//!
//! These codecs and signature checks neither open a role's journal nor retain a
//! peer, private credential, financial original, live writer or currentness loan.
//! Actual native Source/Root gates remain with their closed role owners.

/// Shares the existing source hold readback DATA grammar.
pub mod source_hold_readback;
/// Shares the existing source hold readback v2 DATA grammar.
pub mod source_hold_readback_v2;
/// Shares the existing source genesis readback DATA grammar.
pub mod source_genesis_readback;
/// Verifies the existing Controller genesis comparison signatures.
pub mod controller_genesis_readback;
/// Shares the existing source project admission readback DATA grammar.
pub mod source_project_admission_readback;
/// Shares the existing source successor readback DATA grammar.
pub mod source_successor_readback;
/// Shares the existing source signer wire DATA grammar.
pub mod source_signer_wire;

pub use source_hold_readback::{SOURCE_HOLD_READBACK_BYTES_V1, SourceHoldReadbackErrorV1, SourceHoldReadbackChallengeV1, PinnedSourceHoldReadbackSignerV1, encode_source_hold_readback_signer_credential_v1, verify_current_source_hold_readback_v1};
pub use source_hold_readback_v2::{SOURCE_HOLD_READBACK_BYTES_V2, verify_source_hold_readback_with_names_v2};
pub use source_genesis_readback::{SourceTreeGenesisStateV1, SOURCE_TREE_GENESIS_READBACK_BYTES_V1, SOURCE_TREE_GENESIS_READBACK_BYTES_V2, SOURCE_PROJECT_GENESIS_READBACK_BYTES_V3, SOURCE_PROJECT_RESOURCE_GENESIS_READBACK_BYTES_V4, SourceProjectGenesisReadbackPacketV4, SourceTreeGenesisReadbackPacketV2, SourceProjectGenesisChallengeV3, VerifiedSourceProjectGenesisReadbackV3, verify_source_project_genesis_readback_v3, SourceTreeGenesisChallengeV1, VerifiedSourceTreeGenesisReadbackV1, verify_source_tree_genesis_readback_v1, verify_source_tree_genesis_readback_v2};
pub use source_project_admission_readback::{SOURCE_PROJECT_COMPLETED_TERMINAL_READBACK_BYTES_V1, VerifiedSourceProjectTerminalReadbackV1, verify_source_project_completed_terminal_readback_v1, SOURCE_PROJECT_ADMISSION_READBACK_BYTES_V1, SOURCE_PROJECT_RESERVATION_READBACK_BYTES_V1, verify_source_project_reservation_readback_v1, verify_source_project_admission_readback_v1, verify_source_project_retirement_readback_v1};
pub use source_successor_readback::{SOURCE_FIRST_SUCCESSOR_READBACK_BYTES_V2, SOURCE_PROJECT_CONTINUATION_READBACK_BYTES_V3, SOURCE_RESOURCE_SUCCESSOR_LEGACY_GENESIS_BYTES_V4, SOURCE_RESOURCE_SUCCESSOR_READBACK_BYTES_V4, SourceFirstSuccessorReadbackPhaseV2, VerifiedSourceFirstSuccessorReadbackV2, VerifiedSourceProjectContinuationReadbackV3, verify_source_first_successor_readback_v2, verify_source_project_continuation_readback_v3, verify_source_resource_first_successor_readback_v4, verify_source_resource_project_continuation_readback_v5};

#[cfg(target_os = "linux")]
pub use source_genesis_readback::{SourceTreeGenesisIntentContextV1, SOURCE_TREE_GENESIS_INTENT_CONTEXT_BYTES_V1, SOURCE_TREE_GENESIS_INTENT_CONTEXT_BYTES_V2};

/// Preserves the typed leaf of a historical Source observation comparison.
#[derive(Debug, thiserror::Error)]
pub enum SourceSignerGenesisDataErrorV1 {
    /// A fixed field, signature or frame is noncanonical.
    #[error("invalid Source genesis record or exact owner join")]
    NonCanonical,
    /// The exact saved receipt, phase or original join conflicts.
    #[error("Source genesis project or flight conflicts with retained state")]
    Conflict,
    /// The original native-format mechanical decoder failed.
    #[error(transparent)]
    Mechanical(#[from] aos_sandbox_broker::canonical_journal::CanonicalJournalMechanicalErrorV1),
    /// The original protected physical-name DATA decoder failed.
    #[error(transparent)]
    History(#[from] aos_sandbox_protocol::domain_ledger::ProtectedHistoryDataErrorV1),
    /// The original canonical saved Source graph decoder failed.
    #[error(transparent)]
    SourceData(#[from] crate::data::SourceSuccessorDataErrorV2),
}

impl From<crate::genesis::SourceGenesisReceiptDataErrorV1> for SourceSignerGenesisDataErrorV1 {
    fn from(error: crate::genesis::SourceGenesisReceiptDataErrorV1) -> Self {
        match error { crate::genesis::SourceGenesisReceiptDataErrorV1::NonCanonical => Self::NonCanonical }
    }
}

#[doc(hidden)]
pub mod credential_validation;
