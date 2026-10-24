//! Names original transfer schema phases without holding a transfer owner.

/// Names the exact registered transfer feature.
pub const PACKET_COMPLETE_RESTORE_TRANSFER_FEATURE: &str =
    "source-owned.packet-complete-restore-transfer/12";

/// Names the exact registered prepare extension.
pub const PACKET_COMPLETE_RESTORE_PREPARE_EXTENSION: &str =
    "source-owned.packet-complete-restore-prepare/12";

/// Names the exact registered prepare proof extension.
pub const PACKET_COMPLETE_RESTORE_PREPARE_PROOF_EXTENSION: &str =
    "source-owned.packet-complete-restore-prepare-proof/12";

/// Names the exact registered prepare receipt extension.
pub const PACKET_COMPLETE_RESTORE_PREPARE_RECEIPT_EXTENSION: &str =
    "source-owned.packet-complete-restore-prepare-receipt/12";

/// Names the exact registered commit extension.
pub const PACKET_COMPLETE_RESTORE_COMMIT_EXTENSION: &str =
    "source-owned.packet-complete-restore-commit/12";

/// Names the exact registered commit proof extension.
pub const PACKET_COMPLETE_RESTORE_COMMIT_PROOF_EXTENSION: &str =
    "source-owned.packet-complete-restore-commit-proof/12";

/// Names the exact registered commit receipt extension.
pub const PACKET_COMPLETE_RESTORE_COMMIT_RECEIPT_EXTENSION: &str =
    "source-owned.packet-complete-restore-commit-receipt/12";

/// Bounds the canonical transfer request and its separately charged scratch.
pub const MAXIMUM_COMPLETE_RESTORE_TRANSFER_REQUEST_BYTES: usize = 16384;

/// Bounds the canonical transfer context and its separately charged scratch.
pub const MAXIMUM_COMPLETE_RESTORE_TRANSFER_CONTEXT_BYTES: usize = 4096;

/// Bounds the canonical transfer proof and its separately charged scratch.
pub const MAXIMUM_COMPLETE_RESTORE_TRANSFER_PROOF_BYTES: usize = 256;

/// Bounds the canonical transfer receipt and its separately charged scratch.
pub const MAXIMUM_COMPLETE_RESTORE_TRANSFER_RECEIPT_BYTES: usize = 1536;

/// Selects an independently authenticated phase, without issuing authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PacketCompleteRestoreTransferPhase {
    /// Permits only exact precharged input custody.
    Prepare,
    /// Consumes the same lease before installation effects.
    Commit,
}

impl PacketCompleteRestoreTransferPhase {
    /// Returns the exact registered request extension.
    pub const fn request_extension(self) -> &'static str {
        match self {
            Self::Prepare => PACKET_COMPLETE_RESTORE_PREPARE_EXTENSION,
            Self::Commit => PACKET_COMPLETE_RESTORE_COMMIT_EXTENSION,
        }
    }
    /// Returns the exact registered request proof extension.
    pub const fn proof_extension(self) -> &'static str {
        match self {
            Self::Prepare => PACKET_COMPLETE_RESTORE_PREPARE_PROOF_EXTENSION,
            Self::Commit => PACKET_COMPLETE_RESTORE_COMMIT_PROOF_EXTENSION,
        }
    }
    /// Returns the exact registered response receipt extension.
    pub const fn receipt_extension(self) -> &'static str {
        match self {
            Self::Prepare => PACKET_COMPLETE_RESTORE_PREPARE_RECEIPT_EXTENSION,
            Self::Commit => PACKET_COMPLETE_RESTORE_COMMIT_RECEIPT_EXTENSION,
        }
    }
}

mod contract;
pub use contract::{
    CompleteRestoreTransferContractValue, PacketCompleteRestoreTransferSchema,
    complete_restore_transfer_contract, complete_restore_transfer_schema,
};
