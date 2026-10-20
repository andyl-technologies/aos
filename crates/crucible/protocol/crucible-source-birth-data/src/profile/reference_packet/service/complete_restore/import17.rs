//! Defines portable phase vocabulary without native ownership.

use super::transfer::PacketCompleteRestoreTransferPhase;
use serde::{Deserialize, Serialize};

pub mod stage;

/// Identifies one separately spent phase; this label grants no phase permission.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketNativeImport17Phase {
    /// Reserves and authenticates the original six input banks.
    Prepare,
    /// Installs the same verified mapping and model exactly once.
    Commit,
}

impl PacketNativeImport17Phase {
    /// Returns the unchanged inert payload's extension key.
    pub const fn request_extension(self) -> &'static str {
        self.payload_phase().request_extension()
    }

    /// Returns this family's distinct phase proof key.
    pub const fn proof_extension(self) -> &'static str {
        match self {
            Self::Prepare => "source-owned.packet-native-import-prepare-proof/17",
            Self::Commit => "source-owned.packet-native-import-commit-proof/17",
        }
    }

    /// Returns this family's distinct assigned-response receipt key.
    pub const fn receipt_extension(self) -> &'static str {
        match self {
            Self::Prepare => "source-owned.packet-native-import-prepare-receipt/17",
            Self::Commit => "source-owned.packet-native-import-commit-receipt/17",
        }
    }

    const fn payload_phase(self) -> PacketCompleteRestoreTransferPhase {
        match self {
            Self::Prepare => PacketCompleteRestoreTransferPhase::Prepare,
            Self::Commit => PacketCompleteRestoreTransferPhase::Commit,
        }
    }

    /// Returns the original inert proof-domain label, never a key.
    pub const fn proof_domain(self) -> &'static str {
        match self {
            Self::Prepare => "source-owned.packet-native-import-prepare-key/17",
            Self::Commit => "source-owned.packet-native-import-commit-key/17",
        }
    }
}
