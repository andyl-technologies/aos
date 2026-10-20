//! Separates import18 Envelope keys from unchanged inner phase17 DATA domains.
//!
//! The receipt key identifies the wire family even when a response has no
//! binding extension. Actual pending-original correlation and negotiated full
//! selection remain mandatory; an extension label supplies no phase permission.

use super::super::import17::PacketNativeImport17Phase;
use super::*;

/// Names an import18 phase without reinterpreting an older assigned Envelope.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketNativeImport18Phase {
    /// Prepares the distinct seven-bank transaction.
    Prepare,
    /// Installs the same completed transaction once.
    Commit,
}

impl PacketNativeImport18Phase {
    /// Returns the unchanged inert request12 payload key.
    pub const fn request_extension(self) -> &'static str {
        self.payload_phase_data().request_extension()
    }

    /// Returns this successor's unambiguous assigned-request proof key.
    pub const fn proof_extension(self) -> &'static str {
        match self {
            Self::Prepare => "source-owned.packet-native-import-prepare-proof/18",
            Self::Commit => "source-owned.packet-native-import-commit-proof/18",
        }
    }

    /// Returns this successor's unambiguous correlated-response receipt key.
    pub const fn receipt_extension(self) -> &'static str {
        match self {
            Self::Prepare => "source-owned.packet-native-import-prepare-receipt/18",
            Self::Commit => "source-owned.packet-native-import-commit-receipt/18",
        }
    }

    /// Identifies the unchanged inner phase17 DATA and cryptographic domain.
    pub const fn payload_phase_data(self) -> PacketNativeImport17Phase {
        match self {
            Self::Prepare => PacketNativeImport17Phase::Prepare,
            Self::Commit => PacketNativeImport17Phase::Commit,
        }
    }
}
