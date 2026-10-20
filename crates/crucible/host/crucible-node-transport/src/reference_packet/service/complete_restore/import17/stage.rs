//! Defines the original finite Native17 stage vocabulary as inert DATA.
//!
//! Only the defining enum, constants and key selectors needed by the imported18
//! declaration are selected here. No native stage, proof owner or issuer is installed.

use super::*;
use crate::envelope::Method;

/// Names the separate stage binding extension and complete grammar.
pub const NATIVE_IMPORT17_STAGE_EXTENSION: &str = "source-owned.packet-native-import-stage/17";
/// Bounds the complete literal stage association independently of older families.
pub const MAXIMUM_NATIVE_IMPORT17_STAGE_BINDING_BYTES: usize = 8192;
/// Bounds the closed three-digest stage context.
pub const MAXIMUM_NATIVE_IMPORT17_STAGE_CONTEXT_BYTES: usize = 1024;
/// Bounds the complete distinct stage proof.
pub const MAXIMUM_NATIVE_IMPORT17_STAGE_PROOF_BYTES: usize = 512;
/// Bounds the complete distinct stage receipt.
pub const MAXIMUM_NATIVE_IMPORT17_STAGE_RECEIPT_BYTES: usize = 1024;

/// Distinguishes three independently spent native17 stages.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketNativeImport17Stage {
    /// Arms the actual fresh owner behind the same physical Hold.
    Arm,
    /// Accepts the actual published global World before releasing that Hold.
    World,
    /// Observes once after the same actual World release.
    FirstObserve,
}

impl PacketNativeImport17Stage {
    /// Returns its baseline method without creating a phase permission.
    pub const fn method_data(self) -> Method {
        match self {
            Self::Arm => Method::Activate,
            Self::World => Method::WorldActivate,
            Self::FirstObserve => Method::Observe,
        }
    }

    /// Returns its distinct original proof key.
    pub const fn proof_extension(self) -> &'static str {
        match self {
            Self::Arm => "source-owned.packet-native-import-arm-proof/17",
            Self::World => "source-owned.packet-native-import-world-proof/17",
            Self::FirstObserve => "source-owned.packet-native-import-first-observe-proof/17",
        }
    }

    /// Returns its distinct correlated terminal receipt key.
    pub const fn receipt_extension(self) -> &'static str {
        match self {
            Self::Arm => "source-owned.packet-native-import-arm-receipt/17",
            Self::World => "source-owned.packet-native-import-world-receipt/17",
            Self::FirstObserve => "source-owned.packet-native-import-first-observe-receipt/17",
        }
    }

    const fn proof_domain(self) -> &'static str {
        match self {
            Self::Arm => "source-owned.packet-native-import-arm-key/17",
            Self::World => "source-owned.packet-native-import-world-key/17",
            Self::FirstObserve => "source-owned.packet-native-import-first-observe-key/17",
        }
    }

    const fn receipt_domain(self) -> &'static str {
        match self {
            Self::Arm => "source-owned.packet-native-import-arm-receipt-key/17",
            Self::World => "source-owned.packet-native-import-world-receipt-key/17",
            Self::FirstObserve => "source-owned.packet-native-import-first-observe-receipt-key/17",
        }
    }
}
