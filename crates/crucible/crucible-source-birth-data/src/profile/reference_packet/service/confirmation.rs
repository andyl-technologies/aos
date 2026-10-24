//! Defines the unchanged closed confirmation selector data.

use serde::{Deserialize, Serialize};

/// Names the separately negotiated request/response confirmation feature.
pub const PACKET_NATIVE_AFTER_CONFIRMATION_FEATURE: &str =
    "source-owned.packet-native-after-confirmation/5";

/// Names the envelope extension carrying the source-selected confirmation.
pub const PACKET_NATIVE_AFTER_CONFIRMATION_EXTENSION: &str =
    PACKET_NATIVE_AFTER_CONFIRMATION_FEATURE;

/// Selects the separately installed native-after confirmation dialect.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PacketNative5ConfirmationSelection {
    /// Confirms retained native-after bytes with a correlated original Poll.
    AfterProtocolPoll5,
}

mod contract;
pub use contract::{
    NativeAfterConfirmationContractValue, native_after_confirmation_contract,
    native_after_confirmation_schema,
};
