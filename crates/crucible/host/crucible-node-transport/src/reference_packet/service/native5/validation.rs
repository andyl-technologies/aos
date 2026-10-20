//! Keeps the independent saved full-launch validator above the shared DATA code.

use super::*;
use crate::reference_packet::{Native5Policy, service};
#[path = "validation/original.rs"]
mod original;

/// Exposes only the saved original validator to crate-local parity controls.
pub(crate) trait PacketNative5LaunchValidationOracle {
    fn validate_original_for_projection_test_data(&self) -> Result<(), ProviderError>;
}

#[cfg(test)]
impl PacketNative5LaunchValidationOracle for PacketNative5SourceLaunch {
    /// Runs the saved original validator only for crate-local parity controls.
    ///
    /// The oracle lives under the same service visibility boundary as the real
    /// validator; no production policy constructor becomes more visible.
    ///
    /// # Errors
    /// Returns the unchanged original full-launch validation refusal.
    fn validate_original_for_projection_test_data(&self) -> Result<(), ProviderError> {
        original::validate(self)
    }
}
