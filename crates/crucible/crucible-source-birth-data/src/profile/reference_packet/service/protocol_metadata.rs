//! Selects finite metadata row counts independently of actual native banks.

use crate::errors::ProviderError;
use crucible_node_format::U64;
use serde::{Deserialize, Serialize};

/// Selects native before/after record and alias row banks independently of bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PacketNative5ProtocolMetadataLimits {
    /// Bounds each native-before metadata and alias bank's row population.
    pub native_before_rows: U64,
    /// Bounds each native-after metadata and alias bank's row population.
    pub native_after_rows: U64,
}

impl PacketNative5ProtocolMetadataLimits {
    /// Checks each selected bank against the metadata walker's enforced ceiling.
    ///
    /// # Errors
    /// Refuses zero or more than131072 rows in either independent native cut.
    pub fn validate_data(&self) -> Result<(), ProviderError> {
        if [self.native_before_rows, self.native_after_rows]
            .iter()
            .any(|rows| rows.get() == 0 || rows.get() > 131_072)
        {
            return Err(ProviderError::ResourceExhausted(
                "native metadata selected row bounds",
            ));
        }
        Ok(())
    }
}
