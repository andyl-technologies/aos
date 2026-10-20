//! Shares receiving ceilings as ordinary unauthenticated negotiation data.

use super::bodies::invalid;
use crucible_node_format::*;
use serde::{Deserialize, Serialize};

/// Declares positive receiving ceilings within the baseline hard limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    /// Bounds one UTF-8 JSON frame to at most 16777216 bytes.
    pub frame_bytes: U64,
    /// Bounds JSON container nesting to at most 64.
    pub nesting: U64,
    /// Bounds outstanding IDs in each request direction to at most 256.
    pub requests: U64,
    /// Bounds retained journal entries per request origin to at most 4096.
    pub journal_entries: U64,
    /// Bounds decoded inline chunks to at most 1048576 bytes.
    pub blob_chunk_bytes: U64,
}

impl Validate for Limits {
    fn validate(&self) -> Result<(), ContractError> {
        for (value, maximum) in [
            (self.frame_bytes, 16_777_216),
            (self.nesting, 64),
            (self.requests, 256),
            (self.journal_entries, 4096),
            (self.blob_chunk_bytes, 1_048_576),
        ] {
            if value.get() == 0 || value.get() > maximum {
                return Err(invalid(
                    "limits",
                    "require positive receiving ceilings within baseline hard caps",
                ));
            }
        }
        Ok(())
    }
}

impl Limits {
    /// Selects each smaller advertised positive receiving limit.
    ///
    /// # Errors
    /// Rejects either advertisement if it exceeds baseline bounds.
    pub fn intersection(self, other: Self) -> Result<Self, ContractError> {
        self.validate()?;
        other.validate()?;
        Ok(Self {
            frame_bytes: self.frame_bytes.min(other.frame_bytes),
            nesting: self.nesting.min(other.nesting),
            requests: self.requests.min(other.requests),
            journal_entries: self.journal_entries.min(other.journal_entries),
            blob_chunk_bytes: self.blob_chunk_bytes.min(other.blob_chunk_bytes),
        })
    }
}

/// Names the opt-in wire contract and required transport feature.
pub const EXTENSION_NEGOTIATION_V1: &str = "cnp.extension-negotiation/1";
