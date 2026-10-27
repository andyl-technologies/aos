//! Shares receiving ceilings as ordinary unauthenticated negotiation data.

use super::bodies::invalid;
use crucible_node_format::*;
use serde::Serialize;

crucible_node_format::wire_record! {
    /// Declares positive receiving ceilings within the baseline hard limits.
    #[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
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
}

impl Validate for Limits {
    fn validate(&self) -> Result<(), ContractError> {
        if !self.is_valid_data() {
            return Err(invalid(
                "limits",
                "require positive receiving ceilings within baseline hard caps",
            ));
        }
        Ok(())
    }
}

impl Limits {
    /// Checks the receiving ceilings without constructing an owned diagnostic.
    ///
    /// This is the same predicate used by [`Validate::validate`]. The result is
    /// ordinary negotiation DATA and supplies no storage admission or authority.
    pub fn is_valid_data(&self) -> bool {
        [
            (self.frame_bytes, 16_777_216),
            (self.nesting, 64),
            (self.requests, 256),
            (self.journal_entries, 4096),
            (self.blob_chunk_bytes, 1_048_576),
        ]
        .into_iter()
        .all(|(value, maximum)| value.get() != 0 && value.get() <= maximum)
    }

    /// Names the fixed controls of the allocation-free ceiling predicate.
    pub fn validation_counter_scratch_data() -> usize {
        std::mem::size_of::<&Self>()
            + std::mem::size_of::<[(U64, u64); 5]>()
            + std::mem::size_of::<std::array::IntoIter<(U64, u64), 5>>()
            + std::mem::size_of::<(U64, u64)>()
            + std::mem::size_of::<bool>()
    }

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allocation_free_limits_check_matches_every_validation_boundary() {
        let caps = [16_777_216, 64, 256, 4096, 1_048_576];
        for field in 0..caps.len() {
            for value in [0, 1, caps[field], caps[field] + 1, u64::MAX] {
                let mut values = caps;
                values[field] = value;
                let [
                    frame_bytes,
                    nesting,
                    requests,
                    journal_entries,
                    blob_chunk_bytes,
                ] = values.map(U64::new);
                let limits = Limits {
                    frame_bytes,
                    nesting,
                    requests,
                    journal_entries,
                    blob_chunk_bytes,
                };

                assert_eq!(limits.is_valid_data(), value > 0 && value <= caps[field]);
                assert_eq!(limits.is_valid_data(), limits.validate().is_ok());
            }
        }
    }
}
