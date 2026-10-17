//! Bounded edition-four recovery of an original preparation-successor object.
//!
//! ```text
//! query80 = scope[32], initialization_sequence:u64be, original_cut[32], offset:u64be
//! chunk = facts248, offset:u64be, original_bytes[1..3000]
//! ```
//!
//! Queries recover a cached object. They never select a new source cut, grant
//! initialization or acknowledge an operation. Every slice carries its complete
//! immutable historical facts so a different object cannot replace a prefix.

use super::preparation_successor::{
    NATIVE_PREPARATION_SUCCESSOR_MAX_BYTES, NativePreparationSuccessorFacts,
};
use super::{NativeCommandError, codec::Cursor};
use crucible_node_contract::U64;

/// Bounds one original canonical preparation-successor byte slice.
pub const NATIVE_PREPARATION_SUCCESSOR_CHUNK_BYTES: usize = 3000;

/// Requests an exact original post-initialization object slice.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativePreparationSuccessorQuery {
    /// Binds the complete originally prepared inactive scope.
    pub prepared_scope_hash: [u8; 32],
    /// Identifies the original initialization command rather than execution.
    pub initialization_sequence: U64,
    /// Binds the original source-selected initialization callback cut.
    pub original_cut_digest: [u8; 32],
    /// Selects a checked offset in the same retained immutable object.
    pub offset: U64,
}

#[cfg(test)]
#[path = "preparation_successor_frame_tests.rs"]
mod tests;

impl NativePreparationSuccessorQuery {
    /// Validates a finite correlation request without granting source custody.
    ///
    /// # Errors
    /// Rejects missing original identities or an offset beyond the object cap.
    pub fn validate(&self) -> Result<(), NativeCommandError> {
        if self.prepared_scope_hash == [0; 32]
            || self.original_cut_digest == [0; 32]
            || self.initialization_sequence.get() == 0
            || self.offset.get() >= NATIVE_PREPARATION_SUCCESSOR_MAX_BYTES as u64
        {
            return Err(NativeCommandError::Invalid("preparation successor query"));
        }
        Ok(())
    }

    /// Encodes the fixed request without changing earlier query bodies.
    ///
    /// # Errors
    /// Rejects any invalid correlation request.
    pub fn encode(&self) -> Result<[u8; 80], NativeCommandError> {
        self.validate()?;
        let mut bytes = [0; 80];
        bytes[..32].copy_from_slice(&self.prepared_scope_hash);
        bytes[32..40].copy_from_slice(&self.initialization_sequence.get().to_be_bytes());
        bytes[40..72].copy_from_slice(&self.original_cut_digest);
        bytes[72..].copy_from_slice(&self.offset.get().to_be_bytes());
        Ok(bytes)
    }

    /// Decodes exactly one bounded original request.
    ///
    /// # Errors
    /// Rejects truncation, trailing bytes or invalid identities and offsets.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        if bytes.len() != 80 {
            return Err(NativeCommandError::Invalid("successor query extent"));
        }
        let mut cursor = Cursor(bytes);
        let value = Self {
            prepared_scope_hash: cursor.array()?,
            initialization_sequence: U64::new(cursor.u64()?),
            original_cut_digest: cursor.array()?,
            offset: U64::new(cursor.u64()?),
        };
        value.validate()?;
        Ok(value)
    }
}

/// Retains one checked byte slice with its complete immutable historical identity.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativePreparationSuccessorChunk {
    /// Preserves source-selected fixed historical facts, without ACK or Ready.
    pub facts: NativePreparationSuccessorFacts,
    /// Records the exact original checked offset.
    pub offset: U64,
    /// Preserves the original byte slice without re-encoding native inventories.
    pub bytes: Vec<u8>,
}

impl NativePreparationSuccessorChunk {
    /// Checks the finite slice against its immutable source object's extent.
    ///
    /// # Errors
    /// Rejects invalid facts, empty/oversized slices, overflow and out-of-range offsets.
    pub fn validate(&self) -> Result<(), NativeCommandError> {
        self.facts.validate()?;
        let end = self
            .offset
            .get()
            .checked_add(self.bytes.len() as u64)
            .ok_or(NativeCommandError::ResourceLimit)?;
        if self.bytes.is_empty()
            || self.bytes.len() > NATIVE_PREPARATION_SUCCESSOR_CHUNK_BYTES
            || end > self.facts.content_length.get()
        {
            return Err(NativeCommandError::Invalid(
                "preparation successor slice extent",
            ));
        }
        Ok(())
    }

    /// Encodes a bounded original slice without native layout or pointer fields.
    ///
    /// # Errors
    /// Rejects any invalid facts or checked slice extent.
    pub fn encode(&self) -> Result<Vec<u8>, NativeCommandError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(256 + self.bytes.len());
        bytes.extend_from_slice(&self.facts.encode()?);
        bytes.extend_from_slice(&self.offset.get().to_be_bytes());
        bytes.extend_from_slice(&self.bytes);
        Ok(bytes)
    }

    /// Decodes a bounded slice before copying its original bytes.
    ///
    /// # Errors
    /// Rejects short/oversized packets, invalid historical facts and slice bounds.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        if bytes.len() <= 256 || bytes.len() > 256 + NATIVE_PREPARATION_SUCCESSOR_CHUNK_BYTES {
            return Err(NativeCommandError::Invalid(
                "preparation successor slice length",
            ));
        }
        let mut cursor = Cursor(bytes);
        let value = Self {
            facts: NativePreparationSuccessorFacts::decode(cursor.take(248)?)?,
            offset: U64::new(cursor.u64()?),
            bytes: cursor.0.to_vec(),
        };
        value.validate()?;
        Ok(value)
    }
}
