//! Edition-two slices of retained original held-writer observations.

use crucible_node_contract::U64;

use super::{NATIVE_WRITER_OBJECT_MAX_BYTES, NativeCommandError};

/// Bounds each independently retrievable original observation slice.
pub const NATIVE_WRITER_CHUNK_BYTES: usize = 3000;

/// Selects one retained original cut without requesting native resampling.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeWriterQuery {
    /// Binds the exact supervised process scope.
    pub prepared_scope_hash: [u8; 32],
    /// Selects the original stop, or zero for the initial physical park.
    pub sequence: U64,
    /// Selects the next original byte offset.
    pub offset: U64,
}

impl NativeWriterQuery {
    /// Checks the finite local query shape without proving native custody.
    ///
    /// # Errors
    /// Rejects empty scope commitments and offsets outside the object allowance.
    pub fn validate(&self) -> Result<(), NativeCommandError> {
        if self.prepared_scope_hash == [0; 32] {
            return Err(NativeCommandError::Invalid("empty writer scope"));
        }
        if self.offset.get() >= NATIVE_WRITER_OBJECT_MAX_BYTES as u64 {
            return Err(NativeCommandError::ResourceLimit);
        }
        Ok(())
    }
}

/// Copies bounded bytes from one immutable original writer observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativeWriterChunk {
    /// Binds the exact original supervised process scope.
    pub prepared_scope_hash: [u8; 32],
    /// Selects the original stop or initial physical park.
    pub sequence: U64,
    /// Commits to every byte of the original complete object with BLAKE3.
    pub object_digest: [u8; 32],
    /// Bounds the complete original encoded object.
    pub total_bytes: U64,
    /// Locates these original bytes within that object.
    pub offset: U64,
    /// Preserves original bytes without native pointers or padding.
    pub bytes: Vec<u8>,
}

impl NativeWriterChunk {
    /// Checks finite offsets and slice sizes without authenticating an observation.
    ///
    /// # Errors
    /// Rejects empty commitments, exhausted allowances and overflowing ranges.
    pub fn validate(&self) -> Result<(), NativeCommandError> {
        if self.prepared_scope_hash == [0; 32] || self.object_digest == [0; 32] {
            return Err(NativeCommandError::Invalid("empty writer commitment"));
        }
        if self.total_bytes.get() == 0
            || self.total_bytes.get() > NATIVE_WRITER_OBJECT_MAX_BYTES as u64
            || self.bytes.is_empty()
            || self.bytes.len() > NATIVE_WRITER_CHUNK_BYTES
            || self
                .offset
                .get()
                .checked_add(self.bytes.len() as u64)
                .is_none_or(|end| end > self.total_bytes.get())
        {
            return Err(NativeCommandError::ResourceLimit);
        }
        Ok(())
    }
}
