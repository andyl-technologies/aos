//! Separate bounded slices of an original phase-aware timer observation.
//!
//! These bodies require a separately pinned native channel edition and frame
//! kind. Their bytes never select an edition, adopt native authority, or ask
//! the source to resample a previously retained observation.
//!
//! ```text
//! query: prepared_scope[32] | original_sequence:u64 | offset:u64
//! chunk: prepared_scope[32] | original_sequence:u64 | object_digest[32]
//!        total_bytes:u64 | offset:u64 | original_bytes[remaining_body_bytes]
//! ```
//!
//! Integers are big endian. The independent phase-aware object allowance does
//! not extend or reinterpret the legacy timer query or chunk allowance.

use crucible_node_contract::U64;

use super::phase_timers::{NATIVE_PHASE_TIMER_OBJECT_MAX_BYTES, NATIVE_PHASE_TIMER_SUMMARY_BYTES};
use super::{NativeCommandError, codec::Cursor};

/// Bounds each portable slice below the independently negotiated frame allowance.
pub const NATIVE_PHASE_TIMER_CHUNK_BYTES: usize = 3_000;

/// Selects bytes of an already retained original phase-aware timer observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativePhaseTimerQuery {
    /// Binds the exact originally prepared native owner scope.
    pub prepared_scope_hash: [u8; 32],
    /// Names the original stopped command, or zero for the initial native park.
    pub sequence: U64,
    /// Locates the requested bytes within the same immutable original object.
    pub offset: U64,
}

impl NativePhaseTimerQuery {
    /// Checks a finite query without authenticating native observation custody.
    ///
    /// # Errors
    /// Rejects an empty scope or an offset outside the separate object allowance.
    pub fn validate(&self) -> Result<(), NativeCommandError> {
        if self.prepared_scope_hash == [0; 32] {
            return Err(NativeCommandError::Conflict);
        }
        if self.offset.get() >= NATIVE_PHASE_TIMER_OBJECT_MAX_BYTES as u64 {
            return Err(NativeCommandError::ResourceLimit);
        }
        Ok(())
    }

    /// Encodes the fixed query body for a separately pinned frame kind.
    ///
    /// # Errors
    /// Rejects any query that fails [`Self::validate`].
    pub fn encode(&self) -> Result<[u8; 48], NativeCommandError> {
        self.validate()?;
        let mut bytes = [0; 48];
        bytes[..32].copy_from_slice(&self.prepared_scope_hash);
        bytes[32..40].copy_from_slice(&self.sequence.get().to_be_bytes());
        bytes[40..48].copy_from_slice(&self.offset.get().to_be_bytes());
        Ok(bytes)
    }

    /// Decodes exactly one query body without negotiating a native edition.
    ///
    /// # Errors
    /// Rejects truncation, trailing bytes, missing scope or excessive offsets.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        if bytes.len() != 48 {
            return Err(NativeCommandError::Invalid(
                "native phase timer query length",
            ));
        }
        let mut cursor = Cursor(bytes);
        let value = Self {
            prepared_scope_hash: cursor.array()?,
            sequence: U64::new(cursor.u64()?),
            offset: U64::new(cursor.u64()?),
        };
        value.validate()?;
        Ok(value)
    }
}

/// Transfers immutable bytes from an original separately typed timer observation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NativePhaseTimerChunk {
    /// Binds the exact originally prepared native owner scope.
    pub prepared_scope_hash: [u8; 32],
    /// Names the original stopped command, or zero for the initial native park.
    pub sequence: U64,
    /// Commits to the complete original canonical observation with BLAKE3-256.
    pub object_digest: [u8; 32],
    /// Bounds the complete immutable original observation length.
    pub total_bytes: U64,
    /// Locates this slice inside the same retained original observation.
    pub offset: U64,
    /// Contains at most 3000 original portable bytes without native pointers.
    pub bytes: Vec<u8>,
}

impl NativePhaseTimerChunk {
    /// Checks finite geometry without authenticating native data or source custody.
    ///
    /// # Errors
    /// Rejects empty commitments or chunks, impossible object extents, excessive
    /// chunk sizes, integer overflow or slices outside the complete object.
    pub fn validate(&self) -> Result<(), NativeCommandError> {
        if self.prepared_scope_hash == [0; 32] || self.object_digest == [0; 32] {
            return Err(NativeCommandError::Conflict);
        }
        if self.total_bytes.get() < NATIVE_PHASE_TIMER_SUMMARY_BYTES as u64
            || self.total_bytes.get() > NATIVE_PHASE_TIMER_OBJECT_MAX_BYTES as u64
            || self.bytes.is_empty()
            || self.bytes.len() > NATIVE_PHASE_TIMER_CHUNK_BYTES
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

    /// Encodes a bounded body under its independently selected native frame kind.
    ///
    /// # Errors
    /// Rejects any chunk that fails [`Self::validate`].
    pub fn encode(&self) -> Result<Vec<u8>, NativeCommandError> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(88 + self.bytes.len());
        bytes.extend_from_slice(&self.prepared_scope_hash);
        bytes.extend_from_slice(&self.sequence.get().to_be_bytes());
        bytes.extend_from_slice(&self.object_digest);
        bytes.extend_from_slice(&self.total_bytes.get().to_be_bytes());
        bytes.extend_from_slice(&self.offset.get().to_be_bytes());
        bytes.extend_from_slice(&self.bytes);
        Ok(bytes)
    }

    /// Decodes a bounded chunk body before allocating its portable payload bytes.
    ///
    /// # Errors
    /// Rejects truncated or excessive bodies and any invalid chunk geometry.
    pub fn decode(bytes: &[u8]) -> Result<Self, NativeCommandError> {
        if bytes.len() <= 88 || bytes.len() > 88 + NATIVE_PHASE_TIMER_CHUNK_BYTES {
            return Err(NativeCommandError::ResourceLimit);
        }
        let mut cursor = Cursor(bytes);
        let prepared_scope_hash = cursor.array()?;
        let sequence = U64::new(cursor.u64()?);
        let object_digest = cursor.array()?;
        let total_bytes = U64::new(cursor.u64()?);
        let offset = U64::new(cursor.u64()?);
        let value = Self {
            prepared_scope_hash,
            sequence,
            object_digest,
            total_bytes,
            offset,
            bytes: cursor.take(cursor.0.len())?.to_vec(),
        };
        value.validate()?;
        Ok(value)
    }
}

#[cfg(test)]
#[path = "phase_timer_frame_tests.rs"]
mod tests;
