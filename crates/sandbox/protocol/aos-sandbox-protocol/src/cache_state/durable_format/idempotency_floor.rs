//! Historical Cache idempotency-floor DATA codec.
//!
//! The committed key prefix prevents historical reuse when consumed by a
//! separately authenticated coordinator. This parser supplies no current
//! capability or permission to compact a protected journal.
//!
//! ```text
//! AOSIFL01 | v1 | principal/method/key | partition | checkpoint | generation | digest
//! ```

use aos_sandbox_model::ObjectDigest;
use sha2::{Digest as _, Sha256};

use crate::cache_state::PhysicalPartitionId;
use super::{CacheFormatError, CacheMethodV1, VERSION, read_array, read_u16, read_u64};

/// Encoded idempotency compaction-floor width in bytes.
pub const IDEMPOTENCY_FLOOR_BYTES: usize = 168;

/// Fences a compacted terminal idempotency-key prefix against future reuse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheIdempotencyCompactionFloorV1 {
    scope: ([u8; 16], u16, [u8; 16]),
    partition: ObjectDigest,
    checkpoint: ObjectDigest,
    generation: u64,
    digest: ObjectDigest,
}

impl CacheIdempotencyCompactionFloorV1 {
    /// Builds a historical floor from the already selected DATA fields.
    ///
    /// This commitment grants no compaction or current authority. The Native
    /// coordinator independently validates its live capability before calling.
    #[doc(hidden)]
    pub fn from_data_v1(
        scope: ([u8; 16], u16, [u8; 16]),
        partition: ObjectDigest,
        checkpoint: ObjectDigest,
        generation: u64,
    ) -> Self {
        let floor = Self {
            scope,
            partition,
            checkpoint,
            generation,
            digest: ObjectDigest::from_bytes([0; 32]),
        };
        Self {
            digest: idempotency_floor_digest(&floor),
            ..floor
        }
    }

    /// Returns the historical floor generation.
    #[doc(hidden)]
    pub const fn generation_data_v1(self) -> u64 {
        self.generation
    }

    /// Returns the protected checkpoint anchoring the compacted prefix.
    #[must_use]
    pub const fn checkpoint(self) -> ObjectDigest {
        self.checkpoint
    }

    /// Returns the historical principal/method/key floor.
    #[doc(hidden)]
    pub const fn scope(self) -> ([u8; 16], u16, [u8; 16]) {
        self.scope
    }
}

/// Encodes an idempotency compaction floor into its canonical fixed format.
///
/// # Errors
///
/// Returns [`CacheFormatError::InvalidFloor`] for an inconsistent floor.
pub fn encode_idempotency_floor(
    floor: CacheIdempotencyCompactionFloorV1,
) -> Result<[u8; IDEMPOTENCY_FLOOR_BYTES], CacheFormatError> {
    if floor.digest != idempotency_floor_digest(&floor) {
        return Err(CacheFormatError::InvalidFloor);
    }
    let mut bytes = [0_u8; IDEMPOTENCY_FLOOR_BYTES];
    bytes[0..8].copy_from_slice(b"AOSIFL01");
    bytes[8..10].copy_from_slice(&VERSION.to_be_bytes());
    bytes[16..32].copy_from_slice(&floor.scope.0);
    bytes[32..34].copy_from_slice(&floor.scope.1.to_be_bytes());
    bytes[48..64].copy_from_slice(&floor.scope.2);
    bytes[64..96].copy_from_slice(floor.partition.as_bytes());
    bytes[96..128].copy_from_slice(floor.checkpoint.as_bytes());
    bytes[128..136].copy_from_slice(&floor.generation.to_be_bytes());
    bytes[136..168].copy_from_slice(floor.digest.as_bytes());
    Ok(bytes)
}

/// Decodes a historical floor without establishing current authority.
///
/// # Errors
///
/// Returns [`CacheFormatError::InvalidFloor`] for malformed framing, a different
/// partition or invalid historical fields and commitment.
#[doc(hidden)]
pub fn decode_idempotency_floor_persisted(
    partition: PhysicalPartitionId,
    bytes: &[u8],
) -> Result<CacheIdempotencyCompactionFloorV1, CacheFormatError> {
    if bytes.len() != IDEMPOTENCY_FLOOR_BYTES
        || &bytes[0..8] != b"AOSIFL01"
        || read_u16(bytes, 8)? != VERSION
        || bytes[10..16] != [0; 6]
        || bytes[34..48] != [0; 14]
    {
        return Err(CacheFormatError::InvalidFloor);
    }
    let floor = CacheIdempotencyCompactionFloorV1 {
        scope: (
            read_array(bytes, 16)?,
            CacheMethodV1::from_code(read_u16(bytes, 32)?)? as u16,
            read_array(bytes, 48)?,
        ),
        partition: ObjectDigest::from_bytes(read_array(bytes, 64)?),
        checkpoint: ObjectDigest::from_bytes(read_array(bytes, 96)?),
        generation: read_u64(bytes, 128)?,
        digest: ObjectDigest::from_bytes(read_array(bytes, 136)?),
    };
    if floor.scope.0 == [0; 16]
        || floor.scope.2 == [0; 16]
        || floor.partition != partition.digest()
        || floor.checkpoint.as_bytes() == &[0; 32]
        || floor.digest != idempotency_floor_digest(&floor)
    {
        return Err(CacheFormatError::InvalidFloor);
    }
    Ok(floor)
}

fn idempotency_floor_digest(floor: &CacheIdempotencyCompactionFloorV1) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(b"aos.sandbox.cache.idempotency-compaction-floor.v1\0");
    hasher.update(floor.scope.0);
    hasher.update(floor.scope.1.to_be_bytes());
    hasher.update(floor.scope.2);
    hasher.update(floor.partition.as_bytes());
    hasher.update(floor.checkpoint.as_bytes());
    hasher.update(floor.generation.to_be_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}
