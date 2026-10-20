//! Canonical historical pin-compaction floor DATA codec.
//!
//! Decoding establishes historical framing and commitments only. Native
//! compaction still requires the live capability and retained physical proof.
//!
//! ```text
//! AOSPFL01 | v1 | pin | partition | checkpoint | generation | digest
//! ```

use aos_sandbox_core::{ObjectDigest, bounded_codec::checked_byte_region};
use super::{PhysicalPartitionId, pin_data::{CachePinId, PinDataErrorV1}};

/// Encoded historical pin-floor width in bytes.
pub const PIN_FLOOR_BYTES: usize = 136;

/// Fences a protected compacted pin-tombstone prefix against identity reuse.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PinCompactionFloorDataV1 {
    /// Greatest historical compacted pin identity.
    pub pin: CachePinId,
    /// Historical physical partition digest.
    pub partition: ObjectDigest,
    /// Historical checkpoint commitment.
    pub checkpoint: ObjectDigest,
    /// Historical floor generation.
    pub generation: u64,
    /// Canonical historical floor digest.
    pub digest: ObjectDigest,
}

impl PinCompactionFloorDataV1 {
    /// Returns the greatest compacted pin identity.
    #[must_use]
    pub const fn pin(self) -> CachePinId {
        self.pin
    }

    /// Returns the protected checkpoint anchoring compaction.
    #[must_use]
    pub const fn checkpoint(self) -> ObjectDigest {
        self.checkpoint
    }
}

/// Encodes a protected pin-compaction floor into its canonical fixed format.
///
/// # Errors
///
/// Returns [`PinDataErrorV1::InvalidFloor`] for an inconsistent recovered floor.
pub fn encode_pin_compaction_floor(
    floor: PinCompactionFloorDataV1,
) -> Result<[u8; PIN_FLOOR_BYTES], PinDataErrorV1> {
    if floor.digest
        != pin_compaction_floor_digest(
            floor.pin,
            floor.partition,
            floor.checkpoint,
            floor.generation,
        )
    {
        return Err(PinDataErrorV1::InvalidFloor);
    }
    let mut bytes = [0_u8; PIN_FLOOR_BYTES];
    bytes[0..8].copy_from_slice(b"AOSPFL01");
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    bytes[16..32].copy_from_slice(floor.pin.as_bytes());
    bytes[32..64].copy_from_slice(floor.partition.as_bytes());
    bytes[64..96].copy_from_slice(floor.checkpoint.as_bytes());
    bytes[96..104].copy_from_slice(&floor.generation.to_be_bytes());
    bytes[104..136].copy_from_slice(floor.digest.as_bytes());
    Ok(bytes)
}

/// Decodes an exact historical floor without checking current authority.
///
/// # Errors
///
/// Returns [`PinDataErrorV1`] for malformed fields, partition or digest.
#[doc(hidden)]
pub fn decode_pin_compaction_floor_persisted(
    partition: PhysicalPartitionId,
    bytes: &[u8],
) -> Result<PinCompactionFloorDataV1, PinDataErrorV1> {
    if bytes.len() != PIN_FLOOR_BYTES
        || &bytes[0..8] != b"AOSPFL01"
        || bytes[8..10] != 1_u16.to_be_bytes()
        || bytes[10..16] != [0; 6]
    {
        return Err(PinDataErrorV1::InvalidFloor);
    }
    let pin = CachePinId::from_bytes(read_pin_array(bytes, 16)?)?;
    let floor = PinCompactionFloorDataV1 {
        pin,
        partition: ObjectDigest::from_bytes(read_pin_array(bytes, 32)?),
        checkpoint: ObjectDigest::from_bytes(read_pin_array(bytes, 64)?),
        generation: u64::from_be_bytes(read_pin_array(bytes, 96)?),
        digest: ObjectDigest::from_bytes(read_pin_array(bytes, 104)?),
    };
    if floor.partition != partition.digest()
        || floor.checkpoint.as_bytes() == &[0; 32]
        || floor.digest
            != pin_compaction_floor_digest(
                floor.pin,
                floor.partition,
                floor.checkpoint,
                floor.generation,
            )
    {
        return Err(PinDataErrorV1::InvalidFloor);
    }
    Ok(floor)
}

/// Commits the exact historical floor fields.
#[doc(hidden)]
pub fn pin_compaction_floor_digest(
    pin: CachePinId,
    partition: ObjectDigest,
    checkpoint: ObjectDigest,
    generation: u64,
) -> ObjectDigest {
    let mut hasher = sha2::Sha256::new();
    use sha2::Digest as _;
    hasher.update(b"aos.sandbox.cache.pin-compaction-floor.v1\0");
    hasher.update(pin.as_bytes());
    hasher.update(partition.as_bytes());
    hasher.update(checkpoint.as_bytes());
    hasher.update(generation.to_be_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn read_pin_array<const N: usize>(bytes: &[u8], offset: usize) -> Result<[u8; N], PinDataErrorV1> {
    let (value, _) = checked_byte_region(bytes, offset, N).map_err(|_| PinDataErrorV1::InvalidFloor)?;
    value.try_into().map_err(|_| PinDataErrorV1::InvalidFloor)
}
