//! Encodes canonical monotonic Cache clock-floor comparison DATA.
//!
//! This historical value does not capture a clock, hold a journal, admit a
//! financial purpose or establish currentness. Actual role owners preserve
//! their native floor/clock comparisons and independently owed posts.
//!
//! ```text
//! AOSCCL01 | version:u16=1 | reserved:6 | owner:32 | revision:u64 |
//! observed-unix:u64 | predecessor-unix:u64 | SHA256(domain || preceding)
//! ```

use aos_sandbox_model::ObjectDigest;
use sha2::{Digest as _, Sha256};

/// Identifies the existing fixed clock-floor row key.
pub const CACHE_CLOCK_KEY: &[u8] = b"\0aos-cache-residency-clock-v1\0current";
const CACHE_CLOCK_MAGIC: &[u8; 8] = b"AOSCCL01";
/// Names the complete fixed clock-floor encoding width.
pub const CACHE_CLOCK_BYTES: usize = 104;

/// Refuses malformed canonical floor DATA without a native or clock grant.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Cache clock-floor DATA is invalid")]
pub struct CacheClockFloorDataErrorV1;

/// Carries the existing historical floor fields without live clock authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheClockFloorDataV1 {
    /// Exact fixed Cache owner commitment.
    pub owner_scope: ObjectDigest,
    /// Monotonic nonzero durable revision.
    pub revision: u64,
    /// Observed durable wall-clock floor in Unix seconds.
    pub observed_unix_seconds: u64,
    /// Previous durable floor, or zero only at the first revision.
    pub predecessor_unix_seconds: u64,
}

/// Encodes the existing fixed clock-floor DATA without clock authority.
#[must_use]
pub fn encode_cache_clock_floor(floor: CacheClockFloorDataV1) -> Vec<u8> {
    let mut bytes = vec![0_u8; CACHE_CLOCK_BYTES];
    bytes[..8].copy_from_slice(CACHE_CLOCK_MAGIC);
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    bytes[16..48].copy_from_slice(floor.owner_scope.as_bytes());
    bytes[48..56].copy_from_slice(&floor.revision.to_be_bytes());
    bytes[56..64].copy_from_slice(&floor.observed_unix_seconds.to_be_bytes());
    bytes[64..72].copy_from_slice(&floor.predecessor_unix_seconds.to_be_bytes());
    let digest = Sha256::new()
        .chain_update(b"aos.sandbox.cache-residency.clock-floor.v1\0")
        .chain_update(&bytes[..72])
        .finalize();
    bytes[72..104].copy_from_slice(&digest);
    bytes
}

/// Decodes the exact existing clock-floor framing and monotonic fields.
///
/// # Errors
/// Rejects malformed fixed bytes, checksum, sentinel fields or floor ordering.
pub fn decode_cache_clock_floor(
    bytes: &[u8],
) -> Result<CacheClockFloorDataV1, CacheClockFloorDataErrorV1> {
    if bytes.len() != CACHE_CLOCK_BYTES
        || &bytes[..8] != CACHE_CLOCK_MAGIC
        || bytes[8..10] != 1_u16.to_be_bytes()
        || bytes[10..16] != [0; 6]
        || bytes[72..104]
            != Sha256::new()
                .chain_update(b"aos.sandbox.cache-residency.clock-floor.v1\0")
                .chain_update(&bytes[..72])
                .finalize()[..]
    {
        return Err(CacheClockFloorDataErrorV1);
    }
    let floor = CacheClockFloorDataV1 {
        owner_scope: ObjectDigest::from_bytes(read_array(bytes, 16)?),
        revision: read_u64(bytes, 48)?,
        observed_unix_seconds: read_u64(bytes, 56)?,
        predecessor_unix_seconds: read_u64(bytes, 64)?,
    };
    if floor.owner_scope.as_bytes() == &[0; 32]
        || floor.revision == 0
        || floor.observed_unix_seconds == 0
        || (floor.revision == 1 && floor.predecessor_unix_seconds != 0)
        || (floor.revision > 1
            && (floor.predecessor_unix_seconds == 0
                || floor.predecessor_unix_seconds > floor.observed_unix_seconds))
    {
        return Err(CacheClockFloorDataErrorV1);
    }
    Ok(floor)
}

fn read_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], CacheClockFloorDataErrorV1> {
    let end = offset.checked_add(N).ok_or(CacheClockFloorDataErrorV1)?;
    bytes
        .get(offset..end)
        .ok_or(CacheClockFloorDataErrorV1)?
        .try_into()
        .map_err(|_| CacheClockFloorDataErrorV1)
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, CacheClockFloorDataErrorV1> {
    Ok(u64::from_be_bytes(read_array(bytes, offset)?))
}

/// Derives the existing canonical clock-floor transaction identifier.
///
/// This hash is historical DATA and carries no clock or append authority.
///
/// # Errors
/// Refuses an invalid fixed digest extraction or the reserved zero identity.
pub fn cache_clock_transaction_id_data_v1(
    encoded: &[u8],
) -> Result<[u8; 16], CacheClockFloorDataErrorV1> {
    let digest = Sha256::new()
        .chain_update(b"aos.sandbox.cache-residency.clock-transaction.v1\0")
        .chain_update(encoded)
        .finalize();
    let transaction_id: [u8; 16] = digest[..16]
        .try_into()
        .map_err(|_| CacheClockFloorDataErrorV1)?;
    if transaction_id == [0; 16] {
        return Err(CacheClockFloorDataErrorV1);
    }
    Ok(transaction_id)
}
