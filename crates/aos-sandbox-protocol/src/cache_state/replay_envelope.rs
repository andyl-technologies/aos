//! Shares the existing borrowed Cache replay envelope and partition codec.
//!
//! The envelope is historical comparison DATA. Decoding supplies neither
//! protected journal provenance nor a current authority capability. Native
//! callers keep their actual claimed journal and current-record verification.
//!
//! ```text
//! AOSCRM01 | version:u16=1 | reserved:6 | partition:241 | purpose:u8 |
//! scope:128 | floor:152 | key-length:u16 | checkpoint-length:u32 |
//! prior-length:u32 | key | checkpoint | optional prior checkpoint
//! ```

use super::authority_record::{CacheAuthorityPurposeV1, CacheAuthorityScopeV1};
use super::durable_format::{CacheHistoryFloorV1, decode_floor};
use super::{CacheNodeIdV1, PhysicalPartitionId, ProtectedBackingIdentityV1};
use aos_sandbox_core::{
    CacheDomainId, ObjectDigest, OperationId,
    model::{CacheDomain, CacheDomainKind},
};

/// Identifies the complete replay manifest's established fixed header size.
pub const CACHE_MANIFEST_FIXED_BYTES: usize = 555;
/// Identifies the complete replay manifest's established magic.
pub const CACHE_MANIFEST_MAGIC: &[u8; 8] = b"AOSCRM01";
/// Identifies the partition descriptor's established byte width.
pub const PARTITION_DESCRIPTOR_BYTES: usize = 241;
/// Identifies the partition descriptor's established magic.
pub const PARTITION_DESCRIPTOR_MAGIC: &[u8; 8] = b"AOSCPP01";

/// Refuses malformed replay-envelope comparison DATA without native authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
#[error("Cache replay envelope DATA is noncanonical")]
pub struct CacheReplayEnvelopeDataErrorV1;

/// Owns historical replay evidence without a native capability or admission.
///
/// Native validators independently verify these fields against their actual
/// protected journal. This DATA can also describe hostile or stale history.
#[derive(Clone, Eq, PartialEq)]
pub struct CacheReplayPartitionEvidenceDataV1 {
    /// Complete physical partition identity.
    pub partition: PhysicalPartitionId,
    /// Historical authority-record purpose.
    pub purpose: CacheAuthorityPurposeV1,
    /// Exact historical scope expected in the authority record.
    pub scope: CacheAuthorityScopeV1,
    /// Complete authority-record lookup key.
    pub record_key: Vec<u8>,
    /// Complete encoded typed checkpoint.
    pub typed_checkpoint: Vec<u8>,
    /// Complete optional prior checkpoint.
    pub prior_typed_checkpoint: Option<Vec<u8>>,
    /// Exact checkpoint/history retention floor.
    pub floor: CacheHistoryFloorV1,
}

/// Borrows the existing manifest header and its actual encoded checkpoint slices.
pub struct BorrowedCacheReplayManifestDataV1<'bytes> {
    /// Complete independently encoded physical partition.
    pub partition: PhysicalPartitionId,
    /// Historical purpose code; this is not a purpose grant.
    pub purpose: CacheAuthorityPurposeV1,
    /// Complete historical scope; current-record verification remains separate.
    pub scope: CacheAuthorityScopeV1,
    /// Complete retained history floor.
    pub floor: CacheHistoryFloorV1,
    /// Actual borrowed authority-record lookup key.
    pub record_key: &'bytes [u8],
    /// Actual borrowed complete typed checkpoint bytes.
    pub typed_checkpoint: &'bytes [u8],
    /// Actual borrowed prior typed checkpoint, when present.
    pub prior_typed_checkpoint: Option<&'bytes [u8]>,
}

/// Borrows the same complete envelope using its actual configured payload bound.
///
/// This validates only the established envelope, lengths, fields and floor;
/// actual callers still perform the same complete typed-checkpoint decode.
///
/// # Errors
/// Refuses wrong framing, reserved bytes, partition, purpose, scope, floor,
/// key width, checkpoint bounds or aggregate/trailing byte extent.
pub fn borrow_cache_replay_manifest(
    bytes: &[u8],
    maximum_payload_bytes: usize,
) -> Result<BorrowedCacheReplayManifestDataV1<'_>, CacheReplayEnvelopeDataErrorV1> {
    if bytes.len() < CACHE_MANIFEST_FIXED_BYTES
        || &bytes[..8] != CACHE_MANIFEST_MAGIC
        || bytes[8..10] != 1_u16.to_be_bytes()
        || bytes[10..16] != [0; 6]
        || bytes[258..265] != [0; 7]
    {
        return Err(CacheReplayEnvelopeDataErrorV1);
    }
    let partition =
        decode_partition_descriptor(&bytes[16..257]).ok_or(CacheReplayEnvelopeDataErrorV1)?;
    let purpose =
        decode_cache_authority_purpose(bytes[257]).ok_or(CacheReplayEnvelopeDataErrorV1)?;
    let operation_bytes: [u8; 16] = bytes[297..313]
        .try_into()
        .map_err(|_| CacheReplayEnvelopeDataErrorV1)?;
    let operation = (operation_bytes != [0; 16]).then(|| OperationId::from_bytes(operation_bytes));
    let scope = CacheAuthorityScopeV1::new(
        partition,
        ObjectDigest::from_bytes(read_array(bytes, 265)?),
        operation,
        ObjectDigest::from_bytes(read_array(bytes, 313)?),
        ObjectDigest::from_bytes(read_array(bytes, 345)?),
        read_u64(bytes, 377)?,
        read_u64(bytes, 385)?,
    )
    .map_err(|_| CacheReplayEnvelopeDataErrorV1)?;
    let floor = decode_floor(&bytes[393..545]).map_err(|_| CacheReplayEnvelopeDataErrorV1)?;
    let record_key_bytes = usize::from(read_u16(bytes, 545)?);
    let checkpoint_bytes =
        usize::try_from(read_u32(bytes, 547)?).map_err(|_| CacheReplayEnvelopeDataErrorV1)?;
    let prior_bytes =
        usize::try_from(read_u32(bytes, 551)?).map_err(|_| CacheReplayEnvelopeDataErrorV1)?;
    if record_key_bytes == 0
        || record_key_bytes > 1024
        || checkpoint_bytes == 0
        || checkpoint_bytes > maximum_payload_bytes
        || prior_bytes > maximum_payload_bytes
        || CACHE_MANIFEST_FIXED_BYTES
            .checked_add(record_key_bytes)
            .and_then(|length| length.checked_add(checkpoint_bytes))
            .and_then(|length| length.checked_add(prior_bytes))
            != Some(bytes.len())
    {
        return Err(CacheReplayEnvelopeDataErrorV1);
    }
    let record_key_end = CACHE_MANIFEST_FIXED_BYTES + record_key_bytes;
    let checkpoint_end = record_key_end + checkpoint_bytes;
    Ok(BorrowedCacheReplayManifestDataV1 {
        partition,
        purpose,
        scope,
        floor,
        record_key: &bytes[CACHE_MANIFEST_FIXED_BYTES..record_key_end],
        typed_checkpoint: &bytes[record_key_end..checkpoint_end],
        prior_typed_checkpoint: (prior_bytes != 0).then(|| &bytes[checkpoint_end..]),
    })
}

fn decode_cache_authority_purpose(code: u8) -> Option<CacheAuthorityPurposeV1> {
    use CacheAuthorityPurposeV1 as Purpose;
    Some(match code {
        1 => Purpose::Source,
        2 => Purpose::Read,
        3 => Purpose::Admission,
        4 => Purpose::Eviction,
        5 => Purpose::PinDrain,
        6 => Purpose::UnlinkObservation,
        7 => Purpose::Reclamation,
        8 => Purpose::Scrub,
        9 => Purpose::Retry,
        10 => Purpose::Replay,
        11 => Purpose::PinAcquire,
        12 => Purpose::AdmissionCleanup,
        13 => Purpose::PendingCancellation,
        _ => return None,
    })
}

/// Encodes the same complete physical partition as historical DATA.
pub fn encode_partition_descriptor(
    partition: PhysicalPartitionId,
) -> [u8; PARTITION_DESCRIPTOR_BYTES] {
    let mut bytes = [0_u8; PARTITION_DESCRIPTOR_BYTES];
    bytes[..8].copy_from_slice(PARTITION_DESCRIPTOR_MAGIC);
    bytes[8..10].copy_from_slice(&1_u16.to_be_bytes());
    bytes[16..32].copy_from_slice(partition.node().as_bytes());
    let backing = partition.backing();
    bytes[32..64].copy_from_slice(backing.root().as_bytes());
    bytes[64..96].copy_from_slice(backing.dataset().as_bytes());
    bytes[96..128].copy_from_slice(backing.pool().as_bytes());
    bytes[128..160].copy_from_slice(backing.backend().as_bytes());
    bytes[160] = match partition.disclosure().kind() {
        CacheDomainKind::Private => 1,
        CacheDomainKind::Project => 2,
        CacheDomainKind::TrustDomain => 3,
        CacheDomainKind::Public => 4,
    };
    bytes[161..177].copy_from_slice(partition.disclosure().domain_id().as_bytes());
    bytes[177..209].copy_from_slice(partition.isolation_policy().as_bytes());
    bytes[209..].copy_from_slice(partition.digest().as_bytes());
    bytes
}

/// Decodes the same complete partition fields and digest as historical DATA.
pub fn decode_partition_descriptor(bytes: &[u8]) -> Option<PhysicalPartitionId> {
    if bytes.len() != PARTITION_DESCRIPTOR_BYTES
        || &bytes[..8] != PARTITION_DESCRIPTOR_MAGIC
        || bytes[8..10] != 1_u16.to_be_bytes()
        || bytes[10..16] != [0; 6]
    {
        return None;
    }
    let array =
        |start: usize| -> Option<[u8; 32]> { bytes.get(start..start + 32)?.try_into().ok() };
    let node = CacheNodeIdV1::from_bytes(bytes.get(16..32)?.try_into().ok()?).ok()?;
    let backing = ProtectedBackingIdentityV1::new(
        ObjectDigest::from_bytes(array(32)?),
        ObjectDigest::from_bytes(array(64)?),
        ObjectDigest::from_bytes(array(96)?),
        ObjectDigest::from_bytes(array(128)?),
    )
    .ok()?;
    let kind = match bytes[160] {
        1 => CacheDomainKind::Private,
        2 => CacheDomainKind::Project,
        3 => CacheDomainKind::TrustDomain,
        4 => CacheDomainKind::Public,
        _ => return None,
    };
    let disclosure = CacheDomain::new(
        kind,
        CacheDomainId::from_bytes(bytes.get(161..177)?.try_into().ok()?),
    );
    let partition = PhysicalPartitionId::derive(
        node,
        backing,
        disclosure,
        ObjectDigest::from_bytes(array(177)?),
    )
    .ok()?;
    if partition.digest().as_bytes() != bytes.get(209..241)? {
        return None;
    }
    Some(partition)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, CacheReplayEnvelopeDataErrorV1> {
    Ok(u16::from_be_bytes(read_array(bytes, offset)?))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, CacheReplayEnvelopeDataErrorV1> {
    Ok(u32::from_be_bytes(read_array(bytes, offset)?))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, CacheReplayEnvelopeDataErrorV1> {
    Ok(u64::from_be_bytes(read_array(bytes, offset)?))
}

fn read_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], CacheReplayEnvelopeDataErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(CacheReplayEnvelopeDataErrorV1)
}
