//! Owns canonical Cache authority-record scope and fixed bytes as passive DATA.
//!
//! Native currentness, journal snapshots, verified capabilities and effect
//! admission remain with the actual role owner. This module cannot mint them.
//!
//! ```text
//! AOSCAR01 | version:u16=1 | purpose:u8 | reserved:5 | owner-scope:32 |
//! partition:32 | subject:32 | operation:16 | plan:32 | root-custody:32 |
//! generation:u64be | valid-until:u64be
//! ```

use super::PhysicalPartitionId;
use aos_sandbox_model::{ObjectDigest, OperationId};
use sha2::{Digest as _, Sha256};

/// Identifies the exact canonical Cache authority-record width.
pub const CACHE_AUTHORITY_RECORD_BYTES_V1: usize = 208;
const MAGIC: &[u8; 8] = b"AOSCAR01";
const DOMAIN: &[u8] = b"aos.sandbox.cache.authority-record.v1\0";

/// Rejects malformed nonauthorizing Cache scope or record DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CacheAuthorityRecordDataErrorV1 {
    /// A scope contains a sentinel identity, generation or lifetime.
    #[error("cache authority scope is invalid")]
    InvalidScope,
    /// The fixed record's header, role, owner or canonical scope differs.
    #[error("cache authority record is invalid")]
    InvalidRecord,
}

/// Identifies one closed Cache record purpose as comparison DATA.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum CacheAuthorityPurposeV1 {
    /// Current immutable-source authorization.
    Source = 1,
    /// Current lookup/read disclosure authorization.
    Read = 2,
    /// Current admission authority.
    Admission = 3,
    /// Current eviction authority.
    Eviction = 4,
    /// Trusted pin-drain observation.
    PinDrain = 5,
    /// Trusted unlink observation.
    UnlinkObservation = 6,
    /// Trusted physical reclamation observation.
    Reclamation = 7,
    /// Trusted scrub observation.
    Scrub = 8,
    /// Fresh retry authority after an old executor is fenced.
    Retry = 9,
    /// Current authority permitting historical result disclosure.
    Replay = 10,
    /// Current authority permitting one exact pin acquisition.
    PinAcquire = 11,
    /// Current authority permitting expired-admission cleanup or recovery.
    AdmissionCleanup = 12,
    /// Current authority permitting observed no-effect cancellation.
    PendingCancellation = 13,
}

/// Describes the exact semantic scope encoded by a Cache record.
///
/// Constructing this DATA proves no live capability or protected authority.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheAuthorityScopeV1 {
    partition: ObjectDigest,
    subject: ObjectDigest,
    operation: [u8; 16],
    plan: ObjectDigest,
    root_custody: ObjectDigest,
    generation: u64,
    valid_until: u64,
}

impl CacheAuthorityScopeV1 {
    /// Constructs complete scope DATA without a native authority or capability.
    ///
    /// # Errors
    ///
    /// Returns [`CacheAuthorityRecordDataErrorV1::InvalidScope`] for sentinel fields.
    pub fn new(
        partition: PhysicalPartitionId,
        subject: ObjectDigest,
        operation: Option<OperationId>,
        plan: ObjectDigest,
        root_custody: ObjectDigest,
        generation: u64,
        valid_until: u64,
    ) -> Result<Self, CacheAuthorityRecordDataErrorV1> {
        if subject.as_bytes() == &[0; 32]
            || plan.as_bytes() == &[0; 32]
            || root_custody.as_bytes() == &[0; 32]
            || generation == 0
            || valid_until == 0
        {
            return Err(CacheAuthorityRecordDataErrorV1::InvalidScope);
        }
        Ok(Self {
            partition: partition.digest(),
            subject,
            operation: operation.map_or([0; 16], |value| value.into_bytes()),
            plan,
            root_custody,
            generation,
            valid_until,
        })
    }

    /// Returns the physical partition commitment.
    #[must_use]
    pub const fn partition(&self) -> ObjectDigest {
        self.partition
    }

    /// Returns the exact subject commitment.
    #[must_use]
    pub const fn subject(&self) -> ObjectDigest {
        self.subject
    }

    /// Returns the operation bytes, or zero for operation-independent authority.
    #[must_use]
    pub const fn operation(&self) -> [u8; 16] {
        self.operation
    }

    /// Returns the exact plan commitment.
    #[must_use]
    pub const fn plan(&self) -> ObjectDigest {
        self.plan
    }

    /// Returns the protected root custody commitment.
    #[must_use]
    pub const fn root_custody(&self) -> ObjectDigest {
        self.root_custody
    }

    /// Returns the current protected generation.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Returns the capability deadline.
    #[must_use]
    pub const fn valid_until(&self) -> u64 {
        self.valid_until
    }
}

/// Decodes the one exact scope recorded for a supplied owner and purpose.
///
/// A decoded scope is historical comparison DATA, never a live capability.
///
/// # Errors
/// Rejects a nonexact extent, altered header/owner/purpose or sentinel scope.
pub fn decode_cache_authority_record_v1(
    record: &[u8],
    owner_scope: ObjectDigest,
    purpose: CacheAuthorityPurposeV1,
) -> Result<CacheAuthorityScopeV1, CacheAuthorityRecordDataErrorV1> {
    if record.len() != CACHE_AUTHORITY_RECORD_BYTES_V1
        || &record[..8] != MAGIC
        || record[8..10] != 1_u16.to_be_bytes()
        || record[10] != purpose as u8
        || record[11..16] != [0; 5]
        || record[16..48] != *owner_scope.as_bytes()
    {
        return Err(CacheAuthorityRecordDataErrorV1::InvalidRecord);
    }
    let scope = CacheAuthorityScopeV1 {
        partition: ObjectDigest::from_bytes(read_array(record, 48)?),
        subject: ObjectDigest::from_bytes(read_array(record, 80)?),
        operation: read_array(record, 112)?,
        plan: ObjectDigest::from_bytes(read_array(record, 128)?),
        root_custody: ObjectDigest::from_bytes(read_array(record, 160)?),
        generation: u64::from_be_bytes(read_array(record, 192)?),
        valid_until: u64::from_be_bytes(read_array(record, 200)?),
    };
    if scope.partition.as_bytes() == &[0; 32]
        || scope.subject.as_bytes() == &[0; 32]
        || scope.plan.as_bytes() == &[0; 32]
        || scope.root_custody.as_bytes() == &[0; 32]
        || scope.generation == 0
        || scope.valid_until == 0
        || record != encode_cache_authority_record_v1(owner_scope, purpose, scope).as_slice()
    {
        return Err(CacheAuthorityRecordDataErrorV1::InvalidRecord);
    }
    Ok(scope)
}

/// Encodes the sole fixed record for supplied scope DATA without authorizing it.
#[must_use]
pub fn encode_cache_authority_record_v1(
    owner_scope: ObjectDigest,
    purpose: CacheAuthorityPurposeV1,
    scope: CacheAuthorityScopeV1,
) -> [u8; CACHE_AUTHORITY_RECORD_BYTES_V1] {
    let mut record = [0_u8; CACHE_AUTHORITY_RECORD_BYTES_V1];
    record[0..8].copy_from_slice(MAGIC);
    record[8..10].copy_from_slice(&1_u16.to_be_bytes());
    record[10] = purpose as u8;
    record[16..48].copy_from_slice(owner_scope.as_bytes());
    record[48..80].copy_from_slice(scope.partition().as_bytes());
    record[80..112].copy_from_slice(scope.subject().as_bytes());
    record[112..128].copy_from_slice(&scope.operation());
    record[128..160].copy_from_slice(scope.plan().as_bytes());
    record[160..192].copy_from_slice(scope.root_custody().as_bytes());
    record[192..200].copy_from_slice(&scope.generation().to_be_bytes());
    record[200..208].copy_from_slice(&scope.valid_until().to_be_bytes());
    record
}

/// Commits supplied record-key and record bytes without authenticating storage.
///
/// Native consumers validate their original key and record bounds before this
/// exact existing digest recipe. Hashing DATA supplies no snapshot or approval.
#[must_use]
pub fn cache_authority_record_digest_v1(record_key: &[u8], record: &[u8]) -> ObjectDigest {
    let mut hasher = Sha256::new();
    hasher.update(DOMAIN);
    hasher.update((record_key.len() as u16).to_be_bytes());
    hasher.update(record_key);
    hasher.update((record.len() as u32).to_be_bytes());
    hasher.update(record);
    ObjectDigest::from_bytes(hasher.finalize().into())
}

fn read_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], CacheAuthorityRecordDataErrorV1> {
    bytes
        .get(offset..offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(CacheAuthorityRecordDataErrorV1::InvalidRecord)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> CacheAuthorityScopeV1 {
        CacheAuthorityScopeV1 {
            partition: ObjectDigest::from_bytes([1; 32]),
            subject: ObjectDigest::from_bytes([2; 32]),
            operation: [3; 16],
            plan: ObjectDigest::from_bytes([4; 32]),
            root_custody: ObjectDigest::from_bytes([5; 32]),
            generation: 6,
            valid_until: 7,
        }
    }

    #[test]
    fn fixed_record_preserves_native_bytes_and_refuses_wrong_owner_purpose_or_zero_scope() {
        let owner = ObjectDigest::from_bytes([8; 32]);
        let purpose = CacheAuthorityPurposeV1::Replay;
        let encoded = encode_cache_authority_record_v1(owner, purpose, scope());

        assert_eq!(encoded.len(), 208);
        assert_eq!(&encoded[..16], b"AOSCAR01\0\x01\x0a\0\0\0\0\0");
        assert_eq!(
            decode_cache_authority_record_v1(&encoded, owner, purpose).unwrap(),
            scope()
        );
        assert_eq!(
            cache_authority_record_digest_v1(b"scope-key", &encoded).as_bytes(),
            &[
                144, 112, 133, 141, 18, 65, 32, 252, 253, 253, 172, 146, 177, 234, 160, 12, 210,
                113, 41, 6, 112, 202, 61, 42, 25, 150, 161, 162, 11, 124, 20, 79
            ]
        );
        assert!(decode_cache_authority_record_v1(&encoded[..207], owner, purpose).is_err());
        assert!(
            decode_cache_authority_record_v1(&encoded, ObjectDigest::from_bytes([9; 32]), purpose)
                .is_err()
        );
        assert!(
            decode_cache_authority_record_v1(&encoded, owner, CacheAuthorityPurposeV1::Read)
                .is_err()
        );
        for (offset, width) in [(48, 32), (80, 32), (128, 32), (160, 32), (192, 8), (200, 8)] {
            let mut changed = encoded;
            changed[offset..offset + width].fill(0);
            assert_eq!(
                decode_cache_authority_record_v1(&changed, owner, purpose),
                Err(CacheAuthorityRecordDataErrorV1::InvalidRecord)
            );
        }
        let mut changed = encoded;
        changed[11] = 1;
        assert!(decode_cache_authority_record_v1(&changed, owner, purpose).is_err());
    }
}
