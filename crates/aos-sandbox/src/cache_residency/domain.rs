//! Protected current authority for Cache decisions and lookup identities.
//!
//! Physical partition and isolation-policy DATA live in
//! `aos_sandbox_protocol::cache_state::partition`. This module retains the
//! original protected journal verifier and opaque capabilities. Lookup keys
//! additionally commit to current read authority so positive, negative, and
//! coalesced observations cannot become a cross-principal presence oracle.

use aos_sandbox_core::model::{CacheDomain, CacheDomainKind};
use aos_sandbox_core::{ObjectDescriptor, ObjectDigest, OperationId, PrincipalId};
use sha2::{Digest as _, Sha256};

use aos_sandbox_protocol::cache_state::{
    CacheDomainError, PhysicalPartitionId, cache_domain_code, object_descriptor_commitment,
    validate_object_descriptor,
};

use crate::journal::{JournalError, ProtectedJournalAuthority, ProtectedJournalSnapshot};

const LOOKUP_DOMAIN: &[u8] = b"aos.sandbox.cache.authorized-lookup.v1\0";
const AUTHORITY_RECORD_DOMAIN: &[u8] = b"aos.sandbox.cache.authority-record.v1\0";
const AUTHORITY_RECORD_MAGIC: &[u8; 8] = b"AOSCAR01";
const AUTHORITY_RECORD_BYTES: usize = 208;

/// Selects the closed protected capability purpose.
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

/// Defines the exact semantic scope of one protected capability.
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
    /// Constructs a complete scope for one protected decision or observation.
    ///
    /// # Errors
    ///
    /// Returns [`CacheAuthorityError::InvalidScope`] for sentinel fields.
    pub(crate) fn new(
        partition: PhysicalPartitionId,
        subject: ObjectDigest,
        operation: Option<OperationId>,
        plan: ObjectDigest,
        root_custody: ObjectDigest,
        generation: u64,
        valid_until: u64,
    ) -> Result<Self, CacheAuthorityError> {
        if subject.as_bytes() == &[0; 32]
            || plan.as_bytes() == &[0; 32]
            || root_custody.as_bytes() == &[0; 32]
            || generation == 0
            || valid_until == 0
        {
            return Err(CacheAuthorityError::InvalidScope);
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

/// Owns verification against one live protected journal authority.
pub struct CacheAuthorityOwner<'authority, 'journal> {
    authority: &'authority ProtectedJournalAuthority<'journal>,
    owner_scope: ObjectDigest,
    maximum_record_bytes: usize,
}

/// Proves one exact record remains current in a protected journal snapshot.
pub struct VerifiedCacheCapabilityV1 {
    snapshot: ProtectedJournalSnapshot,
    owner_scope: ObjectDigest,
    purpose: CacheAuthorityPurposeV1,
    scope: CacheAuthorityScopeV1,
    record_digest: ObjectDigest,
}

impl<'authority, 'journal> CacheAuthorityOwner<'authority, 'journal> {
    /// Binds a verifier to one already-claimed protected journal namespace.
    ///
    /// # Errors
    ///
    /// Returns [`CacheAuthorityError`] for sentinel scope, invalid bounds, or
    /// unavailable protected authority.
    pub(crate) fn new(
        authority: &'authority ProtectedJournalAuthority<'journal>,
        owner_scope: ObjectDigest,
        maximum_record_bytes: usize,
    ) -> Result<Self, CacheAuthorityError> {
        if owner_scope.as_bytes() == &[0; 32]
            || maximum_record_bytes < AUTHORITY_RECORD_BYTES
            || maximum_record_bytes > 1024 * 1024
        {
            return Err(CacheAuthorityError::InvalidScope);
        }
        let _validated_snapshot = authority.snapshot()?;
        Ok(Self {
            authority,
            owner_scope,
            maximum_record_bytes,
        })
    }

    /// Verifies an exact current protected record and issues an opaque capability.
    ///
    /// # Errors
    ///
    /// Returns [`CacheAuthorityError`] when the key is absent, the record is
    /// not the canonical exact scope, or protected authority is unavailable.
    pub(crate) fn verify_current_record(
        &self,
        purpose: CacheAuthorityPurposeV1,
        scope: CacheAuthorityScopeV1,
        record_key: &[u8],
    ) -> Result<VerifiedCacheCapabilityV1, CacheAuthorityError> {
        if record_key.is_empty() || record_key.len() > 1024 {
            return Err(CacheAuthorityError::InvalidScope);
        }
        let record = self
            .authority
            .get(record_key)?
            .ok_or(CacheAuthorityError::RecordAbsent)?;
        if record.len() != AUTHORITY_RECORD_BYTES || record.len() > self.maximum_record_bytes {
            return Err(CacheAuthorityError::InvalidRecord);
        }
        let expected = self.canonical_record(purpose, scope);
        if record != expected.as_slice() {
            return Err(CacheAuthorityError::RecordMismatch);
        }
        let mut hasher = Sha256::new();
        hasher.update(AUTHORITY_RECORD_DOMAIN);
        hasher.update((record_key.len() as u16).to_be_bytes());
        hasher.update(record_key);
        hasher.update((record.len() as u32).to_be_bytes());
        hasher.update(record);
        let record_digest = ObjectDigest::from_bytes(hasher.finalize().into());
        Ok(VerifiedCacheCapabilityV1 {
            snapshot: self.authority.snapshot()?,
            owner_scope: self.owner_scope,
            purpose,
            scope,
            record_digest,
        })
    }

    /// Derives and verifies one exact scope from its protected canonical record.
    pub(crate) fn verify_current_record_for_purpose(
        &self,
        purpose: CacheAuthorityPurposeV1,
        record_key: &[u8],
    ) -> Result<VerifiedCacheCapabilityV1, CacheAuthorityError> {
        let record = self
            .authority
            .get(record_key)?
            .ok_or(CacheAuthorityError::RecordAbsent)?;
        if record.len() != AUTHORITY_RECORD_BYTES
            || &record[..8] != AUTHORITY_RECORD_MAGIC
            || record[8..10] != 1_u16.to_be_bytes()
            || record[10] != purpose as u8
            || record[11..16] != [0; 5]
            || record[16..48] != *self.owner_scope.as_bytes()
        {
            return Err(CacheAuthorityError::InvalidRecord);
        }
        let scope = CacheAuthorityScopeV1 {
            partition: ObjectDigest::from_bytes(read_authority_array(record, 48)?),
            subject: ObjectDigest::from_bytes(read_authority_array(record, 80)?),
            operation: read_authority_array(record, 112)?,
            plan: ObjectDigest::from_bytes(read_authority_array(record, 128)?),
            root_custody: ObjectDigest::from_bytes(read_authority_array(record, 160)?),
            generation: u64::from_be_bytes(read_authority_array(record, 192)?),
            valid_until: u64::from_be_bytes(read_authority_array(record, 200)?),
        };
        if scope.partition.as_bytes() == &[0; 32]
            || scope.subject.as_bytes() == &[0; 32]
            || scope.plan.as_bytes() == &[0; 32]
            || scope.root_custody.as_bytes() == &[0; 32]
            || scope.generation == 0
            || scope.valid_until == 0
            || record != self.canonical_record(purpose, scope).as_slice()
        {
            return Err(CacheAuthorityError::InvalidRecord);
        }
        self.verify_current_record(purpose, scope, record_key)
    }

    /// Encodes the only protected journal value accepted for an exact scope.
    #[must_use]
    pub fn canonical_record(
        &self,
        purpose: CacheAuthorityPurposeV1,
        scope: CacheAuthorityScopeV1,
    ) -> [u8; AUTHORITY_RECORD_BYTES] {
        let mut record = [0_u8; AUTHORITY_RECORD_BYTES];
        record[0..8].copy_from_slice(AUTHORITY_RECORD_MAGIC);
        record[8..10].copy_from_slice(&1_u16.to_be_bytes());
        record[10] = purpose as u8;
        record[16..48].copy_from_slice(self.owner_scope.as_bytes());
        record[48..80].copy_from_slice(scope.partition().as_bytes());
        record[80..112].copy_from_slice(scope.subject().as_bytes());
        record[112..128].copy_from_slice(&scope.operation());
        record[128..160].copy_from_slice(scope.plan().as_bytes());
        record[160..192].copy_from_slice(scope.root_custody().as_bytes());
        record[192..200].copy_from_slice(&scope.generation().to_be_bytes());
        record[200..208].copy_from_slice(&scope.valid_until().to_be_bytes());
        record
    }

    /// Revalidates capability currentness and exact purpose/scope at effect time.
    ///
    /// # Errors
    ///
    /// Returns [`CacheAuthorityError`] after any journal advance or mismatch.
    fn validate_for_effect(
        &self,
        capability: &VerifiedCacheCapabilityV1,
        purpose: CacheAuthorityPurposeV1,
        scope: CacheAuthorityScopeV1,
    ) -> Result<(), CacheAuthorityError> {
        if capability.owner_scope != self.owner_scope
            || capability.purpose != purpose
            || capability.scope != scope
        {
            return Err(CacheAuthorityError::CapabilityMismatch);
        }
        self.authority
            .validate_snapshot_for_effect(&capability.snapshot)?;
        Ok(())
    }

    /// Revalidates exact protected currentness and a trusted time bound.
    ///
    /// # Errors
    ///
    /// Returns [`CacheAuthorityError`] for zero/expired time or any ordinary
    /// capability mismatch/currentness failure.
    pub fn validate_for_effect_at(
        &self,
        capability: &VerifiedCacheCapabilityV1,
        purpose: CacheAuthorityPurposeV1,
        scope: CacheAuthorityScopeV1,
        now: u64,
    ) -> Result<(), CacheAuthorityError> {
        if now == 0 || now >= scope.valid_until() {
            return Err(CacheAuthorityError::Expired);
        }
        self.validate_for_effect(capability, purpose, scope)
    }
}

fn read_authority_array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], CacheAuthorityError> {
    bytes
        .get(offset..offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(CacheAuthorityError::InvalidRecord)
}

impl VerifiedCacheCapabilityV1 {
    pub(crate) const fn purpose(&self) -> CacheAuthorityPurposeV1 {
        self.purpose
    }

    pub(crate) const fn scope(&self) -> CacheAuthorityScopeV1 {
        self.scope
    }

    pub(crate) const fn record_digest(&self) -> ObjectDigest {
        self.record_digest
    }
}

/// Reports protected capability verification failures.
#[derive(Debug, thiserror::Error)]
pub enum CacheAuthorityError {
    /// Capability scope or verifier limits are invalid.
    #[error("cache authority scope is invalid")]
    InvalidScope,
    /// The protected record is absent.
    #[error("cache authority record is absent")]
    RecordAbsent,
    /// The protected record is empty or outside its fixed bound.
    #[error("cache authority record is invalid")]
    InvalidRecord,
    /// The protected record commitment differs.
    #[error("cache authority record mismatches")]
    RecordMismatch,
    /// The opaque capability has a different owner, purpose, or scope.
    #[error("cache authority capability mismatches")]
    CapabilityMismatch,
    /// Trusted current time is absent or outside the capability lifetime.
    #[error("cache authority capability is expired")]
    Expired,
    /// Protected journal currentness failed.
    #[error(transparent)]
    Journal(#[from] JournalError),
}

/// Commits one lookup to the principal and current authorization revision.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct LookupAuthorityScopeV1 {
    principal: PrincipalId,
    policy_revision: ObjectDigest,
    disclosure: CacheDomain,
    descriptor: ObjectDigest,
    revocation_generation: u64,
    authority_record: ObjectDigest,
}

impl LookupAuthorityScopeV1 {
    /// Validates a complete current authority scope.
    ///
    /// # Errors
    ///
    /// Returns [`CacheDomainError::InvalidAuthority`] for sentinel identities,
    /// an absent policy commitment, or generation zero.
    pub fn from_verified_at(
        owner: &CacheAuthorityOwner<'_, '_>,
        capability: &VerifiedCacheCapabilityV1,
        partition: PhysicalPartitionId,
        principal: PrincipalId,
        policy_revision: ObjectDigest,
        authority_plan: ObjectDigest,
        disclosure: CacheDomain,
        descriptor: &ObjectDescriptor,
        revocation_generation: u64,
        valid_until: u64,
        now: u64,
    ) -> Result<Self, CacheAuthorityError> {
        validate_object_descriptor(descriptor).map_err(|_| CacheAuthorityError::InvalidScope)?;
        if principal.as_bytes() == &[0; 16]
            || disclosure != partition.disclosure()
            || policy_revision.as_bytes() == &[0; 32]
        {
            return Err(CacheAuthorityError::InvalidScope);
        }
        let descriptor = object_descriptor_commitment(descriptor);
        let scope = CacheAuthorityScopeV1::new(
            partition,
            descriptor,
            None,
            authority_plan,
            partition.backing().root(),
            revocation_generation,
            valid_until,
        )?;
        owner.validate_for_effect_at(capability, CacheAuthorityPurposeV1::Read, scope, now)?;
        Ok(Self {
            principal,
            policy_revision,
            disclosure,
            descriptor,
            revocation_generation,
            authority_record: capability.record_digest(),
        })
    }

    pub(crate) fn validate(self) -> Result<Self, CacheDomainError> {
        if self.principal.as_bytes() == &[0; 16]
            || self.disclosure.domain_id().as_bytes() == &[0; 16]
            || self.policy_revision.as_bytes() == &[0; 32]
            || self.descriptor.as_bytes() == &[0; 32]
            || self.authority_record.as_bytes() == &[0; 32]
            || self.revocation_generation == 0
        {
            return Err(CacheDomainError::InvalidAuthority);
        }
        Ok(self)
    }
}

/// Keys a positive, negative, or coalesced lookup without exposing raw scope.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct AuthorizedLookupKey(ObjectDigest);

impl AuthorizedLookupKey {
    /// Returns the opaque authority-scoped lookup commitment.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.0
    }

    pub(crate) fn from_digest(digest: ObjectDigest) -> Result<Self, CacheDomainError> {
        if digest.as_bytes() == &[0; 32] {
            return Err(CacheDomainError::InvalidAuthority);
        }
        Ok(Self(digest))
    }

    /// Derives the shared key used by every cache-result class.
    ///
    /// # Errors
    ///
    /// Returns [`CacheDomainError`] when the authority or partition binding is
    /// malformed, or when the requested descriptor has zero size.
    pub fn derive(
        partition: PhysicalPartitionId,
        scope: LookupAuthorityScopeV1,
        descriptor: &ObjectDescriptor,
    ) -> Result<Self, CacheDomainError> {
        let scope = scope.validate()?;
        if scope.disclosure != partition.disclosure() {
            return Err(CacheDomainError::InvalidAuthority);
        }
        validate_object_descriptor(descriptor)?;
        if scope.descriptor != object_descriptor_commitment(descriptor) {
            return Err(CacheDomainError::InvalidAuthority);
        }
        let media = descriptor.media_type().as_str().as_bytes();
        let media_len =
            u16::try_from(media.len()).map_err(|_| CacheDomainError::InvalidDescriptor)?;

        let mut hasher = Sha256::new();
        hasher.update(LOOKUP_DOMAIN);
        hasher.update(partition.digest().as_bytes());
        hasher.update(scope.principal.as_bytes());
        hasher.update(scope.policy_revision.as_bytes());
        hasher.update(scope.authority_record.as_bytes());
        hasher.update([cache_domain_code(scope.disclosure.kind())]);
        hasher.update(scope.disclosure.domain_id().as_bytes());
        hasher.update(scope.revocation_generation.to_be_bytes());
        hasher.update(media_len.to_be_bytes());
        hasher.update(media);
        hasher.update(descriptor.digest().as_bytes());
        hasher.update(descriptor.encoded_size().to_be_bytes());
        Ok(Self(ObjectDigest::from_bytes(hasher.finalize().into())))
    }
}
