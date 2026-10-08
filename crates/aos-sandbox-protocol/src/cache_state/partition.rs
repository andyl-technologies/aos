//! Physical Cache partition identities and isolation-policy DATA.
//!
//! These values validate identity inputs and canonical commitments. They do not
//! retain a protected root, prove currentness, or authorize an effect. Native
//! enforcement and protected authority remain with their original owners.

use aos_sandbox_core::model::{CacheDomain, CacheDomainKind};
use aos_sandbox_core::{ObjectDescriptor, ObjectDigest};
use sha2::{Digest as _, Sha256};

const PARTITION_DOMAIN: &[u8] = b"aos.sandbox.cache.physical-partition.v1\0";
const ISOLATION_DOMAIN: &[u8] = b"aos.sandbox.cache.isolation-policy.v1\0";
const DESCRIPTOR_DOMAIN: &[u8] = b"aos.sandbox.cache.object-descriptor.v1\0";

/// Selects the physical cache-identity boundary supplied by a backend.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum BackingIsolationV1 {
    /// One protected root permits acknowledged sharing inside the domain.
    SharedDomainRoot = 1,
    /// A distinct filesystem or dataset supplies an independent cache identity.
    SeparateFilesystemOrDataset = 2,
    /// A distinct pool supplies an independent ARC and block identity.
    SeparatePool = 3,
    /// Data caching is disabled because isolation cannot otherwise be proved.
    DataCacheDisabled = 4,
}

/// Selects the advertised residency enforcement profile.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ResidencyEnforcementV1 {
    /// Kernel first-touch page-cache accounting with node-bounded residency.
    PayloadPageCache = 1,
    /// Non-passthrough reads charged to a domain service cgroup.
    DomainServiceResidency = 2,
    /// Node-global ARC is bounded without a per-project hard-share claim.
    NodeGlobalArc = 3,
    /// A proven independent mechanism enforces domain residency.
    HardIsolatedResidency = 4,
}

/// Identifies the node whose kernel and storage caches participate in a partition.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct CacheNodeIdV1([u8; 16]);

impl CacheNodeIdV1 {
    /// Constructs a non-sentinel protected node identity.
    ///
    /// # Errors
    ///
    /// Returns [`CacheDomainError::InvalidDomain`] for the zero sentinel.
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, CacheDomainError> {
        if bytes == [0; 16] {
            return Err(CacheDomainError::InvalidDomain);
        }
        Ok(Self(bytes))
    }

    /// Borrows the stable node identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Commits the protected storage root, dataset, pool, and backend implementation.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct ProtectedBackingIdentityV1 {
    root: ObjectDigest,
    dataset: ObjectDigest,
    pool: ObjectDigest,
    backend: ObjectDigest,
}

impl ProtectedBackingIdentityV1 {
    /// Constructs a complete protected backing identity.
    ///
    /// Dataset and pool commitments remain mandatory even for filesystems that
    /// model them as protected singleton identities. This prevents a later
    /// backend migration from accidentally retaining the old partition key.
    ///
    /// # Errors
    ///
    /// Returns [`CacheDomainError::InvalidDomain`] for a zero commitment.
    pub fn new(
        root: ObjectDigest,
        dataset: ObjectDigest,
        pool: ObjectDigest,
        backend: ObjectDigest,
    ) -> Result<Self, CacheDomainError> {
        if [root, dataset, pool, backend]
            .iter()
            .any(|value| value.as_bytes() == &[0; 32])
        {
            return Err(CacheDomainError::InvalidDomain);
        }
        Ok(Self {
            root,
            dataset,
            pool,
            backend,
        })
    }

    /// Returns the protected root custody identity.
    #[must_use]
    pub const fn root(self) -> ObjectDigest {
        self.root
    }

    /// Returns the protected dataset identity.
    #[must_use]
    pub const fn dataset(self) -> ObjectDigest {
        self.dataset
    }

    /// Returns the protected pool identity.
    #[must_use]
    pub const fn pool(self) -> ObjectDigest {
        self.pool
    }

    /// Returns the closed backend implementation identity.
    #[must_use]
    pub const fn backend(self) -> ObjectDigest {
        self.backend
    }
}

/// Defines the complete physical cache isolation semantics.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CacheIsolationPolicyV1 {
    /// Physical backing identity boundary.
    pub backing: BackingIsolationV1,
    /// Residency accounting/enforcement profile.
    pub residency: ResidencyEnforcementV1,
    /// Whether cross-object reflink or clone reuse is enabled inside the domain.
    pub reflink_or_clone: bool,
    /// Whether block-level deduplication is enabled inside the domain.
    pub block_deduplication: bool,
    /// Whether one ARC/page-cache identity may be shared inside the domain.
    pub shared_page_cache: bool,
    /// Whether authorized misses may be coalesced inside the domain.
    pub fetch_coalescing: bool,
    /// Whether this policy promises strict physical/timing isolation.
    pub strict: bool,
    /// Monotone policy revision.
    pub revision: u64,
}

impl CacheIsolationPolicyV1 {
    /// Validates enforceable strict-domain mechanics.
    ///
    /// A strict profile rejects shared roots, reflink/clone, deduplication,
    /// page-cache identity sharing, and fetch coalescing. It additionally
    /// requires hard isolated residency or disabled data caching.
    ///
    /// # Errors
    ///
    /// Returns [`CacheDomainError::InvalidIsolationPolicy`] for an inconsistent
    /// or generation-zero policy.
    pub fn validate(self) -> Result<Self, CacheDomainError> {
        let strict_backing = matches!(
            self.backing,
            BackingIsolationV1::SeparateFilesystemOrDataset
                | BackingIsolationV1::SeparatePool
                | BackingIsolationV1::DataCacheDisabled
        );
        let strict_residency = matches!(
            self.residency,
            ResidencyEnforcementV1::HardIsolatedResidency
        ) || self.backing == BackingIsolationV1::DataCacheDisabled;
        if self.revision == 0
            || (self.strict
                && (!strict_backing
                    || !strict_residency
                    || self.reflink_or_clone
                    || self.block_deduplication
                    || self.shared_page_cache
                    || self.fetch_coalescing))
        {
            return Err(CacheDomainError::InvalidIsolationPolicy);
        }
        Ok(self)
    }

    /// Returns the domain-separated commitment included in partition identity.
    ///
    /// # Errors
    ///
    /// Returns [`CacheDomainError::InvalidIsolationPolicy`] when validation
    /// fails.
    pub fn digest(self) -> Result<ObjectDigest, CacheDomainError> {
        let policy = self.validate()?;
        let mut hasher = Sha256::new();
        hasher.update(ISOLATION_DOMAIN);
        hasher.update([policy.backing as u8, policy.residency as u8]);
        hasher.update([
            u8::from(policy.reflink_or_clone),
            u8::from(policy.block_deduplication),
            u8::from(policy.shared_page_cache),
            u8::from(policy.fetch_coalescing),
            u8::from(policy.strict),
        ]);
        hasher.update(policy.revision.to_be_bytes());
        Ok(ObjectDigest::from_bytes(hasher.finalize().into()))
    }
}

/// Identifies one physically isolated cache partition.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
pub struct PhysicalPartitionId {
    digest: ObjectDigest,
    node: CacheNodeIdV1,
    backing: ProtectedBackingIdentityV1,
    disclosure: CacheDomain,
    isolation_policy: ObjectDigest,
}

impl PhysicalPartitionId {
    /// Derives a partition identity from complete isolation semantics.
    ///
    /// # Errors
    ///
    /// Returns [`CacheDomainError`] for invalid domain or isolation policy.
    pub fn from_policy(
        node: CacheNodeIdV1,
        backing: ProtectedBackingIdentityV1,
        disclosure: CacheDomain,
        policy: CacheIsolationPolicyV1,
    ) -> Result<Self, CacheDomainError> {
        if disclosure.kind() == CacheDomainKind::Private && !policy.strict {
            return Err(CacheDomainError::InvalidIsolationPolicy);
        }
        Self::derive(node, backing, disclosure, policy.digest()?)
    }

    /// Reconstructs partition identity DATA from disclosure and policy commitments.
    ///
    /// # Errors
    ///
    /// Returns [`CacheDomainError::InvalidDomain`] for sentinel identities or
    /// an absent isolation-policy commitment. The result proves neither native
    /// isolation enforcement nor protected currentness or effect authority.
    pub fn derive(
        node: CacheNodeIdV1,
        backing: ProtectedBackingIdentityV1,
        disclosure: CacheDomain,
        isolation_policy: ObjectDigest,
    ) -> Result<Self, CacheDomainError> {
        if disclosure.domain_id().as_bytes() == &[0; 16] || isolation_policy.as_bytes() == &[0; 32]
        {
            return Err(CacheDomainError::InvalidDomain);
        }

        let mut hasher = Sha256::new();
        hasher.update(PARTITION_DOMAIN);
        hasher.update(node.as_bytes());
        hasher.update(backing.root().as_bytes());
        hasher.update(backing.dataset().as_bytes());
        hasher.update(backing.pool().as_bytes());
        hasher.update(backing.backend().as_bytes());
        hasher.update([cache_domain_code(disclosure.kind())]);
        hasher.update(disclosure.domain_id().as_bytes());
        hasher.update(isolation_policy.as_bytes());
        Ok(Self {
            digest: ObjectDigest::from_bytes(hasher.finalize().into()),
            node,
            backing,
            disclosure,
            isolation_policy,
        })
    }

    /// Returns the domain-separated partition commitment.
    #[must_use]
    pub const fn digest(self) -> ObjectDigest {
        self.digest
    }

    /// Returns the node committed by this physical identity.
    #[must_use]
    pub const fn node(self) -> CacheNodeIdV1 {
        self.node
    }

    /// Returns the complete protected backing identity.
    #[must_use]
    pub const fn backing(self) -> ProtectedBackingIdentityV1 {
        self.backing
    }

    /// Returns the exact disclosure domain committed by this partition.
    #[must_use]
    pub const fn disclosure(self) -> CacheDomain {
        self.disclosure
    }

    /// Returns the exact isolation-policy commitment.
    #[must_use]
    pub const fn isolation_policy(self) -> ObjectDigest {
        self.isolation_policy
    }
}

/// Checks that an immutable object descriptor has non-sentinel content DATA.
///
/// # Errors
///
/// Returns [`CacheDomainError::InvalidDescriptor`] for zero size or digest.
pub fn validate_object_descriptor(descriptor: &ObjectDescriptor) -> Result<(), CacheDomainError> {
    if descriptor.encoded_size() == 0 || descriptor.digest().as_bytes() == &[0; 32] {
        return Err(CacheDomainError::InvalidDescriptor);
    }
    Ok(())
}

/// Commits descriptor DATA under its existing u64-prefixed media-type domain.
///
/// This commitment is not a seal, currentness proof, or disclosure authority.
pub fn object_descriptor_commitment(descriptor: &ObjectDescriptor) -> ObjectDigest {
    let media = descriptor.media_type().as_str().as_bytes();
    let mut hasher = Sha256::new();
    hasher.update(DESCRIPTOR_DOMAIN);
    hasher.update((media.len() as u64).to_be_bytes());
    hasher.update(media);
    hasher.update(descriptor.digest().as_bytes());
    hasher.update(descriptor.encoded_size().to_be_bytes());
    ObjectDigest::from_bytes(hasher.finalize().into())
}

/// Reports malformed cache-domain identity inputs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CacheDomainError {
    /// The disclosure or isolation-policy identity is incomplete.
    #[error("cache physical domain is invalid")]
    InvalidDomain,
    /// The current lookup authority scope is incomplete.
    #[error("cache lookup authority is invalid")]
    InvalidAuthority,
    /// The immutable object descriptor is incomplete.
    #[error("cache object descriptor is invalid")]
    InvalidDescriptor,
    /// Physical isolation semantics cannot support their advertised guarantees.
    #[error("cache isolation policy is invalid")]
    InvalidIsolationPolicy,
}

/// Returns the existing zero-based Cache disclosure-domain hash discriminant.
///
/// These hash codes are distinct from the one-based protected journal wire codes.
pub const fn cache_domain_code(kind: CacheDomainKind) -> u8 {
    match kind {
        CacheDomainKind::Private => 0,
        CacheDomainKind::Project => 1,
        CacheDomainKind::TrustDomain => 2,
        CacheDomainKind::Public => 3,
    }
}
