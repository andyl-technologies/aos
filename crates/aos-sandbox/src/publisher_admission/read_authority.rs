//! Independent current cache-read authority, catalog lookup, and retained pins.
//!
//! Publication permission never implies disclosure permission. This reducer
//! joins a current read grant, current protected catalog generation, and active
//! root custody. Every mismatch has the same concealed result.

use std::collections::BTreeMap;

use aos_sandbox_core::{
    CacheDomainId, MediaType, ObjectDescriptor, ObjectDigest, PrincipalId, ProjectId, ResourceId,
    model::{CacheDomain, CacheDomainKind},
};

use crate::publisher_roots::PublicationRootId;
#[cfg(target_os = "linux")]
use crate::publisher_roots::{AuthorizedPublicationRoot, PublicationRootRegistry};

use super::digest_parts;

const READ_GRANT_DOMAIN: &[u8] = b"aos.sandbox.publisher.read-grant.v1\0";
const CATALOG_ENTRY_DOMAIN: &[u8] = b"aos.sandbox.publisher.read-catalog-entry.v1\0";
const READ_REQUEST_DOMAIN: &[u8] = b"aos.sandbox.publisher.open-for-read.v1\0";
const ENTRY_MAGIC: &[u8; 8] = b"AOSCRE01";

/// Reports malformed or exhausted protected read projections.
#[derive(Clone, Debug, Eq, PartialEq, thiserror::Error)]
pub enum CacheReadAuthorityError {
    /// A sentinel, disclosure domain, digest, or generation is invalid.
    #[error("cache read authority record is invalid")]
    InvalidRecord,
    /// A retained identity was reused with different facts.
    #[error("cache read authority record conflicts")]
    Conflict,
    /// A configured cardinality or monotone generation was exhausted.
    #[error("cache read authority capacity is exhausted")]
    Capacity,
}

/// States whether one protected read grant may authorize a new open.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadGrantStateV1 {
    /// The exact holder may request current catalog entries.
    Active,
    /// New reads are denied without revealing catalog membership.
    Revoked,
}

/// Stores one protected, independently revocable disclosure grant.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReadAuthorityGrantV1 {
    /// Authenticated holder.
    pub holder: PrincipalId,
    /// Authorized project.
    pub project: ProjectId,
    /// Logical cache resource.
    pub resource: ResourceId,
    /// Exact project disclosure domain.
    pub domain: CacheDomain,
    /// Effective read-policy commitment.
    pub policy_digest: ObjectDigest,
    /// Monotone revocation generation.
    pub generation: u64,
    /// Current grant state.
    pub state: ReadGrantStateV1,
    /// Canonical commitment to all preceding fields.
    pub grant_digest: ObjectDigest,
}

impl ReadAuthorityGrantV1 {
    /// Constructs a canonical active read grant.
    ///
    /// # Errors
    ///
    /// Returns [`CacheReadAuthorityError::InvalidRecord`] for sentinel fields,
    /// a non-project domain, or generation zero.
    pub fn active(
        holder: PrincipalId,
        project: ProjectId,
        resource: ResourceId,
        domain: CacheDomain,
        policy_digest: ObjectDigest,
        generation: u64,
    ) -> Result<Self, CacheReadAuthorityError> {
        let mut grant = Self {
            holder,
            project,
            resource,
            domain,
            policy_digest,
            generation,
            state: ReadGrantStateV1::Active,
            grant_digest: ObjectDigest::from_bytes([0; 32]),
        };
        grant.grant_digest = read_grant_digest(&grant);
        grant.validate()?;
        Ok(grant)
    }

    fn validate(&self) -> Result<(), CacheReadAuthorityError> {
        if self.holder.as_bytes() == &[0; 16]
            || self.project.as_bytes() == &[0; 16]
            || self.resource.as_bytes() == &[0; 16]
            || self.domain.domain_id().as_bytes() == &[0; 16]
            || self.domain.kind() != CacheDomainKind::Project
            || self.policy_digest.as_bytes() == &[0; 32]
            || self.generation == 0
            || self.grant_digest != read_grant_digest(self)
        {
            return Err(CacheReadAuthorityError::InvalidRecord);
        }
        Ok(())
    }
}

/// Owns the current independently revocable read grants.
///
/// V1 deliberately keys by authenticated holder and permits exactly one stable
/// project/resource/domain/policy scope per holder. Scope changes require a new
/// holder identity; replay rejects attempts to reuse a holder across scopes.
#[derive(Debug)]
pub struct ReadAuthorityRegistryV1 {
    grants: BTreeMap<[u8; 16], ReadAuthorityGrantV1>,
    checkpoint_digest: ObjectDigest,
}

impl ReadAuthorityRegistryV1 {
    /// Replays a bounded grant projection, rejecting gaps and forks.
    ///
    /// # Errors
    ///
    /// Returns [`CacheReadAuthorityError`] for invalid capacity, records,
    /// noncontiguous generations, changed scope, or conflicting successors.
    pub(crate) fn replay(
        maximum_records: usize,
        records: impl IntoIterator<Item = ReadAuthorityGrantV1>,
    ) -> Result<Self, CacheReadAuthorityError> {
        if maximum_records == 0 || maximum_records > 65_536 {
            return Err(CacheReadAuthorityError::Capacity);
        }
        let mut grants = BTreeMap::new();
        let mut count = 0_usize;
        for grant in records {
            grant.validate()?;
            count = count
                .checked_add(1)
                .ok_or(CacheReadAuthorityError::Capacity)?;
            if count > maximum_records {
                return Err(CacheReadAuthorityError::Capacity);
            }
            let key = *grant.holder.as_bytes();
            if let Some(previous) = grants.get(&key) {
                let previous: &ReadAuthorityGrantV1 = previous;
                let next = previous
                    .generation
                    .checked_add(1)
                    .ok_or(CacheReadAuthorityError::Capacity)?;
                if grant.generation != next
                    || grant.project != previous.project
                    || grant.resource != previous.resource
                    || grant.domain != previous.domain
                    || grant.policy_digest != previous.policy_digest
                    || previous.state != ReadGrantStateV1::Active
                    || grant.state != ReadGrantStateV1::Revoked
                {
                    return Err(CacheReadAuthorityError::Conflict);
                }
            } else if grant.generation != 1 || grant.state != ReadGrantStateV1::Active {
                return Err(CacheReadAuthorityError::Conflict);
            }
            grants.insert(key, grant);
        }
        let checkpoint_digest = read_registry_digest(&grants);
        Ok(Self {
            grants,
            checkpoint_digest,
        })
    }

    /// Revokes one current grant and returns its protected successor.
    ///
    /// # Errors
    ///
    /// Returns [`CacheReadAuthorityError`] if the holder is absent, already
    /// revoked, or its monotone generation is exhausted.
    pub(crate) fn revoke(
        &mut self,
        holder: PrincipalId,
    ) -> Result<ReadAuthorityGrantV1, CacheReadAuthorityError> {
        let current = self
            .grants
            .get(holder.as_bytes())
            .ok_or(CacheReadAuthorityError::Conflict)?;
        if current.state != ReadGrantStateV1::Active {
            return Err(CacheReadAuthorityError::Conflict);
        }
        let mut successor = current.clone();
        successor.generation = successor
            .generation
            .checked_add(1)
            .ok_or(CacheReadAuthorityError::Capacity)?;
        successor.state = ReadGrantStateV1::Revoked;
        successor.grant_digest = read_grant_digest(&successor);
        self.grants.insert(*holder.as_bytes(), successor.clone());
        self.checkpoint_digest = read_registry_digest(&self.grants);
        Ok(successor)
    }

    /// Borrows one exact active grant from the singular protected projection.
    pub(crate) fn select_current(&self, holder: PrincipalId) -> Option<CurrentReadAuthority<'_>> {
        let grant = self.grants.get(holder.as_bytes())?;
        (grant.state == ReadGrantStateV1::Active).then_some(CurrentReadAuthority {
            registry: self,
            grant,
            checkpoint_digest: self.checkpoint_digest,
        })
    }
}

/// Borrows one active grant and the exact singular registry checkpoint.
#[derive(Debug)]
pub struct CurrentReadAuthority<'registry> {
    registry: &'registry ReadAuthorityRegistryV1,
    grant: &'registry ReadAuthorityGrantV1,
    checkpoint_digest: ObjectDigest,
}

/// Describes one current protected catalog entry without filesystem locators.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommittedReadEntryV1 {
    object: ObjectDescriptor,
    project: ProjectId,
    resource: ResourceId,
    domain: CacheDomain,
    root_id: PublicationRootId,
    root_digest: ObjectDigest,
    root_generation: u64,
    backing_identity_digest: ObjectDigest,
    allocated_bytes: u64,
    entry_digest: ObjectDigest,
}

impl CommittedReadEntryV1 {
    /// Constructs an entry from a committed publication observation.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn committed(
        object: ObjectDescriptor,
        project: ProjectId,
        resource: ResourceId,
        domain: CacheDomain,
        root_id: PublicationRootId,
        root_digest: ObjectDigest,
        root_generation: u64,
        backing_identity_digest: ObjectDigest,
        allocated_bytes: u64,
    ) -> Result<Self, CacheReadAuthorityError> {
        let mut entry = Self {
            object,
            project,
            resource,
            domain,
            root_id,
            root_digest,
            root_generation,
            backing_identity_digest,
            allocated_bytes,
            entry_digest: ObjectDigest::from_bytes([0; 32]),
        };
        entry.entry_digest = catalog_entry_digest(&entry);
        entry.validate()?;
        Ok(entry)
    }

    fn validate(&self) -> Result<(), CacheReadAuthorityError> {
        if self.object.digest().as_bytes() == &[0; 32]
            || self.object.media_type().as_str().len() > usize::from(u8::MAX)
            || self.project.as_bytes() == &[0; 16]
            || self.resource.as_bytes() == &[0; 16]
            || self.domain.kind() != CacheDomainKind::Project
            || self.domain.domain_id().as_bytes() == &[0; 16]
            || self.root_digest.as_bytes() == &[0; 32]
            || self.root_generation == 0
            || self.backing_identity_digest.as_bytes() == &[0; 32]
            || self.allocated_bytes < self.object.encoded_size()
            || self.entry_digest != catalog_entry_digest(self)
        {
            return Err(CacheReadAuthorityError::InvalidRecord);
        }
        Ok(())
    }

    pub(super) const fn object(&self) -> &ObjectDescriptor {
        &self.object
    }

    pub(super) const fn project(&self) -> ProjectId {
        self.project
    }

    pub(super) const fn resource(&self) -> ResourceId {
        self.resource
    }

    pub(super) const fn domain(&self) -> CacheDomain {
        self.domain
    }

    pub(super) const fn root_digest(&self) -> ObjectDigest {
        self.root_digest
    }

    pub(super) const fn root_id(&self) -> PublicationRootId {
        self.root_id
    }

    pub(super) const fn root_generation(&self) -> u64 {
        self.root_generation
    }

    pub(super) const fn allocated(&self) -> u64 {
        self.allocated_bytes
    }

    pub(super) const fn backing_digest(&self) -> ObjectDigest {
        self.backing_identity_digest
    }

    pub(super) const fn digest(&self) -> ObjectDigest {
        self.entry_digest
    }
}

/// Owns a bounded, current committed-catalog projection.
#[derive(Debug)]
pub struct ReadCatalogProjectionV1 {
    entries: BTreeMap<ObjectDescriptor, CommittedReadEntryV1>,
    maximum_entries: usize,
    generation: u64,
    checkpoint_digest: ObjectDigest,
    poisoned: bool,
}

impl ReadCatalogProjectionV1 {
    /// Replays one current bounded catalog generation.
    ///
    /// # Errors
    ///
    /// Returns [`CacheReadAuthorityError`] for nonempty generation zero,
    /// invalid or duplicate entries, or a cardinality violation.
    pub(crate) fn replay(
        generation: u64,
        maximum_entries: usize,
        entries: impl IntoIterator<Item = CommittedReadEntryV1>,
    ) -> Result<Self, CacheReadAuthorityError> {
        if maximum_entries == 0 || maximum_entries > 1_048_576 {
            return Err(CacheReadAuthorityError::Capacity);
        }

        // Stream replay so an untrusted iterator cannot force an unbounded
        // intermediate allocation before the configured ceiling is checked.
        let mut retained = BTreeMap::new();
        for entry in entries {
            if generation == 0 {
                return Err(CacheReadAuthorityError::InvalidRecord);
            }
            entry.validate()?;
            if retained.contains_key(entry.object()) {
                return Err(CacheReadAuthorityError::Conflict);
            }
            if retained.len() >= maximum_entries {
                return Err(CacheReadAuthorityError::Capacity);
            }

            retained.insert(entry.object.clone(), entry);
        }
        let checkpoint_digest = read_catalog_digest(generation, maximum_entries, false, &retained);
        Ok(Self {
            entries: retained,
            maximum_entries,
            generation,
            checkpoint_digest,
            poisoned: false,
        })
    }

    /// Exclusively retains one exact active catalog entry for durable eviction.
    ///
    /// The mutable borrow prevents any [`AuthorizedCacheRead`] pin from
    /// coexisting with this custody. The trusted catalog adapter must consume
    /// the custody only after durable removal.
    ///
    /// # Errors
    ///
    /// Returns [`CacheReadAuthorityError`] if the entry is absent, duplicated,
    /// or the requested catalog predecessor is stale.
    pub(crate) fn begin_exclusive_eviction(
        &mut self,
        operation: aos_sandbox_core::OperationId,
        catalog_entry_digest: ObjectDigest,
    ) -> Result<ExclusiveCatalogEvictionCustody<'_>, CacheReadAuthorityError> {
        let mut matches = self
            .entries
            .iter()
            .filter(|(_, entry)| entry.entry_digest == catalog_entry_digest);
        let object = matches
            .next()
            .map(|(object, _)| object.clone())
            .ok_or(CacheReadAuthorityError::Conflict)?;
        if matches.next().is_some() || self.generation == 0 || self.poisoned {
            return Err(CacheReadAuthorityError::Conflict);
        }
        let next_generation = self
            .generation
            .checked_add(1)
            .ok_or(CacheReadAuthorityError::Capacity)?;
        Ok(ExclusiveCatalogEvictionCustody {
            operation,
            catalog_entry_digest,
            prior_catalog_generation: self.generation,
            next_catalog_generation: next_generation,
            object,
            catalog: self,
        })
    }

    /// Returns the current generation without granting membership knowledge.
    #[must_use]
    pub const fn generation(&self) -> u64 {
        self.generation
    }

    /// Borrows one exact entry and the singular catalog checkpoint.
    pub(crate) fn select_current(
        &self,
        object: &ObjectDescriptor,
        generation: u64,
    ) -> Option<CurrentReadCatalog<'_>> {
        if self.poisoned || self.generation != generation {
            return None;
        }
        Some(CurrentReadCatalog {
            catalog: self,
            entry: self.entries.get(object)?,
            checkpoint_digest: self.checkpoint_digest,
        })
    }

    pub(super) fn contains_object(&self, object: &ObjectDescriptor) -> bool {
        self.entries.contains_key(object)
    }

    pub(super) fn recovery_entry(
        &self,
        object: &ObjectDescriptor,
    ) -> Option<&CommittedReadEntryV1> {
        (!self.poisoned).then(|| self.entries.get(object)).flatten()
    }

    pub(super) fn begin_exclusive_insertion(
        &mut self,
        prior_generation: u64,
        entry: CommittedReadEntryV1,
    ) -> Result<ExclusiveCatalogInsertionCustody<'_>, CacheReadAuthorityError> {
        if self.poisoned
            || self.generation != prior_generation
            || self.entries.contains_key(entry.object())
        {
            return Err(CacheReadAuthorityError::Conflict);
        }
        if self.entries.len() >= self.maximum_entries {
            return Err(CacheReadAuthorityError::Capacity);
        }
        let next = prior_generation
            .checked_add(1)
            .ok_or(CacheReadAuthorityError::Capacity)?;

        Ok(ExclusiveCatalogInsertionCustody {
            prior_generation,
            next_generation: next,
            entry,
            catalog: self,
        })
    }

    pub(super) fn poison(&mut self) {
        self.poisoned = true;
        self.checkpoint_digest =
            read_catalog_digest(self.generation, self.maximum_entries, true, &self.entries);
    }
}

/// Exclusively retains a validated catalog-insertion successor until settlement.
#[derive(Debug)]
pub(super) struct ExclusiveCatalogInsertionCustody<'catalog> {
    prior_generation: u64,
    next_generation: u64,
    entry: CommittedReadEntryV1,
    catalog: &'catalog mut ReadCatalogProjectionV1,
}

impl ExclusiveCatalogInsertionCustody<'_> {
    pub(super) const fn prior_generation(&self) -> u64 {
        self.prior_generation
    }

    pub(super) const fn entry(&self) -> &CommittedReadEntryV1 {
        &self.entry
    }

    /// Applies the prevalidated successor after protected acknowledgement.
    pub(super) fn commit(self) {
        self.catalog
            .entries
            .insert(self.entry.object.clone(), self.entry);
        self.catalog.generation = self.next_generation;
        self.catalog.checkpoint_digest = read_catalog_digest(
            self.next_generation,
            self.catalog.maximum_entries,
            false,
            &self.catalog.entries,
        );
    }

    /// Permanently denies reads after the poison branch is acknowledged.
    pub(super) fn poison(self) {
        self.catalog.poison();
    }
}

/// Borrows one entry and the exact singular catalog checkpoint.
#[derive(Debug)]
pub struct CurrentReadCatalog<'catalog> {
    catalog: &'catalog ReadCatalogProjectionV1,
    entry: &'catalog CommittedReadEntryV1,
    checkpoint_digest: ObjectDigest,
}

/// Exclusively borrows the current catalog and all in-process read pins.
#[derive(Debug)]
pub struct ExclusiveCatalogEvictionCustody<'catalog> {
    operation: aos_sandbox_core::OperationId,
    catalog_entry_digest: ObjectDigest,
    prior_catalog_generation: u64,
    next_catalog_generation: u64,
    object: ObjectDescriptor,
    catalog: &'catalog mut ReadCatalogProjectionV1,
}

impl ExclusiveCatalogEvictionCustody<'_> {
    pub(super) const fn operation(&self) -> aos_sandbox_core::OperationId {
        self.operation
    }

    pub(super) const fn entry_digest(&self) -> ObjectDigest {
        self.catalog_entry_digest
    }

    pub(super) const fn prior_generation(&self) -> u64 {
        self.prior_catalog_generation
    }

    pub(super) fn commit(self) {
        self.catalog.entries.remove(&self.object);
        self.catalog.generation = self.next_catalog_generation;
        self.catalog.checkpoint_digest = read_catalog_digest(
            self.next_catalog_generation,
            self.catalog.maximum_entries,
            false,
            &self.catalog.entries,
        );
    }

    pub(super) fn poison(self) {
        self.catalog.poison();
    }
}

/// Commits the exact inputs of one `OpenForRead` request.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OpenForReadRequestV1 {
    holder: PrincipalId,
    project: ProjectId,
    object: ObjectDescriptor,
    read_authority_digest: ObjectDigest,
    catalog_generation: u64,
    request_digest: ObjectDigest,
}

impl OpenForReadRequestV1 {
    /// Constructs the exact canonical read request commitment.
    pub fn new(
        holder: PrincipalId,
        project: ProjectId,
        object: ObjectDescriptor,
        read_authority_digest: ObjectDigest,
        catalog_generation: u64,
    ) -> Self {
        let request_digest = digest_parts(
            READ_REQUEST_DOMAIN,
            &[
                holder.as_bytes(),
                project.as_bytes(),
                object.media_type().as_str().as_bytes(),
                object.digest().as_bytes(),
                &object.encoded_size().to_be_bytes(),
                read_authority_digest.as_bytes(),
                &catalog_generation.to_be_bytes(),
            ],
        );
        Self {
            holder,
            project,
            object,
            read_authority_digest,
            catalog_generation,
            request_digest,
        }
    }

    /// Returns the commitment used by the concealed response.
    #[must_use]
    pub const fn request_digest(&self) -> ObjectDigest {
        self.request_digest
    }
}

/// Opaque pin retaining the exact catalog projection and live root custody.
#[derive(Debug)]
#[cfg(target_os = "linux")]
pub struct AuthorizedCacheRead<'authority> {
    entry: &'authority CommittedReadEntryV1,
    _authority: CurrentReadAuthority<'authority>,
    _catalog: CurrentReadCatalog<'authority>,
    _root: &'authority AuthorizedPublicationRoot<'authority>,
}

/// Gives absent and concealed objects the identical external result.
#[derive(Debug)]
#[cfg(target_os = "linux")]
pub enum CacheReadDecisionV1<'authority> {
    /// Current authorization and a retained catalog/root pin permit opening.
    Found(AuthorizedCacheRead<'authority>),
    /// Absence, denial, revocation, or stale catalog/root share one result.
    NotFoundOrConcealed {
        /// Exact request commitment, not an existence discriminator.
        request_digest: ObjectDigest,
    },
}

/// Resolves independent current read authority while retaining all borrows.
///
/// Existing committed entries remain readable while their root is `Draining`.
/// Draining rejects new publications but does not revoke already-authorized
/// disclosure; retirement remains blocked until catalog eviction and all pins
/// release. A `Retired` root is always concealed.
#[must_use]
#[cfg(target_os = "linux")]
pub fn authorize_cache_read_v1<'authority>(
    request: &OpenForReadRequestV1,
    authority: CurrentReadAuthority<'authority>,
    catalog: CurrentReadCatalog<'authority>,
    roots: &'authority PublicationRootRegistry,
    root: &'authority AuthorizedPublicationRoot<'authority>,
) -> CacheReadDecisionV1<'authority> {
    let concealed = || CacheReadDecisionV1::NotFoundOrConcealed {
        request_digest: request.request_digest,
    };
    let grant = authority.grant;
    let entry = catalog.entry;
    let root_is_current = roots.head(entry.root_id).is_some_and(|current| {
        matches!(
            current.state,
            crate::publisher_roots::PublicationRootStateV1::Active
                | crate::publisher_roots::PublicationRootStateV1::Draining
        ) && roots.generation_digest(entry.root_id, entry.root_generation)
            == Some(entry.root_digest)
            && current.generation >= entry.root_generation
            && entry.root_digest == root.record_digest()
            && entry.root_generation == root.generation()
    });
    if grant.state != ReadGrantStateV1::Active
        || grant.grant_digest != request.read_authority_digest
        || authority.registry.checkpoint_digest != authority.checkpoint_digest
        || grant.project != request.project
        || grant.project != entry.project
        || grant.resource != entry.resource
        || grant.domain != entry.domain
        || request.catalog_generation != catalog.catalog.generation
        || catalog.catalog.checkpoint_digest != catalog.checkpoint_digest
        || !root_is_current
    {
        return concealed();
    }
    CacheReadDecisionV1::Found(AuthorizedCacheRead {
        entry,
        _authority: authority,
        _catalog: catalog,
        _root: root,
    })
}

#[cfg(target_os = "linux")]
impl AuthorizedCacheRead<'_> {
    /// Returns the exact pinned object descriptor.
    #[must_use]
    pub const fn object(&self) -> &ObjectDescriptor {
        &self.entry.object
    }

    /// Returns the immutable backing identity expected from the carrier.
    #[must_use]
    pub const fn backing_identity_digest(&self) -> ObjectDigest {
        self.entry.backing_identity_digest
    }

    /// Returns the current catalog-entry commitment.
    #[must_use]
    pub const fn catalog_entry_digest(&self) -> ObjectDigest {
        self.entry.entry_digest
    }

    /// Returns the exact allocated bytes charged to residency.
    #[must_use]
    pub const fn allocated_bytes(&self) -> u64 {
        self.entry.allocated_bytes
    }
}

fn read_grant_digest(grant: &ReadAuthorityGrantV1) -> ObjectDigest {
    digest_parts(
        READ_GRANT_DOMAIN,
        &[
            grant.holder.as_bytes(),
            grant.project.as_bytes(),
            grant.resource.as_bytes(),
            &[domain_code(grant.domain)],
            grant.domain.domain_id().as_bytes(),
            grant.policy_digest.as_bytes(),
            &grant.generation.to_be_bytes(),
            &[match grant.state {
                ReadGrantStateV1::Active => 1,
                ReadGrantStateV1::Revoked => 2,
            }],
        ],
    )
}

fn read_registry_digest(grants: &BTreeMap<[u8; 16], ReadAuthorityGrantV1>) -> ObjectDigest {
    let values: Vec<&[u8]> = grants
        .values()
        .map(|grant| grant.grant_digest.as_bytes().as_slice())
        .collect();
    digest_parts(b"aos.sandbox.publisher.read-registry.v1\0", &values)
}

fn read_catalog_digest(
    generation: u64,
    maximum_entries: usize,
    poisoned: bool,
    entries: &BTreeMap<ObjectDescriptor, CommittedReadEntryV1>,
) -> ObjectDigest {
    let generation_bytes = generation.to_be_bytes();
    let maximum_entries_bytes = (maximum_entries as u64).to_be_bytes();
    let mut values = Vec::with_capacity(entries.len().saturating_add(3));
    values.push(generation_bytes.as_slice());
    values.push(maximum_entries_bytes.as_slice());
    let poison = [u8::from(poisoned)];
    values.push(poison.as_slice());
    values.extend(
        entries
            .values()
            .map(|entry| entry.entry_digest.as_bytes().as_slice()),
    );
    digest_parts(b"aos.sandbox.publisher.read-catalog.v1\0", &values)
}

fn catalog_entry_digest(entry: &CommittedReadEntryV1) -> ObjectDigest {
    digest_parts(
        CATALOG_ENTRY_DOMAIN,
        &[
            entry.object.media_type().as_str().as_bytes(),
            entry.object.digest().as_bytes(),
            &entry.object.encoded_size().to_be_bytes(),
            entry.project.as_bytes(),
            entry.resource.as_bytes(),
            &[domain_code(entry.domain)],
            entry.domain.domain_id().as_bytes(),
            entry.root_id.as_bytes(),
            entry.root_digest.as_bytes(),
            &entry.root_generation.to_be_bytes(),
            entry.backing_identity_digest.as_bytes(),
            &entry.allocated_bytes.to_be_bytes(),
        ],
    )
}

fn domain_code(domain: CacheDomain) -> u8 {
    match domain.kind() {
        CacheDomainKind::Private => 1,
        CacheDomainKind::Project => 2,
        CacheDomainKind::TrustDomain => 3,
        CacheDomainKind::Public => 4,
    }
}

pub(super) fn encode_committed_read_entry_v1(entry: &CommittedReadEntryV1) -> Vec<u8> {
    let media = entry.object.media_type().as_str().as_bytes();
    let mut bytes = Vec::with_capacity(228 + media.len());
    bytes.extend_from_slice(ENTRY_MAGIC);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.push(media.len() as u8);
    bytes.extend_from_slice(media);
    bytes.extend_from_slice(entry.object.digest().as_bytes());
    bytes.extend_from_slice(&entry.object.encoded_size().to_be_bytes());
    bytes.extend_from_slice(entry.project.as_bytes());
    bytes.extend_from_slice(entry.resource.as_bytes());
    bytes.push(domain_code(entry.domain));
    bytes.extend_from_slice(entry.domain.domain_id().as_bytes());
    bytes.extend_from_slice(entry.root_id.as_bytes());
    bytes.extend_from_slice(entry.root_digest.as_bytes());
    bytes.extend_from_slice(&entry.root_generation.to_be_bytes());
    bytes.extend_from_slice(entry.backing_identity_digest.as_bytes());
    bytes.extend_from_slice(&entry.allocated_bytes.to_be_bytes());
    bytes.extend_from_slice(entry.entry_digest.as_bytes());
    bytes
}

pub(super) fn decode_committed_read_entry_v1(
    bytes: &[u8],
) -> Result<CommittedReadEntryV1, CacheReadAuthorityError> {
    if bytes.len() < 228 || &bytes[..8] != ENTRY_MAGIC || bytes[8..10] != 1_u16.to_be_bytes() {
        return Err(CacheReadAuthorityError::InvalidRecord);
    }
    let media_length = usize::from(bytes[10]);
    if bytes.len() != 228 + media_length {
        return Err(CacheReadAuthorityError::InvalidRecord);
    }
    let mut offset = 11_usize;
    let media = std::str::from_utf8(take(bytes, &mut offset, media_length)?)
        .map_err(|_| CacheReadAuthorityError::InvalidRecord)?;
    let media =
        MediaType::new(media.to_owned()).map_err(|_| CacheReadAuthorityError::InvalidRecord)?;
    let object_digest = ObjectDigest::from_bytes(array(take(bytes, &mut offset, 32)?)?);
    let object_size = u64::from_be_bytes(array(take(bytes, &mut offset, 8)?)?);
    let project = ProjectId::from_bytes(array(take(bytes, &mut offset, 16)?)?);
    let resource = ResourceId::from_bytes(array(take(bytes, &mut offset, 16)?)?);
    let kind = match take(bytes, &mut offset, 1)?[0] {
        1 => CacheDomainKind::Private,
        2 => CacheDomainKind::Project,
        3 => CacheDomainKind::TrustDomain,
        4 => CacheDomainKind::Public,
        _ => return Err(CacheReadAuthorityError::InvalidRecord),
    };
    let domain = CacheDomain::new(
        kind,
        CacheDomainId::from_bytes(array(take(bytes, &mut offset, 16)?)?),
    );
    let root_id = PublicationRootId::from_bytes(array(take(bytes, &mut offset, 16)?)?)
        .map_err(|_| CacheReadAuthorityError::InvalidRecord)?;
    let root_digest = ObjectDigest::from_bytes(array(take(bytes, &mut offset, 32)?)?);
    let root_generation = u64::from_be_bytes(array(take(bytes, &mut offset, 8)?)?);
    let backing = ObjectDigest::from_bytes(array(take(bytes, &mut offset, 32)?)?);
    let allocated = u64::from_be_bytes(array(take(bytes, &mut offset, 8)?)?);
    let stored_digest = ObjectDigest::from_bytes(array(take(bytes, &mut offset, 32)?)?);
    if offset != bytes.len() {
        return Err(CacheReadAuthorityError::InvalidRecord);
    }
    let entry = CommittedReadEntryV1::committed(
        ObjectDescriptor::new(media, object_digest, object_size),
        project,
        resource,
        domain,
        root_id,
        root_digest,
        root_generation,
        backing,
        allocated,
    )?;
    if entry.entry_digest != stored_digest || encode_committed_read_entry_v1(&entry) != bytes {
        return Err(CacheReadAuthorityError::InvalidRecord);
    }
    Ok(entry)
}

fn take<'a>(
    bytes: &'a [u8],
    offset: &mut usize,
    count: usize,
) -> Result<&'a [u8], CacheReadAuthorityError> {
    let end = offset
        .checked_add(count)
        .ok_or(CacheReadAuthorityError::Capacity)?;
    let value = bytes
        .get(*offset..end)
        .ok_or(CacheReadAuthorityError::InvalidRecord)?;
    *offset = end;
    Ok(value)
}

fn array<const N: usize>(bytes: &[u8]) -> Result<[u8; N], CacheReadAuthorityError> {
    bytes
        .try_into()
        .map_err(|_| CacheReadAuthorityError::InvalidRecord)
}
