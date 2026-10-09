//! Canonical protected publication-root models.

use aos_sandbox_core::{
    NodeId, ObjectDigest, PrincipalId, ProjectId, ResourceId,
    model::{CacheDomain, CacheDomainKind},
};
use sha2::{Digest as _, Sha256};

const ROOT_DOMAIN: &[u8] = b"aos.sandbox.publisher.root-record.v1\0";

/// Identifies one logical protected publication root across generations.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct PublicationRootId([u8; 16]);

impl PublicationRootId {
    /// Validates an exact nonzero root identity.
    ///
    /// # Errors
    ///
    /// Returns [`super::PublicationRootRegistryError::InvalidRecord`] for zero.
    pub fn from_bytes(bytes: [u8; 16]) -> Result<Self, super::PublicationRootRegistryError> {
        if bytes == [0; 16] {
            return Err(super::PublicationRootRegistryError::InvalidRecord);
        }
        Ok(Self(bytes))
    }

    /// Borrows the exact portable identity bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }
}

/// Selects the exclusive purpose of one protected directory.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PublicationRootRoleV1 {
    /// Holds private fresh inodes and canonically named committed objects.
    ImmutablePublicationObjects = 1,
}

impl PublicationRootRoleV1 {
    pub(super) fn from_code(code: u8) -> Result<Self, super::RootRecordCodecError> {
        match code {
            1 => Ok(Self::ImmutablePublicationObjects),
            _ => Err(super::RootRecordCodecError::Malformed),
        }
    }
}

/// Selects the exact filesystem mechanics required by a root.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PublicationFilesystemProfileV1 {
    /// Fresh inode, exact stream verification, fs-verity SHA-256, and no-replace rename.
    FsVeritySha256NoReplace = 1,
}

impl PublicationFilesystemProfileV1 {
    pub(super) fn from_code(code: u8) -> Result<Self, super::RootRecordCodecError> {
        match code {
            1 => Ok(Self::FsVeritySha256NoReplace),
            _ => Err(super::RootRecordCodecError::Malformed),
        }
    }
}

/// States whether one registry generation accepts new operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum PublicationRootStateV1 {
    /// Freshly observed custody may authorize exact new operations.
    Active = 1,
    /// New operations are denied while retained obligations drain.
    Draining = 2,
    /// No authority or retained obligation refers to this generation.
    Retired = 3,
}

impl PublicationRootStateV1 {
    pub(super) fn from_code(code: u8) -> Result<Self, super::RootRecordCodecError> {
        match code {
            1 => Ok(Self::Active),
            2 => Ok(Self::Draining),
            3 => Ok(Self::Retired),
            _ => Err(super::RootRecordCodecError::Malformed),
        }
    }
}

/// Counts all facts that prevent safe root retirement.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct PublicationRootObligationsV1 {
    /// Unspent or recovery-held completion permits.
    pub outstanding_permits: u64,
    /// Catalog records whose committed content resides beneath the root.
    pub catalog_entries: u64,
    /// Operations with an uncertain filesystem or durable-store effect.
    pub uncertain_effects: u64,
}

impl PublicationRootObligationsV1 {
    /// Returns whether retirement would discard authority-relevant state.
    #[must_use]
    pub const fn blocks_retirement(self) -> bool {
        self.outstanding_permits != 0 || self.catalog_entries != 0 || self.uncertain_effects != 0
    }
}

/// Binds one root generation to service identity, tenant scope, and mechanics.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicationRootRecordV1 {
    /// Stable logical root identity.
    pub root_id: PublicationRootId,
    /// Monotone generation for this logical root.
    pub generation: u64,
    /// Node on which the protected service owns custody.
    pub service_node: NodeId,
    /// Dedicated service principal allowed to exercise custody.
    pub service_principal: PrincipalId,
    /// Project whose objects occupy this root.
    pub project: ProjectId,
    /// Logical cache resource backed by this root.
    pub resource: ResourceId,
    /// Exact disclosure domain; v1 publisher roots are project-scoped.
    pub domain: CacheDomain,
    /// Physical isolation-policy commitment.
    pub isolation_policy: ObjectDigest,
    /// Exclusive directory role.
    pub role: PublicationRootRoleV1,
    /// Required immutable-file mechanics.
    pub filesystem_profile: PublicationFilesystemProfileV1,
    /// Current lifecycle state.
    pub state: PublicationRootStateV1,
    /// Digest of the immediately preceding generation.
    pub predecessor_digest: Option<ObjectDigest>,
    /// Domain-separated digest of the complete record.
    pub record_digest: ObjectDigest,
}

impl PublicationRootRecordV1 {
    /// Constructs the first generation of one logical protected root.
    ///
    /// # Errors
    ///
    /// Returns [`super::PublicationRootRegistryError::InvalidRecord`] for any
    /// sentinel identity, non-project domain, or zero generation-independent
    /// policy commitment.
    #[allow(clippy::too_many_arguments)]
    pub fn initial(
        root_id: PublicationRootId,
        service_node: NodeId,
        service_principal: PrincipalId,
        project: ProjectId,
        resource: ResourceId,
        domain: CacheDomain,
        isolation_policy: ObjectDigest,
        role: PublicationRootRoleV1,
        filesystem_profile: PublicationFilesystemProfileV1,
    ) -> Result<Self, super::PublicationRootRegistryError> {
        let mut record = Self {
            root_id,
            generation: 1,
            service_node,
            service_principal,
            project,
            resource,
            domain,
            isolation_policy,
            role,
            filesystem_profile,
            state: PublicationRootStateV1::Active,
            predecessor_digest: None,
            record_digest: ObjectDigest::from_bytes([0; 32]),
        };
        record.record_digest = root_record_digest(&record);
        record.validate()
    }

    /// Validates an externally decoded record and its derived digest.
    ///
    /// # Errors
    ///
    /// Returns [`super::PublicationRootRegistryError::InvalidRecord`] for a
    /// sentinel, non-project domain, broken generation chain shape, or digest
    /// mismatch.
    pub fn validate(self) -> Result<Self, super::PublicationRootRegistryError> {
        let invalid = self.generation == 0
            || self.service_node.as_bytes() == &[0; 16]
            || self.service_principal.as_bytes() == &[0; 16]
            || self.project.as_bytes() == &[0; 16]
            || self.resource.as_bytes() == &[0; 16]
            || self.domain.domain_id().as_bytes() == &[0; 16]
            || self.domain.kind() != CacheDomainKind::Project
            || self.isolation_policy.as_bytes() == &[0; 32]
            || (self.generation == 1) != self.predecessor_digest.is_none()
            || (self.generation == 1 && self.state != PublicationRootStateV1::Active)
            || self.record_digest != root_record_digest(&self);
        if invalid {
            return Err(super::PublicationRootRegistryError::InvalidRecord);
        }
        Ok(self)
    }

    pub(super) fn successor(
        &self,
        state: PublicationRootStateV1,
    ) -> Result<Self, super::PublicationRootRegistryError> {
        let generation = self
            .generation
            .checked_add(1)
            .ok_or(super::PublicationRootRegistryError::GenerationExhausted)?;
        let mut next = self.clone();
        next.generation = generation;
        next.state = state;
        next.predecessor_digest = Some(self.record_digest);
        next.record_digest = ObjectDigest::from_bytes([0; 32]);
        next.record_digest = root_record_digest(&next);
        Ok(next)
    }

    pub(super) fn follows(
        &self,
        predecessor: &Self,
    ) -> Result<(), super::PublicationRootRegistryError> {
        let same_binding = self.root_id == predecessor.root_id
            && self.service_node == predecessor.service_node
            && self.service_principal == predecessor.service_principal
            && self.project == predecessor.project
            && self.resource == predecessor.resource
            && self.domain == predecessor.domain
            && self.isolation_policy == predecessor.isolation_policy
            && self.role == predecessor.role
            && self.filesystem_profile == predecessor.filesystem_profile;
        let transition = matches!(
            (predecessor.state, self.state),
            (
                PublicationRootStateV1::Active,
                PublicationRootStateV1::Draining
            ) | (
                PublicationRootStateV1::Draining,
                PublicationRootStateV1::Retired
            )
        );
        let next_generation = predecessor
            .generation
            .checked_add(1)
            .ok_or(super::PublicationRootRegistryError::GenerationExhausted)?;
        if !same_binding
            || !transition
            || self.generation != next_generation
            || self.predecessor_digest != Some(predecessor.record_digest)
        {
            return Err(super::PublicationRootRegistryError::GenerationConflict);
        }
        Ok(())
    }
}

pub(super) fn root_record_digest(record: &PublicationRootRecordV1) -> ObjectDigest {
    let predecessor = record
        .predecessor_digest
        .map_or([0; 32], |digest| *digest.as_bytes());
    let mut digest = Sha256::new();
    digest.update(ROOT_DOMAIN);
    digest.update(record.root_id.as_bytes());
    digest.update(record.generation.to_be_bytes());
    digest.update(record.service_node.as_bytes());
    digest.update(record.service_principal.as_bytes());
    digest.update(record.project.as_bytes());
    digest.update(record.resource.as_bytes());
    digest.update([domain_code(record.domain)]);
    digest.update(record.domain.domain_id().as_bytes());
    digest.update(record.isolation_policy.as_bytes());
    digest.update([record.role as u8]);
    digest.update([record.filesystem_profile as u8]);
    digest.update([record.state as u8]);
    digest.update(predecessor);
    ObjectDigest::from_bytes(digest.finalize().into())
}

pub(super) fn domain_code(domain: CacheDomain) -> u8 {
    match domain.kind() {
        CacheDomainKind::Private => 1,
        CacheDomainKind::Project => 2,
        CacheDomainKind::TrustDomain => 3,
        CacheDomainKind::Public => 4,
    }
}
