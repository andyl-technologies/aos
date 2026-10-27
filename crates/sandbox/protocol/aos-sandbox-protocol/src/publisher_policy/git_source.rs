//! Original signed-policy DATA and protected non-admitting Git bootstrap records.
//!
//! This module shares the sole AOSPSC01 verifier with ordinary publisher startup.
//! A clean new account family is not a complete project usage inventory or permit.

use crate::publisher_project_authorization::{
    HEAD_DOMAIN,
    REVISION_DOMAIN,
    commitment,
};

use aos_sandbox_model::model::CacheDomainKind;
use aos_sandbox_model::{
    DecodeLimits, NodeId, ObjectDigest, Operation, PrincipalId, ProjectId,
    ResourceId, ResourceKind, RevocationScopeId, Selector,
};
use ed25519_dalek::{Signature, Verifier as _, VerifyingKey};
use sha2::{Digest as _, Sha256};

use crate::publisher_session::PublisherSessionScope;
use aos_sandbox_model::{
    GitUploadCapacityV1, ObjectDescriptorVerifier, PortableMediaType,
    ResourceAccount, ResourceCeilings, ResourceDimension, ResourceVector,
    decode_git_upload_capacity_v1,
};
use std::collections::BTreeMap;

use super::*;

const MAGIC: &[u8; 8] = b"AOSPSC01";
const SIGNING_DOMAIN: &[u8] = b"aos.sandbox.publisher-policy-source.v1\0";
const TRANSACTION_DOMAIN: &[u8] = b"aos.sandbox.publisher-policy-source-transaction.v1\0";
const PACKET_BYTES: usize = 272;
const SIGNED_BYTES: usize = 208;

// The ordinary adapter drops/classifies at the original failure site, before
// its statement/policy locals. Retained startup parks the actual typed cause.
#[derive(Clone, Copy)]
enum SignedSourceErrorCustodyV1 {
    Local,
    Retained,
}

impl SignedSourceErrorCustodyV1 {
    fn failure(self, cause: GitUploadSourceDataErrorV1) -> GitUploadSourceDataErrorV1 {
        match self {
            Self::Local => GitUploadSourceDataErrorV1::InvalidSource,
            Self::Retained => cause,
        }
    }
}

/// Reports the original typed failure of a non-admitting bootstrap.
#[derive(Debug, thiserror::Error)]
pub enum GitUploadSourceDataErrorV1 {
    /// The source or capacity scope is invalid.
    #[error("Git upload bootstrap source is invalid")]
    InvalidSource,
    /// The original signature engine rejected the source.
    #[error("Git upload bootstrap signature is invalid")]
    Signature(#[source] ed25519_dalek::SignatureError),
    /// The canonical object-identity engine rejected the capacity bytes.
    #[error("Git upload bootstrap object commitment is invalid")]
    Descriptor(#[source] aos_sandbox_model::ObjectDescriptorVerificationError),
    /// The canonical capacity decoder rejected the input.
    #[error("Git upload bootstrap capacity is invalid")]
    Capacity(#[source] aos_sandbox_model::CanonicalCborError),
    /// The retained state differs from the original initial source.
    #[error("Git upload bootstrap conflicts with protected state")]
    Conflict,
    /// Protected policy or journal work failed.
    #[error("Git upload bootstrap protected state failed")]
    Store(#[from] PublisherPolicyError),
}

/// Retains one verified full-policy signature as DATA, not current authority.
#[derive(Debug)]
pub struct VerifiedPublisherPolicySourceV1 {
    packet: [u8; PACKET_BYTES],
    policy: PreparedPublisherPolicyRevisionV1,
    resource: PublisherResourceBindingV1,
    controller: PublisherControllerHeadV1,
    revocation: PublisherRevocationHeadV1,
    key: [u8; 32],
    scope: PublisherSessionScope,
}

impl VerifiedPublisherPolicySourceV1 {
    /// Verifies the unchanged packet signature, scope and ordinary cache grant.
    ///
    /// # Errors
    ///
    /// Returns the original signature or policy cause, or invalid signed scope.
    pub fn verify(
        packet: [u8; PACKET_BYTES],
        canonical_policy: &[u8],
        key: [u8; 32],
        scope: PublisherSessionScope,
        now: i64,
    ) -> Result<Self, GitUploadSourceDataErrorV1> {
        Self::verify_with_error_custody(
            packet, canonical_policy, key, scope, now, SignedSourceErrorCustodyV1::Retained,
        )
    }

    /// Preserves ordinary local classification and failure-site error drop.
    ///
    /// # Errors
    ///
    /// Returns invalid-source DATA under the unchanged ordinary check order.
    pub fn verify_ordinary(
        packet: [u8; PACKET_BYTES],
        canonical_policy: &[u8],
        key: [u8; 32],
        scope: PublisherSessionScope,
        now: i64,
    ) -> Result<Self, GitUploadSourceDataErrorV1> {
        Self::verify_with_error_custody(
            packet, canonical_policy, key, scope, now, SignedSourceErrorCustodyV1::Local,
        )
    }

    fn verify_with_error_custody(
        packet: [u8; PACKET_BYTES],
        canonical_policy: &[u8],
        key: [u8; 32],
        scope: PublisherSessionScope,
        now: i64,
        custody: SignedSourceErrorCustodyV1,
    ) -> Result<Self, GitUploadSourceDataErrorV1> {
        if &packet[..8] != MAGIC {
            return Err(GitUploadSourceDataErrorV1::InvalidSource);
        }
        let verifying_key =
            VerifyingKey::from_bytes(&key)
                .map_err(|cause| custody.failure(GitUploadSourceDataErrorV1::Signature(cause)))?;
        let signature = Signature::from_slice(&packet[SIGNED_BYTES..])
            .map_err(|cause| custody.failure(GitUploadSourceDataErrorV1::Signature(cause)))?;
        let mut statement = Vec::with_capacity(SIGNING_DOMAIN.len() + SIGNED_BYTES);
        statement.extend_from_slice(SIGNING_DOMAIN);
        statement.extend_from_slice(&packet[..SIGNED_BYTES]);
        verifying_key
            .verify(&statement, &signature)
            .map_err(|cause| custody.failure(GitUploadSourceDataErrorV1::Signature(cause)))?;

        let publisher_principal = PrincipalId::from_bytes(read_array(&packet, 8)?);
        let node = NodeId::from_bytes(read_array(&packet, 24)?);
        let project = ProjectId::from_bytes(read_array(&packet, 40)?);
        let resource_id = ResourceId::from_bytes(read_array(&packet, 56)?);
        let isolation = ObjectDigest::from_bytes(read_array(&packet, 72)?);
        let controller_principal = PrincipalId::from_bytes(read_array(&packet, 104)?);
        let controller_generation = read_u64(&packet, 120)?;
        let revocation_scope = RevocationScopeId::from_bytes(read_array(&packet, 128)?);
        let revocation_generation = read_u64(&packet, 144)?;
        let policy_generation = read_u64(&packet, 152)?;
        let not_before = read_i64(&packet, 160)?;
        let expires_at = read_i64(&packet, 168)?;
        let expected_digest: [u8; 32] = read_array(&packet, 176)?;
        if publisher_principal != scope.principal
            || node != scope.node
            || project != scope.project
            || resource_id != scope.cache_resource
            || controller_principal.as_bytes() == &[0; 16]
            || revocation_scope.as_bytes() == &[0; 16]
            || controller_generation != 1
            || revocation_generation != 1
            || policy_generation != 1
            || now < not_before
            || now >= expires_at
        {
            return Err(GitUploadSourceDataErrorV1::InvalidSource);
        }
        let policy = PreparedPublisherPolicyRevisionV1::from_canonical_bytes(
            project,
            policy_generation,
            not_before,
            expires_at,
            canonical_policy,
            DecodeLimits::default(),
        )
        .map_err(|cause| {
            custody.failure(GitUploadSourceDataErrorV1::Store(
                PublisherPolicyError::from(cause),
            ))
        })?;
        if policy.descriptor().digest().as_bytes() != &expected_digest
            || policy.policy().cache_domain().kind() != CacheDomainKind::Project
            || !policy.policy().effective_grants().iter().any(|grant| {
                grant.resource_kind() == ResourceKind::CachePublish
                    && grant.operations().contains(Operation::Publish)
                    && matches!(
                        grant.selector(),
                        Selector::Resource { resource } if *resource == resource_id
                    )
            })
            || policy.policy().effective_grants().iter().any(|grant| {
                grant.resource_kind() == ResourceKind::CachePublish
                    && grant.operations().contains(Operation::Publish)
                    && !matches!(
                        grant.selector(),
                        Selector::Resource { resource } if *resource == resource_id
                    )
            })
        {
            return Err(GitUploadSourceDataErrorV1::InvalidSource);
        }
        let resource = PublisherResourceBindingV1::new(
            resource_id,
            project,
            policy.policy().cache_domain(),
            isolation,
        )
        .map_err(|cause| custody.failure(GitUploadSourceDataErrorV1::Store(cause)))?;
        Ok(Self {
            packet,
            policy,
            resource,
            controller: PublisherControllerHeadV1 {
                principal: controller_principal,
                generation: controller_generation,
            },
            revocation: PublisherRevocationHeadV1 {
                scope: revocation_scope,
                generation: revocation_generation,
            },
            key,
            scope,
        })
    }

    /// Borrows the exact signature-checked packet as DATA.
    pub const fn packet(&self) -> &[u8; PACKET_BYTES] {
        &self.packet
    }

    /// Borrows the supplied verification key as DATA, not a fixed issuer.
    pub const fn verification_key(&self) -> &[u8; 32] {
        &self.key
    }

    /// Returns the exact ordinary prepared policy.
    pub const fn policy(&self) -> &PreparedPublisherPolicyRevisionV1 {
        &self.policy
    }

    /// Returns the original signature-checked registration scope as DATA.
    pub const fn scope(&self) -> PublisherSessionScope {
        self.scope
    }

    /// Returns the distinct immutable cache-publication binding.
    pub const fn resource(&self) -> &PublisherResourceBindingV1 {
        &self.resource
    }

    /// Returns the initial Controller head DATA.
    pub const fn controller(&self) -> PublisherControllerHeadV1 {
        self.controller
    }

    /// Returns the initial revocation head DATA.
    pub const fn revocation(&self) -> PublisherRevocationHeadV1 {
        self.revocation
    }

    /// Decodes the one signed capacity input without treating it as a permit.
    ///
    /// # Errors
    ///
    /// Rejects a missing or duplicate descriptor, object mismatch, malformed
    /// declaration, or Git resource/project mismatch with the full policy.
    pub fn verify_git_capacity(
        &self,
        bytes: &[u8],
    ) -> Result<GitUploadCapacityV1, GitUploadSourceDataErrorV1> {
        let mut descriptors = self.policy.policy().input_commitments().iter().filter(|descriptor| {
            descriptor.media_type().as_str() == PortableMediaType::GitUploadCapacity.as_str()
        });
        let descriptor = descriptors.next()
            .ok_or(GitUploadSourceDataErrorV1::InvalidSource)?;
        if descriptors.next().is_some() {
            return Err(GitUploadSourceDataErrorV1::InvalidSource);
        }
        let mut verifier = ObjectDescriptorVerifier::new(descriptor.clone());
        verifier.update(bytes).map_err(GitUploadSourceDataErrorV1::Descriptor)?;
        verifier.finish().map_err(GitUploadSourceDataErrorV1::Descriptor)?;

        let capacity = decode_git_upload_capacity_v1(bytes)
            .map_err(GitUploadSourceDataErrorV1::Capacity)?;
        if capacity.project() != self.policy.project()
            || capacity.resource() == self.resource.resource()
            || !self.policy.policy().effective_grants().iter().any(|grant|
                grant.resource_kind() == ResourceKind::GitObjectDatabase)
            || self.policy.policy().effective_grants().iter()
                .chain(self.policy.policy().delegable_grants()).any(|grant|
                    grant.resource_kind() == ResourceKind::GitObjectDatabase
                        && !matches!(grant.selector(),
                            Selector::Resource { resource } if *resource == capacity.resource()))
        {
            return Err(GitUploadSourceDataErrorV1::InvalidSource);
        }
        Ok(capacity)
    }

    /// Derives the unchanged ordinary transaction identity.
    pub fn transaction_id(&self, kind: &[u8]) -> [u8; 16] {
        let digest = Sha256::new()
            .chain_update(TRANSACTION_DOMAIN)
            .chain_update(kind)
            .chain_update(self.packet)
            .finalize();
        let mut id = [0; 16];
        id.copy_from_slice(&digest[..16]);
        id
    }
}

fn read_array<const N: usize>(
    packet: &[u8],
    offset: usize,
) -> Result<[u8; N], GitUploadSourceDataErrorV1> {
    packet
        .get(offset..offset + N)
        .ok_or(GitUploadSourceDataErrorV1::InvalidSource)?
        .try_into()
        .map_err(|_| GitUploadSourceDataErrorV1::InvalidSource)
}

fn read_u64(packet: &[u8], offset: usize) -> Result<u64, GitUploadSourceDataErrorV1> {
    Ok(u64::from_be_bytes(read_array(packet, offset)?))
}

fn read_i64(packet: &[u8], offset: usize) -> Result<i64, GitUploadSourceDataErrorV1> {
    Ok(i64::from_be_bytes(read_array(packet, offset)?))
}

/// Prefixes immutable signed Git bootstrap origins.
pub const ORIGIN_PREFIX: &[u8] = b"git-upload/bootstrap-origin/";
/// Identifies the established Git bootstrap origin format.
pub const ORIGIN_MAGIC: &[u8; 8] = b"AOSGUBO1";
/// Separates signed Git bootstrap origin commitments.
pub const ORIGIN_DOMAIN: &[u8] = b"aos.sandbox.git-upload.bootstrap-origin.v1\0";
/// Counts the complete fixed origin header before its capacity bytes.
pub const ORIGIN_FIXED_BYTES: usize = 408;

crate::define_provider_native_account_data_recipe_v1!(
    PublisherPolicyError::CorruptState
);
/// Encodes the original immutable Git bootstrap origin key.

pub fn origin_key(project: ProjectId) -> Vec<u8> {
    key(ORIGIN_PREFIX, project.as_bytes(), None)
}
/// Encodes the original Git record magic, version, project and generation header.

pub fn record_header(magic: &[u8; 8], project: ProjectId, generation: u64) -> Vec<u8> {
    let mut bytes = Vec::new();
    bytes.extend_from_slice(magic);
    bytes.extend_from_slice(&1_u16.to_be_bytes());
    bytes.extend_from_slice(&0_u16.to_be_bytes());
    bytes.extend_from_slice(project.as_bytes());
    bytes.extend_from_slice(&generation.to_be_bytes());
    bytes
}
/// Encodes the verified signed source and its exact capacity bytes as historical origin DATA.
///
/// # Errors
///
/// Rejects an unrepresentable capacity length or invalid canonical policy encoding.

pub fn encode_origin(
    source: &VerifiedPublisherPolicySourceV1,
    body: &[u8],
) -> Result<Vec<u8>, PublisherPolicyError> {
    let mut bytes = record_header(ORIGIN_MAGIC, source.policy.project(), source.policy.generation());
    bytes.extend_from_slice(commitment(HEAD_DOMAIN, &encode_policy_head(&source.policy)).as_bytes());
    bytes.extend_from_slice(commitment(REVISION_DOMAIN, &encode_policy_revision(&source.policy)?).as_bytes());
    bytes.extend_from_slice(&source.key);
    bytes.extend_from_slice(&source.packet);
    let length = u32::try_from(body.len()).map_err(|_| PublisherPolicyError::CorruptState)?;
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(body);
    Ok(bytes)
}
/// Encodes the complete predecessor/origin and both resource vectors of a Git account.

pub fn encode_account(
    project: ProjectId,
    generation: u64,
    predecessor: ObjectDigest,
    origin: ObjectDigest,
    committed: ResourceVector,
    reserved: ResourceVector,
) -> Vec<u8> {
    let mut bytes = record_header(ACCOUNT_MAGIC, project, generation);
    bytes.extend_from_slice(predecessor.as_bytes());
    bytes.extend_from_slice(origin.as_bytes());
    for vector in [committed, reserved] {
        for dimension in ResourceDimension::ALL {
            bytes.extend_from_slice(&vector.get(dimension).to_be_bytes());
        }
    }
    bytes
}
/// Encodes the selected Git account revision digest and generation.

pub fn encode_account_head(project: ProjectId, generation: u64, revision: ObjectDigest) -> Vec<u8> {
    let mut bytes = record_header(HEAD_MAGIC, project, generation);
    bytes.extend_from_slice(revision.as_bytes());
    bytes
}

struct HistoricalOrigin {
    capacity: GitUploadCapacityV1,
    digest: ObjectDigest,
}

/// Accumulates the closed Git families inside the sole namespace replay.
///
/// Companions lend their original bytes; there is no second account reducer
/// or owning projection of the complete coverage catalog.
#[derive(Default)]
pub struct GitUploadBootstrapReplayV1<'journal> {
    origins: BTreeMap<ProjectId, HistoricalOrigin>,
    accounts: BTreeMap<ProjectId, BTreeMap<u64, AccountRevision>>,
    heads: BTreeMap<ProjectId, (u64, ObjectDigest)>,
    coverage: BTreeMap<ProjectId, BTreeMap<u64, super::account_coverage::AccountCoverageV1<'journal>>>,
}

impl<'journal> GitUploadBootstrapReplayV1<'journal> {
    /// Consumes one established Git origin, account, head or coverage row.
    ///
    /// # Errors
    ///
    /// Rejects malformed rows, duplicate generations or invalid signed-source/capacity cross-links.
    pub fn consume(
        &mut self,
        journal: PublisherReadDataV2<'journal>,
        record_key: &[u8],
        bytes: &'journal [u8],
    ) -> Result<bool, PublisherPolicyError> {
        if record_key.starts_with(ORIGIN_PREFIX) {
            let (project, generation) = check_record_header(bytes, ORIGIN_MAGIC, ORIGIN_FIXED_BYTES)?;
            let length = u32::from_be_bytes(array(bytes, 404)?) as usize;
            if length == 0 || length > aos_sandbox_model::MAXIMUM_GIT_UPLOAD_CAPACITY_BYTES_V1
                || bytes.len() != ORIGIN_FIXED_BYTES + length || record_key != origin_key(project)
            {
                return Err(PublisherPolicyError::CorruptState);
            }
            let revision_bytes = journal.get(RecordNamespace::PublisherPolicy,
                &policy_revision_key(project, generation)).ok_or(PublisherPolicyError::CorruptState)?;
            if revision_bytes.get(..8) != Some(POLICY_REVISION_MAGIC.as_slice()) {
                return Err(PublisherPolicyError::CorruptState);
            }
            let revision = decode_policy_revision(revision_bytes)?;
            let packet: [u8; PACKET_BYTES] = array(bytes, 132)?;
            let scope = PublisherSessionScope {
                principal: PrincipalId::from_bytes(array(&packet, 8)?),
                node: NodeId::from_bytes(array(&packet, 24)?),
                project,
                cache_resource: ResourceId::from_bytes(array(&packet, 56)?),
            };
            let source = VerifiedPublisherPolicySourceV1::verify(
                packet, revision.canonical_policy(), array(bytes, 100)?, scope, revision.not_before(),
            ).map_err(|_| PublisherPolicyError::CorruptState)?;
            let capacity = source.verify_git_capacity(&bytes[ORIGIN_FIXED_BYTES..])
                .map_err(|_| PublisherPolicyError::CorruptState)?;
            if source.policy != revision || commitment(HEAD_DOMAIN, &encode_policy_head(&revision))
                    != ObjectDigest::from_bytes(array(bytes, 36)?)
                || commitment(REVISION_DOMAIN, revision_bytes) != ObjectDigest::from_bytes(array(bytes, 68)?)
                || self.origins.insert(project, HistoricalOrigin {
                    capacity, digest: commitment(ORIGIN_DOMAIN, bytes),
                }).is_some()
            {
                return Err(PublisherPolicyError::CorruptState);
            }
        } else if record_key.starts_with(ACCOUNT_PREFIX) {
            let (project, generation) = check_record_header(bytes, ACCOUNT_MAGIC, ACCOUNT_BYTES)?;
            if bytes.len() != ACCOUNT_BYTES || record_key != account_key(project, generation) {
                return Err(PublisherPolicyError::CorruptState);
            }
            let revision = decode_account_contents(bytes)?;
            if self.accounts.entry(project).or_default().insert(generation, revision).is_some() {
                return Err(PublisherPolicyError::CorruptState);
            }
        } else if record_key.starts_with(HEAD_PREFIX) {
            let (project, generation) = check_record_header(bytes, HEAD_MAGIC, HEAD_BYTES)?;
            if bytes.len() != HEAD_BYTES || record_key != account_head_key(project)
                || self.heads.insert(project, (generation, ObjectDigest::from_bytes(array(bytes, 36)?))).is_some()
            {
                return Err(PublisherPolicyError::CorruptState);
            }
        } else if record_key.starts_with(super::account_coverage::PREFIX) {
            let coverage = super::account_coverage::AccountCoverageV1::decode(bytes)?;
            coverage.require_empty_first_profile()?;
            if record_key != coverage.key()?
                || self.coverage.entry(coverage.project()?).or_default()
                    .insert(coverage.generation()?, coverage).is_some()
            {
                return Err(PublisherPolicyError::CorruptState);
            }
        } else {
            return Ok(false);
        }
        Ok(true)
    }
    /// Checks complete Git origin/account/head sets and contiguous covered account history.
    ///
    /// # Errors
    ///
    /// Rejects incomplete families, broken predecessors, invalid resource accounting or coverage disagreement.

    pub fn finish(self) -> Result<(), PublisherPolicyError> {
        if self.origins.len() != self.accounts.len() || self.origins.len() != self.heads.len() {
            return Err(PublisherPolicyError::CorruptState);
        }
        if self.coverage.keys().any(|project| !self.origins.contains_key(project)) {
            return Err(PublisherPolicyError::CorruptState);
        }
        for (project, origin) in self.origins {
            let revisions = self.accounts.get(&project).ok_or(PublisherPolicyError::CorruptState)?;
            let mut generation = 0_u64;
            let mut previous = ObjectDigest::from_bytes([0; 32]);
            for (actual, revision) in revisions {
                generation = generation.checked_add(1).ok_or(PublisherPolicyError::CorruptState)?;
                if *actual != generation || revision.predecessor != previous
                    || revision.origin != origin.digest
                    || ResourceAccount::from_usage(
                        ResourceCeilings::bounded(origin.capacity.ceilings()),
                        revision.committed, revision.reserved,
                    ).is_err()
                    || (generation == 1
                        && (revision.committed != ResourceVector::ZERO || revision.reserved != ResourceVector::ZERO))
                {
                    return Err(PublisherPolicyError::CorruptState);
                }
                previous = revision.digest;
            }
            if generation == 0 || self.heads.get(&project) != Some(&(generation, previous)) {
                return Err(PublisherPolicyError::CorruptState);
            }
            if let Some(coverage) = self.coverage.get(&project) {
                require_coverage_chain(&origin, revisions, coverage)?;
            }
        }
        Ok(())
    }
}

// The existing namespace pass owns account continuity and all ResourceAccount
// arithmetic. This adds the full companion relation only when that new family
// is present; ordinary/gen1 histories keep their original checks and results.
fn require_coverage_chain(
    origin: &HistoricalOrigin,
    revisions: &BTreeMap<u64, AccountRevision>,
    coverage: &BTreeMap<u64, super::account_coverage::AccountCoverageV1<'_>>,
) -> Result<(), PublisherPolicyError> {
    if coverage.len().checked_add(1) != Some(revisions.len()) {
        return Err(PublisherPolicyError::CorruptState);
    }
    let original = coverage.get(&2).ok_or(PublisherPolicyError::CorruptState)?;
    let enrollment = original.enrollment()?;
    let original_owners = original.owner_bytes();
    let mut predecessor = ObjectDigest::from_bytes([0; 32]);

    // The original verifier already compared the unique signed descriptor to
    // these canonical capacity bytes. Reuse the sole encoder/descriptor engine
    // only for the new companion family; ordinary replay's stored origin and
    // allocation layout remain unchanged.
    let ceiling_authority = capacity_authority_digest(&origin.capacity)?;

    for (generation, revision) in revisions.range(2..) {
        let companion = coverage.get(generation).ok_or(PublisherPolicyError::CorruptState)?;
        companion.require_empty_first_profile()?;
        let (committed, reserved) = companion.fold()?;
        if companion.origin()? != origin.digest
            || companion.account()? != revision.digest
            || companion.predecessor()? != predecessor
            || companion.enrollment()? != enrollment
            || companion.owner_bytes() != original_owners
            || companion.ceiling_authority()? != ceiling_authority
            || companion.cpu_period_micros()? != origin.capacity.cpu_period_micros()
            || committed != revision.committed
            || reserved != revision.reserved
        {
            return Err(PublisherPolicyError::CorruptState);
        }
        predecessor = companion.digest();
    }
    Ok(())
}
/// Commits the canonical capacity declaration through the existing descriptor engine.
///
/// # Errors
///
/// Rejects an invalid canonical capacity media type.

pub fn capacity_authority_digest(capacity: &GitUploadCapacityV1) -> Result<ObjectDigest, PublisherPolicyError> {
    let canonical_capacity = aos_sandbox_model::encode_git_upload_capacity_v1(capacity);
    let media_type = aos_sandbox_model::MediaType::new(PortableMediaType::GitUploadCapacity.as_str())
        .map_err(|_| PublisherPolicyError::CorruptState)?;
    Ok(aos_sandbox_model::descriptor_for_bytes(media_type, &canonical_capacity).digest())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_account_and_head_records_preserve_all_twenty_two_amounts() {
        let project = ProjectId::from_bytes([1; 16]);
        let committed = ResourceVector::new(std::array::from_fn(|index| index as u64 + 1));
        let reserved = ResourceVector::new(std::array::from_fn(|index| index as u64 + 30));
        let bytes = encode_account(
            project, 2, ObjectDigest::from_bytes([2; 32]),
            ObjectDigest::from_bytes([3; 32]), committed, reserved,
        );
        let head = encode_account_head(project, 2, commitment(ACCOUNT_DOMAIN, &bytes));

        assert_eq!(bytes.len(), ACCOUNT_BYTES);
        assert_eq!(head.len(), HEAD_BYTES);
        assert_eq!(check_record_header(&bytes, ACCOUNT_MAGIC, ACCOUNT_BYTES).unwrap(), (project, 2));
        for (index, dimension) in ResourceDimension::ALL.into_iter().enumerate() {
            assert_eq!(u64::from_be_bytes(array(&bytes, 100 + index * 8).unwrap()), committed.get(dimension));
            assert_eq!(u64::from_be_bytes(array(&bytes, 276 + index * 8).unwrap()), reserved.get(dimension));
        }
    }

    #[test]
    fn partial_account_family_is_not_replay_complete() {
        let project = ProjectId::from_bytes([1; 16]);
        let mut replay = GitUploadBootstrapReplayV1::default();
        replay.heads.insert(project, (1, ObjectDigest::from_bytes([2; 32])));

        assert!(replay.finish().is_err());
    }

    #[test]
    fn record_header_version_and_reserved_bytes_are_closed() {
        let project = ProjectId::from_bytes([1; 16]);
        let original = encode_account_head(project, 1, ObjectDigest::from_bytes([2; 32]));
        assert!(check_record_header(&original, HEAD_MAGIC, HEAD_BYTES).is_ok());

        for index in [9, 11] {
            let mut changed = original.clone();
            changed[index] = 2;
            assert!(check_record_header(&changed, HEAD_MAGIC, HEAD_BYTES).is_err());
        }
    }
}
