//! Durable publisher-policy record encoding and generation validation.
//!
//! Every integer is big-endian, identifiers and digests are their fixed-width
//! byte forms, and no record permits trailing bytes. The namespace uses these
//! version-one layouts:
//!
//! ```text
//! policy/revision/<project:16><generation:u64> =
//!   "AOSPOLR1" project:16 generation:u64 not_before:i64 expires_at:i64
//!   digest:32 policy_length:u32 canonical_policy:policy_length
//! policy/current/<project:16> =
//!   "AOSPOLH1" project:16 generation:u64 digest:32
//! resource/<resource:16> =
//!   "AOSRESB1" resource:16 project:16 domain_kind:u8 domain_id:16
//!   isolation_policy:32
//! controller/revision/<generation:u64> =
//!   "AOSCTLR1" principal:16 generation:u64
//! controller/current = "AOSCTLH1" principal:16 generation:u64
//! revocation/revision/<scope:16><generation:u64> =
//!   "AOSREVR1" scope:16 generation:u64
//! revocation/current/<scope:16> = "AOSREVH1" scope:16 generation:u64
//! ```

use super::*;

const PROJECT_CACHE_DOMAIN_TAG: u8 = 1;

#[derive(Clone, Copy)]
pub(super) struct PolicyHead {
    pub(super) project: ProjectId,
    pub(super) generation: u64,
    pub(super) digest: ObjectDigest,
}

pub(super) fn bounded_decode_limits(requested: DecodeLimits) -> DecodeLimits {
    DecodeLimits {
        maximum_bytes: requested.maximum_bytes.min(MAXIMUM_POLICY_BYTES),
        maximum_collection_items: requested
            .maximum_collection_items
            .min(MAXIMUM_COLLECTION_ITEMS),
        maximum_total_items: requested.maximum_total_items.min(MAXIMUM_TOTAL_ITEMS),
        maximum_byte_string_bytes: requested
            .maximum_byte_string_bytes
            .min(MAXIMUM_STRING_BYTES),
        maximum_text_bytes: requested.maximum_text_bytes.min(MAXIMUM_STRING_BYTES),
        maximum_depth: requested.maximum_depth.min(MAXIMUM_DEPTH),
    }
}

pub(super) fn policy_media_type() -> Result<MediaType, PublisherPolicyError> {
    MediaType::new(
        aos_sandbox_core::PortableMediaType::Policy
            .as_str()
            .to_owned(),
    )
    .map_err(|_| PublisherPolicyError::InvalidPolicyRevision)
}

pub(super) fn validate_successor(
    current: Option<u64>,
    expected: Option<u64>,
    next: u64,
) -> Result<(), PublisherPolicyError> {
    if current != expected {
        return Err(PublisherPolicyError::CompareAndSwapFailed);
    }
    let required = match current {
        Some(generation) => generation
            .checked_add(1)
            .ok_or(PublisherPolicyError::GenerationExhausted)?,
        None => 1,
    };
    if next != required {
        return Err(PublisherPolicyError::NoncontiguousGeneration);
    }
    Ok(())
}

pub(super) fn key(prefix: &[u8], identity: &[u8], generation: Option<u64>) -> Vec<u8> {
    let mut key = Vec::with_capacity(prefix.len() + identity.len() + generation.map_or(0, |_| 8));
    key.extend_from_slice(prefix);
    key.extend_from_slice(identity);
    if let Some(generation) = generation {
        key.extend_from_slice(&generation.to_be_bytes());
    }
    key
}
pub(super) fn policy_revision_key(project: ProjectId, generation: u64) -> Vec<u8> {
    key(POLICY_REVISION_PREFIX, project.as_bytes(), Some(generation))
}
pub(super) fn policy_current_key(project: ProjectId) -> Vec<u8> {
    key(POLICY_CURRENT_PREFIX, project.as_bytes(), None)
}
pub(super) fn resource_key(resource: ResourceId) -> Vec<u8> {
    key(RESOURCE_PREFIX, resource.as_bytes(), None)
}
pub(super) fn controller_revision_key(generation: u64) -> Vec<u8> {
    key(CONTROLLER_REVISION_PREFIX, &[], Some(generation))
}
pub(super) fn revocation_revision_key(scope: RevocationScopeId, generation: u64) -> Vec<u8> {
    key(
        REVOCATION_REVISION_PREFIX,
        scope.as_bytes(),
        Some(generation),
    )
}
pub(super) fn revocation_current_key(scope: RevocationScopeId) -> Vec<u8> {
    key(REVOCATION_CURRENT_PREFIX, scope.as_bytes(), None)
}

pub(super) fn encode_policy_revision(
    value: &PreparedPublisherPolicyRevisionV1,
) -> Result<Vec<u8>, PublisherPolicyError> {
    let length = u32::try_from(value.canonical_policy.len())
        .map_err(|_| PublisherPolicyError::LimitExceeded("policy bytes"))?;
    let mut bytes = Vec::with_capacity(84 + value.canonical_policy.len());
    bytes.extend_from_slice(POLICY_REVISION_MAGIC);
    bytes.extend_from_slice(value.project.as_bytes());
    bytes.extend_from_slice(&value.generation.to_be_bytes());
    bytes.extend_from_slice(&value.not_before.to_be_bytes());
    bytes.extend_from_slice(&value.expires_at.to_be_bytes());
    bytes.extend_from_slice(value.descriptor.digest().as_bytes());
    bytes.extend_from_slice(&length.to_be_bytes());
    bytes.extend_from_slice(&value.canonical_policy);
    Ok(bytes)
}
pub(super) fn decode_policy_revision(
    bytes: &[u8],
) -> Result<PreparedPublisherPolicyRevisionV1, PublisherPolicyError> {
    if bytes.len() < 84 || &bytes[..8] != POLICY_REVISION_MAGIC {
        return Err(PublisherPolicyError::CorruptState);
    }
    let project = ProjectId::from_bytes(array(bytes, 8)?);
    let generation = u64::from_be_bytes(array(bytes, 24)?);
    let not_before = i64::from_be_bytes(array(bytes, 32)?);
    let expires_at = i64::from_be_bytes(array(bytes, 40)?);
    let digest = ObjectDigest::from_bytes(array(bytes, 48)?);
    let length = u32::from_be_bytes(array(bytes, 80)?) as usize;
    if bytes.len()
        != 84usize
            .checked_add(length)
            .ok_or(PublisherPolicyError::CorruptState)?
    {
        return Err(PublisherPolicyError::CorruptState);
    }
    let value = PreparedPublisherPolicyRevisionV1::from_canonical_bytes(
        project,
        generation,
        not_before,
        expires_at,
        &bytes[84..],
        DecodeLimits::default(),
    )
    .map_err(|_| PublisherPolicyError::CorruptState)?;
    if value.descriptor.digest() != digest {
        return Err(PublisherPolicyError::CorruptState);
    }
    Ok(value)
}
pub(super) fn encode_policy_head(value: &PreparedPublisherPolicyRevisionV1) -> Vec<u8> {
    let mut bytes = Vec::with_capacity(64);
    bytes.extend_from_slice(POLICY_CURRENT_MAGIC);
    bytes.extend_from_slice(value.project.as_bytes());
    bytes.extend_from_slice(&value.generation.to_be_bytes());
    bytes.extend_from_slice(value.descriptor.digest().as_bytes());
    bytes
}
pub(super) fn decode_policy_head(bytes: &[u8]) -> Result<PolicyHead, PublisherPolicyError> {
    if bytes.len() != 64 || &bytes[..8] != POLICY_CURRENT_MAGIC {
        return Err(PublisherPolicyError::CorruptState);
    }
    Ok(PolicyHead {
        project: ProjectId::from_bytes(array(bytes, 8)?),
        generation: u64::from_be_bytes(array(bytes, 24)?),
        digest: ObjectDigest::from_bytes(array(bytes, 32)?),
    })
}
pub(super) fn encode_resource(value: &PublisherResourceBindingV1) -> Vec<u8> {
    let mut b = Vec::with_capacity(89);
    b.extend_from_slice(RESOURCE_MAGIC);
    b.extend_from_slice(value.resource.as_bytes());
    b.extend_from_slice(value.project.as_bytes());
    b.push(PROJECT_CACHE_DOMAIN_TAG);
    b.extend_from_slice(value.cache_domain.domain_id().as_bytes());
    b.extend_from_slice(value.isolation_policy.as_bytes());
    b
}
pub(super) fn decode_resource(
    bytes: &[u8],
) -> Result<PublisherResourceBindingV1, PublisherPolicyError> {
    if bytes.len() != 89 || &bytes[..8] != RESOURCE_MAGIC || bytes[40] != PROJECT_CACHE_DOMAIN_TAG {
        return Err(PublisherPolicyError::CorruptState);
    }
    PublisherResourceBindingV1::new(
        ResourceId::from_bytes(array(bytes, 8)?),
        ProjectId::from_bytes(array(bytes, 24)?),
        CacheDomain::new(
            CacheDomainKind::Project,
            aos_sandbox_core::CacheDomainId::from_bytes(array(bytes, 41)?),
        ),
        ObjectDigest::from_bytes(array(bytes, 57)?),
    )
    .map_err(|_| PublisherPolicyError::CorruptState)
}
pub(super) fn encode_controller(v: PublisherControllerHeadV1, magic: &[u8; 8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(32);
    b.extend_from_slice(magic);
    b.extend_from_slice(v.principal.as_bytes());
    b.extend_from_slice(&v.generation.to_be_bytes());
    b
}
pub(super) fn decode_controller(
    bytes: &[u8],
    magic: &[u8; 8],
) -> Result<PublisherControllerHeadV1, PublisherPolicyError> {
    if bytes.len() != 32 || &bytes[..8] != magic {
        return Err(PublisherPolicyError::CorruptState);
    }
    let value = PublisherControllerHeadV1 {
        principal: PrincipalId::from_bytes(array(bytes, 8)?),
        generation: u64::from_be_bytes(array(bytes, 24)?),
    };
    if value.principal.as_bytes() == &[0; 16] || value.generation == 0 {
        return Err(PublisherPolicyError::CorruptState);
    }
    Ok(value)
}
pub(super) fn encode_revocation(v: PublisherRevocationHeadV1, magic: &[u8; 8]) -> Vec<u8> {
    let mut b = Vec::with_capacity(32);
    b.extend_from_slice(magic);
    b.extend_from_slice(v.scope.as_bytes());
    b.extend_from_slice(&v.generation.to_be_bytes());
    b
}
pub(super) fn decode_revocation(
    bytes: &[u8],
    magic: &[u8; 8],
) -> Result<PublisherRevocationHeadV1, PublisherPolicyError> {
    if bytes.len() != 32 || &bytes[..8] != magic {
        return Err(PublisherPolicyError::CorruptState);
    }
    let value = PublisherRevocationHeadV1 {
        scope: RevocationScopeId::from_bytes(array(bytes, 8)?),
        generation: u64::from_be_bytes(array(bytes, 24)?),
    };
    if value.scope.as_bytes() == &[0; 16] || value.generation == 0 {
        return Err(PublisherPolicyError::CorruptState);
    }
    Ok(value)
}
pub(super) fn array<const N: usize>(
    bytes: &[u8],
    offset: usize,
) -> Result<[u8; N], PublisherPolicyError> {
    bytes
        .get(offset..offset + N)
        .and_then(|slice| slice.try_into().ok())
        .ok_or(PublisherPolicyError::CorruptState)
}
